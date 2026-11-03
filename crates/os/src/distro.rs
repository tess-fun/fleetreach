//! Which distribution and release an image runs, from `/etc/os-release`, mapped onto the
//! osv.dev ecosystem that holds its advisories (`Debian:12`, `Alpine:v3.20`, `Wolfi`, ...).
//!
//! Fail-closed: an ID this table does not know, or a release it cannot name (Debian
//! testing, Alpine edge), is a coverage gap with the reason, never "no vulnerabilities".
//! A derivative that says `ID_LIKE=debian` is not matched against Debian, because its
//! backports and version strings are its own; for the same reason CentOS, Oracle Linux and
//! Fedora are not matched against Red Hat's records, and are gaps until a feed of their own
//! is read.

/// Which package format a distribution uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    /// dpkg (`/var/lib/dpkg`), Debian versions.
    Deb,
    /// apk (`/lib/apk/db/installed`), apk-tools versions.
    Apk,
    /// rpm (`/var/lib/rpm`, `/usr/lib/sysimage/rpm`), rpm versions.
    Rpm,
}

impl Family {
    /// The package-URL type (`deb`, `apk`, `rpm`).
    pub fn purl_type(self) -> &'static str {
        match self {
            Family::Deb => "deb",
            Family::Apk => "apk",
            Family::Rpm => "rpm",
        }
    }
}

/// The fields of an os-release file that identify a distribution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsRelease {
    pub id: String,
    pub id_like: Vec<String>,
    pub version_id: Option<String>,
    /// `VERSION`, which openEuler needs for its service pack (`22.03 (LTS-SP3)`).
    pub version: Option<String>,
    pub pretty_name: Option<String>,
}

/// Parse an os-release file (`KEY=value`, values optionally quoted).
pub fn parse_os_release(text: &str) -> OsRelease {
    let mut out = OsRelease::default();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value)
            .replace("\\\"", "\"");
        match key.trim() {
            "ID" => out.id = value.to_ascii_lowercase(),
            "ID_LIKE" => out.id_like = value.split_whitespace().map(str::to_string).collect(),
            "VERSION_ID" if !value.is_empty() => out.version_id = Some(value),
            "VERSION" if !value.is_empty() => out.version = Some(value),
            "PRETTY_NAME" if !value.is_empty() => out.pretty_name = Some(value),
            _ => {}
        }
    }
    out
}

/// A detected distribution and the OSV ecosystems its packages are matched against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distro {
    pub family: Family,
    /// For people: `Debian 12`, `Alpine 3.20`, `Wolfi`.
    pub name: String,
    /// The package-URL namespace (`debian`, `alpine`, `wolfi`), also the prefix of every
    /// package name in findings (`debian/openssl`).
    pub namespace: String,
    /// The osv.dev ecosystem of the release (`Debian:12`).
    pub ecosystem: String,
    /// More ecosystems of the same release, matched alongside it: the other repositories of a
    /// Red Hat release (`Red Hat:enterprise_linux:9::appstream` beside `::baseos`).
    pub also: Vec<String>,
    /// Whether the advisories name binary packages (Red Hat, AlmaLinux: `openssl-libs`)
    /// rather than source packages (everyone else: `openssl`).
    pub binary_names: bool,
    /// Ecosystems that take precedence for the same package and CVE: Ubuntu Pro (ESM) and
    /// Root's patched packages, when the installed versions show them.
    pub overlays: Vec<String>,
}

impl Distro {
    /// Every ecosystem to load: the release, its other repositories, then its overlays.
    pub fn ecosystems(&self) -> Vec<String> {
        let mut out = vec![self.ecosystem.clone()];
        out.extend(self.also.iter().cloned());
        out.extend(self.overlays.iter().cloned());
        out
    }
}

/// The osv.dev export directories that can serve `ecosystem`, smallest first: the
/// per-release export where osv.dev publishes one (`Debian:12/all.zip`, 43 MB), then the
/// whole distribution (`Debian/all.zip`, 80 MB; Ubuntu's is 806 MB against 142 MB for one
/// LTS release).
pub fn export_candidates(ecosystem: &str) -> Vec<String> {
    let base = ecosystem.split(':').next().unwrap_or(ecosystem).to_string();
    if base == ecosystem {
        vec![base]
    } else {
        vec![ecosystem.to_string(), base]
    }
}

/// What the installed versions say beyond os-release.
#[derive(Debug, Clone, Copy, Default)]
pub struct Hints {
    /// Some package carries an Ubuntu Pro (ESM) version (`+esm`).
    pub esm: bool,
    /// Some package carries a Root patched version (`root.io`).
    pub root_io: bool,
}

impl Hints {
    /// Read the hints off installed version strings.
    pub fn from_versions<'a>(versions: impl IntoIterator<Item = &'a str>) -> Hints {
        let mut h = Hints::default();
        for v in versions {
            h.esm |= v.contains("+esm");
            h.root_io |= v.contains("root.io");
        }
        h
    }
}

fn major(v: &str) -> Option<&str> {
    let m = v.split('.').next()?;
    (!m.is_empty() && m.bytes().all(|b| b.is_ascii_digit())).then_some(m)
}

/// Map os-release (and `/etc/debian_version` for Debian images without `VERSION_ID`) onto a
/// [`Distro`]. `Err` carries the coverage-gap reason.
///
/// # Errors
///
/// When the distribution or its release is not one fleetreach can match.
pub fn detect(
    os: &OsRelease,
    debian_version: Option<&str>,
    hints: Hints,
) -> Result<Distro, String> {
    let pretty = os.pretty_name.clone().unwrap_or_else(|| os.id.clone());
    let version = os.version_id.as_deref();
    let distro = |family, name: String, namespace: &str, ecosystem: String| Distro {
        family,
        name,
        namespace: namespace.to_string(),
        ecosystem,
        also: Vec::new(),
        binary_names: false,
        overlays: Vec::new(),
    };
    let release = |what: &str| {
        version
            .and_then(major)
            .ok_or_else(|| format!("{pretty}: no {what} release number in VERSION_ID"))
    };
    let rpm = |name: String, namespace: &str, ecosystem: String| {
        distro(Family::Rpm, name, namespace, ecosystem)
    };
    let mut d = match os.id.as_str() {
        "debian" => {
            let release = version
                .and_then(major)
                .or_else(|| debian_version.map(str::trim).and_then(major))
                .ok_or_else(|| {
                    format!(
                        "{pretty}: a Debian release without a version number (testing or \
                         unstable) has no OSV release to match against"
                    )
                })?;
            distro(
                Family::Deb,
                format!("Debian {release}"),
                "debian",
                format!("Debian:{release}"),
            )
        }
        "ubuntu" => {
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            let (yy, mm) = v
                .split_once('.')
                .filter(|(y, m)| y.len() == 2 && m.len() == 2)
                .ok_or_else(|| format!("{pretty}: unrecognized Ubuntu VERSION_ID {v:?}"))?;
            let lts = mm == "04" && yy.parse::<u32>().is_ok_and(|y| y % 2 == 0);
            let eco = if lts {
                format!("Ubuntu:{yy}.{mm}:LTS")
            } else {
                format!("Ubuntu:{yy}.{mm}")
            };
            let mut d = distro(Family::Deb, format!("Ubuntu {v}"), "ubuntu", eco);
            if hints.esm && lts {
                d.overlays.push(format!("Ubuntu:Pro:{yy}.{mm}:LTS"));
            }
            d
        }
        "alpine" => {
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            let mut parts = v.split('.');
            let (Some(maj), Some(min)) = (parts.next(), parts.next()) else {
                return Err(format!("{pretty}: unrecognized Alpine VERSION_ID {v:?}"));
            };
            if !maj.bytes().all(|b| b.is_ascii_digit()) || !min.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(format!(
                    "{pretty}: Alpine edge ({v}) has no OSV release to match against"
                ));
            }
            distro(
                Family::Apk,
                format!("Alpine {maj}.{min}"),
                "alpine",
                format!("Alpine:v{maj}.{min}"),
            )
        }
        "wolfi" => distro(Family::Apk, "Wolfi".into(), "wolfi", "Wolfi".into()),
        "chainguard" => distro(
            Family::Apk,
            "Chainguard".into(),
            "chainguard",
            "Chainguard".into(),
        ),
        "minimos" => distro(Family::Apk, "MinimOS".into(), "minimos", "MinimOS".into()),
        "cleanstart" => distro(
            Family::Apk,
            "CleanStart".into(),
            "cleanstart",
            "CleanStart".into(),
        ),
        "alpaquita" => {
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            distro(
                Family::Apk,
                format!("Alpaquita {v}"),
                "alpaquita",
                format!("Alpaquita:{v}"),
            )
        }
        "echo" => distro(Family::Deb, "Echo".into(), "echo", "Echo".into()),
        "rhel" => {
            let r = release("Red Hat Enterprise Linux")?;
            // RHEL 7 has one repository per variant; containers (UBI 7) use `server`.
            let repos: &[&str] = if r == "7" {
                &["server"]
            } else {
                &["baseos", "appstream", "crb"]
            };
            let mut d = rpm(
                format!("Red Hat Enterprise Linux {r}"),
                "redhat",
                format!("Red Hat:enterprise_linux:{r}::{}", repos[0]),
            );
            d.also = repos[1..]
                .iter()
                .map(|repo| format!("Red Hat:enterprise_linux:{r}::{repo}"))
                .collect();
            d.binary_names = true;
            d
        }
        "almalinux" => {
            let r = release("AlmaLinux")?;
            let mut d = rpm(
                format!("AlmaLinux {r}"),
                "almalinux",
                format!("AlmaLinux:{r}"),
            );
            d.binary_names = true;
            d
        }
        "rocky" => {
            let r = release("Rocky Linux")?;
            rpm(
                format!("Rocky Linux {r}"),
                "rocky-linux",
                format!("Rocky Linux:{r}"),
            )
        }
        "opensuse-leap" => {
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            rpm(
                format!("openSUSE Leap {v}"),
                "opensuse",
                format!("openSUSE:Leap {v}"),
            )
        }
        "opensuse-leap-micro" => {
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            rpm(
                format!("openSUSE Leap Micro {v}"),
                "opensuse",
                format!("openSUSE:Leap Micro {v}"),
            )
        }
        "opensuse-tumbleweed" => rpm(
            "openSUSE Tumbleweed".into(),
            "opensuse",
            "openSUSE:Tumbleweed".into(),
        ),
        "sles" => {
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            let (maj, sp) = v.split_once('.').unwrap_or((v, "0"));
            if maj != "15" || !sp.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!(
                    "{pretty}: only SUSE Linux Enterprise 15 releases are matched"
                ));
            }
            let product =
                |module: &str| format!("SUSE:Linux Enterprise Module for {module} 15 SP{sp}");
            let mut d = rpm(
                format!("SUSE Linux Enterprise 15 SP{sp}"),
                "suse",
                product("Basesystem"),
            );
            d.also = vec![product("Server Applications")];
            d
        }
        "sle-micro" => {
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            rpm(
                format!("SUSE Linux Enterprise Micro {v}"),
                "suse",
                format!("SUSE:Linux Enterprise Micro {v}"),
            )
        }
        "sl-micro" => {
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            rpm(
                format!("SUSE Linux Micro {v}"),
                "suse",
                format!("SUSE:Linux Micro {v}"),
            )
        }
        "azurelinux" | "mariner" => {
            let r = release("Azure Linux")?;
            if os.id == "mariner" && r != "2" {
                return Err(format!("{pretty}: only CBL-Mariner 2.0 is in osv.dev"));
            }
            rpm(
                format!("Azure Linux {r}"),
                "azure-linux",
                format!("Azure Linux:{r}"),
            )
        }
        "mageia" => {
            let r = release("Mageia")?;
            rpm(format!("Mageia {r}"), "mageia", format!("Mageia:{r}"))
        }
        "openeuler" => {
            // `VERSION_ID="22.03"` and `VERSION="22.03 (LTS-SP3)"` give `openEuler:22.03-LTS-SP3`.
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            let tag = os
                .version
                .as_deref()
                .and_then(|full| full.split_once('(')?.1.strip_suffix(')'))
                .map(|t| format!("-{}", t.trim()))
                .unwrap_or_default();
            rpm(
                format!("openEuler {v}{tag}"),
                "openeuler",
                format!("openEuler:{v}{tag}"),
            )
        }
        "centos" | "ol" | "fedora" | "amzn" | "photon" => {
            return Err(format!(
                "{pretty}: osv.dev has no advisories for this distribution, so its OS packages \
                 were not matched"
            ))
        }
        "" => return Err("no os-release ID".to_string()),
        other => {
            return Err(format!(
                "{pretty}: distribution {other:?} is not supported, so its OS packages were not \
                 matched"
            ))
        }
    };
    if hints.root_io {
        let root = match d.namespace.as_str() {
            "debian" => version.and_then(major).map(|r| format!("Root:Debian:{r}")),
            "ubuntu" => version.map(|v| format!("Root:Ubuntu:{v}")),
            "alpine" => d
                .ecosystem
                .strip_prefix("Alpine:v")
                .map(|v| format!("Root:Alpine:{v}")),
            _ => None,
        };
        d.overlays.extend(root);
    }
    Ok(d)
}

/// The package family of an osv.dev distro ecosystem (`Debian:12` is dpkg, `Wolfi` is apk),
/// or `None` for one fleetreach does not match.
pub fn family_of(ecosystem: &str) -> Option<Family> {
    let mut parts = ecosystem.split(':');
    let base = parts.next().unwrap_or_default();
    let base = if base == "Root" {
        parts.next().unwrap_or_default()
    } else {
        base
    };
    match base {
        "Debian" | "Ubuntu" | "Echo" => Some(Family::Deb),
        "Red Hat" | "AlmaLinux" | "Rocky Linux" | "SUSE" | "openSUSE" | "Azure Linux"
        | "Mageia" | "openEuler" => Some(Family::Rpm),
        "Alpine"
        | "Wolfi"
        | "Chainguard"
        | "MinimOS"
        | "Alpaquita"
        | "CleanStart"
        | "BellSoft Hardened Containers" => Some(Family::Apk),
        _ => None,
    }
}

/// Whether `ecosystem` is a distro ecosystem fleetreach matches.
pub fn known_ecosystem(ecosystem: &str) -> bool {
    family_of(ecosystem).is_some()
}

/// A distribution named explicitly in `fleet.toml` (`distro = "Debian:12"`), for images
/// whose os-release is missing or not recognized. The family comes from the package
/// database found in the image.
pub fn explicit(ecosystem: &str, family: Family) -> Distro {
    let base = ecosystem.split(':').next().unwrap_or(ecosystem);
    Distro {
        family,
        name: ecosystem.replace(':', " "),
        namespace: match base {
            "Red Hat" => "redhat".to_string(),
            other => other.to_ascii_lowercase().replace(' ', "-"),
        },
        ecosystem: ecosystem.to_string(),
        also: Vec::new(),
        binary_names: matches!(base, "Red Hat" | "AlmaLinux"),
        overlays: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn os(text: &str) -> OsRelease {
        parse_os_release(text)
    }

    #[test]
    fn families_of_explicit_ecosystems() {
        assert_eq!(family_of("Debian:12"), Some(Family::Deb));
        assert_eq!(family_of("Root:Alpine:3.20"), Some(Family::Apk));
        assert_eq!(
            family_of("BellSoft Hardened Containers:23"),
            Some(Family::Apk)
        );
        assert_eq!(family_of("Root:npm"), None);
        assert_eq!(family_of("PyPI"), None);
    }

    #[test]
    fn real_os_release_files() {
        let deb =
            os("PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nVERSION_ID=\"12\"\nID=debian\n");
        assert_eq!(
            detect(&deb, None, Hints::default()).unwrap().ecosystem,
            "Debian:12"
        );
        let distroless = os("PRETTY_NAME=\"Distroless\"\nID=\"debian\"\nVERSION_ID=\"12\"\n");
        assert_eq!(
            detect(&distroless, None, Hints::default())
                .unwrap()
                .ecosystem,
            "Debian:12"
        );
        let ubuntu = os("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n");
        assert_eq!(
            detect(&ubuntu, None, Hints::default()).unwrap().ecosystem,
            "Ubuntu:24.04:LTS"
        );
        let interim = os("ID=ubuntu\nVERSION_ID=\"24.10\"\n");
        assert_eq!(
            detect(&interim, None, Hints::default()).unwrap().ecosystem,
            "Ubuntu:24.10"
        );
        let alpine = os("NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.10\n");
        assert_eq!(
            detect(&alpine, None, Hints::default()).unwrap().ecosystem,
            "Alpine:v3.20"
        );
        let wolfi = os("ID=wolfi\nNAME=\"Wolfi\"\nVERSION_ID=\"20230201\"\n");
        let d = detect(&wolfi, None, Hints::default()).unwrap();
        assert_eq!((d.ecosystem.as_str(), d.family), ("Wolfi", Family::Apk));
        let alpaquita = os("ID=alpaquita\nID_LIKE=alpine\nVERSION_ID=stream\n");
        assert_eq!(
            detect(&alpaquita, None, Hints::default())
                .unwrap()
                .ecosystem,
            "Alpaquita:stream"
        );
    }

    #[test]
    fn rpm_os_release_files() {
        let eco = |text: &str| {
            let d = detect(&os(text), None, Hints::default()).unwrap();
            assert_eq!(d.family, Family::Rpm);
            (d.ecosystems(), d.binary_names)
        };
        assert_eq!(
            eco("ID=\"rhel\"\nVERSION_ID=\"9.4\"\n"),
            (
                vec![
                    "Red Hat:enterprise_linux:9::baseos".to_string(),
                    "Red Hat:enterprise_linux:9::appstream".to_string(),
                    "Red Hat:enterprise_linux:9::crb".to_string(),
                ],
                true
            )
        );
        assert_eq!(
            eco("ID=\"rhel\"\nVERSION_ID=\"7.9\"\n").0,
            vec!["Red Hat:enterprise_linux:7::server"]
        );
        assert_eq!(
            eco("ID=\"almalinux\"\nVERSION_ID=\"8.8\"\n"),
            (vec!["AlmaLinux:8".to_string()], true)
        );
        assert_eq!(
            eco("ID=\"rocky\"\nVERSION_ID=\"9.2\"\n"),
            (vec!["Rocky Linux:9".to_string()], false)
        );
        assert_eq!(
            eco("ID=\"opensuse-leap\"\nVERSION_ID=\"15.6\"\n").0,
            vec!["openSUSE:Leap 15.6"]
        );
        assert_eq!(
            eco("ID=\"sles\"\nVERSION_ID=\"15.6\"\n").0,
            vec![
                "SUSE:Linux Enterprise Module for Basesystem 15 SP6",
                "SUSE:Linux Enterprise Module for Server Applications 15 SP6"
            ]
        );
        assert_eq!(
            eco("ID=azurelinux\nVERSION_ID=\"3.0\"\n").0,
            vec!["Azure Linux:3"]
        );
        assert_eq!(
            eco("ID=mariner\nVERSION_ID=\"2.0\"\n").0,
            vec!["Azure Linux:2"]
        );
        assert_eq!(
            eco("ID=\"openEuler\"\nVERSION=\"22.03 (LTS-SP3)\"\nVERSION_ID=\"22.03\"\n").0,
            vec!["openEuler:22.03-LTS-SP3"]
        );
        // No osv.dev data, and not matched against Red Hat's: gaps that say why.
        for id in ["ol", "centos", "fedora", "amzn", "photon"] {
            let e = detect(
                &os(&format!("ID={id}\nVERSION_ID=9\n")),
                None,
                Hints::default(),
            );
            assert!(e.unwrap_err().contains("no advisories"), "{id}");
        }
        assert_eq!(
            family_of("Red Hat:enterprise_linux:9::baseos"),
            Some(Family::Rpm)
        );
        let d = explicit("Red Hat:enterprise_linux:9::baseos", Family::Rpm);
        assert_eq!((d.namespace.as_str(), d.binary_names), ("redhat", true));
        assert_eq!(
            export_candidates("Rocky Linux:9"),
            vec!["Rocky Linux:9", "Rocky Linux"]
        );
    }

    #[test]
    fn unknown_distro_and_release_are_gaps() {
        let mint = os("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=22\n");
        assert!(detect(&mint, None, Hints::default()).is_err());
        let sid = os("PRETTY_NAME=\"Debian GNU/Linux trixie/sid\"\nID=debian\n");
        assert!(detect(&sid, Some("trixie/sid\n"), Hints::default()).is_err());
        assert_eq!(
            detect(&sid, Some("13.1\n"), Hints::default())
                .unwrap()
                .ecosystem,
            "Debian:13"
        );
        let edge = os("ID=alpine\nVERSION_ID=3.21_alpha20240807\n");
        assert!(detect(&edge, None, Hints::default()).is_err());
        assert!(detect(&OsRelease::default(), None, Hints::default()).is_err());
    }

    #[test]
    fn overlays_from_installed_versions() {
        let ubuntu = os("ID=ubuntu\nVERSION_ID=\"18.04\"\n");
        let h = Hints::from_versions(["1.2-3ubuntu0.1+esm2"]);
        assert_eq!(
            detect(&ubuntu, None, h).unwrap().overlays,
            vec!["Ubuntu:Pro:18.04:LTS"]
        );
        let deb = os("ID=debian\nVERSION_ID=\"12\"\n");
        let h = Hints::from_versions(["3.0.11-1~deb12u2.root.io.1"]);
        assert_eq!(
            detect(&deb, None, h).unwrap().ecosystems(),
            vec!["Debian:12", "Root:Debian:12"]
        );
    }

    #[test]
    fn export_candidates_prefer_the_release() {
        assert_eq!(export_candidates("Debian:12"), vec!["Debian:12", "Debian"]);
        assert_eq!(export_candidates("Wolfi"), vec!["Wolfi"]);
        assert_eq!(
            export_candidates("Ubuntu:Pro:24.04:LTS"),
            vec!["Ubuntu:Pro:24.04:LTS", "Ubuntu"]
        );
    }
}
