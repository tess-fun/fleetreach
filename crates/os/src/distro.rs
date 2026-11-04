//! Which distribution and release an image runs, from `/etc/os-release`, mapped onto the
//! osv.dev ecosystem that holds its advisories (`Debian:12`, `Alpine:v3.20`, `Wolfi`, ...).
//!
//! Fail-closed: an ID this table does not know, or a release it cannot name (Debian
//! testing, Alpine edge), is a coverage gap with the reason, never "no vulnerabilities".
//! A derivative that says `ID_LIKE=debian` is not matched against Debian, because its
//! backports and version strings are its own; for the same reason CentOS and Fedora are not
//! matched against Red Hat's records, and are gaps. Oracle Linux, Amazon Linux and Photon OS
//! are matched against their vendors' own feeds ([`crate::feeds`]).

use std::collections::BTreeMap;

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
    /// Ecosystems that speak only about CVEs the release and its overlays never mention:
    /// Canonical stops publishing a release's records when standard support ends and never
    /// publishes universe's outside Ubuntu Pro, and Red Hat's after maintenance are its
    /// Extended Life Support's, so there they are the only word.
    pub supplements: Vec<String>,
    /// The module streams enabled in the image (`php` -> `7.4`), for gating advisories
    /// about module builds whose packages carry no modularity label.
    pub modules: BTreeMap<String, String>,
    /// Ecosystems consulted for a package and CVE only when the release's own ecosystems
    /// say nothing about that CVE for it, matched by binary or source name: the vendors'
    /// CSAF VEX ([`red_hat_vex`], [`suse_vex`]).
    pub fallbacks: Vec<String>,
    /// Ecosystems among `also`, `supplements` and `fallbacks` that may be absent or empty
    /// without a gap: a SUSE module the image may not use, an LTSS stream a release has not
    /// reached, or the [`frozen`] copy of a release, whose absence [`crate::eol::withdrawn`]
    /// reports.
    pub optional: Vec<String>,
    /// Fallbacks that speak about the codestream the release is built from rather than the
    /// release itself (SLE 15 SP6 for openSUSE Leap 15.6). Only their fixes count: an older
    /// build is vulnerable, but the fix is not in the release's repositories, so the match is
    /// reported as fixed only in another line.
    pub borrowed: Vec<String>,
    /// Fallbacks from the distribution a release rebuilds (Red Hat Enterprise Linux 9 for
    /// AlmaLinux 9 and Rocky Linux 9). Only their open statuses and "not affected" count:
    /// the rebuild ships the same sources, so a CVE Red Hat has not fixed is not fixed there
    /// either, but Red Hat's fix versions are not the rebuild's builds.
    pub borrowed_opens: Vec<String>,
    /// For a rebuild matched against the records of the distribution it rebuilds (CentOS
    /// Linux against Red Hat's), the release whose bundled final builds decide which of
    /// those fixes it shipped; a fix it never shipped is fixed only in another line.
    pub final_builds: Option<String>,
}

impl Distro {
    /// Every ecosystem to load: the release, its other repositories, its overlays, then its
    /// fallbacks.
    pub fn ecosystems(&self) -> Vec<String> {
        let mut out = vec![self.ecosystem.clone()];
        out.extend(self.also.iter().cloned());
        out.extend(self.overlays.iter().cloned());
        out.extend(self.supplements.iter().cloned());
        out.extend(self.fallbacks.iter().cloned());
        out
    }
}

/// The ecosystem holding what Red Hat's CSAF VEX says about RHEL `release` beyond osv.dev's
/// Red Hat export: unfixed statuses (affected with no fix yet, will not fix, fix deferred,
/// out of support, under investigation), which that export does not carry, and fixes it has
/// not imported yet. It is derived from the VEX, not published by osv.dev.
pub fn red_hat_vex(release: &str) -> String {
    format!("Red Hat:enterprise_linux:{release}::vex")
}

/// Whether `ecosystem` is one of the [`red_hat_vex`] ecosystems.
pub fn is_red_hat_vex(ecosystem: &str) -> bool {
    ecosystem.starts_with("Red Hat:enterprise_linux:") && ecosystem.ends_with("::vex")
}

/// The ecosystem holding what SUSE's CSAF VEX says about the product osv.dev calls
/// `ecosystem` (`openSUSE:Leap 15.6::vex`): unfixed statuses and fixes, per binary package.
pub fn suse_vex(ecosystem: &str) -> String {
    format!("{ecosystem}::vex")
}

/// Whether `ecosystem` is one of the [`suse_vex`] ecosystems.
pub fn is_suse_vex(ecosystem: &str) -> bool {
    (ecosystem.starts_with("SUSE:") || ecosystem.starts_with("openSUSE:"))
        && ecosystem.ends_with("::vex")
}

/// Whether `ecosystem` is derived from a vendor's CSAF VEX ([`red_hat_vex`], [`suse_vex`]).
pub fn is_vex(ecosystem: &str) -> bool {
    is_red_hat_vex(ecosystem) || is_suse_vex(ecosystem)
}

/// The osv.dev ecosystem of a product in SUSE's CSAF (`openSUSE Leap 15.6` is
/// `openSUSE:Leap 15.6`), for the products images are matched against: openSUSE Leap, Leap
/// Micro and Tumbleweed, SLE Micro, SUSE Linux Micro, and SLES 15 as the whole product
/// (`SUSE Linux Enterprise Server 15 SP6`, and `...-LTSS`), as SUSE's OVAL checks it; `None`
/// for the rest (modules, SUSE Manager, cloud images, SLES 12, NonFree, ...).
pub fn suse_product_ecosystem(product: &str) -> Option<String> {
    let version = |v: &str| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    let known = match product.split_once(' ')? {
        ("openSUSE", "Tumbleweed") => true,
        ("openSUSE", rest) => rest
            .strip_prefix("Leap Micro ")
            .or_else(|| rest.strip_prefix("Leap "))
            .is_some_and(version),
        ("SUSE", rest) => {
            if let Some(sp) = rest.strip_prefix("Linux Enterprise Server 15 SP") {
                version(sp.strip_suffix("-LTSS").unwrap_or(sp))
            } else {
                rest.strip_prefix("Linux Enterprise Micro ")
                    .or_else(|| rest.strip_prefix("Linux Micro "))
                    .is_some_and(version)
            }
        }
        _ => false,
    };
    known.then(|| product.replacen(' ', ":", 1))
}

/// The osv.dev ecosystems of SUSE Linux Enterprise 15 SP`sp` beyond its Basesystem module:
/// the other modules an image can take packages from, and the LTSS stream that carries the
/// release's fixes once its general support ends. All are optional.
fn sles_optional(sp: &str) -> Vec<String> {
    const MODULES: &[&str] = &[
        "Certifications",
        "Containers",
        "Desktop Applications",
        "Development Tools",
        "HPC",
        "Legacy",
        "Package Hub",
        "Public Cloud",
        "Python 3",
        "SAP Applications",
        "Systems Management",
        "Transactional Server",
        "Web and Scripting",
    ];
    MODULES
        .iter()
        .map(|m| format!("SUSE:Linux Enterprise Module for {m} 15 SP{sp}"))
        .chain([format!("SUSE:Linux Enterprise Server 15 SP{sp}-LTSS")])
        .collect()
}

/// What `/etc/centos-release` or `/etc/redhat-release` says, for a release older than
/// os-release: `CentOS release 6.10 (Final)`, `Red Hat Enterprise Linux Server release 6.10`.
pub fn legacy_release(text: &str) -> Option<OsRelease> {
    let line = text.lines().next()?.trim();
    let id = if line.starts_with("CentOS") {
        "centos"
    } else if line.starts_with("Red Hat Enterprise Linux") {
        "rhel"
    } else {
        return None;
    };
    let (_, after) = line.split_once(" release ")?;
    let version = after.split_whitespace().next()?;
    Some(parse_os_release(&format!(
        "ID={id}\nVERSION_ID={version}\nPRETTY_NAME=\"{line}\"\n"
    )))
}

/// Debian releases gone from the security tracker that osv.dev's frozen exports still cover.
const FROZEN_DEBIAN: [&str; 5] = ["7", "8", "9", "10", "11"];

/// What marks a release's frozen export as an ecosystem of its own.
const FROZEN: &str = "::frozen";

/// The ecosystem holding what osv.dev's frozen export of `ecosystem` says, for a Debian
/// release that has left the security tracker. Debian's maintained export keeps little of
/// such a release (about 2,900 entries for Debian 11 against 60,000 for 12), while the frozen
/// one stopped in October 2024 with what the tracker said then, CVEs left open included. It
/// is a supplement, so anything the maintained export says about a CVE comes first.
pub fn frozen(ecosystem: &str) -> Option<String> {
    let release = ecosystem.strip_prefix("Debian:")?;
    FROZEN_DEBIAN
        .contains(&release)
        .then(|| format!("{ecosystem}{FROZEN}"))
}

/// The export behind a [`frozen`] ecosystem (`Debian:11` for `Debian:11::frozen`), whose
/// records name the plain release.
pub fn frozen_export(ecosystem: &str) -> Option<&str> {
    ecosystem.strip_suffix(FROZEN)
}

/// The osv.dev export directories that can serve `ecosystem`, in order: the whole
/// distribution (`Debian/all.zip`), which is what osv.dev maintains, then the release's own,
/// for a copy laid out by hand. osv.dev's per-release exports (`Debian:12/all.zip`,
/// `Ubuntu:22.04:LTS/all.zip`, `Alpine:v3.20/all.zip`) still download but stopped changing in
/// October 2024, and are not in its `ecosystems.txt`: reading one misses every later CVE.
pub fn export_candidates(ecosystem: &str) -> Vec<String> {
    if let Some(export) = frozen_export(ecosystem) {
        return vec![export.to_string()];
    }
    let base = ecosystem.split(':').next().unwrap_or(ecosystem).to_string();
    // A vendor feed, or a vendor's VEX, is an export of its own release only.
    if base == ecosystem || crate::feeds::feed_for(ecosystem).is_some() || is_vex(ecosystem) {
        vec![ecosystem.to_string()]
    } else {
        vec![base, ecosystem.to_string()]
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

/// Red Hat's fixes after a release's maintenance ended, sold as Extended Life Support: a build
/// without them stays affected, and the release's own records say nothing about it.
fn red_hat_els(release: &str) -> Option<String> {
    matches!(release, "6" | "7").then(|| format!("Red Hat:rhel_els:{release}"))
}

/// A rebuild of Red Hat Enterprise Linux `release` takes Red Hat's open statuses for it
/// (see [`Distro::borrowed_opens`]).
fn rebuild_of_rhel(mut d: Distro, release: &str) -> Distro {
    let vex = red_hat_vex(release);
    d.fallbacks.push(vex.clone());
    d.borrowed_opens.push(vex);
    d
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
        supplements: Vec::new(),
        modules: BTreeMap::new(),
        fallbacks: Vec::new(),
        optional: Vec::new(),
        borrowed: Vec::new(),
        borrowed_opens: Vec::new(),
        final_builds: None,
    };
    // A SUSE product takes SUSE's VEX for each of its products.
    let suse = |mut d: Distro| {
        d.fallbacks = std::iter::once(&d.ecosystem)
            .chain(&d.also)
            .map(|e| suse_vex(e))
            .collect();
        d
    };
    // Fallbacks from the codestream a community release is built from, after its own.
    let borrow = |mut d: Distro, from: &[String]| {
        d.fallbacks.extend(from.iter().cloned());
        d.optional.extend(from.iter().cloned());
        d.borrowed.extend(from.iter().cloned());
        d
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
            let mut d = distro(
                Family::Deb,
                format!("Debian {release}"),
                "debian",
                format!("Debian:{release}"),
            );
            if let Some(frozen) = frozen(&d.ecosystem) {
                d.supplements.push(frozen.clone());
                d.optional.push(frozen);
            }
            d
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
            if lts {
                let pro = format!("Ubuntu:Pro:{yy}.{mm}:LTS");
                if hints.esm {
                    d.overlays.push(pro);
                } else {
                    d.supplements.push(pro);
                }
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
            // Since RHEL 10 Red Hat's records go by minor release, with no repository. An image
            // takes later minors' fixes too: they reach it as updates.
            let ecosystems: Vec<String> = if r.parse::<u32>().is_ok_and(|major| major >= 10) {
                (0..10)
                    .map(|minor| format!("Red Hat:enterprise_linux:{r}.{minor}"))
                    .collect()
            } else {
                repos
                    .iter()
                    .map(|repo| format!("Red Hat:enterprise_linux:{r}::{repo}"))
                    .collect()
            };
            let mut d = rpm(
                format!("Red Hat Enterprise Linux {r}"),
                "redhat",
                ecosystems[0].clone(),
            );
            d.also = ecosystems[1..].to_vec();
            if ecosystems[0].ends_with(".0") {
                d.optional = d.also.clone();
            }
            d.fallbacks = vec![red_hat_vex(r)];
            d.binary_names = true;
            d.supplements.extend(red_hat_els(r));
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
            rebuild_of_rhel(d, r)
        }
        "rocky" => {
            let r = release("Rocky Linux")?;
            rebuild_of_rhel(
                rpm(
                    format!("Rocky Linux {r}"),
                    "rocky-linux",
                    format!("Rocky Linux:{r}"),
                ),
                r,
            )
        }
        "opensuse-leap" => {
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            let d = suse(rpm(
                format!("openSUSE Leap {v}"),
                "opensuse",
                format!("openSUSE:Leap {v}"),
            ));
            // Leap 15.6 is built from SLE 15 SP6, whose statuses SUSE's own Leap OVAL takes.
            match v.strip_prefix("15.").filter(|sp| *sp != "0") {
                Some(sp) => {
                    let server = format!("SUSE:Linux Enterprise Server 15 SP{sp}");
                    borrow(d, &[suse_vex(&server), suse_vex(&format!("{server}-LTSS"))])
                }
                None => d,
            }
        }
        "opensuse-leap-micro" => {
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            let d = suse(rpm(
                format!("openSUSE Leap Micro {v}"),
                "opensuse",
                format!("openSUSE:Leap Micro {v}"),
            ));
            borrow(d, &[suse_vex(&format!("SUSE:Linux Enterprise Micro {v}"))])
        }
        "opensuse-tumbleweed" => suse(rpm(
            "openSUSE Tumbleweed".into(),
            "opensuse",
            "openSUSE:Tumbleweed".into(),
        )),
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
            d.optional = sles_optional(sp);
            d.also = std::iter::once(product("Server Applications"))
                .chain(d.optional.iter().cloned())
                .collect();
            // SUSE's VEX speaks about the whole product, as its OVAL does.
            let server = format!("SUSE:Linux Enterprise Server 15 SP{sp}");
            let ltss = suse_vex(&format!("{server}-LTSS"));
            d.fallbacks = vec![suse_vex(&server), ltss.clone()];
            d.optional.push(ltss);
            d
        }
        "sle-micro" => {
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            suse(rpm(
                format!("SUSE Linux Enterprise Micro {v}"),
                "suse",
                format!("SUSE:Linux Enterprise Micro {v}"),
            ))
        }
        "sl-micro" => {
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            suse(rpm(
                format!("SUSE Linux Micro {v}"),
                "suse",
                format!("SUSE:Linux Micro {v}"),
            ))
        }
        "azurelinux" | "mariner" => {
            let r = release("Azure Linux")?;
            if os.id == "mariner" && r != "2" {
                return Err(format!("{pretty}: only CBL-Mariner 2.0 is in osv.dev"));
            }
            let mut d = rpm(
                format!("Azure Linux {r}"),
                "azure-linux",
                format!("Azure Linux:{r}"),
            );
            // Microsoft's last CBL-Mariner 2.0 advisories are only in its OVAL.
            if r == "2" {
                d.overlays.push(crate::feeds::MARINER_2_OVAL.to_string());
            }
            d
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
        // Vendor feeds osv.dev does not carry (see `crate::feeds`); all name binaries.
        "amzn" => {
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            if !matches!(v, "2" | "2023") {
                return Err(format!(
                    "{pretty}: only Amazon Linux 2 and 2023 have advisory feeds, so its OS \
                     packages were not matched"
                ));
            }
            let mut d = rpm(
                format!("Amazon Linux {v}"),
                "amazon",
                format!("Amazon Linux:{v}"),
            );
            d.binary_names = true;
            d
        }
        // One advisory feed for every variant and version; packages from the application
        // inventory, each its own source.
        "bottlerocket" => {
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            let mut d = rpm(
                format!("Bottlerocket {v}"),
                "bottlerocket",
                crate::feeds::BOTTLEROCKET.to_string(),
            );
            d.binary_names = true;
            d
        }
        "ol" => {
            let r = release("Oracle Linux")?;
            let mut d = rpm(
                format!("Oracle Linux {r}"),
                "oracle",
                format!("Oracle Linux:{r}"),
            );
            d.binary_names = true;
            d
        }
        "photon" => {
            let v = version.ok_or_else(|| format!("{pretty}: no VERSION_ID"))?;
            let eco = format!("Photon OS:{v}");
            if crate::feeds::feed_for(&eco).is_none() {
                return Err(format!(
                    "{pretty}: Photon OS {v} has no advisory feed, so its OS packages were not \
                     matched"
                ));
            }
            let mut d = rpm(format!("Photon OS {v}"), "photon", eco);
            d.binary_names = true;
            d
        }
        "fedora" => {
            let r = release("Fedora")?;
            if crate::feeds::feed_for(&format!("Fedora:{r}")).is_none() {
                return Err(format!(
                    "{pretty}: Fedora releases before {} have no advisory feed fleetreach \
                     reads, so its OS packages were not matched",
                    crate::feeds::FEDORA_FIRST
                ));
            }
            let mut d = rpm(format!("Fedora {r}"), "fedora", format!("Fedora:{r}"));
            d.binary_names = true;
            d
        }
        // CentOS Linux rebuilt RHEL and published no advisories: Red Hat's records for the
        // release it rebuilds, with only the fixes CentOS shipped (see `final_builds`).
        // CentOS Stream is built ahead of RHEL, so neither its versions nor its fixes are
        // Red Hat's.
        "centos" => {
            let r = release("CentOS")?;
            let stream = os
                .pretty_name
                .as_deref()
                .is_some_and(|n| n.contains("Stream"));
            if stream || !matches!(r, "6" | "7" | "8") {
                return Err(format!(
                    "{pretty}: CentOS Stream has no advisories fleetreach reads, and Red Hat's \
                     are not about its builds, so its OS packages were not matched"
                ));
            }
            // CentOS 6 and 7 rebuilt the Server variant; 8 BaseOS, AppStream and PowerTools.
            let repos: &[&str] = if r == "8" {
                &["baseos", "appstream", "crb"]
            } else {
                &["server"]
            };
            let mut d = rpm(
                format!("CentOS Linux {r}"),
                "centos",
                format!("Red Hat:enterprise_linux:{r}::{}", repos[0]),
            );
            d.also = repos[1..]
                .iter()
                .map(|repo| format!("Red Hat:enterprise_linux:{r}::{repo}"))
                .collect();
            d.binary_names = true;
            d.final_builds = Some(r.to_string());
            d.supplements.extend(red_hat_els(r));
            rebuild_of_rhel(d, r)
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
        | "Mageia" | "openEuler" | "Amazon Linux" | "Oracle Linux" | "Photon OS"
        | "Bottlerocket" | "Fedora" => Some(Family::Rpm),
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
    let d = Distro {
        family,
        name: ecosystem.replace(':', " "),
        namespace: match base {
            "Red Hat" => "redhat".to_string(),
            "Amazon Linux" => "amazon".to_string(),
            "Oracle Linux" => "oracle".to_string(),
            "Photon OS" => "photon".to_string(),
            other => other.to_ascii_lowercase().replace(' ', "-"),
        },
        ecosystem: ecosystem.to_string(),
        also: Vec::new(),
        binary_names: matches!(
            base,
            "Red Hat"
                | "AlmaLinux"
                | "Amazon Linux"
                | "Oracle Linux"
                | "Photon OS"
                | "Bottlerocket"
                | "Fedora"
        ),
        overlays: Vec::new(),
        supplements: Vec::new(),
        modules: BTreeMap::new(),
        // `Red Hat:enterprise_linux:9::baseos` takes RHEL 9's VEX too, and a SUSE product its own.
        fallbacks: match ecosystem.split(':').collect::<Vec<_>>().as_slice() {
            ["Red Hat", "enterprise_linux", release, ..]
                if !release.is_empty() && release.bytes().all(|b| b.is_ascii_digit()) =>
            {
                vec![red_hat_vex(release)]
            }
            _ if suse_product_ecosystem(&ecosystem.replacen(':', " ", 1)).as_deref()
                == Some(ecosystem) =>
            {
                vec![suse_vex(ecosystem)]
            }
            _ => Vec::new(),
        },
        optional: Vec::new(),
        borrowed: Vec::new(),
        borrowed_opens: Vec::new(),
        final_builds: None,
    };
    // `AlmaLinux:9` and `Rocky Linux:9` take RHEL 9's open statuses, as when detected.
    match ecosystem.split_once(':') {
        Some(("AlmaLinux" | "Rocky Linux", release))
            if !release.is_empty() && release.bytes().all(|b| b.is_ascii_digit()) =>
        {
            rebuild_of_rhel(d, release)
        }
        _ => d,
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
        // One feed for every Bottlerocket variant and version.
        assert_eq!(
            eco("ID=bottlerocket\nVERSION_ID=1.68.1\nVARIANT_ID=aws-k8s-1.33\n"),
            (vec!["Bottlerocket".to_string()], true)
        );
        assert!(known_ecosystem("Bottlerocket"));
        assert_eq!(
            eco("ID=\"rhel\"\nVERSION_ID=\"9.4\"\n"),
            (
                vec![
                    "Red Hat:enterprise_linux:9::baseos".to_string(),
                    "Red Hat:enterprise_linux:9::appstream".to_string(),
                    "Red Hat:enterprise_linux:9::crb".to_string(),
                    "Red Hat:enterprise_linux:9::vex".to_string(),
                ],
                true
            )
        );
        assert_eq!(
            eco("ID=\"rhel\"\nVERSION_ID=\"7.9\"\n").0,
            vec![
                "Red Hat:enterprise_linux:7::server",
                "Red Hat:rhel_els:7",
                "Red Hat:enterprise_linux:7::vex"
            ]
        );
        let rhel10 = eco("ID=\"rhel\"\nVERSION_ID=\"10.1\"\n").0;
        assert_eq!(rhel10[0], "Red Hat:enterprise_linux:10.0");
        assert_eq!(rhel10[2], "Red Hat:enterprise_linux:10.2");
        assert!(is_red_hat_vex("Red Hat:enterprise_linux:7::vex"));
        assert!(is_suse_vex("openSUSE:Leap 15.6::vex") && !is_suse_vex("openSUSE:Leap 15.6"));
        assert_eq!(
            suse_product_ecosystem("SUSE Linux Enterprise Server 15 SP6-LTSS").as_deref(),
            Some("SUSE:Linux Enterprise Server 15 SP6-LTSS")
        );
        assert_eq!(
            suse_product_ecosystem("SUSE Linux Enterprise Module for Basesystem 15 SP6"),
            None
        );
        assert_eq!(suse_product_ecosystem("openSUSE Leap 15.6 NonFree"), None);
        assert_eq!(
            suse_product_ecosystem("SUSE Linux Enterprise Micro for Rancher 5.4"),
            None
        );
        assert_eq!(
            suse_product_ecosystem("openSUSE Tumbleweed").as_deref(),
            Some("openSUSE:Tumbleweed")
        );
        assert_eq!(
            suse_product_ecosystem("SUSE Linux Enterprise Server 12 SP5"),
            None
        );
        assert_eq!(suse_product_ecosystem("SUSE Manager Server 4.3"), None);
        assert_eq!(
            explicit("SUSE:Linux Micro 6.1", Family::Rpm).fallbacks,
            vec!["SUSE:Linux Micro 6.1::vex"]
        );
        assert_eq!(
            export_candidates("openSUSE:Leap 15.6::vex"),
            vec!["openSUSE:Leap 15.6::vex"]
        );
        assert_eq!(
            export_candidates("Red Hat:enterprise_linux:7::vex"),
            vec!["Red Hat:enterprise_linux:7::vex"]
        );
        assert_eq!(
            explicit("Red Hat:enterprise_linux:8::appstream", Family::Rpm).fallbacks,
            vec!["Red Hat:enterprise_linux:8::vex"]
        );
        // Rebuilds take Red Hat's open statuses for the release they rebuild.
        assert_eq!(
            eco("ID=\"almalinux\"\nVERSION_ID=\"8.8\"\n"),
            (
                vec![
                    "AlmaLinux:8".to_string(),
                    "Red Hat:enterprise_linux:8::vex".to_string()
                ],
                true
            )
        );
        assert_eq!(
            eco("ID=\"rocky\"\nVERSION_ID=\"9.2\"\n"),
            (
                vec![
                    "Rocky Linux:9".to_string(),
                    "Red Hat:enterprise_linux:9::vex".to_string()
                ],
                false
            )
        );
        let rocky = explicit("Rocky Linux:9", Family::Rpm);
        assert_eq!(
            rocky.borrowed_opens,
            vec!["Red Hat:enterprise_linux:9::vex"]
        );
        assert!(rocky.borrowed.is_empty());
        assert_eq!(
            eco("ID=\"opensuse-leap\"\nVERSION_ID=\"15.6\"\n").0,
            vec![
                "openSUSE:Leap 15.6",
                "openSUSE:Leap 15.6::vex",
                // Borrowed: SUSE's fixes for the SLE codestream Leap is built from.
                "SUSE:Linux Enterprise Server 15 SP6::vex",
                "SUSE:Linux Enterprise Server 15 SP6-LTSS::vex",
            ]
        );
        assert_eq!(
            eco("ID=\"sles\"\nVERSION_ID=\"15.6\"\n").0[..3],
            [
                "SUSE:Linux Enterprise Module for Basesystem 15 SP6",
                "SUSE:Linux Enterprise Module for Server Applications 15 SP6",
                "SUSE:Linux Enterprise Module for Certifications 15 SP6",
            ]
        );
        let sles = detect(
            &parse_os_release("ID=\"sles\"\nVERSION_ID=\"15.6\"\n"),
            None,
            Hints::default(),
        )
        .unwrap();
        assert_eq!(
            sles.fallbacks,
            [
                "SUSE:Linux Enterprise Server 15 SP6::vex",
                "SUSE:Linux Enterprise Server 15 SP6-LTSS::vex"
            ]
        );
        assert!(sles
            .also
            .contains(&"SUSE:Linux Enterprise Server 15 SP6-LTSS".to_string()));
        assert!(sles
            .optional
            .contains(&"SUSE:Linux Enterprise Server 15 SP6-LTSS::vex".to_string()));
        assert!(!sles
            .optional
            .contains(&"SUSE:Linux Enterprise Server 15 SP6::vex".to_string()));
        assert_eq!(
            eco("ID=azurelinux\nVERSION_ID=\"3.0\"\n").0,
            vec!["Azure Linux:3"]
        );
        assert_eq!(
            eco("ID=mariner\nVERSION_ID=\"2.0\"\n").0,
            vec!["Azure Linux:2", "Azure Linux:2::oval"]
        );
        assert_eq!(
            eco("ID=\"openEuler\"\nVERSION=\"22.03 (LTS-SP3)\"\nVERSION_ID=\"22.03\"\n").0,
            vec!["openEuler:22.03-LTS-SP3"]
        );
        // Vendor feeds, matched by binary name.
        for (text, want, ns) in [
            (
                "ID=amzn\nVERSION_ID=\"2023\"\n",
                "Amazon Linux:2023",
                "amazon",
            ),
            (
                "ID=\"amzn\"\nVERSION_ID=\"2\"\n",
                "Amazon Linux:2",
                "amazon",
            ),
            (
                "ID=\"ol\"\nVERSION_ID=\"9.4\"\n",
                "Oracle Linux:9",
                "oracle",
            ),
            ("ID=photon\nVERSION_ID=5.0\n", "Photon OS:5.0", "photon"),
        ] {
            let d = detect(&os(text), None, Hints::default()).unwrap();
            assert_eq!(
                (d.ecosystem.as_str(), d.namespace.as_str(), d.binary_names),
                (want, ns, true)
            );
            assert_eq!(export_candidates(want), vec![want]);
        }
        for text in [
            "ID=amzn\nVERSION_ID=2018.03\n",
            "ID=photon\nVERSION_ID=2.0\n",
            "ID=fedora\nVERSION_ID=40\n",
        ] {
            let e = detect(&os(text), None, Hints::default()).unwrap_err();
            assert!(e.contains("feed"), "{e}");
        }
        let fedora = detect(&os("ID=fedora\nVERSION_ID=43\n"), None, Hints::default()).unwrap();
        assert_eq!(
            (fedora.ecosystem.as_str(), fedora.binary_names),
            ("Fedora:43", true)
        );
        assert_eq!(family_of("Fedora:43"), Some(Family::Rpm));
        // CentOS Linux: Red Hat's records for the release it rebuilt, its statuses, and
        // only the fixes CentOS shipped.
        let centos = |text: &str| detect(&os(text), None, Hints::default());
        let c7 = centos("ID=centos\nVERSION_ID=7\n").unwrap();
        assert_eq!(
            (
                c7.ecosystem.as_str(),
                c7.namespace.as_str(),
                c7.binary_names
            ),
            ("Red Hat:enterprise_linux:7::server", "centos", true)
        );
        assert!(c7.also.is_empty());
        assert_eq!(c7.final_builds.as_deref(), Some("7"));
        assert_eq!(c7.borrowed_opens, [red_hat_vex("7")]);
        let c8 = centos("ID=centos\nVERSION_ID=8\nPRETTY_NAME=\"CentOS Linux 8\"\n").unwrap();
        assert_eq!(
            c8.also,
            [
                "Red Hat:enterprise_linux:8::appstream",
                "Red Hat:enterprise_linux:8::crb"
            ]
        );
        // CentOS Stream is not a RHEL rebuild: a gap that says why.
        for text in [
            "ID=centos\nVERSION_ID=8\nPRETTY_NAME=\"CentOS Stream 8\"\n",
            "ID=centos\nVERSION_ID=9\n",
        ] {
            assert!(
                centos(text).unwrap_err().contains("CentOS Stream"),
                "{text}"
            );
        }
        assert_eq!(
            family_of("Red Hat:enterprise_linux:9::baseos"),
            Some(Family::Rpm)
        );
        let d = explicit("Red Hat:enterprise_linux:9::baseos", Family::Rpm);
        assert_eq!((d.namespace.as_str(), d.binary_names), ("redhat", true));
        assert_eq!(
            export_candidates("Rocky Linux:9"),
            vec!["Rocky Linux", "Rocky Linux:9"]
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
    fn releases_older_than_os_release_are_read() {
        let centos = legacy_release("CentOS release 6.10 (Final)\n").unwrap();
        let d = detect(&centos, None, Hints::default()).unwrap();
        assert_eq!(d.ecosystem, "Red Hat:enterprise_linux:6::server");
        assert_eq!(
            legacy_release("Red Hat Enterprise Linux Server release 6.10 (Santiago)\n")
                .unwrap()
                .version_id
                .as_deref(),
            Some("6.10")
        );
        assert!(legacy_release("Fedora release 20 (Heisenbug)\n").is_none());
    }

    #[test]
    fn overlays_from_installed_versions() {
        let ubuntu = os("ID=ubuntu\nVERSION_ID=\"18.04\"\n");
        let h = Hints::from_versions(["1.2-3ubuntu0.1+esm2"]);
        assert_eq!(
            detect(&ubuntu, None, h).unwrap().overlays,
            vec!["Ubuntu:Pro:18.04:LTS"]
        );
        // Without Pro its records still say what the release's own no longer do.
        let plain = detect(&ubuntu, None, Hints::default()).unwrap();
        assert!(plain.overlays.is_empty());
        assert_eq!(plain.supplements, vec!["Ubuntu:Pro:18.04:LTS"]);
        let deb = os("ID=debian\nVERSION_ID=\"12\"\n");
        let h = Hints::from_versions(["3.0.11-1~deb12u2.root.io.1"]);
        assert_eq!(
            detect(&deb, None, h).unwrap().ecosystems(),
            vec!["Debian:12", "Root:Debian:12"]
        );
    }

    #[test]
    fn export_candidates_prefer_the_maintained_export() {
        assert_eq!(export_candidates("Debian:12"), vec!["Debian", "Debian:12"]);
        assert_eq!(export_candidates("Wolfi"), vec!["Wolfi"]);
        assert_eq!(
            export_candidates("Ubuntu:Pro:24.04:LTS"),
            vec!["Ubuntu", "Ubuntu:Pro:24.04:LTS"]
        );
        assert_eq!(export_candidates("Debian:11::frozen"), vec!["Debian:11"]);
    }

    #[test]
    fn retired_debian_is_supplemented_by_its_frozen_export() {
        let os = |v: &str| parse_os_release(&format!("ID=debian\nVERSION_ID={v}\n"));
        let old = detect(&os("11"), None, Hints::default()).unwrap();
        assert_eq!(old.supplements, ["Debian:11::frozen"]);
        assert_eq!(old.optional, ["Debian:11::frozen"]);
        assert_eq!(family_of("Debian:11::frozen"), Some(Family::Deb));
        let live = detect(&os("12"), None, Hints::default()).unwrap();
        assert!(live.supplements.is_empty());
    }
}
