//! OS packages from the package URLs of an SBOM (`pkg:deb`, `pkg:apk`, `pkg:rpm`), as the
//! [`Inspection`] an image would give, so a Syft or Trivy image SBOM is matched like the image.
//!
//! The URL names the binary package, while most advisories name its source package. Syft puts
//! the source in the `upstream` qualifier and leaves it out when the names agree; Trivy puts it
//! outside the URL, in `aquasecurity:trivy:Src*` properties or SPDX's `sourceInfo`. The release
//! comes from the `distro` qualifier, spelled differently by each tool, else from the
//! operating-system component. A document that names no release is a gap, never a guess.

use std::collections::{BTreeMap, BTreeSet};

use crate::distro::{self, Family, Hints, OsRelease};
use crate::packages::{self, Inventory, OsPackage};
use crate::Inspection;

/// One OS package an SBOM lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub family: Family,
    pub namespace: Option<String>,
    /// The `distro` qualifier as written.
    pub distro: Option<String>,
    pub package: OsPackage,
    /// The document says what source the package was built from, or could have.
    pub sourced: bool,
}

/// The source package a document gives outside the URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceHint {
    pub name: String,
    /// `[epoch:]version[-release]`, when given.
    pub version: Option<String>,
}

/// What a document says of a package outside its URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hint {
    pub source: Option<SourceHint>,
    /// The rpm's modularity label, `name:stream:version:context`.
    pub module: Option<String>,
}

/// Percent-decode one part of a package URL.
pub fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            if let Some(b) = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `name` and version of a source rpm's file name (`openssl-3.0.7-27.el9.src.rpm`).
fn source_rpm(file: &str) -> Option<(&str, &str)> {
    let stem = file
        .strip_suffix(".src.rpm")
        .or_else(|| file.strip_suffix(".nosrc.rpm"))?;
    let (rest, _release) = stem.rsplit_once('-')?;
    let (name, _version) = rest.rsplit_once('-')?;
    (!name.is_empty()).then(|| (name, &stem[name.len() + 1..]))
}

/// An OS package URL as a [`Component`]; `None` for any other URL, or one with no version.
pub fn component(purl: &str, hint: &Hint) -> Option<Component> {
    let rest = purl.strip_prefix("pkg:")?;
    let rest = rest.split('#').next().unwrap_or(rest);
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (ty, path) = path.split_once('/')?;
    let family = match ty.to_ascii_lowercase().as_str() {
        "deb" => Family::Deb,
        "apk" => Family::Apk,
        "rpm" => Family::Rpm,
        _ => return None,
    };
    let (path, version) = path.rsplit_once('@')?;
    let (namespace, name) = match path.rsplit_once('/') {
        Some((namespace, name)) => (Some(decode(namespace).to_ascii_lowercase()), decode(name)),
        None => (None, decode(path)),
    };
    let qualifiers: BTreeMap<&str, String> = query
        .split('&')
        .filter_map(|q| q.split_once('='))
        .map(|(k, v)| (k, decode(v)))
        .collect();
    let mut version = decode(version);
    if name.is_empty() || version.is_empty() {
        return None;
    }
    // Trivy and Syft keep an rpm's epoch out of the version; Syft keeps a deb's in it.
    let epoch = qualifiers.get("epoch").filter(|e| e.as_str() != "0");
    if let Some(epoch) = epoch.filter(|_| !version.contains(':')) {
        version = format!("{epoch}:{version}");
    }
    let upstream = qualifiers.get("upstream").filter(|u| !u.is_empty());
    let with_epoch = |v: &str| match epoch {
        Some(epoch) if !v.contains(':') => format!("{epoch}:{v}"),
        _ => v.to_string(),
    };
    let (source, source_version) = match (upstream, &hint.source) {
        (Some(up), _) => match source_rpm(up) {
            Some((source, v)) => (source.to_string(), with_epoch(v)),
            None => match up.split_once('@') {
                Some((source, v)) => (source.to_string(), v.to_string()),
                None => (up.clone(), version.clone()),
            },
        },
        (None, Some(hint)) => (
            hint.name.clone(),
            hint.version.clone().unwrap_or_else(|| version.clone()),
        ),
        (None, None) => (name.clone(), version.clone()),
    };
    Some(Component {
        family,
        namespace,
        distro: qualifiers.get("distro").cloned(),
        sourced: upstream.is_some() || hint.source.is_some(),
        package: OsPackage {
            name,
            version,
            source,
            source_version,
            arch: qualifiers.get("arch").cloned(),
            module: hint.module.as_deref().and_then(packages::module_stream),
        },
    })
}

/// Trivy and Syft do not spell every release as os-release does.
fn os_release_id(id: &str) -> String {
    match id.to_ascii_lowercase().as_str() {
        "alma" => "almalinux".to_string(),
        "amazon" => "amzn".to_string(),
        "cbl-mariner" => "mariner".to_string(),
        "oracle" => "ol".to_string(),
        "redhat" => "rhel".to_string(),
        other => other.to_string(),
    }
}

/// The os-release id and version a `distro` qualifier says: `debian-12.15`, `opensuse-leap-15.6`
/// and `amazon-2 (Karoo)`, or Trivy's bare `3.20.10` with the id in the URL's namespace.
fn release(distro: &str, namespace: Option<&str>) -> Option<(String, String)> {
    let split = distro
        .match_indices('-')
        .map(|(i, _)| i)
        .find(|i| distro[i + 1..].starts_with(|c: char| c.is_ascii_digit()));
    let (id, version) = match split {
        Some(i) => (&distro[..i], &distro[i + 1..]),
        None => {
            let ns = namespace?;
            let bare = distro.strip_prefix(ns);
            (ns, bare.map_or(distro, |v| v.trim_start_matches('-')))
        }
    };
    let id = os_release_id(id);
    let version = version.split_whitespace().next()?;
    // Trivy reads Amazon's `2023.12.20261102` from system-release, not os-release's `2023`.
    let version = match version.split_once('.') {
        Some((major, _)) if id == "amzn" => major,
        _ => version,
    };
    Some((id, version.to_string()))
}

/// What an SBOM's OS packages amount to. `named` is its operating-system component, name and
/// version, for documents whose URLs carry no `distro`.
pub fn inspect(components: &[Component], named: Option<&(String, String)>) -> Inspection {
    let mut families = BTreeSet::new();
    let mut releases = BTreeSet::new();
    let mut unnamed = false;
    for c in components {
        families.insert(c.family.purl_type());
        match c
            .distro
            .as_deref()
            .and_then(|d| release(d, c.namespace.as_deref()))
        {
            Some(found) => {
                releases.insert(found);
            }
            None => unnamed = true,
        }
    }
    if unnamed {
        if let Some((name, version)) = named {
            releases.extend(release(&format!("{name}-{version}"), None));
        }
    }
    let mut pkgs: Vec<OsPackage> = components.iter().map(|c| c.package.clone()).collect();
    pkgs.sort_by(|a, b| (&a.name, &a.version, &a.arch).cmp(&(&b.name, &b.version, &b.arch)));
    pkgs.dedup();
    packages::share_source_epoch(&mut pkgs);
    let family = components.first().map(|c| c.family);
    let mut problems = Vec::new();
    if components.iter().all(|c| !c.sourced) {
        problems.push(
            "the SBOM names no source packages, so packages were matched by their binary names \
             and advisories filed under a source package may be missed"
                .to_string(),
        );
    }
    let unlabelled = pkgs
        .iter()
        .filter(|p| p.module.is_none() && p.version.contains(".module"))
        .count();
    if unlabelled > 0 {
        problems.push(format!(
            "the SBOM does not say which module stream {unlabelled} module builds came from, so \
             advisories of other streams may be reported and a stream's open ones missed"
        ));
    }
    let hints = Hints::from_versions(pkgs.iter().map(|p| p.version.as_str()));
    let (os_release, distro) = match (releases.len(), releases.iter().next()) {
        _ if families.len() > 1 => (
            None,
            Err(format!(
                "the SBOM lists packages of several formats ({})",
                families.into_iter().collect::<Vec<_>>().join(", ")
            )),
        ),
        (1, Some((id, version))) => {
            let os = OsRelease {
                id: id.clone(),
                version_id: Some(version.clone()),
                ..OsRelease::default()
            };
            let debian = (id == "debian").then_some(version.as_str());
            let found = distro::detect(&os, debian, hints);
            (Some(os), found)
        }
        (0, _) => (
            None,
            Err("the SBOM does not say which distribution its packages are from".to_string()),
        ),
        _ => (
            None,
            Err(format!(
                "the SBOM lists packages of several distributions ({})",
                releases
                    .iter()
                    .map(|(id, version)| format!("{id} {version}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        ),
    };
    let distro = distro.and_then(|d| match family {
        Some(f) if f != d.family => Err(format!(
            "{} uses {} packages but the SBOM lists {} ones",
            d.name,
            d.family.purl_type(),
            f.purl_type()
        )),
        _ => Ok(d),
    });
    Inspection {
        os_release,
        distro,
        inventory: Inventory {
            family,
            packages: pkgs,
            problems,
            ..Inventory::default()
        },
        no_os: false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn one(purl: &str) -> Component {
        component(purl, &Hint::default()).unwrap()
    }

    #[test]
    fn syft_names_the_source_in_the_upstream_qualifier() {
        let deb = one("pkg:deb/debian/bsdutils@1%3A2.38.1-5%2Bdeb12u3?arch=amd64&distro=debian-12.15&upstream=util-linux%402.38.1-5%2Bdeb12u3");
        assert_eq!(deb.package.version, "1:2.38.1-5+deb12u3");
        assert_eq!(deb.package.source, "util-linux");
        assert_eq!(deb.package.source_version, "2.38.1-5+deb12u3");

        let rpm = one("pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?arch=x86_64&distro=rocky-9.3&epoch=1&upstream=openssl-3.0.7-24.el9.src.rpm");
        assert_eq!(rpm.package.version, "1:3.0.7-24.el9");
        assert_eq!(rpm.package.source, "openssl");
        assert_eq!(rpm.package.source_version, "1:3.0.7-24.el9");

        let apk = one(
            "pkg:apk/alpine/libssl3@3.3.7-r0?arch=x86_64&distro=alpine-3.20.10&upstream=openssl",
        );
        assert_eq!(
            (
                apk.package.source.as_str(),
                apk.package.source_version.as_str()
            ),
            ("openssl", "3.3.7-r0")
        );
    }

    #[test]
    fn a_hint_stands_in_for_the_qualifier_and_no_source_is_the_binary() {
        let hint = Hint {
            source: Some(SourceHint {
                name: "glibc".into(),
                version: Some("2.36-9".into()),
            }),
            ..Hint::default()
        };
        let c = component(
            "pkg:deb/debian/libc6@2.36-9%2Bb1?distro=debian-12.15",
            &hint,
        )
        .unwrap();
        assert_eq!(
            (c.package.source.as_str(), c.package.source_version.as_str()),
            ("glibc", "2.36-9")
        );
        assert!(c.sourced);
        let bare = one("pkg:deb/debian/bash@5.2?distro=debian-12");
        assert_eq!(bare.package.source, "bash");
        assert!(!bare.sourced);
    }

    #[test]
    fn other_urls_and_incomplete_ones_are_not_components() {
        for purl in [
            "pkg:npm/a@1.0.0",
            "pkg:deb/debian/bash",
            "pkg:deb/debian/bash@",
            "deb/debian/bash@1",
        ] {
            assert!(component(purl, &Hint::default()).is_none(), "{purl}");
        }
    }

    #[test]
    fn each_tools_spelling_of_a_release_reads_alike() {
        let cases = [
            ("debian-12.15", Some("debian"), ("debian", "12.15")),
            ("3.20.10", Some("alpine"), ("alpine", "3.20.10")),
            ("20230201", Some("wolfi"), ("wolfi", "20230201")),
            (
                "opensuse-leap-15.6",
                Some("opensuse"),
                ("opensuse-leap", "15.6"),
            ),
            ("amazon-2 (Karoo)", Some("amazon"), ("amzn", "2")),
            (
                "amazon-2023.12.20261102 (Amazon Linux)",
                Some("amazon"),
                ("amzn", "2023"),
            ),
            ("alma-9.8", Some("alma"), ("almalinux", "9.8")),
            ("redhat-9.8", Some("redhat"), ("rhel", "9.8")),
            ("rhel-9.8", Some("redhat"), ("rhel", "9.8")),
            ("oracle-9.8", Some("oracle"), ("ol", "9.8")),
            ("cbl-mariner-2.0", Some("cbl-mariner"), ("mariner", "2.0")),
            ("sles-15.6", Some("suse"), ("sles", "15.6")),
        ];
        for (distro, namespace, (id, version)) in cases {
            assert_eq!(
                release(distro, namespace),
                Some((id.to_string(), version.to_string())),
                "{distro}"
            );
        }
    }

    #[test]
    fn what_cannot_be_placed_is_an_error_not_a_guess() {
        let no_release = [one("pkg:deb/debian/bash@5.2?upstream=bash")];
        assert!(inspect(&no_release, None).distro.is_err());
        let named = ("debian".to_string(), "12.15".to_string());
        assert!(inspect(&no_release, Some(&named)).distro.is_ok());

        let two = [
            one("pkg:deb/debian/bash@5.2?distro=debian-12&upstream=bash"),
            one("pkg:deb/ubuntu/bash@5.1?distro=ubuntu-22.04&upstream=bash"),
        ];
        assert!(inspect(&two, None)
            .distro
            .unwrap_err()
            .contains("several distributions"));

        let formats = [
            one("pkg:deb/debian/bash@5.2?distro=debian-12&upstream=bash"),
            one("pkg:rpm/debian/bash@5.2-1?distro=debian-12&upstream=bash"),
        ];
        assert!(inspect(&formats, None)
            .distro
            .unwrap_err()
            .contains("several formats"));

        let wrong = [one("pkg:rpm/debian/bash@5.2-1?distro=debian-12")];
        assert!(inspect(&wrong, None).distro.is_err());
    }

    #[test]
    fn module_builds_take_their_label_and_say_when_they_have_none() {
        let purl = "pkg:rpm/redhat/nodejs@20.20.2-1.module+el9.7.0?distro=rhel-9.8&upstream=nodejs-20.20.2-1.module%2Bel9.7.0.src.rpm";
        let hint = Hint {
            module: Some("nodejs:20:9070020251:abcd".into()),
            ..Hint::default()
        };
        let labelled = component(purl, &hint).unwrap();
        assert_eq!(labelled.package.module.as_deref(), Some("nodejs:20"));
        assert!(inspect(&[labelled], None).inventory.problems.is_empty());
        let problems = inspect(&[one(purl)], None).inventory.problems;
        assert!(problems[0].contains("1 module builds"), "{problems:?}");
    }

    #[test]
    fn a_document_without_sources_says_so() {
        let inspection = inspect(&[one("pkg:deb/debian/libc6@2.36?distro=debian-12")], None);
        assert_eq!(inspection.inventory.problems.len(), 1);
        let inspection = inspect(
            &[one(
                "pkg:deb/debian/libc6@2.36?distro=debian-12&upstream=glibc",
            )],
            None,
        );
        assert!(inspection.inventory.problems.is_empty());
    }
}
