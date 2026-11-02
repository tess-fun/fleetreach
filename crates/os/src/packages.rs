//! The installed-package databases: dpkg's `/var/lib/dpkg/status` (and distroless's
//! `/var/lib/dpkg/status.d/*`, one file per package) and apk's `/lib/apk/db/installed`.
//!
//! Advisories name **source** packages (Debian's `Source:`, apk's origin `o:`), so every
//! binary package is mapped to its source name and version: `libssl3` is matched as
//! `openssl`. The files each package owns are collected too, so a language lockfile that
//! an OS package installed is not reported a second time through its language feeder.

use std::collections::BTreeSet;

use crate::distro::Family;
use crate::image::ImageFs;

/// One installed OS package.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OsPackage {
    /// The binary package name (`libssl3`).
    pub name: String,
    /// The binary package version.
    pub version: String,
    /// The source package advisories name (`openssl`); the binary name when none is given.
    pub source: String,
    /// The source version (differs from the binary one after a binNMU, `+b1`).
    pub source_version: String,
    pub arch: Option<String>,
}

/// dpkg states in which a package's files are on disk.
const DPKG_PRESENT: &[&str] = &[
    "installed",
    "half-installed",
    "unpacked",
    "half-configured",
    "triggers-awaiting",
    "triggers-pending",
];

/// The fields of one deb822 stanza, continuation lines joined.
fn stanzas(text: &str) -> Vec<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut cur: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, v)) = cur.last_mut() {
                v.push('\n');
                v.push_str(line.trim());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            cur.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Packages from a dpkg status file. `require_status` is false for distroless `status.d`
/// entries, which may omit the `Status` field.
pub fn parse_dpkg_status(text: &str, require_status: bool) -> Vec<OsPackage> {
    let mut out = Vec::new();
    for st in stanzas(text) {
        let get = |key: &str| {
            st.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, v)| v.as_str())
        };
        let (Some(name), Some(version)) = (get("Package"), get("Version")) else {
            continue;
        };
        match get("Status") {
            Some(status) => {
                let state = status.split_whitespace().nth(2).unwrap_or_default();
                if !DPKG_PRESENT.contains(&state) {
                    continue;
                }
            }
            None if require_status => continue,
            None => {}
        }
        let (source, source_version) = match get("Source") {
            Some(src) => match src.split_once('(') {
                Some((n, v)) => (
                    n.trim().to_string(),
                    v.trim_end_matches(')').trim().to_string(),
                ),
                None => (src.trim().to_string(), version.to_string()),
            },
            None => (name.to_string(), version.to_string()),
        };
        out.push(OsPackage {
            name: name.to_string(),
            version: version.to_string(),
            source,
            source_version,
            arch: get("Architecture").map(str::to_string),
        });
    }
    out
}

/// Packages and owned files from an apk installed database.
pub fn parse_apk_installed(text: &str) -> (Vec<OsPackage>, BTreeSet<String>) {
    let mut out = Vec::new();
    let mut owned = BTreeSet::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut origin: Option<String> = None;
    let mut arch: Option<String> = None;
    let mut dir = String::new();
    let mut flush = |name: &mut Option<String>,
                     version: &mut Option<String>,
                     origin: &mut Option<String>,
                     arch: &mut Option<String>| {
        if let (Some(n), Some(v)) = (name.take(), version.take()) {
            out.push(OsPackage {
                source: origin.take().unwrap_or_else(|| n.clone()),
                source_version: v.clone(),
                name: n,
                version: v,
                arch: arch.take(),
            });
        }
        *origin = None;
        *arch = None;
    };
    for line in text.lines() {
        if line.is_empty() {
            flush(&mut name, &mut version, &mut origin, &mut arch);
            dir.clear();
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key {
            "P" => name = Some(value.to_string()),
            "V" => version = Some(value.to_string()),
            "o" => origin = Some(value.to_string()),
            "A" => arch = Some(value.to_string()),
            "F" => dir = value.trim_matches('/').to_string(),
            "R" if dir.is_empty() => {
                owned.insert(value.to_string());
            }
            "R" => {
                owned.insert(format!("{dir}/{value}"));
            }
            _ => {}
        }
    }
    flush(&mut name, &mut version, &mut origin, &mut arch);
    (out, owned)
}

/// Where each format keeps its database, for opening only what is needed.
pub(crate) fn wanted(path: &str) -> bool {
    matches!(
        path,
        "etc/os-release"
            | "usr/lib/os-release"
            | "etc/debian_version"
            | "var/lib/dpkg/status"
            | "lib/apk/db/installed"
            | "usr/lib/apk/db/installed"
    ) || path
        .strip_prefix("var/lib/dpkg/status.d/")
        .is_some_and(|f| !f.contains('/'))
        || path
            .strip_prefix("var/lib/dpkg/info/")
            .is_some_and(|f| !f.contains('/') && f.ends_with(".list"))
}

/// What an image's package database says.
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    /// The package format found, `None` when the image has no package database.
    pub family: Option<Family>,
    /// Installed packages, sorted.
    pub packages: Vec<OsPackage>,
    /// Paths owned by an OS package, relative to `/`.
    pub owned: BTreeSet<String>,
    /// Problems that make the inventory incomplete (an unreadable database, two formats).
    pub problems: Vec<String>,
}

/// Read the image's package database.
pub fn inventory(fs: &ImageFs) -> Inventory {
    let mut inv = Inventory::default();
    let text = |path: &str| {
        fs.read(path)
            .map(|b| String::from_utf8_lossy(b).into_owned())
    };
    let dpkg_status = fs.is_file("var/lib/dpkg/status");
    let status_d = fs.list_dir("var/lib/dpkg/status.d");
    let apk_db = ["lib/apk/db/installed", "usr/lib/apk/db/installed"]
        .into_iter()
        .find(|p| fs.is_file(p));
    let has_dpkg = dpkg_status || !status_d.is_empty();
    if has_dpkg && apk_db.is_some() {
        inv.problems
            .push("the image has both a dpkg and an apk package database".to_string());
    }
    if has_dpkg {
        inv.family = Some(Family::Deb);
        if dpkg_status {
            match text("var/lib/dpkg/status") {
                Some(t) => inv.packages.extend(parse_dpkg_status(&t, true)),
                None => inv
                    .problems
                    .push("var/lib/dpkg/status could not be read".to_string()),
            }
        }
        for name in &status_d {
            let path = format!("var/lib/dpkg/status.d/{name}");
            if name.ends_with(".md5sums") {
                // distroless: one `<md5>  <path>` line per file the package owns.
                if let Some(t) = text(&path) {
                    inv.owned.extend(
                        t.lines()
                            .filter_map(|l| l.split_whitespace().nth(1))
                            .map(|p| p.trim_start_matches('/').to_string()),
                    );
                }
                continue;
            }
            match text(&path) {
                Some(t) => inv.packages.extend(parse_dpkg_status(&t, false)),
                None => inv.problems.push(format!("{path} could not be read")),
            }
        }
        for name in fs.list_dir("var/lib/dpkg/info") {
            if name.ends_with(".list") {
                if let Some(t) = text(&format!("var/lib/dpkg/info/{name}")) {
                    inv.owned.extend(
                        t.lines()
                            .map(|l| l.trim().trim_start_matches('/').to_string())
                            .filter(|l| !l.is_empty()),
                    );
                }
            }
        }
    } else if let Some(db) = apk_db {
        inv.family = Some(Family::Apk);
        match text(db) {
            Some(t) => {
                let (pkgs, owned) = parse_apk_installed(&t);
                inv.packages = pkgs;
                inv.owned = owned;
            }
            None => inv.problems.push(format!("{db} could not be read")),
        }
    }
    for s in fs.skipped() {
        if wanted(s.split(':').next().unwrap_or_default()) {
            inv.problems.push(s.clone());
        }
    }
    inv.packages.sort();
    inv.packages.dedup();
    inv
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    const STATUS: &str = "\
Package: libssl3
Status: install ok installed
Architecture: arm64
Source: openssl
Version: 3.0.15-1~deb12u1
Description: Secure Sockets Layer toolkit
 continuation line

Package: gcc-12-base
Status: install ok installed
Source: gcc-12 (12.2.0-14)
Version: 12.2.0-14+b1

Package: removed
Status: deinstall ok config-files
Version: 1.0-1

Package: tzdata
Status: install ok installed
Version: 2024a-0+deb12u1
";

    #[test]
    fn dpkg_status_maps_binaries_to_sources() {
        let pkgs = parse_dpkg_status(STATUS, true);
        assert_eq!(pkgs.len(), 3, "config-files only is not installed");
        assert_eq!(
            (pkgs[0].source.as_str(), pkgs[0].source_version.as_str()),
            ("openssl", "3.0.15-1~deb12u1")
        );
        assert_eq!(
            pkgs[1].source_version, "12.2.0-14",
            "binNMU keeps the source version"
        );
        assert_eq!(pkgs[2].source, "tzdata");
    }

    #[test]
    fn apk_installed_origin_and_files() {
        let db = "\
C:Q1abc=
P:libcrypto3
V:3.3.2-r0
A:aarch64
o:openssl
F:usr/lib
R:libcrypto.so.3

P:busybox
V:1.36.1-r29
F:bin
R:busybox
F:app
R:package-lock.json
";
        let (pkgs, owned) = parse_apk_installed(db);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(
            (pkgs[0].source.as_str(), pkgs[0].version.as_str()),
            ("openssl", "3.3.2-r0")
        );
        assert_eq!(
            pkgs[1].source, "busybox",
            "no origin: the package is its own source"
        );
        assert!(owned.contains("usr/lib/libcrypto.so.3"));
        assert!(owned.contains("app/package-lock.json"));
    }

    #[test]
    fn distroless_status_d_and_md5sums() {
        let fs = ImageFs::from_files([
            (
                "var/lib/dpkg/status.d/base-files",
                &b"Package: base-files\nVersion: 12.4+deb12u7\nArchitecture: arm64\n"[..],
            ),
            (
                "var/lib/dpkg/status.d/base-files.md5sums",
                &b"d41d8cd98f00b204e9800998ecf8427e  etc/debian_version\n"[..],
            ),
        ]);
        let inv = inventory(&fs);
        assert_eq!(inv.family, Some(Family::Deb));
        assert_eq!(inv.packages.len(), 1);
        assert!(inv.owned.contains("etc/debian_version"));
    }
}
