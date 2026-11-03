//! The installed-package databases: dpkg's `/var/lib/dpkg/status` (and distroless's
//! `/var/lib/dpkg/status.d/*`, one file per package), apk's `/lib/apk/db/installed`,
//! rpm's database ([`crate::rpmdb`]), and Bottlerocket's application inventory (it ships rpms
//! but no rpm database).
//!
//! Advisories name **source** packages (Debian's `Source:`, apk's origin `o:`, rpm's
//! `SOURCERPM`), so every binary package is mapped to its source name and version: `libssl3`
//! is matched as `openssl`. The files each package owns are collected too, so a language lockfile that
//! an OS package installed is not reported a second time through its language feeder.

use std::collections::{BTreeMap, BTreeSet};

use crate::distro::Family;
use crate::image::ImageFs;
use crate::rpmdb::{self, Backend, RpmPackage};

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
    /// The module stream an rpm came from (`nodejs:18`, from its modularity label).
    pub module: Option<String>,
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
            module: None,
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
                module: None,
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

/// Where rpm keeps its database: `/usr/lib/sysimage/rpm` since rpm 4.16, `/var/lib/rpm`
/// before (and still on RHEL 9, which links one to the other).
const RPM_DIRS: &[&str] = &["usr/lib/sysimage/rpm", "var/lib/rpm"];
const RPM_FILES: &[&str] = &[
    "rpmdb.sqlite",
    "rpmdb.sqlite-wal",
    "Packages.db",
    "Packages",
];

/// The installed version as rpm prints it, `[epoch:]version-release`.
fn evr(epoch: Option<u32>, version: &str, release: &str) -> String {
    match epoch {
        Some(e) => format!("{e}:{version}-{release}"),
        None => format!("{version}-{release}"),
    }
}

/// An rpm package as an [`OsPackage`]: the source name and version come from its source rpm
/// file name (`openssl-3.0.7-27.el9.src.rpm`), with the binary's epoch. `None` for rpm's
/// `gpg-pubkey` pseudo-packages, which hold signing keys, not software.
pub fn from_rpm(p: &RpmPackage) -> Option<OsPackage> {
    if p.name == "gpg-pubkey" && p.arch.is_none() {
        return None;
    }
    let version = evr(p.epoch, &p.version, &p.release);
    let source = p.source_rpm.as_deref().and_then(|s| {
        let stem = s
            .strip_suffix(".src.rpm")
            .or_else(|| s.strip_suffix(".nosrc.rpm"))?;
        let (rest, release) = stem.rsplit_once('-')?;
        let (name, ver) = rest.rsplit_once('-')?;
        (!name.is_empty()).then(|| (name.to_string(), evr(p.epoch, ver, release)))
    });
    let (source, source_version) = source.unwrap_or_else(|| (p.name.clone(), version.clone()));
    Some(OsPackage {
        name: p.name.clone(),
        version,
        source,
        source_version,
        arch: p.arch.clone(),
        // `name:stream:version:context`: the stream is what advisories gate on.
        module: p.modularity_label.as_deref().and_then(|l| {
            let mut parts = l.split(':');
            match (parts.next(), parts.next()) {
                (Some(n), Some(s)) if !n.is_empty() && !s.is_empty() => Some(format!("{n}:{s}")),
                _ => None,
            }
        }),
    })
}

/// The packages of each rpm database in the image, by directory. A directory that is a
/// link to another is read once.
fn rpm_databases(fs: &ImageFs) -> Vec<(String, Result<Vec<RpmPackage>, String>)> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for dir in RPM_DIRS {
        let Some(backend) = [Backend::Sqlite, Backend::Ndb, Backend::BerkeleyDb]
            .into_iter()
            .find(|b| fs.is_file(&format!("{dir}/{}", b.file_name())))
        else {
            continue;
        };
        let path = format!("{dir}/{}", backend.file_name());
        if !seen.insert(fs.canonical(&path).unwrap_or_else(|| path.clone())) {
            continue;
        }
        let wal = fs.read(&format!("{dir}/rpmdb.sqlite-wal"));
        let read = match fs.read(&path) {
            Some(file) => rpmdb::read(backend, file, wal).map_err(|e| format!("{path}: {e}")),
            None => Err(format!("{path} could not be read")),
        };
        out.push((path, read));
    }
    out
}

/// Bottlerocket's record of its installed rpms (`{"Content": [{"Name", "Epoch", "Version",
/// "Release", ...}]}`), written at build time; the image has no rpm database.
pub const BOTTLEROCKET_INVENTORY: &str = "usr/share/bottlerocket/application-inventory.json";

/// A path under Bottlerocket's system root (`x86_64-bottlerocket-linux-gnu/sys-root/usr/...`)
/// as the path it is reached by (`usr/...`; `/usr` is a symlink there). Files are selected
/// while a layer is read, before symlinks can be followed, so the real path must be known.
fn bottlerocket_sysroot(path: &str) -> &str {
    match path.split_once("/sys-root/") {
        Some((triple, rest))
            if !triple.contains('/') && triple.ends_with("-bottlerocket-linux-gnu") =>
        {
            rest
        }
        _ => path,
    }
}

/// Where each format keeps its database, for opening only what is needed.
pub(crate) fn wanted(path: &str) -> bool {
    let path = bottlerocket_sysroot(path);
    path == BOTTLEROCKET_INVENTORY
        || matches!(
            path,
            "etc/os-release"
                | "usr/lib/os-release"
                | "etc/debian_version"
                | "var/lib/dpkg/status"
                | "lib/apk/db/installed"
                | "usr/lib/apk/db/installed"
        )
        || RPM_DIRS.iter().any(|d| {
            path.strip_prefix(d)
                .and_then(|f| f.strip_prefix('/'))
                .is_some_and(|f| RPM_FILES.contains(&f))
        })
        || path
            .strip_prefix("var/lib/dpkg/status.d/")
            .is_some_and(|f| !f.contains('/'))
        || path
            .strip_prefix("var/lib/dpkg/info/")
            .is_some_and(|f| !f.contains('/') && f.ends_with(".list"))
        || path
            .strip_prefix(MODULES_D)
            .is_some_and(|f| !f.contains('/') && f.ends_with(".module"))
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BottlerocketInventory {
    content: Vec<BottlerocketApp>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BottlerocketApp {
    name: String,
    #[serde(default)]
    epoch: String,
    version: String,
    release: String,
    #[serde(default)]
    architecture: Option<String>,
}

/// The packages in Bottlerocket's application inventory. Each is its own source: Bottlerocket's
/// advisories name the packages as the inventory does (`kernel-6.12`, `runc`). The epoch is
/// kept, as the advisories' versions need it (packages moved from the OS version, epoch 0, to
/// upstream versions, epoch 1).
///
/// # Errors
///
/// An inventory that is not the documented shape, or a package without a usable epoch: fail
/// closed, never a partial list.
pub fn parse_bottlerocket_inventory(text: &str) -> Result<Vec<OsPackage>, String> {
    let inv: BottlerocketInventory =
        serde_json::from_str(text).map_err(|e| format!("{BOTTLEROCKET_INVENTORY}: {e}"))?;
    inv.content
        .into_iter()
        .map(|a| {
            let epoch = match a.epoch.trim() {
                "" => None,
                e => Some(e.parse::<u32>().map_err(|_| {
                    format!("{BOTTLEROCKET_INVENTORY}: {} has epoch {e:?}", a.name)
                })?),
            };
            if a.name.is_empty() || a.version.is_empty() || a.release.is_empty() {
                return Err(format!(
                    "{BOTTLEROCKET_INVENTORY}: a package without name, version or release"
                ));
            }
            let version = evr(epoch, &a.version, &a.release);
            Ok(OsPackage {
                source: a.name.clone(),
                source_version: version.clone(),
                name: a.name,
                version,
                arch: a.architecture.filter(|s| !s.is_empty()),
                module: None,
            })
        })
        .collect()
}

/// Where dnf records the module streams enabled in the image.
const MODULES_D: &str = "etc/dnf/modules.d/";

/// The enabled streams in dnf's module state files (`[php]` `stream=7.4` `state=enabled`),
/// by module name.
pub fn parse_module_state(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let (mut name, mut stream, mut enabled) = (None, None, false);
    let mut flush = |name: &mut Option<String>, stream: &mut Option<String>, enabled: bool| {
        if let (Some(n), Some(s), true) = (name.take(), stream.take(), enabled) {
            out.insert(n, s);
        }
    };
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            flush(&mut name, &mut stream, enabled);
            enabled = false;
        } else if let Some((k, v)) = line.split_once('=') {
            let v = v.trim();
            match k.trim() {
                "name" => name = Some(v.to_string()),
                "stream" if !v.is_empty() => stream = Some(v.to_string()),
                "state" => enabled = v == "enabled",
                _ => {}
            }
        }
    }
    flush(&mut name, &mut stream, enabled);
    out
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
    /// The module streams dnf has enabled (`php` -> `7.4`), from `/etc/dnf/modules.d`.
    pub modules: BTreeMap<String, String>,
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
    let rpm_dbs = rpm_databases(fs);
    let bottlerocket = fs.is_file(BOTTLEROCKET_INVENTORY);
    let found: Vec<&str> = [
        (has_dpkg, "dpkg"),
        (apk_db.is_some(), "apk"),
        (!rpm_dbs.is_empty(), "rpm"),
        (bottlerocket, "Bottlerocket inventory"),
    ]
    .into_iter()
    .filter_map(|(has, name)| has.then_some(name))
    .collect();
    if found.len() > 1 {
        inv.problems.push(format!(
            "the image has more than one package database ({}); only the {} one was read",
            found.join(", "),
            found[0]
        ));
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
    } else if !rpm_dbs.is_empty() {
        inv.family = Some(Family::Rpm);
        let mut read: Vec<(String, Vec<RpmPackage>)> = Vec::new();
        for (path, result) in rpm_dbs {
            match result {
                Ok(pkgs) => read.push((path, pkgs)),
                Err(e) => inv.problems.push(e),
            }
        }
        // An image can ship a stray empty database beside the real one (Oracle Linux 9 has
        // an empty `/usr/lib/sysimage/rpm/rpmdb.sqlite`; rpm uses `/var/lib/rpm`): the one
        // with packages is the one rpm reads. Two that disagree is a gap, never a guess.
        read.retain(|(_, pkgs)| !pkgs.is_empty());
        read.sort_by_key(|(_, pkgs)| std::cmp::Reverse(pkgs.len()));
        if let [(_, a), (_, b), ..] = read.as_slice() {
            if a == b {
                read.truncate(1);
            }
        }
        if let [(first, _), (second, _), ..] = read.as_slice() {
            inv.problems.push(format!(
                "the image has two rpm databases with packages ({first} and {second}); only \
                 {first} was read"
            ));
        }
        if let Some((_, pkgs)) = read.into_iter().next() {
            for p in &pkgs {
                inv.owned.extend(
                    p.files
                        .iter()
                        .map(|f| f.trim_start_matches('/').to_string()),
                );
            }
            inv.packages = pkgs.iter().filter_map(from_rpm).collect();
        }
        for name in fs.list_dir(MODULES_D.trim_end_matches('/')) {
            if let Some(t) = name
                .ends_with(".module")
                .then(|| text(&format!("{MODULES_D}{name}")))
                .flatten()
            {
                inv.modules.extend(parse_module_state(&t));
            }
        }
    } else if bottlerocket {
        inv.family = Some(Family::Rpm);
        match text(BOTTLEROCKET_INVENTORY).map(|t| parse_bottlerocket_inventory(&t)) {
            Some(Ok(pkgs)) => inv.packages = pkgs,
            Some(Err(e)) => inv.problems.push(e),
            None => inv
                .problems
                .push(format!("{BOTTLEROCKET_INVENTORY} could not be read")),
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

    /// Bottlerocket's inventory, trimmed from 1.68.1: epochs as strings, and a source-package
    /// entry with no `PackageId`.
    #[test]
    fn bottlerocket_inventory() {
        let text = r#"{"Content":[
          {"Name":"runc","Publisher":"bottlerocket-core-kit","Version":"1.3.6",
           "Release":"1.1792624615.46ecbcc6.br1","Epoch":"1","InstalledTime":"2026-10-30T23:52:19Z",
           "ApplicationType":"Unspecified","Architecture":"x86_64","Url":"https://github.com/opencontainers/runc",
           "Summary":"CLI for running Open Containers",
           "PackageId":"bottlerocket-runc-1.3.6-1.1792624615.46ecbcc6.br1.x86_64.rpm@sha256:00"},
          {"Name":"kernel-6.12","Version":"6.12.113","Release":"1.1793397975.cb1065fd.br1",
           "Epoch":"0","Architecture":"x86_64","PackageId":""}]}"#;
        let pkgs = parse_bottlerocket_inventory(text).unwrap();
        assert_eq!(pkgs[0].name, "runc");
        assert_eq!(pkgs[0].version, "1:1.3.6-1.1792624615.46ecbcc6.br1");
        assert_eq!(pkgs[0].source, "runc");
        assert_eq!(pkgs[1].version, "0:6.12.113-1.1793397975.cb1065fd.br1");
        // Fail closed on a shape it does not know.
        assert!(parse_bottlerocket_inventory(r#"{"Content":[{"Name":"x"}]}"#).is_err());
        assert!(parse_bottlerocket_inventory(
            r#"{"Content":[{"Name":"x","Version":"1","Release":"1","Epoch":"one"}]}"#
        )
        .is_err());

        // Kept under its real path below the system root, read through the `/usr` symlink.
        assert!(wanted(
            "x86_64-bottlerocket-linux-gnu/sys-root/usr/share/bottlerocket/application-inventory.json"
        ));
        assert!(wanted(
            "aarch64-bottlerocket-linux-gnu/sys-root/usr/lib/os-release"
        ));
        assert!(!wanted(
            "x86_64-other-linux-gnu/sys-root/usr/lib/os-release"
        ));
        #[cfg(unix)]
        {
            let dir = std::env::temp_dir().join(format!("fr-bottlerocket-{}", std::process::id()));
            let sysroot = dir.join("x86_64-bottlerocket-linux-gnu/sys-root");
            std::fs::create_dir_all(sysroot.join("usr/share/bottlerocket")).unwrap();
            std::fs::create_dir_all(sysroot.join("usr/lib")).unwrap();
            std::fs::write(
                sysroot
                    .join("usr")
                    .join(BOTTLEROCKET_INVENTORY.trim_start_matches("usr/")),
                text,
            )
            .unwrap();
            std::fs::write(
                sysroot.join("usr/lib/os-release"),
                "ID=bottlerocket\nVERSION_ID=1.68.1\n",
            )
            .unwrap();
            std::os::unix::fs::symlink(
                "./x86_64-bottlerocket-linux-gnu/sys-root/usr",
                dir.join("usr"),
            )
            .unwrap();
            let fs = crate::open_image(&dir, &|_| false, None).unwrap();
            let _ = std::fs::remove_dir_all(&dir);
            assert!(fs.read("usr/lib/os-release").is_some());
            let inv = inventory(&fs);
            assert_eq!(inv.family, Some(Family::Rpm));
            assert!(inv.problems.is_empty(), "{:?}", inv.problems);
            assert_eq!(inv.packages.len(), 2);
        }
    }

    #[test]
    fn dnf_module_state() {
        let text = "[php]\nname=php\nstream=7.4\nprofiles=\nstate=enabled\n\
                    [nginx]\nname=nginx\nstream=\nprofiles=\nstate=\n\
                    [perl]\nname=perl\nstream=5.30\nstate=disabled\n";
        let m = parse_module_state(text);
        assert_eq!(
            m.into_iter().collect::<Vec<_>>(),
            [("php".into(), "7.4".into())]
        );
    }

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

    fn rpm(name: &str, epoch: Option<u32>, src: Option<&str>) -> RpmPackage {
        RpmPackage {
            name: name.into(),
            epoch,
            version: "3.0.7".into(),
            release: "27.el9".into(),
            arch: Some("aarch64".into()),
            source_rpm: src.map(str::to_string),
            ..RpmPackage::default()
        }
    }

    #[test]
    fn rpm_binaries_map_to_their_source_rpm() {
        let p = from_rpm(&rpm(
            "openssl-libs",
            Some(1),
            Some("openssl-3.0.7-27.el9.src.rpm"),
        ))
        .unwrap();
        assert_eq!(
            (
                p.version.as_str(),
                p.source.as_str(),
                p.source_version.as_str()
            ),
            ("1:3.0.7-27.el9", "openssl", "1:3.0.7-27.el9")
        );
        // SUSE source names carry dashes of their own.
        let p = from_rpm(&rpm(
            "libopenssl3",
            None,
            Some("openssl-3-3.1.4-150600.5.15.1.src.rpm"),
        ))
        .unwrap();
        assert_eq!(
            (p.source.as_str(), p.source_version.as_str()),
            ("openssl-3", "3.1.4-150600.5.15.1")
        );
        let p = from_rpm(&rpm("orphan", None, None)).unwrap();
        assert_eq!(p.source, "orphan");
        let mut key = rpm("gpg-pubkey", None, None);
        key.arch = None;
        assert!(from_rpm(&key).is_none(), "signing keys are not packages");
    }

    #[test]
    fn rpm_inventory_skips_a_stray_empty_database_and_owns_files() {
        let fixture = |p: &str| {
            std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/rpmdb")
                    .join(p),
            )
            .unwrap()
        };
        let (real, empty) = (fixture("db-bdb/Packages"), fixture("db-empty/rpmdb.sqlite"));
        // Oracle Linux 9's layout: the newer location holds an empty database.
        let fs = ImageFs::from_files([
            ("var/lib/rpm/Packages", real.as_slice()),
            ("usr/lib/sysimage/rpm/rpmdb.sqlite", empty.as_slice()),
        ]);
        let inv = inventory(&fs);
        assert_eq!(inv.family, Some(Family::Rpm));
        assert!(inv.problems.is_empty(), "{:?}", inv.problems);
        let names: Vec<_> = inv.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["basesystem", "libpng", "which"]);
        assert_eq!(inv.packages[1].version, "2:1.6.34-11.el8_10");
        assert!(inv.owned.contains("usr/bin/which"), "{:?}", inv.owned);

        // Two databases that disagree: the larger is read and the scan says so.
        let ndb = fixture("db-ndb/Packages.db");
        let fs = ImageFs::from_files([
            ("var/lib/rpm/Packages", real.as_slice()),
            ("usr/lib/sysimage/rpm/Packages.db", ndb.as_slice()),
        ]);
        let inv = inventory(&fs);
        assert_eq!(inv.packages.len(), 3);
        assert!(
            inv.problems[0].contains("two rpm databases"),
            "{:?}",
            inv.problems
        );

        // A database that cannot be read is a problem, never an empty image.
        let fs = ImageFs::from_files([("var/lib/rpm/Packages", &real[..4096])]);
        let inv = inventory(&fs);
        assert!(inv.packages.is_empty() && !inv.problems.is_empty());
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
