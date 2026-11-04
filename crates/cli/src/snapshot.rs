//! Dated snapshots and offline bundles of the advisory data (spec 16, row 11).
//!
//! One directory holds every source a scan reads: the OSV exports and vendor feeds, the CVE
//! and CSAF indexes, and with `db sync --source` or `db import` the RustSec clone
//! (`advisory-db/`), the KEV catalog and EPSS scores (`enrich/kev.json`, `enrich/epss.csv`) and
//! copies of the NVD and Vulnrichment caches (`enrich/nvd/`, `enrich/vulnrichment/`).
//!
//! `db snapshot` hashes that directory into a manifest, `scan --db-snapshot` refuses to run on
//! anything else, and `db bundle` packs it into one tar that `db import --bundle` unpacks,
//! checked against the manifest before any of it replaces what is there.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::curated::sha256_file;
use crate::osvdb::{self, Meta};

/// The RustSec clone, relative to the data directory.
pub const RUSTSEC_DIR: &str = "advisory-db";
/// The KEV catalog, the file `--kev-file` reads.
pub const KEV_FILE: &str = "enrich/kev.json";
/// The EPSS scores, the file `--epss-file` reads.
pub const EPSS_FILE: &str = "enrich/epss.csv";
/// The copy of the NVD score cache.
pub const NVD_DIR: &str = "enrich/nvd";
/// The copy of the Vulnrichment cache.
pub const VULNRICHMENT_DIR: &str = "enrich/vulnrichment";

/// The manifest's name inside a bundle and an imported directory.
const MANIFEST: &str = "manifest.json";
const SCHEMA: u32 = 1;

/// What a snapshot recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: u32,
    /// RFC3339.
    pub created: String,
    pub tool_version: String,
    pub sources: Vec<Source>,
}

/// One top-level entry of the data directory: an export, `csaf`, `advisory-db`, `enrich`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub name: String,
    /// The git commit, for the RustSec clone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    pub files: Vec<File>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct File {
    /// Relative to the data directory, with `/` separators.
    pub path: String,
    pub sha256: String,
    pub size: u64,
    /// Where it came from and the upstream date, when a sync recorded them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

/// How a file under the data directory counts.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Kind {
    /// Advisory data: hashed and pinned.
    Data,
    /// Carried in a bundle but free to change: a sync rewrites a `.meta.json` with no new data.
    Companion,
    /// Rebuilt when needed, or not part of the data.
    Skip,
}

fn classify(path: &str) -> Kind {
    let name = path.rsplit('/').next().unwrap_or(path);
    let top = path.split('/').next().unwrap_or(path);
    if name.ends_with(".partial")
        || name == "all.zip.index.json"
        || top == MANIFEST
        || top.starts_with(".import-")
        || (top.starts_with("snapshot-") && top.ends_with(".json"))
    {
        Kind::Skip
    } else if name.ends_with(".meta.json")
        || path.starts_with("advisory-db/.git/")
        || (top == "csaf" && name == "derived")
    {
        Kind::Companion
    } else {
        Kind::Data
    }
}

/// Every file under `root`, relative and sorted, with how it counts. A symlink is refused: it
/// could point outside what the manifest vouches for.
fn walk(root: &Path) -> Result<Vec<(String, Kind)>, String> {
    fn visit(dir: &Path, prefix: &str, out: &mut Vec<(String, Kind)>) -> Result<(), String> {
        let entries =
            std::fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("reading {}: {e}", dir.display()))?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| format!("{}: a file name that is not UTF-8", dir.display()))?;
            let path = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}/{name}")
            };
            let kind = entry
                .file_type()
                .map_err(|e| format!("reading {path}: {e}"))?;
            if kind.is_symlink() {
                return Err(format!("{path} is a symlink"));
            }
            if kind.is_dir() {
                if !path.starts_with(".import-") {
                    visit(&entry.path(), &path, out)?;
                }
            } else if kind.is_file() {
                let class = classify(&path);
                out.push((path, class));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    visit(root, "", &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Hash every source under `root`.
///
/// # Errors
///
/// An unreadable file, a symlink, or a directory with no data in it.
pub fn build(root: &Path) -> Result<Manifest, String> {
    let paths: Vec<String> = walk(root)?
        .into_iter()
        .filter(|(_, kind)| *kind == Kind::Data)
        .map(|(path, _)| path)
        .collect();
    let files: Vec<File> = paths
        .par_iter()
        .map(|path| {
            let full = root.join(path);
            let (sha256, size) =
                sha256_file(&full).map_err(|e| format!("reading {}: {e}", full.display()))?;
            let meta = osvdb::read_meta(&full);
            Ok(File {
                path: path.clone(),
                sha256,
                size,
                upstream: meta.as_ref().map(|m| m.url.clone()),
                last_modified: meta.and_then(|m| m.last_modified),
            })
        })
        .collect::<Result<_, String>>()?;
    if files.is_empty() {
        return Err(format!("no advisory data in {}", root.display()));
    }
    let mut sources: BTreeMap<String, Vec<File>> = BTreeMap::new();
    for file in files {
        let top = file.path.split('/').next().unwrap_or_default().to_string();
        sources.entry(top).or_default().push(file);
    }
    let commit = rustsec_commit(root);
    Ok(Manifest {
        schema: SCHEMA,
        created: crate::history::format_time(crate::history::now()),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        sources: sources
            .into_iter()
            .map(|(name, files)| Source {
                commit: commit.clone().filter(|_| name == RUSTSEC_DIR),
                name,
                files,
            })
            .collect(),
    })
}

fn rustsec_commit(root: &Path) -> Option<String> {
    let dir = root.join(RUSTSEC_DIR);
    if !dir.is_dir() {
        return None;
    }
    fleetreach_scan::AdvisoryDb::open(&dir).ok()?.meta().commit
}

/// What differs between the manifest and `actual`, one line each; empty when they agree.
fn differences(manifest: &Manifest, actual: &Manifest) -> Vec<String> {
    let index = |m: &Manifest| -> BTreeMap<String, (String, u64)> {
        m.sources
            .iter()
            .flat_map(|s| &s.files)
            .map(|f| (f.path.clone(), (f.sha256.clone(), f.size)))
            .collect()
    };
    let (want, have) = (index(manifest), index(actual));
    let mut out = Vec::new();
    for (path, entry) in &want {
        match have.get(path) {
            None => out.push(format!("{path}: missing")),
            Some(other) if other != entry => out.push(format!("{path}: changed")),
            Some(_) => {}
        }
    }
    out.extend(
        have.keys()
            .filter(|path| !want.contains_key(*path))
            .map(|path| format!("{path}: not in the snapshot")),
    );
    out
}

fn summarize(root: &Path, differences: &[String]) -> String {
    let shown = differences.iter().take(5).cloned().collect::<Vec<_>>();
    let more = differences.len().saturating_sub(shown.len());
    let tail = if more > 0 {
        format!(", and {more} more")
    } else {
        String::new()
    };
    format!(
        "{} does not match the snapshot: {}{tail}",
        root.display(),
        shown.join(", ")
    )
}

/// The canonical manifest text, and its hash, which a report records.
fn render(manifest: &Manifest) -> Result<String, String> {
    serde_json::to_string_pretty(manifest)
        .map(|json| json + "\n")
        .map_err(|e| e.to_string())
}

/// Write the manifest to `out`.
///
/// # Errors
///
/// A failed write.
pub fn write(manifest: &Manifest, out: &Path) -> Result<(), String> {
    std::fs::write(out, render(manifest)?).map_err(|e| format!("writing {}: {e}", out.display()))
}

/// The default name of a snapshot of `manifest`, dated by its creation.
#[must_use]
pub fn default_name(manifest: &Manifest) -> String {
    let date = manifest.created.get(..10).unwrap_or("undated");
    format!("snapshot-{date}.json")
}

/// A run pinned to a snapshot.
pub struct Pinned {
    /// The directory the snapshot describes.
    pub root: PathBuf,
    pub has_rustsec: bool,
    /// sha256 of the manifest file.
    pub sha256: String,
}

/// Check the data against the manifest at `path`, in `root` or else the manifest's directory.
///
/// # Errors
///
/// An unreadable manifest, or data that is not exactly what it lists.
pub fn pin(path: &Path, root: Option<&Path>) -> Result<Pinned, String> {
    let text = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let manifest: Manifest =
        serde_json::from_slice(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if manifest.schema != SCHEMA {
        return Err(format!(
            "{}: snapshot schema {} is not one this version reads",
            path.display(),
            manifest.schema
        ));
    }
    let root = match root {
        Some(root) => root.to_path_buf(),
        None => match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        },
    };
    let found = differences(&manifest, &build(&root)?);
    if !found.is_empty() {
        return Err(summarize(&root, &found));
    }
    let (sha256, _) = sha256_file(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    Ok(Pinned {
        has_rustsec: manifest.sources.iter().any(|s| s.name == RUSTSEC_DIR),
        root,
        sha256,
    })
}

/// Pack `root` into the tar `out`, its manifest first. Returns the manifest and the tar's
/// sha256. The exports are already compressed, so the tar is not.
///
/// # Errors
///
/// An unreadable file or a failed write; a partial tar is removed.
pub fn bundle(root: &Path, out: &Path) -> Result<(Manifest, String), String> {
    let manifest = build(root)?;
    let tmp = out.with_extension("partial");
    let result = (|| {
        let file =
            std::fs::File::create(&tmp).map_err(|e| format!("creating {}: {e}", tmp.display()))?;
        let mut tar = tar::Builder::new(std::io::BufWriter::new(file));
        tar.follow_symlinks(false);
        let text = render(&manifest)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(text.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        tar.append_data(&mut header, MANIFEST, text.as_bytes())
            .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
        for (path, kind) in walk(root)? {
            if kind != Kind::Skip {
                tar.append_path_with_name(root.join(&path), &path)
                    .map_err(|e| format!("adding {path}: {e}"))?;
            }
        }
        let mut writer = tar
            .into_inner()
            .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
        writer
            .flush()
            .map_err(|e| format!("writing {}: {e}", tmp.display()))
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, out).map_err(|e| format!("installing {}: {e}", out.display()))?;
    let (sha256, _) = sha256_file(out).map_err(|e| format!("reading {}: {e}", out.display()))?;
    Ok((manifest, sha256))
}

/// What `import` installed.
pub struct Imported {
    pub manifest: Manifest,
    /// Sources already in the directory that the bundle does not carry; a pin there fails.
    pub left_over: Vec<String>,
}

/// Unpack a bundle into `root`. It lands in a staging directory first and every file is
/// checked against the bundle's manifest, so a damaged bundle replaces nothing.
///
/// # Errors
///
/// A wrong `sha256`, an unsafe or unexpected entry, or data that disagrees with the manifest.
pub fn import(bundle: &Path, root: &Path, sha256: Option<&str>) -> Result<Imported, String> {
    if let Some(expected) = sha256 {
        let (actual, _) =
            sha256_file(bundle).map_err(|e| format!("reading {}: {e}", bundle.display()))?;
        if !actual.eq_ignore_ascii_case(expected.trim()) {
            return Err(format!(
                "{}: sha256 is {actual}, not {expected}",
                bundle.display()
            ));
        }
    }
    osvdb::create_private_dir(root).map_err(|e| format!("creating {}: {e}", root.display()))?;
    let staging = root.join(format!(".import-{}", std::process::id()));
    osvdb::create_private_dir(&staging)
        .map_err(|e| format!("creating {}: {e}", staging.display()))?;
    let result = unpack(bundle, &staging).and_then(|manifest| {
        let found = differences(&manifest, &build(&staging)?);
        if found.is_empty() {
            install(&staging, root, manifest)
        } else {
            Err(summarize(bundle, &found))
        }
    });
    let _ = std::fs::remove_dir_all(&staging);
    result
}

fn unpack(bundle: &Path, staging: &Path) -> Result<Manifest, String> {
    let file =
        std::fs::File::open(bundle).map_err(|e| format!("reading {}: {e}", bundle.display()))?;
    let mut archive = tar::Archive::new(file);
    archive.set_preserve_mtime(true);
    let name = bundle.display();
    let mut manifest = None;
    for entry in archive
        .entries()
        .map_err(|e| format!("reading {name}: {e}"))?
    {
        let mut entry = entry.map_err(|e| format!("reading {name}: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("reading {name}: {e}"))?
            .into_owned();
        let shown = path.display().to_string();
        if !path.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(format!("{name}: unsafe path `{shown}`"));
        }
        if !entry.header().entry_type().is_file() {
            return Err(format!("{name}: `{shown}` is not a regular file"));
        }
        if manifest.is_none() {
            if path != Path::new(MANIFEST) {
                return Err(format!("{name}: does not start with a manifest"));
            }
            let mut text = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut text)
                .map_err(|e| format!("reading {name}: {e}"))?;
            std::fs::write(staging.join(MANIFEST), &text)
                .map_err(|e| format!("writing {MANIFEST}: {e}"))?;
            let parsed: Manifest =
                serde_json::from_slice(&text).map_err(|e| format!("{name}: {e}"))?;
            if parsed.schema != SCHEMA {
                return Err(format!(
                    "{name}: snapshot schema {} is not one this version reads",
                    parsed.schema
                ));
            }
            manifest = Some(parsed);
            continue;
        }
        let out = staging.join(&path);
        if let Some(parent) = out.parent() {
            osvdb::create_private_dir(parent)
                .map_err(|e| format!("creating {}: {e}", parent.display()))?;
        }
        entry
            .unpack(&out)
            .map_err(|e| format!("unpacking {shown}: {e}"))?;
    }
    manifest.ok_or_else(|| format!("{name}: empty bundle"))
}

/// Move the staged sources into `root`, each replacing what was there under its name.
fn install(staging: &Path, root: &Path, manifest: Manifest) -> Result<Imported, String> {
    let mut staged = Vec::new();
    for entry in
        std::fs::read_dir(staging).map_err(|e| format!("reading {}: {e}", staging.display()))?
    {
        let entry = entry.map_err(|e| format!("reading {}: {e}", staging.display()))?;
        staged.push(entry.file_name());
    }
    for name in &staged {
        let target = root.join(name);
        match std::fs::symlink_metadata(&target) {
            Ok(md) if md.is_dir() => std::fs::remove_dir_all(&target),
            Ok(_) => std::fs::remove_file(&target),
            Err(_) => Ok(()),
        }
        .map_err(|e| format!("replacing {}: {e}", target.display()))?;
        std::fs::rename(staging.join(name), &target)
            .map_err(|e| format!("installing {}: {e}", target.display()))?;
    }
    let mut left_over: Vec<String> = walk(root)?
        .into_iter()
        .filter(|(_, kind)| *kind == Kind::Data)
        .filter_map(|(path, _)| path.split('/').next().map(str::to_string))
        .filter(|top| !manifest.sources.iter().any(|s| s.name == *top))
        .collect();
    left_over.dedup();
    Ok(Imported {
        manifest,
        left_over,
    })
}

/// Write `bytes` to `<root>/<relative>` by way of a temp file, with its provenance.
///
/// # Errors
///
/// A failed write; what was there stays.
pub fn install_file(
    root: &Path,
    relative: &str,
    bytes: &[u8],
    url: &str,
    last_modified: Option<String>,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        osvdb::create_private_dir(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let tmp = path.with_extension("partial");
    std::fs::write(&tmp, bytes).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("installing {}: {e}", path.display()))?;
    let meta = Meta {
        url: url.to_string(),
        etag: None,
        last_modified,
        fetched_at: osvdb::now_rfc3339(),
        fetched_unix: osvdb::now_unix(),
        sha256: Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        size: bytes.len() as u64,
    };
    let json = serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?;
    let meta_path = osvdb::meta_path(&path);
    std::fs::write(&meta_path, json).map_err(|e| format!("writing {}: {e}", meta_path.display()))
}

/// Copy the tree `from` to `<root>/<relative>`, replacing it only once the copy is whole.
///
/// # Errors
///
/// An unreadable source or a failed write; what was there stays.
pub fn install_tree(root: &Path, relative: &str, from: &Path) -> Result<usize, String> {
    let target = root.join(relative);
    let tmp = target.with_extension("partial");
    let _ = std::fs::remove_dir_all(&tmp);
    let copied = copy_tree(from, &tmp).inspect_err(|_| {
        let _ = std::fs::remove_dir_all(&tmp);
    })?;
    if target.is_dir() {
        std::fs::remove_dir_all(&target)
            .map_err(|e| format!("replacing {}: {e}", target.display()))?;
    }
    std::fs::rename(&tmp, &target).map_err(|e| format!("installing {}: {e}", target.display()))?;
    Ok(copied)
}

fn copy_tree(from: &Path, to: &Path) -> Result<usize, String> {
    osvdb::create_private_dir(to).map_err(|e| format!("creating {}: {e}", to.display()))?;
    let mut copied = 0;
    for entry in std::fs::read_dir(from).map_err(|e| format!("reading {}: {e}", from.display()))? {
        let entry = entry.map_err(|e| format!("reading {}: {e}", from.display()))?;
        let kind = entry
            .file_type()
            .map_err(|e| format!("reading {}: {e}", entry.path().display()))?;
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            copied += copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), &target)
                .map_err(|e| format!("copying {}: {e}", entry.path().display()))?;
            copied += 1;
        }
    }
    Ok(copied)
}

/// `db status` rows for the sources beyond the exports and indexes.
#[must_use]
pub fn status_rows(root: &Path) -> Vec<[String; 5]> {
    let count = |dir: &Path| std::fs::read_dir(dir).map_or(0, |entries| entries.flatten().count());
    let mut rows = Vec::new();
    let mut row = |name: &str, size: String, sha: String| {
        rows.push([
            name.to_string(),
            "present".to_string(),
            String::new(),
            size,
            sha,
        ]);
    };
    if root.join(RUSTSEC_DIR).is_dir() {
        let commit = rustsec_commit(root).unwrap_or_default();
        row("RustSec", String::new(), commit.chars().take(12).collect());
    }
    for (name, file) in [("KEV", KEV_FILE), ("EPSS", EPSS_FILE)] {
        if let Some(meta) = Some(root.join(file))
            .filter(|p| p.is_file())
            .and_then(|p| osvdb::read_meta(&p))
        {
            let sha = meta.sha256.chars().take(12).collect();
            row(name, osvdb::human_size(meta.size), sha);
        }
    }
    for (name, dir) in [("NVD cache", NVD_DIR), ("Vulnrichment", VULNRICHMENT_DIR)] {
        let dir = root.join(dir);
        if dir.is_dir() {
            row(name, format!("{} CVEs", count(&dir)), String::new());
        }
    }
    rows
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn data(root: &Path) {
        std::fs::create_dir_all(root.join("PyPI")).unwrap();
        std::fs::write(root.join("PyPI/all.zip"), b"zip").unwrap();
        std::fs::write(root.join("PyPI/all.zip.meta.json"), b"{}").unwrap();
        std::fs::write(root.join("PyPI/all.zip.index.json"), b"{}").unwrap();
        std::fs::create_dir_all(root.join("enrich/nvd")).unwrap();
        std::fs::write(root.join("enrich/kev.json"), b"kev").unwrap();
        std::fs::write(root.join("enrich/nvd/CVE-2024-0001.json"), b"{}").unwrap();
        std::fs::create_dir_all(root.join("csaf/redhat")).unwrap();
        std::fs::write(root.join("csaf/redhat/index.jsonl.gz"), b"gz").unwrap();
        std::fs::write(root.join("csaf/redhat/derived"), b"stamp").unwrap();
    }

    fn paths(manifest: &Manifest) -> Vec<&str> {
        manifest
            .sources
            .iter()
            .flat_map(|s| &s.files)
            .map(|f| f.path.as_str())
            .collect()
    }

    #[test]
    fn a_manifest_lists_data_and_not_bookkeeping() {
        let dir = tempfile::tempdir().unwrap();
        data(dir.path());
        std::fs::write(dir.path().join("PyPI/all.zip.partial"), b"half").unwrap();
        std::fs::write(dir.path().join("snapshot-2026-01-01.json"), b"{}").unwrap();
        let manifest = build(dir.path()).unwrap();
        assert_eq!(
            paths(&manifest),
            [
                "PyPI/all.zip",
                "csaf/redhat/index.jsonl.gz",
                "enrich/kev.json",
                "enrich/nvd/CVE-2024-0001.json"
            ]
        );
    }

    #[test]
    fn a_pin_fails_on_a_changed_a_missing_and_an_extra_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        data(root);
        let file = root.join("snapshot-x.json");
        write(&build(root).unwrap(), &file).unwrap();
        assert!(pin(&file, None).is_ok());
        // A sync that found nothing new rewrites only the meta.
        std::fs::write(root.join("PyPI/all.zip.meta.json"), b"{\"later\":1}").unwrap();
        assert!(pin(&file, None).is_ok());

        std::fs::write(root.join("PyPI/all.zip"), b"zap").unwrap();
        let e = pin(&file, None).err().unwrap();
        assert!(e.contains("PyPI/all.zip: changed"), "{e}");
        std::fs::write(root.join("PyPI/all.zip"), b"zip").unwrap();

        std::fs::remove_file(root.join("enrich/kev.json")).unwrap();
        let e = pin(&file, None).err().unwrap();
        assert!(e.contains("enrich/kev.json: missing"), "{e}");
        std::fs::write(root.join("enrich/kev.json"), b"kev").unwrap();

        std::fs::create_dir_all(root.join("Hex")).unwrap();
        std::fs::write(root.join("Hex/all.zip"), b"more").unwrap();
        let e = pin(&file, None).err().unwrap();
        assert!(e.contains("Hex/all.zip: not in the snapshot"), "{e}");
    }

    #[test]
    fn a_bundle_round_trips_with_its_companions() {
        let dir = tempfile::tempdir().unwrap();
        let (from, to) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::create_dir(&from).unwrap();
        data(&from);
        let tar = dir.path().join("x.tar");
        let (manifest, sha) = bundle(&from, &tar).unwrap();
        let imported = import(&tar, &to, Some(&sha)).unwrap();
        assert_eq!(imported.manifest, manifest);
        assert!(imported.left_over.is_empty());
        assert_eq!(std::fs::read(to.join("PyPI/all.zip")).unwrap(), b"zip");
        assert!(to.join("PyPI/all.zip.meta.json").is_file());
        assert!(to.join("csaf/redhat/derived").is_file());
        assert!(!to.join("PyPI/all.zip.index.json").exists());
        assert!(pin(&to.join(MANIFEST), None).is_ok());
        assert!(!std::fs::read_dir(&to)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with(".import-")));
    }

    #[test]
    fn a_wrong_hash_or_a_damaged_bundle_replaces_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (from, to) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::create_dir(&from).unwrap();
        data(&from);
        let tar = dir.path().join("x.tar");
        bundle(&from, &tar).unwrap();
        std::fs::create_dir_all(to.join("PyPI")).unwrap();
        std::fs::write(to.join("PyPI/all.zip"), b"old").unwrap();
        assert!(import(&tar, &to, Some("00")).is_err());

        // Same length, so the tar stays readable and only the content is wrong.
        let mut bytes = std::fs::read(&tar).unwrap();
        let at = bytes.windows(3).position(|w| w == b"zip").unwrap();
        let at = at
            + bytes[at + 3..]
                .windows(3)
                .position(|w| w == b"zip")
                .unwrap()
            + 3;
        bytes[at] = b'Z';
        std::fs::write(&tar, bytes).unwrap();
        let _ = import(&tar, &to, None);
        assert_eq!(std::fs::read(to.join("PyPI/all.zip")).unwrap(), b"old");
    }

    type Entry<'a> = (&'a str, tar::EntryType, &'a [u8]);

    fn tar_with(entries: &[Entry]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, kind, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_entry_type(*kind);
            header.set_size(body.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            out.extend_from_slice(header.as_bytes());
            out.extend_from_slice(body);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
        out.resize(out.len() + 1024, 0);
        out
    }

    #[test]
    fn unsafe_entries_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let manifest = render(&Manifest {
            schema: SCHEMA,
            created: String::new(),
            tool_version: String::new(),
            sources: Vec::new(),
        })
        .unwrap();
        let file = tar::EntryType::Regular;
        let cases: [(&[Entry], &str); 4] = [
            (&[("PyPI/all.zip", file, b"zip")], "start with a manifest"),
            (
                &[
                    (MANIFEST, file, manifest.as_bytes()),
                    ("../evil", file, b"x"),
                ],
                "unsafe path",
            ),
            (
                &[
                    (MANIFEST, file, manifest.as_bytes()),
                    ("PyPI/link", tar::EntryType::Symlink, b""),
                ],
                "not a regular file",
            ),
            (
                &[
                    (MANIFEST, file, manifest.as_bytes()),
                    ("Unlisted/all.zip", file, b"zip"),
                ],
                "not in the snapshot",
            ),
        ];
        for (entries, expected) in cases {
            let tar = dir.path().join("x.tar");
            std::fs::write(&tar, tar_with(entries)).unwrap();
            let e = import(&tar, &root, None).err().unwrap();
            assert!(e.contains(expected), "{e}");
        }
        assert!(!dir.path().join("evil").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_in_the_data_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        data(dir.path());
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("PyPI/link")).unwrap();
        assert!(build(dir.path()).err().unwrap().contains("symlink"));
    }

    #[test]
    fn a_failed_tree_copy_leaves_the_old_one() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("enrich/nvd")).unwrap();
        std::fs::write(root.join("enrich/nvd/old.json"), b"{}").unwrap();
        assert!(install_tree(root, NVD_DIR, &root.join("absent")).is_err());
        assert!(root.join("enrich/nvd/old.json").is_file());
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(root.join("src/new.json"), b"{}").unwrap();
        assert_eq!(install_tree(root, NVD_DIR, &root.join("src")).unwrap(), 1);
        assert!(root.join("enrich/nvd/new.json").is_file());
        assert!(!root.join("enrich/nvd/old.json").exists());
    }
}
