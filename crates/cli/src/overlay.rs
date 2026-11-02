//! Local advisory overlays (spec 16, row 12): an organization's own advisories and
//! corrections, as OSV JSON records in a directory versioned with its config
//! (`[settings.advisories] dir`).
//!
//! Every OSV feeder layers them over its upstream export (see
//! [`fleetreach_core::osv::load_with_overlay`]): a record with an upstream id **replaces** that
//! record everywhere, a record with a new id is an **addition**, and a record with `withdrawn`
//! set **retracts** the upstream record of that id. Records for ecosystems with no OSV feeder
//! (Go's offline matcher reads its own format, Rust reads RustSec) are not applied, and the
//! scan says so instead of dropping them silently.
//!
//! Fail-closed: a configured directory that is missing, unreadable or holds a record that is
//! not valid OSV JSON stops the scan, since a correction that is silently not applied could
//! hide a finding.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, OsvRecord};
use fleetreach_core::OsvProvenance;
use sha2::{Digest, Sha256};

use crate::osvdb;

/// What a scan learned from reading the overlay directory.
#[derive(Debug, Clone)]
pub struct Overlay {
    pub dir: PathBuf,
    /// Number of records read.
    pub records: usize,
    /// sha256 over every record's relative path and bytes, in path order: pins the overlay
    /// a report was produced with.
    pub sha256: String,
    /// `(record id, ecosystem)` pairs no feeder applies.
    pub not_applied: Vec<(String, String)>,
}

impl Overlay {
    /// The report's provenance entry for the overlay (`ecosystem: "overlay"`).
    #[must_use]
    pub fn provenance(&self) -> OsvProvenance {
        OsvProvenance {
            ecosystem: "overlay".to_string(),
            source: "advisories".to_string(),
            path: self.dir.display().to_string(),
            upstream_modified: None,
            fetched_at: None,
            sha256: Some(self.sha256.clone()),
            age_basis: "unknown".to_string(),
        }
    }

    /// One warning per ecosystem whose overlay records no feeder applies.
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        let ecosystems: BTreeSet<&str> = self.not_applied.iter().map(|(_, e)| e.as_str()).collect();
        ecosystems
            .into_iter()
            .map(|eco| {
                let ids: Vec<&str> = self
                    .not_applied
                    .iter()
                    .filter(|(_, e)| e == eco)
                    .map(|(id, _)| id.as_str())
                    .collect();
                format!(
                    "advisory overlay: {} record(s) for `{eco}` are not applied (only the OSV \
                     export ecosystems are layered): {}",
                    ids.len(),
                    ids.join(", ")
                )
            })
            .collect()
    }
}

/// The OSV `affected[].package.ecosystem` names an overlay can apply to: every osv.dev export
/// a feeder loads through the shared OSV loader (all but Go).
#[must_use]
pub fn applied_ecosystem(name: &str) -> bool {
    osvdb::OSV_ECOSYSTEMS
        .iter()
        .filter(|&&eco| eco != fleetreach_core::Ecosystem::Go)
        .any(|&eco| osvdb::osv_name(eco) == Some(name))
}

/// Read and check the overlay directory.
///
/// # Errors
///
/// A missing or unreadable directory, or a record that is not valid OSV JSON.
pub fn inspect(dir: &Path) -> Result<Overlay, String> {
    if !dir.is_dir() {
        return Err(format!(
            "[settings.advisories] dir {} is not a directory",
            dir.display()
        ));
    }
    let records = osv::read_overlay(dir)
        .map_err(|e| format!("advisory overlay {}: {}", e.path.display(), e.source))?;
    let mut not_applied = Vec::new();
    for record in &records {
        let mut seen = BTreeSet::new();
        for affected in &record.affected {
            let eco = affected.package.ecosystem.as_deref().unwrap_or("");
            if !applied_ecosystem(eco) && seen.insert(eco.to_string()) {
                not_applied.push((record.id.clone(), eco.to_string()));
            }
        }
    }
    let ids: BTreeSet<&str> = records.iter().map(|r| r.id.as_str()).collect();
    if ids.len() != records.len() {
        let mut seen = BTreeSet::new();
        let dup = records
            .iter()
            .find(|r| !seen.insert(r.id.as_str()))
            .map_or("", |r| r.id.as_str());
        return Err(format!(
            "advisory overlay {}: id {dup} is defined twice",
            dir.display()
        ));
    }
    Ok(Overlay {
        dir: dir.to_path_buf(),
        records: records.len(),
        sha256: digest(dir)?,
        not_applied,
    })
}

/// The overlay's records, for `db quality` (same reader the feeders use).
///
/// # Errors
///
/// As [`inspect`].
pub fn records(dir: &Path) -> Result<Vec<OsvRecord>, String> {
    osv::read_overlay(dir)
        .map_err(|e| format!("advisory overlay {}: {}", e.path.display(), e.source))
}

fn digest(dir: &Path) -> Result<String, String> {
    let mut paths: Vec<PathBuf> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_entry(|e| e.depth() == 0 || !e.file_name().to_string_lossy().starts_with('.'))
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
        .collect();
    paths.sort();
    let mut hasher = Sha256::new();
    for path in paths {
        let rel = path.strip_prefix(dir).unwrap_or(&path);
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update([0]);
        let bytes = std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        hasher.update(&bytes);
        hasher.update([0]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fr-overlay-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn inspects_records_and_names_what_is_not_applied() {
        let dir = tmp("inspect");
        std::fs::create_dir_all(dir.join("go")).unwrap();
        std::fs::write(
            dir.join("a.json"),
            r#"{"id":"ORG-1","affected":[{"package":{"ecosystem":"npm","name":"x"}}]}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("go/b.json"),
            r#"{"id":"ORG-2","affected":[{"package":{"ecosystem":"Go","name":"y"}},
                {"package":{"ecosystem":"crates.io","name":"z"}}]}"#,
        )
        .unwrap();
        std::fs::write(dir.join("notes.md"), "ignored").unwrap();
        let overlay = inspect(&dir).unwrap();
        assert_eq!(overlay.records, 2);
        assert_eq!(
            overlay.not_applied,
            vec![
                ("ORG-2".to_string(), "Go".to_string()),
                ("ORG-2".to_string(), "crates.io".to_string())
            ]
        );
        assert_eq!(overlay.warnings().len(), 2);
        assert_eq!(overlay.sha256.len(), 64);
        // The digest moves when a record changes.
        let before = overlay.sha256.clone();
        std::fs::write(
            dir.join("a.json"),
            r#"{"id":"ORG-1","affected":[{"package":{"ecosystem":"npm","name":"xx"}}]}"#,
        )
        .unwrap();
        assert_ne!(inspect(&dir).unwrap().sha256, before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broken_missing_or_duplicate_fails_closed() {
        let dir = tmp("broken");
        assert!(inspect(&dir.join("absent")).is_err());
        std::fs::write(dir.join("a.json"), r#"{"id":"ORG-1"}"#).unwrap();
        std::fs::write(dir.join("b.json"), r#"{"id":"ORG-1"}"#).unwrap();
        let err = inspect(&dir).unwrap_err();
        assert!(err.contains("defined twice"), "{err}");
        std::fs::write(dir.join("b.json"), "{not json").unwrap();
        let err = inspect(&dir).unwrap_err();
        assert!(err.contains("b.json"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
