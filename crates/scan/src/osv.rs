//! The osv.dev `crates.io` export, for what RustSec does not carry. GitHub reviews advisories
//! RustSec has no record of (hundreds of them, with `rustix`, `deno` and `surrealdb` among the
//! crates), and its ranges are sometimes wider than RustSec's for the same issue. A package
//! RustSec already reported an advisory for keeps RustSec's finding, with its unsound and
//! unmaintained kinds, so nothing is reported twice; where the two disagree the package is
//! reported, failing closed. What RustSec withdrew stays withdrawn.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Match, OsvDb, Spec, TierCFinding};
use fleetreach_core::semver::{Version, VersionReq};
use fleetreach_core::{Ecosystem, RepoId, VulnFinding};

use crate::{AdvisoryDb, ScanError};

/// One advisory's facts for a single affected crate.
pub type Advisory = osv::Advisory<Version>;

fn spec() -> Spec<Version> {
    Spec {
        ecosystem: "crates.io",
        // GitHub writes a few as `ECOSYSTEM`, over the same versions.
        range_type: "SEMVER|ECOSYSTEM",
        parse_version: parse_bound,
        normalize_name: |name| name.to_string(),
        use_versions: true,
        severity: osv::default_severity,
    }
}

/// A range bound. GitHub writes some as `0.62` or `3`, which SemVer alone would drop, losing
/// the fix.
fn parse_bound(raw: &str) -> Option<Version> {
    let raw = raw.strip_prefix('v').unwrap_or(raw);
    Version::parse(raw)
        .or_else(|_| Version::parse(&format!("{raw}.0")))
        .or_else(|_| Version::parse(&format!("{raw}.0.0")))
        .ok()
}

/// The filesystem path of an offline (`file://`) DB mirror, or `None` for anything else.
#[must_use]
pub fn crates_db_path(mirror: &str) -> Option<PathBuf> {
    mirror.strip_prefix("file://").map(PathBuf::from)
}

/// The offline `crates.io` DB: crate name to advisories.
#[derive(Debug, Default)]
pub struct CratesDb {
    db: OsvDb<Version>,
    /// Ids and aliases of the advisories RustSec withdrew.
    withdrawn: BTreeSet<String>,
}

impl CratesDb {
    /// Load the OSV mirror at `root`, a directory of `*.json` records or the export `.zip`,
    /// with an organization's own records from `overlay` on top.
    ///
    /// # Errors
    ///
    /// [`ScanError::DatabaseLoad`] if a mirror or overlay cannot be read or a record is not
    /// valid JSON, failing closed.
    pub fn load_with_overlay(root: &Path, overlay: Option<&Path>) -> Result<CratesDb, ScanError> {
        let db = osv::load_with_overlay(root, overlay, &spec())
            .map_err(|e| ScanError::DatabaseLoad(format!("{}: {}", e.path.display(), e.source)))?;
        Ok(CratesDb {
            db,
            withdrawn: BTreeSet::new(),
        })
    }

    /// Honor what `rustsec` withdrew.
    #[must_use]
    pub fn beside(mut self, rustsec: &AdvisoryDb) -> CratesDb {
        let metadata = rustsec.inner.iter().map(|a| &a.metadata);
        for meta in metadata.filter(|m| m.withdrawn.is_some()) {
            self.withdrawn.insert(meta.id.to_string());
            self.withdrawn
                .extend(meta.aliases.iter().map(ToString::to_string));
        }
        self
    }

    /// The advisories on one crate.
    #[must_use]
    pub fn advisories_for(&self, name: &str) -> &[Advisory] {
        self.db.advisories_for(name)
    }

    /// Every `(crate, advisory)` pair, in key order (for `db quality`).
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Advisory)> {
        self.db.iter()
    }

    /// Whether this advisory is for this source to report, beside the ids RustSec `reported`
    /// for the package. RustSec's own records never are, even when the local copy is older than
    /// the export: they would lose their unsound and unmaintained kinds here, and the next sync
    /// brings them.
    fn own(&self, advisory: &Advisory, reported: &BTreeSet<String>) -> bool {
        let mut ids = std::iter::once(&advisory.id).chain(&advisory.aliases);
        !advisory.id.starts_with("RUSTSEC-")
            && !ids.any(|id| self.withdrawn.contains(id) || reported.contains(id))
    }

    /// The findings for crate `name` at `version`, each with `dependency_path`, leaving out the
    /// advisories RustSec `reported` for it.
    pub(crate) fn findings(
        &self,
        repo: &RepoId,
        name: &str,
        version: &Version,
        reported: &BTreeSet<String>,
        direct: bool,
        dependency_path: &[String],
    ) -> Vec<VulnFinding> {
        self.db
            .advisories_for(name)
            .iter()
            .filter(|a| self.own(a, reported))
            .filter(|a| {
                let hit = osv::affected_fixed_parsed(version, &a.ranges, |v, bound| v >= bound);
                matches!(hit, Match::Affected { .. }) || a.versions.binary_search(version).is_ok()
            })
            .map(|a| {
                let patched: Vec<VersionReq> = osv::patched_reqs(
                    &osv::safe_intervals(version, &a.ranges),
                    ToString::to_string,
                );
                TierCFinding {
                    ecosystem: Ecosystem::Cargo,
                    advisory_id: a.id.clone(),
                    aliases: a.aliases.clone(),
                    title: a.summary.clone().unwrap_or_else(|| a.id.clone()),
                    severity: a.severity,
                    cvss_score: a.cvss_score,
                    cvss_vector: a.cvss_vector.clone(),
                    package: name.to_string(),
                    installed: version.clone(),
                    patched,
                    direct,
                    dev: false,
                    dependency_path: dependency_path.to_vec(),
                    repo,
                    reach_reason: "package-level scan: version match only",
                }
                .build()
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    fn db(records: &[(&str, &str)]) -> CratesDb {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("fr-crates-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (id, body) in records {
            std::fs::write(dir.join(format!("{id}.json")), body).unwrap();
        }
        let db = CratesDb::load_with_overlay(&dir, None).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        db
    }

    fn record(id: &str, aliases: &str, kind: &str) -> (String, String) {
        let body = format!(
            r#"{{"id":"{id}","aliases":[{aliases}],"summary":"bad","affected":[{{
            "package":{{"name":"rustix","ecosystem":"crates.io"}},
            "ranges":[{{"type":"{kind}","events":[{{"introduced":"0"}},{{"fixed":"0.38.19"}}]}}]}}]}}"#
        );
        (id.to_string(), body)
    }

    fn ids_beside(db: &CratesDb, version: &str, reported: &BTreeSet<String>) -> Vec<String> {
        let repo = RepoId("r".into());
        let v = Version::parse(version).unwrap();
        db.findings(&repo, "rustix", &v, reported, false, &[])
            .into_iter()
            .map(|f| f.advisory_id)
            .collect()
    }

    fn ids(db: &CratesDb, version: &str) -> Vec<String> {
        ids_beside(db, version, &BTreeSet::new())
    }

    #[test]
    fn matches_both_range_types_and_stops_at_the_fix() {
        for kind in ["SEMVER", "ECOSYSTEM"] {
            let (id, body) = record("GHSA-1", "", kind);
            let db = db(&[(&id, &body)]);
            assert_eq!(ids(&db, "0.38.11"), ["GHSA-1"], "{kind}");
            assert!(ids(&db, "0.38.19").is_empty(), "{kind}");
        }
    }

    #[test]
    fn short_bounds_keep_their_fix() {
        let body = record("GHSA-1", "", "ECOSYSTEM")
            .1
            .replace("0.38.19", "0.62");
        let db = db(&[("GHSA-1", &body)]);
        assert_eq!(ids(&db, "0.61.9"), ["GHSA-1"]);
        assert!(ids(&db, "0.84.0").is_empty());
    }

    #[test]
    fn what_rustsec_reported_or_withdrew_is_left_to_it() {
        let (a, a_body) = record("GHSA-1", r#""RUSTSEC-2024-1""#, "SEMVER");
        let (b, b_body) = record("GHSA-2", r#""CVE-2024-2""#, "SEMVER");
        let (c, c_body) = record("GHSA-3", r#""RUSTSEC-2024-3""#, "SEMVER");
        let mut db = db(&[(&a, &a_body), (&b, &b_body), (&c, &c_body)]);
        db.withdrawn.insert("RUSTSEC-2024-3".to_string());
        let reported = BTreeSet::from(["RUSTSEC-2024-1".to_string()]);
        assert_eq!(ids_beside(&db, "0.38.11", &reported), ["GHSA-2"]);
        // A wider GitHub range than RustSec's: RustSec reported nothing, so this package stays.
        assert_eq!(ids(&db, "0.38.11"), ["GHSA-1", "GHSA-2"]);
    }

    #[test]
    fn rustsec_records_in_the_export_are_never_reported() {
        let (id, body) = record("RUSTSEC-2099-1", "", "SEMVER");
        assert!(ids(&db(&[(&id, &body)]), "0.38.11").is_empty());
    }
}
