//! The offline OSV vulnerability DB for GitHub Actions: a directory of OSV JSON records
//! (exactly what OSV.dev's `GitHub Actions/all.zip` unzips to) or the `.zip` itself, loaded
//! **once** and indexed by lowercased action name (`owner/repo[/subpath]`) via the shared
//! [`osv`] feeder scaffolding.
//!
//! GitHub Actions advisory ranges are `ECOSYSTEM`-typed; bounds are version tags (`46.0.1`, or
//! a major-only `5`), parsed by [`crate::parse_gha_version`] into the shared SemVer type.

use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Match, OsvDb, ParsedRange, Spec};
use fleetreach_core::semver::Version;

use crate::error::GhaError;
use crate::workflow::parse_gha_version;

/// The filesystem path of an offline (`file://`) DB mirror, or `None` for anything else.
///
/// # Examples
///
/// ```
/// use fleetreach_ghactions::ghactions_db_path;
/// use std::path::PathBuf;
///
/// assert_eq!(ghactions_db_path("file:///opt/gha/all.zip"), Some(PathBuf::from("/opt/gha/all.zip")));
/// assert_eq!(ghactions_db_path("https://osv.dev"), None);
/// ```
pub fn ghactions_db_path(db: &str) -> Option<PathBuf> {
    db.strip_prefix("file://").map(PathBuf::from)
}

/// One advisory's facts for a single affected action (see [`osv::Advisory`]).
pub type Advisory = osv::Advisory<Version>;

/// The per-ecosystem knobs the shared loader needs for the GitHub Actions OSV export. Names are
/// lowercased (GitHub treats `owner/repo` case-insensitively); ranges are `ECOSYSTEM`-typed.
fn spec() -> Spec<Version> {
    Spec {
        ecosystem: "GitHub Actions",
        range_type: "ECOSYSTEM",
        parse_version: parse_gha_version,
        normalize_name: |name| name.to_ascii_lowercase(),
        use_versions: true,
        severity: osv::default_severity,
    }
}

/// The offline GitHub Actions OSV DB: `action name (lowercase) → advisories affecting it`.
#[derive(Debug, Default)]
pub struct GhActionsDb(OsvDb<Version>);

impl GhActionsDb {
    /// Load the OSV mirror at `root`, a directory of `*.json` records or the export `.zip`.
    ///
    /// # Errors
    ///
    /// Returns [`GhaError::Db`] if `root` cannot be read, the archive cannot be decompressed,
    /// or a record is not valid JSON — failing closed.
    pub fn load(root: &Path) -> Result<GhActionsDb, GhaError> {
        osv::load(root, &spec())
            .map(GhActionsDb)
            .map_err(|e| GhaError::db(e.path, e.source))
    }

    /// The advisories indexed under `action` (pass any case — it is lowercased here), or an
    /// empty slice if none.
    pub fn advisories_for(&self, action: &str) -> &[Advisory] {
        self.0.advisories_for(&action.to_ascii_lowercase())
    }

    /// Total advisory-package index entries — for diagnostics/tests.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the DB indexed no GitHub Actions advisories at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Evaluate the advisory's `ECOSYSTEM` ranges for an action's tag `version` (the shared
/// [`osv::affected_fixed`] skeleton + tag bounds parsed by [`parse_gha_version`]; versions
/// order as SemVer, so the `introduced` comparison is a plain `>=`).
pub(crate) fn affected_fixed(version: &Version, ranges: &[ParsedRange<Version>]) -> Match<Version> {
    osv::affected_fixed_parsed(version, ranges, |ver, bound| ver >= bound)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use fleetreach_core::osv::{Event, OsvRecord, Range};
    use fleetreach_core::Severity;

    fn v(s: &str) -> Version {
        parse_gha_version(s).unwrap()
    }

    fn ranges(events: &[(&str, &str)]) -> Vec<ParsedRange<Version>> {
        let range = Range {
            matchable: true,
            events: events
                .iter()
                .map(|(k, val)| Event {
                    introduced: (*k == "introduced").then(|| val.to_string()),
                    fixed: (*k == "fixed").then(|| val.to_string()),
                    last_affected: (*k == "last_affected").then(|| val.to_string()),
                })
                .collect(),
        };
        vec![osv::parse_range(&range, parse_gha_version)]
    }

    #[test]
    fn tj_actions_changed_files_window() {
        // The real tj-actions/changed-files supply-chain advisory: everything below 46.0.1.
        let r = ranges(&[("introduced", "0"), ("fixed", "46.0.1")]);
        assert_eq!(
            affected_fixed(&v("44"), &r), // pinned to the v44 major tag
            Match::Affected {
                fixed: Some(v("46.0.1"))
            }
        );
        assert_eq!(affected_fixed(&v("46.0.1"), &r), Match::NotAffected);
        assert_eq!(affected_fixed(&v("47"), &r), Match::NotAffected);
    }

    #[test]
    fn major_only_bound() {
        // A `fixed: 2` bound means fixed in v2 → 2.0.0.
        let r = ranges(&[("introduced", "0"), ("fixed", "2")]);
        assert_eq!(
            affected_fixed(&v("1.5.0"), &r),
            Match::Affected {
                fixed: Some(v("2"))
            }
        );
        assert_eq!(affected_fixed(&v("2"), &r), Match::NotAffected);
    }

    #[test]
    fn indexes_gha_lowercased() {
        let json = r#"{
          "id": "GHSA-gha-1",
          "summary": "compromised action",
          "database_specific": { "severity": "CRITICAL" },
          "affected": [
            { "package": { "ecosystem": "GitHub Actions", "name": "tj-actions/changed-files" },
              "ranges": [ { "type": "ECOSYSTEM", "events": [ {"introduced":"0"}, {"fixed":"46.0.1"} ] } ] }
          ]
        }"#;
        let osv: OsvRecord = serde_json::from_str(json).unwrap();
        let pairs = osv::advisories_from(osv, &spec());
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "tj-actions/changed-files");
        assert_eq!(pairs[0].1.severity, Severity::Critical);
    }

    #[test]
    fn ghactions_db_path_only_file_urls() {
        assert_eq!(
            ghactions_db_path("file:///opt/db"),
            Some(PathBuf::from("/opt/db"))
        );
        assert_eq!(ghactions_db_path("https://osv.dev"), None);
    }
}
