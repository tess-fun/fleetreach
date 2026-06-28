//! The offline OSV vulnerability DB for Julia: a directory of OSV JSON records (exactly what
//! OSV.dev's `Julia/all.zip` unzips to) or the `.zip` itself, loaded **once** and indexed by
//! package name via the shared [`osv`] feeder scaffolding.
//!
//! Julia advisory ranges are `SEMVER`-typed (not `ECOSYSTEM` like Packagist/NuGet), so the
//! `matchable` gate is `type == "SEMVER"`, as for npm/Go. Bounds are Julia versions, parsed by
//! [`crate::parse_julia_version`] and compared with Julia's own (build-significant) ordering.

use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Match, OsvDb, ParsedRange, Spec};

use crate::error::JuliaError;
use crate::version::{parse_julia_version, Version};

/// The filesystem path of an offline (`file://`) DB mirror, or `None` for anything else. The
/// path may be the osv.dev export `Julia/all.zip` or a directory of unzipped OSV records.
///
/// # Examples
///
/// ```
/// use fleetreach_julia::julia_db_path;
/// use std::path::PathBuf;
///
/// assert_eq!(julia_db_path("file:///opt/julia/all.zip"), Some(PathBuf::from("/opt/julia/all.zip")));
/// assert_eq!(julia_db_path("https://osv.dev"), None);
/// ```
pub fn julia_db_path(db: &str) -> Option<PathBuf> {
    db.strip_prefix("file://").map(PathBuf::from)
}

/// One advisory's facts for a single affected Julia package (see [`osv::Advisory`]).
pub type Advisory = osv::Advisory<Version>;

/// The per-ecosystem knobs the shared loader needs for the Julia OSV export. Names are kept
/// verbatim (Julia names are case-sensitive); ranges are `SEMVER`-typed.
fn spec() -> Spec<Version> {
    Spec {
        ecosystem: "Julia",
        range_type: "SEMVER",
        parse_version: parse_julia_version,
        normalize_name: |name| name.to_string(),
        use_versions: true,
        severity: osv::default_severity,
    }
}

/// The offline Julia OSV DB: `package name → advisories affecting it` (verbatim names).
#[derive(Debug, Default)]
pub struct JuliaDb(OsvDb<Version>);

impl JuliaDb {
    /// Load the OSV mirror at `root`, a directory of `*.json` records or the export `.zip`.
    ///
    /// # Errors
    ///
    /// Returns [`JuliaError::Db`] if `root` cannot be read, the archive cannot be
    /// decompressed, or a record is not valid JSON — failing closed.
    pub fn load(root: &Path) -> Result<JuliaDb, JuliaError> {
        osv::load(root, &spec())
            .map(JuliaDb)
            .map_err(|e| JuliaError::db(e.path, e.source))
    }

    /// The advisories indexed under `package` (verbatim, case-sensitive), or an empty slice.
    pub fn advisories_for(&self, package: &str) -> &[Advisory] {
        self.0.advisories_for(package)
    }

    /// Total advisory-package index entries — for diagnostics/tests.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the DB indexed no Julia advisories at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Evaluate the advisory's `SEMVER` ranges for a Julia [`Version`] (the shared
/// [`osv::affected_fixed_parsed`] skeleton + Julia bounds). Julia versions order per their own
/// `Ord` (build-significant), so the `introduced` comparison is a plain `>=`.
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
        parse_julia_version(s).unwrap()
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
        vec![osv::parse_range(&range, parse_julia_version)]
    }

    #[test]
    fn jll_build_window_matches_on_build_counter() {
        // The Julia-specific case: an advisory keyed on the JLL build counter. 3.0.8+0 is
        // affected; the fix 3.0.11+0 (and a higher build of it) is not.
        let r = ranges(&[("introduced", "0"), ("fixed", "3.0.11+0")]);
        assert_eq!(
            affected_fixed(&v("3.0.8+0"), &r),
            Match::Affected {
                fixed: Some(v("3.0.11+0"))
            }
        );
        assert_eq!(affected_fixed(&v("3.0.11+0"), &r), Match::NotAffected);
        assert_eq!(affected_fixed(&v("3.0.11+1"), &r), Match::NotAffected);
    }

    #[test]
    fn build_counter_below_fix_is_affected() {
        // Same patch, lower build counter than the fix → affected.
        let r = ranges(&[("introduced", "8.15.0+0"), ("fixed", "8.15.0+2")]);
        assert_eq!(
            affected_fixed(&v("8.15.0+1"), &r),
            Match::Affected {
                fixed: Some(v("8.15.0+2"))
            }
        );
        assert_eq!(affected_fixed(&v("8.15.0+2"), &r), Match::NotAffected);
    }

    #[test]
    fn malformed_introduced_fails_loud() {
        let r = ranges(&[("introduced", "garbage"), ("fixed", "99.0.0")]);
        assert_eq!(
            affected_fixed(&v("1.0.0"), &r),
            Match::Affected {
                fixed: Some(v("99.0.0"))
            }
        );
    }

    #[test]
    fn only_semver_ranges_matchable_and_names_verbatim() {
        let json = r#"{
          "id": "GHSA-jl-1",
          "summary": "issue in HTTP",
          "database_specific": { "severity": "HIGH" },
          "affected": [
            { "package": { "ecosystem": "Julia", "name": "HTTP" },
              "ranges": [ { "type": "SEMVER", "events": [ {"introduced":"0"}, {"fixed":"1.9.5"} ] } ] }
          ]
        }"#;
        let osv: OsvRecord = serde_json::from_str(json).unwrap();
        let pairs = osv::advisories_from(osv, &spec());
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "HTTP", "verbatim, case-sensitive");
        assert!(pairs[0].1.ranges[0].matchable);
        assert_eq!(pairs[0].1.severity, Severity::High);
    }

    #[test]
    fn julia_db_path_only_file_urls() {
        assert_eq!(
            julia_db_path("file:///opt/db"),
            Some(PathBuf::from("/opt/db"))
        );
        assert_eq!(julia_db_path("https://osv.dev"), None);
    }
}
