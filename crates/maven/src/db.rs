//! The offline OSV vulnerability DB for Maven: a directory of OSV JSON records (exactly what
//! OSV.dev's `Maven/all.zip` unzips to) or the `.zip` itself, loaded **once** and indexed by
//! `group:artifact` coordinate via the shared [`osv`] feeder scaffolding.
//!
//! Maven advisory ranges are `ECOSYSTEM`-typed; bounds are Maven versions, parsed by
//! [`crate::parse_maven_version`] and compared with Maven's `ComparableVersion` ordering.

use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Match, OsvDb, ParsedRange, Spec};

use crate::error::MavenError;
use crate::version::{parse_maven_version, Version};

/// The filesystem path of an offline (`file://`) DB mirror, or `None` for anything else.
///
/// # Examples
///
/// ```
/// use fleetreach_maven::maven_db_path;
/// use std::path::PathBuf;
///
/// assert_eq!(maven_db_path("file:///opt/maven/all.zip"), Some(PathBuf::from("/opt/maven/all.zip")));
/// assert_eq!(maven_db_path("https://osv.dev"), None);
/// ```
pub fn maven_db_path(db: &str) -> Option<PathBuf> {
    db.strip_prefix("file://").map(PathBuf::from)
}

/// One advisory's facts for a single affected Maven artifact (see [`osv::Advisory`]).
pub type Advisory = osv::Advisory<Version>;

/// The per-ecosystem knobs the shared loader needs for the Maven OSV export. Coordinates are
/// kept verbatim (Maven coordinates are case-sensitive); ranges are `ECOSYSTEM`-typed.
fn spec() -> Spec<Version> {
    Spec {
        ecosystem: "Maven",
        range_type: "ECOSYSTEM",
        parse_version: parse_maven_version,
        normalize_name: |name| name.to_string(),
        use_versions: true,
        severity: osv::default_severity,
    }
}

/// The offline Maven OSV DB: `group:artifact → advisories affecting it` (verbatim coordinates).
#[derive(Debug, Default)]
pub struct MavenDb(OsvDb<Version>);

impl MavenDb {
    /// Load the OSV mirror at `root`, a directory of `*.json` records or the export `.zip`.
    ///
    /// # Errors
    ///
    /// Returns [`MavenError::Db`] if `root` cannot be read, the archive cannot be decompressed,
    /// or a record is not valid JSON — failing closed.
    pub fn load(root: &Path) -> Result<MavenDb, MavenError> {
        osv::load(root, &spec())
            .map(MavenDb)
            .map_err(|e| MavenError::db(e.path, e.source))
    }

    /// The advisories indexed under `coordinate` (`group:artifact`, verbatim), or an empty
    /// slice if none.
    pub fn advisories_for(&self, coordinate: &str) -> &[Advisory] {
        self.0.advisories_for(coordinate)
    }

    /// Total advisory-package index entries — for diagnostics/tests.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the DB indexed no Maven advisories at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Evaluate the advisory's `ECOSYSTEM` ranges for a Maven [`Version`] (the shared
/// [`osv::affected_fixed_parsed`] skeleton + Maven bounds). Maven versions order per their own
/// `ComparableVersion`, so the `introduced` comparison is a plain `>=`.
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
        parse_maven_version(s).unwrap()
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
        vec![osv::parse_range(&range, parse_maven_version)]
    }

    #[test]
    fn affected_below_fix_reports_patch() {
        let r = ranges(&[("introduced", "10.1.1.0"), ("fixed", "10.14.3")]);
        assert_eq!(
            affected_fixed(&v("10.14.2.0"), &r),
            Match::Affected {
                fixed: Some(v("10.14.3"))
            }
        );
        assert_eq!(affected_fixed(&v("10.14.3"), &r), Match::NotAffected);
    }

    #[test]
    fn qualifier_bounds_use_maven_ordering() {
        // 14.0-rc-1 sorts below 14.0, and a `.RELEASE` fix equals the bare release.
        let r = ranges(&[("introduced", "14.0-rc-1"), ("fixed", "14.4")]);
        assert_eq!(
            affected_fixed(&v("14.0"), &r),
            Match::Affected {
                fixed: Some(v("14.4"))
            }
        );
        assert_eq!(
            affected_fixed(&v("14.0-rc-1"), &r),
            Match::Affected {
                fixed: Some(v("14.4"))
            }
        );
    }

    #[test]
    fn malformed_introduced_never_clean() {
        // Maven parses anything, so a "garbage" bound parses to a qualifier and still matches
        // — never a silent clean.
        let r = ranges(&[("introduced", "0"), ("fixed", "2.0")]);
        assert_eq!(
            affected_fixed(&v("1.5"), &r),
            Match::Affected {
                fixed: Some(v("2.0"))
            }
        );
    }

    #[test]
    fn indexes_maven_verbatim() {
        let json = r#"{
          "id": "GHSA-mvn-1",
          "summary": "issue in derby",
          "database_specific": { "severity": "HIGH" },
          "affected": [
            { "package": { "ecosystem": "Maven", "name": "org.apache.derby:derby" },
              "ranges": [ { "type": "ECOSYSTEM", "events": [ {"introduced":"0"}, {"fixed":"10.14.3"} ] } ] },
            { "package": { "ecosystem": "npm", "name": "x" }, "ranges": [] }
          ]
        }"#;
        let osv: OsvRecord = serde_json::from_str(json).unwrap();
        let pairs = osv::advisories_from(osv, &spec());
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "org.apache.derby:derby");
        assert_eq!(pairs[0].1.severity, Severity::High);
    }

    #[test]
    fn maven_db_path_only_file_urls() {
        assert_eq!(
            maven_db_path("file:///opt/db"),
            Some(PathBuf::from("/opt/db"))
        );
        assert_eq!(maven_db_path("https://osv.dev"), None);
    }
}
