//! The offline OSV vulnerability DB for Swift: a directory of OSV JSON records (exactly what
//! OSV.dev's `SwiftURL/all.zip` unzips to) or the `.zip` itself, loaded **once** and indexed
//! by normalized package URL via the shared [`osv`] feeder scaffolding.
//!
//! Swift advisory ranges are `SEMVER`-typed and Swift versions are plain SemVer, so this reuses
//! `fleetreach_core::semver::Version` directly (no bespoke comparator, like npm). Packages are
//! identified by a normalized source URL (see [`crate::normalize_package_url`]), which the OSV
//! `affected[].package.name` is itself run through so the index key matches the normalized
//! installed URL.

use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Match, OsvDb, ParsedRange, Spec};
use fleetreach_core::semver::Version;

use crate::error::SwiftError;
use crate::lockfile::normalize_package_url;

/// The filesystem path of an offline (`file://`) DB mirror, or `None` for anything else.
///
/// # Examples
///
/// ```
/// use fleetreach_swift::swift_db_path;
/// use std::path::PathBuf;
///
/// assert_eq!(swift_db_path("file:///opt/swift/all.zip"), Some(PathBuf::from("/opt/swift/all.zip")));
/// assert_eq!(swift_db_path("https://osv.dev"), None);
/// ```
pub fn swift_db_path(db: &str) -> Option<PathBuf> {
    db.strip_prefix("file://").map(PathBuf::from)
}

/// One advisory's facts for a single affected package (see [`osv::Advisory`]).
pub type Advisory = osv::Advisory<Version>;

/// The per-ecosystem knobs the shared loader needs for the Swift OSV export. Packages are keyed
/// by normalized source URL (the OSV name run through [`normalize_package_url`]); ranges are
/// `SEMVER`-typed.
fn spec() -> Spec<Version> {
    Spec {
        ecosystem: "SwiftURL",
        range_type: "SEMVER",
        parse_version: parse_bound,
        normalize_name: normalize_package_url,
        use_versions: true,
        severity: osv::default_severity,
    }
}

/// The offline Swift OSV DB: `normalized package URL → advisories affecting it`.
#[derive(Debug, Default)]
pub struct SwiftDb(OsvDb<Version>);

impl SwiftDb {
    /// Load the OSV mirror at `root`, a directory of `*.json` records or the export `.zip`.
    ///
    /// # Errors
    ///
    /// Returns [`SwiftError::Db`] if `root` cannot be read, the archive cannot be decompressed,
    /// or a record is not valid JSON — failing closed.
    pub fn load(root: &Path) -> Result<SwiftDb, SwiftError> {
        osv::load(root, &spec())
            .map(SwiftDb)
            .map_err(|e| SwiftError::db(e.path, e.source))
    }

    /// The advisories indexed under `url` (pass a normalized URL — see
    /// [`crate::normalize_package_url`]), or an empty slice if none.
    pub fn advisories_for(&self, url: &str) -> &[Advisory] {
        self.0.advisories_for(url)
    }

    /// Total advisory-package index entries — for diagnostics/tests.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the DB indexed no Swift advisories at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Evaluate the advisory's `SEMVER` ranges for `version` (the shared [`osv::affected_fixed_parsed`]
/// skeleton + Swift's plain-SemVer bounds; Swift versions order normally, so the `introduced`
/// comparison is a plain `>=`).
pub(crate) fn affected_fixed(version: &Version, ranges: &[ParsedRange<Version>]) -> Match<Version> {
    osv::affected_fixed_parsed(version, ranges, |ver, bound| ver >= bound)
}

/// Parse an OSV range bound. `"0"` (the universal lower bound) is not valid SemVer, so map it
/// to `0.0.0`; a leading `v` is tolerated.
pub(crate) fn parse_bound(raw: &str) -> Option<Version> {
    if raw == "0" {
        return Some(Version::new(0, 0, 0));
    }
    Version::parse(raw.strip_prefix('v').unwrap_or(raw)).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use fleetreach_core::osv::{Event, OsvRecord, Range};
    use fleetreach_core::Severity;

    fn v(s: &str) -> Version {
        parse_bound(s).unwrap()
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
        vec![osv::parse_range(&range, parse_bound)]
    }

    #[test]
    fn affected_below_fix_reports_patch() {
        let r = ranges(&[("introduced", "2.39.0"), ("fixed", "2.41.0")]);
        assert_eq!(
            affected_fixed(&v("2.40.0"), &r),
            Match::Affected {
                fixed: Some(v("2.41.0"))
            }
        );
        assert_eq!(affected_fixed(&v("2.41.0"), &r), Match::NotAffected);
    }

    #[test]
    fn prerelease_bounds_are_handled() {
        let r = ranges(&[("introduced", "2.0.0-alpha.1"), ("fixed", "2.0.0-alpha.2")]);
        assert_eq!(
            affected_fixed(&v("2.0.0-alpha.1"), &r),
            Match::Affected {
                fixed: Some(v("2.0.0-alpha.2"))
            }
        );
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
    fn indexes_swifturl_by_normalized_url() {
        let json = r#"{
          "id": "GHSA-sw-1",
          "summary": "issue in swift-nio",
          "database_specific": { "severity": "HIGH" },
          "affected": [
            { "package": { "ecosystem": "SwiftURL", "name": "github.com/apple/swift-nio" },
              "ranges": [ { "type": "SEMVER", "events": [ {"introduced":"0"}, {"fixed":"2.41.0"} ] } ] },
            { "package": { "ecosystem": "npm", "name": "x" }, "ranges": [] }
          ]
        }"#;
        let osv: OsvRecord = serde_json::from_str(json).unwrap();
        let pairs = osv::advisories_from(osv, &spec());
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "github.com/apple/swift-nio");
        assert_eq!(pairs[0].1.severity, Severity::High);
    }

    #[test]
    fn swift_db_path_only_file_urls() {
        assert_eq!(
            swift_db_path("file:///opt/db"),
            Some(PathBuf::from("/opt/db"))
        );
        assert_eq!(swift_db_path("https://osv.dev"), None);
    }
}
