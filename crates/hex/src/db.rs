//! The offline OSV vulnerability DB for Hex: a directory of OSV JSON records (exactly what
//! OSV.dev's `Hex/all.zip` unzips to) or the `.zip` itself, loaded **once** and indexed by
//! package name via the shared [`osv`] feeder scaffolding.
//!
//! Hex advisory ranges are `SEMVER`-typed and Hex versions are plain SemVer, so this reuses
//! `fleetreach_core::semver::Version` directly (no bespoke comparator, like npm/Swift). Hex
//! package names are lowercase and matched verbatim.

use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Match, OsvDb, ParsedRange, Spec};
use fleetreach_core::semver::Version;

use crate::error::HexError;

/// The filesystem path of an offline (`file://`) DB mirror, or `None` for anything else.
///
/// # Examples
///
/// ```
/// use fleetreach_hex::hex_db_path;
/// use std::path::PathBuf;
///
/// assert_eq!(hex_db_path("file:///opt/hex/all.zip"), Some(PathBuf::from("/opt/hex/all.zip")));
/// assert_eq!(hex_db_path("https://osv.dev"), None);
/// ```
pub fn hex_db_path(db: &str) -> Option<PathBuf> {
    db.strip_prefix("file://").map(PathBuf::from)
}

/// One advisory's facts for a single affected Hex package (see [`osv::Advisory`]).
pub type Advisory = osv::Advisory<Version>;

/// The per-ecosystem knobs the shared loader needs for the Hex OSV export. Names are kept
/// verbatim (Hex names are lowercase); ranges are `SEMVER`-typed.
fn spec() -> Spec<Version> {
    Spec {
        ecosystem: "Hex",
        range_type: "SEMVER",
        parse_version: parse_bound,
        normalize_name: |name| name.to_string(),
        use_versions: true,
        severity: osv::default_severity,
    }
}

/// The offline Hex OSV DB: `package name → advisories affecting it` (verbatim names).
#[derive(Debug, Default)]
pub struct HexDb(OsvDb<Version>);

impl HexDb {
    /// Load the OSV mirror at `root`, a directory of `*.json` records or the export `.zip`.
    ///
    /// # Errors
    ///
    /// Returns [`HexError::Db`] if `root` cannot be read, the archive cannot be decompressed,
    /// or a record is not valid JSON — failing closed.
    pub fn load(root: &Path) -> Result<HexDb, HexError> {
        osv::load(root, &spec())
            .map(HexDb)
            .map_err(|e| HexError::db(e.path, e.source))
    }

    /// The advisories indexed under `package` (verbatim), or an empty slice if none.
    pub fn advisories_for(&self, package: &str) -> &[Advisory] {
        self.0.advisories_for(package)
    }

    /// Total advisory-package index entries — for diagnostics/tests.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the DB indexed no Hex advisories at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Evaluate the advisory's `SEMVER` ranges for `version` (the shared
/// [`osv::affected_fixed_parsed`] skeleton + Hex's plain-SemVer bounds; Hex versions order
/// normally, so the `introduced` comparison is a plain `>=`).
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
        let r = ranges(&[("introduced", "1.5.0"), ("fixed", "1.15.5")]);
        assert_eq!(
            affected_fixed(&v("1.6.2"), &r),
            Match::Affected {
                fixed: Some(v("1.15.5"))
            }
        );
        assert_eq!(affected_fixed(&v("1.15.5"), &r), Match::NotAffected);
    }

    #[test]
    fn prerelease_bounds_handled() {
        let r = ranges(&[("introduced", "5.0.0-rc.0"), ("fixed", "5.0.0-rc.10")]);
        assert_eq!(
            affected_fixed(&v("5.0.0-rc.5"), &r),
            Match::Affected {
                fixed: Some(v("5.0.0-rc.10"))
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
    fn indexes_hex_verbatim() {
        let json = r#"{
          "id": "GHSA-hx-1",
          "summary": "issue in hackney",
          "database_specific": { "severity": "HIGH" },
          "affected": [
            { "package": { "ecosystem": "Hex", "name": "hackney" },
              "ranges": [ { "type": "SEMVER", "events": [ {"introduced":"0"}, {"fixed":"1.15.2"} ] } ] },
            { "package": { "ecosystem": "npm", "name": "x" }, "ranges": [] }
          ]
        }"#;
        let osv: OsvRecord = serde_json::from_str(json).unwrap();
        let pairs = osv::advisories_from(osv, &spec());
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "hackney");
        assert_eq!(pairs[0].1.severity, Severity::High);
    }

    #[test]
    fn hex_db_path_only_file_urls() {
        assert_eq!(
            hex_db_path("file:///opt/db"),
            Some(PathBuf::from("/opt/db"))
        );
        assert_eq!(hex_db_path("https://osv.dev"), None);
    }
}
