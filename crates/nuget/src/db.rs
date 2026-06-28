//! The offline OSV vulnerability DB for NuGet: a directory of OSV JSON records (exactly what
//! OSV.dev's `NuGet/all.zip` unzips to) or the `.zip` itself, loaded **once** and indexed by
//! lowercased package id via the shared [`osv`] feeder scaffolding.
//!
//! NuGet advisory ranges are `ECOSYSTEM`-typed; bounds are NuGet versions, parsed by
//! [`crate::parse_nuget_version`]. Package ids are case-insensitive, so they are lowercased.

use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Match, OsvDb, ParsedRange, Spec};

use crate::error::NuGetError;
use crate::version::{parse_nuget_version, Version};

/// The filesystem path of an offline (`file://`) DB mirror, or `None` for anything else. The
/// path may be the osv.dev export `NuGet/all.zip` or a directory of unzipped OSV records —
/// [`NuGetDb::load`] handles either.
///
/// # Examples
///
/// ```
/// use fleetreach_nuget::nuget_db_path;
/// use std::path::PathBuf;
///
/// assert_eq!(nuget_db_path("file:///opt/nuget/all.zip"), Some(PathBuf::from("/opt/nuget/all.zip")));
/// assert_eq!(nuget_db_path("https://osv.dev"), None);
/// ```
pub fn nuget_db_path(db: &str) -> Option<PathBuf> {
    db.strip_prefix("file://").map(PathBuf::from)
}

/// One advisory's facts for a single affected NuGet package (see [`osv::Advisory`]).
pub type Advisory = osv::Advisory<Version>;

/// The per-ecosystem knobs the shared loader needs for the NuGet OSV export. Package ids are
/// lowercased (NuGet ids are case-insensitive); ranges are `ECOSYSTEM`-typed.
fn spec() -> Spec<Version> {
    Spec {
        ecosystem: "NuGet",
        range_type: "ECOSYSTEM",
        parse_version: parse_nuget_version,
        normalize_name: |name| name.to_ascii_lowercase(),
        use_versions: true,
        severity: osv::default_severity,
    }
}

/// The offline NuGet OSV DB: `package id (lowercase) → advisories affecting it`.
#[derive(Debug, Default)]
pub struct NuGetDb(OsvDb<Version>);

impl NuGetDb {
    /// Load the OSV mirror at `root`, which may be **either** a directory of `*.json` records
    /// **or** the osv.dev export `.zip` directly. Each NuGet `affected` package is indexed by
    /// its lowercase id; non-`.json` entries and records with no `NuGet` package are ignored;
    /// a present-but-malformed JSON record is a hard error.
    ///
    /// # Errors
    ///
    /// Returns [`NuGetError::Db`] if `root` cannot be read, the archive cannot be
    /// decompressed, or a record is not valid JSON — failing closed.
    pub fn load(root: &Path) -> Result<NuGetDb, NuGetError> {
        osv::load(root, &spec())
            .map(NuGetDb)
            .map_err(|e| NuGetError::db(e.path, e.source))
    }

    /// The advisories indexed under `package` (matched case-insensitively — pass any case, it
    /// is lowercased here), or an empty slice if none.
    pub fn advisories_for(&self, package: &str) -> &[Advisory] {
        self.0.advisories_for(&package.to_ascii_lowercase())
    }

    /// Total advisory-package index entries — for diagnostics/tests.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the DB indexed no NuGet advisories at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Evaluate the advisory's `ECOSYSTEM` ranges for a NuGet [`Version`] (the shared
/// [`osv::affected_fixed_parsed`] skeleton + NuGet bounds). NuGet excludes prereleases from a
/// stable bound (`[1.0.0,)` does not match `1.0.0-rc1`), so — unlike Composer — the
/// `introduced` comparison is a plain `>=`, like npm/PyPI/RubyGems.
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
        parse_nuget_version(s).unwrap()
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
        vec![osv::parse_range(&range, parse_nuget_version)]
    }

    #[test]
    fn affected_below_fix_reports_patch() {
        let r = ranges(&[("introduced", "0"), ("fixed", "13.0.1")]);
        assert_eq!(
            affected_fixed(&v("12.0.3"), &r),
            Match::Affected {
                fixed: Some(v("13.0.1"))
            }
        );
        assert_eq!(affected_fixed(&v("13.0.1"), &r), Match::NotAffected);
    }

    #[test]
    fn prerelease_excluded_from_stable_introduced_bound() {
        // Unlike Composer, NuGet's `>=1.0.0` does NOT include 1.0.0-rc1 (it orders below).
        let r = ranges(&[("introduced", "1.0.0"), ("fixed", "2.0.0")]);
        assert_eq!(affected_fixed(&v("1.0.0-rc1"), &r), Match::NotAffected);
        assert_eq!(
            affected_fixed(&v("1.0.0"), &r),
            Match::Affected {
                fixed: Some(v("2.0.0"))
            }
        );
    }

    #[test]
    fn malformed_introduced_fails_loud() {
        let r = ranges(&[("introduced", "garbage"), ("fixed", "99.0")]);
        assert_eq!(
            affected_fixed(&v("1.0"), &r),
            Match::Affected {
                fixed: Some(v("99.0"))
            },
            "unparseable introduced must read affected, never clean"
        );
    }

    #[test]
    fn indexes_nuget_affected_lowercased() {
        let json = r#"{
          "id": "GHSA-ng-0001",
          "aliases": ["CVE-2020-0001"],
          "summary": "issue in Newtonsoft.Json",
          "database_specific": { "severity": "HIGH" },
          "affected": [
            { "package": { "ecosystem": "NuGet", "name": "Newtonsoft.Json" },
              "ranges": [ { "type": "ECOSYSTEM", "events": [ {"introduced":"0"}, {"fixed":"13.0.1"} ] } ] },
            { "package": { "ecosystem": "npm", "name": "ignored" }, "ranges": [] }
          ]
        }"#;
        let osv: OsvRecord = serde_json::from_str(json).unwrap();
        let pairs = osv::advisories_from(osv, &spec());
        assert_eq!(pairs.len(), 1, "only the NuGet affected entry");
        let (name, adv) = &pairs[0];
        assert_eq!(name, "newtonsoft.json", "indexed under the lowercase id");
        assert_eq!(adv.severity, Severity::High);
    }

    #[test]
    fn cvss_vector_supplies_score_and_band() {
        let json = r#"{
          "id": "GHSA-ng-0002",
          "summary": "cvss only",
          "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } ],
          "affected": [
            { "package": { "ecosystem": "NuGet", "name": "pkg" },
              "ranges": [ { "type": "ECOSYSTEM", "events": [ {"introduced":"0"} ] } ] }
          ]
        }"#;
        let osv: OsvRecord = serde_json::from_str(json).unwrap();
        let pairs = osv::advisories_from(osv, &spec());
        let (_, adv) = &pairs[0];
        assert_eq!(adv.severity, Severity::Critical);
        assert!((adv.cvss_score.unwrap() - 9.8).abs() < 0.05);
    }

    #[test]
    fn nuget_db_path_only_file_urls() {
        assert_eq!(
            nuget_db_path("file:///opt/db"),
            Some(PathBuf::from("/opt/db"))
        );
        assert_eq!(nuget_db_path("https://osv.dev"), None);
    }
}
