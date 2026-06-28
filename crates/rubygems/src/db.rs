//! The offline OSV vulnerability DB for RubyGems: a directory of OSV JSON records (exactly
//! what OSV.dev's `RubyGems/all.zip` unzips to) or the `.zip` itself, loaded **once** and
//! indexed by gem name via the shared [`osv`] feeder scaffolding.
//!
//! RubyGems advisory ranges are `ECOSYSTEM`-typed; bounds are `Gem::Version`s, parsed by
//! [`crate::parse_rubygems_version`] and compared with `Gem::Version` ordering. Gem names
//! are kept verbatim (RubyGems names are case-sensitive).

use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Match, OsvDb, ParsedRange, Spec};

use crate::error::RubyGemsError;
use crate::version::{parse_rubygems_version, Version};

/// The filesystem path of an offline (`file://`) DB mirror, or `None` for anything else.
/// The path may be the osv.dev export `RubyGems/all.zip` or a directory of unzipped OSV
/// records — [`RubyGemsDb::load`] handles either. Mirrors the npm/PyPI feeders.
///
/// # Examples
///
/// ```
/// use fleetreach_rubygems::rubygems_db_path;
/// use std::path::PathBuf;
///
/// assert_eq!(rubygems_db_path("file:///opt/rubygems/all.zip"), Some(PathBuf::from("/opt/rubygems/all.zip")));
/// assert_eq!(rubygems_db_path("https://osv.dev"), None);
/// ```
pub fn rubygems_db_path(db: &str) -> Option<PathBuf> {
    db.strip_prefix("file://").map(PathBuf::from)
}

/// One advisory's facts for a single affected gem (see [`osv::Advisory`]).
pub type Advisory = osv::Advisory<Version>;

/// The per-ecosystem knobs the shared loader needs for the RubyGems OSV export. Gem names
/// are kept verbatim (RubyGems names are case-sensitive); ranges are `ECOSYSTEM`-typed and
/// the enumerated `versions` list is collected (some records list versions instead of a
/// range, so a range-only matcher would false-clean them).
fn spec() -> Spec<Version> {
    Spec {
        ecosystem: "RubyGems",
        range_type: "ECOSYSTEM",
        parse_version: parse_rubygems_version,
        normalize_name: |name| name.to_string(),
        use_versions: true,
        severity: osv::default_severity,
    }
}

/// The offline RubyGems OSV DB: `gem name → advisories affecting it` (verbatim names).
#[derive(Debug, Default)]
pub struct RubyGemsDb(OsvDb<Version>);

impl RubyGemsDb {
    /// Load the OSV mirror at `root`, a directory of `*.json` records or the export `.zip`.
    ///
    /// # Errors
    ///
    /// Returns [`RubyGemsError::Db`] if `root` cannot be read, the archive cannot be
    /// decompressed, or a record is not valid JSON — failing closed, so a broken mirror is
    /// an honest gap.
    pub fn load(root: &Path) -> Result<RubyGemsDb, RubyGemsError> {
        osv::load(root, &spec())
            .map(RubyGemsDb)
            .map_err(|e| RubyGemsError::db(e.path, e.source))
    }

    /// The advisories indexed under `gem` (matched verbatim), or an empty slice if none.
    pub fn advisories_for(&self, gem: &str) -> &[Advisory] {
        self.0.advisories_for(gem)
    }

    /// Total advisory-package index entries — for diagnostics/tests.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the DB indexed no RubyGems advisories at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Evaluate the advisory's `ECOSYSTEM` ranges for a `Gem::Version` (the shared
/// [`osv::affected_fixed_parsed`] skeleton + `Gem::Version` bounds; `Gem::Version`s order
/// per their own `Ord`, so the `introduced` comparison is a plain `>=`, like npm/PyPI and
/// unlike Go's pseudo-version case).
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
        parse_rubygems_version(s).unwrap()
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
        vec![osv::parse_range(&range, parse_rubygems_version)]
    }

    #[test]
    fn affected_below_fix_reports_patch() {
        let r = ranges(&[("introduced", "0"), ("fixed", "2.2.8")]);
        assert_eq!(
            affected_fixed(&v("2.2.7"), &r),
            Match::Affected {
                fixed: Some(v("2.2.8"))
            }
        );
        assert_eq!(affected_fixed(&v("2.2.8"), &r), Match::NotAffected);
    }

    #[test]
    fn prerelease_in_affected_window_is_flagged() {
        // 1.0.0.beta is below 1.0.0; in [0, 1.0.0) it is affected. A standard SemVer
        // comparator would also get this, but the Gem::Version one must too.
        let r = ranges(&[("introduced", "0"), ("fixed", "1.0.0")]);
        assert_eq!(
            affected_fixed(&v("1.0.0.beta"), &r),
            Match::Affected {
                fixed: Some(v("1.0.0"))
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
    fn non_ecosystem_ranges_are_skipped() {
        let r = vec![osv::parse_range(
            &Range {
                matchable: false,
                events: vec![Event {
                    introduced: Some("0".into()),
                    fixed: None,
                    last_affected: None,
                }],
            },
            parse_rubygems_version,
        )];
        assert_eq!(affected_fixed(&v("1.0"), &r), Match::NotAffected);
    }

    #[test]
    fn indexes_rubygems_affected_verbatim_with_band() {
        let json = r#"{
          "id": "GHSA-rg-0001",
          "aliases": ["CVE-2020-0001"],
          "summary": "issue in rack",
          "database_specific": { "severity": "HIGH" },
          "affected": [
            { "package": { "ecosystem": "RubyGems", "name": "rack" },
              "ranges": [ { "type": "ECOSYSTEM", "events": [ {"introduced":"0"}, {"fixed":"2.2.8"} ] } ] },
            { "package": { "ecosystem": "npm", "name": "ignored" }, "ranges": [] }
          ]
        }"#;
        let osv: OsvRecord = serde_json::from_str(json).unwrap();
        let pairs = osv::advisories_from(osv, &spec());
        assert_eq!(pairs.len(), 1, "only the RubyGems affected entry");
        let (name, adv) = &pairs[0];
        assert_eq!(name, "rack", "indexed under the verbatim gem name");
        assert_eq!(adv.severity, Severity::High);
        assert_eq!(adv.cvss_score, None);
        assert_eq!(adv.aliases, vec!["CVE-2020-0001"]);
    }

    #[test]
    fn cvss_vector_supplies_score_and_band_when_no_label() {
        let json = r#"{
          "id": "GHSA-rg-0002",
          "summary": "no GHSA band, only a CVSS vector",
          "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } ],
          "affected": [
            { "package": { "ecosystem": "RubyGems", "name": "nokogiri" },
              "ranges": [ { "type": "ECOSYSTEM", "events": [ {"introduced":"0"} ] } ] }
          ]
        }"#;
        let osv: OsvRecord = serde_json::from_str(json).unwrap();
        let pairs = osv::advisories_from(osv, &spec());
        let (_, adv) = &pairs[0];
        assert_eq!(adv.severity, Severity::Critical, "band derived from vector");
        assert!((adv.cvss_score.unwrap() - 9.8).abs() < 0.05);
    }

    #[test]
    fn rubygems_db_path_only_file_urls() {
        assert_eq!(
            rubygems_db_path("file:///opt/rgdb"),
            Some(PathBuf::from("/opt/rgdb"))
        );
        assert_eq!(rubygems_db_path("https://osv.dev"), None);
        assert_eq!(rubygems_db_path("/bare/path"), None);
    }
}
