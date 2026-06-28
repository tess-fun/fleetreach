//! The offline OSV vulnerability DB for Packagist: a directory of OSV JSON records (exactly
//! what OSV.dev's `Packagist/all.zip` unzips to) or the `.zip` itself, loaded **once** and
//! indexed by package name. Like the npm/PyPI/RubyGems exports it ships no prebuilt index,
//! so the index is built in memory at load time from each record's `affected[].package`.
//!
//! Only `Packagist` (the public Composer registry) `affected` entries are indexed. The
//! namespaced `Packagist:https://packages.drupal.org/8` feed — Drupal contrib modules, which
//! use Drupal's own `8.x-1.2` version scheme, not Composer versions — is **not** matched
//! here (the same stance as skipping non-registry pins); a Composer-version comparator would
//! mishandle those bounds.
//!
//! Loading is done once per scan and the resulting [`PackagistDb`] is shared read-only
//! across every repo, because re-reading the advisory set per repo would dominate the scan.

use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Match, OsvDb, ParsedRange, Spec};

use crate::error::PackagistError;
use crate::version::{parse_composer_version, Version};

/// The filesystem path of an offline (`file://`) DB mirror, or `None` for anything else.
/// The path may be the osv.dev export `Packagist/all.zip` or a directory of unzipped OSV
/// records — [`PackagistDb::load`] handles either. Mirrors the npm/PyPI/RubyGems feeders.
///
/// # Examples
///
/// ```
/// use fleetreach_packagist::packagist_db_path;
/// use std::path::PathBuf;
///
/// assert_eq!(packagist_db_path("file:///opt/packagist/all.zip"), Some(PathBuf::from("/opt/packagist/all.zip")));
/// assert_eq!(packagist_db_path("https://osv.dev"), None);
/// ```
pub fn packagist_db_path(db: &str) -> Option<PathBuf> {
    db.strip_prefix("file://").map(PathBuf::from)
}

/// One advisory's facts for a single affected package (see [`osv::Advisory`]).
pub type Advisory = osv::Advisory<Version>;

/// The per-ecosystem knobs the shared loader needs for the Packagist OSV export. Package
/// names are lowercased (Composer names are case-insensitive); ranges are `ECOSYSTEM`-typed.
fn spec() -> Spec<Version> {
    Spec {
        ecosystem: "Packagist",
        range_type: "ECOSYSTEM",
        parse_version: parse_composer_version,
        normalize_name: |name| name.to_ascii_lowercase(),
        use_versions: true,
        severity: osv::default_severity,
    }
}

/// The offline Packagist OSV DB: `package name (lowercase) → advisories affecting it`.
#[derive(Debug, Default)]
pub struct PackagistDb(OsvDb<Version>);

impl PackagistDb {
    /// Load the OSV mirror at `root`, a directory of `*.json` records or the export `.zip`.
    ///
    /// # Errors
    ///
    /// Returns [`PackagistError::Db`] if `root` cannot be read, the archive cannot be
    /// decompressed, or a record is not valid JSON — failing closed, so a broken mirror is
    /// an honest gap.
    pub fn load(root: &Path) -> Result<PackagistDb, PackagistError> {
        osv::load(root, &spec())
            .map(PackagistDb)
            .map_err(|e| PackagistError::db(e.path, e.source))
    }

    /// The advisories indexed under `package` (matched case-insensitively — pass any case,
    /// it is lowercased here), or an empty slice if none.
    pub fn advisories_for(&self, package: &str) -> &[Advisory] {
        self.0.advisories_for(&package.to_ascii_lowercase())
    }

    /// Total advisory-package index entries — for diagnostics/tests.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the DB indexed no Packagist advisories at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Evaluate the advisory's `ECOSYSTEM` ranges for a Composer [`Version`] (the shared
/// [`osv::affected_fixed`] skeleton + Composer bounds). The `introduced` comparison uses
/// Composer's constraint semantics rather than a plain `>=`: a bare `>=X` bound floors at
/// `X-dev`, so a prerelease of the introduced release (`8.7.0-rc1` for `introduced: 8.7.0`)
/// is in range — unlike PEP 440 / RubyGems. See [`Version::at_or_after_introduced`].
pub(crate) fn affected_fixed(version: &Version, ranges: &[ParsedRange<Version>]) -> Match<Version> {
    osv::affected_fixed_parsed(version, ranges, |ver, bound| {
        ver.at_or_after_introduced(bound)
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use fleetreach_core::osv::{Event, OsvRecord, Range};
    use fleetreach_core::Severity;

    fn v(s: &str) -> Version {
        parse_composer_version(s).unwrap()
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
        vec![osv::parse_range(&range, parse_composer_version)]
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
    fn magento_patch_level_above_fix_is_not_affected() {
        // The Composer-specific case: fixed at 2.4.5, installed 2.4.5-p1 is a PATCH level
        // above the release, so it must read NotAffected (a SemVer comparator would
        // false-positive it as a prerelease below 2.4.5).
        let r = ranges(&[("introduced", "0"), ("fixed", "2.4.5")]);
        assert_eq!(affected_fixed(&v("2.4.5-p1"), &r), Match::NotAffected);
        assert_eq!(
            affected_fixed(&v("2.4.4-p1"), &r),
            Match::Affected {
                fixed: Some(v("2.4.5"))
            }
        );
    }

    #[test]
    fn prerelease_at_introduced_boundary_is_affected() {
        // Composer's `>=8.7.0` includes 8.7.0-rc1 (floored at 8.7.0-dev), so a prerelease
        // pinned at the introduced boundary must not false-clean.
        let r = ranges(&[("introduced", "8.7.0"), ("fixed", "9.5.11")]);
        assert_eq!(
            affected_fixed(&v("8.7.0-rc1"), &r),
            Match::Affected {
                fixed: Some(v("9.5.11"))
            }
        );
        // A prerelease below the introduced release stays clean.
        assert_eq!(affected_fixed(&v("8.6.0-rc1"), &r), Match::NotAffected);
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
            parse_composer_version,
        )];
        assert_eq!(affected_fixed(&v("1.0"), &r), Match::NotAffected);
    }

    #[test]
    fn indexes_packagist_affected_lowercased_with_band() {
        let json = r#"{
          "id": "GHSA-pk-0001",
          "aliases": ["CVE-2020-0001"],
          "summary": "issue in monolog",
          "database_specific": { "severity": "HIGH" },
          "affected": [
            { "package": { "ecosystem": "Packagist", "name": "Monolog/Monolog" },
              "ranges": [ { "type": "ECOSYSTEM", "events": [ {"introduced":"0"}, {"fixed":"2.2.8"} ] } ] },
            { "package": { "ecosystem": "Packagist:https://packages.drupal.org/8", "name": "drupal/ignored" }, "ranges": [] },
            { "package": { "ecosystem": "npm", "name": "ignored" }, "ranges": [] }
          ]
        }"#;
        let osv: OsvRecord = serde_json::from_str(json).unwrap();
        let pairs = osv::advisories_from(osv, &spec());
        assert_eq!(pairs.len(), 1, "only the public Packagist affected entry");
        let (name, adv) = &pairs[0];
        assert_eq!(name, "monolog/monolog", "indexed under the lowercase name");
        assert_eq!(adv.severity, Severity::High);
        assert_eq!(adv.aliases, vec!["CVE-2020-0001"]);
    }

    #[test]
    fn cvss_vector_supplies_score_and_band_when_no_label() {
        let json = r#"{
          "id": "GHSA-pk-0002",
          "summary": "no GHSA band, only a CVSS vector",
          "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } ],
          "affected": [
            { "package": { "ecosystem": "Packagist", "name": "vendor/pkg" },
              "ranges": [ { "type": "ECOSYSTEM", "events": [ {"introduced":"0"} ] } ] }
          ]
        }"#;
        let osv: OsvRecord = serde_json::from_str(json).unwrap();
        let (_, adv) = &osv::advisories_from(osv, &spec())[0];
        assert_eq!(adv.severity, Severity::Critical, "band derived from vector");
        assert!((adv.cvss_score.unwrap() - 9.8).abs() < 0.05);
    }

    #[test]
    fn packagist_db_path_only_file_urls() {
        assert_eq!(
            packagist_db_path("file:///opt/pkgdb"),
            Some(PathBuf::from("/opt/pkgdb"))
        );
        assert_eq!(packagist_db_path("https://osv.dev"), None);
        assert_eq!(packagist_db_path("/bare/path"), None);
    }
}
