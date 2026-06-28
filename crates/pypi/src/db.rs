//! The offline OSV vulnerability DB for PyPI: a directory of OSV JSON records (exactly
//! what OSV.dev's `PyPI/all.zip` unzips to) or the `.zip` itself, loaded **once** and
//! indexed by [PEP 503]-normalized package name via the shared [`osv`] feeder scaffolding.
//!
//! PyPI advisory ranges are `ECOSYSTEM`-typed; bounds are PEP 440 versions, parsed by
//! [`parse_bound`] (which wraps [`crate::parse_pypi_version`] and the `"0"` convention) and
//! compared with PEP 440's own ordering. PyPI records often enumerate affected `versions`
//! instead of a range, so [`Spec::use_versions`] is `true`.
//!
//! [PEP 503]: https://peps.python.org/pep-0503/#normalized-names

use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Match, OsvDb, ParsedRange, Spec};

use crate::error::PyPiError;
use crate::version::normalize_name as pep503_normalize;
use crate::version::{parse_pypi_version, Version};

/// The filesystem path of an offline (`file://`) DB mirror, or `None` for anything else.
/// The path may be the osv.dev export `PyPI/all.zip` or a directory of unzipped OSV
/// records — [`PyPiDb::load`] handles either. Mirrors the npm feeder's `npm_db_path`.
///
/// # Examples
///
/// ```
/// use fleetreach_pypi::pypi_db_path;
/// use std::path::PathBuf;
///
/// assert_eq!(pypi_db_path("file:///opt/pypi/all.zip"), Some(PathBuf::from("/opt/pypi/all.zip")));
/// assert_eq!(pypi_db_path("https://osv.dev"), None);
/// ```
pub fn pypi_db_path(db: &str) -> Option<PathBuf> {
    db.strip_prefix("file://").map(PathBuf::from)
}

/// One advisory's facts for a single affected PyPI package (see [`osv::Advisory`]). One OSV
/// record contributes one [`Advisory`] per PyPI `affected[]` entry (an advisory affecting
/// two packages indexes under both names). PyPI records often enumerate affected `versions`
/// instead of a range, so [`osv::Advisory::versions`] is load-bearing here.
pub type Advisory = osv::Advisory<Version>;

/// The per-ecosystem knobs the shared loader needs for the PyPI OSV export. Package names are
/// PEP 503-normalized into the index key; ranges are `ECOSYSTEM`-typed; the enumerated
/// `versions` are collected (PyPI records frequently list versions instead of a range).
fn spec() -> Spec<Version> {
    Spec {
        ecosystem: "PyPI",
        range_type: "ECOSYSTEM",
        parse_version: parse_bound,
        normalize_name: pep503_normalize,
        use_versions: true,
        severity: osv::default_severity,
    }
}

/// The offline PyPI OSV DB: `normalized package name → advisories affecting it`.
#[derive(Debug, Default)]
pub struct PyPiDb(OsvDb<Version>);

impl PyPiDb {
    /// Load the OSV mirror at `root`, which may be **either** a directory of `*.json`
    /// records **or** the osv.dev export `.zip` directly. Each PyPI `affected` package is
    /// indexed by its PEP 503-normalized name; non-`.json` entries and records with no
    /// PyPI package are ignored; a present-but-malformed JSON record is a hard error (a
    /// corrupt mirror must not silently drop advisories).
    ///
    /// # Errors
    ///
    /// Returns [`PyPiError::Db`] if `root` cannot be read, the archive cannot be
    /// decompressed, or a record is not valid JSON — failing closed, so a broken mirror
    /// is an honest gap.
    pub fn load(root: &Path) -> Result<PyPiDb, PyPiError> {
        osv::load(root, &spec())
            .map(PyPiDb)
            .map_err(|e| PyPiError::db(e.path, e.source))
    }

    /// The advisories indexed under `normalized_name` (already PEP 503-normalized by the
    /// caller), or an empty slice if none.
    pub fn advisories_for(&self, normalized_name: &str) -> &[Advisory] {
        self.0.advisories_for(normalized_name)
    }

    /// Total advisory-package index entries — for diagnostics/tests.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the DB indexed no PyPI advisories at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Evaluate the advisory's `ECOSYSTEM` ranges for a PEP 440 `version` (the shared
/// [`osv::affected_fixed_parsed`] skeleton + PEP 440 bounds; PEP 440 versions order per their
/// own `Ord`, so the `introduced` comparison is a plain `>=`, like npm and unlike Go's
/// pseudo-version case).
pub(crate) fn affected_fixed(version: &Version, ranges: &[ParsedRange<Version>]) -> Match<Version> {
    osv::affected_fixed_parsed(version, ranges, |ver, bound| ver >= bound)
}

/// Parse an OSV range bound. `"0"` (the near-universal lower bound) parses fine as PEP
/// 440, but is kept explicit for clarity; anything else goes through the PEP 440 parser.
pub(crate) fn parse_bound(raw: &str) -> Option<Version> {
    parse_pypi_version(raw)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use fleetreach_core::osv::{Event, OsvRecord, Range};
    use fleetreach_core::Severity;

    fn v(s: &str) -> Version {
        parse_pypi_version(s).unwrap()
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
        let r = ranges(&[("introduced", "0"), ("fixed", "2.31.0")]);
        assert_eq!(
            affected_fixed(&v("2.30.0"), &r),
            Match::Affected {
                fixed: Some(v("2.31.0"))
            }
        );
        assert_eq!(affected_fixed(&v("2.31.0"), &r), Match::NotAffected);
    }

    #[test]
    fn pep440_prerelease_and_post_handled() {
        // a1 is below 1.0; in [0, 1.0) it is affected. post1 is above 1.0; not affected.
        let r = ranges(&[("introduced", "0"), ("fixed", "1.0")]);
        assert_eq!(
            affected_fixed(&v("1.0a1"), &r),
            Match::Affected {
                fixed: Some(v("1.0"))
            }
        );
        assert_eq!(affected_fixed(&v("1.0.post1"), &r), Match::NotAffected);
    }

    #[test]
    fn epoch_dominates_in_matching() {
        // 1!0.1 (epoch 1) is far above 2.0 (epoch 0): a [0, 2.0) window excludes it.
        let r = ranges(&[("introduced", "0"), ("fixed", "2.0")]);
        assert_eq!(affected_fixed(&v("1!0.1"), &r), Match::NotAffected);
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
            parse_bound,
        )];
        assert_eq!(affected_fixed(&v("1.0"), &r), Match::NotAffected);
    }

    #[test]
    fn indexes_pypi_affected_normalized_with_band() {
        let json = r#"{
          "id": "GHSA-pypi-0001",
          "aliases": ["CVE-2020-0001"],
          "summary": "issue in Flask",
          "database_specific": { "severity": "HIGH" },
          "affected": [
            { "package": { "ecosystem": "PyPI", "name": "Flask" },
              "ranges": [ { "type": "ECOSYSTEM", "events": [ {"introduced":"0"}, {"fixed":"2.0.0"} ] } ] },
            { "package": { "ecosystem": "npm", "name": "ignored" }, "ranges": [] }
          ]
        }"#;
        let osv: OsvRecord = serde_json::from_str(json).unwrap();
        let pairs = osv::advisories_from(osv, &spec());
        assert_eq!(pairs.len(), 1, "only the PyPI affected entry");
        let (name, adv) = &pairs[0];
        assert_eq!(name, "flask", "indexed under the normalized name");
        assert_eq!(adv.severity, Severity::High);
        assert_eq!(adv.cvss_score, None);
        assert_eq!(adv.aliases, vec!["CVE-2020-0001"]);
    }

    #[test]
    fn cvss_vector_supplies_score_and_band_when_no_label() {
        let json = r#"{
          "id": "PYSEC-2021-1",
          "summary": "no GHSA band, only a CVSS vector",
          "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } ],
          "affected": [
            { "package": { "ecosystem": "PyPI", "name": "requests" },
              "ranges": [ { "type": "ECOSYSTEM", "events": [ {"introduced":"0"} ] } ] }
          ]
        }"#;
        let osv: OsvRecord = serde_json::from_str(json).unwrap();
        let (_, adv) = &osv::advisories_from(osv, &spec())[0];
        assert_eq!(
            adv.severity,
            Severity::Critical,
            "band derived from the vector"
        );
        assert!((adv.cvss_score.unwrap() - 9.8).abs() < 0.05);
    }

    #[test]
    fn pypi_db_path_only_file_urls() {
        assert_eq!(
            pypi_db_path("file:///opt/pypidb"),
            Some(PathBuf::from("/opt/pypidb"))
        );
        assert_eq!(pypi_db_path("https://osv.dev"), None);
        assert_eq!(pypi_db_path("/bare/path"), None);
    }
}
