//! The offline OSV vulnerability DB for npm: a directory of OSV JSON records (exactly
//! what OSV.dev's `npm/all.zip` unzips to) or the `.zip` itself, loaded **once** and
//! indexed by package name via the shared [`osv`] feeder scaffolding.
//!
//! npm advisory ranges are `SEMVER`-typed; bounds are plain SemVer versions, parsed by
//! [`parse_bound`] and compared with normal SemVer ordering. Severity comes from the
//! GitHub Advisory Database band (`database_specific.severity`) only.

use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Match, OsvDb, ParsedRange, Spec};
use fleetreach_core::semver::Version;
use fleetreach_core::Severity;

use crate::error::NpmError;

/// The filesystem path of an offline (`file://`) DB mirror, or `None` for anything
/// else. The path may be the osv.dev export `all.zip` or a directory of unzipped OSV
/// records — [`NpmDb::load`] handles either. Mirrors the Go feeder's `offline_db_path`.
///
/// # Examples
///
/// ```
/// use fleetreach_npm::npm_db_path;
/// use std::path::PathBuf;
///
/// assert_eq!(npm_db_path("file:///opt/npm/all.zip"), Some(PathBuf::from("/opt/npm/all.zip")));
/// assert_eq!(npm_db_path("https://osv.dev"), None);
/// ```
pub fn npm_db_path(db: &str) -> Option<PathBuf> {
    db.strip_prefix("file://").map(PathBuf::from)
}

/// One advisory's facts for a single affected npm package (see [`osv::Advisory`]).
pub type Advisory = osv::Advisory<Version>;

/// The per-ecosystem knobs the shared loader needs for the npm OSV export. Package names
/// are kept verbatim; ranges are `SEMVER`-typed; severity is the GHSA band only.
fn spec() -> Spec<Version> {
    Spec {
        ecosystem: "npm",
        range_type: "SEMVER",
        parse_version: parse_bound,
        normalize_name: |name| name.to_string(),
        use_versions: false,
        severity: npm_severity,
    }
}

/// The offline npm OSV DB: `package name → advisories affecting it`.
#[derive(Debug, Default)]
pub struct NpmDb(OsvDb<Version>);

impl NpmDb {
    /// Load the OSV mirror at `root`, which may be **either** a directory of `*.json`
    /// records **or** the osv.dev export `.zip` directly. Each npm `affected` package is
    /// indexed by name; non-`.json` entries and records with no npm package are ignored;
    /// a present-but-malformed JSON record is a hard error (a corrupt mirror must not
    /// silently drop advisories).
    ///
    /// # Errors
    ///
    /// Returns [`NpmError::Db`] if `root` cannot be read, the archive cannot be
    /// decompressed, or a record is not valid JSON — failing closed, so a broken mirror
    /// is an honest gap.
    pub fn load(root: &Path) -> Result<NpmDb, NpmError> {
        osv::load(root, &spec())
            .map(NpmDb)
            .map_err(|e| NpmError::db(e.path, e.source))
    }

    /// The advisories indexed under `package`, or an empty slice if none.
    pub fn advisories_for(&self, package: &str) -> &[Advisory] {
        self.0.advisories_for(package)
    }

    /// Total advisory-package index entries — for diagnostics/tests.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the DB indexed no npm advisories at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// npm's `(severity, cvss_score)` derivation: the GitHub Advisory Database band only
/// (never the CVSS_V3 score), so npm findings carry no numeric score.
fn npm_severity(osv: &osv::OsvRecord) -> (Severity, Option<f32>) {
    (severity_from_osv(osv), None)
}

/// Map a GHSA/OSV severity band (`database_specific.severity`) onto our [`Severity`].
/// npm OSV records (GitHub Advisory Database) carry this string, so npm findings get a
/// real band rather than the all-`Unknown` the Go Tier-C is stuck with.
fn severity_from_osv(osv: &osv::OsvRecord) -> Severity {
    match osv
        .database_specific
        .as_ref()
        .and_then(|d| d.severity.as_deref())
        .map(str::to_ascii_uppercase)
        .as_deref()
    {
        Some("LOW") => Severity::Low,
        Some("MODERATE") | Some("MEDIUM") => Severity::Medium,
        Some("HIGH") => Severity::High,
        Some("CRITICAL") => Severity::Critical,
        _ => Severity::Unknown,
    }
}

/// Evaluate the advisory's SEMVER ranges for `version` with npm's plain-SemVer bounds
/// (the shared [`osv::affected_fixed_parsed`] skeleton + npm's [`parse_bound`]; npm
/// versions order normally, so the `introduced` comparison is a plain `>=`, unlike Go's
/// pseudo-version case).
pub(crate) fn affected_fixed(version: &Version, ranges: &[ParsedRange<Version>]) -> Match<Version> {
    osv::affected_fixed_parsed(version, ranges, |ver, bound| ver >= bound)
}

/// Parse an OSV range bound. `"0"` (the near-universal lower bound) is not valid SemVer,
/// so map it to `0.0.0`; a leading `v` (rare in npm OSV) is tolerated.
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

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
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
        let r = ranges(&[("introduced", "0"), ("fixed", "4.17.21")]);
        assert_eq!(
            affected_fixed(&v("4.17.20"), &r),
            Match::Affected {
                fixed: Some(v("4.17.21"))
            }
        );
    }

    #[test]
    fn not_affected_at_or_above_fix() {
        let r = ranges(&[("introduced", "0"), ("fixed", "4.17.21")]);
        assert_eq!(affected_fixed(&v("4.17.21"), &r), Match::NotAffected);
        assert_eq!(affected_fixed(&v("5.0.0"), &r), Match::NotAffected);
    }

    #[test]
    fn windowed_introduced_excludes_older() {
        let r = ranges(&[("introduced", "1.2.0"), ("fixed", "1.2.5")]);
        assert_eq!(affected_fixed(&v("1.1.0"), &r), Match::NotAffected);
        assert_eq!(
            affected_fixed(&v("1.2.3"), &r),
            Match::Affected {
                fixed: Some(v("1.2.5"))
            }
        );
    }

    #[test]
    fn prerelease_orders_below_release() {
        // npm pre-releases order below the release (standard SemVer): 1.2.0-rc.1 is in
        // [0, 1.2.5) and must be flagged; 1.2.5 itself is clean.
        let r = ranges(&[("introduced", "0"), ("fixed", "1.2.5")]);
        assert_eq!(
            affected_fixed(&v("1.2.0-rc.1"), &r),
            Match::Affected {
                fixed: Some(v("1.2.5"))
            }
        );
        assert_eq!(affected_fixed(&v("1.2.5"), &r), Match::NotAffected);
    }

    #[test]
    fn last_affected_without_fix() {
        let r = ranges(&[("introduced", "1.0.0"), ("last_affected", "1.4.0")]);
        assert_eq!(
            affected_fixed(&v("1.3.0"), &r),
            Match::Affected { fixed: None }
        );
        assert_eq!(affected_fixed(&v("1.5.0"), &r), Match::NotAffected);
    }

    #[test]
    fn malformed_introduced_fails_loud() {
        let r = ranges(&[("introduced", "garbage"), ("fixed", "99.0.0")]);
        assert_eq!(
            affected_fixed(&v("1.0.0"), &r),
            Match::Affected {
                fixed: Some(v("99.0.0"))
            },
            "unparseable introduced must be affected, not silently clean"
        );
        // No introduced event at all is introduced-at-0 (OSV convention).
        let no_intro = vec![osv::parse_range(
            &Range {
                matchable: true,
                events: vec![Event {
                    introduced: None,
                    fixed: Some("2.0.0".into()),
                    last_affected: None,
                }],
            },
            parse_bound,
        )];
        assert_eq!(
            affected_fixed(&v("1.5.0"), &no_intro),
            Match::Affected {
                fixed: Some(v("2.0.0"))
            }
        );
    }

    #[test]
    fn non_semver_ranges_are_skipped() {
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
        assert_eq!(affected_fixed(&v("1.0.0"), &r), Match::NotAffected);
    }

    #[test]
    fn indexes_npm_affected_and_maps_severity() {
        let json = r#"{
          "id": "GHSA-test-0001",
          "aliases": ["CVE-2020-0001"],
          "summary": "Prototype pollution in lodash",
          "database_specific": { "severity": "HIGH" },
          "affected": [
            { "package": { "ecosystem": "npm", "name": "lodash" },
              "ranges": [ { "type": "SEMVER", "events": [ {"introduced":"0"}, {"fixed":"4.17.21"} ] } ] },
            { "package": { "ecosystem": "PyPI", "name": "ignored" }, "ranges": [] }
          ]
        }"#;
        let osv: OsvRecord = serde_json::from_str(json).unwrap();
        let pairs = osv::advisories_from(osv, &spec());
        // One npm affected entry (lodash); the PyPI one is filtered out.
        assert_eq!(pairs.len(), 1);
        let (name, adv) = &pairs[0];
        assert_eq!(name, "lodash");
        assert_eq!(adv.severity, Severity::High);
        assert_eq!(adv.cvss_score, None);
        assert_eq!(adv.aliases, vec!["CVE-2020-0001"]);
    }

    #[test]
    fn npm_db_path_only_file_urls() {
        assert_eq!(
            npm_db_path("file:///opt/npmdb"),
            Some(PathBuf::from("/opt/npmdb"))
        );
        assert_eq!(npm_db_path("https://osv.dev"), None);
        assert_eq!(npm_db_path("/bare/path"), None);
    }
}
