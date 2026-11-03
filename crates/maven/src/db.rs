//! The offline OSV vulnerability DB for Maven: a directory of OSV JSON records (exactly what
//! OSV.dev's `Maven/all.zip` unzips to) or the `.zip` itself, loaded **once** and indexed by
//! `group:artifact` coordinate via the shared [`osv`] feeder scaffolding.
//!
//! Maven advisory ranges are `ECOSYSTEM`-typed; bounds are Maven versions, parsed by
//! [`crate::parse_maven_version`] and compared with Maven's `ComparableVersion` ordering.

use std::collections::BTreeMap;
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

/// Where a jar with an artifact name but no group belongs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Group<'a> {
    /// No advisory names this artifact in any group: nothing to match.
    NoAdvisories,
    /// One coordinate fits the jar's class packages.
    Settled(&'a str),
    /// Advisories name the artifact, and the class packages do not single one out: a
    /// coverage gap, never a guess.
    Unsettled,
}

/// Whether an OSGi bundle name is `group`, or starts with it as a name: `com.h2database` and
/// `org.apache.tomcat-catalina` for `org.apache.tomcat`.
fn bundle_in_group(bundle: &str, coordinate: &str) -> bool {
    let group = coordinate.split(':').next().unwrap_or_default();
    bundle
        .strip_prefix(group)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '-']))
}

/// The coordinate of an OSGi bundle with no file name to go on, from the coordinates with
/// advisories (`artifacts`, from [`MavenDb::artifacts`]): the last word of the bundle name is
/// the artifact and the name starts with its group (`org.apache.tomcat-catalina` is
/// `org.apache.tomcat:tomcat-catalina`). `None` says nothing about the bundle: names do not
/// always follow its coordinates.
pub fn settle_bundle<'a>(
    artifacts: &BTreeMap<&str, Vec<&'a str>>,
    bundle: &str,
) -> Option<&'a str> {
    let artifact = bundle.rsplit('.').next().unwrap_or(bundle);
    let fits: Vec<&'a str> = artifacts
        .get(artifact)?
        .iter()
        .copied()
        .filter(|c| bundle_in_group(bundle, c))
        .collect();
    match fits[..] {
        [one] => Some(one),
        _ => None,
    }
}

/// Settle a jar's group from `candidates` (the coordinates with advisories that share its
/// artifact name, from [`MavenDb::artifacts`]), first by its OSGi `bundle` name, then by its
/// class `packages` (`org/springframework`): a candidate fits when a package word other than
/// a top-level domain is a word of its group (`okhttp3` in `com.squareup.okhttp3`). Of several
/// that fit, one whose whole group is a package wins (`org.dom4j:dom4j` over `dom4j:dom4j`).
pub fn settle_group<'a>(
    candidates: &[&'a str],
    packages: &[String],
    bundle: Option<&str>,
) -> Group<'a> {
    const DOMAINS: &[&str] = &["com", "org", "net", "io", "edu", "gov", "de", "uk", "fr"];
    if candidates.is_empty() {
        return Group::NoAdvisories;
    }
    if let Some(bundle) = bundle {
        let named: Vec<&'a str> = candidates
            .iter()
            .copied()
            .filter(|c| bundle_in_group(bundle, c))
            .collect();
        if let [one] = named[..] {
            return Group::Settled(one);
        }
    }
    let words: Vec<&str> = packages
        .iter()
        .flat_map(|p| p.split('/'))
        .filter(|w| !DOMAINS.contains(w))
        .collect();
    let fits: Vec<&'a str> = candidates
        .iter()
        .copied()
        .filter(|c| {
            let group = c.split(':').next().unwrap_or_default();
            group.split('.').any(|g| words.contains(&g))
        })
        .collect();
    let whole: Vec<&'a str> = fits
        .iter()
        .copied()
        .filter(|c| {
            let group = c.split(':').next().unwrap_or_default().replace('.', "/");
            packages.contains(&group)
        })
        .collect();
    match (&fits[..], &whole[..]) {
        ([one], _) | (_, [one]) => Group::Settled(one),
        _ => Group::Unsettled,
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

    /// [`MavenDb::load`] with an organization's own OSV records from `overlay` layered on top:
    /// a record with an upstream id replaces it, a new id adds one, a withdrawn one retracts
    /// (see [`osv::load_with_overlay`]).
    ///
    /// # Errors
    ///
    /// As [`MavenDb::load`], plus an unreadable overlay directory or an overlay record that is
    /// not valid OSV JSON.
    pub fn load_with_overlay(root: &Path, overlay: Option<&Path>) -> Result<MavenDb, MavenError> {
        osv::load_with_overlay(root, overlay, &spec())
            .map(MavenDb)
            .map_err(|e| MavenError::db(e.path, e.source))
    }

    /// Every `(package key, advisory)` pair, in key order (for `db quality`).
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Advisory)> {
        self.0.iter()
    }

    /// The advisories indexed under `coordinate` (`group:artifact`, verbatim), or an empty
    /// slice if none.
    pub fn advisories_for(&self, coordinate: &str) -> &[Advisory] {
        self.0.advisories_for(coordinate)
    }

    /// The coordinates with advisories, by artifact name, for placing a jar known only by its
    /// file name (see [`settle_group`]).
    pub fn artifacts(&self) -> BTreeMap<&str, Vec<&str>> {
        let mut out: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (coordinate, _) in self.0.iter() {
            if let Some((_, artifact)) = coordinate.split_once(':') {
                let at = out.entry(artifact).or_default();
                if at.last() != Some(&coordinate) {
                    at.push(coordinate);
                }
            }
        }
        out
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

    #[test]
    fn a_group_needs_evidence_from_the_jars_classes() {
        let packages = |p: &[&str]| p.iter().map(ToString::to_string).collect::<Vec<_>>();
        let spring = "org.springframework:spring-core";
        assert_eq!(settle_group(&[], &[], None), Group::NoAdvisories);
        assert_eq!(
            settle_group(&[spring], &packages(&["org/springframework"]), None),
            Group::Settled(spring)
        );
        // A class package need not be the group: `okhttp3` in `com.squareup.okhttp3`.
        let okhttp = "com.squareup.okhttp3:okhttp";
        assert_eq!(
            settle_group(&[okhttp], &packages(&["okhttp3"]), None),
            Group::Settled(okhttp)
        );
        // A jar of the same name and other classes, or none: not placed.
        assert_eq!(
            settle_group(&["com.foo:core"], &packages(&["com/acme"]), None),
            Group::Unsettled
        );
        assert_eq!(settle_group(&[spring], &[], None), Group::Unsettled);
        // Top-level domains are no evidence, and two that fit are a gap, not a guess.
        assert_eq!(
            settle_group(&["org.a:core"], &packages(&["org/b"]), None),
            Group::Unsettled
        );
        assert_eq!(
            settle_group(
                &["org.a.x:core", "org.a.y:core"],
                &packages(&["org/a"]),
                None
            ),
            Group::Unsettled
        );
        // A class package that is the whole group beats one that shares a word with it.
        assert_eq!(
            settle_group(
                &["dom4j:dom4j", "org.dom4j:dom4j"],
                &packages(&["org/dom4j"]),
                None
            ),
            Group::Settled("org.dom4j:dom4j")
        );
        // The bundle name goes first: h2's classes are `org/h2`, its group `com.h2database`.
        assert_eq!(
            settle_group(
                &["com.h2database:h2"],
                &packages(&["org/h2"]),
                Some("com.h2database")
            ),
            Group::Settled("com.h2database:h2")
        );
    }

    #[test]
    fn a_bundle_name_finds_its_coordinate() {
        let artifacts: BTreeMap<&str, Vec<&str>> = [
            ("tomcat-catalina", vec!["org.apache.tomcat:tomcat-catalina"]),
            ("guava", vec!["com.google.guava:guava"]),
            ("core", vec!["org.other:core"]),
        ]
        .into();
        for (bundle, want) in [
            (
                "org.apache.tomcat-catalina",
                Some("org.apache.tomcat:tomcat-catalina"),
            ),
            ("com.google.guava", Some("com.google.guava:guava")),
            ("org.acme.core", None),
            ("org.acme.unknown", None),
        ] {
            assert_eq!(settle_bundle(&artifacts, bundle), want, "{bundle}");
        }
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
