//! `fleetreach db quality` (spec 16, row 12): data-quality problems in the local advisory
//! data, reported instead of hidden. Each check names the record and package so a finding can
//! be checked against the source and, when it is upstream's, corrected in an overlay and
//! reported upstream.
//!
//! The checks read the data the way the matchers do: an entry the feeder cannot evaluate is
//! "unmatchable" for that feeder (npm reads only `SEMVER` ranges and ignores enumerated
//! versions), and range checks run on the bounds as the feeder parsed them, with the overlay
//! applied.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Advisory, Match, ParsedBound};
use fleetreach_core::Ecosystem;
use serde::Serialize;

use crate::cve5::{normalize_name, normalize_version, CveSummary};
use crate::osvdb;
use crate::osvrecords::{self, Record};

/// How much an issue matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// The data cannot be used as intended (an overlay record no feeder applies).
    Error,
    /// The data may produce a wrong answer (a false clean or a wrong fix).
    Warning,
    /// Worth knowing; no wrong answer follows from it alone.
    Info,
}

/// One data-quality finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Issue {
    pub check: &'static str,
    pub level: Level,
    /// The OSV ecosystem (or `overlay`).
    pub ecosystem: String,
    /// The advisory id.
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    pub detail: String,
}

/// Every check, with its level and a one-line description (for the docs and `--json`).
pub const CHECKS: &[(&str, Level, &str)] = &[
    ("unmatchable-entry", Level::Warning, "an affected package has no range or version list its feeder evaluates, so it can never match"),
    ("versions-outside-ranges", Level::Warning, "enumerated affected versions that the record's own ranges call safe"),
    ("events-out-of-order", Level::Warning, "range events whose bounds go down in the order written (the matcher walks them in order)"),
    ("unparseable-bound", Level::Warning, "an introduced bound the ecosystem's version parser rejects (matched as affected, loudly)"),
    ("alias-conflict", Level::Warning, "records for the same CVE and package that name different fixed versions"),
    ("rejected-cve-alias", Level::Warning, "a live record aliasing a CVE the CVE Program has rejected"),
    ("missing-severity", Level::Info, "no CVSS vector and no severity band (MAL- and GO- records, which never carry one, aside)"),
    ("withdrawn", Level::Info, "a withdrawn record still in the export (never matched)"),
    ("overlay-not-applied", Level::Error, "an overlay record for an ecosystem no OSV feeder layers"),
    ("overlay-stale", Level::Warning, "an overlay replaces an upstream record modified after the overlay was"),
    ("overlay-revives-withdrawn", Level::Warning, "an overlay replaces a withdrawn upstream record with a live one"),
];

fn level(check: &str) -> Level {
    CHECKS
        .iter()
        .find(|(c, _, _)| *c == check)
        .map_or(Level::Info, |(_, l, _)| *l)
}

fn issue(
    check: &'static str,
    ecosystem: &str,
    id: &str,
    package: Option<&str>,
    detail: String,
) -> Issue {
    Issue {
        check,
        level: level(check),
        ecosystem: ecosystem.to_string(),
        id: id.to_string(),
        package: package.map(str::to_string),
        detail,
    }
}

/// The range type a feeder evaluates and whether it reads enumerated versions.
fn feeder_rules(ecosystem: &str) -> Option<(&'static str, bool)> {
    Some(match ecosystem {
        "npm" => ("SEMVER", false),
        "Go" => ("SEMVER", false),
        "PyPI" | "RubyGems" | "Packagist" | "NuGet" | "GitHub Actions" | "Maven" => {
            ("ECOSYSTEM", true)
        }
        "Julia" | "SwiftURL" | "Hex" => ("SEMVER", true),
        _ => return None,
    })
}

/// Where the checks read from.
pub struct Inputs<'a> {
    /// The OSV directory (`<dir>/<Ecosystem>/all.zip`).
    pub dir: &'a Path,
    /// `[settings.advisories] dir`, if any.
    pub overlay: Option<&'a Path>,
    /// The CVE index, when synced (enables `rejected-cve-alias`).
    pub cves: Option<&'a [CveSummary]>,
}

/// Run every check.
///
/// # Errors
///
/// An unreadable export, overlay or index: the report would be incomplete, so it fails closed.
pub fn run(inputs: &Inputs) -> Result<Vec<Issue>, String> {
    let exports: Vec<&str> = osvdb::OSV_ECOSYSTEMS
        .iter()
        .filter_map(|&e| osvdb::osv_name(e))
        .collect();
    let records = osvrecords::load_dir(inputs.dir, Some(&exports))?;
    let overlay = match inputs.overlay {
        Some(dir) => {
            crate::overlay::inspect(dir)?;
            read_overlay(dir)?
        }
        None => Vec::new(),
    };
    let mut issues = Vec::new();
    overlay_checks(&records, &overlay, &mut issues);

    // The data as the feeders see it: upstream with the overlay layered on.
    let replaced: BTreeSet<&str> = overlay.iter().map(|r| r.id.as_str()).collect();
    let merged: Vec<&Record> = records
        .values()
        .map(|(_, r)| r)
        .filter(|r| !replaced.contains(r.id.as_str()))
        .chain(overlay.iter())
        .collect();
    // Go's offline matcher reads only the `GO-` records (vuln.go.dev's set); the export's
    // GHSA copies of them never reach it.
    let merged: Vec<&Record> = merged
        .into_iter()
        .filter(|r| r.id.starts_with("GO-") || !only_ecosystem(r, "Go"))
        .collect();
    record_checks(&merged, &mut issues);
    alias_conflicts(&merged, &mut issues);
    if let Some(cves) = inputs.cves {
        rejected_aliases(&merged, cves, &mut issues);
    }
    issues.extend(parsed_checks(inputs.dir, inputs.overlay)?);
    issues.sort();
    issues.dedup();
    Ok(issues)
}

fn read_overlay(dir: &Path) -> Result<Vec<Record>, String> {
    let mut paths: Vec<PathBuf> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_entry(|e| e.depth() == 0 || !e.file_name().to_string_lossy().starts_with('.'))
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(walkdir::DirEntry::into_path)
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|p| {
            let body =
                std::fs::read_to_string(p).map_err(|e| format!("reading {}: {e}", p.display()))?;
            serde_json::from_str(&body)
                .map_err(|e| format!("advisory overlay {}: {e}", p.display()))
        })
        .collect()
}

fn overlay_checks(
    upstream: &BTreeMap<String, (String, Record)>,
    overlay: &[Record],
    out: &mut Vec<Issue>,
) {
    for record in overlay {
        let mut seen = BTreeSet::new();
        for affected in &record.affected {
            let eco = affected.package.ecosystem.as_deref().unwrap_or("");
            if !crate::overlay::applied_ecosystem(eco) && seen.insert(eco) {
                out.push(issue(
                    "overlay-not-applied",
                    "overlay",
                    &record.id,
                    affected.package.name.as_deref(),
                    format!("ecosystem `{eco}` has no OSV feeder; the record changes nothing"),
                ));
            }
        }
        let Some((_, up)) = upstream.get(&record.id) else {
            continue;
        };
        if let (Some(theirs), Some(ours)) = (up.modified.as_deref(), record.modified.as_deref()) {
            // RFC 3339 in UTC compares as text.
            if theirs > ours {
                out.push(issue(
                    "overlay-stale",
                    "overlay",
                    &record.id,
                    None,
                    format!("upstream modified {theirs}, overlay {ours}: review the correction"),
                ));
            }
        }
        if up.withdrawn.is_some() && record.withdrawn.is_none() {
            out.push(issue(
                "overlay-revives-withdrawn",
                "overlay",
                &record.id,
                None,
                format!(
                    "upstream withdrew it on {}",
                    up.withdrawn.as_deref().unwrap_or("")
                ),
            ));
        }
    }
}

/// Whether every affected package of `record` is in `ecosystem`.
fn only_ecosystem(record: &Record, ecosystem: &str) -> bool {
    !record.affected.is_empty()
        && record
            .affected
            .iter()
            .all(|a| a.package.ecosystem.as_deref() == Some(ecosystem))
}

fn record_checks(records: &[&Record], out: &mut Vec<Issue>) {
    for record in records {
        let ecosystems: BTreeSet<&str> = record
            .affected
            .iter()
            .filter_map(|a| a.package.ecosystem.as_deref())
            .filter(|e| feeder_rules(e).is_some())
            .collect();
        let first = ecosystems.iter().next().copied().unwrap_or("");
        if record.withdrawn.is_some() {
            out.push(issue(
                "withdrawn",
                first,
                &record.id,
                None,
                format!("withdrawn {}", record.withdrawn.as_deref().unwrap_or("")),
            ));
            continue;
        }
        // Malware records and the Go vulnerability database never carry a severity by policy.
        let by_policy = record.id.starts_with("MAL-") || record.id.starts_with("GO-");
        if !record.has_severity() && !ecosystems.is_empty() && !by_policy {
            out.push(issue(
                "missing-severity",
                first,
                &record.id,
                None,
                String::new(),
            ));
        }
        // Group entries per package: GHSA writes one entry per release line, and one
        // matchable entry makes the package matchable.
        let mut packages: BTreeMap<(&str, &str), (bool, Vec<String>)> = BTreeMap::new();
        for affected in &record.affected {
            let (Some(eco), Some(name)) = (
                affected.package.ecosystem.as_deref(),
                affected.package.name.as_deref(),
            ) else {
                continue;
            };
            let Some((range_type, use_versions)) = feeder_rules(eco) else {
                continue;
            };
            let slot = packages.entry((eco, name)).or_default();
            let ranges = affected
                .ranges
                .iter()
                .any(|r| r.kind.as_deref() == Some(range_type) && !r.events.is_empty());
            let versions = use_versions && !affected.versions.is_empty();
            slot.0 |= ranges || versions;
            for r in &affected.ranges {
                slot.1.push(r.kind.clone().unwrap_or_default());
            }
            if !affected.versions.is_empty() {
                slot.1.push("versions".to_string());
            }
        }
        for ((eco, name), (matchable, kinds)) in packages {
            if !matchable {
                let mut kinds = kinds;
                kinds.sort();
                kinds.dedup();
                out.push(issue(
                    "unmatchable-entry",
                    eco,
                    &record.id,
                    Some(name),
                    if kinds.is_empty() {
                        "no ranges and no versions".to_string()
                    } else {
                        format!("only {}", kinds.join(", "))
                    },
                ));
            }
        }
    }
}

/// Records sharing a CVE that name different fixes for one package.
fn alias_conflicts(records: &[&Record], out: &mut Vec<Issue>) {
    // (CVE, ecosystem, package) -> record id -> normalized fixes.
    let mut groups: BTreeMap<(String, String, String), BTreeMap<String, BTreeSet<String>>> =
        BTreeMap::new();
    for record in records.iter().filter(|r| r.withdrawn.is_none()) {
        let packages: BTreeSet<(&str, &str)> = record
            .affected
            .iter()
            .filter_map(|a| Some((a.package.ecosystem.as_deref()?, a.package.name.as_deref()?)))
            .filter(|(e, _)| feeder_rules(e).is_some())
            .collect();
        for (eco, name) in packages {
            let fixes: BTreeSet<String> =
                record.fixes_for(eco, name).map(normalize_version).collect();
            if fixes.is_empty() {
                continue;
            }
            for cve in record.cves() {
                groups
                    .entry((cve.to_string(), eco.to_string(), normalize_name(eco, name)))
                    .or_default()
                    .insert(record.id.clone(), fixes.clone());
            }
        }
    }
    for ((cve, eco, name), by_id) in groups {
        if by_id.len() < 2 {
            continue;
        }
        let distinct: BTreeSet<&BTreeSet<String>> = by_id.values().collect();
        if distinct.len() < 2 {
            continue;
        }
        let detail = by_id
            .iter()
            .map(|(id, fixes)| {
                format!(
                    "{id} fixed {}",
                    fixes.iter().cloned().collect::<Vec<_>>().join("/")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let ids: Vec<&String> = by_id.keys().collect();
        out.push(issue(
            "alias-conflict",
            &eco,
            &cve,
            Some(&name),
            format!("{detail} ({} records)", ids.len()),
        ));
    }
}

fn rejected_aliases(records: &[&Record], cves: &[CveSummary], out: &mut Vec<Issue>) {
    let rejected: BTreeSet<&str> = cves
        .iter()
        .filter(|c| c.state == "REJECTED")
        .map(|c| c.id.as_str())
        .collect();
    for record in records.iter().filter(|r| r.withdrawn.is_none()) {
        let eco = record
            .affected
            .iter()
            .find_map(|a| a.package.ecosystem.as_deref())
            .unwrap_or("");
        for cve in record.cves().filter(|c| rejected.contains(c)) {
            out.push(issue(
                "rejected-cve-alias",
                eco,
                &record.id,
                None,
                format!("{cve} is REJECTED in cvelistV5"),
            ));
        }
    }
}

/// The checks that need each ecosystem's version parser: run on the feeders' own parsed DBs.
fn parsed_checks(dir: &Path, overlay: Option<&Path>) -> Result<Vec<Issue>, String> {
    use rayon::prelude::*;
    let ecosystems: Vec<Ecosystem> = osvdb::OSV_ECOSYSTEMS
        .iter()
        .copied()
        .filter(|&e| e != Ecosystem::Go)
        .collect();
    let per_eco: Vec<Result<Vec<Issue>, String>> = ecosystems
        .par_iter()
        .map(|&eco| {
            let name = osvdb::osv_name(eco).unwrap_or_default();
            let root = dir.join(name).join("all.zip");
            let root = if root.is_file() { root } else { dir.join(name) };
            if !root.exists() {
                return Ok(Vec::new());
            }
            let err = |e: &dyn std::fmt::Display| format!("{name} export: {e}");
            let mut out = Vec::new();
            macro_rules! check {
                ($db:ty) => {{
                    let db = <$db>::load_with_overlay(&root, overlay).map_err(|e| err(&e))?;
                    range_checks(name, db.iter(), &mut out);
                }};
            }
            match eco {
                Ecosystem::Npm => check!(fleetreach_npm::NpmDb),
                Ecosystem::Pypi => check!(fleetreach_pypi::PyPiDb),
                Ecosystem::RubyGems => check!(fleetreach_rubygems::RubyGemsDb),
                Ecosystem::Packagist => check!(fleetreach_packagist::PackagistDb),
                Ecosystem::NuGet => check!(fleetreach_nuget::NuGetDb),
                Ecosystem::Julia => check!(fleetreach_julia::JuliaDb),
                Ecosystem::Swift => check!(fleetreach_swift::SwiftDb),
                Ecosystem::Hex => check!(fleetreach_hex::HexDb),
                Ecosystem::GitHubActions => check!(fleetreach_ghactions::GhActionsDb),
                Ecosystem::Maven => check!(fleetreach_maven::MavenDb),
                // Go and Rust use their own databases; distro exports are per distribution
                // and not range-checked here yet.
                Ecosystem::Go | Ecosystem::Cargo | Ecosystem::Deb | Ecosystem::Apk => {}
            }
            Ok(out)
        })
        .collect();
    let mut out = Vec::new();
    for issues in per_eco {
        out.extend(issues?);
    }
    Ok(out)
}

/// Range checks on one feeder's parsed advisories. Generic over the version type; only
/// ordering is needed (`>=` for introduced, as every feeder but Go uses).
fn range_checks<'a, V: Ord + Clone + std::fmt::Display + 'a>(
    ecosystem: &str,
    advisories: impl Iterator<Item = (&'a str, &'a Advisory<V>)>,
    out: &mut Vec<Issue>,
) {
    for (package, adv) in advisories {
        let matchable: Vec<_> = adv.ranges.iter().filter(|r| r.matchable).cloned().collect();
        if !matchable.is_empty() && !adv.versions.is_empty() {
            let outside: Vec<&V> = adv
                .versions
                .iter()
                .filter(|v| {
                    osv::affected_fixed_parsed(*v, &matchable, |v, b| v >= b) == Match::NotAffected
                })
                .collect();
            if let Some(first) = outside.first() {
                out.push(issue(
                    "versions-outside-ranges",
                    ecosystem,
                    &adv.id,
                    Some(package),
                    format!(
                        "{} of {} enumerated version(s) fall outside every range, first {first}",
                        outside.len(),
                        adv.versions.len()
                    ),
                ));
            }
        }
        for range in &matchable {
            if range
                .events
                .iter()
                .any(|e| e.introduced == Some(ParsedBound::Unparseable))
            {
                out.push(issue(
                    "unparseable-bound",
                    ecosystem,
                    &adv.id,
                    Some(package),
                    "an introduced bound does not parse".to_string(),
                ));
            }
            let bounds: Vec<&V> = range
                .events
                .iter()
                .flat_map(|e| {
                    let intro = match &e.introduced {
                        Some(ParsedBound::Version(v)) => Some(v),
                        _ => None,
                    };
                    intro
                        .into_iter()
                        .chain(e.fixed.as_ref())
                        .chain(e.last_affected.as_ref())
                })
                .collect();
            if bounds.windows(2).any(|w| matches!(w, [a, b] if a > b)) {
                out.push(issue(
                    "events-out-of-order",
                    ecosystem,
                    &adv.id,
                    Some(package),
                    "bounds decrease in the order written".to_string(),
                ));
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, body: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    /// A small PyPI export with one record per problem, plus an overlay.
    #[test]
    fn each_check_fires_on_its_case_and_not_on_clean_data() {
        let root = std::env::temp_dir().join(format!("fr-quality-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let db = root.join("db");
        // Clean: ranges, versions inside them, severity.
        write(
            &db,
            "PyPI/GHSA-ok.json",
            r#"{"id":"GHSA-ok","aliases":["CVE-2024-1"],
            "database_specific":{"severity":"HIGH"},
            "affected":[{"package":{"ecosystem":"PyPI","name":"a"},
              "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"1.2"}]}],
              "versions":["1.0","1.1"]}]}"#,
        );
        // Same CVE and package, a different fix: alias conflict.
        write(
            &db,
            "PyPI/PYSEC-1.json",
            r#"{"id":"PYSEC-1","aliases":["CVE-2024-1"],
            "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected":[{"package":{"ecosystem":"PyPI","name":"a"},
              "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.3"}]}]}]}"#,
        );
        // Only a GIT range: unmatchable. No severity.
        write(
            &db,
            "PyPI/GHSA-git.json",
            r#"{"id":"GHSA-git",
            "affected":[{"package":{"ecosystem":"PyPI","name":"b"},
              "ranges":[{"type":"GIT","repo":"https://x/y","events":[{"introduced":"0"},{"fixed":"abc"}]}]}]}"#,
        );
        // A version the ranges call safe; events out of order.
        write(
            &db,
            "PyPI/GHSA-bad.json",
            r#"{"id":"GHSA-bad","database_specific":{"severity":"LOW"},
            "affected":[{"package":{"ecosystem":"PyPI","name":"c"},
              "ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"2.0"},{"introduced":"1.0"}]}],
              "versions":["1.0","0.5"]}]}"#,
        );
        // Aliases a rejected CVE; withdrawn record.
        write(
            &db,
            "PyPI/GHSA-rej.json",
            r#"{"id":"GHSA-rej","aliases":["CVE-2020-9"],
            "database_specific":{"severity":"LOW"},
            "affected":[{"package":{"ecosystem":"PyPI","name":"d"},
              "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1"}]}]}]}"#,
        );
        write(
            &db,
            "PyPI/GHSA-wd.json",
            r#"{"id":"GHSA-wd","withdrawn":"2024-01-01T00:00:00Z",
            "modified":"2024-01-01T00:00:00Z","affected":[]}"#,
        );
        // Overlay: fixes GHSA-git (so it is no longer unmatchable), revives GHSA-wd with an
        // older modified time, and adds a Go record no feeder layers.
        let ov = root.join("advisories");
        write(
            &ov,
            "GHSA-git.json",
            r#"{"id":"GHSA-git","database_specific":{"severity":"LOW"},
            "affected":[{"package":{"ecosystem":"PyPI","name":"b"},
              "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2"}]}]}]}"#,
        );
        write(
            &ov,
            "GHSA-wd.json",
            r#"{"id":"GHSA-wd","modified":"2023-01-01T00:00:00Z",
            "database_specific":{"severity":"LOW"},
            "affected":[{"package":{"ecosystem":"PyPI","name":"e"},
              "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}"#,
        );
        write(
            &ov,
            "go/ORG-1.json",
            r#"{"id":"ORG-1","affected":[{"package":{"ecosystem":"Go","name":"m"}}]}"#,
        );
        let cves = vec![CveSummary {
            id: "CVE-2020-9".into(),
            state: "REJECTED".into(),
            ..CveSummary::default()
        }];

        let checks = |overlay: Option<&Path>| -> BTreeMap<(&'static str, String), usize> {
            let issues = run(&Inputs {
                dir: &db,
                overlay,
                cves: Some(&cves),
            })
            .unwrap();
            let mut by = BTreeMap::new();
            for i in issues {
                *by.entry((i.check, i.id)).or_default() += 1;
            }
            by
        };
        let without = checks(None);
        let has = |m: &BTreeMap<(&str, String), usize>, c: &str, id: &str| {
            m.contains_key(&(c, id.to_string()))
        };
        assert!(has(&without, "unmatchable-entry", "GHSA-git"));
        assert!(has(&without, "missing-severity", "GHSA-git"));
        assert!(has(&without, "versions-outside-ranges", "GHSA-bad"));
        assert!(has(&without, "events-out-of-order", "GHSA-bad"));
        assert!(has(&without, "alias-conflict", "CVE-2024-1"));
        assert!(has(&without, "rejected-cve-alias", "GHSA-rej"));
        assert!(has(&without, "withdrawn", "GHSA-wd"));
        assert!(
            !without.keys().any(|(_, id)| id == "GHSA-ok"),
            "{without:?}"
        );

        let with = checks(Some(&ov));
        assert!(
            !has(&with, "unmatchable-entry", "GHSA-git"),
            "the overlay fixed it"
        );
        assert!(has(&with, "overlay-revives-withdrawn", "GHSA-wd"));
        assert!(!has(&with, "withdrawn", "GHSA-wd"));
        assert!(has(&with, "overlay-not-applied", "ORG-1"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stale_overlay_is_flagged() {
        let mut upstream = BTreeMap::new();
        let up: Record =
            serde_json::from_str(r#"{"id":"X","modified":"2025-02-01T00:00:00Z"}"#).unwrap();
        upstream.insert("X".to_string(), ("PyPI".to_string(), up));
        let ours: Record =
            serde_json::from_str(r#"{"id":"X","modified":"2025-01-01T00:00:00Z"}"#).unwrap();
        let mut out = Vec::new();
        overlay_checks(&upstream, &[ours], &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].check, "overlay-stale");
    }
}
