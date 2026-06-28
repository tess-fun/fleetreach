//! Two-report comparison: an advisory lands in exactly one of new / fixed /
//! still-open, blast-radius drift is captured per surviving advisory, and the
//! regression gate mirrors the scan `--fail-on` semantics (Unknown fails closed).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fleetreach_core::semver::Version;
use fleetreach_core::{
    DependencyKind, FleetReport, Occurrence, Provenance, RepoId, Severity, Summary, VulnFinding,
    WarnFinding, WarnKind,
};
use fleetreach_report::{diff_reports, to_diff_json, to_diff_table};

fn provenance() -> Provenance {
    Provenance {
        tool_version: "0".into(),
        rustsec_crate_version: "0".into(),
        db_commit: None,
        db_timestamp: None,
        host_os: "linux".into(),
        host_arch: "x86_64".into(),
        generated_at: "t".into(),
    }
}

fn occ(repo: &str) -> Occurrence {
    Occurrence::InRepo {
        repo: RepoId(repo.into()),
        package: "pkg".into(),
        installed: Version::new(1, 0, 0),
        patched: vec![],
        dependency_kind: DependencyKind::Direct,
        dependency_path: vec![],
        active: None,
        source: Default::default(),
    }
}

fn vuln(id: &str, severity: Severity, repos: &[&str]) -> VulnFinding {
    VulnFinding {
        advisory_id: id.into(),
        aliases: vec![],
        ecosystem: Default::default(),
        title: id.into(),
        severity,
        cvss_score: None,
        url: None,
        occurrences: repos.iter().map(|r| occ(r)).collect(),
        affected_functions: vec![],
        reachable: None,
        reachability: None,
        exploit: Default::default(),
    }
}

fn report(vulns: Vec<VulnFinding>, warnings: Vec<WarnFinding>) -> FleetReport {
    FleetReport {
        schema_version: 1,
        provenance: provenance(),
        summary: Summary {
            repos_scanned: 3,
            repos_errored: 0,
            vuln_count: vulns.len(),
            warn_count: warnings.len(),
            max_severity: Severity::Critical,
            stale_ignores: vec![],
        },
        vulnerabilities: vulns,
        warnings,
        outcomes: vec![],
    }
}

#[test]
fn buckets_new_fixed_and_still_open_with_drift() {
    let base = report(
        vec![
            vuln("RUSTSEC-2021-0001", Severity::High, &["a"]), // will be fixed
            vuln("RUSTSEC-2021-0002", Severity::Medium, &["a", "b"]), // persists, shrinks
        ],
        vec![],
    );
    let curr = report(
        vec![
            vuln("RUSTSEC-2021-0002", Severity::Medium, &["a"]), // lost repo b
            vuln("RUSTSEC-2026-9999", Severity::Critical, &["a", "c"]), // new
        ],
        vec![],
    );

    let diff = diff_reports(&base, &curr);

    assert_eq!(diff.new.len(), 1);
    assert_eq!(diff.new[0].advisory_id, "RUSTSEC-2026-9999");
    assert_eq!(diff.new[0].current_repos, 2);
    assert_eq!(diff.new[0].repos_added, vec!["a", "c"]);

    assert_eq!(diff.fixed.len(), 1);
    assert_eq!(diff.fixed[0].advisory_id, "RUSTSEC-2021-0001");
    assert_eq!(diff.fixed[0].current_repos, 0);
    assert_eq!(diff.fixed[0].repos_removed, vec!["a"]);

    assert_eq!(diff.still_open.len(), 1);
    let so = &diff.still_open[0];
    assert_eq!(so.advisory_id, "RUSTSEC-2021-0002");
    assert_eq!(so.baseline_repos, 2);
    assert_eq!(so.current_repos, 1);
    assert_eq!(so.repos_removed, vec!["b"]);
    assert!(so.repos_added.is_empty());
}

#[test]
fn identical_reports_have_no_new_or_fixed() {
    let r = report(
        vec![vuln("RUSTSEC-2021-0002", Severity::Medium, &["a"])],
        vec![],
    );
    let diff = diff_reports(&r, &r);
    assert!(diff.new.is_empty());
    assert!(diff.fixed.is_empty());
    assert_eq!(diff.still_open.len(), 1);
    // No drift => repo delta sets stay empty.
    assert!(diff.still_open[0].repos_added.is_empty());
    assert!(diff.still_open[0].repos_removed.is_empty());

    let table = to_diff_table(&diff, false);
    assert!(table.contains("No advisories appeared or cleared."));
    assert!(table.contains("1 still open, unchanged"));
}

#[test]
fn new_is_sorted_worst_first() {
    let base = report(vec![], vec![]);
    let curr = report(
        vec![
            vuln("RUSTSEC-2026-0010", Severity::Low, &["a"]),
            vuln("RUSTSEC-2026-0020", Severity::Critical, &["a"]),
            vuln("RUSTSEC-2026-0030", Severity::Medium, &["a"]),
        ],
        vec![],
    );
    let diff = diff_reports(&base, &curr);
    let order: Vec<&str> = diff.new.iter().map(|e| e.advisory_id.as_str()).collect();
    assert_eq!(
        order,
        [
            "RUSTSEC-2026-0020",
            "RUSTSEC-2026-0030",
            "RUSTSEC-2026-0010"
        ]
    );
}

#[test]
fn regressions_gate_mirrors_fail_on_with_unknown_failing_closed() {
    let base = report(vec![], vec![]);
    let curr = report(
        vec![
            vuln("RUSTSEC-2026-0001", Severity::Low, &["a"]),
            vuln("RUSTSEC-2026-0002", Severity::Unknown, &["a"]),
            vuln("RUSTSEC-2026-0003", Severity::High, &["a"]),
        ],
        vec![],
    );
    let diff = diff_reports(&base, &curr);

    // floor = High: the High one and the Unknown (fail-closed) gate; Low does not.
    assert_eq!(diff.regressions(Severity::High, false), 2);
    // floor = Low: Low, Unknown, and High all gate.
    assert_eq!(diff.regressions(Severity::Low, false), 3);
}

#[test]
fn warnings_diff_and_gate_only_when_asked() {
    let warn = |id: &str| WarnFinding {
        kind: WarnKind::Unmaintained,
        advisory_id: Some(id.into()),
        title: id.into(),
        occurrences: vec![occ("a")],
    };
    let base = report(vec![], vec![]);
    let curr = report(vec![], vec![warn("RUSTSEC-2026-0100")]);
    let diff = diff_reports(&base, &curr);

    assert_eq!(diff.new.len(), 1);
    assert!(diff.new[0].warning);
    assert_eq!(diff.new[0].severity, None);

    // A new warning does not gate by default, but does with `fail_on_warnings`.
    assert_eq!(diff.regressions(Severity::Low, false), 0);
    assert_eq!(diff.regressions(Severity::Low, true), 1);

    let json = to_diff_json(&diff).unwrap();
    assert!(json.contains("\"warning\": true"));
}
