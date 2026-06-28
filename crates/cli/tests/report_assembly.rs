//! Report assembly + the §8 exit-code contract, including the fail-closed cases
//! (errored repo, unknown severity) and byte-identical determinism.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fleetreach_cli::assemble::{build_report, exit_code, GateConfig};
use fleetreach_cli::config::Ignore;
use fleetreach_cli::ScanData;
use fleetreach_core::semver::Version;
use fleetreach_core::{
    DependencyKind, Occurrence, Provenance, RepoId, RepoOutcome, ScanStatus, Severity, VulnFinding,
    WarnFinding, WarnKind,
};

fn provenance() -> Provenance {
    Provenance {
        tool_version: "0.1.0".into(),
        rustsec_crate_version: "0.33.0".into(),
        db_commit: Some("abc123".into()),
        db_timestamp: Some("2026-06-23T00:00:00Z".into()),
        host_os: "linux".into(),
        host_arch: "x86_64".into(),
        generated_at: "2026-06-24T00:00:00Z".into(),
    }
}

fn vuln(id: &str, severity: Severity, repo: &str) -> VulnFinding {
    VulnFinding {
        advisory_id: id.into(),
        aliases: vec![],
        ecosystem: Default::default(),
        reachability: None,
        exploit: Default::default(),
        affected_functions: vec![],
        reachable: None,
        title: format!("title {id}"),
        severity,
        cvss_score: None,
        url: None,
        occurrences: vec![Occurrence::InRepo {
            repo: RepoId(repo.into()),
            package: "pkg".into(),
            installed: Version::new(1, 0, 0),
            patched: vec![],
            dependency_kind: DependencyKind::Transitive,
            dependency_path: vec![],
            active: None,
            source: Default::default(),
        }],
    }
}

fn warn(id: &str, repo: &str) -> WarnFinding {
    WarnFinding {
        kind: WarnKind::Unmaintained,
        advisory_id: Some(id.into()),
        title: "unmaintained".into(),
        occurrences: vec![Occurrence::InRepo {
            repo: RepoId(repo.into()),
            package: "pkg".into(),
            installed: Version::new(0, 1, 0),
            patched: vec![],
            dependency_kind: DependencyKind::Transitive,
            dependency_path: vec![],
            active: None,
            source: Default::default(),
        }],
    }
}

fn scanned(id: &str, vulns: usize, warnings: usize) -> RepoOutcome {
    RepoOutcome {
        repo: RepoId(id.into()),
        status: ScanStatus::Scanned { vulns, warnings },
    }
}

fn errored(id: &str) -> RepoOutcome {
    RepoOutcome {
        repo: RepoId(id.into()),
        status: ScanStatus::Errored {
            reason: "missing Cargo.lock".into(),
        },
    }
}

fn gate(fail_on: Severity, fail_on_warnings: bool) -> GateConfig {
    GateConfig {
        fail_on,
        fail_on_warnings,
    }
}

#[test]
fn clean_fleet_exits_zero() {
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![],
        warnings: vec![],
        outcomes: vec![scanned("a", 0, 0), scanned("b", 0, 0)],
    };
    let report = build_report(scan, &[], None, provenance());
    assert_eq!(report.summary.repos_scanned, 2);
    assert_eq!(exit_code(&report, &gate(Severity::Low, false)), 0);
}

#[test]
fn vuln_at_or_above_fail_on_exits_one() {
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![vuln("RUSTSEC-1", Severity::High, "a")],
        warnings: vec![],
        outcomes: vec![scanned("a", 1, 0)],
    };
    let report = build_report(scan, &[], None, provenance());
    assert_eq!(exit_code(&report, &gate(Severity::Low, false)), 1);
    // High is below Critical and not Unknown -> does not trip a Critical gate.
    assert_eq!(exit_code(&report, &gate(Severity::Critical, false)), 0);
}

#[test]
fn errored_repo_forces_two_even_with_no_findings() {
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![],
        warnings: vec![],
        outcomes: vec![scanned("a", 0, 0), errored("b")],
    };
    let report = build_report(scan, &[], None, provenance());
    assert_eq!(report.summary.repos_errored, 1);
    assert_eq!(exit_code(&report, &gate(Severity::Low, false)), 2);
}

#[test]
fn zero_repos_scanned_exits_two() {
    // An empty fleet is untrustworthy: we read nothing, so we cannot claim clean.
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![],
        warnings: vec![],
        outcomes: vec![],
    };
    let report = build_report(scan, &[], None, provenance());
    assert_eq!(report.summary.repos_scanned, 0);
    assert_eq!(exit_code(&report, &gate(Severity::Low, false)), 2);
}

#[test]
fn unknown_severity_vuln_is_fail_closed() {
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![vuln("RUSTSEC-1", Severity::Unknown, "a")],
        warnings: vec![],
        outcomes: vec![scanned("a", 1, 0)],
    };
    let report = build_report(scan, &[], None, provenance());
    // Even with the strictest gate, an unknown-severity vuln still trips it.
    assert_eq!(exit_code(&report, &gate(Severity::Critical, false)), 1);
}

#[test]
fn warnings_only_gate_when_opted_in() {
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![],
        warnings: vec![warn("RUSTSEC-W", "a")],
        outcomes: vec![scanned("a", 0, 1)],
    };
    let report = build_report(scan, &[], None, provenance());
    assert_eq!(exit_code(&report, &gate(Severity::Low, false)), 0);
    assert_eq!(exit_code(&report, &gate(Severity::Low, true)), 1);
}

#[test]
fn ignores_suppress_findings_and_report_stale() {
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![vuln("RUSTSEC-PRESENT", Severity::High, "a")],
        warnings: vec![],
        outcomes: vec![scanned("a", 1, 0)],
    };
    let ignores = vec![
        Ignore {
            id: "RUSTSEC-PRESENT".into(),
            reason: "dev only".into(),
        },
        Ignore {
            id: "RUSTSEC-ABSENT".into(),
            reason: "no longer relevant".into(),
        },
    ];
    let report = build_report(scan, &ignores, None, provenance());

    assert_eq!(report.vulnerabilities.len(), 0, "present id suppressed");
    assert_eq!(
        report.summary.stale_ignores,
        vec!["RUSTSEC-ABSENT".to_string()]
    );
    // Suppressed -> nothing to gate on.
    assert_eq!(exit_code(&report, &gate(Severity::Low, false)), 0);
}

#[test]
fn repo_scoped_suppression_removes_only_that_repos_occurrence() {
    use fleetreach_cli::assemble::{assemble, Suppression};

    // One advisory in two repos; a repo-scoped suppression must clear only `a`.
    let mut v = vuln("RUSTSEC-SCOPED", Severity::High, "a");
    if let Occurrence::InRepo { .. } = &v.occurrences[0] {
        v.occurrences.push(Occurrence::InRepo {
            repo: RepoId("b".into()),
            package: "pkg".into(),
            installed: Version::new(1, 0, 0),
            patched: vec![],
            dependency_kind: DependencyKind::Transitive,
            dependency_path: vec![],
            active: None,
            source: Default::default(),
        });
    }
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![v],
        warnings: vec![],
        outcomes: vec![scanned("a", 1, 0), scanned("b", 1, 0)],
    };
    let suppressions = vec![Suppression {
        id: "RUSTSEC-SCOPED".into(),
        repo: Some(RepoId("a".into())),
        justification: Some("component_not_present".into()),
        reason: "dev only in a".into(),
        approved_by: Some("secteam".into()),
    }];
    let out = assemble(scan, &suppressions, None, provenance());

    // The finding survives (repo `b` still vulnerable) with one occurrence left.
    assert_eq!(out.report.vulnerabilities.len(), 1);
    let occs = &out.report.vulnerabilities[0].occurrences;
    assert_eq!(occs.len(), 1);
    assert!(matches!(&occs[0], Occurrence::InRepo { repo, .. } if repo.0 == "b"));
    // The suppressed `a` occurrence is captured with its assertion metadata.
    assert_eq!(out.suppressed.len(), 1);
    let s = &out.suppressed[0];
    assert_eq!(s.advisory_id, "RUSTSEC-SCOPED");
    assert_eq!(s.justification.as_deref(), Some("component_not_present"));
    assert_eq!(s.approved_by.as_deref(), Some("secteam"));
    assert!(matches!(&s.occurrence, Occurrence::InRepo { repo, .. } if repo.0 == "a"));
    // `b` still trips the gate.
    assert_eq!(exit_code(&out.report, &gate(Severity::Low, false)), 1);
}

#[test]
fn min_severity_filters_below_threshold_but_keeps_unknown() {
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![
            vuln("RUSTSEC-LOW", Severity::Low, "a"),
            vuln("RUSTSEC-HIGH", Severity::High, "a"),
            vuln("RUSTSEC-UNK", Severity::Unknown, "a"),
        ],
        warnings: vec![],
        outcomes: vec![scanned("a", 3, 0)],
    };
    let report = build_report(scan, &[], Some(Severity::High), provenance());
    let ids: Vec<&str> = report
        .vulnerabilities
        .iter()
        .map(|v| v.advisory_id.as_str())
        .collect();
    // High kept, Unknown kept (fail-closed), Low dropped.
    assert!(ids.contains(&"RUSTSEC-HIGH"));
    assert!(ids.contains(&"RUSTSEC-UNK"));
    assert!(!ids.contains(&"RUSTSEC-LOW"));
}

#[test]
fn assembly_is_byte_identical_across_runs() {
    let make = || ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![
            vuln("RUSTSEC-2", Severity::Low, "z"),
            vuln("RUSTSEC-1", Severity::High, "a"),
            vuln("RUSTSEC-1", Severity::High, "b"),
        ],
        warnings: vec![warn("RUSTSEC-W", "a")],
        outcomes: vec![scanned("a", 2, 1), scanned("b", 1, 0), scanned("z", 1, 0)],
    };
    let a = build_report(make(), &[], None, provenance());
    let b = build_report(make(), &[], None, provenance());
    let ja = fleetreach_report::to_json(&a).unwrap();
    let jb = fleetreach_report::to_json(&b).unwrap();
    assert_eq!(ja, jb, "same inputs must render byte-identically");
}

#[test]
fn json_matches_the_schema_shape() {
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![vuln("RUSTSEC-1", Severity::High, "a")],
        warnings: vec![],
        outcomes: vec![scanned("a", 1, 0)],
    };
    let report = build_report(scan, &[], None, provenance());
    let value: serde_json::Value =
        serde_json::from_str(&fleetreach_report::to_json(&report).unwrap()).unwrap();

    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["summary"]["vuln_count"], 1);
    assert_eq!(value["summary"]["max_severity"], "high");
    assert_eq!(value["vulnerabilities"][0]["severity"], "high");
    assert_eq!(
        value["vulnerabilities"][0]["occurrences"][0]["kind"],
        "in_repo"
    );
    assert_eq!(value["outcomes"][0]["status"], "scanned");
}
