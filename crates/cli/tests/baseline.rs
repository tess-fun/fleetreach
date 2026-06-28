//! `--baseline` diffing: surface only findings new since a prior JSON report,
//! while preserving §8 exit-code precedence.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fleetreach_cli::assemble::{build_report, combine_baseline, retain_new};
use fleetreach_cli::ScanData;
use fleetreach_core::semver::Version;
use fleetreach_core::{
    DependencyKind, Occurrence, Provenance, RepoId, RepoOutcome, ScanStatus, Severity, VulnFinding,
};

fn provenance() -> Provenance {
    Provenance {
        tool_version: "0.1.0".into(),
        rustsec_crate_version: "0.33.0".into(),
        db_commit: Some("abc".into()),
        db_timestamp: Some("2026-06-23T00:00:00Z".into()),
        host_os: "linux".into(),
        host_arch: "x86_64".into(),
        generated_at: "2026-06-24T00:00:00Z".into(),
    }
}

fn vuln(id: &str) -> VulnFinding {
    VulnFinding {
        advisory_id: id.into(),
        aliases: vec![],
        ecosystem: Default::default(),
        reachability: None,
        exploit: Default::default(),
        affected_functions: vec![],
        reachable: None,
        title: id.into(),
        severity: Severity::High,
        cvss_score: None,
        url: None,
        occurrences: vec![Occurrence::InRepo {
            repo: RepoId("a".into()),
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

fn report_with(ids: &[&str]) -> fleetreach_core::FleetReport {
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: ids.iter().map(|id| vuln(id)).collect(),
        warnings: vec![],
        outcomes: vec![RepoOutcome {
            repo: RepoId("a".into()),
            status: ScanStatus::Scanned {
                vulns: ids.len(),
                warnings: 0,
            },
        }],
    };
    build_report(scan, &[], None, provenance())
}

#[test]
fn retain_new_drops_known_findings_and_recounts() {
    let mut report = report_with(&["RUSTSEC-OLD", "RUSTSEC-NEW"]);
    let baseline: BTreeSet<String> = ["RUSTSEC-OLD".to_string()].into_iter().collect();

    retain_new(&mut report, &baseline);

    assert_eq!(report.vulnerabilities.len(), 1);
    assert_eq!(report.vulnerabilities[0].advisory_id, "RUSTSEC-NEW");
    assert_eq!(report.summary.vuln_count, 1, "summary recounted");
}

#[test]
fn baseline_ids_round_trip_through_json() {
    let prior = report_with(&["RUSTSEC-1", "RUSTSEC-2"]);
    let json = fleetreach_report::to_json(&prior).unwrap();
    let ids = fleetreach_report::baseline_ids_from_json(&json).unwrap();
    assert!(ids.contains("RUSTSEC-1"));
    assert!(ids.contains("RUSTSEC-2"));
}

#[test]
fn drop_phantom_removes_unbuilt_keeps_built_and_unknown() {
    use fleetreach_cli::assemble::drop_phantom;

    let occ = |active: Option<bool>| Occurrence::InRepo {
        repo: RepoId("a".into()),
        package: "pkg".into(),
        installed: Version::new(1, 0, 0),
        patched: vec![],
        dependency_kind: DependencyKind::Transitive,
        dependency_path: vec![],
        active,
        source: Default::default(),
    };
    let finding = |id: &str, active: Option<bool>| VulnFinding {
        advisory_id: id.into(),
        aliases: vec![],
        ecosystem: Default::default(),
        reachability: None,
        exploit: Default::default(),
        affected_functions: vec![],
        reachable: None,
        title: id.into(),
        severity: Severity::High,
        cvss_score: None,
        url: None,
        occurrences: vec![occ(active)],
    };

    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![
            finding("RUSTSEC-PHANTOM", Some(false)),
            finding("RUSTSEC-BUILT", Some(true)),
            finding("RUSTSEC-UNKNOWN", None),
        ],
        warnings: vec![],
        outcomes: vec![RepoOutcome {
            repo: RepoId("a".into()),
            status: ScanStatus::Scanned {
                vulns: 3,
                warnings: 0,
            },
        }],
    };
    let mut report = build_report(scan, &[], None, provenance());

    let removed = drop_phantom(&mut report);

    assert_eq!(removed, 1, "only the phantom finding is removed");
    let ids: Vec<&str> = report
        .vulnerabilities
        .iter()
        .map(|v| v.advisory_id.as_str())
        .collect();
    assert!(ids.contains(&"RUSTSEC-BUILT"));
    assert!(
        ids.contains(&"RUSTSEC-UNKNOWN"),
        "unknown build status is kept (fail-closed)"
    );
    assert!(!ids.contains(&"RUSTSEC-PHANTOM"));
    assert_eq!(report.summary.vuln_count, 2, "counts recomputed");
}

#[test]
fn combine_baseline_respects_exit_precedence() {
    // An untrustworthy 2 always wins, even if there are new findings.
    assert_eq!(combine_baseline(2, true), 2);
    // A new finding lifts a clean run to 1.
    assert_eq!(combine_baseline(0, true), 1);
    // No new findings leaves the code untouched.
    assert_eq!(combine_baseline(0, false), 0);
    assert_eq!(combine_baseline(1, false), 1);
}
