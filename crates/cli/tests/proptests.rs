//! Property tests over the cli's owned logic: the config parser never panics on
//! arbitrary input, and the full assemble pipeline is internally consistent and
//! deterministic for any combination of findings and outcomes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use fleetreach_cli::assemble::{build_report, exit_code, GateConfig};
use fleetreach_cli::config::Config;
use fleetreach_cli::ScanData;
use fleetreach_core::semver::Version;
use fleetreach_core::{
    DependencyKind, Occurrence, Provenance, RepoId, RepoOutcome, ScanStatus, Severity, VulnFinding,
    WarnFinding, WarnKind,
};
use proptest::prelude::*;

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

fn arb_occurrence() -> impl Strategy<Value = Occurrence> {
    ((0u32..3), (0u64..3, 0u64..3, 0u64..3)).prop_map(|(repo, (a, b, c))| Occurrence::InRepo {
        repo: RepoId(format!("repo-{repo}")),
        package: "pkg".into(),
        installed: Version::new(a, b, c),
        patched: vec![],
        dependency_kind: DependencyKind::Transitive,
        dependency_path: vec![],
        active: None,
        source: Default::default(),
    })
}

fn arb_vuln() -> impl Strategy<Value = VulnFinding> {
    (
        (0u32..6).prop_map(|n| format!("RUSTSEC-2099-{n:04}")),
        prop_oneof![
            Just(Severity::Unknown),
            Just(Severity::Low),
            Just(Severity::Medium),
            Just(Severity::High),
            Just(Severity::Critical),
        ],
        arb_occurrence(),
    )
        .prop_map(|(advisory_id, severity, occ)| VulnFinding {
            advisory_id,
            aliases: vec![],
            ecosystem: Default::default(),
            reachability: None,
            exploit: Default::default(),
            affected_functions: vec![],
            reachable: None,
            title: "t".into(),
            severity,
            cvss_score: None,
            url: None,
            occurrences: vec![occ],
        })
}

fn arb_warn() -> impl Strategy<Value = WarnFinding> {
    (
        prop_oneof![
            Just(WarnKind::Unmaintained),
            Just(WarnKind::Yanked),
            Just(WarnKind::Unsound),
            Just(WarnKind::Notice),
        ],
        (0u32..4).prop_map(|n| Some(format!("RUSTSEC-2098-{n:04}"))),
        arb_occurrence(),
    )
        .prop_map(|(kind, advisory_id, occ)| WarnFinding {
            kind,
            advisory_id,
            title: "w".into(),
            occurrences: vec![occ],
        })
}

fn arb_outcome() -> impl Strategy<Value = RepoOutcome> {
    (
        (0u32..8).prop_map(|n| RepoId(format!("repo-{n}"))),
        prop_oneof![
            (0usize..5, 0usize..5).prop_map(|(v, w)| ScanStatus::Scanned {
                vulns: v,
                warnings: w
            }),
            Just(ScanStatus::Errored {
                reason: "boom".into()
            }),
        ],
    )
        .prop_map(|(repo, status)| RepoOutcome { repo, status })
}

proptest! {
    /// The untrusted config parser must return — Ok or Err — for any input,
    /// never panic. (CI-runnable companion to the cargo-fuzz target.)
    #[test]
    fn config_from_str_never_panics(s in ".*") {
        let _ = Config::from_str(&s, Path::new("."), "prop");
    }

    /// For any scan result, the assembled report's summary is consistent with
    /// its contents, assembly is deterministic, and the exit code is well-formed.
    #[test]
    fn pipeline_is_consistent_and_deterministic(
        vulns in prop::collection::vec(arb_vuln(), 0..15),
        warns in prop::collection::vec(arb_warn(), 0..15),
        outcomes in prop::collection::vec(arb_outcome(), 0..8),
    ) {
        let make = || ScanData { skipped_unparseable: 0,
            vulnerabilities: vulns.clone(),
            warnings: warns.clone(),
            outcomes: outcomes.clone(),
        };
        let r1 = build_report(make(), &[], None, provenance());
        let r2 = build_report(make(), &[], None, provenance());

        // summary mirrors the actual contents
        prop_assert_eq!(r1.summary.vuln_count, r1.vulnerabilities.len());
        prop_assert_eq!(r1.summary.warn_count, r1.warnings.len());
        prop_assert_eq!(
            r1.summary.repos_scanned + r1.summary.repos_errored,
            outcomes.len()
        );

        // identical inputs render byte-identically
        let j1 = fleetreach_report::to_json(&r1).unwrap();
        let j2 = fleetreach_report::to_json(&r2).unwrap();
        prop_assert_eq!(j1, j2);

        // exit code is always one of 0/1/2 for a completed scan
        let code = exit_code(
            &r1,
            &GateConfig { fail_on: Severity::Low, fail_on_warnings: false },
        );
        prop_assert!(code <= 2);
    }
}
