//! End-to-end static reachability through the cli orchestration: a finding that
//! names a function living in a dependency gets a `Reachable` verdict after the
//! engine builds the repo and merges the whole closure.
//!
//! Ignored by default — needs the pinned nightly + a built reach-driver. Run:
//!   (cd crates/reach-driver && cargo build)
//!   cargo test -p fleetreach-cli --test static_reach_e2e -- --ignored

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fleetreach_cli::config::{Config, Repo};
use fleetreach_cli::static_reach::{assess, Options};
use fleetreach_core::{FleetReport, RepoId};
use serde_json::json;

fn driver_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .join("reach-driver/target/debug/fleetreach-reach-driver")
}

fn cross_crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .join("reach/tests/projects/cross_crate")
}

fn generic_uninstantiated_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .join("reach/tests/projects/generic_uninstantiated")
}

#[test]
#[ignore = "requires pinned nightly + built reach-driver; run with --ignored"]
fn static_engine_annotates_a_dependency_finding_reachable() {
    let driver = driver_path();
    assert!(
        driver.exists(),
        "build the driver first: (cd crates/reach-driver && cargo build)"
    );

    // One finding naming a function that lives in the `vuln_lib` dependency,
    // occurring in repo "cc".
    let mut report: FleetReport = serde_json::from_value(json!({
        "schema_version": 1,
        "provenance": {
            "tool_version": "0.1.0",
            "rustsec_crate_version": "0.33.0",
            "db_commit": null,
            "db_timestamp": null,
            "host_os": "macos",
            "host_arch": "x86_64",
            "generated_at": "2026-06-24T00:00:00Z"
        },
        "summary": {
            "repos_scanned": 1,
            "repos_errored": 0,
            "vuln_count": 1,
            "warn_count": 0,
            "max_severity": "high",
            "stale_ignores": []
        },
        "vulnerabilities": [{
            "advisory_id": "RUSTSEC-2099-0001",
            "aliases": [],
            "title": "vulnerable_fn is bad",
            "severity": "high",
            "url": null,
            "affected_functions": ["vuln_lib::vulnerable_fn"],
            "occurrences": [{
                "kind": "in_repo",
                "repo": "cc",
                "package": "vuln_lib",
                "installed": "0.0.0",
                "patched": [],
                "dependency_kind": "direct"
            }]
        }],
        "warnings": [],
        "outcomes": []
    }))
    .expect("construct FleetReport");

    let config = Config {
        repos: vec![Repo {
            id: RepoId("cc".into()),
            path: cross_crate_dir(),
            glob: false,
            glob_max_depth: 0,
            vex_product_id: None,
            ecosystem: None,
        }],
        ignores: vec![],
        vex: Default::default(),
        vex_assertions: vec![],
    };

    assess(
        &mut report,
        &config,
        &Options {
            driver: &driver,
            features: fleetreach_reach::FeatureSelection::default(),
            sandbox: fleetreach_reach::SandboxPolicy::Off,
            verbose: true,
        },
    );

    let finding = &report.vulnerabilities[0];
    let reach = finding
        .reachability
        .as_ref()
        .expect("static engine set a reachability verdict");
    use fleetreach_core::ReachVerdict;
    match &reach.verdict {
        ReachVerdict::Reachable { witness } => {
            assert!(witness.last().is_some_and(|l| l.contains("vulnerable_fn")));
            assert_eq!(finding.reachable, Some(true), "legacy bool mapped");
        }
        other => panic!("expected Reachable, got {other:?}"),
    }
}

#[test]
#[ignore = "requires pinned nightly + built reach-driver; run with --ignored"]
fn uninstantiated_generic_dependency_fn_is_not_reachable() {
    // The dependency `vuln_gen` exports a *generic* `vulnerable_generic` that the
    // bin never calls, so it is never monomorphized and has no graph node. The
    // driver records it as an exported generic def (positive evidence), letting
    // the engine soundly upgrade Unknown → NotReachable rather than fail closed.
    let driver = driver_path();
    assert!(
        driver.exists(),
        "build the driver first: (cd crates/reach-driver && cargo build)"
    );

    let mut report: FleetReport = serde_json::from_value(json!({
        "schema_version": 1,
        "provenance": {
            "tool_version": "0.1.0",
            "rustsec_crate_version": "0.33.0",
            "db_commit": null,
            "db_timestamp": null,
            "host_os": "macos",
            "host_arch": "x86_64",
            "generated_at": "2026-06-24T00:00:00Z"
        },
        "summary": {
            "repos_scanned": 1,
            "repos_errored": 0,
            "vuln_count": 1,
            "warn_count": 0,
            "max_severity": "high",
            "stale_ignores": []
        },
        "vulnerabilities": [{
            "advisory_id": "RUSTSEC-2099-0002",
            "aliases": [],
            "title": "vulnerable_generic is bad",
            "severity": "high",
            "url": null,
            "affected_functions": ["vuln_gen::vulnerable_generic"],
            "occurrences": [{
                "kind": "in_repo",
                "repo": "gu",
                "package": "vuln_gen",
                "installed": "0.0.0",
                "patched": [],
                "dependency_kind": "direct"
            }]
        }],
        "warnings": [],
        "outcomes": []
    }))
    .expect("construct FleetReport");

    let config = Config {
        repos: vec![Repo {
            id: RepoId("gu".into()),
            path: generic_uninstantiated_dir(),
            glob: false,
            glob_max_depth: 0,
            vex_product_id: None,
            ecosystem: None,
        }],
        ignores: vec![],
        vex: Default::default(),
        vex_assertions: vec![],
    };

    assess(
        &mut report,
        &config,
        &Options {
            driver: &driver,
            features: fleetreach_reach::FeatureSelection::default(),
            sandbox: fleetreach_reach::SandboxPolicy::Off,
            verbose: true,
        },
    );

    let finding = &report.vulnerabilities[0];
    let reach = finding
        .reachability
        .as_ref()
        .expect("static engine set a reachability verdict");
    use fleetreach_core::ReachVerdict;
    match &reach.verdict {
        ReachVerdict::NotReachable => {
            assert_eq!(finding.reachable, Some(false), "legacy bool mapped");
        }
        other => panic!("expected NotReachable, got {other:?}"),
    }
}
