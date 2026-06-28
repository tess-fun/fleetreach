//! R8 differential (spec §9): static reachability vs the grep heuristic, on a
//! case engineered to make them disagree — and to show the static engine is the
//! one that's right.
//!
//! `boom`'s NAME appears in the repo source (so the heuristic flags it
//! `Some(true)` — possibly reachable), but it is only address-taken, never
//! called, so static reachability soundly proves it `NotReachable`. Under
//! `--reachable-only` the heuristic would KEEP the finding (it cannot prove
//! absence); the static engine DROPS it. That precision is the whole point.
//!
//! Ignored by default (the static half needs the nightly + built driver). Run:
//!   (cd crates/reach-driver && cargo build)
//!   cargo test -p fleetreach-cli --test differential -- --ignored

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fleetreach_cli::config::{Config, Repo};
use fleetreach_cli::{reach, static_reach};
use fleetreach_core::{FleetReport, ReachVerdict, RepoId};
use serde_json::json;

fn driver_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .join("reach-driver/target/debug/fleetreach-reach-driver")
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/projects/differential")
}

fn report() -> FleetReport {
    serde_json::from_value(json!({
        "schema_version": 1,
        "provenance": {
            "tool_version": "0.1.0", "rustsec_crate_version": "0.33.0",
            "db_commit": null, "db_timestamp": null,
            "host_os": "linux", "host_arch": "x86_64",
            "generated_at": "2026-06-24T00:00:00Z"
        },
        "summary": {
            "repos_scanned": 1, "repos_errored": 0, "vuln_count": 1,
            "warn_count": 0, "max_severity": "high", "stale_ignores": []
        },
        "vulnerabilities": [{
            "advisory_id": "RUSTSEC-2099-0001",
            "aliases": [], "title": "boom is bad", "severity": "high", "url": null,
            "affected_functions": ["differential::boom"],
            "occurrences": [{
                "kind": "in_repo", "repo": "d", "package": "differential",
                "installed": "0.0.0", "patched": [], "dependency_kind": "direct"
            }]
        }],
        "warnings": [], "outcomes": []
    }))
    .expect("FleetReport")
}

fn config() -> Config {
    Config {
        repos: vec![Repo {
            id: RepoId("d".into()),
            path: fixture_dir(),
            glob: false,
            glob_max_depth: 0,
            vex_product_id: None,
            ecosystem: None,
        }],
        ignores: vec![],
        vex: Default::default(),
        vex_assertions: vec![],
    }
}

#[test]
#[ignore = "static half needs the pinned nightly + built reach-driver; run with --ignored"]
fn static_proves_unreachable_where_the_heuristic_only_sees_the_name() {
    // --- Heuristic: the name `boom` appears in the repo source → Some(true). ---
    let mut heuristic = report();
    reach::assess(&mut heuristic, &config());
    assert_eq!(
        heuristic.vulnerabilities[0].reachable,
        Some(true),
        "heuristic matches the name in source"
    );

    // --- Static: `boom` is collected but never called → NotReachable. ---
    let driver = driver_path();
    assert!(driver.exists(), "build the driver first");
    let mut statik = report();
    static_reach::assess(
        &mut statik,
        &config(),
        &static_reach::Options {
            driver: &driver,
            features: fleetreach_reach::FeatureSelection::default(),
            sandbox: fleetreach_reach::SandboxPolicy::Off,
            verbose: true,
        },
    );
    let v = &statik.vulnerabilities[0];
    assert_eq!(
        v.reachability.as_ref().map(|r| &r.verdict),
        Some(&ReachVerdict::NotReachable),
        "static proves boom is not called"
    );
    assert_eq!(
        v.reachable,
        Some(false),
        "legacy bool reflects NotReachable"
    );

    // The payoff: the two engines disagree, and the sound one suppresses.
    assert_ne!(
        heuristic.vulnerabilities[0].reachable, statik.vulnerabilities[0].reachable,
        "this case exists to show the heuristic over-keeps where static suppresses"
    );
}
