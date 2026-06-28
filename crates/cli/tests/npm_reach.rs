//! npm module-import-graph reachability: a vulnerable package is `Reachable` (with a witness
//! import-chain) when first-party code reaches it directly or transitively; `NotReachable`
//! (under the prune opt-in) when node_modules is present and no import path reaches it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fleetreach_cli::config::Config;
use fleetreach_cli::npm_reach::{self, Options};
use fleetreach_cli::{build_report, ScanData};
use fleetreach_core::semver::Version;
use fleetreach_core::{
    DependencyKind, Ecosystem, Exploitability, Occurrence, Provenance, ReachVerdict, RepoId,
    VulnFinding,
};

fn base() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn provenance() -> Provenance {
    Provenance {
        tool_version: "0".into(),
        rustsec_crate_version: "0".into(),
        db_commit: None,
        db_timestamp: None,
        host_os: "x".into(),
        host_arch: "x".into(),
        generated_at: "2026-06-28T00:00:00Z".into(),
    }
}

fn npm_finding(id: &str, package: &str) -> VulnFinding {
    VulnFinding {
        advisory_id: id.into(),
        aliases: vec![],
        ecosystem: Ecosystem::Npm,
        affected_functions: vec![],
        reachable: None,
        reachability: None,
        exploit: Exploitability::default(),
        title: id.into(),
        severity: fleetreach_core::Severity::High,
        cvss_score: None,
        url: None,
        occurrences: vec![Occurrence::InRepo {
            repo: RepoId("app".into()),
            package: package.into(),
            installed: Version::new(1, 0, 0),
            patched: vec![],
            dependency_kind: DependencyKind::Direct,
            dependency_path: vec![],
            active: None,
            source: Default::default(),
        }],
    }
}

fn config() -> Config {
    Config::from_str(
        r#"
        [[repo]]
        id = "app"
        path = "npm-reach/app"
        ecosystem = "npm"
        "#,
        &base(),
        "reach.toml",
    )
    .expect("valid config")
}

fn verdict_of<'a>(report: &'a fleetreach_core::FleetReport, id: &str) -> &'a ReachVerdict {
    &report
        .vulnerabilities
        .iter()
        .find(|v| v.advisory_id == id)
        .unwrap()
        .reachability
        .as_ref()
        .unwrap()
        .verdict
}

#[test]
fn import_graph_resolves_direct_transitive_and_prune() {
    // The fixture app imports lodash; lodash imports minimist (transitive); qs is in the lockfile
    // and node_modules but imported by nobody.
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![
            npm_finding("LODASH", "lodash"),
            npm_finding("MINIMIST", "minimist"),
            npm_finding("QS", "qs"),
        ],
        warnings: vec![],
        outcomes: vec![],
    };

    // Without prune: reached -> Reachable (+witness), unreached -> Unknown (never NotReachable).
    let mut report = build_report(scan.clone(), &[], None, provenance());
    npm_reach::assess(&mut report, &config(), &Options { prune: false });

    assert_eq!(
        verdict_of(&report, "LODASH"),
        &ReachVerdict::Reachable {
            witness: vec!["lodash".into()]
        },
        "directly imported"
    );
    assert_eq!(
        verdict_of(&report, "MINIMIST"),
        &ReachVerdict::Reachable {
            witness: vec!["lodash".into(), "minimist".into()]
        },
        "transitive: your code -> lodash -> minimist"
    );
    assert!(
        matches!(verdict_of(&report, "QS"), ReachVerdict::Unknown { .. }),
        "unreached stays Unknown without prune"
    );

    // With prune: qs is NotReachable (node_modules present, no path reaches it).
    let mut pruned = build_report(scan, &[], None, provenance());
    npm_reach::assess(&mut pruned, &config(), &Options { prune: true });
    assert_eq!(
        verdict_of(&pruned, "QS"),
        &ReachVerdict::NotReachable,
        "prune marks the unreached package NotReachable"
    );
    // The reachable ones are unaffected by prune.
    assert!(matches!(
        verdict_of(&pruned, "LODASH"),
        ReachVerdict::Reachable { .. }
    ));
}
