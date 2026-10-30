//! PyPI package-import-graph reachability: a vulnerable distribution is `Reachable` (with a
//! witness import-chain) when first-party code reaches it directly or through installed
//! distributions in the repo's virtualenv; otherwise `Unknown`, never `NotReachable`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fleetreach_cli::config::Config;
use fleetreach_cli::py_reach;
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
        generated_at: "2026-10-30T00:00:00Z".into(),
    }
}

fn pypi_finding(id: &str, repo: &str, package: &str) -> VulnFinding {
    VulnFinding {
        advisory_id: id.into(),
        aliases: vec![],
        ecosystem: Ecosystem::Pypi,
        affected_functions: vec![],
        reachable: None,
        reachability: None,
        exploit: Exploitability::default(),
        title: id.into(),
        severity: fleetreach_core::Severity::High,
        cvss_score: None,
        url: None,
        occurrences: vec![Occurrence::InRepo {
            repo: RepoId(repo.into()),
            package: package.into(),
            installed: Version::new(1, 0, 0),
            patched: vec![],
            dependency_kind: DependencyKind::Transitive,
            dependency_path: vec![],
            active: None,
            source: Default::default(),
            scope: Default::default(),
        }],
    }
}

fn config() -> Config {
    Config::from_str(
        r#"
        [[repo]]
        id = "app"
        path = "py-reach/app"
        ecosystem = "pypi"
        [[repo]]
        id = "novenv"
        path = "py-reach/novenv"
        ecosystem = "pypi"
        "#,
        &base(),
        "reach.toml",
    )
    .expect("valid config")
}

fn assessed(findings: Vec<VulnFinding>) -> fleetreach_core::FleetReport {
    let scan = ScanData {
        vulnerabilities: findings,
        warnings: vec![],
        outcomes: vec![],
        skipped_unparseable: 0,
        unsupported_lockfiles: Vec::new(),
    };
    let mut report = build_report(scan, &[], None, provenance());
    py_reach::assess(&mut report, &config());
    report
}

fn witness(report: &fleetreach_core::FleetReport, id: &str) -> Option<Vec<String>> {
    let v = report
        .vulnerabilities
        .iter()
        .find(|v| v.advisory_id == id)
        .unwrap();
    match &v.reachability.as_ref().unwrap().verdict {
        ReachVerdict::Reachable { witness } => {
            assert_eq!(v.reachable, Some(true));
            Some(witness.clone())
        }
        ReachVerdict::Unknown { .. } => None,
        ReachVerdict::NotReachable => panic!("{id}: the Python engine never claims NotReachable"),
    }
}

#[test]
fn witness_chains_through_the_virtualenv() {
    let report = assessed(vec![
        pypi_finding("MULTIPART", "app", "python-multipart"),
        pypi_finding("YAML", "app", "PyYAML"),
        pypi_finding("PLUGIN", "app", "myplugin"),
        pypi_finding("UNUSED", "app", "unused-lib"),
    ]);
    // An optional import inside a dependency of a dependency is still found.
    assert_eq!(
        witness(&report, "MULTIPART"),
        Some(vec![
            "fastapi".to_string(),
            "starlette".to_string(),
            "python-multipart".to_string()
        ])
    );
    // `import yaml` resolves to the PyYAML distribution through its RECORD.
    assert_eq!(witness(&report, "YAML"), Some(vec!["pyyaml".to_string()]));
    // A plugin host loading entry points reaches the registered plugin.
    assert_eq!(
        witness(&report, "PLUGIN"),
        Some(vec!["pluginhost".to_string(), "myplugin".to_string()])
    );
    // Installed but never imported (the app imports its own `internal.unused_lib`, which is
    // first-party code, not the distribution): unknown, not "not reachable".
    assert_eq!(witness(&report, "UNUSED"), None);
}

#[test]
fn without_a_virtualenv_direct_imports_still_witness() {
    let report = assessed(vec![
        pypi_finding("REQ", "novenv", "requests"),
        pypi_finding("URLLIB3", "novenv", "urllib3"),
    ]);
    assert_eq!(witness(&report, "REQ"), Some(vec!["requests".to_string()]));
    // Transitive without an environment: no graph to follow, so unknown.
    assert_eq!(witness(&report, "URLLIB3"), None);
}
