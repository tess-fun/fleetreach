//! Multi-repo orchestration (§10 step 4): per-repo degradation, glob discovery
//! with a depth bound, and toolchain advisories — all offline against the
//! shared fixture advisory DB.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fleetreach_cli::config::Config;
use fleetreach_cli::orchestrate::{
    scan_fleet, GhActionsScan, GoScan, HexScan, JuliaScan, MavenScan, NpmScan, NuGetScan,
    PackagistScan, PyPiScan, RubyGemsScan, SwiftScan, Toolchain,
};
use fleetreach_core::semver::Version;
use fleetreach_core::{Occurrence, RepoId, ScanStatus};
use fleetreach_go::SandboxPolicy;
use fleetreach_scan::AdvisoryDb;

/// Neutral Go scan config: these Cargo-only fixtures never reach the Go path.
fn go() -> GoScan<'static> {
    GoScan {
        govulncheck: None,
        sandbox: SandboxPolicy::Off,
        vuln_db: None,
        offline: false,
    }
}

/// Neutral npm scan config: these Cargo-only fixtures never reach the npm path.
fn npm() -> NpmScan<'static> {
    NpmScan { vuln_db: None }
}

/// Neutral PyPI scan config: these Cargo-only fixtures never reach the PyPI path.
fn pypi() -> PyPiScan<'static> {
    PyPiScan { vuln_db: None }
}

/// Neutral RubyGems scan config: these Cargo-only fixtures never reach the RubyGems path.
fn rubygems() -> RubyGemsScan<'static> {
    RubyGemsScan { vuln_db: None }
}

/// Neutral Packagist scan config: these Cargo-only fixtures never reach the Packagist path.
fn packagist() -> PackagistScan<'static> {
    PackagistScan { vuln_db: None }
}

/// Neutral NuGet scan config: these Cargo-only fixtures never reach the NuGet path.
fn nuget() -> NuGetScan<'static> {
    NuGetScan { vuln_db: None }
}

/// Neutral Julia scan config: these Cargo-only fixtures never reach the Julia path.
fn julia() -> JuliaScan<'static> {
    JuliaScan { vuln_db: None }
}

/// Neutral Swift scan config: these Cargo-only fixtures never reach the Swift path.
fn swift() -> SwiftScan<'static> {
    SwiftScan { vuln_db: None }
}

/// Neutral Hex scan config: these Cargo-only fixtures never reach the Hex path.
fn hex() -> HexScan<'static> {
    HexScan { vuln_db: None }
}

/// Neutral GitHub Actions scan config: these Cargo-only fixtures never reach that path.
fn ghactions() -> GhActionsScan<'static> {
    GhActionsScan { vuln_db: None }
}

/// Neutral Maven scan config: these Cargo-only fixtures never reach the Maven path.
fn maven() -> MavenScan<'static> {
    MavenScan { vuln_db: None }
}

fn cli_fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn advisory_db() -> AdvisoryDb {
    // Reuse the scan crate's fixture advisory DB (one vuln, one unmaintained,
    // one toolchain advisory).
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scan/tests/fixtures/advisory-db");
    AdvisoryDb::open(&path).expect("open fixture advisory db")
}

const FLEET: &str = r#"
[[repo]]
id = "repo-vuln"
path = "repos/repo-vuln"

[[repo]]
id = "repo-warn"
path = "repos/repo-warn"

[[repo]]
id = "repo-empty"
path = "repos/repo-empty"

[[repo]]
id = "repo-glob"
path = "repos/repo-glob"
glob = true
glob_max_depth = 2
"#;

fn config() -> Config {
    Config::from_str(FLEET, &cli_fixtures(), "fleet.toml").expect("valid fleet config")
}

fn status_of<'a>(data: &'a fleetreach_cli::ScanData, id: &str) -> &'a ScanStatus {
    &data
        .outcomes
        .iter()
        .find(|o| o.repo == RepoId(id.into()))
        .unwrap_or_else(|| panic!("no outcome for {id}"))
        .status
}

#[test]
fn each_repo_degrades_independently() {
    let data = scan_fleet(
        &advisory_db(),
        &config(),
        None,
        None,
        &go(),
        &npm(),
        &pypi(),
        &rubygems(),
        &packagist(),
        &nuget(),
        &julia(),
        &swift(),
        &hex(),
        &ghactions(),
        &maven(),
    );

    assert_eq!(data.outcomes.len(), 4);
    assert_eq!(
        status_of(&data, "repo-vuln"),
        &ScanStatus::Scanned {
            vulns: 1,
            warnings: 0
        }
    );
    assert_eq!(
        status_of(&data, "repo-warn"),
        &ScanStatus::Scanned {
            vulns: 0,
            warnings: 1
        }
    );
    // No Cargo.lock -> Errored, but the run still produced the other repos.
    assert!(matches!(
        status_of(&data, "repo-empty"),
        ScanStatus::Errored { .. }
    ));
}

#[test]
fn glob_discovery_respects_the_depth_bound() {
    let data = scan_fleet(
        &advisory_db(),
        &config(),
        None,
        None,
        &go(),
        &npm(),
        &pypi(),
        &rubygems(),
        &packagist(),
        &nuget(),
        &julia(),
        &swift(),
        &hex(),
        &ghactions(),
        &maven(),
    );
    // svc-a/Cargo.lock is at depth 2 (found); svc-a/deep/Cargo.lock is at depth
    // 3 (excluded). So exactly one lockfile, one vuln.
    assert_eq!(
        status_of(&data, "repo-glob"),
        &ScanStatus::Scanned {
            vulns: 1,
            warnings: 0
        }
    );
}

#[test]
fn aggregates_findings_across_the_fleet() {
    let data = scan_fleet(
        &advisory_db(),
        &config(),
        None,
        None,
        &go(),
        &npm(),
        &pypi(),
        &rubygems(),
        &packagist(),
        &nuget(),
        &julia(),
        &swift(),
        &hex(),
        &ghactions(),
        &maven(),
    );
    // repo-vuln (1) + repo-glob (1) = 2 vulns; repo-warn = 1 warning.
    assert_eq!(data.vulnerabilities.len(), 2);
    assert_eq!(data.warnings.len(), 1);
    // Every pre-correlation finding carries exactly one occurrence.
    assert!(data
        .vulnerabilities
        .iter()
        .all(|v| v.occurrences.len() == 1));
}

#[test]
fn toolchain_advisory_joins_the_fleet_streams() {
    let toolchain = Toolchain {
        channel: "stable 1.40.0".into(),
        version: Version::new(1, 40, 0),
    };
    let data = scan_fleet(
        &advisory_db(),
        &config(),
        Some(&toolchain),
        None,
        &go(),
        &npm(),
        &pypi(),
        &rubygems(),
        &packagist(),
        &nuget(),
        &julia(),
        &swift(),
        &hex(),
        &ghactions(),
        &maven(),
    );

    // The 2 in-repo vulns plus the 1 toolchain vuln.
    assert_eq!(data.vulnerabilities.len(), 3);
    let toolchain_vuln = data
        .vulnerabilities
        .iter()
        .find(|v| v.advisory_id == "RUSTSEC-2099-0003")
        .expect("toolchain advisory present");
    assert!(matches!(
        toolchain_vuln.occurrences[0],
        Occurrence::Toolchain { .. }
    ));
}
