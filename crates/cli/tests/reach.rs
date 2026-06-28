//! The reachability heuristic: does an affected function name appear in a repo's
//! own source? Honest about its limits — a `Some(false)` only means "not in your
//! code", never "unreachable".
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fleetreach_cli::config::Config;
use fleetreach_cli::{build_report, reach, retain_reachable, ScanData};
use fleetreach_core::semver::Version;
use fleetreach_core::{
    DependencyKind, Ecosystem, Exploitability, Occurrence, Provenance, RepoId, RepoOutcome,
    ScanStatus, Severity, VulnFinding,
};

fn base() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn provenance() -> Provenance {
    Provenance {
        tool_version: "0.1.0".into(),
        rustsec_crate_version: "0.33.0".into(),
        db_commit: None,
        db_timestamp: None,
        host_os: "linux".into(),
        host_arch: "x86_64".into(),
        generated_at: "2026-06-24T00:00:00Z".into(),
    }
}

fn finding(id: &str, repo: &str) -> VulnFinding {
    VulnFinding {
        advisory_id: id.into(),
        aliases: vec![],
        ecosystem: Default::default(),
        affected_functions: vec!["fixturevuln::boom".into()],
        reachable: None,
        reachability: None,
        exploit: Exploitability::default(),
        title: id.into(),
        severity: Severity::High,
        cvss_score: None,
        url: None,
        occurrences: vec![Occurrence::InRepo {
            repo: RepoId(repo.into()),
            package: "fixturevuln".into(),
            installed: Version::new(1, 0, 0),
            patched: vec![],
            dependency_kind: DependencyKind::Transitive,
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
        id = "uses"
        path = "reach-uses"
        [[repo]]
        id = "clean"
        path = "reach-clean"
        "#,
        &base(),
        "reach.toml",
    )
    .expect("valid config")
}

#[test]
fn assess_flags_source_presence_per_repo() {
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![finding("R-USES", "uses"), finding("R-CLEAN", "clean")],
        warnings: vec![],
        outcomes: vec![
            RepoOutcome {
                repo: RepoId("uses".into()),
                status: ScanStatus::Scanned {
                    vulns: 1,
                    warnings: 0,
                },
            },
            RepoOutcome {
                repo: RepoId("clean".into()),
                status: ScanStatus::Scanned {
                    vulns: 1,
                    warnings: 0,
                },
            },
        ],
    };
    let mut report = build_report(scan, &[], None, provenance());
    reach::assess(&mut report, &config());

    let by_id = |id: &str| {
        report
            .vulnerabilities
            .iter()
            .find(|v| v.advisory_id == id)
            .unwrap()
            .reachable
    };
    assert_eq!(
        by_id("R-USES"),
        Some(true),
        "boom() appears in reach-uses source"
    );
    assert_eq!(
        by_id("R-CLEAN"),
        Some(false),
        "boom is not in reach-clean source"
    );

    // --reachable-only drops the not-found one, keeps the in-source one.
    let removed = retain_reachable(&mut report);
    assert_eq!(removed, 1);
    assert_eq!(report.vulnerabilities.len(), 1);
    assert_eq!(report.vulnerabilities[0].advisory_id, "R-USES");
}

/// A Tier-C finding for `package` in `repo`, of `kind`, in `eco`.
fn tier_c(
    id: &str,
    eco: Ecosystem,
    repo: &str,
    package: &str,
    kind: DependencyKind,
) -> VulnFinding {
    VulnFinding {
        advisory_id: id.into(),
        aliases: vec![],
        ecosystem: eco,
        affected_functions: vec![], // Tier-C advisories name no functions
        reachable: None,
        reachability: None,
        exploit: Exploitability::default(),
        title: id.into(),
        severity: Severity::High,
        cvss_score: None,
        url: None,
        occurrences: vec![Occurrence::InRepo {
            repo: RepoId(repo.into()),
            package: package.into(),
            installed: Version::new(1, 0, 0),
            patched: vec![],
            dependency_kind: kind,
            dependency_path: vec![],
            active: None,
            source: Default::default(),
        }],
    }
}

fn tier_c_config() -> Config {
    Config::from_str(
        r#"
        [[repo]]
        id = "npm"
        path = "reach-npm"
        ecosystem = "npm"
        [[repo]]
        id = "julia"
        path = "reach-julia"
        ecosystem = "julia"
        [[repo]]
        id = "ruby"
        path = "reach-rubygems"
        ecosystem = "rubygems"
        [[repo]]
        id = "pypi"
        path = "reach-pypi"
        ecosystem = "pypi"
        [[repo]]
        id = "nuget"
        path = "reach-nuget"
        ecosystem = "nuget"
        [[repo]]
        id = "maven"
        path = "reach-maven"
        ecosystem = "maven"
        [[repo]]
        id = "hex"
        path = "reach-hex"
        ecosystem = "hex"
        [[repo]]
        id = "gha"
        path = "reach-ghactions"
        ecosystem = "githubactions"
        "#,
        &base(),
        "reach.toml",
    )
    .expect("valid config")
}

#[test]
fn hex_and_github_actions_reachability() {
    use DependencyKind::Direct;
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![
            // Hex: package `plug` -> module `Plug`, used in app.ex
            tier_c("HEX-USED", Ecosystem::Hex, "hex", "plug", Direct),
            // Hex: an unused package stays None
            tier_c("HEX-UNUSED", Ecosystem::Hex, "hex", "ecto", Direct),
            // GitHub Actions: a `uses:` reference is an active CI step
            tier_c(
                "GHA-USED",
                Ecosystem::GitHubActions,
                "gha",
                "actions/checkout",
                Direct,
            ),
            // GitHub Actions: an action not referenced stays None
            tier_c(
                "GHA-UNUSED",
                Ecosystem::GitHubActions,
                "gha",
                "actions/setup-go",
                Direct,
            ),
        ],
        warnings: vec![],
        outcomes: vec![],
    };
    let mut report = build_report(scan, &[], None, provenance());
    reach::assess(&mut report, &tier_c_config());
    let by_id = |id: &str| {
        report
            .vulnerabilities
            .iter()
            .find(|v| v.advisory_id == id)
            .unwrap()
            .reachable
    };
    assert_eq!(by_id("HEX-USED"), Some(true), "Plug module used in app.ex");
    assert_eq!(by_id("HEX-UNUSED"), None, "unused hex dep stays unknown");
    assert_eq!(by_id("GHA-USED"), Some(true), "actions/checkout is used:");
    assert_eq!(
        by_id("GHA-UNUSED"),
        None,
        "unreferenced action stays unknown"
    );
    assert_eq!(retain_reachable(&mut report), 0, "never auto-suppress");
}

#[test]
fn name_mapping_ecosystems_detect_imports_securely() {
    use DependencyKind::{Direct, Transitive};
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![
            // imported direct deps -> Some(true) via the per-ecosystem name heuristic
            tier_c("PY-USED", Ecosystem::Pypi, "pypi", "requests", Direct),
            tier_c(
                "NG-USED",
                Ecosystem::NuGet,
                "nuget",
                "Newtonsoft.Json",
                Direct,
            ),
            tier_c(
                "MV-USED",
                Ecosystem::Maven,
                "maven",
                "org.apache.logging.log4j:log4j-core",
                Direct,
            ),
            // not imported (different package) direct dep -> stays None (NEVER Some(false))
            tier_c("PY-UNUSED", Ecosystem::Pypi, "pypi", "django", Direct),
            // transitive -> stays None
            tier_c(
                "NG-TRANS",
                Ecosystem::NuGet,
                "nuget",
                "Newtonsoft.Json",
                Transitive,
            ),
        ],
        warnings: vec![],
        outcomes: vec![],
    };
    let mut report = build_report(scan, &[], None, provenance());
    reach::assess(&mut report, &tier_c_config());

    let by_id = |id: &str| {
        report
            .vulnerabilities
            .iter()
            .find(|v| v.advisory_id == id)
            .unwrap()
            .reachable
    };
    assert_eq!(by_id("PY-USED"), Some(true), "requests imported in app.py");
    assert_eq!(
        by_id("NG-USED"),
        Some(true),
        "Newtonsoft.Json used in Program.cs"
    );
    assert_eq!(
        by_id("MV-USED"),
        Some(true),
        "log4j group imported in App.java"
    );
    // The secure invariant holds for the heuristic ecosystems too: never Some(false).
    assert_eq!(
        by_id("PY-UNUSED"),
        None,
        "unimported direct dep stays unknown"
    );
    assert_eq!(by_id("NG-TRANS"), None, "transitive stays unknown");

    let removed = retain_reachable(&mut report);
    assert_eq!(
        removed, 0,
        "a heuristic miss must never auto-suppress a finding"
    );
}

#[test]
fn tier_c_import_presence_is_secure() {
    use DependencyKind::{Direct, Transitive};
    let scan = ScanData {
        skipped_unparseable: 0,
        vulnerabilities: vec![
            // imported direct deps -> Some(true)
            tier_c("NPM-USED", Ecosystem::Npm, "npm", "lodash", Direct),
            tier_c("JL-USED", Ecosystem::Julia, "julia", "HTTP", Direct),
            tier_c("RB-USED", Ecosystem::RubyGems, "ruby", "rack", Direct),
            // direct dep NOT imported in source -> stays None (NEVER Some(false))
            tier_c("NPM-UNUSED", Ecosystem::Npm, "npm", "express", Direct),
            // transitive dep -> stays None (no import signal expected)
            tier_c("NPM-TRANS", Ecosystem::Npm, "npm", "lodash", Transitive),
        ],
        warnings: vec![],
        outcomes: vec![],
    };
    let mut report = build_report(scan, &[], None, provenance());
    reach::assess(&mut report, &tier_c_config());

    let by_id = |id: &str| {
        report
            .vulnerabilities
            .iter()
            .find(|v| v.advisory_id == id)
            .unwrap()
            .reachable
    };
    assert_eq!(
        by_id("NPM-USED"),
        Some(true),
        "lodash is required in app.js"
    );
    assert_eq!(by_id("JL-USED"), Some(true), "HTTP is `using`d in main.jl");
    assert_eq!(by_id("RB-USED"), Some(true), "rack is required in app.rb");
    // The secure invariant: an unimported or transitive Tier-C dep is NEVER Some(false).
    assert_eq!(
        by_id("NPM-UNUSED"),
        None,
        "unimported direct dep stays unknown"
    );
    assert_eq!(by_id("NPM-TRANS"), None, "transitive dep stays unknown");

    // --reachable-only must drop NOTHING here: no Tier-C finding is Some(false).
    let before = report.vulnerabilities.len();
    let removed = retain_reachable(&mut report);
    assert_eq!(
        removed, 0,
        "a grep miss must never auto-suppress a Tier-C finding"
    );
    assert_eq!(report.vulnerabilities.len(), before);
}
