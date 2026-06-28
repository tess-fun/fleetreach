//! Exploit-risk enrichment from local KEV/EPSS files (offline), plus the
//! risk-ranking that turns findings into an action queue.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use fleetreach_cli::enrich::{rank, Enrichment};
use fleetreach_core::semver::Version;
use fleetreach_core::{
    DependencyKind, Ecosystem, Exploitability, Occurrence, RepoId, Severity, VulnFinding,
};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn vuln(id: &str, cve: &str, severity: Severity) -> VulnFinding {
    VulnFinding {
        advisory_id: id.into(),
        aliases: vec![cve.into()],
        ecosystem: Default::default(),
        reachability: None,
        title: id.into(),
        severity,
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
        affected_functions: vec![],
        reachable: None,
        exploit: Exploitability::default(),
    }
}

fn vuln_eco(id: &str, cve: &str, severity: Severity, eco: Ecosystem) -> VulnFinding {
    VulnFinding {
        ecosystem: eco,
        ..vuln(id, cve, severity)
    }
}

/// P3 parity: enrichment keys purely on a finding's CVE aliases, so it backfills KEV/EPSS and
/// (for unknown findings) NVD severity identically for every ecosystem — not just Cargo/Go.
/// Confirmed live: a real PyPI scan EPSS-backfilled 24/26 findings via their CVE aliases.
#[test]
fn enrich_is_ecosystem_agnostic_keying_on_cve() {
    let enrichment = Enrichment {
        kev: BTreeSet::from(["CVE-2099-0001".to_string()]),
        epss: BTreeMap::from([("CVE-2099-0001".to_string(), 0.42)]),
        cvss: BTreeMap::from([("CVE-2022-0778".to_string(), 7.5)]),
    };
    let mut findings = vec![
        vuln_eco("npm-f", "CVE-2099-0001", Severity::High, Ecosystem::Npm),
        vuln_eco(
            "pypi-f",
            "CVE-2022-0778",
            Severity::Unknown,
            Ecosystem::Pypi,
        ),
        vuln_eco(
            "nuget-f",
            "CVE-2099-0001",
            Severity::Medium,
            Ecosystem::NuGet,
        ),
    ];
    enrichment.apply(&mut findings);

    // npm: KEV + EPSS applied by CVE, regardless of ecosystem.
    assert!(findings[0].exploit.kev, "npm finding gets KEV by CVE");
    assert!((findings[0].exploit.epss.unwrap() - 0.42).abs() < 1e-6);
    // pypi: an unknown-severity finding is severity-backfilled from NVD by CVE.
    assert_eq!(
        findings[1].severity,
        Severity::High,
        "pypi NVD severity backfill"
    );
    assert_eq!(findings[1].cvss_score, Some(7.5));
    // nuget: KEV + EPSS applied just the same.
    assert!(findings[2].exploit.kev, "nuget finding gets KEV by CVE");
    assert!((findings[2].exploit.epss.unwrap() - 0.42).abs() < 1e-6);
}

#[test]
fn from_files_annotates_kev_and_epss_by_cve() {
    let enrichment = Enrichment::from_files(
        Some(&fixtures().join("kev.json")),
        Some(&fixtures().join("epss.csv")),
    )
    .expect("load fixtures");

    let mut findings = vec![
        vuln("R1", "CVE-2099-0001", Severity::High), // KEV + high epss
        vuln("R2", "CVE-2099-0002", Severity::High), // not KEV, low epss
        vuln("R3", "CVE-2099-9999", Severity::High), // no data
    ];
    enrichment.apply(&mut findings);

    assert!(findings[0].exploit.kev, "R1 is in the KEV catalog");
    assert!((findings[0].exploit.epss.unwrap() - 0.97).abs() < 1e-4);

    assert!(!findings[1].exploit.kev);
    assert!((findings[1].exploit.epss.unwrap() - 0.012).abs() < 1e-4);

    assert!(!findings[2].exploit.kev);
    assert_eq!(findings[2].exploit.epss, None, "no enrichment data for R3");
}

#[test]
fn backfill_fills_unknown_severity_and_score_from_nvd_without_downgrading() {
    let enrichment = Enrichment {
        kev: BTreeSet::new(),
        epss: BTreeMap::new(),
        cvss: BTreeMap::from([
            ("CVE-2022-0778".to_string(), 7.5),
            ("CVE-2099-0002".to_string(), 9.5),
        ]),
    };

    let mut findings = vec![
        // unknown advisory (vendored C lib) gets the NVD severity + score
        vuln("R1", "CVE-2022-0778", Severity::Unknown),
        // already-scored advisory is left untouched, even if NVD says higher
        vuln("R2", "CVE-2099-0002", Severity::Medium),
        // unknown with no NVD data stays unknown
        vuln("R3", "CVE-2099-9999", Severity::Unknown),
    ];
    enrichment.apply(&mut findings);

    assert_eq!(findings[0].severity, Severity::High, "backfilled from NVD");
    assert_eq!(
        findings[0].cvss_score,
        Some(7.5),
        "numeric score is recorded"
    );
    assert_eq!(
        findings[1].severity,
        Severity::Medium,
        "never overrides a severity the advisory already carries"
    );
    assert_eq!(
        findings[1].cvss_score, None,
        "scored advisory left untouched"
    );
    assert_eq!(
        findings[2].severity,
        Severity::Unknown,
        "no NVD data, stays unknown"
    );
    assert_eq!(findings[2].cvss_score, None);
}

#[test]
fn backfill_takes_worst_score_across_aliases() {
    let enrichment = Enrichment {
        kev: BTreeSet::new(),
        epss: BTreeMap::new(),
        cvss: BTreeMap::from([
            ("CVE-2099-0001".to_string(), 3.5),
            ("CVE-2099-0002".to_string(), 9.5),
        ]),
    };

    let mut finding = vuln("R1", "CVE-2099-0001", Severity::Unknown);
    finding.aliases.push("CVE-2099-0002".into());
    let mut findings = vec![finding];
    enrichment.apply(&mut findings);

    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(findings[0].cvss_score, Some(9.5));
}

#[test]
fn summary_max_severity_is_refreshed_after_enrichment_backfill() {
    // Regression: the summary is built at correlate time, before enrichment. NVD
    // CVSS backfill turns an `unknown` finding (govulncheck / vendored-C case) into
    // a real severity; without a refresh the summary reports a stale `unknown` for a
    // fleet that is actually critical. (Network-only NVD is why this escaped the
    // offline tests, so it is exercised here with a hand-built cvss map.)
    use fleetreach_core::{FleetReport, Provenance, Summary, SCHEMA_VERSION};

    let mut report = FleetReport {
        schema_version: SCHEMA_VERSION,
        provenance: Provenance {
            tool_version: String::new(),
            rustsec_crate_version: String::new(),
            db_commit: None,
            db_timestamp: None,
            host_os: String::new(),
            host_arch: String::new(),
            generated_at: String::new(),
        },
        summary: Summary {
            repos_scanned: 1,
            repos_errored: 0,
            vuln_count: 1,
            warn_count: 0,
            max_severity: Severity::Unknown,
            stale_ignores: vec![],
        },
        vulnerabilities: vec![vuln("R1", "CVE-2022-0778", Severity::Unknown)],
        warnings: vec![],
        outcomes: vec![],
    };

    let enrichment = Enrichment {
        kev: BTreeSet::new(),
        epss: BTreeMap::new(),
        cvss: BTreeMap::from([("CVE-2022-0778".to_string(), 9.8)]),
    };
    enrichment.apply(&mut report.vulnerabilities);
    assert_eq!(report.vulnerabilities[0].severity, Severity::Critical);
    assert_eq!(
        report.summary.max_severity,
        Severity::Unknown,
        "summary is still stale until recomputed"
    );

    report.refresh_summary();
    assert_eq!(
        report.summary.max_severity,
        Severity::Critical,
        "summary reflects the enrichment-backfilled severity"
    );
}

#[test]
fn rank_puts_kev_first_then_epss_descending() {
    let with = |id: &str, kev: bool, epss: Option<f32>| {
        let mut v = vuln(id, "CVE-0000-0000", Severity::Low);
        v.exploit = Exploitability { kev, epss };
        v
    };
    let mut findings = vec![
        with("low-epss", false, Some(0.10)),
        with("kev", true, Some(0.05)),
        with("high-epss", false, Some(0.90)),
        with("none", false, None),
    ];
    rank(&mut findings);

    let order: Vec<&str> = findings.iter().map(|v| v.advisory_id.as_str()).collect();
    // KEV first (even with low epss), then epss desc, unknown last.
    assert_eq!(order, vec!["kev", "high-epss", "low-epss", "none"]);
}
