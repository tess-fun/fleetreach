//! End-to-end M2 test: a fixture advisory DB + a fixture lockfile, fully
//! offline and deterministic, exercising **both** the vulnerability and warning
//! streams. This is also the seed of the M6 golden-test net.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fleetreach_core::semver::Version;
use fleetreach_core::{DependencyKind, Occurrence, RepoId, Severity, WarnKind};
use fleetreach_scan::{scan_lockfile, scan_toolchain, AdvisoryDb};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn run() -> fleetreach_scan::RepoScan {
    let db = AdvisoryDb::open(&fixtures().join("advisory-db")).expect("open fixture db");
    let repo = RepoId("fixture-repo".into());
    scan_lockfile(&db, &repo, &fixtures().join("Cargo.lock")).expect("scan fixture lockfile")
}

#[test]
fn finds_the_vulnerability_with_mapped_severity() {
    let scan = run();
    assert_eq!(scan.vulnerabilities.len(), 1, "exactly one vuln expected");

    let vuln = &scan.vulnerabilities[0];
    assert_eq!(vuln.advisory_id, "RUSTSEC-2099-0001");
    assert_eq!(vuln.aliases, vec!["CVE-2099-0001".to_string()]);
    assert_eq!(vuln.severity, Severity::Critical); // CVSS 9.8
                                                   // The advisory scopes itself to specific functions at this version.
    assert_eq!(
        vuln.affected_functions,
        vec!["fixturevuln::boom".to_string()]
    );

    assert_eq!(vuln.occurrences.len(), 1);
    match &vuln.occurrences[0] {
        Occurrence::InRepo {
            repo,
            package,
            installed,
            patched,
            ..
        } => {
            assert_eq!(repo, &RepoId("fixture-repo".into()));
            assert_eq!(package, "fixturevuln");
            assert_eq!(installed.to_string(), "1.0.0");
            assert_eq!(patched.len(), 1);
            assert_eq!(patched[0].to_string(), ">=1.0.1");
        }
        other => panic!("expected InRepo occurrence, got {other:?}"),
    }
}

#[test]
fn finds_the_unmaintained_warning_in_a_separate_stream() {
    let scan = run();
    assert_eq!(scan.warnings.len(), 1, "exactly one warning expected");

    let warn = &scan.warnings[0];
    assert_eq!(warn.kind, WarnKind::Unmaintained);
    assert_eq!(warn.advisory_id.as_deref(), Some("RUSTSEC-2099-0002"));
    assert_eq!(warn.occurrences.len(), 1);
}

#[test]
fn streams_do_not_cross_contaminate() {
    let scan = run();
    // The unmaintained advisory must NOT appear among vulnerabilities, and the
    // CVE must NOT appear among warnings — separate streams, separate counts.
    assert!(scan
        .vulnerabilities
        .iter()
        .all(|v| v.advisory_id != "RUSTSEC-2099-0002"));
    assert!(scan
        .warnings
        .iter()
        .all(|w| w.advisory_id.as_deref() != Some("RUSTSEC-2099-0001")));
}

#[test]
fn toolchain_advisory_surfaces_for_an_affected_version() {
    let db = AdvisoryDb::open(&fixtures().join("advisory-db")).expect("open fixture db");
    let scan = scan_toolchain(&db, "stable 1.40.0", &Version::new(1, 40, 0));

    assert_eq!(scan.vulnerabilities.len(), 1);
    let vuln = &scan.vulnerabilities[0];
    assert_eq!(vuln.advisory_id, "RUSTSEC-2099-0003");
    match &vuln.occurrences[0] {
        Occurrence::Toolchain {
            channel,
            installed,
            patched,
        } => {
            assert_eq!(channel, "stable 1.40.0");
            assert_eq!(
                installed.as_ref().map(ToString::to_string).as_deref(),
                Some("1.40.0")
            );
            assert_eq!(patched[0].to_string(), ">=1.50.0");
        }
        other => panic!("expected Toolchain occurrence, got {other:?}"),
    }
}

#[test]
fn toolchain_advisory_absent_for_a_patched_version() {
    let db = AdvisoryDb::open(&fixtures().join("advisory-db")).expect("open fixture db");
    let scan = scan_toolchain(&db, "stable 1.96.0", &Version::new(1, 96, 0));
    assert!(scan.vulnerabilities.is_empty(), "1.96.0 is past the patch");
    assert!(scan.warnings.is_empty());
}

#[test]
fn vulnerability_carries_its_dependency_path() {
    let db = AdvisoryDb::open(&fixtures().join("advisory-db")).expect("open fixture db");
    let repo = RepoId("svc".into());
    let scan = scan_lockfile(&db, &repo, &fixtures().join("Cargo-transitive.lock"))
        .expect("scan transitive lockfile");

    assert_eq!(scan.vulnerabilities.len(), 1);
    match &scan.vulnerabilities[0].occurrences[0] {
        Occurrence::InRepo {
            package,
            dependency_kind,
            dependency_path,
            ..
        } => {
            assert_eq!(package, "fixturevuln");
            // The chain from the root crate down to the flagged package.
            assert_eq!(
                dependency_path,
                &vec![
                    "app".to_string(),
                    "middle".to_string(),
                    "fixturevuln".to_string()
                ]
            );
            assert_eq!(*dependency_kind, DependencyKind::Transitive);
        }
        other => panic!("expected InRepo occurrence, got {other:?}"),
    }
}

#[test]
fn routes_to_traces_a_package_into_the_tree() {
    let lock = fixtures().join("Cargo-transitive.lock");
    let routes = fleetreach_scan::routes_to(&lock, "fixturevuln").expect("routes");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].path, vec!["app", "middle", "fixturevuln"]);
    assert!(!routes[0].direct);

    // A package not in the tree yields no routes.
    assert!(fleetreach_scan::routes_to(&lock, "absent")
        .unwrap()
        .is_empty());
}

#[test]
fn explain_renders_known_advisory_and_misses_unknown() {
    let db = AdvisoryDb::open(&fixtures().join("advisory-db")).expect("open fixture db");

    let detail = db
        .explain("RUSTSEC-2099-0001")
        .expect("valid id")
        .expect("present");
    assert!(detail.contains("RUSTSEC-2099-0001"));
    assert!(detail.contains("Fixture vulnerability in fixturevuln"));
    assert!(detail.contains(">=1.0.1"));

    assert!(db.explain("RUSTSEC-2098-0001").expect("valid id").is_none());
    // A bogus id must never falsely resolve to an advisory.
    assert!(!matches!(db.explain("not-an-id"), Ok(Some(_))));
}
