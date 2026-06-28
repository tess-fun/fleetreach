//! End-to-end Tier-C scan from disk: load a directory of OSV records, read a real
//! `package-lock.json`, and check the findings (match, direct/transitive, dedup,
//! determinism, fail-closed on a missing lockfile).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fleetreach_core::{DependencyKind, Ecosystem, Occurrence, RepoId, Severity};
use fleetreach_npm::{scan_offline, NpmDb};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn db() -> NpmDb {
    NpmDb::load(&fixtures().join("db")).expect("load fixture OSV DB")
}

#[test]
fn loads_only_npm_advisories_skipping_non_json() {
    let db = db();
    // Two OSV JSON records (lodash, minimist); the .txt file is ignored.
    assert_eq!(db.len(), 2);
    assert!(!db.advisories_for("lodash").is_empty());
    assert!(db.advisories_for("nonexistent").is_empty());
}

#[test]
fn loads_from_a_zip_identically_to_a_directory() {
    // The osv.dev export ships as one `all.zip`; reading it directly must produce the
    // same index as the unzipped directory (it's the perf path, not a different result).
    let from_zip = NpmDb::load(&fixtures().join("db.zip")).expect("load fixture db.zip");
    assert_eq!(from_zip.len(), db().len());
    let dir_lodash = db().advisories_for("lodash")[0].id.clone();
    assert_eq!(from_zip.advisories_for("lodash")[0].id, dir_lodash);
    assert_eq!(
        from_zip.advisories_for("minimist")[0].severity,
        Severity::Critical
    );
}

#[test]
fn scans_a_lockfile_into_findings() {
    let findings = scan_offline(&fixtures().join("repo"), &db(), &RepoId("demo-app".into()))
        .expect("scan succeeds")
        .findings;

    // lodash (direct, HIGH) + minimist (transitive, CRITICAL); express and safe-pkg
    // are not in the DB. Sorted by advisory id: GHSA-p6mc (lodash) < GHSA-vh95 (minimist).
    assert_eq!(findings.len(), 2);

    let lodash = findings
        .iter()
        .find(|f| f.advisory_id == "GHSA-p6mc-m468-83gw")
        .expect("lodash finding");
    assert_eq!(lodash.ecosystem, Ecosystem::Npm);
    assert_eq!(lodash.severity, Severity::High);
    assert_eq!(lodash.aliases, vec!["CVE-2020-8203"]);
    match &lodash.occurrences[0] {
        Occurrence::InRepo {
            package,
            dependency_kind,
            ..
        } => {
            assert_eq!(package, "lodash");
            assert_eq!(*dependency_kind, DependencyKind::Direct);
        }
        _ => panic!("expected InRepo"),
    }

    let minimist = findings
        .iter()
        .find(|f| f.advisory_id == "GHSA-vh95-rmgr-6w4m")
        .expect("minimist finding");
    assert_eq!(minimist.severity, Severity::Critical);
    match &minimist.occurrences[0] {
        Occurrence::InRepo {
            dependency_kind, ..
        } => assert_eq!(*dependency_kind, DependencyKind::Transitive),
        _ => panic!("expected InRepo"),
    }
}

#[test]
fn scan_is_deterministic() {
    let a = scan_offline(&fixtures().join("repo"), &db(), &RepoId("demo-app".into())).unwrap();
    let b = scan_offline(&fixtures().join("repo"), &db(), &RepoId("demo-app".into())).unwrap();
    let ids = |v: &[fleetreach_core::VulnFinding]| {
        v.iter().map(|f| f.advisory_id.clone()).collect::<Vec<_>>()
    };
    assert_eq!(ids(&a.findings), ids(&b.findings));
}

#[test]
fn unparseable_version_is_counted_not_silently_dropped() {
    // The fixture pins `vcs-dep` to a git URL, which is not a SemVer registry version. It is
    // correctly skipped (a VCS pin has no registry advisory), but the skip must be *counted*
    // and surfaced, not silent — so a malformed-but-real version is distinguishable from clean.
    let scan = scan_offline(&fixtures().join("repo"), &db(), &RepoId("demo-app".into()))
        .expect("scan succeeds");
    assert_eq!(
        scan.skipped_unparseable, 1,
        "the git-pinned dep must be counted"
    );
    // The skip does not change the real findings (lodash + minimist).
    assert_eq!(scan.findings.len(), 2);
}

#[test]
fn missing_lockfile_fails_closed() {
    // A repo dir with no package-lock.json is an honest error, never a clean scan.
    let err = scan_offline(&fixtures(), &db(), &RepoId("x".into())).unwrap_err();
    assert!(err.to_string().contains("package-lock.json"), "{err}");
}
