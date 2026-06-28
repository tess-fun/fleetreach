//! The serde wire contract (§5, §9). These pin the externally-visible JSON shape
//! so a careless field rename or `rename_all` change is caught immediately.
#![allow(clippy::unwrap_used, clippy::panic)]

use fleetreach_core::semver::{Version, VersionReq};
use fleetreach_core::{
    DepSource, DependencyKind, Occurrence, Provenance, RepoId, RepoOutcome, ScanStatus, Severity,
    WarnKind,
};

#[test]
fn provenance_serializes_absent_db_fields_as_null() {
    let provenance = Provenance {
        tool_version: "0.1.0".into(),
        rustsec_crate_version: "0.33.0".into(),
        db_commit: None,
        db_timestamp: None,
        host_os: "linux".into(),
        host_arch: "x86_64".into(),
        generated_at: "2026-06-24T00:00:00Z".into(),
    };
    let v = serde_json::to_value(&provenance).unwrap();
    // Honest absence: null, never an empty string.
    assert!(v["db_commit"].is_null());
    assert!(v["db_timestamp"].is_null());
}

#[test]
fn severity_serializes_lowercase() {
    assert_eq!(
        serde_json::to_string(&Severity::Critical).unwrap(),
        "\"critical\""
    );
    assert_eq!(
        serde_json::to_string(&Severity::Unknown).unwrap(),
        "\"unknown\""
    );
}

#[test]
fn severity_orders_with_critical_highest() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Unknown);

    let worst = [Severity::Low, Severity::Critical, Severity::Medium]
        .into_iter()
        .max()
        .unwrap();
    assert_eq!(worst, Severity::Critical);
}

#[test]
fn in_repo_occurrence_is_internally_tagged() {
    let occ = Occurrence::InRepo {
        repo: RepoId("core-lib".into()),
        package: "foo".into(),
        installed: Version::new(1, 2, 0),
        patched: vec![VersionReq::parse(">=1.2.3").unwrap()],
        dependency_kind: DependencyKind::Transitive,
        dependency_path: vec![],
        active: None,
        source: Default::default(),
    };
    let v = serde_json::to_value(&occ).unwrap();
    assert_eq!(v["kind"], "in_repo");
    assert_eq!(v["repo"], "core-lib"); // RepoId is transparent, not an object
    assert_eq!(v["package"], "foo");
    assert_eq!(v["installed"], "1.2.0"); // semver::Version -> string at the boundary
    assert_eq!(v["dependency_kind"], "transitive");
    // A crates.io source is the default, so it is omitted — `schema_version: 1`
    // JSON is byte-identical to before the field existed.
    assert!(
        v.get("source").is_none(),
        "default crates.io source is omitted"
    );
}

#[test]
fn dep_source_is_additive_and_round_trips() {
    // A non-crates.io source is emitted and survives a round-trip; the default is
    // CratesIo, so an occurrence with no `source` in its JSON deserializes to it.
    let git = Occurrence::InRepo {
        repo: RepoId("app".into()),
        package: "foo".into(),
        installed: Version::new(1, 0, 0),
        patched: vec![],
        dependency_kind: DependencyKind::Direct,
        dependency_path: vec![],
        active: None,
        source: DepSource::Git {
            url: "https://github.com/o/r".into(),
            rev: Some("abc123".into()),
        },
    };
    let v = serde_json::to_value(&git).unwrap();
    assert_eq!(v["source"]["git"]["url"], "https://github.com/o/r");
    assert_eq!(v["source"]["git"]["rev"], "abc123");
    let back: Occurrence = serde_json::from_value(v).unwrap();
    assert_eq!(back, git);

    // Legacy JSON without `source` defaults to crates.io.
    let legacy = serde_json::json!({
        "kind": "in_repo",
        "repo": "app",
        "package": "foo",
        "installed": "1.0.0",
        "patched": [],
        "dependency_kind": "direct"
    });
    let occ: Occurrence = serde_json::from_value(legacy).unwrap();
    let Occurrence::InRepo { source, .. } = occ else {
        panic!("expected in_repo");
    };
    assert_eq!(source, DepSource::CratesIo);
}

#[test]
fn toolchain_occurrence_uses_its_own_tag() {
    let occ = Occurrence::Toolchain {
        channel: "stable 1.96".into(),
        installed: None,
        patched: vec![],
    };
    let v = serde_json::to_value(&occ).unwrap();
    assert_eq!(v["kind"], "toolchain");
    assert!(v.get("repo").is_none());
    assert!(v["installed"].is_null());
}

#[test]
fn warn_kind_serializes_lowercase() {
    assert_eq!(
        serde_json::to_string(&WarnKind::Unmaintained).unwrap(),
        "\"unmaintained\""
    );
}

#[test]
fn repo_outcome_flattens_status_tag() {
    let outcome = RepoOutcome {
        repo: RepoId("core-lib".into()),
        status: ScanStatus::Scanned {
            vulns: 2,
            warnings: 1,
        },
    };
    let v = serde_json::to_value(&outcome).unwrap();
    assert_eq!(v["repo"], "core-lib");
    assert_eq!(v["status"], "scanned");
    assert_eq!(v["vulns"], 2);
    assert_eq!(v["warnings"], 1);

    let errored = RepoOutcome {
        repo: RepoId("services".into()),
        status: ScanStatus::Errored {
            reason: "missing Cargo.lock".into(),
        },
    };
    let v = serde_json::to_value(&errored).unwrap();
    assert_eq!(v["status"], "errored");
    assert_eq!(v["reason"], "missing Cargo.lock");
}
