//! Fail-closed edge cases for the per-occurrence verdict.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fleetreach_core::semver::{Version, VersionReq};
use fleetreach_core::{DependencyKind, Occurrence, RepoId};

fn in_repo(installed: Version, patched: Vec<VersionReq>) -> Occurrence {
    Occurrence::InRepo {
        repo: RepoId("r".into()),
        package: "p".into(),
        installed,
        patched,
        dependency_kind: DependencyKind::Transitive,
        dependency_path: vec![],
        active: None,
        source: Default::default(),
    }
}

#[test]
fn empty_patched_set_is_vulnerable() {
    // No published fix -> vulnerable, no matter the installed version.
    assert!(in_repo(Version::new(9, 9, 9), vec![]).is_vulnerable());
}

#[test]
fn installed_at_or_above_patch_is_not_vulnerable() {
    let patched = vec![VersionReq::parse(">=1.2.3").unwrap()];
    assert!(!in_repo(Version::new(1, 2, 3), patched.clone()).is_vulnerable());
    assert!(in_repo(Version::new(1, 2, 2), patched).is_vulnerable());
}

#[test]
fn toolchain_with_unknown_version_is_vulnerable() {
    let occ = Occurrence::Toolchain {
        channel: "stable".into(),
        installed: None,
        patched: vec![VersionReq::parse(">=1.50.0").unwrap()],
    };
    assert!(
        occ.is_vulnerable(),
        "unknown installed version is fail-closed"
    );
}
