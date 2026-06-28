//! Tier-C scan for Swift: read a repo's `Package.resolved`, match every installed package
//! against the offline OSV DB, and emit a module-level [`VulnFinding`] per affected package.
//!
//! Like the other Tier-C paths this is the lowest-fidelity tier — package + version matching
//! only, so every finding is `Unknown` reachability (never `NotReachable`). The trade is that
//! it is **safe by construction**: it parses the lockfile and compares versions, never running
//! `swift`/SwiftPM or any package's build, so it needs no untrusted-build consent and no
//! sandbox.

use std::path::Path;

use fleetreach_core::osv::{sort_dedup_findings, Match, TierCFinding, TierCScan};
use fleetreach_core::semver::{Version, VersionReq};
use fleetreach_core::{Ecosystem, RepoId, VulnFinding};

use crate::db::{affected_fixed, Advisory, SwiftDb};
use crate::error::SwiftError;
use crate::lockfile::{installed_packages, InstalledPackage};

/// Parse a Swift package version (plain SemVer, tolerating a leading `v`). Public for parity
/// with the other feeders.
pub fn parse_swift_version(raw: &str) -> Option<Version> {
    Version::parse(raw.trim().strip_prefix('v').unwrap_or(raw.trim())).ok()
}

/// Scan the Swift project at `repo_dir` (containing `Package.resolved`) against the preloaded
/// OSV DB, without a Swift toolchain. The sibling `Package.swift`, if present, marks which
/// packages are direct dependencies. Emits one module-level [`VulnFinding`] per affected
/// package; output is sorted by `(advisory id, package)` for determinism.
///
/// # Errors
///
/// Returns [`SwiftError::Db`] if `Package.resolved` is missing, cannot be read, or is not valid
/// JSON — failing closed, so an unreadable/absent/corrupt lockfile is an honest gap.
pub fn scan_offline(repo_dir: &Path, db: &SwiftDb, repo: &RepoId) -> Result<TierCScan, SwiftError> {
    let resolved_path = repo_dir.join("Package.resolved");
    let resolved =
        std::fs::read_to_string(&resolved_path).map_err(|e| SwiftError::db(&resolved_path, e))?;
    let package_swift = std::fs::read_to_string(repo_dir.join("Package.swift")).ok();
    let installed = installed_packages(&resolved, package_swift.as_deref())
        .map_err(|e| SwiftError::db(&resolved_path, e))?;

    let mut out: Vec<VulnFinding> = Vec::new();
    let mut skipped_unparseable = 0u32;
    for pkg in &installed {
        let Some(version) = parse_swift_version(&pkg.version) else {
            skipped_unparseable += 1;
            continue;
        };
        for adv in db.advisories_for(&pkg.name) {
            if let Some(finding) = match_advisory(adv, pkg, &version, repo) {
                out.push(finding);
            }
        }
    }
    sort_dedup_findings(&mut out);
    Ok(TierCScan {
        findings: out,
        skipped_unparseable,
    })
}

/// Build a finding if `adv` lists `pkg` as affected at `version` (a SemVer version).
fn match_advisory(
    adv: &Advisory,
    pkg: &InstalledPackage,
    version: &Version,
    repo: &RepoId,
) -> Option<VulnFinding> {
    let fixed = match affected_fixed(version, &adv.ranges) {
        Match::Affected { fixed } => fixed,
        Match::NotAffected if adv.versions.binary_search(version).is_ok() => None,
        Match::NotAffected => return None,
    };
    let patched: Vec<VersionReq> = fixed
        .as_ref()
        .and_then(|f| VersionReq::parse(&format!(">={f}")).ok())
        .into_iter()
        .collect();

    Some(
        TierCFinding {
            ecosystem: Ecosystem::Swift,
            advisory_id: adv.id.clone(),
            aliases: adv.aliases.clone(),
            title: adv.summary.clone().unwrap_or_else(|| adv.id.clone()),
            severity: adv.severity,
            cvss_score: adv.cvss_score,
            package: pkg.name.clone(),
            installed: version.clone(),
            patched,
            direct: pkg.direct,
            dependency_path: Vec::new(),
            repo,
            reach_reason: "package-level scan (no toolchain): version match only",
        }
        .build(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use fleetreach_core::osv::{self, Event, Range};
    use fleetreach_core::{DependencyKind, Occurrence, Severity};

    fn adv(id: &str, fixed: &str) -> Advisory {
        let range = Range {
            matchable: true,
            events: vec![
                Event {
                    introduced: Some("0".into()),
                    fixed: None,
                    last_affected: None,
                },
                Event {
                    introduced: None,
                    fixed: Some(fixed.into()),
                    last_affected: None,
                },
            ],
        };
        Advisory {
            id: id.to_string(),
            aliases: vec![],
            summary: Some(format!("bug in {id}")),
            severity: Severity::High,
            cvss_score: Some(7.5),
            ranges: vec![osv::parse_range(&range, crate::db::parse_bound)],
            versions: vec![],
        }
    }

    fn pkg(name: &str, version: &str, direct: bool) -> InstalledPackage {
        InstalledPackage {
            name: name.to_string(),
            version: version.to_string(),
            direct,
        }
    }

    #[test]
    fn affected_package_becomes_a_finding() {
        let a = adv("GHSA-sw", "2.41.0");
        let p = pkg("github.com/apple/swift-nio", "2.40.0", true);
        let f = match_advisory(
            &a,
            &p,
            &parse_swift_version("2.40.0").unwrap(),
            &RepoId("r".into()),
        )
        .unwrap();
        assert_eq!(f.ecosystem, Ecosystem::Swift);
        match &f.occurrences[0] {
            Occurrence::InRepo {
                package,
                dependency_kind,
                installed,
                ..
            } => {
                assert_eq!(package, "github.com/apple/swift-nio");
                assert_eq!(installed.to_string(), "2.40.0");
                assert_eq!(*dependency_kind, DependencyKind::Direct);
            }
            _ => panic!("expected InRepo"),
        }
    }

    #[test]
    fn patched_version_is_not_a_finding() {
        let a = adv("GHSA-sw", "2.41.0");
        assert!(match_advisory(
            &a,
            &pkg("github.com/apple/swift-nio", "2.41.0", true),
            &parse_swift_version("2.41.0").unwrap(),
            &RepoId("r".into())
        )
        .is_none());
    }
}
