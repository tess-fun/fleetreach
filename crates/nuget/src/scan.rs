//! Tier-C scan for NuGet: read a repo's `packages.lock.json`, match every installed package
//! against the offline OSV DB, and emit a module-level [`VulnFinding`] per affected package.
//!
//! Like the other Tier-C paths this is the lowest-fidelity tier — package + version matching
//! only, so every finding is `Unknown` reachability (never `NotReachable`). The trade is that
//! it is **safe by construction**: it parses the lockfile and compares versions, never running
//! `dotnet`/`nuget` or any package's build, so it needs no untrusted-build consent and no
//! sandbox.

use std::path::Path;

use fleetreach_core::osv::{sort_dedup_findings, Match, TierCFinding, TierCScan};
use fleetreach_core::semver::VersionReq;
use fleetreach_core::{Ecosystem, RepoId, VulnFinding};

use crate::db::{affected_fixed, Advisory, NuGetDb};
use crate::error::NuGetError;
use crate::lockfile::{parse_lockfile, InstalledPackage};
use crate::version::{parse_nuget_version, to_semver, Version};

/// Scan the .NET project at `repo_dir` (containing `packages.lock.json`) against the
/// preloaded OSV DB, without a .NET toolchain. Emits one module-level [`VulnFinding`] per
/// affected package; output is sorted by `(advisory id, package)` for determinism.
///
/// # Errors
///
/// Returns [`NuGetError::Db`] if `packages.lock.json` is missing, cannot be read, or is not
/// valid JSON — failing closed, so an unreadable/absent/corrupt lockfile is an honest gap.
pub fn scan_offline(repo_dir: &Path, db: &NuGetDb, repo: &RepoId) -> Result<TierCScan, NuGetError> {
    let lock_path = repo_dir.join("packages.lock.json");
    let lock_text =
        std::fs::read_to_string(&lock_path).map_err(|e| NuGetError::db(&lock_path, e))?;
    let (installed, graph) =
        parse_lockfile(&lock_text).map_err(|e| NuGetError::db(&lock_path, e))?;

    let mut out: Vec<VulnFinding> = Vec::new();
    let mut skipped_unparseable = 0u32;
    for pkg in &installed {
        let Some(version) = parse_nuget_version(&pkg.version) else {
            // A non-release pin (a project/floating reference that slipped through) has no
            // registry artifact to match. Skipping it does not hide a NuGet advisory.
            skipped_unparseable += 1;
            continue;
        };
        // The representative introducer chain `[root, …, pkg]` (pkg.name is lowercased,
        // matching the graph nodes), computed once per package.
        let dependency_path = graph.chain_to(&pkg.name);
        for adv in db.advisories_for(&pkg.name) {
            if let Some(finding) = match_advisory(adv, pkg, &version, &dependency_path, repo) {
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

/// Build a finding if `adv` lists `pkg` as affected at `version` (a NuGet version).
fn match_advisory(
    adv: &Advisory,
    pkg: &InstalledPackage,
    version: &Version,
    dependency_path: &[String],
    repo: &RepoId,
) -> Option<VulnFinding> {
    let fixed = match affected_fixed(version, &adv.ranges) {
        Match::Affected { fixed } => fixed,
        Match::NotAffected if adv.versions.binary_search(version).is_ok() => None,
        Match::NotAffected => return None,
    };
    let patched: Vec<VersionReq> = fixed
        .as_ref()
        .and_then(|f| VersionReq::parse(&format!(">={}", to_semver(f))).ok())
        .into_iter()
        .collect();

    Some(
        TierCFinding {
            ecosystem: Ecosystem::NuGet,
            advisory_id: adv.id.clone(),
            aliases: adv.aliases.clone(),
            title: adv.summary.clone().unwrap_or_else(|| adv.id.clone()),
            severity: adv.severity,
            cvss_score: adv.cvss_score,
            package: pkg.name.clone(),
            installed: to_semver(version),
            patched,
            direct: pkg.direct,
            dependency_path: dependency_path.to_vec(),
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
            ranges: vec![osv::parse_range(&range, parse_nuget_version)],
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
        let a = adv("GHSA-aaaa", "13.0.1");
        let p = pkg("newtonsoft.json", "12.0.3", true);
        let f = match_advisory(
            &a,
            &p,
            &parse_nuget_version("12.0.3").unwrap(),
            &[],
            &RepoId("r".into()),
        )
        .unwrap();
        assert_eq!(f.advisory_id, "GHSA-aaaa");
        assert_eq!(f.ecosystem, Ecosystem::NuGet);
        match &f.occurrences[0] {
            Occurrence::InRepo {
                package,
                dependency_kind,
                installed,
                ..
            } => {
                assert_eq!(package, "newtonsoft.json");
                assert_eq!(installed.to_string(), "12.0.3");
                assert_eq!(*dependency_kind, DependencyKind::Direct);
            }
            _ => panic!("expected InRepo"),
        }
    }

    #[test]
    fn patched_version_is_not_a_finding() {
        let a = adv("GHSA-aaaa", "13.0.1");
        assert!(match_advisory(
            &a,
            &pkg("newtonsoft.json", "13.0.1", true),
            &parse_nuget_version("13.0.1").unwrap(),
            &[],
            &RepoId("r".into())
        )
        .is_none());
    }

    #[test]
    fn version_only_record_matches_via_versions() {
        let a = Advisory {
            id: "GHSA-only".into(),
            aliases: vec![],
            summary: None,
            severity: Severity::Critical,
            cvss_score: None,
            ranges: vec![],
            versions: vec![parse_nuget_version("1.1.1.1").unwrap()],
        };
        assert!(match_advisory(
            &a,
            &pkg("p", "1.1.1.1", false),
            &parse_nuget_version("1.1.1.1").unwrap(),
            &[],
            &RepoId("r".into())
        )
        .is_some());
        assert!(match_advisory(
            &a,
            &pkg("p", "1.1.1.2", false),
            &parse_nuget_version("1.1.1.2").unwrap(),
            &[],
            &RepoId("r".into())
        )
        .is_none());
    }
}
