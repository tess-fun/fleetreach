//! Tier-C scan for Julia: read a repo's `Manifest.toml`, match every installed package
//! against the offline OSV DB, and emit a module-level [`VulnFinding`] per affected package.
//!
//! Like the other Tier-C paths this is the lowest-fidelity tier — package + version matching
//! only, so every finding is `Unknown` reachability (never `NotReachable`). The trade is that
//! it is **safe by construction**: it parses the manifest and compares versions, never running
//! `julia`/`Pkg` or any package's build, so it needs no untrusted-build consent and no sandbox.

use std::path::Path;

use fleetreach_core::osv::{sort_dedup_findings, Match, TierCFinding, TierCScan};
use fleetreach_core::semver::VersionReq;
use fleetreach_core::{Ecosystem, RepoId, VulnFinding};

use crate::db::{affected_fixed, Advisory, JuliaDb};
use crate::error::JuliaError;
use crate::lockfile::{installed_packages, InstalledPackage};
use crate::version::{parse_julia_version, to_semver, Version};

/// Scan the Julia project at `repo_dir` (containing `Manifest.toml`) against the preloaded
/// OSV DB, without a Julia toolchain. The sibling `Project.toml`, if present, marks which
/// packages are direct dependencies. Emits one module-level [`VulnFinding`] per affected
/// package; output is sorted by `(advisory id, package)` for determinism.
///
/// # Errors
///
/// Returns [`JuliaError::Db`] if `Manifest.toml` is missing, cannot be read, or is not valid
/// TOML — failing closed, so an unreadable/absent/corrupt manifest is an honest gap.
pub fn scan_offline(repo_dir: &Path, db: &JuliaDb, repo: &RepoId) -> Result<TierCScan, JuliaError> {
    let manifest_path = repo_dir.join("Manifest.toml");
    let manifest =
        std::fs::read_to_string(&manifest_path).map_err(|e| JuliaError::db(&manifest_path, e))?;
    // Project.toml is optional context for the direct/transitive flag.
    let project = std::fs::read_to_string(repo_dir.join("Project.toml")).ok();
    let (installed, graph) = installed_packages(&manifest, project.as_deref())
        .map_err(|e| JuliaError::db(&manifest_path, e))?;

    let mut out: Vec<VulnFinding> = Vec::new();
    let mut skipped_unparseable = 0u32;
    for pkg in &installed {
        let Some(version) = parse_julia_version(&pkg.version) else {
            skipped_unparseable += 1;
            continue;
        };
        // The representative introducer chain `[root, …, pkg]`, computed once per package.
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

/// Build a finding if `adv` lists `pkg` as affected at `version` (a Julia version).
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
            ecosystem: Ecosystem::Julia,
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
            ranges: vec![osv::parse_range(&range, parse_julia_version)],
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
    fn affected_jll_package_becomes_a_finding() {
        let a = adv("GHSA-jll", "3.0.11+0");
        let p = pkg("OpenSSL_jll", "3.0.8+0", false);
        let f = match_advisory(
            &a,
            &p,
            &parse_julia_version("3.0.8+0").unwrap(),
            &[],
            &RepoId("r".into()),
        )
        .unwrap();
        assert_eq!(f.advisory_id, "GHSA-jll");
        assert_eq!(f.ecosystem, Ecosystem::Julia);
        match &f.occurrences[0] {
            Occurrence::InRepo {
                package,
                dependency_kind,
                ..
            } => {
                assert_eq!(package, "OpenSSL_jll");
                assert_eq!(*dependency_kind, DependencyKind::Transitive);
            }
            _ => panic!("expected InRepo"),
        }
    }

    #[test]
    fn patched_build_is_not_a_finding() {
        let a = adv("GHSA-jll", "3.0.11+0");
        assert!(match_advisory(
            &a,
            &pkg("OpenSSL_jll", "3.0.11+0", false),
            &parse_julia_version("3.0.11+0").unwrap(),
            &[],
            &RepoId("r".into())
        )
        .is_none());
    }
}
