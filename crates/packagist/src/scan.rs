//! Tier-C scan for Packagist: read a repo's `composer.lock`, match every installed package
//! against the offline OSV DB, and emit a module-level [`VulnFinding`] per affected package.
//!
//! Like the Go, npm, PyPI, and RubyGems Tier-C paths this is the lowest-fidelity tier —
//! package + version matching only, so every finding is `Unknown` reachability (never
//! `NotReachable`). The trade is that it is **safe by construction**: it parses the lockfile
//! and compares versions, never running `composer`/`php` or any package's build, so it needs
//! no untrusted-build consent and no sandbox.

use std::path::Path;

use fleetreach_core::osv::{sort_dedup_findings, Match, TierCFinding, TierCScan};
use fleetreach_core::semver::VersionReq;
use fleetreach_core::{Ecosystem, RepoId, VulnFinding};

use crate::db::{affected_fixed, Advisory, PackagistDb};
use crate::error::PackagistError;
use crate::lockfile::{installed_packages, InstalledPackage};
use crate::version::{parse_composer_version, to_semver, Version};

/// Scan the PHP project at `repo_dir` (containing `composer.lock`) against the preloaded
/// OSV DB, without a PHP toolchain. The sibling `composer.json`, if present, marks which
/// packages are direct dependencies. Emits one module-level [`VulnFinding`] per affected
/// package; output is sorted by `(advisory id, package)` for determinism.
///
/// # Errors
///
/// Returns [`PackagistError::Db`] if `composer.lock` is missing, cannot be read, or is not
/// valid JSON — failing closed, so an unreadable/absent/corrupt lockfile is an honest gap
/// rather than a false-clean scan.
pub fn scan_offline(
    repo_dir: &Path,
    db: &PackagistDb,
    repo: &RepoId,
) -> Result<TierCScan, PackagistError> {
    let lock_path = repo_dir.join("composer.lock");
    let lock_text =
        std::fs::read_to_string(&lock_path).map_err(|e| PackagistError::db(&lock_path, e))?;
    // composer.json is optional context for the direct/transitive flag; a read failure just
    // leaves every package transitive (a conservative under-claim), never an error.
    let composer_json = std::fs::read_to_string(repo_dir.join("composer.json")).ok();
    let (installed, graph) = installed_packages(&lock_text, composer_json.as_deref())
        .map_err(|e| PackagistError::db(&lock_path, e))?;

    let mut out: Vec<VulnFinding> = Vec::new();
    let mut skipped_unparseable = 0u32;
    for pkg in &installed {
        let Some(version) = parse_composer_version(&pkg.version) else {
            // A non-release pin (a `dev-<branch>` VCS reference) cannot be matched against
            // the registry advisory DB. Skipping it does not hide a Packagist advisory (the
            // artifact is not a registry release), so this is not a soundness gap — the same
            // stance as the npm/PyPI/RubyGems feeders' non-registry pins.
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

/// Build a finding if `adv` lists `pkg` as affected at `version` (a Composer version).
fn match_advisory(
    adv: &Advisory,
    pkg: &InstalledPackage,
    version: &Version,
    dependency_path: &[String],
    repo: &RepoId,
) -> Option<VulnFinding> {
    // A package is affected if a range covers the version OR the record explicitly lists it.
    // The range path supplies the `fixed` hint; a version-only match has no fix metadata.
    let fixed = match affected_fixed(version, &adv.ranges) {
        Match::Affected { fixed } => fixed,
        Match::NotAffected if adv.versions.binary_search(version).is_ok() => None,
        Match::NotAffected => return None,
    };
    // The fix and installed version are stored in the shared model's SemVer form (see
    // `to_semver`); detection above used the true Composer comparison.
    let patched: Vec<VersionReq> = fixed
        .as_ref()
        .and_then(|f| VersionReq::parse(&format!(">={}", to_semver(f))).ok())
        .into_iter()
        .collect();

    Some(
        TierCFinding {
            ecosystem: Ecosystem::Packagist,
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
    use fleetreach_core::{DependencyKind, Occurrence, ReachVerdict, Severity};

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
            ranges: vec![osv::parse_range(&range, parse_composer_version)],
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
        let a = adv("GHSA-aaaa", "2.2.8");
        let p = pkg("monolog/monolog", "2.2.7", true);
        let f = match_advisory(
            &a,
            &p,
            &parse_composer_version("2.2.7").unwrap(),
            &[],
            &RepoId("r".into()),
        )
        .unwrap();
        assert_eq!(f.advisory_id, "GHSA-aaaa");
        assert_eq!(f.ecosystem, Ecosystem::Packagist);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.cvss_score, Some(7.5));
        match &f.occurrences[0] {
            Occurrence::InRepo {
                package,
                dependency_kind,
                patched,
                installed,
                ..
            } => {
                assert_eq!(package, "monolog/monolog");
                assert_eq!(installed.to_string(), "2.2.7");
                assert_eq!(*dependency_kind, DependencyKind::Direct);
                assert!(patched[0].matches(&to_semver(&parse_composer_version("2.2.8").unwrap())));
            }
            _ => panic!("expected InRepo"),
        }
        assert!(matches!(
            f.reachability.unwrap().verdict,
            ReachVerdict::Unknown { .. }
        ));
    }

    #[test]
    fn patched_version_is_not_a_finding() {
        let a = adv("GHSA-aaaa", "2.2.8");
        let p = pkg("monolog/monolog", "2.2.8", true);
        assert!(match_advisory(
            &a,
            &p,
            &parse_composer_version("2.2.8").unwrap(),
            &[],
            &RepoId("r".into())
        )
        .is_none());
    }

    #[test]
    fn magento_patch_install_above_fix_is_clean() {
        // fixed at 2.4.5; installed 2.4.5-p1 (a patch level above the release) is not a
        // finding — the Composer comparator orders it above the fix.
        let a = adv("GHSA-mag", "2.4.5");
        assert!(match_advisory(
            &a,
            &pkg("magento/community-edition", "2.4.5-p1", true),
            &parse_composer_version("2.4.5-p1").unwrap(),
            &[],
            &RepoId("r".into())
        )
        .is_none());
    }

    #[test]
    fn version_only_record_with_no_range_is_matched() {
        let a = Advisory {
            id: "GHSA-only".into(),
            aliases: vec![],
            summary: Some("listed versions".into()),
            severity: Severity::Critical,
            cvss_score: None,
            ranges: vec![],
            versions: vec![parse_composer_version("1.0.0").unwrap()],
        };
        let p = pkg("evil/pkg", "1.0.0", false);
        // A version-only record (no range) must still match via the enumerated `versions`.
        let f = match_advisory(
            &a,
            &p,
            &parse_composer_version("1.0.0").unwrap(),
            &[],
            &RepoId("r".into()),
        )
        .unwrap();
        assert_eq!(f.advisory_id, "GHSA-only");
        match &f.occurrences[0] {
            Occurrence::InRepo { patched, .. } => assert!(patched.is_empty()),
            _ => panic!("expected InRepo"),
        }
        // A different version is not matched by the enumerated list.
        assert!(match_advisory(
            &a,
            &pkg("evil/pkg", "1.0.1", false),
            &parse_composer_version("1.0.1").unwrap(),
            &[],
            &RepoId("r".into())
        )
        .is_none());
    }
}
