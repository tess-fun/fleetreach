//! Tier-C scan for RubyGems: read a repo's `Gemfile.lock`, match every installed gem
//! against the offline OSV DB, and emit a module-level [`VulnFinding`] per affected gem.
//!
//! Like the Go, npm, and PyPI Tier-C paths this is the lowest-fidelity tier — package +
//! version matching only, so every finding is `Unknown` reachability (never
//! `NotReachable`). The trade is that it is **safe by construction**: it parses the
//! lockfile and compares versions, never running `bundler`/`gem` or any gem's build, so it
//! needs no untrusted-build consent and no sandbox.

use std::path::Path;

use fleetreach_core::osv::{sort_dedup_findings, Match, TierCFinding, TierCScan};
use fleetreach_core::semver::VersionReq;
use fleetreach_core::{Ecosystem, RepoId, VulnFinding};

use crate::db::{affected_fixed, Advisory, RubyGemsDb};
use crate::error::RubyGemsError;
use crate::lockfile::{dependency_graph, installed_gems, InstalledGem};
use crate::version::{parse_rubygems_version, to_semver, Version};

/// Scan the Ruby project at `repo_dir` (containing `Gemfile.lock`) against the preloaded
/// OSV DB, without a Ruby toolchain. Emits one module-level [`VulnFinding`] per affected
/// gem; output is sorted by `(advisory id, gem)` for determinism.
///
/// # Errors
///
/// Returns [`RubyGemsError::Db`] if `Gemfile.lock` is missing or cannot be read — failing
/// closed, so an unreadable/absent lockfile is an honest gap rather than a false-clean scan.
pub fn scan_offline(
    repo_dir: &Path,
    db: &RubyGemsDb,
    repo: &RepoId,
) -> Result<TierCScan, RubyGemsError> {
    let lock_path = repo_dir.join("Gemfile.lock");
    let body = std::fs::read_to_string(&lock_path).map_err(|e| RubyGemsError::db(&lock_path, e))?;
    let installed = installed_gems(&body);
    let graph = dependency_graph(&body);

    let mut out: Vec<VulnFinding> = Vec::new();
    let mut skipped_unparseable = 0u32;
    for gem in &installed {
        let Some(version) = parse_rubygems_version(&gem.version) else {
            // A non-Gem::Version pin (a git-ref or path resolution that slipped through)
            // cannot be matched against the registry advisory DB. Skipping it does not hide
            // a RubyGems advisory (the artifact is not a registry release), so this is not a
            // soundness gap — the same stance as the npm/PyPI feeders' non-registry pins.
            skipped_unparseable += 1;
            continue;
        };
        let dependency_path = graph.chain_to(&gem.name);
        for adv in db.advisories_for(&gem.name) {
            if let Some(finding) = match_advisory(adv, gem, &version, &dependency_path, repo) {
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

/// Build a finding if `adv` lists `gem` as affected at `version` (a `Gem::Version`).
fn match_advisory(
    adv: &Advisory,
    gem: &InstalledGem,
    version: &Version,
    dependency_path: &[String],
    repo: &RepoId,
) -> Option<VulnFinding> {
    // A gem is affected if a range covers the version OR the record explicitly lists it.
    // The range path supplies the `fixed` hint; a version-only match has no fix metadata.
    let fixed = match affected_fixed(version, &adv.ranges) {
        Match::Affected { fixed } => fixed,
        Match::NotAffected if adv.versions.binary_search(version).is_ok() => None,
        Match::NotAffected => return None,
    };
    // The fix and installed version are stored in the shared model's SemVer form (see
    // `to_semver`); detection above used the true Gem::Version comparison.
    let patched: Vec<VersionReq> = fixed
        .as_ref()
        .and_then(|f| VersionReq::parse(&format!(">={}", to_semver(f))).ok())
        .into_iter()
        .collect();

    Some(
        TierCFinding {
            ecosystem: Ecosystem::RubyGems,
            advisory_id: adv.id.clone(),
            aliases: adv.aliases.clone(),
            title: adv.summary.clone().unwrap_or_else(|| adv.id.clone()),
            severity: adv.severity,
            cvss_score: adv.cvss_score,
            package: gem.name.clone(),
            installed: to_semver(version),
            patched,
            direct: gem.direct,
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
            ranges: vec![osv::parse_range(&range, parse_rubygems_version)],
            versions: vec![],
        }
    }

    fn gem(name: &str, version: &str, direct: bool) -> InstalledGem {
        InstalledGem {
            name: name.to_string(),
            version: version.to_string(),
            direct,
        }
    }

    #[test]
    fn affected_gem_becomes_a_finding() {
        let a = adv("GHSA-aaaa", "2.2.8");
        let p = gem("rack", "2.2.7", true);
        let path = vec!["(root)".to_string(), "rack".to_string()];
        let f = match_advisory(
            &a,
            &p,
            &parse_rubygems_version("2.2.7").unwrap(),
            &path,
            &RepoId("r".into()),
        )
        .unwrap();
        assert_eq!(f.advisory_id, "GHSA-aaaa");
        assert_eq!(f.ecosystem, Ecosystem::RubyGems);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.cvss_score, Some(7.5));
        match &f.occurrences[0] {
            Occurrence::InRepo {
                package,
                dependency_kind,
                patched,
                installed,
                dependency_path,
                ..
            } => {
                assert_eq!(package, "rack", "verbatim gem name");
                assert_eq!(installed.to_string(), "2.2.7");
                assert_eq!(*dependency_kind, DependencyKind::Direct);
                assert_eq!(
                    dependency_path,
                    &vec!["(root)".to_string(), "rack".to_string()]
                );
                assert!(patched[0].matches(&to_semver(&parse_rubygems_version("2.2.8").unwrap())));
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
        let p = gem("rack", "2.2.8", true);
        assert!(match_advisory(
            &a,
            &p,
            &parse_rubygems_version("2.2.8").unwrap(),
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
            versions: vec![parse_rubygems_version("1.0.0").unwrap()],
        };
        let p = gem("evil", "1.0.0", false);
        // A version-only record (no range) must still match via the enumerated `versions`.
        let f = match_advisory(
            &a,
            &p,
            &parse_rubygems_version("1.0.0").unwrap(),
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
            &gem("evil", "1.0.1", false),
            &parse_rubygems_version("1.0.1").unwrap(),
            &[],
            &RepoId("r".into())
        )
        .is_none());
    }

    #[test]
    fn prerelease_in_affected_window_is_flagged() {
        // 1.0.0.beta is in [0, 1.0.0): a vulnerable prerelease must be reported, and its
        // stored version must order below the 1.0.0 fix.
        let a = adv("GHSA-pre", "1.0.0");
        let f = match_advisory(
            &a,
            &gem("x", "1.0.0.beta", false),
            &parse_rubygems_version("1.0.0.beta").unwrap(),
            &[],
            &RepoId("r".into()),
        )
        .unwrap();
        match &f.occurrences[0] {
            Occurrence::InRepo {
                installed, patched, ..
            } => {
                assert_eq!(installed.to_string(), "1.0.0-beta");
                assert!(!patched[0].matches(installed));
            }
            _ => panic!("expected InRepo"),
        }
    }
}
