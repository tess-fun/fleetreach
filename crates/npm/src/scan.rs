//! Tier-C scan for npm: read a repo's `package-lock.json`, match every installed
//! package against the offline OSV DB, and emit a module-level [`VulnFinding`] per
//! affected package.
//!
//! Like the Go Tier-C path this is the lowest-fidelity tier — package + version
//! matching only, so every finding is `Unknown` reachability (never `NotReachable`).
//! The trade is that it is **safe by construction**: it parses the lockfile and
//! compares versions, never running `npm` or any package's install scripts, so it
//! needs no untrusted-build consent and no sandbox.

use std::path::Path;

use fleetreach_core::osv::{sort_dedup_findings, Match, TierCFinding, TierCScan};
use fleetreach_core::semver::{Version, VersionReq};
use fleetreach_core::{Ecosystem, RepoId, VulnFinding};

use crate::db::{affected_fixed, Advisory, NpmDb};
use crate::error::NpmError;
use crate::lockfile::{parse_lockfile, InstalledPackage};

/// Scan the npm project at `repo_dir` (containing `package-lock.json`) against the
/// preloaded OSV DB, without an `npm` toolchain. Emits one module-level
/// [`VulnFinding`] per affected package; output is sorted by `(advisory id, package)`
/// for determinism.
///
/// # Errors
///
/// Returns [`NpmError::Db`] if `package-lock.json` is missing or cannot be parsed —
/// failing closed, so an unreadable lockfile is an honest gap rather than a
/// false-clean scan.
pub fn scan_offline(repo_dir: &Path, db: &NpmDb, repo: &RepoId) -> Result<TierCScan, NpmError> {
    let lock_path = repo_dir.join("package-lock.json");
    let body = std::fs::read_to_string(&lock_path).map_err(|e| NpmError::db(&lock_path, e))?;
    let (installed, graph) = parse_lockfile(&body).map_err(|e| NpmError::db(&lock_path, e))?;

    let mut out: Vec<VulnFinding> = Vec::new();
    let mut skipped_unparseable = 0u32;
    for pkg in &installed {
        let Some(version) = parse_npm_version(&pkg.version) else {
            // A non-SemVer resolved version (a git/url/file dependency pin) cannot be
            // matched against the registry advisory DB. Skipping it does not hide a
            // registry advisory (the artifact is not from the registry), so unlike an
            // unparseable Go module version this is not a soundness gap — but the count is
            // surfaced so the skip is visible rather than silent.
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

/// Build a finding if `adv` lists `pkg` as affected at `version`.
fn match_advisory(
    adv: &Advisory,
    pkg: &InstalledPackage,
    version: &Version,
    dependency_path: &[String],
    repo: &RepoId,
) -> Option<VulnFinding> {
    let Match::Affected { fixed } = affected_fixed(version, &adv.ranges) else {
        return None;
    };
    let patched: Vec<VersionReq> = fixed
        .as_ref()
        .and_then(|f| VersionReq::parse(&format!(">={f}")).ok())
        .into_iter()
        .collect();

    Some(
        TierCFinding {
            ecosystem: Ecosystem::Npm,
            advisory_id: adv.id.clone(),
            aliases: adv.aliases.clone(),
            title: adv.summary.clone().unwrap_or_else(|| adv.id.clone()),
            severity: adv.severity,
            // npm derives severity from the GitHub band only; it does not extract a CVSS score.
            cvss_score: None,
            package: pkg.name.clone(),
            installed: version.clone(),
            patched,
            direct: pkg.direct,
            dependency_path: dependency_path.to_vec(),
            repo,
            reach_reason: "package-level scan (no toolchain): version match only",
        }
        .build(),
    )
}

/// Parse a lockfile-resolved version string into a [`Version`]. npm versions are plain
/// SemVer; a leading `v` is tolerated. Returns `None` for a non-SemVer pin (a git sha,
/// `file:`/`link:` spec, or url), which has no registry advisory to match.
pub fn parse_npm_version(raw: &str) -> Option<Version> {
    Version::parse(raw.strip_prefix('v').unwrap_or(raw)).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::db::parse_bound;
    use fleetreach_core::osv::{self, Event, Range};
    use fleetreach_core::{DependencyKind, Occurrence, ReachVerdict};

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
            severity: fleetreach_core::Severity::High,
            cvss_score: None,
            ranges: vec![osv::parse_range(&range, parse_bound)],
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
        let a = adv("GHSA-aaaa", "4.17.21");
        let p = pkg("lodash", "4.17.20", true);
        let f = match_advisory(
            &a,
            &p,
            &parse_npm_version("4.17.20").unwrap(),
            &[],
            &RepoId("r".into()),
        )
        .unwrap();
        assert_eq!(f.advisory_id, "GHSA-aaaa");
        assert_eq!(f.ecosystem, Ecosystem::Npm);
        assert_eq!(f.severity, fleetreach_core::Severity::High);
        match &f.occurrences[0] {
            Occurrence::InRepo {
                package,
                dependency_kind,
                patched,
                ..
            } => {
                assert_eq!(package, "lodash");
                assert_eq!(*dependency_kind, DependencyKind::Direct);
                assert!(patched[0].matches(&Version::parse("4.17.21").unwrap()));
            }
            _ => panic!("expected InRepo"),
        }
        // Reachability is the Tier-C Unknown contract, never NotReachable.
        assert!(matches!(
            f.reachability.unwrap().verdict,
            ReachVerdict::Unknown { .. }
        ));
    }

    #[test]
    fn patched_version_is_not_a_finding() {
        let a = adv("GHSA-aaaa", "4.17.21");
        let p = pkg("lodash", "4.17.21", true);
        assert!(match_advisory(
            &a,
            &p,
            &parse_npm_version("4.17.21").unwrap(),
            &[],
            &RepoId("r".into())
        )
        .is_none());
    }

    #[test]
    fn non_semver_version_parses_to_none() {
        assert!(parse_npm_version("git+https://x/y#abc").is_none());
        assert!(parse_npm_version("1.2.3").is_some());
        assert!(parse_npm_version("v1.2.3").is_some());
    }
}
