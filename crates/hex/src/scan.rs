//! Tier-C scan for Hex: read a repo's `mix.lock`, match every installed package against the
//! offline OSV DB, and emit a module-level [`VulnFinding`] per affected package.
//!
//! Like the other Tier-C paths this is the lowest-fidelity tier — package + version matching
//! only, so every finding is `Unknown` reachability (never `NotReachable`). The trade is that
//! it is **safe by construction**: it parses the lockfile and compares versions, never running
//! `mix`/Elixir or any package's build, so it needs no untrusted-build consent and no sandbox.

use std::path::Path;

use fleetreach_core::osv::{sort_dedup_findings, Match, TierCFinding, TierCScan};
use fleetreach_core::semver::{Version, VersionReq};
use fleetreach_core::{Ecosystem, RepoId, VulnFinding};

use crate::db::{affected_fixed, Advisory, HexDb};
use crate::error::HexError;
use crate::lockfile::{installed_packages, InstalledPackage};

/// Parse a Hex package version (plain SemVer, tolerating a leading `v`). Public for parity
/// with the other feeders.
pub fn parse_hex_version(raw: &str) -> Option<Version> {
    Version::parse(raw.trim().strip_prefix('v').unwrap_or(raw.trim())).ok()
}

/// Scan the Elixir project at `repo_dir` (containing `mix.lock`) against the preloaded OSV DB,
/// without an Elixir toolchain. Emits one module-level [`VulnFinding`] per affected package;
/// output is sorted by `(advisory id, package)` for determinism.
///
/// # Errors
///
/// Returns [`HexError::Db`] if `mix.lock` is missing or cannot be read — failing closed, so an
/// unreadable/absent lockfile is an honest gap rather than a false-clean scan.
pub fn scan_offline(repo_dir: &Path, db: &HexDb, repo: &RepoId) -> Result<TierCScan, HexError> {
    let lock_path = repo_dir.join("mix.lock");
    let lock_text = std::fs::read_to_string(&lock_path).map_err(|e| HexError::db(&lock_path, e))?;
    let (installed, graph) = installed_packages(&lock_text);

    let mut out: Vec<VulnFinding> = Vec::new();
    let mut skipped_unparseable = 0u32;
    for pkg in &installed {
        let Some(version) = parse_hex_version(&pkg.version) else {
            skipped_unparseable += 1;
            continue;
        };
        // The representative introducer chain `[(root), …, pkg]`, computed once per package.
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

/// Build a finding if `adv` lists `pkg` as affected at `version` (a SemVer version).
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
        .and_then(|f| VersionReq::parse(&format!(">={f}")).ok())
        .into_iter()
        .collect();

    Some(
        TierCFinding {
            ecosystem: Ecosystem::Hex,
            advisory_id: adv.id.clone(),
            aliases: adv.aliases.clone(),
            title: adv.summary.clone().unwrap_or_else(|| adv.id.clone()),
            severity: adv.severity,
            cvss_score: adv.cvss_score,
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

    fn pkg(name: &str, version: &str) -> InstalledPackage {
        InstalledPackage {
            name: name.to_string(),
            version: version.to_string(),
            direct: false,
        }
    }

    #[test]
    fn affected_package_becomes_a_finding() {
        let a = adv("GHSA-hx", "1.15.2");
        let f = match_advisory(
            &a,
            &pkg("hackney", "1.15.0"),
            &parse_hex_version("1.15.0").unwrap(),
            &["(root)".into(), "phoenix".into(), "hackney".into()],
            &RepoId("r".into()),
        )
        .unwrap();
        assert_eq!(f.ecosystem, Ecosystem::Hex);
        match &f.occurrences[0] {
            Occurrence::InRepo {
                package,
                dependency_kind,
                dependency_path,
                ..
            } => {
                assert_eq!(package, "hackney");
                assert_eq!(*dependency_kind, DependencyKind::Transitive);
                assert_eq!(dependency_path, &["(root)", "phoenix", "hackney"]);
            }
            _ => panic!("expected InRepo"),
        }
    }

    #[test]
    fn patched_version_is_not_a_finding() {
        let a = adv("GHSA-hx", "1.15.2");
        assert!(match_advisory(
            &a,
            &pkg("hackney", "1.15.2"),
            &parse_hex_version("1.15.2").unwrap(),
            &[],
            &RepoId("r".into())
        )
        .is_none());
    }
}
