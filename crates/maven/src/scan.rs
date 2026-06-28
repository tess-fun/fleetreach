//! Tier-C scan for Maven: read a repo's `gradle.lockfile` (preferred) or `pom.xml`, match
//! every dependency against the offline OSV DB, and emit a module-level [`VulnFinding`] per
//! affected artifact.
//!
//! Like the other Tier-C paths this is the lowest-fidelity tier — package + version matching
//! only, so every finding is `Unknown` reachability (never `NotReachable`). It is **safe by
//! construction**: it parses the manifest and compares versions, never running `mvn`/`gradle`
//! or any plugin, so it needs no untrusted-build consent and no sandbox.

use std::path::Path;

use fleetreach_core::osv::{sort_dedup_findings, Match, TierCFinding, TierCScan};
use fleetreach_core::semver::VersionReq;
use fleetreach_core::{Ecosystem, RepoId, VulnFinding};

use crate::db::{affected_fixed, Advisory, MavenDb};
use crate::error::MavenError;
use crate::lockfile::{parse_gradle_lockfile, parse_pom_xml, InstalledPackage};
use crate::version::{parse_maven_version, to_semver, Version};

/// Scan the Java project at `repo_dir` against the preloaded OSV DB, without a Java toolchain.
/// Prefers a `gradle.lockfile` (the full resolved closure); otherwise reads `pom.xml` (direct
/// dependencies with literal versions). Emits one module-level [`VulnFinding`] per affected
/// artifact; output is sorted by `(advisory id, coordinate)` for determinism.
///
/// # Errors
///
/// Returns [`MavenError::Db`] if neither `gradle.lockfile` nor `pom.xml` can be read — failing
/// closed, so an unreadable/absent manifest is an honest gap.
pub fn scan_offline(repo_dir: &Path, db: &MavenDb, repo: &RepoId) -> Result<TierCScan, MavenError> {
    let gradle = repo_dir.join("gradle.lockfile");
    let pom = repo_dir.join("pom.xml");

    let installed: Vec<InstalledPackage> = if gradle.is_file() {
        let text = std::fs::read_to_string(&gradle).map_err(|e| MavenError::db(&gradle, e))?;
        parse_gradle_lockfile(&text)
    } else {
        let text = std::fs::read_to_string(&pom).map_err(|e| MavenError::db(&pom, e))?;
        parse_pom_xml(&text)
    };

    let mut out: Vec<VulnFinding> = Vec::new();
    let mut skipped_unparseable = 0u32;
    for pkg in &installed {
        let Some(version) = parse_maven_version(&pkg.version) else {
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

/// Build a finding if `adv` lists `pkg` as affected at `version` (a Maven version).
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
        .and_then(|f| VersionReq::parse(&format!(">={}", to_semver(f))).ok())
        .into_iter()
        .collect();

    Some(
        TierCFinding {
            ecosystem: Ecosystem::Maven,
            advisory_id: adv.id.clone(),
            aliases: adv.aliases.clone(),
            title: adv.summary.clone().unwrap_or_else(|| adv.id.clone()),
            severity: adv.severity,
            cvss_score: adv.cvss_score,
            package: pkg.name.clone(),
            installed: to_semver(version),
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
            ranges: vec![osv::parse_range(&range, parse_maven_version)],
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
    fn affected_artifact_becomes_a_finding() {
        let a = adv("GHSA-mvn", "2.9.10.7");
        let p = pkg(
            "com.fasterxml.jackson.core:jackson-databind",
            "2.9.8",
            false,
        );
        let f = match_advisory(
            &a,
            &p,
            &parse_maven_version("2.9.8").unwrap(),
            &RepoId("r".into()),
        )
        .unwrap();
        assert_eq!(f.ecosystem, Ecosystem::Maven);
        match &f.occurrences[0] {
            Occurrence::InRepo {
                package,
                dependency_kind,
                ..
            } => {
                assert_eq!(package, "com.fasterxml.jackson.core:jackson-databind");
                assert_eq!(*dependency_kind, DependencyKind::Transitive);
            }
            _ => panic!("expected InRepo"),
        }
    }

    #[test]
    fn patched_version_is_not_a_finding() {
        let a = adv("GHSA-mvn", "2.9.10.7");
        assert!(match_advisory(
            &a,
            &pkg("g:a", "2.9.10.7", true),
            &parse_maven_version("2.9.10.7").unwrap(),
            &RepoId("r".into())
        )
        .is_none());
    }
}
