//! Tier-C scan for GitHub Actions: read a repo's workflow files, match every `uses:` action
//! reference against the offline OSV DB, and emit a module-level [`VulnFinding`] per affected
//! action.
//!
//! This reads `.github/workflows/*.yml` (and a root `action.yml`/`action.yaml` for composite
//! actions), parses each `uses:` reference, and matches version-tag pins against the OSV
//! ranges. A branch or commit-SHA pin has no semantic version and is skipped (an honest gap).
//! Every finding is `Unknown` reachability (never `NotReachable`) — it is **safe by
//! construction**: it reads YAML and compares versions, running nothing.

use std::path::Path;

use fleetreach_core::osv::{sort_dedup_findings, Match, TierCFinding, TierCScan};
use fleetreach_core::semver::{Version, VersionReq};
use fleetreach_core::{Ecosystem, RepoId, VulnFinding};

use walkdir::WalkDir;

use crate::db::{affected_fixed, Advisory, GhActionsDb};
use crate::error::GhaError;
use crate::workflow::{parse_gha_version, used_actions, UsedAction};

/// Scan the repo at `repo_dir` for vulnerable GitHub Actions, without any toolchain. Reads
/// every workflow under `.github/workflows/` plus a root `action.yml`/`action.yaml`, matches
/// each version-pinned `uses:` reference against the preloaded OSV DB, and emits one
/// module-level [`VulnFinding`] per affected action; output is sorted by `(advisory id,
/// action)` for determinism.
///
/// # Errors
///
/// Returns [`GhaError::Db`] if `.github/workflows/` cannot be fully walked or a workflow file
/// cannot be read — failing closed, so an unreadable workflow is an honest gap.
pub fn scan_offline(
    repo_dir: &Path,
    db: &GhActionsDb,
    repo: &RepoId,
) -> Result<TierCScan, GhaError> {
    let mut actions: Vec<UsedAction> = Vec::new();

    // Every workflow under `.github/workflows/` (one or two levels, to allow includes).
    let workflows = repo_dir.join(".github").join("workflows");
    if workflows.is_dir() {
        for entry in WalkDir::new(&workflows).max_depth(2) {
            let entry = entry.map_err(|e| {
                GhaError::db(&workflows, crate::error::DbError::Walk(e.to_string()))
            })?;
            if entry.file_type().is_file() && is_yaml(entry.path()) {
                let text = std::fs::read_to_string(entry.path())
                    .map_err(|e| GhaError::db(entry.path(), e))?;
                actions.extend(used_actions(&text));
            }
        }
    }
    // A composite/reusable action at the repo root can `uses:` other actions too.
    for name in ["action.yml", "action.yaml"] {
        let path = repo_dir.join(name);
        if path.is_file() {
            let text = std::fs::read_to_string(&path).map_err(|e| GhaError::db(&path, e))?;
            actions.extend(used_actions(&text));
        }
    }
    actions.sort();
    actions.dedup();

    let mut out: Vec<VulnFinding> = Vec::new();
    let mut skipped_unparseable = 0u32;
    for action in &actions {
        let Some(version) = parse_gha_version(&action.version_ref) else {
            // A branch or commit-SHA pin has no semantic version to match (resolving a SHA to
            // its release would need the network), so it is skipped — an honest gap.
            skipped_unparseable += 1;
            continue;
        };
        for adv in db.advisories_for(&action.name) {
            if let Some(finding) = match_advisory(adv, action, &version, repo) {
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

fn is_yaml(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yml") | Some("yaml")
    )
}

/// Build a finding if `adv` lists `action` as affected at `version` (a parsed tag).
fn match_advisory(
    adv: &Advisory,
    action: &UsedAction,
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
            ecosystem: Ecosystem::GitHubActions,
            advisory_id: adv.id.clone(),
            aliases: adv.aliases.clone(),
            title: adv.summary.clone().unwrap_or_else(|| adv.id.clone()),
            severity: adv.severity,
            cvss_score: adv.cvss_score,
            package: action.name.clone(),
            installed: version.clone(),
            patched,
            // A workflow references an action directly.
            direct: true,
            dependency_path: Vec::new(),
            repo,
            reach_reason: "workflow scan (no toolchain): action version match only",
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
            severity: Severity::Critical,
            cvss_score: Some(9.8),
            ranges: vec![osv::parse_range(&range, parse_gha_version)],
            versions: vec![],
        }
    }

    fn action(name: &str, version_ref: &str) -> UsedAction {
        UsedAction {
            name: name.to_string(),
            version_ref: version_ref.to_string(),
        }
    }

    #[test]
    fn vulnerable_major_tag_pin_becomes_a_finding() {
        let a = adv("GHSA-gha", "46.0.1");
        let f = match_advisory(
            &a,
            &action("tj-actions/changed-files", "v44"),
            &parse_gha_version("v44").unwrap(),
            &RepoId("r".into()),
        )
        .unwrap();
        assert_eq!(f.ecosystem, Ecosystem::GitHubActions);
        match &f.occurrences[0] {
            Occurrence::InRepo {
                package,
                dependency_kind,
                ..
            } => {
                assert_eq!(package, "tj-actions/changed-files");
                assert_eq!(*dependency_kind, DependencyKind::Direct);
            }
            _ => panic!("expected InRepo"),
        }
    }

    #[test]
    fn patched_pin_is_not_a_finding() {
        let a = adv("GHSA-gha", "46.0.1");
        assert!(match_advisory(
            &a,
            &action("tj-actions/changed-files", "v46.0.1"),
            &parse_gha_version("v46.0.1").unwrap(),
            &RepoId("r".into())
        )
        .is_none());
    }
}
