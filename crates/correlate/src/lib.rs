//! Fold per-repo, single-occurrence findings into deduplicated fleet-wide findings.
//!
//! `fleetreach-correlate` groups vulnerabilities by RUSTSEC id and warnings by
//! `(kind, id)`, conserving every occurrence (never dropped or invented) and
//! merging them into the group. The output is totally ordered (severity desc,
//! then id) with each finding's occurrences sorted, so identical inputs render
//! byte-identically. The per-occurrence verdict stays in `fleetreach-core`: the
//! same advisory can apply to different versions across the fleet, one already
//! patched, one not.
//!
//! # Usage
//!
//! ```sh
//! cargo add fleetreach-correlate
//! ```
//!
//! ```
//! use fleetreach_correlate::correlate;
//! # use fleetreach_core::semver::Version;
//! # use fleetreach_core::{DependencyKind, Occurrence, RepoId, Severity, VulnFinding};
//! # fn finding(repo: &str) -> VulnFinding {
//! #     VulnFinding {
//! #         advisory_id: "RUSTSEC-2024-0001".into(), aliases: vec![], ecosystem: Default::default(), title: "boom".into(),
//! #         severity: Severity::High, cvss_score: None, url: None, affected_functions: vec![],
//! #         reachable: None, reachability: None, exploit: Default::default(),
//! #         occurrences: vec![Occurrence::InRepo {
//! #             repo: RepoId(repo.into()), package: "foo".into(), installed: Version::new(1, 0, 0),
//! #             patched: vec![], dependency_kind: DependencyKind::Transitive,
//! #             dependency_path: vec![], active: None, source: Default::default() }],
//! #     }
//! # }
//! // The same advisory in two repos folds into one finding with two occurrences.
//! let correlated = correlate(vec![finding("app"), finding("svc")], vec![]);
//! assert_eq!(correlated.vulnerabilities.len(), 1);
//! assert_eq!(correlated.vulnerabilities[0].occurrences.len(), 2);
//! ```
//!
//! # Minimum supported Rust version
//!
//! 1.89. An MSRV increase is treated as a minor-version bump.

use std::collections::BTreeMap;

use fleetreach_core::{Occurrence, VulnFinding, WarnFinding, WarnKind};

/// Fleet-wide findings after cross-repo deduplication.
#[derive(Debug, Clone, Default)]
pub struct Correlated {
    pub vulnerabilities: Vec<VulnFinding>,
    pub warnings: Vec<WarnFinding>,
}

/// Group the two pre-correlation streams independently. The streams never cross:
/// a vulnerability can never become a warning or vice versa.
pub fn correlate(vulnerabilities: Vec<VulnFinding>, warnings: Vec<WarnFinding>) -> Correlated {
    Correlated {
        vulnerabilities: correlate_vulns(vulnerabilities),
        warnings: correlate_warns(warnings),
    }
}

fn correlate_vulns(input: Vec<VulnFinding>) -> Vec<VulnFinding> {
    let mut groups: BTreeMap<String, VulnFinding> = BTreeMap::new();
    for finding in input {
        match groups.get_mut(&finding.advisory_id) {
            Some(group) => merge_vuln(group, finding),
            None => {
                groups.insert(finding.advisory_id.clone(), finding);
            }
        }
    }

    let mut out: Vec<VulnFinding> = groups.into_values().collect();
    for finding in &mut out {
        // `sort_by_cached_key` computes each key once (the key allocates), then
        // `dedup` collapses occurrences that are identical down to the version —
        // e.g. the same package surfaced by two lockfiles of one glob repo.
        finding.occurrences.sort_by_cached_key(occurrence_key);
        finding.occurrences.dedup();
        finding.aliases.sort();
        finding.aliases.dedup();
    }
    // Severity descending (Critical first), then advisory id ascending. Group ids
    // are unique, so this comparator is a strict total order — total and stable.
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.advisory_id.cmp(&b.advisory_id))
    });
    out
}

fn merge_vuln(group: &mut VulnFinding, finding: VulnFinding) {
    // The metadata is a property of the advisory, so it is identical across
    // occurrences of the same id. We still merge defensively: take the worst
    // severity, union aliases, and keep the first non-empty title/url.
    group.severity = group.severity.max(finding.severity);
    if group.title.is_empty() {
        group.title = finding.title;
    }
    if group.url.is_none() {
        group.url = finding.url;
    }
    group.aliases.extend(finding.aliases);
    group.occurrences.extend(finding.occurrences);
}

fn correlate_warns(input: Vec<WarnFinding>) -> Vec<WarnFinding> {
    let mut groups: BTreeMap<(WarnKind, Option<String>), WarnFinding> = BTreeMap::new();
    for finding in input {
        let key = (finding.kind, finding.advisory_id.clone());
        match groups.get_mut(&key) {
            Some(group) => {
                if group.title.is_empty() {
                    group.title = finding.title;
                }
                group.occurrences.extend(finding.occurrences);
            }
            None => {
                groups.insert(key, finding);
            }
        }
    }

    let mut out: Vec<WarnFinding> = groups.into_values().collect();
    for finding in &mut out {
        finding.occurrences.sort_by_cached_key(occurrence_key);
        finding.occurrences.dedup();
    }
    out.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.advisory_id.cmp(&b.advisory_id))
    });
    out
}

/// A total, deterministic ordering key for occurrences within a finding, so the
/// rendered output is stable across runs. In-repo occurrences sort before
/// toolchain ones.
fn occurrence_key(occurrence: &Occurrence) -> (u8, String, String, String) {
    match occurrence {
        Occurrence::InRepo {
            repo,
            package,
            installed,
            ..
        } => (0, repo.0.clone(), package.clone(), installed.to_string()),
        Occurrence::Toolchain {
            channel, installed, ..
        } => (
            1,
            channel.clone(),
            String::new(),
            installed
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
        ),
    }
}
