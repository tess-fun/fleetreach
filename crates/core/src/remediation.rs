//! v2 remediation: turn a correlated [`FleetReport`] into a queue of *actions*.
//!
//! `fix-first` ranks *which advisory* to patch; this layer answers *what to do* —
//! the concrete dependency bump, batched by the bump that delivers it, with a
//! reachability gate so vulns in provably dead code drop out of the active queue.
//!
//! This is a **pure, I/O-free assembly** over the existing model (no new scan-time
//! data): the fix range is [`Occurrence::patched`], the sound verdict is
//! [`VulnFinding::reachability`], and blast radius is the occurrence set. VEX
//! suppression is *not* handled here — already-mitigated findings are filtered
//! upstream before [`remediations`] ever sees them, keeping this crate VEX-free.

use std::collections::{BTreeMap, BTreeSet};

use semver::{Op, Version, VersionReq};
use serde::{Deserialize, Serialize};

use crate::{Ecosystem, FleetReport, Occurrence, ReachVerdict, Severity, VulnFinding};

/// Where an action sits relative to the active fix queue. Only a **sound static**
/// `NotReachable` demotes an item to the informational tier — the grep heuristic
/// ([`VulnFinding::reachable`]) is too weak to gate, and an absent verdict is
/// treated as [`Unknown`](ReachTier::Unknown) (fail-open: we never hide a vuln on
/// weak evidence, the same stance as `--min-epss`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachTier {
    /// A concrete call path exists, or at least one grouped advisory is reachable.
    Reachable,
    /// Undecided for at least one grouped advisory (no engine run, or `Unknown`).
    Unknown,
    /// Every grouped advisory is soundly `NotReachable` — informational, not work.
    NotReachable,
}

impl ReachTier {
    /// Whether this item belongs in the active fix queue (vs the informational
    /// tier). Only a fully-`NotReachable` group is demoted.
    pub fn is_actionable(self) -> bool {
        self != ReachTier::NotReachable
    }
}

/// What to actually do about a group of advisories on one package.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// Bump the package to `to` (the minimal version clearing every grouped
    /// advisory). `breaking` flags a semver-major jump (or a `0.x` minor jump) so
    /// the queue can favour low-churn fixes.
    Upgrade { to: Version, breaking: bool },
    /// No grouped advisory publishes a fix — route to VEX / mitigation, never a
    /// fabricated upgrade.
    NoFixAvailable,
}

/// One actionable remediation, derived from one or more [`VulnFinding`]s that
/// share a target package. Computed from a [`FleetReport`]; never persisted in
/// scan output, so it carries its own ranking signals (max/any across the group)
/// to spare the report layer a re-join.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemediationItem {
    /// The dependency to act on (crate name, or toolchain channel).
    pub package: String,
    pub ecosystem: Ecosystem,
    /// Distinct vulnerable versions present across the fleet, ascending.
    pub current: Vec<Version>,
    /// Advisory ids this single action resolves, sorted.
    pub advisories: Vec<String>,
    pub action: Action,
    /// Worst-case reachability across the grouped advisories.
    pub reach: ReachTier,
    /// Distinct repos with a vulnerable occurrence.
    pub repos: usize,
    /// Total vulnerable occurrences covered.
    pub occurrences: usize,
    /// Highest severity in the group — primary ranking signal.
    pub max_severity: Severity,
    /// Any grouped advisory is actively exploited (CISA KEV).
    pub kev: bool,
    /// Highest EPSS in the group, when any is enriched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_epss: Option<f32>,
    /// Highest CVSS base score in the group, when any is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cvss: Option<f32>,
}

/// Assemble the remediation queue from a correlated report.
///
/// Findings are grouped by target package; within a group, advisories that share
/// a compatible fix range collapse into one [`Action::Upgrade`] (the batching
/// win), while incompatible ranges (one demands `<2.0`, another `>=2.1`) split
/// back into per-advisory actions. Findings with no published fix become
/// [`Action::NoFixAvailable`]. The result is deterministically ordered by package
/// then advisory set; the report layer applies the fix-first ranking on top.
pub fn remediations(report: &FleetReport) -> Vec<RemediationItem> {
    // Key on (ecosystem, package): a crate and a Go module can share a name, and
    // they must never batch into one bump.
    let mut groups: BTreeMap<(Ecosystem, String), Vec<&VulnFinding>> = BTreeMap::new();
    for v in &report.vulnerabilities {
        // Skip findings whose every occurrence is already patched — nothing to do.
        if vuln_occ_count(v) == 0 {
            continue;
        }
        if let Some(package) = finding_package(v) {
            groups.entry((v.ecosystem, package)).or_default().push(v);
        }
    }

    let mut items = Vec::new();
    for ((ecosystem, package), findings) in groups {
        let (fixable, nofix): (Vec<&VulnFinding>, Vec<&VulnFinding>) = findings
            .into_iter()
            .partition(|f| finding_floor(&finding_patched(f)).is_some());

        if !nofix.is_empty() {
            items.push(build_item(
                ecosystem,
                &package,
                &nofix,
                Action::NoFixAvailable,
            ));
        }
        if fixable.is_empty() {
            continue;
        }

        // Never suggest a downgrade: the bump must clear the advisory *and* land at
        // or above the newest version any repo already has (an advisory's safe set
        // can include a lower line — smallvec's >=0.6.14 alongside >=1.6.1). The
        // batched target is the max of each advisory's forward fix; it's a single
        // valid bump only if every advisory's safe set actually contains it, else
        // the ranges conflict and we split per-advisory.
        let group_lb = fixable
            .iter()
            .flat_map(|f| installed_versions(f))
            .max()
            .unwrap_or(Version::new(0, 0, 0));
        let candidate = match fixable
            .iter()
            .filter_map(|f| finding_target(&finding_patched(f), &group_lb))
            .max()
        {
            Some(c) => c,
            None => continue, // unreachable given the partition, but never panic
        };
        let compatible = fixable
            .iter()
            .all(|f| satisfied_by(&finding_patched(f), &candidate));

        if compatible {
            let action = upgrade_action(&fixable, &candidate);
            items.push(build_item(ecosystem, &package, &fixable, action));
        } else {
            for &f in &fixable {
                let lb = installed_versions(f)
                    .into_iter()
                    .max()
                    .unwrap_or(Version::new(0, 0, 0));
                if let Some(target) = finding_target(&finding_patched(f), &lb) {
                    let action = upgrade_action(&[f], &target);
                    items.push(build_item(ecosystem, &package, &[f], action));
                }
            }
        }
    }

    items.sort_by(|a, b| {
        a.package
            .cmp(&b.package)
            .then_with(|| a.ecosystem.cmp(&b.ecosystem))
            .then_with(|| a.advisories.cmp(&b.advisories))
    });
    items
}

/// Build one item from a subset of findings on the same (ecosystem, package), with
/// a precomputed action.
fn build_item(
    ecosystem: Ecosystem,
    package: &str,
    subset: &[&VulnFinding],
    action: Action,
) -> RemediationItem {
    let mut advisories: Vec<String> = subset.iter().map(|f| f.advisory_id.clone()).collect();
    advisories.sort();
    advisories.dedup();

    let mut current: Vec<Version> = subset.iter().flat_map(|f| installed_versions(f)).collect();
    current.sort();
    current.dedup();

    let repos: BTreeSet<&str> = subset.iter().flat_map(|f| repo_ids(f)).collect();
    let occurrences = subset.iter().map(|f| vuln_occ_count(f)).sum();
    let max_severity = subset.iter().map(|f| f.severity).max().unwrap_or_default();
    let kev = subset.iter().any(|f| f.exploit.kev);
    let max_epss = subset
        .iter()
        .filter_map(|f| f.exploit.epss)
        .reduce(f32::max);
    let max_cvss = subset.iter().filter_map(|f| f.cvss_score).reduce(f32::max);

    RemediationItem {
        package: package.to_string(),
        ecosystem,
        current,
        advisories,
        action,
        reach: collapse_reach(subset.iter().copied()),
        repos: repos.len(),
        occurrences,
        max_severity,
        kev,
        max_epss,
        max_cvss,
    }
}

/// An [`Action::Upgrade`] to `to`, flagged breaking when it crosses the
/// compatibility boundary from the newest version the fleet currently has.
fn upgrade_action(subset: &[&VulnFinding], to: &Version) -> Action {
    let current_max = subset.iter().flat_map(|f| installed_versions(f)).max();
    let breaking = match &current_max {
        // Cargo treats `0.x` minor bumps as breaking; everything else by major.
        Some(c) => to.major != c.major || (to.major == 0 && to.minor != c.minor),
        None => false,
    };
    Action::Upgrade {
        to: to.clone(),
        breaking,
    }
}

/// Collapse a group's per-finding verdicts to the safest queue placement: any
/// reachable wins; else any undecided keeps it active; only an all-`NotReachable`
/// group is demoted.
fn collapse_reach<'a>(findings: impl Iterator<Item = &'a VulnFinding>) -> ReachTier {
    let mut tier = ReachTier::NotReachable;
    for f in findings {
        match finding_reach(f) {
            ReachTier::Reachable => return ReachTier::Reachable,
            ReachTier::Unknown => tier = ReachTier::Unknown,
            ReachTier::NotReachable => {}
        }
    }
    tier
}

fn finding_reach(f: &VulnFinding) -> ReachTier {
    match f.reachability.as_ref().map(|r| &r.verdict) {
        Some(ReachVerdict::Reachable { .. }) => ReachTier::Reachable,
        Some(ReachVerdict::NotReachable) => ReachTier::NotReachable,
        Some(ReachVerdict::Unknown { .. }) | None => ReachTier::Unknown,
    }
}

/// The minimal lower-bound version a single requirement permits (its floor). An
/// upper-bound-only req (`<2.0`) has no floor and yields `None`.
fn req_floor(req: &VersionReq) -> Option<Version> {
    req.comparators.iter().find_map(|c| match c.op {
        Op::Exact | Op::Greater | Op::GreaterEq | Op::Tilde | Op::Caret => Some(Version::new(
            c.major,
            c.minor.unwrap_or(0),
            c.patch.unwrap_or(0),
        )),
        _ => None,
    })
}

/// Whether any forward fix is namable for a finding (drives fixable/no-fix
/// partition). `patched` is OR semantics — a version is safe if it matches *any*
/// req (see [`Occurrence::is_vulnerable`]) — so this is true iff some req has a
/// lower bound. `None` means no fix is published (empty set) or none is namable.
fn finding_floor(patched: &[VersionReq]) -> Option<Version> {
    patched.iter().filter_map(req_floor).min()
}

/// The version to actually upgrade *to*: the smallest req floor at or above the
/// current floor `lb`, so we never recommend a downgrade when the advisory's safe
/// set spans an older line too. Falls back to the highest available fix when every
/// fix predates `lb` (pathological — the only published fixes are on a line below
/// what's installed).
fn finding_target(patched: &[VersionReq], lb: &Version) -> Option<Version> {
    let mut floors: Vec<Version> = patched.iter().filter_map(req_floor).collect();
    floors.sort();
    floors
        .iter()
        .find(|v| *v >= lb)
        .cloned()
        .or_else(|| floors.last().cloned())
}

/// Whether a version lands in a finding's safe set (matches any patched req).
fn satisfied_by(patched: &[VersionReq], v: &Version) -> bool {
    patched.iter().any(|r| r.matches(v))
}

/// The target package key for a finding: the crate name, or a toolchain channel.
fn finding_package(f: &VulnFinding) -> Option<String> {
    f.occurrences.first().map(|o| match o {
        Occurrence::InRepo { package, .. } => package.clone(),
        Occurrence::Toolchain { channel, .. } => channel.clone(),
    })
}

/// The union of patched ranges across a finding's occurrences (normally identical
/// — the range comes from the advisory — but deduped defensively).
fn finding_patched(f: &VulnFinding) -> Vec<VersionReq> {
    let mut reqs: Vec<VersionReq> = f
        .occurrences
        .iter()
        .flat_map(|o| match o {
            Occurrence::InRepo { patched, .. } => patched.clone(),
            Occurrence::Toolchain { patched, .. } => patched.clone(),
        })
        .collect();
    reqs.sort_by_key(|r| r.to_string());
    reqs.dedup_by(|a, b| a.to_string() == b.to_string());
    reqs
}

fn installed_versions(f: &VulnFinding) -> Vec<Version> {
    f.occurrences
        .iter()
        .filter(|o| o.is_vulnerable())
        .filter_map(|o| match o {
            Occurrence::InRepo { installed, .. } => Some(installed.clone()),
            Occurrence::Toolchain { installed, .. } => installed.clone(),
        })
        .collect()
}

fn repo_ids(f: &VulnFinding) -> Vec<&str> {
    f.occurrences
        .iter()
        .filter(|o| o.is_vulnerable())
        .filter_map(|o| match o {
            Occurrence::InRepo { repo, .. } => Some(repo.0.as_str()),
            Occurrence::Toolchain { .. } => None,
        })
        .collect()
}

fn vuln_occ_count(f: &VulnFinding) -> usize {
    f.occurrences.iter().filter(|o| o.is_vulnerable()).count()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::{DependencyKind, Provenance, Reachability, RepoId, Summary, SCHEMA_VERSION};

    fn in_repo(repo: &str, pkg: &str, installed: &str, patched: &[&str]) -> Occurrence {
        Occurrence::InRepo {
            repo: RepoId(repo.into()),
            package: pkg.into(),
            installed: Version::parse(installed).unwrap(),
            patched: patched
                .iter()
                .map(|p| VersionReq::parse(p).unwrap())
                .collect(),
            dependency_kind: DependencyKind::Transitive,
            dependency_path: vec![],
            active: None,
            source: Default::default(),
        }
    }

    fn vuln(id: &str, sev: Severity, occ: Vec<Occurrence>) -> VulnFinding {
        VulnFinding {
            advisory_id: id.into(),
            aliases: vec![],
            ecosystem: Ecosystem::Cargo,
            title: id.into(),
            severity: sev,
            cvss_score: None,
            url: None,
            occurrences: occ,
            affected_functions: vec![],
            reachable: None,
            reachability: None,
            exploit: Default::default(),
        }
    }

    fn with_reach(mut f: VulnFinding, verdict: ReachVerdict) -> VulnFinding {
        f.reachability = Some(Reachability {
            verdict,
            config: "cfg".into(),
            engine: "test".into(),
            targets: vec![],
            witness: None,
        });
        f
    }

    fn report_of(vulns: Vec<VulnFinding>) -> FleetReport {
        FleetReport {
            schema_version: SCHEMA_VERSION,
            provenance: Provenance {
                tool_version: "t".into(),
                rustsec_crate_version: "t".into(),
                db_commit: None,
                db_timestamp: None,
                host_os: "t".into(),
                host_arch: "t".into(),
                generated_at: "t".into(),
            },
            summary: Summary {
                repos_scanned: 0,
                repos_errored: 0,
                vuln_count: vulns.len(),
                warn_count: 0,
                max_severity: Severity::Unknown,
                stale_ignores: vec![],
            },
            vulnerabilities: vulns,
            warnings: vec![],
            outcomes: vec![],
        }
    }

    #[test]
    fn single_fixable_finding_yields_one_upgrade() {
        let r = report_of(vec![vuln(
            "RUSTSEC-1",
            Severity::High,
            vec![in_repo("app", "foo", "1.0.0", &[">=1.2.0"])],
        )]);
        let items = remediations(&r);
        assert_eq!(items.len(), 1);
        let it = &items[0];
        assert_eq!(it.package, "foo");
        assert_eq!(it.advisories, ["RUSTSEC-1"]);
        assert_eq!(
            it.action,
            Action::Upgrade {
                to: Version::new(1, 2, 0),
                breaking: false,
            }
        );
        assert_eq!(it.reach, ReachTier::Unknown);
        assert_eq!(it.repos, 1);
        assert_eq!(it.occurrences, 1);
        assert_eq!(it.current, [Version::new(1, 0, 0)]);
    }

    #[test]
    fn compatible_advisories_batch_into_one_bump() {
        // Two advisories on the same crate, fixable by a single >=1.5.0 bump,
        // in two different repos -> one batched action covering both repos.
        let r = report_of(vec![
            vuln(
                "RUSTSEC-A",
                Severity::Medium,
                vec![in_repo("app1", "foo", "1.0.0", &[">=1.2.0"])],
            ),
            vuln(
                "RUSTSEC-B",
                Severity::High,
                vec![in_repo("app2", "foo", "1.1.0", &[">=1.5.0"])],
            ),
        ]);
        let items = remediations(&r);
        assert_eq!(items.len(), 1);
        let it = &items[0];
        assert_eq!(it.advisories, ["RUSTSEC-A", "RUSTSEC-B"]);
        assert_eq!(
            it.action,
            Action::Upgrade {
                to: Version::new(1, 5, 0),
                breaking: false,
            }
        );
        assert_eq!(it.repos, 2);
        // Ranking signal is the worst of the group.
        assert_eq!(it.max_severity, Severity::High);
    }

    #[test]
    fn incompatible_ranges_split_per_advisory() {
        // One advisory fixed only in the 1.x line (<2.0), another only in >=2.1 —
        // no single bump satisfies both, so they split.
        let r = report_of(vec![
            vuln(
                "RUSTSEC-A",
                Severity::High,
                vec![in_repo("app", "foo", "1.0.0", &[">=1.2.0, <2.0.0"])],
            ),
            vuln(
                "RUSTSEC-B",
                Severity::High,
                vec![in_repo("app", "foo", "1.0.0", &[">=2.1.0"])],
            ),
        ]);
        let items = remediations(&r);
        assert_eq!(items.len(), 2);
        let tos: Vec<&Action> = items.iter().map(|i| &i.action).collect();
        assert!(tos.contains(&&Action::Upgrade {
            to: Version::new(1, 2, 0),
            breaking: false,
        }));
        assert!(tos.contains(&&Action::Upgrade {
            to: Version::new(2, 1, 0),
            breaking: true,
        }));
    }

    #[test]
    fn distinct_ecosystems_never_batch() {
        // A crate `foo` and a Go module `foo` share a name but must stay separate.
        let mut go = vuln(
            "GO-2024-0001",
            Severity::High,
            vec![in_repo("r", "foo", "1.0.0", &[">=1.2.0"])],
        );
        go.ecosystem = Ecosystem::Go;
        let cargo = vuln(
            "RUSTSEC-2024-0001",
            Severity::High,
            vec![in_repo("r", "foo", "1.0.0", &[">=1.2.0"])],
        );
        let items = remediations(&report_of(vec![go, cargo]));
        assert_eq!(
            items.len(),
            2,
            "same name, different ecosystem must not batch"
        );
        let ecos: Vec<Ecosystem> = items.iter().map(|i| i.ecosystem).collect();
        assert!(ecos.contains(&Ecosystem::Cargo) && ecos.contains(&Ecosystem::Go));
    }

    #[test]
    fn never_recommends_a_downgrade() {
        // smallvec RUSTSEC-2021-0003 shape: fixed in both the old 0.6.x line and
        // 1.6.1+. Installed 1.6.0 must bump UP to 1.6.1, not down to 0.6.14.
        let r = report_of(vec![vuln(
            "RUSTSEC-2021-0003",
            Severity::Critical,
            vec![in_repo(
                "app",
                "smallvec",
                "1.6.0",
                &[">=0.6.14, <1.0.0", ">=1.6.1"],
            )],
        )]);
        let items = remediations(&r);
        assert_eq!(
            items[0].action,
            Action::Upgrade {
                to: Version::new(1, 6, 1),
                breaking: false, // 1.6.0 -> 1.6.1 is a patch bump
            }
        );
    }

    #[test]
    fn no_published_fix_is_honest() {
        let r = report_of(vec![vuln(
            "RUSTSEC-1",
            Severity::Critical,
            vec![in_repo("app", "foo", "1.0.0", &[])],
        )]);
        let items = remediations(&r);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].action, Action::NoFixAvailable);
        assert_eq!(items[0].max_severity, Severity::Critical);
    }

    #[test]
    fn major_bump_is_breaking() {
        let r = report_of(vec![vuln(
            "RUSTSEC-1",
            Severity::High,
            vec![in_repo("app", "foo", "1.4.0", &[">=2.0.0"])],
        )]);
        let items = remediations(&r);
        assert_eq!(
            items[0].action,
            Action::Upgrade {
                to: Version::new(2, 0, 0),
                breaking: true,
            }
        );
    }

    #[test]
    fn zerover_minor_bump_is_breaking() {
        let r = report_of(vec![vuln(
            "RUSTSEC-1",
            Severity::Low,
            vec![in_repo("app", "foo", "0.4.0", &[">=0.5.0"])],
        )]);
        let items = remediations(&r);
        assert_eq!(
            items[0].action,
            Action::Upgrade {
                to: Version::new(0, 5, 0),
                breaking: true,
            }
        );
    }

    #[test]
    fn not_reachable_demotes_to_informational() {
        let r = report_of(vec![with_reach(
            vuln(
                "RUSTSEC-1",
                Severity::High,
                vec![in_repo("app", "foo", "1.0.0", &[">=1.2.0"])],
            ),
            ReachVerdict::NotReachable,
        )]);
        let items = remediations(&r);
        assert_eq!(items[0].reach, ReachTier::NotReachable);
        assert!(!items[0].reach.is_actionable());
    }

    #[test]
    fn reachable_stays_actionable() {
        let r = report_of(vec![with_reach(
            vuln(
                "RUSTSEC-1",
                Severity::High,
                vec![in_repo("app", "foo", "1.0.0", &[">=1.2.0"])],
            ),
            ReachVerdict::Reachable { witness: vec![] },
        )]);
        let items = remediations(&r);
        assert_eq!(items[0].reach, ReachTier::Reachable);
        assert!(items[0].reach.is_actionable());
    }

    #[test]
    fn any_reachable_in_a_batch_keeps_it_active() {
        // One advisory NotReachable, one Reachable, batched on the same crate:
        // the safe collapse keeps the whole action active.
        let r = report_of(vec![
            with_reach(
                vuln(
                    "RUSTSEC-A",
                    Severity::Medium,
                    vec![in_repo("app", "foo", "1.0.0", &[">=1.2.0"])],
                ),
                ReachVerdict::NotReachable,
            ),
            with_reach(
                vuln(
                    "RUSTSEC-B",
                    Severity::High,
                    vec![in_repo("app", "foo", "1.0.0", &[">=1.2.0"])],
                ),
                ReachVerdict::Reachable { witness: vec![] },
            ),
        ]);
        let items = remediations(&r);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].reach, ReachTier::Reachable);
    }

    #[test]
    fn fully_patched_finding_is_skipped() {
        // Installed version already satisfies the patched range -> not vulnerable
        // -> no remediation.
        let r = report_of(vec![vuln(
            "RUSTSEC-1",
            Severity::High,
            vec![in_repo("app", "foo", "1.2.0", &[">=1.2.0"])],
        )]);
        assert!(remediations(&r).is_empty());
    }
}
