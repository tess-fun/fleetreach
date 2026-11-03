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

/// How likely an upgrade is to break its callers (spec 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Medium,
    High,
}

impl Risk {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
        }
    }
}

/// How much of the fleet already runs an upgrade's target (spec 13): repos whose lockfile
/// has the package at the target or a later, compatible version (same major; same minor
/// for `0.x`). Your own fleet is the best evidence that an upgrade is survivable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetEvidence {
    /// How many repos already run it.
    pub repos: usize,
    /// The highest such version.
    pub newest: Version,
}

/// A smaller upgrade for the repos still on an older compatible line than the main target
/// (spec 13): the lowest version on their own line that clears what it can, so they are not
/// pushed across a major for a fix their line also has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alternative {
    pub to: Version,
    /// Repos with a vulnerable version on this line.
    pub repos: usize,
    /// Grouped advisories this version clears, sorted.
    pub clears: Vec<String>,
    /// Grouped advisories with no fix on this line, which still need the main target.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leaves_open: Vec<String>,
    /// Repos already on it or a later compatible version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<FleetEvidence>,
}

/// How many repos must already run the new major for a breaking bump to rate `medium`.
const PROVEN_REPOS: usize = 3;

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
    /// Repos already on the upgrade target (spec 13); `None` when there is no upgrade or the
    /// report carries no fleet versions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<FleetEvidence>,
    /// The upgrade's risk; `None` without an upgrade.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<Risk>,
    /// Why, in a few words each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risk_reasons: Vec<String>,
    /// In-line upgrades for repos on an older line than `to`, oldest line first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternatives: Vec<Alternative>,
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
    // An advisory can name several packages (npm's @babel/helpers and @babel/runtime, Go's
    // pgx/v4 and pgproto3/v2), and each one needs its own bump: split before grouping.
    let per_package: Vec<VulnFinding> = report
        .vulnerabilities
        .iter()
        .flat_map(split_by_package)
        .collect();
    let mut groups: BTreeMap<(Ecosystem, String), Vec<&VulnFinding>> = BTreeMap::new();
    for v in &per_package {
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

        let fleet = report
            .package_versions
            .iter()
            .find(|p| p.ecosystem == ecosystem && p.package == package);
        let build = |subset: &[&VulnFinding], action: Action| {
            let mut item = build_item(ecosystem, &package, subset, action);
            assess_risk(&mut item, fleet);
            item.alternatives = alternatives(subset, &item.action, fleet);
            item
        };
        if !nofix.is_empty() {
            items.push(build(&nofix, Action::NoFixAvailable));
        }
        if fixable.is_empty() {
            continue;
        }

        // Never suggest a downgrade: the bump must clear the advisory *and* land at
        // or above the newest version any repo already has (an advisory's safe set
        // can include a lower line — smallvec's >=0.6.14 alongside >=1.6.1). The
        // batched target starts at the max of each advisory's forward fix; when a
        // later branch re-introduces one of them there (grpc 1.83.1 fixes one advisory
        // while 1.83.0-1.83.1 carry another), it moves up to the next fix floor that
        // every advisory's safe set contains (1.83.2). When none does, the ranges
        // conflict and we split per-advisory.
        let group_lb = fixable
            .iter()
            .flat_map(|f| installed_versions(f))
            .max()
            .unwrap_or(Version::new(0, 0, 0));
        let Some(start) = fixable
            .iter()
            .filter_map(|f| finding_target(&finding_patched(f), &group_lb))
            .max()
        else {
            continue; // unreachable given the partition, but never panic
        };
        let mut floors: Vec<Version> = fixable
            .iter()
            .flat_map(|f| {
                finding_patched(f)
                    .iter()
                    .filter_map(req_floor)
                    .collect::<Vec<_>>()
            })
            .filter(|v| *v >= start)
            .collect();
        floors.sort();
        floors.dedup();
        let common = floors
            .into_iter()
            .find(|v| fixable.iter().all(|f| satisfied_by(&finding_patched(f), v)));
        if let Some(candidate) = common {
            let action = upgrade_action(&fixable, &candidate);
            items.push(build(&fixable, action));
        } else {
            for &f in &fixable {
                let lb = installed_versions(f)
                    .into_iter()
                    .max()
                    .unwrap_or(Version::new(0, 0, 0));
                if let Some(target) = finding_target(&finding_patched(f), &lb) {
                    let action = upgrade_action(&[f], &target);
                    items.push(build(&[f], action));
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
        evidence: None,
        risk: None,
        risk_reasons: Vec::new(),
        alternatives: Vec::new(),
    }
}

/// Whether `v` is a compatible later release of `to`: Cargo's rule, which every
/// SemVer-coerced ecosystem shares (same major, or same minor under `0.x`).
fn compatible_with(to: &Version, v: &Version) -> bool {
    v >= to && line(v) == line(to)
}

/// A version's compatibility line: its major, or its minor under `0.x`.
pub fn line(v: &Version) -> (u64, u64) {
    (v.major, if v.major == 0 { v.minor } else { 0 })
}

/// How many repos already run `to` or a later compatible version, and the newest of those.
fn evidence_for(to: &Version, fleet: &crate::PackageVersions) -> Option<FleetEvidence> {
    let on_target: Vec<&crate::VersionInFleet> = fleet
        .versions
        .iter()
        .filter(|v| compatible_with(to, &v.version))
        .collect();
    let repos: BTreeSet<&str> = on_target
        .iter()
        .flat_map(|v| v.repos.iter().map(|r| r.0.as_str()))
        .collect();
    on_target.last().map(|newest| FleetEvidence {
        repos: repos.len(),
        newest: newest.version.clone(),
    })
}

/// The in-line alternatives to an upgrade (spec 13): for each line older than the target
/// that has vulnerable repos, the smallest version on that line, at or above what they run,
/// that clears every grouped advisory with a fix there. Lines where no advisory has a fix are
/// left out: those repos need the main target.
fn alternatives(
    subset: &[&VulnFinding],
    action: &Action,
    fleet: Option<&crate::PackageVersions>,
) -> Vec<Alternative> {
    let Action::Upgrade { to, .. } = action else {
        return Vec::new();
    };
    // Each older line's highest vulnerable version, its repos and the advisories on it.
    type Line<'a> = (Version, BTreeSet<&'a str>, Vec<&'a VulnFinding>);
    let mut lines: BTreeMap<(u64, u64), Line<'_>> = BTreeMap::new();
    for &f in subset {
        for o in f.occurrences.iter().filter(|o| o.is_vulnerable()) {
            let Occurrence::InRepo {
                repo, installed, ..
            } = o
            else {
                continue;
            };
            if line(installed) >= line(to) {
                continue;
            }
            let entry = lines
                .entry(line(installed))
                .or_insert_with(|| (installed.clone(), BTreeSet::new(), Vec::new()));
            entry.0 = entry.0.clone().max(installed.clone());
            entry.1.insert(repo.0.as_str());
            if !entry.2.iter().any(|g| std::ptr::eq(*g, f)) {
                entry.2.push(f);
            }
        }
    }
    let mut out = Vec::new();
    for (key, (floor, repos, on_line)) in lines {
        let candidate = on_line
            .iter()
            .filter_map(|f| {
                let mut floors: Vec<Version> = finding_patched(f)
                    .iter()
                    .filter_map(req_floor)
                    .filter(|v| line(v) == key && *v >= floor)
                    .collect();
                floors.sort();
                floors.into_iter().next()
            })
            .max();
        let Some(candidate) = candidate else {
            continue;
        };
        let (mut clears, mut leaves_open): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
        for f in &on_line {
            if satisfied_by(&finding_patched(f), &candidate) {
                clears.push(f.advisory_id.clone());
            } else {
                leaves_open.push(f.advisory_id.clone());
            }
        }
        if clears.is_empty() {
            continue;
        }
        for list in [&mut clears, &mut leaves_open] {
            list.sort();
            list.dedup();
        }
        out.push(Alternative {
            evidence: fleet.and_then(|fleet| evidence_for(&candidate, fleet)),
            to: candidate,
            repos: repos.len(),
            clears,
            leaves_open,
        });
    }
    out
}

/// Fill an upgrade item's fleet evidence and risk (spec 13, phase 1):
///
/// | Upgrade | Risk |
/// |---------|------|
/// | within the current major | low |
/// | breaking, at least [`PROVEN_REPOS`] repos already on it | medium |
/// | breaking, fewer | high |
fn assess_risk(item: &mut RemediationItem, fleet: Option<&crate::PackageVersions>) {
    let Action::Upgrade { to, breaking } = &item.action else {
        return;
    };
    item.evidence = fleet.and_then(|fleet| evidence_for(to, fleet));
    let (risk, reasons) = upgrade_risk(to, *breaking, item.evidence.as_ref(), fleet.is_some());
    item.risk = Some(risk);
    item.risk_reasons = reasons;
}

/// An upgrade's risk and why (spec 13), from whether it is `breaking` and how many repos
/// already run `to` (`evidence`; `fleet_known` says whether the report had fleet versions).
#[must_use]
pub fn upgrade_risk(
    to: &Version,
    breaking: bool,
    evidence: Option<&FleetEvidence>,
    fleet_known: bool,
) -> (Risk, Vec<String>) {
    let proven = evidence.map_or(0, |e| e.repos);
    let in_fleet = match proven {
        0 if fleet_known => "no repo in the fleet runs it yet".to_string(),
        0 => String::new(),
        1 => format!("1 repo already runs {to}+"),
        n => format!("{n} repos already run {to}+"),
    };
    let (risk, why) = if !breaking {
        (Risk::Low, "within the current major".to_string())
    } else if proven >= PROVEN_REPOS {
        (Risk::Medium, "breaking (new major)".to_string())
    } else {
        (Risk::High, "breaking (new major)".to_string())
    };
    let reasons = std::iter::once(why)
        .chain((!in_fleet.is_empty()).then_some(in_fleet))
        .collect();
    (risk, reasons)
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

/// One finding per package it names, each holding only that package's occurrences.
fn split_by_package(f: &VulnFinding) -> Vec<VulnFinding> {
    let mut by_package: BTreeMap<String, Vec<Occurrence>> = BTreeMap::new();
    for o in &f.occurrences {
        by_package
            .entry(occurrence_package(o).to_string())
            .or_default()
            .push(o.clone());
    }
    if by_package.len() <= 1 {
        return vec![f.clone()];
    }
    by_package
        .into_values()
        .map(|occurrences| VulnFinding {
            occurrences,
            ..f.clone()
        })
        .collect()
}

fn occurrence_package(o: &Occurrence) -> &str {
    match o {
        Occurrence::InRepo { package, .. } => package,
        Occurrence::Toolchain { channel, .. } => channel,
    }
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
            scope: Default::default(),
            layer: None,
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
            cvss_vector: None,
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
                osv: Vec::new(),
                sources: Vec::new(),
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
            coverage: Vec::new(),
            context: Vec::new(),
            ssvc: None,
            package_versions: Vec::new(),
            base_images: Vec::new(),
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

    fn fleet(package: &str, versions: &[(&str, &[&str])]) -> crate::PackageVersions {
        crate::PackageVersions {
            ecosystem: Ecosystem::Cargo,
            package: package.into(),
            versions: versions
                .iter()
                .map(|(v, repos)| crate::VersionInFleet {
                    version: Version::parse(v).unwrap(),
                    repos: repos.iter().map(|r| RepoId((*r).into())).collect(),
                })
                .collect(),
        }
    }

    fn bump(installed: &str, patched: &str, versions: &[(&str, &[&str])]) -> RemediationItem {
        let mut r = report_of(vec![vuln(
            "RUSTSEC-1",
            Severity::High,
            vec![in_repo("app", "foo", installed, &[patched])],
        )]);
        r.package_versions = vec![fleet("foo", versions)];
        remediations(&r).remove(0)
    }

    #[test]
    fn a_batch_skips_a_fix_a_later_branch_breaks_again() {
        // caddy 2.6 on grpc 1.46.0: 1.83.1 fixes GO-2026-6348, but GO-2026-6443 is back in
        // 1.83.0-1.83.1, so the one bump that clears all of them is 1.83.2.
        let r = report_of(vec![
            vuln(
                "GO-2023-2153",
                Severity::High,
                vec![in_repo(
                    "caddy",
                    "grpc",
                    "1.46.0",
                    &[">=1.56.3, <1.57.0", ">=1.58.3"],
                )],
            ),
            vuln(
                "GO-2026-6348",
                Severity::High,
                vec![in_repo("caddy", "grpc", "1.46.0", &[">=1.83.1"])],
            ),
            vuln(
                "GO-2026-6443",
                Severity::High,
                vec![in_repo(
                    "caddy",
                    "grpc",
                    "1.46.0",
                    &[">=1.82.2, <1.83.0", ">=1.83.2, <1.84.0"],
                )],
            ),
        ]);
        let items = remediations(&r);
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!(
            items[0].action,
            Action::Upgrade {
                to: Version::new(1, 83, 2),
                breaking: false
            }
        );
    }

    #[test]
    fn a_batch_never_lands_below_an_advisorys_own_fix() {
        // js-yaml across gitea (3.14.1, 4.1.0) and elysia (4.1.1): GHSA-mh29 is fixed in
        // 4.1.1, GHSA-2883 only in 4.3.2. The 3.x occurrence's safe set includes its own line,
        // so it must not let 4.1.1 pass for the batch.
        let r = report_of(vec![
            vuln(
                "GHSA-2883",
                Severity::High,
                vec![
                    in_repo("gitea", "js-yaml", "3.14.1", &[">=3.15.2"]),
                    in_repo("gitea", "js-yaml", "4.1.0", &[">=4.3.2"]),
                    in_repo("elysia", "js-yaml", "4.1.1", &[">=4.3.2"]),
                ],
            ),
            vuln(
                "GHSA-mh29",
                Severity::High,
                vec![
                    in_repo("gitea", "js-yaml", "3.14.1", &[">=3.14.2"]),
                    in_repo("gitea", "js-yaml", "4.1.0", &[">=4.1.1"]),
                ],
            ),
        ]);
        let items = remediations(&r);
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!(
            items[0].action,
            Action::Upgrade {
                to: Version::new(4, 3, 2),
                breaking: false
            }
        );
    }

    #[test]
    fn an_advisory_naming_two_packages_gets_a_bump_for_each() {
        // gitea 1.17: GHSA-968p-4wvh-cqc8 names @babel/helpers and @babel/runtime.
        let r = report_of(vec![vuln(
            "GHSA-968p",
            Severity::Medium,
            vec![
                in_repo("app", "helpers", "7.18.0", &[">=7.26.10"]),
                in_repo("app", "runtime", "7.18.3", &[">=7.26.10"]),
            ],
        )]);
        let items = remediations(&r);
        let got: Vec<(&str, &[Version])> = items
            .iter()
            .map(|i| (i.package.as_str(), i.current.as_slice()))
            .collect();
        assert_eq!(
            got,
            [
                ("helpers", &[Version::new(7, 18, 0)][..]),
                ("runtime", &[Version::new(7, 18, 3)][..])
            ]
        );
    }

    #[test]
    fn repos_on_an_older_line_get_the_fix_on_their_own_line() {
        // One advisory is fixed on both lines, the other only on 2.x.
        let both = &[">=1.4.2, <2.0.0", ">=2.1.0"];
        let mut r = report_of(vec![
            vuln(
                "RUSTSEC-A",
                Severity::High,
                vec![
                    in_repo("old", "foo", "1.4.0", both),
                    in_repo("older", "foo", "1.2.0", both),
                    in_repo("new", "foo", "2.0.0", both),
                ],
            ),
            vuln(
                "RUSTSEC-B",
                Severity::Low,
                vec![in_repo("new", "foo", "2.0.0", &[">=2.0.3"])],
            ),
        ]);
        r.package_versions = vec![fleet(
            "foo",
            &[
                ("1.2.0", &["older"]),
                ("1.4.0", &["old"]),
                ("1.5.0", &["other"]),
                ("2.0.0", &["new"]),
            ],
        )];
        let it = remediations(&r).remove(0);
        assert_eq!(
            it.action,
            Action::Upgrade {
                to: Version::new(2, 1, 0),
                breaking: false
            }
        );
        let [alt] = it.alternatives.as_slice() else {
            panic!("{:?}", it.alternatives)
        };
        assert_eq!(
            alt.to,
            Version::new(1, 4, 2),
            "at or above the line's newest"
        );
        assert_eq!(alt.repos, 2);
        assert_eq!(alt.clears, ["RUSTSEC-A"]);
        assert!(alt.leaves_open.is_empty(), "B never reached 1.x");
        assert_eq!(alt.evidence.as_ref().map(|e| e.repos), Some(1));

        // Without a fix on the old line there is no alternative.
        let r = report_of(vec![vuln(
            "RUSTSEC-C",
            Severity::High,
            vec![
                in_repo("old", "foo", "1.4.0", &[">=2.1.0"]),
                in_repo("new", "foo", "2.0.0", &[">=2.1.0"]),
            ],
        )]);
        assert!(remediations(&r)[0].alternatives.is_empty());
    }

    #[test]
    fn an_alternative_names_the_advisories_its_line_cannot_fix() {
        let r = report_of(vec![
            vuln(
                "RUSTSEC-A",
                Severity::High,
                vec![in_repo(
                    "app",
                    "foo",
                    "0.3.1",
                    &[">=0.3.4, <0.4.0", ">=0.4.1"],
                )],
            ),
            vuln(
                "RUSTSEC-B",
                Severity::High,
                vec![in_repo("app", "foo", "0.3.1", &[">=0.4.1"])],
            ),
        ]);
        let it = remediations(&r).remove(0);
        assert_eq!(
            it.action,
            Action::Upgrade {
                to: Version::new(0, 4, 1),
                breaking: true
            }
        );
        let alt = &it.alternatives[0];
        assert_eq!(alt.to, Version::new(0, 3, 4));
        assert_eq!(alt.clears, ["RUSTSEC-A"]);
        assert_eq!(alt.leaves_open, ["RUSTSEC-B"]);
    }

    #[test]
    fn a_bump_within_the_major_is_low_risk() {
        let it = bump(
            "1.0.0",
            ">=1.2.0",
            &[("1.0.0", &["app"]), ("1.3.1", &["b"])],
        );
        assert_eq!(it.risk, Some(Risk::Low));
        let evidence = it.evidence.unwrap();
        assert_eq!(
            (evidence.repos, evidence.newest),
            (1, Version::new(1, 3, 1))
        );
        assert_eq!(
            it.risk_reasons,
            ["within the current major", "1 repo already runs 1.2.0+"]
        );
    }

    #[test]
    fn a_breaking_bump_is_medium_only_once_enough_repos_run_it() {
        let proven = bump(
            "1.0.0",
            ">=2.0.0",
            &[
                ("1.0.0", &["app"]),
                ("2.0.0", &["b", "c"]),
                ("2.4.0", &["d", "b"]),
            ],
        );
        assert_eq!(proven.risk, Some(Risk::Medium));
        assert_eq!(proven.evidence.unwrap().repos, 3, "b counts once");

        let unproven = bump(
            "1.0.0",
            ">=2.0.0",
            &[("1.0.0", &["app"]), ("2.1.0", &["b"])],
        );
        assert_eq!(unproven.risk, Some(Risk::High));
        assert_eq!(unproven.evidence.unwrap().repos, 1);
    }

    #[test]
    fn evidence_only_counts_versions_compatible_with_the_target() {
        // 3.x is a different major from the 2.0.0 target, and 1.x is below it.
        let it = bump(
            "1.0.0",
            ">=2.0.0",
            &[
                ("1.0.0", &["app"]),
                ("1.9.0", &["b"]),
                ("3.0.0", &["c", "d", "e"]),
            ],
        );
        assert_eq!(it.evidence, None);
        assert_eq!(it.risk, Some(Risk::High));
        assert_eq!(
            it.risk_reasons,
            ["breaking (new major)", "no repo in the fleet runs it yet"]
        );
    }

    #[test]
    fn zero_major_evidence_must_share_the_minor() {
        let it = bump(
            "0.3.0",
            ">=0.4.0",
            &[
                ("0.3.0", &["app"]),
                ("0.4.2", &["b"]),
                ("0.5.0", &["c", "d"]),
            ],
        );
        assert_eq!(it.risk, Some(Risk::High), "0.3 to 0.4 is breaking");
        let evidence = it.evidence.unwrap();
        assert_eq!(
            (evidence.repos, evidence.newest),
            (1, Version::new(0, 4, 2))
        );
    }

    #[test]
    fn without_fleet_data_a_bump_still_gets_a_risk() {
        let r = report_of(vec![vuln(
            "RUSTSEC-1",
            Severity::High,
            vec![in_repo("app", "foo", "1.0.0", &[">=2.0.0"])],
        )]);
        let it = remediations(&r).remove(0);
        assert_eq!(it.evidence, None);
        assert_eq!(it.risk, Some(Risk::High));
        assert_eq!(it.risk_reasons, ["breaking (new major)"]);
    }
}
