//! Views over the SSVC decisions and repo context (spec 08): `-f ssvc`, `-f owners`, and the
//! lookups the other views use to put the most urgent work first.

use std::collections::{BTreeMap, BTreeSet};

use comfy_table::{Cell, Color};
use fleetreach_core::ssvc::Outcome;
use fleetreach_core::{FleetReport, Occurrence, SsvcDecision};

use crate::{maybe_color, sanitize_cell, styled_table, to_remediation, truncate};

/// The decision for one occurrence, keyed by (advisory, repo, package).
pub(crate) type DecisionIndex<'a> = BTreeMap<(&'a str, &'a str, &'a str), &'a SsvcDecision>;

pub(crate) fn index(report: &FleetReport) -> DecisionIndex<'_> {
    report
        .ssvc
        .iter()
        .flat_map(|s| &s.decisions)
        .map(|d| {
            (
                (
                    d.advisory_id.as_str(),
                    d.repo.0.as_str(),
                    d.package.as_str(),
                ),
                d,
            )
        })
        .collect()
}

/// The most urgent outcome across an advisory's decisions, optionally for one package only.
pub(crate) fn max_outcome(
    report: &FleetReport,
    advisory: &str,
    package: Option<&str>,
) -> Option<Outcome> {
    report
        .ssvc
        .iter()
        .flat_map(|s| &s.decisions)
        .filter(|d| d.advisory_id == advisory && package.is_none_or(|p| d.package == p))
        .map(|d| d.outcome)
        .max()
}

/// Whether the report carries any SSVC decision (the views add their SSVC columns then).
pub(crate) fn decided(report: &FleetReport) -> bool {
    report
        .ssvc
        .as_ref()
        .is_some_and(|s| !s.decisions.is_empty())
}

/// The most urgent outcome among the decisions `keep` selects, and the weighted reach: each
/// repo counts once, at the weight of its most urgent outcome (spec 08: a repo deciding
/// `immediate` counts 8, `defer` 0, unless `[settings.ssvc] weights` says otherwise).
pub(crate) fn weighted_reach(
    report: &FleetReport,
    keep: impl Fn(&SsvcDecision) -> bool,
) -> (Option<Outcome>, u32) {
    let Some(ssvc) = &report.ssvc else {
        return (None, 0);
    };
    let mut per_repo: BTreeMap<&str, Outcome> = BTreeMap::new();
    for d in ssvc.decisions.iter().filter(|d| keep(d)) {
        let slot = per_repo.entry(d.repo.0.as_str()).or_insert(d.outcome);
        *slot = (*slot).max(d.outcome);
    }
    let weight = per_repo
        .values()
        .map(|o| ssvc.weights.get(o).copied().unwrap_or(0))
        .sum();
    (per_repo.values().copied().max(), weight)
}

/// The SARIF level for an outcome: act now is an error, plan it is a warning, defer is a note.
pub(crate) fn sarif_level(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Immediate | Outcome::OutOfCycle => "error",
        Outcome::Scheduled => "warning",
        Outcome::Defer => "note",
    }
}

fn outcome_color(outcome: Outcome) -> Color {
    match outcome {
        Outcome::Immediate => Color::Red,
        Outcome::OutOfCycle => Color::Yellow,
        Outcome::Scheduled => Color::Cyan,
        Outcome::Defer => Color::DarkGrey,
    }
}

/// SSVC view: every decision, most urgent first, with its decision vector and why.
pub fn to_ssvc(report: &FleetReport, color: bool) -> String {
    let Some(ssvc) = &report.ssvc else {
        return "No SSVC decisions: set `exposure`, `mission_impact` and `safety_impact` on \
                [[repo]] or in [settings.context.defaults], and run with --enrich."
            .to_string();
    };
    if let Some(why) = &ssvc.not_computed {
        return format!("No SSVC decisions: {why}.");
    }
    if ssvc.decisions.is_empty() {
        return "No SSVC decisions: no vulnerable occurrences in repos.".to_string();
    }
    let mut table = styled_table(
        color,
        vec![
            "Outcome", "Vector", "Advisory", "Repo", "Package", "Owner", "Why",
        ],
    );
    for d in &ssvc.decisions {
        table.add_row(vec![
            maybe_color(
                Cell::new(d.outcome.label()),
                color.then(|| outcome_color(d.outcome)),
            ),
            Cell::new(&d.vector),
            Cell::new(sanitize_cell(&d.advisory_id)),
            Cell::new(sanitize_cell(&d.repo.0)),
            Cell::new(format!(
                "{} {}",
                sanitize_cell(&d.package),
                sanitize_cell(&d.installed)
            )),
            Cell::new(d.owner.as_deref().map(sanitize_cell).unwrap_or_default()),
            Cell::new(truncate(&sanitize_cell(&d.rationale), 60)),
        ]);
    }
    let counts: Vec<String> = Outcome::ALL
        .iter()
        .map(|o| {
            let n = ssvc.decisions.iter().filter(|d| d.outcome == *o).count();
            format!("{n} {o}")
        })
        .collect();
    format!(
        "{}\n{} ({}). E: exploitation, X: exposure, A: automatable, HI: human impact.",
        table,
        counts.join(", "),
        ssvc.table
    )
}

/// Owners view: the remediation queue split by each repo's `owner`, one section per owner,
/// so each team sees only the bumps in its own repos.
pub fn to_owners(report: &FleetReport, color: bool) -> String {
    let owner_of: BTreeMap<&str, &str> = report
        .context
        .iter()
        .filter_map(|c| Some((c.repo.0.as_str(), c.owner.as_deref()?)))
        .collect();
    if owner_of.is_empty() {
        return "No owners: set `owner` on [[repo]] or in [settings.context.defaults].".to_string();
    }
    const UNOWNED: &str = "(no owner)";
    let mut repos_by_owner: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for v in &report.vulnerabilities {
        for occ in &v.occurrences {
            if let Occurrence::InRepo { repo, .. } = occ {
                let owner = owner_of.get(repo.0.as_str()).copied().unwrap_or(UNOWNED);
                repos_by_owner.entry(owner).or_default().insert(&repo.0);
            }
        }
    }
    if repos_by_owner.is_empty() {
        return "No remediations: nothing to fix.".to_string();
    }
    // The unowned section goes last: it is the queue nobody has claimed yet.
    let mut owners: Vec<&str> = repos_by_owner.keys().copied().collect();
    owners.sort_by_key(|o| (*o == UNOWNED, *o));
    owners
        .into_iter()
        .map(|owner| {
            let repos = &repos_by_owner[owner];
            let mut scoped = report.clone();
            for v in &mut scoped.vulnerabilities {
                v.occurrences.retain(|occ| match occ {
                    Occurrence::InRepo { repo, .. } => repos.contains(repo.0.as_str()),
                    Occurrence::Toolchain { .. } => false,
                });
            }
            scoped.vulnerabilities.retain(|v| !v.occurrences.is_empty());
            if let Some(s) = &mut scoped.ssvc {
                s.decisions.retain(|d| repos.contains(d.repo.0.as_str()));
            }
            let names: Vec<&str> = repos.iter().copied().collect();
            format!(
                "{} ({} repo(s): {})\n{}",
                sanitize_cell(owner),
                repos.len(),
                sanitize_cell(&names.join(", ")),
                to_remediation(&scoped, color)
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}
