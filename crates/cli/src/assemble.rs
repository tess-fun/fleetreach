//! Turning raw scan output into a final [`FleetReport`] plus its exit code.
//!
//! Pipeline steps §10.5–8: correlate, apply ignores (recording stale ones),
//! filter by min severity, summarize. The clock is injected via `provenance`, so
//! report assembly is fully deterministic and testable.

use std::collections::BTreeSet;

use fleetreach_core::{
    max_severity_of, FleetReport, Occurrence, Provenance, RepoId, RepoOutcome, ScanStatus,
    Severity, Summary,
};

/// Drop occurrences known to be phantom — a `Cargo.lock`-only optional dependency
/// that is never compiled (`active: Some(false)`, from `--resolve-features`) —
/// and remove any finding left with no occurrences. Recomputes summary counts.
/// Returns the number of findings removed entirely. Occurrences with unknown
/// build status (`active: None`) are always kept (fail-closed).
pub fn drop_phantom(report: &mut FleetReport) -> usize {
    fn is_phantom(occurrence: &Occurrence) -> bool {
        matches!(
            occurrence,
            Occurrence::InRepo {
                active: Some(false),
                ..
            }
        )
    }

    for v in &mut report.vulnerabilities {
        v.occurrences.retain(|o| !is_phantom(o));
    }
    for w in &mut report.warnings {
        w.occurrences.retain(|o| !is_phantom(o));
    }

    let before = report.vulnerabilities.len() + report.warnings.len();
    report.vulnerabilities.retain(|v| !v.occurrences.is_empty());
    report.warnings.retain(|w| !w.occurrences.is_empty());
    let removed = before - (report.vulnerabilities.len() + report.warnings.len());

    report.refresh_summary();
    removed
}

/// Drop vulnerabilities the reachability heuristic marked `Some(false)` (no
/// affected function name found in your source). `None`/`Some(true)` are kept —
/// fail-closed, since the heuristic cannot prove unreachability. Returns the
/// number removed.
pub fn retain_reachable(report: &mut FleetReport) -> usize {
    let before = report.vulnerabilities.len();
    report
        .vulnerabilities
        .retain(|v| v.reachable != Some(false));
    let removed = before - report.vulnerabilities.len();
    report.refresh_summary();
    removed
}

/// Keep only vulnerabilities whose EPSS is at/above `min`; unknown EPSS is kept
/// (fail-closed). Recomputes counts. Returns the `(advisory_id, epss)` of each
/// finding dropped — the EPSS score is network-sourced and *hides* a finding, so
/// the caller surfaces exactly what a feed suppressed (auditable, not silent).
pub fn retain_min_epss(report: &mut FleetReport, min: f32) -> Vec<(String, f32)> {
    let dropped: Vec<(String, f32)> = report
        .vulnerabilities
        .iter()
        .filter_map(|v| {
            v.exploit
                .epss
                .filter(|&e| e < min)
                .map(|e| (v.advisory_id.clone(), e))
        })
        .collect();
    report
        .vulnerabilities
        .retain(|v| v.exploit.epss.is_none_or(|e| e >= min));
    report.refresh_summary();
    dropped
}

/// Filter a report down to findings **not** present in the baseline id set, then
/// recompute the affected summary counts. Used by `--baseline` to surface only
/// what is new since a prior run.
pub fn retain_new(report: &mut FleetReport, baseline_ids: &BTreeSet<String>) {
    report
        .vulnerabilities
        .retain(|v| !baseline_ids.contains(&v.advisory_id));
    report.warnings.retain(|w| {
        w.advisory_id
            .as_ref()
            .is_none_or(|id| !baseline_ids.contains(id))
    });
    report.refresh_summary();
}

/// Fold a `--baseline` "has new findings" signal into an exit code while
/// preserving §8 precedence: an untrustworthy `2` always wins; otherwise a new
/// finding raises the code to at least `1`.
///
/// ```
/// use fleetreach_cli::assemble::combine_baseline;
///
/// assert_eq!(combine_baseline(2, true), 2);  // untrustworthy wins
/// assert_eq!(combine_baseline(0, true), 1);  // a new finding gates
/// assert_eq!(combine_baseline(0, false), 0); // nothing new, unchanged
/// ```
pub fn combine_baseline(code: u8, baseline_new: bool) -> u8 {
    if code == 2 {
        2
    } else if baseline_new {
        code.max(1)
    } else {
        code
    }
}
use fleetreach_correlate::{correlate, Correlated};

use crate::config::{Ignore, VexAssertion};
use crate::orchestrate::ScanData;

/// A human suppression applied before gating (§6): an `ignore` (fleet-wide, no
/// approver) or a `vex_assertion` (optionally repo-scoped, approved). Matching
/// occurrences are removed from the gated report and captured for `-f vex`.
#[derive(Debug, Clone)]
pub struct Suppression {
    pub id: String,
    /// `None` = fleet-wide; else only this repo.
    pub repo: Option<RepoId>,
    pub justification: Option<String>,
    /// The OpenVEX `impact_statement` when there is no `justification`.
    pub reason: String,
    /// `None` for an `ignore`; `Some(approver)` for a `vex_assertion`.
    pub approved_by: Option<String>,
}

impl Suppression {
    pub fn from_ignore(ignore: &Ignore) -> Self {
        Self {
            id: ignore.id.clone(),
            repo: None,
            justification: None,
            reason: ignore.reason.clone(),
            approved_by: None,
        }
    }

    pub fn from_assertion(assertion: &VexAssertion) -> Self {
        Self {
            id: assertion.id.clone(),
            repo: assertion.repo.clone(),
            justification: assertion.justification.clone(),
            reason: assertion.reason.clone(),
            approved_by: Some(assertion.approved_by.clone()),
        }
    }
}

/// An occurrence removed by a [`Suppression`], with the context `-f vex` needs to
/// emit a `not_affected` statement (§6, §7.1).
#[derive(Debug, Clone)]
pub struct SuppressedOccurrence {
    pub advisory_id: String,
    pub aliases: Vec<String>,
    pub occurrence: Occurrence,
    pub justification: Option<String>,
    pub impact_statement: String,
    pub approved_by: Option<String>,
}

/// An assembled report plus the suppressed occurrences (consumed only by `-f vex`).
pub struct Assembled {
    pub report: FleetReport,
    pub suppressed: Vec<SuppressedOccurrence>,
}

/// What makes a trustworthy run "fail" with exit `1` (§8).
#[derive(Debug, Clone)]
pub struct GateConfig {
    pub fail_on: Severity,
    pub fail_on_warnings: bool,
}

/// Correlate and assemble the report, capturing occurrences removed by
/// `suppressions` for VEX promotion.
pub fn assemble(
    scan: ScanData,
    suppressions: &[Suppression],
    min_severity: Option<Severity>,
    provenance: Provenance,
) -> Assembled {
    let correlated = correlate(scan.vulnerabilities, scan.warnings);
    let (mut correlated, stale_ignores, suppressed) = apply_suppressions(correlated, suppressions);
    if let Some(min) = min_severity {
        correlated
            .vulnerabilities
            .retain(|v| passes_threshold(v.severity, min));
    }
    let summary = summarize(&correlated, &scan.outcomes, stale_ignores);
    Assembled {
        report: FleetReport {
            schema_version: fleetreach_core::SCHEMA_VERSION,
            provenance,
            summary,
            vulnerabilities: correlated.vulnerabilities,
            warnings: correlated.warnings,
            outcomes: scan.outcomes,
        },
        suppressed,
    }
}

/// [`assemble`] for non-VEX callers: each ignore is a fleet-wide suppression and
/// the captured occurrences are discarded.
pub fn build_report(
    scan: ScanData,
    ignores: &[Ignore],
    min_severity: Option<Severity>,
    provenance: Provenance,
) -> FleetReport {
    let suppressions: Vec<Suppression> = ignores.iter().map(Suppression::from_ignore).collect();
    assemble(scan, &suppressions, min_severity, provenance).report
}

/// The §8 exit code for an already-assembled (trustworthy) report.
///
/// Precedence is resolved by the caller for the "could not scan" cases (config
/// invalid, DB unloadable/stale) → `2`. Here we resolve the rest: any errored
/// repo or zero repos scanned is still `2` (a gap means we cannot claim clean);
/// otherwise `1` if the gate trips, else `0`.
pub fn exit_code(report: &FleetReport, gate: &GateConfig) -> u8 {
    if report.summary.repos_errored > 0 || report.summary.repos_scanned == 0 {
        return 2;
    }
    let vuln_hit = report
        .vulnerabilities
        .iter()
        .any(|v| gates(v.severity, gate.fail_on));
    let warn_hit = gate.fail_on_warnings && !report.warnings.is_empty();
    u8::from(vuln_hit || warn_hit)
}

/// Apply suppressions per occurrence: each match is removed and captured, and a
/// finding is dropped only once all its occurrences are gone. A fleet-wide
/// suppression clears every occurrence; a repo-scoped one only that repo's.
fn apply_suppressions(
    mut correlated: Correlated,
    suppressions: &[Suppression],
) -> (Correlated, Vec<String>, Vec<SuppressedOccurrence>) {
    let mut matched: BTreeSet<String> = BTreeSet::new();
    let mut suppressed: Vec<SuppressedOccurrence> = Vec::new();

    correlated.vulnerabilities.retain_mut(|v| {
        let mut kept: Vec<Occurrence> = Vec::with_capacity(v.occurrences.len());
        for occ in std::mem::take(&mut v.occurrences) {
            match matching_suppression(suppressions, &v.advisory_id, &occ) {
                Some(s) => {
                    matched.insert(s.id.clone());
                    suppressed.push(SuppressedOccurrence {
                        advisory_id: v.advisory_id.clone(),
                        aliases: v.aliases.clone(),
                        occurrence: occ,
                        justification: s.justification.clone(),
                        impact_statement: s.reason.clone(),
                        approved_by: s.approved_by.clone(),
                    });
                }
                None => kept.push(occ),
            }
        }
        v.occurrences = kept;
        !v.occurrences.is_empty()
    });

    // Warnings have no per-occurrence subcomponent; suppressed only fleet-wide.
    correlated.warnings.retain(|w| match &w.advisory_id {
        Some(id) if suppressions.iter().any(|s| &s.id == id && s.repo.is_none()) => {
            matched.insert(id.clone());
            false
        }
        _ => true,
    });

    // Suppressions that matched nothing are stale (surfaced). Deduped, order kept.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let stale = suppressions
        .iter()
        .map(|s| s.id.as_str())
        .filter(|id| !matched.contains(*id) && seen.insert(id))
        .map(str::to_string)
        .collect();
    (correlated, stale, suppressed)
}

/// The first suppression that applies to `occ` of `advisory_id`: ids must match,
/// and a repo-scoped suppression matches only an in-repo occurrence of that repo.
fn matching_suppression<'a>(
    suppressions: &'a [Suppression],
    advisory_id: &str,
    occ: &Occurrence,
) -> Option<&'a Suppression> {
    let repo = match occ {
        Occurrence::InRepo { repo, .. } => Some(repo),
        Occurrence::Toolchain { .. } => None,
    };
    suppressions.iter().find(|s| {
        s.id == advisory_id
            && match &s.repo {
                None => true,
                Some(scoped) => repo == Some(scoped),
            }
    })
}

fn summarize(
    correlated: &Correlated,
    outcomes: &[RepoOutcome],
    stale_ignores: Vec<String>,
) -> Summary {
    let repos_scanned = outcomes
        .iter()
        .filter(|o| matches!(o.status, ScanStatus::Scanned { .. }))
        .count();
    let repos_errored = outcomes
        .iter()
        .filter(|o| matches!(o.status, ScanStatus::Errored { .. }))
        .count();
    Summary {
        repos_scanned,
        repos_errored,
        vuln_count: correlated.vulnerabilities.len(),
        warn_count: correlated.warnings.len(),
        max_severity: max_severity_of(&correlated.vulnerabilities),
        stale_ignores,
    }
}

/// Fail-closed gating: an `Unknown`-severity vulnerability always trips the gate,
/// because we cannot prove it sits below the threshold.
fn gates(severity: Severity, fail_on: Severity) -> bool {
    severity == Severity::Unknown || severity >= fail_on
}

fn passes_threshold(severity: Severity, min: Severity) -> bool {
    severity == Severity::Unknown || severity >= min
}
