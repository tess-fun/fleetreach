//! Render a `FleetReport` to a human table, JSON, SARIF, or OpenVEX — side-effect free.
//!
//! `fleetreach-report` is the presentation layer: every function takes a
//! `fleetreach_core::FleetReport` and returns a `String`. It never writes to a
//! stream, decides an exit code, or emits color unless the caller asks — so
//! stream routing and TTY detection stay in the binary. It covers the machine
//! formats a CI pipeline consumes (`to_json`, `to_sarif`, `to_vex` for OpenVEX
//! suppression) alongside the human `to_table`, blast-radius `to_impact`, its
//! direct-vs-transitive `to_blast` split (with a manifest/upstream fix hint), the
//! package-level `to_packages` rollup (which dependency is the biggest fleet
//! liability; also `to_packages_json`), remediation-priority `to_fix_first`, the
//! actionable fix-queue `to_remediation` views, and a two-report comparison
//! (`diff_reports` → `to_diff_table`/`to_diff_json`) that splits new from fixed from
//! still-open findings for tracking fleet drift over time.
//!
//! # Usage
//!
//! ```sh
//! cargo add fleetreach-report
//! ```
//!
//! ```
//! use fleetreach_report::to_table;
//! # use fleetreach_core::semver::Version;
//! # use fleetreach_core::{DependencyKind, FleetReport, Occurrence, Provenance, RepoId,
//! #     Severity, Summary, VulnFinding};
//! # fn report() -> FleetReport {
//! #     let vuln = VulnFinding {
//! #         advisory_id: "RUSTSEC-2024-0001".into(), aliases: vec![], ecosystem: Default::default(), title: "use-after-free".into(),
//! #         severity: Severity::High, cvss_score: Some(7.5), url: None, affected_functions: vec![],
//! #         reachable: None, reachability: None, exploit: Default::default(),
//! #         occurrences: vec![Occurrence::InRepo {
//! #             repo: RepoId("app".into()), package: "foo".into(), installed: Version::new(1, 0, 0),
//! #             patched: vec![], dependency_kind: DependencyKind::Direct,
//! #             dependency_path: vec![], active: None, source: Default::default() }] };
//! #     FleetReport {
//! #         schema_version: 1,
//! #         provenance: Provenance { tool_version: "0".into(), rustsec_crate_version: "0".into(),
//! #             db_commit: None, db_timestamp: None, host_os: "linux".into(),
//! #             host_arch: "x86_64".into(), generated_at: "t".into() },
//! #         summary: Summary { repos_scanned: 1, repos_errored: 0, vuln_count: 1, warn_count: 0,
//! #             max_severity: Severity::High, stale_ignores: vec![] },
//! #         vulnerabilities: vec![vuln], warnings: vec![], outcomes: vec![] }
//! # }
//! // Render the fleet report as a plain-text table (no color for piped output).
//! let table = to_table(&report(), false);
//! assert!(table.contains("RUSTSEC-2024-0001"));
//! ```
//!
//! # Minimum supported Rust version
//!
//! 1.89. An MSRV increase is treated as a minor-version bump.

use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, BTreeSet};

use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Table};
use fleetreach_core::{
    remediations, Action, DependencyKind, Ecosystem, Exploitability, FleetReport, Occurrence,
    ReachTier, RemediationItem, Severity, VulnFinding, WarnFinding,
};
use serde::Serialize;

mod vex;
pub use vex::{
    project, to_vex, HumanAssertion, StatementView, VexParams, VexScope, OPENVEX_CONTEXT,
};

/// The machine payload (§9). Pretty-printed; still clean through `jq`.
pub fn to_json(report: &FleetReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

/// SARIF 2.1.0 for GitHub code scanning: one rule per advisory, one result per
/// occurrence, located at `Cargo.lock`.
///
/// §11: a machine-sound `not_affected` (static `NotReachable` or a phantom dep)
/// carries a `suppressions[]` entry so the Security tab greys it out; each
/// `approved` human assertion becomes an extra suppressed result. Pass `&[]` for
/// plain SARIF.
pub fn to_sarif(
    report: &FleetReport,
    approved: &[HumanAssertion],
) -> Result<String, serde_json::Error> {
    let mut rules = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for v in &report.vulnerabilities {
        if seen.insert(v.advisory_id.clone()) {
            rules.push(SarifRule {
                id: v.advisory_id.clone(),
                name: v.advisory_id.clone(),
                short_description: SarifText {
                    text: v.title.clone(),
                },
                help_uri: v.url.clone(),
                // Real CVSS score for the GitHub badge, else a per-band stand-in.
                properties: Some(SarifProps {
                    security_severity: v
                        .cvss_score
                        .unwrap_or_else(|| security_severity(v.severity))
                        .to_string(),
                }),
            });
        }
    }
    for w in &report.warnings {
        let id = warn_rule_id(w);
        if seen.insert(id.clone()) {
            rules.push(SarifRule {
                id: id.clone(),
                name: id,
                short_description: SarifText {
                    text: w.title.clone(),
                },
                help_uri: None,
                properties: None,
            });
        }
    }

    let mut results = Vec::new();
    for v in &report.vulnerabilities {
        for occ in &v.occurrences {
            // A machine-sound not_affected suppresses the result (§11).
            let suppression = match vex::machine_status(v, occ) {
                vex::MachineStatus::NotAffected { justification } => Some(format!(
                    "VEX not_affected: {justification} (automated static analysis)"
                )),
                _ => None,
            };
            results.push(sarif_result(
                v.advisory_id.clone(),
                sarif_level(v.severity),
                &v.title,
                occ,
                suppression,
            ));
        }
    }
    for w in &report.warnings {
        let id = warn_rule_id(w);
        for occ in &w.occurrences {
            results.push(sarif_result(id.clone(), "warning", &w.title, occ, None));
        }
    }
    // Approved human assertions (§11), re-injected as suppressed results.
    for a in approved.iter().filter(|a| a.approved_by.is_some()) {
        if seen.insert(a.advisory_id.clone()) {
            rules.push(SarifRule {
                id: a.advisory_id.clone(),
                name: a.advisory_id.clone(),
                short_description: SarifText {
                    text: format!("{} (human-asserted not_affected)", a.advisory_id),
                },
                help_uri: None,
                properties: None,
            });
        }
        results.push(human_sarif_result(a));
    }

    let sarif = SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: [SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "fleetreach",
                    information_uri: "https://github.com/tess-fun/fleetreach",
                    version: &report.provenance.tool_version,
                    rules,
                },
            },
            results,
        }],
    };
    serde_json::to_string_pretty(&sarif)
}

// ---- Typed SARIF 2.1.0 wire structs ----
//
// Typed structs (vs the `json!` macro) avoid building an intermediate Value tree
// per result, which profiling showed dominated SARIF emission at fleet scale.

#[derive(Serialize)]
struct SarifLog<'a> {
    #[serde(rename = "$schema")]
    schema: &'a str,
    version: &'a str,
    runs: [SarifRun<'a>; 1],
}

#[derive(Serialize)]
struct SarifRun<'a> {
    tool: SarifTool<'a>,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool<'a> {
    driver: SarifDriver<'a>,
}

#[derive(Serialize)]
struct SarifDriver<'a> {
    name: &'a str,
    #[serde(rename = "informationUri")]
    information_uri: &'a str,
    version: &'a str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifText,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    help_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifProps>,
}

#[derive(Serialize)]
struct SarifText {
    text: String,
}

#[derive(Serialize)]
struct SarifProps {
    #[serde(rename = "security-severity")]
    security_severity: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifText,
    locations: [SarifLocation; 1],
    #[serde(skip_serializing_if = "Vec::is_empty")]
    suppressions: Vec<SarifSuppression>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifResultProps>,
}

/// Per-result property bag. `dependencyKind` lets a SARIF consumer distinguish a
/// directly-declared dependency (fixable in this repo's manifest) from a transitive
/// one (needs an upstream bump or override) — the same direct/transitive signal the
/// `-f blast` view surfaces, in the format CI security tooling already ingests.
#[derive(Serialize)]
struct SarifResultProps {
    #[serde(rename = "dependencyKind")]
    dependency_kind: &'static str,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysical,
}

#[derive(Serialize)]
struct SarifPhysical {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifact,
}

#[derive(Serialize)]
struct SarifArtifact {
    uri: &'static str,
}

/// A SARIF `suppressions[]` entry (§11): `kind: external` because it comes from VEX.
#[derive(Serialize)]
struct SarifSuppression {
    kind: &'static str,
    justification: String,
}

/// A suppressed result for an approved human `not_affected` assertion.
fn human_sarif_result(a: &HumanAssertion) -> SarifResult {
    let approver = a.approved_by.as_deref().unwrap_or("");
    let reason = a
        .justification
        .clone()
        .unwrap_or_else(|| a.impact_statement.clone());
    SarifResult {
        rule_id: a.advisory_id.clone(),
        level: "warning",
        message: SarifText {
            text: format!(
                "not_affected (human-asserted) — {} {} ({reason}); approved_by {approver}",
                a.package, a.version
            ),
        },
        locations: [location("Cargo.lock")],
        suppressions: vec![SarifSuppression {
            kind: "external",
            justification: format!("VEX not_affected: {reason}; approved_by {approver}"),
        }],
        properties: None,
    }
}

fn warn_rule_id(w: &WarnFinding) -> String {
    w.advisory_id
        .clone()
        .unwrap_or_else(|| format!("{:?}", w.kind).to_lowercase())
}

fn location(uri: &'static str) -> SarifLocation {
    SarifLocation {
        physical_location: SarifPhysical {
            artifact_location: SarifArtifact { uri },
        },
    }
}

fn sarif_result(
    rule_id: String,
    level: &'static str,
    title: &str,
    occ: &Occurrence,
    suppression: Option<String>,
) -> SarifResult {
    let (text, uri) = match occ {
        Occurrence::InRepo {
            repo,
            package,
            installed,
            dependency_path,
            patched,
            ..
        } => {
            let fix = fix_target(patched)
                .map(|t| format!("; fix: update to {t}"))
                .unwrap_or_default();
            let via = if dependency_path.len() > 2 {
                format!(
                    " (via {})",
                    dependency_path[1..dependency_path.len() - 1].join(" → ")
                )
            } else {
                String::new()
            };
            (
                format!("{title} — {package} {installed} in {repo}{via}{fix}"),
                "Cargo.lock",
            )
        }
        Occurrence::Toolchain {
            channel, installed, ..
        } => (
            format!(
                "{title} — toolchain {channel} {}",
                installed
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default()
            ),
            "rust-toolchain.toml",
        ),
    };
    let properties = match occ {
        Occurrence::InRepo {
            dependency_kind, ..
        } => Some(SarifResultProps {
            dependency_kind: match dependency_kind {
                DependencyKind::Direct => "direct",
                DependencyKind::Transitive => "transitive",
            },
        }),
        Occurrence::Toolchain { .. } => None,
    };
    SarifResult {
        rule_id,
        level,
        message: SarifText { text },
        locations: [location(uri)],
        suppressions: suppression
            .map(|justification| SarifSuppression {
                kind: "external",
                justification,
            })
            .into_iter()
            .collect(),
        properties,
    }
}

/// SARIF severity level. Unknown is fail-closed to `warning` (visible), not note.
fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low | Severity::Unknown => "warning",
    }
}

/// GitHub reads `security-severity` as a CVSS-like 0–10 number to set its badge.
fn security_severity(severity: Severity) -> f32 {
    match severity {
        Severity::Critical => 9.5,
        Severity::High => 8.0,
        Severity::Medium => 5.5,
        Severity::Low => 2.0,
        Severity::Unknown => 0.0,
    }
}

/// The set of advisory ids present in a prior JSON report — the baseline against
/// which `--baseline` diffs to surface only *new* findings.
pub fn baseline_ids_from_json(
    json: &str,
) -> Result<std::collections::BTreeSet<String>, serde_json::Error> {
    let prior: FleetReport = serde_json::from_str(json)?;
    let mut ids = std::collections::BTreeSet::new();
    for v in &prior.vulnerabilities {
        ids.insert(v.advisory_id.clone());
    }
    for w in &prior.warnings {
        if let Some(id) = &w.advisory_id {
            ids.insert(id.clone());
        }
    }
    Ok(ids)
}

/// A comparison of two fleet reports — what appeared, what cleared, and what
/// persists — keyed on `advisory_id` (the canonical correlation key, same as
/// [`baseline_ids_from_json`]). Built by [`diff_reports`]; rendered by
/// [`to_diff_table`]/[`to_diff_json`]; turned into a CI exit code by
/// [`FleetDiff::regressions`]. The point a `--baseline` flag can't make: it splits
/// *fixed* from *still open* and carries each surviving advisory's blast-radius drift.
#[derive(Debug, Serialize)]
pub struct FleetDiff {
    /// Advisories present now but absent from the baseline — regressions.
    pub new: Vec<DiffEntry>,
    /// Advisories present in the baseline but gone now — wins.
    pub fixed: Vec<DiffEntry>,
    /// Advisories in both reports, each carrying its repo-count drift.
    pub still_open: Vec<DiffEntry>,
}

/// One advisory's place in a [`FleetDiff`]: its identity, how bad it is, and the
/// set of repos it touched before vs. now.
#[derive(Debug, Serialize)]
pub struct DiffEntry {
    pub advisory_id: String,
    pub title: String,
    /// Omitted from JSON for the common Cargo case (matches the finding schema).
    #[serde(skip_serializing_if = "Ecosystem::is_cargo")]
    pub ecosystem: Ecosystem,
    /// `None` for a supply-chain warning, which carries no severity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// A supply-chain warning rather than a vulnerability.
    pub warning: bool,
    /// Repos the advisory hit in the baseline report.
    pub baseline_repos: usize,
    /// Repos it hits in the current report.
    pub current_repos: usize,
    /// Repos newly affected since the baseline (current \ baseline).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub repos_added: Vec<String>,
    /// Repos cleared since the baseline (baseline \ current).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub repos_removed: Vec<String>,
}

impl FleetDiff {
    /// Count of newly introduced findings that should fail CI: a new vulnerability
    /// at or above `floor` (or of Unknown severity, which fails closed), plus new
    /// warnings when `warnings` is set. Mirrors the scan gate (`--fail-on`).
    pub fn regressions(&self, floor: Severity, warnings: bool) -> usize {
        self.new
            .iter()
            .filter(|e| match e.severity {
                Some(s) => s == Severity::Unknown || s >= floor,
                None => warnings,
            })
            .count()
    }
}

/// One report reduced to the per-advisory facts the diff needs.
struct DiffSide<'a> {
    title: &'a str,
    severity: Option<Severity>,
    ecosystem: Ecosystem,
    warning: bool,
    repos: BTreeSet<&'a str>,
}

/// Index a report by `advisory_id`. Vulnerabilities always carry an id; warnings
/// without one (a bare yank) can't be diffed across runs and are skipped.
fn index_findings(report: &FleetReport) -> BTreeMap<&str, DiffSide<'_>> {
    let mut map = BTreeMap::new();
    for v in &report.vulnerabilities {
        map.insert(
            v.advisory_id.as_str(),
            DiffSide {
                title: &v.title,
                severity: Some(v.severity),
                ecosystem: v.ecosystem,
                warning: false,
                repos: affected_repos(&v.occurrences),
            },
        );
    }
    for w in &report.warnings {
        if let Some(id) = &w.advisory_id {
            map.insert(
                id.as_str(),
                DiffSide {
                    title: &w.title,
                    severity: None,
                    ecosystem: Ecosystem::default(),
                    warning: true,
                    repos: affected_repos(&w.occurrences),
                },
            );
        }
    }
    map
}

fn diff_entry(
    id: &str,
    side: &DiffSide,
    base: &BTreeSet<&str>,
    curr: &BTreeSet<&str>,
) -> DiffEntry {
    let added = curr.difference(base).map(|r| r.to_string()).collect();
    let removed = base.difference(curr).map(|r| r.to_string()).collect();
    DiffEntry {
        advisory_id: id.to_string(),
        title: side.title.to_string(),
        ecosystem: side.ecosystem,
        severity: side.severity,
        warning: side.warning,
        baseline_repos: base.len(),
        current_repos: curr.len(),
        repos_added: added,
        repos_removed: removed,
    }
}

/// Compare two fleet reports. An advisory is *new* if its id is in `current` only,
/// *fixed* if in `baseline` only, *still open* if in both. Each bucket is sorted
/// worst-first (severity desc, warnings last, then id) for stable output.
pub fn diff_reports(baseline: &FleetReport, current: &FleetReport) -> FleetDiff {
    let base = index_findings(baseline);
    let curr = index_findings(current);
    let empty = BTreeSet::new();

    let mut new = Vec::new();
    let mut still_open = Vec::new();
    for (id, c) in &curr {
        match base.get(id) {
            None => new.push(diff_entry(id, c, &empty, &c.repos)),
            Some(b) => still_open.push(diff_entry(id, c, &b.repos, &c.repos)),
        }
    }
    let mut fixed = Vec::new();
    for (id, b) in &base {
        if !curr.contains_key(id) {
            fixed.push(diff_entry(id, b, &b.repos, &empty));
        }
    }

    let sort = |v: &mut Vec<DiffEntry>| {
        v.sort_by(|a, b| {
            Reverse(severity_tier(a.severity))
                .cmp(&Reverse(severity_tier(b.severity)))
                .then_with(|| a.advisory_id.cmp(&b.advisory_id))
        });
    };
    sort(&mut new);
    sort(&mut fixed);
    sort(&mut still_open);
    FleetDiff {
        new,
        fixed,
        still_open,
    }
}

/// The diff as JSON — the machine-readable form a CI job stores between runs.
pub fn to_diff_json(diff: &FleetDiff) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(diff)
}

/// The human diff: a one-line tally, then a section per non-empty bucket. New and
/// fixed list every advisory; still-open lists only the entries whose blast radius
/// drifted (with an "N unchanged" footer), since an unchanged persistent finding is
/// the boring majority on a real fleet.
pub fn to_diff_table(diff: &FleetDiff, color: bool) -> String {
    let mut sections: Vec<String> = vec![format!(
        "{} new, {} fixed, {} still open.",
        diff.new.len(),
        diff.fixed.len(),
        diff.still_open.len(),
    )];
    if !diff.new.is_empty() {
        sections.push(format!("New ({}):", diff.new.len()));
        sections.push(diff_table(&diff.new, color));
    }
    if !diff.fixed.is_empty() {
        sections.push(format!("Fixed ({}):", diff.fixed.len()));
        sections.push(diff_table(&diff.fixed, color));
    }
    let drifted: Vec<&DiffEntry> = diff
        .still_open
        .iter()
        .filter(|e| !e.repos_added.is_empty() || !e.repos_removed.is_empty())
        .collect();
    if !drifted.is_empty() {
        sections.push(format!(
            "Still open, blast radius changed ({}):",
            drifted.len()
        ));
        let rows: Vec<DiffEntry> = drifted.into_iter().map(clone_entry).collect();
        sections.push(diff_table(&rows, color));
    }
    let unchanged = diff.still_open.len()
        - diff
            .still_open
            .iter()
            .filter(|e| !e.repos_added.is_empty() || !e.repos_removed.is_empty())
            .count();
    if unchanged > 0 {
        sections.push(format!("({unchanged} still open, unchanged)"));
    }
    if diff.new.is_empty() && diff.fixed.is_empty() {
        sections.push("No advisories appeared or cleared.".to_string());
    }
    sections.join("\n\n")
}

fn clone_entry(e: &DiffEntry) -> DiffEntry {
    DiffEntry {
        advisory_id: e.advisory_id.clone(),
        title: e.title.clone(),
        ecosystem: e.ecosystem,
        severity: e.severity,
        warning: e.warning,
        baseline_repos: e.baseline_repos,
        current_repos: e.current_repos,
        repos_added: e.repos_added.clone(),
        repos_removed: e.repos_removed.clone(),
    }
}

fn diff_table(entries: &[DiffEntry], color: bool) -> String {
    let mut table = styled_table(color, vec!["Severity", "Advisory", "Repos", "Title"]);
    for e in entries {
        let sev_cell = if e.warning {
            Cell::new("warning")
        } else {
            maybe_color(
                Cell::new(severity_label(e.severity.unwrap_or(Severity::Unknown))),
                color.then(|| severity_color(e.severity.unwrap_or(Severity::Unknown))),
            )
        };
        table.add_row(vec![
            sev_cell,
            Cell::new(sanitize_cell(&e.advisory_id)),
            Cell::new(diff_repo_cell(e)),
            Cell::new(sanitize_cell(&e.title)),
        ]);
    }
    table.to_string()
}

/// The repo cell: the current count, with `+added`/`-removed` deltas when the
/// blast radius moved. New findings read `N (+N)`, fixed read `0 (-M)`, drift reads
/// `5 (+2 -1)`.
fn diff_repo_cell(e: &DiffEntry) -> String {
    let mut deltas = Vec::new();
    if !e.repos_added.is_empty() {
        deltas.push(format!("+{}", e.repos_added.len()));
    }
    if !e.repos_removed.is_empty() {
        deltas.push(format!("-{}", e.repos_removed.len()));
    }
    if deltas.is_empty() {
        e.current_repos.to_string()
    } else {
        format!("{} ({})", e.current_repos, deltas.join(" "))
    }
}

/// The human findings view. Returns a friendly note when the fleet is clean.
/// `color` tints the severity/kind cells with ANSI — pass `true` only for a TTY,
/// never for JSON or piped output.
pub fn to_table(report: &FleetReport, color: bool) -> String {
    let mut sections: Vec<String> = Vec::new();
    if !report.vulnerabilities.is_empty() {
        sections.push(vuln_table(&report.vulnerabilities, color));
    }
    if !report.warnings.is_empty() {
        sections.push(warn_table(&report.warnings, color));
    }
    if sections.is_empty() {
        return "No advisories found.".to_string();
    }
    sections.join("\n\n")
}

/// Blast-radius view: findings ranked by how many repos they hit — the
/// cross-repo angle only a fleet tool can show. Answers "which advisory clears
/// the most repos if I fix it?". `KEV` is flagged inline (high blast radius +
/// actively exploited = top priority).
/// One advisory (or warning) flattened to the fields the ranked table views —
/// [`to_impact`] and [`to_fix_first`] — rank and render by. Built once by
/// [`advisory_rows`]; each view supplies its own sort order and column layout.
struct AdvisoryRow<'a> {
    repos: BTreeSet<&'a str>,
    toolchain: bool,
    severity: Option<Severity>,
    kev: bool,
    /// Severity tier: vulns map `Unknown..Critical` → `1..=5`; warnings sit at `0`.
    tier: u8,
    cvss: f32,
    epss: f32,
    label: String,
    id: &'a str,
    title: &'a str,
}

/// Flatten every vulnerability and warning into [`AdvisoryRow`]s — the shared first
/// step of the ranked views, which then differ only in how they sort and lay out.
fn advisory_rows(report: &FleetReport) -> Vec<AdvisoryRow<'_>> {
    let mut rows = Vec::with_capacity(report.vulnerabilities.len() + report.warnings.len());
    for v in &report.vulnerabilities {
        rows.push(AdvisoryRow {
            repos: affected_repos(&v.occurrences),
            toolchain: has_toolchain(&v.occurrences),
            severity: Some(v.severity),
            kev: v.exploit.kev,
            tier: severity_tier(Some(v.severity)),
            cvss: v.cvss_score.unwrap_or(0.0),
            epss: v.exploit.epss.unwrap_or(-1.0),
            label: severity_cell_text(v),
            id: &v.advisory_id,
            title: &v.title,
        });
    }
    for w in &report.warnings {
        rows.push(AdvisoryRow {
            repos: affected_repos(&w.occurrences),
            toolchain: has_toolchain(&w.occurrences),
            severity: None,
            kev: false,
            tier: severity_tier(None),
            cvss: 0.0,
            epss: -1.0,
            label: format!("{:?}", w.kind).to_lowercase(),
            id: w.advisory_id.as_deref().unwrap_or("-"),
            title: &w.title,
        });
    }
    rows
}

/// The severity cell shared by the ranked views: the severity `label` with a `KEV`
/// suffix when actively exploited, tinted by severity on a TTY (`color`) and left plain
/// otherwise (and for warnings, which have no severity).
fn advisory_sev_cell(label: &str, kev: bool, severity: Option<Severity>, color: bool) -> Cell {
    let label = if kev {
        format!("{label} KEV")
    } else {
        label.to_string()
    };
    match (color, severity) {
        (true, Some(s)) => Cell::new(label).fg(severity_color(s)),
        _ => Cell::new(label),
    }
}

pub fn to_impact(report: &FleetReport, color: bool) -> String {
    let mut rows = advisory_rows(report);
    if rows.is_empty() {
        return "No advisories found.".to_string();
    }
    // Most repos first; ties broken by severity desc (warnings last), then id.
    rows.sort_by(|a, b| {
        b.repos
            .len()
            .cmp(&a.repos.len())
            .then(b.severity.cmp(&a.severity))
            .then(a.id.cmp(b.id))
    });

    let mut table = styled_table(
        color,
        vec!["Repos", "Severity", "Advisory", "Affected", "Title"],
    );
    for r in &rows {
        table.add_row(vec![
            Cell::new(impact_count(r.repos.len(), r.toolchain)),
            advisory_sev_cell(&r.label, r.kev, r.severity, color),
            Cell::new(sanitize_cell(r.id)),
            Cell::new(affected_list(&r.repos, r.toolchain)),
            Cell::new(truncate(&sanitize_cell(r.title), 40)),
        ]);
    }
    table.to_string()
}

/// Blast view: the same blast-radius ranking as [`to_impact`], decomposed into
/// **direct** vs **transitive** reach so the fix *strategy* is legible. A corpus
/// study found that across a real ecosystem the
/// large majority of vulnerable-dependency exposures are transitive, and that the
/// transitive picture reorders the headline relative to a direct-only view. That is
/// actionable: an advisory reaching most of its repos *transitively* cannot be fixed
/// by editing those repos' manifests — it needs an upstream bump or a dependency
/// override — whereas a *direct* one can. Columns: total `Repos`, `Direct` (repos where
/// the package is a direct dependency), `Transitive` (repos where it is reached only
/// transitively), and a `Fix` hint (`manifest` / `upstream` / `mixed`). Ranked by total
/// blast radius, like [`to_impact`].
pub fn to_blast(report: &FleetReport, color: bool) -> String {
    struct Row<'a> {
        total: usize,
        direct: usize,
        transitive: usize,
        severity: Option<Severity>,
        kev: bool,
        label: String,
        id: &'a str,
        title: &'a str,
    }

    fn split(occurrences: &[Occurrence]) -> (usize, usize, usize) {
        let all = affected_repos(occurrences);
        let direct = direct_repos(occurrences);
        // A repo is "transitive" for this advisory when the package is reached there
        // only transitively (no direct occurrence) — so direct + transitive == total.
        let transitive = all.len() - direct.len();
        (all.len(), direct.len(), transitive)
    }

    let mut rows: Vec<Row> = Vec::new();
    for v in &report.vulnerabilities {
        let (total, direct, transitive) = split(&v.occurrences);
        rows.push(Row {
            total,
            direct,
            transitive,
            severity: Some(v.severity),
            kev: v.exploit.kev,
            label: severity_cell_text(v),
            id: &v.advisory_id,
            title: &v.title,
        });
    }
    for w in &report.warnings {
        let (total, direct, transitive) = split(&w.occurrences);
        rows.push(Row {
            total,
            direct,
            transitive,
            severity: None,
            kev: false,
            label: format!("{:?}", w.kind).to_lowercase(),
            id: w.advisory_id.as_deref().unwrap_or("-"),
            title: &w.title,
        });
    }
    if rows.is_empty() {
        return "No advisories found.".to_string();
    }
    // Most repos first; ties broken by severity desc (warnings last), then id — the
    // same ordering as `to_impact`, so the two views agree on rank.
    rows.sort_by(|a, b| {
        b.total
            .cmp(&a.total)
            .then(b.severity.cmp(&a.severity))
            .then(a.id.cmp(b.id))
    });

    let mut table = styled_table(
        color,
        vec![
            "Repos",
            "Direct",
            "Transitive",
            "Fix",
            "Severity",
            "Advisory",
            "Title",
        ],
    );
    for r in &rows {
        table.add_row(vec![
            Cell::new(r.total),
            Cell::new(r.direct),
            Cell::new(r.transitive),
            Cell::new(fix_strategy(r.direct, r.transitive)),
            advisory_sev_cell(&r.label, r.kev, r.severity, color),
            Cell::new(sanitize_cell(r.id)),
            Cell::new(truncate(&sanitize_cell(r.title), 40)),
        ]);
    }
    table.to_string()
}

/// The remediation strategy implied by an advisory's direct/transitive split:
/// `manifest` if every affected repo depends on it directly (each can fix in its own
/// manifest), `upstream` if every exposure is transitive (needs an upstream bump or a
/// dependency override), else `mixed`.
fn fix_strategy(direct: usize, transitive: usize) -> &'static str {
    match (direct, transitive) {
        (_, 0) => "manifest",
        (0, _) => "upstream",
        _ => "mixed",
    }
}

/// One vulnerable dependency, rolled up across the whole fleet — the unit of the
/// [`to_packages`] view. A single package (e.g. `golang.org/x/net`) typically carries
/// many advisories across many repos, and one bump clears them all; this is the
/// "which dependency is my biggest fleet liability" rollup of [`to_blast`]'s per-
/// advisory rows.
#[derive(Serialize)]
pub struct PackageImpact {
    /// The vulnerable package / module name.
    pub package: String,
    /// Its ecosystem (omitted from JSON for the default `cargo`, like elsewhere).
    #[serde(skip_serializing_if = "Ecosystem::is_cargo")]
    pub ecosystem: Ecosystem,
    /// Distinct repos where this package is a vulnerable dependency (its fleet reach).
    pub repos: usize,
    /// Of `repos`, how many depend on it directly (fixable in their own manifest).
    pub direct: usize,
    /// Of `repos`, how many reach it only transitively (need an upstream bump/override).
    pub transitive: usize,
    /// Distinct advisories affecting this package across the fleet — all cleared by one
    /// fix if a single version is past them all.
    pub advisories: usize,
    /// The worst severity among those advisories.
    pub max_severity: Severity,
    /// `manifest` / `upstream` / `mixed`, from the direct/transitive split.
    pub fix: &'static str,
    /// Any affecting advisory is in CISA KEV (actively exploited).
    pub kev: bool,
    /// The highest EPSS (exploit probability) among the affecting advisories.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_epss: Option<f32>,
}

/// Roll every vulnerability up to its `(ecosystem, package)`, aggregating fleet reach,
/// the direct/transitive split, advisory count, worst severity, and exploit signal.
/// Ranked by reach (repos) first — the dependency hitting the most of your fleet — then
/// severity, then advisory count, then name. Warnings are not advisories, so excluded.
fn package_impacts(report: &FleetReport) -> Vec<PackageImpact> {
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Agg<'a> {
        repos: BTreeSet<&'a str>,
        direct: BTreeSet<&'a str>,
        advisories: BTreeSet<&'a str>,
        max_severity: Option<Severity>,
        kev: bool,
        max_epss: Option<f32>,
    }

    let mut map: BTreeMap<(Ecosystem, &str), Agg> = BTreeMap::new();
    for v in &report.vulnerabilities {
        for occ in &v.occurrences {
            let Occurrence::InRepo {
                repo,
                package,
                dependency_kind,
                ..
            } = occ
            else {
                continue;
            };
            let a = map.entry((v.ecosystem, package.as_str())).or_default();
            a.repos.insert(repo.0.as_str());
            if matches!(dependency_kind, DependencyKind::Direct) {
                a.direct.insert(repo.0.as_str());
            }
            a.advisories.insert(v.advisory_id.as_str());
            a.max_severity = Some(a.max_severity.map_or(v.severity, |m| m.max(v.severity)));
            a.kev |= v.exploit.kev;
            if let Some(p) = v.exploit.epss {
                a.max_epss = Some(a.max_epss.map_or(p, |m: f32| m.max(p)));
            }
        }
    }

    let mut rows: Vec<PackageImpact> = map
        .into_iter()
        .map(|((ecosystem, package), a)| {
            let repos = a.repos.len();
            let direct = a.direct.len();
            let transitive = repos - direct;
            PackageImpact {
                package: package.to_string(),
                ecosystem,
                repos,
                direct,
                transitive,
                advisories: a.advisories.len(),
                max_severity: a.max_severity.unwrap_or(Severity::Unknown),
                fix: fix_strategy(direct, transitive),
                kev: a.kev,
                max_epss: a.max_epss,
            }
        })
        .collect();
    // Biggest fleet liability first: reach, then severity, then advisory count, then name.
    rows.sort_by(|x, y| {
        y.repos
            .cmp(&x.repos)
            .then(y.max_severity.cmp(&x.max_severity))
            .then(y.advisories.cmp(&x.advisories))
            .then(x.package.cmp(&y.package))
    });
    rows
}

/// Package-impact view: vulnerable dependencies ranked by fleet reach — the answer to
/// "which single dependency is my biggest liability, and would one bump clear the
/// most?". Where [`to_blast`] ranks advisories, this rolls them up to the package, so a
/// dependency carrying twenty advisories across sixty repos reads as one row. Columns:
/// `Repos` (reach), `Direct`/`Transitive` split, `Advisories` (how many one bump
/// clears), worst `Severity`, the `Fix` path, and the `Exploit` signal.
pub fn to_packages(report: &FleetReport, color: bool) -> String {
    let rows = package_impacts(report);
    if rows.is_empty() {
        return "No vulnerable dependencies found.".to_string();
    }

    let mut table = styled_table(
        color,
        vec![
            "Repos",
            "Direct",
            "Transitive",
            "Advisories",
            "Severity",
            "Fix",
            "Exploit",
            "Package",
        ],
    );
    for r in &rows {
        let sev_label = format!("{:?}", r.max_severity).to_lowercase();
        let sev_cell = maybe_color(
            Cell::new(sev_label),
            color.then(|| severity_color(r.max_severity)),
        );
        let pkg = match r.ecosystem {
            Ecosystem::Cargo => sanitize_cell(&r.package),
            other => format!(
                "{} ({})",
                sanitize_cell(&r.package),
                format!("{other:?}").to_lowercase()
            ),
        };
        table.add_row(vec![
            Cell::new(r.repos),
            Cell::new(r.direct),
            Cell::new(r.transitive),
            Cell::new(r.advisories),
            sev_cell,
            Cell::new(r.fix),
            Cell::new(exploit_cell(r.kev, r.max_epss.unwrap_or(-1.0))),
            Cell::new(pkg),
        ]);
    }
    table.to_string()
}

/// The package-impact rollup as JSON, for automation (a dashboard of the fleet's
/// worst dependencies). Same ranking as [`to_packages`].
pub fn to_packages_json(report: &FleetReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&package_impacts(report))
}

/// Fix-first view: findings ranked by remediation priority — the answer to "what
/// should I patch first?". Unlike [`to_impact`] (pure blast radius), this is
/// severity-dominant: an actively-exploited (`KEV`) finding leads, then strictly
/// by severity band, and only *within* a band by how many repos it clears. That
/// keeps real CVEs above high-spread informational warnings — an unsound-but-low
/// lint hitting thousands of repos should not outrank a critical CVE in a handful.
/// The `#` column is the fix order (1 = fix first); blast radius and the exploit
/// signals (KEV/EPSS) are shown so the ranking is legible.
pub fn to_fix_first(report: &FleetReport, color: bool) -> String {
    let mut rows = advisory_rows(report);
    if rows.is_empty() {
        return "No advisories found.".to_string();
    }

    // KEV first, then severity tier desc, then blast radius desc (the fleet-only
    // tie-breaker), then EPSS desc, CVSS desc, and id for a total, stable order.
    rows.sort_by(|a, b| {
        b.kev
            .cmp(&a.kev)
            .then(b.tier.cmp(&a.tier))
            .then(b.repos.len().cmp(&a.repos.len()))
            .then(b.epss.partial_cmp(&a.epss).unwrap_or(Ordering::Equal))
            .then(b.cvss.partial_cmp(&a.cvss).unwrap_or(Ordering::Equal))
            .then(a.id.cmp(b.id))
    });

    let mut table = styled_table(
        color,
        vec!["#", "Severity", "Repos", "Exploit", "Advisory", "Title"],
    );
    for (i, r) in rows.iter().enumerate() {
        table.add_row(vec![
            Cell::new(i + 1),
            advisory_sev_cell(&r.label, r.kev, r.severity, color),
            Cell::new(impact_count(r.repos.len(), r.toolchain)),
            Cell::new(exploit_cell(r.kev, r.epss)),
            Cell::new(sanitize_cell(r.id)),
            Cell::new(truncate(&sanitize_cell(r.title), 40)),
        ]);
    }
    table.to_string()
}

/// Remediation view: the actionable fix queue. Where [`to_fix_first`] ranks *which
/// advisory* to patch, this ranks *what to do* — the concrete dependency bump,
/// batched so one row clears every advisory a single version bump resolves, with a
/// reachability gate. The active queue is fix-first-ordered (KEV, severity, blast,
/// EPSS, CVSS); advisories that are soundly `NotReachable` drop to an
/// informational tail (shown, never numbered) so dead-code findings never crowd
/// out real work. The `#` column is the fix order.
pub fn to_remediation(report: &FleetReport, color: bool) -> String {
    let items = remediations(report);
    if items.is_empty() {
        return "No remediations: nothing to fix.".to_string();
    }
    let (mut active, mut informational): (Vec<&RemediationItem>, Vec<&RemediationItem>) =
        items.iter().partition(|i| i.reach.is_actionable());

    // Active queue: the proven fix-first order, applied to batched actions. Within
    // a severity band, a *confirmed-reachable* batch leads an unconfirmed one
    // before blast radius breaks the tie — a govulncheck-confirmed call site is a
    // stronger "fix this" signal than merely hitting more repos. (Decisive for Go,
    // whose advisories carry no CVSS, so most sit in the same `unknown` band.)
    active.sort_by(|a, b| {
        b.kev
            .cmp(&a.kev)
            .then(severity_tier(Some(b.max_severity)).cmp(&severity_tier(Some(a.max_severity))))
            .then(reach_rank(b.reach).cmp(&reach_rank(a.reach)))
            .then(b.repos.cmp(&a.repos))
            .then(
                b.max_epss
                    .unwrap_or(-1.0)
                    .partial_cmp(&a.max_epss.unwrap_or(-1.0))
                    .unwrap_or(Ordering::Equal),
            )
            .then(
                b.max_cvss
                    .unwrap_or(0.0)
                    .partial_cmp(&a.max_cvss.unwrap_or(0.0))
                    .unwrap_or(Ordering::Equal),
            )
            .then(a.package.cmp(&b.package))
    });
    // Informational tail: blast radius desc, then package — these aren't work.
    informational.sort_by(|a, b| b.repos.cmp(&a.repos).then(a.package.cmp(&b.package)));

    let mut sections: Vec<String> = Vec::new();
    if !active.is_empty() {
        sections.push(remediation_table(&active, true, color));
    }
    if !informational.is_empty() {
        let mut section =
            String::from("Informational \u{2014} not reachable (shown, not queued):\n");
        section.push_str(&remediation_table(&informational, false, color));
        sections.push(section);
    }
    sections.join("\n\n")
}

/// The remediation queue as JSON, for automation (a CI step that opens upgrade
/// PRs). Each item carries its own `reach` so the consumer filters the active set
/// itself; order is `core`'s stable package order, not the presentation ranking.
pub fn to_remediation_json(report: &FleetReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&remediations(report))
}

fn remediation_table(items: &[&RemediationItem], numbered: bool, color: bool) -> String {
    let mut table = styled_table(
        color,
        vec![
            "#", "Action", "Severity", "Resolves", "Repos", "Reach", "Exploit",
        ],
    );
    for (i, it) in items.iter().enumerate() {
        let num = if numbered {
            (i + 1).to_string()
        } else {
            "-".to_string()
        };
        let sev_cell = maybe_color(
            Cell::new(remediation_severity_text(it)),
            color.then(|| severity_color(it.max_severity)),
        );
        table.add_row(vec![
            Cell::new(num),
            Cell::new(action_label(it)),
            sev_cell,
            Cell::new(resolves_text(it)),
            Cell::new(it.repos),
            Cell::new(reach_tier_label(it.reach)),
            Cell::new(exploit_cell(it.kev, it.max_epss.unwrap_or(-1.0))),
        ]);
    }
    table.to_string()
}

/// The action as a one-line instruction: `bump foo 1.0.0 → 1.5.0 (breaking)` or
/// `no fix: foo`. The package name and versions are untrusted, so sanitized.
fn action_label(it: &RemediationItem) -> String {
    let pkg = sanitize_cell(&it.package);
    match &it.action {
        Action::Upgrade { to, breaking } => {
            let from = it
                .current
                .first()
                .map(|v| format!("{v} \u{2192} "))
                .unwrap_or_default();
            let brk = if *breaking { " (breaking)" } else { "" };
            format!("bump {pkg} {from}{to}{brk}")
        }
        Action::NoFixAvailable => format!("no fix: {pkg}"),
    }
}

/// The advisory it clears: the bare id when a single one, else a count.
fn resolves_text(it: &RemediationItem) -> String {
    match it.advisories.as_slice() {
        [one] => sanitize_cell(one),
        many => format!("{} advisories", many.len()),
    }
}

/// Severity label with the worst CVSS in the batch appended when known.
fn remediation_severity_text(it: &RemediationItem) -> String {
    match it.max_cvss {
        Some(score) => format!("{} {score:.1}", severity_label(it.max_severity)),
        None => severity_label(it.max_severity).to_string(),
    }
}

/// Ranking weight for the active-queue tiebreak: a confirmed-reachable batch
/// outranks an unconfirmed one. (`NotReachable` never reaches here — those are
/// split into the informational tail.)
fn reach_rank(tier: ReachTier) -> u8 {
    match tier {
        ReachTier::Reachable => 2,
        ReachTier::Unknown => 1,
        ReachTier::NotReachable => 0,
    }
}

fn reach_tier_label(tier: ReachTier) -> &'static str {
    match tier {
        ReachTier::Reachable => "reachable",
        ReachTier::Unknown => "unknown",
        ReachTier::NotReachable => "not reachable",
    }
}

/// Severity ordinal for fix-first ranking: vulns map `Unknown..Critical` onto
/// `1..=5`; warnings (no severity) sit at `0`, below every real advisory.
fn severity_tier(severity: Option<Severity>) -> u8 {
    match severity {
        Some(s) => s as u8 + 1,
        None => 0,
    }
}

/// The exploit-signal cell for the fix-first view: `KEV` and/or `EPSS NN%`, or
/// `-` when the finding carries neither (e.g. a scan without `--enrich`).
fn exploit_cell(kev: bool, epss: f32) -> String {
    let mut parts = Vec::new();
    if kev {
        parts.push("KEV".to_string());
    }
    if epss >= 0.0 {
        parts.push(format!("EPSS {:.0}%", epss * 100.0));
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(" ")
    }
}

/// A `comfy_table::Table` with the project's standard preset and a header row. When
/// `color` is set, ANSI styling is forced on regardless of comfy-table's own TTY
/// detection — the caller has already decided the output is a real terminal (it passes
/// `true` only then). Every table view goes through here so the preset/styling is set
/// in exactly one place.
fn styled_table(color: bool, header: Vec<&str>) -> Table {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    if color {
        table.enforce_styling();
    }
    table.set_header(header);
    table
}

fn affected_repos(occurrences: &[Occurrence]) -> BTreeSet<&str> {
    occurrences
        .iter()
        .filter_map(|o| match o {
            Occurrence::InRepo { repo, .. } => Some(repo.0.as_str()),
            Occurrence::Toolchain { .. } => None,
        })
        .collect()
}

/// Repos where this advisory is reached through a **direct** dependency (at least one
/// direct occurrence). A repo with only transitive occurrences is excluded, so
/// `direct_repos(..).len()` and the transitive remainder partition [`affected_repos`].
fn direct_repos(occurrences: &[Occurrence]) -> BTreeSet<&str> {
    occurrences
        .iter()
        .filter_map(|o| match o {
            Occurrence::InRepo {
                repo,
                dependency_kind: DependencyKind::Direct,
                ..
            } => Some(repo.0.as_str()),
            _ => None,
        })
        .collect()
}

fn has_toolchain(occurrences: &[Occurrence]) -> bool {
    occurrences
        .iter()
        .any(|o| matches!(o, Occurrence::Toolchain { .. }))
}

fn impact_count(repos: usize, toolchain: bool) -> String {
    if repos == 0 && toolchain {
        "toolchain".to_string()
    } else {
        repos.to_string()
    }
}

fn affected_list(repos: &BTreeSet<&str>, toolchain: bool) -> String {
    let mut names: Vec<&str> = repos.iter().copied().collect();
    let extra = names.len().saturating_sub(4);
    names.truncate(4);
    // Repo names are untrusted (from fleet.toml / discovered paths) — sanitize before
    // they reach the terminal.
    let mut out = names
        .iter()
        .map(|n| sanitize_cell(n))
        .collect::<Vec<_>>()
        .join(", ");
    if extra > 0 {
        out.push_str(&format!(", (+{extra})"));
    }
    if toolchain {
        if !out.is_empty() {
            out.push_str(", ");
        }
        out.push_str("toolchain");
    }
    out
}

/// One-line summary for stderr (suppressible with `-q`).
pub fn summary_line(report: &FleetReport) -> String {
    let s = &report.summary;
    let mut line = format!(
        "Scanned {} repo(s) ({} errored): {} vuln{}, {} warning(s); max severity {}.",
        s.repos_scanned,
        s.repos_errored,
        s.vuln_count,
        if s.vuln_count == 1 { "" } else { "s" },
        s.warn_count,
        severity_label(s.max_severity),
    );
    if !s.stale_ignores.is_empty() {
        let ignores: Vec<String> = s.stale_ignores.iter().map(|i| sanitize_cell(i)).collect();
        line.push_str(&format!(" Stale ignores: {}.", ignores.join(", ")));
    }
    line
}

fn vuln_table(vulns: &[VulnFinding], color: bool) -> String {
    // Conditional columns: only shown when that analysis actually ran.
    let enriched = vulns
        .iter()
        .any(|v| v.exploit.kev || v.exploit.epss.is_some());
    let reach_checked = vulns.iter().any(|v| v.reachable.is_some());

    let mut header = vec!["Severity"];
    if enriched {
        header.push("Risk");
    }
    if reach_checked {
        header.push("Reach");
    }
    header.extend(["Advisory", "Title", "Locations"]);
    let mut table = styled_table(color, header);

    for v in vulns {
        let mut row = vec![maybe_color(
            Cell::new(severity_cell_text(v)),
            color.then(|| severity_color(v.severity)),
        )];
        if enriched {
            row.push(risk_cell(&v.exploit, color));
        }
        if reach_checked {
            row.push(Cell::new(reach_label(v.reachable)));
        }
        row.push(Cell::new(sanitize_cell(&v.advisory_id)));
        row.push(Cell::new(title_with_functions(v)));
        row.push(Cell::new(locations(&v.occurrences)));
        table.add_row(row);
    }
    table.to_string()
}

/// Honest labels for the source-presence heuristic — never "(un)reachable".
fn reach_label(reachable: Option<bool>) -> &'static str {
    match reachable {
        Some(true) => "in source",
        Some(false) => "not found",
        None => "?",
    }
}

fn warn_table(warns: &[WarnFinding], color: bool) -> String {
    let mut table = styled_table(color, vec!["Kind", "Advisory", "Locations"]);
    for w in warns {
        let kind = Cell::new(format!("{:?}", w.kind).to_lowercase());
        table.add_row(vec![
            maybe_color(kind, color.then_some(Color::DarkYellow)),
            Cell::new(sanitize_cell(w.advisory_id.as_deref().unwrap_or("-"))),
            Cell::new(locations(&w.occurrences)),
        ]);
    }
    table.to_string()
}

fn maybe_color(cell: Cell, color: Option<Color>) -> Cell {
    match color {
        Some(c) => cell.fg(c),
        None => cell,
    }
}

/// The triage hint appended to a location: direct deps you can bump yourself;
/// for transitive ones, the intermediate chain (entry … parent) that drags the
/// package in. The complete chain is always available in the JSON output.
fn dependency_hint(kind: fleetreach_core::DependencyKind, path: &[String]) -> String {
    use fleetreach_core::DependencyKind;
    if matches!(kind, DependencyKind::Direct) {
        return " (direct)".to_string();
    }
    // Intermediates strictly between the root and the flagged package.
    if path.len() < 3 {
        return " (transitive)".to_string();
    }
    // Path segments are package names from Cargo.lock (untrusted).
    let mids: Vec<String> = path[1..path.len() - 1]
        .iter()
        .map(|s| sanitize_cell(s))
        .collect();
    if mids.len() <= 3 {
        format!(" (via {})", mids.join(" → "))
    } else {
        format!(" (via {} → … → {})", mids[0], mids[mids.len() - 1])
    }
}

/// The title, with a second line naming the specific functions the advisory
/// scopes itself to (short names) — so you can see at a glance whether to care.
fn title_with_functions(v: &VulnFinding) -> String {
    let mut out = truncate(&sanitize_cell(&v.title), 48);
    if !v.affected_functions.is_empty() {
        let names: Vec<String> = v
            .affected_functions
            .iter()
            .map(|p| sanitize_cell(p.rsplit("::").next().unwrap_or(p.as_str())))
            .collect();
        let shown = if names.len() > 3 {
            format!("{}, +{}", names[..3].join(", "), names.len() - 3)
        } else {
            names.join(", ")
        };
        out.push_str(&format!("\naffects fn: {shown}"));
    }
    out
}

fn risk_cell(exploit: &Exploitability, color: bool) -> Cell {
    let mut parts = Vec::new();
    if exploit.kev {
        parts.push("KEV".to_string());
    }
    if let Some(epss) = exploit.epss {
        parts.push(format!("epss {:.0}%", epss * 100.0));
    }
    let cell = Cell::new(parts.join(" "));
    // KEV (actively exploited) is the loudest signal.
    if color && exploit.kev {
        cell.fg(Color::Red)
    } else {
        cell
    }
}

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::DarkRed,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Cyan,
        Severity::Unknown => Color::Grey,
    }
}

fn locations(occurrences: &[Occurrence]) -> String {
    occurrences
        .iter()
        .map(|o| match o {
            Occurrence::InRepo {
                repo,
                package,
                installed,
                patched,
                dependency_kind,
                dependency_path,
                active,
                ..
            } => {
                // The upgrade target — the lower bound of the patched range —
                // shows exactly what to bump to (`cargo update -p pkg --precise T`).
                let upgrade = fix_target(patched)
                    .map(|t| format!(" → {t}"))
                    .unwrap_or_default();
                // `--resolve-features` flags packages that are in Cargo.lock but
                // never compiled (off-by-default optional deps).
                let phantom = if *active == Some(false) {
                    " ⚠ not in default build"
                } else {
                    ""
                };
                // repo id and package name are untrusted (fleet.toml / Cargo.lock).
                format!(
                    "{}/{}@{installed}{upgrade}{}{phantom}",
                    sanitize_cell(&repo.0),
                    sanitize_cell(package),
                    dependency_hint(*dependency_kind, dependency_path)
                )
            }
            Occurrence::Toolchain {
                channel, installed, ..
            } => format!(
                "toolchain[{}]@{}",
                sanitize_cell(channel),
                installed
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "?".to_string())
            ),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The upgrade target for a finding: the lower bound of the first patched
/// requirement (e.g. `>=1.2.3` → `1.2.3`). `None` when no fix is published.
pub(crate) fn fix_target(patched: &[fleetreach_core::semver::VersionReq]) -> Option<String> {
    use fleetreach_core::semver::Op;
    let req = patched.first()?;
    req.comparators.iter().find_map(|c| match c.op {
        Op::GreaterEq | Op::Greater | Op::Caret | Op::Tilde | Op::Exact => Some(format!(
            "{}.{}.{}",
            c.major,
            c.minor.unwrap_or(0),
            c.patch.unwrap_or(0)
        )),
        _ => None,
    })
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Unknown => "unknown",
    }
}

/// The severity label with the CVSS base score appended when known, e.g.
/// `high 7.5`. Falls back to the bare label for advisories that carry no CVSS.
fn severity_cell_text(v: &VulnFinding) -> String {
    match v.cvss_score {
        Some(score) => format!("{} {score:.1}", severity_label(v.severity)),
        None => severity_label(v.severity).to_string(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Neutralize terminal control sequences in an untrusted single-line string
/// (package/advisory/repo ids, titles, dependency-path segments). Every control
/// char — ESC/CSI/OSC (`0x1b`), BEL, CR, backspace, C1, DEL, and even newline/tab
/// — is replaced with U+FFFD so attacker-controlled advisory titles or crate names
/// cannot move the cursor, erase rows, or recolor the table to misrepresent fleet
/// risk. The common (clean) string is returned untouched. Machine outputs
/// (JSON/SARIF/VEX) are serde-escaped and do not use this.
pub fn sanitize_cell(s: &str) -> String {
    if !s.chars().any(char::is_control) {
        return s.to_string();
    }
    s.chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

/// Like [`sanitize_cell`] but for untrusted multi-line text (the `--explain`
/// advisory description): newlines and tabs are preserved so the markdown still
/// reads, while every other control char — notably ESC — is neutralized.
pub fn sanitize_text(s: &str) -> String {
    if !s.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return s.to_string();
    }
    s.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '\u{fffd}'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod sanitize_tests {
    use super::{sanitize_cell, sanitize_text};

    #[test]
    fn sanitize_cell_neutralizes_control_and_keeps_clean() {
        assert_eq!(sanitize_cell("regex 1.2.3"), "regex 1.2.3"); // clean passthrough
                                                                 // ESC, BEL, CR, newline, tab all become U+FFFD in a single-line cell.
        assert_eq!(sanitize_cell("a\x1b[2Kb"), "a\u{fffd}[2Kb");
        assert_eq!(sanitize_cell("a\nb\tc\rd"), "a\u{fffd}b\u{fffd}c\u{fffd}d");
        assert!(!sanitize_cell("evil\x07").contains('\x07'));
    }

    #[test]
    fn sanitize_text_keeps_newlines_but_kills_esc() {
        // Multi-line markdown: newlines/tabs survive, ESC does not.
        assert_eq!(sanitize_text("line1\nline2\tx"), "line1\nline2\tx");
        assert_eq!(sanitize_text("a\x1bb"), "a\u{fffd}b");
        assert!(!sanitize_text("x\x1b]0;title\x07").contains('\x1b'));
    }
}
