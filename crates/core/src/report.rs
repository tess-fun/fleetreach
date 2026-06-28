use serde::{Deserialize, Serialize};

use crate::{RepoOutcome, Severity, VulnFinding, WarnFinding};

/// Pinned from day one so machine consumers can branch on the wire format.
/// v2 enrichment is additive and must not bump this.
pub const SCHEMA_VERSION: u32 = 1;

/// The complete result of one `scan`. Field order matches the JSON schema (§9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FleetReport {
    pub schema_version: u32,
    pub provenance: Provenance,
    pub summary: Summary,
    /// Sorted: severity desc, then advisory id (total, stable).
    pub vulnerabilities: Vec<VulnFinding>,
    pub warnings: Vec<WarnFinding>,
    pub outcomes: Vec<RepoOutcome>,
}

/// Everything needed to reproduce a stored report by re-running with the same
/// `--db-rev`. The DB timestamp is the freshness signal (§3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    pub tool_version: String,
    pub rustsec_crate_version: String,
    /// git sha of the advisory-db commit used; `null` when the DB carries no
    /// commit metadata (e.g. a non-git directory) — honest absence, not `""`.
    pub db_commit: Option<String>,
    /// RFC3339 timestamp of that commit; `null` when unknown.
    pub db_timestamp: Option<String>,
    /// Advisories are OS/arch-scoped, so the host matters.
    pub host_os: String,
    pub host_arch: String,
    /// RFC3339.
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub repos_scanned: usize,
    pub repos_errored: usize,
    pub vuln_count: usize,
    pub warn_count: usize,
    pub max_severity: Severity,
    /// Configured ignores that matched nothing this run — dead suppressions
    /// surfaced as a warning so they don't silently mask future regressions.
    pub stale_ignores: Vec<String>,
}

/// The maximum severity across `vulns` (`Unknown` when empty). The single definition
/// of the summary's "max severity", so the initial summary and every stage that later
/// filters findings derive it identically.
pub fn max_severity_of(vulns: &[VulnFinding]) -> Severity {
    vulns
        .iter()
        .map(|v| v.severity)
        .max()
        .unwrap_or(Severity::Unknown)
}

impl FleetReport {
    /// Recompute the summary's finding-derived fields (`vuln_count`, `warn_count`,
    /// `max_severity`) from the current findings.
    ///
    /// The summary is a denormalized cache. Rather than each pipeline stage that
    /// mutates the finding set (phantom drop, enrichment backfill, EPSS / reachability
    /// / baseline filtering) recomputing these inline — six near-identical copies that
    /// drift, as a missed one once reported `max_severity: unknown` for a critical
    /// fleet — every such stage calls this. There is exactly ONE definition of these
    /// values, so a stage cannot get them subtly wrong, and a new stage just calls
    /// `refresh_summary()`. `repos_scanned` / `repos_errored` / `stale_ignores` are set
    /// once at assembly and are not touched here.
    pub fn refresh_summary(&mut self) {
        self.summary.vuln_count = self.vulnerabilities.len();
        self.summary.warn_count = self.warnings.len();
        self.summary.max_severity = max_severity_of(&self.vulnerabilities);
    }
}
