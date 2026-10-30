use serde::{Deserialize, Serialize};

use crate::{Ecosystem, RepoId, RepoOutcome, Severity, VulnFinding, WarnFinding};

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
    /// Sources that were read but not as a full resolved dependency graph (spec 00, C1).
    /// A repo listed here is still `scanned`; its findings are real, but packages outside
    /// what was read were never matched. Empty (and omitted) when everything was full.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage: Vec<CoverageGap>,
}

/// Where a repo discovered by a fleet source (spec 06) was checked out from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoSource {
    pub repo: RepoId,
    pub url: String,
    pub commit: String,
}

/// How much of a source's dependency graph a scan could see (spec 00, C1).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum Coverage {
    /// The resolved transitive closure with exact versions (a lockfile).
    #[default]
    Full,
    /// Declared (direct) dependencies only, e.g. a `pom.xml` without a resolved graph.
    DirectOnly,
    /// Some of the graph could not be read; `reason` names what.
    Partial,
}

impl Coverage {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Coverage::Full => "full",
            Coverage::DirectOnly => "direct-only",
            Coverage::Partial => "partial",
        }
    }
}

/// One source whose coverage was less than [`Coverage::Full`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageGap {
    pub repo: RepoId,
    /// The source file, relative to the repo root.
    pub source: String,
    pub ecosystem: Ecosystem,
    pub level: Coverage,
    pub reason: String,
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
    /// The osv.dev exports the toolchain-free feeders matched against, one per ecosystem
    /// used. Empty (and omitted) for a Rust/Go-only run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub osv: Vec<OsvProvenance>,
    /// Repos discovered by fleet sources (spec 06): where each was cloned from and the
    /// commit scanned, so the report is reproducible. Empty (and omitted) without sources.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<RepoSource>,
}

/// Where one ecosystem's OSV export came from and how old it was, so a clean verdict
/// shows the data it rested on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvProvenance {
    /// The osv.dev ecosystem name (`npm`, `PyPI`, ...).
    pub ecosystem: String,
    /// `flag`, `dir` or `cache`.
    pub source: String,
    pub path: String,
    /// The upstream `Last-Modified` recorded at download; `null` when unknown.
    pub upstream_modified: Option<String>,
    /// RFC3339 time of the last successful sync; `null` for exports fleetreach did not fetch.
    pub fetched_at: Option<String>,
    pub sha256: Option<String>,
    /// What the age is measured from: `upstream`, `mtime` or `unknown`.
    pub age_basis: String,
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
