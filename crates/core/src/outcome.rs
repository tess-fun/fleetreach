use serde::{Deserialize, Serialize};

use crate::RepoId;

/// Per-repo scan status. A repo we could not read is `Errored` and the run
/// continues — but it forces a non-clean exit (§8): you cannot assert
/// "fleet-clean" over a repo you never read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoOutcome {
    pub repo: RepoId,
    #[serde(flatten)]
    pub status: ScanStatus,
}

/// Serializes with a `status` tag and the variant fields inlined, e.g.
/// `{ "repo": "core-lib", "status": "scanned", "vulns": 2, "warnings": 1 }`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ScanStatus {
    Scanned { vulns: usize, warnings: usize },
    Errored { reason: String },
}
