//! GitHub Actions ecosystem feeder for fleetreach: a **toolchain-free** Tier-C matcher that
//! turns a repo's workflow files plus an offline OSV vulnerability DB into the shared
//! `VulnFinding` model, so the existing correlate / report / remediation pipeline works on
//! pinned GitHub Actions unchanged.
//!
//! It reads `.github/workflows/*.yml` (and a root `action.yml`/`action.yaml`), extracts each
//! `uses: owner/repo@ref` reference, and matches the version-tag pins against OSV `ECOSYSTEM`
//! ranges, running nothing — so it is **safe by construction**: no untrusted-build consent
//! and no sandbox.
//!
//! Two things are GitHub-Actions-specific. Identity is `owner/repo[/subpath]` (case-
//! insensitive, matched lowercased). And the `@ref` is a git tag, branch, or commit SHA:
//! only a **version tag** (`v4`, `4.1.1`) can be matched against the semantic ranges — a
//! partial tag is padded (`v4` → `4.0.0`, the way the OSV ranges treat it) — while a branch
//! (`@main`) or a commit SHA has no semantic version and is skipped (an honest gap, since
//! resolving a SHA to its release would need the network).
//!
//! Consistent with the feeder contract, every finding is package-level `Unknown` reachability
//! (engine `fleetreach-tier-c`) and **never** `NotReachable`. Severity is carried where the
//! record has it — the GHSA band, or a band + base score derived from a CVSS_V3 vector — and
//! otherwise left `Unknown` for `--enrich` to backfill via CVE aliases.
//!
//! ```no_run
//! use fleetreach_ghactions::{ghactions_db_path, GhActionsDb, scan_offline};
//! use fleetreach_core::RepoId;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let root = ghactions_db_path("file:///opt/gha/all.zip").expect("a file:// mirror");
//! let db = GhActionsDb::load(&root)?;
//! let findings = scan_offline(Path::new("/srv/repo"), &db, &RepoId("repo".into()))?;
//! # let _ = findings;
//! # Ok(())
//! # }
//! ```
//!
//! # Minimum supported Rust version
//!
//! 1.89. An MSRV increase is treated as a minor-version bump.

mod db;
mod error;
mod scan;
mod workflow;

pub use db::{ghactions_db_path, Advisory, GhActionsDb};
pub use error::{DbError, GhaError};
/// The OSV version-match outcome, shared with the other ecosystem feeders.
pub use fleetreach_core::osv::Match;
pub use scan::scan_offline;
pub use workflow::{parse_gha_version, used_actions, UsedAction};
