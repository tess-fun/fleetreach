//! Julia ecosystem feeder for fleetreach: a **toolchain-free** Tier-C matcher that turns a
//! repo's `Manifest.toml` plus an offline OSV vulnerability DB into the shared `VulnFinding`
//! model, so the existing correlate / report / remediation pipeline works on Julia packages
//! unchanged.
//!
//! Like the other Tier-C feeders it needs no build: `Manifest.toml` already pins the full
//! dependency tree to exact versions. It reads the manifest and compares versions against OSV
//! `SEMVER` ranges, running no Julia tool and no package build, so it is **safe by
//! construction**: no untrusted-build consent and no sandbox.
//!
//! One thing is Julia-specific. Julia's `VersionNumber` looks like SemVer but, unlike strict
//! SemVer, **build metadata is significant for ordering**: Julia's binary `_jll` packages
//! carry a build counter (`8.15.0+0`, `8.15.0+1`) and the advisory ranges key on it (most
//! Julia bounds carry a `+build`), so matching uses a faithful `VersionNumber` comparator (the
//! false-clean-critical part) via the shared `fleetreach_core::osv` skeleton; the stored
//! finding keeps a SemVer rendering for the shared model. Package names are case-sensitive,
//! matched verbatim.
//!
//! `Manifest.toml` does not record which dependencies are direct, so the sibling
//! `Project.toml`'s `[deps]` keys mark the direct/transitive split when present.
//!
//! Consistent with the feeder contract, every finding is package-level `Unknown` reachability
//! (engine `fleetreach-tier-c`) and **never** `NotReachable`. Severity is carried where the
//! record has it — the GHSA band, or a band + base score derived from a CVSS_V3 vector — and
//! otherwise left `Unknown` for `--enrich` to backfill via CVE aliases.
//!
//! ```no_run
//! use fleetreach_julia::{julia_db_path, JuliaDb, scan_offline};
//! use fleetreach_core::RepoId;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let root = julia_db_path("file:///opt/julia/all.zip").expect("a file:// mirror");
//! let db = JuliaDb::load(&root)?;
//! let findings = scan_offline(Path::new("/srv/app"), &db, &RepoId("app".into()))?;
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
mod lockfile;
mod scan;
mod version;

pub use db::{julia_db_path, Advisory, JuliaDb};
pub use error::{DbError, JuliaError};
/// The OSV version-match outcome, shared with the other ecosystem feeders.
pub use fleetreach_core::osv::Match;
pub use lockfile::{installed_packages, InstalledPackage};
pub use scan::scan_offline;
pub use version::{parse_julia_version, to_semver, Version};
