//! npm ecosystem feeder for fleetreach: a **toolchain-free** Tier-C matcher that turns
//! a repo's `package-lock.json` plus an offline OSV vulnerability DB into the shared
//! `VulnFinding` model, so the existing correlate / report / remediation pipeline works
//! on npm packages unchanged.
//!
//! Unlike the Go feeder — where `govulncheck` is the primary, build-based engine and
//! the offline matcher is a fallback — npm needs no build at all: the lockfile already
//! pins the full transitive tree to exact versions, so the matcher is the *only* tier.
//! It parses the lockfile and compares versions against OSV SEMVER ranges, running no
//! `npm` and no package install scripts, so it is **safe by construction**: no
//! untrusted-build consent and no sandbox, the same positioning win the Go Tier-C has.
//!
//! Consistent with the feeder contract, every finding is package-level `Unknown`
//! reachability (engine `fleetreach-tier-c`) and **never** `NotReachable` — there is no
//! call-graph evidence, only a version match. Severity *is* carried, mapped from the
//! GitHub Advisory Database band in the OSV record, so npm findings rank and gate like
//! Rust ones rather than collapsing to `unknown`.
//!
//! ```no_run
//! use fleetreach_npm::{npm_db_path, NpmDb, scan_offline};
//! use fleetreach_core::RepoId;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Load the OSV mirror once (the osv.dev `all.zip` directly, or an unzipped
//! // directory), then scan each repo against it.
//! let root = npm_db_path("file:///opt/npm/all.zip").expect("a file:// mirror");
//! let db = NpmDb::load(&root)?;
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

pub use db::{npm_db_path, Advisory, NpmDb};
pub use error::{DbError, NpmError};
/// The OSV version-match outcome, shared with the other ecosystem feeders.
pub use fleetreach_core::osv::Match;
pub use lockfile::{installed_packages, InstalledPackage};
pub use scan::{parse_npm_version, scan_offline};
