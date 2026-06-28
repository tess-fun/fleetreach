//! Swift ecosystem feeder for fleetreach: a **toolchain-free** Tier-C matcher that turns a
//! repo's `Package.resolved` plus an offline OSV vulnerability DB into the shared
//! `VulnFinding` model, so the existing correlate / report / remediation pipeline works on
//! Swift packages unchanged.
//!
//! Like the other Tier-C feeders it needs no build: `Package.resolved` already pins the full
//! dependency graph to exact versions. It reads the lockfile and compares versions against OSV
//! `SEMVER` ranges, running no Swift tool and no package build, so it is **safe by
//! construction**: no untrusted-build consent and no sandbox.
//!
//! Swift versions are plain SemVer, so this reuses the shared SemVer comparator (no bespoke
//! version logic, like npm). The Swift-specific part is **package identity**: a Swift package
//! is named by its **source URL**, and the OSV `SwiftURL` ecosystem keys advisories on a
//! normalized form (`github.com/apple/swift-nio`). `Package.resolved` records the full clone
//! URL, so both sides are run through [`normalize_package_url`] (strip scheme/`git@`/`.git`/
//! trailing slash, lowercase) before matching.
//!
//! `Package.resolved` does not record which dependencies are direct, so the sibling
//! `Package.swift`'s `.package(url:)` declarations mark the direct/transitive split when
//! present.
//!
//! Consistent with the feeder contract, every finding is package-level `Unknown` reachability
//! (engine `fleetreach-tier-c`) and **never** `NotReachable`. Severity is carried where the
//! record has it — the GHSA band, or a band + base score derived from a CVSS_V3 vector — and
//! otherwise left `Unknown` for `--enrich` to backfill via CVE aliases.
//!
//! ```no_run
//! use fleetreach_swift::{swift_db_path, SwiftDb, scan_offline};
//! use fleetreach_core::RepoId;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let root = swift_db_path("file:///opt/swift/all.zip").expect("a file:// mirror");
//! let db = SwiftDb::load(&root)?;
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

pub use db::{swift_db_path, Advisory, SwiftDb};
pub use error::{DbError, SwiftError};
/// The OSV version-match outcome, shared with the other ecosystem feeders.
pub use fleetreach_core::osv::Match;
pub use lockfile::{installed_packages, normalize_package_url, InstalledPackage};
pub use scan::{parse_swift_version, scan_offline};
