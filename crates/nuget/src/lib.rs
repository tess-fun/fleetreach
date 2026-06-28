//! NuGet (.NET) ecosystem feeder for fleetreach: a **toolchain-free** Tier-C matcher that
//! turns a repo's `packages.lock.json` plus an offline OSV vulnerability DB into the shared
//! `VulnFinding` model, so the existing correlate / report / remediation pipeline works on
//! NuGet packages unchanged.
//!
//! Like the npm/PyPI/RubyGems/Packagist feeders it needs no build: `packages.lock.json`
//! already pins the full transitive tree to exact versions and records whether each package
//! is a direct or transitive dependency. It reads the lockfile and compares versions against
//! OSV `ECOSYSTEM` ranges, running no .NET tool and no package build, so it is **safe by
//! construction**: no untrusted-build consent and no sandbox.
//!
//! One thing is NuGet-specific. A NuGet version is SemVer 2.0 with a **four-component**
//! numeric core (`Major.Minor.Patch.Revision`, e.g. `1.1.1.1`) and **case-insensitive**
//! prerelease labels; trailing zeros and `+build` metadata are insignificant. The stock
//! three-component `semver` crate cannot represent that, so matching uses a faithful
//! `NuGetVersion` comparator (the false-clean-critical part) via the shared
//! `fleetreach_core::osv` skeleton; the stored finding keeps a SemVer rendering for the shared
//! model. Package ids are case-insensitive, matched lowercased.
//!
//! Consistent with the feeder contract, every finding is package-level `Unknown` reachability
//! (engine `fleetreach-tier-c`) and **never** `NotReachable`. Severity is carried where the
//! record has it — the GHSA band, or a band + base score derived from a CVSS_V3 vector — and
//! otherwise left `Unknown` for `--enrich` to backfill via CVE aliases.
//!
//! ```no_run
//! use fleetreach_nuget::{nuget_db_path, NuGetDb, scan_offline};
//! use fleetreach_core::RepoId;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Load the OSV mirror once (the osv.dev `NuGet/all.zip` directly, or an unzipped
//! // directory), then scan each repo against it.
//! let root = nuget_db_path("file:///opt/nuget/all.zip").expect("a file:// mirror");
//! let db = NuGetDb::load(&root)?;
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

pub use db::{nuget_db_path, Advisory, NuGetDb};
pub use error::{DbError, NuGetError};
/// The OSV version-match outcome, shared with the other ecosystem feeders.
pub use fleetreach_core::osv::Match;
pub use lockfile::{installed_packages, InstalledPackage};
pub use scan::scan_offline;
pub use version::{parse_nuget_version, to_semver, Version};
