//! RubyGems ecosystem feeder for fleetreach: a **toolchain-free** Tier-C matcher that turns
//! a repo's `Gemfile.lock` plus an offline OSV vulnerability DB into the shared
//! `VulnFinding` model, so the existing correlate / report / remediation pipeline works on
//! Ruby gems unchanged.
//!
//! Like the npm and PyPI feeders it needs no build: `Gemfile.lock` already pins the full
//! transitive tree to exact versions, so the matcher is the only tier. It reads the lockfile
//! and compares versions against OSV `ECOSYSTEM` ranges, running no Ruby tool and no gem
//! build, so it is **safe by construction**: no untrusted-build consent and no sandbox.
//!
//! Two things are Ruby-specific. Versions are [`Gem::Version`](https://docs.ruby-lang.org/en/master/Gem/Version.html), **not** SemVer: any segment
//! with a letter is a prerelease (`1.0.0.beta`), segments are arbitrary-length and split
//! alphanumerically, and a string segment sorts below a numeric one — so matching uses a
//! faithful `Gem::Version` comparator (the false-clean-critical part) via the shared
//! `fleetreach_core::osv` skeleton; the stored finding keeps a SemVer rendering (a
//! best-effort coercion) for the shared model. Names are matched **verbatim** — RubyGems
//! names are case-sensitive and not normalized, unlike PyPI.
//!
//! Only gems under a `GEM` section whose `remote:` is rubygems.org are matchable; `GIT`/
//! `PATH` sources and private registries have no OSV `RubyGems` advisory and are skipped.
//!
//! Consistent with the feeder contract, every finding is package-level `Unknown`
//! reachability (engine `fleetreach-tier-c`) and **never** `NotReachable`. Severity is
//! carried where the record has it — the GHSA band, or a band + base score derived from a
//! CVSS_V3 vector — and otherwise left `Unknown` for `--enrich` to backfill via CVE aliases.
//!
//! ```no_run
//! use fleetreach_rubygems::{rubygems_db_path, RubyGemsDb, scan_offline};
//! use fleetreach_core::RepoId;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Load the OSV mirror once (the osv.dev `RubyGems/all.zip` directly, or an unzipped
//! // directory), then scan each repo against it.
//! let root = rubygems_db_path("file:///opt/rubygems/all.zip").expect("a file:// mirror");
//! let db = RubyGemsDb::load(&root)?;
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

pub use db::{rubygems_db_path, Advisory, RubyGemsDb};
pub use error::{DbError, RubyGemsError};
/// The OSV version-match outcome, shared with the other ecosystem feeders.
pub use fleetreach_core::osv::Match;
pub use lockfile::{installed_gems, InstalledGem};
pub use scan::scan_offline;
pub use version::{parse_rubygems_version, to_semver, Version};
