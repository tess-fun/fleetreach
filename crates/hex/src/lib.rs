//! Hex (Elixir/Erlang) ecosystem feeder for fleetreach: a **toolchain-free** Tier-C matcher
//! that turns a repo's `mix.lock` plus an offline OSV vulnerability DB into the shared
//! `VulnFinding` model, so the existing correlate / report / remediation pipeline works on Hex
//! packages unchanged.
//!
//! Like the other Tier-C feeders it needs no build: `mix.lock` already pins every dependency
//! to an exact version. It reads the lockfile and compares versions against OSV `SEMVER`
//! ranges, running no Elixir tool and no package build, so it is **safe by construction**: no
//! untrusted-build consent and no sandbox.
//!
//! Hex versions are plain SemVer, so this reuses the shared SemVer comparator (no bespoke
//! version logic, like npm). The Hex-specific part is the lockfile: `mix.lock` is an Elixir
//! map literal (not JSON/TOML), so a small hand-rolled scan reads the `{:hex, :name, "version",
//! …}` tuples; `{:git, …}`/`{:path, …}` dependencies have no Hex release and are skipped.
//! Package names are lowercase, matched verbatim. `mix.lock` does not record which
//! dependencies are direct (that lives in `mix.exs`), so every package is reported transitive.
//!
//! Consistent with the feeder contract, every finding is package-level `Unknown` reachability
//! (engine `fleetreach-tier-c`) and **never** `NotReachable`. Severity is carried where the
//! record has it — the GHSA band, or a band + base score derived from a CVSS_V3 vector — and
//! otherwise left `Unknown` for `--enrich` to backfill via CVE aliases.
//!
//! ```no_run
//! use fleetreach_hex::{hex_db_path, HexDb, scan_offline};
//! use fleetreach_core::RepoId;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let root = hex_db_path("file:///opt/hex/all.zip").expect("a file:// mirror");
//! let db = HexDb::load(&root)?;
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

pub use db::{hex_db_path, Advisory, HexDb};
pub use error::{DbError, HexError};
/// The OSV version-match outcome, shared with the other ecosystem feeders.
pub use fleetreach_core::osv::Match;
pub use lockfile::{installed_packages, InstalledPackage};
pub use scan::{parse_hex_version, scan_offline};
