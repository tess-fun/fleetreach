//! PyPI ecosystem feeder for fleetreach: a **toolchain-free** Tier-C matcher that turns
//! a repo's Python lockfile plus an offline OSV vulnerability DB into the shared
//! `VulnFinding` model, so the existing correlate / report / remediation pipeline works
//! on Python packages unchanged.
//!
//! Like the npm feeder it needs no build: a lockfile already pins the full transitive
//! tree to exact versions, so the matcher is the only tier. It reads `uv.lock`,
//! `poetry.lock`, or `Pipfile.lock` (in that detection order) and compares versions
//! against OSV `ECOSYSTEM` ranges, running no Python tool and no package build, so it is
//! **safe by construction**: no untrusted-build consent and no sandbox.
//!
//! Two things are Python-specific. Versions are [PEP 440] (epochs, `.post`/`.dev`,
//! `a1`/`rc1`, local segments), not SemVer, so matching uses the `pep440_rs` crate via
//! the shared `fleetreach_core::osv` skeleton; the stored finding keeps a SemVer
//! rendering (a best-effort coercion) for the shared model. Names are matched after
//! [PEP 503] normalization so `Flask`/`flask` and `ruamel.yaml`/`ruamel-yaml` resolve to
//! the same advisory.
//!
//! Consistent with the feeder contract, every finding is package-level `Unknown`
//! reachability (engine `fleetreach-tier-c`) and **never** `NotReachable`. Severity is
//! carried where the record has it — the GHSA band, or a band + base score derived from a
//! CVSS_V3 vector — and otherwise left `Unknown` for `--enrich` to backfill via CVE
//! aliases.
//!
//! ```no_run
//! use fleetreach_pypi::{pypi_db_path, PyPiDb, scan_offline};
//! use fleetreach_core::RepoId;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Load the OSV mirror once (the osv.dev `PyPI/all.zip` directly, or an unzipped
//! // directory), then scan each repo against it.
//! let root = pypi_db_path("file:///opt/pypi/all.zip").expect("a file:// mirror");
//! let db = PyPiDb::load(&root)?;
//! let findings = scan_offline(Path::new("/srv/app"), &db, &RepoId("app".into()))?;
//! # let _ = findings;
//! # Ok(())
//! # }
//! ```
//!
//! [PEP 440]: https://peps.python.org/pep-0440/
//! [PEP 503]: https://peps.python.org/pep-0503/#normalized-names
//!
//! # Minimum supported Rust version
//!
//! 1.89. An MSRV increase is treated as a minor-version bump.

mod db;
mod error;
mod lockfile;
mod scan;
mod version;

pub use db::{pypi_db_path, Advisory, PyPiDb};
pub use error::{DbError, PyPiError};
/// The OSV version-match outcome, shared with the other ecosystem feeders.
pub use fleetreach_core::osv::Match;
pub use lockfile::{detect, installed_packages, InstalledPackage, LockfileKind};
pub use scan::scan_offline;
pub use version::{normalize_name, parse_pypi_version, to_semver, Version};
