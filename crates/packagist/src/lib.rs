//! Packagist (Composer/PHP) ecosystem feeder for fleetreach: a **toolchain-free** Tier-C
//! matcher that turns a repo's `composer.lock` plus an offline OSV vulnerability DB into the
//! shared `VulnFinding` model, so the existing correlate / report / remediation pipeline
//! works on Composer packages unchanged.
//!
//! Like the npm, PyPI, and RubyGems feeders it needs no build: `composer.lock` already pins
//! the full transitive tree to exact versions, so the matcher is the only tier. It reads the
//! lockfile and compares versions against OSV `ECOSYSTEM` ranges, running no PHP tool and no
//! package build, so it is **safe by construction**: no untrusted-build consent and no
//! sandbox.
//!
//! One thing is Composer-specific. Versions are compared with PHP's `version_compare`
//! semantics, **not** SemVer: the stability ladder is `dev < alpha < beta < RC < <stable> <
//! patch`, so `alpha`/`beta`/`RC` prereleases sort below their release (as in SemVer) but a
//! `patch` level (`2.4.5-p1`, Magento's scheme) sorts **above** it — the opposite of SemVer.
//! Matching therefore uses a faithful Composer comparator (the false-clean-critical part)
//! via the shared `fleetreach_core::osv` skeleton; the stored finding keeps a SemVer
//! rendering (a best-effort coercion) for the shared model. Package names are Composer's
//! case-insensitive `vendor/name`, matched lowercased.
//!
//! Only `Packagist` (the public Composer registry) advisories are matched; the namespaced
//! `Packagist:https://packages.drupal.org/8` feed (Drupal contrib, on Drupal's own `8.x-N.M`
//! version scheme) is out of scope. `composer.lock` does not record which dependencies are
//! direct, so the sibling `composer.json`'s `require`/`require-dev` keys mark the
//! direct/transitive split when present.
//!
//! Consistent with the feeder contract, every finding is package-level `Unknown`
//! reachability (engine `fleetreach-tier-c`) and **never** `NotReachable`. Severity is
//! carried where the record has it — the GHSA band, or a band + base score derived from a
//! CVSS_V3 vector — and otherwise left `Unknown` for `--enrich` to backfill via CVE aliases.
//!
//! ```no_run
//! use fleetreach_packagist::{packagist_db_path, PackagistDb, scan_offline};
//! use fleetreach_core::RepoId;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Load the OSV mirror once (the osv.dev `Packagist/all.zip` directly, or an unzipped
//! // directory), then scan each repo against it.
//! let root = packagist_db_path("file:///opt/packagist/all.zip").expect("a file:// mirror");
//! let db = PackagistDb::load(&root)?;
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

pub use db::{packagist_db_path, Advisory, PackagistDb};
pub use error::{DbError, PackagistError};
/// The OSV version-match outcome, shared with the other ecosystem feeders.
pub use fleetreach_core::osv::Match;
pub use lockfile::{installed_packages, InstalledPackage};
pub use scan::scan_offline;
pub use version::{parse_composer_version, to_semver, Version};
