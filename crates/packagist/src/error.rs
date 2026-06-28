use std::path::PathBuf;

use thiserror::Error;

/// Why a manifest or a file under the offline OSV DB could not be used (shared across feeders).
pub use fleetreach_core::osv::DbError;

/// Errors from the toolchain-free Packagist matcher: reading a `composer.lock` (or its
/// `composer.json` sibling) or a file under the offline OSV DB mirror.
///
/// Like the Go, npm, PyPI, and RubyGems feeders, a present-but-broken input fails
/// **closed** — an unreadable/invalid lockfile, or a corrupt advisory record, is an honest
/// gap, never a false-clean scan. The underlying I/O or parse cause is preserved via
/// [`source`](std::error::Error::source) so callers can walk the chain.
///
/// `#[non_exhaustive]`: new variants may be added in a minor release, so match with a
/// wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PackagistError {
    /// A `composer.lock`, or a file under the offline OSV DB at `path`, could not be read
    /// or parsed. The underlying I/O or parse error is the
    /// [`source`](std::error::Error::source).
    #[error("packagist scan {path}: {source}")]
    Db {
        /// The file that could not be read or parsed.
        path: PathBuf,
        /// The underlying read or parse failure.
        #[source]
        source: DbError,
    },
}

impl PackagistError {
    /// Build a [`PackagistError::Db`] from a path and any [`DbError`] source (an I/O, JSON,
    /// or zip error, all of which `into()` into [`DbError`]).
    pub(crate) fn db(path: impl Into<PathBuf>, source: impl Into<DbError>) -> Self {
        PackagistError::Db {
            path: path.into(),
            source: source.into(),
        }
    }
}
