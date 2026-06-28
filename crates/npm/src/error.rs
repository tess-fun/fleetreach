use std::path::PathBuf;

use thiserror::Error;

/// Why a `package-lock.json` or a file under the offline OSV DB could not be used (shared
/// across feeders).
pub use fleetreach_core::osv::DbError;

/// Errors from the toolchain-free npm matcher: reading a `package-lock.json` or a
/// file under the offline OSV DB mirror.
///
/// Like the Go feeder, a present-but-broken input fails **closed** — an unreadable
/// lockfile or a corrupt advisory file is an honest gap, never a false-clean scan.
/// The underlying I/O or JSON cause is preserved via
/// [`source`](std::error::Error::source) so callers can walk the chain.
///
/// `#[non_exhaustive]`: new variants may be added in a minor release, so match with a
/// wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NpmError {
    /// A `package-lock.json` or a file under the offline OSV DB at `path` could not be
    /// read or parsed. The underlying I/O or JSON error is the
    /// [`source`](std::error::Error::source).
    #[error("npm scan {path}: {source}")]
    Db {
        /// The file that could not be read or parsed.
        path: PathBuf,
        /// The underlying read or parse failure.
        #[source]
        source: DbError,
    },
}

impl NpmError {
    /// Build a [`NpmError::Db`] from a path and any [`DbError`] source (an I/O or JSON
    /// error, both of which `into()` into [`DbError`]).
    pub(crate) fn db(path: impl Into<PathBuf>, source: impl Into<DbError>) -> Self {
        NpmError::Db {
            path: path.into(),
            source: source.into(),
        }
    }
}
