use std::path::PathBuf;

use thiserror::Error;

/// Why a manifest or a file under the offline OSV DB could not be used (shared across feeders).
pub use fleetreach_core::osv::DbError;

/// Errors from the toolchain-free NuGet matcher: reading a `packages.lock.json` or a file
/// under the offline OSV DB mirror.
///
/// Like the other feeders, a present-but-broken input fails **closed** — an unreadable or
/// invalid lockfile, or a corrupt advisory record, is an honest gap, never a false-clean
/// scan. The underlying I/O or parse cause is preserved via
/// [`source`](std::error::Error::source).
///
/// `#[non_exhaustive]`: new variants may be added in a minor release, so match with a
/// wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NuGetError {
    /// A `packages.lock.json`, or a file under the offline OSV DB at `path`, could not be
    /// read or parsed. The underlying I/O or parse error is the
    /// [`source`](std::error::Error::source).
    #[error("nuget scan {path}: {source}")]
    Db {
        /// The file that could not be read or parsed.
        path: PathBuf,
        /// The underlying read or parse failure.
        #[source]
        source: DbError,
    },
}

impl NuGetError {
    /// Build a [`NuGetError::Db`] from a path and any [`DbError`] source.
    pub(crate) fn db(path: impl Into<PathBuf>, source: impl Into<DbError>) -> Self {
        NuGetError::Db {
            path: path.into(),
            source: source.into(),
        }
    }
}
