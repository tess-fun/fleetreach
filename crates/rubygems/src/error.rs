use std::path::PathBuf;

use thiserror::Error;

/// Why a `Gemfile.lock` or a file under the offline OSV DB could not be used (shared across feeders).
pub use fleetreach_core::osv::DbError;

/// Errors from the toolchain-free RubyGems matcher: reading a `Gemfile.lock` or a file
/// under the offline OSV DB mirror.
///
/// Like the Go, npm, and PyPI feeders, a present-but-broken input fails **closed** — an
/// unreadable lockfile, or a corrupt advisory record, is an honest gap, never a
/// false-clean scan. The underlying I/O or parse cause is preserved via
/// [`source`](std::error::Error::source) so callers can walk the chain.
///
/// `#[non_exhaustive]`: new variants may be added in a minor release, so match with a
/// wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RubyGemsError {
    /// A `Gemfile.lock` or a file under the offline OSV DB at `path` could not be read or
    /// parsed. The underlying I/O or parse error is the
    /// [`source`](std::error::Error::source).
    #[error("rubygems scan {path}: {source}")]
    Db {
        /// The file that could not be read or parsed.
        path: PathBuf,
        /// The underlying read or parse failure.
        #[source]
        source: DbError,
    },
}

impl RubyGemsError {
    /// Build a [`RubyGemsError::Db`] from a path and any [`DbError`] source (an I/O, JSON,
    /// or zip error, all of which `into()` into [`DbError`]).
    pub(crate) fn db(path: impl Into<PathBuf>, source: impl Into<DbError>) -> Self {
        RubyGemsError::Db {
            path: path.into(),
            source: source.into(),
        }
    }
}
