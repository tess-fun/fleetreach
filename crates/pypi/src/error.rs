use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Errors from the toolchain-free PyPI matcher: reading a Python lockfile
/// (`poetry.lock` / `uv.lock` / `Pipfile.lock`) or a file under the offline OSV DB
/// mirror.
///
/// Like the Go and npm feeders, a present-but-broken input fails **closed** — an
/// unreadable or malformed lockfile, or a corrupt advisory record, is an honest gap,
/// never a false-clean scan. The underlying I/O or parse cause is preserved via
/// [`source`](std::error::Error::source) so callers can walk the chain.
///
/// `#[non_exhaustive]`: new variants may be added in a minor release, so match with a
/// wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PyPiError {
    /// A lockfile or a file under the offline OSV DB at `path` could not be read or
    /// parsed. The underlying I/O or parse error is the
    /// [`source`](std::error::Error::source).
    #[error("pypi scan {path}: {source}")]
    Db {
        /// The file that could not be read or parsed.
        path: PathBuf,
        /// The underlying read or parse failure.
        #[source]
        source: DbError,
    },
}

impl PyPiError {
    /// Build a [`PyPiError::Db`] from a path and any [`DbError`] source (an I/O, JSON,
    /// or TOML error, all of which `into()` into [`DbError`]).
    pub(crate) fn db(path: impl Into<PathBuf>, source: impl Into<DbError>) -> Self {
        PyPiError::Db {
            path: path.into(),
            source: source.into(),
        }
    }
}

/// Why a lockfile or a file under the offline OSV DB could not be used.
///
/// Unlike the range-only feeders that re-export `osv::DbError`, PyPI keeps its own
/// `DbError` because its lockfiles are TOML (`poetry.lock`, `uv.lock`) — a variant the
/// shared error does not carry. The shared loader's `osv::DbError` folds into this one via
/// the `From` impl below, so `PyPiDb::load` can wrap it verbatim.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DbError {
    /// The file could not be read.
    #[error("read failed: {0}")]
    Read(#[from] io::Error),
    /// The file was not valid JSON (`Pipfile.lock`, OSV records).
    #[error("invalid JSON: {0}")]
    Parse(#[from] serde_json::Error),
    /// The file was not valid TOML (`poetry.lock`, `uv.lock`).
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    /// The OSV mirror `.zip` could not be opened or decompressed.
    #[error("invalid zip archive: {0}")]
    Archive(String),
}

impl From<fleetreach_core::osv::DbError> for DbError {
    fn from(e: fleetreach_core::osv::DbError) -> Self {
        match e {
            fleetreach_core::osv::DbError::Read(io) => DbError::Read(io),
            fleetreach_core::osv::DbError::Parse(json) => DbError::Parse(json),
            other => DbError::Archive(other.to_string()),
        }
    }
}
