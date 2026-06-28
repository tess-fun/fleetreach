use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Errors from the toolchain-free GitHub Actions matcher: reading a workflow file or a file
/// under the offline OSV DB mirror.
///
/// Like the other feeders, a present-but-broken input fails **closed** — an unreadable
/// workflow, or a corrupt advisory record, is an honest gap, never a false-clean scan. The
/// underlying cause is preserved via [`source`](std::error::Error::source).
///
/// `#[non_exhaustive]`: new variants may be added in a minor release, so match with a
/// wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GhaError {
    /// A workflow file, or a file under the offline OSV DB at `path`, could not be read or
    /// parsed. The underlying error is the [`source`](std::error::Error::source).
    #[error("github-actions scan {path}: {source}")]
    Db {
        /// The file that could not be read or parsed.
        path: PathBuf,
        /// The underlying read or parse failure.
        #[source]
        source: DbError,
    },
}

impl GhaError {
    /// Build a [`GhaError::Db`] from a path and any [`DbError`] source.
    pub(crate) fn db(path: impl Into<PathBuf>, source: impl Into<DbError>) -> Self {
        GhaError::Db {
            path: path.into(),
            source: source.into(),
        }
    }
}

/// Why a workflow file or a file under the offline OSV DB could not be used.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DbError {
    /// The file (or workflow directory) could not be read.
    #[error("read failed: {0}")]
    Read(#[from] io::Error),
    /// An OSV record was not valid JSON.
    #[error("invalid JSON: {0}")]
    Parse(#[from] serde_json::Error),
    /// The OSV mirror `.zip` could not be opened or decompressed.
    #[error("invalid zip archive: {0}")]
    Archive(String),
    /// The `.github/workflows` directory could not be fully walked, so a workflow file may
    /// have been missed — the repo cannot be reported clean.
    #[error("could not fully read workflows: {0}")]
    Walk(String),
}

impl From<fleetreach_core::osv::DbError> for DbError {
    fn from(e: fleetreach_core::osv::DbError) -> Self {
        match e {
            fleetreach_core::osv::DbError::Read(io) => DbError::Read(io),
            fleetreach_core::osv::DbError::Parse(json) => DbError::Parse(json),
            fleetreach_core::osv::DbError::Archive(s) => DbError::Archive(s),
            other => DbError::Archive(other.to_string()),
        }
    }
}
