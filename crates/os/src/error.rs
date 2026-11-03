use std::path::PathBuf;

use thiserror::Error;

/// Why a file under the offline OSV DB could not be used (shared across feeders).
pub use fleetreach_core::osv::DbError;

/// Errors from reading an image or a distro OSV export.
///
/// Like every feeder, a present-but-broken input fails **closed**: an unreadable image, a
/// layer that does not match its digest, or a corrupt advisory record is an honest gap,
/// never a clean scan. The underlying cause is kept as the
/// [`source`](std::error::Error::source) where there is one.
///
/// `#[non_exhaustive]`: new variants may be added in a minor release, so match with a
/// wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OsError {
    /// The image at `path` could not be read.
    #[error("image {path}: {source}")]
    Io {
        /// The image (or the file in it) that could not be read.
        path: PathBuf,
        /// The underlying read failure.
        #[source]
        source: std::io::Error,
    },
    /// The image at `path` is not one this reader understands, or is corrupt.
    #[error("image {path}: {reason}")]
    Image {
        /// The image path.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
    /// A distro OSV export at `path` could not be read or parsed.
    #[error("distro OSV export {path}: {source}")]
    Db {
        /// The export (`all.zip` or a directory of records).
        path: PathBuf,
        /// The underlying read or parse failure.
        #[source]
        source: DbError,
    },
}

impl OsError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        OsError::Io {
            path: path.into(),
            source,
        }
    }

    pub(crate) fn image(path: impl Into<PathBuf>, reason: impl Into<String>) -> Self {
        OsError::Image {
            path: path.into(),
            reason: reason.into(),
        }
    }

    pub(crate) fn db(path: impl Into<PathBuf>, source: impl Into<DbError>) -> Self {
        OsError::Db {
            path: path.into(),
            source: source.into(),
        }
    }
}
