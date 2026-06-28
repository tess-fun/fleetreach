use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Errors from running govulncheck or matching against the offline OSV DB.
///
/// Variants preserve their underlying cause via [`std::error::Error::source`] where one
/// exists (the subprocess [`io::Error`], the JSON [`serde_json::Error`], or a [`DbError`]),
/// so callers can walk the chain rather than parse a flattened string.
///
/// `#[non_exhaustive]`: new variants may be added in a minor release, so match with a
/// wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GoError {
    /// The govulncheck JSON stream could not be parsed.
    #[error("parsing govulncheck JSON: {0}")]
    Parse(#[from] serde_json::Error),
    /// Spawning or waiting on the govulncheck subprocess failed.
    #[error("running govulncheck: {0}")]
    Spawn(#[from] io::Error),
    /// govulncheck produced no JSON on stdout (its stderr is captured here).
    #[error("govulncheck produced no output: {stderr}")]
    NoOutput {
        /// The subprocess's stderr, for diagnosis.
        stderr: String,
    },
    /// govulncheck exited non-zero — a genuine failure (build error, or a confined scan
    /// whose denied network blocked the DB fetch), not a clean result. In `-format json`
    /// mode a clean or vulns-found scan both exit zero, so a non-zero status is never
    /// "vulns found".
    #[error("govulncheck failed: {stderr}")]
    Failed {
        /// The subprocess's stderr, for diagnosis.
        stderr: String,
    },
    /// The build sandbox could not be set up — e.g. `--build-sandbox=require`
    /// with no mechanism available, or the scratch work dir could not be created.
    #[error("build sandbox: {0}")]
    Sandbox(String),
    /// govulncheck exceeded its wall-clock timeout and was killed. A distinct variant
    /// (not [`Failed`](GoError::Failed)) so a caller can tell a hang from a build error.
    #[error("govulncheck timed out after {secs}s (a hostile or oversized module may be hanging the build)")]
    Timeout {
        /// The timeout that was exceeded, in seconds.
        secs: u64,
    },
    /// A confined or `--offline` Go scan denies the network but no offline vulnerability
    /// DB mirror was supplied, so govulncheck has nothing to consult. Fails closed rather
    /// than scanning online or masquerading as clean. Accurate whether confinement came
    /// from `--offline` or `--build-sandbox=require`.
    #[error("a confined/offline Go scan denies the network but no offline vulnerability DB is set; pass --go-vuln-db=file://<mirror> (or GOVULNDB)")]
    MirrorRequired,
    /// A Go manifest or the offline OSV DB at `path` could not be read or parsed. The
    /// repo is an honest gap rather than a false-clean module-level scan. The underlying
    /// I/O or JSON error is the [`source`](std::error::Error::source).
    #[error("offline vulnerability DB {path}: {source}")]
    Db {
        /// The file that could not be read or parsed.
        path: PathBuf,
        /// The underlying read or parse failure.
        #[source]
        source: DbError,
    },
}

/// Why a file under the offline OSV DB (or a `go.mod`) could not be used.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DbError {
    /// The file could not be read.
    #[error("read failed: {0}")]
    Read(#[from] io::Error),
    /// The file was not valid JSON.
    #[error("invalid JSON: {0}")]
    Parse(#[from] serde_json::Error),
}

impl GoError {
    /// Build a [`Db`](GoError::Db) error for `path` from a read or parse failure.
    pub(crate) fn db(path: impl Into<PathBuf>, source: impl Into<DbError>) -> Self {
        GoError::Db {
            path: path.into(),
            source: source.into(),
        }
    }
}
