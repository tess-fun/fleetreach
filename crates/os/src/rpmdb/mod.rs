//! Installed packages of an RPM-based image, read from its rpm database without running
//! `rpm` and without linking a database library (spec 16, row 10: the 1.7.0 RPM spike).
//!
//! rpm has stored its database three ways, all read here by pure Rust:
//!
//! - **SQLite** (`rpmdb.sqlite`): Fedora 33+, RHEL 9 and its rebuilds, Amazon Linux 2023,
//!   Azure Linux, Photon. Read with a small b-tree walker ([`sqlite`]).
//! - **Berkeley DB** (`Packages`, hash format): RHEL 7 and 8, CentOS 7, Amazon Linux 2.
//! - **NDB** (`Packages.db`): SUSE and openSUSE.
//!
//! Each package is its stored RPM header ([`header`]), reduced to the fields that identify it
//! and the files it owns. Images are read through [`read`], on the bytes the image reader
//! kept; [`read_dir`] reads a database directory on disk.
//!
//! Fail-closed like every reader in this crate: a database that cannot be read in full is an
//! error, never a short package list.

mod bdb;
mod header;
mod ndb;
pub mod sqlite;

use std::path::{Path, PathBuf};

/// Databases larger than this are refused rather than read into memory (real ones are tens
/// of megabytes).
const MAX_DB_BYTES: u64 = 2 << 30;

/// One installed package, as `rpm -q` names it.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct RpmPackage {
    pub name: String,
    /// `None` when the package has no epoch (rpm compares it as 0).
    pub epoch: Option<u32>,
    pub version: String,
    pub release: String,
    /// `None` for pseudo-packages such as `gpg-pubkey`.
    pub arch: Option<String>,
    /// The source package (`openssl-3.0.7-27.el9.src.rpm`), which advisories name.
    pub source_rpm: Option<String>,
    /// The module stream a package came from (RHEL 8+ AppStream), if any.
    pub modularity_label: Option<String>,
    /// The paths the package installs, absolute (`/usr/bin/openssl`).
    pub files: Vec<String>,
}

/// Why an rpm database could not be read.
#[derive(Debug, thiserror::Error)]
#[error("rpm database {path}: {reason}")]
pub struct RpmDbError {
    pub path: PathBuf,
    pub reason: String,
}

/// Which storage an rpm database directory uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Sqlite,
    BerkeleyDb,
    Ndb,
}

/// The backend of the database in `dir` (`/var/lib/rpm` or `/usr/lib/sysimage/rpm`), if any.
#[must_use]
pub fn detect(dir: &Path) -> Option<Backend> {
    if dir.join("rpmdb.sqlite").is_file() {
        Some(Backend::Sqlite)
    } else if dir.join("Packages.db").is_file() {
        Some(Backend::Ndb)
    } else if dir.join("Packages").is_file() {
        Some(Backend::BerkeleyDb)
    } else {
        None
    }
}

impl Backend {
    /// The database file's name (`rpmdb.sqlite`, `Packages`, `Packages.db`).
    pub fn file_name(self) -> &'static str {
        match self {
            Backend::Sqlite => "rpmdb.sqlite",
            Backend::BerkeleyDb => "Packages",
            Backend::Ndb => "Packages.db",
        }
    }
}

/// Every installed package in a database file's bytes, sorted. `wal` is SQLite's
/// write-ahead log (`rpmdb.sqlite-wal`), if present.
///
/// # Errors
///
/// When the database cannot be read in full.
pub fn read(backend: Backend, file: &[u8], wal: Option<&[u8]>) -> Result<Vec<RpmPackage>, String> {
    let blobs = match backend {
        Backend::Sqlite => sqlite_blobs(file, wal)?,
        Backend::BerkeleyDb => bdb::blobs(file)?,
        Backend::Ndb => ndb::blobs(file)?,
    };
    let mut out = Vec::with_capacity(blobs.len());
    for (i, blob) in blobs.iter().enumerate() {
        match header::parse(blob) {
            Ok(Some(pkg)) => out.push(pkg),
            Ok(None) => {}
            Err(e) => return Err(format!("package {i}: {e}")),
        }
    }
    out.sort();
    Ok(out)
}

/// Every installed package in the database in `dir`, sorted.
///
/// # Errors
///
/// When there is no database in `dir` or it cannot be read in full.
pub fn read_dir(dir: &Path) -> Result<Vec<RpmPackage>, RpmDbError> {
    let backend = detect(dir).ok_or_else(|| RpmDbError {
        path: dir.to_path_buf(),
        reason: "no rpm database here".into(),
    })?;
    let path = dir.join(backend.file_name());
    let file = read_file(&path)?;
    let wal_path = dir.join("rpmdb.sqlite-wal");
    let wal = if backend == Backend::Sqlite && wal_path.is_file() {
        Some(read_file(&wal_path)?)
    } else {
        None
    };
    read(backend, &file, wal.as_deref()).map_err(|reason| RpmDbError { path, reason })
}

fn read_file(path: &Path) -> Result<Vec<u8>, RpmDbError> {
    let err = |reason: String| RpmDbError {
        path: path.to_path_buf(),
        reason,
    };
    let len = std::fs::metadata(path)
        .map_err(|e| err(e.to_string()))?
        .len();
    if len > MAX_DB_BYTES {
        return Err(err(format!("{len} bytes is larger than any rpm database")));
    }
    std::fs::read(path).map_err(|e| err(e.to_string()))
}

/// The header blobs of the `Packages` table.
fn sqlite_blobs(file: &[u8], wal: Option<&[u8]>) -> Result<Vec<Vec<u8>>, String> {
    let db = sqlite::Db::open(file, wal)?;
    let root = db.table_root("Packages")?.ok_or("no Packages table")?;
    let mut out = Vec::new();
    db.scan(root, &mut |_, rec| {
        let row = sqlite::record(&rec)?;
        // (hnum INTEGER PRIMARY KEY, blob BLOB): the key is the rowid, stored as NULL.
        match row.get(1) {
            Some(sqlite::Value::Blob(b)) => {
                out.push(b.clone());
                Ok(())
            }
            _ => Err("a Packages row has no header blob".into()),
        }
    })?;
    Ok(out)
}
