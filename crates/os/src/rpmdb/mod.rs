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
//! Each package is its stored RPM header ([`header`]), reduced to the fields that identify it.
//! Not wired into scans yet: matching RPM packages against advisories is 1.7.0 work.
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

/// Every installed package in the database in `dir`, sorted.
pub fn read_dir(dir: &Path) -> Result<Vec<RpmPackage>, RpmDbError> {
    let err = |path: &Path, reason: String| RpmDbError {
        path: path.to_path_buf(),
        reason,
    };
    let backend = detect(dir).ok_or_else(|| err(dir, "no rpm database here".into()))?;
    let (path, blobs) = match backend {
        Backend::Sqlite => {
            let path = dir.join("rpmdb.sqlite");
            let file = read(&path)?;
            let wal_path = dir.join("rpmdb.sqlite-wal");
            let wal = if wal_path.is_file() {
                Some(read(&wal_path)?)
            } else {
                None
            };
            let blobs = sqlite_blobs(&file, wal.as_deref()).map_err(|e| err(&path, e))?;
            (path, blobs)
        }
        Backend::BerkeleyDb => {
            let path = dir.join("Packages");
            let blobs = bdb::blobs(&read(&path)?).map_err(|e| err(&path, e))?;
            (path, blobs)
        }
        Backend::Ndb => {
            let path = dir.join("Packages.db");
            let blobs = ndb::blobs(&read(&path)?).map_err(|e| err(&path, e))?;
            (path, blobs)
        }
    };
    let mut out = Vec::with_capacity(blobs.len());
    for (i, blob) in blobs.iter().enumerate() {
        match header::parse(blob) {
            Ok(Some(pkg)) => out.push(pkg),
            Ok(None) => {}
            Err(e) => return Err(err(&path, format!("package {i}: {e}"))),
        }
    }
    out.sort();
    Ok(out)
}

fn read(path: &Path) -> Result<Vec<u8>, RpmDbError> {
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
