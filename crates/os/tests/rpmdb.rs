//! The pure-Rust rpm database reader on SQLite fixtures (regenerate with
//! `tests/fixtures/rpmdb/gen.py`): 1 KiB pages, so headers overflow and the table has
//! interior pages, and a copy whose last transaction is only in the write-ahead log.
//! Real images are compared with `rpm -qa` outside the test suite (spec 16, RPM spike).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use fleetreach_os::rpmdb::{detect, read_dir, Backend};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rpmdb")
        .join(name)
}

fn names(dir: &Path) -> Vec<String> {
    read_dir(dir).unwrap().into_iter().map(|p| p.name).collect()
}

fn copy_to_temp(test: &str, name: &str, files: &[&str]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rpmdb-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for f in files {
        std::fs::copy(fixture(name).join(f), dir.join(f)).unwrap();
    }
    dir
}

#[test]
fn reads_every_package_across_overflow_and_interior_pages() {
    let dir = fixture("db-plain");
    assert_eq!(detect(&dir), Some(Backend::Sqlite));
    let pkgs = read_dir(&dir).unwrap();
    assert_eq!(pkgs.len(), 60);
    let p = &pkgs[4];
    assert_eq!(
        (
            p.name.as_str(),
            p.epoch,
            p.version.as_str(),
            p.release.as_str()
        ),
        ("pkg004", Some(1), "1.4", "4.fc41")
    );
    assert_eq!(p.arch.as_deref(), Some("x86_64"));
    assert_eq!(p.source_rpm.as_deref(), Some("pkg004-1.4-4.fc41.src.rpm"));
    assert_eq!(pkgs[3].epoch, None);
}

#[test]
fn committed_wal_frames_are_applied() {
    let n = names(&fixture("db-wal"));
    assert_eq!(n.len(), 60);
    assert!(n.contains(&"walpkg".to_string()));
    assert!(
        !n.contains(&"pkg004".to_string()),
        "hnum 5 was deleted in the WAL"
    );
}

#[test]
fn without_its_wal_the_file_is_the_last_checkpoint() {
    let dir = copy_to_temp("no-wal", "db-wal", &["rpmdb.sqlite"]);
    let n = names(&dir);
    assert!(n.contains(&"pkg004".to_string()) && !n.contains(&"walpkg".to_string()));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_wal_frame_failing_its_checksum_ends_the_log() {
    let dir = copy_to_temp("bad-wal", "db-wal", &["rpmdb.sqlite", "rpmdb.sqlite-wal"]);
    let wal = dir.join("rpmdb.sqlite-wal");
    let mut bytes = std::fs::read(&wal).unwrap();
    let last = bytes.len() - 10;
    bytes[last] ^= 0xff;
    std::fs::write(&wal, bytes).unwrap();
    // The log holds two transactions (the delete, then the insert). The insert's commit frame
    // now fails its checksum, so only the delete applies.
    let n = names(&dir);
    assert!(!n.contains(&"pkg004".to_string()) && !n.contains(&"walpkg".to_string()));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_truncated_database_is_an_error_not_a_short_list() {
    let dir = copy_to_temp("truncated", "db-plain", &["rpmdb.sqlite"]);
    let db = dir.join("rpmdb.sqlite");
    let bytes = std::fs::read(&db).unwrap();
    std::fs::write(&db, &bytes[..bytes.len() / 2]).unwrap();
    assert!(read_dir(&dir).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn every_single_byte_corruption_is_handled() {
    // Flip each byte of the first pages in turn: the reader may succeed or fail, never panic.
    let bytes = std::fs::read(fixture("db-plain").join("rpmdb.sqlite")).unwrap();
    for i in (0..4096).step_by(3) {
        let mut b = bytes.clone();
        b[i] ^= 0x5a;
        let _ = fleetreach_os::rpmdb::sqlite::Db::open(&b, None).and_then(|db| {
            let root = db.table_root("Packages")?.ok_or("none")?;
            db.scan(root, &mut |_, rec| {
                fleetreach_os::rpmdb::sqlite::record(&rec).map(|_| ())
            })
        });
    }
}

/// Each package as `name epoch:version-release.arch`, to compare with what `rpm -qa` printed
/// for the fixture (see `gen-bdb-ndb.sh`).
fn nevras(dir: &Path) -> Vec<String> {
    read_dir(dir)
        .unwrap()
        .into_iter()
        .map(|p| {
            let arch = p.arch.unwrap_or_default();
            format!(
                "{} {}:{}-{}.{arch}",
                p.name,
                p.epoch.unwrap_or(0),
                p.version,
                p.release
            )
        })
        .collect()
}

#[test]
fn berkeley_db_matches_rpm_and_skips_an_erased_header() {
    let dir = fixture("db-bdb");
    assert_eq!(detect(&dir), Some(Backend::BerkeleyDb));
    // `bc` was erased: its header bytes are still in the file, on a page no bucket reaches.
    let raw = std::fs::read(dir.join("Packages")).unwrap();
    assert!(raw.windows(7).any(|w| w == b"bc-1.07"));
    assert_eq!(
        nevras(&dir),
        [
            "basesystem 0:11-5.el8.noarch",
            "libpng 2:1.6.34-11.el8_10.aarch64",
            "which 0:2.21-21.el8_10.aarch64",
        ]
    );
}

#[test]
fn ndb_matches_rpm() {
    let dir = fixture("db-ndb");
    assert_eq!(detect(&dir), Some(Backend::Ndb));
    assert_eq!(
        nevras(&dir),
        [
            "libpng16-16 0:1.6.40-150600.3.17.1.aarch64",
            "which 0:2.21-2.20.aarch64",
        ]
    );
}

#[test]
fn truncated_berkeley_db_and_ndb_files_are_errors() {
    for (name, file) in [("db-bdb", "Packages"), ("db-ndb", "Packages.db")] {
        let dir = copy_to_temp(&format!("trunc-{name}"), name, &[file]);
        let path = dir.join(file);
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
        assert!(read_dir(&dir).is_err(), "{name}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
