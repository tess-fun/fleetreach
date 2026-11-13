//! Hostile input: a class file or archive made to crash or stall the reader is a gap in the
//! read, never a panic and never minutes of work.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use fleetreach_jvm::classpath::{load, Input};
use fleetreach_jvm::model::Role;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("jvm-hostile-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn input(path: &Path) -> Input {
    Input {
        path: path.to_path_buf(),
        role: Role::Dependency,
    }
}

/// A damaged class whose name entry is not modified UTF-8: `cafebabe` 0.9 panics on it.
#[test]
fn a_class_the_parser_panics_on_is_unread() {
    let dir = scratch("class");
    std::fs::write(dir.join("Bad.class"), include_bytes!("bad-name.class")).unwrap();
    let cp = load(&[input(&dir)]).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(cp.classes.is_empty());
    assert_eq!(cp.unread.len(), 1);
    assert!(
        cp.unread[0].ends_with("the class file parser rejected it"),
        "{:?}",
        cp.unread
    );
}

/// One stored entry named by `count` central directory records: `count` times its size to
/// read from a file barely larger than one copy.
fn overlapping_zip(count: u32, data: &[u8]) -> Vec<u8> {
    let crc = crc32(data);
    let size = u32::try_from(data.len()).unwrap();
    let first = b"A0.class";
    let mut out = Vec::new();
    out.extend_from_slice(&0x0403_4b50_u32.to_le_bytes());
    for v in [20u16, 0, 0, 0, 0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for v in [crc, size, size] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&u16::try_from(first.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(first);
    out.extend_from_slice(data);
    let central_at = u32::try_from(out.len()).unwrap();
    for i in 0..count {
        let name = format!("A{i}.class");
        out.extend_from_slice(&0x0201_4b50_u32.to_le_bytes());
        for v in [20u16, 20, 0, 0, 0, 0] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in [crc, size, size] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        let len = u16::try_from(name.len()).unwrap();
        for v in [len, 0, 0, 0, 0] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
    }
    let central_len = u32::try_from(out.len()).unwrap() - central_at;
    out.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
    let n = u16::try_from(count).unwrap();
    for v in [0u16, 0, n, n] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&central_len.to_le_bytes());
    out.extend_from_slice(&central_at.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn budget_cut(unread: &[String]) -> usize {
    unread
        .iter()
        .filter(|u| u.contains("inflates past its budget"))
        .count()
}

/// 400 entries of 1 MiB (not class files, so each is a gap of its own) from a 1 MiB jar: past
/// the budget, 64 MiB plus 32 times the jar's size, the rest of the archive is one more gap.
#[test]
fn an_archive_that_inflates_far_past_its_size_is_cut_off() {
    let dir = scratch("bomb");
    let jar = dir.join("bomb.jar");
    std::fs::write(&jar, overlapping_zip(400, &vec![0; 1 << 20])).unwrap();
    let cp = load(&[input(&jar)]).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(budget_cut(&cp.unread), 1, "{:?}", cp.unread.last());
    assert_eq!(cp.unread.len(), 96 + 1);
}

/// The same layout within the budget reads every entry: the cut-off is the budget, not the
/// layout.
#[test]
fn an_archive_within_its_budget_reads_every_entry() {
    let dir = scratch("small");
    let jar = dir.join("small.jar");
    std::fs::write(&jar, overlapping_zip(20, &vec![0; 1 << 20])).unwrap();
    let cp = load(&[input(&jar)]).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(budget_cut(&cp.unread), 0);
    assert_eq!(cp.unread.len(), 20);
}
