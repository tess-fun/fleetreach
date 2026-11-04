//! What a Rust executable says it was built from: the crate list `cargo auditable` embeds. A
//! static binary owns no package database entry, so this is the only record of what it holds,
//! and a binary built without it says nothing.
//!
//! Nothing is run. The list is zlib-compressed JSON in the ELF section `.dep-v0`.

use std::io::Read;

use serde::Deserialize;

use crate::gobin::uint;

const SECTION: &[u8] = b".dep-v0";
/// What the standard library's panic messages leave in a binary, with or without symbols.
const RUSTC_PATH: &[u8] = b"/rustc/";
/// The limit `rust-audit-info` sets on the decompressed list: it is attacker-supplied.
const MAX_LIST_BYTES: u64 = 8 << 20;
const MAX_SECTIONS: usize = 1 << 16;

/// What a Rust binary is known to be built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustBuild {
    /// The crates linked in, by name and version. Those from a path count too: ripgrep's
    /// `globset` is a workspace member and also the published crate, and the binary's own
    /// crate may be one with advisories of its own.
    pub crates: Vec<(String, String)>,
    /// Whether the binary carried a crate list that could be read.
    pub audited: bool,
}

#[derive(Deserialize)]
struct List {
    packages: Vec<Crate>,
}

#[derive(Deserialize)]
struct Crate {
    name: String,
    version: String,
    /// `build` is a build script or proc macro's: compiled, but not linked in.
    #[serde(default)]
    kind: Option<String>,
}

/// The crates of the ELF file `data`, or `None` if it is not a Rust binary. A Rust binary with
/// no list that can be read is one whose crates are unknown, not one with none.
pub fn read(data: &[u8]) -> Option<RustBuild> {
    if data.get(..4)? != b"\x7fELF" {
        return None;
    }
    if let Some(crates) = section(data, SECTION).and_then(list) {
        return Some(RustBuild {
            crates,
            audited: true,
        });
    }
    memchr::memmem::find(data, RUSTC_PATH).map(|_| RustBuild {
        crates: Vec::new(),
        audited: false,
    })
}

fn list(compressed: &[u8]) -> Option<Vec<(String, String)>> {
    let mut json = Vec::new();
    flate2::read::ZlibDecoder::new(compressed)
        .take(MAX_LIST_BYTES)
        .read_to_end(&mut json)
        .ok()?;
    let list: List = serde_json::from_slice(&json).ok()?;
    let mut crates: Vec<(String, String)> = list
        .packages
        .into_iter()
        .filter(|c| c.kind.as_deref().is_none_or(|k| k == "runtime"))
        .map(|c| (c.name, c.version))
        .collect();
    crates.sort();
    crates.dedup();
    Some(crates)
}

/// The contents of the ELF section `name`.
fn section<'a>(data: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let wide = *data.get(4)? == 2;
    let big = *data.get(5)? == 2;
    let word = if wide { 8 } else { 4 };
    let read = |at: usize, size: usize| uint(data.get(at..)?, size, big);
    let table = usize::try_from(read(if wide { 40 } else { 32 }, word)?).ok()?;
    let entry = usize::try_from(read(if wide { 58 } else { 46 }, 2)?).ok()?;
    let count = usize::try_from(read(if wide { 60 } else { 48 }, 2)?).ok()?;
    let names = usize::try_from(read(if wide { 62 } else { 50 }, 2)?).ok()?;
    // `(name offset, file offset, size)` of the section header at index `i`.
    let header = |i: usize| -> Option<(usize, usize, usize)> {
        let at = table.checked_add(i.checked_mul(entry)?)?;
        // First: `at` is in the file from here on, so the sums below cannot overflow.
        let name = read(at, 4)?;
        let (offset, size) = if wide {
            (read(at + 24, 8)?, read(at + 32, 8)?)
        } else {
            (read(at + 16, 4)?, read(at + 20, 4)?)
        };
        Some((
            usize::try_from(name).ok()?,
            usize::try_from(offset).ok()?,
            usize::try_from(size).ok()?,
        ))
    };
    let (_, strings, strings_size) = header(names)?;
    let strings = data.get(strings..strings.checked_add(strings_size)?)?;
    (0..count.min(MAX_SECTIONS)).find_map(|i| {
        let (at, offset, size) = header(i)?;
        let here = strings.get(at..)?;
        let matches = here.strip_prefix(name)?.first() == Some(&0);
        matches.then(|| data.get(offset..offset.checked_add(size)?))?
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A minimal 64-bit little-endian ELF with the sections `.shstrtab` and `.dep-v0`.
    fn elf(section: &[u8]) -> Vec<u8> {
        let names = b"\0.shstrtab\0.dep-v0\0";
        let strings_at = 64_u64;
        let body_at = strings_at + names.len() as u64;
        let table = body_at + section.len() as u64;
        let mut out = vec![0_u8; 64];
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = 2;
        out[5] = 1;
        out[40..48].copy_from_slice(&table.to_le_bytes());
        out[58..60].copy_from_slice(&64_u16.to_le_bytes());
        out[60..62].copy_from_slice(&3_u16.to_le_bytes());
        out[62..64].copy_from_slice(&1_u16.to_le_bytes());
        out.extend_from_slice(names);
        out.extend_from_slice(section);
        let mut header = |name: u32, offset: u64, size: u64| {
            let mut h = [0_u8; 64];
            h[..4].copy_from_slice(&name.to_le_bytes());
            h[24..32].copy_from_slice(&offset.to_le_bytes());
            h[32..40].copy_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&h);
        };
        header(0, 0, 0);
        header(1, strings_at, names.len() as u64);
        header(11, body_at, section.len() as u64);
        out
    }

    fn zlib(text: &str) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(text.as_bytes()).unwrap();
        z.finish().unwrap()
    }

    #[test]
    fn reads_the_crates_linked_in() {
        let json = r#"{"packages":[
            {"name":"app","version":"0.1.0","source":"local","root":true},
            {"name":"smallvec","version":"1.6.0","source":"crates.io"},
            {"name":"time","version":"0.1.43","source":"crates.io","kind":"runtime"},
            {"name":"cc","version":"1.0.0","source":"crates.io","kind":"build"}]}"#;
        let build = read(&elf(&zlib(json))).unwrap();
        assert!(build.audited);
        let names: Vec<&str> = build.crates.iter().map(|c| c.0.as_str()).collect();
        assert_eq!(names, ["app", "smallvec", "time"]);
    }

    #[test]
    fn a_rust_binary_with_no_readable_list_is_unknown_not_empty() {
        let mut unaudited = elf(b"not zlib");
        unaudited.extend_from_slice(b"/rustc/0123456789/library/core/src/panicking.rs");
        let build = read(&unaudited).unwrap();
        assert!(!build.audited && build.crates.is_empty());
        assert_eq!(read(&elf(b"not zlib")), None);
        assert_eq!(read(b"#!/bin/sh\n"), None);
    }

    #[test]
    fn a_section_table_past_the_file_is_no_list() {
        let mut bad = elf(&zlib(r#"{"packages":[]}"#));
        bad[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(read(&bad), None);
        // Near the end of the address space, as the fuzzer found.
        bad[40..48].copy_from_slice(&(u64::MAX - 8).to_le_bytes());
        assert_eq!(read(&bad), None);
    }
}
