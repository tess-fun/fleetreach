//! What a Go executable says it was built from: the toolchain and module versions the linker
//! stamps into every binary (`go version -m`). Static Go binaries own no package database
//! entry, so this is the only record of what they hold.
//!
//! Nothing is run. The blob is found by its magic in an ELF file: since Go 1.18 it holds the
//! strings inline, and before that it points at them, which the ELF program headers resolve.

/// The magic that opens the build information.
const MAGIC: &[u8] = b"\xff Go buildinf:";
/// Go aligns the blob to this.
const ALIGN: usize = 16;
/// The sentinels around the module information.
const SENTINEL: usize = 16;
/// The most modules read from one binary.
const MAX_MODULES: usize = 100_000;

/// What built a Go binary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GoBuild {
    /// The toolchain, as a module version (`v1.21.5`), which sets the standard library's.
    pub toolchain: Option<String>,
    /// The modules linked in, as `(path, version)`, replacements applied.
    pub modules: Vec<(String, String)>,
}

/// The Go module holding the standard library in advisories.
pub const STDLIB: &str = "stdlib";

/// The build information of the ELF file `data`, or `None` if it is not a Go binary.
pub fn read(data: &[u8]) -> Option<GoBuild> {
    let elf = Elf::parse(data)?;
    let at = (0..data.len().saturating_sub(MAGIC.len()))
        .step_by(ALIGN)
        .find(|&i| data.get(i..i + MAGIC.len()) == Some(MAGIC))?;
    let pointer_size = usize::from(*data.get(at + 14)?);
    let flags = *data.get(at + 15)?;
    let (version, info) = if flags & 2 != 0 {
        let (version, next) = inline_string(data, at + 32)?;
        let (info, _) = inline_string(data, next)?;
        (version, info)
    } else {
        let big = flags & 1 != 0;
        let first = at + 16;
        (
            elf.go_string(
                uint(data.get(first..)?, pointer_size, big)?,
                pointer_size,
                big,
            )?,
            elf.go_string(
                uint(data.get(first + pointer_size..)?, pointer_size, big)?,
                pointer_size,
                big,
            )?,
        )
    };
    let text = String::from_utf8_lossy(strip_sentinels(info));
    Some(GoBuild {
        toolchain: toolchain_version(&String::from_utf8_lossy(version)),
        modules: modules(&text),
    })
}

fn strip_sentinels(info: &[u8]) -> &[u8] {
    if info.len() > 2 * SENTINEL && info.get(info.len() - SENTINEL - 1) == Some(&b'\n') {
        info.get(SENTINEL..info.len() - SENTINEL).unwrap_or(&[])
    } else {
        &[]
    }
}

/// A length-prefixed string at `at`, and where the next one starts.
fn inline_string(data: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let mut length = 0usize;
    let mut i = at;
    for shift in (0..64).step_by(7) {
        let b = *data.get(i)?;
        i += 1;
        length |= usize::from(b & 0x7f).checked_shl(shift)?;
        if b & 0x80 == 0 {
            let end = i.checked_add(length)?;
            return Some((data.get(i..end)?, end));
        }
    }
    None
}

fn uint(bytes: &[u8], size: usize, big: bool) -> Option<u64> {
    let bytes = bytes.get(..size)?;
    let fold = |n: u64, b: &u8| (n << 8) | u64::from(*b);
    Some(if big {
        bytes.iter().fold(0, fold)
    } else {
        bytes.iter().rev().fold(0, fold)
    })
}

/// A file's loadable segments, enough to follow a pointer.
struct Elf<'a> {
    data: &'a [u8],
    /// `(virtual address, file offset, size in the file)`.
    segments: Vec<(u64, u64, u64)>,
}

impl<'a> Elf<'a> {
    fn parse(data: &'a [u8]) -> Option<Elf<'a>> {
        if data.get(..4)? != b"\x7fELF" {
            return None;
        }
        let wide = *data.get(4)? == 2;
        let big = *data.get(5)? == 2;
        let word = if wide { 8 } else { 4 };
        let read = |at: usize, size: usize| uint(data.get(at..)?, size, big);
        let table = usize::try_from(read(if wide { 32 } else { 28 }, word)?).ok()?;
        let entry = usize::try_from(read(if wide { 54 } else { 42 }, 2)?).ok()?;
        let count = usize::try_from(read(if wide { 56 } else { 44 }, 2)?).ok()?;
        let mut segments = Vec::new();
        for i in 0..count {
            let at = table.checked_add(i.checked_mul(entry)?)?;
            if read(at, 4)? != 1 {
                continue;
            }
            let (offset, address, size) = if wide {
                (read(at + 8, 8)?, read(at + 16, 8)?, read(at + 32, 8)?)
            } else {
                (read(at + 4, 4)?, read(at + 8, 4)?, read(at + 16, 4)?)
            };
            segments.push((address, offset, size));
        }
        Some(Elf { data, segments })
    }

    fn at(&self, address: u64) -> Option<&'a [u8]> {
        let (start, offset, size) = self
            .segments
            .iter()
            .find(|(a, _, s)| address >= *a && address - a < *s)?;
        let from = usize::try_from(offset.checked_add(address - start)?).ok()?;
        let end = usize::try_from(offset.checked_add(*size)?).ok()?;
        self.data.get(from..end)
    }

    /// The Go string whose header (pointer, length) is at `address`.
    fn go_string(&self, address: u64, size: usize, big: bool) -> Option<&'a [u8]> {
        let header = self.at(address)?;
        let pointer = uint(header, size, big)?;
        let length = usize::try_from(uint(header.get(size..)?, size, big)?).ok()?;
        self.at(pointer)?.get(..length)
    }
}

/// `go1.21.5` as a module version. `go1.20` is `v1.20.0`, `go1.21rc2` is `v1.21.0-rc.2`, and a
/// development toolchain (`devel go1.22-abc`) has no release to match.
fn toolchain_version(raw: &str) -> Option<String> {
    let word = raw.split_whitespace().next()?;
    let rest = word.strip_prefix("go")?;
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(rest.len());
    let (numbers, tail) = rest.split_at(end);
    let mut parts: Vec<&str> = numbers.split('.').collect();
    if parts.len() < 2 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    while parts.len() < 3 {
        parts.push("0");
    }
    let numbers = parts.join(".");
    for (word, tag) in [("rc", "rc"), ("beta", "beta")] {
        if let Some(n) = tail.strip_prefix(word) {
            let digits: String = n.chars().take_while(char::is_ascii_digit).collect();
            return (!digits.is_empty()).then(|| format!("v{numbers}-{tag}.{digits}"));
        }
    }
    Some(format!("v{numbers}"))
}

/// The version a build stamped through `-ldflags`: `-X main.Version=1.22.6`, as Trivy reads it.
/// A `main` variable wins, and only what reads as a release counts.
fn stamped_version(flags: &str) -> Option<String> {
    let flags = flags.replace("\\\"", "\"");
    let flags = flags.trim().trim_matches('"');
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    for c in flags.chars() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), _) if q == c => quote = None,
            (None, ' ') => words.extend((!word.is_empty()).then(|| std::mem::take(&mut word))),
            _ => word.push(c),
        }
    }
    words.push(word);
    let mut stamped: Vec<(bool, &str)> = Vec::new();
    for pair in words.windows(2) {
        let [flag, assignment] = pair else { continue };
        if !matches!(flag.as_str(), "-X" | "--X") {
            continue;
        }
        let Some((key, value)) = assignment.split_once('=') else {
            continue;
        };
        let lower = key.to_ascii_lowercase();
        if (lower.ends_with(".version") || lower.ends_with(".ver")) && release(value) {
            stamped.push((!lower.starts_with("main."), value));
        }
    }
    stamped.sort_by_key(|(other, _)| *other);
    let (_, value) = stamped.first()?;
    Some(format!("v{}", value.trim_start_matches('v')))
}

/// Whether `value` reads as a release: `1.22.6`, `v2.0`, `1.2.3-rc.1`.
fn release(value: &str) -> bool {
    let value = value.trim_start_matches('v');
    let core = value.split(['-', '+']).next().unwrap_or_default();
    let numbers: Vec<&str> = core.split('.').collect();
    numbers.len() >= 2
        && numbers
            .iter()
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The modules in `go version -m` form. A `=>` line replaces the `dep` above it, and a main
/// module the toolchain left as `(devel)` takes the version the build stamped, if any.
fn modules(info: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut main = None;
    let mut stamped = None;
    for line in info.lines().take(MAX_MODULES) {
        let mut cols = line.split('\t');
        let (Some(kind), Some(path), version) = (cols.next(), cols.next(), cols.next()) else {
            continue;
        };
        let version = version.unwrap_or_default();
        match kind {
            "mod" | "dep" if !version.is_empty() && version != "(devel)" => {
                out.push((path.to_string(), version.to_string()));
            }
            "mod" => main = Some(path),
            "build" => {
                if let Some(flags) = path.strip_prefix("-ldflags=") {
                    stamped = stamped_version(flags);
                }
            }
            "=>" => {
                if let Some(last) = out.last_mut() {
                    *last = (path.to_string(), version.to_string());
                }
            }
            _ => {}
        }
    }
    out.extend(
        main.zip(stamped)
            .map(|(path, version)| (path.to_string(), version)),
    );
    out.retain(|(_, version)| !version.is_empty());
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const INFO: &str = "path\tgithub.com/a/cmd\nmod\tgithub.com/a\t(devel)\t\n\
        dep\tgithub.com/b\tv1.2.3\th1:x=\ndep\tgithub.com/c\tv1.0.0\n\
        =>\tgithub.com/fork/c\tv1.0.1\th1:y=\nbuild\tGOOS=linux\n";

    fn wrapped() -> Vec<u8> {
        let mut info = vec![b'0'; SENTINEL];
        info.extend_from_slice(INFO.as_bytes());
        info.extend_from_slice(&[b'1'; SENTINEL]);
        info
    }

    fn varint(mut n: usize, out: &mut Vec<u8>) {
        while n >= 0x80 {
            out.push(u8::try_from(n & 0x7f).unwrap() | 0x80);
            n >>= 7;
        }
        out.push(u8::try_from(n).unwrap());
    }

    /// A minimal 64-bit little-endian ELF, its one segment mapping the file at `BASE`.
    const BASE: u64 = 0x40_0000;
    fn elf(body: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 128];
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = 2;
        out[5] = 1;
        out[32..40].copy_from_slice(&64u64.to_le_bytes());
        out[54..56].copy_from_slice(&56u16.to_le_bytes());
        out[56..58].copy_from_slice(&1u16.to_le_bytes());
        out[64..68].copy_from_slice(&1u32.to_le_bytes());
        out[80..88].copy_from_slice(&BASE.to_le_bytes());
        out.extend_from_slice(body);
        let size = out.len() as u64;
        out[96..104].copy_from_slice(&size.to_le_bytes());
        out
    }

    fn inline(version: &str) -> Vec<u8> {
        let mut blob = MAGIC.to_vec();
        blob.extend_from_slice(&[8, 2]);
        blob.resize(32, 0);
        varint(version.len(), &mut blob);
        blob.extend_from_slice(version.as_bytes());
        let info = wrapped();
        varint(info.len(), &mut blob);
        blob.extend_from_slice(&info);
        elf(&blob)
    }

    fn expected() -> Vec<(String, String)> {
        vec![
            ("github.com/b".to_string(), "v1.2.3".to_string()),
            ("github.com/fork/c".to_string(), "v1.0.1".to_string()),
        ]
    }

    #[test]
    fn inline_build_information_is_read() {
        let build = read(&inline("go1.21.5")).unwrap();
        assert_eq!(build.toolchain.as_deref(), Some("v1.21.5"));
        assert_eq!(build.modules, expected());
    }

    #[test]
    fn pointers_of_older_toolchains_are_followed() {
        // The blob, then the two string headers, then the strings.
        let start = 128u64;
        let version = b"go1.16.7";
        let info = wrapped();
        let headers = start + 32;
        let strings = headers + 32;
        let mut blob = MAGIC.to_vec();
        blob.extend_from_slice(&[8, 0]);
        blob.extend_from_slice(&(BASE + headers).to_le_bytes());
        blob.extend_from_slice(&(BASE + headers + 16).to_le_bytes());
        for (at, len) in [
            (strings, version.len()),
            (strings + version.len() as u64, info.len()),
        ] {
            blob.extend_from_slice(&(BASE + at).to_le_bytes());
            blob.extend_from_slice(&(len as u64).to_le_bytes());
        }
        blob.extend_from_slice(version);
        blob.extend_from_slice(&info);
        let build = read(&elf(&blob)).unwrap();
        assert_eq!(build.toolchain.as_deref(), Some("v1.16.7"));
        assert_eq!(build.modules, expected());
    }

    #[test]
    fn a_main_module_takes_the_version_its_build_stamped() {
        let stamped = |flags: &str| {
            modules(&format!(
                "mod\tcode.gitea.io/gitea\t(devel)\t\nbuild\t-ldflags={flags}\n"
            ))
        };
        let gitea = vec![("code.gitea.io/gitea".to_string(), "v1.22.6".to_string())];
        assert_eq!(
            stamped(r#""-s -w -X \"main.MakeVersion=GNU Make 4.4.1\" -X \"main.Version=1.22.6\"""#),
            gitea
        );
        assert_eq!(stamped("-X main.version=v1.22.6"), gitea);
        assert_eq!(
            stamped("-X a/b.Version=9.9.9 -X main.Version=1.22.6"),
            gitea
        );
        // Neither a commit nor another variable says what was released.
        assert_eq!(stamped("-X main.version=abc123"), Vec::new());
        assert_eq!(stamped("-X main.commit=1.2.3"), Vec::new());
    }

    #[test]
    fn toolchain_versions_become_module_versions() {
        for (raw, want) in [
            ("go1.20", Some("v1.20.0")),
            ("go1.21.5", Some("v1.21.5")),
            ("go1.21rc2", Some("v1.21.0-rc.2")),
            ("go1.22beta1", Some("v1.22.0-beta.1")),
            ("go1.21.4 X:nocoverageredesign", Some("v1.21.4")),
            ("go1.20.7-fips", Some("v1.20.7")),
            ("devel go1.22-abcdef", None),
            ("go", None),
            ("", None),
        ] {
            assert_eq!(toolchain_version(raw).as_deref(), want, "{raw}");
        }
    }

    #[test]
    fn what_is_not_a_go_binary_is_none_and_truncation_never_panics() {
        assert_eq!(read(b""), None);
        assert_eq!(read(b"#!/bin/sh\n"), None);
        assert_eq!(read(&elf(b"no magic here")), None);
        let whole = inline("go1.21.5");
        for end in 0..whole.len() {
            let _ = read(&whole[..end]);
        }
        let mut corrupt = whole.clone();
        for i in (0..corrupt.len()).step_by(7) {
            corrupt[i] = 0xff;
            let _ = read(&corrupt);
        }
    }
}
