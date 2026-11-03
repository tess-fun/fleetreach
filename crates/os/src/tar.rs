//! A small read-only tar reader: ustar and GNU headers, GNU long names (`L`/`K`) and PAX
//! extended headers (`x`), which is what image layers and `docker save` archives use.
//!
//! It never touches the filesystem: entries are handed to the caller, which keeps the few
//! files it wants in memory. A header whose checksum does not match is an error, not the
//! end of the archive, so a corrupt layer fails closed instead of reading as a short one.

use std::io::{self, Read};

/// What a tar entry is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    /// A hard link to an earlier entry (the target path).
    Hardlink(String),
    /// A symbolic link (the target, verbatim).
    Symlink(String),
    Dir,
    /// Devices, FIFOs and anything else without content that matters here.
    Other,
}

/// One entry's header, with long names and PAX overrides applied.
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub(crate) path: String,
    pub(crate) kind: Kind,
    pub(crate) size: u64,
}

/// Something a tar can be read from, with a way to skip data cheaply (a seek for files).
pub(crate) trait Source: Read + Sized {
    fn skip(&mut self, n: u64) -> io::Result<()> {
        let copied = io::copy(&mut self.by_ref().take(n), &mut io::sink())?;
        if copied < n {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tar archive ends inside an entry",
            ));
        }
        Ok(())
    }
}

impl<R: Read + ?Sized> Source for Box<R> {}
impl<R: Read> Source for io::BufReader<R> {}
impl Source for &[u8] {}

/// Reads entries one after another; the caller reads or skips each entry's data.
pub(crate) struct Reader<S: Source> {
    src: S,
    /// Unread bytes of the current entry's data, then its padding to the next block.
    remaining: u64,
    padding: u64,
    /// Bytes consumed so far, so a caller can record where an entry's data starts.
    pos: u64,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// A NUL-terminated header field.
fn field(block: &[u8], at: usize, len: usize) -> &[u8] {
    let f = block.get(at..at + len).unwrap_or_default();
    let end = f.iter().position(|&b| b == 0).unwrap_or(f.len());
    f.get(..end).unwrap_or_default()
}

/// A numeric field: octal text, or GNU base-256 when the high bit of the first byte is set.
fn number(block: &[u8], at: usize, len: usize) -> io::Result<u64> {
    let f = block.get(at..at + len).unwrap_or_default();
    if f.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v: u64 = 0;
        for (i, &b) in f.iter().enumerate() {
            let b = if i == 0 { b & 0x7f } else { b };
            v = v
                .checked_mul(256)
                .and_then(|v| v.checked_add(u64::from(b)))
                .ok_or_else(|| invalid("tar size field overflows"))?;
        }
        return Ok(v);
    }
    let text = String::from_utf8_lossy(f);
    let text = text.trim_matches(|c: char| c == '\0' || c == ' ');
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8).map_err(|_| invalid(format!("bad tar number {text:?}")))
}

fn checksum_ok(block: &[u8]) -> io::Result<bool> {
    let stored = number(block, 148, 8)?;
    let sum: u64 = block
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                32
            } else {
                u64::from(b)
            }
        })
        .sum();
    Ok(stored == sum)
}

/// Apply PAX records (`<len> <key>=<value>\n`) for the keys that matter here.
fn pax(data: &[u8], path: &mut Option<String>, link: &mut Option<String>, size: &mut Option<u64>) {
    let mut rest = data;
    while !rest.is_empty() {
        let Some(sp) = rest.iter().position(|&b| b == b' ') else {
            return;
        };
        let Some(len) = std::str::from_utf8(rest.get(..sp).unwrap_or_default())
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
        else {
            return;
        };
        let Some(record) = rest.get(sp + 1..len) else {
            return;
        };
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        if let Some(eq) = record.iter().position(|&b| b == b'=') {
            let key = record.get(..eq).unwrap_or_default();
            let value =
                String::from_utf8_lossy(record.get(eq + 1..).unwrap_or_default()).into_owned();
            match key {
                b"path" => *path = Some(value),
                b"linkpath" => *link = Some(value),
                b"size" => *size = value.parse().ok(),
                _ => {}
            }
        }
        rest = rest.get(len..).unwrap_or_default();
    }
}

impl<S: Source> Reader<S> {
    pub(crate) fn new(src: S) -> Self {
        Reader {
            src,
            remaining: 0,
            padding: 0,
            pos: 0,
        }
    }

    /// Bytes consumed from the source so far.
    pub(crate) fn position(&self) -> u64 {
        self.pos
    }

    fn read_block(&mut self, block: &mut [u8; 512]) -> io::Result<bool> {
        let mut filled = 0;
        while filled < 512 {
            let n = self.src.read(block.get_mut(filled..).unwrap_or_default())?;
            if n == 0 {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(invalid("tar archive ends inside a header"));
            }
            filled += n;
        }
        self.pos += 512;
        Ok(true)
    }

    fn finish_entry(&mut self) -> io::Result<()> {
        let n = self.remaining + self.padding;
        if n > 0 {
            self.src.skip(n)?;
            self.pos += n;
        }
        self.remaining = 0;
        self.padding = 0;
        Ok(())
    }

    fn read_meta(&mut self, size: u64) -> io::Result<Vec<u8>> {
        if size > 1 << 20 {
            return Err(invalid("tar extended header larger than 1 MiB"));
        }
        self.remaining = size;
        self.padding = (512 - size % 512) % 512;
        let data = self.read_data(size)?;
        self.finish_entry()?;
        Ok(data)
    }

    /// The next entry, or `None` at the end of the archive.
    pub(crate) fn next_entry(&mut self) -> io::Result<Option<Entry>> {
        self.finish_entry()?;
        let mut long_name: Option<String> = None;
        let mut long_link: Option<String> = None;
        let mut pax_size: Option<u64> = None;
        let mut block = [0u8; 512];
        loop {
            if !self.read_block(&mut block)? {
                return Ok(None);
            }
            if block.iter().all(|&b| b == 0) {
                return Ok(None);
            }
            if !checksum_ok(&block)? {
                return Err(invalid("tar header checksum mismatch"));
            }
            let size = number(&block, 124, 12)?;
            let flag = block.get(156).copied().unwrap_or(0);
            match flag {
                b'L' => {
                    let data = self.read_meta(size)?;
                    long_name =
                        Some(String::from_utf8_lossy(field(&data, 0, data.len())).into_owned());
                    continue;
                }
                b'K' => {
                    let data = self.read_meta(size)?;
                    long_link =
                        Some(String::from_utf8_lossy(field(&data, 0, data.len())).into_owned());
                    continue;
                }
                b'x' => {
                    let data = self.read_meta(size)?;
                    pax(&data, &mut long_name, &mut long_link, &mut pax_size);
                    continue;
                }
                b'g' => {
                    self.read_meta(size)?;
                    continue;
                }
                _ => {}
            }
            let ustar = field(&block, 257, 6).starts_with(b"ustar");
            let name = String::from_utf8_lossy(field(&block, 0, 100)).into_owned();
            let path = long_name.take().unwrap_or_else(|| {
                let prefix = if ustar {
                    String::from_utf8_lossy(field(&block, 345, 155)).into_owned()
                } else {
                    String::new()
                };
                if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                }
            });
            let link = long_link
                .take()
                .unwrap_or_else(|| String::from_utf8_lossy(field(&block, 157, 100)).into_owned());
            let size = pax_size.take().unwrap_or(size);
            let kind = match flag {
                b'0' | 0 | b'7' => {
                    if path.ends_with('/') {
                        Kind::Dir
                    } else {
                        Kind::File
                    }
                }
                b'1' => Kind::Hardlink(link),
                b'2' => Kind::Symlink(link),
                b'5' => Kind::Dir,
                _ => Kind::Other,
            };
            // Links and directories carry no data even when a size is set.
            let data = if matches!(kind, Kind::File | Kind::Other) {
                size
            } else {
                0
            };
            self.remaining = data;
            self.padding = (512 - data % 512) % 512;
            return Ok(Some(Entry { path, kind, size }));
        }
    }

    /// Read up to `limit` bytes of the current entry's data (all of it when it fits).
    pub(crate) fn read_data(&mut self, limit: u64) -> io::Result<Vec<u8>> {
        let n = self.remaining.min(limit);
        let mut buf = Vec::with_capacity(usize::try_from(n).unwrap_or(0));
        let got = self.src.by_ref().take(n).read_to_end(&mut buf)? as u64;
        if got < n {
            return Err(invalid("tar archive ends inside an entry"));
        }
        self.remaining -= got;
        self.pos += got;
        Ok(buf)
    }
}

#[cfg(test)]
pub(crate) mod build {
    //! Writing tars for tests.

    fn octal(out: &mut [u8], v: u64) {
        let s = format!("{v:0width$o}", width = out.len() - 1);
        out.get_mut(..s.len())
            .unwrap_or_default()
            .copy_from_slice(s.as_bytes());
    }

    fn header(path: &str, flag: u8, size: u64, link: &str) -> [u8; 512] {
        let mut h = [0u8; 512];
        let n = path.len().min(100);
        h[..n].copy_from_slice(&path.as_bytes()[..n]);
        octal(&mut h[100..108], 0o644);
        octal(&mut h[108..116], 0);
        octal(&mut h[116..124], 0);
        octal(&mut h[124..136], size);
        octal(&mut h[136..148], 0);
        h[156] = flag;
        let l = link.len().min(100);
        h[157..157 + l].copy_from_slice(&link.as_bytes()[..l]);
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
        let s = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(s.as_bytes());
        h
    }

    fn pad(out: &mut Vec<u8>) {
        while !out.len().is_multiple_of(512) {
            out.push(0);
        }
    }

    /// One tar entry to write.
    pub(crate) enum E<'a> {
        File(&'a str, &'a [u8]),
        Dir(&'a str),
        Symlink(&'a str, &'a str),
        Hardlink(&'a str, &'a str),
        /// A GNU long-name entry followed by a file.
        LongFile(&'a str, &'a [u8]),
    }

    pub(crate) fn tar(entries: &[E]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in entries {
            match e {
                E::File(p, d) => {
                    out.extend_from_slice(&header(p, b'0', d.len() as u64, ""));
                    out.extend_from_slice(d);
                    pad(&mut out);
                }
                E::Dir(p) => out.extend_from_slice(&header(p, b'5', 0, "")),
                E::Symlink(p, t) => out.extend_from_slice(&header(p, b'2', 0, t)),
                E::Hardlink(p, t) => out.extend_from_slice(&header(p, b'1', 0, t)),
                E::LongFile(p, d) => {
                    let mut name = p.as_bytes().to_vec();
                    name.push(0);
                    out.extend_from_slice(&header("././@LongLink", b'L', name.len() as u64, ""));
                    out.extend_from_slice(&name);
                    pad(&mut out);
                    out.extend_from_slice(&header("short", b'0', d.len() as u64, ""));
                    out.extend_from_slice(d);
                    pad(&mut out);
                }
            }
        }
        out.extend_from_slice(&[0u8; 1024]);
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::build::{tar, E};
    use super::*;

    #[test]
    fn reads_files_links_and_long_names() {
        let long = format!("{}/package-lock.json", "d".repeat(150));
        let bytes = tar(&[
            E::Dir("etc/"),
            E::File("etc/os-release", b"ID=debian\n"),
            E::Symlink("usr/lib/os-release", "../../etc/os-release"),
            E::Hardlink("etc/again", "etc/os-release"),
            E::LongFile(&long, b"{}"),
        ]);
        let mut r = Reader::new(bytes.as_slice());
        let mut seen = Vec::new();
        while let Some(e) = r.next_entry().unwrap() {
            let data = if e.kind == Kind::File {
                r.read_data(1024).unwrap()
            } else {
                Vec::new()
            };
            seen.push((e.path, e.kind, data));
        }
        assert_eq!(seen.len(), 5);
        assert_eq!(seen[1].2, b"ID=debian\n");
        assert_eq!(seen[2].1, Kind::Symlink("../../etc/os-release".into()));
        assert_eq!(seen[3].1, Kind::Hardlink("etc/os-release".into()));
        assert_eq!(seen[4].0, long);
        assert_eq!(seen[4].2, b"{}");
    }

    #[test]
    fn bad_checksum_and_truncation_fail_closed() {
        let mut bytes = tar(&[E::File("a", b"hello")]);
        bytes[0] = b'b';
        assert!(Reader::new(bytes.as_slice()).next_entry().is_err());

        let bytes = tar(&[E::File("a", &[7u8; 2000])]);
        let cut = bytes.get(..1024).unwrap();
        let mut r = Reader::new(cut);
        r.next_entry().unwrap().unwrap();
        assert!(r.read_data(4096).is_err());
    }

    #[test]
    fn pax_path_overrides_the_header_name() {
        let mut out = Vec::new();
        let record = b"32 path=very/long/name/here.txt\n";
        let mut h = tar(&[E::File("PaxHeader", record)]);
        h.truncate(1024);
        h[156] = b'x';
        // Re-checksum the edited header.
        h[148..156].copy_from_slice(b"        ");
        let sum: u64 = h[..512].iter().map(|&b| u64::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(&tar(&[E::File("short", b"x")]));
        let mut r = Reader::new(out.as_slice());
        let e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.path, "very/long/name/here.txt");
    }
}
