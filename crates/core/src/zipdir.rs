//! A small ZIP reader for OSV exports: the central directory (ZIP64 included) kept as one
//! offset, size and checksum per member, and each member read from the file when asked for.
//!
//! The `zip` crate indexes every member by name and the OSV loaders held the whole archive in
//! memory. For npm's export (about 230,000 members) that was some 500 MB before a single
//! record was parsed. Here a member costs 32 bytes, and only the members being read are in
//! memory. Every member is checked against its recorded size and CRC-32; an encrypted member,
//! a compression method other than stored or deflate, or any field that does not add up is an
//! error, never a skipped record.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// One member: where its data starts and how to read it.
#[derive(Debug, Clone, Copy)]
struct Member {
    /// Offset of the member's local header.
    header: u64,
    compressed: u64,
    size: u64,
    crc: u32,
    deflated: bool,
}

/// An open archive: the file and its members, in central directory order.
#[derive(Debug)]
pub struct Archive {
    file: File,
    members: Vec<Member>,
}

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("zip: {what}"))
}

fn u16_at(b: &[u8], at: usize) -> io::Result<u16> {
    b.get(at..at + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| bad("truncated field"))
}

fn u32_at(b: &[u8], at: usize) -> io::Result<u32> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| bad("truncated field"))
}

fn u64_at(b: &[u8], at: usize) -> io::Result<u64> {
    let s = b.get(at..at + 8).ok_or_else(|| bad("truncated field"))?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_le_bytes(a))
}

#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn read_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset)? {
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
        }
    }
    Ok(())
}

fn read_vec(file: &File, offset: u64, len: u64) -> io::Result<Vec<u8>> {
    let len = usize::try_from(len).map_err(|_| bad("member too large"))?;
    let mut buf = vec![0u8; len];
    read_at(file, &mut buf, offset)?;
    Ok(buf)
}

const EOCD: u32 = 0x0605_4b50;
const ZIP64_LOCATOR: u32 = 0x0706_4b50;
const ZIP64_EOCD: u32 = 0x0606_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const LOCAL: u32 = 0x0403_4b50;

impl Archive {
    /// Open `path` and read its central directory; with `keep`, only members whose name it
    /// accepts are kept (in order).
    ///
    /// # Errors
    ///
    /// The file cannot be read, or is not a ZIP archive this reader can read in full.
    pub fn open(path: &Path, keep: impl Fn(&str) -> bool) -> io::Result<Archive> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        // The end record is 22 bytes plus a comment of at most 65,535.
        let tail_len = len.min(22 + 65_535);
        let tail = read_vec(&file, len - tail_len, tail_len)?;
        let at = (0..tail.len().saturating_sub(21))
            .rev()
            .find(|&i| u32_at(&tail, i).ok() == Some(EOCD))
            .ok_or_else(|| bad("no end of central directory"))?;
        let eocd_offset = len - tail_len + at as u64;
        let mut count = u64::from(u16_at(&tail, at + 10)?);
        let mut cd_size = u64::from(u32_at(&tail, at + 12)?);
        let mut cd_offset = u64::from(u32_at(&tail, at + 16)?);
        if u16_at(&tail, at + 4)? != 0 || u16_at(&tail, at + 6)? != 0 {
            return Err(bad("multi-disk archive"));
        }
        if count == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF {
            let locator_at = eocd_offset
                .checked_sub(20)
                .ok_or_else(|| bad("no ZIP64 locator"))?;
            let locator = read_vec(&file, locator_at, 20)?;
            if u32_at(&locator, 0)? != ZIP64_LOCATOR {
                return Err(bad("no ZIP64 locator"));
            }
            let record = read_vec(&file, u64_at(&locator, 8)?, 56)?;
            if u32_at(&record, 0)? != ZIP64_EOCD {
                return Err(bad("no ZIP64 end record"));
            }
            count = u64_at(&record, 32)?;
            cd_size = u64_at(&record, 40)?;
            cd_offset = u64_at(&record, 48)?;
        }
        if cd_offset.checked_add(cd_size).is_none_or(|end| end > len) {
            return Err(bad("central directory outside the file"));
        }
        let cd = read_vec(&file, cd_offset, cd_size)?;
        let mut members = Vec::new();
        let mut at = 0usize;
        for _ in 0..count {
            if u32_at(&cd, at)? != CENTRAL {
                return Err(bad("bad central directory entry"));
            }
            let flags = u16_at(&cd, at + 8)?;
            let method = u16_at(&cd, at + 10)?;
            let crc = u32_at(&cd, at + 16)?;
            let mut compressed = u64::from(u32_at(&cd, at + 20)?);
            let mut size = u64::from(u32_at(&cd, at + 24)?);
            let name_len = usize::from(u16_at(&cd, at + 28)?);
            let extra_len = usize::from(u16_at(&cd, at + 30)?);
            let comment_len = usize::from(u16_at(&cd, at + 32)?);
            let mut header = u64::from(u32_at(&cd, at + 42)?);
            let name_at = at + 46;
            let name = cd
                .get(name_at..name_at + name_len)
                .ok_or_else(|| bad("truncated name"))?;
            let extra = cd
                .get(name_at + name_len..name_at + name_len + extra_len)
                .ok_or_else(|| bad("truncated extra field"))?;
            // ZIP64: the fields at their maximum are in the 0x0001 extra field, in order.
            let mut e = 0;
            while e + 4 <= extra.len() {
                let id = u16_at(extra, e)?;
                let data_len = usize::from(u16_at(extra, e + 2)?);
                if id == 0x0001 {
                    let mut f = e + 4;
                    for field in [&mut size, &mut compressed, &mut header] {
                        if *field == 0xFFFF_FFFF {
                            *field = u64_at(extra, f)?;
                            f += 8;
                        }
                    }
                }
                e += 4 + data_len;
            }
            at = name_at + name_len + extra_len + comment_len;
            let name = std::str::from_utf8(name).map_err(|_| bad("member name is not UTF-8"))?;
            if !keep(name) {
                continue;
            }
            if flags & 0x1 != 0 {
                return Err(bad("encrypted member"));
            }
            let deflated = match method {
                0 => false,
                8 => true,
                _ => return Err(bad("unsupported compression method")),
            };
            members.push(Member {
                header,
                compressed,
                size,
                crc,
                deflated,
            });
        }
        Ok(Archive { file, members })
    }

    /// Members kept.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Member `i`'s contents, checked against its size and CRC-32.
    ///
    /// # Errors
    ///
    /// The member cannot be read, does not inflate, or fails its size or checksum.
    pub fn read(&self, i: usize) -> io::Result<Vec<u8>> {
        let m = self.members.get(i).ok_or_else(|| bad("no such member"))?;
        let local = read_vec(&self.file, m.header, 30)?;
        if u32_at(&local, 0)? != LOCAL {
            return Err(bad("bad local header"));
        }
        let data_at =
            m.header + 30 + u64::from(u16_at(&local, 26)?) + u64::from(u16_at(&local, 28)?);
        let raw = read_vec(&self.file, data_at, m.compressed)?;
        let capacity = usize::try_from(m.size).map_err(|_| bad("member too large"))?;
        let body = if m.deflated {
            let mut out = Vec::with_capacity(capacity);
            flate2::read::DeflateDecoder::new(&raw[..])
                .take(m.size + 1)
                .read_to_end(&mut out)?;
            out
        } else {
            raw
        };
        if body.len() as u64 != m.size {
            return Err(bad("member size does not match"));
        }
        if crc32fast::hash(&body) != m.crc {
            return Err(bad("member checksum does not match"));
        }
        Ok(body)
    }

    /// Member `i` as UTF-8 text.
    ///
    /// # Errors
    ///
    /// As [`Archive::read`], or the member is not UTF-8.
    pub fn read_string(&self, i: usize) -> io::Result<String> {
        String::from_utf8(self.read(i)?).map_err(|_| bad("member is not UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::io::Write;

    fn write_zip(path: &Path, members: &[(String, Vec<u8>, bool)]) {
        let file = File::create(path).unwrap();
        let mut w = zip::ZipWriter::new(file);
        for (name, body, deflate) in members {
            let method = if *deflate {
                zip::CompressionMethod::Deflated
            } else {
                zip::CompressionMethod::Stored
            };
            let opts = zip::write::SimpleFileOptions::default().compression_method(method);
            w.start_file(name.as_str(), opts).unwrap();
            w.write_all(body).unwrap();
        }
        w.finish().unwrap();
    }

    #[test]
    fn reads_what_the_zip_crate_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.zip");
        let members = vec![
            ("a.json".to_string(), b"{\"id\":\"A\"}".to_vec(), true),
            ("dir/".to_string(), Vec::new(), false),
            ("b.json".to_string(), vec![b'x'; 100_000], false),
            ("c.json".to_string(), "é".repeat(5000).into_bytes(), true),
        ];
        write_zip(&path, &members);
        let all = Archive::open(&path, |_| true).unwrap();
        assert_eq!(all.len(), 4);
        for (i, (_, body, _)) in members.iter().enumerate() {
            assert_eq!(&all.read(i).unwrap(), body);
        }
        let json = Archive::open(&path, |n| n.ends_with(".json")).unwrap();
        assert_eq!(json.len(), 3);
        assert_eq!(json.read_string(2).unwrap(), "é".repeat(5000));
    }

    #[test]
    fn more_members_than_a_classic_zip_holds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.zip");
        let members: Vec<(String, Vec<u8>, bool)> = (0..70_000)
            .map(|i| (format!("{i}.json"), i.to_string().into_bytes(), i % 2 == 0))
            .collect();
        write_zip(&path, &members);
        let a = Archive::open(&path, |_| true).unwrap();
        assert_eq!(a.len(), 70_000);
        assert_eq!(a.read_string(69_999).unwrap(), "69999");
        assert_eq!(a.read_string(12_344).unwrap(), "12344");
    }

    #[test]
    fn damage_is_an_error_never_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.zip");
        write_zip(
            &path,
            &[
                ("a.json".to_string(), b"{\"id\":\"A\"}".repeat(20), true),
                ("b.json".to_string(), b"plain".to_vec(), false),
            ],
        );
        let good = std::fs::read(&path).unwrap();
        let damaged = dir.path().join("d.zip");
        let mut caught = 0;
        for at in 0..good.len() {
            let mut b = good.clone();
            b[at] ^= 0x55;
            std::fs::write(&damaged, &b).unwrap();
            if let Ok(a) = Archive::open(&damaged, |_| true) {
                for i in 0..a.len() {
                    match a.read(i) {
                        Ok(body) => assert!(
                            body == good_body(i),
                            "byte {at} changed member {i} without an error"
                        ),
                        Err(_) => caught += 1,
                    }
                }
            } else {
                caught += 1;
            }
        }
        assert!(caught > 0);
        for cut in 0..good.len() {
            std::fs::write(&damaged, &good[..cut]).unwrap();
            if let Ok(a) = Archive::open(&damaged, |_| true) {
                for i in 0..a.len() {
                    let _ = a.read(i);
                }
            }
        }
    }

    fn good_body(i: usize) -> Vec<u8> {
        if i == 0 {
            b"{\"id\":\"A\"}".repeat(20)
        } else {
            b"plain".to_vec()
        }
    }
}
