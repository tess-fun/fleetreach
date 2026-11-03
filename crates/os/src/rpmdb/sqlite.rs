//! A read-only reader for one kind of SQLite table: a rowid table's rows, by walking its
//! b-tree. That is all an RPM database (`rpmdb.sqlite`, table `Packages(hnum INTEGER PRIMARY
//! KEY, blob BLOB)`) needs, and it keeps the reader pure Rust (linking SQLite would bring C).
//!
//! Format: <https://www.sqlite.org/fileformat2.html>. Committed frames of a write-ahead log
//! (`-wal` file) are applied over the main file, as SQLite would on open, with their salts
//! and checksums checked; frames after the last valid commit are ignored.
//!
//! Every offset and page number read from the file is bounds-checked, and the walk refuses
//! to visit a page twice or go deeper than any real b-tree, so a corrupt or hostile file is an
//! error, never a panic or a loop.

use std::collections::{BTreeMap, BTreeSet};

/// A b-tree deeper than this is corrupt (a 4 KiB-page table of billions of rows is under 10).
const MAX_DEPTH: usize = 64;

/// A database file, with any committed WAL frames applied.
pub struct Db<'a> {
    file: &'a [u8],
    page_size: usize,
    usable: usize,
    pages: usize,
    /// Pages replaced by the WAL, by page number.
    wal: BTreeMap<u32, &'a [u8]>,
}

/// One value of a record.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Int(i64),
    Float(f64),
    Text(Vec<u8>),
    Blob(Vec<u8>),
}

impl<'a> Db<'a> {
    /// Open the main file's bytes, and the WAL's if there is one (an empty WAL is none).
    pub fn open(file: &'a [u8], wal: Option<&'a [u8]>) -> Result<Self, String> {
        if file.len() < 100 || &file[..16] != b"SQLite format 3\0" {
            return Err("not an SQLite 3 database".into());
        }
        let page_size = match u16::from_be_bytes([file[16], file[17]]) {
            1 => 65536,
            n if n >= 512 && n.is_power_of_two() => usize::from(n),
            n => return Err(format!("page size {n} is not valid")),
        };
        let reserved = usize::from(file[20]);
        let usable = page_size
            .checked_sub(reserved)
            .filter(|&u| u >= 480)
            .ok_or("reserved space leaves too little of each page")?;
        if u32::from_be_bytes([file[56], file[57], file[58], file[59]]) > 1 {
            // Text in UTF-16 would need decoding; rpm never writes it.
            return Err("only UTF-8 databases are supported".into());
        }
        let mut db = Db {
            file,
            page_size,
            usable,
            pages: file.len() / page_size,
            wal: BTreeMap::new(),
        };
        if let Some(wal) = wal.filter(|w| !w.is_empty()) {
            db.apply_wal(wal)?;
        }
        Ok(db)
    }

    fn apply_wal(&mut self, wal: &'a [u8]) -> Result<(), String> {
        if wal.len() < 32 {
            return Err("write-ahead log is truncated".into());
        }
        let be = |b: &[u8], at: usize| u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        let magic = be(wal, 0);
        let big_endian = match magic {
            0x377f_0683 => true,
            0x377f_0682 => false,
            _ => return Err("write-ahead log has a bad magic number".into()),
        };
        let page_size = match be(wal, 8) {
            65536 => 65536,
            n => n as usize,
        };
        if page_size != self.page_size {
            return Err("write-ahead log page size differs from the database's".into());
        }
        let (salt1, salt2) = (be(wal, 16), be(wal, 20));
        let mut sum = checksum(big_endian, &wal[..24], (0, 0));
        if sum != (be(wal, 24), be(wal, 28)) {
            // A WAL whose header fails its checksum holds nothing SQLite would read.
            return Ok(());
        }
        let frame = 24 + page_size;
        let mut pending: BTreeMap<u32, &'a [u8]> = BTreeMap::new();
        let mut committed_pages = None;
        let mut at = 32;
        while at + frame <= wal.len() {
            let head = &wal[at..at + 24];
            let data = &wal[at + 24..at + frame];
            if be(head, 8) != salt1 || be(head, 12) != salt2 {
                break;
            }
            sum = checksum(big_endian, &head[..8], sum);
            sum = checksum(big_endian, data, sum);
            if sum != (be(head, 16), be(head, 20)) {
                break;
            }
            let page = be(head, 0);
            if page == 0 {
                break;
            }
            pending.insert(page, data);
            let db_pages = be(head, 4);
            if db_pages != 0 {
                // A commit frame: everything so far is part of the database.
                self.wal.append(&mut pending);
                committed_pages = Some(db_pages as usize);
            }
            at += frame;
        }
        if let Some(n) = committed_pages {
            self.pages = n;
        }
        Ok(())
    }

    /// Page `n` (1-based) as stored, WAL first.
    fn page(&self, n: u32) -> Result<&'a [u8], String> {
        let idx = n as usize;
        if n == 0 || idx > self.pages {
            return Err(format!("page {n} is outside the database"));
        }
        if let Some(p) = self.wal.get(&n) {
            return Ok(p);
        }
        let start = (idx - 1) * self.page_size;
        self.file
            .get(start..start + self.page_size)
            .ok_or_else(|| format!("page {n} is past the end of the file"))
    }

    /// The root page of table `name`, from `sqlite_schema`.
    pub fn table_root(&self, name: &str) -> Result<Option<u32>, String> {
        let mut root = None;
        self.scan(1, &mut |_, rec| {
            let row = record(&rec)?;
            let is =
                |i: usize, s: &str| matches!(row.get(i), Some(Value::Text(t)) if t == s.as_bytes());
            if is(0, "table") && is(1, name) {
                if let Some(Value::Int(r)) = row.get(3) {
                    root = u32::try_from(*r).ok();
                }
            }
            Ok(())
        })?;
        Ok(root)
    }

    /// Every row of the table rooted at `root`, in rowid order, as `(rowid, record bytes)`.
    pub fn scan(
        &self,
        root: u32,
        each: &mut dyn FnMut(i64, Vec<u8>) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut seen = BTreeSet::new();
        self.walk(root, 0, &mut seen, each)
    }

    fn walk(
        &self,
        n: u32,
        depth: usize,
        seen: &mut BTreeSet<u32>,
        each: &mut dyn FnMut(i64, Vec<u8>) -> Result<(), String>,
    ) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err("b-tree is deeper than any valid one".into());
        }
        if !seen.insert(n) {
            return Err(format!("page {n} is reached twice"));
        }
        let page = self.page(n)?;
        let base = if n == 1 { 100 } else { 0 };
        let kind = *page.get(base).ok_or("page header out of bounds")?;
        let cells = usize::from(read_u16(page, base + 3)?);
        let (header, interior) = match kind {
            0x0d => (8, false),
            0x05 => (12, true),
            _ => {
                return Err(format!(
                    "page {n} is not a table b-tree page (type {kind:#x})"
                ))
            }
        };
        for i in 0..cells {
            let ptr = usize::from(read_u16(page, base + header + 2 * i)?);
            if ptr >= self.usable {
                return Err(format!("page {n}: cell {i} points outside the page"));
            }
            if interior {
                let child = read_u32(page, ptr)?;
                self.walk(child, depth + 1, seen, each)?;
            } else {
                let (size, a) = varint(page, ptr)?;
                let (rowid, b) = varint(page, ptr + a)?;
                let payload = self.payload(page, ptr + a + b, size)?;
                each(rowid as i64, payload)?;
            }
        }
        if interior {
            let right = read_u32(page, base + 8)?;
            self.walk(right, depth + 1, seen, each)?;
        }
        Ok(())
    }

    /// A table leaf cell's payload of `size` bytes starting at `at`, following overflow pages.
    fn payload(&self, page: &[u8], at: usize, size: u64) -> Result<Vec<u8>, String> {
        let u = self.usable;
        let p = usize::try_from(size).map_err(|_| "payload size overflows")?;
        if p > self.file.len() + self.wal.len() * self.page_size {
            return Err("payload is larger than the database".into());
        }
        let x = u - 35;
        let local = if p <= x {
            p
        } else {
            let m = (u - 12) * 32 / 255 - 23;
            let k = m + (p - m) % (u - 4);
            if k <= x {
                k
            } else {
                m
            }
        };
        let mut out = Vec::with_capacity(p);
        out.extend_from_slice(
            page.get(at..at + local)
                .ok_or("cell payload out of bounds")?,
        );
        if local == p {
            return Ok(out);
        }
        let mut next = read_u32(page, at + local)?;
        let mut seen = BTreeSet::new();
        while out.len() < p {
            if !seen.insert(next) {
                return Err("overflow chain loops".into());
            }
            let ov = self.page(next)?;
            let take = (p - out.len()).min(u - 4);
            out.extend_from_slice(ov.get(4..4 + take).ok_or("overflow page out of bounds")?);
            next = read_u32(ov, 0)?;
        }
        Ok(out)
    }
}

/// WAL checksum over 8-byte chunks.
fn checksum(big_endian: bool, data: &[u8], (mut s0, mut s1): (u32, u32)) -> (u32, u32) {
    let word = |a: [u8; 4]| {
        if big_endian {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    };
    for &[a0, a1, a2, a3, b0, b1, b2, b3] in data.as_chunks::<8>().0 {
        s0 = s0.wrapping_add(word([a0, a1, a2, a3])).wrapping_add(s1);
        s1 = s1.wrapping_add(word([b0, b1, b2, b3])).wrapping_add(s0);
    }
    (s0, s1)
}

/// Decode a record into its values.
pub fn record(rec: &[u8]) -> Result<Vec<Value>, String> {
    let (header_len, mut at) = varint(rec, 0)?;
    let header_len = usize::try_from(header_len).map_err(|_| "record header too long")?;
    if header_len > rec.len() {
        return Err("record header runs past the record".into());
    }
    let mut types = Vec::new();
    while at < header_len {
        let (t, n) = varint(rec, at)?;
        types.push(t);
        at += n;
    }
    let mut body = header_len;
    let mut out = Vec::with_capacity(types.len());
    for t in types {
        let int = |len: usize, body: usize| -> Result<i64, String> {
            let b = rec
                .get(body..body + len)
                .ok_or("record value out of bounds")?;
            let mut v: i64 = if b[0] & 0x80 != 0 { -1 } else { 0 };
            for &byte in b {
                v = (v << 8) | i64::from(byte);
            }
            Ok(v)
        };
        let (value, len) = match t {
            0 => (Value::Null, 0),
            1..=4 => {
                let len = t as usize;
                (Value::Int(int(len, body)?), len)
            }
            5 => (Value::Int(int(6, body)?), 6),
            6 => (Value::Int(int(8, body)?), 8),
            7 => (Value::Float(f64::from_bits(int(8, body)? as u64)), 8),
            8 => (Value::Int(0), 0),
            9 => (Value::Int(1), 0),
            10 | 11 => return Err("reserved serial type in record".into()),
            n => {
                let len = usize::try_from((n - 12) / 2).map_err(|_| "value too long")?;
                let bytes = rec
                    .get(body..body + len)
                    .ok_or("record value out of bounds")?
                    .to_vec();
                (
                    if n % 2 == 0 {
                        Value::Blob(bytes)
                    } else {
                        Value::Text(bytes)
                    },
                    len,
                )
            }
        };
        out.push(value);
        body += len;
    }
    Ok(out)
}

fn read_u16(b: &[u8], at: usize) -> Result<u16, String> {
    b.get(at..at + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or_else(|| "read past the end of a page".to_string())
}

fn read_u32(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| "read past the end of a page".to_string())
}

/// SQLite's big-endian varint: up to 9 bytes, the 9th contributing all 8 bits.
fn varint(b: &[u8], at: usize) -> Result<(u64, usize), String> {
    let mut v: u64 = 0;
    for i in 0..9 {
        let byte = *b.get(at + i).ok_or("varint runs past the end")?;
        if i == 8 {
            return Ok(((v << 8) | u64::from(byte), 9));
        }
        v = (v << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Ok((v, i + 1));
        }
    }
    Err("varint too long".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        assert_eq!(varint(&[0x05], 0), Ok((5, 1)));
        assert_eq!(varint(&[0x81, 0x00], 0), Ok((128, 2)));
        assert_eq!(varint(&[0xff; 9], 0), Ok((u64::MAX, 9)));
        assert!(varint(&[0x81], 0).is_err());
    }

    #[test]
    fn records() {
        // header 4: [4, 1 (int8), 0 (null), 19 (text len 3)] then 0x7f, "abc"
        let rec = [4, 1, 0, 19, 0x7f, b'a', b'b', b'c'];
        assert_eq!(
            record(&rec),
            Ok(vec![
                Value::Int(127),
                Value::Null,
                Value::Text(b"abc".to_vec())
            ])
        );
        assert!(record(&[4, 1, 0, 19, 0x7f, b'a']).is_err());
    }

    #[test]
    fn garbage_is_an_error() {
        assert!(Db::open(b"not a database at all", None).is_err());
        let mut f = vec![0u8; 4096];
        f[..16].copy_from_slice(b"SQLite format 3\0");
        f[16] = 0x10; // 4096
        assert!(Db::open(&f, None).is_ok_and(|db| db.table_root("Packages").is_err()));
    }
}
