//! Berkeley DB hash databases: rpm's `Packages` before rpm 4.16 (RHEL 7 and 8, CentOS 7,
//! Amazon Linux 2). Read-only, from the page layout (Berkeley DB's `db_page.h`): every hash
//! bucket page holds key/data pairs; a data item is either inline (`H_KEYDATA`) or a chain of
//! overflow pages (`H_OFFPAGE`). Keys are rpm's 4-byte header numbers; key 0 is rpm's own
//! bookkeeping, not a package.
//!
//! Only pages a hash bucket reaches are read, so free pages that still hold old headers
//! (common after package removals) are never mistaken for installed packages.

use std::collections::BTreeSet;

const HASH_MAGIC: u32 = 0x0006_1561;
const P_HASH_UNSORTED: u8 = 2;
const P_OVERFLOW: u8 = 7;
const P_HASHMETA: u8 = 8;
const P_HASH: u8 = 13;
const H_KEYDATA: u8 = 1;
const H_OFFPAGE: u8 = 3;
/// Generic page header size.
const PAGE_HEADER: usize = 26;

struct File<'a> {
    b: &'a [u8],
    little: bool,
    page_size: usize,
}

impl File<'_> {
    fn u32(&self, at: usize) -> Result<u32, String> {
        let s = self
            .b
            .get(at..at + 4)
            .ok_or("read past the end of the file")?;
        let a = [s[0], s[1], s[2], s[3]];
        Ok(if self.little {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }

    fn u16(&self, at: usize) -> Result<u16, String> {
        let s = self
            .b
            .get(at..at + 2)
            .ok_or("read past the end of the file")?;
        let a = [s[0], s[1]];
        Ok(if self.little {
            u16::from_le_bytes(a)
        } else {
            u16::from_be_bytes(a)
        })
    }

    fn page(&self, n: u32) -> Result<&[u8], String> {
        let start = (n as usize)
            .checked_mul(self.page_size)
            .ok_or("page number overflows")?;
        self.b
            .get(start..start + self.page_size)
            .ok_or_else(|| format!("page {n} is past the end of the file"))
    }
}

/// The data items (package header blobs) of every key but 0.
pub fn blobs(b: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if b.len() < 512 {
        return Err("too short for a Berkeley DB file".into());
    }
    let magic_le = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
    let magic_be = u32::from_be_bytes([b[12], b[13], b[14], b[15]]);
    let little = match (magic_le, magic_be) {
        (HASH_MAGIC, _) => true,
        (_, HASH_MAGIC) => false,
        _ => return Err("not a Berkeley DB hash database".into()),
    };
    let mut f = File {
        b,
        little,
        page_size: 0,
    };
    let page_size = f.u32(20)? as usize;
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(format!("page size {page_size} is not valid"));
    }
    f.page_size = page_size;
    if b[25] != P_HASHMETA {
        return Err("the first page is not hash metadata".into());
    }
    if b[24] != 0 {
        return Err("the database is encrypted".into());
    }
    let last = f.u32(32)?;
    if (last as usize + 1) * page_size > b.len() {
        return Err("the file is shorter than its metadata says".into());
    }

    let mut out = Vec::new();
    let mut overflow_seen = BTreeSet::new();
    for n in 1..=last {
        let page = f.page(n)?;
        if !matches!(page[25], P_HASH | P_HASH_UNSORTED) {
            continue;
        }
        let base = n as usize * page_size;
        let entries = usize::from(f.u16(base + 20)?);
        if entries % 2 != 0 || PAGE_HEADER + 2 * entries > page_size {
            return Err(format!(
                "page {n}: {entries} entries do not make key/data pairs"
            ));
        }
        let offset = |i: usize| -> Result<usize, String> {
            let o = usize::from(f.u16(base + PAGE_HEADER + 2 * i)?);
            if o < PAGE_HEADER + 2 * entries || o >= page_size {
                return Err(format!("page {n}: item {i} is outside the page"));
            }
            Ok(o)
        };
        // Items are stored from the end of the page down: item i ends where item i-1 starts.
        let end = |i: usize| -> Result<usize, String> {
            if i == 0 {
                Ok(page_size)
            } else {
                offset(i - 1)
            }
        };
        for pair in 0..entries / 2 {
            let (k, d) = (2 * pair, 2 * pair + 1);
            let (ko, ke) = (offset(k)?, end(k)?);
            if ke <= ko {
                return Err(format!("page {n}: key {pair} has a negative length"));
            }
            let key = &page[ko..ke];
            if key[0] != H_KEYDATA {
                return Err(format!("page {n}: key {pair} is not inline"));
            }
            if key[1..].iter().all(|&x| x == 0) {
                continue; // rpm's key 0
            }
            let (dofs, dend) = (offset(d)?, end(d)?);
            if dend <= dofs {
                return Err(format!("page {n}: item {pair} has a negative length"));
            }
            let item = &page[dofs..dend];
            match item[0] {
                H_KEYDATA => out.push(item[1..].to_vec()),
                H_OFFPAGE => {
                    if item.len() < 12 {
                        return Err(format!("page {n}: off-page item {pair} is truncated"));
                    }
                    let first = f.u32(base + dofs + 4)?;
                    let total = f.u32(base + dofs + 8)? as usize;
                    out.push(overflow(&f, first, total, &mut overflow_seen)?);
                }
                t => return Err(format!("page {n}: item {pair} has type {t}, not a header")),
            }
        }
    }
    Ok(out)
}

/// The `total` bytes stored on the overflow chain starting at `first`.
fn overflow(
    f: &File,
    first: u32,
    total: usize,
    seen: &mut BTreeSet<u32>,
) -> Result<Vec<u8>, String> {
    if total > f.b.len() {
        return Err("an off-page item is longer than the file".into());
    }
    let mut out = Vec::with_capacity(total);
    let mut n = first;
    while out.len() < total {
        if n == 0 || !seen.insert(n) {
            return Err(format!("overflow page {n} is missing or shared"));
        }
        let page = f.page(n)?;
        if page[25] != P_OVERFLOW {
            return Err(format!("page {n} is not an overflow page"));
        }
        let base = n as usize * f.page_size;
        // On overflow pages the free-area offset holds the length of the data on the page.
        let len = usize::from(f.u16(base + 22)?);
        let data = page
            .get(PAGE_HEADER..PAGE_HEADER + len)
            .ok_or_else(|| format!("overflow page {n} claims more data than it holds"))?;
        out.extend_from_slice(data);
        n = f.u32(base + 16)?;
    }
    if out.len() != total {
        return Err("an overflow chain is longer than its item".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::blobs;

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/rpmdb/db-bdb/Packages");

    #[test]
    fn reads_the_fixture_and_survives_every_single_byte_corruption() {
        assert_eq!(blobs(FIXTURE).map(|b| b.len()), Ok(3));
        for i in 0..FIXTURE.len() {
            let mut b = FIXTURE.to_vec();
            b[i] ^= 0x5a;
            let _ = blobs(&b);
        }
    }
}
