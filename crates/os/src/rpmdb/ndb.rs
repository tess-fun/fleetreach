//! NDB databases: rpm's own package store (`Packages.db`), the default on SUSE and openSUSE.
//! Read-only, from rpm's `lib/backend/ndb/rpmpkg.c`: a 32-byte file header, then slot pages
//! of 16-byte slots (`Slot`, package index, block offset, block count), each pointing at a
//! blob of 16-byte blocks (`BlbS` head, the header blob, an `adler32`/`BlbE` tail). All
//! integers are little-endian.
//!
//! Every blob's checksum is verified, so a torn or corrupt record is an error, not a package.

const DB_MAGIC: &[u8; 4] = b"RpmP";
const SLOT_MAGIC: &[u8; 4] = b"Slot";
const HEAD_MAGIC: &[u8; 4] = b"BlbS";
const TAIL_MAGIC: &[u8; 4] = b"BlbE";
const PAGE_SIZE: usize = 4096;
const HEADER_SIZE: usize = 32;
const SLOT_SIZE: usize = 16;
const BLK_SIZE: usize = 16;
const HEAD_SIZE: usize = 16;
const TAIL_SIZE: usize = 12;

fn le(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| "read past the end of the file".to_string())
}

/// The header blob of every used slot, in slot order.
pub fn blobs(b: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if b.get(..4) != Some(DB_MAGIC) {
        return Err("not an rpm NDB package database".into());
    }
    let version = le(b, 4)?;
    if version != 0 {
        return Err(format!("NDB version {version} is not supported"));
    }
    let slot_pages = le(b, 12)? as usize;
    let slots_end = slot_pages
        .checked_mul(PAGE_SIZE)
        .filter(|&end| end >= PAGE_SIZE && end <= b.len())
        .ok_or("the slot pages run past the end of the file")?;

    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for at in (HEADER_SIZE..slots_end).step_by(SLOT_SIZE) {
        if &b[at..at + 4] != SLOT_MAGIC {
            return Err(format!("slot at byte {at} has no slot magic"));
        }
        let pkg = le(b, at + 4)?;
        if pkg == 0 {
            continue; // a free slot
        }
        if !seen.insert(pkg) {
            return Err(format!("package {pkg} has two slots"));
        }
        let (off, count) = (le(b, at + 8)? as usize, le(b, at + 12)? as usize);
        out.push(blob(b, pkg, off, count).map_err(|e| format!("package {pkg}: {e}"))?);
    }
    Ok(out)
}

/// The header stored in the `count` blocks at block `off`, checked against its slot.
fn blob(b: &[u8], pkg: u32, off: usize, count: usize) -> Result<Vec<u8>, String> {
    let start = off.checked_mul(BLK_SIZE).ok_or("block offset overflows")?;
    let len = count.checked_mul(BLK_SIZE).ok_or("block count overflows")?;
    let region = start
        .checked_add(len)
        .and_then(|end| b.get(start..end))
        .filter(|r| r.len() >= HEAD_SIZE + TAIL_SIZE)
        .ok_or("blob runs past the end of the file")?;
    if &region[..4] != HEAD_MAGIC {
        return Err("blob has no head magic".into());
    }
    if le(region, 4)? != pkg {
        return Err("blob belongs to another package".into());
    }
    let data_len = le(region, 12)? as usize;
    if HEAD_SIZE + data_len + TAIL_SIZE > region.len() {
        return Err("blob is longer than its blocks".into());
    }
    let tail = region.len() - TAIL_SIZE;
    if &region[tail + 8..] != TAIL_MAGIC || le(region, tail + 4)? as usize != data_len {
        return Err("blob tail does not match its head".into());
    }
    // The checksum covers everything before the tail; the gap after the data is zeroed.
    if adler32(&region[..tail]) != le(region, tail)? {
        return Err("blob checksum does not match".into());
    }
    Ok(region[HEAD_SIZE..HEAD_SIZE + data_len].to_vec())
}

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let (mut a, mut b) = (1u32, 0u32);
    // 5552 bytes is the most that can be summed before `b` could overflow a u32.
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += u32::from(x);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::{adler32, blobs};

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/rpmdb/db-ndb/Packages.db");

    #[test]
    fn reads_the_fixture_and_survives_every_single_byte_corruption() {
        assert_eq!(blobs(FIXTURE).map(|b| b.len()), Ok(2));
        for i in 0..FIXTURE.len() {
            let mut b = FIXTURE.to_vec();
            b[i] ^= 0x5a;
            let _ = blobs(&b);
        }
    }

    #[test]
    fn adler32_known_values() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(adler32(&[0xff; 100_000]), {
            let (mut a, mut b) = (1u64, 0u64);
            for _ in 0..100_000 {
                a = (a + 255) % 65521;
                b = (b + a) % 65521;
            }
            u32::try_from((b << 16) | a).unwrap_or(0)
        });
    }
}
