//! An installed package's RPM header, as the rpm database stores it: a header blob without
//! the on-disk magic (`il`, `dl`, `il` index entries of 16 bytes, then `dl` bytes of data).
//! Only the tags that identify a package are read.

use super::RpmPackage;

const NAME: i32 = 1000;
const VERSION: i32 = 1001;
const RELEASE: i32 = 1002;
const EPOCH: i32 = 1003;
const ARCH: i32 = 1022;
const SOURCERPM: i32 = 1044;
const MODULARITYLABEL: i32 = 5096;

const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;
const TYPE_STRING_ARRAY: u32 = 8;
const TYPE_I18NSTRING: u32 = 9;

/// A header holding more entries than this is corrupt (real ones have a few hundred).
const MAX_ENTRIES: usize = 1 << 16;

/// The package a header blob describes. `Ok(None)` for a header with no name (not a package).
pub fn parse(blob: &[u8]) -> Result<Option<RpmPackage>, String> {
    let be = |at: usize| -> Result<u32, String> {
        blob.get(at..at + 4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| "header is truncated".to_string())
    };
    let il = be(0)? as usize;
    let dl = be(4)? as usize;
    if il == 0 || il > MAX_ENTRIES {
        return Err(format!("header claims {il} entries"));
    }
    let data_start = 8 + il * 16;
    let data = blob
        .get(data_start..data_start + dl)
        .ok_or("header data runs past the blob")?;

    let mut pkg = RpmPackage::default();
    let mut named = false;
    for i in 0..il {
        let e = 8 + i * 16;
        let tag = be(e)? as i32;
        let kind = be(e + 4)?;
        let offset = be(e + 8)? as i32;
        let count = be(e + 12)? as usize;
        let offset = usize::try_from(offset).map_err(|_| format!("tag {tag}: negative offset"))?;
        if offset > data.len() {
            return Err(format!("tag {tag}: offset outside the header data"));
        }
        let string = || -> Result<String, String> {
            if !matches!(kind, TYPE_STRING | TYPE_STRING_ARRAY | TYPE_I18NSTRING) || count == 0 {
                return Err(format!("tag {tag}: not a string"));
            }
            let rest = &data[offset..];
            let end = rest
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| format!("tag {tag}: string is not terminated"))?;
            Ok(String::from_utf8_lossy(&rest[..end]).into_owned())
        };
        match tag {
            NAME => {
                pkg.name = string()?;
                named = true;
            }
            VERSION => pkg.version = string()?,
            RELEASE => pkg.release = string()?,
            ARCH => pkg.arch = Some(string()?),
            SOURCERPM => pkg.source_rpm = Some(string()?),
            MODULARITYLABEL => pkg.modularity_label = Some(string()?),
            EPOCH => {
                if kind != TYPE_INT32 || count == 0 {
                    return Err("epoch is not an int32".into());
                }
                let b = data
                    .get(offset..offset + 4)
                    .ok_or("epoch outside the header data")?;
                pkg.epoch = Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
            }
            _ => {}
        }
    }
    Ok(named.then_some(pkg))
}
