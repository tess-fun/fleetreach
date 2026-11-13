//! The PE image, the CLI header and the ECMA-335 metadata: streams and tables (partition II,
//! sections 24 and 25). Every table is sized, so a table this crate never reads still moves the
//! next one to the right place; anything out of bounds is an error, never a guess.

use crate::ClrError;

/// Metadata tables by number (ECMA-335 II.22).
pub(crate) mod table {
    pub const MODULE: usize = 0x00;
    pub const TYPE_REF: usize = 0x01;
    pub const TYPE_DEF: usize = 0x02;
    pub const FIELD_PTR: usize = 0x03;
    pub const FIELD: usize = 0x04;
    pub const METHOD_PTR: usize = 0x05;
    pub const METHOD_DEF: usize = 0x06;
    pub const PARAM_PTR: usize = 0x07;
    pub const PARAM: usize = 0x08;
    pub const INTERFACE_IMPL: usize = 0x09;
    pub const MEMBER_REF: usize = 0x0A;
    pub const CONSTANT: usize = 0x0B;
    pub const CUSTOM_ATTRIBUTE: usize = 0x0C;
    pub const FIELD_MARSHAL: usize = 0x0D;
    pub const DECL_SECURITY: usize = 0x0E;
    pub const CLASS_LAYOUT: usize = 0x0F;
    pub const FIELD_LAYOUT: usize = 0x10;
    pub const STAND_ALONE_SIG: usize = 0x11;
    pub const EVENT_MAP: usize = 0x12;
    pub const EVENT_PTR: usize = 0x13;
    pub const EVENT: usize = 0x14;
    pub const PROPERTY_MAP: usize = 0x15;
    pub const PROPERTY_PTR: usize = 0x16;
    pub const PROPERTY: usize = 0x17;
    pub const METHOD_SEMANTICS: usize = 0x18;
    pub const METHOD_IMPL: usize = 0x19;
    pub const MODULE_REF: usize = 0x1A;
    pub const TYPE_SPEC: usize = 0x1B;
    pub const IMPL_MAP: usize = 0x1C;
    pub const FIELD_RVA: usize = 0x1D;
    pub const ENC_LOG: usize = 0x1E;
    pub const ENC_MAP: usize = 0x1F;
    pub const ASSEMBLY: usize = 0x20;
    pub const ASSEMBLY_PROCESSOR: usize = 0x21;
    pub const ASSEMBLY_OS: usize = 0x22;
    pub const ASSEMBLY_REF: usize = 0x23;
    pub const ASSEMBLY_REF_PROCESSOR: usize = 0x24;
    pub const ASSEMBLY_REF_OS: usize = 0x25;
    pub const FILE: usize = 0x26;
    pub const EXPORTED_TYPE: usize = 0x27;
    pub const MANIFEST_RESOURCE: usize = 0x28;
    pub const NESTED_CLASS: usize = 0x29;
    pub const GENERIC_PARAM: usize = 0x2A;
    pub const METHOD_SPEC: usize = 0x2B;
    pub const GENERIC_PARAM_CONSTRAINT: usize = 0x2C;
    /// One past the last table an assembly may hold (0x30 and up are portable PDB tables).
    pub const COUNT: usize = 0x2D;
}

/// Coded indexes (II.24.2.6): the tables each can point into, in tag order. `None` is a tag
/// the standard leaves unused.
pub(crate) mod coded {
    use super::table::*;
    pub const TYPE_DEF_OR_REF: &[Option<usize>] =
        &[Some(TYPE_DEF), Some(TYPE_REF), Some(TYPE_SPEC)];
    pub const HAS_CONSTANT: &[Option<usize>] = &[Some(FIELD), Some(PARAM), Some(PROPERTY)];
    pub const HAS_CUSTOM_ATTRIBUTE: &[Option<usize>] = &[
        Some(METHOD_DEF),
        Some(FIELD),
        Some(TYPE_REF),
        Some(TYPE_DEF),
        Some(PARAM),
        Some(INTERFACE_IMPL),
        Some(MEMBER_REF),
        Some(MODULE),
        Some(DECL_SECURITY),
        Some(PROPERTY),
        Some(EVENT),
        Some(STAND_ALONE_SIG),
        Some(MODULE_REF),
        Some(TYPE_SPEC),
        Some(ASSEMBLY),
        Some(ASSEMBLY_REF),
        Some(FILE),
        Some(EXPORTED_TYPE),
        Some(MANIFEST_RESOURCE),
        Some(GENERIC_PARAM),
        Some(GENERIC_PARAM_CONSTRAINT),
        Some(METHOD_SPEC),
    ];
    pub const HAS_FIELD_MARSHAL: &[Option<usize>] = &[Some(FIELD), Some(PARAM)];
    pub const HAS_DECL_SECURITY: &[Option<usize>] =
        &[Some(TYPE_DEF), Some(METHOD_DEF), Some(ASSEMBLY)];
    pub const MEMBER_REF_PARENT: &[Option<usize>] = &[
        Some(TYPE_DEF),
        Some(TYPE_REF),
        Some(MODULE_REF),
        Some(METHOD_DEF),
        Some(TYPE_SPEC),
    ];
    pub const HAS_SEMANTICS: &[Option<usize>] = &[Some(EVENT), Some(PROPERTY)];
    pub const METHOD_DEF_OR_REF: &[Option<usize>] = &[Some(METHOD_DEF), Some(MEMBER_REF)];
    pub const MEMBER_FORWARDED: &[Option<usize>] = &[Some(FIELD), Some(METHOD_DEF)];
    pub const IMPLEMENTATION: &[Option<usize>] =
        &[Some(FILE), Some(ASSEMBLY_REF), Some(EXPORTED_TYPE)];
    pub const CUSTOM_ATTRIBUTE_TYPE: &[Option<usize>] =
        &[None, None, Some(METHOD_DEF), Some(MEMBER_REF), None];
    pub const RESOLUTION_SCOPE: &[Option<usize>] = &[
        Some(MODULE),
        Some(MODULE_REF),
        Some(ASSEMBLY_REF),
        Some(TYPE_REF),
    ];
    pub const TYPE_OR_METHOD_DEF: &[Option<usize>] = &[Some(TYPE_DEF), Some(METHOD_DEF)];
}

/// One column's kind, which fixes its width.
#[derive(Clone, Copy)]
enum Col {
    U8,
    U16,
    U32,
    Str,
    Guid,
    Blob,
    /// A plain index into the table.
    Table(usize),
    Coded(&'static [Option<usize>]),
}

/// The columns of every table an assembly may hold, in order (II.22).
fn schema(t: usize) -> &'static [Col] {
    use coded::*;
    use table::*;
    use Col::{Blob, Coded, Guid, Str, Table, U16, U32, U8};
    match t {
        MODULE => &[U16, Str, Guid, Guid, Guid],
        TYPE_REF => &[Coded(RESOLUTION_SCOPE), Str, Str],
        TYPE_DEF => &[
            U32,
            Str,
            Str,
            Coded(TYPE_DEF_OR_REF),
            Table(FIELD),
            Table(METHOD_DEF),
        ],
        FIELD_PTR => &[Table(FIELD)],
        FIELD => &[U16, Str, Blob],
        METHOD_PTR => &[Table(METHOD_DEF)],
        METHOD_DEF => &[U32, U16, U16, Str, Blob, Table(PARAM)],
        PARAM_PTR => &[Table(PARAM)],
        PARAM => &[U16, U16, Str],
        INTERFACE_IMPL => &[Table(TYPE_DEF), Coded(TYPE_DEF_OR_REF)],
        MEMBER_REF => &[Coded(MEMBER_REF_PARENT), Str, Blob],
        CONSTANT => &[U8, U8, Coded(HAS_CONSTANT), Blob],
        CUSTOM_ATTRIBUTE => &[
            Coded(HAS_CUSTOM_ATTRIBUTE),
            Coded(CUSTOM_ATTRIBUTE_TYPE),
            Blob,
        ],
        FIELD_MARSHAL => &[Coded(HAS_FIELD_MARSHAL), Blob],
        DECL_SECURITY => &[U16, Coded(HAS_DECL_SECURITY), Blob],
        CLASS_LAYOUT => &[U16, U32, Table(TYPE_DEF)],
        FIELD_LAYOUT => &[U32, Table(FIELD)],
        STAND_ALONE_SIG => &[Blob],
        EVENT_MAP => &[Table(TYPE_DEF), Table(EVENT)],
        EVENT_PTR => &[Table(EVENT)],
        EVENT => &[U16, Str, Coded(TYPE_DEF_OR_REF)],
        PROPERTY_MAP => &[Table(TYPE_DEF), Table(PROPERTY)],
        PROPERTY_PTR => &[Table(PROPERTY)],
        PROPERTY => &[U16, Str, Blob],
        METHOD_SEMANTICS => &[U16, Table(METHOD_DEF), Coded(HAS_SEMANTICS)],
        METHOD_IMPL => &[
            Table(TYPE_DEF),
            Coded(METHOD_DEF_OR_REF),
            Coded(METHOD_DEF_OR_REF),
        ],
        MODULE_REF => &[Str],
        TYPE_SPEC => &[Blob],
        IMPL_MAP => &[U16, Coded(MEMBER_FORWARDED), Str, Table(MODULE_REF)],
        FIELD_RVA => &[U32, Table(FIELD)],
        ENC_LOG => &[U32, U32],
        ENC_MAP => &[U32],
        ASSEMBLY => &[U32, U16, U16, U16, U16, U32, Blob, Str, Str],
        ASSEMBLY_PROCESSOR => &[U32],
        ASSEMBLY_OS => &[U32, U32, U32],
        ASSEMBLY_REF => &[U16, U16, U16, U16, U32, Blob, Str, Str, Blob],
        ASSEMBLY_REF_PROCESSOR => &[U32, Table(ASSEMBLY_REF)],
        ASSEMBLY_REF_OS => &[U32, U32, U32, Table(ASSEMBLY_REF)],
        FILE => &[U32, Str, Blob],
        EXPORTED_TYPE => &[U32, U32, Str, Str, Coded(IMPLEMENTATION)],
        MANIFEST_RESOURCE => &[U32, U32, Str, Coded(IMPLEMENTATION)],
        NESTED_CLASS => &[Table(TYPE_DEF), Table(TYPE_DEF)],
        GENERIC_PARAM => &[U16, U16, Coded(TYPE_OR_METHOD_DEF), Str],
        METHOD_SPEC => &[Coded(METHOD_DEF_OR_REF), Blob],
        GENERIC_PARAM_CONSTRAINT => &[Table(GENERIC_PARAM), Coded(TYPE_DEF_OR_REF)],
        _ => &[],
    }
}

/// Little-endian reads that fail instead of panicking.
pub(crate) fn u8_at(b: &[u8], at: usize) -> Result<u8, ClrError> {
    b.get(at).copied().ok_or(ClrError::Truncated("byte"))
}
pub(crate) fn u16_at(b: &[u8], at: usize) -> Result<u16, ClrError> {
    let s = b.get(at..at + 2).ok_or(ClrError::Truncated("u16"))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
pub(crate) fn u32_at(b: &[u8], at: usize) -> Result<u32, ClrError> {
    let s = b.get(at..at + 4).ok_or(ClrError::Truncated("u32"))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

struct Section {
    rva: u32,
    size: u32,
    offset: u32,
    raw: u32,
}

/// A table: where its rows start, how many there are, and each column's offset and width.
#[derive(Default, Clone)]
struct Table {
    start: usize,
    rows: u32,
    row_size: usize,
    cols: Vec<(usize, usize)>,
}

/// A parsed assembly image: the PE sections and the metadata, borrowed from the file bytes.
pub struct Image<'a> {
    bytes: &'a [u8],
    sections: Vec<Section>,
    strings: &'a [u8],
    blobs: &'a [u8],
    user_strings: &'a [u8],
    table_bytes: &'a [u8],
    tables: Vec<Table>,
    /// The `#-` (uncompressed) stream: the `*Ptr` indirection tables may be present.
    pub(crate) uncompressed: bool,
    pub(crate) entry_point: u32,
}

impl<'a> Image<'a> {
    /// Parse the PE headers, the CLI header and the metadata tables.
    ///
    /// # Errors
    ///
    /// [`ClrError`] when the file is not a .NET assembly or any part lies outside it.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ClrError> {
        if bytes.get(..2) != Some(b"MZ") {
            return Err(ClrError::NotPe);
        }
        let pe = u32_at(bytes, 0x3C)? as usize;
        if bytes.get(pe..pe + 4) != Some(b"PE\0\0") {
            return Err(ClrError::NotPe);
        }
        let coff = pe + 4;
        let section_count = u16_at(bytes, coff + 2)? as usize;
        let optional_size = u16_at(bytes, coff + 16)? as usize;
        let optional = coff + 20;
        let dirs = match u16_at(bytes, optional)? {
            0x10b => optional + 96,
            0x20b => optional + 112,
            _ => return Err(ClrError::NotPe),
        };
        let dir_count = u32_at(bytes, dirs - 4)? as usize;
        if dir_count < 15 {
            return Err(ClrError::NotDotNet);
        }
        let cli_rva = u32_at(bytes, dirs + 14 * 8)?;
        if cli_rva == 0 {
            return Err(ClrError::NotDotNet);
        }
        let mut sections = Vec::with_capacity(section_count);
        let table_at = optional + optional_size;
        for i in 0..section_count {
            let s = table_at + i * 40;
            sections.push(Section {
                size: u32_at(bytes, s + 8)?,
                rva: u32_at(bytes, s + 12)?,
                raw: u32_at(bytes, s + 16)?,
                offset: u32_at(bytes, s + 20)?,
            });
        }
        let mut image = Image {
            bytes,
            sections,
            strings: &[],
            blobs: &[],
            user_strings: &[],
            table_bytes: &[],
            tables: Vec::new(),
            uncompressed: false,
            entry_point: 0,
        };
        let cli = image.offset(cli_rva)?;
        let meta_rva = u32_at(bytes, cli + 8)?;
        let meta_size = u32_at(bytes, cli + 12)? as usize;
        image.entry_point = u32_at(bytes, cli + 20)?;
        let meta = image.offset(meta_rva)?;
        let meta = bytes
            .get(meta..meta + meta_size)
            .ok_or(ClrError::Truncated("metadata"))?;
        image.streams(meta)?;
        Ok(image)
    }

    /// The file offset of an RVA.
    pub(crate) fn offset(&self, rva: u32) -> Result<usize, ClrError> {
        for s in &self.sections {
            let span = s.size.max(s.raw);
            if rva >= s.rva && rva - s.rva < span {
                let within = rva - s.rva;
                if within >= s.raw {
                    break; // zero-filled, not in the file
                }
                return Ok((s.offset + within) as usize);
            }
        }
        Err(ClrError::BadRva(rva))
    }

    pub(crate) fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    fn streams(&mut self, meta: &'a [u8]) -> Result<(), ClrError> {
        if u32_at(meta, 0)? != 0x424A_5342 {
            return Err(ClrError::NotDotNet);
        }
        let version_len = u32_at(meta, 12)? as usize;
        let mut at = 16 + version_len;
        let count = u16_at(meta, at + 2)? as usize;
        at += 4;
        let mut tables: Option<&'a [u8]> = None;
        for _ in 0..count {
            let offset = u32_at(meta, at)? as usize;
            let size = u32_at(meta, at + 4)? as usize;
            let name_at = at + 8;
            let name_len = meta
                .get(name_at..)
                .and_then(|rest| rest.iter().take(32).position(|&b| b == 0))
                .ok_or(ClrError::Truncated("stream name"))?;
            let name = &meta[name_at..name_at + name_len];
            at = name_at + (name_len + 4) / 4 * 4;
            let data = meta
                .get(offset..offset + size)
                .ok_or(ClrError::Truncated("stream"))?;
            match name {
                b"#~" => tables = Some(data),
                b"#-" => {
                    tables = Some(data);
                    self.uncompressed = true;
                }
                b"#Strings" => self.strings = data,
                b"#Blob" => self.blobs = data,
                b"#US" => self.user_strings = data,
                _ => {}
            }
        }
        let tables = tables.ok_or(ClrError::NotDotNet)?;
        self.tables(tables)
    }

    fn tables(&mut self, s: &'a [u8]) -> Result<(), ClrError> {
        let heap_sizes = u8_at(s, 6)?;
        let valid = u64::from(u32_at(s, 8)?) | (u64::from(u32_at(s, 12)?) << 32);
        if valid >> table::COUNT != 0 {
            return Err(ClrError::UnknownTable(valid));
        }
        let mut rows = [0u32; table::COUNT];
        let mut at = 24;
        for (t, row) in rows.iter_mut().enumerate() {
            if valid & (1 << t) != 0 {
                *row = u32_at(s, at)?;
                at += 4;
            }
        }
        if heap_sizes & 0x40 != 0 {
            at += 4; // extra data in an uncompressed stream
        }
        let str_w = if heap_sizes & 1 != 0 { 4 } else { 2 };
        let guid_w = if heap_sizes & 2 != 0 { 4 } else { 2 };
        let blob_w = if heap_sizes & 4 != 0 { 4 } else { 2 };
        let width = |col: Col| -> usize {
            match col {
                Col::U8 => 1,
                Col::U16 => 2,
                Col::U32 => 4,
                Col::Str => str_w,
                Col::Guid => guid_w,
                Col::Blob => blob_w,
                Col::Table(t) => {
                    if rows[t] < 1 << 16 {
                        2
                    } else {
                        4
                    }
                }
                Col::Coded(targets) => {
                    let bits = tag_bits(targets.len());
                    let max = targets
                        .iter()
                        .flatten()
                        .map(|&t| rows[t])
                        .max()
                        .unwrap_or(0);
                    if max < 1 << (16 - bits) {
                        2
                    } else {
                        4
                    }
                }
            }
        };
        self.tables = vec![Table::default(); table::COUNT];
        #[allow(clippy::needless_range_loop)]
        for t in 0..table::COUNT {
            if rows[t] == 0 {
                continue;
            }
            let mut cols = Vec::new();
            let mut row_size = 0;
            for &col in schema(t) {
                let w = width(col);
                cols.push((row_size, w));
                row_size += w;
            }
            let len = row_size * rows[t] as usize;
            if s.len() < at + len {
                return Err(ClrError::Truncated("table"));
            }
            self.tables[t] = Table {
                start: at,
                rows: rows[t],
                row_size,
                cols,
            };
            at += len;
        }
        // The table stream itself, kept through the image's lifetime.
        self.table_bytes = s;
        Ok(())
    }

    /// Rows in table `t`.
    pub(crate) fn rows(&self, t: usize) -> u32 {
        self.tables.get(t).map_or(0, |t| t.rows)
    }

    /// Column `col` of row `row` (1-based, as tokens count) in table `t`.
    pub(crate) fn cell(&self, t: usize, row: u32, col: usize) -> Result<u32, ClrError> {
        let table = self.tables.get(t).ok_or(ClrError::BadToken(t, row))?;
        if row == 0 || row > table.rows {
            return Err(ClrError::BadToken(t, row));
        }
        let &(offset, width) = table.cols.get(col).ok_or(ClrError::BadToken(t, row))?;
        let at = table.start + (row as usize - 1) * table.row_size + offset;
        Ok(match width {
            1 => u32::from(u8_at(self.table_bytes, at)?),
            2 => u32::from(u16_at(self.table_bytes, at)?),
            _ => u32_at(self.table_bytes, at)?,
        })
    }

    /// A `#Strings` entry: UTF-8 up to its NUL.
    pub(crate) fn string(&self, index: u32) -> Result<&'a str, ClrError> {
        let rest = self
            .strings
            .get(index as usize..)
            .ok_or(ClrError::Truncated("string"))?;
        let end = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(ClrError::Truncated("string"))?;
        std::str::from_utf8(&rest[..end]).map_err(|_| ClrError::BadString(index))
    }

    /// A `#Blob` entry, without its length prefix.
    pub(crate) fn blob(&self, index: u32) -> Result<&'a [u8], ClrError> {
        heap_entry(self.blobs, index)
    }

    /// A `#US` entry (a string literal) as text: UTF-16LE, without the trailing flag byte.
    pub(crate) fn user_string(&self, index: u32) -> Result<String, ClrError> {
        let raw = heap_entry(self.user_strings, index)?;
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        Ok(String::from_utf16_lossy(&units))
    }
}

/// Bits a coded index spends on its tag.
fn tag_bits(tables: usize) -> u32 {
    usize::BITS - (tables.saturating_sub(1)).leading_zeros()
}

/// A coded index as (table, row); `None` for a null index (row 0).
pub(crate) fn decode(
    targets: &[Option<usize>],
    value: u32,
) -> Result<Option<(usize, u32)>, ClrError> {
    let bits = tag_bits(targets.len());
    let tag = (value & ((1 << bits) - 1)) as usize;
    let row = value >> bits;
    if row == 0 {
        return Ok(None);
    }
    match targets.get(tag) {
        Some(Some(t)) => Ok(Some((*t, row))),
        _ => Err(ClrError::BadCodedIndex(value)),
    }
}

/// A compressed unsigned integer (II.23.2) at the front of `b`, and the bytes it took.
pub(crate) fn compressed(b: &[u8]) -> Result<(u32, usize), ClrError> {
    let first = *b.first().ok_or(ClrError::Truncated("compressed integer"))?;
    if first & 0x80 == 0 {
        Ok((u32::from(first), 1))
    } else if first & 0xC0 == 0x80 {
        let second = *b.get(1).ok_or(ClrError::Truncated("compressed integer"))?;
        Ok(((u32::from(first & 0x3F) << 8) | u32::from(second), 2))
    } else if first & 0xE0 == 0xC0 {
        let rest = b
            .get(1..4)
            .ok_or(ClrError::Truncated("compressed integer"))?;
        Ok((
            (u32::from(first & 0x1F) << 24)
                | (u32::from(rest[0]) << 16)
                | (u32::from(rest[1]) << 8)
                | u32::from(rest[2]),
            4,
        ))
    } else {
        Err(ClrError::Truncated("compressed integer"))
    }
}

fn heap_entry(heap: &[u8], index: u32) -> Result<&[u8], ClrError> {
    let rest = heap
        .get(index as usize..)
        .ok_or(ClrError::Truncated("blob"))?;
    let (len, used) = compressed(rest)?;
    rest.get(used..used + len as usize)
        .ok_or(ClrError::Truncated("blob"))
}
