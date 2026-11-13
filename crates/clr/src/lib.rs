//! .NET assemblies for call graphs (spec 16, row 13): an in-house ECMA-335 reader.
//!
//! Assemblies are data: the PE file is parsed, its metadata tables and IL method bodies read,
//! and nothing is loaded or run. `read` gives every type the assembly defines, with each
//! method's calls, object creations, delegate targets, string literals and static field
//! accesses, named the way the runtime's own reflection names them (`Namespace.Outer+Inner`,
//! with the generic arity suffix, as in `List` and a backtick and `1`).
//!
//! The reader is checked against .NET's own `System.Reflection.Metadata` on every method of
//! every assembly in a .NET SDK and a NuGet package cache: same types, same methods, same
//! instructions in the same order. A file outside the format (a truncated table, an opcode
//! the standard does not define, a token past its table) is an error, never a partial answer.

mod il;
mod metadata;

use std::collections::HashMap;

pub use il::Invoke;
use il::Raw;
use metadata::{coded, compressed, decode, table, Image};

#[derive(Debug, thiserror::Error)]
pub enum ClrError {
    #[error("not a PE file")]
    NotPe,
    #[error("a PE file without .NET metadata")]
    NotDotNet,
    #[error("truncated {0}")]
    Truncated(&'static str),
    #[error("RVA {0:#x} is outside every section")]
    BadRva(u32),
    #[error("metadata table {0:#x} has no row {1}")]
    BadToken(usize, u32),
    #[error("coded index {0:#x} names no table")]
    BadCodedIndex(u32),
    #[error("tables beyond the assembly set are present ({0:#x})")]
    UnknownTable(u64),
    #[error("string heap entry {0} is not UTF-8")]
    BadString(u32),
    #[error("method body at RVA {0:#x} has no valid header")]
    BadBody(u32),
    #[error("opcode {0:#x} is not defined by ECMA-335")]
    BadOpcode(u16),
}

/// A method someone calls: its declaring type and its name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Target {
    pub type_name: String,
    pub name: String,
}

/// What a method body does that matters to a call graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Invoke {
        kind: Invoke,
        target: Target,
    },
    /// A string literal, which may name a type.
    Str(String),
    /// `ldtoken` of a type (`typeof`).
    TypeToken(String),
    /// `ldtoken` of a method.
    MethodToken(Target),
    /// `ldtoken` of a field: the field's declaring type.
    FieldToken(String),
    /// A static field read or written: the declaring type is initialized.
    StaticField(String),
}

#[derive(Debug, Clone)]
pub struct Method {
    pub name: String,
    /// `MethodAttributes` (II.23.1.10).
    pub flags: u16,
    /// IL size in bytes, and the ops; `None` for a method with no body (abstract, extern,
    /// runtime-implemented).
    pub body: Option<(usize, Vec<Op>)>,
}

impl Method {
    #[must_use]
    pub fn is_static(&self) -> bool {
        self.flags & 0x0010 != 0
    }
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.flags & 0x0007 == 0x0006
    }
    #[must_use]
    pub fn is_private(&self) -> bool {
        self.flags & 0x0007 == 0x0001
    }
}

#[derive(Debug, Clone)]
pub struct Type {
    /// As reflection names it: `Namespace.Name`, `Namespace.Outer+Inner`.
    pub full_name: String,
    /// `TypeAttributes` (II.23.1.15).
    pub flags: u32,
    pub extends: Option<String>,
    pub interfaces: Vec<String>,
    pub methods: Vec<Method>,
}

#[derive(Debug, Clone)]
pub struct Assembly {
    /// The assembly's name; empty for a module without an assembly manifest.
    pub name: String,
    /// The names of the assemblies it references.
    pub references: Vec<String>,
    pub types: Vec<Type>,
}

/// Read an assembly file's types and method bodies.
///
/// # Errors
///
/// [`ClrError`] when the file is not a .NET assembly or does not follow ECMA-335.
pub fn read(bytes: &[u8]) -> Result<Assembly, ClrError> {
    let image = Image::parse(bytes)?;
    Reader::new(&image)?.assembly()
}

struct Reader<'i, 'a> {
    image: &'i Image<'a>,
    /// Reflection names of TypeDef rows (index row - 1).
    type_defs: Vec<String>,
    /// The TypeDef row owning each MethodDef row (index row - 1).
    method_owner: Vec<u32>,
    field_owner: Vec<u32>,
}

impl<'i, 'a> Reader<'i, 'a> {
    fn new(image: &'i Image<'a>) -> Result<Self, ClrError> {
        let types = image.rows(table::TYPE_DEF);
        let mut enclosing: HashMap<u32, u32> = HashMap::new();
        for row in 1..=image.rows(table::NESTED_CLASS) {
            enclosing.insert(
                image.cell(table::NESTED_CLASS, row, 0)?,
                image.cell(table::NESTED_CLASS, row, 1)?,
            );
        }
        let mut type_defs = vec![String::new(); types as usize];
        for row in 1..=types {
            type_defs[row as usize - 1] = def_name(image, &enclosing, row, 0)?;
        }
        let method_owner = owners(image, table::METHOD_DEF, 5, table::METHOD_PTR)?;
        let field_owner = owners(image, table::FIELD, 4, table::FIELD_PTR)?;
        Ok(Reader {
            image,
            type_defs,
            method_owner,
            field_owner,
        })
    }

    fn assembly(&self) -> Result<Assembly, ClrError> {
        let image = self.image;
        let name = if image.rows(table::ASSEMBLY) > 0 {
            image
                .string(image.cell(table::ASSEMBLY, 1, 7)?)?
                .to_string()
        } else {
            String::new()
        };
        let mut references = Vec::new();
        for row in 1..=image.rows(table::ASSEMBLY_REF) {
            references.push(
                image
                    .string(image.cell(table::ASSEMBLY_REF, row, 6)?)?
                    .to_string(),
            );
        }
        let mut interfaces: HashMap<u32, Vec<String>> = HashMap::new();
        for row in 1..=image.rows(table::INTERFACE_IMPL) {
            let class = image.cell(table::INTERFACE_IMPL, row, 0)?;
            let iface = image.cell(table::INTERFACE_IMPL, row, 1)?;
            if let Some((t, r)) = decode(coded::TYPE_DEF_OR_REF, iface)? {
                interfaces
                    .entry(class)
                    .or_default()
                    .push(self.type_name(t, r)?);
            }
        }
        let mut types = Vec::new();
        for row in 1..=image.rows(table::TYPE_DEF) {
            let extends =
                match decode(coded::TYPE_DEF_OR_REF, image.cell(table::TYPE_DEF, row, 3)?)? {
                    Some((t, r)) => Some(self.type_name(t, r)?),
                    None => None,
                };
            let mut methods = Vec::new();
            for method in self.range(row, 5, table::METHOD_DEF, table::METHOD_PTR)? {
                methods.push(self.method(method)?);
            }
            types.push(Type {
                full_name: self.type_defs[row as usize - 1].clone(),
                flags: image.cell(table::TYPE_DEF, row, 0)?,
                extends,
                interfaces: interfaces.remove(&row).unwrap_or_default(),
                methods,
            });
        }
        Ok(Assembly {
            name,
            references,
            types,
        })
    }

    /// The physical rows of a TypeDef's methods (column 5) or fields (column 4).
    fn range(&self, row: u32, col: usize, t: usize, ptr: usize) -> Result<Vec<u32>, ClrError> {
        let image = self.image;
        let (start, end) = list_bounds(image, row, col, t, ptr)?;
        (start..end)
            .map(|logical| physical(image, ptr, logical))
            .collect()
    }

    fn method(&self, row: u32) -> Result<Method, ClrError> {
        let image = self.image;
        let rva = image.cell(table::METHOD_DEF, row, 0)?;
        let name = image
            .string(image.cell(table::METHOD_DEF, row, 3)?)?
            .to_string();
        let flags = u16::try_from(image.cell(table::METHOD_DEF, row, 2)?).unwrap_or(0);
        let impl_flags = image.cell(table::METHOD_DEF, row, 1)?;
        // A body exists for IL code (code type 0) at a non-zero RVA.
        let body = if rva == 0 || impl_flags & 0x3 != 0 {
            None
        } else {
            let code = il::body(image, rva)?;
            let ops = il::decode(code)?
                .into_iter()
                .map(|raw| self.op(raw))
                .collect::<Result<Vec<_>, _>>()?;
            Some((code.len(), ops))
        };
        Ok(Method { name, flags, body })
    }

    fn op(&self, raw: Raw) -> Result<Op, ClrError> {
        Ok(match raw {
            Raw::Method(kind, token) => Op::Invoke {
                kind,
                target: self.method_target(token)?,
            },
            Raw::Str(offset) => Op::Str(self.image.user_string(offset)?),
            Raw::StaticField(token) => Op::StaticField(self.field_owner_name(token)?),
            Raw::Token(token) => match token >> 24 {
                0x01 | 0x02 | 0x1B => {
                    Op::TypeToken(self.type_name((token >> 24) as usize, token & 0x00FF_FFFF)?)
                }
                0x04 | 0x0A if self.is_field(token)? => {
                    Op::FieldToken(self.field_owner_name(token)?)
                }
                _ => Op::MethodToken(self.method_target(token)?),
            },
        })
    }

    /// Whether a MemberRef (or FieldDef) token names a field: its signature starts with 0x06.
    fn is_field(&self, token: u32) -> Result<bool, ClrError> {
        if token >> 24 == 0x04 {
            return Ok(true);
        }
        let sig = self
            .image
            .blob(self.image.cell(table::MEMBER_REF, token & 0x00FF_FFFF, 2)?)?;
        Ok(sig.first() == Some(&0x06))
    }

    fn field_owner_name(&self, token: u32) -> Result<String, ClrError> {
        let row = token & 0x00FF_FFFF;
        match token >> 24 {
            0x04 => {
                let owner = *self
                    .field_owner
                    .get((row as usize).wrapping_sub(1))
                    .ok_or(ClrError::BadToken(table::FIELD, row))?;
                self.type_name(table::TYPE_DEF, owner)
            }
            0x0A => self.member_ref_parent(row),
            t => Err(ClrError::BadToken(t as usize, row)),
        }
    }

    fn method_target(&self, token: u32) -> Result<Target, ClrError> {
        let row = token & 0x00FF_FFFF;
        match token >> 24 {
            0x06 => self.def_target(row),
            0x0A => Ok(Target {
                type_name: self.member_ref_parent(row)?,
                name: self
                    .image
                    .string(self.image.cell(table::MEMBER_REF, row, 1)?)?
                    .to_string(),
            }),
            0x2B => {
                let method = self.image.cell(table::METHOD_SPEC, row, 0)?;
                match decode(coded::METHOD_DEF_OR_REF, method)? {
                    Some((table::METHOD_DEF, r)) => self.def_target(r),
                    Some((_, r)) => self.method_target(0x0A00_0000 | r),
                    None => Err(ClrError::BadToken(table::METHOD_SPEC, row)),
                }
            }
            t => Err(ClrError::BadToken(t as usize, row)),
        }
    }

    fn def_target(&self, row: u32) -> Result<Target, ClrError> {
        let owner = *self
            .method_owner
            .get((row as usize).wrapping_sub(1))
            .ok_or(ClrError::BadToken(table::METHOD_DEF, row))?;
        Ok(Target {
            type_name: self.type_name(table::TYPE_DEF, owner)?,
            name: self
                .image
                .string(self.image.cell(table::METHOD_DEF, row, 3)?)?
                .to_string(),
        })
    }

    fn member_ref_parent(&self, row: u32) -> Result<String, ClrError> {
        let parent = self.image.cell(table::MEMBER_REF, row, 0)?;
        match decode(coded::MEMBER_REF_PARENT, parent)? {
            Some((table::MODULE_REF, _)) => Ok("<module>".to_string()),
            Some((table::METHOD_DEF, r)) => Ok(self.def_target(r)?.type_name),
            Some((t, r)) => self.type_name(t, r),
            None => Err(ClrError::BadToken(table::MEMBER_REF, row)),
        }
    }

    /// A TypeDef, TypeRef or TypeSpec as reflection names it. A generic instantiation is named
    /// by its generic type; any other TypeSpec (an array, a pointer, a generic parameter) is
    /// `<spec>`.
    fn type_name(&self, t: usize, row: u32) -> Result<String, ClrError> {
        self.type_name_at(t, row, 0)
    }

    /// `type_name`, `depth` TypeRefs deep in a nesting chain (a damaged file may loop).
    fn type_name_at(&self, t: usize, row: u32, depth: usize) -> Result<String, ClrError> {
        let image = self.image;
        match t {
            table::TYPE_DEF => self
                .type_defs
                .get((row as usize).wrapping_sub(1))
                .cloned()
                .ok_or(ClrError::BadToken(t, row)),
            table::TYPE_REF => {
                let name = image.string(image.cell(t, row, 1)?)?;
                let namespace = image.string(image.cell(t, row, 2)?)?;
                let local = qualified(namespace, name);
                match decode(coded::RESOLUTION_SCOPE, image.cell(t, row, 0)?)? {
                    Some((table::TYPE_REF, outer)) if outer != row => {
                        if depth >= 64 {
                            return Err(ClrError::BadToken(table::TYPE_REF, row));
                        }
                        let outer = self.type_name_at(table::TYPE_REF, outer, depth + 1)?;
                        Ok(format!("{outer}+{local}"))
                    }
                    _ => Ok(local),
                }
            }
            table::TYPE_SPEC => {
                let sig = image.blob(image.cell(t, row, 0)?)?;
                // GENERICINST (CLASS | VALUETYPE) TypeDefOrRefOrSpecEncoded ...
                if sig.first() == Some(&0x15) && matches!(sig.get(1), Some(0x11 | 0x12)) {
                    let (encoded, _) = compressed(sig.get(2..).unwrap_or_default())?;
                    let row = encoded >> 2;
                    match encoded & 0x3 {
                        0 => self.type_name(table::TYPE_DEF, row),
                        1 => self.type_name(table::TYPE_REF, row),
                        _ => Ok("<spec>".to_string()),
                    }
                } else {
                    Ok("<spec>".to_string())
                }
            }
            _ => Err(ClrError::BadToken(t, row)),
        }
    }
}

fn qualified(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}

/// A TypeDef's reflection name, through its enclosing types (`depth` stops a cycle).
fn def_name(
    image: &Image<'_>,
    enclosing: &HashMap<u32, u32>,
    row: u32,
    depth: usize,
) -> Result<String, ClrError> {
    let name = image.string(image.cell(table::TYPE_DEF, row, 1)?)?;
    let namespace = image.string(image.cell(table::TYPE_DEF, row, 2)?)?;
    let local = qualified(namespace, name);
    match enclosing.get(&row) {
        Some(&outer) if depth < 64 && outer != row => Ok(format!(
            "{}+{local}",
            def_name(image, enclosing, outer, depth + 1)?
        )),
        _ => Ok(local),
    }
}

/// The logical `[start, end)` of a TypeDef's member list in column `col`.
fn list_bounds(
    image: &Image<'_>,
    row: u32,
    col: usize,
    t: usize,
    ptr: usize,
) -> Result<(u32, u32), ClrError> {
    let count = if image.rows(ptr) > 0 {
        image.rows(ptr)
    } else {
        image.rows(t)
    };
    let start = image.cell(table::TYPE_DEF, row, col)?;
    let end = if row < image.rows(table::TYPE_DEF) {
        image.cell(table::TYPE_DEF, row + 1, col)?
    } else {
        count + 1
    };
    let end = end.min(count + 1);
    Ok((start, end.max(start)))
}

/// A list position as a physical row, through a `*Ptr` table when there is one.
fn physical(image: &Image<'_>, ptr: usize, logical: u32) -> Result<u32, ClrError> {
    if image.rows(ptr) > 0 {
        image.cell(ptr, logical, 0)
    } else {
        Ok(logical)
    }
}

/// The TypeDef row owning each row of table `t` (methods: column 5, fields: column 4).
fn owners(image: &Image<'_>, t: usize, col: usize, ptr: usize) -> Result<Vec<u32>, ClrError> {
    let mut owner = vec![0u32; image.rows(t) as usize];
    for row in 1..=image.rows(table::TYPE_DEF) {
        let (start, end) = list_bounds(image, row, col, t, ptr)?;
        for logical in start..end {
            let member = physical(image, ptr, logical)?;
            if let Some(slot) = owner.get_mut((member as usize).wrapping_sub(1)) {
                *slot = row;
            }
        }
    }
    Ok(owner)
}
