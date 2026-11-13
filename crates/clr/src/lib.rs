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
//!
//! `graph::analyze` builds a rapid type analysis call graph over a service's assemblies,
//! and `verdict::judge` answers one curated sink record against it, as `fleetreach-jvm`
//! does for class files. The graph is checked against what the runtime itself ran: on 11
//! apps built from real NuGet packages, every method the JIT compiled in their assemblies is
//! in the graph (`docs/differential/clr/jit`).
//!
//! `propose` drafts sink records for NuGet advisories from the IL diff of a package's last
//! vulnerable and first fixed release, narrowed to the types whose source files the fix
//! commits changed. A draft is `proposed` until a person reviews it.

pub mod graph;
mod il;
mod metadata;
pub mod propose;
mod sig;
pub mod verdict;

use foldhash::{HashMap, HashMapExt};

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
    /// Types the body's tokens name as generic arguments (`new List<Foo>()`, `Get<Foo>()`),
    /// each once, in first-seen order. Generic code can make them (`new T()`).
    pub type_args: Vec<String>,
    /// Types `initobj`, `box`, `newarr`, `constrained.` and the other value-type
    /// instructions name: a value type comes into being without `newobj`.
    pub mentions: Vec<String>,
    /// Each parameter's type as the first type it names (a generic instantiation by its
    /// generic type), empty for a primitive or a generic parameter.
    pub params: Vec<String>,
}

impl Method {
    /// `virtual`.
    #[must_use]
    pub fn is_virtual(&self) -> bool {
        self.flags & 0x0040 != 0
    }
    /// `newslot`: introduces a slot rather than overriding one.
    #[must_use]
    pub fn is_new_slot(&self) -> bool {
        self.flags & 0x0100 != 0
    }
    #[must_use]
    pub fn is_abstract(&self) -> bool {
        self.flags & 0x0400 != 0
    }
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
    /// Types the fields' signatures name, generic arguments included.
    pub field_types: Vec<String>,
    /// Custom attribute types on the type or its methods, fields, properties and parameters.
    pub attributes: Vec<String>,
    /// Strings in those attributes' arguments that look like type names (a `typeof` argument
    /// is stored as its name).
    pub attribute_text: Vec<String>,
}

impl Type {
    #[must_use]
    pub fn is_interface(&self) -> bool {
        self.flags & 0x20 != 0
    }
    #[must_use]
    pub fn is_abstract(&self) -> bool {
        self.flags & 0x80 != 0
    }
}

#[derive(Debug, Clone)]
pub struct Assembly {
    /// The assembly's name; empty for a module without an assembly manifest.
    pub name: String,
    /// The names of the assemblies it references.
    pub references: Vec<String>,
    pub types: Vec<Type>,
    /// Assembly-level custom attribute types, and type-like strings in their arguments.
    pub attributes: Vec<String>,
    pub attribute_text: Vec<String>,
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

/// An interface an assembly defines: its reflection name, its methods' names and the
/// interfaces it extends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub full_name: String,
    pub methods: Vec<String>,
    pub extends: Vec<String>,
}

/// Read only the interfaces of the .NET assembly in `bytes`, from its metadata: no method body
/// is decoded. What [`read`] gives for the same types, at a fraction of the work.
///
/// # Errors
///
/// As [`read`].
pub fn read_interfaces(bytes: &[u8]) -> Result<Vec<Interface>, ClrError> {
    let image = Image::parse(bytes)?;
    Reader::new(&image)?.interfaces()
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

    /// Every InterfaceImpl row, by the TypeDef row that implements (or extends) it.
    fn interface_impls(&self) -> Result<HashMap<u32, Vec<String>>, ClrError> {
        let image = self.image;
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
        Ok(interfaces)
    }

    fn interfaces(&self) -> Result<Vec<Interface>, ClrError> {
        let image = self.image;
        let mut impls = self.interface_impls()?;
        let mut out = Vec::new();
        for row in 1..=image.rows(table::TYPE_DEF) {
            if image.cell(table::TYPE_DEF, row, 0)? & 0x20 == 0 {
                continue;
            }
            let mut methods = Vec::new();
            for method in self.range(row, 5, table::METHOD_DEF, table::METHOD_PTR)? {
                methods.push(
                    image
                        .string(image.cell(table::METHOD_DEF, method, 3)?)?
                        .to_string(),
                );
            }
            out.push(Interface {
                full_name: self.type_defs[row as usize - 1].clone(),
                methods,
                extends: impls.remove(&row).unwrap_or_default(),
            });
        }
        Ok(out)
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
        let mut interfaces = self.interface_impls()?;
        let mut attrs = self.attributes()?;
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
            let mut named = Vec::new();
            for field in self.range(row, 4, table::FIELD, table::FIELD_PTR)? {
                sig::Sig::new(image.blob(image.cell(table::FIELD, field, 2)?)?)
                    .field(&mut named)?;
            }
            let mut field_types = Vec::new();
            self.names(&named, &mut field_types, 0)?;
            let (attributes, attribute_text) = attrs.remove(&row).unwrap_or_default();
            types.push(Type {
                full_name: self.type_defs[row as usize - 1].clone(),
                flags: image.cell(table::TYPE_DEF, row, 0)?,
                extends,
                interfaces: interfaces.remove(&row).unwrap_or_default(),
                methods,
                field_types,
                attributes,
                attribute_text,
            });
        }
        let (attributes, attribute_text) = attrs.remove(&0).unwrap_or_default();
        Ok(Assembly {
            name,
            references,
            types,
            attributes,
            attribute_text,
        })
    }

    /// Custom attributes by the TypeDef row they belong to (0: the assembly), as attribute
    /// types and the type-like strings of their arguments.
    #[allow(clippy::type_complexity)]
    fn attributes(&self) -> Result<HashMap<u32, (Vec<String>, Vec<String>)>, ClrError> {
        let image = self.image;
        let mut out: HashMap<u32, (Vec<String>, Vec<String>)> = HashMap::new();
        let rows = image.rows(table::CUSTOM_ATTRIBUTE);
        if rows == 0 {
            return Ok(out);
        }
        let property_owner = map_owners(
            image,
            table::PROPERTY_MAP,
            table::PROPERTY,
            table::PROPERTY_PTR,
        )?;
        let param_method = method_params(image)?;
        for row in 1..=rows {
            let parent = image.cell(table::CUSTOM_ATTRIBUTE, row, 0)?;
            let owner = match decode(coded::HAS_CUSTOM_ATTRIBUTE, parent)? {
                Some((table::TYPE_DEF, r)) => Some(r),
                Some((table::METHOD_DEF, r)) => self.method_owner.get(r as usize - 1).copied(),
                Some((table::FIELD, r)) => self.field_owner.get(r as usize - 1).copied(),
                Some((table::PROPERTY, r)) => property_owner.get(r as usize - 1).copied(),
                Some((table::PARAM, r)) => param_method
                    .get(r as usize - 1)
                    .and_then(|m| self.method_owner.get((*m as usize).wrapping_sub(1)))
                    .copied(),
                Some((table::ASSEMBLY, _)) => Some(0),
                _ => None,
            };
            let Some(owner) = owner.filter(|o| *o != 0 || is_assembly(parent)) else {
                continue;
            };
            let ctor = image.cell(table::CUSTOM_ATTRIBUTE, row, 1)?;
            let ty = match decode(coded::CUSTOM_ATTRIBUTE_TYPE, ctor)? {
                Some((table::METHOD_DEF, r)) => self.def_target(r)?.type_name,
                Some((_, r)) => self.member_ref_parent(r)?,
                None => continue,
            };
            let slot = out.entry(owner).or_default();
            if !slot.0.contains(&ty) {
                slot.0.push(ty);
            }
            for text in
                type_like_strings(image.blob(image.cell(table::CUSTOM_ATTRIBUTE, row, 2)?)?)
            {
                if !slot.1.contains(&text) {
                    slot.1.push(text);
                }
            }
        }
        Ok(out)
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
        let mut type_args = Vec::new();
        let mut mentions = Vec::new();
        let body = if rva == 0 || impl_flags & 0x3 != 0 {
            None
        } else {
            let code = il::body(image, rva)?;
            let raws = il::decode(code)?;
            let mut named = Vec::new();
            let mut mentioned = Vec::new();
            for raw in &raws {
                if let Raw::Mention(token) = raw {
                    mentioned.push(((token >> 24) as usize, token & 0x00FF_FFFF));
                } else {
                    self.generic_args(*raw, &mut named)?;
                }
            }
            self.names(&named, &mut type_args, 0)?;
            self.names(&mentioned, &mut mentions, 0)?;
            let ops = raws
                .into_iter()
                .filter(|raw| !matches!(raw, Raw::Mention(_)))
                .map(|raw| self.op(raw))
                .collect::<Result<Vec<_>, _>>()?;
            Some((code.len(), ops))
        };
        let mut params = Vec::new();
        let raw = sig::Sig::new(image.blob(image.cell(table::METHOD_DEF, row, 4)?)?).params()?;
        for p in raw {
            params.push(match p {
                Some((table::TYPE_SPEC, r)) => self.type_name(table::TYPE_SPEC, r)?,
                Some((t, r)) => self.type_name(t, r)?,
                None => String::new(),
            });
        }
        Ok(Method {
            name,
            flags,
            body,
            type_args,
            mentions,
            params,
        })
    }

    /// The types an instruction's token names inside generic instantiations.
    fn generic_args(&self, raw: Raw, out: &mut Vec<sig::Named>) -> Result<(), ClrError> {
        let token = match raw {
            Raw::Method(_, t) | Raw::Token(t) | Raw::StaticField(t) => t,
            Raw::Str(_) | Raw::Mention(_) => return Ok(()),
        };
        let image = self.image;
        let row = token & 0x00FF_FFFF;
        match token >> 24 {
            0x2B => {
                sig::Sig::new(image.blob(image.cell(table::METHOD_SPEC, row, 1)?)?)
                    .instantiation(out)?;
                let method = image.cell(table::METHOD_SPEC, row, 0)?;
                if let Some((table::MEMBER_REF, r)) = decode(coded::METHOD_DEF_OR_REF, method)? {
                    self.generic_args(Raw::Token(0x0A00_0000 | r), out)?;
                }
            }
            0x0A => {
                let parent = image.cell(table::MEMBER_REF, row, 0)?;
                if let Some((table::TYPE_SPEC, r)) = decode(coded::MEMBER_REF_PARENT, parent)? {
                    out.push((table::TYPE_SPEC, r));
                }
            }
            0x1B => out.push((table::TYPE_SPEC, row)),
            _ => {}
        }
        Ok(())
    }

    /// Reflection names of `named`, TypeSpecs opened up to what they name, each once.
    fn names(
        &self,
        named: &[sig::Named],
        out: &mut Vec<String>,
        depth: usize,
    ) -> Result<(), ClrError> {
        for &(t, row) in named {
            if t == table::TYPE_SPEC {
                if depth >= 16 {
                    return Err(ClrError::BadToken(t, row));
                }
                let mut inner = Vec::new();
                sig::Sig::new(self.image.blob(self.image.cell(t, row, 0)?)?).ty(&mut inner, 0)?;
                self.names(&inner, out, depth + 1)?;
            } else {
                let name = self.type_name(t, row)?;
                if !out.contains(&name) {
                    out.push(name);
                }
            }
        }
        Ok(())
    }

    fn op(&self, raw: Raw) -> Result<Op, ClrError> {
        Ok(match raw {
            Raw::Method(kind, token) => Op::Invoke {
                kind,
                target: self.method_target(token)?,
            },
            Raw::Str(offset) => Op::Str(self.image.user_string(offset)?),
            Raw::StaticField(token) => Op::StaticField(self.field_owner_name(token)?),
            // Filtered out before ops are made.
            Raw::Mention(token) => return Err(ClrError::BadToken(0, token)),
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

/// The TypeDef owning each row of `child`, through a map table (PropertyMap, EventMap) whose
/// rows give a parent and the start of its list.
fn map_owners(
    image: &Image<'_>,
    map: usize,
    child: usize,
    ptr: usize,
) -> Result<Vec<u32>, ClrError> {
    let count = if image.rows(ptr) > 0 {
        image.rows(ptr)
    } else {
        image.rows(child)
    };
    let mut owner = vec![0u32; image.rows(child) as usize];
    let rows = image.rows(map);
    for row in 1..=rows {
        let parent = image.cell(map, row, 0)?;
        let start = image.cell(map, row, 1)?;
        let end = if row < rows {
            image.cell(map, row + 1, 1)?
        } else {
            count + 1
        }
        .min(count + 1);
        for logical in start..end.max(start) {
            let member = physical(image, ptr, logical)?;
            if let Some(slot) = owner.get_mut((member as usize).wrapping_sub(1)) {
                *slot = parent;
            }
        }
    }
    Ok(owner)
}

/// The MethodDef row owning each Param row.
fn method_params(image: &Image<'_>) -> Result<Vec<u32>, ClrError> {
    let count = if image.rows(table::PARAM_PTR) > 0 {
        image.rows(table::PARAM_PTR)
    } else {
        image.rows(table::PARAM)
    };
    let mut owner = vec![0u32; image.rows(table::PARAM) as usize];
    let methods = image.rows(table::METHOD_DEF);
    for row in 1..=methods {
        let start = image.cell(table::METHOD_DEF, row, 5)?;
        let end = if row < methods {
            image.cell(table::METHOD_DEF, row + 1, 5)?
        } else {
            count + 1
        }
        .min(count + 1);
        for logical in start..end.max(start) {
            let param = physical(image, table::PARAM_PTR, logical)?;
            if let Some(slot) = owner.get_mut((param as usize).wrapping_sub(1)) {
                *slot = row;
            }
        }
    }
    Ok(owner)
}

/// Strings in a custom attribute blob that could name a type: every length-prefixed UTF-8
/// run made of name characters. A `typeof` argument is stored this way (II.23.3), so this
/// over-collects, never misses.
fn type_like_strings(blob: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = 2; // the 0x0001 prolog
    while at < blob.len() {
        if let Ok((len, used)) = compressed(&blob[at..]) {
            let len = len as usize;
            if len >= 2 {
                if let Some(bytes) = blob.get(at + used..at + used + len) {
                    if let Ok(text) = std::str::from_utf8(bytes) {
                        if text.contains(|c: char| c.is_ascii_alphabetic())
                            && text.chars().all(|c| {
                                c.is_alphanumeric()
                                    || matches!(
                                        c,
                                        '.' | '+' | '`' | ',' | ' ' | '=' | '[' | ']' | '_'
                                    )
                            })
                        {
                            out.push(text.to_string());
                        }
                    }
                }
            }
        }
        at += 1;
    }
    out
}

/// Whether a HasCustomAttribute index points at the Assembly row.
fn is_assembly(parent: u32) -> bool {
    matches!(
        decode(coded::HAS_CUSTOM_ATTRIBUTE, parent),
        Ok(Some((table::ASSEMBLY, _)))
    )
}
