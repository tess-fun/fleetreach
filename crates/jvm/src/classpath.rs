//! Read a service's classes and resources from jars, wars, fat jars and class directories.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};

use cafebabe::attributes::{Annotation, AnnotationElementValue, AttributeData, AttributeInfo};
use cafebabe::bytecode::Opcode;
use cafebabe::constant_pool::{
    BootstrapArgument, LiteralConstant, Loadable, MethodHandle, ReferenceKind,
};
use cafebabe::descriptors::FieldType;
use cafebabe::{ClassAccessFlags, MethodAccessFlags, ParseOptions};

use foldhash::HashMap;

use crate::model::{CallKind, Class, Interner, Method, Op, Role, Sym};

/// A jar entry larger than this is refused: a hostile archive must not exhaust memory.
const MAX_ENTRY: u64 = 256 * 1024 * 1024;
/// Text resources larger than this are not searched for class names.
const MAX_TEXT: u64 = 4 * 1024 * 1024;
/// Entries read from one input, nested jars included.
const MAX_ENTRIES: usize = 2_000_000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {message}")]
    Read { path: String, message: String },
}

/// One input: a jar, a war, a Spring Boot fat jar, or a directory of classes.
#[derive(Debug, Clone)]
pub struct Input {
    pub path: PathBuf,
    pub role: Role,
}

/// What was read.
#[derive(Debug, Default, Clone)]
pub struct ClassPath {
    pub names: Interner,
    pub classes: Vec<Class>,
    pub by_name: HashMap<Sym, usize>,
    /// Class names found in text resources, with the first resource that named each.
    pub named_in_resources: BTreeMap<String, String>,
    /// `Main-Class` and `Start-Class` of the inputs' manifests, dotted.
    pub main_classes: Vec<String>,
    /// Entries that could not be read. Any of these makes "not reached" unsafe.
    pub unread: Vec<String>,
    /// A class defined twice with another superclass: the graph walks up both.
    pub other_superclasses: HashMap<Sym, Vec<Sym>>,
    tokens: BTreeMap<String, String>,
}

impl ClassPath {
    /// The class a dotted name gives. A nested class can be spelled with dots throughout, as
    /// Spring Boot's own `spring.factories` does.
    #[must_use]
    pub fn class_named(&self, name: &str) -> Option<usize> {
        let mut path = name.replace('.', "/");
        loop {
            if let Some(i) = self.names.get(&path).and_then(|s| self.by_name.get(&s)) {
                return Some(*i);
            }
            let dot = path.rfind('/')?;
            path.replace_range(dot..=dot, "$");
        }
    }
}

/// Read every input. A class defined twice holds what both definitions do: the graph cannot
/// tell which one a JVM loads.
pub fn load(inputs: &[Input]) -> Result<ClassPath, Error> {
    let mut cp = ClassPath::default();
    for input in inputs {
        let err = |message: String| Error::Read {
            path: input.path.display().to_string(),
            message,
        };
        if input.path.is_dir() {
            read_dir(&input.path, input.role, &mut cp).map_err(err)?;
        } else {
            let file = std::fs::File::open(&input.path).map_err(|e| err(e.to_string()))?;
            let label = input.path.display().to_string();
            // One archive this reader rejects is a gap in the read, not the end of it.
            if let Err(e) = read_archive(file, &label, input.role, true, &mut cp) {
                cp.unread.push(format!("{label}: {e}"));
            }
        }
    }
    let tokens = std::mem::take(&mut cp.tokens);
    for (token, origin) in tokens {
        if cp.class_named(&token).is_some() {
            cp.named_in_resources.insert(token, origin);
        }
    }
    Ok(cp)
}

fn read_dir(dir: &Path, role: Role, cp: &mut ClassPath) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        let path = entry.path();
        if kind.is_dir() {
            read_dir(&path, role, cp)?;
        } else if kind.is_file() {
            let label = path.display().to_string();
            if label.ends_with(".class") {
                let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
                add_class(&bytes, &label, role, cp);
            } else if is_text_resource(&label) {
                let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
                scan_text(&bytes, &label, cp);
            }
        }
    }
    Ok(())
}

fn read_archive<R: Read + Seek>(
    reader: R,
    label: &str,
    role: Role,
    outer: bool,
    cp: &mut ClassPath,
) -> Result<(), String> {
    let mut zip = zip::ZipArchive::new(reader).map_err(|e| e.to_string())?;
    if zip.len() > MAX_ENTRIES {
        return Err(format!("{} entries", zip.len()));
    }
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
        let name = entry.name().map_err(|e| e.to_string())?.to_string();
        let size = entry.size();
        let is_class = name.ends_with(".class");
        let is_jar = outer
            && name.ends_with(".jar")
            && (name.starts_with("BOOT-INF/lib/") || name.starts_with("WEB-INF/lib/"));
        let is_manifest = name == "META-INF/MANIFEST.MF";
        let is_text = is_text_resource(&name) && size <= MAX_TEXT;
        if !(is_class || is_jar || is_manifest || is_text) {
            continue;
        }
        // Overlays for newer JDKs repeat classes; the base version is the one that counts.
        if is_class && (name.starts_with("META-INF/") || name.ends_with("module-info.class")) {
            continue;
        }
        let at = format!("{label}!{name}");
        if size > MAX_ENTRY {
            cp.unread.push(format!("{at}: {size} bytes"));
            continue;
        }
        let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
        if let Err(e) = entry.by_ref().take(MAX_ENTRY).read_to_end(&mut bytes) {
            cp.unread.push(format!("{at}: {e}"));
            continue;
        }
        if is_class {
            // A fat jar's own code sits under these prefixes; its libraries are nested jars.
            let own = name.starts_with("BOOT-INF/classes/") || name.starts_with("WEB-INF/classes/");
            // The launcher a fat jar carries at its root is no more the service than a library.
            let launcher = name.starts_with("org/springframework/boot/loader/");
            let role = match (own, launcher) {
                (true, _) => Role::App,
                (false, true) => Role::Dependency,
                (false, false) => role,
            };
            add_class(&bytes, &at, role, cp);
        } else if is_jar {
            if let Err(e) = read_archive(Cursor::new(bytes), &at, Role::Dependency, false, cp) {
                cp.unread.push(format!("{at}: {e}"));
            }
        } else if is_manifest {
            if outer {
                read_manifest(&bytes, cp);
            }
        } else {
            scan_text(&bytes, &at, cp);
        }
    }
    Ok(())
}

fn read_manifest(bytes: &[u8], cp: &mut ClassPath) {
    for line in String::from_utf8_lossy(bytes).lines() {
        for key in ["Main-Class:", "Start-Class:"] {
            if let Some(value) = line.strip_prefix(key) {
                cp.main_classes.push(value.trim().to_string());
            }
        }
    }
}

/// Files that name classes for something to load: XML and properties anywhere, everything
/// under `META-INF/services` or `META-INF/spring` (Camel's component files included), Spring's
/// XML namespace handlers, Log4j 2's plugin cache, and the SezPoz indexes under
/// `META-INF/annotations` (Jenkins `@Extension`): binary files that hold class names as strings.
/// LDIF too: ApacheDS's schema names its comparators and syntax checkers in `m-fqcn`.
fn is_text_resource(name: &str) -> bool {
    if name.contains("META-INF/maven/") || name.contains("META-INF/native-image/") {
        return false;
    }
    name.ends_with(".xml")
        || name.ends_with(".properties")
        || name.ends_with(".ldif")
        || name.ends_with(".factories")
        || name.ends_with(".imports")
        || (name.contains("META-INF/services/") && !name.ends_with('/'))
        || (name.contains("META-INF/spring/") && !name.ends_with('/'))
        || name.ends_with("META-INF/spring.handlers")
        || name.ends_with("Log4j2Plugins.dat")
        || (name.contains("META-INF/annotations/") && !name.ends_with('/'))
}

/// Remember every dotted word; [`load`] keeps those that turn out to be classes.
fn scan_text(bytes: &[u8], origin: &str, cp: &mut ClassPath) {
    let text = String::from_utf8_lossy(bytes);
    for word in text.split(|c: char| !(c.is_alphanumeric() || matches!(c, '.' | '_' | '$'))) {
        let word = word.trim_matches('.');
        if word.contains('.') && !cp.tokens.contains_key(word) {
            cp.tokens.insert(word.to_string(), origin.to_string());
        }
    }
    // Log4j's plugin cache and Java serialization write each name after a two-byte length, and
    // the bytes either side can be letters (`Borg.apache...`, `...SubversionStatuspsq`), so read
    // every string by its length too.
    if origin.ends_with(".dat") || origin.contains("META-INF/annotations/") {
        for i in 0..bytes.len().saturating_sub(2) {
            let len = usize::from(u16::from_be_bytes([bytes[i], bytes[i + 1]]));
            let Some(name) = bytes.get(i + 2..i + 2 + len) else {
                continue;
            };
            let name_like = name
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'$'))
                && name.contains(&b'.');
            if name_like {
                let name = String::from_utf8_lossy(name).into_owned();
                cp.tokens.entry(name).or_insert_with(|| origin.to_string());
            }
        }
    }
    // A services file is named after the interface it fills, which is no reason to load that.
}

fn add_class(bytes: &[u8], at: &str, role: Role, cp: &mut ClassPath) {
    match parse(bytes, role, &mut cp.names) {
        Ok(class) => match cp.by_name.entry(class.name) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(cp.classes.len());
                cp.classes.push(class);
            }
            std::collections::hash_map::Entry::Occupied(slot) => {
                let first = &mut cp.classes[*slot.get()];
                if let Some(other) = class.superclass.filter(|s| first.superclass != Some(*s)) {
                    let others = cp.other_superclasses.entry(first.name).or_default();
                    if !others.contains(&other) {
                        others.push(other);
                    }
                }
                merge(first, class);
            }
        },
        Err(e) => cp.unread.push(format!("{at}: {e}")),
    }
}

/// Fold a second definition of a class into the first. Which one a JVM loads depends on a
/// class path order the files do not say (a directory of jars, two wars in one image), so the
/// graph takes what either does: every method, every call, every annotation.
fn merge(first: &mut Class, other: Class) {
    if other.role == Role::App {
        first.role = Role::App;
    }
    first.is_abstract &= other.is_abstract;
    for i in other.interfaces {
        if !first.interfaces.contains(&i) {
            first.interfaces.push(i);
        }
    }
    first.annotations.extend(other.annotations);
    first.annotation_refs.extend(other.annotation_refs);
    for m in other.methods {
        match first
            .methods
            .iter_mut()
            .find(|f| f.name == m.name && f.desc == m.desc)
        {
            Some(f) => {
                f.is_abstract &= m.is_abstract;
                f.is_private &= m.is_private;
                f.ops.extend(m.ops);
                f.annotations.extend(m.annotations);
                f.annotation_refs.extend(m.annotation_refs);
            }
            None => first.methods.push(m),
        }
    }
}

fn parse(bytes: &[u8], role: Role, names: &mut Interner) -> Result<Class, String> {
    let file = cafebabe::parse_class_with_options(bytes, &ParseOptions::default())
        .map_err(|e| e.to_string())?;
    let bootstraps = file.attributes.iter().find_map(|a| match &a.data {
        AttributeData::BootstrapMethods(b) => Some(b),
        _ => None,
    });
    let mut methods = Vec::with_capacity(file.methods.len());
    for m in &file.methods {
        let flags = m.access_flags;
        let mut method = Method {
            name: names.intern(&m.name),
            desc: names.intern(&m.descriptor.to_string()),
            is_static: flags.contains(MethodAccessFlags::STATIC),
            is_abstract: flags.contains(MethodAccessFlags::ABSTRACT),
            is_private: flags.contains(MethodAccessFlags::PRIVATE),
            ..Method::default()
        };
        read_annotations(
            &m.attributes,
            names,
            &mut method.annotations,
            &mut method.annotation_refs,
        );
        for attribute in &m.attributes {
            if let AttributeData::AnnotationDefault(value) = &attribute.data {
                read_value(value, names, &mut method.annotation_refs);
            }
            // A parameter's annotation can name what handles it: Log4j's `@PluginAttribute`
            // carries `@PluginVisitorStrategy(PluginAttributeVisitor.class)`.
            if let AttributeData::RuntimeVisibleParameterAnnotations(params)
            | AttributeData::RuntimeInvisibleParameterAnnotations(params) = &attribute.data
            {
                for annotation in params.iter().flat_map(|p| &p.annotations) {
                    let mut types = Vec::new();
                    read_annotation(annotation, names, &mut types, &mut method.annotation_refs);
                    method.annotation_refs.extend(types);
                }
            }
            if let AttributeData::Code(code) = &attribute.data {
                let Some(bytecode) = &code.bytecode else {
                    return Err(format!("{}: unparsed code", m.name));
                };
                for (_, op) in &bytecode.opcodes {
                    read_op(op, bootstraps.map(Vec::as_slice), names, &mut method.ops);
                }
            }
        }
        methods.push(method);
    }
    let mut annotations = Vec::new();
    let mut annotation_refs = Vec::new();
    read_annotations(
        &file.attributes,
        names,
        &mut annotations,
        &mut annotation_refs,
    );
    for field in &file.fields {
        let mut types = Vec::new();
        read_annotations(&field.attributes, names, &mut types, &mut annotation_refs);
        annotation_refs.extend(types);
    }
    let flags = file.access_flags;
    Ok(Class {
        name: names.intern(&file.this_class.to_string()),
        superclass: file
            .super_class
            .as_ref()
            .map(|s| names.intern(&s.to_string())),
        interfaces: file
            .interfaces
            .iter()
            .map(|i| names.intern(&i.to_string()))
            .collect(),
        is_interface: flags.contains(ClassAccessFlags::INTERFACE),
        is_abstract: flags.contains(ClassAccessFlags::ABSTRACT),
        role,
        methods,
        annotations,
        annotation_refs,
    })
}

fn read_annotations(
    attributes: &[AttributeInfo<'_>],
    names: &mut Interner,
    types: &mut Vec<Sym>,
    refs: &mut Vec<Sym>,
) {
    for attribute in attributes {
        let list = match &attribute.data {
            AttributeData::RuntimeVisibleAnnotations(l)
            | AttributeData::RuntimeInvisibleAnnotations(l) => l,
            _ => continue,
        };
        for annotation in list {
            read_annotation(annotation, names, types, refs);
        }
    }
}

fn read_annotation(
    annotation: &Annotation<'_>,
    names: &mut Interner,
    types: &mut Vec<Sym>,
    refs: &mut Vec<Sym>,
) {
    if let FieldType::Object(name) = &annotation.type_descriptor.field_type {
        types.push(names.intern(&name.to_string()));
    }
    for element in &annotation.elements {
        read_value(&element.value, names, refs);
    }
}

fn read_value(value: &AnnotationElementValue<'_>, names: &mut Interner, refs: &mut Vec<Sym>) {
    match value {
        AnnotationElementValue::ClassLiteral { class_name } => {
            let name = class_name
                .strip_prefix('L')
                .and_then(|n| n.strip_suffix(';'))
                .unwrap_or(class_name);
            refs.push(names.intern(name));
        }
        AnnotationElementValue::EnumConstant { type_name, .. } => {
            if let FieldType::Object(name) = &type_name.field_type {
                refs.push(names.intern(&name.to_string()));
            }
        }
        AnnotationElementValue::StringConstant(s) if s.contains('.') => {
            refs.push(names.intern(&s.replace('.', "/")));
        }
        AnnotationElementValue::ArrayValue(values) => {
            for v in values {
                read_value(v, names, refs);
            }
        }
        AnnotationElementValue::AnnotationValue(nested) => {
            let mut ignored = Vec::new();
            read_annotation(nested, names, &mut ignored, refs);
        }
        _ => {}
    }
}

fn read_op(
    op: &Opcode<'_>,
    bootstraps: Option<&[cafebabe::attributes::BootstrapMethodEntry<'_>]>,
    names: &mut Interner,
    ops: &mut Vec<Op>,
) {
    let mut call = |kind, m: &cafebabe::constant_pool::MemberRef<'_>, ops: &mut Vec<Op>| {
        ops.push(Op::Call {
            kind,
            class: names.intern(&m.class_name),
            name: names.intern(&m.name_and_type.name),
            desc: names.intern(&m.name_and_type.descriptor),
        });
    };
    match op {
        Opcode::Invokestatic(m) => call(CallKind::Static, m, ops),
        Opcode::Invokespecial(m) => call(CallKind::Special, m, ops),
        Opcode::Invokevirtual(m) | Opcode::Invokeinterface(m, _) => {
            call(CallKind::Virtual, m, ops);
        }
        Opcode::New(class) => ops.push(Op::New(names.intern(class))),
        Opcode::Getstatic(m) | Opcode::Putstatic(m) => {
            ops.push(Op::Touch(names.intern(&m.class_name)));
        }
        Opcode::Ldc(l) | Opcode::LdcW(l) => match l {
            Loadable::LiteralConstant(LiteralConstant::String(s)) if s.contains('.') => {
                ops.push(Op::Text(names.intern(&s.replace('.', "/"))));
            }
            Loadable::ClassInfo(c) => ops.push(Op::ClassConst(names.intern(c))),
            Loadable::MethodHandle(h) => read_handle(h, names, ops),
            _ => {}
        },
        Opcode::Invokedynamic(indy) => {
            let entry = bootstraps.and_then(|b| b.get(usize::from(indy.attr_index)));
            let mut resolved = false;
            if let Some(entry) = entry {
                let factory = entry.method.class_name.as_ref();
                resolved = matches!(
                    factory,
                    "java/lang/invoke/LambdaMetafactory"
                        | "java/lang/invoke/StringConcatFactory"
                        | "java/lang/runtime/ObjectMethods"
                );
                for argument in &entry.arguments {
                    if let BootstrapArgument::MethodHandle(h) = argument {
                        read_handle(h, names, ops);
                    }
                }
            }
            if !resolved {
                ops.push(Op::OpenDynamic);
            }
        }
        _ => {}
    }
}

/// A method handle constant or a lambda's body: treated as a call where it appears.
fn read_handle(h: &MethodHandle<'_>, names: &mut Interner, ops: &mut Vec<Op>) {
    let class = names.intern(&h.class_name);
    let kind = match h.kind {
        ReferenceKind::InvokeStatic => CallKind::Static,
        ReferenceKind::InvokeSpecial => CallKind::Special,
        ReferenceKind::NewInvokeSpecial => {
            ops.push(Op::New(class));
            CallKind::Special
        }
        ReferenceKind::InvokeVirtual | ReferenceKind::InvokeInterface => CallKind::Virtual,
        ReferenceKind::GetField
        | ReferenceKind::GetStatic
        | ReferenceKind::PutField
        | ReferenceKind::PutStatic => return,
    };
    ops.push(Op::Call {
        kind,
        class,
        name: names.intern(&h.member_ref.name),
        desc: names.intern(&h.member_ref.descriptor),
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn an_archive_the_reader_rejects_is_a_gap_not_a_failure() {
        let dir = std::env::temp_dir().join(format!("jvm-classpath-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("broken.jar");
        std::fs::write(&path, b"not a zip").unwrap();
        let input = Input {
            path,
            role: Role::Dependency,
        };
        let cp = load(&[input]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(cp.unread.len(), 1);
    }

    #[test]
    fn a_class_defined_twice_keeps_what_both_definitions_call() {
        let mut names = Interner::default();
        let mut class = |calls: &str, extra: Option<&str>| {
            let call = Op::Call {
                kind: CallKind::Static,
                class: names.intern("lib/Sink"),
                name: names.intern(calls),
                desc: names.intern("()V"),
            };
            let mut methods = vec![Method {
                name: names.intern("run"),
                desc: names.intern("()V"),
                ops: vec![call],
                ..Method::default()
            }];
            if let Some(extra) = extra {
                methods.push(Method {
                    name: names.intern(extra),
                    desc: names.intern("()V"),
                    ..Method::default()
                });
            }
            Class {
                name: names.intern("lib/Twice"),
                superclass: None,
                interfaces: vec![],
                is_interface: false,
                is_abstract: false,
                role: Role::Dependency,
                methods,
                annotations: vec![],
                annotation_refs: vec![],
            }
        };
        let mut first = class("safe", None);
        let mut second = class("flawed", Some("added"));
        second.role = Role::App;
        merge(&mut first, second);
        assert_eq!(first.role, Role::App);
        assert_eq!(first.methods.len(), 2);
        let called: Vec<&str> = first.methods[0]
            .ops
            .iter()
            .filter_map(|op| match op {
                Op::Call { name, .. } => Some(names.name(*name)),
                _ => None,
            })
            .collect();
        assert_eq!(called, ["safe", "flawed"]);
    }

    #[test]
    fn spring_handlers_and_the_log4j_plugin_cache_name_classes() {
        assert!(is_text_resource("META-INF/spring.handlers"));
        assert!(is_text_resource(
            "META-INF/org/apache/logging/log4j/core/config/plugins/Log4j2Plugins.dat"
        ));
        assert!(!is_text_resource("META-INF/spring.schemas.bak"));
        let mut cp = ClassPath::default();
        scan_text(
            b"\x00\x12org.example.Plugin\x00",
            "x/Log4j2Plugins.dat",
            &mut cp,
        );
        assert!(cp.tokens.contains_key("org.example.Plugin"));
    }

    #[test]
    fn a_sezpoz_index_names_classes() {
        assert!(is_text_resource("META-INF/annotations/hudson.Extension"));
        assert!(is_text_resource(
            "schema/ou=schema/cn=apache/ou=comparators/m-oid=1.ldif"
        ));
        assert!(!is_text_resource("META-INF/annotations/"));
        let mut cp = ClassPath::default();
        let name = "hudson.scm.SubversionStatus$DescriptorImplWithAVeryLongNameIndeedYes";
        let mut bytes = b"\xac\xed\x00\x05t\x00".to_vec();
        bytes.push(u8::try_from(name.len()).unwrap());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(b"psq");
        scan_text(&bytes, "x/META-INF/annotations/hudson.Extension", &mut cp);
        assert_eq!(bytes[6], b'D');
        assert!(cp.tokens.contains_key(name));
    }
}
