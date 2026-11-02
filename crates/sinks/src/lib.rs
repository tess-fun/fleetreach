//! Vulnerable-function (sink) data from artifact diffs (spec 16, row 13).
//!
//! The first source is the JVM: the difference between the last affected and the first fixed
//! jar of an advisory is a superset of its fix. [`diff_jars`] compares the two at the method
//! level after normalization, so rebuild noise (line tables, local variable tables,
//! constant-pool order, compiler-numbered lambdas) is not reported as a change.
//!
//! Jars are data: they are unzipped and parsed, never loaded or run.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Read;
use std::path::Path;

use cafebabe::attributes::{AttributeData, CodeData};
use cafebabe::bytecode::Opcode;
use cafebabe::{MethodAccessFlags, ParseOptions};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Why a jar could not be diffed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {message}")]
    Read { path: String, message: String },
}

/// What happened to a method between the two jars.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}

/// One changed method. `class` is the binary name with dots (`org.a.Outer$Inner`);
/// `descriptor` is the JVM descriptor, or `lambda` for the lambdas declared in `method`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct MethodChange {
    pub class: String,
    pub method: String,
    pub descriptor: String,
    pub kind: ChangeKind,
}

/// A jar's methods: `(class, method, descriptor)` to a fingerprint of the normalized body.
pub type Fingerprints = BTreeMap<(String, String, String), [u8; 32]>;

/// Fingerprint every method of every class in a jar. Multi-release overlays
/// (`META-INF/versions/`) and unparseable classes are skipped; the count of skipped classes
/// is returned so a caller can tell a partial read from a clean one.
pub fn fingerprint_jar(path: &Path) -> Result<(Fingerprints, usize), Error> {
    let err = |message: String| Error::Read {
        path: path.display().to_string(),
        message,
    };
    let file = std::fs::File::open(path).map_err(|e| err(e.to_string()))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| err(e.to_string()))?;
    let mut out = Fingerprints::new();
    let mut skipped = 0;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| err(e.to_string()))?;
        let name = entry.name().map_err(|e| err(e.to_string()))?.to_string();
        if !name.ends_with(".class") || name.starts_with("META-INF/") {
            continue;
        }
        let mut bytes = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| err(format!("{name}: {e}")))?;
        if fingerprint_class(&bytes, &mut out).is_err() {
            skipped += 1;
        }
    }
    Ok((out, skipped))
}

/// The methods whose normalized bodies differ between two fingerprinted jars.
#[must_use]
pub fn diff(old: &Fingerprints, new: &Fingerprints) -> Vec<MethodChange> {
    let keys: BTreeSet<_> = old.keys().chain(new.keys()).collect();
    keys.into_iter()
        .filter_map(|key| {
            let kind = match (old.get(key), new.get(key)) {
                (Some(a), Some(b)) if a == b => return None,
                (Some(_), Some(_)) => ChangeKind::Modified,
                (None, Some(_)) => ChangeKind::Added,
                (Some(_), None) => ChangeKind::Removed,
                (None, None) => return None,
            };
            Some(MethodChange {
                class: key.0.clone(),
                method: key.1.clone(),
                descriptor: key.2.clone(),
                kind,
            })
        })
        .collect()
}

/// [`fingerprint_jar`] both jars, then [`diff`].
pub fn diff_jars(old: &Path, new: &Path) -> Result<Vec<MethodChange>, Error> {
    let (a, _) = fingerprint_jar(old)?;
    let (b, _) = fingerprint_jar(new)?;
    Ok(diff(&a, &b))
}

/// Add one class's methods to `out`. Lambda bodies (`lambda$m$N`) are folded into one
/// fingerprint per declaring method `m` as a sorted multiset, so renumbering is not a change.
fn fingerprint_class(bytes: &[u8], out: &mut Fingerprints) -> Result<(), String> {
    let class = cafebabe::parse_class_with_options(bytes, &ParseOptions::default())
        .map_err(|e| e.to_string())?;
    let class_name = class.this_class.to_string().replace('/', ".");
    let mut lambdas: BTreeMap<String, Vec<[u8; 32]>> = BTreeMap::new();
    for method in &class.methods {
        let flags = method.access_flags;
        if flags.contains(MethodAccessFlags::BRIDGE) {
            continue;
        }
        let body = method.attributes.iter().find_map(|a| match &a.data {
            AttributeData::Code(code) => Some(code),
            _ => None,
        });
        let mut text = format!("{:?}\n", flags.bits());
        if let Some(code) = body {
            normalize_code(code, &mut text);
        }
        let hash: [u8; 32] = Sha256::digest(text.as_bytes()).into();
        if flags.contains(MethodAccessFlags::SYNTHETIC) {
            if let Some(owner) = lambda_owner(&method.name) {
                lambdas.entry(owner.to_string()).or_default().push(hash);
            }
            // Other synthetic methods (access$000, enum $values) follow their callers.
            continue;
        }
        out.insert(
            (
                class_name.clone(),
                method.name.to_string(),
                method.descriptor.to_string(),
            ),
            hash,
        );
    }
    for (owner, mut hashes) in lambdas {
        hashes.sort_unstable();
        let mut h = Sha256::new();
        for x in &hashes {
            h.update(x);
        }
        out.insert(
            (class_name.clone(), owner, "lambda".to_string()),
            h.finalize().into(),
        );
    }
    Ok(())
}

/// `lambda$foo$3` -> `foo`; `lambda$static$0` (a lambda in `<clinit>`) -> `<clinit>`.
fn lambda_owner(name: &str) -> Option<&str> {
    let rest = name.strip_prefix("lambda$")?;
    let owner = rest.rsplit_once('$').map_or(rest, |(o, _)| o);
    Some(match owner {
        "static" => "<clinit>",
        "new" => "<init>",
        o => o,
    })
}

/// A body's normalized text: opcodes with constant-pool references resolved to names,
/// branch offsets kept (they move only when code does), the exception table, and nothing
/// from debug attributes.
fn normalize_code(code: &CodeData<'_>, text: &mut String) {
    match &code.bytecode {
        Some(bytecode) => {
            for (_, op) in &bytecode.opcodes {
                normalize_op(op, text);
                text.push('\n');
            }
        }
        None => {
            let _ = writeln!(text, "raw {:x?}", code.code);
        }
    }
    for e in &code.exception_table {
        let _ = writeln!(
            text,
            "catch {} {} {} {}",
            e.start_pc,
            e.end_pc,
            e.handler_pc,
            e.catch_type.as_deref().unwrap_or("*")
        );
    }
}

fn normalize_op(op: &Opcode<'_>, text: &mut String) {
    match op {
        // The bootstrap index is a class-file position, not meaning; the call site's name and
        // type are what the code asks for.
        Opcode::Invokedynamic(d) => {
            let _ = write!(
                text,
                "indy {} {}",
                d.name_and_type.name, d.name_and_type.descriptor
            );
        }
        other => {
            let s = format!("{other:?}");
            // Lambda implementation names carry a compiler-assigned number.
            text.push_str(&strip_lambda_numbers(&s));
        }
    }
}

fn strip_lambda_numbers(s: &str) -> Cow<'_, str> {
    if !s.contains("lambda$") {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("lambda$") {
        out.push_str(&rest[..i + 7]);
        rest = &rest[i + 7..];
        let end = rest
            .find(|c: char| !(c.is_alphanumeric() || c == '$' || c == '_'))
            .unwrap_or(rest.len());
        let (ident, tail) = rest.split_at(end);
        out.push_str(ident.rsplit_once('$').map_or(ident, |(o, _)| o));
        rest = tail;
    }
    out.push_str(rest);
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lambda_owners() {
        assert_eq!(lambda_owner("lambda$parse$3"), Some("parse"));
        assert_eq!(lambda_owner("lambda$static$0"), Some("<clinit>"));
        assert_eq!(lambda_owner("access$000"), None);
    }

    #[test]
    fn lambda_numbers_are_dropped_from_references() {
        assert_eq!(
            strip_lambda_numbers("MethodHandle(lambda$parse$3, x) lambda$run$12)"),
            "MethodHandle(lambda$parse, x) lambda$run)"
        );
    }

    #[test]
    fn diff_reports_added_removed_and_modified() {
        let k = |m: &str| ("C".to_string(), m.to_string(), "()V".to_string());
        let old = Fingerprints::from([(k("a"), [0; 32]), (k("b"), [1; 32]), (k("c"), [2; 32])]);
        let new = Fingerprints::from([(k("a"), [0; 32]), (k("b"), [9; 32]), (k("d"), [3; 32])]);
        let kinds: Vec<_> = diff(&old, &new)
            .into_iter()
            .map(|c| (c.method, c.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                ("b".into(), ChangeKind::Modified),
                ("c".into(), ChangeKind::Removed),
                ("d".into(), ChangeKind::Added)
            ]
        );
    }
}
