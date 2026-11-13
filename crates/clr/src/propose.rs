//! Sink proposals for NuGet advisories (spec 16, row 13): the methods whose IL differs between
//! the last vulnerable and the first fixed release of a package, narrowed to the types whose
//! source files the fix commits changed.
//!
//! A proposal is a `proposed` record: a person reviews it before it may support "not
//! reached". Compiler-generated code is charged to the method that owns it (an `async`
//! method's state machine, a lambda's closure class, a local function), since a call graph
//! reaches the owner by name and the generated code only through it.

use std::collections::{BTreeMap, BTreeSet};

use fleetreach_sinks::record::{
    Evidence, Excluded, Sink, SinkRecord, Status, Verdict as RecordKind, SCHEMA,
};

use crate::Assembly;

/// What the fix did to one method, by owning type and name (overloads together).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Change {
    /// In both releases, with a different body, signature or attributes.
    Changed,
    /// Only in the fixed release.
    Added,
}

/// Every method of `old` and `new` that differs, keyed by `(type, method)` as a sink names
/// it, after charging generated code to its owner. A method only in `old` is not listed: a
/// sink must exist in the fixed release's predecessor and the reviewer reads the removals
/// in the commit.
#[must_use]
pub fn diff(old: &[Assembly], new: &[Assembly]) -> BTreeMap<(String, String), Change> {
    let before = fingerprints(old);
    let after = fingerprints(new);
    let mut out = BTreeMap::new();
    for (key, prints) in &after {
        let change = match before.get(key) {
            None => Change::Added,
            Some(old_prints) if old_prints != prints => Change::Changed,
            Some(_) => continue,
        };
        let Some(owner) = owner(&key.0, &key.1) else {
            continue;
        };
        // A changed generated method changes its owner, whatever the owner's own body did.
        let entry = out.entry(owner).or_insert(change);
        if change == Change::Changed {
            *entry = Change::Changed;
        }
    }
    // An owner that existed before is changed, not added, even if all its edits were in
    // generated code that is new.
    for (key, change) in &mut out {
        if *change == Change::Added
            && before
                .keys()
                .any(|k| owner(&k.0, &k.1).as_ref() == Some(key))
        {
            *change = Change::Changed;
        }
    }
    out
}

/// Each method's fingerprints (one per overload), sorted, by `(type, method)` as the
/// metadata names them.
fn fingerprints(assemblies: &[Assembly]) -> BTreeMap<(String, String), Vec<String>> {
    let mut out: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for a in assemblies {
        for t in &a.types {
            for m in &t.methods {
                let print = format!(
                    "{:x}|{:?}|{:?}|{:?}|{:?}",
                    m.flags, m.params, m.body, m.type_args, m.mentions
                );
                out.entry((t.full_name.clone(), m.name.clone()))
                    .or_default()
                    .push(print);
            }
        }
    }
    for prints in out.values_mut() {
        prints.sort();
    }
    out
}

/// The `<Name>` a C# compiler puts at the start of the names it generates, through any
/// nesting: an async local function's state machine is `<<Write>g__Core|0>d`, owned by
/// `Write`.
fn generated_owner(name: &str) -> Option<&str> {
    let mut name = name;
    while let Some(rest) = name.strip_prefix('<') {
        let mut depth = 1usize;
        let end = rest.char_indices().find_map(|(i, c)| {
            match c {
                '<' => depth += 1,
                '>' => depth -= 1,
                _ => {}
            }
            (depth == 0).then_some(i)
        })?;
        name = rest.get(..end)?;
    }
    (!name.is_empty()).then_some(name)
}

/// The type and method a sink names for `(type, method)`: generated closure classes, state
/// machines and local functions belong to the method they were written in.
fn owner(type_name: &str, method: &str) -> Option<(String, String)> {
    // A local function or lambda body hoisted onto the type itself: `<Decode>g__Read|3_0`.
    // Generated code with no owner (`<>n__0`, a base-call proxy) is no one's sink.
    if method.starts_with('<') {
        return owner(type_name, generated_owner(method)?);
    }
    // A nested generated type: `Outer+<DecodeAsync>d__12::MoveNext`,
    // `Outer+<>c__DisplayClass3_0::<Decode>b__0`.
    if let Some((outer, nested)) = type_name.rsplit_once('+') {
        if nested.starts_with('<') {
            return match generated_owner(nested) {
                Some(name) => owner(outer, name),
                None => owner(outer, method),
            };
        }
    }
    // A generated type that no method owns (an anonymous type, a file-local `<File>F1A2__Name`
    // type, or a type nested in one) belongs to no method a call graph names.
    if type_name
        .split(['.', '+'])
        .any(|part| part.starts_with('<'))
    {
        return None;
    }
    Some((type_name.to_string(), method.to_string()))
}

/// The simple name of a type as its source file is usually named: the outermost type, no
/// namespace, no generic arity (`Ns.Outer`1+Inner` is `Outer`).
fn file_stem_of(type_name: &str) -> &str {
    let outer = type_name.split('+').next().unwrap_or(type_name);
    let simple = outer.rsplit('.').next().unwrap_or(outer);
    simple.split('`').next().unwrap_or(simple)
}

/// The type names a changed source file can hold: `Formats/Gif/GifDecoderCore.cs` holds
/// `GifDecoderCore`, a partial `Foo.Bar.cs` holds `Foo`, a generic `Foo{T}.cs` or
/// `Foo`1.cs` holds `Foo`. Java sources count too: IKVM compiles them to assemblies
/// (MPXJ.Net). Test sources and other files hold none.
#[must_use]
pub fn file_types(paths: &[String]) -> BTreeSet<String> {
    paths
        .iter()
        .filter(|p| !is_test_path(p))
        .filter_map(|p| {
            let name = p.rsplit('/').next()?;
            let file = name
                .strip_suffix(".cs")
                .or_else(|| name.strip_suffix(".java"))?;
            let stem = file.split(['.', '{', '`', '-']).next()?;
            (!stem.is_empty()).then(|| stem.to_string())
        })
        .collect()
}

/// Whether a type can come from one of the changed files: its own file, or a file whose
/// name starts its name (`CompactBinary.cs` holds `CompactBinaryReader`1` and
/// `CompactBinaryWriter`1`). Only changed methods are ever kept, so a loose match costs a
/// reviewer a line, while a missed one hides the fix.
fn in_changed_file(types: &BTreeSet<String>, stem: &str) -> bool {
    types.contains(stem) || types.iter().any(|t| stem.starts_with(t.as_str()))
}

/// A path under a test or benchmark project.
#[must_use]
pub fn is_test_path(path: &str) -> bool {
    path.split('/').any(|seg| {
        let s = seg.to_ascii_lowercase();
        s == "test"
            || s == "tests"
            || s.ends_with(".tests")
            || s.ends_with(".test")
            || s.ends_with(".unittests")
            || s.contains("benchmark")
            || s == "samples"
    })
}

/// What a proposal is made from.
#[derive(Debug, Clone, Default)]
pub struct Advisory {
    pub id: String,
    pub aliases: Vec<String>,
    pub packages: Vec<String>,
    /// Fix commit URLs.
    pub commits: Vec<String>,
    /// The paths the fix commits changed; empty when they could not be read.
    pub changed_files: Vec<String>,
    /// `package old -> new`, for the note.
    pub releases: String,
}

/// Generated code the reviewer never names: compiler plumbing on every type.
fn is_plumbing(method: &str) -> bool {
    matches!(method, ".cctor") || method.starts_with("get_") || method.starts_with("set_")
}

/// A `proposed` record from the IL diff `changes`.
#[must_use]
pub fn propose(advisory: &Advisory, changes: &BTreeMap<(String, String), Change>) -> SinkRecord {
    let types = file_types(&advisory.changed_files);
    let narrow = !types.is_empty();
    let mut sinks = BTreeSet::new();
    let mut excluded = Vec::new();
    for ((class, method), change) in changes {
        // Only the excluded methods of the changed files help a reviewer; the rest of a
        // release diff would bury them.
        if narrow && !in_changed_file(&types, file_stem_of(class)) {
            continue;
        }
        let reason = if *change == Change::Added {
            Some("added by the fix")
        } else if is_plumbing(method) {
            Some("property accessor or static initializer")
        } else {
            None
        };
        match reason {
            Some(r) => excluded.push(Excluded {
                class: class.clone(),
                method: method.clone(),
                reason: r.to_string(),
            }),
            None => {
                sinks.insert(Sink {
                    class: class.clone(),
                    method: method.clone(),
                    descriptor: None,
                });
            }
        }
    }
    let (verdict, note) = if sinks.is_empty() {
        (
            RecordKind::NoMethodSink,
            Some(format!(
                "Proposed: no managed method of a source file the fix changed differs between \
                 {}; the flaw may be in native code, configuration or another package.",
                advisory.releases
            )),
        )
    } else {
        let scope = if narrow {
            "methods of the files the fix commits changed"
        } else {
            "every changed method (the fix commits could not be read)"
        };
        (
            RecordKind::Sinks,
            Some(format!(
                "Proposed from the IL diff of {}: {scope}.",
                advisory.releases
            )),
        )
    };
    SinkRecord {
        schema: SCHEMA.into(),
        id: advisory.id.clone(),
        aliases: advisory.aliases.clone(),
        ecosystem: "NuGet".into(),
        packages: advisory.packages.clone(),
        status: Status::Proposed,
        verdict,
        sinks: sinks.into_iter().collect(),
        gadgets: Vec::new(),
        reached_by_name: false,
        evidence: Evidence {
            commits: advisory.commits.clone(),
            excluded,
        },
        review: None,
        note,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn generated_code_belongs_to_its_owner() {
        let o = |t: &str, m: &str| owner(t, m).unwrap();
        let want = |t: &str, m: &str| (t.to_string(), m.to_string());
        assert_eq!(
            o("Ns.Gif+<DecodeAsync>d__12", "MoveNext"),
            want("Ns.Gif", "DecodeAsync")
        );
        assert_eq!(
            o("Ns.Gif+<>c__DisplayClass3_0", "<Decode>b__0"),
            want("Ns.Gif", "Decode")
        );
        assert_eq!(o("Ns.Gif+<>c", "<Read>b__4_1"), want("Ns.Gif", "Read"));
        assert_eq!(o("Ns.Gif", "<Decode>g__Skip|3_0"), want("Ns.Gif", "Decode"));
        assert_eq!(o("Ns.Gif+Frame", "Read"), want("Ns.Gif+Frame", "Read"));
        assert_eq!(o("Ns.Gif", ".ctor"), want("Ns.Gif", ".ctor"));
        assert_eq!(owner("Ns.Gif", "<>n__0"), None);
        assert_eq!(owner("<>f__AnonymousType28`1", ".ctor"), None);
        assert_eq!(
            owner("Ns.Generated.<Regex_g>F8BD__PasswordRegex_1", "Scan"),
            None
        );
        assert_eq!(
            o("Ns.Buffer+<<WriteBytesRaw>g__Core|0>d", "MoveNext"),
            want("Ns.Buffer", "WriteBytesRaw")
        );
    }

    #[test]
    fn source_files_name_their_types() {
        let paths: Vec<String> = [
            "src/ImageSharp/Formats/Gif/GifDecoderCore.cs",
            "src/Lib/Buffer{T}.cs",
            "src/Lib/Parser.Tokens.cs",
            "src/main/java/net/sf/mpxj/merlin/MerlinReader.java",
            "tests/ImageSharp.Tests/Formats/GifTests.cs",
            "README.md",
        ]
        .map(String::from)
        .to_vec();
        let types = file_types(&paths);
        assert_eq!(
            types.into_iter().collect::<Vec<_>>(),
            ["Buffer", "GifDecoderCore", "MerlinReader", "Parser"]
        );
        assert_eq!(file_stem_of("Ns.Outer`1+Inner"), "Outer");
        let one: BTreeSet<String> = ["CompactBinary".to_string()].into();
        assert!(in_changed_file(
            &one,
            file_stem_of("Bond.Protocols.CompactBinaryReader`1")
        ));
        assert!(!in_changed_file(
            &one,
            file_stem_of("Bond.Protocols.SimpleBinaryReader`1")
        ));
    }

    #[test]
    fn proposals_keep_changed_methods_of_changed_files() {
        let mut changes = BTreeMap::new();
        let mut add = |t: &str, m: &str, c| {
            changes.insert((t.to_string(), m.to_string()), c);
        };
        add("Ns.GifDecoderCore", "ReadFrame", Change::Changed);
        add("Ns.GifDecoderCore", "CheckBounds", Change::Added);
        add("Ns.GifDecoderCore", "get_Size", Change::Changed);
        add("Ns.PngDecoderCore", "Decode", Change::Changed);
        let advisory = Advisory {
            id: "GHSA-aaaa-bbbb-cccc".into(),
            packages: vec!["SixLabors.ImageSharp".into()],
            changed_files: vec!["src/Gif/GifDecoderCore.cs".into()],
            releases: "SixLabors.ImageSharp 3.1.4 -> 3.1.5".into(),
            ..Advisory::default()
        };
        let record = propose(&advisory, &changes);
        record.validate().unwrap();
        assert_eq!(record.verdict, RecordKind::Sinks);
        let keys: Vec<String> = record.sinks.iter().map(Sink::key).collect();
        assert_eq!(keys, ["Ns.GifDecoderCore.ReadFrame"]);
        let excluded: Vec<&str> = record
            .evidence
            .excluded
            .iter()
            .map(|e| e.method.as_str())
            .collect();
        assert_eq!(excluded, ["CheckBounds", "get_Size"]);

        let none = propose(&advisory, &BTreeMap::new());
        none.validate().unwrap();
        assert_eq!(none.verdict, RecordKind::NoMethodSink);
    }
}
