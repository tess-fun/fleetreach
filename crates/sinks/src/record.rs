//! Curated sink records (spec 16, row 13): which methods of a library hold an advisory's
//! flaw, one JSON file per advisory.
//!
//! The E2 experiments showed that no automatic method finds JVM sinks precisely enough to
//! suppress findings on, so a sink is **data a person reviews**. The pipeline writes
//! `proposed` records ([`crate::propose`]); a reviewer checks them against the fix and the
//! advisory, edits them, and sets `status = "reviewed"` with their name and the date. Only
//! reviewed records may ever support a "not reached" verdict; proposed ones can only produce
//! witnesses ("reached").
//!
//! A record says one of three things about an advisory (its `verdict`):
//!
//! - `sinks`: the listed methods hold the flaw.
//! - `deny-list`: the fix adds classes to a deserialization deny list (Jackson and similar);
//!   exposure is a listed gadget class on the classpath plus a polymorphic-typing entry point,
//!   which is a rule, not a sink.
//! - `no-method-sink`: the flaw is not in any method (configuration, scripts) or not in the
//!   fix; the note says why.
//!
//! Reaching a sink is one question and not reaching one another: `reached_by_name` marks a
//! record whose sinks run through a name a call graph cannot follow (JCA, plugin systems,
//! framework dispatch). Such a record can say "reached", and [`SinkRecord::supports_not_reached`]
//! is the one check a scanner makes before it says "not reached".
//!
//! [`load_dir`] is fail-closed: an unknown field, a malformed name, a duplicate id, or a
//! reviewed record without a reviewer is an error for the whole directory, since a sink set
//! that is silently partly read could support a wrong "not reached".

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The `schema` value every record carries.
pub const SCHEMA: &str = "fleetreach-sinks/1";

/// One advisory's sink record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkRecord {
    /// Always [`SCHEMA`].
    pub schema: String,
    /// The advisory id (GHSA, CVE, ...); the file is `<id>.json`.
    pub id: String,
    /// Other ids of the same advisory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// OSV ecosystem name: `Maven`, `PyPI`, `npm` or `NuGet`.
    pub ecosystem: String,
    /// The advisory's affected packages, as OSV names them (`group:artifact` for Maven). The
    /// sinks may live in a sibling artifact; a sink is found by its class name.
    pub packages: Vec<String>,
    pub status: Status,
    pub verdict: Verdict,
    /// For `verdict = "sinks"`: the methods holding the flaw.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sinks: Vec<Sink>,
    /// For `verdict = "deny-list"`: the gadget classes the fix denies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gadgets: Vec<String>,
    /// For `verdict = "sinks"`: applications reach these sinks through a name, not a call, so
    /// finding no path to one proves nothing. The note says how.
    #[serde(default, skip_serializing_if = "is_false")]
    pub reached_by_name: bool,
    /// What the record was derived from.
    #[serde(default, skip_serializing_if = "Evidence::is_empty")]
    pub evidence: Evidence,
    /// Who reviewed it; required when `status = "reviewed"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<Review>,
    /// Free text; required for `verdict = "no-method-sink"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Written by the pipeline or a labeller; not yet checked by a person. Witnesses only.
    Proposed,
    /// Checked by the person named in `review`.
    Reviewed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Sinks,
    DenyList,
    NoMethodSink,
}

/// A method: class binary name with dots and `$` for nested classes, method name
/// (`<init>`, `<clinit>` included), and optionally the JVM descriptor. Without a descriptor
/// every overload of the name is meant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sink {
    pub class: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<String>,
}

impl Sink {
    /// `class.method`, the form the source-level proposer and the labels use.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}.{}", self.class, self.method)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Fix commit URLs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commits: Vec<String>,
    /// Methods the proposer considered and did not put in `sinks`, with the reason, so a
    /// reviewer sees what was left out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded: Vec<Excluded>,
}

impl Evidence {
    fn is_empty(&self) -> bool {
        self.commits.is_empty() && self.excluded.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Excluded {
    pub class: String,
    pub method: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    /// The reviewer's name or handle.
    pub by: String,
    /// `YYYY-MM-DD`.
    pub date: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Why a record or a directory of records was refused.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("{path}: {message}")]
    Invalid { path: String, message: String },
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl SinkRecord {
    /// Whether finding no path to this record's sinks may be read as "not reached". Only a
    /// person's sink list qualifies, and only when a call graph can see its sinks.
    #[must_use]
    pub fn supports_not_reached(&self) -> bool {
        self.status == Status::Reviewed && self.verdict == Verdict::Sinks && !self.reached_by_name
    }

    /// Every rule a record must satisfy on its own.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != SCHEMA {
            return Err(format!("schema is `{}`, expected `{SCHEMA}`", self.schema));
        }
        if !valid_id(&self.id) {
            return Err(format!("id `{}` is not an advisory id", self.id));
        }
        if let Some(a) = self.aliases.iter().find(|a| !valid_id(a) || **a == self.id) {
            return Err(format!("alias `{a}` is not a distinct advisory id"));
        }
        let eco = self.ecosystem.as_str();
        let (valid_package, package_form): (fn(&str) -> bool, &str) = match eco {
            "Maven" => (valid_maven_package, "`group:artifact`"),
            "PyPI" => (valid_pypi_package, "a PyPI project name"),
            "npm" => (valid_npm_package, "an npm package name"),
            "NuGet" => (valid_nuget_package, "a NuGet package id"),
            other => {
                return Err(format!(
                    "ecosystem `{other}` is not supported (Maven, PyPI, npm or NuGet)"
                ))
            }
        };
        if self.packages.is_empty() {
            return Err("packages is empty".into());
        }
        if let Some(p) = self.packages.iter().find(|p| !valid_package(p)) {
            return Err(format!("package `{p}` is not {package_form}"));
        }
        if eco != "Maven" {
            if self.sinks.iter().any(|s| s.descriptor.is_some()) {
                return Err("only Maven sinks carry a JVM descriptor".into());
            }
            if self.verdict == Verdict::DenyList {
                return Err("verdict `deny-list` is for Maven deserialization fixes".into());
            }
        }
        for s in &self.sinks {
            check_member(eco, &s.class, &s.method)?;
            if let Some(d) = &s.descriptor {
                if !valid_descriptor(d) {
                    return Err(format!(
                        "{}: descriptor `{d}` is not a JVM method descriptor",
                        s.key()
                    ));
                }
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        if let Some(s) = self.sinks.iter().find(|s| !seen.insert(*s)) {
            return Err(format!("sink {} is listed twice", s.key()));
        }
        if let Some(g) = self.gadgets.iter().find(|g| !valid_class(g)) {
            return Err(format!("gadget `{g}` is not a class name"));
        }
        for e in &self.evidence.excluded {
            check_member(eco, &e.class, &e.method)?;
        }
        match self.verdict {
            Verdict::Sinks if self.sinks.is_empty() => {
                return Err("verdict `sinks` needs at least one sink".into());
            }
            Verdict::DenyList if self.gadgets.is_empty() => {
                return Err("verdict `deny-list` needs at least one gadget class".into());
            }
            Verdict::NoMethodSink if self.note.as_deref().is_none_or(str::is_empty) => {
                return Err("verdict `no-method-sink` needs a note saying why".into());
            }
            _ => {}
        }
        if self.verdict != Verdict::Sinks && !self.sinks.is_empty() {
            return Err("only verdict `sinks` lists sinks".into());
        }
        if self.verdict != Verdict::DenyList && !self.gadgets.is_empty() {
            return Err("only verdict `deny-list` lists gadgets".into());
        }
        if self.reached_by_name && self.verdict != Verdict::Sinks {
            return Err("only verdict `sinks` can be reached by name".into());
        }
        if self.reached_by_name && self.note.as_deref().is_none_or(str::is_empty) {
            return Err("`reached_by_name` needs a note saying how".into());
        }
        match (&self.status, &self.review) {
            (Status::Reviewed, None) => return Err("a reviewed record needs `review`".into()),
            (Status::Reviewed, Some(r)) => {
                if r.by.trim().is_empty() {
                    return Err("review.by is empty".into());
                }
                if !valid_date(&r.date) {
                    return Err(format!("review.date `{}` is not YYYY-MM-DD", r.date));
                }
            }
            (Status::Proposed, Some(_)) => {
                return Err("a proposed record has no `review` (set status to reviewed)".into());
            }
            (Status::Proposed, None) => {}
        }
        Ok(())
    }
}

/// A directory's records, by id.
#[derive(Debug, Clone, Default)]
pub struct SinkSet {
    pub records: BTreeMap<String, SinkRecord>,
    /// Alias to the id of the record carrying it.
    pub aliases: BTreeMap<String, String>,
}

impl SinkSet {
    /// The record for an advisory id or any of its aliases.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&SinkRecord> {
        self.records
            .get(id)
            .or_else(|| self.aliases.get(id).and_then(|i| self.records.get(i)))
    }

    /// Records a person has reviewed.
    pub fn reviewed(&self) -> impl Iterator<Item = &SinkRecord> {
        self.records
            .values()
            .filter(|r| r.status == Status::Reviewed)
    }
}

/// Read every `*.json` record under `dir` (recursively). Fail-closed: any invalid record, a
/// file not named after its id, or an id or alias claimed twice refuses the whole directory.
pub fn load_dir(dir: &Path) -> Result<SinkSet, RecordError> {
    let mut files = Vec::new();
    collect(dir, &mut files)?;
    files.sort();
    let mut set = SinkSet::default();
    for path in files {
        let text = std::fs::read_to_string(&path).map_err(|e| RecordError::Invalid {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        add(&mut set, &path, &text)?;
    }
    Ok(set)
}

mod bundle {
    include!(concat!(env!("OUT_DIR"), "/bundled.rs"));
}

/// The records this crate was built with, from its `data/` directory, checked as
/// [`load_dir`] checks a directory.
///
/// # Errors
///
/// As [`load_dir`]: an invalid record refuses the whole set.
pub fn bundled() -> Result<SinkSet, RecordError> {
    let mut set = SinkSet::default();
    for (path, text) in bundle::BUNDLED {
        add(&mut set, Path::new(path), text)?;
    }
    Ok(set)
}

/// Check one record file and add it to `set`.
fn add(set: &mut SinkSet, path: &Path, text: &str) -> Result<(), RecordError> {
    let err = |message: String| RecordError::Invalid {
        path: path.display().to_string(),
        message,
    };
    let record: SinkRecord = serde_json::from_str(text).map_err(|e| err(e.to_string()))?;
    record.validate().map_err(err)?;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    if stem != record.id {
        return Err(err(format!(
            "the file for `{}` must be named `{}.json`",
            record.id, record.id
        )));
    }
    for name in std::iter::once(&record.id).chain(&record.aliases) {
        if set.records.contains_key(name) || set.aliases.contains_key(name) {
            return Err(err(format!(
                "`{name}` is already claimed by another record"
            )));
        }
    }
    for alias in &record.aliases {
        set.aliases.insert(alias.clone(), record.id.clone());
    }
    set.records.insert(record.id.clone(), record);
    Ok(())
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), RecordError> {
    let err = |message: String| RecordError::Invalid {
        path: dir.display().to_string(),
        message,
    };
    for entry in std::fs::read_dir(dir).map_err(|e| err(e.to_string()))? {
        let entry = entry.map_err(|e| err(e.to_string()))?;
        let kind = entry.file_type().map_err(|e| err(e.to_string()))?;
        let path = entry.path();
        if kind.is_symlink() {
            return Err(err(format!(
                "{}: symlinks are not followed",
                path.display()
            )));
        }
        if kind.is_dir() {
            collect(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
    Ok(())
}

/// A sink's owner and name in the ecosystem's form: a JVM class and method; a Python module
/// (with any classes) and function; a JS file path inside the repo (with any class) and
/// function.
fn check_member(eco: &str, class: &str, method: &str) -> Result<(), String> {
    match eco {
        "PyPI" => {
            if !class.split('.').all(valid_identifier) || class.contains('$') {
                return Err(format!("`{class}` is not a Python module path"));
            }
        }
        "npm" => {
            let file_ok = !class.is_empty()
                && !class.starts_with('/')
                && !class.split('/').any(|seg| seg.is_empty() || seg == "..")
                && class.chars().all(|c| {
                    c.is_ascii_alphanumeric()
                        || matches!(
                            c,
                            '/' | '.' | '_' | '-' | '@' | '$' | '[' | ']' | '(' | ')' | '+'
                        )
                });
            if !file_ok {
                return Err(format!(
                    "`{class}` is not a file path inside the repository"
                ));
            }
        }
        "NuGet" => {
            if !valid_dotnet_type(class) {
                return Err(format!("`{class}` is not a .NET type name"));
            }
            return if valid_dotnet_method(method) {
                Ok(())
            } else {
                Err(format!("`{method}` is not a .NET method name"))
            };
        }
        _ => return check_method(class, method),
    }
    if valid_identifier(method) || method == "[computed]" {
        Ok(())
    } else {
        Err(format!("`{method}` is not a function name"))
    }
}

fn check_method(class: &str, method: &str) -> Result<(), String> {
    if !valid_class(class) {
        return Err(format!("`{class}` is not a class binary name"));
    }
    if !(method == "<init>" || method == "<clinit>" || valid_identifier(method)) {
        return Err(format!("`{method}` is not a method name"));
    }
    Ok(())
}

fn valid_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c.is_alphabetic() || c == '_' || c == '$')
        && chars.all(|c| c.is_alphanumeric() || c == '_' || c == '$')
}

/// `org.a.Outer$Inner`: dot-separated identifiers, `$` allowed inside them.
fn valid_class(s: &str) -> bool {
    !s.is_empty() && s.split('.').all(valid_identifier)
}

/// A PyPI project name (PEP 508 name characters).
fn valid_pypi_package(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 214
        && s.starts_with(|c: char| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// A NuGet package id: letters, digits, `.`, `-`, `_`, at most 100 characters.
fn valid_nuget_package(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// A .NET type as reflection names it: `Ns.Type`, `Ns.Outer+Inner`, `Ns.Generic`1`.
fn valid_dotnet_type(s: &str) -> bool {
    let part = |p: &str| {
        let (name, arity) = p.split_once('`').unwrap_or((p, "1"));
        valid_identifier(name) && !arity.is_empty() && arity.chars().all(|c| c.is_ascii_digit())
    };
    !s.is_empty() && s.split(['.', '+']).all(part)
}

/// A .NET method name: an identifier, `.ctor`, `.cctor`, or an explicit interface
/// implementation (`System.IDisposable.Dispose`, `IEnumerable<T>.GetEnumerator`, and as
/// source generators write it, `global::System.IDisposable.Dispose`; some compilers join the
/// parts with `-`, as in `Csla-Server-IDataPortalTarget-CheckRulesAsync`).
fn valid_dotnet_method(s: &str) -> bool {
    matches!(s, ".ctor" | ".cctor")
        || (!s.is_empty()
            && !s.starts_with('.')
            && s.chars().all(|c| {
                c.is_alphanumeric()
                    || matches!(
                        c,
                        '_' | '.' | '<' | '>' | ',' | '`' | '+' | '$' | ':' | '-' | '?'
                    )
            }))
}

/// An npm package name: `name` or `@scope/name`, URL-safe characters.
fn valid_npm_package(s: &str) -> bool {
    let ok = |p: &str| {
        !p.is_empty()
            && !p.starts_with('.')
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~'))
    };
    match s.strip_prefix('@') {
        Some(rest) => rest
            .split_once('/')
            .is_some_and(|(scope, name)| ok(scope) && ok(name)),
        None => s.len() <= 214 && ok(s),
    }
}

fn valid_maven_package(s: &str) -> bool {
    let mut parts = s.split(':');
    let ok = |p: Option<&str>| {
        p.is_some_and(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        })
    };
    ok(parts.next()) && ok(parts.next()) && parts.next().is_none()
}

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !s.starts_with('.')
}

fn valid_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
        && (1..=12).contains(&s[5..7].parse::<u8>().unwrap_or(0))
        && (1..=31).contains(&s[8..10].parse::<u8>().unwrap_or(0))
}

/// `(params)return`, with JVM field types inside.
fn valid_descriptor(s: &str) -> bool {
    fn field(b: &[u8], mut i: usize) -> Option<usize> {
        while b.get(i) == Some(&b'[') {
            i += 1;
        }
        match b.get(i)? {
            b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'Z' => Some(i + 1),
            b'L' => {
                let end = i + b[i..].iter().position(|&c| c == b';')?;
                (end > i + 1).then_some(end + 1)
            }
            _ => None,
        }
    }
    let b = s.as_bytes();
    if b.first() != Some(&b'(') {
        return false;
    }
    let mut i = 1;
    while b.get(i).is_some_and(|&c| c != b')') {
        match field(b, i) {
            Some(next) => i = next,
            None => return false,
        }
    }
    if b.get(i) != Some(&b')') {
        return false;
    }
    i += 1;
    if b.get(i) == Some(&b'V') {
        return i + 1 == b.len();
    }
    field(b, i) == Some(b.len())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[test]
    fn the_bundled_records_are_the_data_directory() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("data");
        let bundled = super::bundled().unwrap();
        assert_eq!(bundled.records, load_dir(&dir).unwrap().records);
        assert!(bundled.records.len() >= 100);
    }

    use super::*;

    fn record() -> SinkRecord {
        SinkRecord {
            schema: SCHEMA.into(),
            id: "GHSA-ff2w-cq2g-wv5f".into(),
            aliases: vec!["CVE-2020-7238".into()],
            ecosystem: "Maven".into(),
            packages: vec!["io.netty:netty-handler".into()],
            status: Status::Proposed,
            verdict: Verdict::Sinks,
            sinks: vec![Sink {
                class: "io.netty.handler.codec.http.HttpObjectDecoder".into(),
                method: "readHeaders".into(),
                descriptor: None,
            }],
            gadgets: vec![],
            reached_by_name: false,
            evidence: Evidence::default(),
            review: None,
            note: None,
        }
    }

    #[test]
    fn a_proposed_record_is_valid() {
        assert_eq!(record().validate(), Ok(()));
    }

    #[test]
    fn pypi_and_npm_records_use_their_own_names() {
        let sink = |class: &str, method: &str| Sink {
            class: class.into(),
            method: method.into(),
            descriptor: None,
        };
        let mut py = record();
        py.ecosystem = "PyPI".into();
        py.packages = vec!["Jinja2".into()];
        py.sinks = vec![sink("jinja2.sandbox.SandboxedEnvironment", "call")];
        assert_eq!(py.validate(), Ok(()));
        py.packages = vec!["org.ex:lib".into()];
        assert!(py.validate().is_err());

        let mut js = record();
        js.ecosystem = "npm".into();
        js.packages = vec!["@scope/lib".into(), "lodash".into()];
        js.sinks = vec![
            sink("lib/merge.js", "merge"),
            sink("src/a.ts.Parser", "parse"),
            sink("app/api/[provider]/(auth)/route.js", "GET"),
        ];
        assert_eq!(js.validate(), Ok(()));
        js.sinks = vec![sink("../outside.js", "f")];
        assert!(js.validate().is_err());
        js.sinks = vec![Sink {
            descriptor: Some("()V".into()),
            ..sink("lib/a.js", "f")
        }];
        assert!(js.validate().is_err());

        let mut net = record();
        net.ecosystem = "NuGet".into();
        net.packages = vec!["Newtonsoft.Json".into()];
        net.sinks =
            vec![
            sink(
                "Newtonsoft.Json.Serialization.JsonSerializerInternalReader",
                "CreateObject",
            ),
            sink("Acme.Outer+Inner`1", ".ctor"),
            sink("Acme.Reader", "System.IDisposable.Dispose"),
            sink(
                "Acme.Context",
                "global::System.Text.Json.Serialization.Metadata.IJsonTypeInfoResolver.GetTypeInfo",
            ),
            sink("Acme.Portal", "Csla-Server-IDataPortalTarget-CheckRulesAsync"),
            sink("Acme.Store", "Weasel-Storage-ISelector<T?>-ResolveAsync"),
        ];
        assert_eq!(net.validate(), Ok(()));
        net.sinks = vec![sink("Acme..Bad", "f")];
        assert!(net.validate().is_err());
        net.packages = vec!["org.ex:lib".into()];
        assert!(net.validate().is_err());

        let mut other = record();
        other.ecosystem = "Go".into();
        assert!(other.validate().is_err());
    }

    #[test]
    fn reviewed_needs_a_reviewer_and_date() {
        let mut r = record();
        r.status = Status::Reviewed;
        assert!(r.validate().unwrap_err().contains("review"));
        r.review = Some(Review {
            by: "ann".into(),
            date: "2026-13-02".into(),
            note: None,
        });
        assert!(r.validate().unwrap_err().contains("YYYY-MM-DD"));
        r.review = Some(Review {
            by: "ann".into(),
            date: "2026-11-02".into(),
            note: None,
        });
        assert_eq!(r.validate(), Ok(()));
    }

    #[test]
    fn verdicts_constrain_the_lists() {
        let mut r = record();
        r.verdict = Verdict::DenyList;
        assert!(r.validate().is_err());
        r.sinks.clear();
        assert!(r.validate().unwrap_err().contains("gadget"));
        r.gadgets = vec!["org.slf4j.ext.EventData".into()];
        assert_eq!(r.validate(), Ok(()));
        r.verdict = Verdict::NoMethodSink;
        r.gadgets.clear();
        assert!(r.validate().unwrap_err().contains("note"));
    }

    #[test]
    fn only_reviewed_sinks_a_call_graph_can_see_support_not_reached() {
        let mut r = record();
        assert!(!r.supports_not_reached());
        r.status = Status::Reviewed;
        assert!(r.supports_not_reached());
        r.reached_by_name = true;
        assert!(!r.supports_not_reached());
        r.reached_by_name = false;
        r.sinks.clear();
        r.gadgets = vec!["org.slf4j.ext.EventData".into()];
        r.verdict = Verdict::DenyList;
        assert!(!r.supports_not_reached());
    }

    #[test]
    fn reached_by_name_needs_sinks_and_a_note() {
        let mut r = record();
        r.reached_by_name = true;
        assert!(r.validate().unwrap_err().contains("note"));
        r.note = Some("loaded through the plugin system".into());
        assert_eq!(r.validate(), Ok(()));
        r.sinks.clear();
        r.gadgets = vec!["org.slf4j.ext.EventData".into()];
        r.verdict = Verdict::DenyList;
        assert!(r.validate().unwrap_err().contains("reached by name"));
    }

    #[test]
    fn names_are_checked() {
        let mut r = record();
        r.sinks[0].method = "read Headers".into();
        assert!(r.validate().is_err());
        let mut r = record();
        r.sinks[0].class = "io..Decoder".into();
        assert!(r.validate().is_err());
        let mut r = record();
        r.packages = vec!["netty-handler".into()];
        assert!(r.validate().is_err());
    }

    #[test]
    fn descriptors() {
        for ok in ["()V", "(I[JLjava/lang/String;)Z", "([[B)Ljava/lang/Object;"] {
            assert!(valid_descriptor(ok), "{ok}");
        }
        for bad in ["V", "()", "(L;)V", "(Q)V", "()VV", "(I"] {
            assert!(!valid_descriptor(bad), "{bad}");
        }
    }

    #[test]
    fn unknown_fields_are_refused() {
        let mut v = serde_json::to_value(record()).unwrap();
        v["confidence"] = 0.9.into();
        assert!(serde_json::from_value::<SinkRecord>(v).is_err());
    }

    #[test]
    fn load_dir_refuses_duplicates_and_misnamed_files() {
        let dir = std::env::temp_dir().join(format!("sinks-load-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("maven")).unwrap();
        let write = |name: &str, r: &SinkRecord| {
            std::fs::write(
                dir.join("maven").join(name),
                serde_json::to_string(r).unwrap(),
            )
            .unwrap();
        };
        write("GHSA-ff2w-cq2g-wv5f.json", &record());
        let set = load_dir(&dir).unwrap();
        assert!(set.get("CVE-2020-7238").is_some());
        assert_eq!(set.reviewed().count(), 0);

        let mut other = record();
        other.id = "GHSA-aaaa-bbbb-cccc".into();
        write("GHSA-aaaa-bbbb-cccc.json", &other);
        assert!(load_dir(&dir)
            .unwrap_err()
            .to_string()
            .contains("already claimed"));

        other.aliases.clear();
        write("GHSA-aaaa-bbbb-cccc.json", &other);
        assert_eq!(load_dir(&dir).unwrap().records.len(), 2);

        write("wrong-name.json", &record());
        assert!(load_dir(&dir)
            .unwrap_err()
            .to_string()
            .contains("must be named"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
