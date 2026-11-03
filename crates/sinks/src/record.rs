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
    /// OSV ecosystem name. Only `Maven` for now.
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

impl SinkRecord {
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
        if self.ecosystem != "Maven" {
            return Err(format!(
                "ecosystem `{}` is not supported yet (only Maven)",
                self.ecosystem
            ));
        }
        if self.packages.is_empty() {
            return Err("packages is empty".into());
        }
        if let Some(p) = self.packages.iter().find(|p| !valid_maven_package(p)) {
            return Err(format!("package `{p}` is not `group:artifact`"));
        }
        for s in &self.sinks {
            check_method(&s.class, &s.method)?;
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
            check_method(&e.class, &e.method)?;
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
        let err = |message: String| RecordError::Invalid {
            path: path.display().to_string(),
            message,
        };
        let text = std::fs::read_to_string(&path).map_err(|e| err(e.to_string()))?;
        let record: SinkRecord = serde_json::from_str(&text).map_err(|e| err(e.to_string()))?;
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
    }
    Ok(set)
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
