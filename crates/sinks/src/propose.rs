//! Propose a sink record from an advisory's fix (spec 16, row 13; measured as E2b).
//!
//! Every method the fix changes is a candidate, then:
//!
//! 1. methods the fix **added** are dropped: they do not exist in the vulnerable version;
//! 2. methods whose only change is comments, braces, imports or logging are dropped;
//! 3. if the advisory text names some of the remaining classes or methods, only those stay;
//! 4. **plumbing** is dropped (a change that threads a new argument or swaps a callee name,
//!    with no added or removed guard or security call), unless that would leave nothing.
//!
//! On the E2b pilot the full candidate set (after step 1) held every true sink with a median
//! of 2 methods, and the final set was at least 90% precise for 45% of advisories. That is a
//! good proposal for a reviewer and not good enough to act on unreviewed, which is why the
//! output is always a `proposed` record. Excluded candidates are listed with their reason.
//!
//! A fix that only adds class names to a static initializer (a deserialization deny list)
//! is proposed as `deny-list` with those classes as gadgets.

use std::collections::BTreeMap;

use crate::java::{self, Method};
use crate::record::{Evidence, Excluded, Sink, SinkRecord, Status, Verdict, SCHEMA};

/// One Java file a fix commit touches. `old` is `None` for an added file, `new` for a removed
/// one.
#[derive(Debug, Clone)]
pub struct FileChange {
    pub path: String,
    pub old: Option<String>,
    pub new: Option<String>,
}

/// What the advisory says about itself.
#[derive(Debug, Clone, Default)]
pub struct Advisory {
    pub id: String,
    pub aliases: Vec<String>,
    pub packages: Vec<String>,
    /// Summary and details, for matching names.
    pub text: String,
    /// Fix commit URLs, recorded as evidence.
    pub commits: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    Added,
    Modified,
    Removed,
}

struct Candidate {
    key: String,
    change: Change,
    old: Method,
    new: Method,
}

/// The `proposed` record for an advisory, from its fix's changed files.
#[must_use]
pub fn propose(advisory: &Advisory, files: &[FileChange]) -> SinkRecord {
    let candidates = changed_methods(files);
    let mut excluded = Vec::new();
    let exclude = |out: &mut Vec<Excluded>, key: &str, reason: &str| {
        let (class, method) = split_key(key);
        out.push(Excluded {
            class: class.to_string(),
            method: method.to_string(),
            reason: reason.to_string(),
        });
    };

    let existing: Vec<&Candidate> = candidates
        .iter()
        .filter(|c| c.change != Change::Added)
        .collect();
    let mut substantive = Vec::new();
    for c in existing {
        if changed_lines(c).is_empty() {
            exclude(
                &mut excluded,
                &c.key,
                "only comments, braces, imports or logging changed",
            );
        } else {
            substantive.push(c);
        }
    }

    let gadgets = deny_list_gadgets(&substantive);
    let named: Vec<&Candidate> = substantive
        .iter()
        .copied()
        .filter(|c| mentioned(&c.key, &advisory.text))
        .collect();
    let narrowed = if named.is_empty() {
        substantive.clone()
    } else {
        named
    };
    for c in &substantive {
        if !narrowed.iter().any(|n| n.key == c.key) {
            exclude(
                &mut excluded,
                &c.key,
                "the advisory names other methods of this fix",
            );
        }
    }
    let unplumbed: Vec<&Candidate> = narrowed.iter().copied().filter(|c| !plumbing(c)).collect();
    let chosen = if unplumbed.is_empty() {
        narrowed.clone()
    } else {
        unplumbed
    };
    for c in &narrowed {
        if !chosen.iter().any(|n| n.key == c.key) {
            exclude(
                &mut excluded,
                &c.key,
                "plumbing: only passes a new argument or renames a call",
            );
        }
    }

    let (verdict, sinks, gadgets, note) = if !gadgets.is_empty() {
        (Verdict::DenyList, Vec::new(), gadgets, None)
    } else if chosen.is_empty() {
        let note = "the fix changes no method that exists in the vulnerable version";
        (
            Verdict::NoMethodSink,
            Vec::new(),
            Vec::new(),
            Some(note.to_string()),
        )
    } else {
        let sinks = chosen
            .iter()
            .map(|c| {
                let (class, method) = split_key(&c.key);
                Sink {
                    class: class.to_string(),
                    method: method.to_string(),
                    descriptor: None,
                }
            })
            .collect();
        (Verdict::Sinks, sinks, Vec::new(), None)
    };
    excluded.sort_by(|a, b| (&a.class, &a.method).cmp(&(&b.class, &b.method)));
    SinkRecord {
        schema: SCHEMA.to_string(),
        id: advisory.id.clone(),
        aliases: advisory.aliases.clone(),
        ecosystem: "Maven".to_string(),
        packages: advisory.packages.clone(),
        status: Status::Proposed,
        verdict,
        sinks,
        gadgets,
        evidence: Evidence {
            commits: advisory.commits.clone(),
            excluded,
        },
        review: None,
        note,
    }
}

fn changed_methods(files: &[FileChange]) -> Vec<Candidate> {
    let mut out: BTreeMap<String, Candidate> = BTreeMap::new();
    for f in files {
        if !f.path.ends_with(".java") || java::is_test_path(&f.path) {
            continue;
        }
        let old = f.old.as_deref().map(java::methods).unwrap_or_default();
        let new = f.new.as_deref().map(java::methods).unwrap_or_default();
        for key in old.keys().chain(new.keys()) {
            let (a, b) = (old.get(key), new.get(key));
            if a.map(|m| &m.key) == b.map(|m| &m.key) || out.contains_key(key) {
                continue;
            }
            let change = match (a, b) {
                (None, _) => Change::Added,
                (_, None) => Change::Removed,
                _ => Change::Modified,
            };
            out.insert(
                key.clone(),
                Candidate {
                    key: key.clone(),
                    change,
                    old: a.cloned().unwrap_or_default(),
                    new: b.cloned().unwrap_or_default(),
                },
            );
        }
    }
    out.into_values().collect()
}

fn split_key(key: &str) -> (&str, &str) {
    key.rsplit_once('.').unwrap_or(("", key))
}

/// Removed and added lines, minus noise (braces, annotations, imports, logging).
fn changed_lines(c: &Candidate) -> Vec<(char, &str)> {
    let old: Vec<&str> = c
        .old
        .source
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let new: Vec<&str> = c
        .new
        .source
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let mut out: Vec<(char, &str)> = Vec::new();
    for (sign, from, other) in [('-', &old, &new), ('+', &new, &old)] {
        // A multiset difference: line order changes are rare in fixes and not worth an LCS.
        let mut pool: BTreeMap<&str, usize> = BTreeMap::new();
        for l in other.iter() {
            *pool.entry(l).or_default() += 1;
        }
        for l in from.iter() {
            match pool.get_mut(l) {
                Some(n) if *n > 0 => *n -= 1,
                _ if !noise(l) => out.push((sign, l)),
                _ => {}
            }
        }
    }
    out
}

fn noise(line: &str) -> bool {
    let l = line.trim();
    if l.chars()
        .all(|c| matches!(c, '{' | '}' | '(' | ')' | ';' | ' '))
    {
        return true;
    }
    if l == "@Override" || l.starts_with("import ") {
        return true;
    }
    let lower = l.to_lowercase();
    ["log.", "logger.", "log .", "logger ."]
        .iter()
        .any(|p| lower.contains(p))
        && [
            ".debug",
            ".trace",
            ".info",
            ".warn",
            ".error",
            "isdebugenabled",
            "istraceenabled",
        ]
        .iter()
        .any(|p| lower.contains(p))
}

/// Words that mark a change as a fix rather than plumbing: control flow, checks, and the
/// security switches of the XML and TLS APIs.
const GUARDS: &[&str] = &[
    "if", "throw", "catch", "return", "while", "for", "switch", "case", "else",
];
const GUARD_CALLS: &[&str] = &[
    "setFeature",
    "setProperty",
    "setAttribute",
    "setURIResolver",
    "setEndpointIdentificationAlgorithm",
    "isEqual",
    "check",
    "valid",
    "escape",
    "matches",
];

fn plumbing(c: &Candidate) -> bool {
    if c.change == Change::Removed {
        return false;
    }
    let lines = changed_lines(c);
    // A guard counts when the fix adds or removes one, not when a changed line merely keeps
    // the `return` or `if` it already had.
    let guards = |sign: char| -> BTreeMap<&str, usize> {
        let mut out = BTreeMap::new();
        for (_, l) in lines.iter().filter(|(s, _)| *s == sign) {
            for w in l.split(|ch: char| !(ch.is_alphanumeric() || ch == '_')) {
                if GUARDS.contains(&w) {
                    *out.entry(w).or_default() += 1;
                }
            }
            for g in GUARD_CALLS.iter().filter(|g| l.contains(*g)) {
                *out.entry(*g).or_default() += 1;
            }
        }
        out
    };
    if guards('+') != guards('-') {
        return false;
    }
    let added = lines.iter().filter(|(s, _)| *s == '+').count();
    let removed = lines.iter().filter(|(s, _)| *s == '-').count();
    added <= 2 * removed.max(1)
}

/// Whether the advisory text names the method's class (simple name) or the method itself.
fn mentioned(key: &str, text: &str) -> bool {
    let (class, method) = split_key(key);
    let simple = class.rsplit(['.', '$']).next().unwrap_or(class);
    has_word(text, simple)
        || (method.len() > 3 && !method.starts_with('<') && has_word(text, method))
}

fn has_word(text: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    text.match_indices(word).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let after = text[i + word.len()..].chars().next();
        let boundary = |c: Option<char>| c.is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        boundary(before) && boundary(after)
    })
}

/// A deny-list fix: every substantive change is in static initializers, and the added lines
/// carry string literals that are class names. Those classes are the gadgets.
fn deny_list_gadgets(changed: &[&Candidate]) -> Vec<String> {
    if changed.is_empty() || !changed.iter().all(|c| c.key.ends_with(".<clinit>")) {
        return Vec::new();
    }
    let mut gadgets = Vec::new();
    for c in changed {
        for (sign, line) in changed_lines(c) {
            if sign != '+' {
                continue;
            }
            for literal in line.split('"').skip(1).step_by(2) {
                let parts: Vec<&str> = literal.split('.').collect();
                let class_like = parts.len() >= 3
                    && parts.iter().all(|p| {
                        p.chars()
                            .next()
                            .is_some_and(|c| c.is_alphabetic() || c == '_')
                            && p.chars()
                                .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
                    })
                    && parts
                        .last()
                        .is_some_and(|p| p.starts_with(char::is_uppercase));
                if class_like && !gadgets.iter().any(|g| g == literal) {
                    gadgets.push(literal.to_string());
                }
            }
        }
    }
    gadgets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, old: &str, new: &str) -> FileChange {
        FileChange {
            path: path.into(),
            old: Some(old.into()),
            new: Some(new.into()),
        }
    }

    fn advisory(text: &str) -> Advisory {
        Advisory {
            id: "GHSA-xxxx-yyyy-zzzz".into(),
            packages: vec!["org.ex:lib".into()],
            text: text.into(),
            ..Advisory::default()
        }
    }

    #[test]
    fn plumbing_and_new_methods_are_left_out() {
        let old = "package p; class Mongo {
            Client create() {
                return client(spec.ssl());
            }
            static Opts options(boolean ssl) {
                if (ssl) {
                    b.ssl(true).ctx(trustAll());
                }
                return b;
            }
        }";
        let new = "package p; class Mongo {
            Client create() {
                return client(spec.ssl(), spec.ignoreCert());
            }
            static Opts options(boolean ssl, boolean ignore) {
                if (ssl) {
                    b.ssl(true);
                    if (ignore) {
                        b.ctx(trustAll());
                    }
                }
                return b;
            }
            static boolean ignoreCert() { return false; }
        }";
        let r = propose(
            &advisory("trust checking is disabled"),
            &[file("src/main/p/Mongo.java", old, new)],
        );
        assert_eq!(r.verdict, Verdict::Sinks);
        let keys: Vec<String> = r.sinks.iter().map(Sink::key).collect();
        assert_eq!(keys, ["p.Mongo.options"]);
        assert_eq!(r.evidence.excluded.len(), 1);
        assert!(r.evidence.excluded[0].reason.starts_with("plumbing"));
        assert_eq!(r.validate(), Ok(()));
    }

    #[test]
    fn advisory_text_narrows_and_logging_is_noise() {
        let old = "package p; class Parser {
            void readHeaders() { parse(); }
            void other() { LOG.debug(\"x\"); go(); }
            void third() { a(); }
        }";
        let new = "package p; class Parser {
            void readHeaders() { if (bad) { throw new E(); } parse(); }
            void other() { if (LOG.isDebugEnabled()) { LOG.debug(\"x\"); } go(); }
            void third() { if (z) { a(); } }
        }";
        let r = propose(
            &advisory("readHeaders mishandles whitespace"),
            &[file("src/main/p/Parser.java", old, new)],
        );
        let keys: Vec<String> = r.sinks.iter().map(Sink::key).collect();
        assert_eq!(keys, ["p.Parser.readHeaders"]);
        let reasons: Vec<&str> = r
            .evidence
            .excluded
            .iter()
            .map(|e| e.reason.as_str())
            .collect();
        assert!(reasons.iter().any(|r| r.starts_with("only comments")));
        assert!(reasons.iter().any(|r| r.contains("advisory names")));
    }

    #[test]
    fn deny_list_fix_proposes_gadgets() {
        let old = "package p; class SubTypeValidator {
            static {
                s.add(\"a.b.Old\");
            }
        }";
        let new = "package p; class SubTypeValidator {
            static {
                s.add(\"a.b.Old\");
                s.add(\"com.mysql.cj.jdbc.admin.MiniAdmin\");
            }
        }";
        let r = propose(
            &advisory("gadget"),
            &[file("src/main/p/SubTypeValidator.java", old, new)],
        );
        assert_eq!(r.verdict, Verdict::DenyList);
        assert_eq!(r.gadgets, ["com.mysql.cj.jdbc.admin.MiniAdmin"]);
        assert_eq!(r.validate(), Ok(()));
    }

    #[test]
    fn tests_and_added_only_fixes_give_no_method_sink() {
        let r = propose(
            &advisory("x"),
            &[
                file(
                    "src/test/p/ATest.java",
                    "class ATest { void t() {} }",
                    "class ATest { void t() { a(); } }",
                ),
                FileChange {
                    path: "src/main/p/New.java".into(),
                    old: None,
                    new: Some("package p; class New { void f() {} }".into()),
                },
            ],
        );
        assert_eq!(r.verdict, Verdict::NoMethodSink);
        assert_eq!(r.validate(), Ok(()));
    }
}
