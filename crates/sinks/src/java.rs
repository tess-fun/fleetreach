//! Java source, method by method: enough of a parser to say which methods a fix commit
//! changed. It tracks braces outside comments and literals, names classes (nested ones joined
//! with `$`) and methods (constructors as `<init>`, static blocks as `<clinit>`), and keeps
//! each method's text with comments removed. Bodies of anonymous and local classes count as
//! part of the method declaring them. Overloads share one entry: a change to any of them is
//! a change to the name.

use std::collections::BTreeMap;

/// One method's text: `source` is the declaration with comments blanked (string literals
/// kept), `key` its whitespace-free form for comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Method {
    pub source: String,
    pub key: String,
}

/// Every method of a compilation unit, by `pkg.Outer$Inner.method`.
#[must_use]
pub fn methods(src: &str) -> BTreeMap<String, Method> {
    let chars: Vec<char> = src.chars().collect();
    // Structure is read from `blank` (comments and literal contents blanked); text is taken
    // from `code` (comments blanked, literals kept), which has the same offsets.
    let blank = strip(&chars, true);
    let code = strip(&chars, false);
    let blank_str: String = blank.iter().collect();
    let pkg = package(&blank_str);

    enum Frame {
        Class(String),
        Method(String, usize),
        Block,
    }
    let mut stack: Vec<Frame> = Vec::new();
    let mut last = 0;
    let mut out: BTreeMap<String, Method> = BTreeMap::new();
    for (i, &c) in blank.iter().enumerate() {
        if !matches!(c, ';' | '{' | '}') {
            continue;
        }
        if c == '{' {
            let header = remove_annotations(&blank[last..i].iter().collect::<String>());
            let in_class = matches!(stack.last(), None | Some(Frame::Class(_)));
            let frame = if let (true, Some(name)) = (in_class, class_name(&header)) {
                Frame::Class(name)
            } else if matches!(stack.last(), Some(Frame::Class(_))) {
                if let Some(name) = method_name(&header) {
                    Frame::Method(name, last)
                } else if header.trim() == "static" {
                    Frame::Method("<clinit>".into(), last)
                } else {
                    Frame::Block
                }
            } else {
                Frame::Block
            };
            stack.push(frame);
        } else if c == '}' {
            if let Some(Frame::Method(name, start)) = stack.pop() {
                let classes: Vec<&str> = stack
                    .iter()
                    .filter_map(|f| match f {
                        Frame::Class(n) => Some(n.as_str()),
                        _ => None,
                    })
                    .collect();
                if let Some(&innermost) = classes.last() {
                    let name = if name == innermost {
                        "<init>"
                    } else {
                        name.as_str()
                    };
                    let key = format!("{pkg}{}.{name}", classes.join("$"));
                    let text: String = code[start..=i].iter().collect();
                    let entry = out.entry(key).or_default();
                    entry
                        .key
                        .extend(text.chars().filter(|c| !c.is_whitespace()));
                    entry.source.push_str(text.trim());
                    entry.source.push('\n');
                }
            }
        }
        last = i + 1;
    }
    out
}

/// Blank comments (keeping newlines), and string and char literal contents when
/// `literals` is set, so offsets stay the same as the source's.
fn strip(src: &[char], literals: bool) -> Vec<char> {
    let mut out = src.to_vec();
    let n = src.len();
    let at = |i: usize, s: &str| {
        s.chars()
            .enumerate()
            .all(|(k, c)| src.get(i + k) == Some(&c))
    };
    let mut i = 0;
    while i < n {
        if at(i, "//") {
            while i < n && src[i] != '\n' {
                out[i] = ' ';
                i += 1;
            }
        } else if at(i, "/*") {
            let mut j = i + 2;
            while j < n && !at(j, "*/") {
                j += 1;
            }
            let end = (j + 2).min(n);
            blank(&mut out[i..end], ' ');
            i = end;
        } else if at(i, "\"\"\"") {
            let mut j = i + 3;
            while j < n && !at(j, "\"\"\"") {
                j += 1;
            }
            if literals {
                blank(&mut out[(i + 3).min(n)..j.min(n)], ' ');
            }
            i = (j + 3).min(n);
        } else if src[i] == '"' || src[i] == '\'' {
            let quote = src[i];
            let mut j = i + 1;
            while j < n && src[j] != quote && src[j] != '\n' {
                j += if src[j] == '\\' { 2 } else { 1 };
            }
            if literals {
                out[(i + 1).min(n)..j.min(n)].fill('x');
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Overwrite every character but newlines.
fn blank(span: &mut [char], with: char) {
    for c in span.iter_mut().filter(|c| **c != '\n') {
        *c = with;
    }
}

fn package(src: &str) -> String {
    for line in src.lines() {
        let Some(rest) = line.trim_start().strip_prefix("package") else {
            continue;
        };
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        if let Some((name, _)) = rest.split_once(';') {
            let name = name.trim();
            if !name.is_empty() && name.chars().all(|c| is_word(c) || c == '.') {
                return format!("{name}.");
            }
        }
    }
    String::new()
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Drop `@Name` and `@Name(...)` (one level of nested parentheses), as annotations sit in
/// headers and their parentheses would read as a method's.
fn remove_annotations(header: &str) -> String {
    let c: Vec<char> = header.chars().collect();
    let mut out = String::with_capacity(header.len());
    let mut i = 0;
    while i < c.len() {
        if c[i] != '@' {
            out.push(c[i]);
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < c.len() && (is_word(c[j]) || c[j] == '.') {
            j += 1;
        }
        if j == i + 1 {
            out.push('@');
            i += 1;
            continue;
        }
        let mut k = j;
        while k < c.len() && c[k].is_whitespace() {
            k += 1;
        }
        if c.get(k) == Some(&'(') {
            let mut depth = 0;
            let mut m = k;
            while m < c.len() {
                match c[m] {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                m += 1;
            }
            if m < c.len() && depth == 0 {
                j = m + 1;
            }
        }
        out.push(' ');
        i = j;
    }
    out
}

/// `class|interface|enum|record Name` in a header, unless it sits right after `(`.
fn class_name(header: &str) -> Option<String> {
    let words: Vec<(usize, &str)> = word_spans(header);
    for (w, &(start, word)) in words.iter().enumerate() {
        if matches!(word, "class" | "interface" | "enum" | "record") {
            let (_, name) = *words.get(w + 1)?;
            let before = header[..start].trim_end_matches(|c: char| c.is_whitespace());
            if before.ends_with('(') {
                return None;
            }
            return Some(name.to_string());
        }
    }
    None
}

fn word_spans(s: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in s.char_indices() {
        match (is_word(c), start) {
            (true, None) => start = Some(i),
            (false, Some(st)) => {
                out.push((st, &s[st..i]));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(st) = start {
        out.push((st, &s[st..]));
    }
    out
}

const KEYWORDS: &[&str] = &[
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "synchronized",
    "try",
    "return",
    "new",
    "else",
    "do",
    "finally",
];

/// The method a header declares: `name(...)` at the end, optionally `throws A, B`, no `=`.
fn method_name(header: &str) -> Option<String> {
    if header.contains('=') {
        return None;
    }
    let h = header.trim();
    let close = h.rfind(')')?;
    let tail = h[close + 1..].trim();
    if !tail.is_empty() {
        let rest = tail.strip_prefix("throws")?;
        if !rest.starts_with(char::is_whitespace)
            || !rest
                .chars()
                .all(|c| is_word(c) || c.is_whitespace() || matches!(c, '.' | ',' | '<' | '>'))
        {
            return None;
        }
    }
    // The first `word (` before the last `)`.
    for (i, c) in h[..close].char_indices() {
        if c != '(' {
            continue;
        }
        let before = h[..i].trim_end();
        let word_start = before
            .char_indices()
            .rev()
            .take_while(|&(_, c)| is_word(c))
            .last()
            .map(|(k, _)| k)?;
        let name = &before[word_start..];
        if KEYWORDS.contains(&name) {
            return None;
        }
        return Some(name.to_string());
    }
    None
}

/// Test sources, which never hold a library's sinks.
#[must_use]
pub fn is_test_path(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("/test/")
        || p.contains("/tests/")
        || p.starts_with("test")
        || p.contains("/it/")
        || p.ends_with("test.java")
        || p.ends_with("tests.java")
        || p.contains("/testing/")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = r#"
package org.ex;

import java.util.List;

/** A { brace in a comment */
@SuppressWarnings({"unchecked", "rawtypes"})
public class Outer extends Base {
    static { INIT = "}"; }
    private int x = 1;

    public Outer(int x) { this.x = x; }

    @Override
    public <T> List<T> read(String s) throws java.io.IOException, IllegalStateException {
        if (s == null) { return null; } // a { comment
        Runnable r = new Runnable() { public void run() { go(); } };
        return List.of();
    }

    static class Inner {
        void go(int a) { a++; }
        void go(String b) { }
    }

    interface Shape { double area(); }
}
"#;

    #[test]
    fn methods_are_named_like_bytecode() {
        let m = methods(SRC);
        let keys: Vec<&str> = m.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "org.ex.Outer$Inner.go",
                "org.ex.Outer.<clinit>",
                "org.ex.Outer.<init>",
                "org.ex.Outer.read",
            ]
        );
        // The anonymous class's method belongs to `read`; comments are gone, strings kept.
        assert!(m["org.ex.Outer.read"].source.contains("go();"));
        assert!(!m["org.ex.Outer.read"].source.contains("a { comment"));
        assert!(m["org.ex.Outer.<clinit>"].source.contains("\"}\""));
    }

    #[test]
    fn comment_only_changes_are_not_changes() {
        let a = methods("class A { void f() { g(); } }");
        let b = methods("class A { void f() {\n  // why\n  g();\n} }");
        assert_eq!(a["A.f"].key, b["A.f"].key);
        let c = methods("class A { void f() { g(\"x\"); } }");
        assert_ne!(a["A.f"].key, c["A.f"].key);
    }

    #[test]
    fn headers() {
        assert_eq!(method_name(" public void run() "), Some("run".into()));
        assert_eq!(method_name(" if (x) "), None);
        assert_eq!(method_name(" int[] a = new int[] "), None);
        assert_eq!(method_name(" void f() throws X, y.Z "), Some("f".into()));
        assert_eq!(method_name(" void f() extra "), None);
        assert_eq!(
            remove_annotations("@A(b = (1)) @c.D void f()"),
            "    void f()"
        );
        assert_eq!(
            class_name(" public final class Foo<T> "),
            Some("Foo".into())
        );
        assert_eq!(class_name(" foo(class X "), None);
    }
}
