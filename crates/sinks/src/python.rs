//! Python source, function by function: enough of a reader to say which functions a fix commit
//! changed, written by hand because the maintained Python parsers on crates.io pull in vendored
//! C or assembly (`stacker`/`psm`) or a license outside the project's list.
//!
//! It blanks comments, tracks string literals (prefixes, triple quotes, escapes) and brackets so
//! that logical lines are right, and reads blocks by indentation. A `def` (with its decorators)
//! runs until the next line indented no deeper than it. Functions are keyed
//! `module.Class.name`; a function or class inside a function counts as part of it, as
//! anonymous classes do in the Java reader. Docstrings and other bare string statements are
//! blanked like comments, so a docstring edit is not a code change. Same names in one module
//! share an entry.

use std::collections::BTreeMap;

use crate::java::Method;

/// Whether `path` is Python source this reader takes.
#[must_use]
pub fn is_source(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.ends_with(".py")
}

/// The dotted module a repository path holds: `src/pkg/mod.py` is `pkg.mod`,
/// `pkg/__init__.py` is `pkg`.
#[must_use]
pub fn module_name(path: &str) -> String {
    let path = path.trim_start_matches("./");
    let stem = path.strip_suffix(".py").unwrap_or(path);
    let parts: Vec<&str> = stem.split('/').filter(|p| !p.is_empty()).collect();
    let start = parts.iter().rposition(|p| *p == "src").map_or(0, |i| i + 1);
    let mut parts: Vec<&str> = parts[start..].to_vec();
    if parts.last() == Some(&"__init__") && parts.len() > 1 {
        parts.pop();
    }
    // Only the trailing run of importable names is the module (`python-pkg/pkg/x.py` is `pkg.x`).
    let importable = |p: &&&str| {
        p.starts_with(|c: char| c.is_alphabetic() || c == '_')
            && p.chars().all(|c| c.is_alphanumeric() || c == '_')
    };
    let keep = parts.iter().rev().take_while(importable).count();
    parts[parts.len() - keep..].join(".")
}

/// Every function of one module, keyed `module.Class.name` (see [`module_name`]).
#[must_use]
pub fn functions(path: &str, src: &str) -> BTreeMap<String, Method> {
    let module = module_name(path);
    let (code, blank) = strip(src);
    let lines = logical_lines(&blank);
    // Docstrings and bare string statements: blank them in `code` too.
    let mut code: Vec<u8> = code.into_bytes();
    for l in &lines {
        if is_string_statement(&blank[l.start..l.end]) {
            for b in &mut code[l.start..l.end] {
                if *b != b'\n' {
                    *b = b' ';
                }
            }
        }
    }
    let code = String::from_utf8_lossy(&code).into_owned();

    struct Open {
        indent: usize,
        /// The short name, and the qualified one recorded.
        name: String,
        qual: String,
        is_def: bool,
        start: usize,
    }
    let mut stack: Vec<Open> = Vec::new();
    let mut found: Vec<(String, usize, usize)> = Vec::new();
    let mut decorator_start: Option<usize> = None;
    let mut last_end = 0;
    let close = |stack: &mut Vec<Open>, found: &mut Vec<(String, usize, usize)>, indent, end| {
        while stack.last().is_some_and(|o| o.indent >= indent) {
            if let Some(o) = stack.pop() {
                // Record a def only when no def encloses it.
                if o.is_def && !stack.iter().any(|p| p.is_def) {
                    found.push((o.qual, o.start, end));
                }
            }
        }
    };
    for l in &lines {
        let text = blank[l.start..l.end].trim();
        if text.is_empty() {
            continue;
        }
        close(&mut stack, &mut found, l.indent, last_end);
        last_end = l.end;
        if text.starts_with('@') {
            decorator_start.get_or_insert(l.start);
            continue;
        }
        let start = decorator_start.take().unwrap_or(l.start);
        if let Some((name, is_def)) = header(text) {
            let qual = std::iter::once(module.as_str())
                .chain(stack.iter().map(|o| o.name.as_str()))
                .chain(std::iter::once(name))
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join(".");
            stack.push(Open {
                indent: l.indent,
                name: name.to_string(),
                qual,
                is_def,
                start,
            });
        }
    }
    close(&mut stack, &mut found, 0, last_end);

    let mut out: BTreeMap<String, Method> = BTreeMap::new();
    for (name, start, end) in found {
        let Some(text) = code.get(start..end) else {
            continue;
        };
        let entry = out.entry(name).or_default();
        if !entry.source.is_empty() {
            entry.source.push('\n');
        }
        entry.source.push_str(text.trim_end());
        entry.key = entry.source.split_whitespace().collect();
    }
    out
}

/// `def name` / `async def name` / `class Name` at the start of a logical line.
fn header(text: &str) -> Option<(&str, bool)> {
    let (rest, is_def) = if let Some(r) = text.strip_prefix("def ") {
        (r, true)
    } else if let Some(r) = text.strip_prefix("async ") {
        (r.trim_start().strip_prefix("def ")?, true)
    } else {
        (text.strip_prefix("class ")?, false)
    };
    let rest = rest.trim_start();
    let end = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let name = &rest[..end];
    (!name.is_empty()).then_some((name, is_def))
}

/// A logical line that is only string literals (a docstring), seen in the blanked text where
/// literal contents are spaces and quotes stay.
fn is_string_statement(blank: &str) -> bool {
    let t = blank.trim();
    if t.is_empty() {
        return false;
    }
    let mut chars = t.chars().peekable();
    let mut any = false;
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() || c == '(' || c == ')' {
            chars.next();
        } else if matches!(c, 'r' | 'R' | 'b' | 'B' | 'u' | 'U' | 'f' | 'F') {
            chars.next();
            if !matches!(
                chars.peek(),
                Some('\'' | '"' | 'r' | 'R' | 'b' | 'B' | 'f' | 'F')
            ) {
                return false;
            }
        } else if c == '\'' || c == '"' {
            any = true;
            chars.next();
        } else {
            return false;
        }
    }
    any
}

struct Logical {
    start: usize,
    end: usize,
    indent: usize,
}

/// Logical lines of the blanked text: physical lines joined inside brackets and after a
/// trailing backslash. `indent` is the first physical line's (tabs to the next multiple of 8).
fn logical_lines(blank: &str) -> Vec<Logical> {
    let mut out = Vec::new();
    let bytes = blank.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        let mut indent = 0;
        let mut j = i;
        while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\x0c') {
            indent = if bytes[j] == b'\t' {
                (indent / 8 + 1) * 8
            } else {
                indent + 1
            };
            j += 1;
        }
        let mut depth: i32 = 0;
        loop {
            while j < bytes.len() && bytes[j] != b'\n' {
                match bytes[j] {
                    b'(' | b'[' | b'{' => depth += 1,
                    b')' | b']' | b'}' => depth = (depth - 1).max(0),
                    _ => {}
                }
                j += 1;
            }
            let continued = depth > 0 || (j > start && bytes[j - 1] == b'\\');
            if j >= bytes.len() || !continued {
                break;
            }
            j += 1;
        }
        out.push(Logical {
            start,
            end: j,
            indent,
        });
        i = j + 1;
    }
    out
}

/// `(code, blank)`: comments replaced by spaces in both; string literal contents kept in
/// `code` and spaces in `blank`. Offsets are byte offsets, the same in both and in `src`.
fn strip(src: &str) -> (String, String) {
    let b = src.as_bytes();
    let mut code = b.to_vec();
    let mut blank = b.to_vec();
    let mut i = 0;
    let space = |v: &mut Vec<u8>, from: usize, to: usize| {
        for x in &mut v[from..to] {
            if *x != b'\n' {
                *x = b' ';
            }
        }
    };
    while i < b.len() {
        match b[i] {
            b'#' => {
                let end = b[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .map_or(b.len(), |p| i + p);
                space(&mut code, i, end);
                space(&mut blank, i, end);
                i = end;
            }
            q @ (b'\'' | b'"') => {
                // A prefix like `rb` is already passed as an identifier; raw only changes how
                // escapes read, and a backslash still keeps the next quote in the string.
                let triple = b.len() >= i + 3 && b[i + 1] == q && b[i + 2] == q;
                let open = if triple { 3 } else { 1 };
                let mut j = i + open;
                let close;
                loop {
                    if j >= b.len() {
                        close = b.len();
                        break;
                    }
                    if b[j] == b'\\' {
                        j += 2;
                        continue;
                    }
                    if !triple && b[j] == b'\n' {
                        close = j;
                        break;
                    }
                    if b[j] == q
                        && (!triple || (b.get(j + 1) == Some(&q) && b.get(j + 2) == Some(&q)))
                    {
                        close = j + if triple { 3 } else { 1 };
                        break;
                    }
                    j += 1;
                }
                let close = close.min(b.len());
                let inner_end = close.saturating_sub(open).max(i + open);
                // Newlines too, so a triple-quoted string stays inside one logical line.
                for x in &mut blank[(i + open).min(b.len())..inner_end.min(b.len())] {
                    *x = b' ';
                }
                i = close;
            }
            _ => i += 1,
        }
    }
    (
        String::from_utf8_lossy(&code).into_owned(),
        String::from_utf8_lossy(&blank).into_owned(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const SRC: &str = r#"
"""Module docstring."""
import os  # comment

@decorator(
    arg=1,
)
def parse(data, *, strict=False):
    """Parse it."""
    text = "def not_a_function(): # not a comment"
    return helper(data, {
        "k": 1,
    })

async def fetch(url):
    return url

class Loader(Base):
    '''Loads.'''

    def load(self, path):
        def inner():
            return 1
        return inner()

    @property
    def name(self):
        return 'x'  # trailing

def helper(a, b):
    s = """
def fake():
    pass
"""
    return a
"#;

    #[test]
    fn functions_by_indentation_with_decorators() {
        let f = functions("src/pkg/core.py", SRC);
        let keys: Vec<&str> = f.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "pkg.core.Loader.load",
                "pkg.core.Loader.name",
                "pkg.core.fetch",
                "pkg.core.helper",
                "pkg.core.parse",
            ]
        );
        let parse = &f["pkg.core.parse"].source;
        assert!(parse.starts_with("@decorator("), "{parse}");
        assert!(parse.contains("\"k\": 1"), "{parse}");
        assert!(!parse.contains("Parse it"), "docstring kept: {parse}");
        assert!(
            parse.contains("def not_a_function"),
            "string literal kept: {parse}"
        );
        assert!(f["pkg.core.Loader.load"].source.contains("def inner"));
        assert!(!f["pkg.core.Loader.name"].source.contains("trailing"));
        assert!(f["pkg.core.helper"].source.contains("def fake"));
    }

    #[test]
    fn module_names() {
        assert_eq!(module_name("src/pkg/mod.py"), "pkg.mod");
        assert_eq!(module_name("pkg/__init__.py"), "pkg");
        assert_eq!(module_name("libs/x/src/a/b.py"), "a.b");
        assert_eq!(module_name("setup.py"), "setup");
        assert_eq!(module_name("python-pkg/pkg/x.py"), "pkg.x");
    }

    #[test]
    fn a_docstring_only_change_keeps_the_key() {
        let a = functions("m.py", "def f(x):\n    \"\"\"Old.\"\"\"\n    return x\n");
        let b = functions(
            "m.py",
            "def f(x):\n    \"\"\"New text.\"\"\"\n    return x  # note\n",
        );
        assert_eq!(a["m.f"].key, b["m.f"].key);
    }
}
