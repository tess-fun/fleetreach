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

use crate::calls::{Expr, ModuleFacts, Spec, MAIN};
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

/// What one module defines, imports and calls, for the call graph (`crate::calls`). Function
/// names are those of [`functions`] without the module.
#[must_use]
pub fn facts(src: &str) -> ModuleFacts {
    let (_, blank) = strip(src);
    let lines = logical_lines(&blank);
    // From the source: the blanked text turns newlines inside strings into spaces.
    let line_starts: Vec<usize> = std::iter::once(0)
        .chain(src.match_indices('\n').map(|(i, _)| i + 1))
        .collect();
    let line_of =
        |at: usize| u32::try_from(line_starts.partition_point(|&s| s <= at)).unwrap_or(u32::MAX);

    struct Open {
        indent: usize,
        name: String,
        is_def: bool,
    }
    let mut stack: Vec<Open> = Vec::new();
    let mut facts = ModuleFacts::default();
    for l in &lines {
        let raw = &blank[l.start..l.end];
        let text = raw.trim();
        if text.is_empty() || is_string_statement(raw) {
            continue;
        }
        while stack.last().is_some_and(|o| o.indent >= l.indent) {
            stack.pop();
        }
        // The outermost def on the stack owns what runs here.
        let scope = stack
            .iter()
            .position(|o| o.is_def)
            .map(|i| {
                stack[..=i]
                    .iter()
                    .map(|o| o.name.as_str())
                    .collect::<Vec<_>>()
                    .join(".")
            })
            .unwrap_or_default();
        let offset = l.start + (raw.len() - raw.trim_start().len());
        if let Some((name, is_def)) = header(text) {
            let qual = stack
                .iter()
                .map(|o| o.name.as_str())
                .chain(std::iter::once(name))
                .collect::<Vec<_>>()
                .join(".");
            let enclosed = stack.iter().any(|o| o.is_def);
            if !enclosed {
                if is_def {
                    facts.functions.entry(qual).or_default();
                } else {
                    facts.classes.insert(qual, class_bases(text));
                }
            }
            stack.push(Open {
                indent: l.indent,
                name: name.to_string(),
                is_def,
            });
            continue;
        }
        // `if __name__ == "__main__":` at the top level runs only as a script.
        if stack.is_empty() && is_main_guard(text) {
            stack.push(Open {
                indent: l.indent,
                name: MAIN.to_string(),
                is_def: true,
            });
            facts.functions.entry(MAIN.to_string()).or_default();
            continue;
        }
        if !text.starts_with('@') {
            statement(&mut facts, &scope, text, line_of(offset));
            // What a function returns, from its own body (not a nested def's).
            if let Some(value) = text.strip_prefix("return ") {
                if stack.iter().filter(|o| o.is_def).count() == 1 {
                    if let Some(v) = chain_value(value.trim()) {
                        facts.ret(&scope, v);
                    }
                }
            }
        }
        for (at, callee) in chains(text) {
            facts.call(&scope, callee, line_of(offset + at));
        }
    }
    facts
}

/// Imports and assignments of one logical line (decorators and headers excluded).
fn statement(facts: &mut ModuleFacts, scope: &str, text: &str, line: u32) {
    let flat: String = text
        .chars()
        .map(|c| {
            if matches!(c, '(' | ')' | '\\' | '\n') {
                ' '
            } else {
                c
            }
        })
        .collect();
    let words = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(rest) = words.strip_prefix("import ") {
        for item in rest.split(',') {
            let mut it = item.trim().splitn(2, " as ");
            let module = it.next().unwrap_or("").trim();
            if !is_dotted(module) {
                continue;
            }
            let spec = Spec::Py {
                module: module.to_string(),
                level: 0,
            };
            facts.import(scope, spec.clone(), line);
            match it.next().map(str::trim) {
                Some(alias) if is_ident(alias) => {
                    facts.bind(scope, alias.to_string(), Expr::Import(spec))
                }
                _ => {
                    let top = module.split('.').next().unwrap_or(module);
                    let top_spec = Spec::Py {
                        module: top.to_string(),
                        level: 0,
                    };
                    facts.bind(scope, top.to_string(), Expr::Import(top_spec));
                }
            }
        }
        return;
    }
    if let Some(rest) = words.strip_prefix("from ") {
        let Some((module, names)) = rest.split_once(" import ") else {
            return;
        };
        let module = module.trim();
        let level = module.chars().take_while(|c| *c == '.').count();
        let name = &module[level..];
        if !(name.is_empty() || is_dotted(name)) {
            return;
        }
        let spec = Spec::Py {
            module: name.to_string(),
            level,
        };
        facts.import(scope, spec.clone(), line);
        for item in names.split(',') {
            let item = item.trim();
            if item == "*" {
                facts.star.push(Expr::Import(spec.clone()));
                continue;
            }
            let mut it = item.splitn(2, " as ");
            let n = it.next().unwrap_or("").trim();
            let local = it.next().map_or(n, str::trim);
            if is_ident(n) && is_ident(local) {
                let v = Expr::Member(Box::new(Expr::Import(spec.clone())), n.to_string());
                facts.bind(scope, local.to_string(), v);
            }
        }
        return;
    }
    // `with A() as a:`
    let unasync = text.strip_prefix("async ").unwrap_or(text).trim_start();
    if let Some(rest) = unasync.strip_prefix("with ") {
        for item in top_level_split(rest.trim_end().trim_end_matches(':')) {
            if let Some((value, local)) = item.split_once(" as ") {
                let local = local.trim();
                if is_ident(local) {
                    if let Some(v) = chain_value(value.trim()) {
                        facts.bind(scope, local.to_string(), v);
                    }
                }
            }
        }
        return;
    }
    // `name = value` and `name: T = value`
    let ident_end = text
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(text.len());
    let name = &text[..ident_end];
    if name.is_empty() || !is_ident(name) || is_keyword(name) {
        return;
    }
    let rest = text[ident_end..].trim_start();
    let rest = match rest.strip_prefix(':') {
        Some(annotated) => match annotated.find('=') {
            Some(i) => &annotated[i..],
            None => return,
        },
        None => rest,
    };
    if let Some(value) = rest.strip_prefix('=') {
        if value.starts_with('=') {
            return;
        }
        if let Some(v) = chain_value(value.trim()) {
            facts.bind(scope, name.to_string(), v);
        }
    }
}

/// `if __name__ == "__main__":` in blanked text (string contents are spaces, so only the
/// shape is checked).
fn is_main_guard(text: &str) -> bool {
    let t: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    t.starts_with("if__name__==")
        && t.ends_with(':')
        && t.len() <= "if__name__==\"________\":".len() + 2
}

/// `text` split at commas outside brackets.
fn top_level_split(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut from) = (0i32, 0);
    for (i, c) in text.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&text[from..i]);
                from = i + 1;
            }
            _ => {}
        }
    }
    out.push(&text[from..]);
    out
}

/// The base classes of a `class` header, as names (keywords such as `metaclass=` skipped).
fn class_bases(text: &str) -> Vec<Expr> {
    let Some(open) = text.find('(') else {
        return Vec::new();
    };
    let inner = &text[open + 1..text.rfind(')').unwrap_or(text.len())];
    top_level_split(inner)
        .into_iter()
        .filter(|b| !b.contains('='))
        .filter_map(|b| chain_value(b.trim()))
        .collect()
}

/// The value a chain such as `a.b(x).c` at the start of `text` is.
fn chain_value(text: &str) -> Option<Expr> {
    let b = text.as_bytes();
    if !b
        .first()
        .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
    {
        return None;
    }
    let (expr, _, _) = parse_chain(b, 0);
    (expr != Expr::Unknown).then_some(expr)
}

/// Every call in a logical line: the offset of its `(` and the callee.
fn chains(text: &str) -> Vec<(usize, Expr)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let starts = (c.is_ascii_alphabetic() || c == b'_')
            && (i == 0
                || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_' || b[i - 1] == b'.'));
        if !starts {
            i += 1;
            continue;
        }
        let end = ident_end(b, i);
        if is_keyword(&text[i..end]) {
            i = end;
            continue;
        }
        let (_, sites, _) = parse_chain(b, i);
        out.extend(sites);
        i = end;
    }
    out
}

fn ident_end(b: &[u8], from: usize) -> usize {
    let mut j = from;
    while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_' || b[j] >= 0x80) {
        j += 1;
    }
    j
}

/// Parse `name(.name | (...) | [...])*` from `start`: the value, the calls on the way, and the
/// end offset.
fn parse_chain(b: &[u8], start: usize) -> (Expr, Vec<(usize, Expr)>, usize) {
    let end = ident_end(b, start);
    let word = String::from_utf8_lossy(&b[start..end]).into_owned();
    let mut expr = if word == "self" || word == "cls" {
        Expr::This
    } else {
        Expr::Name(word)
    };
    let mut sites = Vec::new();
    let mut j = end;
    loop {
        let mut k = j;
        while k < b.len() && b[k] == b' ' {
            k += 1;
        }
        match b.get(k) {
            Some(b'.') => {
                let mut n = k + 1;
                while n < b.len() && b[n] == b' ' {
                    n += 1;
                }
                let e = ident_end(b, n);
                if e == n {
                    break;
                }
                let member = String::from_utf8_lossy(&b[n..e]).into_owned();
                expr = Expr::Member(Box::new(expr), member);
                j = e;
            }
            Some(b'(') => {
                if expr != Expr::Unknown {
                    sites.push((k, expr.clone()));
                }
                expr = Expr::Call(Box::new(expr));
                j = matching(b, k);
            }
            Some(b'[') => {
                expr = Expr::Unknown;
                j = matching(b, k);
            }
            _ => break,
        }
    }
    (expr, sites, j)
}

/// The offset after the bracket closing the one at `open` (strings are already blank).
fn matching(b: &[u8], open: usize) -> usize {
    let mut depth = 0i32;
    let mut j = open;
    while j < b.len() {
        match b[j] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
        j += 1;
    }
    b.len()
}

fn is_ident(s: &str) -> bool {
    s.starts_with(|c: char| c.is_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

fn is_dotted(s: &str) -> bool {
    !s.is_empty() && s.split('.').all(is_ident)
}

fn is_keyword(w: &str) -> bool {
    matches!(
        w,
        "if" | "elif"
            | "else"
            | "while"
            | "for"
            | "in"
            | "not"
            | "and"
            | "or"
            | "return"
            | "yield"
            | "await"
            | "lambda"
            | "assert"
            | "del"
            | "raise"
            | "except"
            | "with"
            | "as"
            | "import"
            | "from"
            | "is"
            | "None"
            | "True"
            | "False"
            | "global"
            | "nonlocal"
            | "pass"
            | "try"
            | "finally"
            | "async"
            | "def"
            | "class"
            | "break"
            | "continue"
            | "match"
            | "case"
    )
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
    fn facts_bind_imports_and_calls() {
        let src = "import os.path\nfrom .util import helper as h\nfrom lxml import etree\nimport yaml as y\n\n\
                   class Loader(Base, metaclass=M):\n    def load(self, p):\n        doc = etree.parse(p)\n        \
                   doc.getroot().find('x')\n        return self.check(h(y.load(p)))\n\n\
                   def main():\n    from x import f\n    with Loader() as l:\n        l.load(\"(a)\")\n";
        let f = facts(src);
        assert!(f.functions.contains_key("Loader.load") && f.functions.contains_key("main"));
        assert_eq!(f.classes["Loader"], vec![Expr::Name("Base".into())]);
        let calls: Vec<String> = f.functions["Loader.load"]
            .calls
            .iter()
            .map(|c| format!("{:?}@{}", c.callee, c.line))
            .collect();
        assert!(
            calls
                .iter()
                .any(|c| c.starts_with("Member(Name(\"etree\"), \"parse\")@8")),
            "{calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|c| c.starts_with("Member(This, \"check\")")),
            "{calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|c| c.starts_with("Member(Name(\"y\"), \"load\")")),
            "{calls:?}"
        );
        assert!(
            calls.iter().any(|c| c.starts_with("Name(\"h\")")),
            "{calls:?}"
        );
        assert_eq!(
            f.bindings["h"],
            Expr::Member(
                Box::new(Expr::Import(Spec::Py {
                    module: "util".into(),
                    level: 1
                })),
                "helper".into()
            )
        );
        assert_eq!(
            f.bindings["os"],
            Expr::Import(Spec::Py {
                module: "os".into(),
                level: 0
            })
        );
        let main = &f.functions["main"];
        assert_eq!(
            main.locals["l"],
            Expr::Call(Box::new(Expr::Name("Loader".into())))
        );
        assert!(main.locals.contains_key("f"));
        assert!(main
            .calls
            .iter()
            .any(|c| c.callee == Expr::Member(Box::new(Expr::Name("l".into())), "load".into())));
    }

    #[test]
    fn call_lines_count_newlines_inside_strings() {
        let f = facts("def f():\n    '''Doc\n    more.\n    '''\n    g()\n");
        assert_eq!(f.functions["f"].calls[0].line, 5);
    }

    #[test]
    fn main_guard_code_is_its_own_entry_point() {
        let f = facts(
            "import a\n\ndef run():\n    import b\n\nif __name__ == '__main__':\n    run()\n",
        );
        assert_eq!(f.functions[MAIN].calls[0].callee, Expr::Name("run".into()));
        assert!(f.functions.get("").is_none_or(|t| t.calls.is_empty()));
        let scopes: Vec<(&str, u32)> = f.imports.iter().map(|(s, _, l)| (s.as_str(), *l)).collect();
        assert_eq!(scopes, [("", 1), ("run", 4)]);
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
