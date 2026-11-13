//! JavaScript and TypeScript source, function by function, through `oxc_parser`: enough to say
//! which functions a fix commit changed.
//!
//! A function is named from where it is defined: a declaration (`function parse`), a variable
//! (`const parse = () => ...`), a class method (`Parser.parse`), an object property
//! (`{ parse() {} }`), or an assignment (`exports.parse = ...`, `Parser.prototype.parse =
//! ...`, which give `parse` and `Parser.parse`). Functions inside a named function count as
//! part of it, as anonymous classes do in the Java reader, so a callback's change is a change to
//! the function that passes it. Anonymous wrappers (an IIFE, a UMD factory) are not functions
//! of their own: what they define is named as if at the top level. Same names in one file
//! share an entry.
//!
//! Keys are `file.name` with the repository path as the file (`lib/parse.js.Parser.parse`),
//! split by [`crate::record::Sink`] at the last dot into the file plus class and the method.

use std::collections::BTreeMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ArrowFunctionExpression, AssignmentExpression, Class, Expression, Function, MethodDefinition,
    ObjectProperty, Program, VariableDeclarator,
};
use oxc_ast_visit::{walk, Visit};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};
use oxc_syntax::scope::ScopeFlags;

use crate::java::Method;

/// Whether `path` is JavaScript or TypeScript source this reader takes (declaration files
/// hold no code).
#[must_use]
pub fn is_source(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    if p.ends_with(".d.ts") || p.ends_with(".min.js") {
        return false;
    }
    [".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"]
        .iter()
        .any(|ext| p.ends_with(ext))
}

/// Every named function of one file, keyed `path.name`. A file that does not parse gives
/// nothing (the caller sees no candidates, never a wrong one).
#[must_use]
pub fn functions(path: &str, src: &str) -> BTreeMap<String, Method> {
    let source_type = SourceType::from_path(path)
        .unwrap_or_default()
        .with_module(true);
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, src, source_type).parse();
    if ret.fatal_error {
        return BTreeMap::new();
    }
    let program = ret.program;
    let mut finder = Finder::default();
    finder.visit_program(&program);
    let comments: Vec<Span> = program.comments.iter().map(|c| c.span).collect();
    let mut out: BTreeMap<String, Method> = BTreeMap::new();
    for (name, span) in finder.found {
        let text = blank_comments(src, span, &comments);
        let entry = out.entry(format!("{path}.{name}")).or_default();
        if !entry.source.is_empty() {
            entry.source.push('\n');
        }
        entry.source.push_str(&text);
        entry.key = entry.source.split_whitespace().collect();
    }
    out
}

/// `src[span]` with each comment inside it replaced by spaces (newlines kept, so lines line up).
fn blank_comments(src: &str, span: Span, comments: &[Span]) -> String {
    let (start, end) = (span.start as usize, span.end as usize);
    let Some(text) = src.get(start..end) else {
        return String::new();
    };
    let mut bytes = text.as_bytes().to_vec();
    for c in comments {
        let (cs, ce) = (c.start as usize, c.end as usize);
        if cs >= start && ce <= end {
            for b in &mut bytes[cs - start..ce - start] {
                if *b != b'\n' {
                    *b = b' ';
                }
            }
        }
    }
    // Blanking whole comments keeps UTF-8 valid except inside a comment's multi-byte
    // characters, which become spaces byte by byte; fall back to lossless text if not.
    String::from_utf8(bytes).unwrap_or_else(|_| text.to_string())
}

#[derive(Default)]
struct Finder {
    /// Name the next function gets from its context (a declarator, property or assignment).
    pending: Option<String>,
    /// Enclosing class names, for methods.
    classes: Vec<String>,
    /// Depth inside a named function: functions in there are part of it.
    inside: usize,
    found: Vec<(String, Span)>,
}

impl Finder {
    fn record(&mut self, name: String, span: Span) {
        if self.inside == 0 {
            self.found.push((name, span));
        }
    }

    /// A function value with a name from its context: record it and walk it as one body.
    fn named(&mut self, name: Option<String>, span: Span, walk_it: impl FnOnce(&mut Self)) {
        match name {
            Some(name) => {
                self.record(name, span);
                self.inside += 1;
                walk_it(self);
                self.inside -= 1;
            }
            None => walk_it(self),
        }
    }

    fn qualified(&self, name: &str) -> String {
        match self.classes.last() {
            Some(class) => format!("{class}.{name}"),
            None => name.to_string(),
        }
    }
}

/// The function or class a value expression is, if any (parentheses removed).
fn is_function_value(e: &Expression<'_>) -> bool {
    matches!(
        e.without_parentheses(),
        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
    )
}

/// `a.b.c` as its last two names: `Parser.prototype.parse` gives `Parser.parse`,
/// `module.exports.parse` and `exports.parse` give `parse`.
fn member_name(e: &Expression<'_>) -> Option<String> {
    let mut parts = Vec::new();
    let mut cur = e;
    loop {
        match cur {
            Expression::StaticMemberExpression(m) => {
                parts.push(m.property.name.to_string());
                cur = &m.object;
            }
            Expression::Identifier(id) => {
                parts.push(id.name.to_string());
                break;
            }
            Expression::ThisExpression(_) => break,
            _ => return None,
        }
    }
    parts.reverse();
    let parts: Vec<String> = parts
        .into_iter()
        .filter(|p| p != "prototype" && p != "module" && p != "exports" && p != "default")
        .collect();
    match parts.as_slice() {
        [] => None,
        [name] => Some(name.clone()),
        [.., owner, name] => Some(format!("{owner}.{name}")),
    }
}

impl<'a> Visit<'a> for Finder {
    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        let name = it
            .id
            .as_ref()
            .map(|id| id.name.to_string())
            .or_else(|| self.pending.take());
        let name = name.map(|n| self.qualified(&n));
        self.named(name, it.span, |me| walk::walk_function(me, it, flags));
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        let name = self.pending.take().map(|n| self.qualified(&n));
        self.named(name, it.span, |me| {
            walk::walk_arrow_function_expression(me, it);
        });
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let (Some(init), Some(name)) = (&it.init, it.id.get_binding_identifier()) {
            if is_function_value(init) {
                self.pending = Some(name.name.to_string());
            } else if let Expression::ClassExpression(_) = init.without_parentheses() {
                self.pending = Some(name.name.to_string());
            }
        }
        walk::walk_variable_declarator(self, it);
        self.pending = None;
    }

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        if is_function_value(&it.value) {
            self.pending = it.key.static_name().map(|n| n.display().to_string());
        }
        walk::walk_object_property(self, it);
        self.pending = None;
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if is_function_value(&it.right) {
            let name = it
                .left
                .as_simple_assignment_target()
                .and_then(|t| t.as_member_expression())
                .and_then(|m| {
                    let prop = m.static_property_name()?.display().to_string();
                    let owner = member_name(m.object());
                    Some(match owner {
                        Some(o) => format!("{o}.{prop}"),
                        None => prop,
                    })
                })
                .or_else(|| it.left.get_identifier_name().map(str::to_string));
            // `exports.parse = ...` names `parse`, `A.prototype.b = ...` names `A.b`.
            self.pending = name.map(|n| {
                let parts: Vec<&str> = n
                    .split('.')
                    .filter(|p| !matches!(*p, "prototype" | "module" | "exports" | "default"))
                    .collect();
                match parts.as_slice() {
                    [] => n.clone(),
                    [one] => (*one).to_string(),
                    [.., owner, last] => format!("{owner}.{last}"),
                }
            });
        }
        walk::walk_assignment_expression(self, it);
        self.pending = None;
    }

    fn visit_class(&mut self, it: &Class<'a>) {
        let name = it
            .id
            .as_ref()
            .map(|id| id.name.to_string())
            .or_else(|| self.pending.take())
            .unwrap_or_else(|| "default".to_string());
        self.classes.push(name);
        walk::walk_class(self, it);
        self.classes.pop();
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        let name = it
            .key
            .static_name()
            .map(|n| n.display().to_string())
            .unwrap_or_else(|| "[computed]".to_string());
        let name = if it.kind.is_constructor() {
            "constructor".to_string()
        } else {
            name
        };
        let name = self.qualified(&name);
        self.named(Some(name), it.span(), |me| {
            walk::walk_method_definition(me, it);
        });
    }

    fn visit_program(&mut self, it: &Program<'a>) {
        walk::walk_program(self, it);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const SRC: &str = r#"
'use strict';
// a header comment
function parse(input) { return helper(input, x => x + 1); }
const helper = (a, f) => { /* inner */ return f(a); };
class Parser {
  constructor(o) { this.o = o; }
  run() { function inner() { return 1; } return inner(); }
}
Parser.prototype.legacy = function () { return 2; };
module.exports.render = function render() { return 3; };
exports.escape = s => s.replace(/</g, '&lt;');
const api = { decode(s) { return s; }, value: 1 };
(function () { function wrapped() { return 4; } })();
"#;

    #[test]
    fn names_functions_from_where_they_are_defined() {
        let f = functions("lib/p.js", SRC);
        let keys: Vec<&str> = f.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "lib/p.js.Parser.constructor",
                "lib/p.js.Parser.legacy",
                "lib/p.js.Parser.run",
                "lib/p.js.decode",
                "lib/p.js.escape",
                "lib/p.js.helper",
                "lib/p.js.parse",
                "lib/p.js.render",
                "lib/p.js.wrapped",
            ]
        );
        // Comments are blanked; a nested function is part of its parent.
        assert!(!f["lib/p.js.helper"].source.contains("inner"));
        assert!(f["lib/p.js.Parser.run"].source.contains("function inner"));
    }

    #[test]
    fn typescript_and_unparseable_files() {
        let ts = "export function check(a: string): boolean { return a.length > 0; }\n\
                  export default class Guard { allow(x: number): void {} }\n";
        let f = functions("src/g.ts", ts);
        assert!(f.contains_key("src/g.ts.check"), "{:?}", f.keys());
        assert!(f.contains_key("src/g.ts.Guard.allow"), "{:?}", f.keys());
        assert!(functions("x.js", "function (( {").is_empty());
        assert!(is_source("a/b.tsx") && !is_source("a/b.d.ts") && !is_source("a.min.js"));
    }
}
