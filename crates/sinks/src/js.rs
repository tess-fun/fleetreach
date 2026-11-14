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
    Argument, ArrowFunctionExpression, AssignmentExpression, BindingPattern, CallExpression,
    ChainElement, Class, Declaration, ExportAllDeclaration, ExportDeclaration,
    ExportDefaultDeclaration, ExportDefaultDeclarationKind, ExportFromDeclaration,
    ExportNamedDeclaration, Expression, Function, ImportDeclaration, ImportDeclarationSpecifier,
    ImportExpression, MethodDefinition, NewExpression, ObjectProperty, ObjectPropertyKind, Program,
    ReturnStatement, VariableDeclarator,
};
use oxc_ast_visit::{walk, Visit};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};
use oxc_syntax::scope::ScopeFlags;

use crate::calls::{Expr, ModuleFacts, Spec, MAX_LINKS};
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

/// `src` parsed as a module of the kind its path names; `None` when it does not parse.
fn parse<'a>(allocator: &'a Allocator, path: &str, src: &'a str) -> Option<Program<'a>> {
    let source_type = SourceType::from_path(path)
        .unwrap_or_default()
        .with_module(true);
    let ret = Parser::new(allocator, src, source_type).parse();
    (!ret.fatal_error).then_some(ret.program)
}

/// Every named function of one file, keyed `path.name`. A file that does not parse gives
/// nothing (the caller sees no candidates, never a wrong one).
#[must_use]
pub fn functions(path: &str, src: &str) -> BTreeMap<String, Method> {
    crate::stack::on_own_stack(src, &crate::stack::JS, || functions_here(path, src))
        .unwrap_or_default()
}

fn functions_here(path: &str, src: &str) -> BTreeMap<String, Method> {
    let allocator = Allocator::default();
    let Some(program) = parse(&allocator, path, src) else {
        return BTreeMap::new();
    };
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

/// What one file defines, imports, exports and calls, for the call graph (`crate::calls`).
/// Function names are those of [`functions`] without the file. A file that does not parse
/// gives nothing.
#[must_use]
pub fn facts(path: &str, src: &str) -> ModuleFacts {
    crate::stack::on_own_stack(src, &crate::stack::JS, || facts_here(path, src)).unwrap_or_default()
}

fn facts_here(path: &str, src: &str) -> ModuleFacts {
    let allocator = Allocator::default();
    let Some(program) = parse(&allocator, path, src) else {
        return ModuleFacts::default();
    };
    let mut finder = Finder {
        line_starts: std::iter::once(0)
            .chain(src.match_indices('\n').map(|(i, _)| i + 1))
            .collect(),
        ..Finder::default()
    };
    finder.visit_program(&program);
    let mut facts = finder.facts;
    for (name, _) in finder.found {
        facts.functions.entry(name).or_default();
    }
    facts
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
    /// The outermost named function being walked: calls inside belong to it.
    current: Option<String>,
    /// Function nesting (named or not), and the depth of `current`'s own body: only its own
    /// `return`s are what it returns.
    depth: usize,
    current_depth: usize,
    facts: ModuleFacts,
    line_starts: Vec<usize>,
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
                let outermost = self.inside == 0;
                if outermost {
                    self.current = Some(name.clone());
                    self.current_depth = self.depth;
                }
                self.record(name, span);
                self.inside += 1;
                walk_it(self);
                self.inside -= 1;
                if outermost {
                    self.current = None;
                }
            }
            None => walk_it(self),
        }
    }

    fn scope(&self) -> String {
        self.current.clone().unwrap_or_default()
    }

    fn line(&self, span: Span) -> u32 {
        let at = span.start as usize;
        let line = self.line_starts.partition_point(|&s| s <= at);
        u32::try_from(line).unwrap_or(u32::MAX)
    }

    fn bind(&mut self, name: String, value: Expr) {
        if value != Expr::Unknown {
            let scope = self.scope();
            self.facts.bind(&scope, name, value);
        }
    }

    fn export(&mut self, name: String, value: Expr) {
        self.facts.exports.insert(name, value);
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
        if parts.len() >= MAX_LINKS {
            return None;
        }
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

/// A value expression as the call graph sees it.
fn expr_of(e: &Expression<'_>) -> Expr {
    expr_at(e, 0)
}

/// [`expr_of`] `links` deep into a chain: past [`MAX_LINKS`] the rest is unknown.
fn expr_at(e: &Expression<'_>, links: usize) -> Expr {
    if links >= MAX_LINKS {
        return Expr::Unknown;
    }
    let inner = |e: &Expression<'_>| Box::new(expr_at(e, links + 1));
    match e.get_inner_expression() {
        Expression::Identifier(id) => Expr::Name(id.name.to_string()),
        Expression::ThisExpression(_) => Expr::This,
        Expression::StaticMemberExpression(m) => {
            Expr::Member(inner(&m.object), m.property.name.to_string())
        }
        Expression::ComputedMemberExpression(m) => match &m.expression {
            Expression::StringLiteral(s) => {
                Expr::Member(inner(&m.object), s.value.display().to_string())
            }
            _ => Expr::Unknown,
        },
        Expression::CallExpression(c) => call_value(c, links),
        Expression::NewExpression(n) => Expr::Call(inner(&n.callee)),
        Expression::ImportExpression(i) => match &i.source {
            Expression::StringLiteral(s) => Expr::Import(Spec::Js(s.value.display().to_string())),
            _ => Expr::Unknown,
        },
        Expression::AwaitExpression(a) => expr_at(&a.argument, links + 1),
        Expression::ChainExpression(c) => match &c.expression {
            ChainElement::CallExpression(call) => call_value(call, links),
            ChainElement::StaticMemberExpression(m) => {
                Expr::Member(inner(&m.object), m.property.name.to_string())
            }
            _ => Expr::Unknown,
        },
        _ => Expr::Unknown,
    }
}

/// `require("x")` is an import; any other call is the value it returns.
fn call_value(c: &CallExpression<'_>, links: usize) -> Expr {
    match require_spec(c) {
        Some(spec) => Expr::Import(Spec::Js(spec)),
        None => Expr::Call(Box::new(expr_at(&c.callee, links + 1))),
    }
}

fn require_spec(c: &CallExpression<'_>) -> Option<String> {
    let Expression::Identifier(id) = c.callee.get_inner_expression() else {
        return None;
    };
    if id.name != "require" {
        return None;
    }
    match c.arguments.first()? {
        Argument::StringLiteral(s) => Some(s.value.display().to_string()),
        _ => None,
    }
}

/// `module.exports.x` as its names, `this` as `this`.
fn member_parts(e: &Expression<'_>) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    let mut cur = e;
    loop {
        if parts.len() >= MAX_LINKS {
            return None;
        }
        match cur.get_inner_expression() {
            Expression::StaticMemberExpression(m) => {
                parts.push(m.property.name.to_string());
                cur = &m.object;
            }
            Expression::Identifier(id) => {
                parts.push(id.name.to_string());
                break;
            }
            _ => return None,
        }
    }
    parts.reverse();
    Some(parts)
}

impl<'a> Visit<'a> for Finder {
    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        let name = it
            .id
            .as_ref()
            .map(|id| id.name.to_string())
            .or_else(|| self.pending.take());
        let name = name.map(|n| self.qualified(&n));
        self.depth += 1;
        self.named(name, it.span, |me| walk::walk_function(me, it, flags));
        self.depth -= 1;
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        let name = self.pending.take().map(|n| self.qualified(&n));
        self.depth += 1;
        self.named(name, it.span, |me| {
            if me.current.is_some() && me.depth == me.current_depth {
                if let Some(e) = it.get_expression() {
                    let (scope, value) = (me.scope(), expr_of(e));
                    me.facts.ret(&scope, value);
                }
            }
            walk::walk_arrow_function_expression(me, it);
        });
        self.depth -= 1;
    }

    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        if let (Some(arg), true) = (&it.argument, self.depth == self.current_depth) {
            let (scope, value) = (self.scope(), expr_of(arg));
            self.facts.ret(&scope, value);
        }
        walk::walk_return_statement(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let (Some(init), Some(name)) = (&it.init, it.id.get_binding_identifier()) {
            if is_function_value(init) {
                self.pending = Some(name.name.to_string());
            } else if let Expression::ClassExpression(_) = init.without_parentheses() {
                self.pending = Some(name.name.to_string());
            }
        }
        if let Some(init) = &it.init {
            let value = expr_of(init);
            match &it.id {
                BindingPattern::BindingIdentifier(id) => self.bind(id.name.to_string(), value),
                BindingPattern::ObjectPattern(o) => {
                    for p in &o.properties {
                        let Some(key) = p.key.static_name() else {
                            continue;
                        };
                        let local = match &p.value {
                            BindingPattern::BindingIdentifier(id) => Some(id.name.to_string()),
                            BindingPattern::AssignmentPattern(a) => a
                                .left
                                .get_binding_identifier()
                                .map(|id| id.name.to_string()),
                            _ => None,
                        };
                        if let Some(local) = local {
                            let member =
                                Expr::Member(Box::new(value.clone()), key.display().to_string());
                            self.bind(local, member);
                        }
                    }
                }
                _ => {}
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
        let target = it
            .left
            .as_simple_assignment_target()
            .and_then(|t| t.as_member_expression())
            .and_then(|m| {
                let mut parts = member_parts(m.object())?;
                parts.push(m.static_property_name()?.display().to_string());
                Some(parts)
            });
        let value = |k: &str| {
            if is_function_value(&it.right) {
                Expr::Name(k.to_string())
            } else {
                expr_of(&it.right)
            }
        };
        match target
            .as_deref()
            .map(|v| v.iter().map(String::as_str).collect::<Vec<_>>())
        {
            Some(parts) if parts == ["module", "exports"] => {
                let whole = expr_of(&it.right);
                if let Expression::ObjectExpression(o) = it.right.get_inner_expression() {
                    for prop in &o.properties {
                        if let ObjectPropertyKind::ObjectProperty(p) = prop {
                            if let Some(k) = p.key.static_name() {
                                let k = k.display().to_string();
                                let v = if is_function_value(&p.value) {
                                    Expr::Name(k.clone())
                                } else {
                                    expr_of(&p.value)
                                };
                                self.export(k, v);
                            }
                        }
                    }
                } else {
                    self.facts.star.push(whole.clone());
                    self.export("default".to_string(), whole);
                }
            }
            Some(parts)
                if matches!(parts.as_slice(), ["exports", _] | ["module", "exports", _]) =>
            {
                if let Some(k) = parts.last() {
                    let v = value(k);
                    self.export((*k).to_string(), v);
                }
            }
            _ => {
                if let Some(name) = it.left.get_identifier_name() {
                    let v = expr_of(&it.right);
                    self.bind(name.to_string(), v);
                }
            }
        }
        walk::walk_assignment_expression(self, it);
        self.pending = None;
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Some(spec) = require_spec(it) {
            let (scope, line) = (self.scope(), self.line(it.span));
            self.facts.import(&scope, Spec::Js(spec), line);
        } else {
            let scope = self.scope();
            let line = self.line(it.span);
            self.facts.call(&scope, expr_of(&it.callee), line);
        }
        walk::walk_call_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        let scope = self.scope();
        let line = self.line(it.span);
        self.facts.call(&scope, expr_of(&it.callee), line);
        walk::walk_new_expression(self, it);
    }

    fn visit_import_expression(&mut self, it: &ImportExpression<'a>) {
        if let Expression::StringLiteral(s) = &it.source {
            let (scope, line) = (self.scope(), self.line(it.span));
            self.facts
                .import(&scope, Spec::Js(s.value.display().to_string()), line);
        }
        walk::walk_import_expression(self, it);
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        let spec = Spec::Js(it.source.value.display().to_string());
        let line = self.line(it.span);
        self.facts.import("", spec.clone(), line);
        for s in it.specifiers.iter().flatten() {
            let (local, value) = match s {
                ImportDeclarationSpecifier::ImportSpecifier(i) => (
                    i.local.name.to_string(),
                    Expr::Member(
                        Box::new(Expr::Import(spec.clone())),
                        i.imported.name().to_string(),
                    ),
                ),
                ImportDeclarationSpecifier::ImportDefaultSpecifier(i) => (
                    i.local.name.to_string(),
                    Expr::Member(Box::new(Expr::Import(spec.clone())), "default".to_string()),
                ),
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(i) => {
                    (i.local.name.to_string(), Expr::Import(spec.clone()))
                }
            };
            self.facts.bindings.insert(local, value);
        }
        walk::walk_import_declaration(self, it);
    }

    fn visit_export_declaration(&mut self, it: &ExportDeclaration<'a>) {
        match &it.declaration {
            Declaration::VariableDeclaration(v) => {
                for d in &v.declarations {
                    if let Some(id) = d.id.get_binding_identifier() {
                        self.export(id.name.to_string(), Expr::Name(id.name.to_string()));
                    }
                }
            }
            d => {
                if let Some(id) = d.id() {
                    self.export(id.name.to_string(), Expr::Name(id.name.to_string()));
                }
            }
        }
        walk::walk_export_declaration(self, it);
    }

    fn visit_export_named_declaration(&mut self, it: &ExportNamedDeclaration<'a>) {
        for s in &it.specifiers {
            self.export(
                s.exported.name().to_string(),
                Expr::Name(s.local.name().to_string()),
            );
        }
        walk::walk_export_named_declaration(self, it);
    }

    fn visit_export_from_declaration(&mut self, it: &ExportFromDeclaration<'a>) {
        let spec = Spec::Js(it.source.value.display().to_string());
        let line = self.line(it.span);
        self.facts.import("", spec.clone(), line);
        for s in &it.specifiers {
            let v = Expr::Member(
                Box::new(Expr::Import(spec.clone())),
                s.local.name().to_string(),
            );
            self.export(s.exported.name().to_string(), v);
        }
        walk::walk_export_from_declaration(self, it);
    }

    fn visit_export_all_declaration(&mut self, it: &ExportAllDeclaration<'a>) {
        let spec = Spec::Js(it.source.value.display().to_string());
        let line = self.line(it.span);
        self.facts.import("", spec.clone(), line);
        match &it.exported {
            Some(ns) => self.export(ns.name().to_string(), Expr::Import(spec)),
            None => self.facts.star.push(Expr::Import(spec)),
        }
        walk::walk_export_all_declaration(self, it);
    }

    fn visit_export_default_declaration(&mut self, it: &ExportDefaultDeclaration<'a>) {
        let value = match &it.declaration {
            ExportDefaultDeclarationKind::FunctionDeclaration(f) => {
                if f.id.is_none() {
                    self.pending = Some("default".to_string());
                }
                Expr::Name(
                    f.id.as_ref()
                        .map_or("default".to_string(), |i| i.name.to_string()),
                )
            }
            ExportDefaultDeclarationKind::ClassDeclaration(c) => Expr::Name(
                c.id.as_ref()
                    .map_or("default".to_string(), |i| i.name.to_string()),
            ),
            ExportDefaultDeclarationKind::TSInterfaceDeclaration(_) => Expr::Unknown,
            other => match other.as_expression() {
                Some(e) if is_function_value(e) => {
                    self.pending = Some("default".to_string());
                    Expr::Name("default".to_string())
                }
                Some(e) => expr_of(e),
                None => Expr::Unknown,
            },
        };
        self.export("default".to_string(), value);
        walk::walk_export_default_declaration(self, it);
        self.pending = None;
    }

    fn visit_class(&mut self, it: &Class<'a>) {
        let name = it
            .id
            .as_ref()
            .map(|id| id.name.to_string())
            .or_else(|| self.pending.take())
            .unwrap_or_else(|| "default".to_string());
        if self.inside == 0 {
            let bases = it.heritage.iter().map(|h| expr_of(&h.expression)).collect();
            self.facts.classes.insert(name.clone(), bases);
        }
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
