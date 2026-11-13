//! Function-level call graphs over JavaScript/TypeScript and Python source, judged against sink
//! records: does a chain of calls lead from the project's own code to a sink?
//!
//! Positive-only. Calls are resolved by name through imports, module exports, classes and the
//! values local variables are assigned (`x = new C()` makes `x.m()` a call of `C.m`), with no
//! type inference beyond that. A call that does not resolve is dropped, so a sink not reached
//! says nothing: JavaScript and Python call through values the graph cannot see (callbacks,
//! `getattr`, framework dispatch). A sink reached is a chain of real call sites, each
//! resolved through names the code itself binds, so it is a witness, not a proof that the
//! vulnerable input gets there.
//!
//! Every first-party function, and each first-party module's top-level code, is an entry
//! point. Dependency source is read when installed (`node_modules`, a virtualenv's
//! `site-packages`) and only as far as calls lead into it; without it, a call into a package
//! becomes an external name (`xml-crypto` `SignedXml.checkSignature`) matched against the
//! record's sinks by name.
//!
//! Function names are the sink proposer's own (`js::functions`, `python::functions`), so a
//! node and a record's sink compare as written.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};

use crate::record::{SinkRecord, Status, Verdict};

/// A value expression as the graph sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Name(String),
    Member(Box<Expr>, String),
    /// The result of calling (or `new`-ing) the inner expression.
    Call(Box<Expr>),
    /// `this`, or `self`/`cls` in a method.
    This,
    Import(Spec),
    Unknown,
}

/// An import: a JS specifier, or a Python module with its relative level (dots).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spec {
    Js(String),
    Py { module: String, level: usize },
}

/// One call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub callee: Expr,
    /// 1-based.
    pub line: u32,
}

/// What one function's body does.
#[derive(Debug, Clone, Default)]
pub struct FnFacts {
    pub calls: Vec<Site>,
    /// Local names and the value last assigned to them.
    pub locals: BTreeMap<String, Expr>,
    /// What its `return` statements return.
    pub returns: Vec<Expr>,
}

/// What one module defines and does. Function keys are the proposer's names without the file
/// (`Parser.parse`); `""` is the module's top-level code.
#[derive(Debug, Clone, Default)]
pub struct ModuleFacts {
    pub functions: BTreeMap<String, FnFacts>,
    /// Class name to its base classes.
    pub classes: BTreeMap<String, Vec<Expr>>,
    /// Top-level names bound by imports and assignments.
    pub bindings: BTreeMap<String, Expr>,
    /// JavaScript exports by name (`default` included).
    pub exports: BTreeMap<String, Expr>,
    /// Re-exported wholes: `export * from`, `module.exports = X`, Python `from x import *`.
    pub star: Vec<Expr>,
    /// Modules imported, with the function that imports them (`""`: the module's top level)
    /// and the line: loading one runs its top-level code.
    pub imports: Vec<(String, Spec, u32)>,
}

impl ModuleFacts {
    fn top(&mut self) -> &mut FnFacts {
        self.functions.entry(String::new()).or_default()
    }

    /// Bind `name` in `function`'s scope (`""`: the module's).
    pub fn bind(&mut self, function: &str, name: String, value: Expr) {
        if function.is_empty() {
            self.bindings.insert(name, value);
        } else {
            self.functions
                .entry(function.to_string())
                .or_default()
                .locals
                .insert(name, value);
        }
    }

    pub fn ret(&mut self, function: &str, value: Expr) {
        if !function.is_empty() && value != Expr::Unknown {
            let f = self.functions.entry(function.to_string()).or_default();
            if f.returns.len() < 8 && !f.returns.contains(&value) {
                f.returns.push(value);
            }
        }
    }

    pub fn import(&mut self, function: &str, spec: Spec, line: u32) {
        self.imports.push((function.to_string(), spec, line));
    }

    pub fn call(&mut self, function: &str, callee: Expr, line: u32) {
        let f = if function.is_empty() {
            self.top()
        } else {
            self.functions.entry(function.to_string()).or_default()
        };
        f.calls.push(Site { callee, line });
    }
}

/// Which language a project's graph is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Lang {
    Js,
    Python,
}

/// What to build a graph over.
pub struct Project<'a> {
    pub lang: Lang,
    pub root: PathBuf,
    /// The project's own source files.
    pub first_party: Vec<PathBuf>,
    /// Python: installed `site-packages` directories. JavaScript reads `node_modules` from the
    /// directories above each file.
    pub site_dirs: Vec<PathBuf>,
    /// Reads a file, `None` when it cannot or should not be read.
    pub read: &'a dyn Fn(&Path) -> Option<String>,
}

/// One step of a witness chain: a function, and the line of its call to the next step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// Relative to the project root with `/`, or the package name for an external call.
    pub file: String,
    pub function: String,
    pub line: Option<u32>,
    /// A name in a package whose source was not read.
    pub external: bool,
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.external, self.line) {
            (true, _) if self.function.is_empty() => write!(f, "{}", self.file),
            (true, _) => write!(f, "{} {}", self.file, self.function),
            (false, Some(line)) => write!(f, "{} ({}:{line})", self.function, self.file),
            (false, None) => write!(f, "{} ({})", self.function, self.file),
        }
    }
}

/// What a graph found.
#[derive(Debug, Default)]
pub struct Outcome {
    /// Record id to the shortest chain found from first-party code to one of its sinks.
    pub reached: BTreeMap<String, Vec<Step>>,
    pub modules: usize,
    pub functions: usize,
    /// The graph stopped at its size limit (only fewer witnesses, never a wrong one).
    pub truncated: bool,
}

/// The function key of a Python module's `if __name__ == "__main__":` block: an entry point
/// of a first-party script, never run by an import.
pub const MAIN: &str = "(main)";

/// Limits that keep one repository's graph bounded.
const MAX_MODULES: usize = 40_000;
const MAX_NODES: usize = 1_000_000;
const MAX_FILE_BYTES: usize = 2 << 20;
const MAX_DEPTH: usize = 24;

/// A proposed record with more sinks than this names a broad fix (a refactor in the same
/// commit), too broad for a witness until a person narrows it.
pub const MAX_PROPOSED_SINKS: usize = 10;

/// Build the graph over `project` and look for each record's sinks.
#[must_use]
pub fn witnesses(project: &Project<'_>, records: &[&SinkRecord]) -> Outcome {
    let matchers: Vec<Matcher> = records
        .iter()
        .filter(|r| r.verdict == Verdict::Sinks && !r.sinks.is_empty())
        .filter(|r| r.status == Status::Reviewed || r.sinks.len() <= MAX_PROPOSED_SINKS)
        .map(|r| Matcher::new(project.lang, r))
        .collect();
    let mut g = Graph::new(project);
    for path in &project.first_party {
        g.load(path, true);
    }
    let mut out = Outcome::default();
    if matchers.is_empty() {
        out.modules = g.modules.len();
        return out;
    }

    // Production code first: test, example and script files are entry points only for what
    // it does not reach, so a witness starts in production code whenever one does.
    let (mut roots, mut later): (Vec<Key>, Vec<Key>) = (Vec::new(), Vec::new());
    for (id, m) in g.modules.iter().enumerate() {
        if m.first_party {
            let rel = g.rel(&m.path);
            let side = crate::propose::is_non_library_path(&rel);
            for q in m.facts.functions.keys() {
                let k = Key::Fn(id, q.clone());
                if side {
                    later.push(k)
                } else {
                    roots.push(k)
                }
            }
        }
    }
    let mut parent: HashMap<Key, Option<(Key, u32)>> = HashMap::new();
    let mut queue: VecDeque<Key> = VecDeque::new();
    let seed = |keys: Vec<Key>,
                parent: &mut HashMap<Key, Option<(Key, u32)>>,
                queue: &mut VecDeque<Key>| {
        for k in keys {
            if !parent.contains_key(&k) {
                parent.insert(k.clone(), None);
                queue.push_back(k);
            }
        }
    };
    seed(roots, &mut parent, &mut queue);
    let mut pending: BTreeSet<&str> = matchers.iter().map(|m| m.id.as_str()).collect();
    loop {
        let Some(key) = queue.pop_front() else {
            if later.is_empty() {
                break;
            }
            seed(std::mem::take(&mut later), &mut parent, &mut queue);
            continue;
        };
        if pending.is_empty() {
            break;
        }
        if parent.len() > MAX_NODES || g.modules.len() > MAX_MODULES {
            out.truncated = true;
            break;
        }
        for m in &matchers {
            if pending.contains(m.id.as_str()) && g.matches(m, &key) {
                pending.remove(m.id.as_str());
                out.reached.insert(m.id.clone(), chain(&g, &parent, &key));
            }
        }
        let Key::Fn(id, q) = &key else {
            continue;
        };
        for (next, line) in g.targets(*id, q) {
            if !parent.contains_key(&next) {
                parent.insert(next.clone(), Some((key.clone(), line)));
                queue.push_back(next);
            }
        }
    }
    out.modules = g.modules.len();
    out.functions = parent.len();
    out
}

fn chain(g: &Graph<'_>, parent: &HashMap<Key, Option<(Key, u32)>>, end: &Key) -> Vec<Step> {
    let mut steps = vec![g.step(end, None)];
    let mut cur = end.clone();
    while let Some(Some((p, line))) = parent.get(&cur) {
        steps.push(g.step(p, (*line > 0).then_some(*line)));
        cur = p.clone();
    }
    steps.reverse();
    steps
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Fn(usize, String),
    /// An external name: the npm package or the Python module path, then members.
    Ext(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Val {
    Module(usize),
    Def(usize, String),
    Inst(usize, String),
    Ext(Vec<String>),
    ExtInst(Vec<String>),
    Unknown,
}

struct Module {
    path: PathBuf,
    first_party: bool,
    /// JS: the npm package an installed file belongs to. Python: the dotted module name of an
    /// installed file.
    package: Option<String>,
    is_init: bool,
    facts: ModuleFacts,
}

struct Graph<'p> {
    project: &'p Project<'p>,
    modules: Vec<Module>,
    by_path: HashMap<PathBuf, Option<usize>>,
    /// Python first-party modules by every dotted suffix of their path.
    py_names: BTreeMap<String, Vec<usize>>,
}

impl<'p> Graph<'p> {
    fn new(project: &'p Project<'p>) -> Self {
        Graph {
            project,
            modules: Vec::new(),
            by_path: HashMap::new(),
            py_names: BTreeMap::new(),
        }
    }

    fn load(&mut self, path: &Path, first_party: bool) -> Option<usize> {
        let normal = normalize(path);
        let path = normal.as_path();
        if let Some(id) = self.by_path.get(path) {
            return *id;
        }
        self.by_path.insert(path.to_path_buf(), None);
        if self.modules.len() >= MAX_MODULES {
            return None;
        }
        let text = (self.project.read)(path).filter(|t| t.len() <= MAX_FILE_BYTES)?;
        let rel = self.rel(path);
        let facts = match self.project.lang {
            Lang::Js => crate::js::facts(&rel, &text),
            Lang::Python => crate::python::facts(&text),
        };
        let is_init = path.file_name().is_some_and(|n| n == "__init__.py");
        let package = match self.project.lang {
            Lang::Js => npm_package_of(path),
            Lang::Python => self.site_module(path),
        };
        let id = self.modules.len();
        self.modules.push(Module {
            path: path.to_path_buf(),
            first_party,
            package,
            is_init,
            facts,
        });
        self.by_path.insert(path.to_path_buf(), Some(id));
        if first_party && self.project.lang == Lang::Python {
            for name in py_suffixes(&rel) {
                self.py_names.entry(name).or_default().push(id);
            }
        }
        Some(id)
    }

    fn rel(&self, path: &Path) -> String {
        path.strip_prefix(&self.project.root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    }

    /// The dotted module an installed Python file is.
    fn site_module(&self, path: &Path) -> Option<String> {
        let site = self
            .project
            .site_dirs
            .iter()
            .find(|s| path.starts_with(s))?;
        let rel = path
            .strip_prefix(site)
            .ok()?
            .to_string_lossy()
            .replace('\\', "/");
        let stem = rel.strip_suffix(".py")?;
        let stem = stem.strip_suffix("/__init__").unwrap_or(stem);
        Some(stem.replace('/', "."))
    }

    fn step(&self, key: &Key, line: Option<u32>) -> Step {
        match key {
            Key::Fn(id, q) => Step {
                file: self.rel(&self.modules[*id].path),
                function: if q.is_empty() {
                    "(module)".to_string()
                } else {
                    q.clone()
                },
                line,
                external: false,
            },
            Key::Ext(path) => {
                let (file, rest) = match self.project.lang {
                    Lang::Js => (
                        path[0].clone(),
                        path[1..]
                            .iter()
                            .filter(|p| *p != "default")
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("."),
                    ),
                    Lang::Python => (path.join("."), String::new()),
                };
                Step {
                    file,
                    function: rest,
                    line,
                    external: true,
                }
            }
        }
    }

    // ----- resolution -------------------------------------------------------------------

    fn resolve(&mut self, m: usize, func: &str, e: &Expr, depth: usize) -> Val {
        if depth > MAX_DEPTH {
            return Val::Unknown;
        }
        match e {
            Expr::Unknown => Val::Unknown,
            Expr::Name(n) => self.name(m, func, n, depth),
            Expr::This => {
                let class = func.rsplit_once('.').map(|(c, _)| c.to_string());
                match class {
                    Some(c) if self.is_class(m, &c) => Val::Inst(m, c),
                    _ => Val::Unknown,
                }
            }
            Expr::Import(spec) => self.import(m, spec),
            Expr::Member(base, n) => {
                let b = self.resolve(m, func, base, depth + 1);
                self.member(b, n, depth + 1)
            }
            Expr::Call(callee) => match self.resolve(m, func, callee, depth + 1) {
                Val::Def(id, q) if self.is_class(id, &q) => Val::Inst(id, q),
                // A factory: what the function returns.
                Val::Def(id, q) => {
                    let returns = self.modules[id]
                        .facts
                        .functions
                        .get(&q)
                        .map(|f| f.returns.clone())
                        .unwrap_or_default();
                    for r in returns {
                        let v = self.resolve(id, &q, &r, depth + 2);
                        if v != Val::Unknown {
                            return v;
                        }
                    }
                    Val::Unknown
                }
                Val::Ext(p) => Val::ExtInst(p),
                _ => Val::Unknown,
            },
        }
    }

    fn name(&mut self, m: usize, func: &str, n: &str, depth: usize) -> Val {
        if !func.is_empty() {
            let local = self.modules[m]
                .facts
                .functions
                .get(func)
                .and_then(|f| f.locals.get(n))
                .cloned();
            if let Some(e) = local {
                if e != Expr::Name(n.to_string()) {
                    return self.resolve(m, func, &e, depth + 1);
                }
            }
        }
        let facts = &self.modules[m].facts;
        if facts.functions.contains_key(n) || facts.classes.contains_key(n) {
            return Val::Def(m, n.to_string());
        }
        if let Some(e) = facts.bindings.get(n).cloned() {
            if e != Expr::Name(n.to_string()) {
                return self.resolve(m, "", &e, depth + 1);
            }
        }
        Val::Unknown
    }

    fn is_class(&self, m: usize, q: &str) -> bool {
        let f = &self.modules[m].facts;
        f.classes.contains_key(q) || {
            let prefix = format!("{q}.");
            f.functions
                .range(prefix.clone()..)
                .next()
                .is_some_and(|(k, _)| k.starts_with(&prefix))
        }
    }

    fn member(&mut self, base: Val, n: &str, depth: usize) -> Val {
        if depth > MAX_DEPTH {
            return Val::Unknown;
        }
        match base {
            Val::Module(id) => self.export(id, n, depth + 1),
            Val::Def(id, q) => {
                let key = format!("{q}.{n}");
                if self.has_def(id, &key) {
                    Val::Def(id, key)
                } else if self.is_class(id, &q) {
                    self.method(id, &q, n, depth + 1)
                } else {
                    Val::Unknown
                }
            }
            Val::Inst(id, q) => self.method(id, &q, n, depth + 1),
            Val::Ext(mut p) | Val::ExtInst(mut p) => {
                p.push(n.to_string());
                Val::Ext(p)
            }
            Val::Unknown => Val::Unknown,
        }
    }

    fn has_def(&self, m: usize, q: &str) -> bool {
        let f = &self.modules[m].facts;
        f.functions.contains_key(q) || f.classes.contains_key(q)
    }

    /// `n` on an instance of class `q` in module `m`, through base classes.
    fn method(&mut self, m: usize, q: &str, n: &str, depth: usize) -> Val {
        if depth > MAX_DEPTH {
            return Val::Unknown;
        }
        let key = format!("{q}.{n}");
        if self.has_def(m, &key) {
            return Val::Def(m, key);
        }
        let bases = self.modules[m]
            .facts
            .classes
            .get(q)
            .cloned()
            .unwrap_or_default();
        for base in bases {
            let found = match self.resolve(m, "", &base, depth + 1) {
                Val::Def(id, c) => self.method(id, &c, n, depth + 1),
                Val::Ext(mut p) => {
                    p.push(n.to_string());
                    Val::Ext(p)
                }
                _ => Val::Unknown,
            };
            if found != Val::Unknown {
                return found;
            }
        }
        Val::Unknown
    }

    fn export(&mut self, id: usize, n: &str, depth: usize) -> Val {
        if depth > MAX_DEPTH {
            return Val::Unknown;
        }
        match self.project.lang {
            Lang::Js => {
                if let Some(e) = self.modules[id].facts.exports.get(n).cloned() {
                    return self.resolve(id, "", &e, depth + 1);
                }
            }
            Lang::Python => {
                let v = self.name(id, "", n, depth + 1);
                if v != Val::Unknown {
                    return v;
                }
                if self.modules[id].is_init {
                    let dir = self.modules[id].path.parent().map(Path::to_path_buf);
                    if let Some(sub) = dir.and_then(|d| self.py_file(&d, &[n])) {
                        if let Some(sid) = self.load(&sub, self.modules[id].first_party) {
                            return Val::Module(sid);
                        }
                    }
                }
            }
        }
        for star in self.modules[id].facts.star.clone() {
            let base = self.resolve(id, "", &star, depth + 1);
            let v = self.member(base, n, depth + 1);
            if v != Val::Unknown {
                return v;
            }
        }
        Val::Unknown
    }

    fn import(&mut self, from: usize, spec: &Spec) -> Val {
        match spec {
            Spec::Js(s) => self.js_import(from, s),
            Spec::Py { module, level } => self.py_import(from, module, *level),
        }
    }

    fn js_import(&mut self, from: usize, spec: &str) -> Val {
        let dir = match self.modules[from].path.parent() {
            Some(d) => d.to_path_buf(),
            None => return Val::Unknown,
        };
        let first_party = self.modules[from].first_party;
        if spec.starts_with("./") || spec.starts_with("../") || spec == "." || spec == ".." {
            return match js_file(&dir.join(spec)) {
                Some(p) => self
                    .load(&p, first_party && !in_node_modules(&p))
                    .map_or(Val::Unknown, Val::Module),
                None => Val::Unknown,
            };
        }
        if spec.starts_with("node:")
            || NODE_BUILTINS.contains(&spec.split('/').next().unwrap_or(spec))
        {
            return Val::Unknown;
        }
        let (pkg, sub) = split_package(spec);
        if pkg.is_empty() {
            return Val::Unknown;
        }
        if let Some(pkg_dir) = find_package(&dir, &self.project.root, pkg) {
            let entry = if sub.is_empty() {
                package_entry(&pkg_dir, self.project.read)
            } else {
                js_file(&pkg_dir.join(sub))
            };
            if let Some(p) = entry {
                if let Some(id) = self.load(&p, false) {
                    return Val::Module(id);
                }
            }
        }
        // Not installed: an external name. A subpath import stays apart from the package's
        // main exports (its first member can never equal a sink's name).
        let mut path = vec![pkg.to_string()];
        if !sub.is_empty() {
            path.push(format!("/{sub}"));
        }
        Val::Ext(path)
    }

    fn py_import(&mut self, from: usize, module: &str, level: usize) -> Val {
        let parts: Vec<&str> = module.split('.').filter(|p| !p.is_empty()).collect();
        let first_party = self.modules[from].first_party;
        if level > 0 {
            let Some(mut base) = self.modules[from].path.parent().map(Path::to_path_buf) else {
                return Val::Unknown;
            };
            for _ in 1..level {
                match base.parent() {
                    Some(p) => base = p.to_path_buf(),
                    None => return Val::Unknown,
                }
            }
            return match self.py_file(&base, &parts) {
                Some(p) => self.load(&p, first_party).map_or(Val::Unknown, Val::Module),
                None => Val::Unknown,
            };
        }
        if parts.is_empty() {
            return Val::Unknown;
        }
        // An installed distribution first, then the project's own modules.
        for site in self.project.site_dirs.clone() {
            if let Some(p) = self.py_file(&site, &parts) {
                if let Some(id) = self.load(&p, false) {
                    return Val::Module(id);
                }
            }
        }
        if let Some(ids) = self.py_names.get(&parts.join(".")) {
            if let Some(&id) = ids.first() {
                return Val::Module(id);
            }
        }
        Val::Ext(parts.iter().map(|s| (*s).to_string()).collect())
    }

    fn py_file(&self, base: &Path, parts: &[&str]) -> Option<PathBuf> {
        let mut p = base.to_path_buf();
        for part in parts {
            p.push(part);
        }
        let init = p.join("__init__.py");
        if init.is_file() {
            return Some(init);
        }
        let file = p.with_extension("py");
        if !parts.is_empty() && file.is_file() {
            return Some(file);
        }
        None
    }

    // ----- edges -----------------------------------------------------------------------

    /// The functions (and external names) `q` in module `m` calls, with the line of each call.
    fn targets(&mut self, m: usize, q: &str) -> Vec<(Key, u32)> {
        let Some(f) = self.modules[m].facts.functions.get(q) else {
            return Vec::new();
        };
        let calls = f.calls.clone();
        let mut out = Vec::new();
        // A function's module is loaded, so its top-level code ran; what the function
        // imports is loaded when it runs.
        if !q.is_empty() && q != MAIN {
            out.push((Key::Fn(m, String::new()), 0));
        }
        let imports: Vec<(Spec, u32)> = self.modules[m]
            .facts
            .imports
            .iter()
            .filter(|(scope, _, _)| scope == q)
            .map(|(_, spec, line)| (spec.clone(), *line))
            .collect();
        for (spec, line) in imports {
            if let Val::Module(id) = self.import(m, &spec) {
                out.push((Key::Fn(id, String::new()), line));
            }
        }
        for site in calls {
            let v = self.resolve(m, q, &site.callee, 0);
            for k in self.callable(v, 0) {
                out.push((k, site.line));
            }
        }
        out
    }

    /// The functions a call of `v` runs.
    fn callable(&mut self, v: Val, depth: usize) -> Vec<Key> {
        if depth > 4 {
            return Vec::new();
        }
        match v {
            Val::Def(id, q) => {
                let mut out = Vec::new();
                let f = &self.modules[id].facts;
                if f.functions.contains_key(&q) {
                    out.push(Key::Fn(id, q.clone()));
                }
                if self.is_class(id, &q) {
                    for ctor in ["constructor", "__init__", "__new__", "__call__"] {
                        if let Val::Def(cid, cq) = self.method(id, &q, ctor, depth + 1) {
                            if ctor != "__call__" {
                                out.push(Key::Fn(cid, cq));
                            }
                        }
                    }
                }
                out
            }
            Val::Module(id) => {
                // A CommonJS module whose `module.exports` is a function.
                let d = self.export(id, "default", depth + 1);
                if d == Val::Module(id) {
                    Vec::new()
                } else {
                    self.callable(d, depth + 1)
                }
            }
            Val::Ext(p) => vec![Key::Ext(p)],
            Val::Inst(..) | Val::ExtInst(_) | Val::Unknown => Vec::new(),
        }
    }

    // ----- sinks -----------------------------------------------------------------------

    fn matches(&self, m: &Matcher, key: &Key) -> bool {
        match (key, self.project.lang) {
            (Key::Fn(id, q), Lang::Js) => {
                let module = &self.modules[*id];
                if module.first_party || q.is_empty() {
                    return false;
                }
                let Some(pkg) = &module.package else {
                    return false;
                };
                if !m.packages.contains(pkg) {
                    return false;
                }
                let stem = file_stem(&module.path.to_string_lossy());
                m.js.iter()
                    .any(|(s, qual)| qual == q && (*s == stem || qual.contains('.')))
            }
            (Key::Fn(id, q), Lang::Python) => {
                let module = &self.modules[*id];
                if module.first_party || q.is_empty() {
                    return false;
                }
                let Some(dotted) = &module.package else {
                    return false;
                };
                let full: Vec<&str> = dotted.split('.').chain(q.split('.')).collect();
                m.py.iter().any(|s| py_match(&full, s))
            }
            (Key::Ext(p), Lang::Js) => {
                if !m.packages.contains(&p[0]) {
                    return false;
                }
                let members: Vec<&str> = p[1..]
                    .iter()
                    .map(String::as_str)
                    .filter(|s| *s != "default")
                    .collect();
                !members.is_empty() && {
                    let joined = members.join(".");
                    m.js.iter().any(|(_, qual)| *qual == joined)
                }
            }
            (Key::Ext(p), Lang::Python) => {
                let full: Vec<&str> = p.iter().map(String::as_str).collect();
                m.py.iter().any(|s| py_match(&full, s))
            }
        }
    }
}

/// A record's sinks in the forms the graph compares.
struct Matcher {
    id: String,
    packages: BTreeSet<String>,
    /// JS: (file stem, name in the file).
    js: Vec<(String, String)>,
    /// Python: dotted segments.
    py: Vec<Vec<String>>,
}

impl Matcher {
    fn new(lang: Lang, r: &SinkRecord) -> Self {
        let mut js = Vec::new();
        let mut py = Vec::new();
        for s in &r.sinks {
            let key = s.key();
            match lang {
                Lang::Js => {
                    if let Some((file, qual)) = split_js_key(&key) {
                        js.push((file_stem(file), qual.to_string()));
                    }
                }
                Lang::Python => py.push(key.split('.').map(str::to_string).collect()),
            }
        }
        Matcher {
            id: r.id.clone(),
            packages: r.packages.iter().cloned().collect(),
            js,
            py,
        }
    }
}

/// `lib/a.js.Class.m` as (`lib/a.js`, `Class.m`): the file ends at the last source extension
/// followed by a dot.
#[must_use]
pub fn split_js_key(key: &str) -> Option<(&str, &str)> {
    let mut best = None;
    for ext in [
        ".js.", ".mjs.", ".cjs.", ".jsx.", ".ts.", ".mts.", ".cts.", ".tsx.",
    ] {
        let mut from = 0;
        while let Some(i) = key[from..].find(ext) {
            let at = from + i + ext.len() - 1;
            if best.is_none_or(|b| at > b) {
                best = Some(at);
            }
            from += i + 1;
        }
    }
    best.map(|at| (&key[..at], &key[at + 1..]))
}

/// `lib/signed-xml.js` → `signed-xml`; `src/index.ts` → `index`.
fn file_stem(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.split('.').next().unwrap_or(name).to_string()
}

/// Whether the dotted name `a` (a module path and members, as code reaches it) names sink `s`
/// (a module path from the repository, then the function). Each splits into modules and a
/// qualified name, which starts at the first capitalised segment after the top-level package,
/// or is the last segment. The qualified names must be equal and `a`'s modules a prefix of
/// `s`'s, since a package re-exports what its submodules define (`jinja2.Template.render`
/// names `jinja2.environment.Template.render`; `yaml.load` does not name
/// `yaml.loader.Loader.load`). `s` may carry leading repository directories
/// (`web.pgadmin...`).
fn py_match(a: &[&str], s: &[String]) -> bool {
    let s: Vec<&str> = s.iter().map(String::as_str).collect();
    let Some((a_mods, a_qual)) = split_py(a) else {
        return false;
    };
    (0..s.len()).any(|i| {
        let Some((s_mods, s_qual)) = split_py(&s[i..]) else {
            return false;
        };
        a_qual == s_qual && s_mods.starts_with(a_mods)
    })
}

fn split_py<'a, 'b>(name: &'b [&'a str]) -> Option<(&'b [&'a str], &'b [&'a str])> {
    if name.len() < 2 {
        return None;
    }
    let at = (1..name.len())
        .find(|&i| name[i].starts_with(char::is_uppercase))
        .unwrap_or(name.len() - 1);
    Some(name.split_at(at))
}

/// Every dotted suffix of a Python file's path made of importable names:
/// `backend/app/api.py` gives `api`, `app.api`, `backend.app.api`.
fn py_suffixes(rel: &str) -> Vec<String> {
    let Some(stem) = rel.strip_suffix(".py") else {
        return Vec::new();
    };
    let mut parts: Vec<&str> = stem.split('/').collect();
    if parts.last() == Some(&"__init__") {
        parts.pop();
    }
    let ok = |p: &&&str| {
        p.starts_with(|c: char| c.is_alphabetic() || c == '_')
            && p.chars().all(|c| c.is_alphanumeric() || c == '_')
    };
    let keep = parts.iter().rev().take_while(ok).count();
    let parts = &parts[parts.len() - keep..];
    (0..parts.len()).map(|i| parts[i..].join(".")).collect()
}

const NODE_BUILTINS: &[&str] = &[
    "assert",
    "buffer",
    "child_process",
    "cluster",
    "crypto",
    "dgram",
    "dns",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "net",
    "os",
    "path",
    "process",
    "querystring",
    "readline",
    "stream",
    "string_decoder",
    "timers",
    "tls",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "worker_threads",
    "zlib",
];

/// `@scope/name/sub/path` → (`@scope/name`, `sub/path`).
fn split_package(spec: &str) -> (&str, &str) {
    let mut it = spec.splitn(3, '/');
    let first = it.next().unwrap_or("");
    if first.starts_with('@') {
        let second = it.next().unwrap_or("");
        let len = first.len() + 1 + second.len();
        let pkg = spec.get(..len.min(spec.len())).unwrap_or(spec);
        let sub = spec.get(len + 1..).unwrap_or("");
        (pkg, sub)
    } else {
        (first, spec.get(first.len() + 1..).unwrap_or(""))
    }
}

/// `p` with `.` and `..` components folded away (lexically; nothing is resolved on disk).
fn normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn in_node_modules(p: &Path) -> bool {
    p.components().any(|c| c.as_os_str() == "node_modules")
}

/// The npm package an installed file belongs to: the name after its last `node_modules`.
fn npm_package_of(p: &Path) -> Option<String> {
    let parts: Vec<String> = p
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let at = parts.iter().rposition(|c| c == "node_modules")?;
    let first = parts.get(at + 1)?;
    if first.starts_with('@') {
        Some(format!("{first}/{}", parts.get(at + 2)?))
    } else {
        Some(first.clone())
    }
}

/// `node_modules/<pkg>` in `dir` or a directory above it, up to `root`.
fn find_package(dir: &Path, root: &Path, pkg: &str) -> Option<PathBuf> {
    let mut cur = Some(dir);
    while let Some(d) = cur {
        let candidate = d.join("node_modules").join(pkg);
        if candidate.is_dir() {
            return Some(candidate);
        }
        if d == root || !d.starts_with(root) {
            break;
        }
        cur = d.parent();
    }
    None
}

/// The file a package's bare import loads: `exports["."]` (a string or its `require`,
/// `node`, `import`, `default` condition), else `main`, else `index.js`.
fn package_entry(dir: &Path, read: &dyn Fn(&Path) -> Option<String>) -> Option<PathBuf> {
    let manifest: Option<serde_json::Value> =
        read(&dir.join("package.json")).and_then(|t| serde_json::from_str(&t).ok());
    let mut candidates = Vec::new();
    if let Some(m) = &manifest {
        if let Some(e) = m.get("exports") {
            let dot = e.get(".").unwrap_or(e);
            if let Some(s) = condition(dot, 0) {
                candidates.push(s);
            }
        }
        for field in ["main", "module"] {
            if let Some(s) = m.get(field).and_then(|v| v.as_str()) {
                candidates.push(s.to_string());
            }
        }
    }
    candidates.push("index".to_string());
    candidates
        .iter()
        .find_map(|c| js_file(&dir.join(c.trim_start_matches("./"))))
}

fn condition(v: &serde_json::Value, depth: usize) -> Option<String> {
    if depth > 4 {
        return None;
    }
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(o) => ["require", "node", "import", "default"]
            .iter()
            .find_map(|k| o.get(*k).and_then(|x| condition(x, depth + 1))),
        _ => None,
    }
}

/// The file an import path names: itself, with a JS/TS extension, or its directory's index.
/// A TypeScript import of `./x.js` finds `./x.ts`.
fn js_file(p: &Path) -> Option<PathBuf> {
    const EXTS: [&str; 7] = ["js", "ts", "tsx", "mjs", "cjs", "jsx", "mts"];
    if p.is_file() {
        return Some(p.to_path_buf());
    }
    let s = p.to_string_lossy();
    let base = ["js", "mjs", "cjs", "jsx"]
        .iter()
        .find_map(|e| s.strip_suffix(&format!(".{e}")))
        .map(PathBuf::from);
    for b in base.iter().chain(std::iter::once(&p.to_path_buf())) {
        for e in EXTS {
            let c = PathBuf::from(format!("{}.{e}", b.to_string_lossy()));
            if c.is_file() {
                return Some(c);
            }
        }
    }
    if p.is_dir() {
        for e in EXTS {
            let c = p.join(format!("index.{e}"));
            if c.is_file() {
                return Some(c);
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn write(root: &Path, files: &[(&str, &str)]) {
        for (rel, text) in files {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
    }

    fn record(eco: &str, pkg: &str, sinks: &[(&str, &str)]) -> SinkRecord {
        let sinks: Vec<serde_json::Value> = sinks
            .iter()
            .map(|(c, m)| serde_json::json!({"class": c, "method": m}))
            .collect();
        serde_json::from_value(serde_json::json!({
            "schema": crate::record::SCHEMA, "id": "GHSA-test", "ecosystem": eco,
            "packages": [pkg], "status": "proposed", "verdict": "sinks", "sinks": sinks,
        }))
        .unwrap()
    }

    fn run(
        lang: Lang,
        root: &Path,
        first_party: &[&str],
        site: &[&str],
        r: &SinkRecord,
    ) -> Outcome {
        let read = |p: &Path| std::fs::read_to_string(p).ok();
        let project = Project {
            lang,
            root: root.to_path_buf(),
            first_party: first_party.iter().map(|f| root.join(f)).collect(),
            site_dirs: site.iter().map(|f| root.join(f)).collect(),
            read: &read,
        };
        witnesses(&project, &[r])
    }

    fn shown(o: &Outcome) -> Vec<String> {
        o.reached
            .get("GHSA-test")
            .map(|c| c.iter().map(ToString::to_string).collect())
            .unwrap_or_default()
    }

    #[test]
    fn js_chain_through_an_installed_package() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, &[
            ("src/app.ts", "import { verify } from './auth';\nexport function handler(req) {\n  return verify(req.body);\n}\n"),
            ("src/auth.ts", "const { SignedXml } = require('xml-crypto');\nexport function verify(xml) {\n  const sig = new SignedXml();\n  return sig.checkSignature(xml);\n}\n"),
            ("src/other.js", "const x = require('xml-crypto');\nfunction unrelated() { return x.version; }\n"),
            ("node_modules/xml-crypto/package.json", r#"{"main": "./lib/index.js"}"#),
            ("node_modules/xml-crypto/lib/index.js", "module.exports = require('./signed-xml');\n"),
            ("node_modules/xml-crypto/lib/signed-xml.js", "class SignedXml {\n  checkSignature(x) { return this.validate(x); }\n  validate(x) { return true; }\n}\nexports.SignedXml = SignedXml;\n"),
        ]);
        let r = record(
            "npm",
            "xml-crypto",
            &[("lib/signed-xml.js.SignedXml", "validate")],
        );
        let o = run(
            Lang::Js,
            root,
            &["src/app.ts", "src/auth.ts", "src/other.js"],
            &[],
            &r,
        );
        assert_eq!(
            shown(&o),
            [
                "verify (src/auth.ts:4)",
                "SignedXml.checkSignature (node_modules/xml-crypto/lib/signed-xml.js:2)",
                "SignedXml.validate (node_modules/xml-crypto/lib/signed-xml.js)",
            ]
        );
        // A sink nothing calls is not reached.
        let r = record(
            "npm",
            "xml-crypto",
            &[("lib/signed-xml.js.SignedXml", "unused")],
        );
        assert!(run(Lang::Js, root, &["src/app.ts", "src/auth.ts"], &[], &r)
            .reached
            .is_empty());
    }

    #[test]
    fn js_external_call_without_node_modules() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, &[(
            "index.js",
            "import xmlCrypto from 'xml-crypto';\nimport * as cp from 'xml-crypto/lib/x';\n\
             function go(x) { const s = new xmlCrypto.SignedXml(); s.checkSignature(x); cp.SignedXml(); }\n",
        )]);
        let r = record(
            "npm",
            "xml-crypto",
            &[("lib/signed-xml.js.SignedXml", "checkSignature")],
        );
        assert_eq!(
            shown(&run(Lang::Js, root, &["index.js"], &[], &r)),
            ["go (index.js:3)", "xml-crypto SignedXml.checkSignature"]
        );
        // Another package's same name does not match.
        let r = record(
            "npm",
            "other",
            &[("lib/signed-xml.js.SignedXml", "checkSignature")],
        );
        assert!(run(Lang::Js, root, &["index.js"], &[], &r)
            .reached
            .is_empty());
    }

    #[test]
    fn python_chain_through_site_packages_and_external_names() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, &[
            ("app/__init__.py", ""),
            ("app/views.py", "from app.util import render_page\n\ndef index(request):\n    return render_page(request.GET['t'])\n"),
            ("app/util.py", "import jinja2\nfrom yaml import load\n\ndef render_page(t):\n    load(t)\n    return jinja2.Template(t).render()\n"),
            ("venv/lib/python3.12/site-packages/jinja2/__init__.py", "from .environment import Template\n"),
            ("venv/lib/python3.12/site-packages/jinja2/environment.py", "class Template:\n    def render(self):\n        return self._compile()\n\n    def _compile(self):\n        return 1\n"),
        ]);
        let fp = ["app/__init__.py", "app/views.py", "app/util.py"];
        let site = ["venv/lib/python3.12/site-packages"];
        let r = record(
            "PyPI",
            "jinja2",
            &[("jinja2.environment.Template", "_compile")],
        );
        assert_eq!(
            shown(&run(Lang::Python, root, &fp, &site, &r)),
            [
                "render_page (app/util.py:6)",
                "Template.render (venv/lib/python3.12/site-packages/jinja2/environment.py:3)",
                "Template._compile (venv/lib/python3.12/site-packages/jinja2/environment.py)",
            ]
        );
        // yaml is not installed: the call is an external name.
        let r = record("PyPI", "pyyaml", &[("yaml", "load")]);
        assert_eq!(
            shown(&run(Lang::Python, root, &fp, &site, &r)),
            ["render_page (app/util.py:5)", "yaml.load"]
        );
        let r = record("PyPI", "pyyaml", &[("yaml.loader.Loader", "load")]);
        assert!(run(Lang::Python, root, &fp, &site, &r).reached.is_empty());
    }

    #[test]
    fn factories_return_what_they_build() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, &[
            ("app.py", "import sqlparse\n\ndef get_stack():\n    stack = sqlparse.engine.FilterStack()\n    def inner():\n        return 1\n    return stack\n\ndef fmt(sql):\n    return get_stack().run(sql)\n"),
            ("app.js", "const { SignedXml } = require('xml-crypto');\nconst make = () => new SignedXml();\nfunction other() { return [1].map(x => { return x; }); }\nfunction go(x) { return make().checkSignature(x); }\n"),
        ]);
        let r = record(
            "PyPI",
            "sqlparse",
            &[("sqlparse.engine.filter_stack.FilterStack", "run")],
        );
        assert_eq!(
            shown(&run(Lang::Python, root, &["app.py"], &[], &r)),
            ["fmt (app.py:10)", "sqlparse.engine.FilterStack.run"]
        );
        let r = record(
            "npm",
            "xml-crypto",
            &[("lib/signed-xml.js.SignedXml", "checkSignature")],
        );
        assert_eq!(
            shown(&run(Lang::Js, root, &["app.js"], &[], &r)),
            ["go (app.js:4)", "xml-crypto SignedXml.checkSignature"]
        );
    }

    #[test]
    fn js_keys_split_at_the_file() {
        assert_eq!(
            split_js_key("lib/signed-xml.js.SignedXml.checkSignature"),
            Some(("lib/signed-xml.js", "SignedXml.checkSignature"))
        );
        assert_eq!(
            split_js_key("packages/a.js/src/x.ts.run"),
            Some(("packages/a.js/src/x.ts", "run"))
        );
        assert_eq!(split_package("@a/b/c/d"), ("@a/b", "c/d"));
        assert_eq!(split_package("lodash"), ("lodash", ""));
    }

    #[test]
    fn python_names_match_at_module_boundaries() {
        let s = |t: &str| t.split('.').map(str::to_string).collect::<Vec<_>>();
        assert!(py_match(
            &["jinja2", "Template", "render"],
            &s("jinja2.environment.Template.render")
        ));
        assert!(py_match(&["PIL", "Image", "open"], &s("PIL.Image.open")));
        assert!(!py_match(&["yaml", "load"], &s("yaml.loader.Loader.load")));
        assert!(py_match(
            &["pgadmin", "utils", "f"],
            &s("web.pgadmin.utils.f")
        ));
        assert!(!py_match(&["yaml"], &s("yaml.load")));
        assert!(py_match(
            &["sqlparse", "engine", "FilterStack", "run"],
            &s("sqlparse.engine.filter_stack.FilterStack.run")
        ));
        assert!(py_match(&["yaml", "load"], &s("yaml.main.load")));
        assert!(!py_match(&["yaml", "main", "load"], &s("yaml.load")));
        assert_eq!(
            py_suffixes("backend/app/api.py"),
            ["backend.app.api", "app.api", "api"]
        );
    }
}
