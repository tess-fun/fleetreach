//! A rapid type analysis call graph over a service's assemblies.
//!
//! The graph over-approximates on purpose, as the JVM graph does. Every non-private method
//! of the service's own assemblies is an entry point, and every one of its classes is made.
//! A virtual call lands on the method the call is written against and on every made subtype's
//! override; overloads are not told apart (one name, every overload). A type is "made" by
//! `newobj`, and also by any route reflection takes: a `typeof`, a generic argument (`new T()`,
//! dependency injection's `AddSingleton<IFoo, Foo>()`, a serializer's `Deserialize<T>()`), a
//! string naming it, or a custom attribute naming it. A type made by one of those routes
//! makes its fields' types too (a deserializer fills them), and gets its constructors and
//! property accessors called, since reflection is what calls them.
//!
//! Code outside the graph (the .NET runtime and shared frameworks) calls into a made type
//! through what that type overrides or implements from outside: `ToString`, `Dispose`,
//! `IAsyncStateMachine.MoveNext`, an ASP.NET Core interface. A method whose slot comes from
//! outside the graph, or from a `System.*` or `Microsoft.*` assembly that the shared framework
//! may itself call, is reached on every made type.
//!
//! Reached calls into reflection by name (`Type.GetType`, `Activator.CreateInstance`,
//! `MethodBase.Invoke`, ...) are listed in [`Analysis::open_reflection`]: what they load is
//! outside the graph, so "not reached" means "not reached in this graph".

use std::collections::{HashMap, HashSet, VecDeque};

use crate::{Assembly, Invoke, Method, Op, Type};

/// Whose code an assembly is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    App,
    Dependency,
}

/// Why a method is in the graph with no caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Root {
    /// A method of the service's own code.
    AppCode,
    /// Code outside the graph calls it on a made type: it overrides or implements an outside
    /// slot, or reflection calls it (a constructor, a property accessor, a type initializer).
    Outside,
    /// An assembly-level attribute: reflection makes it.
    AssemblyAttribute,
    /// Named in the service's configuration files.
    Configuration,
}

/// One step of a witness, entry point first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The declaring type, as reflection names it.
    pub type_name: String,
    pub method: String,
}

/// A path to a method: why the first step is an entry point, then each step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    pub root: Root,
    pub steps: Vec<Step>,
}

/// The interfaces of assemblies outside the graph (the shared frameworks an image ships),
/// by reflection name: the method names each declares and the interfaces it extends.
///
/// A method that starts a new slot on a type implementing an outside interface may be what
/// that interface's callers land on. With the interface listed here, only a method of a name
/// it (or an interface it extends) declares can be; an interface not listed may declare
/// anything.
#[derive(Debug, Default, Clone)]
pub struct OutsideInterfaces {
    map: HashMap<String, (HashSet<String>, Vec<String>)>,
}

impl OutsideInterfaces {
    /// Add `assembly`'s interfaces. Several versions of one interface pool their names.
    pub fn add(&mut self, assembly: &Assembly) {
        for t in assembly.types.iter().filter(|t| t.is_interface()) {
            self.insert(
                &t.full_name,
                t.methods.iter().map(|m| &m.name),
                &t.interfaces,
            );
        }
    }

    /// Add the interfaces of each `.dll` file in `paths`, read from metadata only
    /// ([`crate::read_interfaces`]). A file that cannot be read adds nothing, which leaves its
    /// interfaces unknown: that only keeps more methods reached.
    pub fn add_files<P: AsRef<std::path::Path>>(&mut self, paths: impl IntoIterator<Item = P>) {
        for path in paths {
            let Some(found) = std::fs::read(path.as_ref())
                .ok()
                .and_then(|b| crate::read_interfaces(&b).ok())
            else {
                continue;
            };
            for i in found {
                self.insert(&i.full_name, i.methods.iter(), &i.extends);
            }
        }
    }

    fn insert<'s>(
        &mut self,
        name: &str,
        methods: impl Iterator<Item = &'s String>,
        extends: &[String],
    ) {
        let (names, bases) = self.map.entry(name.to_string()).or_default();
        names.extend(methods.cloned());
        for i in extends {
            if !bases.contains(i) {
                bases.push(i.clone());
            }
        }
    }

    /// How many interfaces are listed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

type Sym = u32;
type Id = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Via {
    Root(RootKind),
    Call(Id),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootKind {
    AppCode,
    Outside,
    AssemblyAttribute,
    Configuration,
}

impl From<RootKind> for Root {
    fn from(r: RootKind) -> Self {
        match r {
            RootKind::AppCode => Root::AppCode,
            RootKind::Outside => Root::Outside,
            RootKind::AssemblyAttribute => Root::AssemblyAttribute,
            RootKind::Configuration => Root::Configuration,
        }
    }
}

/// Reflection that loads or calls by a name no constant in the graph gives.
const REFLECTION: &[(&str, &str)] = &[
    ("System.Type", "GetType"),
    ("System.Type", "InvokeMember"),
    ("System.Type", "GetMethod"),
    ("System.Type", "GetMethods"),
    ("System.Type", "GetConstructor"),
    ("System.Type", "GetConstructors"),
    ("System.Type", "GetProperty"),
    ("System.Type", "GetMember"),
    ("System.Activator", "CreateInstance"),
    ("System.Activator", "CreateInstanceFrom"),
    ("System.Reflection.Assembly", "GetType"),
    ("System.Reflection.Assembly", "GetTypes"),
    ("System.Reflection.Assembly", "GetExportedTypes"),
    ("System.Reflection.Assembly", "CreateInstance"),
    ("System.Reflection.Assembly", "Load"),
    ("System.Reflection.Assembly", "LoadFrom"),
    ("System.Reflection.Assembly", "LoadFile"),
    ("System.Reflection.MethodBase", "Invoke"),
    ("System.Reflection.MethodInfo", "Invoke"),
    ("System.Reflection.ConstructorInfo", "Invoke"),
    ("System.Reflection.PropertyInfo", "GetValue"),
    ("System.Reflection.PropertyInfo", "SetValue"),
    ("System.Delegate", "CreateDelegate"),
    ("System.Delegate", "DynamicInvoke"),
    ("System.Reflection.MethodInfo", "CreateDelegate"),
    ("System.Linq.Expressions.Expression", "Compile"),
    ("System.Linq.Expressions.LambdaExpression", "Compile"),
];

/// Libraries that call, by name from configuration, any public static method taking one of
/// their types first: when the library's code is reached, those methods are too.
const CONVENTIONS: &[(&str, &[&str])] = &[
    ("Serilog.Settings.Configuration", SERILOG_CONFIGURATION),
    ("Serilog.Settings.AppSettings", SERILOG_CONFIGURATION),
];

const SERILOG_CONFIGURATION: &[&str] = &[
    "Serilog.Configuration.LoggerSinkConfiguration",
    "Serilog.Configuration.LoggerAuditSinkConfiguration",
    "Serilog.Configuration.LoggerEnrichmentConfiguration",
    "Serilog.Configuration.LoggerFilterConfiguration",
    "Serilog.Configuration.LoggerDestructuringConfiguration",
    "Serilog.Configuration.LoggerSettingsConfiguration",
    "Serilog.Configuration.LoggerMinimumLevelConfiguration",
    "Serilog.LoggerConfiguration",
];

/// Assemblies whose types the shared framework may itself call through (it ships them, and
/// a service may bundle a newer copy).
fn framework_family(assembly: &str) -> bool {
    assembly.starts_with("System.")
        || assembly.starts_with("Microsoft.")
        || matches!(assembly, "System" | "mscorlib" | "netstandard")
}

struct TypeInfo<'a> {
    ty: &'a Type,
    name: Sym,
    assembly: u32,
    role: Role,
    value_type: bool,
    framework: bool,
    /// Global ids of its methods: `first..first + ty.methods.len()`.
    first: Id,
}

/// The graph, reached methods with how each was reached.
pub struct Analysis<'a> {
    inputs: &'a [(Assembly, Role)],
    types: Vec<TypeInfo<'a>>,
    names: HashMap<&'a str, Sym>,
    by_name: HashMap<Sym, Vec<u32>>,
    owner: Vec<u32>,
    reached: HashMap<Id, Via>,
    /// Entry points found. None means the inputs held no service to analyze.
    pub roots: usize,
    /// Reached methods that call reflection by name, as `Type::Method`.
    pub open_reflection: Vec<String>,
}

impl std::fmt::Debug for Analysis<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Analysis")
            .field("types", &self.types.len())
            .field("reached", &self.reached.len())
            .field("roots", &self.roots)
            .finish_non_exhaustive()
    }
}

struct Walk<'g, 'a> {
    g: &'g Analysis<'a>,
    outside: &'g OutsideInterfaces,
    /// Per type and method name, the type's methods of that name (overloads).
    members: HashMap<(u32, Sym), Vec<Id>>,
    /// Per type and method name, its explicit interface implementations (`IFoo.Bar`) of it.
    explicit: HashMap<(u32, Sym), Vec<Id>>,
    /// Every type's ancestors (base types and interfaces, transitively), by name.
    ancestors: Vec<Vec<Sym>>,
    reached: HashMap<Id, Via>,
    queue: VecDeque<Id>,
    made: HashSet<u32>,
    /// Made types by each of their ancestors, and by their own name.
    made_by_ancestor: HashMap<Sym, Vec<u32>>,
    /// Virtual call sites by the type written in the call, each method name with its first
    /// caller.
    sites: HashMap<Sym, Vec<(Sym, Id)>>,
    site_seen: HashSet<(Sym, Sym)>,
    initialized: HashSet<u32>,
    /// Types made by a reflective route, whose fields' types were made too.
    filled: HashSet<u32>,
    /// Types whose attributes were made.
    attributed: HashSet<u32>,
    reflection: HashSet<(&'static str, &'static str)>,
    /// Field types still to make reflectively.
    pending: Vec<(u32, Option<Id>, RootKind)>,
    open_reflection: Vec<String>,
    roots: usize,
    ctor: Option<Sym>,
    cctor: Option<Sym>,
    /// Per input assembly, the convention rule its reached code fires, if any.
    convention: Vec<Option<usize>>,
    fired: HashSet<usize>,
}

/// Build the graph over `inputs` from every entry point.
#[must_use]
pub fn analyze(inputs: &[(Assembly, Role)]) -> Analysis<'_> {
    analyze_with(inputs, &[])
}

/// [`analyze`], with type names the service's configuration files give (`appsettings.json`,
/// `web.config`, `nlog.config`): reflection makes those types.
#[must_use]
pub fn analyze_with<'a>(inputs: &'a [(Assembly, Role)], config_names: &[String]) -> Analysis<'a> {
    analyze_outside(inputs, config_names, &OutsideInterfaces::default())
}

/// [`analyze_with`], knowing the interfaces of the shared frameworks the service runs on.
#[must_use]
pub fn analyze_outside<'a>(
    inputs: &'a [(Assembly, Role)],
    config_names: &[String],
    outside: &OutsideInterfaces,
) -> Analysis<'a> {
    let mut g = Analysis {
        inputs,
        types: Vec::new(),
        names: HashMap::new(),
        by_name: HashMap::new(),
        owner: Vec::new(),
        reached: HashMap::new(),
        roots: 0,
        open_reflection: Vec::new(),
    };
    let mut first: Id = 0;
    for (ai, (assembly, role)) in inputs.iter().enumerate() {
        let framework = framework_family(&assembly.name);
        for ty in &assembly.types {
            let name = g.intern(&ty.full_name);
            let index = u32::try_from(g.types.len()).unwrap_or(u32::MAX);
            g.by_name.entry(name).or_default().push(index);
            let value_type = matches!(
                ty.extends.as_deref(),
                Some("System.ValueType" | "System.Enum")
            );
            for m in &ty.methods {
                g.intern(&m.name);
                if let Some((_, method)) = explicit(&m.name) {
                    g.intern(method);
                }
            }
            g.types.push(TypeInfo {
                ty,
                name,
                assembly: u32::try_from(ai).unwrap_or(u32::MAX),
                role: *role,
                value_type,
                framework,
                first,
            });
            for _ in &ty.methods {
                g.owner.push(index);
            }
            first += u32::try_from(ty.methods.len()).unwrap_or(u32::MAX);
        }
    }
    let mut walk = Walk::new(&g, outside);
    walk.seed(config_names);
    walk.run();
    let Walk {
        reached,
        open_reflection,
        roots,
        ..
    } = walk;
    g.reached = reached;
    g.open_reflection = open_reflection;
    g.roots = roots;
    g
}

impl<'a> Analysis<'a> {
    fn intern(&mut self, s: &'a str) -> Sym {
        let next = Sym::try_from(self.names.len()).unwrap_or(Sym::MAX);
        *self.names.entry(s).or_insert(next)
    }

    fn sym(&self, s: &str) -> Option<Sym> {
        self.names.get(s).copied()
    }

    fn method(&self, id: Id) -> (&TypeInfo<'a>, &'a Method) {
        let t = &self.types[self.owner[id as usize] as usize];
        let ty: &'a Type = t.ty;
        (t, &ty.methods[(id - t.first) as usize])
    }

    /// Whether `type_name` (reflection form) is one of the input types.
    #[must_use]
    pub fn has_type(&self, type_name: &str) -> bool {
        self.sym(type_name)
            .is_some_and(|s| self.by_name.contains_key(&s))
    }

    /// Whether the inputs define `type_name::method`.
    #[must_use]
    pub fn has_method(&self, type_name: &str, method: &str) -> bool {
        self.has_method_in(type_name, method, &|_| true)
    }

    /// [`Analysis::has_method`], counting only the assemblies whose name `keep` accepts.
    #[must_use]
    pub fn has_method_in(
        &self,
        type_name: &str,
        method: &str,
        keep: &dyn Fn(&str) -> bool,
    ) -> bool {
        self.ids(type_name, method, keep).next().is_some()
    }

    fn ids<'s>(
        &'s self,
        type_name: &str,
        method: &'s str,
        keep: &'s dyn Fn(&str) -> bool,
    ) -> impl Iterator<Item = Id> + 's {
        let types = self
            .sym(type_name)
            .and_then(|s| self.by_name.get(&s))
            .map_or(&[][..], Vec::as_slice);
        types
            .iter()
            .filter(move |&&t| {
                let assembly = self.types[t as usize].assembly as usize;
                self.inputs
                    .get(assembly)
                    .is_some_and(|(a, _)| keep(&a.name))
            })
            .flat_map(move |&t| {
                let info = &self.types[t as usize];
                info.ty
                    .methods
                    .iter()
                    .enumerate()
                    .filter(move |(_, m)| m.name == method)
                    .map(move |(i, _)| info.first + u32::try_from(i).unwrap_or(0))
            })
    }

    /// A path from an entry point to `type_name::method`, if the graph reaches it.
    #[must_use]
    pub fn witness(&self, type_name: &str, method: &str) -> Option<Witness> {
        self.witness_in(type_name, method, &|_| true)
    }

    /// [`Analysis::witness`], to the method as defined in an assembly whose name `keep`
    /// accepts. A package can carry a copy of a type the runtime also defines
    /// (`System.Net.WebSockets.ManagedWebSocket`), and only the package's copy is its flaw.
    #[must_use]
    pub fn witness_in(
        &self,
        type_name: &str,
        method: &str,
        keep: &dyn Fn(&str) -> bool,
    ) -> Option<Witness> {
        let id = self
            .ids(type_name, method, keep)
            .filter(|id| self.reached.contains_key(id))
            .min_by_key(|id| self.depth(*id))?;
        let mut steps = Vec::new();
        let mut at = id;
        let mut seen = HashSet::new();
        loop {
            let (t, m) = self.method(at);
            steps.push(Step {
                type_name: t.ty.full_name.clone(),
                method: m.name.clone(),
            });
            if !seen.insert(at) {
                return None;
            }
            match self.reached.get(&at)? {
                Via::Root(r) => {
                    steps.reverse();
                    return Some(Witness {
                        root: (*r).into(),
                        steps,
                    });
                }
                Via::Call(from) => at = *from,
            }
        }
    }

    fn depth(&self, mut id: Id) -> usize {
        let mut n = 0;
        while let Some(Via::Call(from)) = self.reached.get(&id) {
            n += 1;
            if n > self.reached.len() {
                break;
            }
            id = *from;
        }
        n
    }

    /// Every reached method as `Type::Method`.
    #[must_use]
    pub fn reached_methods(&self) -> std::collections::BTreeSet<String> {
        self.reached
            .keys()
            .map(|id| {
                let (t, m) = self.method(*id);
                format!("{}::{}", t.ty.full_name, m.name)
            })
            .collect()
    }

    /// Methods in the inputs.
    #[must_use]
    pub fn methods(&self) -> usize {
        self.owner.len()
    }

    /// Methods reached.
    #[must_use]
    pub fn reached(&self) -> usize {
        self.reached.len()
    }

    /// The assembly a reached method's type comes from, by method id (for reports).
    #[must_use]
    pub fn assemblies(&self) -> usize {
        self.inputs.len()
    }
}

/// An explicit interface implementation's name (`System.IDisposable.Dispose`,
/// `System.Collections.Generic.IEnumerable<T>.GetEnumerator`) as the interface's reflection
/// name and the method's own name.
fn explicit(name: &str) -> Option<(String, &str)> {
    if name.starts_with('.') {
        return None;
    }
    let mut depth = 0usize;
    let mut split = None;
    for (i, c) in name.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            '.' if depth == 0 => split = Some(i),
            _ => {}
        }
    }
    let split = split?;
    let (iface, method) = (&name[..split], &name[split + 1..]);
    if method.is_empty() {
        return None;
    }
    let Some(open) = iface.find('<') else {
        return Some((iface.to_string(), method));
    };
    let mut arity = 1;
    let mut depth = 0usize;
    for c in iface[open..].chars() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            ',' if depth == 1 => arity += 1,
            _ => {}
        }
    }
    Some((format!("{}`{arity}", &iface[..open]), method))
}

/// The type a string may name: `Ns.Type`, `Ns.Type, Assembly, Version=...`, `Ns.Type`1[[...]]`.
fn named_type(s: &str) -> &str {
    let s = s.split(',').next().unwrap_or(s);
    let s = s.split('[').next().unwrap_or(s);
    s.trim()
}

/// Every dotted name in `s` (`Ns.Type`, `Ns.Outer+Inner`, `Ns.Gen`1`), as candidates.
fn type_words(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| !(c.is_alphanumeric() || matches!(c, '.' | '+' | '`' | '_')))
        .filter(|w| w.contains('.') && w.len() > 2)
}

impl<'g, 'a> Walk<'g, 'a> {
    fn new(g: &'g Analysis<'a>, outside: &'g OutsideInterfaces) -> Self {
        let mut members: HashMap<(u32, Sym), Vec<Id>> = HashMap::new();
        let mut explicit_members: HashMap<(u32, Sym), Vec<Id>> = HashMap::new();
        for (ti, t) in g.types.iter().enumerate() {
            let ti = u32::try_from(ti).unwrap_or(u32::MAX);
            for (mi, m) in t.ty.methods.iter().enumerate() {
                let id = t.first + u32::try_from(mi).unwrap_or(0);
                if let Some(own) = g.sym(&m.name) {
                    members.entry((ti, own)).or_default().push(id);
                }
                if let Some(s) = explicit(&m.name).and_then(|(_, method)| g.sym(method)) {
                    explicit_members.entry((ti, s)).or_default().push(id);
                }
            }
        }
        let mut walk = Walk {
            g,
            outside,
            members,
            explicit: explicit_members,
            ancestors: Vec::new(),
            reached: HashMap::new(),
            queue: VecDeque::new(),
            made: HashSet::new(),
            made_by_ancestor: HashMap::new(),
            sites: HashMap::new(),
            site_seen: HashSet::new(),
            initialized: HashSet::new(),
            filled: HashSet::new(),
            attributed: HashSet::new(),
            reflection: REFLECTION.iter().copied().collect(),
            pending: Vec::new(),
            open_reflection: Vec::new(),
            roots: 0,
            ctor: g.sym(".ctor"),
            cctor: g.sym(".cctor"),
            convention: g
                .inputs
                .iter()
                .map(|(a, _)| CONVENTIONS.iter().position(|(name, _)| *name == a.name))
                .collect(),
            fired: HashSet::new(),
        };
        walk.ancestors = (0..g.types.len())
            .map(|i| walk.compute_ancestors(u32::try_from(i).unwrap_or(u32::MAX)))
            .collect();
        walk
    }

    /// A name's symbol, for names the inputs use as type or member names.
    fn sym(&self, s: &str) -> Option<Sym> {
        self.g.sym(s)
    }

    fn types_named(&self, name: Sym) -> &'g [u32] {
        self.g.by_name.get(&name).map_or(&[][..], Vec::as_slice)
    }

    /// The types named `name` that a reference in method `from` can mean. When `from`'s own
    /// assembly defines one, only that: the reference is then a TypeDef token, as for a
    /// package's internal copy of a type the runtime also defines, or the attributes every
    /// compiler output embeds. Otherwise every input's.
    fn types_from(&self, name: Sym, from: Id) -> &'g [u32] {
        match self.g.owner.get(from as usize) {
            Some(&t) => self.types_in(name, self.g.types[t as usize].assembly),
            None => self.types_named(name),
        }
    }

    /// The types named `name` that a reference in assembly `own` means: its own when it
    /// defines one, else every input's.
    fn types_in(&self, name: Sym, own: u32) -> &'g [u32] {
        let all = self.types_named(name);
        if all.len() < 2 {
            return all;
        }
        let assembly = |t: &u32| self.g.types[*t as usize].assembly;
        // A type's index grows with its assembly's, so one assembly's are a run.
        let start = all.partition_point(|t| assembly(t) < own);
        let end = all.partition_point(|t| assembly(t) <= own);
        if start < end {
            &all[start..end]
        } else {
            all
        }
    }

    fn compute_ancestors(&self, start: u32) -> Vec<Sym> {
        let mut out: Vec<Sym> = Vec::new();
        let mut seen: HashSet<u32> = HashSet::new();
        let mut stack = vec![start];
        while let Some(t) = stack.pop() {
            if !seen.insert(t) {
                continue;
            }
            let ty = self.g.types[t as usize].ty;
            for parent in ty.extends.iter().chain(&ty.interfaces) {
                let Some(s) = self.sym(parent) else { continue };
                if !out.contains(&s) {
                    out.push(s);
                }
                stack.extend_from_slice(self.types_named(s));
            }
        }
        out
    }

    /// Whether an interface `t` (or a base type of it) implements from outside the graph, or
    /// from a framework-family assembly, may declare a method named `name`: one the
    /// [`OutsideInterfaces`] do not list may declare anything.
    fn outside_may_declare(&self, t: u32, name: &str) -> bool {
        let mut todo: Vec<&'g str> = Vec::new();
        let mut seen_types = HashSet::new();
        let mut stack = vec![t];
        while let Some(t) = stack.pop() {
            if !seen_types.insert(t) {
                continue;
            }
            let ty = self.g.types[t as usize].ty;
            todo.extend(ty.interfaces.iter().map(String::as_str));
            if let Some(base) = ty.extends.as_deref().and_then(|b| self.sym(b)) {
                stack.extend_from_slice(self.types_named(base));
            }
        }
        let mut seen = HashSet::new();
        while let Some(i) = todo.pop() {
            if !seen.insert(i) {
                continue;
            }
            let inside = self.sym(i).map_or(&[][..], |s| self.types_named(s));
            if inside.is_empty() {
                let Some((names, bases)) = self.outside.map.get(i) else {
                    return true;
                };
                if names.contains(name) {
                    return true;
                }
                todo.extend(bases.iter().map(String::as_str));
                continue;
            }
            for &x in inside {
                let info = &self.g.types[x as usize];
                if info.framework && info.ty.methods.iter().any(|m| m.name == name) {
                    return true;
                }
                todo.extend(info.ty.interfaces.iter().map(String::as_str));
            }
        }
        false
    }

    fn reach(&mut self, id: Id, via: Via) {
        if let std::collections::hash_map::Entry::Vacant(slot) = self.reached.entry(id) {
            slot.insert(via);
            self.queue.push_back(id);
            let t = self.g.owner[id as usize];
            self.attributes_of(t, id);
            let assembly = self.g.types[t as usize].assembly as usize;
            if let Some(rule) = self.convention.get(assembly).copied().flatten() {
                if self.fired.insert(rule) {
                    self.convention(rule, id);
                }
            }
        }
    }

    /// A convention library is running: every public static method taking one of its types
    /// first may be called by name.
    fn convention(&mut self, rule: usize, from: Id) {
        let firsts = CONVENTIONS[rule].1;
        let g = self.g;
        for t in &g.types {
            for (mi, m) in t.ty.methods.iter().enumerate() {
                // The library's own surrogates for instance methods are not public.
                let own = g.inputs[t.assembly as usize].0.name == CONVENTIONS[rule].0;
                if m.is_static()
                    && (m.is_public() || own)
                    && m.params
                        .first()
                        .is_some_and(|p| firsts.contains(&p.as_str()))
                {
                    self.reach(t.first + u32::try_from(mi).unwrap_or(0), Via::Call(from));
                }
            }
        }
    }

    fn root(&mut self, id: Id, kind: RootKind) {
        self.roots += 1;
        self.reach(id, Via::Root(kind));
    }

    fn seed(&mut self, names: &[String]) {
        let g = self.g;
        for name in names {
            self.make_named(named_type(name), None, RootKind::Configuration);
        }
        for (ti, t) in g.types.iter().enumerate() {
            let ti = u32::try_from(ti).unwrap_or(u32::MAX);
            if t.role != Role::App {
                continue;
            }
            // Every method, private ones too: `Main` is private by default.
            for mi in 0..t.ty.methods.len() {
                self.root(t.first + u32::try_from(mi).unwrap_or(0), RootKind::AppCode);
            }
            if !t.ty.is_interface() && !t.ty.is_abstract() {
                self.make(ti, true, None);
            }
        }
        for (assembly, _) in g.inputs {
            for name in assembly.attributes.iter().chain(&assembly.attribute_text) {
                self.make_named(named_type(name), None, RootKind::AssemblyAttribute);
            }
        }
    }

    fn run(&mut self) {
        loop {
            while let Some((t, from, kind)) = self.pending.pop() {
                self.make_via(t, true, from, kind);
            }
            let Some(id) = self.queue.pop_front() else {
                if self.pending.is_empty() {
                    break;
                }
                continue;
            };
            let (_, m) = self.g.method(id);
            for name in &m.type_args {
                self.make_token(name, id);
            }
            for name in &m.mentions {
                if let Some(ty) = self.sym(name) {
                    self.value_types(ty, id);
                }
            }
            let Some((_, ops)) = &m.body else { continue };
            for op in ops {
                self.op(id, op);
            }
        }
    }

    fn op(&mut self, from: Id, op: &'a Op) {
        match op {
            Op::Invoke { kind, target } => {
                if self
                    .reflection
                    .contains(&(target.type_name.as_str(), target.name.as_str()))
                {
                    let (t, m) = self.g.method(from);
                    let site = format!("{}::{}", t.ty.full_name, m.name);
                    if !self.open_reflection.contains(&site) {
                        self.open_reflection.push(site);
                    }
                }
                let Some(ty) = self.sym(&target.type_name) else {
                    return;
                };
                let name = self.sym(&target.name);
                self.init(ty, from);
                let Some(name) = name else { return };
                match kind {
                    Invoke::NewObj => {
                        for &t in self.types_from(ty, from) {
                            self.make(t, false, Some(from));
                        }
                        self.resolve(ty, name, from);
                    }
                    Invoke::Call | Invoke::Jmp | Invoke::LdFtn => {
                        if Some(name) == self.ctor {
                            // `call .ctor` builds a value type in place or chains a base
                            // constructor.
                            for &t in self.types_from(ty, from) {
                                if self.g.types[t as usize].value_type {
                                    self.make(t, false, Some(from));
                                }
                            }
                        }
                        self.value_types(ty, from);
                        self.resolve(ty, name, from);
                    }
                    Invoke::CallVirt | Invoke::LdVirtFtn => {
                        self.value_types(ty, from);
                        self.resolve(ty, name, from);
                        self.site(ty, name, from);
                    }
                }
            }
            Op::Str(s) => {
                let n = named_type(s);
                if n.contains('.') {
                    self.make_named(n, Some(from), RootKind::Outside);
                }
                // Configuration held in a string names types inside it.
                if s.len() > n.len() {
                    for word in type_words(s) {
                        self.make_named(word, Some(from), RootKind::Outside);
                    }
                }
            }
            Op::TypeToken(t) => self.make_token(t, from),
            Op::MethodToken(target) => {
                if let (Some(ty), Some(name)) =
                    (self.sym(&target.type_name), self.sym(&target.name))
                {
                    self.resolve(ty, name, from);
                }
            }
            Op::FieldToken(t) | Op::StaticField(t) => {
                if let Some(ty) = self.sym(t) {
                    self.init(ty, from);
                    self.value_types(ty, from);
                }
            }
        }
    }

    /// A value type mentioned in reached code may exist: locals of it need no `newobj`.
    fn value_types(&mut self, ty: Sym, from: Id) {
        for &t in self.types_from(ty, from) {
            if self.g.types[t as usize].value_type {
                self.make(t, false, Some(from));
            }
        }
    }

    fn make_named(&mut self, name: &str, from: Option<Id>, kind: RootKind) {
        let Some(ty) = self.sym(name) else { return };
        for &t in self.types_named(ty) {
            self.make_via(t, true, from, kind);
        }
    }

    /// [`Walk::make_named`] for a type token in `from`'s code (`ldtoken`, a generic argument):
    /// like a call, it means `from`'s own assembly's type when there is one.
    fn make_token(&mut self, name: &str, from: Id) {
        let Some(ty) = self.sym(name) else { return };
        for &t in self.types_from(ty, from) {
            self.make_via(t, true, Some(from), RootKind::Outside);
        }
    }

    fn via(from: Option<Id>, kind: RootKind) -> Via {
        from.map_or(Via::Root(kind), Via::Call)
    }

    fn make(&mut self, t: u32, reflective: bool, from: Option<Id>) {
        self.make_via(t, reflective, from, RootKind::Outside);
    }

    /// `t` is made. A reflective route also calls its constructors and accessors, and makes
    /// its fields' types.
    fn make_via(&mut self, t: u32, reflective: bool, from: Option<Id>, kind: RootKind) {
        let g = self.g;
        let info = &g.types[t as usize];
        let via = Self::via(from, kind);
        if reflective {
            for (mi, m) in info.ty.methods.iter().enumerate() {
                let id = info.first + u32::try_from(mi).unwrap_or(0);
                if !m.is_static()
                    && (m.name == ".ctor"
                        || m.name.starts_with("get_")
                        || m.name.starts_with("set_")
                        || (m.is_public() && matches!(m.name.as_str(), "Invoke" | "InvokeAsync")))
                {
                    self.reach_counted(id, via);
                }
            }
        }
        let first_time = self.made.insert(t);
        if reflective && self.filled.insert(t) {
            // Fields a deserializer fills, once per type. A worklist, not recursion: field
            // types nest deep.
            let fields: Vec<u32> = info
                .ty
                .field_types
                .iter()
                .filter_map(|f| self.sym(f))
                .flat_map(|ft| self.types_in(ft, info.assembly).iter().copied())
                .filter(|x| !self.filled.contains(x))
                .collect();
            self.pending
                .extend(fields.into_iter().map(|x| (x, from, kind)));
        }
        if !first_time {
            return;
        }
        self.init_type(t, via);
        // Outside slots and the dispatch of sites already seen.
        // The made type's own methods and those it inherits.
        let mut chain = vec![t];
        while chain.len() < 64 {
            let Some(base) = self.base_of(chain[chain.len() - 1]) else {
                break;
            };
            chain.push(base);
        }
        for x in chain {
            let xi = &g.types[x as usize];
            for (mi, m) in xi.ty.methods.iter().enumerate() {
                if m.is_static() || !m.is_virtual() {
                    continue;
                }
                let id = xi.first + u32::try_from(mi).unwrap_or(0);
                if !self.reached.contains_key(&id) && self.slot_from_outside(x, m) {
                    self.reach_counted(id, via);
                }
            }
        }
        let mut keys = self.ancestors[t as usize].clone();
        keys.push(info.name);
        for a in keys {
            self.made_by_ancestor.entry(a).or_default().push(t);
            let calls: Vec<(Sym, Id)> = self.sites.get(&a).cloned().unwrap_or_default();
            for (name, caller) in calls {
                self.dispatch(t, name, caller);
            }
        }
    }

    /// Reach a method that code outside the graph runs: a root when nothing in the graph led
    /// there.
    fn reach_counted(&mut self, id: Id, via: Via) {
        if matches!(via, Via::Root(_)) && !self.reached.contains_key(&id) {
            self.roots += 1;
        }
        self.reach(id, via);
    }

    /// The first in-graph type `t` extends.
    fn base_of(&self, t: u32) -> Option<u32> {
        let info = &self.g.types[t as usize];
        let base = info.ty.extends.as_deref()?;
        self.types_in(self.sym(base)?, info.assembly)
            .first()
            .copied()
    }

    /// Whether code outside the graph may call `m`, declared by `t`, on a made instance: its
    /// slot starts outside the graph or in a framework-family assembly.
    fn slot_from_outside(&self, t: u32, m: &Method) -> bool {
        if let Some((iface, _)) = explicit(&m.name) {
            let inside = self.sym(&iface).map_or(&[][..], |s| self.types_named(s));
            return inside.is_empty() || inside.iter().any(|&x| self.g.types[x as usize].framework);
        }
        // (Every method name is interned.)
        let Some(name) = self.sym(&m.name) else {
            return true;
        };
        let mut owners = vec![t];
        for a in &self.ancestors[t as usize] {
            owners.extend(
                self.types_named(*a)
                    .iter()
                    .filter(|&&x| self.members.contains_key(&(x, name))),
            );
        }
        // A declaration whose slot no in-graph ancestor gives starts the slot: outside, when
        // it overrides (not `newslot`) or may implement an outside interface.
        owners.into_iter().any(|x| {
            let info = &self.g.types[x as usize];
            if info.framework {
                return true;
            }
            let inherited = self.ancestors[x as usize].iter().any(|a| {
                self.types_named(*a)
                    .iter()
                    .any(|&y| self.members.contains_key(&(y, name)))
            });
            if inherited {
                return false;
            }
            let own = self.members.get(&(x, name)).map_or(&[][..], Vec::as_slice);
            own.iter().any(|&id| {
                let (_, d) = self.g.method(id);
                !d.is_static() && (!d.is_new_slot() || self.outside_may_declare(x, &m.name))
            })
        })
    }

    fn init(&mut self, ty: Sym, from: Id) {
        for &t in self.types_from(ty, from) {
            self.init_type(t, Via::Call(from));
        }
    }

    fn init_type(&mut self, t: u32, via: Via) {
        if !self.initialized.insert(t) {
            return;
        }
        if let Some(cctor) = self.cctor {
            if let Some(ids) = self.members.get(&(t, cctor)).cloned() {
                for id in ids {
                    self.reach_counted(id, via);
                }
            }
        }
    }

    /// The methods named `name` that a call written against `ty` resolves to, up the base
    /// types.
    fn resolve(&mut self, ty: Sym, name: Sym, from: Id) {
        for &t in self.types_from(ty, from) {
            self.resolve_from(t, name, from);
        }
    }

    fn resolve_from(&mut self, start: u32, name: Sym, from: Id) {
        let mut t = start;
        for _ in 0..64 {
            if let Some(ids) = self.members.get(&(t, name)).cloned() {
                for id in ids {
                    self.reach(id, Via::Call(from));
                }
                return;
            }
            let Some(base) = self.g.types[t as usize]
                .ty
                .extends
                .as_deref()
                .and_then(|b| self.sym(b))
            else {
                return;
            };
            let bases = self.types_in(base, self.g.types[t as usize].assembly);
            let Some(&next) = bases.first() else {
                return;
            };
            for &other in &bases[1..] {
                self.resolve_from(other, name, from);
            }
            t = next;
        }
    }

    fn site(&mut self, ty: Sym, name: Sym, from: Id) {
        if !self.site_seen.insert((ty, name)) {
            return;
        }
        self.sites.entry(ty).or_default().push((name, from));
        let made: Vec<u32> = self.made_by_ancestor.get(&ty).cloned().unwrap_or_default();
        for t in made {
            self.dispatch(t, name, from);
        }
    }

    /// A virtual call to `name` on a made `t`: its override, up the base types, and its
    /// explicit implementations.
    fn dispatch(&mut self, t: u32, name: Sym, from: Id) {
        self.resolve_from(t, name, from);
        // Explicit implementations anywhere up the chain carry the name as their method part.
        let mut at = Some(t);
        let mut guard = 0;
        while let Some(x) = at {
            if let Some(ids) = self.explicit.get(&(x, name)).cloned() {
                for id in ids {
                    self.reach(id, Via::Call(from));
                }
            }
            guard += 1;
            if guard > 64 {
                break;
            }
            at = self.base_of(x);
        }
    }

    /// When a type's code first runs, its attributes may be read: reflection makes them and
    /// what they name.
    fn attributes_of(&mut self, t: u32, from: Id) {
        if !self.attributed.insert(t) {
            return;
        }
        let ty = self.g.types[t as usize].ty;
        for name in ty.attributes.iter().chain(&ty.attribute_text) {
            self.make_named(named_type(name), Some(from), RootKind::Outside);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::explicit;

    #[test]
    fn explicit_implementations_name_their_interface() {
        assert_eq!(
            explicit("System.IDisposable.Dispose"),
            Some(("System.IDisposable".to_string(), "Dispose"))
        );
        assert_eq!(
            explicit("System.Collections.Generic.IDictionary<TKey,TValue>.get_Item"),
            Some((
                "System.Collections.Generic.IDictionary`2".to_string(),
                "get_Item"
            ))
        );
        assert_eq!(
            explicit("System.IComparable<Acme.Money>.CompareTo"),
            Some(("System.IComparable`1".to_string(), "CompareTo"))
        );
        assert_eq!(explicit(".ctor"), None);
        assert_eq!(explicit("Plain"), None);
    }
}
