//! Resolve a `pom.xml` into the dependency tree Maven would build, without running Maven
//! (spec 04). Reads POMs only, never jars or plugins.
//!
//! - **Effective model**: the parent chain (a local `relativePath`, default `../pom.xml`, when
//!   its coordinates match, else the repository), `<properties>` and `${project.*}`
//!   interpolation, `dependencyManagement` merged down the parents and through imported BOMs
//!   (`<scope>import</scope>`), and profiles marked `activeByDefault`.
//! - **Graph**: breadth-first with Maven's mediation: the nearest declaration of an artifact
//!   wins (the first one at equal depth), the root's `dependencyManagement` sets the version
//!   and scope of transitive artifacts, `<exclusions>` (including `*`) prune subtrees, and
//!   `optional` dependencies are not inherited. Scopes follow Maven's propagation table (a
//!   dependency's own `test` and `provided` dependencies are on no classpath) and widen when an
//!   artifact is reached by several paths; `test` and `provided` artifacts are dev scope.
//! - **Ranges** (`[1.0,2.0)`) pick the highest matching version listed in
//!   `maven-metadata.xml`, ordered with the `ComparableVersion` port.
//! - **Reactors**: `<modules>` are resolved from their local POMs, and a dependency on a
//!   sibling module follows that module's dependencies instead of the repository.
//!
//! Where POMs come from is the caller's [`PomSource`]: the local Maven repository, a cache,
//! or a network fetcher. Anything that cannot be resolved (a missing POM, an undefined
//! property, a range with no metadata) is recorded in [`Resolution::missing`] by name, and
//! what did resolve is still returned: the caller reports partial coverage, never a clean one.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use fleetreach_core::DepGraph;
use roxmltree::{Document, Node};

use crate::version::parse_maven_version;

/// Where POMs and version listings come from.
pub trait PomSource {
    /// The POM text of `group:artifact:version`, if available.
    fn pom(&self, group: &str, artifact: &str, version: &str) -> Option<String>;
    /// The `maven-metadata.xml` text of `group:artifact`, if available.
    fn metadata(&self, group: &str, artifact: &str) -> Option<String>;
}

/// POMs from local Maven repository layouts (`~/.m2/repository`, a cache), first hit wins.
pub struct LocalRepositories {
    pub roots: Vec<PathBuf>,
}

impl LocalRepositories {
    fn dir(root: &Path, group: &str, artifact: &str) -> PathBuf {
        let mut p = root.to_path_buf();
        for part in group.split('.') {
            p.push(part);
        }
        p.push(artifact);
        p
    }
}

impl PomSource for LocalRepositories {
    fn pom(&self, group: &str, artifact: &str, version: &str) -> Option<String> {
        self.roots.iter().find_map(|root| {
            let path = Self::dir(root, group, artifact)
                .join(version)
                .join(format!("{artifact}-{version}.pom"));
            std::fs::read_to_string(path).ok()
        })
    }

    fn metadata(&self, group: &str, artifact: &str) -> Option<String> {
        self.roots.iter().find_map(|root| {
            let dir = Self::dir(root, group, artifact);
            ["maven-metadata.xml", "maven-metadata-central.xml"]
                .iter()
                .find_map(|f| std::fs::read_to_string(dir.join(f)).ok())
        })
    }
}

/// Try each source in order.
pub struct Chain<'a>(pub Vec<&'a dyn PomSource>);

impl PomSource for Chain<'_> {
    fn pom(&self, g: &str, a: &str, v: &str) -> Option<String> {
        self.0.iter().find_map(|s| s.pom(g, a, v))
    }
    fn metadata(&self, g: &str, a: &str) -> Option<String> {
        self.0.iter().find_map(|s| s.metadata(g, a))
    }
}

/// One resolved artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDep {
    /// `group:artifact`.
    pub name: String,
    pub version: String,
    /// Declared by a module of the project itself.
    pub direct: bool,
    /// `test` or `provided` scope: not part of the runtime classpath.
    pub dev: bool,
    pub scope: String,
}

/// The resolved tree of a project.
#[derive(Debug, Default)]
pub struct Resolution {
    pub packages: Vec<ResolvedDep>,
    pub graph: DepGraph,
    /// What could not be resolved, one line per item.
    pub missing: Vec<String>,
}

// ---- POM model ----

#[derive(Debug, Clone, Default)]
struct Dep {
    group: String,
    artifact: String,
    version: Option<String>,
    scope: Option<String>,
    kind: Option<String>,
    classifier: Option<String>,
    optional: bool,
    exclusions: Vec<(String, String)>,
}

impl Dep {
    fn key(&self) -> (String, String) {
        (self.group.clone(), self.artifact.clone())
    }
    fn mgmt_key(&self) -> (String, String, String, String) {
        (
            self.group.clone(),
            self.artifact.clone(),
            self.kind.clone().unwrap_or_else(|| "jar".into()),
            self.classifier.clone().unwrap_or_default(),
        )
    }
}

#[derive(Debug, Clone, Default)]
struct RawPom {
    group: Option<String>,
    artifact: String,
    version: Option<String>,
    parent: Option<(String, String, String, Option<String>)>,
    properties: BTreeMap<String, String>,
    deps: Vec<Dep>,
    mgmt: Vec<Dep>,
    modules: Vec<String>,
}

fn child<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    node.children()
        .find(|c| c.is_element() && c.tag_name().name() == name)
}

fn children<'a, 'i>(node: Node<'a, 'i>, name: &'a str) -> impl Iterator<Item = Node<'a, 'i>> + 'a {
    node.children()
        .filter(move |c| c.is_element() && c.tag_name().name() == name)
}

fn text(node: Node<'_, '_>, name: &str) -> Option<String> {
    child(node, name)
        .and_then(|c| c.text())
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

fn parse_deps(list: Option<Node<'_, '_>>) -> Vec<Dep> {
    let Some(list) = list else {
        return Vec::new();
    };
    children(list, "dependency")
        .filter_map(|d| {
            Some(Dep {
                group: text(d, "groupId")?,
                artifact: text(d, "artifactId")?,
                version: text(d, "version"),
                scope: text(d, "scope"),
                kind: text(d, "type"),
                classifier: text(d, "classifier"),
                optional: text(d, "optional").as_deref() == Some("true"),
                exclusions: child(d, "exclusions")
                    .map(|ex| {
                        children(ex, "exclusion")
                            .filter_map(|e| Some((text(e, "groupId")?, text(e, "artifactId")?)))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect()
}

fn parse_pom(xml: &str) -> Result<RawPom, String> {
    let doc = Document::parse(xml.trim_start_matches('\u{feff}')).map_err(|e| e.to_string())?;
    let project = doc.root_element();
    if project.tag_name().name() != "project" {
        return Err("not a POM (no <project>)".into());
    }
    let mut pom = RawPom {
        group: text(project, "groupId"),
        artifact: text(project, "artifactId").ok_or("POM without artifactId")?,
        version: text(project, "version"),
        parent: child(project, "parent").and_then(|p| {
            Some((
                text(p, "groupId")?,
                text(p, "artifactId")?,
                text(p, "version")?,
                child(p, "relativePath").map(|r| r.text().unwrap_or("").trim().to_string()),
            ))
        }),
        ..RawPom::default()
    };
    let absorb = |node: Node<'_, '_>, pom: &mut RawPom| {
        if let Some(props) = child(node, "properties") {
            for p in props.children().filter(Node::is_element) {
                pom.properties.insert(
                    p.tag_name().name().to_string(),
                    p.text().unwrap_or("").trim().to_string(),
                );
            }
        }
        pom.deps.extend(parse_deps(child(node, "dependencies")));
        pom.mgmt.extend(parse_deps(
            child(node, "dependencyManagement").and_then(|m| child(m, "dependencies")),
        ));
    };
    absorb(project, &mut pom);
    if let Some(profiles) = child(project, "profiles") {
        for profile in children(profiles, "profile") {
            let active = child(profile, "activation")
                .and_then(|a| text(a, "activeByDefault"))
                .as_deref()
                == Some("true");
            if active {
                absorb(profile, &mut pom);
            }
        }
    }
    if let Some(modules) = child(project, "modules") {
        pom.modules = children(modules, "module")
            .filter_map(|m| m.text().map(|t| t.trim().to_string()))
            .collect();
    }
    Ok(pom)
}

/// A POM with its parents, properties and managed versions applied.
#[derive(Debug, Clone, Default)]
struct Effective {
    group: String,
    artifact: String,
    deps: Vec<Dep>,
    mgmt: BTreeMap<(String, String, String, String), Dep>,
    modules: Vec<String>,
    /// Properties after this POM (inherited by its children).
    props: BTreeMap<String, String>,
}

const MAX_DEPTH: usize = 24;

struct Resolver<'s> {
    source: &'s dyn PomSource,
    cache: BTreeMap<(String, String, String), Option<Effective>>,
    missing: BTreeSet<String>,
}

impl Resolver<'_> {
    /// The effective model of a POM text (`dir` for a local `relativePath` parent).
    fn effective(
        &mut self,
        xml: &str,
        dir: Option<&Path>,
        depth: usize,
    ) -> Result<Effective, String> {
        if depth > MAX_DEPTH {
            return Err("parent or BOM chain too deep".into());
        }
        let raw = parse_pom(xml)?;
        let parent = match &raw.parent {
            Some((g, a, v, rel)) => {
                let local = dir.and_then(|d| {
                    let rel = rel.clone().unwrap_or_else(|| "../pom.xml".into());
                    if rel.is_empty() {
                        return None;
                    }
                    let mut path = d.join(&rel);
                    if path.is_dir() {
                        path = path.join("pom.xml");
                    }
                    let text = std::fs::read_to_string(&path).ok()?;
                    let p = parse_pom(&text).ok()?;
                    (p.artifact == *a).then_some((text, path.parent().map(Path::to_path_buf)))
                });
                match local {
                    Some((text, pdir)) => {
                        Some(self.effective(&text, pdir.as_deref(), depth + 1)?)
                    }
                    None => self.remote(g, a, v, depth + 1),
                }
            }
            None => None,
        };
        let group = raw
            .group
            .clone()
            .or_else(|| raw.parent.as_ref().map(|p| p.0.clone()))
            .unwrap_or_default();
        let version = raw
            .version
            .clone()
            .or_else(|| raw.parent.as_ref().map(|p| p.2.clone()))
            .unwrap_or_default();
        // Properties: the parent's, then this POM's, then the project model.
        let mut props: BTreeMap<String, String> =
            parent.as_ref().map(|p| p.props.clone()).unwrap_or_default();
        props.extend(raw.properties.clone());
        for (k, v) in [
            ("project.groupId", &group),
            ("project.artifactId", &raw.artifact),
            ("project.version", &version),
            ("pom.groupId", &group),
            ("pom.version", &version),
            ("version", &version),
        ] {
            props.insert(k.to_string(), v.clone());
        }
        if let Some((pg, _, pv, _)) = &raw.parent {
            props.insert("project.parent.version".into(), pv.clone());
            props.insert("project.parent.groupId".into(), pg.clone());
            props.insert("parent.version".into(), pv.clone());
        }
        let mut mgmt = parent.as_ref().map(|p| p.mgmt.clone()).unwrap_or_default();
        let mut imports = Vec::new();
        for d in &raw.mgmt {
            let d = self.interp_dep(d, &props);
            if d.scope.as_deref() == Some("import") {
                imports.push(d);
                continue;
            }
            mgmt.insert(d.mgmt_key(), d);
        }
        // Imported BOMs add only what this POM (and its parents) did not manage itself.
        for bom in imports {
            let Some(v) = bom.version.clone() else {
                continue;
            };
            if let Some(eff) = self.remote(&bom.group, &bom.artifact, &v, depth + 1) {
                for (k, d) in eff.mgmt {
                    mgmt.entry(k).or_insert(d);
                }
            }
        }
        let mut deps: Vec<Dep> = parent.as_ref().map(|p| p.deps.clone()).unwrap_or_default();
        for d in &raw.deps {
            let mut d = self.interp_dep(d, &props);
            if let Some(m) = mgmt.get(&d.mgmt_key()) {
                if d.version.is_none() {
                    d.version.clone_from(&m.version);
                }
                if d.scope.is_none() {
                    d.scope.clone_from(&m.scope);
                }
                if d.exclusions.is_empty() {
                    d.exclusions.clone_from(&m.exclusions);
                }
            }
            // Maven identifies a dependency by group, artifact, type and classifier: a
            // `test-jar` of an artifact is a different dependency from its jar.
            deps.retain(|x| x.mgmt_key() != d.mgmt_key());
            deps.push(d);
        }
        Ok(Effective {
            group,
            artifact: raw.artifact,
            deps,
            mgmt,
            modules: raw.modules,
            props,
        })
    }

    fn interp_dep(&mut self, d: &Dep, props: &BTreeMap<String, String>) -> Dep {
        let mut d = d.clone();
        d.group = interpolate(&d.group, props, &mut self.missing);
        d.artifact = interpolate(&d.artifact, props, &mut self.missing);
        d.version = d.version.map(|v| interpolate(&v, props, &mut self.missing));
        d.scope = d.scope.map(|v| interpolate(&v, props, &mut self.missing));
        d.kind = d.kind.map(|v| interpolate(&v, props, &mut self.missing));
        d.classifier = d
            .classifier
            .map(|v| interpolate(&v, props, &mut self.missing));
        d
    }

    /// The effective model of a repository POM, cached; `None` (recorded as missing) when
    /// it is not available.
    fn remote(&mut self, g: &str, a: &str, v: &str, depth: usize) -> Option<Effective> {
        let key = (g.to_string(), a.to_string(), v.to_string());
        if let Some(hit) = self.cache.get(&key) {
            return hit.clone();
        }
        // Guard against cycles while this POM is being built.
        self.cache.insert(key.clone(), None);
        let result = match self.source.pom(g, a, v) {
            Some(xml) => match self.effective(&xml, None, depth) {
                Ok(eff) => Some(eff),
                Err(e) => {
                    self.missing.insert(format!("{g}:{a}:{v}: {e}"));
                    None
                }
            },
            None => {
                self.missing
                    .insert(format!("{g}:{a}:{v}: POM not available"));
                None
            }
        };
        self.cache.insert(key, result.clone());
        result
    }

    /// A concrete version for a declared one: as is, or the highest listed match of a range.
    fn pick_version(&mut self, g: &str, a: &str, declared: &str) -> Option<String> {
        let declared = declared.trim();
        if !declared.starts_with(['[', '(']) {
            return Some(declared.to_string());
        }
        let ranges = parse_ranges(declared)?;
        let listed = self
            .source
            .metadata(g, a)
            .map(|xml| metadata_versions(&xml));
        let Some(listed) = listed else {
            self.missing.insert(format!(
                "{g}:{a}: range {declared} needs maven-metadata.xml"
            ));
            return None;
        };
        let best = listed
            .into_iter()
            .filter(|v| ranges.iter().any(|r| r.contains(v)))
            .filter_map(|v| parse_maven_version(&v).map(|p| (p, v)))
            .max_by(|x, y| x.0.cmp(&y.0))
            .map(|(_, v)| v);
        if best.is_none() {
            self.missing
                .insert(format!("{g}:{a}: no published version matches {declared}"));
        }
        best
    }
}

/// Substitute `${name}` (repeatedly, bounded); an undefined property is recorded and left.
fn interpolate(
    s: &str,
    props: &BTreeMap<String, String>,
    missing: &mut BTreeSet<String>,
) -> String {
    let mut out = s.to_string();
    for _ in 0..10 {
        let Some(start) = out.find("${") else {
            return out;
        };
        let Some(end) = out[start..].find('}') else {
            return out;
        };
        let name = &out[start + 2..start + end];
        let Some(value) = props.get(name) else {
            missing.insert(format!("property ${{{name}}} is not defined"));
            return out;
        };
        out = format!("{}{}{}", &out[..start], value, &out[start + end + 1..]);
    }
    out
}

/// One `[a,b)` style interval; `None` bounds are open.
struct Interval {
    low: Option<(String, bool)>,
    high: Option<(String, bool)>,
}

impl Interval {
    fn contains(&self, v: &str) -> bool {
        let Some(pv) = parse_maven_version(v) else {
            return false;
        };
        let ok_low = self.low.as_ref().is_none_or(|(b, incl)| {
            parse_maven_version(b).is_some_and(|bv| if *incl { pv >= bv } else { pv > bv })
        });
        let ok_high = self.high.as_ref().is_none_or(|(b, incl)| {
            parse_maven_version(b).is_some_and(|bv| if *incl { pv <= bv } else { pv < bv })
        });
        ok_low && ok_high
    }
}

/// Parse `[1.0,2.0)`, `[1.5,)`, `(,1.0]`, `[1.2]` and unions of them.
fn parse_ranges(spec: &str) -> Option<Vec<Interval>> {
    let mut out = Vec::new();
    let mut rest = spec.trim();
    while !rest.is_empty() {
        let open = rest.chars().next()?;
        if !matches!(open, '[' | '(') {
            return None;
        }
        let close_at = rest.find([']', ')'])?;
        let close = rest[close_at..].chars().next()?;
        let body = &rest[1..close_at];
        let bound = |s: &str, incl: bool| {
            let s = s.trim();
            (!s.is_empty()).then(|| (s.to_string(), incl))
        };
        let interval = match body.split_once(',') {
            Some((lo, hi)) => Interval {
                low: bound(lo, open == '['),
                high: bound(hi, close == ']'),
            },
            None => Interval {
                low: bound(body, true),
                high: bound(body, true),
            },
        };
        out.push(interval);
        rest = rest[close_at + 1..].trim_start_matches(',').trim();
    }
    (!out.is_empty()).then_some(out)
}

fn metadata_versions(xml: &str) -> Vec<String> {
    let Ok(doc) = Document::parse(xml) else {
        return Vec::new();
    };
    doc.descendants()
        .filter(|n| {
            n.tag_name().name() == "version"
                && n.parent()
                    .is_some_and(|p| p.tag_name().name() == "versions")
        })
        .filter_map(|n| n.text().map(|t| t.trim().to_string()))
        .collect()
}

/// Maven's scope of a transitive dependency (`child`) reached through one in `parent`
/// scope; `None` when it is not on any classpath.
fn propagate(parent: &str, child: &str) -> Option<&'static str> {
    match (parent, child) {
        (_, "test" | "provided" | "system" | "import") => None,
        ("compile", "compile") => Some("compile"),
        ("compile", "runtime") | ("runtime", "compile" | "runtime") => Some("runtime"),
        ("provided", "compile" | "runtime") => Some("provided"),
        ("test", "compile" | "runtime") => Some("test"),
        _ => None,
    }
}

/// How broad a scope is, for Maven's widening when one artifact is reached by several paths.
fn scope_rank(scope: &str) -> u8 {
    match scope {
        "compile" => 4,
        "runtime" => 3,
        "provided" => 2,
        "test" => 1,
        _ => 0,
    }
}

/// (dependency, depth, parent node, scope, inherited exclusions, root module index)
type Queue = VecDeque<(Dep, usize, String, String, Vec<(String, String)>, usize)>;

/// Queue an artifact's own dependencies in the scope they inherit (Maven's table): optional
/// and excluded ones are left out; a dependency's own test and provided dependencies are on
/// no classpath.
fn enqueue_children(
    eff: &Effective,
    scope: &str,
    exclusions: &[(String, String)],
    depth: usize,
    name: &str,
    root_ix: usize,
    queue: &mut Queue,
) {
    for child in &eff.deps {
        if child.optional {
            continue;
        }
        let child_scope = child.scope.clone().unwrap_or_else(|| "compile".into());
        let Some(next_scope) = propagate(scope, &child_scope) else {
            continue;
        };
        let excluded = exclusions
            .iter()
            .any(|(g, a)| (g == "*" || *g == child.group) && (a == "*" || *a == child.artifact));
        if excluded {
            continue;
        }
        let mut ex = exclusions.to_vec();
        ex.extend(child.exclusions.iter().cloned());
        queue.push_back((
            child.clone(),
            depth + 1,
            name.to_string(),
            next_scope.to_string(),
            ex,
            root_ix,
        ));
    }
}

/// Resolve the project in `dir` (its `pom.xml` and any `<modules>`).
///
/// # Errors
///
/// When `dir/pom.xml` cannot be read or parsed: failing closed.
pub fn resolve(dir: &Path, source: &dyn PomSource) -> Result<Resolution, String> {
    const ROOT: &str = "(root)";
    let mut r = Resolver {
        source,
        cache: BTreeMap::new(),
        missing: BTreeSet::new(),
    };
    // The reactor: the root POM and every module below it, from local files.
    let mut modules: Vec<Effective> = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    let mut seen_dirs = BTreeSet::new();
    while let Some(d) = stack.pop() {
        if !seen_dirs.insert(d.clone()) || seen_dirs.len() > 500 {
            continue;
        }
        let path = d.join("pom.xml");
        let xml = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let eff = r
            .effective(&xml, Some(&d), 0)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        for m in eff.modules.iter().rev() {
            stack.push(d.join(m));
        }
        modules.push(eff);
    }
    let local: BTreeMap<(String, String), Effective> = modules
        .iter()
        .map(|m| ((m.group.clone(), m.artifact.clone()), m.clone()))
        .collect();

    let mut graph = DepGraph::new(ROOT);
    // Mediation is per group, artifact, type and classifier, as in Maven.
    let mut selected: BTreeMap<(String, String, String, String), ResolvedDep> = BTreeMap::new();
    let mut order: Vec<(String, String, String, String)> = Vec::new();
    // (dependency, depth, parent node, scope, inherited exclusions, root management)
    let mut queue: Queue = VecDeque::new();
    for (i, m) in modules.iter().enumerate() {
        for d in &m.deps {
            if local.contains_key(&d.key()) {
                // A sibling module: its own dependencies are the project's.
                continue;
            }
            let scope = d.scope.clone().unwrap_or_else(|| "compile".into());
            if matches!(scope.as_str(), "system" | "import") {
                continue;
            }
            queue.push_back((
                d.clone(),
                0,
                ROOT.to_string(),
                scope,
                d.exclusions.clone(),
                i,
            ));
        }
    }
    while let Some((dep, depth, parent, scope, exclusions, root_ix)) = queue.pop_front() {
        let key = dep.mgmt_key();
        let name = format!("{}:{}", dep.group, dep.artifact);
        graph.add_edges(&parent, [name.clone()]);
        if let Some(existing) = selected.get_mut(&key) {
            // Nearest wins for the version; the scope widens to the broadest path
            // (compile > runtime > provided > test), and a widened artifact's own
            // dependencies are followed again in the wider scope.
            if !existing.direct && scope_rank(&scope) > scope_rank(&existing.scope) {
                existing.scope.clone_from(&scope);
                existing.dev = matches!(scope.as_str(), "test" | "provided");
                let version = existing.version.clone();
                let eff = match local.get(&dep.key()) {
                    Some(m) => Some(m.clone()),
                    None => r.remote(&dep.group, &dep.artifact, &version, 0),
                };
                if let Some(eff) = eff {
                    enqueue_children(&eff, &scope, &exclusions, depth, &name, root_ix, &mut queue);
                }
            }
            continue;
        }
        // The root's management sets transitive versions and scopes.
        let managed = (depth > 0)
            .then(|| modules[root_ix].mgmt.get(&dep.mgmt_key()))
            .flatten();
        let declared = managed
            .and_then(|m| m.version.clone())
            .or(dep.version.clone());
        let Some(declared) = declared else {
            r.missing
                .insert(format!("{name}: no version (not managed)"));
            continue;
        };
        let scope = match managed.and_then(|m| m.scope.clone()) {
            Some(s) if depth > 0 && s != "import" => s,
            _ => scope,
        };
        let Some(version) = r.pick_version(&dep.group, &dep.artifact, &declared) else {
            continue;
        };
        selected.insert(
            key.clone(),
            ResolvedDep {
                name: name.clone(),
                version: version.clone(),
                direct: depth == 0,
                dev: matches!(scope.as_str(), "test" | "provided"),
                scope: scope.clone(),
            },
        );
        order.push(key);
        let eff = match local.get(&dep.key()) {
            Some(m) => Some(m.clone()),
            None => r.remote(&dep.group, &dep.artifact, &version, 0),
        };
        let Some(eff) = eff else { continue };
        enqueue_children(&eff, &scope, &exclusions, depth, &name, root_ix, &mut queue);
    }
    Ok(Resolution {
        packages: order
            .into_iter()
            .filter_map(|k| selected.remove(&k))
            .collect(),
        graph,
        missing: r.missing.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// POMs in memory, keyed `g:a:v`.
    struct Mem(BTreeMap<String, String>);

    impl PomSource for Mem {
        fn pom(&self, g: &str, a: &str, v: &str) -> Option<String> {
            self.0.get(&format!("{g}:{a}:{v}")).cloned()
        }
        fn metadata(&self, g: &str, a: &str) -> Option<String> {
            self.0.get(&format!("{g}:{a}:metadata")).cloned()
        }
    }

    fn pom(g: &str, a: &str, v: &str, body: &str) -> String {
        format!("<project><modelVersion>4.0.0</modelVersion><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version>{body}</project>")
    }

    fn dep(g: &str, a: &str, v: &str, extra: &str) -> String {
        format!("<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version>{extra}</dependency>")
    }

    fn project(dir_name: &str, body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fr-mvn-{dir_name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pom.xml"), pom("com.acme", "app", "1.0", body)).unwrap();
        dir
    }

    fn rows(r: &Resolution) -> Vec<(String, String, bool, bool)> {
        r.packages
            .iter()
            .map(|p| (p.name.clone(), p.version.clone(), p.direct, p.dev))
            .collect()
    }

    #[test]
    fn nearest_wins_exclusions_optional_and_scopes() {
        let repo = Mem(BTreeMap::from([
            (
                "g:a:1".to_string(),
                pom(
                    "g",
                    "a",
                    "1",
                    &format!(
                        "<dependencies>{}{}{}</dependencies>",
                        dep("g", "c", "2", ""),
                        dep("g", "opt", "1", "<optional>true</optional>"),
                        dep("g", "t", "1", "<scope>test</scope>")
                    ),
                ),
            ),
            (
                "g:b:1".to_string(),
                pom(
                    "g",
                    "b",
                    "1",
                    &format!(
                        "<dependencies>{}{}</dependencies>",
                        dep("g", "c", "3", ""),
                        dep("g", "gone", "1", "")
                    ),
                ),
            ),
            ("g:c:2".to_string(), pom("g", "c", "2", "")),
            ("g:c:3".to_string(), pom("g", "c", "3", "")),
            ("g:junit:4".to_string(), pom("g", "junit", "4", "")),
        ]));
        let dir = project(
            "nearest",
            &format!(
                "<dependencies>{}{}{}</dependencies>",
                dep("g", "a", "1", ""),
                dep("g", "b", "1", "<exclusions><exclusion><groupId>g</groupId><artifactId>gone</artifactId></exclusion></exclusions>"),
                dep("g", "junit", "4", "<scope>test</scope>")
            ),
        );
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(
            rows(&r),
            vec![
                ("g:a".into(), "1".into(), true, false),
                ("g:b".into(), "1".into(), true, false),
                ("g:junit".into(), "4".into(), true, true),
                // c at depth 1 through a (declared first) wins over b's c:3.
                ("g:c".into(), "2".into(), false, false),
            ]
        );
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(r.graph.chain_to("g:c"), vec!["(root)", "g:a", "g:c"]);
    }

    #[test]
    fn parent_properties_management_and_bom_imports() {
        let repo = Mem(BTreeMap::from([
            (
                "com.acme:parent:5".to_string(),
                pom("com.acme", "parent", "5", &format!(
                    "<properties><lib.version>2.17.1</lib.version></properties>\
                     <dependencyManagement><dependencies>{}{}</dependencies></dependencyManagement>",
                    dep("org.apache.logging.log4j", "log4j-core", "${lib.version}", ""),
                    dep("org.bom", "bom", "1", "<type>pom</type><scope>import</scope>"))),
            ),
            ("org.bom:bom:1".to_string(), pom("org.bom", "bom", "1", &format!(
                "<dependencyManagement><dependencies>{}{}</dependencies></dependencyManagement>",
                dep("com.fasterxml.jackson.core", "jackson-databind", "2.9.8", ""),
                dep("org.apache.logging.log4j", "log4j-core", "2.0", "")))),
            ("org.apache.logging.log4j:log4j-core:2.17.1".to_string(), pom("org.apache.logging.log4j", "log4j-core", "2.17.1", "")),
            ("com.fasterxml.jackson.core:jackson-databind:2.9.8".to_string(), pom("com.fasterxml.jackson.core", "jackson-databind", "2.9.8", "")),
        ]));
        let dir = std::env::temp_dir().join(format!("fr-mvn-parent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("pom.xml"),
            "<project><parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>5</version><relativePath/></parent>\
             <artifactId>app</artifactId><dependencies>\
             <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId></dependency>\
             <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId></dependency>\
             </dependencies></project>",
        )
        .unwrap();
        let r = resolve(&dir, &repo).unwrap();
        // The parent's own management (from a property) wins over the BOM's.
        assert_eq!(
            rows(&r),
            vec![
                (
                    "org.apache.logging.log4j:log4j-core".into(),
                    "2.17.1".into(),
                    true,
                    false
                ),
                (
                    "com.fasterxml.jackson.core:jackson-databind".into(),
                    "2.9.8".into(),
                    true,
                    false
                ),
            ]
        );
    }

    #[test]
    fn a_test_jar_does_not_replace_the_jar_of_the_same_artifact() {
        let repo = Mem(BTreeMap::from([
            (
                "g:core:1".to_string(),
                pom(
                    "g",
                    "core",
                    "1",
                    &format!(
                        "<dependencies>{}{}</dependencies>",
                        dep("g", "api", "1", ""),
                        dep("g", "api", "1", "<type>test-jar</type><scope>test</scope>")
                    ),
                ),
            ),
            ("g:api:1".to_string(), pom("g", "api", "1", "")),
        ]));
        let dir = project(
            "testjar",
            &format!("<dependencies>{}</dependencies>", dep("g", "core", "1", "")),
        );
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(rows(&r)[1], ("g:api".into(), "1".into(), false, false));
    }

    #[test]
    fn root_management_overrides_transitive_versions() {
        let repo = Mem(BTreeMap::from([
            (
                "g:a:1".to_string(),
                pom(
                    "g",
                    "a",
                    "1",
                    &format!("<dependencies>{}</dependencies>", dep("g", "c", "1.0", "")),
                ),
            ),
            ("g:c:1.5".to_string(), pom("g", "c", "1.5", "")),
        ]));
        let dir = project("mgmt", &format!(
            "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement><dependencies>{}</dependencies>",
            dep("g", "c", "1.5", ""), dep("g", "a", "1", "")));
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(rows(&r)[1], ("g:c".into(), "1.5".into(), false, false));
    }

    #[test]
    fn ranges_and_missing_poms_are_handled_honestly() {
        let repo = Mem(BTreeMap::from([
            ("g:r:metadata".to_string(), "<metadata><versioning><versions><version>1.0</version><version>1.9</version><version>2.0</version></versions></versioning></metadata>".to_string()),
            ("g:r:1.9".to_string(), pom("g", "r", "1.9", "")),
        ]));
        let dir = project(
            "ranges",
            &format!(
                "<dependencies>{}{}{}</dependencies>",
                dep("g", "r", "[1.0,2.0)", ""),
                dep("g", "absent", "1", ""),
                dep("g", "p", "${undefined.prop}", "")
            ),
        );
        let r = resolve(&dir, &repo).unwrap();
        assert_eq!(rows(&r)[0], ("g:r".into(), "1.9".into(), true, false));
        assert!(
            r.missing
                .iter()
                .any(|m| m.contains("g:absent:1: POM not available")),
            "{:?}",
            r.missing
        );
        assert!(
            r.missing.iter().any(|m| m.contains("${undefined.prop}")),
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn range_syntax() {
        let r = parse_ranges("[1.0,2.0)").unwrap();
        assert!(r[0].contains("1.5") && r[0].contains("1.0") && !r[0].contains("2.0"));
        let r = parse_ranges("(,1.0],[1.2,)").unwrap();
        assert!(r.iter().any(|i| i.contains("0.9")) && !r.iter().any(|i| i.contains("1.1")));
        assert!(parse_ranges("[1.5]").unwrap()[0].contains("1.5"));
        assert_eq!(propagate("compile", "runtime"), Some("runtime"));
        assert_eq!(propagate("compile", "test"), None);
        assert_eq!(propagate("test", "compile"), Some("test"));
    }
}
