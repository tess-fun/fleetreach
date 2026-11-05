//! Dev and build-only scope for ecosystems whose lockfile does not record it. The manifest
//! says which direct dependencies are development-only; a package is `dev` when it sits under
//! one of those and no runtime root reaches it.
//!
//! Fail-closed: `dev` can take a finding out of a gate, so it needs positive evidence. A
//! dependency declared in a way this cannot read, a missing manifest or a member that cannot
//! be found all leave the package at runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fleetreach_core::inventory::SourceInventory;
use fleetreach_core::{DepGraph, DepScope, Ecosystem, Occurrence, VulnFinding};
use walkdir::WalkDir;

/// Which of a unit's packages are dev-only.
#[derive(Debug, Default, PartialEq, Eq)]
pub enum DevSet {
    #[default]
    None,
    /// A test project: nothing in it ships.
    All,
    Names(BTreeSet<String>),
    /// Cargo.lock can hold one name at several versions.
    Versions(BTreeSet<(String, String)>),
}

impl DevSet {
    fn holds(&self, ecosystem: Ecosystem, package: &str, version: &str) -> bool {
        match self {
            DevSet::None => false,
            DevSet::All => true,
            DevSet::Names(names) if ecosystem == Ecosystem::NuGet => {
                names.contains(&package.to_ascii_lowercase())
            }
            DevSet::Names(names) => names.contains(package),
            DevSet::Versions(set) => set.contains(&(package.to_string(), version.to_string())),
        }
    }

    /// Sets the scope of `occurrences` this covers.
    fn mark<'a>(
        &self,
        ecosystem: Ecosystem,
        occurrences: impl Iterator<Item = &'a mut Occurrence>,
    ) {
        for occurrence in occurrences {
            if let Occurrence::InRepo {
                package,
                installed,
                scope,
                ..
            } = occurrence
            {
                if self.holds(ecosystem, package, &installed.to_string()) {
                    *scope = DepScope::Dev;
                }
            }
        }
    }
}

/// Marks the findings of the unit at `dir`.
pub fn mark(ecosystem: Ecosystem, dir: &Path, findings: &mut [VulnFinding]) {
    if findings.is_empty() {
        return;
    }
    dev_packages(ecosystem, dir).mark(
        ecosystem,
        findings.iter_mut().flat_map(|f| f.occurrences.iter_mut()),
    );
}

/// Marks a Cargo scan of `lockfile`.
pub fn mark_cargo(lockfile: &Path, scan: &mut fleetreach_scan::RepoScan) {
    if scan.vulnerabilities.is_empty() && scan.warnings.is_empty() {
        return;
    }
    let vulns = scan.vulnerabilities.iter_mut();
    let warnings = scan.warnings.iter_mut();
    cargo(lockfile).mark(
        Ecosystem::Cargo,
        vulns
            .flat_map(|f| f.occurrences.iter_mut())
            .chain(warnings.flat_map(|f| f.occurrences.iter_mut())),
    );
}

/// Marks the packages of the unit at `dir` in an SBOM source.
pub fn mark_inventory(ecosystem: Ecosystem, dir: &Path, source: &mut SourceInventory) {
    let set = match ecosystem {
        Ecosystem::Cargo => cargo(&dir.join(&source.source)),
        _ => dev_packages(ecosystem, dir),
    };
    for package in &mut source.packages {
        if set.holds(ecosystem, &package.name, &package.version) {
            package.dev = true;
        }
    }
}

fn dev_packages(ecosystem: Ecosystem, dir: &Path) -> DevSet {
    match ecosystem {
        Ecosystem::RubyGems => gems(dir),
        Ecosystem::Hex => hex(dir),
        Ecosystem::NuGet => nuget(dir),
        Ecosystem::Go => go(dir),
        _ => DevSet::None,
    }
}

type Edges = BTreeMap<String, BTreeSet<String>>;

fn edges_of(graph: &DepGraph) -> Edges {
    let mut edges = Edges::new();
    for (from, to) in graph.edges() {
        edges
            .entry(from.to_string())
            .or_default()
            .insert(to.to_string());
    }
    edges
}

fn closure(edges: &Edges, roots: impl IntoIterator<Item = String>) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut todo: Vec<String> = roots.into_iter().collect();
    while let Some(name) = todo.pop() {
        if let Some(next) = edges.get(&name).filter(|_| !seen.contains(&name)) {
            todo.extend(next.iter().cloned());
        }
        seen.insert(name);
    }
    seen
}

/// What sits under `dev` and under no other direct dependency of `graph`, nor under `runtime`.
fn under_dev_only(graph: &DepGraph, dev: BTreeSet<String>, runtime: &BTreeSet<String>) -> DevSet {
    let edges = edges_of(graph);
    let dev: BTreeSet<String> = dev.difference(runtime).cloned().collect();
    if dev.is_empty() {
        return DevSet::None;
    }
    let root = graph.root().to_string();
    let roots = edges
        .get(&root)
        .into_iter()
        .flatten()
        .chain(runtime)
        .filter(|name| !dev.contains(*name))
        .cloned();
    let shipped = closure(&edges, roots);
    DevSet::Names(closure(&edges, dev).difference(&shipped).cloned().collect())
}

/// `Gemfile` declarations: the gems whose every group is `development` or `test`, and the rest.
fn gemfile_groups(text: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    const DEV: [&str; 2] = ["development", "test"];
    let atoms = |text: &str| -> Vec<String> {
        text.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
            .filter_map(|t| t.strip_prefix(':'))
            .map(str::to_string)
            .collect()
    };
    // The value of `group:` or `groups:` in a `gem` line, in either hash spelling.
    let inline = |line: &str| -> Vec<String> {
        let spelled = [
            "groups:",
            "group:",
            ":groups =>",
            ":group =>",
            ":groups=>",
            ":group=>",
        ];
        spelled
            .iter()
            .find_map(|key| line.find(key).map(|i| &line[i + key.len()..]))
            .map(|rest| {
                let end = match rest.trim_start().starts_with('[') {
                    true => rest.find(']').unwrap_or(rest.len()),
                    false => rest.find(',').unwrap_or(rest.len()),
                };
                atoms(&rest[..end])
            })
            .unwrap_or_default()
    };
    let mut dev = BTreeSet::new();
    let mut runtime = BTreeSet::new();
    let mut stack: Vec<Vec<String>> = Vec::new();
    let mut logical = String::new();
    for raw in text.lines() {
        let code = raw.split(" #").next().unwrap_or("");
        let code = code.trim();
        if code.starts_with('#') {
            continue;
        }
        logical.push_str(code);
        if code.ends_with(',') {
            logical.push(' ');
            continue;
        }
        let line = std::mem::take(&mut logical);
        let head = line.split_whitespace().next().unwrap_or("");
        if head == "end" {
            stack.pop();
        } else if head == "group" || line.starts_with("group(") {
            let names = line.split(" do").next().unwrap_or("");
            let names = names.split("optional").next().unwrap_or(names);
            stack.push(atoms(names));
        } else if head == "gem" || line.starts_with("gem(") {
            let Some(name) = line.split(['"', '\'']).nth(1) else {
                continue;
            };
            let mut groups: Vec<String> = stack.iter().flatten().cloned().collect();
            groups.extend(inline(&line));
            let only_dev = !groups.is_empty() && groups.iter().all(|g| DEV.contains(&g.as_str()));
            (if only_dev { &mut dev } else { &mut runtime }).insert(name.to_string());
            if line.ends_with(" do") {
                stack.push(Vec::new());
            }
        } else if matches!(head, "if" | "unless" | "case" | "begin" | "while")
            || line.ends_with(" do")
            || line.contains(" do |")
        {
            stack.push(Vec::new());
        }
    }
    (dev, runtime)
}

fn gems(dir: &Path) -> DevSet {
    let read = |name: &str| fleetreach_core::repofile::read_to_string(dir.join(name)).ok();
    let (Some(lock), Some(gemfile)) = (read("Gemfile.lock"), read("Gemfile")) else {
        return DevSet::None;
    };
    let (dev, runtime) = gemfile_groups(&gemfile);
    under_dev_only(&fleetreach_rubygems::dependency_graph(&lock), dev, &runtime)
}

/// The deps a `mix.exs` declares.
#[derive(Debug, Default)]
struct MixDeps {
    /// Their `only:` leaves out `:prod`.
    dev: BTreeSet<String>,
    runtime: BTreeSet<String>,
    /// Literal `path:` values.
    paths: Vec<String>,
    /// A `path:` whose value is not a literal.
    computed_path: bool,
}

fn mix_deps(text: &str, out: &mut MixDeps) {
    let code: String = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    for (start, _) in code.match_indices("{:") {
        let rest = &code[start + 2..];
        let end_name = rest
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let name = &rest[..end_name];
        let mut depth = 1;
        let mut close = rest.len();
        for (i, c) in rest.char_indices() {
            match c {
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                _ => {}
            }
            if depth == 0 {
                close = i;
                break;
            }
        }
        let tuple = &rest[..close];
        let envs = tuple.find("only:").map(|i| {
            let value = tuple[i + 5..].trim_start();
            match value.strip_prefix('[') {
                Some(list) => list.split(']').next().unwrap_or("").to_string(),
                None => value.split(',').next().unwrap_or("").to_string(),
            }
        });
        let only_dev = envs.is_some_and(|envs| {
            let atoms: Vec<&str> = envs
                .split(',')
                .map(str::trim)
                .filter(|a| !a.is_empty())
                .collect();
            !atoms.is_empty()
                && atoms
                    .iter()
                    .all(|a| a.starts_with(':') && a.len() > 1 && *a != ":prod")
        });
        let into = if only_dev {
            &mut out.dev
        } else {
            &mut out.runtime
        };
        into.insert(name.to_string());
        if let Some(i) = tuple.find("path:") {
            match tuple[i + 5..].trim_start().strip_prefix('"') {
                Some(value) => out
                    .paths
                    .push(value.split('"').next().unwrap_or("").to_string()),
                None => out.computed_path = true,
            }
        }
    }
}

/// The names `mix.lock` holds as git checkouts.
fn mix_git_deps(lock: &str) -> BTreeSet<String> {
    let entries = lock.lines().filter(|line| line.contains(": {:git,"));
    let names = entries.filter_map(|line| line.split('"').nth(1));
    names.map(str::to_string).collect()
}

/// `mix.lock` lists no dependencies for a git dep, and a path dep may sit out of reach. With
/// one of those shipping, anything could sit under it, except what `mix.exs` itself declares
/// dev-only: Mix refuses a child that needs such a dep in another environment.
fn hex(dir: &Path) -> DevSet {
    let Ok(lock) = fleetreach_core::repofile::read_to_string(dir.join("mix.lock")) else {
        return DevSet::None;
    };
    let mut todo = vec![dir.join("mix.exs")];
    let apps = std::fs::read_dir(dir.join("apps")).into_iter().flatten();
    todo.extend(apps.flatten().map(|app| app.path().join("mix.exs")));
    let mut seen = BTreeSet::new();
    let mut deps = MixDeps::default();
    let mut unread = false;
    while let Some(manifest) = todo.pop() {
        let Some(parent) = manifest.parent().map(Path::to_path_buf) else {
            continue;
        };
        if !seen.insert(manifest.clone()) {
            continue;
        }
        let Ok(text) = fleetreach_core::repofile::read_to_string(&manifest) else {
            // `apps/` can hold other files; a path dep cannot be left unread.
            unread |= !parent.starts_with(dir.join("apps"));
            continue;
        };
        let start = deps.paths.len();
        mix_deps(&text, &mut deps);
        for path in deps.paths.split_off(start) {
            if !Path::new(&path).is_absolute() && lexically_under(dir, &parent, &path) {
                todo.push(parent.join(path).join("mix.exs"));
            } else {
                unread = true;
            }
        }
    }
    if dir.join("mix.exs").is_file() {
        let MixDeps {
            dev,
            runtime,
            computed_path,
            ..
        } = deps;
        let git = mix_git_deps(&lock);
        if unread || computed_path || git.iter().any(|name| !dev.contains(name)) {
            let declared: BTreeSet<String> = dev.difference(&runtime).cloned().collect();
            return DevSet::Names(declared);
        }
        let (_, graph) = fleetreach_hex::installed_packages(&lock);
        return under_dev_only(&graph, dev, &runtime);
    }
    DevSet::None
}

fn nuget(dir: &Path) -> DevSet {
    let build_only = fleetreach_nuget::build_only(dir);
    if build_only.test_project {
        return DevSet::All;
    }
    if build_only.packages.is_empty() {
        return DevSet::None;
    }
    let Some(graph) = fleetreach_nuget::dependency_graph(dir) else {
        return DevSet::None;
    };
    // The graph spells names as the lockfile does; the sets here are lower case.
    let mut lower = DepGraph::new(graph.root().to_string());
    for (from, to) in graph.edges() {
        let from = if from == graph.root() {
            from.to_string()
        } else {
            from.to_ascii_lowercase()
        };
        lower.add_edges(&from, [to.to_ascii_lowercase()]);
    }
    match under_dev_only(&lower, build_only.packages.clone(), &BTreeSet::new()) {
        // A package with no node in the graph is still the one the project excluded.
        DevSet::Names(mut names) => {
            names.extend(build_only.packages);
            DevSet::Names(names)
        }
        _ => DevSet::Names(build_only.packages),
    }
}

/// The import paths of a Go source file, from its header.
fn go_imports(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    let mut in_comment = false;
    let quoted = |line: &str| line.split('"').nth(1).map(str::to_string);
    for raw in text.lines() {
        let line = raw.trim();
        if in_comment {
            in_comment = !line.contains("*/");
            continue;
        }
        if line.starts_with("/*") {
            in_comment = !line.contains("*/");
            continue;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if in_block {
            if line.starts_with(')') {
                in_block = false;
            } else {
                out.extend(quoted(line));
            }
        } else if line.starts_with("package ") {
            continue;
        } else if let Some(rest) = line.strip_prefix("import") {
            if rest.trim_start().starts_with('(') {
                in_block = !rest.contains(')');
            } else {
                out.extend(quoted(rest));
            }
        } else {
            break;
        }
    }
    out
}

/// What a `go.mod` says about the modules of a build.
#[derive(Debug, Default, PartialEq, Eq)]
struct GoMod {
    /// The `go` directive as (major, minor).
    go: (u32, u32),
    /// Required modules and their versions.
    requires: BTreeMap<String, String>,
    /// `replace` targets: a module and version, or a local path with no version.
    replaces: BTreeMap<String, (String, Option<String>)>,
}

fn go_mod(text: &str) -> GoMod {
    let mut out = GoMod::default();
    let mut block = "";
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if !block.is_empty() && line.starts_with(')') {
            block = "";
            continue;
        }
        let (kind, entry) = match line.split_once(char::is_whitespace) {
            _ if !block.is_empty() => (block, line),
            Some((kind, rest)) if rest.trim() == "(" => {
                block = if kind == "require" {
                    "require"
                } else {
                    "replace"
                };
                if !matches!(kind, "require" | "replace") {
                    block = "other";
                }
                continue;
            }
            Some(split) => (split.0, split.1.trim()),
            None => continue,
        };
        let words: Vec<&str> = entry
            .split_whitespace()
            .map(|w| w.trim_matches('"'))
            .collect();
        match (kind, words.as_slice()) {
            ("go", [version, ..]) => {
                let mut parts = version.split('.').map(|p| p.parse().unwrap_or(0));
                out.go = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
            }
            ("require", [path, version, ..]) => {
                out.requires.insert(path.to_string(), version.to_string());
            }
            ("replace", [path, rest @ ..]) => {
                let target = rest.iter().position(|w| *w == "=>").map(|i| &rest[i + 1..]);
                if let Some([to, version @ ..]) = target {
                    let version = version.first().map(|v| v.to_string());
                    out.replaces
                        .insert(path.to_string(), (to.to_string(), version));
                }
            }
            _ => {}
        }
    }
    out
}

/// A path as the module cache spells it: capitals become `!` and the lower-case letter.
pub(crate) fn cache_escaped(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn go_mod_cache() -> Option<PathBuf> {
    let set = |name: &str| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if let Some(cache) = set("GOMODCACHE") {
        return Some(cache);
    }
    let gopath = set("GOPATH")
        .and_then(|paths| std::env::split_paths(&paths).next())
        .or_else(|| set("HOME").map(|home| home.join("go")));
    gopath.map(|path| path.join("pkg").join("mod"))
}

/// Finds the source of the packages a build imports: `vendor/`, else the module cache.
struct GoSource<'a> {
    dir: &'a Path,
    module: &'a GoMod,
    vendored: bool,
    cache: Option<PathBuf>,
}

impl GoSource<'_> {
    /// The required module that provides `import`.
    fn module_of(&self, import: &str) -> Option<&str> {
        let provides = |m: &&String| {
            import
                .strip_prefix(m.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        };
        let modules = self.module.requires.keys().filter(provides);
        modules.max_by_key(|m| m.len()).map(String::as_str)
    }

    fn package_dir(&self, module: &str, import: &str) -> Option<PathBuf> {
        if self.vendored {
            return Some(self.dir.join("vendor").join(import));
        }
        let sub = import.strip_prefix(module)?.trim_start_matches('/');
        let required = self.module.requires.get(module)?;
        let (path, version) = match self.module.replaces.get(module) {
            Some((path, None)) => return Some(self.dir.join(path).join(sub)),
            Some((path, Some(version))) => (path.as_str(), version),
            None => (module, required),
        };
        let name = format!("{}@{}", cache_escaped(path), cache_escaped(version));
        Some(self.cache.as_ref()?.join(name).join(sub))
    }

    /// The modules a build of `roots` pulls in, through the source of every package, under all
    /// build tags. `None` when a package's source is not here. An import no required module
    /// provides is the standard library, or a file no build of this module compiles: the `go`
    /// directive below decides that `require` is the whole list.
    fn modules_under(&self, roots: &BTreeSet<String>) -> Option<BTreeSet<String>> {
        let mut modules = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut todo: Vec<String> = roots.iter().cloned().collect();
        while let Some(import) = todo.pop() {
            let Some(module) = self.module_of(&import) else {
                continue;
            };
            if !seen.insert(import.clone()) {
                continue;
            }
            modules.insert(module.to_string());
            for entry in std::fs::read_dir(self.package_dir(module, &import)?).ok()? {
                let path = entry.ok()?.path();
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
                let name = name.unwrap_or_default();
                if !name.ends_with(".go") || name.ends_with("_test.go") {
                    continue;
                }
                let source = fleetreach_core::repofile::read_to_string(&path).ok()?;
                let ignored = source
                    .lines()
                    .take_while(|l| !l.starts_with("package "))
                    .any(|l| l.starts_with("//go:build") && l.contains("ignore"));
                if !ignored {
                    todo.extend(go_imports(&source));
                }
            }
        }
        Some(modules)
    }
}

/// Modules only tests build. A module's own tests importing it proves nothing: a shipped
/// dependency can import it too, so this follows imports through the source of every package,
/// and leaves the repo at runtime when that source is not on this machine.
fn go(dir: &Path) -> DevSet {
    go_with_cache(dir, go_mod_cache())
}

fn go_with_cache(dir: &Path, cache: Option<PathBuf>) -> DevSet {
    let Ok(text) = fleetreach_core::repofile::read_to_string(dir.join("go.mod")) else {
        return DevSet::None;
    };
    let module = go_mod(&text);
    // Before 1.17 go.mod leaves out modules that only other modules need.
    if module.go < (1, 17) {
        return DevSet::None;
    }
    let (mut shipped, mut tests) = (BTreeSet::new(), BTreeSet::new());
    let mut shipped_files = 0usize;
    let walk = WalkDir::new(dir).into_iter().filter_entry(|e| {
        let name = e.file_name().to_string_lossy();
        e.depth() == 0
            || !e.file_type().is_dir()
            || !(name.starts_with(['.', '_'])
                || name == "vendor"
                || name == "testdata"
                || e.path().join("go.mod").is_file())
    });
    for entry in walk {
        let Ok(entry) = entry else {
            return DevSet::None;
        };
        let name = entry.file_name().to_string_lossy();
        if !entry.file_type().is_file() || !name.ends_with(".go") {
            continue;
        }
        let Ok(source) = fleetreach_core::repofile::read_to_string(entry.path()) else {
            return DevSet::None;
        };
        if name.ends_with("_test.go") {
            tests.extend(go_imports(&source));
        } else {
            shipped_files += 1;
            shipped.extend(go_imports(&source));
        }
    }
    // A `lockfiles` checkout has no sources, which says nothing about what imports what.
    if shipped_files == 0 {
        return DevSet::None;
    }
    let source = GoSource {
        dir,
        module: &module,
        vendored: dir.join("vendor/modules.txt").is_file(),
        cache,
    };
    match (source.modules_under(&shipped), source.modules_under(&tests)) {
        (Some(shipped), Some(tests)) => {
            let dev: BTreeSet<String> = tests.difference(&shipped).cloned().collect();
            if dev.is_empty() {
                DevSet::None
            } else {
                DevSet::Names(dev)
            }
        }
        _ => DevSet::None,
    }
}

/// A `Cargo.toml`: its package name and which names its normal dependencies have.
struct Member {
    name: String,
    normal: BTreeSet<String>,
}

fn read_toml(path: &Path) -> Option<toml::Value> {
    toml::from_str(&fleetreach_core::repofile::read_to_string(path).ok()?).ok()
}

fn table_names(table: Option<&toml::Value>, workspace: &toml::Value, into: &mut BTreeSet<String>) {
    let inherited = |key: &str| {
        workspace
            .get("workspace")
            .and_then(|w| w.get("dependencies"))
            .and_then(|d| d.get(key))
            .and_then(|d| d.get("package"))
            .and_then(toml::Value::as_str)
    };
    for (key, value) in table.and_then(toml::Value::as_table).into_iter().flatten() {
        let renamed = value.get("package").and_then(toml::Value::as_str);
        into.insert(renamed.or(inherited(key)).unwrap_or(key).to_string());
    }
}

fn member(manifest: &toml::Value, workspace: &toml::Value) -> Option<Member> {
    let name = manifest.get("package")?.get("name")?.as_str()?.to_string();
    let mut normal = BTreeSet::new();
    table_names(manifest.get("dependencies"), workspace, &mut normal);
    let targets = manifest.get("target").and_then(toml::Value::as_table);
    for target in targets.into_iter().flat_map(|t| t.values()) {
        table_names(target.get("dependencies"), workspace, &mut normal);
    }
    Some(Member { name, normal })
}

/// The `path` values of every dependency table in `manifest`.
fn path_deps(manifest: &toml::Value) -> Vec<&str> {
    let kinds = ["dependencies", "dev-dependencies", "build-dependencies"];
    let targets = manifest.get("target").and_then(toml::Value::as_table);
    let tables = std::iter::once(manifest)
        .chain(manifest.get("workspace"))
        .chain(targets.into_iter().flat_map(|t| t.values()));
    tables
        .flat_map(|table| kinds.iter().filter_map(|kind| table.get(*kind)))
        .filter_map(toml::Value::as_table)
        .flat_map(|deps| deps.values())
        .filter_map(|dep| dep.get("path").and_then(toml::Value::as_str))
        .collect()
}

/// The manifests of the workspace at `dir`: the root, its `members`, whose globs may have one
/// `*` as the last segment, and the path dependencies of all of these, which cargo counts as
/// members. `None` for a pattern this does not expand.
pub fn cargo_manifests(dir: &Path) -> Option<Vec<PathBuf>> {
    let mut found = BTreeSet::new();
    let mut todo = listed_manifests(dir)?;
    while let Some(path) = todo.pop() {
        if !found.insert(path.clone()) {
            continue;
        }
        let parent = path.parent()?;
        for dep in read_toml(&path).iter().flat_map(path_deps) {
            // Outside the lockfile's directory is outside what a scan may read.
            if !Path::new(dep).is_absolute() && lexically_under(dir, parent, dep) {
                todo.push(parent.join(dep).join("Cargo.toml"));
            }
        }
    }
    Some(found.into_iter().collect())
}

/// Whether `from/relative` stays inside `root`, going by its path alone.
fn lexically_under(root: &Path, from: &Path, relative: &str) -> bool {
    let Ok(inside) = from.strip_prefix(root) else {
        return false;
    };
    let mut depth = inside.components().count() as isize;
    for part in Path::new(relative).components() {
        match part {
            std::path::Component::ParentDir => depth -= 1,
            std::path::Component::Normal(_) => depth += 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    true
}

fn listed_manifests(dir: &Path) -> Option<Vec<PathBuf>> {
    let root = dir.join("Cargo.toml");
    let value = read_toml(&root)?;
    let mut out = vec![root];
    let members = value
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(toml::Value::as_array);
    for pattern in members.into_iter().flatten() {
        let pattern = pattern.as_str()?;
        match pattern.strip_suffix("/*") {
            Some(parent) if !parent.contains('*') => {
                let mut found: Vec<PathBuf> = std::fs::read_dir(dir.join(parent))
                    .ok()?
                    .flatten()
                    .map(|e| e.path().join("Cargo.toml"))
                    .filter(|p| p.is_file())
                    .collect();
                found.sort();
                out.extend(found);
            }
            None if !pattern.contains('*') => out.push(dir.join(pattern).join("Cargo.toml")),
            _ => return None,
        }
    }
    Some(out)
}

/// `name`, `name version` or `name version (source)` from a lockfile's `dependencies`.
fn lock_dep(text: &str) -> (&str, Option<&str>) {
    let mut parts = text.split_whitespace();
    (parts.next().unwrap_or(""), parts.next())
}

/// Packages `cargo tree -e normal` from the workspace does not reach. `Cargo.lock` keeps no
/// edge kinds, so past the workspace every edge counts, build dependencies of third-party
/// crates included.
fn cargo(lockfile: &Path) -> DevSet {
    cargo_dev(lockfile).map_or(DevSet::None, DevSet::Versions)
}

fn cargo_dev(lockfile: &Path) -> Option<BTreeSet<(String, String)>> {
    let dir = lockfile.parent()?;
    let lock = read_toml(lockfile)?;
    let packages = lock.get("package")?.as_array()?;
    let workspace = read_toml(&dir.join("Cargo.toml"))?;
    let mut members = BTreeMap::new();
    for path in cargo_manifests(dir)? {
        if let Some(m) = member(&read_toml(&path)?, &workspace) {
            members.insert(m.name.clone(), m);
        }
    }
    type Node = (String, String);
    let mut versions: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut deps: BTreeMap<Node, Vec<&str>> = BTreeMap::new();
    let mut roots: Vec<Node> = Vec::new();
    for p in packages {
        let name = p.get("name")?.as_str()?;
        let version = p.get("version")?.as_str()?;
        versions.entry(name).or_default().push(version);
        let node = (name.to_string(), version.to_string());
        let listed = p.get("dependencies").and_then(toml::Value::as_array);
        deps.insert(
            node.clone(),
            listed
                .into_iter()
                .flatten()
                .filter_map(|d| d.as_str())
                .collect(),
        );
        if p.get("source").is_none() {
            // A local package this workspace does not list: its edges cannot be sorted.
            members.get(name)?;
            roots.push(node);
        }
    }
    let mut seen: BTreeSet<Node> = BTreeSet::new();
    let mut todo = roots;
    while let Some(node) = todo.pop() {
        if !seen.insert(node.clone()) {
            continue;
        }
        let local = members.get(&node.0);
        for dep in deps.get(&node).into_iter().flatten() {
            let (name, version) = lock_dep(dep);
            if local.is_some_and(|m| !m.normal.contains(name)) {
                continue;
            }
            let all = versions.get(name).map_or(&[][..], Vec::as_slice);
            for found in all.iter().filter(|v| version.is_none_or(|w| w == **v)) {
                todo.push((name.to_string(), (*found).to_string()));
            }
        }
    }
    Some(deps.into_keys().filter(|n| !seen.contains(n)).collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[cfg(unix)]
    #[test]
    fn a_manifest_linked_to_a_device_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        std::os::unix::fs::symlink("/dev/zero", &manifest).unwrap();
        assert!(read_toml(&manifest).is_none());
    }

    #[test]
    fn gemfile_groups_read_blocks_inline_forms_and_unions() {
        let text = r#"
source "https://rubygems.org"
gem "rails", "~> 7"
gem "rspec", group: :test
gem "pry", groups: [:development, :test]
gem 'rubocop', :group => :development, require: false
gem "both", group: [:test, :production]
group :development, :test do
  gem "byebug"
  # gem "commented"
  if ENV["X"]
    gem "in_if"
  end
  gem "wide",
    "~> 1"
end
group :production do
  gem "puma"
end
gem "after"
group :assets, optional: true do
  gem "sass"
end
"#;
        let (dev, runtime) = gemfile_groups(text);
        assert_eq!(
            dev,
            set(&["byebug", "in_if", "pry", "rspec", "rubocop", "wide"])
        );
        assert_eq!(runtime, set(&["after", "both", "puma", "rails", "sass"]));
    }

    #[test]
    fn mix_deps_keep_anything_that_can_reach_prod() {
        let text = r#"
  defp deps do
    [
      {:phoenix, "~> 1.7"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:ex_machina, "~> 2.7", only: :test},
      # {:gone, only: :test},
      {:both, "~> 1", only: [:dev, :prod]},
      {:computed, "~> 1", only: Mix.env()},
      {:dialyxir, "~> 1.0", runtime: false},
      {:git, github: "a/b", only: :dev, opts: [x: {:y, 1}]}
    ]
  end
"#;
        let mut deps = MixDeps::default();
        mix_deps(text, &mut deps);
        assert_eq!(deps.dev, set(&["credo", "ex_machina", "git"]));
        assert!(deps
            .runtime
            .is_superset(&set(&["phoenix", "both", "computed", "dialyxir"])));
    }

    fn mix_repo(lock: &str, exs: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mix.lock"), lock).unwrap();
        std::fs::write(dir.path().join("mix.exs"), exs).unwrap();
        dir
    }

    const MIX_LOCK: &str = r#"%{
  "app": {:hex, :app, "1.0.0", "a", [:mix], [], "hexpm", "b"},
  "credo": {:hex, :credo, "1.0.0", "a", [:mix], [{:bunt, "~> 1", [hex: :bunt, repo: "hexpm", optional: false]}], "hexpm", "b"},
  "bunt": {:hex, :bunt, "1.0.0", "a", [:mix], [], "hexpm", "b"},
}
"#;
    const MIX_EXS: &str = r#"[{:app, "~> 1"}, {:credo, "~> 1", only: :dev}]"#;

    #[test]
    fn hex_counts_the_closure_of_a_dev_dep_as_dev() {
        let dir = mix_repo(MIX_LOCK, MIX_EXS);
        assert_eq!(hex(dir.path()), DevSet::Names(set(&["bunt", "credo"])));
    }

    #[test]
    fn a_shipping_git_dep_keeps_only_declared_dev_deps() {
        let lock = MIX_LOCK.replace("%{\n", "%{\n  \"g\": {:git, \"u\", \"r\", []},\n");
        let exs = r#"[{:g, git: "u"}, {:app, "~> 1"}, {:credo, "~> 1", only: :dev}]"#;
        let dir = mix_repo(&lock, exs);
        assert_eq!(hex(dir.path()), DevSet::Names(set(&["credo"])));
    }

    #[test]
    fn a_path_dep_is_read_when_it_is_in_the_repo() {
        let exs = r#"[{:local, path: "./local"}, {:credo, "~> 1", only: :dev}]"#;
        let dir = mix_repo(MIX_LOCK, exs);
        let local = dir.path().join("local");
        std::fs::create_dir(&local).unwrap();
        // Unreadable until the file is there.
        assert_eq!(hex(dir.path()), DevSet::Names(set(&["credo"])));
        std::fs::write(local.join("mix.exs"), r#"[{:bunt, "~> 1"}]"#).unwrap();
        assert_eq!(hex(dir.path()), DevSet::Names(set(&["credo"])));
        let outside = r#"[{:local, path: "../x"}, {:credo, "~> 1", only: :dev}]"#;
        let dir = mix_repo(MIX_LOCK, outside);
        assert_eq!(hex(dir.path()), DevSet::Names(set(&["credo"])));
    }

    #[test]
    fn a_package_under_both_a_dev_and_a_runtime_root_ships() {
        let mut graph = DepGraph::new("(root)");
        graph.add_edges("(root)", ["app", "tester"]);
        graph.add_edges("app", ["shared"]);
        graph.add_edges("tester", ["shared", "only-test"]);
        let got = under_dev_only(&graph, set(&["tester"]), &set(&["app"]));
        assert_eq!(got, DevSet::Names(set(&["only-test", "tester"])));
        // Declared both ways: runtime wins.
        let got = under_dev_only(&graph, set(&["app"]), &set(&["app"]));
        assert_eq!(got, DevSet::None);
    }

    #[test]
    fn go_imports_read_the_header_only() {
        let text = "// c\n/* block\nimport \"no\" */\npackage a\n\nimport \"x/one\"\nimport (\n\tb \"x/two\"\n\t_ \"x/three\" // why\n\n)\n\nfunc f() { s := `import \"no\"` }\n";
        assert_eq!(go_imports(text), vec!["x/one", "x/two", "x/three"]);
    }

    #[test]
    fn go_mod_reads_requires_replaces_and_the_language_version() {
        let text = "module m\n\ngo 1.21.3\n\nrequire a/b v1.0.0\nrequire (\n\tc/d v1.0.0 // indirect\n)\nreplace a/b => ../x\nreplace (\n\tc/d v1.0.0 => e/F v2.0.0\n)\nexclude (\n\tz/z v1.0.0\n)\n";
        let got = go_mod(text);
        assert_eq!(got.go, (1, 21));
        assert_eq!(got.requires.len(), 2);
        assert_eq!(got.replaces["a/b"], ("../x".to_string(), None));
        let target = ("e/F".to_string(), Some("v2.0.0".to_string()));
        assert_eq!(got.replaces["c/d"], target);
        assert_eq!(cache_escaped("github.com/Azure/x"), "github.com/!azure/x");
    }

    fn write(path: PathBuf, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// `t/assert` only in tests, `r/lib` shipped, and `t/shared` imported by tests and by `r/lib`.
    fn go_repo() -> (tempfile::TempDir, tempfile::TempDir) {
        let (repo, cache) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let module = "module m\ngo 1.21\nrequire (\n\tt/assert v1.0.0\n\tt/shared v1.0.0\n\tr/lib v1.0.0\n\tu/under v1.0.0 // indirect\n)\n";
        write(repo.path().join("go.mod"), module);
        let test = "package a\nimport (\n\"t/assert\"\n\"t/shared\"\n)\n";
        write(repo.path().join("a_test.go"), test);
        write(
            repo.path().join("a.go"),
            "package a\nimport \"r/lib/sub\"\n",
        );
        let c = cache.path();
        let lib = "package sub\nimport (\n\"fmt\"\n\"t/shared\"\n)\n";
        write(c.join("r/lib@v1.0.0/sub/s.go"), lib);
        let only_test = "package sub\nimport \"not/built\"\n";
        write(c.join("r/lib@v1.0.0/sub/s_test.go"), only_test);
        write(c.join("t/shared@v1.0.0/x.go"), "package shared\n");
        write(
            c.join("t/assert@v1.0.0/x.go"),
            "package assert\nimport \"u/under\"\n",
        );
        write(c.join("u/under@v1.0.0/x.go"), "package under\n");
        (repo, cache)
    }

    #[test]
    fn go_counts_what_a_shipped_dependency_imports_as_shipped() {
        let (repo, cache) = go_repo();
        let got = go_with_cache(repo.path(), Some(cache.path().to_path_buf()));
        assert_eq!(got, DevSet::Names(set(&["t/assert", "u/under"])));
    }

    #[test]
    fn go_stays_at_runtime_without_the_source_of_a_dependency() {
        let (repo, cache) = go_repo();
        assert_eq!(go_with_cache(repo.path(), None), DevSet::None);
        std::fs::remove_dir_all(cache.path().join("t/shared@v1.0.0")).unwrap();
        let got = go_with_cache(repo.path(), Some(cache.path().to_path_buf()));
        assert_eq!(got, DevSet::None);
    }

    #[test]
    fn go_stays_at_runtime_with_an_incomplete_require_list_or_no_sources() {
        let (repo, cache) = go_repo();
        let cache = Some(cache.path().to_path_buf());
        std::fs::remove_file(repo.path().join("a.go")).unwrap();
        assert_eq!(go_with_cache(repo.path(), cache.clone()), DevSet::None);
        write(repo.path().join("a.go"), "package a\n");
        let old = "module m\ngo 1.16\nrequire t/assert v1.0.0\n";
        write(repo.path().join("go.mod"), old);
        assert_eq!(go_with_cache(repo.path(), cache), DevSet::None);
    }

    fn cargo_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("crates/b")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\n[workspace.dependencies]\nalias = { package = \"real\", version = \"1\" }\n",
        )
        .unwrap();
        std::fs::write(
            root.join("crates/b/Cargo.toml"),
            "[package]\nname = \"b\"\n[dependencies]\nalias = { workspace = true }\n[target.'cfg(unix)'.dependencies]\nunixy = \"1\"\n[dev-dependencies]\ntester = \"1\"\nreal = \"1\"\n[build-dependencies]\ncc = \"1\"\n",
        )
        .unwrap();
        let reg = "source = \"registry+https://github.com/rust-lang/crates.io-index\"";
        let lock = format!(
            "version = 3\n\n[[package]]\nname = \"b\"\nversion = \"0.1.0\"\ndependencies = [\n \"cc\",\n \"real\",\n \"tester\",\n \"unixy\",\n]\n\n[[package]]\nname = \"cc\"\nversion = \"1.0.0\"\n{reg}\n\n[[package]]\nname = \"real\"\nversion = \"1.0.0\"\n{reg}\ndependencies = [\n \"shared 2.0.0\",\n]\n\n[[package]]\nname = \"shared\"\nversion = \"1.0.0\"\n{reg}\n\n[[package]]\nname = \"shared\"\nversion = \"2.0.0\"\n{reg}\n\n[[package]]\nname = \"tester\"\nversion = \"1.0.0\"\n{reg}\ndependencies = [\n \"shared 1.0.0\",\n]\n\n[[package]]\nname = \"unixy\"\nversion = \"1.0.0\"\n{reg}\n"
        );
        std::fs::write(root.join("Cargo.lock"), lock).unwrap();
        dir
    }

    #[test]
    fn cargo_follows_normal_edges_from_the_workspace() {
        let dir = cargo_repo();
        let dev = cargo_dev(&dir.path().join("Cargo.lock")).unwrap();
        let got: Vec<String> = dev.iter().map(|(n, v)| format!("{n} {v}")).collect();
        assert_eq!(got, vec!["cc 1.0.0", "shared 1.0.0", "tester 1.0.0"]);
    }

    #[test]
    fn a_local_package_with_no_manifest_leaves_cargo_at_runtime() {
        let dir = cargo_repo();
        std::fs::remove_file(dir.path().join("crates/b/Cargo.toml")).unwrap();
        assert_eq!(cargo(&dir.path().join("Cargo.lock")), DevSet::None);
    }

    #[test]
    fn a_workspace_pattern_this_cannot_expand_gives_no_manifests() {
        let dir = tempfile::tempdir().unwrap();
        let text = "[workspace]\nmembers = [\"a/*/b\"]\n";
        std::fs::write(dir.path().join("Cargo.toml"), text).unwrap();
        assert!(cargo_manifests(dir.path()).is_none());
    }
}
