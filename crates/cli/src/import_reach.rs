//! Import-graph witness chains for RubyGems, Packagist, NuGet, Maven, Hex and Swift (spec 16,
//! row 14), the siblings of [`crate::npm_reach`] and [`crate::py_reach`].
//!
//! The first hop is a line of the repo's own source that imports a package. Every later hop is
//! a dependency edge of the lockfile, so a chain reads "this file imports A, and A requires B":
//! these ecosystems keep little installed source to read, and the lockfile is always there.
//!
//! | Ecosystem | Lines read | Import to package |
//! |-----------|------------|-------------------|
//! | RubyGems | `require`, `Bundler.require` | the longest prefix of the path that is a gem, `Gemfile` gems for `Bundler.require` |
//! | Packagist | `use` | PSR-4 and PSR-0 prefixes in `composer.lock` |
//! | NuGet | `using`, `open`, `Imports` | assemblies in `project.assets.json`, then package ids |
//! | Maven | `import` in Java, Kotlin, Scala, Groovy | classes in jars in `~/.m2` and the Gradle cache, then group and artifact |
//! | Hex | `alias`, `import`, `require`, `use` | the longest prefix of the module that is a package |
//! | Swift | `import` | `.product` in `Package.swift`, then the repository's name |
//!
//! **Positive-only.** An import read here can show a package is used; none of these languages
//! stops code reaching a package another way, so an unreached finding keeps what it had and
//! nothing here says `NotReachable`. A name that resolves to no locked package is dropped: a
//! wrong guess would invent a witness.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fleetreach_core::inventory::ROOT;
use fleetreach_core::{
    DepGraph, Ecosystem, FleetReport, ImportSite, Occurrence, ReachVerdict, Reachability, RepoId,
};
use rayon::prelude::*;
use walkdir::WalkDir;

use crate::config::{Config, Repo};
use crate::inventory::repo_inventory;

/// The ecosystems this module assesses.
pub const ECOSYSTEMS: [Ecosystem; 6] = [
    Ecosystem::RubyGems,
    Ecosystem::Packagist,
    Ecosystem::NuGet,
    Ecosystem::Maven,
    Ecosystem::Hex,
    Ecosystem::Swift,
];

const ENTRY: &str = "(entry)";
/// Directories of installed or generated code, never the project's own.
const SKIPPED_DIRS: &[&str] = &[
    ".git",
    ".build",
    ".gradle",
    "Carthage",
    "Pods",
    "_build",
    "deps",
    "node_modules",
    "obj",
    "target",
    "vendor",
];
const MAX_SOURCE: u64 = 4 << 20;
/// What `Bundler.require` reads as: every gem of the `Gemfile`.
const BUNDLER: &str = "(Bundler.require)";

/// One import in a source file.
#[derive(Debug, PartialEq, Eq)]
struct Import {
    line: u32,
    name: String,
}

fn import(index: usize, name: &str) -> Import {
    Import {
        line: u32::try_from(index + 1).unwrap_or(u32::MAX),
        name: name.to_string(),
    }
}

/// Adds a witness chain to each finding of these ecosystems that has one. A finding with none
/// keeps what the heuristic gave it. Repos are analyzed once, in parallel.
pub fn assess(report: &mut FleetReport, config: &Config) {
    let mut needed: BTreeMap<&str, BTreeSet<Ecosystem>> = BTreeMap::new();
    for finding in &report.vulnerabilities {
        if ECOSYSTEMS.contains(&finding.ecosystem) {
            for occ in &finding.occurrences {
                if let Occurrence::InRepo { repo, .. } = occ {
                    needed.entry(&repo.0).or_default().insert(finding.ecosystem);
                }
            }
        }
    }
    let work: Vec<(&Repo, &BTreeSet<Ecosystem>)> = config
        .repos
        .iter()
        .filter_map(|repo| Some((repo, needed.get(repo.id.0.as_str())?)))
        .collect();
    let analyses: BTreeMap<(String, Ecosystem), Chains> = work
        .par_iter()
        .flat_map_iter(|(repo, ecosystems)| analyze(repo, ecosystems))
        .collect();
    for finding in &mut report.vulnerabilities {
        let mut best: Option<(Vec<String>, ImportSite)> = None;
        for occ in &finding.occurrences {
            let Occurrence::InRepo { repo, package, .. } = occ else {
                continue;
            };
            let key = (repo.0.clone(), finding.ecosystem);
            let Some((chain, site)) = analyses.get(&key).and_then(|c| c.chain(repo, package))
            else {
                continue;
            };
            if best.as_ref().is_none_or(|(b, _)| chain.len() < b.len()) {
                best = Some((chain, site));
            }
        }
        let Some((witness, site)) = best else {
            continue;
        };
        finding.reachable = Some(true);
        finding.reachability = Some(Reachability {
            verdict: ReachVerdict::Reachable { witness },
            config: "import-graph".to_string(),
            engine: "fleetreach-imports".to_string(),
            targets: Vec::new(),
            witness: None,
            import_site: Some(site),
        });
    }
}

/// One ecosystem of one repo: what its source imports, then the lockfile's edges.
#[derive(Debug)]
pub struct Chains {
    graph: DepGraph,
    /// The first line that imports each package, as `(file, line)`.
    sites: BTreeMap<String, (String, u32)>,
}

impl Chains {
    fn chain(&self, repo: &RepoId, package: &str) -> Option<(Vec<String>, ImportSite)> {
        let chain = self.graph.chain_to(package);
        let (file, line) = self.sites.get(chain.get(1)?)?.clone();
        let site = ImportSite {
            repo: repo.clone(),
            file,
            line,
        };
        Some((chain.into_iter().skip(1).collect(), site))
    }

    /// Every package reached, with its chain and the line that starts it.
    #[must_use]
    pub fn all(&self) -> Vec<(String, Vec<String>, String, u32)> {
        let mut nodes: BTreeSet<&str> = BTreeSet::new();
        for (from, to) in self.graph.edges() {
            nodes.extend([from, to]);
        }
        let reached = nodes.into_iter().filter_map(|node| {
            let chain = self.graph.chain_to(node);
            let (file, line) = self.sites.get(chain.get(1)?)?.clone();
            Some((node.to_string(), chain[1..].to_vec(), file, line))
        });
        reached.collect()
    }
}

/// [`Chains`] of `repo` for each of `ecosystems` that has packages.
#[must_use]
pub fn analyze(
    repo: &Repo,
    ecosystems: &BTreeSet<Ecosystem>,
) -> Vec<((String, Ecosystem), Chains)> {
    let inventory = repo_inventory(repo);
    let mut out = Vec::new();
    for ecosystem in ecosystems {
        let sources = || {
            inventory
                .sources
                .iter()
                .filter(|s| s.ecosystem == *ecosystem)
        };
        let packages: BTreeMap<String, String> = sources()
            .flat_map(|s| s.packages.iter())
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();
        if packages.is_empty() {
            continue;
        }
        let edges = sources().flat_map(|s| s.edges.iter());
        let edges = edges.filter(|(from, _)| from != ROOT);
        let chains = chains(&repo.path, *ecosystem, &packages, edges);
        out.push(((repo.id.0.clone(), *ecosystem), chains));
    }
    out
}

fn chains<'a>(
    root: &Path,
    ecosystem: Ecosystem,
    packages: &BTreeMap<String, String>,
    edges: impl Iterator<Item = &'a (String, String)>,
) -> Chains {
    let language = Language::of(ecosystem);
    let files = source_files(root, language.extensions);
    let scanned: Vec<(&PathBuf, String, Vec<Import>)> = files
        .par_iter()
        .filter_map(|path| {
            let small = path.metadata().is_ok_and(|m| m.len() <= MAX_SOURCE);
            let bytes = small.then(|| std::fs::read(path).ok()).flatten()?;
            let text = String::from_utf8_lossy(&bytes).into_owned();
            let imports = (language.imports)(&text);
            Some((path, text, imports))
        })
        .collect();
    let mut own = BTreeSet::new();
    for (path, text, _) in &scanned {
        own.extend((language.own)(text));
        own.extend(swift_target(ecosystem, root, path));
    }
    let resolver = Resolver::build(ecosystem, root, packages);
    let mut sites: BTreeMap<String, (String, u32)> = BTreeMap::new();
    for (path, _, imports) in &scanned {
        let file = path.strip_prefix(root).unwrap_or(path);
        let file = file.to_string_lossy().replace('\\', "/");
        for found in imports {
            if is_own(&found.name, &own) {
                continue;
            }
            for package in resolver.resolve(&found.name) {
                // Files come sorted and lines in order, so this keeps the first.
                sites
                    .entry(package)
                    .or_insert_with(|| (file.clone(), found.line));
            }
        }
    }
    let mut graph = DepGraph::new(ENTRY);
    graph.add_edges(ENTRY, sites.keys().cloned());
    for (from, to) in edges {
        graph.add_edges(from, [to.clone()]);
    }
    Chains { graph, sites }
}

fn source_files(root: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    let keep = |entry: &walkdir::DirEntry| {
        let name = entry.file_name().to_string_lossy();
        entry.depth() == 0 || !(entry.file_type().is_dir() && SKIPPED_DIRS.contains(&name.as_ref()))
    };
    let walk = WalkDir::new(root).sort_by_file_name().into_iter();
    let files = walk
        .filter_entry(keep)
        .flatten()
        .filter(|e| e.file_type().is_file());
    let matching = files.filter(|entry| {
        let name = entry.file_name().to_string_lossy();
        extensions.iter().any(|ext| name.ends_with(ext))
    });
    matching.map(walkdir::DirEntry::into_path).collect()
}

fn is_own(name: &str, own: &BTreeSet<String>) -> bool {
    let mut prefix = name;
    loop {
        if own.contains(prefix) {
            return true;
        }
        match prefix.rsplit_once('.') {
            Some((head, _)) => prefix = head,
            None => return false,
        }
    }
}

/// A Swift module the repo builds itself: `Sources/<module>/…`, `Tests/<module>/…`.
fn swift_target(ecosystem: Ecosystem, root: &Path, path: &Path) -> Option<String> {
    if ecosystem != Ecosystem::Swift {
        return None;
    }
    let relative = path.strip_prefix(root).ok()?;
    let parts: Vec<_> = relative.iter().map(|p| p.to_string_lossy()).collect();
    let at = parts.iter().position(|p| p == "Sources" || p == "Tests")?;
    parts.get(at + 1).map(ToString::to_string)
}

/// How one ecosystem's source spells an import.
struct Language {
    extensions: &'static [&'static str],
    imports: fn(&str) -> Vec<Import>,
    /// Names the repo itself declares, which an import of is first-party.
    own: fn(&str) -> Vec<String>,
}

impl Language {
    fn of(ecosystem: Ecosystem) -> Language {
        let language = |extensions, imports, own| Language {
            extensions,
            imports,
            own,
        };
        match ecosystem {
            Ecosystem::RubyGems => language(&[".rb", ".rake", ".ru"], ruby_imports, none),
            Ecosystem::Packagist => language(&[".php"], php_imports, none),
            Ecosystem::NuGet => language(&[".cs", ".fs", ".vb"], dotnet_imports, dotnet_own),
            Ecosystem::Maven => language(
                &[".java", ".kt", ".kts", ".scala", ".groovy"],
                jvm_imports,
                jvm_own,
            ),
            Ecosystem::Hex => language(&[".ex", ".exs"], elixir_imports, elixir_own),
            _ => language(&[".swift"], swift_imports, none),
        }
    }
}

fn none(_: &str) -> Vec<String> {
    Vec::new()
}

/// The string literal `text` starts with, unless it interpolates.
fn quoted(text: &str) -> Option<&str> {
    let quote = text.chars().next().filter(|c| matches!(c, '\'' | '"'))?;
    let rest = &text[1..];
    let end = rest.find(quote)?;
    Some(&rest[..end]).filter(|s| !s.is_empty() && !s.contains("#{"))
}

fn is_dotted(name: &str) -> bool {
    !name.is_empty()
        && name
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_alphanumeric() || c == '_'))
}

/// The dotted name `text` starts with, to the first character that cannot be in one.
fn leading_name(text: &str) -> &str {
    let end = text.find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.'));
    text[..end.unwrap_or(text.len())].trim_end_matches('.')
}

fn ruby_imports(text: &str) -> Vec<Import> {
    let mut out = Vec::new();
    let mut in_comment = false;
    for (index, line) in text.lines().enumerate() {
        let line = line.trim_start();
        if line == "__END__" {
            break;
        }
        if line.starts_with("=begin") {
            in_comment = true;
        }
        if in_comment {
            in_comment = !line.starts_with("=end");
            continue;
        }
        if line.starts_with("Bundler.require") {
            out.push(import(index, BUNDLER));
        } else if let Some(rest) = line.strip_prefix("require") {
            if rest.starts_with([' ', '(']) {
                if let Some(path) = quoted(rest.trim_start_matches([' ', '('])) {
                    out.push(import(index, path));
                }
            }
        }
    }
    out
}

fn php_imports(text: &str) -> Vec<Import> {
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let Some(rest) = line.trim_start().strip_prefix("use ") else {
            continue;
        };
        let rest = rest.trim_start();
        let rest = rest
            .strip_prefix("function ")
            .or(rest.strip_prefix("const "))
            .unwrap_or(rest);
        let names = rest.split(';').next().unwrap_or(rest);
        // `use Foo\{Bar, Baz};` names one prefix.
        let (names, group) = match names.split_once('{') {
            Some((prefix, _)) => (prefix, true),
            None => (names, false),
        };
        let parts = if group {
            vec![names]
        } else {
            names.split(',').collect()
        };
        for part in parts {
            let name = part.split_whitespace().next().unwrap_or("");
            let name = name.trim_start_matches('\\');
            let valid = |c: char| c.is_alphanumeric() || c == '_' || c == '\\';
            if name.contains('\\') && name.chars().all(valid) {
                out.push(import(index, name));
            }
        }
    }
    out
}

fn dotnet_imports(text: &str) -> Vec<Import> {
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim_start();
        let line = line.strip_prefix("global ").unwrap_or(line);
        let name = if let Some(rest) = line.strip_prefix("using ") {
            let Some((statement, _)) = rest.split_once(';') else {
                continue;
            };
            let statement = statement.strip_prefix("static ").unwrap_or(statement);
            match statement.split_once('=') {
                // `using var x = y;` is not an import, `using X = A.B;` is.
                Some((alias, target)) if !alias.trim().contains(' ') => target.trim(),
                Some(_) => continue,
                None => statement.trim(),
            }
        } else if let Some(rest) = line.strip_prefix("open ").or(line.strip_prefix("Imports ")) {
            rest.trim()
        } else {
            continue;
        };
        if is_dotted(name) {
            out.push(import(index, name));
        }
    }
    out
}

fn dotnet_own(text: &str) -> Vec<String> {
    let names = text.lines().filter_map(|line| {
        let rest = line.trim_start().strip_prefix("namespace ")?;
        Some(leading_name(rest).to_string()).filter(|n| !n.is_empty())
    });
    names.collect()
}

fn jvm_imports(text: &str) -> Vec<Import> {
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let Some(rest) = line.trim_start().strip_prefix("import ") else {
            continue;
        };
        let rest = rest.trim_start();
        let name = leading_name(rest.strip_prefix("static ").unwrap_or(rest));
        if name.contains('.') {
            out.push(import(index, name));
        }
    }
    out
}

fn jvm_own(text: &str) -> Vec<String> {
    let declared = text.lines().find_map(|line| {
        let rest = line.trim_start().strip_prefix("package ")?;
        Some(leading_name(rest).to_string()).filter(|n| n.contains('.'))
    });
    declared.into_iter().collect()
}

fn elixir_imports(text: &str) -> Vec<Import> {
    let mut out = Vec::new();
    let mut in_doc = false;
    for (index, line) in text.lines().enumerate() {
        if line.matches("\"\"\"").count() % 2 == 1 {
            in_doc = !in_doc;
            continue;
        }
        if in_doc {
            continue;
        }
        let line = line.trim_start();
        let rest = ["alias ", "import ", "require ", "use "]
            .iter()
            .find_map(|word| line.strip_prefix(word));
        if let Some(name) = rest.map(leading_name) {
            if name.starts_with(|c: char| c.is_ascii_uppercase()) {
                out.push(import(index, name));
            }
        }
    }
    out
}

fn elixir_own(text: &str) -> Vec<String> {
    let names = text.lines().filter_map(|line| {
        let rest = line.trim_start().strip_prefix("defmodule ")?;
        Some(leading_name(rest).to_string()).filter(|n| !n.is_empty())
    });
    names.collect()
}

fn swift_imports(text: &str) -> Vec<Import> {
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let skipped = words
            .iter()
            .take_while(|w| w.starts_with('@') || is_access(w))
            .count();
        let (Some(&"import"), Some(next)) = (words.get(skipped), words.get(skipped + 1)) else {
            continue;
        };
        let kinds = [
            "struct",
            "class",
            "enum",
            "protocol",
            "typealias",
            "func",
            "let",
            "var",
        ];
        let name = if kinds.contains(next) {
            words.get(skipped + 2)
        } else {
            Some(next)
        };
        let name = name.map_or("", |n| leading_name(n));
        let name = name.split('.').next().unwrap_or(name);
        if !name.is_empty() {
            out.push(import(index, name));
        }
    }
    out
}

fn is_access(word: &str) -> bool {
    matches!(
        word,
        "public" | "internal" | "package" | "private" | "fileprivate"
    )
}

/// Letters and digits, lowercased: `active_support`, `activesupport` and `ActiveSupport` agree.
fn squashed(name: &str) -> String {
    let kept = name.chars().filter(char::is_ascii_alphanumeric);
    kept.map(|c| c.to_ascii_lowercase()).collect()
}

/// From an import to locked packages, for one ecosystem of one repo.
enum Resolver {
    /// Squashed name to package, and the gems `Bundler.require` loads.
    Gems(BTreeMap<String, String>, Vec<String>),
    /// Namespace prefix to package.
    Composer(BTreeMap<String, String>),
    /// Lowercased assembly or package id to package.
    Assemblies(BTreeMap<String, String>),
    Maven(MavenIndex),
    /// Squashed name to package.
    Hex(BTreeMap<String, String>),
    /// Module to package, then squashed repository name to package.
    Swift(BTreeMap<String, String>, BTreeMap<String, String>),
}

impl Resolver {
    fn build(ecosystem: Ecosystem, root: &Path, packages: &BTreeMap<String, String>) -> Resolver {
        let by_squashed = || packages.keys().map(|p| (squashed(p), p.clone())).collect();
        match ecosystem {
            Ecosystem::RubyGems => Resolver::Gems(by_squashed(), bundled_gems(root, packages)),
            Ecosystem::Packagist => Resolver::Composer(composer_prefixes(root, packages)),
            Ecosystem::NuGet => Resolver::Assemblies(assemblies(root, packages)),
            Ecosystem::Maven => Resolver::Maven(MavenIndex::build(packages)),
            Ecosystem::Hex => Resolver::Hex(by_squashed()),
            _ => {
                let names = packages
                    .keys()
                    .map(|p| (swift_name(p), p.clone()))
                    .collect();
                Resolver::Swift(swift_products(root, packages), names)
            }
        }
    }

    fn resolve(&self, name: &str) -> Vec<String> {
        match self {
            Resolver::Gems(_, bundled) if name == BUNDLER => bundled.clone(),
            Resolver::Gems(gems, _) => longest_prefix(name, '/', gems),
            Resolver::Hex(packages) => longest_prefix(name, '.', packages),
            Resolver::Composer(prefixes) => {
                let parts: Vec<&str> = name.split('\\').collect();
                let found = (1..=parts.len())
                    .rev()
                    .find_map(|end| prefixes.get(&format!("{}\\", parts[..end].join("\\"))));
                found.cloned().into_iter().collect()
            }
            Resolver::Assemblies(known) => {
                let lower = name.to_lowercase();
                let parts: Vec<&str> = lower.split('.').collect();
                let found = (1..=parts.len())
                    .rev()
                    .find_map(|end| known.get(&parts[..end].join(".")));
                found.cloned().into_iter().collect()
            }
            Resolver::Maven(index) => index.resolve(name),
            Resolver::Swift(products, names) => {
                let found = products.get(name).or_else(|| names.get(&squashed(name)));
                found.cloned().into_iter().collect()
            }
        }
    }
}

/// The package whose squashed name equals the most leading parts of `name`.
fn longest_prefix(name: &str, separator: char, packages: &BTreeMap<String, String>) -> Vec<String> {
    let parts: Vec<&str> = name.split(separator).collect();
    let found = (1..=parts.len())
        .rev()
        .find_map(|end| packages.get(&squashed(&parts[..end].concat())));
    found.cloned().into_iter().collect()
}

/// The gems of any `Gemfile` here that `Bundler.require` loads: all but `require: false`.
fn bundled_gems(root: &Path, packages: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = BTreeSet::new();
    for path in source_files(root, &["Gemfile"]) {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        for line in text.lines() {
            let Some(rest) = line.trim_start().strip_prefix("gem ") else {
                continue;
            };
            let squeezed: String = rest.split_whitespace().collect();
            let kept = !squeezed.contains("require:false") && !squeezed.contains(":require=>false");
            if let Some(name) =
                quoted(rest.trim_start()).filter(|n| kept && packages.contains_key(*n))
            {
                out.insert(name.to_string());
            }
        }
    }
    out.into_iter().collect()
}

fn composer_prefixes(root: &Path, packages: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for path in source_files(root, &["composer.lock"]) {
        let Some(lock) = read_json(&path) else {
            continue;
        };
        let listed = ["packages", "packages-dev"]
            .iter()
            .filter_map(|k| lock.get(k)?.as_array());
        for package in listed.flatten() {
            let Some(name) = package["name"]
                .as_str()
                .filter(|n| packages.contains_key(*n))
            else {
                continue;
            };
            for kind in ["psr-4", "psr-0"] {
                let Some(map) = package["autoload"][kind].as_object() else {
                    continue;
                };
                for prefix in map.keys().filter(|p| p.ends_with('\\')) {
                    out.entry(prefix.clone())
                        .or_insert_with(|| name.to_string());
                }
            }
        }
    }
    // A package can name the same prefix as the project: laravel/pint ships an `App\\`.
    for path in source_files(root, &["composer.json"]) {
        let Some(manifest) = read_json(&path) else {
            continue;
        };
        for section in ["autoload", "autoload-dev"] {
            for kind in ["psr-4", "psr-0"] {
                let map = manifest[section][kind].as_object();
                for prefix in map.into_iter().flat_map(|m| m.keys()) {
                    out.remove(prefix);
                }
            }
        }
    }
    out
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Package ids, and the assemblies each `obj/project.assets.json` here says a package holds.
fn assemblies(root: &Path, packages: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = packages
        .keys()
        .map(|p| (p.to_lowercase(), p.clone()))
        .collect();
    let by_lower: BTreeMap<String, &String> =
        packages.keys().map(|p| (p.to_lowercase(), p)).collect();
    let walk = WalkDir::new(root).into_iter().flatten();
    let found = walk.filter(|e| e.file_name() == "project.assets.json");
    for entry in found {
        let Some(assets) = read_json(entry.path()) else {
            continue;
        };
        let targets = assets["targets"].as_object().into_iter().flatten();
        for (key, library) in targets.flat_map(|(_, t)| t.as_object().into_iter().flatten()) {
            let id = key.split('/').next().unwrap_or(key).to_lowercase();
            let Some(package) = by_lower.get(&id) else {
                continue;
            };
            for dll in library["compile"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(k, _)| k)
            {
                let file = dll.rsplit('/').next().unwrap_or(dll);
                if let Some(stem) = file.strip_suffix(".dll") {
                    out.entry(stem.to_lowercase())
                        .or_insert_with(|| (*package).clone());
                }
            }
        }
    }
    out
}

/// What a jar on this machine holds, and what the coordinates alone can say.
#[derive(Default)]
struct MavenIndex {
    /// Class or Java package to the artifacts holding it.
    jars: BTreeMap<String, BTreeSet<String>>,
    /// `group:artifact`, split.
    coordinates: Vec<(String, String)>,
}

impl MavenIndex {
    fn build(packages: &BTreeMap<String, String>) -> MavenIndex {
        let mut index = MavenIndex::default();
        let repositories = maven_roots();
        for (package, version) in packages {
            let Some((group, artifact)) = package.split_once(':') else {
                continue;
            };
            index
                .coordinates
                .push((group.to_string(), artifact.to_string()));
            for jar in jars_of(&repositories, group, artifact, version) {
                index.add_jar(&jar, package);
            }
        }
        index
    }

    fn add_jar(&mut self, jar: &Path, package: &str) {
        let Ok(file) = std::fs::File::open(jar) else {
            return;
        };
        let Ok(archive) = zip::ZipArchive::new(std::io::BufReader::new(file)) else {
            return;
        };
        for entry in archive.file_names().flatten() {
            let Some(class) = entry.strip_suffix(".class").filter(|c| !c.contains('$')) else {
                continue;
            };
            let class = class.replace('/', ".");
            if let Some((java_package, _)) = class.rsplit_once('.') {
                self.jars
                    .entry(java_package.to_string())
                    .or_default()
                    .insert(package.to_string());
            }
            self.jars
                .entry(class)
                .or_default()
                .insert(package.to_string());
        }
    }

    fn resolve(&self, name: &str) -> Vec<String> {
        let mut prefix = name;
        loop {
            if let Some(found) = self.jars.get(prefix) {
                return found.iter().cloned().collect();
            }
            match prefix.rsplit_once('.') {
                Some((head, _)) => prefix = head,
                None => return self.by_coordinates(name),
            }
        }
    }

    /// With no jar to read: the only artifact of the longest group that is a prefix of `name`,
    /// or the only one of them named by a part of it (`jackson-databind` for `….databind.…`).
    /// A two-part group like `com.alibaba` is a vendor's, so it needs the name. Anything less
    /// decided is dropped.
    fn by_coordinates(&self, name: &str) -> Vec<String> {
        let inside = |group: &str| name.strip_prefix(group).is_some_and(|r| r.starts_with('.'));
        let best = self
            .coordinates
            .iter()
            .filter(|(g, _)| inside(g))
            .map(|(g, _)| g.len())
            .max();
        let Some(best) = best else {
            return Vec::new();
        };
        let group = &name[..best];
        let rest: BTreeSet<&str> = name[best..].split('.').collect();
        let same: Vec<&(String, String)> = self
            .coordinates
            .iter()
            .filter(|(g, _)| g == group)
            .collect();
        let named: Vec<&&(String, String)> = same
            .iter()
            .filter(|(_, a)| a.split('-').any(|w| rest.contains(w)))
            .collect();
        let only = match (same.as_slice(), named.as_slice()) {
            ([one], _) if group.matches('.').count() >= 2 => one,
            (_, [one]) => **one,
            _ => return Vec::new(),
        };
        vec![format!("{}:{}", only.0, only.1)]
    }
}

fn maven_roots() -> (Vec<PathBuf>, Vec<PathBuf>) {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let gradle = std::env::var_os("GRADLE_USER_HOME")
        .map(PathBuf::from)
        .or_else(|| Some(home.as_ref()?.join(".gradle")));
    let local = home
        .iter()
        .map(|h| h.join(".m2").join("repository"))
        .collect();
    let cached = gradle
        .iter()
        .map(|g| g.join("caches/modules-2/files-2.1"))
        .collect();
    (local, cached)
}

fn jars_of(
    (local, cached): &(Vec<PathBuf>, Vec<PathBuf>),
    group: &str,
    artifact: &str,
    version: &str,
) -> Vec<PathBuf> {
    let file = format!("{artifact}-{version}.jar");
    let mut out: Vec<PathBuf> = local
        .iter()
        .map(|root| {
            root.join(group.replace('.', "/"))
                .join(artifact)
                .join(version)
                .join(&file)
        })
        .filter(|path| path.is_file())
        .collect();
    for root in cached {
        let dir = root.join(group).join(artifact).join(version);
        let hashes = std::fs::read_dir(dir).into_iter().flatten().flatten();
        out.extend(hashes.map(|e| e.path().join(&file)).filter(|p| p.is_file()));
    }
    out
}

/// The last part of a package URL, as a module would spell it: `swift-log` is `log`.
fn swift_name(package: &str) -> String {
    let name = package.rsplit('/').next().unwrap_or(package);
    squashed(name.strip_prefix("swift-").unwrap_or(name))
}

/// `.product(name: "Logging", package: "swift-log")` lines of each `Package.swift` here.
fn swift_products(root: &Path, packages: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let by_repo: BTreeMap<&str, &String> = packages
        .keys()
        .map(|p| (p.rsplit('/').next().unwrap_or(p), p))
        .collect();
    let mut out = BTreeMap::new();
    for path in source_files(root, &["Package.swift"]) {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        for (_, rest) in text
            .match_indices(".product(")
            .map(|(at, _)| ((), &text[at..]))
        {
            let call = rest.split(')').next().unwrap_or(rest);
            let value = |key: &str| {
                let (_, after) = call.split_once(key)?;
                quoted(after.trim_start_matches([':', ' ']))
            };
            if let (Some(module), Some(repo)) = (value("name"), value("package")) {
                if let Some(package) = by_repo.get(repo) {
                    out.insert(module.to_string(), (*package).clone());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn names(imports: &[Import]) -> Vec<(u32, &str)> {
        imports.iter().map(|i| (i.line, i.name.as_str())).collect()
    }

    fn locked(names: &[&str]) -> BTreeMap<String, String> {
        names
            .iter()
            .map(|n| (n.to_string(), "1.0.0".to_string()))
            .collect()
    }

    fn write(root: &Path, file: &str, text: &str) {
        let path = root.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn ruby_reads_requires_and_not_comments() {
        let text = "# require 'no'\nrequire 'nokogiri'\nrequire(\"rack/test\") if x\n\
            require_relative 'local'\nrequire name\n=begin\nrequire 'doc'\n=end\n\
            Bundler.require(*Rails.groups)\n__END__\nrequire 'data'\n";
        let found = ruby_imports(text);
        assert_eq!(
            names(&found),
            [(2, "nokogiri"), (3, "rack/test"), (9, BUNDLER)]
        );
    }

    #[test]
    fn ruby_paths_resolve_to_the_longest_gem() {
        let gems = locked(&["rack", "rack-test", "activesupport"]);
        let resolver = Resolver::Gems(
            gems.keys().map(|p| (squashed(p), p.clone())).collect(),
            vec![],
        );
        assert_eq!(resolver.resolve("rack/test"), ["rack-test"]);
        assert_eq!(resolver.resolve("rack/utils"), ["rack"]);
        assert_eq!(
            resolver.resolve("active_support/core_ext"),
            ["activesupport"]
        );
        assert!(resolver.resolve("json").is_empty());
    }

    #[test]
    fn bundler_require_leaves_out_require_false() {
        let root = tempfile::tempdir().unwrap();
        write(
            root.path(),
            "Gemfile",
            "gem 'rails', '~> 7'\ngem 'pry', require: false\ngem \"unlocked\"\n",
        );
        let gems = bundled_gems(root.path(), &locked(&["rails", "pry"]));
        assert_eq!(gems, ["rails"]);
    }

    #[test]
    fn php_reads_use_lines() {
        let text = "<?php\nuse Symfony\\Component\\Yaml\\Yaml;\nuse Foo\\{Bar, Baz};\n\
            use function Guzzle\\Http\\get;\nuse A\\B as C, D\\E;\nuse Trait1;\n$f = function() use ($x) {};\n";
        let found = php_imports(text);
        assert_eq!(
            names(&found),
            [
                (2, "Symfony\\Component\\Yaml\\Yaml"),
                (3, "Foo\\"),
                (4, "Guzzle\\Http\\get"),
                (5, "A\\B"),
                (5, "D\\E")
            ]
        );
    }

    #[test]
    fn composer_lock_says_which_package_has_a_namespace() {
        let root = tempfile::tempdir().unwrap();
        let lock = r#"{"packages":[{"name":"symfony/yaml","autoload":{"psr-4":{"Symfony\\Component\\Yaml\\":"","App\\":""}}}],
            "packages-dev":[{"name":"not/locked","autoload":{"psr-4":{"Not\\":""}}}]}"#;
        write(root.path(), "composer.lock", lock);
        write(
            root.path(),
            "composer.json",
            r#"{"autoload":{"psr-4":{"App\\":"app/"}}}"#,
        );
        let prefixes = composer_prefixes(root.path(), &locked(&["symfony/yaml"]));
        let resolver = Resolver::Composer(prefixes);
        assert_eq!(
            resolver.resolve("Symfony\\Component\\Yaml\\Yaml"),
            ["symfony/yaml"]
        );
        assert!(resolver.resolve("Not\\Here").is_empty());
        assert!(
            resolver.resolve("App\\Models\\User").is_empty(),
            "the project's own"
        );
    }

    #[test]
    fn dotnet_reads_usings_and_not_using_statements() {
        let text = "using System;\nglobal using Newtonsoft.Json.Linq;\nusing static Foo.Bar;\n\
            using J = Serilog.Log;\nusing var x = a.b;\nusing (var s = Open()) { }\n";
        let found = dotnet_imports(text);
        assert_eq!(
            names(&found),
            [
                (1, "System"),
                (2, "Newtonsoft.Json.Linq"),
                (3, "Foo.Bar"),
                (4, "Serilog.Log")
            ]
        );
        assert_eq!(dotnet_own("namespace Acme.App;\n"), ["Acme.App"]);
    }

    #[test]
    fn assets_name_the_assemblies_of_a_package() {
        let root = tempfile::tempdir().unwrap();
        let assets = r#"{"targets":{"net8.0":{"Some.Package/1.0.0":{"compile":{"lib/net8.0/Other.Name.dll":{}}}}}}"#;
        write(root.path(), "src/obj/project.assets.json", assets);
        let resolver = Resolver::Assemblies(assemblies(root.path(), &locked(&["Some.Package"])));
        assert_eq!(resolver.resolve("Other.Name.Inner"), ["Some.Package"]);
        assert_eq!(resolver.resolve("some.package"), ["Some.Package"]);
        assert!(resolver.resolve("Some").is_empty());
    }

    #[test]
    fn jvm_reads_imports_of_each_language() {
        let text = "package com.acme.app;\nimport java.util.List;\nimport static org.junit.Assert.fail;\n\
            import com.fasterxml.jackson.databind.*;\nimport a.b.C as D\nimport a.b.{X, Y}\n * import no.no.No;\n";
        let found = jvm_imports(text);
        assert_eq!(
            names(&found),
            [
                (2, "java.util.List"),
                (3, "org.junit.Assert.fail"),
                (4, "com.fasterxml.jackson.databind"),
                (5, "a.b.C"),
                (6, "a.b")
            ]
        );
        assert_eq!(jvm_own(text), ["com.acme.app"]);
    }

    #[test]
    fn coordinates_decide_only_when_one_artifact_fits() {
        let index = MavenIndex {
            jars: BTreeMap::new(),
            coordinates: vec![
                (
                    "com.fasterxml.jackson.core".to_string(),
                    "jackson-databind".to_string(),
                ),
                (
                    "com.fasterxml.jackson.core".to_string(),
                    "jackson-core".to_string(),
                ),
                ("org.yaml".to_string(), "snakeyaml".to_string()),
            ],
        };
        assert_eq!(
            index.resolve("org.yaml.snakeyaml.Yaml"),
            ["org.yaml:snakeyaml"]
        );
        let jackson = index.resolve("com.fasterxml.jackson.core.databind.X");
        assert_eq!(jackson, ["com.fasterxml.jackson.core:jackson-databind"]);
        assert!(index
            .resolve("com.fasterxml.jackson.core.JsonParser")
            .is_empty());
        assert!(index.resolve("org.yamlish.Other").is_empty());
        let vendor = MavenIndex {
            jars: BTreeMap::new(),
            coordinates: vec![("com.fasterxml".to_string(), "classmate".to_string())],
        };
        assert!(vendor
            .resolve("com.fasterxml.jackson.databind.ObjectMapper")
            .is_empty());
    }

    #[test]
    fn a_class_in_a_jar_beats_the_coordinates() {
        let mut index = MavenIndex::default();
        index
            .coordinates
            .push(("com.google.guava".to_string(), "guava".to_string()));
        index.jars.insert(
            "com.google.common.collect".to_string(),
            BTreeSet::from(["com.google.guava:guava".to_string()]),
        );
        assert_eq!(
            index.resolve("com.google.common.collect.Lists"),
            ["com.google.guava:guava"]
        );
    }

    #[test]
    fn elixir_reads_directives_and_not_docs() {
        let text = "defmodule MyApp.Web do\n  @moduledoc \"\"\"\n  use Doc.Example\n  \"\"\"\n  \
            use Phoenix.LiveView, x: 1\n  alias Ecto.{Changeset, Query}\n  import Plug.Conn\n  use my_macro\nend\n";
        let found = elixir_imports(text);
        assert_eq!(
            names(&found),
            [(5, "Phoenix.LiveView"), (6, "Ecto"), (7, "Plug.Conn")]
        );
        assert_eq!(elixir_own(text), ["MyApp.Web"]);
        let hex = locked(&["phoenix", "phoenix_live_view", "plug"]);
        let resolver = Resolver::Hex(hex.keys().map(|p| (squashed(p), p.clone())).collect());
        assert_eq!(
            resolver.resolve("Phoenix.LiveView.Socket"),
            ["phoenix_live_view"]
        );
        assert_eq!(resolver.resolve("Plug.Conn"), ["plug"]);
    }

    #[test]
    fn swift_reads_imports_and_package_products() {
        let text = "import Foundation\n@testable import Vapor\npublic import NIOCore\nimport struct Logging.Logger\n// import No\n";
        let found = swift_imports(text);
        assert_eq!(
            names(&found),
            [
                (1, "Foundation"),
                (2, "Vapor"),
                (3, "NIOCore"),
                (4, "Logging")
            ]
        );
        let root = tempfile::tempdir().unwrap();
        write(
            root.path(),
            "Package.swift",
            ".product(name: \"Logging\", package: \"swift-log\"),\n",
        );
        let packages = locked(&["github.com/apple/swift-log", "github.com/vapor/vapor"]);
        let resolver = Resolver::build(Ecosystem::Swift, root.path(), &packages);
        assert_eq!(resolver.resolve("Logging"), ["github.com/apple/swift-log"]);
        assert_eq!(resolver.resolve("Vapor"), ["github.com/vapor/vapor"]);
        assert!(resolver.resolve("Foundation").is_empty());
    }

    #[test]
    fn a_chain_starts_at_an_import_line_and_follows_the_lockfile() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "app/models/a.rb", "\n\nrequire 'rails'\n");
        write(root.path(), "vendor/gem/b.rb", "require 'never'\n");
        let packages = locked(&["rails", "rack", "never", "lonely"]);
        let edges = [("rails".to_string(), "rack".to_string())];
        let chains = chains(root.path(), Ecosystem::RubyGems, &packages, edges.iter());
        let repo = RepoId("r".to_string());
        let (chain, site) = chains.chain(&repo, "rack").unwrap();
        assert_eq!(chain, ["rails", "rack"]);
        assert_eq!((site.file.as_str(), site.line), ("app/models/a.rb", 3));
        assert!(
            chains.chain(&repo, "never").is_none(),
            "vendored code is not the project's"
        );
        assert!(chains.chain(&repo, "lonely").is_none());
    }

    #[test]
    fn first_party_names_are_not_packages() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "A.cs", "namespace Acme.Core.Things;\n");
        write(
            root.path(),
            "B.cs",
            "using Acme.Core.Things;\nusing Other.Lib;\n",
        );
        let packages = locked(&["Acme.Core", "Other.Lib"]);
        let chains = chains(root.path(), Ecosystem::NuGet, &packages, std::iter::empty());
        let repo = RepoId("r".to_string());
        assert!(chains.chain(&repo, "Acme.Core").is_none());
        assert!(chains.chain(&repo, "Other.Lib").is_some());
    }
}
