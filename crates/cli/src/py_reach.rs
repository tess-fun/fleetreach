//! Build-free PyPI reachability via a **package import graph**, the Python sibling of
//! [`crate::npm_reach`].
//!
//! It parses every `import` in the repo's own source and, when a virtualenv is present, in
//! each installed distribution, resolves module names to distributions through their
//! `*.dist-info/RECORD` (so `yaml` is PyYAML and `google.cloud.storage` is
//! google-cloud-storage), and asks whether a vulnerable distribution is reachable from the
//! first-party code. A reached distribution gets a sound-positive [`ReachVerdict::Reachable`]
//! with a witness import-chain (`your-dep → … → vuln`).
//!
//! **Positive-only.** Python imports dynamically (`__import__(name)`, plugin entry points,
//! framework autoloading) often enough that an unreached distribution is never claimed
//! `NotReachable`; it stays [`ReachVerdict::Unknown`]. A feasibility study on real
//! applications found an import-level negative would set aside only ~3% of findings, so a
//! prune mode is not worth its risk here. To keep the positive side complete:
//!
//! - every first-party file is an entry point (any file may run);
//! - every installed distribution is analysed, not only those on the lockfile's reported
//!   dependency path — a package is often loaded by a dependency that is not on that path
//!   (an optional import, a second dependent);
//! - a distribution that loads plugins (`entry_points(…)`) gets an edge to every distribution
//!   that registers one, since its `entry_points.txt` names code that may be imported.
//!
//! Without a virtualenv, first-party imports still resolve by name (`import requests` →
//! `requests`), so a direct dependency the code imports gets a one-hop witness.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fleetreach_core::{DepGraph, Ecosystem, FleetReport, Occurrence, ReachVerdict, Reachability};
use fleetreach_pypi::normalize_name;
use rayon::prelude::*;

use crate::config::Config;

/// The synthetic graph root whose edges are the first-party imports.
const ENTRY: &str = "(entry)";

/// Directories that never hold the project's own source or an environment we read.
const SKIPPED_DIRS: &[&str] = &["node_modules", ".git", "__pycache__", ".tox", ".nox"];

/// Entry-point groups that are executables, not plugins loaded by library code.
const SCRIPT_GROUPS: &[&str] = &["console_scripts", "gui_scripts"];

/// Annotate every PyPI finding in `report` with import-graph reachability. A reached finding
/// becomes `Reachable` with a witness; an unreached one keeps `reachable` as the heuristic left
/// it and records that the import graph did not reach it. Repos are analyzed once and cached.
pub fn assess(report: &mut FleetReport, config: &Config) {
    let mut cache: BTreeMap<String, Analysis> = BTreeMap::new();
    for finding in &mut report.vulnerabilities {
        if finding.ecosystem != Ecosystem::Pypi {
            continue;
        }
        let mut witness: Option<Vec<String>> = None;
        let mut analysed = false;
        for occ in &finding.occurrences {
            let Occurrence::InRepo { repo, package, .. } = occ else {
                continue;
            };
            let Some(repo_cfg) = config.repos.iter().find(|r| r.id.0 == repo.0) else {
                continue;
            };
            let analysis = cache
                .entry(repo.0.clone())
                .or_insert_with(|| analyze(&repo_cfg.path));
            analysed = true;
            let chain = analysis.graph.chain_to(&normalize_name(package));
            // Keep the shortest witness across repos.
            if chain.len() > 1 && witness.as_ref().is_none_or(|w| chain.len() - 1 < w.len()) {
                witness = Some(chain.into_iter().skip(1).collect());
            }
        }
        if !analysed {
            continue;
        }
        let verdict = match witness {
            Some(witness) => {
                finding.reachable = Some(true);
                ReachVerdict::Reachable { witness }
            }
            None => ReachVerdict::Unknown {
                reason: "import-graph: package not reached from first-party imports".into(),
            },
        };
        finding.reachability = Some(Reachability {
            verdict,
            config: "import-graph".to_string(),
            engine: "fleetreach-pypi-imports".to_string(),
            targets: Vec::new(),
            witness: None,
        });
    }
}

/// One repo's import graph, rooted at [`ENTRY`].
struct Analysis {
    graph: DepGraph,
}

/// Build one repo's graph: [`ENTRY`] → the distributions its own source imports, plus each
/// installed distribution → the distributions it imports.
fn analyze(repo_dir: &Path) -> Analysis {
    let layout = Layout::discover(repo_dir);
    let index = ModuleIndex::build(&layout.site_dirs);

    let mut graph = DepGraph::new(ENTRY);
    let mut first_party = BTreeSet::new();
    for file in &layout.source_files {
        if let Ok(text) = std::fs::read_to_string(file) {
            for module in imported_modules(&text) {
                let top = module.split('.').next().unwrap_or(&module);
                if !layout.own_modules.contains(top) {
                    first_party.extend(index.resolve_or_guess(&module));
                }
            }
        }
    }
    graph.add_edges(ENTRY, first_party);

    let edges: Vec<(String, BTreeSet<String>)> = index
        .files
        .par_iter()
        .map(|(dist, files)| {
            let mut deps = BTreeSet::new();
            let mut loads_plugins = false;
            for file in files {
                let Ok(text) = std::fs::read_to_string(file) else {
                    continue;
                };
                for module in imported_modules(&text) {
                    deps.extend(index.resolve(&module));
                }
                loads_plugins |= calls_entry_points(&text);
            }
            if loads_plugins {
                deps.extend(index.plugin_providers.iter().cloned());
            }
            deps.remove(dist);
            (dist.clone(), deps)
        })
        .collect();
    for (dist, deps) in edges {
        graph.add_edges(&dist, deps);
    }
    Analysis { graph }
}

/// Where a repo's first-party Python source and installed environments are.
struct Layout {
    source_files: Vec<PathBuf>,
    site_dirs: Vec<PathBuf>,
    /// Top-level module names the repo itself provides: every entry at the repo root and
    /// directly under a `src/` directory (`posthog`, `products`, …). An import of one of these
    /// is first-party code, never a distribution.
    own_modules: BTreeSet<String>,
}

impl Layout {
    /// Walk `repo_dir`: a directory holding `pyvenv.cfg` is a virtualenv, whose
    /// `site-packages` is read as an environment and which is not searched for source; every
    /// other `.py` file is first-party.
    fn discover(repo_dir: &Path) -> Layout {
        let mut layout = Layout {
            source_files: Vec::new(),
            site_dirs: Vec::new(),
            own_modules: BTreeSet::new(),
        };
        let mut stack = vec![repo_dir.to_path_buf()];
        while let Some(dir) = stack.pop() {
            if dir.join("pyvenv.cfg").is_file() {
                layout.site_dirs.extend(venv_site_packages(&dir));
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(kind) = entry.file_type() else {
                    continue;
                };
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if dir == repo_dir || dir.file_name().is_some_and(|d| d == "src") {
                    let module = name.strip_suffix(".py").unwrap_or(&name);
                    if is_identifier(module) {
                        layout.own_modules.insert(module.to_string());
                    }
                }
                if kind.is_dir() {
                    if !SKIPPED_DIRS.contains(&name.as_ref()) {
                        stack.push(entry.path());
                    }
                } else if kind.is_file() && name.ends_with(".py") {
                    layout.source_files.push(entry.path());
                }
            }
        }
        layout.source_files.sort();
        layout.site_dirs.sort();
        layout
    }
}

/// The `site-packages` directories of a virtualenv (`lib/python3.X/site-packages` on Unix,
/// `Lib/site-packages` on Windows).
fn venv_site_packages(venv: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let windows = venv.join("Lib").join("site-packages");
    if windows.is_dir() {
        out.push(windows);
    }
    if let Ok(entries) = std::fs::read_dir(venv.join("lib")) {
        for entry in entries.flatten() {
            let site = entry.path().join("site-packages");
            if site.is_dir() {
                out.push(site);
            }
        }
    }
    out
}

/// Installed distributions, keyed by normalized name.
#[derive(Default)]
struct ModuleIndex {
    /// Dotted module path (and every package prefix of one) → the distributions providing it.
    /// A namespace prefix (`google`) maps to several.
    modules: BTreeMap<String, BTreeSet<String>>,
    /// Distribution → its installed `.py` files.
    files: BTreeMap<String, Vec<PathBuf>>,
    /// Distributions whose `entry_points.txt` registers a plugin (a non-script group).
    plugin_providers: BTreeSet<String>,
}

impl ModuleIndex {
    fn build(site_dirs: &[PathBuf]) -> ModuleIndex {
        let mut index = ModuleIndex::default();
        for site in site_dirs {
            let Ok(entries) = std::fs::read_dir(site) else {
                continue;
            };
            for entry in entries.flatten() {
                let dir_name = entry.file_name().to_string_lossy().into_owned();
                let Some(stem) = dir_name.strip_suffix(".dist-info") else {
                    continue;
                };
                // `<name>-<version>`; the name's own dashes are escaped to `_` on disk.
                let dist = normalize_name(stem.split('-').next().unwrap_or(stem));
                let info = entry.path();
                if let Ok(record) = std::fs::read_to_string(info.join("RECORD")) {
                    index.add_record(site, &dist, &record);
                }
                if let Ok(eps) = std::fs::read_to_string(info.join("entry_points.txt")) {
                    if registers_plugin(&eps) {
                        index.plugin_providers.insert(dist.clone());
                    }
                }
            }
        }
        index
    }

    fn add_record(&mut self, site: &Path, dist: &str, record: &str) {
        for line in record.lines() {
            let path = record_path(line);
            if path.starts_with("..") || path.contains(".dist-info/") {
                continue; // scripts outside site-packages, metadata
            }
            let Some(module) = module_of(path) else {
                continue;
            };
            let parts: Vec<&str> = module.split('.').collect();
            for end in 1..=parts.len() {
                self.modules
                    .entry(parts[..end].join("."))
                    .or_default()
                    .insert(dist.to_string());
            }
            if path.ends_with(".py") {
                self.files
                    .entry(dist.to_string())
                    .or_default()
                    .push(site.join(path));
            }
        }
    }

    /// The distributions providing `module`: its longest installed prefix.
    fn resolve(&self, module: &str) -> BTreeSet<String> {
        let parts: Vec<&str> = module.split('.').collect();
        (1..=parts.len())
            .rev()
            .find_map(|end| self.modules.get(&parts[..end].join(".")))
            .cloned()
            .unwrap_or_default()
    }

    /// [`resolve`](Self::resolve) for a third-party import, adding name guesses when no
    /// installed distribution owns the module itself (no virtualenv, not installed, or only a
    /// shared namespace such as `google` matched): the top-level name, the second component,
    /// and the two joined, normalized — so `google.protobuf` guesses `protobuf` and
    /// `google-protobuf`, and `azure.core` guesses `azure-core`. Deeper components are not
    /// guessed: a submodule name is rarely a distribution and would invent witnesses.
    fn resolve_or_guess(&self, module: &str) -> BTreeSet<String> {
        let mut found = self.resolve(module);
        if found.len() == 1 {
            return found;
        }
        let parts: Vec<&str> = module.split('.').take(2).collect();
        found.extend(parts.iter().map(|p| normalize_name(p)));
        if parts.len() == 2 {
            found.insert(normalize_name(&parts.join(".")));
        }
        found
    }
}

/// The path column of a `RECORD` CSV line (quoted when it contains a comma).
fn record_path(line: &str) -> &str {
    if let Some(rest) = line.strip_prefix('"') {
        rest.split('"').next().unwrap_or("")
    } else {
        line.split(',').next().unwrap_or("")
    }
}

/// The dotted module a site-packages file provides: `pkg/sub/__init__.py` → `pkg.sub`,
/// `pkg/mod.py` → `pkg.mod`, `ext.cpython-312-darwin.so` → `ext`. `None` for non-modules.
fn module_of(path: &str) -> Option<String> {
    let path = path.replace('\\', "/");
    let stem = if let Some(stem) = path.strip_suffix(".py") {
        stem.to_string()
    } else if path.ends_with(".so") || path.ends_with(".pyd") {
        let (dir, file) = path
            .rsplit_once('/')
            .map_or(("", path.as_str()), |(d, f)| (d, f));
        let name = file.split('.').next()?;
        if dir.is_empty() {
            name.to_string()
        } else {
            format!("{dir}/{name}")
        }
    } else {
        return None;
    };
    let stem = stem.strip_suffix("/__init__").unwrap_or(&stem);
    let parts: Vec<&str> = stem.split('/').collect();
    parts
        .iter()
        .all(|p| is_identifier(p))
        .then(|| parts.join("."))
}

/// Whether an `entry_points.txt` registers anything other than executables.
fn registers_plugin(text: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim();
        l.starts_with('[')
            && l.ends_with(']')
            && !SCRIPT_GROUPS.contains(&l.trim_matches(|c| c == '[' || c == ']').trim())
    })
}

/// Whether source loads entry-point plugins.
fn calls_entry_points(text: &str) -> bool {
    text.contains("entry_points(") || text.contains("iter_entry_points(")
}

/// The absolute module names a Python source text imports: `import a.b as c, d`,
/// `from a.b import c` (both `a.b` and `a.b.c`, which may be a submodule), and literal
/// `__import__("x")` / `import_module("x")`. Relative imports are skipped (first-party or the
/// same distribution). Loose by design: a spurious match only adds an edge, which
/// over-approximates reachability — the safe direction.
fn imported_modules(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("import ") {
            for item in rest.split(',') {
                let name = item.split_whitespace().next().unwrap_or("");
                if is_dotted(name) {
                    out.insert(name.to_string());
                }
            }
        } else if let Some(rest) = t.strip_prefix("from ") {
            let mut words = rest.split_whitespace();
            let module = words.next().unwrap_or("");
            if !is_dotted(module) || words.next() != Some("import") {
                continue;
            }
            out.insert(module.to_string());
            let names = rest.split_once(" import ").map_or("", |(_, n)| n);
            for item in names.split(',') {
                let name = item
                    .trim_matches(|c: char| c == '(' || c == ')' || c.is_whitespace())
                    .split_whitespace()
                    .next()
                    .unwrap_or("");
                if is_identifier(name) {
                    out.insert(format!("{module}.{name}"));
                }
            }
        }
        for call in ["__import__(", "import_module("] {
            let mut from = 0;
            while let Some(i) = line[from..].find(call) {
                let at = from + i + call.len();
                if let Some(name) = quoted_at(&line[at..]) {
                    if is_dotted(name) {
                        out.insert(name.to_string());
                    }
                }
                from = at;
            }
        }
    }
    out
}

/// The contents of a `'…'`/`"…"` literal at the start of `s` (after whitespace).
fn quoted_at(s: &str) -> Option<&str> {
    let s = s.trim_start();
    let quote = s.chars().next().filter(|c| *c == '\'' || *c == '"')?;
    let body = &s[1..];
    body.find(quote).map(|end| &body[..end])
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_alphabetic() || c == '_')
        && chars.all(|c| c.is_alphanumeric() || c == '_')
}

/// An absolute dotted module name (`a`, `a.b.c`); relative (`.x`) is not.
fn is_dotted(s: &str) -> bool {
    !s.is_empty() && s.split('.').all(is_identifier)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn imported_modules_covers_the_import_forms() {
        let src = r#"
import os, yaml as y
import google.cloud.storage
from requests.adapters import HTTPAdapter
from google.cloud import storage, bigquery as bq
from . import local
from .sibling import thing
    import lazily_imported
mod = importlib.import_module("plugins.x")
"#;
        let m = imported_modules(src);
        for want in [
            "os",
            "yaml",
            "google.cloud.storage",
            "requests.adapters",
            "requests.adapters.HTTPAdapter",
            "google.cloud.storage",
            "google.cloud.bigquery",
            "lazily_imported",
            "plugins.x",
        ] {
            assert!(m.contains(want), "missing {want}: {m:?}");
        }
        assert!(!m
            .iter()
            .any(|x| x.contains("local") || x.contains("sibling")));
    }

    #[test]
    fn record_maps_modules_including_namespaces_and_irregular_names() {
        let mut index = ModuleIndex::default();
        let site = Path::new("/site");
        index.add_record(site, "pyyaml", "yaml/__init__.py,sha256=x,1\nyaml/_yaml.cpython-312-darwin.so,,\nPyYAML-6.0.dist-info/RECORD,,\n");
        index.add_record(
            site,
            "google-cloud-storage",
            "google/cloud/storage/__init__.py,,\n",
        );
        index.add_record(
            site,
            "google-cloud-bigquery",
            "google/cloud/bigquery/client.py,,\n",
        );
        index.add_record(site, "x", "../../../bin/x,,\n\"weird,name.py\",,\n");
        assert_eq!(
            index.resolve("yaml.loader"),
            BTreeSet::from(["pyyaml".to_string()])
        );
        assert_eq!(
            index.resolve("google.cloud.storage.blob"),
            BTreeSet::from(["google-cloud-storage".to_string()])
        );
        // A bare namespace import may come from either: over-approximate to both.
        assert_eq!(index.resolve("google.cloud").len(), 2);
        assert!(index.resolve("requests").is_empty());
        let guesses = index.resolve_or_guess("google.protobuf.message");
        for want in ["google", "protobuf", "google-protobuf"] {
            assert!(guesses.contains(want), "{guesses:?}");
        }
        assert!(
            !guesses.contains("message"),
            "deep components are not guessed"
        );
        assert!(index
            .resolve_or_guess("Flask_Login")
            .contains("flask-login"));
        // Installed modules resolve exactly; no guessing.
        assert_eq!(
            index.resolve_or_guess("yaml"),
            BTreeSet::from(["pyyaml".to_string()])
        );
        assert_eq!(index.files["pyyaml"], vec![site.join("yaml/__init__.py")]);
    }

    #[test]
    fn plugin_groups_exclude_scripts() {
        assert!(registers_plugin(
            "[virtualenv.seed]\npip = virtualenv.seed.embed.pip_invoke:PipInvoke\n"
        ));
        assert!(!registers_plugin(
            "[console_scripts]\nblack = black:patched_main\n"
        ));
    }
}
