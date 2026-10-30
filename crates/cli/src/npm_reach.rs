//! Build-free npm reachability via a **module import graph** (the spec's R2).
//!
//! Unlike the grep heuristic in [`crate::reach`], this resolves *transitive* reachability: it
//! parses every `require`/`import` specifier in the repo's own source and in each installed
//! `node_modules` package, builds a name-level package→package graph, and asks whether a
//! vulnerable package is reachable from the first-party code. A reached package gets a
//! sound-positive [`ReachVerdict::Reachable`] with a witness import-chain (`your-dep → … →
//! vuln`), exactly like the Go/govulncheck path.
//!
//! **Soundness of the negative.** A `NotReachable` is only emitted under an explicit opt-in
//! (`prune`) AND only when `node_modules` is present (so the transitive graph is complete).
//! Even then it is *best-effort sound*: JavaScript can `require(variableExpr)` or autoload via
//! a framework, which this cannot see, so a `NotReachable` can be wrong for such code — the
//! flag is the caller's acknowledgement of that risk. To stay safe by default:
//!
//! - entry points are **over-approximated** to every first-party file (any file may run), so a
//!   dependency used only by a test/script is still `Reachable`, never falsely pruned;
//! - a package whose executable the project runs (a `package.json` script such as
//!   `"test": "vitest run"`, or a CI workflow step such as `npx stylelint`, resolved through each
//!   installed package's `bin`) is an entry point too: a tool like vitest, jest or stylelint is
//!   never imported, but runs whenever the command does, along with all it imports. A tool
//!   started from elsewhere (a Makefile, another ecosystem's build) stays invisible, which is part
//!   of why the negative is opt-in;
//! - package→package edges are taken from *actual parsed import specifiers* (precise, so the
//!   prune has teeth) — the documented trade for the dynamic-import blind spot.
//!
//! Without `prune`, an unreached package stays [`ReachVerdict::Unknown`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fleetreach_core::{
    DepGraph, Ecosystem, FleetReport, Occurrence, ReachVerdict, Reachability, VulnFinding,
};
use walkdir::WalkDir;

use crate::config::Config;

/// The synthetic graph root whose edges are the first-party imports, so a witness
/// `chain_to(pkg)` reads `[(entry), direct-dep, …, pkg]` and the witness is that minus the root.
const ENTRY: &str = "(entry)";

/// First-party source extensions (the repo's own code).
const SRC_EXTS: &[&str] = &["js", "mjs", "cjs", "ts", "tsx", "jsx"];
/// Extensions parsed inside `node_modules` packages (published packages are usually JS).
const DEP_EXTS: &[&str] = &["js", "mjs", "cjs"];

/// The reachability verdict for one package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    /// Reached from first-party code; the witness is the package import-chain
    /// `[direct-dep, …, package]`.
    Reachable { witness: Vec<String> },
    /// `node_modules` was present and no import path reached the package (prune mode only).
    NotReachable,
    /// Not decided (no `node_modules`, or unreached without prune).
    Unknown,
}

/// Options for [`assess`].
pub struct Options {
    /// Emit `NotReachable` for unreached packages (requires `node_modules`). The explicit
    /// opt-in for the best-effort-sound negative verdict.
    pub prune: bool,
}

/// Annotate every npm finding in `report` with import-graph reachability. Repos are analyzed
/// once and cached. Non-npm findings are left untouched.
pub fn assess(report: &mut FleetReport, config: &Config, opts: &Options) {
    let mut cache: BTreeMap<String, Analysis> = BTreeMap::new();

    for finding in &mut report.vulnerabilities {
        if finding.ecosystem != Ecosystem::Npm {
            continue;
        }
        let Some(verdict) = best_verdict(finding, config, opts, &mut cache) else {
            continue;
        };
        finding.reachable = match &verdict {
            ReachVerdict::Reachable { .. } => Some(true),
            ReachVerdict::NotReachable => Some(false),
            ReachVerdict::Unknown { .. } => None,
        };
        finding.reachability = Some(Reachability {
            verdict,
            config: "import-graph".to_string(),
            engine: "fleetreach-npm-imports".to_string(),
            targets: Vec::new(),
            witness: None,
        });
    }
}

/// The best (most reachable) verdict for a finding across its repos: `Reachable` wins, then
/// `Unknown`, then `NotReachable` (a finding is only pruned if unreached in *every* repo).
fn best_verdict(
    finding: &VulnFinding,
    config: &Config,
    opts: &Options,
    cache: &mut BTreeMap<String, Analysis>,
) -> Option<ReachVerdict> {
    let mut best: Option<Reach> = None;
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
        best = Some(merge(best.take(), analysis.reach(package, opts)));
    }
    best.map(|reach| match reach {
        Reach::Reachable { witness } => ReachVerdict::Reachable { witness },
        Reach::NotReachable => ReachVerdict::NotReachable,
        Reach::Unknown => ReachVerdict::Unknown {
            reason: "import-graph: package not reached from first-party source".into(),
        },
    })
}

/// `Reachable` dominates, then `Unknown`, then `NotReachable`.
fn merge(a: Option<Reach>, b: Reach) -> Reach {
    match (a, b) {
        (Some(Reach::Reachable { witness }), _) | (_, Reach::Reachable { witness }) => {
            Reach::Reachable { witness }
        }
        (Some(Reach::Unknown), _) | (_, Reach::Unknown) => Reach::Unknown,
        (Some(Reach::NotReachable), Reach::NotReachable) | (None, Reach::NotReachable) => {
            Reach::NotReachable
        }
    }
}

/// One repo's import graph: a [`DepGraph`] rooted at the synthetic [`ENTRY`] node (its edges are
/// the first-party imports; the rest are the `node_modules` package→package edges), plus whether
/// `node_modules` was present (required to assert `NotReachable`).
struct Analysis {
    graph: DepGraph,
    has_node_modules: bool,
}

impl Analysis {
    /// The reachability of `package`: a non-empty `chain_to` (via the shared BFS) is `Reachable`
    /// with the witness import-chain (the chain minus the synthetic entry root); otherwise
    /// `NotReachable` under prune + `node_modules`, else `Unknown`.
    fn reach(&self, package: &str, opts: &Options) -> Reach {
        let chain = self.graph.chain_to(package);
        if !chain.is_empty() {
            Reach::Reachable {
                witness: chain.into_iter().skip(1).collect(),
            }
        } else if opts.prune && self.has_node_modules {
            Reach::NotReachable
        } else {
            Reach::Unknown
        }
    }
}

/// Build one repo's import graph: the synthetic [`ENTRY`] root → first-party imports, plus each
/// installed package → the packages it imports (from `node_modules` source).
fn analyze(repo_dir: &Path) -> Analysis {
    let mut graph = DepGraph::new(ENTRY);
    // Over-approximated entry set = every package the repo's own source imports.
    graph.add_edges(ENTRY, first_party_imports(repo_dir));

    let node_modules = repo_dir.join("node_modules");
    let has_node_modules = node_modules.is_dir();
    if has_node_modules {
        // Executables the project's scripts run are entry points like first-party imports.
        let bins = bin_owners(&node_modules);
        graph.add_edges(
            ENTRY,
            command_words(repo_dir)
                .iter()
                .filter_map(|word| bins.get(word).cloned()),
        );
        for (pkg, deps) in package_graph(&node_modules) {
            graph.add_edges(&pkg, deps);
        }
    }
    Analysis {
        graph,
        has_node_modules,
    }
}

/// The set of package names directly imported by the repo's own source (node_modules excluded).
fn first_party_imports(repo_dir: &Path) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for entry in WalkDir::new(repo_dir)
        .into_iter()
        .filter_entry(|e| e.file_name() != "node_modules" && e.file_name() != ".git")
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        if has_ext(entry.path(), SRC_EXTS) {
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                for spec in import_packages(&text) {
                    set.insert(spec);
                }
            }
        }
    }
    set
}

/// Build the name-level package→package import graph by scanning each installed package's source.
fn package_graph(node_modules: &Path) -> BTreeMap<String, BTreeSet<String>> {
    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for pkg_dir in package_dirs(node_modules) {
        let Some(name) = package_name_of(node_modules, &pkg_dir) else {
            continue;
        };
        let mut deps = BTreeSet::new();
        for entry in WalkDir::new(&pkg_dir)
            .into_iter()
            .filter_entry(|e| e.file_name() != "node_modules") // its own nested deps handled as their own nodes
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
        {
            if has_ext(entry.path(), DEP_EXTS) {
                if let Ok(text) = std::fs::read_to_string(entry.path()) {
                    for spec in import_packages(&text) {
                        if spec != name {
                            deps.insert(spec);
                        }
                    }
                }
            }
        }
        graph.entry(name).or_default().extend(deps);
    }
    graph
}

/// Every word of every command the project runs: its `package.json` `scripts`, and its CI
/// workflows (`.github/workflows/*.yml`, where `npx stylelint …` style steps live) — the
/// candidate executable names. Shell operators and quotes split words, and a path
/// (`./node_modules/.bin/jest`) keeps its last component. Arguments, env assignments and the
/// rest of a workflow's YAML come along too; they only match if some installed package ships an
/// executable of that name, which over-approximates (safe).
fn command_words(repo_dir: &Path) -> BTreeSet<String> {
    let mut commands: Vec<String> = Vec::new();
    if let Some(scripts) = std::fs::read_to_string(repo_dir.join("package.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|manifest| manifest.get("scripts").and_then(|s| s.as_object()).cloned())
    {
        commands.extend(
            scripts
                .values()
                .filter_map(|c| c.as_str().map(str::to_string)),
        );
    }
    if let Ok(entries) = std::fs::read_dir(repo_dir.join(".github").join("workflows")) {
        for entry in entries.flatten() {
            if has_ext(&entry.path(), &["yml", "yaml"]) {
                commands.extend(std::fs::read_to_string(entry.path()).ok());
            }
        }
    }
    commands
        .iter()
        .flat_map(|cmd| {
            cmd.split(|c: char| c.is_whitespace() || ";&|()`'\"".contains(c))
                .filter(|w| !w.is_empty())
                .map(|w| w.rsplit('/').next().unwrap_or(w).to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Executable name → the installed package that provides it, from each package's `bin` field:
/// a string names the executable after the package (its unscoped name), an object lists them.
fn bin_owners(node_modules: &Path) -> BTreeMap<String, String> {
    let mut owners = BTreeMap::new();
    for pkg_dir in package_dirs(node_modules) {
        let Some(name) = package_name_of(node_modules, &pkg_dir) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(pkg_dir.join("package.json")) else {
            continue;
        };
        let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        match manifest.get("bin") {
            Some(serde_json::Value::String(_)) => {
                let bin = name.rsplit('/').next().unwrap_or(&name).to_string();
                owners.insert(bin, name.clone());
            }
            Some(serde_json::Value::Object(map)) => {
                for bin in map.keys() {
                    owners.insert(bin.clone(), name.clone());
                }
            }
            _ => {}
        }
    }
    owners
}

/// The top-level package directories under `node_modules` (`foo`, `@scope/bar`), skipping
/// `.bin` and dotfiles.
fn package_dirs(node_modules: &Path) -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();
    let Ok(entries) = std::fs::read_dir(node_modules) else {
        return dirs;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if let Some(scope) = name.strip_prefix('@') {
            let _ = scope;
            // scoped: each subdirectory is a package
            if let Ok(inner) = std::fs::read_dir(&path) {
                for sub in inner.flatten() {
                    if sub.path().is_dir() {
                        dirs.push(sub.path());
                    }
                }
            }
        } else {
            dirs.push(path);
        }
    }
    dirs
}

/// The package name for a directory under `node_modules` (`@scope/name` for scoped).
fn package_name_of(node_modules: &Path, pkg_dir: &Path) -> Option<String> {
    let rel = pkg_dir.strip_prefix(node_modules).ok()?;
    let s = rel.to_string_lossy().replace('\\', "/");
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Extract the **bare** package names imported by a JS/TS source text: the module specifier of
/// every `require('x')`, `import … from 'x'`, `import('x')`, `export … from 'x'`, reduced to its
/// package name (`lodash/fp` → `lodash`, `@scope/p/sub` → `@scope/p`). Relative/absolute
/// specifiers are skipped. Loose by design (a spurious match only adds a graph edge, which over-
/// approximates reachability — safe).
fn import_packages(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = text.as_bytes();
    for (kw, off) in keyword_hits(text) {
        // Find the next single- or double-quoted string after the keyword.
        if let Some(spec) = quoted_after(bytes, off + kw) {
            if let Some(pkg) = bare_package(&spec) {
                out.insert(pkg);
            }
        }
    }
    out
}

/// Offsets just past each import-introducing keyword occurrence (`require(`, `from `, `import(`).
fn keyword_hits(text: &str) -> Vec<(usize, usize)> {
    let mut hits = Vec::new();
    for kw in ["require(", "from ", "import(", "from\t"] {
        let mut from = 0;
        while let Some(i) = text[from..].find(kw) {
            let at = from + i;
            hits.push((kw.len(), at));
            from = at + kw.len();
        }
    }
    hits
}

/// The contents of the first `'…'`/`"…"` string starting within a few bytes of `start`
/// (skipping whitespace/`(`), or `None`.
fn quoted_after(bytes: &[u8], start: usize) -> Option<String> {
    let mut i = start;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'(') {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let quote = bytes[i];
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let mut j = i + 1;
    while j < bytes.len() && bytes[j] != quote {
        j += 1;
    }
    if j >= bytes.len() {
        return None;
    }
    std::str::from_utf8(&bytes[i + 1..j])
        .ok()
        .map(str::to_string)
}

/// The package name of a module specifier, or `None` for a relative/absolute path.
fn bare_package(spec: &str) -> Option<String> {
    if spec.is_empty() || spec.starts_with('.') || spec.starts_with('/') {
        return None;
    }
    if let Some(scoped) = spec.strip_prefix('@') {
        let mut parts = scoped.splitn(3, '/');
        let scope = parts.next()?;
        let name = parts.next()?;
        if scope.is_empty() || name.is_empty() {
            return None;
        }
        Some(format!("@{scope}/{name}"))
    } else {
        spec.split('/')
            .next()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }
}

fn has_ext(path: &Path, exts: &[&str]) -> bool {
    path.extension()
        .and_then(|x| x.to_str())
        .is_some_and(|x| exts.contains(&x))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn import_packages_extracts_bare_specifiers() {
        let src = r#"
            const _ = require('lodash');
            import x from "react";
            import { a } from 'lodash/fp';
            const d = await import('@scope/pkg/sub');
            export { y } from './local';      // relative, skipped
            const e = require('./util');      // relative, skipped
        "#;
        let pkgs = import_packages(src);
        assert!(pkgs.contains("lodash"));
        assert!(pkgs.contains("react"));
        assert!(pkgs.contains("@scope/pkg"));
        assert!(!pkgs
            .iter()
            .any(|p| p.contains("local") || p.contains("util")));
    }

    #[test]
    fn command_words_split_scripts_and_workflows_into_executable_candidates() {
        let dir = std::env::temp_dir().join(format!("fr-npm-scripts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{ "scripts": {
                "test": "TZ=UTC vitest run && npm run lint",
                "lint": "npx eslint 'js/**' | tee out.txt",
                "css": "./node_modules/.bin/stylelint css/**;(prettier --check .)"
            } }"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join(".github/workflows")).unwrap();
        std::fs::write(
            dir.join(".github/workflows/ci.yml"),
            "jobs:\n  lint:\n    steps:\n      - run: npx tsc --noEmit\n",
        )
        .unwrap();
        let words = command_words(&dir);
        for want in [
            "vitest",
            "npx",
            "eslint",
            "stylelint",
            "prettier",
            "tee",
            "tsc",
        ] {
            assert!(words.contains(want), "missing {want}: {words:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn bare_package_reduces_subpaths_and_scopes() {
        assert_eq!(bare_package("lodash"), Some("lodash".into()));
        assert_eq!(bare_package("lodash/fp"), Some("lodash".into()));
        assert_eq!(bare_package("@scope/pkg"), Some("@scope/pkg".into()));
        assert_eq!(bare_package("@scope/pkg/sub"), Some("@scope/pkg".into()));
        assert_eq!(bare_package("./rel"), None);
        assert_eq!(bare_package("/abs"), None);
    }

    #[test]
    fn analysis_reach_drops_synthetic_root_from_witness() {
        // entry -> express -> body-parser -> qs ; entry -> express (direct).
        let mut graph = DepGraph::new(ENTRY);
        graph.add_edges(ENTRY, ["express".to_string()]);
        graph.add_edges("express", ["body-parser".to_string()]);
        graph.add_edges("body-parser", ["qs".to_string()]);
        let a = Analysis {
            graph,
            has_node_modules: true,
        };
        let opts = Options { prune: true };
        assert_eq!(
            a.reach("qs", &opts),
            Reach::Reachable {
                witness: vec!["express".into(), "body-parser".into(), "qs".into()]
            }
        );
        assert_eq!(
            a.reach("express", &opts),
            Reach::Reachable {
                witness: vec!["express".into()]
            }
        );
        // unreached + prune + node_modules -> NotReachable
        assert_eq!(a.reach("lodash", &opts), Reach::NotReachable);
        // unreached without prune -> Unknown
        assert_eq!(a.reach("lodash", &Options { prune: false }), Reach::Unknown);
    }

    #[test]
    fn merge_prefers_reachable_then_unknown() {
        let r = || Reach::Reachable {
            witness: vec!["a".into()],
        };
        assert!(matches!(
            merge(Some(Reach::NotReachable), r()),
            Reach::Reachable { .. }
        ));
        assert!(matches!(
            merge(Some(r()), Reach::NotReachable),
            Reach::Reachable { .. }
        ));
        assert!(matches!(
            merge(Some(Reach::NotReachable), Reach::Unknown),
            Reach::Unknown
        ));
        assert!(matches!(
            merge(Some(Reach::NotReachable), Reach::NotReachable),
            Reach::NotReachable
        ));
    }
}
