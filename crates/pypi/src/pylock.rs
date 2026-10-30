//! Read `pylock.toml` / `pylock.<name>.toml`, the standard Python lockfile ([PEP 751]),
//! written by `uv export --format pylock.toml`, `pip lock` and pdm.
//!
//! Every `[[packages]]` entry with a `version` is an installed registry release, so the file is
//! full coverage. Entries without a `version` (a `vcs`, `directory` or `archive` source) have
//! no registry release to match and are counted, not matched.
//!
//! The format marks neither direct nor dev packages, so both come from a sibling
//! `pyproject.toml`: `[project].dependencies` and `optional-dependencies` (plus Poetry's tables)
//! are direct, `[dependency-groups]` direct dev. When entries carry the optional
//! `[[packages.dependencies]]`, those edges give dependency paths and carry dev scope to what
//! only dev groups reach.
//!
//! [PEP 751]: https://packaging.python.org/en/latest/specifications/pylock-toml/

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fleetreach_core::DepGraph;
use serde::Deserialize;

use crate::error::PyPiError;
use crate::lockfile::{poetry_direct_set, requirement_name, InstalledPackage};
use crate::version::normalize_name;

const ROOT: &str = "(root)";

/// The `pylock.toml` and `pylock.<name>.toml` files directly in `dir`, sorted.
pub(crate) fn pylock_files(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name == "pylock.toml"
                || (name.starts_with("pylock.") && name.ends_with(".toml") && name.len() > 12)
        })
        .map(|e| e.path())
        .collect();
    found.sort();
    found
}

#[derive(Deserialize)]
struct PyLock {
    /// Required by the spec; its absence means this is not a pylock file.
    #[serde(rename = "lock-version")]
    #[allow(dead_code)]
    lock_version: String,
    #[serde(default)]
    packages: Vec<PyLockPackage>,
}

#[derive(Deserialize)]
struct PyLockPackage {
    name: String,
    version: Option<String>,
    #[serde(default)]
    dependencies: Vec<PyLockDep>,
    directory: Option<PyLockDirectory>,
}

impl PyLockPackage {
    /// The locked project itself (`directory = { path = "." }`): not a dependency.
    fn is_project(&self) -> bool {
        self.directory
            .as_ref()
            .is_some_and(|d| matches!(d.path.trim_end_matches('/'), "." | ""))
    }
}

#[derive(Deserialize)]
struct PyLockDirectory {
    #[serde(default)]
    path: String,
}

#[derive(Deserialize)]
struct PyLockDep {
    name: Option<String>,
}

/// Packages (with the count of non-registry entries) and the dependency graph of every
/// pylock file in `dir`.
///
/// # Errors
///
/// A pylock file that cannot be read or is not valid pylock TOML fails closed.
pub(crate) fn read_dir(dir: &Path) -> Result<(Vec<InstalledPackage>, DepGraph, u32), PyPiError> {
    let (runtime, dev_direct) = pyproject_direct(dir);
    let mut packages = Vec::new();
    let mut graph = DepGraph::new(ROOT);
    let mut non_registry = 0;
    for path in pylock_files(dir) {
        let body = std::fs::read_to_string(&path).map_err(|e| PyPiError::db(&path, e))?;
        let (pkgs, file_graph_edges, skipped) =
            parse(&body, &runtime, &dev_direct).map_err(|e| PyPiError::db(&path, e))?;
        packages.extend(pkgs);
        for (from, tos) in file_graph_edges {
            graph.add_edges(&from, tos);
        }
        non_registry += skipped;
    }
    Ok((packages, graph, non_registry))
}

type Edges = BTreeMap<String, BTreeSet<String>>;

/// Parse one pylock file given the direct runtime and direct dev names (normalized).
fn parse(
    body: &str,
    runtime: &BTreeSet<String>,
    dev_direct: &BTreeSet<String>,
) -> Result<(Vec<InstalledPackage>, Edges, u32), toml::de::Error> {
    let lock: PyLock = toml::from_str(body)?;
    let mut edges: Edges = BTreeMap::new();
    for pkg in &lock.packages {
        let from = normalize_name(&pkg.name);
        let tos = pkg
            .dependencies
            .iter()
            .filter_map(|d| d.name.as_deref())
            .map(normalize_name);
        edges.entry(from).or_default().extend(tos);
    }
    let dev_only_direct: Vec<String> = dev_direct.difference(runtime).cloned().collect();
    let has_edges = edges.values().any(|tos| !tos.is_empty());
    // With edges, dev = reached from dev-only direct packages and not from runtime ones.
    // Without, only the dev-only direct packages themselves are known to be dev.
    let runtime_reach = closure(&edges, runtime.iter().cloned());
    let dev_reach = if has_edges {
        closure(&edges, dev_only_direct.iter().cloned())
    } else {
        dev_only_direct.iter().cloned().collect()
    };

    let mut out = Vec::new();
    let mut non_registry = 0;
    for pkg in lock.packages {
        let key = normalize_name(&pkg.name);
        if pkg.is_project() {
            continue;
        }
        let Some(version) = pkg.version else {
            non_registry += 1;
            continue;
        };
        out.push(InstalledPackage {
            direct: runtime.contains(&key) || dev_direct.contains(&key),
            dev: dev_reach.contains(&key) && !runtime_reach.contains(&key),
            name: key,
            version,
        });
    }
    let mut graph_edges: Edges = edges;
    graph_edges
        .entry(ROOT.to_string())
        .or_default()
        .extend(runtime.iter().chain(dev_direct).cloned());
    Ok((out, graph_edges, non_registry))
}

/// Everything reachable from `roots` (roots included).
fn closure(edges: &Edges, roots: impl Iterator<Item = String>) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<String> = roots.collect();
    while let Some(name) = stack.pop() {
        if seen.insert(name.clone()) {
            if let Some(tos) = edges.get(&name) {
                stack.extend(tos.iter().cloned());
            }
        }
    }
    seen
}

/// Direct runtime names (PEP 621 dependencies and extras, Poetry tables) and direct dev names
/// (PEP 735 `[dependency-groups]`) from a sibling `pyproject.toml`, normalized. Empty when it
/// is absent or unreadable: direct and dev are reporting hints, never a matching gate.
fn pyproject_direct(dir: &Path) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut runtime = poetry_direct_set(dir);
    let mut dev = BTreeSet::new();
    let Ok(body) = std::fs::read_to_string(dir.join("pyproject.toml")) else {
        return (runtime, dev);
    };
    let Ok(value) = toml::from_str::<toml::Value>(&body) else {
        return (runtime, dev);
    };
    let names = |v: Option<&toml::Value>| -> Vec<String> {
        v.and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .filter_map(requirement_name)
            .map(normalize_name)
            .collect()
    };
    if let Some(extras) = value
        .get("project")
        .and_then(|p| p.get("optional-dependencies"))
        .and_then(toml::Value::as_table)
    {
        for deps in extras.values() {
            runtime.extend(names(Some(deps)));
        }
    }
    if let Some(groups) = value
        .get("dependency-groups")
        .and_then(toml::Value::as_table)
    {
        for deps in groups.values() {
            dev.extend(names(Some(deps)));
        }
    }
    (runtime, dev)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    fn rows(pkgs: &[InstalledPackage]) -> Vec<(&str, &str, bool, bool)> {
        pkgs.iter()
            .map(|p| (p.name.as_str(), p.version.as_str(), p.direct, p.dev))
            .collect()
    }

    const UV_EXPORT: &str = r#"
# This file was autogenerated by uv via the following command:
#    uv export --format pylock.toml -o pylock.toml
lock-version = "1.0"
created-by = "uv"
requires-python = ">=3.10"

[[packages]]
name = "Flask"
version = "2.0.1"
index = "https://pypi.org/simple"
wheels = [{ url = "https://files.pythonhosted.org/f.whl", hashes = { sha256 = "aa" } }]

[[packages]]
name = "jinja2"
version = "3.1.6"
index = "https://pypi.org/simple"

[[packages]]
name = "pytest"
version = "8.0.0"
index = "https://pypi.org/simple"

[[packages]]
name = "colorama"
version = "0.4.6"
marker = "sys_platform == 'win32'"
index = "https://pypi.org/simple"

[[packages]]
name = "mylib"
directory = { path = "libs/mylib", editable = true }

[[packages]]
name = "demo"
directory = { path = ".", editable = true }
"#;

    #[test]
    fn uv_export_reads_every_versioned_package() {
        let (pkgs, edges, skipped) = parse(UV_EXPORT, &set(&["flask"]), &set(&["pytest"])).unwrap();
        assert_eq!(
            rows(&pkgs),
            vec![
                ("flask", "2.0.1", true, false),
                ("jinja2", "3.1.6", false, false),
                ("pytest", "8.0.0", true, true),
                ("colorama", "0.4.6", false, false),
            ]
        );
        assert_eq!(skipped, 1);
        assert_eq!(edges[ROOT], set(&["flask", "pytest"]));
    }

    #[test]
    fn dependency_edges_carry_dev_scope_and_paths() {
        let body = r#"
lock-version = "1.0"
[[packages]]
name = "flask"
version = "2.0.1"
dependencies = [{ name = "jinja2" }]
[[packages]]
name = "jinja2"
version = "3.1.6"
[[packages]]
name = "pytest"
version = "8.0.0"
dependencies = [{ name = "pluggy" }, { name = "jinja2" }]
[[packages]]
name = "pluggy"
version = "1.5.0"
"#;
        let (pkgs, edges, _) = parse(body, &set(&["flask"]), &set(&["pytest"])).unwrap();
        assert_eq!(
            rows(&pkgs),
            vec![
                ("flask", "2.0.1", true, false),
                ("jinja2", "3.1.6", false, false),
                ("pytest", "8.0.0", true, true),
                ("pluggy", "1.5.0", false, true),
            ]
        );
        let mut graph = DepGraph::new(ROOT);
        for (from, tos) in edges {
            graph.add_edges(&from, tos);
        }
        assert_eq!(graph.chain_to("pluggy"), vec![ROOT, "pytest", "pluggy"]);
    }

    #[test]
    fn not_a_pylock_file_fails_closed() {
        assert!(parse("[[packages]]\nname = \"a\"\n", &set(&[]), &set(&[])).is_err());
        assert!(parse(
            "lock-version = \"1.0\"\npackages = 3\n",
            &set(&[]),
            &set(&[])
        )
        .is_err());
    }

    #[test]
    fn finds_named_lock_files() {
        let dir = std::env::temp_dir().join(format!("fr-pylock-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for f in [
            "pylock.toml",
            "pylock.dev.toml",
            "pylock.toml.bak",
            "pyproject.toml",
        ] {
            std::fs::write(dir.join(f), "").unwrap();
        }
        let names: Vec<String> = pylock_files(&dir)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["pylock.dev.toml", "pylock.toml"]);
    }

    #[test]
    fn pyproject_supplies_runtime_extras_and_groups() {
        let dir = std::env::temp_dir().join(format!("fr-pylock-pyproject-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("pyproject.toml"),
            "[project]\nname = \"demo\"\ndependencies = [\"Flask==2.0.1\"]\n\
             [project.optional-dependencies]\nsocks = [\"PySocks>=1\"]\n\
             [dependency-groups]\ndev = [\"pytest\", {include-group = \"lint\"}]\nlint = [\"ruff\"]\n",
        )
        .unwrap();
        let (runtime, dev) = pyproject_direct(&dir);
        assert_eq!(runtime, set(&["flask", "pysocks"]));
        assert_eq!(dev, set(&["pytest", "ruff"]));
    }
}
