//! Parse a resolved Python lockfile into a flat, deduplicated set of installed
//! packages — the input the OSV matcher scans. Read straight from the lockfile, so it
//! needs **no Python toolchain and no network** (the same reason the Rust path reads
//! `Cargo.lock`): a lockfile already pins every package to an exact version across the
//! full transitive tree.
//!
//! Python has no single lockfile, so v1 supports the three that carry a fully-pinned
//! exact transitive tree, in this detection priority:
//! 1. `uv.lock` (TOML) — self-describing: the root project's `dependencies` name the
//!    direct deps, so no sibling manifest is read.
//! 2. `poetry.lock` (TOML) — the `[[package]]` array has the resolved tree; `direct` is
//!    read best-effort from a sibling `pyproject.toml`.
//! 3. `Pipfile.lock` (JSON) — the flat `default`/`develop` resolved set; `direct` is
//!    read best-effort from a sibling `Pipfile`.
//!
//! A lockfile that is present but unparseable is a hard error (the caller fails the repo
//! closed), never a silent empty parse — that would be a false-clean. `direct` is only a
//! reporting hint (it never gates a match), so a missing/odd sibling manifest degrades to
//! "all transitive" rather than failing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fleetreach_core::DepGraph;
use serde::Deserialize;

use crate::error::PyPiError;
use crate::version::normalize_name;

/// One resolved package from a lockfile: its project name (verbatim, for display), exact
/// installed version, and whether the project depends on it **directly** (it is named in
/// the manifest) as opposed to pulling it in transitively.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub direct: bool,
}

/// Which Python lockfile a repo uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockfileKind {
    Uv,
    Poetry,
    Pipfile,
}

/// Detect the repo's lockfile, in priority order (`uv.lock` → `poetry.lock` →
/// `Pipfile.lock`). Returns the kind and its path, or `None` if the repo has none of
/// them (the caller treats that as an honest gap, not a clean scan).
pub fn detect(repo_dir: &Path) -> Option<(LockfileKind, PathBuf)> {
    for (kind, file) in [
        (LockfileKind::Uv, "uv.lock"),
        (LockfileKind::Poetry, "poetry.lock"),
        (LockfileKind::Pipfile, "Pipfile.lock"),
    ] {
        let path = repo_dir.join(file);
        if path.is_file() {
            return Some((kind, path));
        }
    }
    None
}

/// Read and parse the detected lockfile (and, for poetry/pipfile, its sibling manifest
/// for the direct set) into a deduplicated, sorted set of installed packages.
///
/// # Errors
///
/// Returns [`PyPiError::Db`] if the lockfile cannot be read or is malformed — failing
/// closed so a broken lockfile is a gap, not a false-clean.
pub fn installed_packages(
    kind: LockfileKind,
    lock_path: &Path,
    repo_dir: &Path,
) -> Result<(Vec<InstalledPackage>, DepGraph), PyPiError> {
    let body = std::fs::read_to_string(lock_path).map_err(|e| PyPiError::db(lock_path, e))?;
    let (pkgs, graph) = match kind {
        LockfileKind::Uv => {
            let pkgs = parse_uv(&body).map_err(|e| PyPiError::db(lock_path, e))?;
            let graph = uv_graph(&body).map_err(|e| PyPiError::db(lock_path, e))?;
            (pkgs, graph)
        }
        LockfileKind::Poetry => {
            let direct = poetry_direct_set(repo_dir);
            let pkgs = parse_poetry(&body, &direct).map_err(|e| PyPiError::db(lock_path, e))?;
            let graph = poetry_graph(&body, &direct).map_err(|e| PyPiError::db(lock_path, e))?;
            (pkgs, graph)
        }
        LockfileKind::Pipfile => {
            // Pipfile.lock is a flat `default`/`develop` map with no dependency edges, so the
            // chain is unavailable — an empty graph (honest "unknown provenance" fallback).
            let direct = pipfile_direct_set(repo_dir);
            let pkgs =
                parse_pipfile_lock(&body, &direct).map_err(|e| PyPiError::db(lock_path, e))?;
            (pkgs, DepGraph::default())
        }
    };
    Ok((dedupe(pkgs), graph))
}

/// Build the `dependency_path` graph from `uv.lock`: the project package(s)
/// (`source = { virtual | editable }`) form the root, every `[[package]]` contributes its
/// `dependencies` as edges. Names are used verbatim, matching the lockfile and the occurrence
/// package field (uv writes canonical names consistently).
fn uv_graph(lock_text: &str) -> Result<DepGraph, toml::de::Error> {
    let lock: UvLock = toml::from_str(lock_text)?;
    let root = lock
        .package
        .iter()
        .find(|p| p.source.is_project())
        .map_or("(root)", |p| p.name.as_str());
    let mut graph = DepGraph::new(root);
    for pkg in &lock.package {
        let from = if pkg.source.is_project() {
            root
        } else {
            &pkg.name
        };
        graph.add_edges(from, pkg.dependencies.iter().map(|d| d.name.clone()));
    }
    Ok(graph)
}

/// Build the `dependency_path` graph from `poetry.lock` + the `direct` set. poetry.lock does
/// not mark direct deps, so the root's edges are the packages whose normalized name is in
/// `direct`; each package's `[package.dependencies]` keys are its edges. Names are the
/// lockfile's own (which poetry keeps canonical), matching the occurrence package field.
fn poetry_graph(lock_text: &str, direct: &BTreeSet<String>) -> Result<DepGraph, toml::de::Error> {
    let lock: PoetryLock = toml::from_str(lock_text)?;
    let mut graph = DepGraph::new("(root)");
    for pkg in &lock.package {
        if direct.contains(&normalize_name(&pkg.name)) {
            graph.add_edges("(root)", [pkg.name.clone()]);
        }
        graph.add_edges(&pkg.name, pkg.dependencies.keys().cloned());
    }
    Ok(graph)
}

/// Collapse duplicate `(name, version)` rows into one, with `direct` winning if any
/// occurrence was direct, and sort for deterministic output.
fn dedupe(pkgs: Vec<InstalledPackage>) -> Vec<InstalledPackage> {
    let mut by_key: std::collections::BTreeMap<(String, String), bool> =
        std::collections::BTreeMap::new();
    for p in pkgs {
        let e = by_key.entry((p.name, p.version)).or_insert(false);
        *e = *e || p.direct;
    }
    by_key
        .into_iter()
        .map(|((name, version), direct)| InstalledPackage {
            name,
            version,
            direct,
        })
        .collect()
}

// ---- uv.lock (TOML) ----

#[derive(Deserialize)]
struct UvLock {
    #[serde(default)]
    package: Vec<UvPackage>,
}

#[derive(Deserialize)]
struct UvPackage {
    name: String,
    version: Option<String>,
    #[serde(default)]
    source: UvSource,
    #[serde(default)]
    dependencies: Vec<UvDep>,
}

#[derive(Deserialize, Default)]
struct UvSource {
    /// The workspace root / a member is `virtual` or `editable` (a path), not a
    /// registry artifact. Such packages are the project itself, skipped from matching.
    /// `virtual` is a Rust keyword, so the field is renamed.
    #[serde(rename = "virtual")]
    virtual_: Option<toml::Value>,
    editable: Option<toml::Value>,
}

impl UvSource {
    fn is_project(&self) -> bool {
        self.virtual_.is_some() || self.editable.is_some()
    }
}

#[derive(Deserialize)]
struct UvDep {
    name: String,
}

/// Parse `uv.lock`. The direct set is the union of the `dependencies` of every project
/// package (`source = { virtual | editable }`); those project packages are themselves
/// skipped (not registry artifacts). All other `[[package]]` entries are installed
/// dependencies.
pub fn parse_uv(lock_text: &str) -> Result<Vec<InstalledPackage>, toml::de::Error> {
    let lock: UvLock = toml::from_str(lock_text)?;
    let mut direct: BTreeSet<String> = BTreeSet::new();
    for pkg in &lock.package {
        if pkg.source.is_project() {
            for dep in &pkg.dependencies {
                direct.insert(normalize_name(&dep.name));
            }
        }
    }
    let pkgs = lock
        .package
        .into_iter()
        .filter(|p| !p.source.is_project())
        .filter_map(|p| {
            let version = p.version?;
            let is_direct = direct.contains(&normalize_name(&p.name));
            Some(InstalledPackage {
                name: p.name,
                version,
                direct: is_direct,
            })
        })
        .collect();
    Ok(pkgs)
}

// ---- poetry.lock (TOML) ----

#[derive(Deserialize)]
struct PoetryLock {
    #[serde(default)]
    package: Vec<PoetryPackage>,
}

#[derive(Deserialize)]
struct PoetryPackage {
    name: String,
    version: String,
    /// This package's own dependencies (a `[package.dependencies]` table: name → constraint,
    /// where the value may be a string, table, or array). Only the keys (names) are read, for
    /// the `dependency_path` graph.
    #[serde(default)]
    dependencies: BTreeMap<String, toml::Value>,
}

/// Parse `poetry.lock`. Every `[[package]]` is an installed dependency; `direct` is set
/// for names in `direct` (read from a sibling `pyproject.toml`).
pub fn parse_poetry(
    lock_text: &str,
    direct: &BTreeSet<String>,
) -> Result<Vec<InstalledPackage>, toml::de::Error> {
    let lock: PoetryLock = toml::from_str(lock_text)?;
    Ok(lock
        .package
        .into_iter()
        .map(|p| {
            let is_direct = direct.contains(&normalize_name(&p.name));
            InstalledPackage {
                name: p.name,
                version: p.version,
                direct: is_direct,
            }
        })
        .collect())
}

/// Best-effort direct-dependency names from a sibling `pyproject.toml`: the keys of
/// `[tool.poetry.dependencies]` and every `[tool.poetry.group.*.dependencies]`, plus
/// PEP 621 `[project.dependencies]` requirement strings. Returns an empty set if the
/// file is absent or unparseable (direct is only a hint, never a soundness gate).
fn poetry_direct_set(repo_dir: &Path) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let Ok(body) = std::fs::read_to_string(repo_dir.join("pyproject.toml")) else {
        return set;
    };
    let Ok(value) = toml::from_str::<toml::Value>(&body) else {
        return set;
    };

    // [tool.poetry.dependencies] + [tool.poetry.group.<g>.dependencies]
    if let Some(poetry) = value
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(toml::Value::as_table)
    {
        collect_table_keys(poetry.get("dependencies"), &mut set);
        if let Some(groups) = poetry.get("group").and_then(toml::Value::as_table) {
            for group in groups.values() {
                collect_table_keys(group.get("dependencies"), &mut set);
            }
        }
    }
    // PEP 621 [project.dependencies] = ["requests>=2.31", ...]
    if let Some(deps) = value
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(toml::Value::as_array)
    {
        for dep in deps {
            if let Some(name) = dep.as_str().and_then(requirement_name) {
                set.insert(normalize_name(name));
            }
        }
    }
    set.remove("python");
    set
}

/// Insert the normalized keys of a dependency table (skipping the implicit `python`
/// constraint) into `set`.
fn collect_table_keys(table: Option<&toml::Value>, set: &mut BTreeSet<String>) {
    if let Some(map) = table.and_then(toml::Value::as_table) {
        for key in map.keys() {
            if key != "python" {
                set.insert(normalize_name(key));
            }
        }
    }
}

// ---- Pipfile.lock (JSON) ----

#[derive(Deserialize)]
struct PipfileLock {
    #[serde(default)]
    default: std::collections::BTreeMap<String, PipfileEntry>,
    #[serde(default)]
    develop: std::collections::BTreeMap<String, PipfileEntry>,
}

#[derive(Deserialize)]
struct PipfileEntry {
    /// A registry pin like `"==1.2.3"`; absent for a VCS/path/editable dependency.
    version: Option<String>,
}

/// Parse `Pipfile.lock`. The `default` and `develop` maps are the flat resolved set
/// (Pipfile.lock has no dependency tree), each version a `==`-pin we strip. `direct` is
/// set for names in `direct` (read from a sibling `Pipfile`). Entries with no `version`
/// (VCS/path pins) have no registry artifact to match and are skipped.
pub fn parse_pipfile_lock(
    lock_text: &str,
    direct: &BTreeSet<String>,
) -> Result<Vec<InstalledPackage>, serde_json::Error> {
    let lock: PipfileLock = serde_json::from_str(lock_text)?;
    let mut out = Vec::new();
    for (name, entry) in lock.default.into_iter().chain(lock.develop) {
        let Some(raw) = entry.version else { continue };
        let version = raw.trim_start_matches("==").trim().to_string();
        if version.is_empty() {
            continue;
        }
        let is_direct = direct.contains(&normalize_name(&name));
        out.push(InstalledPackage {
            name,
            version,
            direct: is_direct,
        });
    }
    Ok(out)
}

/// Best-effort direct-dependency names from a sibling `Pipfile` (TOML): the keys of
/// `[packages]` and `[dev-packages]`. Empty if absent/unparseable.
fn pipfile_direct_set(repo_dir: &Path) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let Ok(body) = std::fs::read_to_string(repo_dir.join("Pipfile")) else {
        return set;
    };
    let Ok(value) = toml::from_str::<toml::Value>(&body) else {
        return set;
    };
    collect_table_keys(value.get("packages"), &mut set);
    collect_table_keys(value.get("dev-packages"), &mut set);
    set
}

/// The package name at the head of a PEP 508 requirement string (`"requests>=2.31"` →
/// `"requests"`, `"ruamel.yaml[jinja2]"` → `"ruamel.yaml"`). Returns `None` for an empty
/// or non-name leading token.
fn requirement_name(req: &str) -> Option<&str> {
    let end = req
        .find(|c: char| !(c.is_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(req.len());
    let name = &req[..end];
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| normalize_name(n)).collect()
    }

    #[test]
    fn uv_graph_chains_root_to_transitive() {
        // project `app` -> requests -> certifi (transitive); app -> requests (direct).
        let lock = "\
            [[package]]\nname=\"app\"\nversion=\"0.1.0\"\nsource={virtual=\".\"}\n\
            dependencies=[{name=\"requests\"}]\n\n\
            [[package]]\nname=\"requests\"\nversion=\"2.30.0\"\n\
            dependencies=[{name=\"certifi\"}]\n\n\
            [[package]]\nname=\"certifi\"\nversion=\"2023.7.22\"\n";
        let g = uv_graph(lock).unwrap();
        assert_eq!(g.chain_to("certifi"), vec!["app", "requests", "certifi"]);
        assert_eq!(g.chain_to("requests"), vec!["app", "requests"]);
    }

    #[test]
    fn poetry_graph_chains_via_direct_set() {
        // direct = {flask}; flask -> jinja2 (transitive).
        let lock = "\
            [[package]]\nname=\"flask\"\nversion=\"3.0.0\"\n\
            [package.dependencies]\njinja2=\">=3.1\"\n\n\
            [[package]]\nname=\"jinja2\"\nversion=\"3.1.2\"\n";
        let g = poetry_graph(lock, &set(&["flask"])).unwrap();
        assert_eq!(g.chain_to("jinja2"), vec!["(root)", "flask", "jinja2"]);
        // a flat Pipfile.lock has no edges → empty chain (honest fallback).
        assert!(DepGraph::default().chain_to("anything").is_empty());
    }

    fn rows(pkgs: &[InstalledPackage]) -> Vec<(&str, &str, bool)> {
        pkgs.iter()
            .map(|p| (p.name.as_str(), p.version.as_str(), p.direct))
            .collect()
    }

    #[test]
    fn parses_uv_lock_with_self_described_direct() {
        let lock = r#"
version = 1
requires-python = ">=3.9"

[[package]]
name = "myapp"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "certifi" },
]

[[package]]
name = "certifi"
version = "2023.7.22"
source = { registry = "https://pypi.org/simple" }
"#;
        let pkgs = dedupe(parse_uv(lock).unwrap());
        // The virtual project `myapp` is skipped; requests is direct, certifi transitive.
        assert_eq!(
            rows(&pkgs),
            vec![
                ("certifi", "2023.7.22", false),
                ("requests", "2.31.0", true)
            ]
        );
    }

    #[test]
    fn parses_poetry_lock_with_direct_set() {
        let lock = r#"
[[package]]
name = "requests"
version = "2.31.0"
optional = false

[[package]]
name = "certifi"
version = "2023.7.22"
optional = false
"#;
        let pkgs = parse_poetry(lock, &set(&["requests"])).unwrap();
        assert_eq!(
            rows(&pkgs),
            vec![
                ("requests", "2.31.0", true),
                ("certifi", "2023.7.22", false)
            ]
        );
    }

    #[test]
    fn parses_pipfile_lock_strips_eq_and_skips_vcs() {
        let lock = r#"{
          "default": {
            "requests": { "version": "==2.31.0" },
            "certifi": { "version": "==2023.7.22" },
            "somevcs": { "git": "https://example/x.git", "ref": "abc" }
          },
          "develop": {
            "pytest": { "version": "==7.4.0" }
          }
        }"#;
        let pkgs = dedupe(parse_pipfile_lock(lock, &set(&["requests", "pytest"])).unwrap());
        assert_eq!(
            rows(&pkgs),
            vec![
                ("certifi", "2023.7.22", false),
                ("pytest", "7.4.0", true),
                ("requests", "2.31.0", true),
            ]
        );
    }

    #[test]
    fn dedupes_same_name_version_direct_wins() {
        let pkgs = dedupe(vec![
            InstalledPackage {
                name: "x".into(),
                version: "1.0".into(),
                direct: false,
            },
            InstalledPackage {
                name: "x".into(),
                version: "1.0".into(),
                direct: true,
            },
        ]);
        assert_eq!(rows(&pkgs), vec![("x", "1.0", true)]);
    }

    #[test]
    fn requirement_name_extracts_head() {
        assert_eq!(requirement_name("requests>=2.31"), Some("requests"));
        assert_eq!(requirement_name("ruamel.yaml[jinja2]"), Some("ruamel.yaml"));
        assert_eq!(requirement_name("flask"), Some("flask"));
        assert_eq!(requirement_name(">=1.0"), None);
    }

    #[test]
    fn malformed_lockfile_is_an_error_not_empty() {
        assert!(parse_uv("this is { not valid toml").is_err());
        assert!(parse_pipfile_lock("not json", &BTreeSet::new()).is_err());
    }

    /// A scratch repo dir under the OS temp dir, unique per test name.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fleetreach-pypi-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn poetry_direct_set_reads_pyproject_pep621_and_tool_poetry() {
        let dir = scratch("poetry-direct");
        std::fs::write(
            dir.join("pyproject.toml"),
            r#"
[project]
name = "app"
dependencies = ["jinja2==3.1.2", "requests>=2"]

[tool.poetry.dependencies]
python = "^3.9"
click = "^8"

[tool.poetry.group.dev.dependencies]
pytest = "^7"
"#,
        )
        .unwrap();
        let set = poetry_direct_set(&dir);
        // PEP 621 deps + tool.poetry deps + group deps, with `python` excluded.
        assert!(set.contains("jinja2"));
        assert!(set.contains("requests"));
        assert!(set.contains("click"));
        assert!(set.contains("pytest"));
        assert!(!set.contains("python"));
    }

    #[test]
    fn pipfile_direct_set_reads_packages_tables() {
        let dir = scratch("pipfile-direct");
        std::fs::write(
            dir.join("Pipfile"),
            r#"
[packages]
jinja2 = "==3.1.2"

[dev-packages]
pytest = "*"
"#,
        )
        .unwrap();
        let set = pipfile_direct_set(&dir);
        assert!(set.contains("jinja2"));
        assert!(set.contains("pytest"));
    }

    #[test]
    fn installed_packages_marks_direct_from_sibling_manifest() {
        let dir = scratch("poetry-e2e");
        std::fs::write(
            dir.join("pyproject.toml"),
            "[project]\nname=\"a\"\ndependencies=[\"jinja2==3.1.2\"]\n",
        )
        .unwrap();
        let lock = dir.join("poetry.lock");
        std::fs::write(
            &lock,
            "[[package]]\nname=\"jinja2\"\nversion=\"3.1.2\"\n\n\
             [[package]]\nname=\"markupsafe\"\nversion=\"2.1.5\"\n",
        )
        .unwrap();
        let (pkgs, _graph) = installed_packages(LockfileKind::Poetry, &lock, &dir).unwrap();
        let jinja = pkgs.iter().find(|p| p.name == "jinja2").unwrap();
        let mark = pkgs.iter().find(|p| p.name == "markupsafe").unwrap();
        assert!(jinja.direct, "jinja2 is a manifest dependency");
        assert!(!mark.direct, "markupsafe is transitive");
    }
}
