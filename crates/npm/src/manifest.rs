//! The project's own `package.json` files: the root manifest plus yarn/npm workspace
//! members. yarn lockfiles do not record which entries the project asked for, so the yarn
//! readers take the direct set and the dev/runtime split from here (spec 02).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Deserialize, Default)]
struct PackageJson {
    name: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, serde_json::Value>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, serde_json::Value>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    workspaces: Option<serde_json::Value>,
}

/// The declared dependencies of the root project and its workspace members, as
/// `(name, range)` pairs exactly as written (the form yarn keys its lockfile by).
#[derive(Debug, Default)]
pub(crate) struct Declared {
    pub name: Option<String>,
    pub prod: Vec<(String, String)>,
    pub dev: Vec<(String, String)>,
    /// Workspace member names, which are local packages, never registry ones.
    pub workspace_names: Vec<String>,
}

/// Read `<dir>/package.json` and every workspace member it declares. A missing or broken
/// root manifest yields an empty [`Declared`]: the readers then fall back to treating
/// every package as runtime, which never hides a finding.
pub(crate) fn declared(dir: &Path) -> Declared {
    let mut out = Declared::default();
    let Some(root) = read(&dir.join("package.json")) else {
        return out;
    };
    out.name.clone_from(&root.name);
    let members = root
        .workspaces
        .as_ref()
        .map(|w| workspace_dirs(dir, w))
        .unwrap_or_default();
    absorb(&mut out, &root);
    for member in members {
        if let Some(pkg) = read(&member.join("package.json")) {
            if let Some(name) = &pkg.name {
                out.workspace_names.push(name.clone());
            }
            absorb(&mut out, &pkg);
        }
    }
    out
}

fn read(path: &Path) -> Option<PackageJson> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn absorb(out: &mut Declared, pkg: &PackageJson) {
    let pairs = |m: &BTreeMap<String, serde_json::Value>| -> Vec<(String, String)> {
        m.iter()
            .filter_map(|(k, v)| v.as_str().map(|r| (k.clone(), r.to_string())))
            .collect()
    };
    out.prod.extend(pairs(&pkg.dependencies));
    out.prod.extend(pairs(&pkg.optional_dependencies));
    out.dev.extend(pairs(&pkg.dev_dependencies));
}

/// Expand `workspaces` (an array, or `{ "packages": [...] }`) into member directories.
/// Supports exact paths and a trailing `/*` or `/**` (one level), which is what nearly
/// every repo uses; anything else is skipped, which only costs a `direct` label.
fn workspace_dirs(root: &Path, spec: &serde_json::Value) -> Vec<PathBuf> {
    let patterns = spec
        .as_array()
        .or_else(|| spec.get("packages").and_then(|p| p.as_array()))
        .cloned()
        .unwrap_or_default();
    let mut dirs = Vec::new();
    for pattern in patterns.iter().filter_map(|p| p.as_str()) {
        if pattern.starts_with('!') || pattern.contains("..") {
            continue;
        }
        let base = pattern
            .strip_suffix("/**")
            .or_else(|| pattern.strip_suffix("/*"));
        match base {
            Some(base) if !base.contains('*') => {
                let Ok(entries) = std::fs::read_dir(root.join(base)) else {
                    continue;
                };
                let mut found: Vec<PathBuf> = entries
                    .flatten()
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                    .map(|e| e.path())
                    .collect();
                found.sort();
                dirs.extend(found);
            }
            None if !pattern.contains('*') => dirs.push(root.join(pattern)),
            _ => {}
        }
    }
    dirs
}
