//! Parse a resolved npm `package-lock.json` into a flat, deduplicated set of
//! installed packages — the input the OSV matcher scans. Read straight from the
//! lockfile, so it needs **no `npm` toolchain and no network** (the same reason the
//! Rust path reads `Cargo.lock`): the lockfile already pins every package to an
//! exact version across the full transitive tree.
//!
//! Both modern (`lockfileVersion` 2/3, the `packages` map) and legacy
//! (`lockfileVersion` 1, the recursive `dependencies` tree) layouts are supported,
//! because a v1 lockfile that silently parsed to nothing would be a false-clean scan.

use std::collections::BTreeMap;

use fleetreach_core::DepGraph;
use serde::Deserialize;

/// One resolved package from the lockfile: its registry name, exact installed
/// version, and whether the project depends on it **directly** (it is listed in the
/// root manifest's dependency sets) as opposed to pulling it in transitively.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub direct: bool,
}

#[derive(Deserialize)]
struct Lockfile {
    /// Present in lockfileVersion 2/3: keyed by install path (`""` is the root,
    /// `node_modules/<name>` a dependency).
    #[serde(default)]
    packages: BTreeMap<String, PackageEntry>,
    /// Present in lockfileVersion 1 (and mirrored in v2 for back-compat): the
    /// recursive dependency tree. Only read when `packages` is absent.
    #[serde(default)]
    dependencies: BTreeMap<String, DependencyEntry>,
}

#[derive(Deserialize, Default)]
struct PackageEntry {
    version: Option<String>,
    /// The root entry (`""`) carries the project's own name.
    #[serde(default)]
    name: Option<String>,
    /// The root entry (`""`) lists the project's direct dependencies here.
    #[serde(default)]
    dependencies: BTreeMap<String, serde_json::Value>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, serde_json::Value>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, serde_json::Value>,
    #[serde(default, rename = "peerDependencies")]
    peer_dependencies: BTreeMap<String, serde_json::Value>,
    /// A workspace symlink — not a published artifact, so it has nothing to match
    /// against the registry advisory DB.
    #[serde(default)]
    link: bool,
}

#[derive(Deserialize)]
struct DependencyEntry {
    version: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, DependencyEntry>,
}

/// Parse a `package-lock.json` body into a deduplicated, sorted set of installed
/// packages. A package pinned to the same version many times across the tree appears
/// once; if it is reachable both directly and transitively, `direct` wins.
///
/// Returns an empty vector for a lockfile with no dependencies. Parse errors bubble
/// up to the caller (which fails the repo closed rather than reporting it clean).
pub fn installed_packages(lockfile_json: &str) -> Result<Vec<InstalledPackage>, serde_json::Error> {
    Ok(parse_lockfile(lockfile_json)?.0)
}

/// Parse a `package-lock.json` body once into both the installed-package set and the
/// name-level [`DepGraph`] (for `dependency_path`). The graph is empty for a
/// lockfileVersion-1 tree, which carries no resolvable edge data.
pub fn parse_lockfile(
    lockfile_json: &str,
) -> Result<(Vec<InstalledPackage>, DepGraph), serde_json::Error> {
    let lock: Lockfile = serde_json::from_str(lockfile_json)?;
    let graph = dependency_graph(&lock);
    let installed = installed_from(&lock);
    Ok((installed, graph))
}

/// Build the name-level dependency graph from a v2/v3 `packages` map. A v1-only lockfile
/// (no `packages`) yields an empty graph — its recursive tree omits the hoisted edges
/// needed for a reliable chain, so an empty `dependency_path` is the honest fallback.
fn dependency_graph(lock: &Lockfile) -> DepGraph {
    if lock.packages.is_empty() {
        return DepGraph::default();
    }
    let root = lock
        .packages
        .get("")
        .and_then(|e| e.name.as_deref())
        .unwrap_or("(root)");
    let mut graph = DepGraph::new(root);
    graph.add_edges(
        root,
        root_direct_set(&lock.packages)
            .into_iter()
            .map(str::to_string),
    );
    for (path, entry) in &lock.packages {
        if path.is_empty() || entry.link {
            continue;
        }
        let Some(name) = package_name_from_path(path) else {
            continue;
        };
        graph.add_edges(
            name,
            entry
                .dependencies
                .keys()
                .chain(entry.optional_dependencies.keys())
                .cloned(),
        );
    }
    graph
}

fn installed_from(lock: &Lockfile) -> Vec<InstalledPackage> {
    // `direct` may be discovered as true on a later occurrence, so collect into a map
    // keyed by (name, version) and OR the flag in.
    let mut found: BTreeMap<(String, String), bool> = BTreeMap::new();
    let mut add = |name: String, version: String, direct: bool| {
        let entry = found.entry((name, version)).or_insert(false);
        *entry = *entry || direct;
    };

    if !lock.packages.is_empty() {
        let direct = root_direct_set(&lock.packages);
        for (path, entry) in &lock.packages {
            if path.is_empty() || entry.link {
                continue; // the root project / a workspace symlink: not a dependency.
            }
            let Some(name) = package_name_from_path(path) else {
                continue;
            };
            let Some(version) = entry.version.as_deref() else {
                continue; // link/alias entries with no concrete version are unmatchable.
            };
            // Direct only when the project lists this package AND this is its top-level
            // install (`node_modules/<name>`). A nested copy
            // (`node_modules/dep/node_modules/<name>`) is some intermediate's dependency
            // at a different version — transitive — even when the *name* is also a root
            // dep (npm keeps the conflicting version nested). Without the top-level
            // check, that nested copy would be mislabeled direct and get a "fixable in
            // your manifest" hint it does not deserve.
            let is_direct = is_top_level(path) && direct.contains(name);
            add(name.to_string(), version.to_string(), is_direct);
        }
    } else {
        // lockfileVersion 1: top-level entries are direct, nested ones transitive.
        collect_v1(&lock.dependencies, true, &mut add);
    }

    found
        .into_iter()
        .map(|((name, version), direct)| InstalledPackage {
            name,
            version,
            direct,
        })
        .collect()
}

/// The set of direct dependency names declared by the root (`""`) package entry —
/// the union of its runtime, dev, optional, and peer dependency maps.
fn root_direct_set(packages: &BTreeMap<String, PackageEntry>) -> std::collections::BTreeSet<&str> {
    let mut set = std::collections::BTreeSet::new();
    if let Some(root) = packages.get("") {
        for map in [
            &root.dependencies,
            &root.dev_dependencies,
            &root.optional_dependencies,
            &root.peer_dependencies,
        ] {
            set.extend(map.keys().map(String::as_str));
        }
    }
    set
}

/// The package name from a `packages` key: the segment after the **last**
/// `node_modules/`, so a nested `node_modules/a/node_modules/b` resolves to `b` and a
/// scoped `node_modules/@scope/pkg` to `@scope/pkg`. Returns `None` for a key with no
/// `node_modules/` segment (e.g. a workspace path).
fn package_name_from_path(path: &str) -> Option<&str> {
    path.rsplit_once("node_modules/").map(|(_, name)| name)
}

/// Whether a `packages` key is a **top-level** install (`node_modules/<name>`, one
/// `node_modules/` segment) rather than a nested copy
/// (`node_modules/dep/node_modules/<name>`). Holds for scoped names too
/// (`node_modules/@scope/pkg`).
fn is_top_level(path: &str) -> bool {
    path.matches("node_modules/").count() == 1
}

/// Walk the lockfileVersion-1 `dependencies` tree, marking the first level direct and
/// everything nested transitive.
fn collect_v1(
    deps: &BTreeMap<String, DependencyEntry>,
    direct: bool,
    add: &mut impl FnMut(String, String, bool),
) {
    for (name, entry) in deps {
        if let Some(version) = entry.version.as_deref() {
            add(name.clone(), version.to_string(), direct);
        }
        collect_v1(&entry.dependencies, false, add);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn names(pkgs: &[InstalledPackage]) -> Vec<(&str, &str, bool)> {
        pkgs.iter()
            .map(|p| (p.name.as_str(), p.version.as_str(), p.direct))
            .collect()
    }

    #[test]
    fn parses_lockfile_v3_packages_map() {
        let json = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "app", "version": "1.0.0",
                  "dependencies": { "lodash": "^4.17.0" },
                  "devDependencies": { "mocha": "^10.0.0" } },
            "node_modules/lodash": { "version": "4.17.20" },
            "node_modules/mocha": { "version": "10.2.0", "dev": true },
            "node_modules/minimist": { "version": "1.2.5" },
            "node_modules/@scope/pkg": { "version": "2.0.0" }
          }
        }"#;
        let pkgs = installed_packages(json).unwrap();
        assert_eq!(
            names(&pkgs),
            vec![
                ("@scope/pkg", "2.0.0", false),
                ("lodash", "4.17.20", true), // listed in root deps -> direct
                ("minimist", "1.2.5", false), // transitive -> not direct
                ("mocha", "10.2.0", true),   // listed in root devDependencies -> direct
            ]
        );
    }

    #[test]
    fn nested_node_modules_resolves_to_inner_name() {
        let json = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": { "version": "1.0.0" },
            "node_modules/a": { "version": "1.0.0" },
            "node_modules/a/node_modules/minimist": { "version": "0.0.8" }
          }
        }"#;
        let pkgs = installed_packages(json).unwrap();
        assert_eq!(
            names(&pkgs),
            vec![("a", "1.0.0", false), ("minimist", "0.0.8", false)]
        );
    }

    #[test]
    fn root_dep_nested_at_another_version_is_transitive() {
        // minimist is a root dependency (so its top-level 1.2.6 is direct), but express
        // pulls an older 1.2.0 nested under itself — that copy is transitive, not direct,
        // even though the *name* is a root dep.
        let json = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": { "version": "1.0.0", "dependencies": { "minimist": "^1.2.6", "express": "^4" } },
            "node_modules/minimist": { "version": "1.2.6" },
            "node_modules/express": { "version": "4.18.0" },
            "node_modules/express/node_modules/minimist": { "version": "1.2.0" }
          }
        }"#;
        let pkgs = installed_packages(json).unwrap();
        assert_eq!(
            names(&pkgs),
            vec![
                ("express", "4.18.0", true),  // root dep, top-level -> direct
                ("minimist", "1.2.0", false), // nested under express -> transitive
                ("minimist", "1.2.6", true),  // root dep, top-level -> direct
            ]
        );
    }

    #[test]
    fn skips_root_and_workspace_links() {
        let json = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": { "version": "1.0.0" },
            "node_modules/myworkspace": { "resolved": "packages/ws", "link": true },
            "packages/ws": { "version": "9.9.9" },
            "node_modules/real": { "version": "1.2.3" }
          }
        }"#;
        let pkgs = installed_packages(json).unwrap();
        // The linked workspace pkg and the bare workspace path are skipped; only the
        // real published dependency remains.
        assert_eq!(names(&pkgs), vec![("real", "1.2.3", false)]);
    }

    #[test]
    fn parses_lockfile_v1_dependency_tree() {
        let json = r#"{
          "lockfileVersion": 1,
          "dependencies": {
            "lodash": { "version": "4.17.20" },
            "express": {
              "version": "4.18.0",
              "dependencies": {
                "minimist": { "version": "1.2.5" }
              }
            }
          }
        }"#;
        let pkgs = installed_packages(json).unwrap();
        assert_eq!(
            names(&pkgs),
            vec![
                ("express", "4.18.0", true),
                ("lodash", "4.17.20", true),
                ("minimist", "1.2.5", false), // nested -> transitive
            ]
        );
    }

    #[test]
    fn dedupes_same_package_version_direct_wins() {
        // minimist appears nested (transitive) AND top-level (direct): direct wins.
        let json = r#"{
          "lockfileVersion": 1,
          "dependencies": {
            "minimist": { "version": "1.2.5" },
            "express": {
              "version": "4.18.0",
              "dependencies": { "minimist": { "version": "1.2.5" } }
            }
          }
        }"#;
        let pkgs = installed_packages(json).unwrap();
        let minimist: Vec<_> = pkgs.iter().filter(|p| p.name == "minimist").collect();
        assert_eq!(minimist.len(), 1, "deduped to one row");
        assert!(minimist[0].direct, "direct occurrence wins");
    }

    #[test]
    fn empty_lockfile_is_no_packages() {
        let json = r#"{ "lockfileVersion": 3, "packages": { "": { "version": "1.0.0" } } }"#;
        assert!(installed_packages(json).unwrap().is_empty());
    }

    #[test]
    fn dependency_path_chains_root_to_transitive() {
        // app -> express -> minimist (transitive); app -> lodash (direct).
        let json = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "app", "version": "1.0.0",
                  "dependencies": { "express": "^4", "lodash": "^4" } },
            "node_modules/express": { "version": "4.18.0",
                  "dependencies": { "minimist": "^1.2.0" } },
            "node_modules/minimist": { "version": "1.2.0" },
            "node_modules/lodash": { "version": "4.17.20" }
          }
        }"#;
        let (_installed, graph) = parse_lockfile(json).unwrap();
        // transitive: full chain root -> express -> minimist
        assert_eq!(
            graph.chain_to("minimist"),
            vec!["app", "express", "minimist"]
        );
        // direct: chain is [root, pkg], so the "via" render is empty
        assert_eq!(graph.chain_to("lodash"), vec!["app", "lodash"]);
        // a package not in the graph -> empty (honest fallback, never a wrong chain)
        assert!(graph.chain_to("nonexistent").is_empty());
    }

    #[test]
    fn dependency_path_empty_for_v1_lockfile() {
        // lockfileVersion 1 has no `packages` map -> no resolvable edges -> empty chain.
        let json = r#"{
          "lockfileVersion": 1,
          "dependencies": { "lodash": { "version": "4.17.20" } }
        }"#;
        let (installed, graph) = parse_lockfile(json).unwrap();
        assert!(!installed.is_empty());
        assert!(graph.chain_to("lodash").is_empty());
    }
}
