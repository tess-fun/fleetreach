//! Parse a `packages.lock.json` into a flat, deduplicated set of installed NuGet packages —
//! the input the OSV matcher scans. Read straight from the lockfile, so it needs **no .NET
//! toolchain and no network**: NuGet's lockfile already pins the full transitive tree to
//! exact versions and records whether each package is a direct or transitive dependency.
//!
//! `packages.lock.json` is JSON, keyed by target framework, with each package carrying a
//! `type` (`Direct` / `Transitive` / `Project` / `CentralTransitive`) and a `resolved` exact
//! version:
//!
//! ```json
//! {
//!   "version": 1,
//!   "dependencies": {
//!     "net8.0": {
//!       "Newtonsoft.Json": { "type": "Direct",     "requested": "[13.0.1, )", "resolved": "13.0.1" },
//!       "System.Buffers":  { "type": "Transitive", "resolved": "4.5.1" }
//!     }
//!   }
//! }
//! ```
//!
//! NuGet package IDs are **case-insensitive**, so names are lowercased here and in the DB
//! index. `Project` entries are project-to-project references (no registry version) and are
//! skipped; the same package can appear under several target frameworks and is deduplicated.

use std::collections::BTreeMap;

use fleetreach_core::DepGraph;
use serde::Deserialize;

/// One resolved package from `packages.lock.json`: its lowercase id, exact installed version,
/// and whether the project depends on it **directly** (`type: Direct`) rather than only
/// transitively.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub direct: bool,
}

#[derive(Deserialize)]
struct Lock {
    #[serde(default)]
    dependencies: BTreeMap<String, BTreeMap<String, Dep>>,
}

#[derive(Deserialize)]
struct Dep {
    #[serde(rename = "type")]
    kind: Option<String>,
    resolved: Option<String>,
    /// The package's own direct dependencies (`{ <DepName>: <version-range> }`). Keys are the
    /// edge targets for the provenance graph; values are unused here.
    #[serde(default)]
    dependencies: BTreeMap<String, serde_json::Value>,
}

/// Parse `packages.lock.json` JSON into a deduplicated, sorted set of installed packages.
/// Packages are collected across every target framework; a `Project` reference (no registry
/// version) is skipped; `Direct` marks the direct flag.
///
/// # Errors
///
/// Returns the underlying [`serde_json::Error`] if the lockfile is not valid JSON — failing
/// closed, so a corrupt lockfile is an honest gap rather than a false-clean scan.
pub fn installed_packages(lock_text: &str) -> Result<Vec<InstalledPackage>, serde_json::Error> {
    Ok(parse_lockfile(lock_text)?.0)
}

/// Parse `packages.lock.json` once into both the installed-package set and a name-level
/// [`DepGraph`] (for `dependency_path`). The graph is rooted at `"(root)"`, with an edge from
/// the root to every `Direct` package and an edge from each package to each of its own
/// dependencies. **All node names are lowercased** to match the occurrence/DB keying in
/// `scan.rs` (NuGet ids are case-insensitive), so chains line up with the matched package.
///
/// # Errors
///
/// Returns the underlying [`serde_json::Error`] if the lockfile is not valid JSON — failing
/// closed, so a corrupt lockfile is an honest gap rather than a false-clean scan.
pub fn parse_lockfile(
    lock_text: &str,
) -> Result<(Vec<InstalledPackage>, DepGraph), serde_json::Error> {
    let lock: Lock = serde_json::from_str(lock_text)?;
    let graph = dependency_graph(&lock);
    let mut packages = Vec::new();
    for framework in lock.dependencies.into_values() {
        for (name, dep) in framework {
            // Project references have no registry artifact to match against.
            if dep.kind.as_deref() == Some("Project") {
                continue;
            }
            let Some(version) = dep.resolved else {
                continue;
            };
            packages.push(InstalledPackage {
                name: name.to_ascii_lowercase(),
                version,
                direct: dep.kind.as_deref() == Some("Direct"),
            });
        }
    }
    Ok((dedupe(packages), graph))
}

/// Build the name-level provenance graph from every target framework's package table. Names
/// are lowercased (NuGet ids are case-insensitive, and `scan.rs` matches on the lowercase id),
/// so the chain nodes match the occurrence `package`. Root = `"(root)"`, with an edge to each
/// `Direct` package; every package gets an edge to each of its own dependencies.
fn dependency_graph(lock: &Lock) -> DepGraph {
    const ROOT: &str = "(root)";
    let mut graph = DepGraph::new(ROOT);
    for framework in lock.dependencies.values() {
        for (name, dep) in framework {
            let from = name.to_ascii_lowercase();
            if dep.kind.as_deref() == Some("Direct") {
                graph.add_edges(ROOT, [from.clone()]);
            }
            graph.add_edges(
                &from,
                dep.dependencies.keys().map(|d| d.to_ascii_lowercase()),
            );
        }
    }
    graph
}

/// Collapse duplicate `(name, version)` rows into one, with `direct` winning if any
/// occurrence was direct, and sort for deterministic output.
fn dedupe(packages: Vec<InstalledPackage>) -> Vec<InstalledPackage> {
    let mut by_key: BTreeMap<(String, String), bool> = BTreeMap::new();
    for p in packages {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn rows(pkgs: &[InstalledPackage]) -> Vec<(&str, &str, bool)> {
        pkgs.iter()
            .map(|p| (p.name.as_str(), p.version.as_str(), p.direct))
            .collect()
    }

    const LOCK: &str = r#"{
      "version": 1,
      "dependencies": {
        "net8.0": {
          "Newtonsoft.Json": { "type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1" },
          "System.Buffers":  { "type": "Transitive", "resolved": "4.5.1" },
          "MyLib":           { "type": "Project" }
        },
        "net6.0": {
          "Newtonsoft.Json": { "type": "Direct", "resolved": "13.0.1" }
        }
      }
    }"#;

    #[test]
    fn parses_lock_and_lowercases_skips_projects() {
        let pkgs = installed_packages(LOCK).unwrap();
        assert_eq!(
            rows(&pkgs),
            vec![
                ("newtonsoft.json", "13.0.1", true), // direct, deduped across frameworks
                ("system.buffers", "4.5.1", false),  // transitive
            ]
        );
        // The Project reference is not a registry package.
        assert!(pkgs.iter().all(|p| p.name != "mylib"));
    }

    #[test]
    fn malformed_lock_is_an_error() {
        assert!(installed_packages("not json").is_err());
        assert!(installed_packages(r#"{"version":1}"#).unwrap().is_empty());
    }

    #[test]
    fn dependency_graph_chains_direct_and_transitive() {
        // Serilog (Direct) -> Serilog.Sinks.File (Transitive) -> System.Buffers (Transitive).
        const LOCK_TREE: &str = r#"{
          "version": 1,
          "dependencies": {
            "net8.0": {
              "Serilog": {
                "type": "Direct",
                "resolved": "3.1.1",
                "dependencies": { "Serilog.Sinks.File": "5.0.0" }
              },
              "Serilog.Sinks.File": {
                "type": "Transitive",
                "resolved": "5.0.0",
                "dependencies": { "System.Buffers": "4.5.1" }
              },
              "System.Buffers": { "type": "Transitive", "resolved": "4.5.1" }
            }
          }
        }"#;
        let (_pkgs, graph) = parse_lockfile(LOCK_TREE).unwrap();
        // A direct package chains [root, target]; names are lowercased.
        assert_eq!(graph.chain_to("serilog"), vec!["(root)", "serilog"]);
        // A transitive package chains [root, mid, target].
        assert_eq!(
            graph.chain_to("system.buffers"),
            vec!["(root)", "serilog", "serilog.sinks.file", "system.buffers"]
        );
    }

    #[test]
    fn dedupes_direct_wins() {
        let pkgs = dedupe(vec![
            InstalledPackage {
                name: "a".into(),
                version: "1.0".into(),
                direct: false,
            },
            InstalledPackage {
                name: "a".into(),
                version: "1.0".into(),
                direct: true,
            },
        ]);
        assert_eq!(rows(&pkgs), vec![("a", "1.0", true)]);
    }
}
