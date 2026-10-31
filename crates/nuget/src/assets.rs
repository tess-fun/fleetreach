//! Read `obj/project.assets.json`, the restore output every `dotnet restore` (and `dotnet
//! build`) writes next to a project. It holds the full resolved graph, so it is full coverage
//! when it matches the project file; usually present in CI after a restore, rarely committed.
//!
//! ```json
//! {
//!   "version": 3,
//!   "targets": {
//!     "net8.0": {
//!       "Azure.Core/1.25.0": { "type": "package", "dependencies": { "System.Memory.Data": "1.0.2" } },
//!       "MyLib/1.0.0": { "type": "project" }
//!     }
//!   },
//!   "project": {
//!     "frameworks": {
//!       "net8.0": { "dependencies": { "Azure.Core": { "target": "Package", "version": "[1.25.0, )" } } }
//!     }
//!   }
//! }
//! ```
//!
//! `targets` entries of type `package` are the installed packages (keys are `Name/Version`,
//! repeated per framework and runtime); `project.frameworks.*.dependencies` with target
//! `Package` are the direct ones, with the version range the project asked for.

use std::collections::BTreeMap;

use fleetreach_core::DepGraph;
use serde::Deserialize;

use crate::lockfile::{dedupe, InstalledPackage};

#[derive(Deserialize)]
struct Assets {
    #[serde(default)]
    targets: BTreeMap<String, BTreeMap<String, Target>>,
    #[serde(default)]
    project: Option<Project>,
}

#[derive(Deserialize)]
struct Target {
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct Project {
    #[serde(default)]
    frameworks: BTreeMap<String, Framework>,
}

#[derive(Deserialize)]
struct Framework {
    #[serde(default)]
    dependencies: BTreeMap<String, ProjectDep>,
}

#[derive(Deserialize)]
struct ProjectDep {
    target: Option<String>,
    version: Option<String>,
}

/// What a `project.assets.json` holds: installed packages, the dependency graph, and the
/// version range each direct package was requested at (lowercase name → range).
pub(crate) struct Restored {
    pub packages: Vec<InstalledPackage>,
    pub graph: DepGraph,
    pub requested: BTreeMap<String, String>,
}

/// Parse `project.assets.json`.
///
/// # Errors
///
/// The underlying [`serde_json::Error`] if the file is not valid JSON of this shape, failing
/// closed.
pub(crate) fn parse(text: &str) -> Result<Restored, serde_json::Error> {
    const ROOT: &str = "(root)";
    let assets: Assets = serde_json::from_str(text)?;
    let mut requested = BTreeMap::new();
    for framework in assets.project.iter().flat_map(|p| p.frameworks.values()) {
        for (name, dep) in &framework.dependencies {
            if dep
                .target
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case("Package"))
            {
                requested.insert(
                    name.to_ascii_lowercase(),
                    dep.version.clone().unwrap_or_default(),
                );
            }
        }
    }
    let mut graph = DepGraph::new(ROOT);
    graph.add_edges(ROOT, requested.keys().cloned());
    let mut packages = Vec::new();
    for framework in assets.targets.into_values() {
        for (key, target) in framework {
            if !target
                .kind
                .as_deref()
                .is_some_and(|k| k.eq_ignore_ascii_case("package"))
            {
                continue; // a project reference, not a registry release
            }
            let Some((name, version)) = key.split_once('/') else {
                continue;
            };
            let name = name.to_ascii_lowercase();
            graph.add_edges(
                &name,
                target.dependencies.keys().map(|d| d.to_ascii_lowercase()),
            );
            packages.push(InstalledPackage {
                direct: requested.contains_key(&name),
                name,
                version: version.to_string(),
            });
        }
    }
    Ok(Restored {
        packages: dedupe(packages),
        graph,
        requested,
    })
}

/// The lower bound of a NuGet version range as restore records it (`"[1.2.3, )"` → `"1.2.3"`,
/// `"[1.2.3]"` → `"1.2.3"`, `"1.2.3"` → `"1.2.3"`), or `None` for an open lower bound.
pub(crate) fn range_floor(range: &str) -> Option<&str> {
    let inner = range.trim().trim_start_matches(['[', '(']);
    let floor = inner
        .split(',')
        .next()?
        .trim()
        .trim_end_matches([']', ')'])
        .trim();
    (!floor.is_empty()).then_some(floor)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const ASSETS: &str = r#"{
      "version": 4,
      "targets": {
        "net10.0": {
          "Azure.Core/1.25.0": { "type": "package", "dependencies": { "System.Memory.Data": "1.0.2" } },
          "Microsoft.Data.SqlClient/5.1.0": { "type": "package", "dependencies": { "Azure.Core": "1.25.0" } },
          "System.Memory.Data/1.0.2": { "type": "package" },
          "MyLib/1.0.0": { "type": "project" }
        },
        "net10.0/linux-x64": {
          "Microsoft.Data.SqlClient/5.1.0": { "type": "package" }
        }
      },
      "project": {
        "frameworks": {
          "net10.0": {
            "dependencies": {
              "Microsoft.Data.SqlClient": { "target": "Package", "version": "[5.1.0, )" },
              "MyLib": { "target": "Project" }
            }
          }
        }
      }
    }"#;

    #[test]
    fn reads_packages_direct_set_and_chains() {
        let r = parse(ASSETS).unwrap();
        let rows: Vec<(&str, &str, bool)> = r
            .packages
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str(), p.direct))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("azure.core", "1.25.0", false),
                ("microsoft.data.sqlclient", "5.1.0", true),
                ("system.memory.data", "1.0.2", false),
            ]
        );
        assert_eq!(r.requested["microsoft.data.sqlclient"], "[5.1.0, )");
        assert_eq!(
            r.graph.chain_to("system.memory.data"),
            vec![
                "(root)",
                "microsoft.data.sqlclient",
                "azure.core",
                "system.memory.data"
            ]
        );
    }

    #[test]
    fn malformed_assets_fail_closed() {
        assert!(parse("{\"targets\": 3}").is_err());
        assert!(parse("not json").is_err());
    }

    #[test]
    fn range_floor_shapes() {
        assert_eq!(range_floor("[5.1.0, )"), Some("5.1.0"));
        assert_eq!(range_floor("[1.0.0]"), Some("1.0.0"));
        assert_eq!(range_floor("2.0.0"), Some("2.0.0"));
        assert_eq!(range_floor("(, 3.0.0)"), None);
    }
}
