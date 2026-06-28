//! Parse a Julia `Manifest.toml` into a flat, deduplicated set of installed packages — the
//! input the OSV matcher scans. Read straight from the manifest, so it needs **no Julia
//! toolchain and no network**: `Manifest.toml` already pins the full dependency tree to exact
//! versions.
//!
//! Two manifest formats exist. The v2 format (Julia ≥ 1.7) nests packages under a `[deps]`
//! table; the older v1 format lists them at the top level:
//!
//! ```toml
//! # v2
//! manifest_format = "2.0"
//! [[deps.HTTP]]
//! uuid = "cd3eb016-..."
//! version = "1.9.0"
//! ```
//!
//! Both are handled. Standard-library packages carry no `version` and are skipped (no
//! registry release to match). `Manifest.toml` does not record which dependencies are direct,
//! so the direct set is read from the sibling `Project.toml`'s `[deps]` keys when present.
//! Julia package names are **case-sensitive** and matched verbatim.

use std::collections::{BTreeMap, BTreeSet};

use fleetreach_core::DepGraph;

/// One resolved package from `Manifest.toml`: its name (verbatim), exact installed version,
/// and whether the project depends on it **directly** (it appears in `Project.toml`'s
/// `[deps]`) rather than only transitively.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub direct: bool,
}

/// Parse `Manifest.toml` into a deduplicated, sorted set of installed packages plus a
/// name-level [`DepGraph`] for provenance (`pkg (via a → b)`). The optional `project_toml`
/// text marks the `direct` flag and roots the graph; without it every package is reported
/// transitive (a conservative under-claim that never hides a finding) and the graph has no
/// root edges.
///
/// The graph mirrors the manifest tree: each package's `deps` array (a list of dependency
/// package names) becomes edges `name -> dep`, and the project's direct deps become edges
/// `"(root)" -> name`. Nodes are verbatim Julia package names, matching the occurrence's
/// `package`, so [`DepGraph::chain_to`] resolves the introducer chain `[root, …, pkg]`.
///
/// # Errors
///
/// Returns the underlying [`toml::de::Error`] if `Manifest.toml` is not valid TOML — failing
/// closed. A malformed `Project.toml` is tolerated (the direct set is then empty).
pub fn installed_packages(
    manifest_toml: &str,
    project_toml: Option<&str>,
) -> Result<(Vec<InstalledPackage>, DepGraph), toml::de::Error> {
    let root: toml::Table = toml::from_str(manifest_toml)?;
    let direct = project_toml.map(direct_set).unwrap_or_default();

    // v2 nests the package list under `[deps]`; v1 lists packages at the top level (other
    // top-level keys like `julia_version` are scalars, filtered by the array-of-tables check).
    let sections: &toml::Table = match root.get("deps") {
        Some(toml::Value::Table(deps)) => deps,
        _ => &root,
    };

    let mut graph = DepGraph::new("(root)");
    graph.add_edges("(root)", direct.iter().cloned());

    let mut packages = Vec::new();
    for (name, value) in sections {
        let toml::Value::Array(entries) = value else {
            continue;
        };
        for entry in entries {
            // A `deps` field is a TOML array of dependency package names. The rare
            // table form (weak/extension deps) is not array-of-strings, so it is treated
            // as no edges — an honest "unknown provenance" fallback, never a wrong chain.
            if let Some(toml::Value::Array(deps)) = entry.get("deps") {
                graph.add_edges(
                    name,
                    deps.iter().filter_map(|d| d.as_str().map(str::to_string)),
                );
            }
            if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
                packages.push(InstalledPackage {
                    name: name.clone(),
                    version: version.to_string(),
                    direct: direct.contains(name),
                });
            }
        }
    }
    Ok((dedupe(packages), graph))
}

/// The direct-dependency names from a `Project.toml`: the keys of its `[deps]` table (each
/// maps a package name to a UUID). A malformed `Project.toml` yields an empty set.
fn direct_set(project_toml: &str) -> BTreeSet<String> {
    let Ok(root) = toml::from_str::<toml::Table>(project_toml) else {
        return BTreeSet::new();
    };
    match root.get("deps") {
        Some(toml::Value::Table(deps)) => deps.keys().cloned().collect(),
        _ => BTreeSet::new(),
    }
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

    const MANIFEST_V2: &str = r#"
julia_version = "1.9.0"
manifest_format = "2.0"

[[deps.HTTP]]
deps = ["Base64", "URIs"]
uuid = "cd3eb016-35fb-5094-929b-558a96fad6f3"
version = "1.9.0"

[[deps.OpenSSL_jll]]
uuid = "458c3c95-2e84-50aa-8efc-19380b2a3a95"
version = "3.0.8+0"

[[deps.Base64]]
uuid = "2a0f44e3-6c83-55bd-87e4-b1978d98bd5f"
"#;

    const PROJECT: &str = r#"
name = "MyApp"
[deps]
HTTP = "cd3eb016-35fb-5094-929b-558a96fad6f3"
"#;

    #[test]
    fn parses_v2_manifest_with_direct_set() {
        let (pkgs, _graph) = installed_packages(MANIFEST_V2, Some(PROJECT)).unwrap();
        assert_eq!(
            rows(&pkgs),
            vec![
                ("HTTP", "1.9.0", true),           // direct (in Project.toml)
                ("OpenSSL_jll", "3.0.8+0", false), // transitive, JLL build metadata kept
            ]
        );
        // Base64 is a stdlib package with no version → skipped.
        assert!(pkgs.iter().all(|p| p.name != "Base64"));
    }

    #[test]
    fn parses_v1_manifest_top_level() {
        let v1 = r#"
[[HTTP]]
uuid = "cd3eb016-35fb-5094-929b-558a96fad6f3"
version = "0.9.17"

[[JSON]]
version = "0.21.3"
"#;
        let (pkgs, _graph) = installed_packages(v1, None).unwrap();
        assert_eq!(
            rows(&pkgs),
            vec![("HTTP", "0.9.17", false), ("JSON", "0.21.3", false)]
        );
    }

    #[test]
    fn malformed_manifest_is_an_error() {
        assert!(installed_packages("not [ valid toml", None).is_err());
    }

    #[test]
    fn names_are_case_sensitive_verbatim() {
        let (pkgs, _graph) = installed_packages(MANIFEST_V2, None).unwrap();
        assert!(pkgs.iter().any(|p| p.name == "HTTP"));
        assert!(pkgs.iter().all(|p| p.name != "http"));
    }

    #[test]
    fn graph_chains_root_through_deps() {
        // (root) -> HTTP (direct, in Project.toml) -> URIs (transitive, via HTTP's `deps`).
        let manifest = r#"
manifest_format = "2.0"

[[deps.HTTP]]
deps = ["Base64", "URIs"]
uuid = "cd3eb016-35fb-5094-929b-558a96fad6f3"
version = "1.9.0"

[[deps.URIs]]
uuid = "5c2747f8-b7ea-4ff2-ba2e-563bfd36b1d4"
version = "1.4.2"
"#;
        let (_pkgs, graph) = installed_packages(manifest, Some(PROJECT)).unwrap();
        // A transitive package chains through its introducer.
        assert_eq!(graph.chain_to("URIs"), vec!["(root)", "HTTP", "URIs"]);
        // A direct package chains straight from the root.
        assert_eq!(graph.chain_to("HTTP"), vec!["(root)", "HTTP"]);
    }
}
