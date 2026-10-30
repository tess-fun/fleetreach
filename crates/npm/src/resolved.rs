//! A lockfile-agnostic resolved dependency graph, shared by the pnpm and yarn readers
//! (spec 02). Each reader turns its format into [`Resolved`] nodes plus root edges; this
//! module derives what the matcher needs from that, exactly as `package-lock.json` does:
//! the deduplicated [`InstalledPackage`] set (direct, dev) and the name-level [`DepGraph`]
//! for `dependency_path`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fleetreach_core::DepGraph;

use crate::lockfile::InstalledPackage;

/// One resolved package instance. `id` is the reader's own unique key (a pnpm snapshot key,
/// a yarn resolution); several ids may share a `(name, version)`.
#[derive(Debug, Clone)]
pub(crate) struct Node {
    pub name: String,
    pub version: String,
    /// Ids of this node's dependencies (including optional ones).
    pub deps: Vec<String>,
}

/// A lockfile's resolved graph plus its roots.
#[derive(Debug, Default)]
pub(crate) struct Resolved {
    /// The project name for the graph root (`(root)` when unknown).
    pub root_name: String,
    pub nodes: BTreeMap<String, Node>,
    /// Ids the project depends on for runtime (`dependencies`, `optionalDependencies`).
    pub prod_roots: BTreeSet<String>,
    /// Ids the project depends on only for development (`devDependencies`).
    pub dev_roots: BTreeSet<String>,
}

impl Resolved {
    /// Derive the installed-package set and the name-level graph.
    ///
    /// `direct`: the node is a root of the project (or of a workspace member). `dev`: no
    /// runtime root reaches it. When the reader could not tell dev from prod (no roots at
    /// all), everything is runtime, the conservative choice (a dev finding still gates, but
    /// a runtime label never hides one).
    pub fn into_parts(self) -> (Vec<InstalledPackage>, DepGraph) {
        let prod_reach = self.reach(self.prod_roots.iter());
        let no_roots = self.prod_roots.is_empty() && self.dev_roots.is_empty();

        let mut graph = DepGraph::new(self.root_name.clone());
        let root_names = self
            .prod_roots
            .iter()
            .chain(&self.dev_roots)
            .filter_map(|id| self.nodes.get(id))
            .map(|n| n.name.clone());
        graph.add_edges(&self.root_name, root_names);

        let mut found: BTreeMap<(String, String), (bool, bool)> = BTreeMap::new();
        for (id, node) in &self.nodes {
            graph.add_edges(
                &node.name,
                node.deps
                    .iter()
                    .filter_map(|d| self.nodes.get(d))
                    .map(|n| n.name.clone()),
            );
            let direct = self.prod_roots.contains(id) || self.dev_roots.contains(id);
            let dev = !no_roots && !prod_reach.contains(id.as_str());
            let entry = found
                .entry((node.name.clone(), node.version.clone()))
                .or_insert((false, true));
            entry.0 |= direct;
            entry.1 &= dev;
        }
        let installed = found
            .into_iter()
            .map(|((name, version), (direct, dev))| InstalledPackage {
                name,
                version,
                direct,
                dev,
            })
            .collect();
        (installed, graph)
    }

    /// Every id reachable from `roots` (inclusive).
    fn reach<'a>(&'a self, roots: impl Iterator<Item = &'a String>) -> BTreeSet<&'a str> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut queue: VecDeque<&str> = roots.map(String::as_str).collect();
        while let Some(id) = queue.pop_front() {
            if !seen.insert(id) {
                continue;
            }
            if let Some(node) = self.nodes.get(id) {
                queue.extend(node.deps.iter().map(String::as_str));
            }
        }
        seen
    }
}

/// Split `name@version` at the `@` that ends the name (a scoped name starts with `@`).
pub(crate) fn split_name_version(s: &str) -> Option<(&str, &str)> {
    let at = s.get(1..)?.find('@')? + 1;
    let (name, rest) = s.split_at(at);
    let version = rest.get(1..)?;
    (!name.is_empty() && !version.is_empty()).then_some((name, version))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn node(name: &str, version: &str, deps: &[&str]) -> Node {
        Node {
            name: name.into(),
            version: version.into(),
            deps: deps.iter().map(|d| d.to_string()).collect(),
        }
    }

    #[test]
    fn splits_scoped_and_plain_names() {
        assert_eq!(
            split_name_version("lodash@4.17.21"),
            Some(("lodash", "4.17.21"))
        );
        assert_eq!(
            split_name_version("@babel/core@7.24.0"),
            Some(("@babel/core", "7.24.0"))
        );
        assert_eq!(split_name_version("lodash"), None);
        assert_eq!(split_name_version("@scope/only"), None);
    }

    #[test]
    fn dev_is_only_what_no_runtime_root_reaches() {
        let mut r = Resolved {
            root_name: "app".into(),
            ..Resolved::default()
        };
        r.nodes
            .insert("a@1".into(), node("a", "1.0.0", &["shared@1"]));
        r.nodes.insert(
            "t@1".into(),
            node("t", "1.0.0", &["shared@1", "only-dev@1"]),
        );
        r.nodes
            .insert("shared@1".into(), node("shared", "1.0.0", &[]));
        r.nodes
            .insert("only-dev@1".into(), node("only-dev", "1.0.0", &[]));
        r.prod_roots.insert("a@1".into());
        r.dev_roots.insert("t@1".into());
        let (installed, graph) = r.into_parts();
        let get = |n: &str| installed.iter().find(|p| p.name == n).unwrap();
        assert!(get("a").direct && !get("a").dev);
        assert!(get("t").direct && get("t").dev);
        assert!(!get("shared").direct && !get("shared").dev);
        assert!(!get("only-dev").direct && get("only-dev").dev);
        assert_eq!(graph.chain_to("only-dev"), vec!["app", "t", "only-dev"]);
    }
}
