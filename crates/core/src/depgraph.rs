//! A name-level dependency graph + shortest introducer-chain BFS, shared by the
//! toolchain-free feeders to populate `dependency_path` (the `pkg (via a → b)` provenance)
//! without a toolchain.
//!
//! The graph is *name-level*: nodes are package names, edges are "directly requires". Each
//! feeder builds one from its lockfile (npm `packages` map, composer `require`, uv/poetry
//! `dependencies`), then asks [`DepGraph::chain_to`] for a representative shortest chain from
//! the root project down to a vulnerable package. The chain shape — `[root, …, target]`,
//! both ends included — matches the Rust native path so the report's middle-slice `via`
//! rendering is identical across ecosystems. An empty result is the honest "unknown
//! provenance" fallback (a flat lockfile with no edges), never a wrong chain.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// A name-level dependency graph rooted at the scanned project.
#[derive(Debug, Default, Clone)]
pub struct DepGraph {
    root: String,
    edges: BTreeMap<String, BTreeSet<String>>,
}

impl DepGraph {
    /// A graph rooted at the project named `root` (the first element of every chain).
    pub fn new(root: impl Into<String>) -> Self {
        DepGraph {
            root: root.into(),
            edges: BTreeMap::new(),
        }
    }

    /// Record that `from` directly requires each name in `tos`.
    pub fn add_edges<I, S>(&mut self, from: &str, tos: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let set = self.edges.entry(from.to_string()).or_default();
        for to in tos {
            set.insert(to.into());
        }
    }

    /// Whether the graph holds no edges (a flat lockfile with no resolvable tree).
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// A shortest chain of names `[root, …, target]` by which `target` is pulled into the
    /// project, via a multi-source-free BFS from the root. Empty when `target` is unreachable
    /// or the graph carries no edges — the honest "unknown provenance" fallback.
    pub fn chain_to(&self, target: &str) -> Vec<String> {
        if self.edges.is_empty() || self.root == target {
            return Vec::new();
        }
        let mut pred: BTreeMap<&str, &str> = BTreeMap::new();
        let mut visited: BTreeSet<&str> = BTreeSet::new();
        visited.insert(self.root.as_str());
        let mut queue: VecDeque<&str> = VecDeque::from([self.root.as_str()]);
        while let Some(node) = queue.pop_front() {
            if node == target {
                break;
            }
            if let Some(deps) = self.edges.get(node) {
                for dep in deps {
                    if visited.insert(dep.as_str()) {
                        pred.insert(dep.as_str(), node);
                        queue.push_back(dep.as_str());
                    }
                }
            }
        }
        if !visited.contains(target) {
            return Vec::new();
        }
        let mut path = vec![target.to_string()];
        let mut cursor = target;
        while let Some(&parent) = pred.get(cursor) {
            path.push(parent.to_string());
            cursor = parent;
        }
        path.reverse();
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_includes_root_and_target() {
        let mut g = DepGraph::new("app");
        g.add_edges("app", ["express", "lodash"]);
        g.add_edges("express", ["minimist"]);
        assert_eq!(g.chain_to("minimist"), vec!["app", "express", "minimist"]);
        assert_eq!(g.chain_to("lodash"), vec!["app", "lodash"]);
        assert!(g.chain_to("absent").is_empty());
    }

    #[test]
    fn empty_graph_yields_empty_chain() {
        assert!(DepGraph::default().chain_to("anything").is_empty());
        assert!(DepGraph::new("app").chain_to("x").is_empty());
    }

    #[test]
    fn shortest_of_multiple_paths_wins() {
        // app -> a -> target, and app -> b -> c -> target; BFS picks the 3-name chain.
        let mut g = DepGraph::new("app");
        g.add_edges("app", ["a", "b"]);
        g.add_edges("a", ["target"]);
        g.add_edges("b", ["c"]);
        g.add_edges("c", ["target"]);
        assert_eq!(g.chain_to("target"), vec!["app", "a", "target"]);
    }
}
