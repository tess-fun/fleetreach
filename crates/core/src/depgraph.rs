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
use std::sync::OnceLock;

/// A name-level dependency graph rooted at the scanned project.
#[derive(Debug, Default, Clone)]
pub struct DepGraph {
    root: String,
    edges: BTreeMap<String, BTreeSet<String>>,
    /// Each reachable node's BFS parent, from one BFS over the whole graph, built on the
    /// first [`DepGraph::chain_to`]: feeders ask for a chain per package, and a BFS per ask
    /// made a large lockfile quadratic.
    parents: OnceLock<BTreeMap<String, String>>,
}

impl DepGraph {
    /// A graph rooted at the project named `root` (the first element of every chain).
    pub fn new(root: impl Into<String>) -> Self {
        DepGraph {
            root: root.into(),
            edges: BTreeMap::new(),
            parents: OnceLock::new(),
        }
    }

    /// Record that `from` directly requires each name in `tos`.
    pub fn add_edges<I, S>(&mut self, from: &str, tos: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.parents = OnceLock::new();
        let set = self.edges.entry(from.to_string()).or_default();
        for to in tos {
            set.insert(to.into());
        }
    }

    /// The project the graph is rooted at.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Every `(from, to)` edge, sorted.
    pub fn edges(&self) -> impl Iterator<Item = (&str, &str)> {
        self.edges
            .iter()
            .flat_map(|(from, tos)| tos.iter().map(move |to| (from.as_str(), to.as_str())))
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
        let parents = self.parents.get_or_init(|| self.bfs_parents());
        if !parents.contains_key(target) {
            return Vec::new();
        }
        let mut path = vec![target.to_string()];
        let mut cursor = target;
        while let Some(parent) = parents.get(cursor) {
            path.push(parent.clone());
            cursor = parent;
        }
        path.reverse();
        path
    }

    /// The parent of every node reachable from the root, as a BFS first reaches it. A BFS
    /// fixes a node's parent on first visit, so walking these parents up from any target is
    /// the same chain a BFS stopped at that target finds.
    fn bfs_parents(&self) -> BTreeMap<String, String> {
        let mut parents: BTreeMap<String, String> = BTreeMap::new();
        let mut visited: BTreeSet<&str> = BTreeSet::from([self.root.as_str()]);
        let mut queue: VecDeque<&str> = VecDeque::from([self.root.as_str()]);
        while let Some(node) = queue.pop_front() {
            for dep in self.edges.get(node).into_iter().flatten() {
                if visited.insert(dep.as_str()) {
                    parents.insert(dep.clone(), node.to_string());
                    queue.push_back(dep.as_str());
                }
            }
        }
        parents
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

    #[test]
    fn edges_added_after_a_chain_are_seen() {
        let mut g = DepGraph::new("app");
        g.add_edges("app", ["a"]);
        assert!(g.chain_to("b").is_empty());
        g.add_edges("a", ["b"]);
        assert_eq!(g.chain_to("b"), vec!["app", "a", "b"]);
    }

    /// The BFS that stops at its target, as `chain_to` ran before the parents were cached.
    fn chain_by_bfs(g: &DepGraph, target: &str) -> Vec<String> {
        if g.edges.is_empty() || g.root == target {
            return Vec::new();
        }
        let mut pred: BTreeMap<&str, &str> = BTreeMap::new();
        let mut visited: BTreeSet<&str> = BTreeSet::from([g.root.as_str()]);
        let mut queue: VecDeque<&str> = VecDeque::from([g.root.as_str()]);
        while let Some(node) = queue.pop_front() {
            if node == target {
                break;
            }
            for dep in g.edges.get(node).into_iter().flatten() {
                if visited.insert(dep.as_str()) {
                    pred.insert(dep.as_str(), node);
                    queue.push_back(dep.as_str());
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

    #[test]
    fn cached_chains_match_a_bfs_per_target() {
        // Pseudo-random graphs with cycles, self-edges, edges into the root and unreachable
        // nodes: every chain must equal the one a BFS stopped at that target finds.
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = |n: u64| {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            (seed >> 33) % n
        };
        for _ in 0..300 {
            let nodes = 2 + next(30);
            let name = |i: u64| {
                if i == 0 {
                    "root".to_string()
                } else {
                    format!("n{i}")
                }
            };
            let mut g = DepGraph::new("root");
            for _ in 0..next(nodes * 3) {
                let from = name(next(nodes));
                let to = name(next(nodes));
                g.add_edges(&from, [to]);
            }
            for i in 0..=nodes {
                let target = name(i);
                assert_eq!(
                    g.chain_to(&target),
                    chain_by_bfs(&g, &target),
                    "{g:?} {target}"
                );
            }
        }
    }
}
