//! Sound static reachability over a Rust call graph, with a witness chain.
//!
//! A dependency advisory tells you a crate *contains* a vulnerable function, but
//! most of the time your code never calls it, so the finding is noise.
//!
//! `fleetreach-reach` decides whether a sink (the vulnerable function) is
//! reachable from your roots over the compiled call graph, and reports the call
//! chain when it is. Because it backs a security tool, it is **sound for the
//! negative claim**: it returns `NotReachable` only when there is genuinely no
//! path from a root to the sink in the (over-approximating) graph. Every
//! uncertainty resolves to `Reachable` or `Unknown`, never a false
//! `NotReachable`. That trustworthy negative is what an optimizing call graph
//! (which under-approximates) cannot give you, and what lets a `NotReachable`
//! verdict actually suppress noise.
//!
//! # Usage
//!
//! ```sh
//! cargo add fleetreach-reach
//! ```
//!
//! Given a call graph (built inline here; in practice emitted by the driver),
//! `analyze` returns a `Verdict` per sink, with the shortest witness chain when
//! it is reachable:
//!
//! ```
//! # fn main() -> Result<(), fleetreach_reach::ReachError> {
//! use fleetreach_reach::{analyze, parse_graph, Verdict};
//!
//! // A tiny graph: `main` calls a vulnerable function directly.
//! let graph = parse_graph(
//!     r#"{
//!         "schema": 2,
//!         "nodes": [
//!             {"id": 0, "label": "main",          "symbol": "s0"},
//!             {"id": 1, "label": "vulnerable_fn", "symbol": "s1"}
//!         ],
//!         "edges": [{"from": 0, "to": 1, "kind": "direct"}],
//!         "roots": [0],
//!         "sinks": [1]
//!     }"#,
//! )?;
//!
//! let analysis = analyze(&graph)?;
//! let Verdict::Reachable { witness } = &analysis.verdicts[0].verdict else {
//!     unreachable!("the sink is called directly from a root");
//! };
//! assert_eq!(witness.join(" -> "), "main -> vulnerable_fn");
//! # Ok(()) }
//! ```
//!
//! # How it works
//!
//! Nodes are monomorphized function instances. Edges are `Direct` calls,
//! `Virtual` (`dyn`) dispatch, `Indirect` (fn-pointer) calls, and an `Opaque`
//! frontier for FFI / inline asm / unresolved indirection. A query runs two BFS
//! passes from the roots: a sink reached through analyzable edges is `Reachable`
//! (with a witness); one reachable only across the opaque frontier is `Unknown`;
//! one reached by neither is `NotReachable`.
//!
//! This is the analysis half of the `fleetreach` `--reachability=static` engine:
//! the companion `fleetreach-reach-driver` compiles the target under a pinned
//! nightly and reads rustc's own monomorphization set, so the node universe is
//! sound by codegen rather than a hand-audited walk, and this crate merges the
//! per-crate fragments and answers the query.
//!
//! # Minimum supported Rust version
//!
//! 1.89. An MSRV increase is treated as a minor-version bump.
//!
//! # Safety
//!
//! This crate sets `#![forbid(unsafe_code)]`; all `rustc_private` use is
//! quarantined in the separate `fleetreach-reach-driver` binary.

mod cache;
mod merge;
mod model;
mod project;
mod sandbox;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

pub use merge::merge;
pub use model::{
    CallGraph, Edge, EdgeKind, Node, SinkPath, VirtualCall, VirtualImpl, SUPPORTED_SCHEMA,
};
pub use project::{
    analyze_project, analyze_project_cached, BuildConfig, CachedAnalysis, FeatureSelection,
    ProjectAnalysis, ProjectOptions,
};
pub use sandbox::{Confinement, SandboxPolicy};

/// Why an analysis could not run *at all* — distinct from a per-sink
/// [`Verdict::Unknown`], which is a normal, sound outcome. Upstream errors are
/// flattened to a `Display` string so no foreign error type leaks across the API.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReachError {
    /// The graph's `schema` is not one this build understands — a skew between
    /// the `reach-driver` that produced it and this crate. Fail loud rather than
    /// misinterpret an unknown wire format.
    #[error("unsupported call-graph schema {found} (this build understands {supported})")]
    UnsupportedSchema {
        /// The schema version found in the graph.
        found: u32,
        /// The schema version this build supports ([`SUPPORTED_SCHEMA`]).
        supported: u32,
    },
    /// The graph JSON did not parse, or it references a node id that no node
    /// declares (a dangling edge, root, or sink).
    #[error("malformed call graph: {0}")]
    Malformed(String),
    /// A filesystem operation failed — reading a graph fragment, or reading or
    /// writing the graph cache.
    #[error("i/o error: {0}")]
    Io(String),
    /// Driving the cargo build under the wrapper failed: cargo could not be
    /// spawned, the build itself errored, or it emitted no graph fragments.
    #[error("could not build the project for analysis: {0}")]
    Build(String),
}

/// The reachability outcome for a single sink.
///
/// Mirrors `fleetreach_core::ReachVerdict` by design: `reach` is a
/// self-contained analysis library that does not depend on the fleetreach domain
/// model, so the cli maps this onto `core` at the composition boundary — exactly
/// as `scan` maps `rustsec` types onto `core`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A concrete call chain exists; `witness` is `root -> … -> sink` (labels).
    Reachable {
        /// The shortest call chain from a root to the sink, as node labels.
        witness: Vec<String>,
    },
    /// Sound: no path from any root to this sink in the (over-approximating)
    /// graph — neither through analyzable code nor across the opaque frontier.
    NotReachable,
    /// Could not be decided soundly — e.g. the sink resolved to no node, or it is
    /// reachable only across an opaque boundary. Never asserts absence.
    Unknown {
        /// A human-readable explanation of why the verdict is undecided.
        reason: String,
    },
}

/// One sink's outcome: its identifier plus the [`Verdict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkVerdict {
    /// The sink's human-readable node label, or the requested path when the sink
    /// resolved to no node (an unresolved sink).
    pub sink: String,
    /// The reachability verdict for this sink.
    pub verdict: Verdict,
}

/// The full per-sink analysis of one graph, in `graph.sinks` order followed by
/// unresolved sinks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    /// One entry per analyzed sink.
    pub verdicts: Vec<SinkVerdict>,
}

/// Analyze a graph using the roots the driver resolved (bin `main`, etc.).
pub fn analyze(graph: &CallGraph) -> Result<Analysis, ReachError> {
    analyze_with_roots(graph, &graph.roots)
}

/// Analyze a graph against an explicit root set (overriding `graph.roots`).
/// Used for library roots and for testing the verdict trichotomy.
pub fn analyze_with_roots(graph: &CallGraph, roots: &[u32]) -> Result<Analysis, ReachError> {
    if graph.schema != SUPPORTED_SCHEMA {
        return Err(ReachError::UnsupportedSchema {
            found: graph.schema,
            supported: SUPPORTED_SCHEMA,
        });
    }

    // One topology, two BFS passes: `clean` traverses only analyzable edges (for
    // a crisp verdict + witness); `full` also crosses the opaque frontier (FFI /
    // inline asm / unresolved indirect). A sink reachable only in `full` is one we
    // cannot rule out through unknown code — `Unknown`, never `NotReachable`.
    let topo = Topo::build(graph)?;
    let clean = topo.reach(roots, false)?;
    let full = topo.reach(roots, true)?;

    let mut verdicts = Vec::new();

    // Resolved sinks: decide reachability and build a witness.
    for &sink in &graph.sinks {
        let label = topo.label_of(sink)?;
        let verdict = if let Some(witness) = clean.witness_to(&topo, sink) {
            Verdict::Reachable { witness }
        } else if full.is_reached(sink) {
            Verdict::Unknown {
                reason: OPAQUE_ONLY.to_string(),
            }
        } else {
            Verdict::NotReachable
        };
        verdicts.push(SinkVerdict {
            sink: label.to_string(),
            verdict,
        });
    }

    // Unresolved sinks are never NotReachable — they are Unknown.
    for path in &graph.unresolved_sinks {
        verdicts.push(SinkVerdict {
            sink: path.clone(),
            verdict: Verdict::Unknown {
                reason: UNRESOLVED_SINK.to_string(),
            },
        });
    }

    Ok(Analysis { verdicts })
}

/// Reason text for a sink reachable only across the opaque frontier.
const OPAQUE_ONLY: &str =
    "reachable only across an opaque boundary (FFI / inline asm / unresolved indirect call); \
     cannot prove unreachable";
/// Reason text for a sink that resolved to no node.
const UNRESOLVED_SINK: &str = "sink path resolved to no node in this build";

/// Vec-indexed graph topology — built once, then reused for the clean and full
/// BFS. Node ids are dense (`0..n`), so arrays beat hashmaps for both build and
/// lookup, and a single shared topology avoids rebuilding the adjacency twice.
struct Topo<'g> {
    /// `labels[id]` is the node's label, or `None` for a gap (no such node).
    labels: Vec<Option<&'g str>>,
    /// `adj[id]` is the node's out-edges.
    adj: Vec<Vec<Succ>>,
}

/// One out-edge: the callee and whether it crosses the opaque frontier.
#[derive(Clone, Copy)]
struct Succ {
    to: u32,
    opaque: bool,
}

/// Predecessor sentinels (node ids never reach `u32::MAX`).
const UNVISITED: u32 = u32::MAX;
const ROOT: u32 = u32::MAX - 1;

impl<'g> Topo<'g> {
    fn build(graph: &'g CallGraph) -> Result<Self, ReachError> {
        // Node ids are dense (`0..n`) in every graph the driver/merge produce, so
        // they index Vecs directly. Reject ids `>= node count` rather than trust
        // an untrusted graph (cache/fragment) whose huge id would force a
        // multi-GB allocation.
        let len = graph.nodes.len();
        let mut labels = vec![None; len];
        for node in &graph.nodes {
            let i = node.id as usize;
            if i >= len {
                return Err(ReachError::Malformed(format!(
                    "node id {} out of range (graph has {len} nodes)",
                    node.id
                )));
            }
            labels[i] = Some(node.label.as_str());
        }

        let exists =
            |labels: &[Option<&str>], id: u32| labels.get(id as usize).copied().flatten().is_some();
        let mut adj: Vec<Vec<Succ>> = vec![Vec::new(); len];
        for edge in &graph.edges {
            if !exists(&labels, edge.from) {
                return Err(ReachError::Malformed(format!(
                    "edge from unknown node id {}",
                    edge.from
                )));
            }
            if !exists(&labels, edge.to) {
                return Err(ReachError::Malformed(format!(
                    "edge to unknown node id {}",
                    edge.to
                )));
            }
            adj[edge.from as usize].push(Succ {
                to: edge.to,
                opaque: edge.kind == EdgeKind::Opaque,
            });
        }

        Ok(Topo { labels, adj })
    }

    fn label_of(&self, id: u32) -> Result<&'g str, ReachError> {
        self.labels
            .get(id as usize)
            .copied()
            .flatten()
            .ok_or_else(|| ReachError::Malformed(format!("sink references unknown node id {id}")))
    }

    /// Multi-source BFS. With `include_opaque` false, opaque-frontier edges are
    /// skipped, so the result reflects only analyzable call paths.
    fn reach(&self, roots: &[u32], include_opaque: bool) -> Result<Reached, ReachError> {
        let mut pred = vec![UNVISITED; self.labels.len()];
        let mut queue: VecDeque<u32> = VecDeque::new();
        for &root in roots {
            if self.labels.get(root as usize).copied().flatten().is_none() {
                return Err(ReachError::Malformed(format!(
                    "root is unknown node id {root}"
                )));
            }
            // First visit wins (FIFO ⇒ shortest path); roots are marked `ROOT`.
            if pred[root as usize] == UNVISITED {
                pred[root as usize] = ROOT;
                queue.push_back(root);
            }
        }
        while let Some(node) = queue.pop_front() {
            for succ in &self.adj[node as usize] {
                if !include_opaque && succ.opaque {
                    continue;
                }
                if pred[succ.to as usize] == UNVISITED {
                    pred[succ.to as usize] = node;
                    queue.push_back(succ.to);
                }
            }
        }
        Ok(Reached { pred })
    }
}

/// A BFS result: `pred[id]` is the node we arrived from, or `ROOT`/`UNVISITED`.
struct Reached {
    pred: Vec<u32>,
}

impl Reached {
    fn is_reached(&self, id: u32) -> bool {
        self.pred.get(id as usize).is_some_and(|&p| p != UNVISITED)
    }

    /// If `sink` is reached, reconstruct the shortest witness chain
    /// `root -> … -> sink` as labels (needs the topology for labels).
    fn witness_to(&self, topo: &Topo, sink: u32) -> Option<Vec<String>> {
        if self.pred.get(sink as usize).copied().unwrap_or(UNVISITED) == UNVISITED {
            return None;
        }
        let mut chain = Vec::new();
        let mut cur = sink;
        loop {
            let label = topo
                .labels
                .get(cur as usize)
                .copied()
                .flatten()
                .unwrap_or("<unknown>");
            chain.push(label.to_string());
            let p = self.pred[cur as usize];
            if p == ROOT {
                break;
            }
            cur = p;
        }
        chain.reverse();
        Some(chain)
    }
}

/// Per-requested-path verdicts: each advisory path the driver resolved (or
/// could not) mapped to one verdict, combining a path's monomorphizations.
/// Consumers attribute a verdict to an advisory function by exact path — node
/// labels are crate-local and would not match the crate-qualified path.
pub fn analyze_by_path(graph: &CallGraph) -> Result<BTreeMap<String, Verdict>, ReachError> {
    if graph.schema != SUPPORTED_SCHEMA {
        return Err(ReachError::UnsupportedSchema {
            found: graph.schema,
            supported: SUPPORTED_SCHEMA,
        });
    }
    let topo = Topo::build(graph)?;
    let clean = topo.reach(&graph.roots, false)?;
    let full = topo.reach(&graph.roots, true)?;

    let mut out: BTreeMap<String, Verdict> = BTreeMap::new();
    for sp in &graph.sink_paths {
        out.insert(
            sp.path.clone(),
            combine_nodes(&topo, &clean, &full, &sp.nodes),
        );
    }
    for path in &graph.unresolved_sinks {
        out.entry(path.clone()).or_insert_with(|| Verdict::Unknown {
            reason: "sink path resolved to no node in this build".to_string(),
        });
    }
    Ok(out)
}

/// Resolve advisory sink paths against a (possibly cached) graph, a verdict per
/// path. Sinks match each node's crate-qualified `path`, so this re-runs on a
/// cache hit with no rebuild. A path matching no node is `Unknown`.
pub fn analyze_paths(
    graph: &CallGraph,
    advisory_paths: &[String],
) -> Result<BTreeMap<String, Verdict>, ReachError> {
    if graph.schema != SUPPORTED_SCHEMA {
        return Err(ReachError::UnsupportedSchema {
            found: graph.schema,
            supported: SUPPORTED_SCHEMA,
        });
    }
    let topo = Topo::build(graph)?;
    let clean = topo.reach(&graph.roots, false)?;
    let full = topo.reach(&graph.roots, true)?;

    // Index nodes by their crate-qualified path with generic args removed: a
    // node path is `smallvec::SmallVec::<A>::insert_many`, but a RustSec advisory
    // names the function as `smallvec::SmallVec::insert_many`. Normalizing both
    // sides lets every monomorphization of the affected fn match. This widens the
    // matched set (more sink nodes), which can only ever make a sink *more*
    // reachable, never produce a false `NotReachable`.
    let mut nodes_by_path: HashMap<String, Vec<u32>> = HashMap::new();
    for node in &graph.nodes {
        if let Some(p) = &node.path {
            nodes_by_path
                .entry(strip_generics(p))
                .or_default()
                .push(node.id);
        }
    }

    // Positive evidence for the uninstantiated-generic carve-out: the set of
    // exported generic fn defs the build saw (normalized like the node paths), and
    // the crates it fully scanned. A generic fn is codegen'd only on instantiation,
    // so "the driver recorded this generic def" + "no monomorphized node matches"
    // together prove it is never called — soundly `NotReachable`, not `Unknown`.
    let generic_defs: HashSet<String> = graph
        .generic_fns
        .iter()
        .map(|p| strip_generics(p))
        .collect();
    let scanned: HashSet<&str> = graph.scanned_crates.iter().map(String::as_str).collect();

    let mut out: BTreeMap<String, Verdict> = BTreeMap::new();
    for path in advisory_paths {
        let key = strip_generics(path);
        let verdict = match nodes_by_path.get(&key) {
            Some(node_ids) => combine_nodes(&topo, &clean, &full, node_ids),
            // No monomorphized node matches. Stay `Unknown` *unless* we hold
            // positive evidence the absence is genuine: the path names a known
            // exported generic def, and its defining crate was actually scanned.
            // A path that matches neither a node nor a recorded generic def could
            // be a format skew (the bug `strip_generics` fixed for the matched
            // case), so it must fail closed — never a false `NotReachable`.
            None if generic_defs.contains(&key) && scanned.contains(crate_of(&key)) => {
                Verdict::NotReachable
            }
            None => Verdict::Unknown {
                reason: "advisory function resolved to no node in this build".to_string(),
            },
        };
        out.insert(path.clone(), verdict);
    }
    Ok(out)
}

/// The crate segment of a crate-qualified path (`smallvec::SmallVec::insert_many`
/// → `smallvec`).
fn crate_of(path: &str) -> &str {
    path.split("::").next().unwrap_or(path)
}

/// A crate-qualified path with every generic-argument group removed and the
/// empty segments a turbofish leaves behind collapsed:
/// `smallvec::SmallVec::<A>::insert_many` -> `smallvec::SmallVec::insert_many`.
fn strip_generics(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut depth = 0i32;
    for c in path.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            _ if depth <= 0 => out.push(c),
            _ => {}
        }
    }
    out.split("::")
        .filter(|seg| !seg.is_empty())
        .collect::<Vec<_>>()
        .join("::")
}

/// Combine a path's monomorphizations: Reachable (with the first clean witness)
/// if any is cleanly reachable; Unknown if any is reachable only across the
/// opaque frontier; else NotReachable.
fn combine_nodes(topo: &Topo, clean: &Reached, full: &Reached, nodes: &[u32]) -> Verdict {
    let mut witness: Option<Vec<String>> = None;
    let mut full_reached = false;
    for &node in nodes {
        if witness.is_none() {
            witness = clean.witness_to(topo, node);
        }
        full_reached |= full.is_reached(node);
    }
    if let Some(w) = witness {
        Verdict::Reachable { witness: w }
    } else if full_reached {
        Verdict::Unknown {
            reason: OPAQUE_ONLY.to_string(),
        }
    } else {
        Verdict::NotReachable
    }
}

/// Byte ceiling for a single graph file (cache entry or per-crate fragment) read
/// from disk. Whole-closure graphs at fleet scale are tens of MB; this bounds a
/// malformed or hostile file (e.g. a `build.rs`-planted fragment) from forcing a
/// multi-GB read/allocation. Over the cap fails closed (rebuild / `Unknown`).
pub(crate) const MAX_GRAPH_BYTES: u64 = 512 * 1024 * 1024;
/// Node-count ceiling for a parsed graph — well above any real closure (~10^5),
/// a backstop on `Topo`'s per-node allocations against a small-but-numerous-nodes file.
const MAX_NODES: usize = 20_000_000;
/// Edge-count ceiling for a parsed graph.
const MAX_EDGES: usize = 80_000_000;

/// Parse a call graph from the driver's JSON output, rejecting an implausibly
/// large graph (a resource-exhaustion guard on untrusted fragment/cache JSON).
pub fn parse_graph(json: &str) -> Result<CallGraph, ReachError> {
    let graph: CallGraph =
        serde_json::from_str(json).map_err(|e| ReachError::Malformed(e.to_string()))?;
    if graph.nodes.len() > MAX_NODES || graph.edges.len() > MAX_EDGES {
        return Err(ReachError::Malformed(format!(
            "graph too large: {} nodes / {} edges exceeds the cap ({MAX_NODES} / {MAX_EDGES})",
            graph.nodes.len(),
            graph.edges.len()
        )));
    }
    Ok(graph)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{analyze_paths, parse_graph, strip_generics, Verdict};

    /// A minimal graph: one reachable `main`, no node for the advisory fn, plus
    /// the positive-evidence fields. `generic_fns`/`scanned_crates` are spliced in
    /// per test.
    fn graph_json(generic_fns: &str, scanned_crates: &str) -> String {
        format!(
            r#"{{
                "schema": 2,
                "nodes": [{{"id": 0, "label": "main", "symbol": "s0", "path": "bin::main"}}],
                "edges": [],
                "roots": [0],
                "sinks": [],
                "generic_fns": [{generic_fns}],
                "scanned_crates": [{scanned_crates}]
            }}"#
        )
    }

    #[test]
    fn uninstantiated_generic_in_scanned_crate_is_not_reachable() {
        // The advisory names a generic dep fn that was recorded as an exported
        // generic def but never monomorphized → genuinely never called.
        let graph = parse_graph(&graph_json(
            r#""smallvec::SmallVec::<A>::insert_many""#,
            r#""smallvec""#,
        ))
        .expect("parse");
        let out = analyze_paths(&graph, &["smallvec::SmallVec::insert_many".to_string()])
            .expect("analyze");
        assert_eq!(
            out["smallvec::SmallVec::insert_many"],
            Verdict::NotReachable
        );
    }

    #[test]
    fn unknown_generic_def_stays_unknown() {
        // No matching node and no recorded generic def for this path → it could be
        // a path-format skew, so it must fail closed to Unknown, never NotReachable.
        let graph = parse_graph(&graph_json("", r#""smallvec""#)).expect("parse");
        let out = analyze_paths(&graph, &["smallvec::SmallVec::insert_many".to_string()])
            .expect("analyze");
        assert!(matches!(
            out["smallvec::SmallVec::insert_many"],
            Verdict::Unknown { .. }
        ));
    }

    #[test]
    fn generic_def_in_unscanned_crate_stays_unknown() {
        // Recorded generic def but its crate is not in scanned_crates (e.g. a v2
        // graph that never populated it) → fail closed, no false NotReachable.
        let graph = parse_graph(&graph_json(r#""smallvec::SmallVec::<A>::insert_many""#, ""))
            .expect("parse");
        let out = analyze_paths(&graph, &["smallvec::SmallVec::insert_many".to_string()])
            .expect("analyze");
        assert!(matches!(
            out["smallvec::SmallVec::insert_many"],
            Verdict::Unknown { .. }
        ));
    }

    #[test]
    fn strip_generics_matches_rustsec_paths() {
        // A method on a generic type: the node carries `<A>`, the advisory does not.
        assert_eq!(
            strip_generics("smallvec::SmallVec::<A>::insert_many"),
            "smallvec::SmallVec::insert_many"
        );
        // Generic args directly on the type, no turbofish.
        assert_eq!(strip_generics("foo::Bar<T>::baz"), "foo::Bar::baz");
        // Nested generics.
        assert_eq!(strip_generics("a::B::<C<D>>::m"), "a::B::m");
        // No generics: unchanged.
        assert_eq!(
            strip_generics("time::UtcOffset::local_offset_at"),
            "time::UtcOffset::local_offset_at"
        );
    }
}
