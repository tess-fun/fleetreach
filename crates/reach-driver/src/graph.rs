//! The serialized call-graph fragment emitted on stdout — the only thing that
//! crosses the `rustc_private` quarantine. The safe `reach` crate deserializes
//! it and never sees a compiler type, so it is kept small and versioned (a
//! `schema` field, stable string identities).

use std::collections::HashMap;

use serde::Serialize;

/// Bump when the wire format changes incompatibly. v2 added the coercion facts
/// (`coercions`/`imprecise_traits`/`scanned_crates` + `VirtualImpl::{self_key,
/// trait_key}`) for the sound cross-crate `dyn`-target prune in `merge`.
pub const SCHEMA_VERSION: u32 = 2;

/// A monomorphized function instance — one call-graph node.
#[derive(Serialize)]
pub struct Node {
    pub id: u32,
    /// Human-readable, generic args included: `identity::<u32>`.
    pub label: String,
    /// Mangled symbol name — globally unique per monomorphization; the join key.
    pub symbol: String,
    /// Crate-qualified def path (no generic args) — how a consumer resolves an
    /// advisory sink against a cached graph without rebuilding. `None` for the
    /// opaque sentinel and other path-less nodes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// How a call edge dispatches.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Statically resolved callee (a concrete, non-virtual `Instance`).
    Direct,
    /// `dyn Trait` dispatch, RTA-resolved to mono-set impls of the trait method.
    Virtual,
    /// fn-pointer / closure dispatch to signature-compatible address-taken fns.
    Indirect,
    /// Into or out of the opaque frontier (FFI, inline asm, unresolved indirect).
    /// A sink reachable only across an `Opaque` edge is `Unknown`, never
    /// `NotReachable`.
    Opaque,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Edge {
    pub from: u32,
    pub to: u32,
    pub kind: EdgeKind,
}

/// The whole graph, as serialized.
#[derive(Serialize)]
pub struct CallGraph {
    pub schema: u32,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    /// Entry-point node ids (bin: `main`). Reachability is computed from these.
    pub roots: Vec<u32>,
    /// Node ids that are advisory sinks (every monomorphization of a resolved
    /// affected-function `DefId`).
    pub sinks: Vec<u32>,
    /// Requested sink paths that resolved to no node → `Unknown`, never
    /// `NotReachable`.
    pub unresolved_sinks: Vec<String>,
    /// Opaque-frontier node ids (unanalyzable external code).
    pub opaque: Vec<u32>,
    /// `dyn` call sites as facts, so cross-crate merge can resolve them against
    /// the union of impls (the receiver may be coerced in a different crate).
    pub virtual_calls: Vec<VirtualCall>,
    /// Trait-method impls in this fragment, the virtual-call targets.
    pub virtual_impls: Vec<VirtualImpl>,
    /// Resolved sinks: requested advisory path → matched node ids. Maps a verdict
    /// back to the advisory function (node labels are crate-local).
    pub sink_paths: Vec<SinkPath>,
    /// Receiver-type → trait coercions seen in this fragment (supertrait-closed).
    pub coercions: Vec<Coercion>,
    /// Traits whose coercion tracking is incomplete here (never pruned).
    pub imprecise_traits: Vec<String>,
    /// Crate(s) this fragment scanned fully for coercions (for the sysroot-keep
    /// rule in `merge`).
    pub scanned_crates: Vec<String>,
    /// Node ids opaque/external code could re-enter (exported ∪ address-taken).
    /// `merge` wires the global opaque sentinel to the union across all fragments.
    pub escaped: Vec<u32>,
    /// This fragment's `"<crate_name>-<stable_crate_id:016x>"`, matching its
    /// filename stem — `merge` rejects a fragment whose identity and filename disagree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crate_id: Option<String>,
    /// Exported generic ("requires monomorphization") fn defs in this crate, by
    /// crate-qualified path. A generic fn is codegen'd only when instantiated, so
    /// if an advisory names one and *no* monomorphization of it appears anywhere
    /// in the merged closure, it is genuinely never called — positive evidence
    /// that lets the consumer return a sound `NotReachable` rather than `Unknown`.
    /// Omitted for the primary library crate, whose exported API is treated as
    /// callable by a downstream consumer (see `emit_generic_fns`).
    pub generic_fns: Vec<String>,
}

/// A receiver-type → trait-object coercion fact (`self_key` coerced to
/// `dyn trait_key`); keys are crate-qualified paths so they join cross-fragment.
#[derive(Serialize)]
pub struct Coercion {
    pub self_key: String,
    pub trait_key: String,
}

/// A requested sink path and the call-graph nodes it resolved to.
#[derive(Serialize)]
pub struct SinkPath {
    pub path: String,
    pub nodes: Vec<u32>,
}

/// A `dyn Trait` call site; `method` is the trait method's crate-qualified path,
/// the cross-crate join key.
#[derive(Serialize)]
pub struct VirtualCall {
    pub from: u32,
    pub method: String,
}

/// A trait-method implementation available as a virtual-call target.
#[derive(Serialize)]
pub struct VirtualImpl {
    pub method: String,
    pub node: u32,
    /// Crate-qualified path of the impl's receiver-type head (`None` ⇒ never
    /// pruned, e.g. a primitive receiver).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_key: Option<String>,
    /// Crate-qualified path of the trait owning the method (`None` ⇒ never pruned).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trait_key: Option<String>,
}

/// Interns instances by their mangled symbol so each monomorphization maps to a
/// single stable node id, and accumulates deduped edges.
#[derive(Default)]
pub struct GraphBuilder {
    /// symbol -> node id
    index: HashMap<String, u32>,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    seen_edges: std::collections::HashSet<Edge>,
    /// Roots/sinks are tracked by symbol (the stable interner key) during the
    /// walk, then mapped to final node ids in `finish()` — node ids are
    /// reassigned there for determinism.
    root_symbols: std::collections::HashSet<String>,
    sink_symbols: std::collections::HashSet<String>,
    opaque_symbols: std::collections::HashSet<String>,
    unresolved_sinks: Vec<String>,
    /// (provisional caller id, stable method key)
    virtual_calls: Vec<(u32, String)>,
    /// (stable method key, provisional impl node id, self-type key, trait key)
    virtual_impls: Vec<(String, u32, Option<String>, Option<String>)>,
    /// (requested sink path, provisional matched node symbol)
    sink_paths: Vec<(String, String)>,
    /// (receiver-type key, trait key) coercions seen in this fragment.
    coercions: std::collections::HashSet<(String, String)>,
    /// Traits with incomplete coercion tracking here (never pruned in merge).
    imprecise_traits: std::collections::HashSet<String>,
    /// The crate names this fragment scanned fully for coercions.
    scanned_crates: Vec<String>,
    /// Exported generic fn defs in this crate (crate-qualified paths).
    generic_fns: std::collections::HashSet<String>,
    /// Provisional ids of escaped (exported ∪ address-taken) nodes; remapped to
    /// final ids in `finish`.
    escaped_ids: Vec<u32>,
    /// This fragment's crate identity (`<name>-<stable_crate_id:016x>`).
    crate_id: Option<String>,
}

/// The interner symbol of the single opaque-frontier sentinel node.
const OPAQUE_SENTINEL_SYMBOL: &str = "<opaque>";

impl GraphBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a node, returning its stable id. `symbol` is the uniqueness key;
    /// `label` is the human-readable form; `path` is the crate-qualified def path
    /// (the sink-resolution key). The first intern of a symbol wins.
    pub fn intern(
        &mut self,
        symbol: String,
        label: impl FnOnce() -> String,
        path: Option<String>,
    ) -> u32 {
        if let Some(&id) = self.index.get(&symbol) {
            return id;
        }
        let id = self.nodes.len() as u32;
        self.nodes.push(Node {
            id,
            label: label(),
            symbol: symbol.clone(),
            path,
        });
        self.index.insert(symbol, id);
        id
    }

    pub fn edge(&mut self, from: u32, to: u32, kind: EdgeKind) {
        let edge = Edge { from, to, kind };
        if self.seen_edges.insert(edge) {
            self.edges.push(edge);
        }
    }

    /// Mark a node (by interner symbol) as a reachability root.
    pub fn mark_root(&mut self, symbol: String) {
        self.root_symbols.insert(symbol);
    }

    /// Mark a node (by interner symbol) as an advisory sink.
    pub fn mark_sink(&mut self, symbol: String) {
        self.sink_symbols.insert(symbol);
    }

    /// Intern (idempotently) the opaque-frontier sentinel node and return its id.
    /// All unanalyzable call sites point here.
    pub fn opaque_sentinel(&mut self) -> u32 {
        let id = self.intern(
            OPAQUE_SENTINEL_SYMBOL.to_string(),
            || "⟨opaque external code⟩".to_string(),
            None,
        );
        self.opaque_symbols
            .insert(OPAQUE_SENTINEL_SYMBOL.to_string());
        id
    }

    /// Whether the opaque sentinel has been created (any opaque frontier exists).
    pub fn has_opaque(&self) -> bool {
        self.index.contains_key(OPAQUE_SENTINEL_SYMBOL)
    }

    /// Record sink paths that resolved to no node in this build.
    pub fn set_unresolved_sinks(&mut self, paths: Vec<String>) {
        self.unresolved_sinks = paths;
    }

    /// Record a `dyn Trait` call site (caller node, stable trait-method key).
    pub fn virtual_call(&mut self, from: u32, method: String) {
        self.virtual_calls.push((from, method));
    }

    /// Record a trait-method impl available as a virtual-call target, with the
    /// receiver-type key and trait key the coercion prune matches on.
    pub fn virtual_impl(
        &mut self,
        method: String,
        node: u32,
        self_key: Option<String>,
        trait_key: Option<String>,
    ) {
        self.virtual_impls.push((method, node, self_key, trait_key));
    }

    /// Record a receiver-type → trait-object coercion seen in this fragment.
    pub fn add_coercion(&mut self, self_key: String, trait_key: String) {
        self.coercions.insert((self_key, trait_key));
    }

    /// Mark a trait's coercion tracking incomplete (a `dyn*` or a trait object
    /// from a constant) — `merge` never prunes it.
    pub fn mark_imprecise(&mut self, trait_key: String) {
        self.imprecise_traits.insert(trait_key);
    }

    /// Record the crate this fragment fully scanned for coercions.
    pub fn set_scanned_crate(&mut self, name: String) {
        self.scanned_crates.push(name);
    }

    /// Record an exported generic fn def (crate-qualified path) of this crate.
    pub fn add_generic_fn(&mut self, path: String) {
        self.generic_fns.insert(path);
    }

    /// Record the escaped (opaque-reentrant) node set (provisional ids).
    pub fn set_escaped(&mut self, ids: Vec<u32>) {
        self.escaped_ids = ids;
    }

    /// Record this fragment's crate identity (matches its filename stem).
    pub fn set_crate_id(&mut self, id: String) {
        self.crate_id = Some(id);
    }

    /// Record that a requested sink `path` matched the node with `symbol`.
    pub fn sink_path(&mut self, path: String, symbol: String) {
        self.sink_paths.push((path, symbol));
    }

    /// Finalize into the serializable graph, with deterministic ordering
    /// (nodes by symbol, edges by (from, to)).
    pub fn finish(mut self) -> CallGraph {
        // Sort nodes by symbol for determinism (stable ids across runs), then
        // remap edge endpoints. Sort in place so the `Node` structs (and their
        // strings) are moved, never cloned, and reassign ids in one pass — the
        // result is already in id order, so no second sort is needed.
        self.nodes.sort_by(|a, b| a.symbol.cmp(&b.symbol));
        let mut remap = vec![0u32; self.nodes.len()];
        for (new_id, node) in self.nodes.iter_mut().enumerate() {
            remap[node.id as usize] = new_id as u32;
            node.id = new_id as u32;
        }
        let nodes = std::mem::take(&mut self.nodes);

        let mut edges: Vec<Edge> = self
            .edges
            .drain(..)
            .map(|e| Edge {
                from: remap[e.from as usize],
                to: remap[e.to as usize],
                kind: e.kind,
            })
            .collect();
        edges.sort_by_key(|e| (e.from, e.to));

        // Map the tracked root/sink symbols to their final node ids.
        let final_id = |symbol: &str| self.index.get(symbol).map(|&old| remap[old as usize]);
        let mut roots: Vec<u32> = self
            .root_symbols
            .iter()
            .filter_map(|s| final_id(s))
            .collect();
        let mut sinks: Vec<u32> = self
            .sink_symbols
            .iter()
            .filter_map(|s| final_id(s))
            .collect();
        let mut opaque: Vec<u32> = self
            .opaque_symbols
            .iter()
            .filter_map(|s| final_id(s))
            .collect();
        roots.sort_unstable();
        sinks.sort_unstable();
        opaque.sort_unstable();
        let mut unresolved_sinks = self.unresolved_sinks;
        unresolved_sinks.sort();

        // Group requested sink paths to their final node ids.
        let mut sink_path_map: std::collections::BTreeMap<String, Vec<u32>> = Default::default();
        for (path, symbol) in &self.sink_paths {
            if let Some(id) = final_id(symbol) {
                sink_path_map.entry(path.clone()).or_default().push(id);
            }
        }
        let sink_paths: Vec<SinkPath> = sink_path_map
            .into_iter()
            .map(|(path, mut nodes)| {
                nodes.sort_unstable();
                nodes.dedup();
                SinkPath { path, nodes }
            })
            .collect();

        let mut virtual_calls: Vec<VirtualCall> = self
            .virtual_calls
            .into_iter()
            .map(|(from, method)| VirtualCall {
                from: remap[from as usize],
                method,
            })
            .collect();
        virtual_calls.sort_by(|a, b| (a.from, &a.method).cmp(&(b.from, &b.method)));
        virtual_calls.dedup_by(|a, b| a.from == b.from && a.method == b.method);

        let mut virtual_impls: Vec<VirtualImpl> = self
            .virtual_impls
            .into_iter()
            .map(|(method, node, self_key, trait_key)| VirtualImpl {
                method,
                node: remap[node as usize],
                self_key,
                trait_key,
            })
            .collect();
        virtual_impls.sort_by(|a, b| (&a.method, a.node).cmp(&(&b.method, b.node)));
        virtual_impls.dedup_by(|a, b| a.method == b.method && a.node == b.node);

        let mut coercions: Vec<Coercion> = self
            .coercions
            .into_iter()
            .map(|(self_key, trait_key)| Coercion {
                self_key,
                trait_key,
            })
            .collect();
        coercions.sort_by(|a, b| (&a.self_key, &a.trait_key).cmp(&(&b.self_key, &b.trait_key)));
        let mut imprecise_traits: Vec<String> = self.imprecise_traits.into_iter().collect();
        imprecise_traits.sort();
        let mut generic_fns: Vec<String> = self.generic_fns.into_iter().collect();
        generic_fns.sort();
        let mut escaped: Vec<u32> = self
            .escaped_ids
            .iter()
            .map(|&old| remap[old as usize])
            .collect();
        escaped.sort_unstable();
        escaped.dedup();

        CallGraph {
            schema: SCHEMA_VERSION,
            nodes,
            edges,
            roots,
            sinks,
            unresolved_sinks,
            opaque,
            virtual_calls,
            virtual_impls,
            sink_paths,
            coercions,
            imprecise_traits,
            scanned_crates: self.scanned_crates,
            generic_fns,
            escaped,
            crate_id: self.crate_id,
        }
    }
}
