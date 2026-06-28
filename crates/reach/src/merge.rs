//! Merge per-crate fragments into the whole-closure call graph.
//!
//! Each fragment walks only its own crate's MIR, so a dependency's non-generic
//! functions are analyzable only in that dependency's fragment — the whole
//! closure exists only in the union. Nodes join on their mangled symbol.
//!
//! Cross-crate `dyn` dispatch is resolved here (keyed on the trait method's
//! crate-qualified path): a receiver may be coerced to the trait object in one
//! crate while the call is in another, so a virtual call targets every impl in
//! any fragment, pruned by `keep_impl`.

use std::collections::{HashMap, HashSet};

use std::collections::BTreeMap;

use crate::model::{CallGraph, Edge, EdgeKind, Node, SinkPath, SUPPORTED_SCHEMA};
use crate::ReachError;

/// A virtual-call target and the keys the coercion prune decides on.
struct VImpl<'a> {
    node: u32,
    self_key: Option<&'a str>,
    trait_key: Option<&'a str>,
}

/// The crate segment of a crate-qualified key (`gix::Repository` → `gix`).
fn crate_of(key: &str) -> &str {
    key.split("::").next().unwrap_or(key)
}

/// Whether to keep a virtual-dispatch edge to this impl. Kept (sound, possibly
/// over-approximating) unless we can *prove* the receiver type is never coerced
/// to this trait object anywhere in the closure. We keep when any holds:
/// either key is missing (a primitive receiver, or an older fragment); the trait
/// is imprecise (a `dyn*` / a const-built vtable we did not scan); the receiver's
/// defining crate was never scanned (a precompiled sysroot crate may coerce it in
/// code we cannot see); or the receiver *was* coerced to this trait (recorded,
/// supertrait-closed). Only when none holds — full coercion visibility and no
/// observed coercion — do we prune. A pruned edge is always a false `Reachable`;
/// reachability via a direct call or a real coercion is preserved by those edges.
fn keep_impl(
    vi: &VImpl,
    coerced: &HashMap<&str, HashSet<&str>>,
    imprecise: &HashSet<&str>,
    scanned_crates: &HashSet<&str>,
) -> bool {
    let (Some(self_key), Some(trait_key)) = (vi.self_key, vi.trait_key) else {
        return true;
    };
    imprecise.contains(trait_key)
        || !scanned_crates.contains(crate_of(self_key))
        || coerced.get(trait_key).is_some_and(|s| s.contains(self_key))
}

/// Merge fragments into one whole-closure graph.
pub fn merge(fragments: &[CallGraph]) -> Result<CallGraph, ReachError> {
    for f in fragments {
        if f.schema != SUPPORTED_SCHEMA {
            return Err(ReachError::UnsupportedSchema {
                found: f.schema,
                supported: SUPPORTED_SCHEMA,
            });
        }
    }

    // Intern nodes globally by symbol.
    let mut global_id: HashMap<&str, u32> = HashMap::new();
    let mut nodes: Vec<Node> = Vec::new();
    for f in fragments {
        for n in &f.nodes {
            global_id.entry(n.symbol.as_str()).or_insert_with(|| {
                let id = nodes.len() as u32;
                nodes.push(Node {
                    id,
                    label: n.label.clone(),
                    symbol: n.symbol.clone(),
                    path: n.path.clone(),
                });
                id
            });
        }
    }

    let mut edges: HashSet<Edge> = HashSet::new();
    let mut roots: HashSet<u32> = HashSet::new();
    let mut sinks: HashSet<u32> = HashSet::new();
    let mut opaque: HashSet<u32> = HashSet::new();
    // Union of every fragment's escaped (opaque-reentrant) nodes — wired to the
    // global sentinel below so cross-crate opaque re-entry is not lost (H-1).
    let mut escaped: HashSet<u32> = HashSet::new();
    let mut unresolved: HashSet<String> = HashSet::new();
    // Per impl: the node plus the keys the coercion prune matches on.
    let mut impls_by_method: HashMap<&str, Vec<VImpl>> = HashMap::new();
    let mut virtual_calls: Vec<(u32, &str)> = Vec::new();
    let mut sink_path_nodes: BTreeMap<&str, HashSet<u32>> = BTreeMap::new();

    // Global coercion facts unioned across fragments: which receiver types were
    // coerced to which trait object, which traits are imprecise (never prune),
    // and which crates were fully scanned (a receiver from an unscanned crate is
    // never pruned — its coercions may live in code we did not walk).
    let mut coerced: HashMap<&str, HashSet<&str>> = HashMap::new();
    let mut imprecise: HashSet<&str> = HashSet::new();
    let mut scanned_crates: HashSet<&str> = HashSet::new();
    // Exported generic fn defs across the closure (positive evidence for the
    // uninstantiated-generic → NotReachable carve-out in `analyze_paths`).
    let mut generic_fns: HashSet<&str> = HashSet::new();

    for f in fragments {
        // Local (fragment) id → global id for this fragment.
        let to_global: HashMap<u32, u32> = f
            .nodes
            .iter()
            .filter_map(|n| global_id.get(n.symbol.as_str()).map(|&g| (n.id, g)))
            .collect();
        let g = |local: u32| to_global.get(&local).copied();

        for e in &f.edges {
            // `Virtual` edges are re-resolved below from the portable
            // `virtual_call` facts *with the coercion prune applied*. The
            // driver also emits them in-fragment (for single-fragment Direct
            // analysis, which never merges), but those are un-pruned — copying
            // them here would defeat the prune. Every dyn call site has a
            // matching `virtual_call` fact, so dropping them loses nothing.
            if e.kind == EdgeKind::Virtual {
                continue;
            }
            if let (Some(from), Some(to)) = (g(e.from), g(e.to)) {
                edges.insert(Edge {
                    from,
                    to,
                    kind: e.kind,
                });
            }
        }
        roots.extend(f.roots.iter().filter_map(|&r| g(r)));
        sinks.extend(f.sinks.iter().filter_map(|&s| g(s)));
        opaque.extend(f.opaque.iter().filter_map(|&o| g(o)));
        escaped.extend(f.escaped.iter().filter_map(|&e| g(e)));
        unresolved.extend(f.unresolved_sinks.iter().cloned());
        for vc in &f.virtual_calls {
            if let Some(from) = g(vc.from) {
                virtual_calls.push((from, vc.method.as_str()));
            }
        }
        for vi in &f.virtual_impls {
            if let Some(node) = g(vi.node) {
                impls_by_method
                    .entry(vi.method.as_str())
                    .or_default()
                    .push(VImpl {
                        node,
                        self_key: vi.self_key.as_deref(),
                        trait_key: vi.trait_key.as_deref(),
                    });
            }
        }
        for c in &f.coercions {
            coerced
                .entry(c.trait_key.as_str())
                .or_default()
                .insert(c.self_key.as_str());
        }
        imprecise.extend(f.imprecise_traits.iter().map(String::as_str));
        scanned_crates.extend(f.scanned_crates.iter().map(String::as_str));
        generic_fns.extend(f.generic_fns.iter().map(String::as_str));
        for sp in &f.sink_paths {
            let entry = sink_path_nodes.entry(sp.path.as_str()).or_default();
            entry.extend(sp.nodes.iter().filter_map(|&n| g(n)));
        }
    }

    // Resolve cross-crate virtual dispatch against the global impl set, pruning
    // targets whose receiver type was never coerced to the trait object (a sound
    // RTA refinement — see `keep_impl`). The pruned edge would only ever be a
    // *false* `Reachable`; a target reachable some other way (a direct call, a
    // real coercion) keeps its edge.
    for (from, method) in &virtual_calls {
        if let Some(targets) = impls_by_method.get(method) {
            for vi in targets {
                if keep_impl(vi, &coerced, &imprecise, &scanned_crates) {
                    edges.insert(Edge {
                        from: *from,
                        to: vi.node,
                        kind: EdgeKind::Virtual,
                    });
                }
            }
        }
    }

    // H-1: wire the global opaque sentinel to the union of every fragment's
    // escaped set. Opaque/external code (FFI, inline asm, unresolved fn-pointer)
    // can re-enter any escaped function in ANY crate, but the driver only wired
    // this per-fragment — missing a sink reachable solely through opaque code in a
    // different crate, which then collapsed to a false `NotReachable`. Adding these
    // edges only ever makes a sink *more* reachable (Unknown/Reachable), never less,
    // so it is sound. Runs only when the closure actually has an opaque frontier.
    for &sentinel in &opaque {
        for &esc in &escaped {
            edges.insert(Edge {
                from: sentinel,
                to: esc,
                kind: EdgeKind::Opaque,
            });
        }
    }

    let mut edges: Vec<Edge> = edges.into_iter().collect();
    edges.sort_by_key(|e| (e.from, e.to));
    let mut roots: Vec<u32> = roots.into_iter().collect();
    let mut sinks: Vec<u32> = sinks.into_iter().collect();
    let mut opaque: Vec<u32> = opaque.into_iter().collect();
    let mut unresolved_sinks: Vec<String> = unresolved.into_iter().collect();
    roots.sort_unstable();
    sinks.sort_unstable();
    opaque.sort_unstable();
    unresolved_sinks.sort();

    // The merged graph keeps `scanned_crates` and `generic_fns` (unlike the
    // coercion facts, which are consumed into edges above): `analyze_paths` reads
    // both on a cache hit to soundly resolve an uninstantiated-generic sink.
    let mut scanned_crates: Vec<String> = scanned_crates.iter().map(|s| s.to_string()).collect();
    scanned_crates.sort();
    let mut generic_fns: Vec<String> = generic_fns.iter().map(|s| s.to_string()).collect();
    generic_fns.sort();

    let sink_paths: Vec<SinkPath> = sink_path_nodes
        .into_iter()
        .map(|(path, nodes)| {
            let mut nodes: Vec<u32> = nodes.into_iter().collect();
            nodes.sort_unstable();
            SinkPath {
                path: path.to_string(),
                nodes,
            }
        })
        .collect();

    Ok(CallGraph {
        schema: SUPPORTED_SCHEMA,
        nodes,
        edges,
        roots,
        sinks,
        unresolved_sinks,
        opaque,
        // Already resolved into edges above.
        virtual_calls: Vec::new(),
        virtual_impls: Vec::new(),
        sink_paths,
        // Coercion facts are consumed here (applied to the resolved edges); the
        // merged whole-closure graph carries none.
        coercions: Vec::new(),
        imprecise_traits: Vec::new(),
        // Retained: the carve-out in `analyze_paths` needs them on a cache hit.
        scanned_crates,
        generic_fns,
        // Consumed above (wired into opaque edges); merged graph carries neither.
        escaped: Vec::new(),
        crate_id: None,
    })
}
