//! The deserialized call-graph artifact emitted by `reach-driver`.
//!
//! This sits on the *consumer* side of the `rustc_private` quarantine: it mirrors
//! the driver's wire format and is the only thing that crosses the boundary. No
//! compiler types appear here.

use serde::{Deserialize, Serialize};

/// The wire-format version this crate understands. v2 added the coercion facts
/// for the cross-crate `dyn`-target prune; the bump invalidates v1 caches and
/// refuses to mix v1/v2 fragments.
pub const SUPPORTED_SCHEMA: u32 = 2;

/// A monomorphized function instance — one call-graph node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    /// Dense node id, unique within this graph; edge endpoints reference it.
    pub id: u32,
    /// Human-readable, generic args included: `identity::<u32>`.
    pub label: String,
    /// Mangled symbol name — globally unique per monomorphization.
    pub symbol: String,
    /// Crate-qualified def path — the key for resolving an advisory sink against
    /// a cached graph without rebuilding. `None` for path-less nodes.
    #[serde(default)]
    pub path: Option<String>,
}

/// How a call edge dispatches. `Other` catches a kind from a newer driver — it
/// still counts as a real edge, never silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Statically resolved callee (a concrete, non-virtual instance).
    Direct,
    /// `dyn Trait` dispatch, RTA-resolved to mono-set impls of the trait method.
    Virtual,
    /// fn-pointer / closure dispatch to signature-compatible address-taken fns.
    Indirect,
    /// Into or out of the opaque frontier (FFI / inline asm / unresolved indirect).
    Opaque,
    /// An edge kind added by a newer driver than this build — accepted (and still
    /// counted as a real edge) rather than dropped.
    #[serde(other)]
    Other,
}

/// A directed call edge between two nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Edge {
    /// Caller node id.
    pub from: u32,
    /// Callee node id.
    pub to: u32,
    /// How the call dispatches.
    pub kind: EdgeKind,
}

/// The whole graph plus the driver-resolved roots and sinks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    /// Wire-format version; must equal [`SUPPORTED_SCHEMA`] to be analyzed.
    pub schema: u32,
    /// All call-graph nodes.
    pub nodes: Vec<Node>,
    /// All call edges (every kind).
    pub edges: Vec<Edge>,
    /// Entry-point node ids (bin: `main`).
    #[serde(default)]
    pub roots: Vec<u32>,
    /// Node ids that are advisory sinks (every monomorphization of a resolved
    /// affected-function `DefId`).
    #[serde(default)]
    pub sinks: Vec<u32>,
    /// Requested sink paths that resolved to no node in this build.
    #[serde(default)]
    pub unresolved_sinks: Vec<String>,
    /// Node ids representing the opaque frontier (unanalyzable external code).
    #[serde(default)]
    pub opaque: Vec<u32>,
    /// `dyn Trait` call sites as portable facts, for cross-crate resolution.
    #[serde(default)]
    pub virtual_calls: Vec<VirtualCall>,
    /// Trait-method impls available as virtual-call targets.
    #[serde(default)]
    pub virtual_impls: Vec<VirtualImpl>,
    /// Resolved sinks keyed by the requested advisory path → matched node ids.
    #[serde(default)]
    pub sink_paths: Vec<SinkPath>,
    /// Receiver-type → trait coercions observed in this fragment (closed under
    /// supertraits). Used by `merge` to prune `dyn` targets soundly.
    #[serde(default)]
    pub coercions: Vec<Coercion>,
    /// Trait paths for which coercion tracking is incomplete in this fragment
    /// (a `dyn*` or a trait object flowing from a constant): never prune them.
    #[serde(default)]
    pub imprecise_traits: Vec<String>,
    /// The crate(s) whose MIR this fragment fully scanned for coercions. A
    /// virtual impl whose receiver type is defined *outside* this set (e.g. a
    /// precompiled sysroot crate) is never pruned — its coercions may be unseen.
    #[serde(default)]
    pub scanned_crates: Vec<String>,
    /// Exported generic ("requires monomorphization") fn defs known to the build,
    /// by crate-qualified path. Positive evidence that an advisory naming one of
    /// these, with no monomorphized node, is genuinely never instantiated → a
    /// sound `NotReachable` rather than `Unknown`. Empty in a v2 fragment/cache
    /// or an older driver, in which case the carve-out simply stays `Unknown`
    /// (fail-closed): a missing entry never yields a false `NotReachable`.
    #[serde(default)]
    pub generic_fns: Vec<String>,
    /// Node ids in *this fragment* that external/opaque code could re-enter:
    /// exported (extern-indicator) symbols ∪ address-taken (reified fn-pointer)
    /// targets. `merge` wires the global opaque sentinel to the union of every
    /// fragment's escaped set, so a sink reachable only through opaque code in a
    /// *different* crate stays `Unknown` rather than collapsing to a false
    /// `NotReachable`. Empty in a pre-fix fragment (the old per-fragment wiring).
    #[serde(default)]
    pub escaped: Vec<u32>,
    /// This fragment's crate identity, `"<crate_name>-<stable_crate_id:016x>"`,
    /// matching the fragment's filename stem. `merge`/`read_fragments` reject a
    /// fragment whose embedded identity disagrees with its filename, so a hostile
    /// `build.rs` that overwrites a *sibling* crate's fragment with a stripped
    /// graph is caught (raising the bar on the H-4 forge-a-NotReachable path).
    /// `None` in a pre-fix fragment ⇒ the check is skipped.
    #[serde(default)]
    pub crate_id: Option<String>,
}

/// A receiver-type → trait-object coercion: `self_key` was unsize-coerced to
/// `dyn trait_key` (recorded once per supertrait). The keys are crate-qualified
/// paths, so they join across fragments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coercion {
    /// Crate-qualified path of the receiver type's nominal head.
    pub self_key: String,
    /// Crate-qualified path of the (super)trait it can be dispatched through.
    pub trait_key: String,
}

/// A requested sink path and the call-graph nodes it resolved to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkPath {
    /// The requested advisory path (crate-qualified, the RustSec form).
    pub path: String,
    /// Node ids it matched — one per monomorphization.
    pub nodes: Vec<u32>,
}

/// A `dyn Trait` call site, recorded as a portable fact so cross-crate `merge`
/// can resolve it against the union of impls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualCall {
    /// Caller node id.
    pub from: u32,
    /// The trait method's crate-qualified path — the cross-crate join key.
    pub method: String,
}

/// A trait-method implementation available as a virtual-call target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualImpl {
    /// The trait method's crate-qualified path — the cross-crate join key.
    pub method: String,
    /// The implementing node id.
    pub node: u32,
    /// Crate-qualified path of the impl's receiver-type head, for the coercion
    /// prune. `None` (e.g. a primitive receiver) ⇒ never pruned.
    #[serde(default)]
    pub self_key: Option<String>,
    /// Crate-qualified path of the trait owning the method, the coercion-lookup
    /// key. `None` ⇒ never pruned.
    #[serde(default)]
    pub trait_key: Option<String>,
}
