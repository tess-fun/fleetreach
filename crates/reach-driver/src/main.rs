//! A custom `rustc` driver — the only place in fleetreach that touches
//! `rustc_private`. It compiles a crate on the pinned nightly and emits its
//! monomorphized call graph as JSON on stdout.
//!
//! Nodes are the mono collector's `fn` items: `collect_and_partition_mono_items`
//! already computes a sound, over-approximating reachability set, so the node
//! universe is correct by codegen rather than by a hand-audited walk. Edges come
//! from each instance's MIR call terminators (direct / virtual / indirect /
//! opaque). The `MONO_ITEM` stderr lines are a diagnostic dump.

#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

mod graph;
mod rta;

use rustc_driver::{Callbacks, Compilation};
use rustc_hir::def::DefKind;
use rustc_interface::interface::Compiler;
use rustc_middle::mir::{CastKind, Rvalue, StatementKind, TerminatorKind};
use rustc_middle::mono::MonoItem;
use rustc_middle::ty::adjustment::PointerCoercion;
use rustc_middle::ty::{self, Instance, InstanceKind, TyCtxt, TypingEnv};

use graph::{EdgeKind, GraphBuilder};
use rta::Indices;

/// How the driver was invoked.
enum Mode {
    /// Single-file: print the graph to stdout and stop before codegen (tests).
    Direct,
    /// cargo `RUSTC_WRAPPER`: compile normally and write this crate's fragment
    /// to `out_dir`; `reach` merges the per-crate fragments into the closure.
    Wrapper { out_dir: std::path::PathBuf },
}

struct ReachCallbacks {
    mode: Mode,
}

impl Callbacks for ReachCallbacks {
    fn after_analysis(&mut self, _compiler: &Compiler, tcx: TyCtxt<'_>) -> Compilation {
        match &self.mode {
            Mode::Direct => {
                println!("{}", build_call_graph(tcx, true));
                // The collector has already run; nothing else is needed.
                Compilation::Stop
            }
            Mode::Wrapper { out_dir } => {
                if !out_dir.as_os_str().is_empty() {
                    let krate = rustc_span::def_id::LOCAL_CRATE;
                    let name = tcx.crate_name(krate);
                    let id = tcx.stable_crate_id(krate).as_u64();
                    let file = out_dir.join(format!("{name}-{id:016x}.json"));
                    let json = build_call_graph(tcx, false);
                    if let Err(e) = std::fs::write(&file, json) {
                        // A dropped fragment would leave the closure missing this
                        // crate's edges → a possible false NotReachable. Fail the
                        // build (exit non-zero) so the scan resolves to Unknown
                        // rather than silently caching an incomplete graph (L-3).
                        eprintln!("reach-driver: could not write {}: {e}", file.display());
                        std::process::exit(1);
                    }
                }
                // Let the real compilation finish so cargo gets its artifacts.
                Compilation::Continue
            }
        }
    }
}

/// Whether this instance has a MIR body to walk: `Item`s only when MIR is
/// available, never `Intrinsic`/`Virtual`, all other shims yes.
fn has_mir_body<'tcx>(tcx: TyCtxt<'tcx>, instance: Instance<'tcx>) -> bool {
    match instance.def {
        InstanceKind::Item(def_id) => tcx.is_mir_available(def_id),
        InstanceKind::Intrinsic(..) | InstanceKind::Virtual(..) => false,
        _ => true,
    }
}

/// Crate-qualified path of a def, stable across crate compilations (the
/// cross-crate join key). Unlike `def_path_str`, it keeps the crate name for
/// local items too, so a def resolves identically from any crate.
fn full_path(tcx: TyCtxt<'_>, def_id: rustc_hir::def_id::DefId) -> String {
    let path = tcx.def_path_str(def_id);
    if def_id.is_local() {
        format!(
            "{}::{path}",
            tcx.crate_name(rustc_span::def_id::LOCAL_CRATE)
        )
    } else {
        path
    }
}

/// Stable interning key for an instance: its mangled symbol name.
fn symbol_of<'tcx>(tcx: TyCtxt<'tcx>, instance: Instance<'tcx>) -> String {
    tcx.symbol_name(instance).name.to_string()
}

/// An empty but valid graph (consumer-side fields default). Used for skipped
/// crates and the serialization-failure fallback.
const EMPTY_GRAPH: &str = "{\"schema\":2,\"nodes\":[],\"edges\":[]}";

/// Build this crate's call-graph fragment as JSON. With `dump_mono`, also print
/// the `MONO_ITEM` diagnostic dump to stderr (Direct mode only).
fn build_call_graph(tcx: TyCtxt<'_>, dump_mono: bool) -> String {
    let prof = std::env::var_os("REACH_PROFILE").is_some();
    let t_start = std::time::Instant::now();

    // A proc-macro crate runs at compile time, never on a runtime call path, so
    // it is out of scope. Its generated code lives in the consuming crate.
    if tcx
        .crate_types()
        .contains(&rustc_session::config::CrateType::ProcMacro)
    {
        return EMPTY_GRAPH.to_string();
    }

    let env = TypingEnv::fully_monomorphized();

    let instances = collect_fn_instances(tcx);
    let t_collect = t_start.elapsed();

    let mut builder = GraphBuilder::new();
    let mut indices = Indices::default();

    // Stamp this fragment with its crate identity, matching the wrapper's filename
    // stem (`<name>-<stable_crate_id:016x>`), so `read_fragments` can reject a
    // fragment whose embedded identity disagrees with its filename (H-4).
    {
        let krate = rustc_span::def_id::LOCAL_CRATE;
        let cid = tcx.stable_crate_id(krate).as_u64();
        builder.set_crate_id(format!("{}-{cid:016x}", tcx.crate_name(krate)));
    }

    // Pass 1 builds the indices; emit_coercions adds the prune facts. Both must
    // complete before pass 2 resolves any edge.
    let t_p1 = std::time::Instant::now();
    let pass1 = intern_and_index(tcx, env, &instances, dump_mono, &mut builder, &mut indices);
    rta::emit_coercions(tcx, env, &instances, &mut builder);
    emit_generic_fns(tcx, &mut builder);
    let t_pass1 = t_p1.elapsed();

    let t_p2 = std::time::Instant::now();
    emit_call_edges(tcx, env, &instances, &indices, &mut builder);
    let t_pass2 = t_p2.elapsed();

    wire_opaque_frontier(&mut builder, pass1.exported, &indices);
    builder.set_unresolved_sinks(pass1.unresolved_sinks);
    if dump_mono {
        dump_mono_items(pass1.mono_lines);
    }

    let t_fin = std::time::Instant::now();

    let call_graph = builder.finish();
    let (n_nodes, n_edges) = (call_graph.nodes.len(), call_graph.edges.len());
    // Compact JSON on the cargo-wrapper hot path (machine-read fragments);
    // pretty only for the Direct-mode diagnostic dump.
    let serialized = if dump_mono {
        serde_json::to_string_pretty(&call_graph)
    } else {
        serde_json::to_string(&call_graph)
    };
    let out = serialized.unwrap_or_else(|e| {
        eprintln!("reach-driver: failed to serialize call graph: {e}");
        // An empty object parses but carries no nodes/sinks → reach reports it
        // honestly rather than the driver silently exiting mid-build.
        EMPTY_GRAPH.to_string()
    });

    if prof {
        eprintln!(
            "PROF crate={} instances={} nodes={} edges={} | collect={} pass1={} pass2={} finish={} total={}",
            tcx.crate_name(rustc_span::def_id::LOCAL_CRATE),
            instances.len(),
            n_nodes,
            n_edges,
            t_collect.as_micros(),
            t_pass1.as_micros(),
            t_pass2.as_micros(),
            t_fin.elapsed().as_micros(),
            t_start.elapsed().as_micros(),
        );
    }
    out
}

/// What pass 1 produces besides the interned nodes / RTA indices it writes into
/// the builder: the escaped-symbol set (for the opaque frontier), the requested
/// sinks that matched no instance (→ `Unknown`), and the Direct-mode dump lines.
struct Pass1 {
    exported: Vec<u32>,
    unresolved_sinks: Vec<String>,
    mono_lines: Vec<String>,
}

/// Whether this crate's roots are its exported items rather than a `main`: true
/// only for the primary package when it has no entry point (a library being
/// audited, whose every exported item a downstream consumer could call).
fn is_lib_roots(tcx: TyCtxt<'_>) -> bool {
    let has_entry = tcx.entry_fn(()).is_some();
    std::env::var_os("CARGO_PRIMARY_PACKAGE").is_some() && !has_entry
}

/// Emit this crate's exported *generic* fn definitions (crate-qualified paths).
///
/// A generic fn has no machine code until it is instantiated, so the mono
/// collector — the source of every graph node — only ever produces a node for it
/// once it is actually called. If an advisory names such a fn and no
/// monomorphization of it appears anywhere in the merged closure, it is genuinely
/// never called, and the consumer can soundly upgrade `Unknown` → `NotReachable`.
/// Recording the *definition* here is the positive evidence that distinguishes
/// "the driver saw this generic def, uninstantiated" from "this path matched
/// nothing" (a possible path-format skew, which must stay `Unknown`).
///
/// Skipped entirely for the primary library (`is_lib_roots`): its exported API is
/// treated as callable by a downstream consumer, so an uninstantiated exported
/// generic there is not provably unreachable and must remain `Unknown`. For a
/// binary primary and for every dependency, an uninstantiated exported generic is
/// genuinely unreachable from the analyzed roots.
fn emit_generic_fns(tcx: TyCtxt<'_>, builder: &mut GraphBuilder) {
    if is_lib_roots(tcx) {
        return;
    }
    let eff_vis = tcx.effective_visibilities(());
    for &local in tcx.mir_keys(()) {
        let def_id = local.to_def_id();
        if !matches!(tcx.def_kind(def_id), DefKind::Fn | DefKind::AssocFn) {
            continue;
        }
        // `requires_monomorphization` is true iff the item has type/const generic
        // params (walking parents, so a method on a generic type counts) — exactly
        // the items codegen'd lazily on instantiation rather than eagerly.
        if !tcx.generics_of(def_id).requires_monomorphization(tcx) {
            continue;
        }
        // Advisory sinks are public API; restricting to exported fns keeps the set
        // small and aligned with what an advisory can name.
        if !eff_vis.is_exported(local) {
            continue;
        }
        builder.add_generic_fn(full_path(tcx, def_id));
    }
}

/// Pass 1: intern one node per instance, mark roots and advisory sinks, and
/// build the RTA virtual-impl / address-taken indices (which must be complete
/// before pass 2 resolves any edge — a call in the first instance may target an
/// impl interned last).
fn intern_and_index<'tcx>(
    tcx: TyCtxt<'tcx>,
    env: TypingEnv<'tcx>,
    instances: &[(Instance<'tcx>, String)],
    dump_mono: bool,
    builder: &mut GraphBuilder,
    indices: &mut Indices<'tcx>,
) -> Pass1 {
    // Roots: a binary's entry point, or — for the primary library being audited
    // (no `main`) — every exported item, since a downstream consumer could call
    // any of them. Dependency crates contribute no roots. Sinks are the
    // REACH_SINKS advisory paths. All matched by `DefId`/path, not label.
    let entry_def_id = tcx.entry_fn(()).map(|(def_id, _)| def_id);
    let lib_roots = is_lib_roots(tcx);
    let eff_vis = lib_roots.then(|| tcx.effective_visibilities(()));
    let sink_targets: Vec<String> = std::env::var("REACH_SINKS")
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    // This fragment fully scans its own crate's MIR for coercions; record it so
    // `merge` can apply the sysroot-keep rule.
    builder.set_scanned_crate(tcx.crate_name(rustc_span::def_id::LOCAL_CRATE).to_string());

    let mut matched_sinks: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut exported: Vec<u32> = Vec::new();
    let mut mono_lines: Vec<String> = Vec::new();

    for (instance, symbol) in instances {
        let instance = *instance;
        let def_id = instance.def_id();

        // `Instance` Display is expensive; only pay it for the Direct-mode dump.
        if dump_mono {
            mono_lines.push(format!("MONO_ITEM fn {instance}"));
        }

        // The crate-qualified path (`fp`) and the bare def path (`dp`).
        let dp = tcx.def_path_str(def_id);
        let fp = if def_id.is_local() {
            format!("{}::{dp}", tcx.crate_name(rustc_span::def_id::LOCAL_CRATE))
        } else {
            dp.clone()
        };

        let node = builder.intern(symbol.clone(), || format!("{instance}"), Some(fp.clone()));

        let is_root = entry_def_id == Some(def_id)
            || eff_vis.is_some_and(|ev| def_id.as_local().is_some_and(|l| ev.is_exported(l)));
        if is_root {
            builder.mark_root(symbol.clone());
        }
        // Match a requested sink by crate-qualified path (RustSec form) or bare
        // def path (local single-crate fixtures).
        if !sink_targets.is_empty() {
            for cand in [&fp, &dp] {
                if sink_targets.contains(cand) {
                    builder.mark_sink(symbol.clone());
                    builder.sink_path(cand.clone(), symbol.clone());
                    matched_sinks.insert(cand.clone());
                }
            }
        }

        // RTA virtual index: an impl of a trait method is a candidate target of
        // any `dyn Trait` call to it. The receiver/trait keys let `merge` prune
        // it when the receiver was never coerced to the trait object.
        if let Some(trait_method) = rta::trait_method_key(tcx, def_id) {
            indices
                .virtual_impls
                .entry(trait_method)
                .or_default()
                .push(node);
            let self_key = rta::self_head(tcx, instance).map(|h| full_path(tcx, h));
            let trait_key = Some(full_path(tcx, tcx.parent(trait_method)));
            builder.virtual_impl(full_path(tcx, trait_method), node, self_key, trait_key);
        }

        // Exported symbol: external code can call it directly → opaque target.
        if tcx.codegen_fn_attrs(def_id).contains_extern_indicator() {
            exported.push(node);
        }

        // Address-taken set: fn-pointer reifications in this instance's MIR.
        if has_mir_body(tcx, instance) {
            let body = tcx.instance_mir(instance.def);
            for bb in body.basic_blocks.iter() {
                for stmt in &bb.statements {
                    let StatementKind::Assign(assign) = &stmt.kind else {
                        continue;
                    };
                    let Rvalue::Cast(CastKind::PointerCoercion(coercion, _), operand, _) =
                        &assign.1
                    else {
                        continue;
                    };
                    if !matches!(
                        coercion,
                        PointerCoercion::ReifyFnPointer(_) | PointerCoercion::ClosureFnPointer(_)
                    ) {
                        continue;
                    }
                    let op_ty = operand.ty(&body.local_decls, tcx);
                    let op_ty = instance.instantiate_mir_and_normalize_erasing_regions(
                        tcx,
                        env,
                        ty::EarlyBinder::bind(op_ty),
                    );
                    if let Some((target, sig)) = resolve_reified(tcx, env, op_ty) {
                        let id = builder.intern(
                            symbol_of(tcx, target),
                            || format!("{target}"),
                            Some(full_path(tcx, target.def_id())),
                        );
                        indices.address_taken.push((id, sig));
                    }
                }
            }
        }
    }

    // Requested sinks that matched no instance → Unknown (never NotReachable).
    let unresolved_sinks = sink_targets
        .into_iter()
        .filter(|t| !matched_sinks.contains(t))
        .collect();
    Pass1 {
        exported,
        unresolved_sinks,
        mono_lines,
    }
}

/// Print the `MONO_ITEM` diagnostic dump (sorted + deduped), checkable against
/// `rustc -Zprint-mono-items`.
fn dump_mono_items(mut lines: Vec<String>) {
    lines.sort();
    lines.dedup();
    for line in &lines {
        eprintln!("{line}");
    }
}

/// The unique monomorphized `fn` instances of this crate (a fn can appear in
/// several CGUs; dedup by mangled symbol).
fn collect_fn_instances<'tcx>(tcx: TyCtxt<'tcx>) -> Vec<(Instance<'tcx>, String)> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut instances = Vec::new();
    for cgu in tcx.collect_and_partition_mono_items(()).codegen_units {
        for (item, _) in cgu.items() {
            if let MonoItem::Fn(instance) = item {
                let symbol = symbol_of(tcx, *instance);
                if seen.insert(symbol.clone()) {
                    instances.push((*instance, symbol));
                }
            }
        }
    }
    instances
}

/// Pass 2: walk each instance's MIR call terminators and emit one edge per call
/// site — `Direct` to a resolved instance, `Virtual` to the RTA impl set,
/// `Indirect` to signature-matching address-taken fns, or `Opaque` for FFI /
/// inline asm / unresolved indirect. The RTA indices must already be complete.
fn emit_call_edges<'tcx>(
    tcx: TyCtxt<'tcx>,
    env: TypingEnv<'tcx>,
    instances: &[(Instance<'tcx>, String)],
    indices: &Indices<'tcx>,
    builder: &mut GraphBuilder,
) {
    for (instance, symbol) in instances {
        let instance = *instance;
        if !has_mir_body(tcx, instance) {
            continue;
        }
        let caller = builder.intern(symbol.clone(), || format!("{instance}"), None);

        let body = tcx.instance_mir(instance.def);
        for bb in body.basic_blocks.iter() {
            let Some(terminator) = &bb.terminator else {
                continue;
            };
            let func = match &terminator.kind {
                TerminatorKind::Call { func, .. } | TerminatorKind::TailCall { func, .. } => func,
                // Inline asm can do anything we cannot see → opaque frontier.
                TerminatorKind::InlineAsm { .. } => {
                    let sentinel = builder.opaque_sentinel();
                    builder.edge(caller, sentinel, EdgeKind::Opaque);
                    continue;
                }
                _ => continue,
            };

            let func_ty = func.ty(&body.local_decls, tcx);
            let func_ty = instance.instantiate_mir_and_normalize_erasing_regions(
                tcx,
                env,
                ty::EarlyBinder::bind(func_ty),
            );

            match func_ty.kind() {
                // Named fn/method call (or static-dispatch generic): resolve to a
                // concrete instance (Direct), a vtable RTA impl set (Virtual), or
                // — if the callee is a foreign (FFI) fn with no MIR — the opaque
                // frontier. Unresolvable (`Ok(None)`/`Err`): skip, never invent.
                ty::FnDef(def_id, args) => {
                    if let Ok(Some(callee)) = Instance::try_resolve(tcx, env, *def_id, args) {
                        if let InstanceKind::Virtual(trait_method, _) = callee.def {
                            // Portable fact for cross-crate merge + same-fragment edges.
                            builder.virtual_call(caller, full_path(tcx, trait_method));
                            for &target in indices.virtual_targets(trait_method) {
                                builder.edge(caller, target, EdgeKind::Virtual);
                            }
                        } else if tcx.is_foreign_item(callee.def_id()) {
                            let sentinel = builder.opaque_sentinel();
                            builder.edge(caller, sentinel, EdgeKind::Opaque);
                        } else {
                            let to = builder.intern(
                                symbol_of(tcx, callee),
                                || format!("{callee}"),
                                Some(full_path(tcx, callee.def_id())),
                            );
                            builder.edge(caller, to, EdgeKind::Direct);
                        }
                    }
                }
                // Call through a fn pointer: dispatch to signature-compatible
                // address-taken functions (Indirect). None match → opaque frontier.
                ty::FnPtr(..) => {
                    let targets = rta::erased_sig(tcx, func_ty)
                        .map(|sig| indices.indirect_targets(sig))
                        .unwrap_or_default();
                    if targets.is_empty() {
                        let sentinel = builder.opaque_sentinel();
                        builder.edge(caller, sentinel, EdgeKind::Opaque);
                    } else {
                        for target in targets {
                            builder.edge(caller, target, EdgeKind::Indirect);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Record the escaped set (functions external/opaque code could re-enter: the
/// address-taken set ∪ exported symbols) and, *if this fragment has an opaque call
/// site*, wire the sentinel to them in-fragment (for single-fragment Direct mode).
///
/// The escaped set is recorded **unconditionally**, even when this fragment has no
/// opaque edge of its own: `merge` wires the *global* sentinel to the union of
/// every fragment's escaped set, so a sink reachable only through opaque code in a
/// different crate is connected in the whole-closure graph (H-1). Wiring only
/// per-fragment was the bug — it missed exactly that cross-crate case.
fn wire_opaque_frontier(builder: &mut GraphBuilder, exported: Vec<u32>, indices: &Indices) {
    let mut escaped: std::collections::HashSet<u32> = exported.into_iter().collect();
    escaped.extend(indices.address_taken.iter().map(|(id, _)| *id));
    let escaped: Vec<u32> = escaped.into_iter().collect();
    builder.set_escaped(escaped.clone());
    if !builder.has_opaque() {
        return;
    }
    let sentinel = builder.opaque_sentinel();
    for target in escaped {
        builder.edge(sentinel, target, EdgeKind::Opaque);
    }
}

/// Resolve a reified fn-pointer operand (a `FnDef`, or a non-capturing closure
/// via `ClosureFnPointer`) to its target instance + erased signature. Returns
/// `None` if the address-taken target cannot be resolved to a single instance.
fn resolve_reified<'tcx>(
    tcx: TyCtxt<'tcx>,
    env: TypingEnv<'tcx>,
    op_ty: ty::Ty<'tcx>,
) -> Option<(Instance<'tcx>, ty::FnSig<'tcx>)> {
    let (def_id, args) = match op_ty.kind() {
        ty::FnDef(def_id, args) | ty::Closure(def_id, args) => (*def_id, *args),
        _ => return None,
    };
    let instance = Instance::try_resolve(tcx, env, def_id, args).ok()??;
    let sig = rta::instance_sig(tcx, env, instance)?;
    Some((instance, sig))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Wrapper mode: cargo's RUSTC_WORKSPACE_WRAPPER invokes us as
    // `driver <rustc> <args…>`, so argv[1] is the rustc executable. In our
    // single-file (Direct) mode, argv[1] is a `.rs` file.
    let is_wrapper = args
        .get(1)
        .map(|a| std::path::Path::new(a).file_stem() == Some(std::ffi::OsStr::new("rustc")))
        .unwrap_or(false);

    if is_wrapper {
        run_wrapper(&args);
    } else {
        run_direct(args);
    }
}

/// Single-file analysis: inject the baked-in sysroot, emit the graph to stdout.
fn run_direct(mut args: Vec<String>) {
    if !args.iter().any(|a| a == "--sysroot") {
        args.push("--sysroot".to_string());
        args.push(env!("REACH_SYSROOT").to_string());
    }
    let mut callbacks = ReachCallbacks { mode: Mode::Direct };
    rustc_driver::run_compiler(&args, &mut callbacks);
}

/// cargo-wrapper analysis: pass cargo's exact compiler args through to a normal
/// compilation (cargo already supplies the right sysroot/features/cfg/deps), and
/// write the graph for the target crate as a side effect. The build's feature
/// and target resolution is inherited for free — no re-derivation.
fn run_wrapper(args: &[String]) {
    // Drop argv[0] (our path); argv[1..] is `<rustc> <args…>`, which run_compiler
    // takes verbatim (it ignores args[0] as the program name).
    let compiler_args = &args[1..];
    let mode = Mode::Wrapper {
        out_dir: std::env::var_os("REACH_OUT")
            .map(std::path::PathBuf::from)
            .unwrap_or_default(),
    };
    let mut callbacks = ReachCallbacks { mode };
    rustc_driver::run_compiler(compiler_args, &mut callbacks);
}
