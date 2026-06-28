//! RTA-style resolution of non-direct call edges, read off the mono collector.
//!
//! The collector already emits, for every `dyn Trait` coercion, the concrete
//! `<T as Trait>::method` vtable instances, so we don't re-derive which receivers
//! are instantiated. Two indices built in pass 1 drive edge resolution in pass 2:
//!
//! - `virtual_impls`: trait method → its mono-set impl instances; a `dyn` call
//!   dispatches to these (sound, tighter than CHA). `merge` prunes further by
//!   actual coercion.
//! - `address_taken`: address-reified fns + erased signature; a fn-pointer call
//!   reaches a signature-matching one.

use std::collections::{HashMap, HashSet};

use rustc_hir::def_id::DefId;
use rustc_middle::mir::{CastKind, Rvalue, StatementKind};
use rustc_middle::ty::adjustment::PointerCoercion;
use rustc_middle::ty::{self, Instance, Ty, TyCtxt, TypingEnv};

use crate::graph::GraphBuilder;
use crate::{full_path, has_mir_body};

#[derive(Default)]
pub struct Indices<'tcx> {
    /// trait-method `DefId` → node ids of every mono-set instance implementing it.
    pub virtual_impls: HashMap<DefId, Vec<u32>>,
    /// (node id, erased monomorphic signature) for each address-taken function.
    pub address_taken: Vec<(u32, ty::FnSig<'tcx>)>,
}

impl<'tcx> Indices<'tcx> {
    /// Virtual-call targets for a trait method (the RTA-resolved impl set).
    pub fn virtual_targets(&self, trait_method: DefId) -> &[u32] {
        self.virtual_impls
            .get(&trait_method)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Indirect-call targets: address-taken functions whose signature matches
    /// the fn-pointer call site exactly.
    pub fn indirect_targets(&self, call_sig: ty::FnSig<'tcx>) -> Vec<u32> {
        self.address_taken
            .iter()
            .filter(|(_, sig)| *sig == call_sig)
            .map(|(id, _)| *id)
            .collect()
    }
}

/// The trait-method `DefId` an instance dispatches as a vtable entry for, if it
/// is a trait-method implementation (an impl item, or a provided/default
/// method). `None` for inherent methods and free functions — never
/// vtable-dispatched, so never a virtual-call target.
pub fn trait_method_key(tcx: TyCtxt<'_>, def_id: DefId) -> Option<DefId> {
    let item = tcx.opt_associated_item(def_id)?;
    if !item.is_fn() {
        return None;
    }
    match item.trait_item_def_id() {
        // impl method → the trait method it implements
        Some(trait_method) => Some(trait_method),
        // a provided/default method's own instance is itself the trait method
        None if item.container == ty::AssocContainer::Trait => Some(def_id),
        // inherent impl method
        None => None,
    }
}

/// The erased, monomorphic signature of a `FnDef`/`FnPtr` type. Erasing
/// late-bound regions makes signatures comparable across call sites.
pub fn erased_sig<'tcx>(tcx: TyCtxt<'tcx>, ty: Ty<'tcx>) -> Option<ty::FnSig<'tcx>> {
    if !matches!(ty.kind(), ty::FnDef(..) | ty::FnPtr(..)) {
        return None;
    }
    Some(tcx.instantiate_bound_regions_with_erased(ty.fn_sig(tcx)))
}

/// The erased signature of an instance (its address-taken fn-pointer form).
pub fn instance_sig<'tcx>(
    tcx: TyCtxt<'tcx>,
    env: ty::TypingEnv<'tcx>,
    instance: Instance<'tcx>,
) -> Option<ty::FnSig<'tcx>> {
    erased_sig(tcx, instance.ty(tcx, env))
}

// ---- Coercion facts: the cross-crate dyn-target prune ----
//
// `merge` prunes a `dyn Trait` target whose receiver type was never coerced to
// the trait object. These helpers gather, per fragment, the coercion set the
// prune needs: `(receiver head, trait)` for every runtime unsize coercion
// (closed under supertraits), plus the traits whose tracking is incomplete.

/// The nominal "head" `DefId` of a type (ADT / closure / coroutine / foreign),
/// or `None` for primitives and structural types (which we never prune).
pub fn head_def_id(ty: Ty<'_>) -> Option<DefId> {
    match ty.kind() {
        ty::Adt(def, _) => Some(def.did()),
        ty::Closure(did, _) | ty::Coroutine(did, _) | ty::CoroutineClosure(did, _) => Some(*did),
        ty::Foreign(did) => Some(*did),
        _ => None,
    }
}

/// The head `DefId` of a trait-method instance's `Self` type. For an impl
/// method the `Self` lives on the impl (not in the method's args); for a
/// provided/default method it is the instance's first type argument.
pub fn self_head<'tcx>(tcx: TyCtxt<'tcx>, instance: Instance<'tcx>) -> Option<DefId> {
    let did = instance.def_id();
    // The `Self` head is nominal (`Wrap<U>` and `Wrap<i32>` share head `Wrap`),
    // so the un-instantiated impl trait-ref suffices — no normalization needed.
    let self_ty = match tcx
        .opt_associated_item(did)
        .and_then(|i| i.impl_container(tcx))
    {
        Some(impl_did) => tcx.impl_trait_ref(impl_did).skip_binder().self_ty(),
        None => instance.args.types().next()?,
    };
    head_def_id(self_ty)
}

/// Peel one pointer layer (`&T`, `*T`, or a smart pointer `P<T, …>`) to its
/// first type argument, to walk the source/target of an unsize coercion.
fn peel_ptr<'tcx>(ty: Ty<'tcx>) -> Option<Ty<'tcx>> {
    match ty.kind() {
        ty::Ref(_, inner, _) => Some(*inner),
        ty::RawPtr(inner, _) => Some(*inner),
        ty::Adt(_, args) => args.types().next(),
        _ => None,
    }
}

/// For an unsize coercion `src -> tgt`, recover `(receiver head, principal
/// trait)` when `tgt` is a (pointer to) trait object; `None` for non-`dyn`
/// unsizing (array→slice) or a non-nominal source.
fn unsize_pair<'tcx>(src: Ty<'tcx>, tgt: Ty<'tcx>) -> Option<(DefId, DefId)> {
    let (mut s, mut t) = (src, tgt);
    for _ in 0..6 {
        if let ty::Dynamic(preds, _) = t.kind() {
            return Some((head_def_id(s)?, preds.principal_def_id()?));
        }
        s = peel_ptr(s)?;
        t = peel_ptr(t)?;
    }
    None
}

/// The trait and all its supertraits (transitively), including itself.
fn supertrait_closure(tcx: TyCtxt<'_>, trait_id: DefId) -> HashSet<DefId> {
    let mut seen = HashSet::new();
    let mut stack = vec![trait_id];
    while let Some(t) = stack.pop() {
        if !seen.insert(t) {
            continue;
        }
        for (clause, _) in tcx.explicit_super_predicates_of(t).skip_binder() {
            if let Some(tp) = clause.as_trait_clause() {
                stack.push(tp.def_id());
            }
        }
    }
    seen
}

/// Every `Dynamic` principal trait mentioned anywhere in `ty`'s structure.
fn principals_in_ty(ty: Ty<'_>, out: &mut Vec<DefId>) {
    for arg in ty.walk() {
        if let Some(t) = arg.as_type() {
            if let ty::Dynamic(preds, _) = t.kind() {
                if let Some(p) = preds.principal_def_id() {
                    out.push(p);
                }
            }
        }
    }
}

/// Emit this fragment's coercion facts into `builder`: a `(receiver, trait)`
/// fact per supertrait for each runtime unsize coercion, and an `imprecise`
/// mark for anything whose receiver we cannot attribute — a non-`Unsize` cast
/// to a trait object (`dyn*`) or a trait object flowing from a constant (a CTFE
/// / `static` vtable we did not scan). The latter is the safety net that keeps
/// the prune sound where coercion scanning is blind.
pub fn emit_coercions<'tcx>(
    tcx: TyCtxt<'tcx>,
    env: TypingEnv<'tcx>,
    instances: &[(Instance<'tcx>, String)],
    builder: &mut GraphBuilder,
) {
    for (instance, _) in instances {
        let instance = *instance;
        if !has_mir_body(tcx, instance) {
            continue;
        }
        let body = tcx.instance_mir(instance.def);
        let norm = |ty| {
            instance.instantiate_mir_and_normalize_erasing_regions(
                tcx,
                env,
                ty::EarlyBinder::bind(tcx, ty),
            )
        };

        // A constant whose type mentions a trait object: its vtable was built in
        // CTFE / a `static`, outside our runtime-cast scan → mark it imprecise.
        for c in body.required_consts() {
            let mut principals = Vec::new();
            principals_in_ty(norm(c.const_.ty()), &mut principals);
            for p in principals {
                builder.mark_imprecise(full_path(tcx, p));
            }
        }

        for bb in body.basic_blocks.iter() {
            for stmt in &bb.statements {
                let StatementKind::Assign(assign) = &stmt.kind else {
                    continue;
                };
                let Rvalue::Cast(kind, op, tgt) = &assign.1 else {
                    continue;
                };
                let tgt = norm(*tgt);
                if let CastKind::PointerCoercion(PointerCoercion::Unsize, _) = kind {
                    let src = norm(op.ty(&body.local_decls, tcx));
                    if let Some((head, principal)) = unsize_pair(src, tgt) {
                        for t in supertrait_closure(tcx, principal) {
                            builder.add_coercion(full_path(tcx, head), full_path(tcx, t));
                        }
                    }
                    // A `None` source head is a primitive/`str`/slice receiver;
                    // its impls carry no `self_key` and `merge` keeps them anyway.
                } else {
                    // A non-`Unsize` cast producing a trait object (`dyn*`): we
                    // cannot attribute a concrete receiver → imprecise.
                    let mut principals = Vec::new();
                    principals_in_ty(tgt, &mut principals);
                    for p in principals {
                        builder.mark_imprecise(full_path(tcx, p));
                    }
                }
            }
        }
    }
}
