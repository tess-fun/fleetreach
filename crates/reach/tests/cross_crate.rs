//! R7 whole-closure: merging real per-crate fragments reconstructs a call chain
//! that no single fragment contains. The sink (`vulnerable_fn`) lives in a
//! dependency and is only analyzable in that dependency's fragment; the call to
//! it originates in the bin. Only the merged graph proves reachability.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fleetreach_reach::{analyze, merge, parse_graph, EdgeKind, Verdict};

fn frag(name: &str) -> fleetreach_reach::CallGraph {
    let path = format!(
        "{}/tests/fixtures/cross_crate/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = std::fs::read_to_string(path).expect("read fragment");
    parse_graph(&json).expect("parse fragment")
}

#[test]
fn merged_closure_reaches_sink_in_dependency() {
    let bin = frag("bin.json");
    let lib = frag("vuln_lib.json");

    // Neither fragment alone can decide it: the bin has no sink node; the lib has
    // no root.
    assert!(bin.sinks.is_empty(), "bin fragment has no sink node");
    assert!(lib.roots.is_empty(), "lib fragment has no root");

    let whole = merge(&[bin, lib]).expect("merge");
    let a = analyze(&whole).expect("analyze");

    let v = a
        .verdicts
        .iter()
        .find(|v| v.sink.contains("vulnerable_fn"))
        .expect("vulnerable_fn sink present after merge");

    match &v.verdict {
        Verdict::Reachable { witness } => {
            // main -> trigger -> vulnerable_fn, spanning the crate boundary.
            assert_eq!(witness.first().map(String::as_str), Some("main"));
            assert!(
                witness.last().is_some_and(|l| l.contains("vulnerable_fn")),
                "witness ends at the sink: {witness:?}"
            );
            assert!(
                witness.iter().any(|l| l.contains("trigger")),
                "witness crosses through trigger: {witness:?}"
            );
        }
        other => panic!("expected Reachable across the merge, got {other:?}"),
    }
}

#[test]
fn cross_crate_virtual_dispatch_is_resolved_by_merge() {
    // The dyn call (`a.speak()`) is in the bin; the receiver type is coerced and
    // its impl collected only in the lib. The bin fragment therefore has the
    // virtual-call fact but no impl, and the lib has the impl but no call. Only
    // the global virtual-impl index built during merge connects them — without
    // it, `lib_vuln` would be a false NotReachable (a soundness defect).
    let bin = frag2("bin.json");
    let lib = frag2("animal_lib.json");

    // Bin alone cannot prove reachability: `lib_vuln` is not even a node there,
    // so it surfaces (if at all) as an unresolved/Unknown sink — never Reachable.
    let bin_only = analyze(&bin).unwrap();
    assert!(
        !bin_only
            .verdicts
            .iter()
            .any(|v| v.sink.contains("lib_vuln") && matches!(v.verdict, Verdict::Reachable { .. })),
        "bin alone must not prove the cross-crate dyn sink Reachable"
    );

    let whole = merge(&[bin, lib]).unwrap();
    let a = analyze(&whole).unwrap();
    let v = a
        .verdicts
        .iter()
        .find(|v| v.sink.contains("lib_vuln"))
        .expect("lib_vuln sink after merge");

    match &v.verdict {
        Verdict::Reachable { witness } => {
            assert_eq!(witness.first().map(String::as_str), Some("main"));
            assert!(
                witness.iter().any(|l| l.contains("speak")),
                "via the dyn call: {witness:?}"
            );
            assert!(witness.last().is_some_and(|l| l.contains("lib_vuln")));
        }
        other => panic!("cross-crate virtual sink must be Reachable, got {other:?}"),
    }
}

fn frag2(name: &str) -> fleetreach_reach::CallGraph {
    let path = format!(
        "{}/tests/fixtures/cross_dyn/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = std::fs::read_to_string(path).expect("read fragment");
    parse_graph(&json).expect("parse fragment")
}

fn frag_xc(name: &str) -> fleetreach_reach::CallGraph {
    let path = format!(
        "{}/tests/fixtures/prune_xc/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    parse_graph(&std::fs::read_to_string(path).expect("read fragment")).expect("parse fragment")
}

#[test]
fn coercion_prune_drops_uncoerced_dyn_target_but_keeps_direct_path() {
    // `Real` and `Decoy` both impl `Draw`; the lib coerces only `Real` to
    // `dyn Draw` (a real vtable), while `Decoy::draw` is collected solely from a
    // *direct* call. The sound prune must therefore drop the over-approximating
    // `dyn Draw -> Decoy::draw` edge — yet `decoy_vuln` stays Reachable through
    // the direct call. This is the cross-crate prune working AND staying sound.
    let whole = merge(&[frag_xc("bin.json"), frag_xc("widgets.json")]).expect("merge");

    // Soundness: both sinks are genuinely reachable and must remain so.
    let a = analyze(&whole).expect("analyze");
    for sink in ["real_vuln", "decoy_vuln"] {
        let v = a
            .verdicts
            .iter()
            .find(|v| v.sink.contains(sink))
            .unwrap_or_else(|| panic!("{sink} sink present"));
        assert!(
            matches!(v.verdict, Verdict::Reachable { .. }),
            "{sink} must stay Reachable after the prune, got {:?}",
            v.verdict
        );
    }

    // The prune is *active*: find the two impl nodes by their concrete receiver.
    let node = |needle: &str| {
        whole
            .nodes
            .iter()
            .find(|n| n.label.contains(needle) && n.label.contains("draw"))
            .unwrap_or_else(|| panic!("{needle}::draw node"))
    };
    let kinds_into = |id: u32| -> Vec<EdgeKind> {
        whole
            .edges
            .iter()
            .filter(|e| e.to == id)
            .map(|e| e.kind)
            .collect()
    };

    let decoy_in = kinds_into(node("Decoy").id);
    assert!(
        !decoy_in.contains(&EdgeKind::Virtual),
        "the dyn edge to never-coerced Decoy::draw must be pruned: {decoy_in:?}"
    );
    assert!(
        decoy_in.contains(&EdgeKind::Direct),
        "Decoy::draw is still reached by its direct call: {decoy_in:?}"
    );
    // The coerced impl keeps its virtual edge.
    assert!(
        kinds_into(node("Real").id).contains(&EdgeKind::Virtual),
        "coerced Real::draw must keep its dyn edge"
    );
}

#[test]
fn merge_is_order_independent_for_reachability() {
    let forward = merge(&[frag("bin.json"), frag("vuln_lib.json")]).unwrap();
    let reverse = merge(&[frag("vuln_lib.json"), frag("bin.json")]).unwrap();

    let reachable = |g: &fleetreach_reach::CallGraph| {
        analyze(g).unwrap().verdicts.iter().any(|v| {
            v.sink.contains("vulnerable_fn") && matches!(v.verdict, Verdict::Reachable { .. })
        })
    };
    assert!(reachable(&forward));
    assert!(reachable(&reverse));
}
