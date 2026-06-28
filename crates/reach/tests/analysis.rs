//! R3 verification: the reachability closure produces the correct verdict
//! trichotomy and witness chains — on hand-built graphs (the corner cases) and
//! on a real `reach-driver` artifact (the end-to-end shape).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fleetreach_reach::{
    analyze, analyze_by_path, analyze_paths, analyze_with_roots, parse_graph, ReachError, Verdict,
};

/// A tiny linear graph: 0 -> 1 -> 2, with 3 disconnected.
fn linear_graph() -> String {
    r#"{
        "schema": 2,
        "nodes": [
            {"id": 0, "label": "main", "symbol": "s0"},
            {"id": 1, "label": "mid", "symbol": "s1"},
            {"id": 2, "label": "vuln", "symbol": "s2"},
            {"id": 3, "label": "island", "symbol": "s3"}
        ],
        "edges": [
            {"from": 0, "to": 1, "kind": "direct"},
            {"from": 1, "to": 2, "kind": "direct"}
        ],
        "roots": [0],
        "sinks": [2],
        "unresolved_sinks": []
    }"#
    .to_string()
}

#[test]
fn reachable_sink_gets_witness_chain() {
    let g = parse_graph(&linear_graph()).unwrap();
    let a = analyze(&g).unwrap();

    assert_eq!(a.verdicts.len(), 1);
    let v = &a.verdicts[0];
    assert_eq!(v.sink, "vuln");
    assert_eq!(
        v.verdict,
        Verdict::Reachable {
            witness: vec!["main".into(), "mid".into(), "vuln".into()],
        }
    );
}

#[test]
fn unreachable_sink_is_not_reachable() {
    // Override roots to the disconnected island: `vuln` is now unreachable.
    let g = parse_graph(&linear_graph()).unwrap();
    let a = analyze_with_roots(&g, &[3]).unwrap();

    assert_eq!(a.verdicts[0].verdict, Verdict::NotReachable);
}

#[test]
fn a_root_that_is_the_sink_has_a_singleton_witness() {
    let g = parse_graph(&linear_graph()).unwrap();
    // Root == sink (node 2): trivially reachable, witness is just itself.
    let a = analyze_with_roots(&g, &[2]).unwrap();
    assert_eq!(
        a.verdicts[0].verdict,
        Verdict::Reachable {
            witness: vec!["vuln".into()]
        }
    );
}

#[test]
fn unresolved_sink_is_unknown_not_unreachable() {
    let json = r#"{
        "schema": 2,
        "nodes": [{"id": 0, "label": "main", "symbol": "s0"}],
        "edges": [],
        "roots": [0],
        "sinks": [],
        "unresolved_sinks": ["time::UtcOffset::local_offset_at"]
    }"#;
    let g = parse_graph(json).unwrap();
    let a = analyze(&g).unwrap();

    assert_eq!(a.verdicts.len(), 1);
    assert_eq!(a.verdicts[0].sink, "time::UtcOffset::local_offset_at");
    assert!(matches!(a.verdicts[0].verdict, Verdict::Unknown { .. }));
}

#[test]
fn shortest_witness_is_chosen() {
    // Two paths to the sink: 0->1->3 (len 2) and 0->2->4->3 (len 3). BFS must
    // pick the shorter one.
    let json = r#"{
        "schema": 2,
        "nodes": [
            {"id": 0, "label": "root", "symbol": "s0"},
            {"id": 1, "label": "short", "symbol": "s1"},
            {"id": 2, "label": "long_a", "symbol": "s2"},
            {"id": 3, "label": "sink", "symbol": "s3"},
            {"id": 4, "label": "long_b", "symbol": "s4"}
        ],
        "edges": [
            {"from": 0, "to": 1, "kind": "direct"},
            {"from": 1, "to": 3, "kind": "direct"},
            {"from": 0, "to": 2, "kind": "direct"},
            {"from": 2, "to": 4, "kind": "direct"},
            {"from": 4, "to": 3, "kind": "direct"}
        ],
        "roots": [0],
        "sinks": [3],
        "unresolved_sinks": []
    }"#;
    let g = parse_graph(json).unwrap();
    let a = analyze(&g).unwrap();
    assert_eq!(
        a.verdicts[0].verdict,
        Verdict::Reachable {
            witness: vec!["root".into(), "short".into(), "sink".into()]
        }
    );
}

#[test]
fn by_path_keys_verdicts_by_requested_path() {
    // A requested path resolves to one node whose crate-local LABEL ("vuln")
    // differs from the requested PATH ("dep::vuln") — the by-path map keys on the
    // path, which is how a consumer attributes the verdict.
    let json = r#"{
        "schema": 2,
        "nodes": [
            {"id": 0, "label": "main", "symbol": "s0"},
            {"id": 1, "label": "vuln", "symbol": "s1"},
            {"id": 2, "label": "cold", "symbol": "s2"}
        ],
        "edges": [{"from": 0, "to": 1, "kind": "direct"}],
        "roots": [0],
        "sinks": [1, 2],
        "sink_paths": [
            {"path": "dep::vuln", "nodes": [1]},
            {"path": "dep::cold", "nodes": [2]}
        ],
        "unresolved_sinks": ["dep::missing"]
    }"#;
    let g = parse_graph(json).unwrap();
    let by_path = analyze_by_path(&g).unwrap();

    assert_eq!(
        by_path.get("dep::vuln"),
        Some(&Verdict::Reachable {
            witness: vec!["main".into(), "vuln".into()]
        })
    );
    assert_eq!(by_path.get("dep::cold"), Some(&Verdict::NotReachable));
    assert!(matches!(
        by_path.get("dep::missing"),
        Some(Verdict::Unknown { .. })
    ));
}

#[test]
fn analyze_paths_resolves_against_node_paths() {
    // The caching basis: sinks are resolved from each node's crate-qualified
    // `path` (no driver-side sink marking, no rebuild). The node LABELs are
    // crate-local; resolution keys on `path`.
    let json = r#"{
        "schema": 2,
        "nodes": [
            {"id": 0, "label": "main", "symbol": "s0", "path": "app::main"},
            {"id": 1, "label": "v", "symbol": "s1", "path": "dep::vuln"},
            {"id": 2, "label": "c", "symbol": "s2", "path": "dep::cold"}
        ],
        "edges": [{"from": 0, "to": 1, "kind": "direct"}],
        "roots": [0]
    }"#;
    let g = parse_graph(json).unwrap();
    let v = analyze_paths(
        &g,
        &[
            "dep::vuln".into(),
            "dep::cold".into(),
            "dep::missing".into(),
        ],
    )
    .unwrap();

    assert!(matches!(
        v.get("dep::vuln"),
        Some(Verdict::Reachable { .. })
    ));
    assert_eq!(v.get("dep::cold"), Some(&Verdict::NotReachable));
    assert!(matches!(
        v.get("dep::missing"),
        Some(Verdict::Unknown { .. })
    ));
}

#[test]
fn unsupported_schema_errors() {
    let json = r#"{"schema": 999, "nodes": [], "edges": []}"#;
    let g = parse_graph(json).unwrap();
    assert_eq!(
        analyze(&g),
        Err(ReachError::UnsupportedSchema {
            found: 999,
            supported: 2
        })
    );
}

#[test]
fn dangling_edge_is_malformed() {
    let json = r#"{
        "schema": 2,
        "nodes": [{"id": 0, "label": "a", "symbol": "s0"}],
        "edges": [{"from": 0, "to": 99, "kind": "direct"}],
        "roots": [0], "sinks": [], "unresolved_sinks": []
    }"#;
    let g = parse_graph(json).unwrap();
    assert!(matches!(analyze(&g), Err(ReachError::Malformed(_))));
}

#[test]
fn unknown_edge_kind_still_parses() {
    // Forward-compat: a future driver emits an edge kind this build predates.
    // It must parse (as `Other`) and still count as a real edge.
    let json = r#"{
        "schema": 2,
        "nodes": [
            {"id": 0, "label": "root", "symbol": "s0"},
            {"id": 1, "label": "sink", "symbol": "s1"}
        ],
        "edges": [{"from": 0, "to": 1, "kind": "some_future_kind"}],
        "roots": [0], "sinks": [1], "unresolved_sinks": []
    }"#;
    let g = parse_graph(json).unwrap();
    let a = analyze(&g).unwrap();
    assert!(matches!(a.verdicts[0].verdict, Verdict::Reachable { .. }));
}

// ---- end-to-end shape: a real reach-driver artifact ----

#[test]
fn real_driver_graph_main_reaches_identity() {
    let json = include_str!("fixtures/direct_calls.graph.json");
    let g = parse_graph(json).unwrap();
    let a = analyze(&g).unwrap();

    // Two resolved sinks (both monomorphizations of `identity`) + one unresolved.
    assert_eq!(a.verdicts.len(), 3);

    for v in &a.verdicts {
        match v.sink.as_str() {
            "identity::<u32>" => assert_eq!(
                v.verdict,
                Verdict::Reachable {
                    witness: vec![
                        "main".into(),
                        "used_directly".into(),
                        "identity::<u32>".into()
                    ]
                }
            ),
            "identity::<u8>" => assert_eq!(
                v.verdict,
                Verdict::Reachable {
                    witness: vec![
                        "main".into(),
                        "used_directly".into(),
                        "identity::<u8>".into()
                    ]
                }
            ),
            "nonexistent::sink" => assert!(matches!(v.verdict, Verdict::Unknown { .. })),
            other => panic!("unexpected sink {other}"),
        }
    }
}

// ---- R5: opaque frontier + Unknown discipline ----

#[test]
fn opaque_three_way_verdict() {
    // main -> clean_sink (analyzable). main -> <opaque> -> opaque_sink (only via
    // the frontier). unreachable_sink: no path at all.
    let json = r#"{
        "schema": 2,
        "nodes": [
            {"id": 0, "label": "main", "symbol": "s0"},
            {"id": 1, "label": "clean_sink", "symbol": "s1"},
            {"id": 2, "label": "opaque_sink", "symbol": "s2"},
            {"id": 3, "label": "<opaque>", "symbol": "s3"},
            {"id": 4, "label": "unreachable_sink", "symbol": "s4"}
        ],
        "edges": [
            {"from": 0, "to": 1, "kind": "direct"},
            {"from": 0, "to": 3, "kind": "opaque"},
            {"from": 3, "to": 2, "kind": "opaque"}
        ],
        "roots": [0],
        "sinks": [1, 2, 4],
        "opaque": [3],
        "unresolved_sinks": []
    }"#;
    let g = parse_graph(json).unwrap();
    let a = analyze(&g).unwrap();

    let verdict = |label: &str| {
        a.verdicts
            .iter()
            .find(|v| v.sink == label)
            .map(|v| v.verdict.clone())
            .unwrap()
    };

    // Clean path wins → crisp Reachable, and the witness does NOT route through
    // the opaque frontier.
    assert_eq!(
        verdict("clean_sink"),
        Verdict::Reachable {
            witness: vec!["main".into(), "clean_sink".into()]
        }
    );
    // Reachable only across the opaque frontier → Unknown, never NotReachable.
    assert!(matches!(verdict("opaque_sink"), Verdict::Unknown { .. }));
    // No path even through the frontier → sound NotReachable.
    assert_eq!(verdict("unreachable_sink"), Verdict::NotReachable);
}

#[test]
fn ffi_only_path_is_unknown() {
    // End-to-end: `vuln` is reachable only through an FFI callback the driver
    // routed across the opaque frontier.
    let json = include_str!("fixtures/ffi_opaque.graph.json");
    let g = parse_graph(json).unwrap();
    let a = analyze(&g).unwrap();

    let v = a
        .verdicts
        .iter()
        .find(|v| v.sink == "vuln")
        .expect("vuln sink");
    assert!(
        matches!(v.verdict, Verdict::Unknown { .. }),
        "FFI-only sink must be Unknown, got {:?}",
        v.verdict
    );
}

#[test]
fn clean_sink_stays_reachable_despite_reachable_opaque() {
    // direct_calls now has a reachable opaque frontier (runtime startup hits
    // syscalls), but `identity` is reachable by a clean path — still Reachable.
    let json = include_str!("fixtures/direct_calls.graph.json");
    let g = parse_graph(json).unwrap();
    let a = analyze(&g).unwrap();

    for v in &a.verdicts {
        if v.sink.starts_with("identity") {
            assert!(
                matches!(v.verdict, Verdict::Reachable { .. }),
                "{} should stay Reachable, got {:?}",
                v.sink,
                v.verdict
            );
        }
    }
}

#[test]
fn witness_chain_crosses_a_virtual_edge() {
    // End-to-end on a dyn-dispatch graph: the witness to `vulnerable_dog` runs
    // through the virtual call `main -> <Dog as Animal>::speak`. `reach` is
    // edge-kind agnostic, so the chain reads as a normal call path.
    let json = include_str!("fixtures/dyn_dispatch.graph.json");
    let g = parse_graph(json).unwrap();
    let a = analyze(&g).unwrap();

    let v = a
        .verdicts
        .iter()
        .find(|v| v.sink == "vulnerable_dog")
        .expect("vulnerable_dog sink");
    assert_eq!(
        v.verdict,
        Verdict::Reachable {
            witness: vec![
                "main".into(),
                "<Dog as Animal>::speak".into(),
                "vulnerable_dog".into(),
            ]
        }
    );
}

#[test]
fn real_driver_graph_not_reachable_without_roots() {
    // Soundness check on real data: with no roots, the sinks are NotReachable
    // (and never falsely Unknown/Reachable).
    let json = include_str!("fixtures/direct_calls.graph.json");
    let g = parse_graph(json).unwrap();
    let a = analyze_with_roots(&g, &[]).unwrap();

    for v in &a.verdicts {
        if v.sink.starts_with("identity") {
            assert_eq!(v.verdict, Verdict::NotReachable);
        }
    }
}
