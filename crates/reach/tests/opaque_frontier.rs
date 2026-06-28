//! H-1 regression: the opaque frontier must be wired across the *whole closure*,
//! not per-fragment. A sink reachable only through opaque/FFI re-entry in a crate
//! that has no opaque call site of its own must stay `Unknown`, never a false
//! `NotReachable`.
//!
//! Setup: the bin fragment makes an opaque call (`main -> <opaque>`) but does not
//! itself escape the sink; the lib fragment exports the vulnerable function (so
//! opaque code could call it) and records it in `escaped`, but has no opaque edge.
//! Only `merge` wiring the global sentinel to the union of escaped sets connects
//! them — exactly the cross-crate case the old per-fragment wiring missed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fleetreach_reach::{analyze_paths, merge, parse_graph, Verdict};

const BIN: &str = r#"{
    "schema": 2,
    "nodes": [
        {"id": 0, "label": "main", "symbol": "main_s", "path": "bin::main"},
        {"id": 1, "label": "<opaque>", "symbol": "<opaque>"}
    ],
    "edges": [{"from": 0, "to": 1, "kind": "opaque"}],
    "roots": [0],
    "opaque": [1]
}"#;

fn lib(escaped: &str) -> String {
    format!(
        r#"{{
            "schema": 2,
            "nodes": [{{"id": 0, "label": "vuln", "symbol": "vuln_s", "path": "lib::vulnerable_fn"}}],
            "edges": [],
            "escaped": [{escaped}]
        }}"#
    )
}

#[test]
fn cross_crate_opaque_sink_is_unknown_not_notreachable() {
    let bin = parse_graph(BIN).unwrap();
    let lib = parse_graph(&lib("0")).unwrap(); // vuln is escaped (exported)
    let whole = merge(&[bin, lib]).unwrap();

    let verdict =
        &analyze_paths(&whole, &["lib::vulnerable_fn".to_string()]).unwrap()["lib::vulnerable_fn"];
    assert!(
        matches!(verdict, Verdict::Unknown { .. }),
        "a sink reachable only via cross-crate opaque re-entry must be Unknown, got {verdict:?}"
    );
}

#[test]
fn without_escape_record_the_sink_is_unreachable() {
    // The same closure, but the lib fragment does NOT record the sink as escaped
    // (the pre-fix behavior / a sink genuinely unreachable by opaque code): then
    // there is correctly no opaque path and the verdict is NotReachable. This
    // pins that the escaped record is exactly what flips the verdict.
    let bin = parse_graph(BIN).unwrap();
    let lib = parse_graph(&lib("")).unwrap(); // not escaped
    let whole = merge(&[bin, lib]).unwrap();

    let verdict =
        &analyze_paths(&whole, &["lib::vulnerable_fn".to_string()]).unwrap()["lib::vulnerable_fn"];
    assert_eq!(*verdict, Verdict::NotReachable);
}
