//! R6 library roots: a library has no `main`, so its audit entry surface is the
//! exported (public) API. A function reachable from a public item is Reachable;
//! a private function reachable from nothing public is not even collected.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fleetreach_reach::{analyze, parse_graph, Verdict};

#[test]
fn exported_api_is_the_root_set() {
    let json = include_str!("fixtures/lib_only.json");
    let g = parse_graph(json).unwrap();

    // `public_api` is exported → a root; the private fns are not roots.
    let root_labels: Vec<&str> = g
        .roots
        .iter()
        .filter_map(|&id| g.nodes.iter().find(|n| n.id == id))
        .map(|n| n.label.as_str())
        .collect();
    assert_eq!(root_labels, vec!["public_api"]);

    let a = analyze(&g).unwrap();
    let v = a
        .verdicts
        .iter()
        .find(|v| v.sink.contains("internal_vuln"))
        .expect("internal_vuln sink");
    assert_eq!(
        v.verdict,
        Verdict::Reachable {
            witness: vec!["public_api".into(), "internal_vuln".into()]
        }
    );
}
