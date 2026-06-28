#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! R2 verification: the driver emits correct **direct-call** edges, and the
//! graph supports a root→target reachability query (the substrate R3 turns into
//! a witness chain).
//!
//! We parse the JSON artifact as untyped `Value` on purpose — the test sits on
//! the *consumer* side of the parse-not-trust boundary and should depend only on
//! the wire shape, not the driver's internal types.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::process::Command;

use serde_json::Value;

const DRIVER: &str = env!("CARGO_BIN_EXE_fleetreach-reach-driver");

struct Graph {
    /// node id -> label
    labels: HashMap<u64, String>,
    /// label -> node id (labels are unique per monomorphization here)
    by_label: HashMap<String, u64>,
    /// adjacency (all edge kinds): from -> set of to
    adj: HashMap<u64, BTreeSet<u64>>,
    /// (from, to, kind) triples, for kind-specific assertions
    kinded: BTreeSet<(u64, u64, String)>,
    /// opaque-frontier node ids
    opaque: BTreeSet<u64>,
    schema: u64,
}

impl Graph {
    fn of_fixture(name: &str) -> Self {
        let fixture = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        let out = Command::new(DRIVER)
            .args([&fixture, "--crate-type", "bin", "--edition", "2021"])
            .output()
            .expect("run reach-driver");
        assert!(
            out.status.success(),
            "driver failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let json: Value = serde_json::from_slice(&out.stdout).expect("driver stdout is valid JSON");

        let schema = json["schema"].as_u64().expect("schema field");

        let mut labels = HashMap::new();
        let mut by_label = HashMap::new();
        for node in json["nodes"].as_array().expect("nodes array") {
            let id = node["id"].as_u64().expect("node id");
            let label = node["label"].as_str().expect("node label").to_string();
            labels.insert(id, label.clone());
            by_label.insert(label, id);
        }

        let mut adj: HashMap<u64, BTreeSet<u64>> = HashMap::new();
        let mut kinded: BTreeSet<(u64, u64, String)> = BTreeSet::new();
        for edge in json["edges"].as_array().expect("edges array") {
            let from = edge["from"].as_u64().expect("edge from");
            let to = edge["to"].as_u64().expect("edge to");
            let kind = edge["kind"].as_str().expect("edge kind").to_string();
            adj.entry(from).or_default().insert(to);
            kinded.insert((from, to, kind));
        }

        let opaque: BTreeSet<u64> = json["opaque"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_u64).collect())
            .unwrap_or_default();

        Graph {
            labels,
            by_label,
            adj,
            kinded,
            opaque,
            schema,
        }
    }

    fn id(&self, label: &str) -> u64 {
        *self.by_label.get(label).unwrap_or_else(|| {
            panic!(
                "no node labeled {label:?}; have: {:?}",
                self.labels.values().collect::<Vec<_>>()
            )
        })
    }

    fn has_edge(&self, from: &str, to: &str) -> bool {
        self.adj
            .get(&self.id(from))
            .is_some_and(|s| s.contains(&self.id(to)))
    }

    /// Does an edge of the given kind (`direct`/`virtual`/`indirect`) exist?
    fn has_kind(&self, from: &str, to: &str, kind: &str) -> bool {
        self.kinded
            .contains(&(self.id(from), self.id(to), kind.to_string()))
    }

    fn has_node(&self, label: &str) -> bool {
        self.by_label.contains_key(label)
    }

    /// Is `to` reachable from `from`? `clean_only` excludes `opaque` edges.
    fn reaches_inner(&self, from: &str, to: &str, clean_only: bool) -> bool {
        let target = self.id(to);
        let mut seen = BTreeSet::new();
        let mut queue = VecDeque::from([self.id(from)]);
        while let Some(n) = queue.pop_front() {
            if n == target {
                return true;
            }
            if !seen.insert(n) {
                continue;
            }
            for (f, t, kind) in &self.kinded {
                if *f == n && !(clean_only && kind == "opaque") {
                    queue.push_back(*t);
                }
            }
        }
        false
    }

    fn reaches(&self, from: &str, to: &str) -> bool {
        self.reaches_inner(from, to, false)
    }

    fn clean_reaches(&self, from: &str, to: &str) -> bool {
        self.reaches_inner(from, to, true)
    }
}

#[test]
fn direct_edges_are_correct() {
    let g = Graph::of_fixture("direct_calls.rs");

    assert_eq!(g.schema, 2);

    // The hand-written calls in the fixture.
    assert!(
        g.has_edge("main", "used_directly"),
        "main calls used_directly"
    );
    assert!(
        g.has_edge("used_directly", "identity::<u32>"),
        "used_directly calls identity::<u32>"
    );
    assert!(
        g.has_edge("used_directly", "identity::<u8>"),
        "used_directly calls identity::<u8>"
    );
}

#[test]
fn reachability_from_main() {
    let g = Graph::of_fixture("direct_calls.rs");

    // The whole point: a vulnerable sink reachable through a chain is reachable.
    assert!(g.reaches("main", "identity::<u32>"));
    assert!(g.reaches("main", "identity::<u8>"));

    // The dead fn is not even a node (lazy collection from roots), so it is
    // trivially unreachable — no false `Reachable`.
    assert!(!g.by_label.contains_key("never_called"));
}

#[test]
fn no_self_dangling_edges() {
    let g = Graph::of_fixture("direct_calls.rs");
    // Every edge endpoint must be a real node id.
    for (from, tos) in &g.adj {
        assert!(g.labels.contains_key(from), "edge from unknown node {from}");
        for to in tos {
            assert!(g.labels.contains_key(to), "edge to unknown node {to}");
        }
    }
}

// ---- R4: dynamic dispatch (RTA) ----

#[test]
fn virtual_dispatch_targets_every_instantiated_impl() {
    let g = Graph::of_fixture("dyn_dispatch.rs");

    // Both Dog and Cat are coerced to `dyn Animal`, so the virtual call from
    // main dispatches to both impls.
    assert!(g.has_kind("main", "<Dog as Animal>::speak", "virtual"));
    assert!(g.has_kind("main", "<Cat as Animal>::speak", "virtual"));

    // The sink is reachable through the Dog impl: main ->(virtual) Dog::speak
    // ->(direct) vulnerable_dog.
    assert!(g.has_kind("<Dog as Animal>::speak", "vulnerable_dog", "direct"));
    assert!(g.reaches("main", "vulnerable_dog"));
}

#[test]
fn rta_is_tighter_than_cha() {
    let g = Graph::of_fixture("dyn_rta_tight.rs");

    // Only `A` is ever coerced to `dyn Greet`, so the virtual call resolves to
    // A's impl only — and B's impl (a valid CHA target) is not even collected.
    assert!(g.has_kind("main", "<A as Greet>::hi", "virtual"));
    assert!(
        !g.has_node("<B as Greet>::hi"),
        "B::hi must not be a node (uncollected)"
    );
    assert!(!g.has_node("never_reached"));
    assert!(g.reaches("main", "reached"));
}

// ---- R4: fn-pointer / indirect dispatch ----

#[test]
fn fn_pointer_calls_reach_address_taken_targets() {
    let g = Graph::of_fixture("fn_ptr.rs");

    // Both functions have their address taken into the table; the indirect call
    // dispatches to both (signature-compatible).
    assert!(g.has_kind("main", "target_a", "indirect"));
    assert!(g.has_kind("main", "target_b", "indirect"));

    // The sink behind the fn pointer is reachable.
    assert!(g.has_kind("target_a", "vuln_via_ptr", "direct"));
    assert!(g.reaches("main", "vuln_via_ptr"));
}

// ---- R5: opaque frontier (FFI) ----

#[test]
fn ffi_call_routes_through_opaque_frontier() {
    let g = Graph::of_fixture("ffi_opaque.rs");

    // The FFI call and the frontier's callback edge exist.
    let sentinel = "⟨opaque external code⟩";
    assert!(!g.opaque.is_empty(), "an opaque node must exist");
    assert!(
        g.has_kind("main", sentinel, "opaque"),
        "FFI call -> frontier"
    );
    assert!(
        g.has_kind(sentinel, "callback", "opaque"),
        "frontier -> escaped callback"
    );
    assert!(g.has_kind("callback", "vuln", "direct"));

    // `vuln` is reachable only ACROSS the opaque frontier: not via clean edges,
    // but yes when the frontier is traversed. This is exactly what makes reach
    // return Unknown (never NotReachable).
    assert!(
        !g.clean_reaches("main", "vuln"),
        "no analyzable path to vuln"
    );
    assert!(g.reaches("main", "vuln"), "reachable through the frontier");
}
