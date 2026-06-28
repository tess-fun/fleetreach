#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! R8 soundness corpus (spec §9): the end-to-end evidence that earns the word
//! "sound". Each case runs the driver on a fixture, analyzes its graph with the
//! real `reach` engine, and asserts the verdict for a known sink.
//!
//! The load-bearing assertion is the *negative*: the engine must NEVER return
//! `NotReachable` for a sink that is truly reachable. Over-reporting
//! (`Reachable`/`Unknown` when in fact dead) is acceptable; under-reporting is a
//! security defect. The corpus also reports the unknown-rate — the practical
//! quality signal.

use std::process::Command;

use fleetreach_reach::{analyze_by_path, parse_graph, Verdict};

const DRIVER: &str = env!("CARGO_BIN_EXE_fleetreach-reach-driver");

#[derive(Clone, Copy, Debug, PartialEq)]
enum Expect {
    Reachable,
    NotReachable,
    Unknown,
}

struct Case {
    fixture: &'static str,
    /// (sink path, expected verdict) — the ground truth, hand-verified.
    sinks: &'static [(&'static str, Expect)],
}

/// The corpus. Each fixture exercises a distinct construct; the truth column is
/// established by reading the fixture (which call actually reaches which sink).
const CORPUS: &[Case] = &[
    // Direct calls: a generic instantiated and called from main.
    Case {
        fixture: "direct_calls.rs",
        sinks: &[("identity", Expect::Reachable)],
    },
    // The dangerous-direction anchor: cold_fn is collected (address-taken) but
    // never called → must be NotReachable, not a false Reachable/None.
    Case {
        fixture: "not_reachable.rs",
        sinks: &[
            ("warm_fn", Expect::Reachable),
            ("cold_fn", Expect::NotReachable),
        ],
    },
    // dyn dispatch (RTA virtual edge).
    Case {
        fixture: "dyn_dispatch.rs",
        sinks: &[("vulnerable_dog", Expect::Reachable)],
    },
    // RTA tightness: `reached` via the one coerced impl; `never_reached` is not
    // even collected → unresolved → Unknown (never a false NotReachable).
    Case {
        fixture: "dyn_rta_tight.rs",
        sinks: &[
            ("reached", Expect::Reachable),
            ("never_reached", Expect::Unknown),
        ],
    },
    // RTA over-approximation / coercion-prune soundness guard: B is a virtual
    // impl of T but reached only by a direct call; both sinks are reachable, and
    // `direct_only` must stay Reachable even if a future prune drops the
    // (over-approximating) dyn->B::m virtual edge.
    Case {
        fixture: "rta_overapprox.rs",
        sinks: &[
            ("via_dyn", Expect::Reachable),
            ("direct_only", Expect::Reachable),
        ],
    },
    // fn-pointer indirect dispatch.
    Case {
        fixture: "fn_ptr.rs",
        sinks: &[("vuln_via_ptr", Expect::Reachable)],
    },
    // Opaque frontier: reachable only through an FFI callback → Unknown.
    Case {
        fixture: "ffi_opaque.rs",
        sinks: &[("vuln", Expect::Unknown)],
    },
];

fn classify(v: Option<&Verdict>) -> Expect {
    match v {
        Some(Verdict::Reachable { .. }) => Expect::Reachable,
        Some(Verdict::NotReachable) => Expect::NotReachable,
        Some(Verdict::Unknown { .. }) | None => Expect::Unknown,
    }
}

/// Run the driver on `fixture` in Direct mode with `sinks` requested; return its
/// JSON graph from stdout.
fn run_driver(fixture: &str, sinks: &[&str]) -> String {
    let path = format!("{}/tests/fixtures/{fixture}", env!("CARGO_MANIFEST_DIR"));
    let out = Command::new(DRIVER)
        .args([&path, "--crate-type", "bin", "--edition", "2021"])
        .env("REACH_SINKS", sinks.join("\n"))
        .output()
        .expect("run driver");
    assert!(
        out.status.success(),
        "driver failed on {fixture}:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("driver stdout is UTF-8")
}

#[test]
fn soundness_corpus() {
    let mut total = 0usize;
    let mut unknown = 0usize;
    let mut violations: Vec<String> = Vec::new();
    let mut mismatches: Vec<String> = Vec::new();

    for case in CORPUS {
        let sink_paths: Vec<&str> = case.sinks.iter().map(|(p, _)| *p).collect();
        let graph = parse_graph(&run_driver(case.fixture, &sink_paths)).expect("parse graph");
        let verdicts = analyze_by_path(&graph).expect("analyze");

        for (path, expect) in case.sinks {
            total += 1;
            let got = classify(verdicts.get(*path));
            if got == Expect::Unknown {
                unknown += 1;
            }
            // The non-negotiable invariant: a truly-reachable sink must never
            // come back NotReachable.
            if *expect == Expect::Reachable && got == Expect::NotReachable {
                violations.push(format!(
                    "SOUNDNESS VIOLATION: {}::{path} is reachable but the engine said NotReachable",
                    case.fixture
                ));
            }
            if got != *expect {
                mismatches.push(format!(
                    "{}::{path}: expected {expect:?}, got {got:?}",
                    case.fixture
                ));
            }
        }
    }

    // The unknown-rate metric (reported, not gated — the corpus is curated to
    // include Unknowns on purpose).
    let pct = unknown * 100 / total;
    eprintln!(
        "soundness corpus: {total} sinks · unknown-rate {pct}% · {} decided",
        total - unknown
    );

    assert!(violations.is_empty(), "{}", violations.join("\n"));
    assert!(
        mismatches.is_empty(),
        "verdict mismatches:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn driver_output_is_byte_deterministic() {
    // Same input ⇒ identical graph JSON (spec §9 determinism).
    let a = run_driver("dyn_dispatch.rs", &["vulnerable_dog"]);
    let b = run_driver("dyn_dispatch.rs", &["vulnerable_dog"]);
    assert_eq!(a, b, "driver output must be deterministic");
}
