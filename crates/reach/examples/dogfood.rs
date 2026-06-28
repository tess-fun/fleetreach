//! Dogfood the static reachability engine on fleetreach's *own* tree.
//!
//! Unlike the toy fixtures in `tests/`, this drives the full engine over a real,
//! large, multi-crate closure — the `fleetreach-cli` binary and everything it
//! pulls in (rustsec, gix, clap, …) — so it catches what fixtures can't: driver
//! crashes, merge gaps, or cache bugs on real code. It is *self-validating*: it
//! asserts ground-truth invariants that must hold for any honest build, and
//! exits non-zero if one fails.
//!
//! Run it via `scripts/dogfood-reach.sh` (which builds the driver first), or
//! directly:
//!   cargo run -p fleetreach-reach --example dogfood -- \
//!       crates/reach-driver/target/debug/fleetreach-reach-driver [TARGET_MANIFEST]
//!
//! TARGET_MANIFEST defaults to this repo's workspace root — it owns the
//! `Cargo.lock` (so the graph cache engages) and its `fleetreach` binary gives
//! the reachability analysis a real `main` root.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fleetreach_reach::{analyze_paths, analyze_project_cached, BuildConfig, Verdict};

const TOOLCHAIN: &str = "nightly-2026-06-01";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(driver) = args.next().map(PathBuf::from) else {
        eprintln!("usage: dogfood <reach-driver-path> [target-manifest-dir]");
        return ExitCode::from(2);
    };
    if !driver.exists() {
        eprintln!("driver not found at {} — build it first:", driver.display());
        eprintln!("  (cd crates/reach-driver && cargo build)");
        return ExitCode::from(2);
    }
    let manifest = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(default_target_manifest);

    println!("dogfood: analyzing {} (real tree)", manifest.display());
    let cfg = BuildConfig::new(TOOLCHAIN);

    // 1. Build the whole closure under the driver (slow, the point) → graph.
    let first = match analyze_project_cached(&manifest, &driver, &cfg, &[]) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("FAIL: the engine errored on the real tree: {e}");
            return ExitCode::FAILURE;
        }
    };
    let graph = &first.graph;
    println!(
        "  graph: {} nodes, {} edges, {} roots ({})",
        graph.nodes.len(),
        graph.edges.len(),
        graph.roots.len(),
        if first.from_cache {
            "from cache"
        } else {
            "rebuilt"
        }
    );

    let mut ok = true;

    // Invariant: a real binary closure is a substantial graph with at least one
    // root (a `main`). An empty graph or no roots means the driver/merge silently
    // produced nothing.
    ok &= check("graph is non-trivial", graph.nodes.len() > 100);
    ok &= check("has at least one root", !graph.roots.is_empty());

    // Ground truth: the cli binary obviously calls into fleetreach's own crates,
    // so *some* `fleetreach_*` function must be reachable from a root. (We never
    // assert the converse — a false NotReachable is the only real defect.)
    let own: Vec<String> = graph
        .nodes
        .iter()
        .filter_map(|n| n.path.clone())
        .filter(|p| p.starts_with("fleetreach_"))
        .collect();
    let verdicts = analyze_paths(graph, &own).unwrap_or_default();
    let reachable = verdicts
        .values()
        .filter(|v| matches!(v, Verdict::Reachable { .. }))
        .count();
    println!(
        "  fleetreach_* functions in closure: {}, reachable from a root: {}",
        own.len(),
        reachable
    );
    ok &= check(
        "at least one fleetreach_* function is reachable from a root",
        reachable > 0,
    );

    // The cache is a correctness input — re-running must serve the same graph
    // without rebuilding it on a real tree.
    match analyze_project_cached(&manifest, &driver, &cfg, &[]) {
        Ok(second) => ok &= check("second run hits the graph cache", second.from_cache),
        Err(e) => {
            eprintln!("FAIL: second run errored: {e}");
            ok = false;
        }
    }

    if ok {
        println!("dogfood: OK — the engine is sound and consistent on the real tree.");
        ExitCode::SUCCESS
    } else {
        eprintln!("dogfood: FAILED — see the checks above.");
        ExitCode::FAILURE
    }
}

/// Print a pass/fail line for one invariant and return whether it held.
fn check(what: &str, pass: bool) -> bool {
    println!("  [{}] {what}", if pass { "PASS" } else { "FAIL" });
    pass
}

/// This repo's workspace root — `<reach manifest>/../..` — which owns the
/// `Cargo.lock` the graph cache keys on.
fn default_target_manifest() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}
