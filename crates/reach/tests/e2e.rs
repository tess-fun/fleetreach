//! End-to-end: drive a real cargo build of a fixture project under the wrapper
//! and prove the whole-closure analysis reaches a sink that lives in a
//! dependency.
//!
//! Ignored by default — it requires the pinned nightly toolchain and a built
//! reach-driver, so it does not belong in the fast stable suite. Run with:
//!   (cd crates/reach-driver && cargo build)
//!   cargo test -p fleetreach-reach --test e2e -- --ignored

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fleetreach_reach::{
    analyze_project, analyze_project_cached, BuildConfig, FeatureSelection, ProjectOptions, Verdict,
};

const TOOLCHAIN: &str = "nightly-2026-06-27";

fn driver_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .join("reach-driver/target/debug/fleetreach-reach-driver")
}

/// Point the graph cache at a fresh per-process temp dir, so re-running the
/// suite never sees a stale entry (the `!from_cache` assertions below depend on
/// a cold cache) and tests never pollute the developer's real `~/.cache`. Set
/// exactly once, before any build, so parallel tests don't race on the env var.
fn isolated_cache() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let dir = std::env::temp_dir().join(format!("reach-e2e-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("XDG_CACHE_HOME", &dir);
    });
}

fn cross_crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/projects/cross_crate")
}

fn feature_gated_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/projects/feature_gated")
}

#[test]
#[ignore = "requires pinned nightly + built reach-driver; run with --ignored"]
fn cached_second_run_skips_the_build() {
    isolated_cache();
    let driver = driver_path();
    assert!(driver.exists(), "build the driver first");
    let manifest = cross_crate_dir();
    let paths = vec!["vuln_lib::vulnerable_fn".to_string()];

    // Prime the cache, then a second identical run must hit it (no rebuild) and
    // still produce the right verdict from sink resolution alone.
    let build = BuildConfig::new(TOOLCHAIN);
    let _ = analyze_project_cached(&manifest, &driver, &build, &paths).expect("first run");
    let second = analyze_project_cached(&manifest, &driver, &build, &paths).expect("second run");

    assert!(second.from_cache, "second run should hit the graph cache");
    assert!(matches!(
        second.verdicts.get("vuln_lib::vulnerable_fn"),
        Some(Verdict::Reachable { .. })
    ));
}

#[test]
#[ignore = "requires pinned nightly + built reach-driver; run with --ignored"]
fn feature_selection_flips_the_verdict_and_the_cache_key() {
    isolated_cache();
    // The same lock + source, built with vs. without a feature, must give
    // different verdicts — and therefore must NOT share a cache entry, or a
    // feature change would serve a stale graph (a false NotReachable).
    let driver = driver_path();
    assert!(driver.exists(), "build the driver first");
    let manifest = feature_gated_dir();
    let paths = vec!["vuln_lib::vulnerable_fn".to_string()];

    // Default features: `main` never calls into vuln_lib → unreachable.
    let off = analyze_project_cached(&manifest, &driver, &BuildConfig::new(TOOLCHAIN), &paths)
        .expect("build (no feature)");
    assert_eq!(
        off.verdicts.get("vuln_lib::vulnerable_fn"),
        Some(&Verdict::NotReachable),
        "without the feature the call edge is absent"
    );

    // Enabling the feature adds the call edge → reachable. A *different* cache
    // key, so this rebuilds rather than serving the previous graph.
    let with_feature = BuildConfig {
        features: FeatureSelection {
            features: vec!["enable-vuln".to_string()],
            ..Default::default()
        },
        ..BuildConfig::new(TOOLCHAIN)
    };
    let on = analyze_project_cached(&manifest, &driver, &with_feature, &paths)
        .expect("build (feature on)");
    assert!(
        !on.from_cache,
        "a different feature set must miss the cache, not reuse the default-feature graph"
    );
    assert!(
        matches!(
            on.verdicts.get("vuln_lib::vulnerable_fn"),
            Some(Verdict::Reachable { .. })
        ),
        "with the feature the sink becomes reachable, got {:?}",
        on.verdicts.get("vuln_lib::vulnerable_fn")
    );
}

#[test]
#[ignore = "requires pinned nightly + built reach-driver; run with --ignored"]
fn whole_closure_reaches_dependency_sink() {
    isolated_cache();
    let driver = driver_path();
    assert!(
        driver.exists(),
        "build the driver first: (cd crates/reach-driver && cargo build)"
    );

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/projects/cross_crate");
    let sinks = vec!["vuln_lib::vulnerable_fn".to_string()];
    let opts = ProjectOptions {
        manifest_dir: &manifest,
        driver: &driver,
        build: BuildConfig::new(TOOLCHAIN),
        sinks: &sinks,
    };

    let result = analyze_project(&opts).expect("analyze project");

    let v = result
        .analysis
        .verdicts
        .iter()
        .find(|v| v.sink.contains("vulnerable_fn"))
        .expect("vulnerable_fn sink");
    match &v.verdict {
        Verdict::Reachable { witness } => {
            assert_eq!(witness.first().map(String::as_str), Some("main"));
            assert!(witness.last().is_some_and(|l| l.contains("vulnerable_fn")));
        }
        other => panic!("expected Reachable end-to-end, got {other:?}"),
    }
}
