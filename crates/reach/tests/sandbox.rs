//! Build-sandbox confinement, proven end-to-end: the same fixture build, run
//! with confinement off vs. on, differs only in whether a hostile `build.rs`
//! could write outside the build's scratch dir.
//!
//! macOS-only (the verified `sandbox-exec` path) and ignored by default — it
//! needs the pinned nightly + a built reach-driver. Run with:
//!   (cd crates/reach-driver && cargo build)
//!   cargo test -p fleetreach-reach --test sandbox -- --ignored

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(target_os = "macos")]

use std::path::PathBuf;

use fleetreach_reach::{analyze_project, BuildConfig, ProjectOptions, SandboxPolicy};

const TOOLCHAIN: &str = "nightly-2026-06-27";

fn driver_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .join("reach-driver/target/debug/fleetreach-reach-driver")
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/projects/sandbox_probe")
}

/// Run the fixture build under `policy` and report whether its `build.rs`
/// managed to write the marker into the (source) tree.
fn build_and_check_marker(policy: SandboxPolicy) -> bool {
    let dir = fixture_dir();
    let marker = dir.join("build-probe-marker");
    let _ = std::fs::remove_file(&marker);

    let driver = driver_path();
    let opts = ProjectOptions {
        manifest_dir: &dir,
        driver: &driver,
        build: BuildConfig {
            sandbox: policy,
            ..BuildConfig::new(TOOLCHAIN)
        },
        sinks: &[],
    };
    // The build must succeed regardless of confinement — confinement denies the
    // hostile write, it does not break the build.
    analyze_project(&opts).expect("fixture build should succeed");

    let wrote = marker.exists();
    let _ = std::fs::remove_file(&marker);
    wrote
}

#[test]
#[ignore = "requires pinned nightly + built reach-driver (macOS); run with --ignored"]
fn sandbox_confines_a_hostile_build_write() {
    assert!(driver_path().exists(), "build the driver first");

    // Unconfined: the build script's write into the source tree lands.
    assert!(
        build_and_check_marker(SandboxPolicy::Off),
        "without a sandbox, the build.rs write should land (control case)"
    );

    // Confined: the same write is blocked (source tree is read-only), yet the
    // build still succeeds.
    assert!(
        !build_and_check_marker(SandboxPolicy::Auto),
        "with the sandbox, the build.rs write outside the scratch dir must be blocked"
    );
}
