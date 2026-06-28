#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! R1 verification: the driver's monomorphized-`fn` set must match the
//! compiler's own `-Zprint-mono-items`.
//!
//! This is the soundness anchor for the whole engine (spec §14.1): we are
//! asserting that what we read from the collector is exactly what rustc itself
//! would emit, so any future drift in our reading is caught here. It is also the
//! first entry in the determinism suite (§9) — same input ⇒ same set.
//!
//! Both sides run under the crate's pinned nightly: `CARGO_BIN_EXE_*` gives the
//! freshly built driver, and `rustc` on `PATH` resolves to the nightly via this
//! crate's `rust-toolchain.toml`.

use std::collections::BTreeSet;
use std::process::Command;

const DRIVER: &str = env!("CARGO_BIN_EXE_fleetreach-reach-driver");

/// The `fn` mono items the driver reports, as a normalized set.
fn driver_fn_items(fixture: &str) -> BTreeSet<String> {
    let out = Command::new(DRIVER)
        .args([fixture, "--crate-type", "bin", "--edition", "2021"])
        .output()
        .expect("run reach-driver");
    assert!(
        out.status.success(),
        "driver failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The driver emits the `MONO_ITEM` diagnostic view on stderr (stdout carries
    // the JSON call graph — see tests/call_graph.rs).
    parse_fn_items(&String::from_utf8_lossy(&out.stderr))
}

/// The `fn` mono items rustc reports via `-Zprint-mono-items`, as a normalized
/// set. rustc appends a ` @@ <cgu>[mode]` suffix we strip so the two are
/// comparable.
fn rustc_fn_items(fixture: &str) -> BTreeSet<String> {
    let bin = std::env::temp_dir().join("reach_r1_fixture_bin");
    let out = Command::new("rustc")
        .args([
            "-Zprint-mono-items=yes",
            "--crate-type",
            "bin",
            "--edition",
            "2021",
            fixture,
            "-o",
        ])
        .arg(&bin)
        .output()
        .expect("run rustc");
    assert!(
        out.status.success(),
        "rustc failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // rustc prints MONO_ITEM lines on stderr.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    parse_fn_items(&combined)
}

/// Extract `fn` mono items from either tool's output: keep `MONO_ITEM fn …`
/// lines, drop the `MONO_ITEM ` prefix and any ` @@ …` codegen-unit suffix.
fn parse_fn_items(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("MONO_ITEM "))
        .filter(|item| item.starts_with("fn "))
        .map(|item| item.split(" @@ ").next().unwrap_or(item).trim().to_string())
        .collect()
}

#[test]
fn driver_matches_rustc_mono_items() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/direct_calls.rs"
    );

    let ours = driver_fn_items(fixture);
    let theirs = rustc_fn_items(fixture);

    assert_eq!(
        ours,
        theirs,
        "\ndriver-only items: {:?}\nrustc-only items: {:?}",
        ours.difference(&theirs).collect::<Vec<_>>(),
        theirs.difference(&ours).collect::<Vec<_>>(),
    );

    // Sanity: the fixture's distinct monomorphizations are present, and the
    // dead fn is absent (lazy collection from `main`).
    assert!(ours.contains("fn identity::<u32>"));
    assert!(ours.contains("fn identity::<u8>"));
    assert!(ours.iter().all(|i| !i.contains("never_called")));
}

#[test]
fn driver_output_is_deterministic() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/direct_calls.rs"
    );
    assert_eq!(driver_fn_items(fixture), driver_fn_items(fixture));
}
