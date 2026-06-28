//! A stand-in for a hostile build script. It tries to write a marker file into
//! its own (source) directory — somewhere *outside* the build's scratch work
//! dir. Unconfined, the write lands; under the sandbox, the source tree is
//! read-only, so it is blocked. The reach integration test (`tests/sandbox.rs`)
//! uses the marker's presence/absence as the observable proof that confinement
//! actually bites — while the build itself still succeeds.

fn main() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let marker = format!("{dir}/build-probe-marker");
    // Ignore the result: a hostile script would, and the build must still
    // succeed either way (a failed build.rs would mask the FS-confinement signal
    // behind a build failure).
    let _ = std::fs::write(&marker, b"the build wrote here\n");
    // Force a rerun every build (the test also uses a fresh target dir).
    println!("cargo:rerun-if-changed=build.rs");
}
