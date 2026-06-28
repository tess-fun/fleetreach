//! Build script for the reach-driver.
//!
//! A custom `rustc_driver` binary has two runtime needs that cargo does not wire
//! up for us:
//!
//! 1. **Sysroot.** The driver is not installed inside the toolchain, so rustc's
//!    own sysroot inference (relative to the running exe) fails. We capture the
//!    sysroot of the *building* toolchain (`$RUSTC --print sysroot`) at compile
//!    time and bake it into the binary as `REACH_SYSROOT`, so the driver always
//!    points at the nightly it was built against — regardless of runtime `PATH`.
//!
//! 2. **rpath.** The driver dynamically links `librustc_driver-*.dylib` (and the
//!    other rustc internals) which live in `<sysroot>/lib`. We add that directory
//!    to the binary's rpath so it loads at runtime without `DYLD_LIBRARY_PATH`.

// A build script may panic to abort the build with a clear message; the
// `expect`/`unwrap` denies the crate sets for its runtime code don't fit here.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::process::Command;

fn main() {
    // `RUSTC` is set by cargo to the compiler in use (the pinned nightly here).
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());

    let output = Command::new(&rustc)
        .args(["--print", "sysroot"])
        .output()
        .expect("failed to run `rustc --print sysroot`");
    assert!(
        output.status.success(),
        "`rustc --print sysroot` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let sysroot = String::from_utf8(output.stdout)
        .expect("sysroot path is not UTF-8")
        .trim()
        .to_string();

    println!("cargo:rustc-env=REACH_SYSROOT={sysroot}");

    // Load the rustc dylibs from the toolchain at runtime.
    println!("cargo:rustc-link-arg=-Wl,-rpath,{sysroot}/lib");

    // Rebuild if the toolchain (and thus the sysroot) changes.
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-changed=build.rs");
}
