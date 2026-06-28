#![no_main]
//! A scanned repo's `go.mod` flows into the Tier-C parser at our trust boundary, and a
//! panic there aborts the whole rayon fleet scan. Ensure arbitrary bytes never panic any
//! of the pure go.mod / version parsers. (Real-data scanning of 10k+ manifests found no
//! panic; this is the adversarial complement.)
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = fleetreach_go::required_modules(data);
    let _ = fleetreach_go::direct_modules(data);
    let _ = fleetreach_go::main_module(data);
    let _ = fleetreach_go::replace_directives(data);
    // The version adapter parses every require/replace version string.
    for line in data.lines() {
        let _ = fleetreach_go::parse_go_version(line.trim());
    }
});
