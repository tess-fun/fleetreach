#![no_main]
//! Java archives in an image are attacker-supplied zip files, and nested ones are unpacked.
//! Whatever they hold, reading them ends with a list of what was found: no panic, and nesting
//! and sizes stay within their limits.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fleetreach_os::jar::inspect("opt/app-1.0.jar", data);
});
