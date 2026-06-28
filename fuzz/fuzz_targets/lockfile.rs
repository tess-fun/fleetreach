#![no_main]
//! `Cargo.lock` content flows from each repo into rustsec's lockfile parser at
//! our trust boundary. Ensure arbitrary bytes never panic the boundary.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = data.parse::<rustsec::Lockfile>();
});
