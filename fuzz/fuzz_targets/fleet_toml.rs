#![no_main]
//! The `fleet.toml` parser is an untrusted-bytes surface (§13). For *any* input
//! it must return a typed `ConfigError` — never panic. Green here is a
//! precondition for the word "secure".
use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &str| {
    let _ = fleetreach_cli::config::Config::from_str(data, Path::new("."), "fuzz");
});
