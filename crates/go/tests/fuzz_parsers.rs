//! Property-fuzz: the go.mod / version parsers must never panic on arbitrary input.
//!
//! A scanned repo's `go.mod` is untrusted, and a panic in the Tier-C parser aborts the
//! whole rayon fleet scan — so "never panics" is a hard invariant. The cargo-fuzz
//! `go_mod` target gives coverage-guided fuzzing (Linux/CI); this is the toolchain-free,
//! always-on complement that runs under plain `cargo test`.
#![allow(clippy::unwrap_used)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use fleetreach_go::{
    direct_modules, main_module, parse_go_version, replace_directives, required_modules,
};

fn run_all_parsers(s: &str) {
    let _ = required_modules(s);
    let _ = direct_modules(s);
    let _ = main_module(s);
    let _ = replace_directives(s);
    for line in s.lines() {
        let _ = parse_go_version(line.trim());
    }
}

#[test]
fn parsers_never_panic_on_adversarial_input() {
    // Deterministic xorshift64* (no `rand` dep) so a failure reproduces.
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rng = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };

    // go.mod vocabulary plus fragments that hit the parser's branch points and known
    // sharp edges (unbalanced blocks, lone `=>`, pseudo/oversized versions, unicode,
    // terminal escapes, CRLF).
    const TOK: &[&str] = &[
        "module ",
        "require ",
        "replace ",
        "exclude ",
        "retract ",
        "toolchain ",
        "go ",
        "(",
        ")",
        "require (",
        "replace (",
        "=>",
        " => ",
        "//",
        "// indirect",
        "v1.2.3",
        "v0.0.0-20210101000000-abcdef",
        "+incompatible",
        "golang.org/x/text",
        " ",
        "\t",
        "\n",
        "\r\n",
        "",
        "0",
        "v",
        "=>=>",
        "v99999999999999999999999.0.0",
        "你好",
        "\u{1b}[31m",
        "\u{0}",
        "module",
        "=> ../local",
    ];

    for i in 0..100_000u64 {
        let mut s = String::new();
        for _ in 0..(rng() % 40) {
            match rng() % 5 {
                0 => s.push_str(TOK[(rng() as usize) % TOK.len()]),
                1 => s.push((0x20 + (rng() % 0x5e) as u8) as char), // printable ASCII
                2 => s.push('\n'),
                3 => s.push(char::from_u32((rng() % 0x1_0000) as u32).unwrap_or(' ')), // BMP
                _ => s.push_str("require "),
            }
        }
        let input = s;
        let res = catch_unwind(AssertUnwindSafe(|| run_all_parsers(&input)));
        assert!(
            res.is_ok(),
            "parser panicked at iteration {i} on input {input:?}"
        );
    }
}
