//! Differential / fuzz harness for the `Gem::Version` comparator.
//!
//! Usage:
//!   `cargo run -p fleetreach-rubygems --example vercmp -- parse < versions.txt`
//!     prints `version<TAB>ok|fail` per input line (no panic = robustness signal).
//!   `cargo run -p fleetreach-rubygems --example vercmp -- cmp < pairs.txt`
//!     reads `a<TAB>b` per line, prints `a<TAB>b<TAB>{-1,0,1,NA}` for diffing against real
//!     Ruby's `Gem::Version#<=>`.
//!
//! IMPORTANT — pick the oracle Ruby carefully. `Gem::Version#<=>` changed in RubyGems 3.3.0
//! (Dec 2021) to compare `canonical_segments` instead of the raw `segments`; the two disagree
//! on prereleases whose numeric release cores differ in length (e.g. `1.0.0.beta1` vs
//! `1.0.beta2`). This comparator targets the **modern** (canonical-segments) semantics, so the
//! oracle must be RubyGems >= 3.3 (Ruby >= 3.1). A stale system Ruby (e.g. macOS 2.6) uses the
//! old raw-segments rule and will report spurious mismatches. See `tests/ordering_golden.rs`.
//!
//! Not shipped; a throwaway validation tool kept out of the library build.

use std::io::{self, BufRead, Write};

use fleetreach_rubygems::parse_rubygems_version;

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        match mode.as_str() {
            "parse" => {
                let ok = parse_rubygems_version(&line).is_some();
                let _ = writeln!(out, "{line}\t{}", if ok { "ok" } else { "fail" });
            }
            "cmp" => {
                let mut it = line.splitn(2, '\t');
                let a = it.next().unwrap_or_default();
                let b = it.next().unwrap_or_default();
                let sign = match (parse_rubygems_version(a), parse_rubygems_version(b)) {
                    (Some(va), Some(vb)) => match va.cmp(&vb) {
                        std::cmp::Ordering::Less => "-1",
                        std::cmp::Ordering::Equal => "0",
                        std::cmp::Ordering::Greater => "1",
                    },
                    _ => "NA",
                };
                let _ = writeln!(out, "{a}\t{b}\t{sign}");
            }
            _ => {
                eprintln!("usage: vercmp [parse|cmp]");
                std::process::exit(2);
            }
        }
    }
}
