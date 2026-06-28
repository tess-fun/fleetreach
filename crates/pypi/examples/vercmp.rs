//! Differential / fuzz harness for the PyPI (PEP 440) version comparator.
//!
//! Usage:
//!   `cargo run -p fleetreach-pypi --example vercmp -- parse < versions.txt`
//!     prints `version<TAB>ok|fail` per input line (no panic = robustness signal).
//!   `cargo run -p fleetreach-pypi --example vercmp -- cmp < pairs.txt`
//!     reads `a<TAB>b` per line, prints `a<TAB>b<TAB>{-1,0,1,NA}` for diffing against Python's
//!     `packaging.version.Version` (the reference PEP 440 implementation).
//!
//! Ordering is delegated to the `pep440_rs` crate (a vetted PEP 440 port); this harness exists
//! so the delegation can be differentially checked against `packaging` and so the parse path is
//! fuzzable. See `tests/ordering_golden.rs` for the committed, toolchain-free regression corpus.
//!
//! Not shipped; a throwaway validation tool kept out of the library build.

use std::io::{self, BufRead, Write};

use fleetreach_pypi::parse_pypi_version;

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        match mode.as_str() {
            "parse" => {
                let ok = parse_pypi_version(&line).is_some();
                let _ = writeln!(out, "{line}\t{}", if ok { "ok" } else { "fail" });
            }
            "cmp" => {
                let mut it = line.splitn(2, '\t');
                let a = it.next().unwrap_or_default();
                let b = it.next().unwrap_or_default();
                let sign = match (parse_pypi_version(a), parse_pypi_version(b)) {
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
