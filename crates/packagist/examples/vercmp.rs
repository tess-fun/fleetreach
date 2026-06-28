//! Differential / fuzz harness for the Composer version comparator.
//!
//! Usage:
//!   `cargo run -p fleetreach-packagist --example vercmp -- parse < versions.txt`
//!     prints `version<TAB>ok|fail` for each input line (no panic = robustness signal).
//!   `cargo run -p fleetreach-packagist --example vercmp -- cmp < pairs.txt`
//!     reads `a<TAB>b` per line, prints `a<TAB>b<TAB>{-1,0,1,NA}` using the real
//!     `Ord` (NA when either side does not parse), for diffing against PHP `version_compare`.
//!
//! Not shipped; a throwaway validation tool kept out of the library build.

use std::io::{self, BufRead, Write};

use fleetreach_packagist::parse_composer_version;

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        match mode.as_str() {
            "parse" => {
                let ok = parse_composer_version(&line).is_some();
                let _ = writeln!(out, "{line}\t{}", if ok { "ok" } else { "fail" });
            }
            "cmp" => {
                let mut it = line.splitn(2, '\t');
                let a = it.next().unwrap_or_default();
                let b = it.next().unwrap_or_default();
                let sign = match (parse_composer_version(a), parse_composer_version(b)) {
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
