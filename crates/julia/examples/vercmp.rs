//! Differential / fuzz harness for the Julia `VersionNumber` comparator.
//!
//! Usage:
//!   `cargo run -p fleetreach-julia --example vercmp -- parse < versions.txt`
//!   `cargo run -p fleetreach-julia --example vercmp -- cmp < pairs.txt`  (diff vs Julia)
//!
//! Not shipped; a throwaway validation tool kept out of the library build.

use std::io::{self, BufRead, Write};

use fleetreach_julia::parse_julia_version;

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        match mode.as_str() {
            "parse" => {
                let ok = parse_julia_version(&line).is_some();
                let _ = writeln!(out, "{line}\t{}", if ok { "ok" } else { "fail" });
            }
            "cmp" => {
                let mut it = line.splitn(2, '\t');
                let a = it.next().unwrap_or_default();
                let b = it.next().unwrap_or_default();
                let sign = match (parse_julia_version(a), parse_julia_version(b)) {
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
