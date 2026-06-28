//! Differential / fuzz harness for the Maven `ComparableVersion` comparator.
//!
//! Usage: `cargo run -p fleetreach-maven --example vercmp -- cmp < pairs.txt`
//! reads `a<TAB>b` per line, prints `a<TAB>b<TAB>{-1,0,1}` for diffing against the real
//! `org.apache.maven.artifact.versioning.ComparableVersion`.

use std::io::{self, BufRead, Write};

use fleetreach_maven::parse_maven_version;

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        match mode.as_str() {
            "parse" => {
                let ok = parse_maven_version(&line).is_some();
                let _ = writeln!(out, "{line}\t{}", if ok { "ok" } else { "fail" });
            }
            "cmp" => {
                let mut it = line.splitn(2, '\t');
                let a = it.next().unwrap_or_default();
                let b = it.next().unwrap_or_default();
                let sign = match (parse_maven_version(a), parse_maven_version(b)) {
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
