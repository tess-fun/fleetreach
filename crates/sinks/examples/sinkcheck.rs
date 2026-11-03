//! Check a directory of sink records and summarize it; exit 1 if any record is invalid.
//!
//! `cargo run -p fleetreach-sinks --example sinkcheck -- DIR`

use std::path::Path;

use fleetreach_sinks::record::{load_dir, Status, Verdict};

fn main() {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: sinkcheck DIR");
        std::process::exit(2);
    };
    match load_dir(Path::new(&dir)) {
        Ok(set) => {
            let count = |s: Status, v: Verdict| {
                set.records
                    .values()
                    .filter(|r| r.status == s && r.verdict == v)
                    .count()
            };
            println!("{} record(s) in {dir}", set.records.len());
            for (name, status) in [
                ("reviewed", Status::Reviewed),
                ("proposed", Status::Proposed),
            ] {
                println!(
                    "  {name}: {} sinks, {} deny-list, {} no-method-sink",
                    count(status, Verdict::Sinks),
                    count(status, Verdict::DenyList),
                    count(status, Verdict::NoMethodSink),
                );
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
