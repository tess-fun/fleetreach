//! Print the method-level diff of two jars as JSON lines (the E2 experiment's differ).
//!
//! `cargo run -p fleetreach-sinks --example jardiff -- OLD.jar NEW.jar`

use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [old, new] = args.as_slice() else {
        eprintln!("usage: jardiff OLD.jar NEW.jar");
        std::process::exit(2);
    };
    match fleetreach_sinks::diff_jars(Path::new(old), Path::new(new)) {
        Ok(changes) => {
            for c in changes {
                match serde_json::to_string(&c) {
                    Ok(line) => println!("{line}"),
                    Err(e) => eprintln!("error: {e}"),
                }
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}
