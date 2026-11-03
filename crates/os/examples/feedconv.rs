//! Convert a downloaded vendor feed into OSV records, one JSON file per record, to inspect
//! or diff what [`fleetreach_os::feeds::convert`] makes of it.
//!
//! `cargo run -p fleetreach-os --example feedconv -- "Oracle Linux:9" elsa-ol9.xml.bz2 out/`

use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [eco, file, out] = args.as_slice() else {
        eprintln!("usage: feedconv ECOSYSTEM FILE OUTDIR");
        std::process::exit(2);
    };
    let Some(feed) = fleetreach_os::feeds::feed_for(eco) else {
        eprintln!("no vendor feed for {eco}");
        std::process::exit(2);
    };
    let result = std::fs::read(file)
        .map_err(|e| e.to_string())
        .and_then(|raw| fleetreach_os::feeds::convert(&feed, &raw))
        .and_then(|records| {
            std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
            for r in &records {
                std::fs::write(Path::new(out).join(format!("{}.json", r.id)), &r.json)
                    .map_err(|e| e.to_string())?;
            }
            Ok(records.len())
        });
    match result {
        Ok(n) => println!("{n} records"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
