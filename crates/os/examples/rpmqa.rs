//! Print an rpm database's packages like `rpm -qa --qf
//! '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{MODULARITYLABEL}\n'`,
//! for comparing with the real tool.
//!
//! `cargo run -p fleetreach-os --example rpmqa -- /var/lib/rpm`

use std::path::Path;

fn main() {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: rpmqa DIR");
        std::process::exit(2);
    };
    match fleetreach_os::rpmdb::read_dir(Path::new(&dir)) {
        Ok(pkgs) => {
            for p in pkgs {
                let none = || "(none)".to_string();
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    p.name,
                    p.epoch.unwrap_or(0),
                    p.version,
                    p.release,
                    p.arch.unwrap_or_else(none),
                    p.source_rpm.unwrap_or_else(none),
                    p.modularity_label.unwrap_or_else(none),
                );
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
