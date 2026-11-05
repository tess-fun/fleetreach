//! Drives the range checks for `docs/differential/fix_constraints.py`, which compares them
//! with npm's own `semver`, `npm update` and `cargo update`.
//!
//! - `ranges`: reads `range<TAB>version` lines, prints `true`, `false` or `none` for each.
//! - `plan <dir>`: reads an edit as JSON, prints it with the strategy the ranges in `dir` give.
//! - `raise <dir>`: reads an edit as JSON and raises the repo's own manifests for it.

use std::io::{BufRead, Read};
use std::path::Path;

use fleetreach_cli::fix::Edit;
use fleetreach_cli::fix_constraints::{constrain, npm_satisfies, raise_cargo, raise_npm};
use fleetreach_core::semver::Version;
use fleetreach_core::Ecosystem;

fn ranges() {
    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        let Some((range, version)) = line.split_once('\t') else {
            continue;
        };
        let answer = Version::parse(version)
            .ok()
            .and_then(|version| npm_satisfies(range, &version));
        println!("{}", answer.map_or("none".to_string(), |a| a.to_string()));
    }
}

fn read_edit() -> Result<Edit, String> {
    let mut text = String::new();
    std::io::stdin()
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["ranges"] => ranges(),
        ["plan", dir] => {
            let mut edit = read_edit()?;
            constrain(&mut edit, Path::new(dir));
            println!(
                "{}",
                serde_json::to_string(&edit).map_err(|e| e.to_string())?
            );
        }
        ["raise", dir] => {
            let edit = read_edit()?;
            match edit.ecosystem {
                Ecosystem::Cargo => println!("{}", raise_cargo(Path::new(dir), &edit)?),
                _ => println!("{}", raise_npm(Path::new(dir), &edit)?.len()),
            }
        }
        _ => return Err("usage: fix_constraints ranges | plan <dir> | raise <dir>".to_string()),
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}
