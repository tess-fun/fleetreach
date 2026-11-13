//! Propose a NuGet sink record from two releases' assemblies (spec 16, row 13).
//!
//! ```text
//! nugetpropose --id GHSA-... [--alias CVE-...] --package Id [--package Id] \
//!   --old DIR --new DIR [--commit URL]... [--files FILE] --releases "Id 1.0.0 -> 1.0.1"
//! ```
//!
//! `--old` and `--new` hold the `.dll` files of the last vulnerable and the first fixed
//! release (one target framework of each). `--files` lists the paths the fix commits changed,
//! one per line. The assemblies are read as data; nothing is loaded or run. The record is
//! printed as JSON.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fleetreach_clr::propose::{diff, propose, Advisory};
use fleetreach_clr::Assembly;

fn assemblies(dir: &Path) -> Result<Vec<Assembly>, String> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("dll")))
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|p| {
            let bytes = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
            fleetreach_clr::read(&bytes).map_err(|e| format!("{}: {e}", p.display()))
        })
        .collect()
}

fn run() -> Result<String, String> {
    let mut advisory = Advisory::default();
    let (mut old, mut new) = (None, None);
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--id" => advisory.id = value()?,
            "--alias" => advisory.aliases.push(value()?),
            "--package" => advisory.packages.push(value()?),
            "--commit" => advisory.commits.push(value()?),
            "--releases" => advisory.releases = value()?,
            "--old" => old = Some(PathBuf::from(value()?)),
            "--new" => new = Some(PathBuf::from(value()?)),
            "--files" => {
                let path = value()?;
                let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
                advisory.changed_files = text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(String::from)
                    .collect();
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    let old = assemblies(&old.ok_or("--old is required")?)?;
    let new = assemblies(&new.ok_or("--new is required")?)?;
    let record = propose(&advisory, &diff(&old, &new));
    record.validate()?;
    serde_json::to_string_pretty(&record).map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    match run() {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
