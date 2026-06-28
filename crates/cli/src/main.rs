//! `fleetreach` binary: parse arguments, dispatch to the command runner, and map
//! the result to the process exit code (§8).
//!
//! Exit codes: `3` usage error · `2` could-not-scan (config/DB/stale/gap) ·
//! `1` trustworthy scan that trips the gate · `0` trustworthy and clean.
//!
//! All command logic lives in the `fleetreach_cli` library (parsing in `cli`,
//! the `scan` runner in `scan`, the `vex` subcommands in `vex`); this shell only
//! handles `--help`/`--version` (exit 0) vs. a malformed invocation (exit 3).

use std::process::ExitCode;

use clap::Parser;
use fleetreach_cli::cli::{dispatch, Cli};

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            // --help / --version are not errors.
            return match e.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                    ExitCode::from(0)
                }
                _ => ExitCode::from(3),
            };
        }
    };
    ExitCode::from(dispatch(cli))
}
