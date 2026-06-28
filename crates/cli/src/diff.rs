//! The `diff` command: compare two saved fleet reports (`scan -f json`) and show
//! what appeared, what cleared, and which surviving advisories changed blast
//! radius. A first-class take on the scan `--baseline` flag — that flag keeps only
//! *new* findings from a live scan; `diff` is pure (no scanning, no DB, no network),
//! works off two JSON files, and reports fixed + still-open too.
//!
//! Exit code: `0` clean (no gating-new findings), `1` a new finding tripped the
//! gate, `2` a file could not be read or parsed. `--exit-zero` forces `0` for a
//! report-only run.

use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use fleetreach_core::FleetReport;
use fleetreach_report as report;

use crate::cli::{fail, SeverityArg};

#[derive(Parser)]
pub struct DiffArgs {
    /// Prior report JSON — the baseline to compare against.
    baseline: PathBuf,
    /// Current report JSON, from `fleetreach scan -f json`.
    current: PathBuf,
    #[arg(short, long, value_enum, default_value_t = DiffFormat::Table)]
    format: DiffFormat,
    #[arg(
        long,
        value_enum,
        default_value_t = SeverityArg::Low,
        help = "fail if any NEW vuln is at/above this severity (Unknown always counts)"
    )]
    fail_on: SeverityArg,
    #[arg(long, help = "also fail if a NEW supply-chain warning appeared")]
    fail_on_warnings: bool,
    #[arg(long, help = "always exit 0 (report-only; never gate on new findings)")]
    exit_zero: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum DiffFormat {
    Table,
    Json,
}

/// Run `fleetreach diff`, returning the process exit code.
pub fn run_diff(args: DiffArgs) -> u8 {
    let baseline = match read_report(&args.baseline) {
        Ok(r) => r,
        Err(e) => return fail(&e),
    };
    let current = match read_report(&args.current) {
        Ok(r) => r,
        Err(e) => return fail(&e),
    };

    let diff = report::diff_reports(&baseline, &current);
    match args.format {
        DiffFormat::Json => match report::to_diff_json(&diff) {
            Ok(json) => println!("{json}"),
            Err(e) => return fail(&format!("serializing diff: {e}")),
        },
        DiffFormat::Table => {
            println!(
                "{}",
                report::to_diff_table(&diff, std::io::stdout().is_terminal())
            );
        }
    }

    if args.exit_zero {
        return 0;
    }
    u8::from(diff.regressions(args.fail_on.into(), args.fail_on_warnings) > 0)
}

/// Read and parse a saved fleet report, mapping IO/JSON failures to a message.
fn read_report(path: &PathBuf) -> Result<FleetReport, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("reading report `{}`: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("parsing report `{}`: {e}", path.display()))
}
