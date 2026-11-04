//! The `diff` command: compare two saved fleet reports (`scan -f json`) and show
//! what appeared, what cleared, and which surviving advisories changed blast
//! radius. A first-class take on the scan `--baseline` flag — that flag keeps only
//! *new* findings from a live scan; `diff` is pure (no scanning, no DB, no network),
//! works off two JSON files, and reports fixed + still-open too.
//!
//! With `--base <ref>` the new findings go per occurrence and git says which this change
//! brought in; see [`crate::attribute`]. One the merge base already had no longer gates.
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

use crate::attribute;
use crate::cli::{fail, usage_fail, SeverityArg};

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
    /// Attribute each new finding to the lockfile and manifest lines changed since the merge
    /// base with this git ref, and gate only on what the change brought in
    #[arg(long, value_name = "REF")]
    base: Option<String>,
    /// The git checkout `--base` reads
    #[arg(long, value_name = "DIR", default_value = ".", requires = "base")]
    checkout: PathBuf,
    /// The repo id of that checkout, when the reports cover several repos
    #[arg(long, value_name = "ID", requires = "base")]
    repo: Option<String>,
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
    let attributed = match &args.base {
        Some(base) => {
            let mut findings = attribute::new_occurrences(&baseline, &current);
            let repo = match args.repo.clone() {
                Some(repo) => Some(repo),
                None => match attribute::single_repo(&findings) {
                    Ok(repo) => repo,
                    Err(e) => return usage_fail(&e),
                },
            };
            let placed = attribute::Checkout::open(&args.checkout, base)
                .and_then(|checkout| attribute::place(&checkout, repo.as_deref(), &mut findings));
            if let Err(e) = placed {
                return fail(&e);
            }
            findings.sort_by(|a, b| {
                (a.origin, &a.advisory_id, &a.package).cmp(&(b.origin, &b.advisory_id, &b.package))
            });
            Some(findings)
        }
        None => None,
    };
    match args.format {
        DiffFormat::Json => match to_json(&diff, attributed.as_deref()) {
            Ok(json) => println!("{json}"),
            Err(e) => return fail(&format!("serializing diff: {e}")),
        },
        DiffFormat::Table => {
            println!(
                "{}",
                report::to_diff_table(&diff, std::io::stdout().is_terminal())
            );
            if let Some(findings) = &attributed {
                print!("{}", attribution_text(findings));
            }
        }
    }

    if args.exit_zero {
        return 0;
    }
    let (floor, warnings) = (args.fail_on.into(), args.fail_on_warnings);
    let failed = match &attributed {
        Some(findings) => findings.iter().any(|f| f.gates(floor, warnings)),
        None => diff.regressions(floor, warnings) > 0,
    };
    u8::from(failed)
}

fn to_json(
    diff: &report::FleetDiff,
    attributed: Option<&[attribute::Attributed]>,
) -> Result<String, serde_json::Error> {
    let Some(findings) = attributed else {
        return report::to_diff_json(diff);
    };
    let mut value = serde_json::to_value(diff)?;
    if let Some(object) = value.as_object_mut() {
        object.insert("attribution".to_string(), serde_json::to_value(findings)?);
    }
    serde_json::to_string_pretty(&value)
}

/// One section per origin, each finding on a line.
fn attribution_text(findings: &[attribute::Attributed]) -> String {
    use attribute::Origin;
    use report::sanitize_cell;
    let mut out = String::new();
    for (origin, heading) in [
        (Origin::Introduced, "Brought in by this change"),
        (Origin::Unknown, "Not placed in this checkout, still gating"),
        (
            Origin::Existing,
            "Already here before this change, not gating",
        ),
    ] {
        let rows: Vec<_> = findings.iter().filter(|f| f.origin == origin).collect();
        if rows.is_empty() {
            continue;
        }
        out.push_str(&format!("\n{heading} ({}):\n", rows.len()));
        for f in rows {
            let severity = f
                .severity
                .map_or("warning".to_string(), |s| format!("{s:?}").to_lowercase());
            out.push_str(&format!(
                "  {severity:<8} {} {}@{}",
                sanitize_cell(&f.advisory_id),
                sanitize_cell(&f.package),
                sanitize_cell(&f.version),
            ));
            if let Some(at) = &f.at {
                out.push_str(&format!(" at {}", sanitize_cell(&at.to_string())));
            }
            if let Some(cause) = &f.cause {
                out.push_str(&format!(" from {}", sanitize_cell(&cause.to_string())));
            }
            out.push('\n');
        }
    }
    out
}

/// Read and parse a saved fleet report, mapping IO/JSON failures to a message.
pub(crate) fn read_report(path: &PathBuf) -> Result<FleetReport, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("reading report `{}`: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("parsing report `{}`: {e}", path.display()))
}
