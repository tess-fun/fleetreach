//! `fleetreach history`: trends, age, SLA breaches and time to fix, read from the snapshots
//! `scan --history-dir` writes (spec 09).
//!
//! Exit `0` normally; `history sla` exits `1` on any breach so it can gate a scheduled job,
//! and `2` when it cannot judge (no `[settings.sla]`, no readable history).

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use comfy_table::presets::UTF8_FULL;
use comfy_table::Table;
use fleetreach_report::sanitize_cell;
use serde::Serialize;

use crate::cli::fail;
use crate::config::Config;
use crate::history::{self, Entry, GroupBy, History};

#[derive(Subcommand)]
pub enum HistoryCommand {
    /// Open findings per run, grouped.
    Trend(TrendArgs),
    /// Open findings by how long they have been open, oldest first.
    Age(AgeArgs),
    /// Open findings past their `[settings.sla]` deadline; exits 1 on any.
    Sla(SlaArgs),
    /// Mean and median time to fix.
    Mttr(MttrArgs),
}

#[derive(Clone, Copy, ValueEnum)]
pub enum HistoryFormat {
    Table,
    Json,
}

#[derive(Args)]
pub struct Common {
    /// The directory `scan --history-dir` writes
    #[arg(long)]
    history_dir: PathBuf,
    #[arg(short, long, value_enum, default_value = "table")]
    format: HistoryFormat,
    /// Measure as of this time (RFC 3339) instead of now
    #[arg(long)]
    at: Option<String>,
}

#[derive(Args)]
pub struct TrendArgs {
    #[command(flatten)]
    common: Common,
    #[arg(long, value_enum, default_value = "severity")]
    by: GroupBy,
    /// Only runs this recent (`90d`)
    #[arg(long)]
    since: Option<String>,
}

#[derive(Args)]
pub struct AgeArgs {
    #[command(flatten)]
    common: Common,
    /// Only findings open at least this long (`30d`)
    #[arg(long)]
    min_age: Option<String>,
}

#[derive(Args)]
pub struct SlaArgs {
    #[command(flatten)]
    common: Common,
    /// fleet.toml holding `[settings.sla]`
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,
}

#[derive(Args)]
pub struct MttrArgs {
    #[command(flatten)]
    common: Common,
    #[arg(long, value_enum, default_value = "severity")]
    by: GroupBy,
}

pub fn run_history(command: HistoryCommand) -> u8 {
    match command {
        HistoryCommand::Trend(a) => run_trend(&a),
        HistoryCommand::Age(a) => run_age(&a),
        HistoryCommand::Sla(a) => run_sla(&a),
        HistoryCommand::Mttr(a) => run_mttr(&a),
    }
}

/// Load the history and the reference time, reporting unreadable snapshots and a rebuilt
/// index on stderr.
fn open(common: &Common) -> Result<(History, time::OffsetDateTime), String> {
    let at = match &common.at {
        Some(s) => {
            history::parse_time(s).ok_or_else(|| format!("--at `{s}` is not an RFC 3339 time"))?
        }
        None => history::now(),
    };
    let h = history::load(&common.history_dir)?;
    for u in &h.unreadable {
        eprintln!("warning: unreadable snapshot skipped: {u}");
    }
    if let Some(why) = &h.rebuilt {
        eprintln!("note: history index rebuilt in memory: {why}");
    }
    if h.snapshots.is_empty() && h.index.entries.is_empty() {
        return Err(format!(
            "no scan history in {}; record some with `fleetreach scan --history-dir`",
            common.history_dir.display()
        ));
    }
    Ok((h, at))
}

fn since_cutoff(
    spec: Option<&str>,
    at: time::OffsetDateTime,
) -> Result<Option<time::OffsetDateTime>, String> {
    spec.map(|s| crate::db::parse_duration_secs(s).map(|secs| at - time::Duration::seconds(secs)))
        .transpose()
}

fn print_json<T: Serialize>(value: &T) -> u8 {
    match serde_json::to_string_pretty(value) {
        Ok(json) => {
            println!("{json}");
            0
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn table(header: &[&str]) -> Table {
    let mut t = Table::new();
    t.load_style(UTF8_FULL);
    t.set_header(header.to_vec());
    t
}

/// `pkg@version` in `repo`.
fn finding_cells(e: &Entry) -> Vec<String> {
    vec![
        sanitize_cell(&e.key.repo),
        sanitize_cell(&e.key.advisory),
        sanitize_cell(&format!("{}@{}", e.key.package, e.key.version)),
        match e.ssvc {
            Some(o) => format!("{} / {}", label(&e.severity), o.label()),
            None => label(&e.severity),
        },
        sanitize_cell(e.owner.as_deref().unwrap_or("-")),
        e.first_seen.clone(),
    ]
}

fn label<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn run_trend(args: &TrendArgs) -> u8 {
    let (h, at) = match open(&args.common) {
        Ok(x) => x,
        Err(e) => return fail(&e),
    };
    let since = match since_cutoff(args.since.as_deref(), at) {
        Ok(s) => s,
        Err(e) => return fail(&format!("--since: {e}")),
    };
    let points = history::trend(&h, args.by, since);
    if let HistoryFormat::Json = args.common.format {
        return print_json(&points);
    }
    let groups: std::collections::BTreeSet<&String> =
        points.iter().flat_map(|p| p.groups.keys()).collect();
    let mut header = vec!["Run", "Open"];
    header.extend(groups.iter().map(|g| g.as_str()));
    let mut t = table(&header);
    for p in &points {
        let mut row = vec![
            if p.gap {
                format!("{} (gap)", p.at)
            } else {
                p.at.clone()
            },
            p.open.to_string(),
        ];
        row.extend(
            groups
                .iter()
                .map(|g| p.groups.get(*g).copied().unwrap_or(0).to_string()),
        );
        t.add_row(row);
    }
    println!("{t}");
    if points.iter().any(|p| p.gap) {
        eprintln!("note: (gap) runs exited 2; part of the fleet was not read, so their counts are a floor");
    }
    0
}

fn run_age(args: &AgeArgs) -> u8 {
    let (h, at) = match open(&args.common) {
        Ok(x) => x,
        Err(e) => return fail(&e),
    };
    let min = match args
        .min_age
        .as_deref()
        .map(crate::db::parse_duration_secs)
        .transpose()
    {
        Ok(m) => m.unwrap_or(0),
        Err(e) => return fail(&format!("--min-age: {e}")),
    };
    let aged = history::age(&h, at, min);
    if let HistoryFormat::Json = args.common.format {
        return print_json(&aged);
    }
    let mut t = table(&[
        "Repo",
        "Advisory",
        "Package",
        "Severity",
        "Owner",
        "First seen",
        "Age (days)",
    ]);
    for a in &aged {
        let mut row = finding_cells(a.entry);
        row.push(format!("{:.1}", a.age_days));
        t.add_row(row);
    }
    println!("{t}");
    0
}

fn run_sla(args: &SlaArgs) -> u8 {
    let config = match Config::load(&args.config) {
        Ok(c) => c,
        Err(e) => return fail(&e.to_string()),
    };
    if config.sla.is_empty() {
        return fail(&format!(
            "no [settings.sla] in {}; nothing to judge breaches against",
            args.config.display()
        ));
    }
    let (h, at) = match open(&args.common) {
        Ok(x) => x,
        Err(e) => return fail(&e),
    };
    let breaches = history::sla(&h, &config.sla, at);
    let code = u8::from(!breaches.is_empty());
    if let HistoryFormat::Json = args.common.format {
        return match print_json(&breaches) {
            0 => code,
            failed => failed,
        };
    }
    if breaches.is_empty() {
        eprintln!("no SLA breaches");
        return 0;
    }
    let mut t = table(&[
        "Repo",
        "Advisory",
        "Package",
        "Severity",
        "Owner",
        "First seen",
        "Due",
        "Overdue (days)",
    ]);
    for b in &breaches {
        let mut row = finding_cells(b.entry);
        row.push(b.due.clone());
        row.push(format!("{:.1}", b.overdue_days));
        t.add_row(row);
    }
    println!("{t}");
    eprintln!("{} finding(s) past their SLA", breaches.len());
    code
}

fn run_mttr(args: &MttrArgs) -> u8 {
    let (h, _) = match open(&args.common) {
        Ok(x) => x,
        Err(e) => return fail(&e),
    };
    let rows = history::mttr(&h, args.by);
    if let HistoryFormat::Json = args.common.format {
        return print_json(&rows);
    }
    let mut t = table(&[
        "Group",
        "Fixed",
        "Mean (days)",
        "Median (days)",
        "Still open",
    ]);
    for r in &rows {
        t.add_row(vec![
            sanitize_cell(&r.group),
            r.fixed.to_string(),
            format!("{:.1}", r.mean_days),
            format!("{:.1}", r.median_days),
            r.open.to_string(),
        ]);
    }
    println!("{t}");
    0
}
