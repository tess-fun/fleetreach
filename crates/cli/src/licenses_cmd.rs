//! `fleetreach licenses`: the fleet's license inventory and, with a `[settings.licenses]`
//! policy, its violations (spec 11). Reads the same sources `scan` and `sbom` read plus
//! local package metadata; needs no advisory DB and no network.
//!
//! Exit `0` when nothing is denied, `1` when a license is denied by the policy, `2` when a
//! source could not be read or the run failed (a partial inventory is never called clean).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use clap::{Args, ValueEnum};
use comfy_table::presets::UTF8_FULL;
use comfy_table::Table;
use fleetreach_report::sanitize_cell;
use serde::Serialize;

use crate::cli::fail;
use crate::config::Config;
use crate::inventory::repo_inventory;
use crate::licenses::{annotate, decide, Category, Decision, Verdict};
use crate::sources;

#[derive(Clone, Copy, ValueEnum)]
pub enum LicenseFormat {
    Table,
    Json,
}

#[derive(Args)]
pub struct LicensesArgs {
    /// fleet.toml naming the repos (and the `[settings.licenses]` policy)
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,
    #[arg(short, long, value_enum, default_value = "table")]
    format: LicenseFormat,
    /// List `[[source]]` entries afresh and clone or refresh their checkouts first
    #[arg(long)]
    sync: bool,
    /// Look up licenses no local source knows on deps.dev. Sends each such package's
    /// ecosystem, name and version to deps.dev (Google); answers are cached locally
    #[arg(long)]
    fetch: bool,
}

#[derive(Serialize)]
struct Rollup {
    license: String,
    category: Category,
    packages: usize,
    repos: usize,
}

#[derive(Serialize)]
struct Output<'a> {
    policy: bool,
    licenses: Vec<Rollup>,
    violations: Vec<&'a Decision>,
    warnings: Vec<&'a Decision>,
    packages: &'a [Decision],
    unread: Vec<String>,
}

/// A license's category, its `(ecosystem, package, version)` set and its repos.
type RollupRow = (
    Category,
    BTreeSet<(String, String, String)>,
    BTreeSet<String>,
);

pub fn run_licenses(args: &LicensesArgs) -> u8 {
    let mut config = match Config::load(&args.config) {
        Ok(c) => c,
        Err(e) => return fail(&e.to_string()),
    };
    let materialized = match sources::materialize(&config, args.sync, true) {
        Ok(m) => m,
        Err(e) => return fail(&e),
    };
    config.repos.extend(materialized.repos.iter().cloned());
    if config.repos.is_empty() {
        return fail("no repos to describe");
    }
    let mut unread: Vec<String> = materialized
        .failed
        .iter()
        .map(|(repo, why)| format!("{repo}: {why}"))
        .collect();
    let mut inventories: Vec<_> = config
        .repos
        .iter()
        .map(|repo| {
            let mut inv = repo_inventory(repo);
            annotate(&mut inv, &repo.path);
            unread.extend(inv.errors.iter().map(|e| format!("{}: {e}", repo.id)));
            inv
        })
        .collect();
    if args.fetch {
        match crate::licenses::fetch_missing(&mut inventories) {
            Ok((found, wanted, failed)) => {
                eprintln!("deps.dev: {found} of {wanted} unknown license(s) found");
                if failed > 0 {
                    eprintln!(
                        "warning: {failed} deps.dev lookup(s) failed; those packages stay unknown"
                    );
                }
            }
            Err(e) => return fail(&e),
        }
    }
    let decisions = decide(&inventories, config.licenses.as_ref());

    // Rollup: one row per license (unknown grouped), packages and repos counted once.
    let mut rows: BTreeMap<String, RollupRow> = BTreeMap::new();
    for d in &decisions {
        let key = d.license.clone().unwrap_or_else(|| "(unknown)".to_string());
        let row = rows
            .entry(key)
            .or_insert_with(|| (d.category, BTreeSet::new(), BTreeSet::new()));
        row.1
            .insert((d.ecosystem.clone(), d.package.clone(), d.version.clone()));
        row.2.insert(d.repo.clone());
    }
    let mut licenses: Vec<Rollup> = rows
        .into_iter()
        .map(|(license, (category, packages, repos))| Rollup {
            license,
            category,
            packages: packages.len(),
            repos: repos.len(),
        })
        .collect();
    licenses.sort_by(|a, b| {
        (a.category, std::cmp::Reverse(a.packages))
            .cmp(&(b.category, std::cmp::Reverse(b.packages)))
    });
    let violations: Vec<&Decision> = decisions
        .iter()
        .filter(|d| d.verdict == Verdict::Deny)
        .collect();
    let warnings: Vec<&Decision> = decisions
        .iter()
        .filter(|d| d.verdict == Verdict::Warn)
        .collect();

    match args.format {
        LicenseFormat::Json => {
            let out = Output {
                policy: config.licenses.is_some(),
                licenses,
                violations: violations.clone(),
                warnings: warnings.clone(),
                packages: &decisions,
                unread: unread.clone(),
            };
            match serde_json::to_string_pretty(&out) {
                Ok(json) => println!("{json}"),
                Err(e) => return fail(&e.to_string()),
            }
        }
        LicenseFormat::Table => {
            let mut table = Table::new();
            table.load_style(UTF8_FULL);
            table.set_header(vec!["License", "Category", "Packages", "Repos"]);
            for r in &licenses {
                table.add_row(vec![
                    sanitize_cell(&r.license),
                    r.category.label().to_string(),
                    r.packages.to_string(),
                    r.repos.to_string(),
                ]);
            }
            println!("{table}");
            for (label, list) in [("violation", &violations), ("warning", &warnings)] {
                for d in list.iter() {
                    println!(
                        "{label}: {} {} {}@{}: {}",
                        sanitize_cell(&d.repo),
                        d.ecosystem,
                        sanitize_cell(&d.package),
                        sanitize_cell(&d.version),
                        sanitize_cell(&d.reason)
                    );
                }
            }
        }
    }
    let known = decisions.iter().filter(|d| d.license.is_some()).count();
    eprintln!(
        "{} package(s) in {} repo(s): {known} with a known license; {} violation(s), {} warning(s){}",
        decisions.len(),
        inventories.len(),
        violations.len(),
        warnings.len(),
        if config.licenses.is_some() {
            ""
        } else {
            " (no [settings.licenses] policy: inventory only)"
        }
    );
    for u in &unread {
        eprintln!("error: {}", sanitize_cell(u));
    }
    if !unread.is_empty() {
        return 2;
    }
    u8::from(!violations.is_empty())
}
