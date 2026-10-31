//! `fleetreach sbom`: write one CycloneDX 1.6 JSON SBOM per repo (spec 05, phase 1).
//!
//! Reads the same sources `scan` reads (lockfiles and manifests, every ecosystem), needs no
//! advisory DB and no network unless `--sync` refreshes fleet sources. Exit `0` when every
//! repo was read in full, `2` when any source could not be read (its BOM is still written,
//! marked incomplete) or the run itself failed: a partial inventory is never presented as a
//! complete one.

use std::path::PathBuf;

use clap::Args;
use fleetreach_report::{sanitize_cell, to_cyclonedx};

use crate::cli::fail;
use crate::config::Config;
use crate::inventory::repo_inventory;
use crate::sources;

#[derive(Args)]
pub struct SbomArgs {
    /// fleet.toml naming the repos
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,
    /// Directory to write `<repo-id>.cdx.json` files into (created if missing)
    #[arg(short, long)]
    out_dir: PathBuf,
    /// List `[[source]]` entries afresh and clone or refresh their checkouts first
    #[arg(long)]
    sync: bool,
    #[arg(short, long, help = "no progress output")]
    quiet: bool,
}

pub fn run_sbom(args: SbomArgs) -> u8 {
    let mut config = match Config::load(&args.config) {
        Ok(c) => c,
        Err(e) => return fail(&e.to_string()),
    };
    let materialized = match sources::materialize(&config, args.sync, args.quiet) {
        Ok(m) => m,
        Err(e) => return fail(&e),
    };
    config.repos.extend(materialized.repos.iter().cloned());
    if config.repos.is_empty() {
        return fail("no repos to describe");
    }
    if let Err(e) = std::fs::create_dir_all(&args.out_dir) {
        return fail(&format!("{}: {e}", args.out_dir.display()));
    }
    // Reproducible builds set SOURCE_DATE_EPOCH; otherwise stamp the current time.
    let timestamp = source_date_epoch().unwrap_or_else(now_rfc3339);

    let mut incomplete = 0usize;
    for (repo, reason) in &materialized.failed {
        eprintln!("error: {repo}: {reason}");
        incomplete += 1;
    }
    for repo in &config.repos {
        let mut inv = repo_inventory(repo);
        if let Some(p) = materialized.provenance.iter().find(|p| p.repo == repo.id) {
            inv.url = Some(p.url.clone());
            inv.commit = Some(p.commit.clone());
        }
        let bom = match to_cyclonedx(&inv, env!("CARGO_PKG_VERSION"), Some(&timestamp)) {
            Ok(bom) => bom,
            Err(e) => return fail(&format!("{}: {e}", repo.id)),
        };
        let file = args
            .out_dir
            .join(format!("{}.cdx.json", file_stem(&repo.id.0)));
        if let Err(e) = std::fs::write(&file, bom) {
            return fail(&format!("{}: {e}", file.display()));
        }
        let packages: usize = inv.sources.iter().map(|s| s.packages.len()).sum();
        let gaps = inv
            .sources
            .iter()
            .filter(|s| s.coverage != fleetreach_core::Coverage::Full)
            .count();
        for error in &inv.errors {
            eprintln!(
                "error: {}: {}",
                sanitize_cell(&repo.id.0),
                sanitize_cell(error)
            );
        }
        if !inv.errors.is_empty() {
            incomplete += 1;
        }
        if !args.quiet {
            let note = if gaps > 0 {
                format!(", {gaps} source(s) with incomplete coverage")
            } else {
                String::new()
            };
            eprintln!(
                "{}: {packages} package(s) from {} source(s){note} -> {}",
                sanitize_cell(&repo.id.0),
                inv.sources.len(),
                file.display()
            );
        }
    }
    if incomplete > 0 {
        eprintln!("error: {incomplete} repo(s) could not be read in full; their SBOMs are marked incomplete");
        return 2;
    }
    0
}

/// A repo id as a file name: `owner/name` becomes `owner__name`, and anything outside
/// `[A-Za-z0-9._-]` becomes `_`, so an id can never escape the output directory.
fn file_stem(id: &str) -> String {
    let stem: String = id
        .replace('/', "__")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    match stem.trim_start_matches('.') {
        "" => "repo".to_string(),
        s => s.to_string(),
    }
}

fn source_date_epoch() -> Option<String> {
    let secs: i64 = std::env::var("SOURCE_DATE_EPOCH")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()?
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_ids_become_safe_file_names() {
        assert_eq!(file_stem("acme/app"), "acme__app");
        assert_eq!(file_stem("../../etc/passwd"), "__..__etc__passwd");
        assert_eq!(file_stem("a b:c"), "a_b_c");
        assert_eq!(file_stem("..."), "repo");
    }
}
