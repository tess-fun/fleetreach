//! `fleetreach sbom`: write one CycloneDX 1.7 (or SPDX 2.3) JSON SBOM per repo (spec 05).
//!
//! Reads the same sources `scan` reads (lockfiles and manifests, every ecosystem), needs no
//! advisory DB and no network unless `--sync` refreshes fleet sources. Exit `0` when every
//! repo was read in full, `2` when any source could not be read (its BOM is still written,
//! marked incomplete) or the run itself failed: a partial inventory is never presented as a
//! complete one. `--report` embeds a saved scan's findings: CycloneDX `vulnerabilities[]`,
//! or SPDX security references.

use std::path::PathBuf;

use clap::{Args, ValueEnum};
use fleetreach_report::{
    sanitize_cell, to_cyclonedx, to_cyclonedx_with_vulns, to_cyclonedx_xml, to_spdx,
    CycloneDxVersion,
};

use fleetreach_core::inventory::RepoInventory;
use rayon::prelude::*;

use crate::cli::fail;
use crate::config::{Config, Repo};
use crate::inventory::repo_inventory_with;
use crate::sources;

#[derive(Args)]
pub struct SbomArgs {
    /// fleet.toml naming the repos
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,
    /// Directory to write `<repo-id>.cdx.json` (or `.cdx.xml`, `.spdx.json`) files into
    /// (created if missing)
    #[arg(short, long)]
    out_dir: PathBuf,
    /// SBOM format
    #[arg(short, long, value_enum, default_value_t = BomFormat::Cyclonedx)]
    format: BomFormat,
    /// CycloneDX spec version to declare
    #[arg(long, value_enum, default_value_t = SpecVersion::V1_7)]
    cyclonedx_version: SpecVersion,
    /// Embed this saved scan's findings (`fleetreach scan -f json > report.json`)
    #[arg(long)]
    report: Option<PathBuf>,
    /// List `[[source]]` entries afresh and clone or refresh their checkouts first
    #[arg(long)]
    sync: bool,
    #[arg(short, long, help = "no progress output")]
    quiet: bool,
    /// Look up licenses no local source knows on deps.dev. Sends each such package's
    /// ecosystem, name and version to deps.dev (Google); answers are cached locally
    #[arg(long)]
    fetch_licenses: bool,
    #[command(flatten)]
    maven: crate::maven_repo::FetchArgs,
}

#[derive(Clone, Copy, ValueEnum)]
enum BomFormat {
    /// CycloneDX JSON, 1.7 unless `--cyclonedx-version` says otherwise
    Cyclonedx,
    /// CycloneDX XML, the same content as the JSON
    CyclonedxXml,
    /// SPDX 2.3 JSON
    Spdx,
}

#[derive(Clone, Copy, ValueEnum)]
enum SpecVersion {
    #[value(name = "1.6")]
    V1_6,
    #[value(name = "1.7")]
    V1_7,
}

pub fn run_sbom(args: SbomArgs) -> u8 {
    let report = match args
        .report
        .as_ref()
        .map(crate::diff::read_report)
        .transpose()
    {
        Ok(r) => r,
        Err(e) => return fail(&e),
    };
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
    let maven = match args.maven.remote(!args.quiet) {
        Ok(remote) => remote,
        Err(e) => return fail(&e),
    };
    // Inventories and BOMs are built in parallel; messages print afterwards in fleet order,
    // so the output is the same as a serial run. Licenses from the machine-wide caches are
    // read once per package for the whole fleet.
    let cache = crate::licenses::LicenseCache::new();
    let inventory = |repo: &Repo| {
        let mut inv = repo_inventory_with(repo, maven.as_ref());
        crate::licenses::annotate(&mut inv, &repo.path, &cache);
        crate::lockhash::annotate(&mut inv, &repo.path);
        if let Some(p) = materialized.provenance.iter().find(|p| p.repo == repo.id) {
            inv.url = Some(p.url.clone());
            inv.commit = Some(p.commit.clone());
        }
        inv
    };
    let write = |repo: &Repo, inv: RepoInventory| -> Result<Written, String> {
        let version = env!("CARGO_PKG_VERSION");
        let spec = match args.cyclonedx_version {
            SpecVersion::V1_6 => CycloneDxVersion::V1_6,
            SpecVersion::V1_7 => CycloneDxVersion::V1_7,
        };
        let (bom, extension) = match (args.format, &report) {
            (BomFormat::Spdx, r) => (to_spdx(&inv, r.as_ref(), version, &timestamp), "spdx.json"),
            (format, r) => {
                let bom = match r {
                    Some(r) => to_cyclonedx_with_vulns(&inv, r, version, Some(&timestamp), spec),
                    None => to_cyclonedx(&inv, version, Some(&timestamp), spec),
                };
                match format {
                    BomFormat::CyclonedxXml => {
                        (bom.and_then(|json| to_cyclonedx_xml(&json)), "cdx.xml")
                    }
                    _ => (bom, "cdx.json"),
                }
            }
        };
        let bom = bom.map_err(|e| format!("{}: {e}", repo.id))?;
        let file = args
            .out_dir
            .join(format!("{}.{extension}", file_stem(&repo.id.0)));
        std::fs::write(&file, bom).map_err(|e| format!("{}: {e}", file.display()))?;
        Ok(Written {
            file,
            packages: inv.sources.iter().map(|s| s.packages.len()).sum(),
            sources: inv.sources.len(),
            gaps: inv
                .sources
                .iter()
                .filter(|s| s.coverage != fleetreach_core::Coverage::Full)
                .count(),
            errors: inv.errors,
        })
    };
    let written: Vec<Result<Written, String>> = if args.fetch_licenses {
        // deps.dev is asked once for the whole fleet, so a package many repos share is
        // looked up once.
        let mut inventories: Vec<RepoInventory> = config.repos.par_iter().map(inventory).collect();
        match crate::licenses::fetch_missing(&mut inventories) {
            Ok((_, _, failed)) if failed > 0 => {
                eprintln!("warning: {failed} deps.dev license lookup(s) failed")
            }
            Ok(_) => {}
            Err(e) => return fail(&e),
        }
        config
            .repos
            .par_iter()
            .zip(inventories.into_par_iter())
            .map(|(repo, inv)| write(repo, inv))
            .collect()
    } else {
        config
            .repos
            .par_iter()
            .map(|repo| write(repo, inventory(repo)))
            .collect()
    };
    for (repo, written) in config.repos.iter().zip(written) {
        let w = match written {
            Ok(w) => w,
            Err(e) => return fail(&e),
        };
        for error in &w.errors {
            eprintln!(
                "error: {}: {}",
                sanitize_cell(&repo.id.0),
                sanitize_cell(error)
            );
        }
        if !w.errors.is_empty() {
            incomplete += 1;
        }
        if !args.quiet {
            let note = if w.gaps > 0 {
                format!(", {} source(s) with incomplete coverage", w.gaps)
            } else {
                String::new()
            };
            eprintln!(
                "{}: {} package(s) from {} source(s){note} -> {}",
                sanitize_cell(&repo.id.0),
                w.packages,
                w.sources,
                w.file.display()
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
/// What one repo's BOM came to, for the messages printed after the parallel build.
struct Written {
    file: PathBuf,
    packages: usize,
    sources: usize,
    gaps: usize,
    errors: Vec<String>,
}

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
