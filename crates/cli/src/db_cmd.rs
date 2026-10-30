//! The `db` subcommands (spec 01): `db sync` fetches the osv.dev exports a fleet needs into
//! one directory (the default cache, or `--osv-dir` to prepare an air-gapped mirror), and
//! `db status` shows what is there and how old it is.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use clap::Args;
use fleetreach_core::Ecosystem;

use crate::cli::fail;
use crate::config::Config;
use crate::orchestrate::fleet_ecosystems;
use crate::osvdb;
use crate::sources;

#[derive(Args)]
pub struct DbSyncArgs {
    /// fleet.toml whose ecosystems decide what to fetch (ignored with --all/--ecosystems)
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,
    /// fetch these ecosystems (comma-separated, e.g. npm,pypi,maven)
    #[arg(long, value_delimiter = ',', value_name = "ECOS")]
    ecosystems: Vec<String>,
    /// fetch every osv.dev export fleetreach can read
    #[arg(long, conflicts_with = "ecosystems")]
    all: bool,
    /// sync into this directory instead of the default cache (e.g. to copy to an air-gapped host)
    #[arg(long, value_name = "DIR")]
    osv_dir: Option<PathBuf>,
    /// re-download even if the cached export was checked recently
    #[arg(long)]
    force: bool,
    #[arg(short, long, help = "no progress output")]
    quiet: bool,
}

#[derive(Args)]
pub struct DbStatusArgs {
    /// show this directory instead of the default cache
    #[arg(long, value_name = "DIR")]
    osv_dir: Option<PathBuf>,
}

/// The directory to operate on: the flag, else `FLEETREACH_OSV_DIR`, else the default cache.
fn target_dir(explicit: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(dir) = explicit {
        return Ok(dir.to_path_buf());
    }
    if let Some(dir) = std::env::var_os(osvdb::DIR_ENV).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    osvdb::default_cache_dir().ok_or_else(|| {
        "no usable cache directory (set XDG_CACHE_HOME or HOME, or pass --osv-dir; an existing \
         cache that is a symlink or writable by others is refused)"
            .to_string()
    })
}

pub fn run_db_sync(args: DbSyncArgs) -> u8 {
    let dir = match target_dir(args.osv_dir.as_deref()) {
        Ok(dir) => dir,
        Err(e) => return fail(&e),
    };
    let ecosystems: Vec<Ecosystem> = if args.all {
        osvdb::OSV_ECOSYSTEMS.to_vec()
    } else if !args.ecosystems.is_empty() {
        let mut out = Vec::new();
        for name in &args.ecosystems {
            match osvdb::parse_ecosystem(name) {
                Some(eco) if !out.contains(&eco) => out.push(eco),
                Some(_) => {}
                None => {
                    return fail(&format!(
                        "`{name}` is not an ecosystem with an osv.dev export"
                    ))
                }
            }
        }
        out
    } else {
        match Config::load(&args.config) {
            Ok(config) => fleet_ecosystems(&config)
                .into_iter()
                .filter(|&eco| osvdb::osv_name(eco).is_some())
                .collect(),
            Err(e) => {
                return fail(&format!(
                    "{e} (pass --all or --ecosystems to sync without a fleet.toml)"
                ))
            }
        }
    };
    if ecosystems.is_empty() {
        if !args.quiet {
            eprintln!("nothing to sync: the fleet has no toolchain-free ecosystem");
        }
        return 0;
    }
    if let Err(e) = osvdb::create_private_dir(&dir) {
        return fail(&format!("creating {}: {e}", dir.display()));
    }
    let results = osvdb::sync_many(
        &dir,
        &ecosystems,
        osvdb::DEFAULT_REFRESH,
        args.force,
        args.quiet,
    );
    let mut failed = false;
    for (eco, result) in results {
        let name = osvdb::osv_name(eco).unwrap_or_default();
        match result {
            Ok(()) => {
                if !args.quiet {
                    eprintln!("  {name}: ok");
                }
            }
            Err(e) => {
                failed = true;
                eprintln!("  {name}: FAILED: {e}");
            }
        }
    }
    if !args.quiet {
        eprintln!("OSV exports in {}", dir.display());
    }
    // A partial sync is not a usable mirror: fail closed so a scripted refresh notices.
    u8::from(failed) * 2
}

pub fn run_db_status(args: DbStatusArgs) -> u8 {
    let dir = match target_dir(args.osv_dir.as_deref()) {
        Ok(dir) => dir,
        Err(e) => return fail(&e),
    };
    println!("OSV exports in {}", dir.display());
    let header = ["Ecosystem", "Status", "Age", "Size", "sha256"];
    let [name, status, age, size, sha] = header;
    println!("{name:<16} {status:<8} {age:<16} {size:>8}  {sha}");
    for [name, status, age, size, sha] in osvdb::status_rows(&dir, SystemTime::now()) {
        println!("{name:<16} {status:<8} {age:<16} {size:>8}  {sha}");
    }
    0
}

#[derive(Args)]
pub struct FleetSyncArgs {
    /// fleet.toml whose `[[source]]` entries to list and check out
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,
    #[arg(short, long, help = "no progress output")]
    quiet: bool,
}

#[derive(Args)]
pub struct FleetListArgs {
    /// fleet.toml to resolve (explicit repos plus cached source listings)
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,
}

/// `fleet sync`: list every source afresh and clone or refresh its checkouts. Exits 2 if any
/// listing or checkout fails, so a scripted refresh never mistakes a partial fleet for whole.
pub fn run_fleet_sync(args: FleetSyncArgs) -> u8 {
    let config = match Config::load(&args.config) {
        Ok(config) => config,
        Err(e) => return fail(&e.to_string()),
    };
    if config.sources.is_empty() {
        if !args.quiet {
            eprintln!("nothing to sync: fleet.toml has no [[source]] entries");
        }
        return 0;
    }
    let materialized = match sources::materialize(&config, true, args.quiet) {
        Ok(m) => m,
        Err(e) => return fail(&e),
    };
    print_fleet(&config, &materialized);
    u8::from(!materialized.failed.is_empty()) * 2
}

/// `fleet list`: the repos the fleet resolves to from the cached listings and existing
/// checkouts, without touching the network.
pub fn run_fleet_list(args: FleetListArgs) -> u8 {
    let config = match Config::load(&args.config) {
        Ok(config) => config,
        Err(e) => return fail(&e.to_string()),
    };
    let materialized = match sources::materialize(&config, false, true) {
        Ok(m) => m,
        Err(e) => return fail(&e),
    };
    print_fleet(&config, &materialized);
    0
}

fn print_fleet(config: &Config, materialized: &sources::Materialized) {
    use fleetreach_report::sanitize_cell;
    let commits: std::collections::BTreeMap<&str, &str> = materialized
        .provenance
        .iter()
        .map(|p| (p.repo.0.as_str(), p.commit.as_str()))
        .collect();
    println!("{:<40} {:<10} Path", "Repo", "Commit");
    for repo in config.repos.iter().chain(&materialized.repos) {
        let commit = commits
            .get(repo.id.0.as_str())
            .map_or("local", |c| c.get(..10).unwrap_or(c));
        println!(
            "{:<40} {:<10} {}",
            sanitize_cell(&repo.id.0),
            commit,
            repo.path.display()
        );
    }
    for (repo, reason) in &materialized.failed {
        println!(
            "{:<40} {:<10} {}",
            sanitize_cell(&repo.0),
            "MISSING",
            sanitize_cell(reason)
        );
    }
}
