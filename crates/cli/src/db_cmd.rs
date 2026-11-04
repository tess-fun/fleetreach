//! The `db` subcommands (spec 01): `db sync` fetches the osv.dev exports a fleet needs into
//! one directory (the default cache, or `--osv-dir` to prepare an air-gapped mirror), and
//! `db status` shows what is there and how old it is.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use clap::Args;
use fleetreach_core::Ecosystem;

use crate::cli::fail;
use crate::config::Config;
use crate::curated;
use crate::orchestrate::fleet_ecosystems;
use crate::osvdb;
use crate::snapshot;
use crate::sources;

#[derive(Args)]
pub struct DbSyncArgs {
    /// fleet.toml whose ecosystems decide what to fetch (ignored with --all/--ecosystems)
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,
    /// fetch these ecosystems (comma-separated, e.g. npm,pypi,maven)
    #[arg(long, value_delimiter = ',', value_name = "ECOS")]
    ecosystems: Vec<String>,
    /// fetch every language osv.dev export fleetreach can read (distro exports are fetched
    /// only by name or for a fleet's images: some are over a gigabyte)
    #[arg(long, conflicts_with = "ecosystems")]
    all: bool,
    /// fetch the exports for these distro releases (comma-separated, e.g. Debian:12,Wolfi):
    /// the whole distribution's export, which is what osv.dev maintains
    #[arg(long, value_delimiter = ',', value_name = "DISTROS")]
    distros: Vec<String>,
    /// sync into this directory instead of the default cache (e.g. to copy to an air-gapped host)
    #[arg(long, value_name = "DIR")]
    osv_dir: Option<PathBuf>,
    /// what to fetch: `osv` (the exports), `cve` (cvelistV5), `csaf:<provider>` (vendor CSAF
    /// VEX; `csaf:redhat`, `csaf:suse`), `rustsec`, `kev` and `epss`; `nvd` and `vulnrichment`
    /// copy what scans have cached. All of them land in one directory for `db bundle`
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "SOURCES",
        default_value = "osv"
    )]
    source: Vec<String>,
    /// re-download even if the cached export was checked recently
    #[arg(long)]
    force: bool,
    #[arg(short, long, help = "no progress output")]
    quiet: bool,
}

#[derive(Args)]
pub struct DbImportArgs {
    /// a `db bundle` tar: every file is checked against its manifest before any is installed
    #[arg(long, value_name = "PATH")]
    bundle: Option<PathBuf>,
    /// refuse a bundle whose sha256 is not this (the one `db bundle` printed)
    #[arg(long, value_name = "HEX", requires = "bundle")]
    sha256: Option<String>,
    /// a cvelistV5 checkout, its `cves.zip`, or a release's `*_all_CVEs_at_midnight.zip.zip`
    #[arg(
        long,
        value_name = "PATH",
        required_unless_present_any = ["bundle", "csaf", "rustsec", "kev", "epss"]
    )]
    cve: Option<PathBuf>,
    /// a directory of CSAF documents, or a `.tar.zst` or `.tar.bz2` archive (Red Hat's
    /// `csaf_vex_<date>.tar.zst`, SUSE's `csaf-vex.tar.bz2`)
    #[arg(long, value_name = "PATH")]
    csaf: Option<PathBuf>,
    /// the provider name the CSAF index is filed under (`redhat`, `suse`)
    #[arg(long, default_value = "redhat", requires = "csaf")]
    provider: String,
    /// a RustSec advisory-db clone
    #[arg(long, value_name = "DIR")]
    rustsec: Option<PathBuf>,
    /// a KEV catalog JSON file
    #[arg(long, value_name = "PATH")]
    kev: Option<PathBuf>,
    /// an EPSS CSV file
    #[arg(long, value_name = "PATH")]
    epss: Option<PathBuf>,
    /// index into this directory instead of the default cache
    #[arg(long, value_name = "DIR")]
    osv_dir: Option<PathBuf>,
    #[arg(short, long, help = "no progress output")]
    quiet: bool,
}

#[derive(Args)]
pub struct DbSnapshotArgs {
    /// snapshot this directory instead of the default cache
    #[arg(long, value_name = "DIR")]
    osv_dir: Option<PathBuf>,
    /// write here instead of `snapshot-<date>.json` in the directory
    #[arg(short, long, value_name = "FILE")]
    out: Option<PathBuf>,
    #[arg(short, long, help = "no progress output")]
    quiet: bool,
}

#[derive(Args)]
pub struct DbBundleArgs {
    /// pack this directory instead of the default cache
    #[arg(long, value_name = "DIR")]
    osv_dir: Option<PathBuf>,
    /// the tar to write
    #[arg(short, long, value_name = "FILE")]
    out: PathBuf,
    #[arg(short, long, help = "no progress output")]
    quiet: bool,
}

#[derive(Args)]
pub struct DbQualityArgs {
    /// fleet.toml whose `[settings.advisories] dir` overlay to check with the data (optional)
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// check this overlay directory (overrides the config's)
    #[arg(long, value_name = "DIR")]
    advisories_dir: Option<PathBuf>,
    /// read this directory instead of the default cache
    #[arg(long, value_name = "DIR")]
    osv_dir: Option<PathBuf>,
    /// print every issue as JSON instead of the summary
    #[arg(long)]
    json: bool,
    /// examples to print per check
    #[arg(long, default_value_t = 5)]
    limit: usize,
}

#[derive(Args)]
pub struct DbCrosscheckArgs {
    /// read this directory instead of the default cache
    #[arg(long, value_name = "DIR")]
    osv_dir: Option<PathBuf>,
    /// print the measurements as JSON
    #[arg(long)]
    json: bool,
    /// examples to keep per kind
    #[arg(long, default_value_t = 5)]
    limit: usize,
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
    let mut osv = false;
    let mut cve = false;
    let mut providers: Vec<&str> = Vec::new();
    let mut others: Vec<&str> = Vec::new();
    for source in &args.source {
        match source.trim() {
            "osv" => osv = true,
            "cve" => cve = true,
            other @ ("rustsec" | "kev" | "epss" | "nvd" | "vulnrichment") => others.push(other),
            other => match other.strip_prefix("csaf:") {
                Some(provider) if !providers.contains(&provider) => providers.push(provider),
                Some(_) => {}
                None => {
                    return fail(&format!(
                        "`{other}` is not a source (osv, cve, csaf:<provider>, rustsec, kev, \
                         epss, nvd, vulnrichment)"
                    ))
                }
            },
        }
    }
    let mut failed = false;
    if osv {
        match sync_osv(&args, &dir) {
            Ok(ok) => failed |= !ok,
            Err(code) => return code,
        }
    }
    if cve || !providers.is_empty() || !others.is_empty() {
        if let Err(e) = osvdb::create_private_dir(&dir) {
            return fail(&format!("creating {}: {e}", dir.display()));
        }
    }
    let refresh = osvdb::DEFAULT_REFRESH;
    let mut report = |name: &str, result: Result<curated::Indexed, String>| match result {
        Ok(indexed) if !args.quiet && indexed.documents > 0 => eprintln!(
            "  {name}: indexed {} record(s) from {} document(s)",
            indexed.records, indexed.documents
        ),
        Ok(_) if !args.quiet => eprintln!("  {name}: ok (unchanged)"),
        Ok(_) => {}
        Err(e) => {
            failed = true;
            eprintln!("  {name}: FAILED: {e}");
        }
    };
    if cve {
        report(
            "cvelistV5",
            curated::sync_cve(&dir, refresh, args.force, args.quiet),
        );
    }
    for provider in providers {
        let result = curated::sync_csaf(&dir, provider, refresh, args.force, args.quiet);
        report(&format!("csaf:{provider}"), result);
    }
    for source in others {
        match sync_other(source, &dir) {
            Ok(()) if !args.quiet => eprintln!("  {source}: ok"),
            Ok(()) => {}
            Err(e) => {
                failed = true;
                eprintln!("  {source}: FAILED: {e}");
            }
        }
    }
    // A partial sync is not a usable mirror: fail closed so a scripted refresh notices.
    u8::from(failed) * 2
}

/// Bring `rustsec`, `kev`, `epss`, `nvd` or `vulnrichment` into the data directory.
fn sync_other(source: &str, dir: &Path) -> Result<(), String> {
    // A cache is a scan's, so there is nothing to fetch: the copy is what a bundle carries.
    let copy_cache = |name: &str, target: &str| {
        let cache = osvdb::private_subdir(name)
            .filter(|cache| cache.is_dir())
            .ok_or_else(|| format!("no {name} cache yet: a scan with --enrich fills it"))?;
        snapshot::install_tree(dir, target, &cache).map(|_| ())
    };
    match source {
        "nvd" => copy_cache("nvd", snapshot::NVD_DIR),
        "vulnrichment" => copy_cache("vulnrichment", snapshot::VULNRICHMENT_DIR),
        _ => fetch_other(source, dir),
    }
}

#[cfg(feature = "network")]
fn fetch_other(source: &str, dir: &Path) -> Result<(), String> {
    match source {
        "kev" => crate::enrich::sync_kev(dir),
        "epss" => crate::enrich::sync_epss(dir),
        _ => {
            fleetreach_scan::AdvisoryDb::fetch().map_err(|e| e.to_string())?;
            let clone = fleetreach_scan::AdvisoryDb::default_path();
            snapshot::install_tree(dir, snapshot::RUSTSEC_DIR, &clone).map(|_| ())
        }
    }
}

#[cfg(not(feature = "network"))]
fn fetch_other(_: &str, _: &Path) -> Result<(), String> {
    Err("this build has no network support (use `db import`)".to_string())
}

/// `db snapshot`: a dated, hashed manifest of every source in the directory.
pub fn run_db_snapshot(args: DbSnapshotArgs) -> u8 {
    let dir = match target_dir(args.osv_dir.as_deref()) {
        Ok(dir) => dir,
        Err(e) => return fail(&e),
    };
    let manifest = match snapshot::build(&dir) {
        Ok(manifest) => manifest,
        Err(e) => return fail(&e),
    };
    let out = args
        .out
        .unwrap_or_else(|| dir.join(snapshot::default_name(&manifest)));
    if let Err(e) = snapshot::write(&manifest, &out) {
        return fail(&e);
    }
    if !args.quiet {
        let files: usize = manifest.sources.iter().map(|s| s.files.len()).sum();
        eprintln!(
            "{}: {} source(s), {files} file(s)",
            out.display(),
            manifest.sources.len()
        );
    }
    0
}

/// `db bundle`: every source in the directory, in one tar.
pub fn run_db_bundle(args: DbBundleArgs) -> u8 {
    let dir = match target_dir(args.osv_dir.as_deref()) {
        Ok(dir) => dir,
        Err(e) => return fail(&e),
    };
    match snapshot::bundle(&dir, &args.out) {
        Ok((manifest, sha256)) => {
            if !args.quiet {
                eprintln!(
                    "{}: {} source(s)",
                    args.out.display(),
                    manifest.sources.len()
                );
            }
            println!("{sha256}");
            0
        }
        Err(e) => fail(&e),
    }
}

/// Install a bundle, reporting what is left beside it.
fn import_bundle(
    input: &Path,
    dir: &Path,
    sha256: Option<&str>,
    quiet: bool,
) -> Result<(), String> {
    let imported = snapshot::import(input, dir, sha256)?;
    if !quiet {
        eprintln!(
            "  bundle: {} source(s) from {}",
            imported.manifest.sources.len(),
            imported.manifest.created
        );
    }
    if !imported.left_over.is_empty() {
        eprintln!(
            "warning: not in the bundle, so `--db-snapshot` will refuse this directory: {}",
            imported.left_over.join(", ")
        );
    }
    Ok(())
}

/// A local KEV or EPSS file, checked to parse, or a RustSec clone.
fn import_other(args: &DbImportArgs, dir: &Path) -> Vec<(String, Result<(), String>)> {
    let file = |path: &Path, target: &str| {
        let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        let url = format!("file://{}", path.display());
        snapshot::install_file(dir, target, &bytes, &url, None)
    };
    let mut jobs = Vec::new();
    if let Some(path) = &args.rustsec {
        let opened = fleetreach_scan::AdvisoryDb::open(path).map_err(|e| e.to_string());
        let copied = opened
            .and_then(|_| snapshot::install_tree(dir, snapshot::RUSTSEC_DIR, path))
            .map(|_| ());
        jobs.push(("rustsec".to_string(), copied));
    }
    if let Some(path) = &args.kev {
        let result = crate::enrich::Enrichment::from_files(Some(path), None)
            .and_then(|_| file(path, snapshot::KEV_FILE));
        jobs.push(("kev".to_string(), result));
    }
    if let Some(path) = &args.epss {
        let result = crate::enrich::Enrichment::from_files(None, Some(path))
            .and_then(|_| file(path, snapshot::EPSS_FILE));
        jobs.push(("epss".to_string(), result));
    }
    jobs
}

/// `db import`: bring in a bundle or a local copy of one source, for hosts that cannot fetch.
pub fn run_db_import(args: DbImportArgs) -> u8 {
    let dir = match target_dir(args.osv_dir.as_deref()) {
        Ok(dir) => dir,
        Err(e) => return fail(&e),
    };
    if let Err(e) = osvdb::create_private_dir(&dir) {
        return fail(&format!("creating {}: {e}", dir.display()));
    }
    let mut failed = false;
    if let Some(input) = &args.bundle {
        if let Err(e) = import_bundle(input, &dir, args.sha256.as_deref(), args.quiet) {
            failed = true;
            eprintln!("  bundle: FAILED: {e}");
        }
    }
    for (name, result) in import_other(&args, &dir) {
        match result {
            Ok(()) if !args.quiet => eprintln!("  {name}: ok"),
            Ok(()) => {}
            Err(e) => {
                failed = true;
                eprintln!("  {name}: FAILED: {e}");
            }
        }
    }
    let mut jobs: Vec<(String, Result<curated::Indexed, String>)> = Vec::new();
    if let Some(input) = &args.cve {
        jobs.push((
            "cvelistV5".to_string(),
            curated::import_cve(&dir, input, None),
        ));
    }
    if let Some(input) = &args.csaf {
        let result = curated::import_csaf(&dir, &args.provider, input, None);
        jobs.push((format!("csaf:{}", args.provider), result));
    }
    for (name, result) in jobs {
        match result {
            Ok(indexed) => {
                if !args.quiet {
                    eprintln!(
                        "  {name}: indexed {} record(s) from {} document(s){}",
                        indexed.records,
                        indexed.documents,
                        if indexed.skipped > 0 {
                            format!(", {} file(s) were not records", indexed.skipped)
                        } else {
                            String::new()
                        }
                    );
                }
            }
            Err(e) => {
                failed = true;
                eprintln!("  {name}: FAILED: {e}");
            }
        }
    }
    u8::from(failed) * 2
}

/// The osv.dev half of `db sync`. `Ok(false)` when some export failed.
fn sync_osv(args: &DbSyncArgs, dir: &Path) -> Result<bool, u8> {
    for name in &args.distros {
        if !fleetreach_os::distro::known_ecosystem(name) {
            return Err(fail(&format!(
                "`{name}` is not a distro ecosystem fleetreach matches (like Debian:12, \
                 Ubuntu:24.04:LTS, Alpine:v3.20, Wolfi)"
            )));
        }
    }
    let mut distros: Vec<String> = args.distros.clone();
    let ecosystems: Vec<Ecosystem> = if args.all {
        osvdb::OSV_ECOSYSTEMS.to_vec()
    } else if !args.ecosystems.is_empty() {
        let mut out = Vec::new();
        for name in &args.ecosystems {
            match osvdb::parse_ecosystem(name) {
                Some(eco) if !out.contains(&eco) => out.push(eco),
                Some(_) => {}
                None => {
                    return Err(fail(&format!(
                        "`{name}` is not an ecosystem with an osv.dev export"
                    )))
                }
            }
        }
        out
    } else if !distros.is_empty() {
        Vec::new()
    } else {
        match Config::load(&args.config) {
            Ok(config) => {
                // The fleet's images decide which distros to fetch, and add the language
                // ecosystems their lockfiles and installed packages need.
                let images = crate::images::prepare_all(&config.images, false, None);
                for image in &images {
                    if let Err(e) = &image.opened {
                        eprintln!("warning: image {}: {e}", image.source);
                    }
                }
                // A vendor's VEX ecosystems are derived from its CSAF index on scan, not
                // fetched (`--source csaf:<provider>` fetches the index).
                distros = crate::images::distro_ecosystems(&images)
                    .into_iter()
                    .filter(|eco| !fleetreach_os::distro::is_vex(eco))
                    .collect();
                let mut ecos = fleet_ecosystems(&config);
                ecos.extend(crate::images::language_ecosystems(&images));
                ecos.sort();
                ecos.dedup();
                ecos.into_iter()
                    .filter(|&eco| osvdb::osv_name(eco).is_some())
                    .collect()
            }
            Err(e) => {
                return Err(fail(&format!(
                    "{e} (pass --all or --ecosystems to sync without a fleet.toml)"
                )))
            }
        }
    };
    if ecosystems.is_empty() && distros.is_empty() {
        if !args.quiet {
            eprintln!("nothing to sync: the fleet has no toolchain-free ecosystem");
        }
        return Ok(true);
    }
    if let Err(e) = osvdb::create_private_dir(dir) {
        return Err(fail(&format!("creating {}: {e}", dir.display())));
    }
    let results = osvdb::sync_many(
        dir,
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
    let refresh = osvdb::DEFAULT_REFRESH;
    for (distro, result) in osvdb::sync_distros(dir, &distros, refresh, args.force, args.quiet) {
        match result {
            Ok(export) if export == distro => {
                if !args.quiet {
                    eprintln!("  {distro}: ok");
                }
            }
            Ok(export) => {
                if !args.quiet {
                    eprintln!("  {distro}: ok (from the {export} export)");
                }
            }
            Err(e) => {
                failed = true;
                eprintln!("  {distro}: FAILED: {e}");
            }
        }
    }
    if !args.quiet {
        eprintln!("OSV exports in {}", dir.display());
    }
    Ok(!failed)
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
    let now = SystemTime::now();
    for [name, status, age, size, sha] in osvdb::status_rows(&dir, now)
        .into_iter()
        .chain(curated::status_rows(&dir, now))
        .chain(snapshot::status_rows(&dir))
    {
        println!("{name:<16} {status:<8} {age:<16} {size:>8}  {sha}");
    }
    0
}

#[derive(Args)]
pub struct FleetSyncArgs {
    /// fleet.toml whose `[[source]]` entries to list and check out
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,
    /// Append what changed in each source's listing to `inventory.jsonl` in this scan history
    /// directory
    #[arg(long, value_name = "DIR")]
    history_dir: Option<PathBuf>,
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
    if !args.quiet {
        sources::print_inventory(&materialized.inventory);
    }
    if let Some(dir) = &args.history_dir {
        if let Err(e) = crate::history::record_inventory(dir, &materialized.inventory) {
            return fail(&format!("recording inventory: {e}"));
        }
    }
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

/// `db quality`: data-quality issues in the local advisory data. Exit 1 when an issue is an
/// error (an overlay record nothing applies), 2 when the data cannot be read.
pub fn run_db_quality(args: DbQualityArgs) -> u8 {
    use crate::quality::{self, Level};
    let dir = match target_dir(args.osv_dir.as_deref()) {
        Ok(dir) => dir,
        Err(e) => return fail(&e),
    };
    let overlay = match (&args.advisories_dir, &args.config) {
        (Some(dir), _) => Some(dir.clone()),
        (None, Some(path)) => match Config::load(path) {
            Ok(config) => config.osv.advisories,
            Err(e) => return fail(&e.to_string()),
        },
        (None, None) => None,
    };
    let cve_index = crate::cve5::index_path(&dir);
    let cves = if cve_index.is_file() {
        match crate::cve5::read_index(&cve_index) {
            Ok(cves) => Some(cves),
            Err(e) => return fail(&e),
        }
    } else {
        eprintln!("note: no CVE index in {}; `rejected-cve-alias` is not checked (`db sync --source cve`)", dir.display());
        None
    };
    let inputs = quality::Inputs {
        dir: &dir,
        overlay: overlay.as_deref(),
        cves: cves.as_deref(),
    };
    let issues = match quality::run(&inputs) {
        Ok(issues) => issues,
        Err(e) => return fail(&e),
    };
    let errors = issues.iter().any(|i| i.level == Level::Error);
    if args.json {
        match serde_json::to_string_pretty(&issues) {
            Ok(json) => println!("{json}"),
            Err(e) => return fail(&e.to_string()),
        }
        return u8::from(errors);
    }
    use fleetreach_report::sanitize_cell;
    println!("{:<26} {:<8} {:>8}  Description", "Check", "Level", "Count");
    for (check, level, description) in quality::CHECKS {
        let count = issues.iter().filter(|i| i.check == *check).count();
        println!(
            "{check:<26} {:<8} {count:>8}  {description}",
            format!("{level:?}").to_lowercase()
        );
    }
    for (check, _, _) in quality::CHECKS {
        let mut shown = issues
            .iter()
            .filter(|i| i.check == *check)
            .take(args.limit)
            .peekable();
        if shown.peek().is_none() {
            continue;
        }
        println!("\n{check}:");
        for i in shown {
            println!(
                "  {:<14} {:<28} {:<30} {}",
                sanitize_cell(&i.ecosystem),
                sanitize_cell(&i.id),
                sanitize_cell(i.package.as_deref().unwrap_or("")),
                sanitize_cell(&i.detail)
            );
        }
    }
    u8::from(errors)
}

/// `db crosscheck`: what the CVE and CSAF indexes add to or contradict in the OSV exports.
pub fn run_db_crosscheck(args: DbCrosscheckArgs) -> u8 {
    use crate::crosscheck;
    let dir = match target_dir(args.osv_dir.as_deref()) {
        Ok(dir) => dir,
        Err(e) => return fail(&e),
    };
    let records = match crate::osvrecords::load_dir(&dir, None) {
        Ok(records) => records,
        Err(e) => return fail(&e),
    };
    let ecosystems: std::collections::BTreeSet<String> = records
        .values()
        .map(|(export, _)| export.clone())
        .filter(|e| e != "Red Hat")
        .collect();
    let mut out = serde_json::Map::new();
    let cve_index = crate::cve5::index_path(&dir);
    if cve_index.is_file() {
        let cves = match crate::cve5::read_index(&cve_index) {
            Ok(cves) => cves,
            Err(e) => return fail(&e),
        };
        let report = crosscheck::cve_vs_osv(&cves, &records, &ecosystems, args.limit);
        out.insert(
            "cve".into(),
            serde_json::to_value(report).unwrap_or_default(),
        );
    } else {
        eprintln!(
            "note: no CVE index in {} (`db sync --source cve` or `db import --cve`)",
            dir.display()
        );
    }
    for provider in curated::CSAF_PROVIDERS {
        let index = crate::csaf::index_path(&dir, provider);
        if !index.is_file() {
            eprintln!("note: no CSAF index for {provider} in {}", dir.display());
            continue;
        }
        if !records.values().any(|(export, _)| export == "Red Hat") && *provider == "redhat" {
            eprintln!(
                "note: no OSV `Red Hat` export in {}; CSAF counts only",
                dir.display()
            );
        }
        let error = std::cell::RefCell::new(None);
        let vex = match crate::cve5::stream_jsonl_gz(&index, &error) {
            Ok(vex) => vex,
            Err(e) => return fail(&e),
        };
        let report = crosscheck::csaf_vs_osv(provider, vex, &records, args.limit);
        if let Some(e) = error.into_inner() {
            return fail(&e);
        }
        out.insert(
            format!("csaf:{provider}"),
            serde_json::to_value(report).unwrap_or_default(),
        );
    }
    if out.is_empty() {
        return fail("nothing to cross-check: neither a CVE nor a CSAF index is present");
    }
    if !args.json {
        eprintln!("(the cross-check is printed as JSON; it is a measurement, not a table)");
    }
    match serde_json::to_string_pretty(&serde_json::Value::Object(out)) {
        Ok(json) => println!("{json}"),
        Err(e) => return fail(&e.to_string()),
    }
    0
}
