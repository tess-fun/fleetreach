//! The `scan` command: parse `ScanArgs`, run the audit pipeline (config → fleet
//! scan → assemble → enrich → reachability → render), and return the exit code.
//! Also hosts the `--why`/`--explain` short-circuits and `-f vex` parameter build.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use clap::Parser;
use fleetreach_core::{Ecosystem, FleetReport, RepoOutcome, ScanStatus, Severity};
use fleetreach_report as report;
use fleetreach_scan::{routes_to, AdvisoryDb};

use crate::assemble::{
    assemble, combine_baseline, drop_dev, drop_phantom, exit_code, retain_min_epss, retain_new,
    retain_reachable, Assembled, GateConfig, SuppressedOccurrence, Suppression,
};
use crate::cli::{
    fail, usage_fail, BuildSandbox, Format, OutcomeArg, ReachMode, SeverityArg, VexScopeArg,
};
use crate::config::{Config, Repo};
use crate::db::{
    build_provenance, check_db_age, detect_toolchain, fetch_enrichment, load_db_from,
    parse_duration_secs,
};
use crate::enrich::{self, Enrichment};
use crate::orchestrate::{discover_lockfiles, fleet_ecosystems, scan_fleet_with, GoScan, Mirrors};
use crate::{npm_reach, osvdb, py_reach, reach, resolve, sources, static_reach, vex};

#[derive(Parser)]
pub(crate) struct ScanArgs {
    /// The fleet config [default: ./fleet.toml; without one, the current repo is scanned
    /// as a one-repo fleet, or with only `--image`, just the images]
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Scan only this directory as a one-repo fleet, without a fleet.toml
    #[arg(long, value_name = "DIR", conflicts_with = "config")]
    repo: Option<PathBuf>,
    #[arg(short, long, value_enum, default_value_t = Format::Table)]
    format: Format,

    // advisory DB control
    #[arg(long, help = "use a local advisory-db clone instead of fetching")]
    db: Option<PathBuf>,
    #[arg(long, help = "pin advisory DB to an exact commit (requires --db)")]
    db_rev: Option<String>,
    #[arg(long, help = "never fetch; require cache/--db")]
    offline: bool,
    #[arg(long, help = "exit 2 if the usable DB is older than DUR, e.g. 7d")]
    max_db_age: Option<String>,

    // filtering & gating
    #[arg(long, value_enum, help = "report only at/above this severity")]
    min_severity: Option<SeverityArg>,
    #[arg(
        long,
        value_enum,
        help = "fail if any vuln at/above [default: low, or off when --fail-on-ssvc is given alone]"
    )]
    fail_on: Option<SeverityArg>,
    #[arg(long, help = "also fail if any warning is present")]
    fail_on_warnings: bool,
    #[arg(
        long,
        help = "add supply-chain signals as warnings: install scripts, non-registry sources, unexpected registries, missing checksums, third-party GitHub Actions on movable tags"
    )]
    signals: bool,
    #[command(flatten)]
    maven: crate::maven_repo::FetchArgs,
    #[arg(
        long,
        value_name = "DUR",
        help = "warn on dependency versions published less than DUR ago, e.g. 72h (looks publish times up on deps.dev, which sends each package's name and version; cached)"
    )]
    release_age: Option<String>,
    #[arg(
        long,
        help = "exit 2 if any source was read with less than full coverage (a pom.xml without a resolved graph, a lockfile format fleetreach cannot read), as for an errored repo"
    )]
    require_full_coverage: bool,

    #[arg(
        long,
        help = "mark findings built/phantom via cargo tree (needs buildable source)"
    )]
    resolve_features: bool,
    #[arg(
        long,
        help = "suppress findings on phantom (unbuilt optional) deps; implies --resolve-features"
    )]
    ignore_phantom: bool,
    #[arg(
        long,
        help = "suppress findings on dev/build-only deps (npm devDependencies, uv/poetry dev \
                groups, Pipfile dev-packages, composer require-dev)"
    )]
    ignore_dev_deps: bool,

    #[arg(
        long,
        value_name = "DIR",
        help = "read triage decisions from DIR (default: `triage/` beside fleet.toml, if there)"
    )]
    triage_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "read OpenVEX attached to images pulled from registries; a document sets \
                findings aside when --vex-oci-key signed it"
    )]
    vex_oci: bool,
    #[arg(
        long,
        value_name = "PUBLIC_KEY",
        help = "cosign public key whose signature on attached VEX is accepted (repeatable); \
                implies --vex-oci"
    )]
    vex_oci_key: Vec<PathBuf>,
    #[arg(
        long,
        help = "accept attached VEX no key signed, as Trivy does: anyone who can push to the \
                repository can then hide findings; implies --vex-oci"
    )]
    vex_oci_unsigned: bool,

    // exploit-risk enrichment (CISA KEV + FIRST EPSS)
    #[arg(long, help = "enrich findings with CISA KEV + EPSS (network)")]
    enrich: bool,
    #[arg(
        long,
        value_name = "PATH",
        help = "KEV catalog JSON file (offline enrich)"
    )]
    kev_file: Option<PathBuf>,
    #[arg(long, value_name = "PATH", help = "EPSS CSV file (offline enrich)")]
    epss_file: Option<PathBuf>,
    #[arg(long, help = "fail if any finding is in the CISA KEV catalog")]
    fail_on_kev: bool,
    #[arg(long, value_name = "P", help = "report only findings with EPSS >= P")]
    min_epss: Option<f32>,
    #[arg(
        long,
        value_enum,
        value_name = "OUTCOME",
        help = "fail if any SSVC decision is at or above OUTCOME (needs repo context in fleet.toml; implies --enrich)"
    )]
    fail_on_ssvc: Option<OutcomeArg>,
    #[arg(
        long,
        value_name = "DIR",
        help = "a local clone of github.com/cisagov/vulnrichment, for CISA's SSVC Exploitation and Automatable per CVE (with --enrich they are fetched from GitHub instead, cached)"
    )]
    vulnrichment_dir: Option<PathBuf>,

    #[arg(
        long,
        value_enum,
        num_args = 0..=1,
        default_missing_value = "heuristic",
        value_name = "MODE",
        help = "reachability: bare/`heuristic` greps your source (safe, no build); `static` is a sound call-graph analysis that COMPILES each repo — running its build scripts and proc-macros (see --allow-untrusted-builds). Needs --reach-driver."
    )]
    reachability: Option<ReachMode>,
    #[arg(
        long,
        help = "drop findings proven/assumed unreachable; implies --reachability"
    )]
    reachable_only: bool,
    #[arg(
        long,
        help = "npm only: under --reachability, build a module import graph and mark a vulnerable package NotReachable when node_modules is present and no import path reaches it. Best-effort sound — a dynamic require()/framework autoload it cannot see may make a NotReachable wrong (this flag is your acknowledgement). Implies --reachability."
    )]
    npm_prune_unreachable: bool,
    #[arg(
        long,
        help = "REQUIRED to acknowledge that --reachability=static executes the scanned repos' build scripts and proc-macros (arbitrary code). Only scan repos you trust."
    )]
    allow_untrusted_builds: bool,
    #[arg(
        long,
        value_name = "PATH",
        help = "path to the built fleetreach-reach-driver (required for --reachability=static)"
    )]
    reach_driver: Option<PathBuf>,
    #[arg(
        long,
        value_name = "PATH",
        help = "path to the govulncheck binary for scanning Go repos (default: search PATH and $GOPATH/bin). Go scanning also requires --allow-untrusted-builds (govulncheck compiles the module), and the build is confined per --build-sandbox."
    )]
    govulncheck: Option<PathBuf>,
    #[arg(
        long,
        value_name = "URL",
        help = "vulnerability DB for govulncheck (Go), passed as `-db` (default: vuln.go.dev). A `file://<mirror>` lets a confined (network-denied) Go scan run offline; falls back to the GOVULNDB env var."
    )]
    go_vuln_db: Option<String>,
    #[arg(
        long,
        value_name = "URL",
        help = "OSV vulnerability DB for the toolchain-free npm matcher, as `file://<path>` to either the osv.dev npm export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. npm scanning builds nothing, so it needs no --allow-untrusted-builds; without this an npm repo is an honest gap."
    )]
    npm_vuln_db: Option<String>,
    #[arg(
        long,
        value_name = "URL",
        help = "OSV vulnerability DB for the toolchain-free PyPI matcher, as `file://<path>` to either the osv.dev PyPI export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. PyPI scanning reads uv.lock/poetry.lock/Pipfile.lock and builds nothing, so it needs no --allow-untrusted-builds; without this a PyPI repo is an honest gap."
    )]
    pypi_vuln_db: Option<String>,
    #[arg(
        long,
        value_name = "URL",
        help = "OSV vulnerability DB for the toolchain-free RubyGems matcher, as `file://<path>` to either the osv.dev RubyGems export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. RubyGems scanning reads Gemfile.lock and builds nothing, so it needs no --allow-untrusted-builds; without this a RubyGems repo is an honest gap."
    )]
    rubygems_vuln_db: Option<String>,
    #[arg(
        long,
        value_name = "URL",
        help = "OSV vulnerability DB for the toolchain-free Packagist (Composer/PHP) matcher, as `file://<path>` to either the osv.dev Packagist export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. Packagist scanning reads composer.lock and builds nothing, so it needs no --allow-untrusted-builds; without this a Packagist repo is an honest gap."
    )]
    packagist_vuln_db: Option<String>,
    #[arg(
        long,
        value_name = "URL",
        help = "OSV vulnerability DB for the toolchain-free NuGet (.NET) matcher, as `file://<path>` to either the osv.dev NuGet export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. NuGet scanning reads packages.lock.json and builds nothing, so it needs no --allow-untrusted-builds; without this a NuGet repo is an honest gap."
    )]
    nuget_vuln_db: Option<String>,
    #[arg(
        long,
        value_name = "URL",
        help = "OSV vulnerability DB for the toolchain-free Julia matcher, as `file://<path>` to either the osv.dev Julia export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. Julia scanning reads Manifest.toml and builds nothing, so it needs no --allow-untrusted-builds; without this a Julia repo is an honest gap."
    )]
    julia_vuln_db: Option<String>,
    #[arg(
        long,
        value_name = "URL",
        help = "OSV vulnerability DB for the toolchain-free Swift matcher, as `file://<path>` to either the osv.dev SwiftURL export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. Swift scanning reads Package.resolved and builds nothing, so it needs no --allow-untrusted-builds; without this a Swift repo is an honest gap."
    )]
    swift_vuln_db: Option<String>,
    #[arg(
        long,
        value_name = "URL",
        help = "OSV vulnerability DB for the toolchain-free Hex (Elixir) matcher, as `file://<path>` to either the osv.dev Hex export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. Hex scanning reads mix.lock and builds nothing, so it needs no --allow-untrusted-builds; without this a Hex repo is an honest gap."
    )]
    hex_vuln_db: Option<String>,
    #[arg(
        long,
        value_name = "URL",
        help = "OSV vulnerability DB for the toolchain-free GitHub Actions matcher, as `file://<path>` to either the osv.dev GitHub Actions export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. It reads .github/workflows/*.yml and matches version-pinned `uses:` actions, building nothing, so it needs no --allow-untrusted-builds; without this a workflow repo is an honest gap."
    )]
    ghactions_vuln_db: Option<String>,
    #[arg(
        long,
        value_name = "URL",
        help = "OSV vulnerability DB for the crates.io advisories RustSec does not carry, as `file://<path>` to either the osv.dev crates.io export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. RustSec still answers without it, and the repo is marked partial."
    )]
    crates_vuln_db: Option<String>,
    #[arg(
        long,
        value_name = "URL",
        help = "OSV vulnerability DB for the toolchain-free Maven (Java) matcher, as `file://<path>` to either the osv.dev Maven export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. It reads gradle.lockfile (preferred) or pom.xml and builds nothing, so it needs no --allow-untrusted-builds; without this a Maven repo is an honest gap."
    )]
    maven_vuln_db: Option<String>,
    #[arg(
        long,
        help = "list every [[source]] afresh and clone or refresh its checkouts before scanning (otherwise the cached listing and existing checkouts are used)"
    )]
    sync: bool,
    #[arg(
        long,
        value_name = "DIR",
        help = "one directory holding the osv.dev exports for every toolchain-free ecosystem, laid out like the osv.dev bucket: <DIR>/<Ecosystem>/all.zip (or an unzipped <DIR>/<Ecosystem>/). A per-ecosystem --<eco>-vuln-db flag still wins. Also FLEETREACH_OSV_DIR or settings.osv.dir. Without it, the default cache (~/.cache/fleetreach/osv) is used and, in network builds, kept fresh automatically (set FLEETREACH_OSV_SYNC=off or --offline to stop that)."
    )]
    osv_dir: Option<PathBuf>,
    #[arg(
        long = "image",
        value_name = "PATH",
        help = "also scan this container image: a `docker save` or OCI-layout tarball, an OCI-layout directory, a root filesystem (directory or tarball), or `docker://<reference>` to pull one from a registry (network build; a digest already pulled also works with --offline). Repeatable; its id is the file name. Its OS packages are matched against the osv.dev distro export for its release (synced per distro, or from --osv-dir), its lockfiles and installed Python and npm packages with the language matchers. With only --image, no fleet.toml is needed."
    )]
    images: Vec<PathBuf>,
    #[arg(
        long,
        help = "drop Debian advisories the security tracker marks unimportant and Ubuntu ones it rates negligible (by default they are reported, with that urgency in the title)"
    )]
    distro_ignore_unimportant: bool,
    #[arg(
        long,
        value_enum,
        default_value = "auto",
        value_name = "MODE",
        help = "confine the untrusted build (--reachability=static AND govulncheck for Go repos, both of which compile scanned code): `auto` sandboxes when a mechanism is available (sandbox-exec/bwrap/firejail) else warns; `require` fails without one; `off` runs unconfined. Confinement denies network + writes outside a scratch dir. A confined Go scan is therefore offline: `auto` falls back to an online unconfined scan unless --go-vuln-db=file://<mirror> is set, while `require` needs the mirror or fails closed."
    )]
    build_sandbox: BuildSandbox,
    #[arg(
        long,
        value_name = "FEATURES",
        value_delimiter = ',',
        help = "cargo features to enable when building for --reachability=static (comma-separated or repeated). Part of the reachability cache key."
    )]
    features: Vec<String>,
    #[arg(long, help = "build with --all-features for --reachability=static")]
    all_features: bool,
    #[arg(
        long,
        help = "build with --no-default-features for --reachability=static"
    )]
    no_default_features: bool,

    // OpenVEX output (`-f vex`, §12)
    #[arg(
        long,
        value_name = "S",
        help = "OpenVEX mandatory author (overrides settings.vex.author)"
    )]
    vex_author: Option<String>,
    #[arg(long, value_name = "S", help = "OpenVEX document author role")]
    vex_role: Option<String>,
    #[arg(
        long,
        value_name = "IRI",
        help = "explicit OpenVEX document @id (default: content hash)"
    )]
    vex_id: Option<String>,
    #[arg(
        long,
        value_name = "RFC3339",
        help = "pin the OpenVEX timestamp (default: advisory-db commit time)"
    )]
    vex_timestamp: Option<String>,
    #[arg(
        long,
        value_enum,
        value_name = "SCOPE",
        help = "OpenVEX product scope (§7 edge 4)"
    )]
    vex_scope: Option<VexScopeArg>,
    #[arg(
        long,
        help = "omit human-asserted VEX statements, keeping only machine-sound ones"
    )]
    vex_only_sound: bool,
    #[arg(
        long,
        help = "also emit pkg:rustbinary subcomponents for binary-scanning consumers (§4.2)"
    )]
    vex_alias_rustbinary: bool,
    #[arg(
        long,
        help = "emit `fixed` VEX statements for already-patched occurrences"
    )]
    vex_include_fixed: bool,
    #[arg(
        long,
        value_name = "N",
        default_value_t = 1,
        help = "OpenVEX document version (§9.3); bump when statements change"
    )]
    vex_version: u64,
    #[arg(
        long,
        value_name = "IRI",
        help = "prior OpenVEX document @id this one supersedes (§9.3)"
    )]
    vex_supersedes: Option<String>,

    // diffing & inspection
    #[arg(long, help = "prior JSON report; report only findings new since it")]
    baseline: Option<PathBuf>,
    /// Record this run in a scan history directory (a gzipped snapshot plus an index; see
    /// `fleetreach history`). Refuses the flags that drop findings from the report, which
    /// would otherwise be recorded as fixed
    #[arg(long)]
    history_dir: Option<PathBuf>,
    #[arg(
        long,
        value_name = "ID",
        help = "print full detail for one advisory and exit"
    )]
    explain: Option<String>,
    #[arg(
        long,
        value_name = "PKG",
        help = "show how a package enters the fleet's dependency trees and exit"
    )]
    why: Option<String>,

    #[arg(short, long, help = "suppress the summary line")]
    quiet: bool,
    #[arg(short, long, help = "per-repo progress to stderr")]
    verbose: bool,
}

/// The file a SARIF result points at, relative to the repo root: the first of the files the
/// ecosystem is read from that the repo has, in the order its reader tries them, and for a
/// GitHub Action the workflow that uses it. Falls back to the usual file when none is found.
fn sarif_source(repo: Option<&Path>, ecosystem: Ecosystem, package: &str) -> String {
    let fallback = || report::default_source(ecosystem).to_string();
    let Some(repo) = repo else {
        return fallback();
    };
    let candidates: &[&str] = match ecosystem {
        Ecosystem::Npm => &[
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lock",
        ],
        Ecosystem::Pypi => &[
            "uv.lock",
            "poetry.lock",
            "Pipfile.lock",
            "pylock.toml",
            "requirements.txt",
        ],
        Ecosystem::NuGet => &[
            "packages.lock.json",
            "obj/project.assets.json",
            "packages.config",
        ],
        Ecosystem::Maven => &["gradle.lockfile", "pom.xml"],
        Ecosystem::GitHubActions => {
            let dir = repo.join(".github/workflows");
            let mut workflows: Vec<PathBuf> = std::fs::read_dir(&dir)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
                .collect();
            workflows.sort();
            let uses = format!("{package}@");
            return workflows
                .iter()
                .find(|p| std::fs::read_to_string(p).is_ok_and(|t| t.contains(&uses)))
                .and_then(|p| p.file_name())
                .map_or_else(fallback, |name| {
                    format!(".github/workflows/{}", name.to_string_lossy())
                });
        }
        _ => return fallback(),
    };
    candidates
        .iter()
        .find(|c| repo.join(c).is_file())
        .map_or_else(fallback, |c| (*c).to_string())
}

fn load_db(args: &ScanArgs) -> Result<AdvisoryDb, String> {
    load_db_from(args.db.as_deref(), args.db_rev.as_deref(), args.offline)
}

/// The per-ecosystem OSV values given explicitly: the `--<eco>-vuln-db` flag, else its env
/// var (`NPMVULNDB`, `PYPIVULNDB`, ...). Empty values count as absent.
fn explicit_osv_dbs(args: &ScanArgs) -> BTreeMap<Ecosystem, String> {
    let pairs = [
        (Ecosystem::Npm, &args.npm_vuln_db, "NPMVULNDB"),
        (Ecosystem::Pypi, &args.pypi_vuln_db, "PYPIVULNDB"),
        (
            Ecosystem::RubyGems,
            &args.rubygems_vuln_db,
            "RUBYGEMSVULNDB",
        ),
        (
            Ecosystem::Packagist,
            &args.packagist_vuln_db,
            "PACKAGISTVULNDB",
        ),
        (Ecosystem::NuGet, &args.nuget_vuln_db, "NUGETVULNDB"),
        (Ecosystem::Julia, &args.julia_vuln_db, "JULIAVULNDB"),
        (Ecosystem::Swift, &args.swift_vuln_db, "SWIFTVULNDB"),
        (Ecosystem::Hex, &args.hex_vuln_db, "HEXVULNDB"),
        (
            Ecosystem::GitHubActions,
            &args.ghactions_vuln_db,
            "GHACTIONSVULNDB",
        ),
        (Ecosystem::Cargo, &args.crates_vuln_db, "CRATESVULNDB"),
        (Ecosystem::Maven, &args.maven_vuln_db, "MAVENVULNDB"),
    ];
    pairs
        .into_iter()
        .filter_map(|(eco, flag, env)| {
            flag.clone()
                .or_else(|| std::env::var(env).ok())
                .filter(|s| !s.is_empty())
                .map(|v| (eco, v))
        })
        .collect()
}

/// Find the govulncheck binary: an explicit `--govulncheck` path if it exists,
/// else the first `govulncheck` on `PATH`, `$GOPATH/bin`, or `~/go/bin`.
fn locate_govulncheck(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return path.is_file().then(|| path.to_path_buf());
    }
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    if let Some(gopath) = std::env::var_os("GOPATH") {
        dirs.extend(std::env::split_paths(&gopath).map(|p| p.join("bin")));
    }
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join("go").join("bin"));
    }
    dirs.into_iter()
        .map(|d| d.join("govulncheck"))
        .find(|p| p.is_file())
}

pub(crate) fn run_scan(args: ScanArgs) -> u8 {
    match scan_and_report(&args) {
        Ok(code) | Err(code) => code,
    }
}

/// The scan pipeline, phase by phase. Each phase that can stop the run returns `Err` with
/// the exit code, having already said why.
fn scan_and_report(args: &ScanArgs) -> Result<u8, u8> {
    refuse_narrowed_history(args)?;
    // --explain short-circuits (§10.1): load DB, print one advisory, exit.
    // It needs no fleet.toml.
    if let Some(id) = &args.explain {
        return explain(args, id);
    }
    let (config, materialized) = load_fleet(args)?;
    // --why short-circuits (§10.1): a dependency-tree query, no advisory DB.
    if let Some(package) = &args.why {
        return Ok(run_why(&config, package));
    }
    let triage = crate::triage::load_or_fail(&config, args.triage_dir.as_deref())?;
    let db = advisory_db(args)?;
    let vex_policy = oci_vex_policy(args, &config).map_err(|e| fail(&e))?;
    let mut images = crate::images::prepare_all(&config.images, args.offline, vex_policy.as_ref());
    for image in &images {
        if let Some(why) = &image.vex_problem {
            eprintln!(
                "warning: no attached VEX read for image {}, so its findings stand: {why}",
                image.source
            );
        }
        for document in image.attested.iter().flat_map(|a| &a.documents) {
            if let Some(why) = &document.refused {
                eprintln!(
                    "warning: VEX {} on image {} not applied: {why}",
                    document.digest, image.source
                );
            }
        }
    }
    let feeds = Feeds::resolve(args, &config, &images)?;
    let mut scan = scan_fleet_with(
        &db,
        &config,
        feeds.toolchain.as_ref(),
        feeds.host.as_deref(),
        &feeds.go(args),
        &feeds.mirrors(),
        &feeds.images(args, &images),
    );
    let attested: Vec<crate::oci_vex::Attested> = images
        .iter_mut()
        .filter_map(|image| image.attested.take())
        .collect();
    // The images' temporary lockfile copies are removed here.
    drop(images);
    let fleet_packages = add_fleet_signals(args, &config, &feeds, &materialized, &mut scan)?;
    note_scan(args, &scan);
    let coverage_incomplete = !scan.coverage.is_empty();
    let Assembled {
        report: mut fleet_report,
        suppressed,
    } = assemble_report(
        args,
        &config,
        &db,
        &feeds,
        &materialized,
        scan,
        &Decisions {
            attested: &attested,
            triage: &triage.suppressions,
        },
    );
    let exploitation_known = enrich_report(args, &mut fleet_report);
    assess_reachability(args, &config, &mut fleet_report)?;
    let baseline_new = apply_baseline(args, &mut fleet_report)?;
    // 5b2. Fleet evidence for upgrades (spec 13): the versions of each vulnerable package
    //      every repo runs, so the fix queue can say which bumps the fleet already survived.
    crate::evidence::annotate(&mut fleet_report, &config.repos);
    decide_ssvc(args, &config, &mut fleet_report, exploitation_known)?;

    // 6. Render: machine payload to stdout, human summary to stderr.
    let payload = render(args, &config, &fleet_report, &suppressed)?;
    println!("{payload}");
    if !args.quiet {
        eprintln!("{}", report::summary_line(&fleet_report));
    }

    let code = gate(args, &fleet_report, baseline_new, coverage_incomplete);
    // An expired decision is a failure whatever the gate's level: someone owes a new one.
    let code = combine_baseline(code, triage.report_expired(&fleet_report));
    record_history(
        args,
        &config,
        &fleet_report,
        &suppressed,
        code,
        fleet_packages,
    )?;
    Ok(code)
}

/// `--history-dir` records the whole fleet, so it refuses the flags that drop findings.
fn refuse_narrowed_history(args: &ScanArgs) -> Result<(), u8> {
    if args.history_dir.is_some() {
        let narrowing = [
            (args.baseline.is_some(), "--baseline"),
            (args.min_severity.is_some(), "--min-severity"),
            (args.min_epss.is_some(), "--min-epss"),
            (args.ignore_dev_deps, "--ignore-dev-deps"),
            (args.ignore_phantom, "--ignore-phantom"),
            (args.reachable_only, "--reachable-only"),
        ];
        let used: Vec<&str> = narrowing
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, f)| *f)
            .collect();
        if !used.is_empty() {
            return Err(usage_fail(&format!(
                "--history-dir records the whole fleet; {} would drop findings that history \
                 would then count as fixed",
                used.join(", ")
            )));
        }
    }
    Ok(())
}

/// `--explain`: one advisory from the DB, sanitized for the terminal.
fn explain(args: &ScanArgs, id: &str) -> Result<u8, u8> {
    let db = load_db(args).map_err(|e| fail(&e))?;
    Ok(match db.explain(id) {
        Ok(Some(detail)) => {
            // The advisory detail is untrusted DB markdown; neutralize terminal
            // control sequences while keeping newlines so it still reads.
            println!("{}", fleetreach_report::sanitize_text(&detail));
            0
        }
        Ok(None) => fail(&format!("advisory {id} not found in the database")),
        Err(e) => fail(&e.to_string()),
    })
}

/// The git work tree around the working directory (the nearest ancestor holding `.git`, a
/// directory or a worktree's file), else the working directory itself.
fn current_repo_root() -> Result<PathBuf, String> {
    let cwd =
        std::env::current_dir().map_err(|e| format!("cannot read the working directory: {e}"))?;
    Ok(cwd
        .ancestors()
        .find(|d| d.join(".git").exists())
        .unwrap_or(&cwd)
        .to_path_buf())
}

/// The fleet: `fleet.toml` plus the repos its `[[source]]` entries expand to.
fn load_fleet(args: &ScanArgs) -> Result<(Config, sources::Materialized), u8> {
    // 1. Config (§10.2): any failure is a could-not-scan -> 2.
    //    No `-c` and no ./fleet.toml: with only `--image`, the fleet is empty; otherwise the
    //    repo around the working directory is the fleet.
    let default = Path::new("fleet.toml");
    let mut config = match (&args.repo, &args.config) {
        (Some(dir), _) => Config::single_repo(dir),
        (None, Some(path)) => Config::load(path),
        (None, None) if default.exists() => Config::load(default),
        (None, None) if !args.images.is_empty() => {
            Config::from_str("", Path::new("."), "<no fleet.toml>")
        }
        (None, None) => {
            let dir = current_repo_root().map_err(|e| fail(&e))?;
            if !args.quiet {
                eprintln!(
                    "note: no ./fleet.toml; scanning {} as a one-repo fleet",
                    dir.display()
                );
            }
            Config::single_repo(&dir)
        }
    }
    .map_err(|e| fail(&e.to_string()))?;
    for path in &args.images {
        let reference = path.to_str().and_then(|p| p.strip_prefix("docker://"));
        if reference.is_none() && !path.exists() {
            return Err(fail(&format!(
                "--image {}: no such file or directory",
                path.display()
            )));
        }
        let image = match reference {
            Some(reference) => crate::images::from_reference(reference)
                .map_err(|e| fail(&format!("--image: {e}")))?,
            None => crate::images::from_arg(path),
        };
        let taken = config.repos.iter().any(|r| r.id == image.id)
            || config.images.iter().any(|i| i.id == image.id);
        if taken {
            return Err(fail(&format!(
                "--image {}: id `{}` is already used by the fleet; declare it as an [[image]] \
                 with its own id instead",
                path.display(),
                image.id.0
            )));
        }
        config.images.push(image);
    }

    // 1a. Fleet sources (spec 06): expand `[[source]]` into repos. With --sync, list afresh
    //     and clone/refresh; without, use the cached listing and existing checkouts. A
    //     listing that cannot be read stops the run: the fleet itself is unknown.
    let materialized =
        sources::materialize(&config, args.sync, args.quiet).map_err(|e| fail(&e))?;
    config.repos.extend(materialized.repos.iter().cloned());
    for (id, context) in &materialized.context {
        config
            .context
            .entry(id.clone())
            .or_insert_with(|| context.clone());
    }
    if config.repos.is_empty() && !materialized.failed.is_empty() {
        for (repo, reason) in &materialized.failed {
            eprintln!("error: {repo}: {reason}");
        }
        return Err(fail("no fleet-source repo could be checked out"));
    }

    Ok((config, materialized))
}

/// The RustSec DB, held to `--max-db-age`.
fn advisory_db(args: &ScanArgs) -> Result<AdvisoryDb, u8> {
    // 2. Advisory DB (§10.3): network failure / unusable -> 2, loud, never clean.
    let db = load_db(args).map_err(|e| fail(&e))?;

    // 3. Freshness gate (§3): cannot prove freshness -> 2.
    if let Some(spec) = &args.max_db_age {
        check_db_age(&db, spec).map_err(|e| fail(&e))?;
    }
    Ok(db)
}

/// What each ecosystem is scanned with: the toolchain, the host for feature resolution,
/// govulncheck and the Go DB, the OSV export of every toolchain-free ecosystem the fleet
/// has, and the Maven POM remote.
struct Feeds {
    toolchain: Option<crate::orchestrate::Toolchain>,
    host: Option<String>,
    go_govulncheck: Option<PathBuf>,
    go_db: Option<String>,
    osv_sources: BTreeMap<Ecosystem, osvdb::OsvSource>,
    /// The distro exports the images need, and the distro ecosystems with none.
    distro_sources: Vec<osvdb::DistroSource>,
    distro_missing: std::collections::BTreeSet<String>,
    urls: BTreeMap<Ecosystem, String>,
    maven_remote: Option<crate::maven_repo::Remote>,
    /// `[settings.advisories] dir`, read and checked once (spec 16, row 12).
    overlay: Option<crate::overlay::Overlay>,
}

impl Feeds {
    fn resolve(
        args: &ScanArgs,
        config: &Config,
        images: &[crate::images::Prepared],
    ) -> Result<Feeds, u8> {
        // 4. Scan the fleet, plus the toolchain if rustc is detectable. With
        //    --resolve-features, also annotate findings built/phantom for the host.
        let toolchain = detect_toolchain();
        // --ignore-phantom needs the build set, so it implies feature resolution.
        let host = if args.resolve_features || args.ignore_phantom {
            let detected = resolve::host_triple();
            if detected.is_none() {
                eprintln!(
                    "warning: feature resolution requested but host triple undetected; skipping"
                );
            }
            detected
        } else {
            None
        };
        // Go repos are scanned by govulncheck, which compiles the module — gate it on
        // the same consent as static reachability. Absent consent, Go repos surface as
        // an honest Errored gap (handled in orchestrate), never silently skipped.
        let go_govulncheck = if args.allow_untrusted_builds {
            locate_govulncheck(args.govulncheck.as_deref())
        } else {
            None
        };
        // The Go vuln-DB mirror: the explicit flag wins, else the conventional
        // GOVULNDB env var. A `file://` value lets a confined Go scan run offline.
        let go_vuln_db = args
            .go_vuln_db
            .clone()
            .or_else(|| std::env::var("GOVULNDB").ok())
            .filter(|s| !s.is_empty());
        // The OSV exports for the toolchain-free feeders (spec 01). Each ecosystem resolves from
        // its explicit flag (or env var), then the one OSV directory, then the default cache,
        // which network builds keep fresh. Only ecosystems the fleet actually has are resolved,
        // so a Rust-only fleet fetches only crates.io's.
        let mut needed = fleet_ecosystems(config);
        needed.extend(crate::images::language_ecosystems(images));
        needed.sort();
        needed.dedup();
        // Go needs the osv.dev export only for its offline matcher: not when govulncheck runs,
        // and not when a `file://` vuln.go.dev mirror is given.
        if go_govulncheck.is_some()
            || go_vuln_db
                .as_deref()
                .is_some_and(|d| d.starts_with("file://"))
        {
            needed.retain(|e| *e != Ecosystem::Go);
        }
        let explicit = explicit_osv_dbs(args);
        let osv_opts = osvdb::Options {
            dir: args
                .osv_dir
                .clone()
                .or_else(|| std::env::var_os(osvdb::DIR_ENV).map(PathBuf::from))
                .or_else(|| config.osv.dir.clone()),
            cache: osvdb::default_cache_dir(),
            sync: cfg!(feature = "network") && !args.offline && osvdb::sync_enabled_by_env(),
            refresh: config.osv.refresh.unwrap_or(osvdb::DEFAULT_REFRESH),
            quiet: args.quiet,
        };
        let (osv_sources, osv_warnings) = osvdb::resolve_all(&needed, &explicit, &osv_opts);
        for warning in &osv_warnings {
            eprintln!("warning: {warning}");
        }
        let unresolved: Vec<&str> = needed
            .iter()
            .filter(|eco| !osv_sources.contains_key(eco) && !explicit.contains_key(eco))
            .filter_map(|&eco| osvdb::osv_name(eco))
            .collect();
        if !unresolved.is_empty() {
            eprintln!(
                "note: no OSV export for {}; run `fleetreach db sync` (network build) or pass \
                 --osv-dir <dir> laid out as <dir>/<Ecosystem>/all.zip",
                unresolved.join(", ")
            );
        }
        // Freshness gate for OSV data, same contract as the RustSec gate above.
        if let Some(spec) = &args.max_db_age {
            let limit = match parse_duration_secs(spec) {
                Ok(limit) => limit,
                Err(e) => return Err(fail(&e)),
            };
            if let Err(e) = osvdb::check_ages(&osv_sources, limit, std::time::SystemTime::now()) {
                return Err(fail(&e));
            }
        }
        // The distro exports of the images, each distro fetched on its own (never all of them:
        // some are over a gigabyte). A distro with no export errors its images in the scan.
        let distro_ecosystems = crate::images::distro_ecosystems(images);
        let (distro_sources, distro_warnings, distro_missing) =
            osvdb::resolve_distros(&distro_ecosystems, &osv_opts);
        for warning in &distro_warnings {
            eprintln!("warning: {warning}");
        }
        if let Some(spec) = &args.max_db_age {
            let limit = parse_duration_secs(spec).map_err(|e| fail(&e))?;
            osvdb::check_distro_ages(&distro_sources, limit, std::time::SystemTime::now())
                .map_err(|e| fail(&e))?;
        }
        // The organization's own advisories: a configured overlay that cannot be read stops
        // the scan, since a correction silently not applied could hide a finding.
        let overlay = match config.osv.advisories.as_deref() {
            Some(dir) => {
                let overlay = crate::overlay::inspect(dir).map_err(|e| fail(&e))?;
                for warning in overlay.warnings() {
                    eprintln!("warning: {warning}");
                }
                Some(overlay)
            }
            None => None,
        };
        // Each toolchain-free ecosystem's mirror: the resolved export, else its explicit flag.
        let mut urls: BTreeMap<Ecosystem, String> = explicit;
        for (eco, source) in &osv_sources {
            urls.insert(*eco, source.url());
        }
        // govulncheck takes the configured DB as is; the offline matcher takes a `file://`
        // vuln.go.dev mirror, else the osv.dev Go export.
        let go_db = if go_govulncheck.is_some() {
            go_vuln_db.clone()
        } else {
            go_vuln_db
                .clone()
                .filter(|d| d.starts_with("file://"))
                .or_else(|| urls.get(&Ecosystem::Go).cloned())
        };
        // Read once: a mirror that is configured but unusable stops the scan rather than letting
        // POM requests fall back to Maven Central.
        let maven_remote = args.maven.remote(args.verbose).map_err(|e| fail(&e))?;
        Ok(Feeds {
            toolchain,
            host,
            go_govulncheck,
            go_db,
            osv_sources,
            distro_sources,
            distro_missing: distro_missing.into_iter().collect(),
            urls,
            maven_remote,
            overlay,
        })
    }

    fn go<'a>(&'a self, args: &'a ScanArgs) -> GoScan<'a> {
        GoScan {
            govulncheck: self.go_govulncheck.as_deref(),
            sandbox: args.build_sandbox.into(),
            vuln_db: self.go_db.as_deref(),
            offline: args.offline,
        }
    }

    fn images<'a>(
        &self,
        args: &ScanArgs,
        prepared: &'a [crate::images::Prepared],
    ) -> crate::orchestrate::Images<'a> {
        crate::orchestrate::Images {
            prepared,
            exports: self.distro_sources.iter().map(|s| s.path.clone()).collect(),
            frozen: self
                .distro_sources
                .iter()
                .filter_map(|s| Some((s.path.clone(), s.frozen.clone()?)))
                .collect(),
            missing: self.distro_missing.clone(),
            opts: fleetreach_os::ScanOptions {
                ignore_unimportant: args.distro_ignore_unimportant,
            },
        }
    }

    fn mirrors(&self) -> Mirrors<'_> {
        let url = |eco| self.urls.get(&eco).map(String::as_str);
        Mirrors {
            npm: url(Ecosystem::Npm),
            pypi: url(Ecosystem::Pypi),
            rubygems: url(Ecosystem::RubyGems),
            packagist: url(Ecosystem::Packagist),
            nuget: url(Ecosystem::NuGet),
            julia: url(Ecosystem::Julia),
            swift: url(Ecosystem::Swift),
            hex: url(Ecosystem::Hex),
            ghactions: url(Ecosystem::GitHubActions),
            crates: url(Ecosystem::Cargo),
            maven: url(Ecosystem::Maven),
            maven_remote: self.maven_remote.as_ref(),
        }
    }
}

/// Supply-chain signals, fleet novelty and release age, plus the fleet-source repos that
/// could not be checked out. Returns the fleet's packages when history will record them.
fn add_fleet_signals(
    args: &ScanArgs,
    config: &Config,
    feeds: &Feeds,
    materialized: &sources::Materialized,
    scan: &mut crate::orchestrate::ScanData,
) -> Result<Option<Vec<crate::signals::FleetPackage>>, u8> {
    let maven_remote = feeds.maven_remote.as_ref();
    if args.signals {
        scan.warnings.extend(crate::signals::fleet_signals(
            &config.repos,
            &config.signal_registries,
        ));
    }
    // The fleet's packages, read once: recorded in the history, and checked against it for
    // fleet novelty.
    let fleet_packages = args
        .history_dir
        .as_ref()
        .map(|_| crate::signals::fleet_packages(&config.repos, maven_remote));
    if let (true, Some(dir), Some(packages)) = (args.signals, &args.history_dir, &fleet_packages) {
        match novelty(dir, packages) {
            Ok(Some(finding)) => scan.warnings.push(finding),
            Ok(None) => {}
            Err(note) => eprintln!("note: fleet novelty not checked: {note}"),
        }
    }
    if let Some(spec) = &args.release_age {
        let secs = match parse_duration_secs(spec) {
            Ok(secs) => secs,
            Err(e) => return Err(fail(&format!("--release-age: {e}"))),
        };
        match crate::signals::release_age(&config.repos, secs, maven_remote) {
            Ok(findings) => scan.warnings.extend(findings),
            Err(e) => return Err(fail(&format!("--release-age: {e}"))),
        }
    }
    scan.outcomes.extend(
        materialized
            .failed
            .iter()
            .map(|(repo, reason)| RepoOutcome {
                repo: repo.clone(),
                status: ScanStatus::Errored {
                    reason: format!("fleet source: {reason}"),
                },
            }),
    );

    Ok(fleet_packages)
}

/// What the scan could not do in full, on stderr.
fn note_scan(args: &ScanArgs, scan: &crate::orchestrate::ScanData) {
    if args.verbose {
        for outcome in &scan.outcomes {
            eprintln!("  {} — {:?}", outcome.repo, outcome.status);
        }
    }

    // Surface toolchain-free packages skipped for an unparseable version, so the skip is
    // visible rather than silent. These are pins with no registry release (a VCS/URL/path
    // dependency), which carry no registry advisory — benign, but worth showing so a
    // malformed-but-real version the parser wrongly rejects is not mistaken for "clean".
    if scan.skipped_unparseable > 0 {
        eprintln!(
            "note: skipped {} package(s) with an unrecognized version format \
             (non-registry pins have no advisory to match)",
            scan.skipped_unparseable
        );
    }

    // Sources read with less than full coverage (C1): unreadable lockfile formats, manifests
    // that only declare direct dependencies. The repo still scans what it can, so this is a
    // visible note (and a gate under --require-full-coverage), not an errored gap.
    if !scan.coverage.is_empty() {
        eprintln!(
            "note: {} source(s) scanned with incomplete coverage (findings outside what was \
             read were never matched):",
            scan.coverage.len()
        );
        for gap in &scan.coverage {
            eprintln!(
                "  {}: {} [{}] {}",
                fleetreach_report::sanitize_cell(&gap.repo.0),
                fleetreach_report::sanitize_cell(&gap.source),
                gap.level.label(),
                fleetreach_report::sanitize_cell(&gap.reason),
            );
        }
    }
}

/// What may read attached VEX, when the scan was asked to.
fn oci_vex_policy(
    args: &ScanArgs,
    config: &Config,
) -> Result<Option<crate::oci_vex::Policy>, String> {
    let vex = &config.vex;
    let mut keys = args.vex_oci_key.clone();
    keys.extend(vex.oci_keys.iter().cloned());
    let unsigned = args.vex_oci_unsigned || vex.oci_unsigned;
    if !(args.vex_oci || vex.oci || unsigned || !keys.is_empty()) {
        return Ok(None);
    }
    crate::oci_vex::Policy::load(&keys, unsigned).map(Some)
}

/// The report: findings with ignores and VEX assertions applied, then phantom and dev-only
/// findings dropped when asked.
/// What people decided about findings, beside the fleet's config.
struct Decisions<'a> {
    attested: &'a [crate::oci_vex::Attested],
    triage: &'a [Suppression],
}

fn assemble_report(
    args: &ScanArgs,
    config: &Config,
    db: &AdvisoryDb,
    feeds: &Feeds,
    materialized: &sources::Materialized,
    scan: crate::orchestrate::ScanData,
    decisions: &Decisions<'_>,
) -> Assembled {
    // 5. Assemble. Ignores + vex_assertions suppress findings; the removed
    //    occurrences are captured for VEX promotion (used only by `-f vex`).
    let mut provenance = build_provenance(&db.meta());
    provenance.osv = feeds
        .osv_sources
        .values()
        .map(osvdb::OsvSource::provenance)
        .chain(
            feeds
                .distro_sources
                .iter()
                .map(osvdb::DistroSource::provenance),
        )
        .chain(
            feeds
                .overlay
                .as_ref()
                .map(crate::overlay::Overlay::provenance),
        )
        .collect();
    provenance.sources = materialized.provenance.clone();
    provenance.images.clone_from(&scan.pulled);
    let mut suppressions: Vec<Suppression> = config
        .ignores
        .iter()
        .map(Suppression::from_ignore)
        .collect();
    suppressions.extend(
        config
            .vex_assertions
            .iter()
            .map(Suppression::from_assertion),
    );
    let (image_vex, set_aside) =
        crate::oci_vex::suppressions(decisions.attested, &scan.vulnerabilities);
    if !image_vex.is_empty() {
        eprintln!(
            "set aside {} finding(s) on VEX attached to images",
            image_vex.len()
        );
    }
    suppressions.extend(image_vex);
    suppressions.extend_from_slice(decisions.triage);
    for attestation in provenance.images.iter_mut().flat_map(|i| &mut i.vex) {
        attestation.set_aside = set_aside.get(&attestation.digest).copied().unwrap_or(0);
    }
    let mut assembled = assemble(
        scan,
        &suppressions,
        args.min_severity.map(Severity::from),
        provenance,
    );
    let fleet_report = &mut assembled.report;

    // 5a. Suppress phantom findings (unbuilt optional deps), if requested.
    if args.ignore_phantom {
        let dropped = drop_phantom(fleet_report);
        if dropped > 0 && !args.quiet {
            eprintln!("suppressed {dropped} finding(s) on packages not in the default build");
        }
    }

    // 5a1. Suppress dev/build-only findings, if requested.
    if args.ignore_dev_deps {
        let dropped = drop_dev(fleet_report);
        if dropped > 0 && !args.quiet {
            eprintln!("suppressed {dropped} finding(s) on dev/build-only packages");
        }
    }
    assembled
}

/// Exploit-risk enrichment (KEV and EPSS). Returns whether SSVC Exploitation is known.
fn enrich_report(args: &ScanArgs, fleet_report: &mut FleetReport) -> bool {
    // 5a2. Exploit-risk enrichment (KEV + EPSS), opt-in. Annotate, optionally
    //      filter by EPSS, then re-rank by exploit risk (the action queue).
    let enrich_requested = args.enrich
        || args.fail_on_kev
        || args.fail_on_ssvc.is_some()
        || args.min_epss.is_some()
        || args.kev_file.is_some()
        || args.epss_file.is_some();
    // SSVC Exploitation is only known once the KEV catalog was loaded; an EPSS file alone
    // cannot say a finding is not actively exploited.
    let mut exploitation_known = false;
    if enrich_requested {
        let from_files = args.kev_file.is_some() || args.epss_file.is_some();
        let loaded = if args.kev_file.is_some() || args.epss_file.is_some() {
            Enrichment::from_files(args.kev_file.as_deref(), args.epss_file.as_deref())
        } else if args.offline {
            // `--offline` must mean no network: do not silently fetch KEV/EPSS/NVD
            // (which would also leak the fleet's CVE list to a third party).
            Err(
                "enrichment needs the network; with --offline supply --kev-file / \
                 --epss-file (NVD CVSS backfill is unavailable offline)"
                    .to_string(),
            )
        } else {
            fetch_enrichment(fleet_report)
        };
        match loaded {
            Ok(enrichment) => {
                exploitation_known = !from_files || args.kev_file.is_some();
                enrichment.apply(&mut fleet_report.vulnerabilities);
                // apply() backfills `unknown` severities from NVD CVSS, so the summary
                // (built pre-enrichment) must be refreshed or it reports a stale
                // max_severity (e.g. `unknown` for a fleet that is actually critical).
                fleet_report.refresh_summary();
                if let Some(min) = args.min_epss {
                    let dropped = retain_min_epss(fleet_report, min);
                    if !dropped.is_empty() && !args.quiet {
                        // A network-sourced EPSS score hides a finding, so list
                        // exactly which advisories it suppressed (auditable).
                        eprintln!(
                            "filtered {} finding(s) below EPSS {min} (network-sourced scores):",
                            dropped.len()
                        );
                        for (id, epss) in &dropped {
                            eprintln!("  {id} (epss {:.0}%)", epss * 100.0);
                        }
                    }
                }
                enrich::rank(&mut fleet_report.vulnerabilities);
            }
            Err(e) => eprintln!("warning: enrichment failed: {e}"),
        }
    }
    exploitation_known
}

/// Reachability, when asked for, and `--reachable-only`.
fn assess_reachability(
    args: &ScanArgs,
    config: &Config,
    fleet_report: &mut FleetReport,
) -> Result<(), u8> {
    // 5a3. Reachability (opt-in). `--reachable-only` implies the heuristic when no
    //      mode is given. The static engine sets the legacy `reachable` bool too,
    //      so `--reachable-only` drops a sound `NotReachable` via the same path.
    let reach_mode = args.reachability.or_else(|| {
        (args.reachable_only || args.npm_prune_unreachable).then_some(ReachMode::Heuristic)
    });
    if let Some(mode) = reach_mode {
        match mode {
            ReachMode::Heuristic => {
                // npm and PyPI are assessed by their import-graph engines below, which
                // resolve first-party imports themselves, so the grep skips them.
                reach::assess_except(fleet_report, config, &[Ecosystem::Npm, Ecosystem::Pypi]);
                // npm gets the richer module-import-graph engine (transitive reachability +
                // a witness chain; sound-positive, with an opt-in best-effort NotReachable),
                // overriding the grep heuristic for npm findings.
                npm_reach::assess(
                    fleet_report,
                    config,
                    &npm_reach::Options {
                        prune: args.npm_prune_unreachable,
                    },
                );
                // PyPI likewise gets a package import graph over the repo's virtualenv(s):
                // transitive reachability with a witness chain, positive-only.
                py_reach::assess(fleet_report, config);
            }
            ReachMode::Static => {
                // Static reachability COMPILES each repo, which runs its build
                // scripts and proc-macros — arbitrary code execution. Unlike the
                // rest of the tool (which only reads Cargo.lock), this requires
                // explicit, informed consent and warns loudly before any build.
                if !args.allow_untrusted_builds {
                    return Err(fail(
                        "--reachability=static COMPILES each scanned repo, executing its build \
                         scripts and proc-macros (arbitrary code). Re-run with \
                         --allow-untrusted-builds only if you trust every repo in the fleet.",
                    ));
                }
                let Some(driver) = args.reach_driver.as_deref() else {
                    return Err(fail("--reachability=static requires --reach-driver <PATH>"));
                };
                let sandbox = args.build_sandbox.into();
                let confinement = match args.build_sandbox {
                    BuildSandbox::Off => "UNCONFINED (--build-sandbox=off)",
                    BuildSandbox::Auto => {
                        "sandboxed if a mechanism is available (--build-sandbox=auto)"
                    }
                    BuildSandbox::Require => {
                        "sandboxed, or skipped if no mechanism (--build-sandbox=require)"
                    }
                };
                eprintln!(
                    "warning: static reachability is about to BUILD {} repo(s), running their \
                     build scripts and proc-macros: {confinement}. Only trusted repos should be \
                     scanned this way.",
                    config.repos.len(),
                );
                let features = fleetreach_reach::FeatureSelection {
                    all_features: args.all_features,
                    no_default_features: args.no_default_features,
                    features: args.features.clone(),
                };
                static_reach::assess(
                    fleet_report,
                    config,
                    &static_reach::Options {
                        driver,
                        features,
                        sandbox,
                        verbose: args.verbose,
                    },
                );
            }
        }
        if args.reachable_only {
            let dropped = retain_reachable(fleet_report);
            if dropped > 0 && !args.quiet {
                let how = match mode {
                    ReachMode::Heuristic => "not found in your source (heuristic)",
                    ReachMode::Static => "proven unreachable (static)",
                };
                eprintln!("dropped {dropped} finding(s) {how}");
            }
        }
    }
    Ok(())
}

/// `--baseline`: keep only findings new since the prior report. Returns whether any are.
fn apply_baseline(args: &ScanArgs, fleet_report: &mut FleetReport) -> Result<bool, u8> {
    // 5b. Baseline diff (§10.7): keep only findings new since the prior report.
    let mut baseline_new = false;
    if let Some(path) = &args.baseline {
        let json = match std::fs::read_to_string(path) {
            Ok(json) => json,
            Err(e) => return Err(fail(&format!("reading baseline `{}`: {e}", path.display()))),
        };
        let ids = match report::baseline_ids_from_json(&json) {
            Ok(ids) => ids,
            Err(e) => return Err(fail(&format!("parsing baseline `{}`: {e}", path.display()))),
        };
        retain_new(fleet_report, &ids);
        baseline_new =
            !fleet_report.vulnerabilities.is_empty() || !fleet_report.warnings.is_empty();
    }
    Ok(baseline_new)
}

/// Exposure context and SSVC decisions, and the `--fail-on-ssvc` precondition.
fn decide_ssvc(
    args: &ScanArgs,
    config: &Config,
    fleet_report: &mut FleetReport,
    exploitation_known: bool,
) -> Result<(), u8> {
    // 5c. Exposure context and SSVC decisions (spec 08), on what is left to report. CISA's
    //     own assessments (Vulnrichment) are looked up only when there is something to decide.
    let cisa = if crate::ssvc::enabled(config) && exploitation_known {
        let cves: Vec<String> = fleet_report
            .vulnerabilities
            .iter()
            .flat_map(|v| std::iter::once(&v.advisory_id).chain(&v.aliases))
            .filter(|id| crate::enrich::is_valid_cve(id))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        match &args.vulnrichment_dir {
            Some(dir) => crate::vulnrichment::from_dir(dir, &cves),
            None => vulnrichment_fetch(&cves, args.kev_file.is_some() || args.epss_file.is_some()),
        }
    } else {
        Default::default()
    };
    crate::ssvc::annotate(
        fleet_report,
        config,
        crate::ssvc::Inputs {
            exploitation_known,
            poc_epss: config.ssvc_poc_epss,
            cisa: &cisa,
        },
    );
    if let Some(threshold) = args.fail_on_ssvc {
        let why_not = match &fleet_report.ssvc {
            None => Some(
                "--fail-on-ssvc needs repo context: set exposure and impact on [[repo]] or in \
                 [settings.context.defaults]"
                    .to_string(),
            ),
            Some(s) => s.not_computed.clone(),
        };
        if let Some(why) = why_not {
            if !args.quiet {
                eprintln!(
                    "error: no SSVC decisions under --fail-on-ssvc {}: {why}",
                    threshold.0
                );
            }
            return Err(2);
        }
    }
    if !args.quiet {
        if let Some(s) = &fleet_report.ssvc {
            if let Some(why) = &s.not_computed {
                eprintln!("note: SSVC decisions not computed: {why}");
            }
            let fail_closed: Vec<&str> = fleet_report
                .context
                .iter()
                .filter(|c| c.fail_closed)
                .map(|c| c.repo.0.as_str())
                .collect();
            if !fail_closed.is_empty() {
                eprintln!(
                    "note: {} repo(s) have incomplete context and were decided with the most \
                     urgent values: {}",
                    fail_closed.len(),
                    fail_closed.join(", ")
                );
            }
        }
    }
    Ok(())
}

/// The report in the requested format. Color only a TTY table — never JSON, never piped
/// output (§7).
fn render(
    args: &ScanArgs,
    config: &Config,
    fleet_report: &FleetReport,
    suppressed: &[SuppressedOccurrence],
) -> Result<String, u8> {
    Ok(match args.format {
        Format::Json => match report::to_json(fleet_report) {
            Ok(json) => json,
            Err(e) => return Err(fail(&format!("serializing report: {e}"))),
        },
        Format::Sarif => {
            // SARIF suppressions (§11): machine not_affected is computed in
            // to_sarif; approved human assertions are injected here.
            let product_ids = vex::resolve_product_ids(config);
            let assertions = vex::build_human_assertions(suppressed, &product_ids, false);
            let paths: BTreeMap<&str, &Path> = config
                .repos
                .iter()
                .map(|r| (r.id.0.as_str(), r.path.as_path()))
                .collect();
            let locate = |repo: &fleetreach_core::RepoId, ecosystem: Ecosystem, package: &str| {
                sarif_source(paths.get(repo.0.as_str()).copied(), ecosystem, package)
            };
            match report::to_sarif_located(fleet_report, &assertions, &locate) {
                Ok(sarif) => sarif,
                Err(e) => return Err(fail(&format!("serializing SARIF: {e}"))),
            }
        }
        Format::Table => report::to_table(fleet_report, std::io::stdout().is_terminal()),
        Format::Impact => report::to_impact(fleet_report, std::io::stdout().is_terminal()),
        Format::Blast => report::to_blast(fleet_report, std::io::stdout().is_terminal()),
        Format::Packages => report::to_packages(fleet_report, std::io::stdout().is_terminal()),
        Format::PackagesJson => match report::to_packages_json(fleet_report) {
            Ok(json) => json,
            Err(e) => return Err(fail(&format!("serializing packages: {e}"))),
        },
        Format::FixFirst => report::to_fix_first(fleet_report, std::io::stdout().is_terminal()),
        Format::Remediation => {
            report::to_remediation(fleet_report, std::io::stdout().is_terminal())
        }
        Format::Ssvc => report::to_ssvc(fleet_report, std::io::stdout().is_terminal()),
        Format::Owners => report::to_owners(fleet_report, std::io::stdout().is_terminal()),
        Format::RemediationJson => match report::to_remediation_json(fleet_report) {
            Ok(json) => json,
            Err(e) => return Err(fail(&format!("serializing remediation: {e}"))),
        },
        Format::Vex => {
            // Author/timestamp resolution fails closed as a usage error (§7.3 edge 8).
            let params = match build_vex_params(args, config, fleet_report, suppressed) {
                Ok(params) => params,
                Err(e) => return Err(usage_fail(&e)),
            };
            match report::to_vex(fleet_report, &params) {
                Ok(doc) => doc,
                Err(e) => return Err(fail(&format!("serializing VEX: {e}"))),
            }
        }
    })
}

/// The exit code per §8, plus the opt-in KEV, SSVC, baseline and full-coverage gates.
fn gate(
    args: &ScanArgs,
    fleet_report: &FleetReport,
    baseline_new: bool,
    coverage_incomplete: bool,
) -> u8 {
    // 7. Exit per §8, plus the opt-in KEV and baseline gates. `combine_baseline`
    //    elevates a clean/gated code to >=1 on its flag while preserving the
    //    untrustworthy `2`; we reuse it for KEV (any actively-exploited finding).
    let kev_hit = args.fail_on_kev && fleet_report.vulnerabilities.iter().any(|v| v.exploit.kev);
    // `--fail-on-ssvc` on its own replaces the severity gate, so SSVC decides; known
    // malware still fails the run whatever its decision.
    let severity_gate = args
        .fail_on
        .or_else(|| args.fail_on_ssvc.is_none().then_some(SeverityArg::Low));
    let gated;
    let gated_report = match severity_gate {
        Some(_) => fleet_report,
        None => {
            let mut only_malware = fleet_report.clone();
            only_malware
                .vulnerabilities
                .retain(crate::assemble::is_malware);
            gated = only_malware;
            &gated
        }
    };
    let code = exit_code(
        gated_report,
        &GateConfig {
            fail_on: severity_gate.unwrap_or(SeverityArg::Low).into(),
            fail_on_warnings: args.fail_on_warnings,
        },
    );
    let ssvc_hit = args
        .fail_on_ssvc
        .is_some_and(|t| crate::ssvc::gate_hit(fleet_report, t.0));
    let code = combine_baseline(combine_baseline(code, kev_hit), baseline_new);
    let code = combine_baseline(code, ssvc_hit);
    // --require-full-coverage: a source read only partly means the fleet cannot be called
    // clean, the same contract as an errored repo.
    let code = if args.require_full_coverage && coverage_incomplete {
        if !args.quiet {
            eprintln!("error: incomplete coverage under --require-full-coverage (see note above)");
        }
        2
    } else {
        code
    };
    code
}

/// Scan history (spec 09): the run as it gated. Failing to record what was asked for is a
/// failed run.
fn record_history(
    args: &ScanArgs,
    config: &Config,
    fleet_report: &FleetReport,
    suppressed: &[SuppressedOccurrence],
    code: u8,
    fleet_packages: Option<Vec<crate::signals::FleetPackage>>,
) -> Result<(), u8> {
    if let Some(dir) = &args.history_dir {
        let keys = crate::history::suppressed_keys(fleet_report, suppressed);
        let mut names: Vec<crate::history::PackageName> = fleet_packages
            .iter()
            .flatten()
            .map(crate::signals::FleetPackage::key)
            .collect();
        names.sort();
        names.dedup();
        match crate::history::record(dir, fleet_report, keys, code, config.history_keep, names) {
            Ok((path, notes)) => {
                for note in notes {
                    eprintln!("note: {note}");
                }
                if !args.quiet {
                    eprintln!("history: recorded {}", path.display());
                }
            }
            Err(e) => return Err(fail(&format!("recording history: {e}"))),
        }
    }
    Ok(())
}

/// The `new-to-fleet` finding against the history in `dir`. `Err` explains why there is no
/// baseline to judge against: no history yet, or none that recorded package names.
fn novelty(
    dir: &std::path::Path,
    packages: &[crate::signals::FleetPackage],
) -> Result<Option<fleetreach_core::WarnFinding>, String> {
    if !dir.exists() {
        return Err("this is the first recorded run; it becomes the baseline".to_string());
    }
    let history = crate::history::load(dir)?;
    let known = crate::history::known_packages(&history)
        .ok_or("no earlier run recorded package names; this run becomes the baseline")?;
    Ok(crate::signals::new_to_fleet(packages, &known))
}

/// CISA Vulnrichment over the network, only on the network enrichment path: the offline
/// `--kev-file` path sends nothing anywhere.
#[cfg(feature = "network")]
fn vulnrichment_fetch(cves: &[String], offline_enrich: bool) -> crate::vulnrichment::Vulnrichment {
    if offline_enrich {
        return Default::default();
    }
    crate::vulnrichment::fetch(cves)
}

#[cfg(not(feature = "network"))]
fn vulnrichment_fetch(_: &[String], _: bool) -> crate::vulnrichment::Vulnrichment {
    Default::default()
}

/// Resolve `-f vex` parameters from flags + `settings.vex` + the report, failing
/// closed when no author or timestamp resolves.
fn build_vex_params(
    args: &ScanArgs,
    config: &Config,
    fleet_report: &FleetReport,
    suppressed: &[SuppressedOccurrence],
) -> Result<report::VexParams, String> {
    let author = args
        .vex_author
        .clone()
        .or_else(|| config.vex.author.clone())
        .ok_or_else(|| "no VEX author: set --vex-author or settings.vex.author".to_string())?;

    // Per-statement provenance lives in `status_notes`; this is the document role.
    let role = args
        .vex_role
        .clone()
        .or_else(|| config.vex.role.clone())
        .or_else(|| Some("Document Creator".to_string()));

    let scope = args
        .vex_scope
        .map(Into::into)
        .or(config.vex.scope)
        .unwrap_or(report::VexScope::Runtime);

    // Reproducible by default: the advisory-DB commit time, never wall-clock (§9.1).
    let timestamp = args
        .vex_timestamp
        .clone()
        .or_else(|| fleet_report.provenance.db_timestamp.clone())
        .ok_or_else(|| {
            "no advisory-db commit time for the VEX timestamp; pass --vex-timestamp <RFC3339>"
                .to_string()
        })?;

    let base = config.vex.product_id_base.clone();
    let product_ids = vex::resolve_product_ids(config);
    let assertions = vex::build_human_assertions(suppressed, &product_ids, !args.vex_only_sound);

    Ok(report::VexParams {
        author,
        role,
        scope,
        timestamp,
        doc_id: args.vex_id.clone(),
        product_id_base: base,
        product_ids,
        assertions,
        only_sound: args.vex_only_sound,
        alias_rustbinary: args.vex_alias_rustbinary,
        include_fixed: args.vex_include_fixed,
        version: args.vex_version,
        supersedes: args.vex_supersedes.clone(),
    })
}

/// `--why`: print every route by which a package enters each repo's dependency
/// tree, in every ecosystem. Exits `0` if found anywhere, `2` if it is in no tree.
fn run_why(config: &Config, package: &str) -> u8 {
    use fleetreach_report::sanitize_cell;
    let mut found = false;
    for repo in &config.repos {
        for route in other_routes(repo, package) {
            found = true;
            let path: Vec<String> = route.path.iter().map(|s| sanitize_cell(s)).collect();
            println!(
                "{} — {} {} ({}, {}):",
                sanitize_cell(&repo.id.0),
                sanitize_cell(&route.name),
                sanitize_cell(&route.version),
                format!("{:?}", route.ecosystem).to_lowercase(),
                if route.direct { "direct" } else { "transitive" },
            );
            println!("  {}", path.join(" → "));
        }
        for lockfile in discover_lockfiles(repo).0 {
            match routes_to(&lockfile, package) {
                Ok(routes) => {
                    for route in routes {
                        found = true;
                        let kind = if route.direct { "direct" } else { "transitive" };
                        // package (arg), version + path segments (untrusted lockfile)
                        // are echoed to the terminal; neutralize control sequences.
                        let path: Vec<String> =
                            route.path.iter().map(|s| sanitize_cell(s)).collect();
                        println!(
                            "{} — {} {} ({kind}):",
                            sanitize_cell(&repo.id.0),
                            sanitize_cell(package),
                            sanitize_cell(&route.version),
                        );
                        println!("  {}", path.join(" → "));
                    }
                }
                Err(e) => eprintln!("warning: {}: {e}", repo.id),
            }
        }
    }
    if found {
        0
    } else {
        eprintln!("`{package}` is not in any repo's dependency tree");
        2
    }
}

/// One way a non-Cargo package enters a repo, for `--why`.
struct OtherRoute {
    ecosystem: Ecosystem,
    name: String,
    version: String,
    direct: bool,
    path: Vec<String>,
}

/// `--why` outside Cargo: the package in every other source the repo declares, matched by its
/// full name or its last segment (`log4j-core` for `org.apache.logging.log4j:log4j-core`,
/// `grpc` for `google.golang.org/grpc`), case-insensitively, with the shortest chain from the
/// source's dependency graph. A source without a graph shows the repo and the package alone.
fn other_routes(repo: &Repo, package: &str) -> Vec<OtherRoute> {
    use fleetreach_core::depgraph::DepGraph;
    use fleetreach_core::inventory::ROOT;
    let wanted = |name: &str| {
        let last = name.rsplit([':', '/']).next().unwrap_or(name);
        name.eq_ignore_ascii_case(package) || last.eq_ignore_ascii_case(package)
    };
    let inventory = crate::inventory::repo_inventory(repo);
    for error in &inventory.errors {
        eprintln!("warning: {}: {error}", repo.id);
    }
    let mut routes = Vec::new();
    for source in &inventory.sources {
        if source.ecosystem == Ecosystem::Cargo {
            continue;
        }
        let mut graph = DepGraph::new(ROOT);
        for (from, to) in &source.edges {
            graph.add_edges(from, [to.as_str()]);
        }
        for pkg in source.packages.iter().filter(|p| wanted(&p.name)) {
            let mut path = graph.chain_to(&pkg.name);
            if path.is_empty() {
                path = vec![ROOT.to_string(), pkg.name.clone()];
            }
            path[0] = repo.id.0.clone();
            routes.push(OtherRoute {
                ecosystem: source.ecosystem,
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                direct: pkg.direct,
                path,
            });
        }
    }
    routes
}
