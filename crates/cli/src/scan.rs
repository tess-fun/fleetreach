//! The `scan` command: parse `ScanArgs`, run the audit pipeline (config → fleet
//! scan → assemble → enrich → reachability → render), and return the exit code.
//! Also hosts the `--why`/`--explain` short-circuits and `-f vex` parameter build.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use clap::Parser;
use fleetreach_core::{FleetReport, Severity};
use fleetreach_report as report;
use fleetreach_scan::{routes_to, AdvisoryDb};

use crate::assemble::{
    assemble, combine_baseline, drop_phantom, exit_code, retain_min_epss, retain_new,
    retain_reachable, Assembled, GateConfig, SuppressedOccurrence, Suppression,
};
use crate::cli::{fail, usage_fail, BuildSandbox, Format, ReachMode, SeverityArg, VexScopeArg};
use crate::config::Config;
use crate::db::{build_provenance, check_db_age, detect_toolchain, fetch_enrichment, load_db_from};
use crate::enrich::{self, Enrichment};
use crate::orchestrate::{
    discover_lockfiles, scan_fleet, GhActionsScan, GoScan, HexScan, JuliaScan, MavenScan, NpmScan,
    NuGetScan, PackagistScan, PyPiScan, RubyGemsScan, SwiftScan,
};
use crate::{npm_reach, reach, resolve, static_reach, vex};

#[derive(Parser)]
pub(crate) struct ScanArgs {
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,
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
    #[arg(long, value_enum, default_value_t = SeverityArg::Low, help = "fail if any vuln at/above")]
    fail_on: SeverityArg,
    #[arg(long, help = "also fail if any warning is present")]
    fail_on_warnings: bool,

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
        help = "OSV vulnerability DB for the toolchain-free Maven (Java) matcher, as `file://<path>` to either the osv.dev Maven export `all.zip` (read directly, fastest) or a directory of unzipped OSV JSON records. It reads gradle.lockfile (preferred) or pom.xml and builds nothing, so it needs no --allow-untrusted-builds; without this a Maven repo is an honest gap."
    )]
    maven_vuln_db: Option<String>,
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

fn load_db(args: &ScanArgs) -> Result<AdvisoryDb, String> {
    load_db_from(args.db.as_deref(), args.db_rev.as_deref(), args.offline)
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
    // --explain short-circuits (§10.1): load DB, print one advisory, exit.
    // It needs no fleet.toml.
    if let Some(id) = &args.explain {
        let db = match load_db(&args) {
            Ok(db) => db,
            Err(e) => return fail(&e),
        };
        return match db.explain(id) {
            Ok(Some(detail)) => {
                // The advisory detail is untrusted DB markdown; neutralize terminal
                // control sequences while keeping newlines so it still reads.
                println!("{}", fleetreach_report::sanitize_text(&detail));
                0
            }
            Ok(None) => fail(&format!("advisory {id} not found in the database")),
            Err(e) => fail(&e.to_string()),
        };
    }

    // 1. Config (§10.2): any failure is a could-not-scan -> 2.
    let config = match Config::load(&args.config) {
        Ok(c) => c,
        Err(e) => return fail(&e.to_string()),
    };

    // --why short-circuits (§10.1): a dependency-tree query, no advisory DB.
    if let Some(package) = &args.why {
        return run_why(&config, package);
    }

    // 2. Advisory DB (§10.3): network failure / unusable -> 2, loud, never clean.
    let db = match load_db(&args) {
        Ok(db) => db,
        Err(e) => return fail(&e),
    };

    // 3. Freshness gate (§3): cannot prove freshness -> 2.
    if let Some(spec) = &args.max_db_age {
        if let Err(e) = check_db_age(&db, spec) {
            return fail(&e);
        }
    }

    // 4. Scan the fleet, plus the toolchain if rustc is detectable. With
    //    --resolve-features, also annotate findings built/phantom for the host.
    let toolchain = detect_toolchain();
    // --ignore-phantom needs the build set, so it implies feature resolution.
    let host = if args.resolve_features || args.ignore_phantom {
        let detected = resolve::host_triple();
        if detected.is_none() {
            eprintln!("warning: feature resolution requested but host triple undetected; skipping");
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
    // The npm OSV mirror: explicit flag, else the NPMVULNDB env var (mirrors GOVULNDB).
    let npm_vuln_db = args
        .npm_vuln_db
        .clone()
        .or_else(|| std::env::var("NPMVULNDB").ok())
        .filter(|s| !s.is_empty());
    // The PyPI OSV mirror: explicit flag, else the PYPIVULNDB env var (mirrors the above).
    let pypi_vuln_db = args
        .pypi_vuln_db
        .clone()
        .or_else(|| std::env::var("PYPIVULNDB").ok())
        .filter(|s| !s.is_empty());
    // The RubyGems OSV mirror: explicit flag, else the RUBYGEMSVULNDB env var (mirrors the above).
    let rubygems_vuln_db = args
        .rubygems_vuln_db
        .clone()
        .or_else(|| std::env::var("RUBYGEMSVULNDB").ok())
        .filter(|s| !s.is_empty());
    // The Packagist OSV mirror: explicit flag, else the PACKAGISTVULNDB env var (mirrors the above).
    let packagist_vuln_db = args
        .packagist_vuln_db
        .clone()
        .or_else(|| std::env::var("PACKAGISTVULNDB").ok())
        .filter(|s| !s.is_empty());
    // The NuGet OSV mirror: explicit flag, else the NUGETVULNDB env var (mirrors the above).
    let nuget_vuln_db = args
        .nuget_vuln_db
        .clone()
        .or_else(|| std::env::var("NUGETVULNDB").ok())
        .filter(|s| !s.is_empty());
    // The Julia OSV mirror: explicit flag, else the JULIAVULNDB env var (mirrors the above).
    let julia_vuln_db = args
        .julia_vuln_db
        .clone()
        .or_else(|| std::env::var("JULIAVULNDB").ok())
        .filter(|s| !s.is_empty());
    // The Swift OSV mirror: explicit flag, else the SWIFTVULNDB env var (mirrors the above).
    let swift_vuln_db = args
        .swift_vuln_db
        .clone()
        .or_else(|| std::env::var("SWIFTVULNDB").ok())
        .filter(|s| !s.is_empty());
    // The Hex OSV mirror: explicit flag, else the HEXVULNDB env var (mirrors the above).
    let hex_vuln_db = args
        .hex_vuln_db
        .clone()
        .or_else(|| std::env::var("HEXVULNDB").ok())
        .filter(|s| !s.is_empty());
    // The GitHub Actions OSV mirror: explicit flag, else the GHACTIONSVULNDB env var.
    let ghactions_vuln_db = args
        .ghactions_vuln_db
        .clone()
        .or_else(|| std::env::var("GHACTIONSVULNDB").ok())
        .filter(|s| !s.is_empty());
    // The Maven OSV mirror: explicit flag, else the MAVENVULNDB env var.
    let maven_vuln_db = args
        .maven_vuln_db
        .clone()
        .or_else(|| std::env::var("MAVENVULNDB").ok())
        .filter(|s| !s.is_empty());
    let scan = scan_fleet(
        &db,
        &config,
        toolchain.as_ref(),
        host.as_deref(),
        &GoScan {
            govulncheck: go_govulncheck.as_deref(),
            sandbox: args.build_sandbox.into(),
            vuln_db: go_vuln_db.as_deref(),
            offline: args.offline,
        },
        &NpmScan {
            vuln_db: npm_vuln_db.as_deref(),
        },
        &PyPiScan {
            vuln_db: pypi_vuln_db.as_deref(),
        },
        &RubyGemsScan {
            vuln_db: rubygems_vuln_db.as_deref(),
        },
        &PackagistScan {
            vuln_db: packagist_vuln_db.as_deref(),
        },
        &NuGetScan {
            vuln_db: nuget_vuln_db.as_deref(),
        },
        &JuliaScan {
            vuln_db: julia_vuln_db.as_deref(),
        },
        &SwiftScan {
            vuln_db: swift_vuln_db.as_deref(),
        },
        &HexScan {
            vuln_db: hex_vuln_db.as_deref(),
        },
        &GhActionsScan {
            vuln_db: ghactions_vuln_db.as_deref(),
        },
        &MavenScan {
            vuln_db: maven_vuln_db.as_deref(),
        },
    );

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

    // 5. Assemble. Ignores + vex_assertions suppress findings; the removed
    //    occurrences are captured for VEX promotion (used only by `-f vex`).
    let provenance = build_provenance(&db.meta());
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
    let Assembled {
        report: mut fleet_report,
        suppressed,
    } = assemble(
        scan,
        &suppressions,
        args.min_severity.map(Severity::from),
        provenance,
    );

    // 5a. Suppress phantom findings (unbuilt optional deps), if requested.
    if args.ignore_phantom {
        let dropped = drop_phantom(&mut fleet_report);
        if dropped > 0 && !args.quiet {
            eprintln!("suppressed {dropped} finding(s) on packages not in the default build");
        }
    }

    // 5a2. Exploit-risk enrichment (KEV + EPSS), opt-in. Annotate, optionally
    //      filter by EPSS, then re-rank by exploit risk (the action queue).
    let enrich_requested = args.enrich
        || args.fail_on_kev
        || args.min_epss.is_some()
        || args.kev_file.is_some()
        || args.epss_file.is_some();
    if enrich_requested {
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
            fetch_enrichment(&fleet_report)
        };
        match loaded {
            Ok(enrichment) => {
                enrichment.apply(&mut fleet_report.vulnerabilities);
                // apply() backfills `unknown` severities from NVD CVSS, so the summary
                // (built pre-enrichment) must be refreshed or it reports a stale
                // max_severity (e.g. `unknown` for a fleet that is actually critical).
                fleet_report.refresh_summary();
                if let Some(min) = args.min_epss {
                    let dropped = retain_min_epss(&mut fleet_report, min);
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

    // 5a3. Reachability (opt-in). `--reachable-only` implies the heuristic when no
    //      mode is given. The static engine sets the legacy `reachable` bool too,
    //      so `--reachable-only` drops a sound `NotReachable` via the same path.
    let reach_mode = args.reachability.or_else(|| {
        (args.reachable_only || args.npm_prune_unreachable).then_some(ReachMode::Heuristic)
    });
    if let Some(mode) = reach_mode {
        match mode {
            ReachMode::Heuristic => {
                reach::assess(&mut fleet_report, &config);
                // npm gets the richer module-import-graph engine (transitive reachability +
                // a witness chain; sound-positive, with an opt-in best-effort NotReachable),
                // overriding the grep heuristic for npm findings.
                npm_reach::assess(
                    &mut fleet_report,
                    &config,
                    &npm_reach::Options {
                        prune: args.npm_prune_unreachable,
                    },
                );
            }
            ReachMode::Static => {
                // Static reachability COMPILES each repo, which runs its build
                // scripts and proc-macros — arbitrary code execution. Unlike the
                // rest of the tool (which only reads Cargo.lock), this requires
                // explicit, informed consent and warns loudly before any build.
                if !args.allow_untrusted_builds {
                    return fail(
                        "--reachability=static COMPILES each scanned repo, executing its build \
                         scripts and proc-macros (arbitrary code). Re-run with \
                         --allow-untrusted-builds only if you trust every repo in the fleet.",
                    );
                }
                let Some(driver) = args.reach_driver.as_deref() else {
                    return fail("--reachability=static requires --reach-driver <PATH>");
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
                    &mut fleet_report,
                    &config,
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
            let dropped = retain_reachable(&mut fleet_report);
            if dropped > 0 && !args.quiet {
                let how = match mode {
                    ReachMode::Heuristic => "not found in your source (heuristic)",
                    ReachMode::Static => "proven unreachable (static)",
                };
                eprintln!("dropped {dropped} finding(s) {how}");
            }
        }
    }

    // 5b. Baseline diff (§10.7): keep only findings new since the prior report.
    let mut baseline_new = false;
    if let Some(path) = &args.baseline {
        let json = match std::fs::read_to_string(path) {
            Ok(json) => json,
            Err(e) => return fail(&format!("reading baseline `{}`: {e}", path.display())),
        };
        let ids = match report::baseline_ids_from_json(&json) {
            Ok(ids) => ids,
            Err(e) => return fail(&format!("parsing baseline `{}`: {e}", path.display())),
        };
        retain_new(&mut fleet_report, &ids);
        baseline_new =
            !fleet_report.vulnerabilities.is_empty() || !fleet_report.warnings.is_empty();
    }

    // 6. Render: machine payload to stdout, human summary to stderr.
    // Color only a TTY table — never JSON, never piped output (§7).
    let payload = match args.format {
        Format::Json => match report::to_json(&fleet_report) {
            Ok(json) => json,
            Err(e) => return fail(&format!("serializing report: {e}")),
        },
        Format::Sarif => {
            // SARIF suppressions (§11): machine not_affected is computed in
            // to_sarif; approved human assertions are injected here.
            let product_ids = vex::resolve_product_ids(&config);
            let assertions = vex::build_human_assertions(&suppressed, &product_ids, false);
            match report::to_sarif(&fleet_report, &assertions) {
                Ok(sarif) => sarif,
                Err(e) => return fail(&format!("serializing SARIF: {e}")),
            }
        }
        Format::Table => report::to_table(&fleet_report, std::io::stdout().is_terminal()),
        Format::Impact => report::to_impact(&fleet_report, std::io::stdout().is_terminal()),
        Format::Blast => report::to_blast(&fleet_report, std::io::stdout().is_terminal()),
        Format::Packages => report::to_packages(&fleet_report, std::io::stdout().is_terminal()),
        Format::PackagesJson => match report::to_packages_json(&fleet_report) {
            Ok(json) => json,
            Err(e) => return fail(&format!("serializing packages: {e}")),
        },
        Format::FixFirst => report::to_fix_first(&fleet_report, std::io::stdout().is_terminal()),
        Format::Remediation => {
            report::to_remediation(&fleet_report, std::io::stdout().is_terminal())
        }
        Format::RemediationJson => match report::to_remediation_json(&fleet_report) {
            Ok(json) => json,
            Err(e) => return fail(&format!("serializing remediation: {e}")),
        },
        Format::Vex => {
            // Author/timestamp resolution fails closed as a usage error (§7.3 edge 8).
            let params = match build_vex_params(&args, &config, &fleet_report, &suppressed) {
                Ok(params) => params,
                Err(e) => return usage_fail(&e),
            };
            match report::to_vex(&fleet_report, &params) {
                Ok(doc) => doc,
                Err(e) => return fail(&format!("serializing VEX: {e}")),
            }
        }
    };
    println!("{payload}");
    if !args.quiet {
        eprintln!("{}", report::summary_line(&fleet_report));
    }

    // 7. Exit per §8, plus the opt-in KEV and baseline gates. `combine_baseline`
    //    elevates a clean/gated code to >=1 on its flag while preserving the
    //    untrustworthy `2`; we reuse it for KEV (any actively-exploited finding).
    let kev_hit = args.fail_on_kev && fleet_report.vulnerabilities.iter().any(|v| v.exploit.kev);
    let code = exit_code(
        &fleet_report,
        &GateConfig {
            fail_on: args.fail_on.into(),
            fail_on_warnings: args.fail_on_warnings,
        },
    );
    combine_baseline(combine_baseline(code, kev_hit), baseline_new)
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
/// tree. Exits `0` if found anywhere, `2` if it is in no tree.
fn run_why(config: &Config, package: &str) -> u8 {
    let mut found = false;
    for repo in &config.repos {
        for lockfile in discover_lockfiles(repo).0 {
            match routes_to(&lockfile, package) {
                Ok(routes) => {
                    for route in routes {
                        found = true;
                        let kind = if route.direct { "direct" } else { "transitive" };
                        // package (arg), version + path segments (untrusted lockfile)
                        // are echoed to the terminal; neutralize control sequences.
                        use fleetreach_report::sanitize_cell;
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
