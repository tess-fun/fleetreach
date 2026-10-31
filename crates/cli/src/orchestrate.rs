//! The multi-repo scan loop (§10, step 4).
//!
//! Repos are scanned **serially** (no async in v1). Each repo degrades
//! independently: a missing or unreadable lockfile becomes an `Errored`
//! [`RepoOutcome`] and the run continues — but that gap is what later forces a
//! non-clean exit (§8), since we cannot claim a repo is clean without reading it.
//!
//! Output here is **pre-correlation**: every finding carries a single
//! occurrence. Grouping across the fleet happens in `correlate` (M4).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use fleetreach_core::semver::Version;
use fleetreach_core::{
    Coverage, CoverageGap, Ecosystem, Occurrence, RepoId, RepoOutcome, ScanStatus, VulnFinding,
    WarnFinding,
};
use fleetreach_ghactions::{ghactions_db_path, GhActionsDb, GhaError};
use fleetreach_go::{GoDb, GoError, SandboxPolicy};
use fleetreach_hex::{hex_db_path, HexDb, HexError};
use fleetreach_julia::{julia_db_path, JuliaDb, JuliaError};
use fleetreach_maven::{maven_db_path, MavenDb, MavenError};
use fleetreach_npm::{npm_db_path, NpmDb, NpmError};
use fleetreach_nuget::{nuget_db_path, NuGetDb, NuGetError};
use fleetreach_packagist::{packagist_db_path, PackagistDb, PackagistError};
use fleetreach_pypi::{pypi_db_path, PyPiDb, PyPiError};
use fleetreach_rubygems::{rubygems_db_path, RubyGemsDb, RubyGemsError};
use fleetreach_scan::{scan_lockfile, scan_toolchain, AdvisoryDb, RepoScan};
use fleetreach_swift::{swift_db_path, SwiftDb, SwiftError};
use rayon::prelude::*;
use walkdir::WalkDir;

use crate::config::{Config, Repo};
use crate::resolve;

/// The aggregated, pre-correlation result of scanning a fleet.
#[derive(Debug, Default, Clone)]
pub struct ScanData {
    pub vulnerabilities: Vec<VulnFinding>,
    pub warnings: Vec<WarnFinding>,
    pub outcomes: Vec<RepoOutcome>,
    /// Total installed packages skipped across all toolchain-free repos because their
    /// version string did not parse (see [`fleetreach_core::osv::TierCScan`]). Surfaced as a
    /// diagnostic so the skip is visible; never an error.
    pub skipped_unparseable: u32,
    /// Sources read with less than full coverage (spec 00, C1): lockfiles in a format no
    /// feeder reads (their packages went unscanned) and manifests that only declare direct
    /// dependencies. Carried into the report so the weakness is visible, never silent.
    pub coverage: Vec<CoverageGap>,
}

/// An installed toolchain to additionally scan against `Collection::Rust`.
#[derive(Debug, Clone)]
pub struct Toolchain {
    pub channel: String,
    pub version: Version,
}

/// Everything the Go scan path needs, bundled so it threads through the fleet walk as
/// one argument. `govulncheck` is `None` when consent/binary are absent, which routes
/// the repo to the toolchain-free Tier-C matcher (or an errored gap); the rest mirror
/// [`fleetreach_go::GoScanOptions`].
#[derive(Debug, Clone, Copy)]
pub struct GoScan<'a> {
    pub govulncheck: Option<&'a Path>,
    pub sandbox: SandboxPolicy,
    pub vuln_db: Option<&'a str>,
    pub offline: bool,
}

/// Everything the npm scan path needs. npm is **toolchain-free only** (the Tier-C
/// matcher reads `package-lock.json` and an OSV mirror, building nothing), so unlike
/// [`GoScan`] there is no binary, sandbox, or online mode — just the `file://<dir>`
/// OSV mirror, absent which an npm repo is an honest gap.
#[derive(Debug, Clone, Copy)]
pub struct NpmScan<'a> {
    pub vuln_db: Option<&'a str>,
}

/// Everything the PyPI scan path needs. Like npm it is **toolchain-free only** (the
/// Tier-C matcher reads a Python lockfile and an OSV mirror, building nothing), so the
/// only input is the `file://` OSV mirror, absent which a PyPI repo is an honest gap.
#[derive(Debug, Clone, Copy)]
pub struct PyPiScan<'a> {
    pub vuln_db: Option<&'a str>,
}

/// Everything the RubyGems scan path needs. Like npm/PyPI it is **toolchain-free only**
/// (the Tier-C matcher reads `Gemfile.lock` and an OSV mirror, building nothing), so the
/// only input is the `file://` OSV mirror, absent which a Ruby repo is an honest gap.
#[derive(Debug, Clone, Copy)]
pub struct RubyGemsScan<'a> {
    pub vuln_db: Option<&'a str>,
}

/// Everything the Packagist scan path needs. Like npm/PyPI/RubyGems it is **toolchain-free
/// only** (the Tier-C matcher reads `composer.lock` and an OSV mirror, building nothing), so
/// the only input is the `file://` OSV mirror, absent which a PHP repo is an honest gap.
#[derive(Debug, Clone, Copy)]
pub struct PackagistScan<'a> {
    pub vuln_db: Option<&'a str>,
}

/// Everything the NuGet scan path needs. Like the other Tier-C feeders it is **toolchain-free
/// only** (the matcher reads `packages.lock.json` and an OSV mirror, building nothing), so the
/// only input is the `file://` OSV mirror, absent which a .NET repo is an honest gap.
#[derive(Debug, Clone, Copy)]
pub struct NuGetScan<'a> {
    pub vuln_db: Option<&'a str>,
}

/// Everything the Julia scan path needs. Like the other Tier-C feeders it is **toolchain-free
/// only** (the matcher reads `Manifest.toml` and an OSV mirror, building nothing), so the only
/// input is the `file://` OSV mirror, absent which a Julia repo is an honest gap.
#[derive(Debug, Clone, Copy)]
pub struct JuliaScan<'a> {
    pub vuln_db: Option<&'a str>,
}

/// Everything the Swift scan path needs. Like the other Tier-C feeders it is **toolchain-free
/// only** (the matcher reads `Package.resolved` and an OSV mirror, building nothing), so the
/// only input is the `file://` OSV mirror, absent which a Swift repo is an honest gap.
#[derive(Debug, Clone, Copy)]
pub struct SwiftScan<'a> {
    pub vuln_db: Option<&'a str>,
}

/// Everything the Hex scan path needs. Like the other Tier-C feeders it is **toolchain-free
/// only** (the matcher reads `mix.lock` and an OSV mirror, building nothing), so the only input
/// is the `file://` OSV mirror, absent which an Elixir repo is an honest gap.
#[derive(Debug, Clone, Copy)]
pub struct HexScan<'a> {
    pub vuln_db: Option<&'a str>,
}

/// Everything the GitHub Actions scan path needs. Like the other Tier-C feeders it is
/// **toolchain-free only** (the matcher reads `.github/workflows/*.yml` and an OSV mirror,
/// building nothing), so the only input is the `file://` OSV mirror, absent which a workflow
/// repo is an honest gap.
#[derive(Debug, Clone, Copy)]
pub struct GhActionsScan<'a> {
    pub vuln_db: Option<&'a str>,
}

/// Everything the Maven scan path needs. Like the other Tier-C feeders it is **toolchain-free
/// only** (the matcher reads `gradle.lockfile`/`pom.xml` and an OSV mirror, building nothing),
/// so the only input is the `file://` OSV mirror, absent which a Java repo is an honest gap.
#[derive(Debug, Clone, Copy)]
pub struct MavenScan<'a> {
    pub vuln_db: Option<&'a str>,
    /// Fetch POMs missing locally from Maven Central (`--maven-fetch`).
    pub fetch: bool,
}

// Each ecosystem threads its own scan config / once-loaded DB through the fleet walk as an
// independent, clearly-named argument; bundling them into a catch-all struct would obscure
// more than it simplifies (they are configured and loaded separately). The count grows by
// one per ecosystem, so the lint is allowed here rather than chased.
#[allow(clippy::too_many_arguments)]
/// Scan every repo in `config`, plus the toolchain if provided. When
/// `host_triple` is `Some`, each finding is additionally annotated (via
/// `cargo tree`) with whether the package is actually built — see
/// [`crate::resolve`].
pub fn scan_fleet(
    db: &AdvisoryDb,
    config: &Config,
    toolchain: Option<&Toolchain>,
    host_triple: Option<&str>,
    go: &GoScan,
    npm: &NpmScan,
    pypi: &PyPiScan,
    rubygems: &RubyGemsScan,
    packagist: &PackagistScan,
    nuget: &NuGetScan,
    julia: &JuliaScan,
    swift: &SwiftScan,
    hex: &HexScan,
    ghactions: &GhActionsScan,
    maven: &MavenScan,
) -> ScanData {
    let mut data = ScanData::default();

    // Plan every repo up front: which ecosystems it holds and where. The plans decide which
    // OSV DBs are worth loading, then drive the per-repo scan.
    let plans: Vec<RepoPlan> = config
        .repos
        .par_iter()
        .map(|repo| match config.sboms.get(&repo.id) {
            Some(path) => sbom_plan(repo, path),
            None => plan_repo(repo),
        })
        .collect();
    let has = |eco: Ecosystem| {
        plans
            .iter()
            .any(|p| p.units.iter().any(|u| u.ecosystem == eco))
    };

    // The npm OSV DB has no prebuilt index, so it is loaded ONCE here (not per repo)
    // and shared read-only across the parallel walk. Only loaded when the fleet
    // actually has an npm repo and a `file://` mirror was given; a load failure is
    // carried as the `Err` so every npm repo degrades to an honest gap with the reason.
    let npm_db: Option<Result<NpmDb, NpmError>> = if has(Ecosystem::Npm) {
        npm.vuln_db
            .and_then(npm_db_path)
            .map(|root| NpmDb::load(&root))
    } else {
        None
    };

    // The Go Tier-C mirror is likewise loaded ONCE (the 434 KB module index + the
    // advisories it references) and shared, instead of being re-read and re-parsed per
    // repo — profiling showed that re-parse dominated a large Go fleet. Only when Tier-C
    // will actually run: no govulncheck (toolchain path), a `file://` mirror, a Go repo.
    let go_db: Option<Result<GoDb, GoError>> = if go.govulncheck.is_none() && has(Ecosystem::Go) {
        go.vuln_db
            .and_then(fleetreach_go::offline_db_path)
            .map(|root| GoDb::load(&root))
    } else {
        None
    };

    // The PyPI OSV DB, like npm, has no prebuilt index, so it is loaded ONCE and shared
    // read-only across the walk. Only when the fleet has a PyPI repo and a `file://`
    // mirror was given; a load failure is carried as the `Err` so every PyPI repo
    // degrades to an honest gap with the reason.
    let pypi_db: Option<Result<PyPiDb, PyPiError>> = if has(Ecosystem::Pypi) {
        pypi.vuln_db
            .and_then(pypi_db_path)
            .map(|root| PyPiDb::load(&root))
    } else {
        None
    };

    // The RubyGems OSV DB, like npm/PyPI, has no prebuilt index, so it is loaded ONCE and
    // shared read-only across the walk. Only when the fleet has a RubyGems repo and a
    // `file://` mirror was given; a load failure is carried as the `Err` so every RubyGems
    // repo degrades to an honest gap with the reason.
    let rubygems_db: Option<Result<RubyGemsDb, RubyGemsError>> = if has(Ecosystem::RubyGems) {
        rubygems
            .vuln_db
            .and_then(rubygems_db_path)
            .map(|root| RubyGemsDb::load(&root))
    } else {
        None
    };

    // The Packagist OSV DB, like npm/PyPI/RubyGems, has no prebuilt index, so it is loaded
    // ONCE and shared read-only across the walk. Only when the fleet has a Packagist repo and
    // a `file://` mirror was given; a load failure is carried as the `Err` so every Packagist
    // repo degrades to an honest gap with the reason.
    let packagist_db: Option<Result<PackagistDb, PackagistError>> = if has(Ecosystem::Packagist) {
        packagist
            .vuln_db
            .and_then(packagist_db_path)
            .map(|root| PackagistDb::load(&root))
    } else {
        None
    };

    // The NuGet OSV DB, like the other Tier-C feeders, has no prebuilt index, so it is loaded
    // ONCE and shared read-only across the walk. Only when the fleet has a NuGet repo and a
    // `file://` mirror was given; a load failure is carried as the `Err` so every NuGet repo
    // degrades to an honest gap with the reason.
    let nuget_db: Option<Result<NuGetDb, NuGetError>> = if has(Ecosystem::NuGet) {
        nuget
            .vuln_db
            .and_then(nuget_db_path)
            .map(|root| NuGetDb::load(&root))
    } else {
        None
    };

    // The Julia OSV DB, like the other Tier-C feeders, has no prebuilt index, so it is loaded
    // ONCE and shared read-only across the walk. Only when the fleet has a Julia repo and a
    // `file://` mirror was given; a load failure is carried as the `Err` so every Julia repo
    // degrades to an honest gap with the reason.
    let julia_db: Option<Result<JuliaDb, JuliaError>> = if has(Ecosystem::Julia) {
        julia
            .vuln_db
            .and_then(julia_db_path)
            .map(|root| JuliaDb::load(&root))
    } else {
        None
    };

    // The Swift OSV DB, like the other Tier-C feeders, has no prebuilt index, so it is loaded
    // ONCE and shared read-only across the walk. Only when the fleet has a Swift repo and a
    // `file://` mirror was given; a load failure is carried as the `Err` so every Swift repo
    // degrades to an honest gap with the reason.
    let swift_db: Option<Result<SwiftDb, SwiftError>> = if has(Ecosystem::Swift) {
        swift
            .vuln_db
            .and_then(swift_db_path)
            .map(|root| SwiftDb::load(&root))
    } else {
        None
    };

    // The Hex OSV DB, like the other Tier-C feeders, has no prebuilt index, so it is loaded
    // ONCE and shared read-only across the walk. Only when the fleet has a Hex repo and a
    // `file://` mirror was given; a load failure is carried as the `Err` so every Hex repo
    // degrades to an honest gap with the reason.
    let hex_db: Option<Result<HexDb, HexError>> = if has(Ecosystem::Hex) {
        hex.vuln_db
            .and_then(hex_db_path)
            .map(|root| HexDb::load(&root))
    } else {
        None
    };

    // The GitHub Actions OSV DB, like the other Tier-C feeders, has no prebuilt index, so it is
    // loaded ONCE and shared read-only across the walk. Only when the fleet has a workflow repo
    // and a `file://` mirror was given; a load failure is carried as the `Err` so every such
    // repo degrades to an honest gap with the reason.
    let ghactions_db: Option<Result<GhActionsDb, GhaError>> = if has(Ecosystem::GitHubActions) {
        ghactions
            .vuln_db
            .and_then(ghactions_db_path)
            .map(|root| GhActionsDb::load(&root))
    } else {
        None
    };

    // The Maven OSV DB, like the other Tier-C feeders, has no prebuilt index, so it is loaded
    // ONCE and shared read-only across the walk. Only when the fleet has a Java repo and a
    // `file://` mirror was given; a load failure is carried as the `Err` so every Maven repo
    // degrades to an honest gap with the reason.
    let maven_db: Option<Result<MavenDb, MavenError>> = if has(Ecosystem::Maven) {
        maven
            .vuln_db
            .and_then(maven_db_path)
            .map(|root| MavenDb::load(&root))
    } else {
        None
    };

    // Each repo is independent and shares only the read-only advisory DBs, so the
    // per-repo scan (dominated by lockfile parsing) fans out across cores. Results
    // are collected in config order and merged serially, so the assembled output
    // is byte-identical to a serial scan regardless of completion order.
    let scan_unit_with = |unit: &ScanUnit| {
        if let Some(sbom) = &unit.sbom {
            return scan_sbom_unit(
                &unit.repo,
                unit.ecosystem,
                sbom,
                &SbomDbs {
                    npm: npm_db.as_ref(),
                    pypi: pypi_db.as_ref(),
                    rubygems: rubygems_db.as_ref(),
                    packagist: packagist_db.as_ref(),
                    nuget: nuget_db.as_ref(),
                    julia: julia_db.as_ref(),
                    swift: swift_db.as_ref(),
                    hex: hex_db.as_ref(),
                    maven: maven_db.as_ref(),
                },
            );
        }
        scan_unit(
            db,
            &unit.repo,
            unit.ecosystem,
            host_triple,
            go,
            npm_db.as_ref(),
            go_db.as_ref(),
            pypi_db.as_ref(),
            rubygems_db.as_ref(),
            packagist_db.as_ref(),
            nuget_db.as_ref(),
            julia_db.as_ref(),
            swift_db.as_ref(),
            hex_db.as_ref(),
            ghactions_db.as_ref(),
            maven_db.as_ref(),
            maven,
        )
    };
    let per_repo: Vec<RepoResult> = plans
        .par_iter()
        .map(|plan| merge_units(plan, plan.units.iter().map(|u| (u, scan_unit_with(u)))))
        .collect();

    for (plan, result) in plans.iter().zip(per_repo) {
        data.vulnerabilities.extend(result.vulnerabilities);
        data.warnings.extend(result.warnings);
        data.outcomes.push(result.outcome);
        data.skipped_unparseable += result.skipped_unparseable;
        data.coverage.extend(plan.unsupported.iter().cloned());
        data.coverage.extend(result.coverage);
    }

    // Toolchain advisories are global — no repo, scanned once.
    if let Some(tc) = toolchain {
        let ts = scan_toolchain(db, &tc.channel, &tc.version);
        data.vulnerabilities.extend(ts.vulnerabilities);
        data.warnings.extend(ts.warnings);
    }

    data
}

/// The ecosystems present anywhere in the fleet, sorted. Planning only walks directories, so
/// this is cheap; it decides which OSV exports a run needs before any is loaded or fetched.
pub fn fleet_ecosystems(config: &Config) -> Vec<Ecosystem> {
    let found: BTreeSet<Ecosystem> = config
        .repos
        .par_iter()
        .map(plan_repo)
        .collect::<Vec<_>>()
        .iter()
        .flat_map(|p| p.units.iter().map(|u| u.ecosystem))
        .collect();
    found.into_iter().collect()
}

/// The findings and outcome for a single repo, returned by the parallel map so
/// the caller can merge them in deterministic (config) order.
struct RepoResult {
    vulnerabilities: Vec<VulnFinding>,
    warnings: Vec<WarnFinding>,
    outcome: RepoOutcome,
    /// Installed packages skipped because their version did not parse (Tier-C only; 0
    /// otherwise). Summed across the fleet and surfaced as a diagnostic.
    skipped_unparseable: u32,
    /// Sources this unit read with less than full coverage; `source` is relative to the
    /// unit's directory until [`merge_units`] prefixes it.
    coverage: Vec<CoverageGap>,
}

impl RepoResult {
    /// A repo that scanned cleanly to these findings.
    fn scanned(
        repo: &RepoId,
        vulnerabilities: Vec<VulnFinding>,
        warnings: Vec<WarnFinding>,
    ) -> Self {
        let outcome = RepoOutcome {
            repo: repo.clone(),
            status: ScanStatus::Scanned {
                vulns: vulnerabilities.len(),
                warnings: warnings.len(),
            },
        };
        RepoResult {
            vulnerabilities,
            warnings,
            outcome,
            skipped_unparseable: 0,
            coverage: Vec::new(),
        }
    }

    /// Record a source read with less than full coverage.
    fn with_coverage(mut self, gap: CoverageGap) -> Self {
        self.coverage.push(gap);
        self
    }

    /// Record the count of packages skipped for an unparseable version (Tier-C feeders).
    fn with_skipped(mut self, skipped_unparseable: u32) -> Self {
        self.skipped_unparseable = skipped_unparseable;
        self
    }

    /// A repo that could not be fully scanned — an honest gap, never reported clean.
    fn errored(repo: &RepoId, reason: String) -> Self {
        RepoResult {
            vulnerabilities: Vec::new(),
            warnings: Vec::new(),
            outcome: RepoOutcome {
                repo: repo.clone(),
                status: ScanStatus::Errored { reason },
            },
            skipped_unparseable: 0,
            coverage: Vec::new(),
        }
    }
}

/// One thing to scan in a repo: an ecosystem and the repo narrowed to the directory holding its
/// lockfile (`rel_dir`, empty for the root). Cargo is the exception: its unit is the whole repo,
/// because the Cargo path discovers its own `Cargo.lock`s (honouring `glob`).
pub(crate) struct ScanUnit {
    pub(crate) ecosystem: Ecosystem,
    pub(crate) repo: Repo,
    pub(crate) rel_dir: String,
    /// Packages from the repo's SBOM (`[[repo]] sbom`) instead of its lockfiles.
    pub(crate) sbom: Option<std::sync::Arc<Result<crate::sbom_input::SbomInput, String>>>,
}

/// Everything found to scan in one repo, plus what could not be.
pub(crate) struct RepoPlan {
    id: RepoId,
    pub(crate) units: Vec<ScanUnit>,
    /// Directory-walk errors: an unreadable subdirectory may hide a lockfile, so the repo
    /// cannot be called clean.
    pub(crate) walk_errors: Vec<String>,
    /// Lockfiles in formats no feeder reads, as coverage gaps.
    pub(crate) unsupported: Vec<CoverageGap>,
}

/// The plan of a repo scanned from its SBOM: one unit per ecosystem the SBOM holds, plus a
/// coverage gap when the SBOM does not assert completeness or lists packages no matcher takes.
fn sbom_plan(repo: &Repo, path: &Path) -> RepoPlan {
    let source = path
        .strip_prefix(&repo.path)
        .unwrap_or(path)
        .display()
        .to_string();
    let read = crate::sbom_input::read(path);
    let mut plan = RepoPlan {
        id: repo.id.clone(),
        units: Vec::new(),
        walk_errors: Vec::new(),
        unsupported: Vec::new(),
    };
    let gap = |reason: String| CoverageGap {
        repo: repo.id.clone(),
        source: source.clone(),
        ecosystem: Ecosystem::Cargo,
        level: Coverage::Partial,
        reason,
    };
    let ecosystems: Vec<Ecosystem> = match &read {
        Ok(input) => {
            if !input.complete {
                plan.unsupported.push(gap(
                    "the SBOM does not assert it is complete (a CycloneDX composition of its root \
                     with aggregate complete); packages it omits were not scanned"
                        .to_string(),
                ));
            }
            if !input.unrouted.is_empty() {
                plan.unsupported.push(gap(format!(
                    "components not scanned from an SBOM: {}",
                    input.unrouted.join(", ")
                )));
            }
            input.packages.keys().copied().collect()
        }
        Err(_) => Vec::new(),
    };
    let shared = std::sync::Arc::new(read);
    // An unreadable or empty SBOM still gets a unit, which reports it.
    for ecosystem in if ecosystems.is_empty() {
        vec![Ecosystem::Cargo]
    } else {
        ecosystems
    } {
        plan.units.push(ScanUnit {
            ecosystem,
            repo: repo.clone(),
            rel_dir: String::new(),
            sbom: Some(shared.clone()),
        });
    }
    plan
}

/// The once-loaded OSV DBs an SBOM unit may need.
struct SbomDbs<'a> {
    npm: Option<&'a Result<NpmDb, NpmError>>,
    pypi: Option<&'a Result<PyPiDb, PyPiError>>,
    rubygems: Option<&'a Result<RubyGemsDb, RubyGemsError>>,
    packagist: Option<&'a Result<PackagistDb, PackagistError>>,
    nuget: Option<&'a Result<NuGetDb, NuGetError>>,
    julia: Option<&'a Result<JuliaDb, JuliaError>>,
    swift: Option<&'a Result<SwiftDb, SwiftError>>,
    hex: Option<&'a Result<HexDb, HexError>>,
    maven: Option<&'a Result<MavenDb, MavenError>>,
}

/// Scan one ecosystem's packages from an SBOM with that ecosystem's matcher.
fn scan_sbom_unit(
    repo: &Repo,
    ecosystem: Ecosystem,
    sbom: &Result<crate::sbom_input::SbomInput, String>,
    dbs: &SbomDbs,
) -> RepoResult {
    let errored = |reason: String| RepoResult::errored(&repo.id, reason);
    let input = match sbom {
        Ok(input) => input,
        Err(e) => return errored(format!("sbom: {e}")),
    };
    let Some(pkgs) = input.packages.get(&ecosystem) else {
        return errored("sbom: no component has a package URL fleetreach can scan".to_string());
    };
    fn db<D, E: std::fmt::Display>(
        db: Option<&Result<D, E>>,
        ecosystem: Ecosystem,
    ) -> Result<&D, String> {
        match db {
            Some(Ok(db)) => Ok(db),
            Some(Err(e)) => Err(format!("{ecosystem:?} OSV DB: {e}")),
            None => Err(format!(
                "sbom lists {ecosystem:?} packages but no OSV export is available for them (run \
                 `fleetreach db sync`, or pass --osv-dir)"
            )),
        }
    }
    let g = &input.graph;
    let scan = (|| -> Result<fleetreach_core::osv::TierCScan, String> {
        Ok(match ecosystem {
            Ecosystem::Npm => fleetreach_npm::scan_installed(
                &pkgs
                    .iter()
                    .map(|p| fleetreach_npm::InstalledPackage {
                        name: p.name.clone(),
                        version: p.version.clone(),
                        direct: p.direct,
                        dev: p.dev,
                    })
                    .collect::<Vec<_>>(),
                g,
                db(dbs.npm, ecosystem)?,
                &repo.id,
            ),
            Ecosystem::Pypi => fleetreach_pypi::scan_installed(
                &pkgs
                    .iter()
                    .map(|p| fleetreach_pypi::InstalledPackage {
                        name: p.name.clone(),
                        version: p.version.clone(),
                        direct: p.direct,
                        dev: p.dev,
                    })
                    .collect::<Vec<_>>(),
                g,
                db(dbs.pypi, ecosystem)?,
                &repo.id,
            ),
            Ecosystem::Packagist => fleetreach_packagist::scan_installed(
                &pkgs
                    .iter()
                    .map(|p| fleetreach_packagist::InstalledPackage {
                        name: p.name.clone(),
                        version: p.version.clone(),
                        direct: p.direct,
                        dev: p.dev,
                    })
                    .collect::<Vec<_>>(),
                g,
                db(dbs.packagist, ecosystem)?,
                &repo.id,
            ),
            Ecosystem::RubyGems => fleetreach_rubygems::scan_installed(
                &pkgs
                    .iter()
                    .map(|p| fleetreach_rubygems::InstalledGem {
                        name: p.name.clone(),
                        version: p.version.clone(),
                        direct: p.direct,
                    })
                    .collect::<Vec<_>>(),
                g,
                db(dbs.rubygems, ecosystem)?,
                &repo.id,
            ),
            Ecosystem::NuGet => fleetreach_nuget::scan_installed(
                &pkgs
                    .iter()
                    .map(|p| fleetreach_nuget::InstalledPackage {
                        name: p.name.clone(),
                        version: p.version.clone(),
                        direct: p.direct,
                    })
                    .collect::<Vec<_>>(),
                g,
                db(dbs.nuget, ecosystem)?,
                &repo.id,
            ),
            Ecosystem::Julia => fleetreach_julia::scan_installed(
                &pkgs
                    .iter()
                    .map(|p| fleetreach_julia::InstalledPackage {
                        name: p.name.clone(),
                        version: p.version.clone(),
                        direct: p.direct,
                    })
                    .collect::<Vec<_>>(),
                g,
                db(dbs.julia, ecosystem)?,
                &repo.id,
            ),
            Ecosystem::Swift => fleetreach_swift::scan_installed(
                &pkgs
                    .iter()
                    .map(|p| fleetreach_swift::InstalledPackage {
                        name: p.name.clone(),
                        version: p.version.clone(),
                        direct: p.direct,
                    })
                    .collect::<Vec<_>>(),
                g,
                db(dbs.swift, ecosystem)?,
                &repo.id,
            ),
            Ecosystem::Hex => fleetreach_hex::scan_installed(
                &pkgs
                    .iter()
                    .map(|p| fleetreach_hex::InstalledPackage {
                        name: p.name.clone(),
                        version: p.version.clone(),
                        direct: p.direct,
                    })
                    .collect::<Vec<_>>(),
                g,
                db(dbs.hex, ecosystem)?,
                &repo.id,
            ),
            Ecosystem::Maven => {
                let resolution = fleetreach_maven::Resolution {
                    packages: pkgs
                        .iter()
                        .map(|p| fleetreach_maven::ResolvedDep {
                            name: p.name.clone(),
                            version: p.version.clone(),
                            direct: p.direct,
                            dev: p.dev,
                            scope: if p.dev {
                                "test".into()
                            } else {
                                "compile".into()
                            },
                        })
                        .collect(),
                    graph: g.clone(),
                    missing: Vec::new(),
                };
                fleetreach_maven::scan_resolution(&resolution, db(dbs.maven, ecosystem)?, &repo.id)
            }
            other => {
                return Err(format!(
                    "sbom: {other:?} packages are not scanned from an SBOM"
                ))
            }
        })
    })();
    match scan {
        Ok(scan) => RepoResult::scanned(&repo.id, scan.findings, Vec::new())
            .with_skipped(scan.skipped_unparseable),
        Err(e) => errored(e),
    }
}

/// Lockfile formats fleetreach cannot read; reported when no readable lockfile sits beside them.
const UNSUPPORTED_LOCKFILES: &[&str] = &["bun.lockb"];

/// Directories never searched for lockfiles: installed third-party packages and VCS metadata
/// are not the project's own dependency set.
const SKIPPED_DIRS: &[&str] = &["node_modules", ".git"];

/// Decide what to scan in `repo`.
///
/// An explicit `ecosystem` scans exactly that, as before. Otherwise every ecosystem is
/// detected in the root and, with `glob = true`, in every directory whose lockfile lies within
/// `glob_max_depth` (the same bound the `Cargo.lock` glob uses), so a polyglot repo or a
/// monorepo whose lockfiles live below the root is scanned in full instead of as its first
/// detected ecosystem. GitHub Actions is scanned only when nothing else is found, and a repo
/// with nothing at all falls back to Cargo, whose "no Cargo.lock found" is the honest gap.
pub(crate) fn plan_repo(repo: &Repo) -> RepoPlan {
    let unit = |ecosystem: Ecosystem, dir: &Path| {
        let rel_dir = dir
            .strip_prefix(&repo.path)
            .unwrap_or(dir)
            .display()
            .to_string();
        let narrowed = if ecosystem == Ecosystem::Cargo {
            repo.clone()
        } else {
            Repo {
                path: dir.to_path_buf(),
                glob: false,
                ecosystem: Some(ecosystem),
                ..repo.clone()
            }
        };
        ScanUnit {
            ecosystem,
            repo: narrowed,
            rel_dir,
            sbom: None,
        }
    };
    let mut plan = RepoPlan {
        id: repo.id.clone(),
        units: Vec::new(),
        walk_errors: Vec::new(),
        unsupported: Vec::new(),
    };

    if let Some(eco) = repo.ecosystem {
        plan.units.push(ScanUnit {
            ecosystem: eco,
            repo: repo.clone(),
            rel_dir: String::new(),
            sbom: None,
        });
        return plan;
    }

    if !discover_lockfiles(repo).0.is_empty() {
        plan.units.push(unit(Ecosystem::Cargo, &repo.path));
    }

    let mut dirs = vec![repo.path.clone()];
    if repo.glob && repo.glob_max_depth > 1 {
        let walk = WalkDir::new(&repo.path)
            .min_depth(1)
            .max_depth(repo.glob_max_depth - 1)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| {
                !(e.file_type().is_dir() && SKIPPED_DIRS.iter().any(|s| e.file_name() == *s))
            });
        for entry in walk {
            match entry {
                Ok(e) if e.file_type().is_dir() => dirs.push(e.into_path()),
                Ok(_) => {}
                Err(e) => plan.walk_errors.push(e.to_string()),
            }
        }
    }
    for dir in &dirs {
        let files = file_names(dir);
        let found = dir_ecosystems(dir, &files, dir == &repo.path);
        if !found.contains(&Ecosystem::Npm) {
            for name in UNSUPPORTED_LOCKFILES {
                if files.contains(*name) {
                    let path = dir.join(name);
                    let rel = path.strip_prefix(&repo.path).unwrap_or(&path);
                    plan.unsupported.push(CoverageGap {
                        repo: repo.id.clone(),
                        source: rel.display().to_string(),
                        ecosystem: Ecosystem::Npm,
                        level: Coverage::Partial,
                        reason: format!(
                            "{name} is a lockfile format fleetreach cannot read; its packages \
                             were not scanned"
                        ),
                    });
                }
            }
        }
        for eco in found {
            plan.units.push(unit(eco, dir));
        }
    }

    if plan.units.is_empty() {
        let eco = if repo.path.join(".github").join("workflows").is_dir() {
            Ecosystem::GitHubActions
        } else {
            Ecosystem::Cargo
        };
        plan.units.push(unit(eco, &repo.path));
    }
    plan
}

/// The exact names of the regular files directly in `dir` (empty if it cannot be read; an
/// unreadable subdirectory is already a walk error). Matching names exactly, rather than probing
/// `dir.join(name).is_file()`, keeps a case-insensitive filesystem (macOS) from taking Flox's
/// `manifest.toml` for Julia's `Manifest.toml`.
fn file_names(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

/// The non-Cargo ecosystems whose lockfile (or manifest) is among `files`, the file names in
/// `dir`. `pom.xml` counts only at the repo root: a nested one is usually a module of a
/// multi-module build, not a standalone dependency set.
fn dir_ecosystems(dir: &Path, files: &BTreeSet<String>, is_root: bool) -> Vec<Ecosystem> {
    let has = |name: &str| files.contains(name);
    let mut found = Vec::new();
    if has("go.mod") {
        found.push(Ecosystem::Go);
    }
    if fleetreach_npm::LOCKFILES.iter().any(|name| has(name)) {
        found.push(Ecosystem::Npm);
    }
    if fleetreach_pypi::has_python_sources(dir) {
        found.push(Ecosystem::Pypi);
    }
    if has("Gemfile.lock") {
        found.push(Ecosystem::RubyGems);
    }
    if has("composer.lock") {
        found.push(Ecosystem::Packagist);
    }
    if fleetreach_nuget::has_nuget_sources(dir) {
        found.push(Ecosystem::NuGet);
    }
    if has("Manifest.toml") {
        found.push(Ecosystem::Julia);
    }
    if has("Package.resolved") {
        found.push(Ecosystem::Swift);
    }
    if has("mix.lock") {
        found.push(Ecosystem::Hex);
    }
    if has("gradle.lockfile") || (is_root && has("pom.xml")) {
        found.push(Ecosystem::Maven);
    }
    found
}

/// Fold a repo's per-unit results into one: findings concatenated, and the repo errored
/// (keeping every finding gathered) if any unit errored or the walk was incomplete, with each
/// reason prefixed by the directory it came from.
fn merge_units<'a>(
    plan: &RepoPlan,
    results: impl Iterator<Item = (&'a ScanUnit, RepoResult)>,
) -> RepoResult {
    let mut vulnerabilities = Vec::new();
    let mut warnings = Vec::new();
    let mut skipped_unparseable = 0;
    let mut coverage = Vec::new();
    let mut reasons: Vec<String> = plan
        .walk_errors
        .iter()
        .map(|e| format!("could not fully walk the repo: {e}"))
        .collect();
    for (unit, result) in results {
        vulnerabilities.extend(result.vulnerabilities);
        warnings.extend(result.warnings);
        skipped_unparseable += result.skipped_unparseable;
        coverage.extend(result.coverage.into_iter().map(|mut gap| {
            if !unit.rel_dir.is_empty() {
                gap.source = format!("{}/{}", unit.rel_dir, gap.source);
            }
            gap
        }));
        if let ScanStatus::Errored { reason } = result.outcome.status {
            reasons.push(if unit.rel_dir.is_empty() {
                reason
            } else {
                format!("{}: {reason}", unit.rel_dir)
            });
        }
    }
    let status = if reasons.is_empty() {
        ScanStatus::Scanned {
            vulns: vulnerabilities.len(),
            warnings: warnings.len(),
        }
    } else {
        ScanStatus::Errored {
            reason: reasons.join("; "),
        }
    };
    RepoResult {
        vulnerabilities,
        warnings,
        outcome: RepoOutcome {
            repo: plan.id.clone(),
            status,
        },
        skipped_unparseable,
        coverage,
    }
}

/// Scan one unit, dispatching on its ecosystem. Pure (no shared mutable state) so it runs
/// safely in parallel across repos; the only shared input is the read-only `db`.
// One once-loaded OSV DB per Tier-C ecosystem is threaded in as its own argument; see the
// note on `scan_fleet` for why the lint is allowed rather than bundled away.
#[allow(clippy::too_many_arguments)]
fn scan_unit(
    db: &AdvisoryDb,
    repo: &Repo,
    ecosystem: Ecosystem,
    host_triple: Option<&str>,
    go: &GoScan,
    npm_db: Option<&Result<NpmDb, NpmError>>,
    go_db: Option<&Result<GoDb, GoError>>,
    pypi_db: Option<&Result<PyPiDb, PyPiError>>,
    rubygems_db: Option<&Result<RubyGemsDb, RubyGemsError>>,
    packagist_db: Option<&Result<PackagistDb, PackagistError>>,
    nuget_db: Option<&Result<NuGetDb, NuGetError>>,
    julia_db: Option<&Result<JuliaDb, JuliaError>>,
    swift_db: Option<&Result<SwiftDb, SwiftError>>,
    hex_db: Option<&Result<HexDb, HexError>>,
    ghactions_db: Option<&Result<GhActionsDb, GhaError>>,
    maven_db: Option<&Result<MavenDb, MavenError>>,
    maven: &MavenScan,
) -> RepoResult {
    match ecosystem {
        Ecosystem::Go => return scan_go_repo(repo, go, go_db),
        Ecosystem::Npm => return scan_npm_repo(repo, npm_db),
        Ecosystem::Pypi => return scan_pypi_repo(repo, pypi_db),
        Ecosystem::RubyGems => return scan_rubygems_repo(repo, rubygems_db),
        Ecosystem::Packagist => return scan_packagist_repo(repo, packagist_db),
        Ecosystem::NuGet => return scan_nuget_repo(repo, nuget_db),
        Ecosystem::Julia => return scan_julia_repo(repo, julia_db),
        Ecosystem::Swift => return scan_swift_repo(repo, swift_db),
        Ecosystem::Hex => return scan_hex_repo(repo, hex_db),
        Ecosystem::Maven => return scan_maven_repo(repo, maven_db, maven.fetch),
        Ecosystem::GitHubActions => return scan_ghactions_repo(repo, ghactions_db),
        Ecosystem::Cargo => {}
    }
    let (lockfiles, walk_errors) = discover_lockfiles(repo);
    let mut vulnerabilities: Vec<VulnFinding> = Vec::new();
    let mut warnings: Vec<WarnFinding> = Vec::new();
    let mut error: Option<String> = None;

    // A directory under a glob root we could not read might hide a Cargo.lock, so the
    // repo cannot be called clean (fail closed) even if other lockfiles were found.
    if !walk_errors.is_empty() {
        error.get_or_insert_with(|| {
            format!(
                "could not fully walk {}: {}",
                repo.path.display(),
                walk_errors.join("; ")
            )
        });
    }
    if lockfiles.is_empty() {
        error.get_or_insert_with(|| format!("no Cargo.lock found under {}", repo.path.display()));
    }

    for lockfile in &lockfiles {
        match scan_lockfile(db, &repo.id, lockfile) {
            Ok(mut scan) => {
                // Opt-in: mark each occurrence built/phantom for the host's
                // default build. Best-effort — failures leave it unannotated.
                if let (Some(host), Some(dir)) = (host_triple, lockfile.parent()) {
                    if let Ok(built) = resolve::built_package_set(dir, host) {
                        annotate_built(&mut scan, &built);
                    }
                }
                vulnerabilities.extend(scan.vulnerabilities);
                warnings.extend(scan.warnings);
            }
            // Any unreadable lockfile marks the whole repo as a gap; keep the
            // findings we did get, but the repo can no longer be called clean.
            Err(e) => {
                error.get_or_insert_with(|| e.to_string());
            }
        }
    }

    match error {
        // A gap keeps the findings gathered before it (still useful), but the repo can
        // no longer be called clean — so build the Errored outcome around them directly
        // rather than through `RepoResult::errored` (which is for the empty case).
        Some(reason) => RepoResult {
            outcome: RepoOutcome {
                repo: repo.id.clone(),
                status: ScanStatus::Errored { reason },
            },
            vulnerabilities,
            warnings,
            skipped_unparseable: 0,
            coverage: Vec::new(),
        },
        None => RepoResult::scanned(&repo.id, vulnerabilities, warnings),
    }
}

/// Scan a Go repo by running govulncheck as a sidecar. govulncheck **compiles**
/// the module, so it is gated on the same untrusted-build consent as static
/// reachability (when consent/binary are absent — `go_govulncheck` is `None` — the
/// repo is an honest gap (`Errored`), never silently skipped) *and* confined under
/// the same `--build-sandbox` policy.
fn scan_go_repo(repo: &Repo, go: &GoScan, go_db: Option<&Result<GoDb, GoError>>) -> RepoResult {
    let errored = |reason: String| RepoResult::errored(&repo.id, reason);
    let scanned = |vulnerabilities| RepoResult::scanned(&repo.id, vulnerabilities, Vec::new());

    let Some(govulncheck) = go.govulncheck else {
        // No govulncheck (no --allow-untrusted-builds, or no binary). Fall back to
        // the Tier-C offline matcher against the once-loaded mirror (`go_db`): it reads
        // go.mod and matches versions against the OSV DB, compiling nothing, so it needs
        // no untrusted-build consent. Without a mirror it stays an honest gap.
        return match go_db {
            Some(Ok(db)) => match fleetreach_go::scan_offline(&repo.path, db, &repo.id) {
                Ok(vulnerabilities) => scanned(vulnerabilities),
                Err(e) => errored(format!("tier-c offline scan: {e}")),
            },
            Some(Err(e)) => errored(format!("tier-c offline DB: {e}")),
            None => errored(
                "Go repo (go.mod): no govulncheck available (needs --allow-untrusted-builds \
                 and a govulncheck binary via --govulncheck <path> or PATH), and no offline \
                 DB mirror for the toolchain-free Tier-C fallback (pass \
                 --go-vuln-db=file://<mirror>)"
                    .to_string(),
            ),
        };
    };

    let opts = fleetreach_go::GoScanOptions {
        govulncheck,
        sandbox: go.sandbox,
        vuln_db: go.vuln_db,
        offline: go.offline,
    };
    match fleetreach_go::scan_module(&repo.path, &repo.id, &opts) {
        Ok(vulnerabilities) => scanned(vulnerabilities),
        Err(e) => errored(format!("govulncheck: {e}")),
    }
}

/// Scan an npm repo with the toolchain-free Tier-C matcher: read `package-lock.json`
/// and match each package version against the preloaded OSV DB. Builds nothing, so it
/// needs no consent and no sandbox. `npm_db` is the once-loaded DB: `None` means no
/// `file://` mirror was given (an honest gap), `Some(Err)` a mirror that failed to
/// load (the reason is surfaced, never a false-clean).
fn scan_npm_repo(repo: &Repo, npm_db: Option<&Result<NpmDb, NpmError>>) -> RepoResult {
    let errored = |reason: String| RepoResult::errored(&repo.id, reason);

    let db = match npm_db {
        Some(Ok(db)) => db,
        Some(Err(e)) => return errored(format!("npm OSV DB: {e}")),
        None => {
            return errored(
                "npm repo (package-lock.json/pnpm-lock.yaml/yarn.lock/bun.lock): no OSV DB mirror for the toolchain-free \
                 matcher (pass --osv-dir=<dir> or --npm-vuln-db=file://<dir>, e.g. an unzipped osv.dev npm export)"
                    .to_string(),
            )
        }
    };
    match fleetreach_npm::scan_offline(&repo.path, db, &repo.id) {
        Ok(scan) => RepoResult::scanned(&repo.id, scan.findings, Vec::new())
            .with_skipped(scan.skipped_unparseable),
        Err(e) => errored(format!("npm tier-c scan: {e}")),
    }
}

/// Scan a PyPI repo with the toolchain-free Tier-C matcher: read the Python lockfile
/// (`uv.lock`/`poetry.lock`/`Pipfile.lock`), else `pylock.toml`, else requirements files, and
/// match each package version against the preloaded OSV DB. Requirements files that are not a
/// full resolved set are reported as coverage gaps (C1). Builds nothing, so it needs no consent and no sandbox. `pypi_db` is
/// the once-loaded DB: `None` means no `file://` mirror was given (an honest gap),
/// `Some(Err)` a mirror that failed to load (the reason is surfaced, never a false-clean).
fn scan_pypi_repo(repo: &Repo, pypi_db: Option<&Result<PyPiDb, PyPiError>>) -> RepoResult {
    let errored = |reason: String| RepoResult::errored(&repo.id, reason);

    let db = match pypi_db {
        Some(Ok(db)) => db,
        Some(Err(e)) => return errored(format!("PyPI OSV DB: {e}")),
        None => {
            return errored(
                "PyPI repo (uv.lock/poetry.lock/Pipfile.lock/pylock.toml/requirements): no OSV DB mirror for the \
                 toolchain-free matcher (pass --osv-dir=<dir> or --pypi-vuln-db=file://<path>, e.g. the osv.dev \
                 PyPI export all.zip or an unzipped directory)"
                    .to_string(),
            )
        }
    };
    match fleetreach_pypi::scan_offline_with_coverage(&repo.path, db, &repo.id) {
        Ok(scan) => scan.coverage.into_iter().fold(
            RepoResult::scanned(&repo.id, scan.scan.findings, Vec::new())
                .with_skipped(scan.scan.skipped_unparseable),
            |result, gap| {
                result.with_coverage(CoverageGap {
                    repo: repo.id.clone(),
                    source: gap.source,
                    ecosystem: Ecosystem::Pypi,
                    level: gap.level,
                    reason: gap.reason,
                })
            },
        ),
        Err(e) => errored(format!("pypi tier-c scan: {e}")),
    }
}

/// Scan a RubyGems repo with the toolchain-free Tier-C matcher: read `Gemfile.lock` and
/// match each gem version against the preloaded OSV DB. Builds nothing, so it needs no
/// consent and no sandbox. `rubygems_db` is the once-loaded DB: `None` means no `file://`
/// mirror was given (an honest gap), `Some(Err)` a mirror that failed to load (the reason
/// is surfaced, never a false-clean).
fn scan_rubygems_repo(
    repo: &Repo,
    rubygems_db: Option<&Result<RubyGemsDb, RubyGemsError>>,
) -> RepoResult {
    let errored = |reason: String| RepoResult::errored(&repo.id, reason);

    let db = match rubygems_db {
        Some(Ok(db)) => db,
        Some(Err(e)) => return errored(format!("RubyGems OSV DB: {e}")),
        None => {
            return errored(
                "RubyGems repo (Gemfile.lock): no OSV DB mirror for the toolchain-free \
                 matcher (pass --osv-dir=<dir> or --rubygems-vuln-db=file://<path>, e.g. the osv.dev RubyGems \
                 export all.zip or an unzipped directory)"
                    .to_string(),
            )
        }
    };
    match fleetreach_rubygems::scan_offline(&repo.path, db, &repo.id) {
        Ok(scan) => RepoResult::scanned(&repo.id, scan.findings, Vec::new())
            .with_skipped(scan.skipped_unparseable),
        Err(e) => errored(format!("rubygems tier-c scan: {e}")),
    }
}

/// Scan a Packagist (Composer/PHP) repo with the toolchain-free Tier-C matcher: read
/// `composer.lock` and match each package version against the preloaded OSV DB. Builds
/// nothing, so it needs no consent and no sandbox. `packagist_db` is the once-loaded DB:
/// `None` means no `file://` mirror was given (an honest gap), `Some(Err)` a mirror that
/// failed to load (the reason is surfaced, never a false-clean).
fn scan_packagist_repo(
    repo: &Repo,
    packagist_db: Option<&Result<PackagistDb, PackagistError>>,
) -> RepoResult {
    let errored = |reason: String| RepoResult::errored(&repo.id, reason);

    let db = match packagist_db {
        Some(Ok(db)) => db,
        Some(Err(e)) => return errored(format!("Packagist OSV DB: {e}")),
        None => {
            return errored(
                "Packagist repo (composer.lock): no OSV DB mirror for the toolchain-free \
                 matcher (pass --osv-dir=<dir> or --packagist-vuln-db=file://<path>, e.g. the osv.dev Packagist \
                 export all.zip or an unzipped directory)"
                    .to_string(),
            )
        }
    };
    match fleetreach_packagist::scan_offline(&repo.path, db, &repo.id) {
        Ok(scan) => RepoResult::scanned(&repo.id, scan.findings, Vec::new())
            .with_skipped(scan.skipped_unparseable),
        Err(e) => errored(format!("packagist tier-c scan: {e}")),
    }
}

/// Scan a NuGet (.NET) repo with the toolchain-free Tier-C matcher: read
/// `packages.lock.json` and match each package version against the preloaded OSV DB. Builds
/// nothing, so it needs no consent and no sandbox. `nuget_db` is the once-loaded DB: `None`
/// means no `file://` mirror was given (an honest gap), `Some(Err)` a mirror that failed to
/// load (the reason is surfaced, never a false-clean).
fn scan_nuget_repo(repo: &Repo, nuget_db: Option<&Result<NuGetDb, NuGetError>>) -> RepoResult {
    let errored = |reason: String| RepoResult::errored(&repo.id, reason);

    let db = match nuget_db {
        Some(Ok(db)) => db,
        Some(Err(e)) => return errored(format!("NuGet OSV DB: {e}")),
        None => {
            return errored(
                "NuGet repo (packages.lock.json/project.assets.json/packages.config/.csproj): no OSV DB mirror for the toolchain-free \
                 matcher (pass --osv-dir=<dir> or --nuget-vuln-db=file://<path>, e.g. the osv.dev NuGet export \
                 all.zip or an unzipped directory)"
                    .to_string(),
            )
        }
    };
    match fleetreach_nuget::scan_offline_with_coverage(&repo.path, db, &repo.id) {
        Ok(scan) => scan.coverage.into_iter().fold(
            RepoResult::scanned(&repo.id, scan.scan.findings, Vec::new())
                .with_skipped(scan.scan.skipped_unparseable),
            |result, gap| {
                result.with_coverage(CoverageGap {
                    repo: repo.id.clone(),
                    source: gap.source,
                    ecosystem: Ecosystem::NuGet,
                    level: gap.level,
                    reason: gap.reason,
                })
            },
        ),
        Err(e) => errored(format!("nuget tier-c scan: {e}")),
    }
}

/// Scan a Julia repo with the toolchain-free Tier-C matcher: read `Manifest.toml` and match
/// each package version against the preloaded OSV DB. Builds nothing, so it needs no consent
/// and no sandbox. `julia_db` is the once-loaded DB: `None` means no `file://` mirror was
/// given (an honest gap), `Some(Err)` a mirror that failed to load (the reason is surfaced).
fn scan_julia_repo(repo: &Repo, julia_db: Option<&Result<JuliaDb, JuliaError>>) -> RepoResult {
    let errored = |reason: String| RepoResult::errored(&repo.id, reason);

    let db = match julia_db {
        Some(Ok(db)) => db,
        Some(Err(e)) => return errored(format!("Julia OSV DB: {e}")),
        None => {
            return errored(
                "Julia repo (Manifest.toml): no OSV DB mirror for the toolchain-free matcher \
                 (pass --osv-dir=<dir> or --julia-vuln-db=file://<path>, e.g. the osv.dev Julia export all.zip or \
                 an unzipped directory)"
                    .to_string(),
            )
        }
    };
    match fleetreach_julia::scan_offline(&repo.path, db, &repo.id) {
        Ok(scan) => RepoResult::scanned(&repo.id, scan.findings, Vec::new())
            .with_skipped(scan.skipped_unparseable),
        Err(e) => errored(format!("julia tier-c scan: {e}")),
    }
}

/// Scan a Swift repo with the toolchain-free Tier-C matcher: read `Package.resolved` and match
/// each package version against the preloaded OSV DB. Builds nothing, so it needs no consent
/// and no sandbox. `swift_db` is the once-loaded DB: `None` means no `file://` mirror was given
/// (an honest gap), `Some(Err)` a mirror that failed to load (the reason is surfaced).
fn scan_swift_repo(repo: &Repo, swift_db: Option<&Result<SwiftDb, SwiftError>>) -> RepoResult {
    let errored = |reason: String| RepoResult::errored(&repo.id, reason);

    let db =
        match swift_db {
            Some(Ok(db)) => db,
            Some(Err(e)) => return errored(format!("Swift OSV DB: {e}")),
            None => return errored(
                "Swift repo (Package.resolved): no OSV DB mirror for the toolchain-free matcher \
                 (pass --osv-dir=<dir> or --swift-vuln-db=file://<path>, e.g. the osv.dev SwiftURL export all.zip \
                 or an unzipped directory)"
                    .to_string(),
            ),
        };
    match fleetreach_swift::scan_offline(&repo.path, db, &repo.id) {
        Ok(scan) => RepoResult::scanned(&repo.id, scan.findings, Vec::new())
            .with_skipped(scan.skipped_unparseable),
        Err(e) => errored(format!("swift tier-c scan: {e}")),
    }
}

/// Scan a Hex (Elixir) repo with the toolchain-free Tier-C matcher: read `mix.lock` and match
/// each package version against the preloaded OSV DB. Builds nothing, so it needs no consent
/// and no sandbox. `hex_db` is the once-loaded DB: `None` means no `file://` mirror was given
/// (an honest gap), `Some(Err)` a mirror that failed to load (the reason is surfaced).
fn scan_hex_repo(repo: &Repo, hex_db: Option<&Result<HexDb, HexError>>) -> RepoResult {
    let errored = |reason: String| RepoResult::errored(&repo.id, reason);

    let db = match hex_db {
        Some(Ok(db)) => db,
        Some(Err(e)) => return errored(format!("Hex OSV DB: {e}")),
        None => {
            return errored(
                "Hex repo (mix.lock): no OSV DB mirror for the toolchain-free matcher (pass \
                 --osv-dir=<dir> or --hex-vuln-db=file://<path>, e.g. the osv.dev Hex export all.zip or an \
                 unzipped directory)"
                    .to_string(),
            )
        }
    };
    match fleetreach_hex::scan_offline(&repo.path, db, &repo.id) {
        Ok(scan) => RepoResult::scanned(&repo.id, scan.findings, Vec::new())
            .with_skipped(scan.skipped_unparseable),
        Err(e) => errored(format!("hex tier-c scan: {e}")),
    }
}

/// Scan a Maven (Java) repo with the toolchain-free Tier-C matcher: read `gradle.lockfile` or
/// `pom.xml` and match each dependency against the preloaded OSV DB. Builds nothing, so it
/// needs no consent and no sandbox. `maven_db` is the once-loaded DB: `None` means no `file://`
/// mirror was given (an honest gap), `Some(Err)` a mirror that failed to load (surfaced).
fn scan_maven_repo(
    repo: &Repo,
    maven_db: Option<&Result<MavenDb, MavenError>>,
    fetch: bool,
) -> RepoResult {
    let errored = |reason: String| RepoResult::errored(&repo.id, reason);

    let db =
        match maven_db {
            Some(Ok(db)) => db,
            Some(Err(e)) => return errored(format!("Maven OSV DB: {e}")),
            None => return errored(
                "Maven repo (gradle.lockfile/pom.xml): no OSV DB mirror for the toolchain-free \
                 matcher (pass --osv-dir=<dir> or --maven-vuln-db=file://<path>, e.g. the osv.dev Maven export \
                 all.zip or an unzipped directory)"
                    .to_string(),
            ),
        };
    // `gradle.lockfile` is the resolved closure. A `pom.xml` is resolved like Maven would
    // (parents, BOMs, mediation) from local repositories, plus Maven Central with
    // `--maven-fetch`; whatever cannot be resolved is named as partial coverage. A POM that
    // cannot be parsed falls back to its declared dependencies, labelled direct-only.
    if !repo.path.join("gradle.lockfile").is_file() {
        let local = crate::maven_repo::local();
        let central = crate::maven_repo::Central;
        let mut sources: Vec<&dyn fleetreach_maven::PomSource> = vec![&local];
        if fetch {
            sources.push(&central);
        }
        if let Ok(resolution) =
            fleetreach_maven::resolve(&repo.path, &fleetreach_maven::Chain(sources))
        {
            let scan = fleetreach_maven::scan_resolution(&resolution, db, &repo.id);
            let result = RepoResult::scanned(&repo.id, scan.findings, Vec::new())
                .with_skipped(scan.skipped_unparseable);
            if resolution.missing.is_empty() {
                return result;
            }
            let shown: Vec<&str> = resolution
                .missing
                .iter()
                .take(5)
                .map(String::as_str)
                .collect();
            let more = resolution.missing.len().saturating_sub(shown.len());
            let hint = if fetch {
                ""
            } else {
                "; pass --maven-fetch to fetch missing POMs from Maven Central (sends their coordinates), or build once so ~/.m2 has them"
            };
            return result.with_coverage(CoverageGap {
                repo: repo.id.clone(),
                source: "pom.xml".to_string(),
                ecosystem: Ecosystem::Maven,
                level: Coverage::Partial,
                reason: format!(
                    "{} item(s) not resolved: {}{}{hint}",
                    resolution.missing.len(),
                    shown.join("; "),
                    if more > 0 {
                        format!(" and {more} more")
                    } else {
                        String::new()
                    }
                ),
            });
        }
    }
    let direct_only = !repo.path.join("gradle.lockfile").is_file();
    match fleetreach_maven::scan_offline(&repo.path, db, &repo.id) {
        Ok(scan) if direct_only => RepoResult::scanned(&repo.id, scan.findings, Vec::new())
            .with_skipped(scan.skipped_unparseable)
            .with_coverage(CoverageGap {
                repo: repo.id.clone(),
                source: "pom.xml".to_string(),
                ecosystem: Ecosystem::Maven,
                level: Coverage::DirectOnly,
                reason: "pom.xml could not be resolved; only its declared dependencies were \
                         read"
                    .to_string(),
            }),
        Ok(scan) => RepoResult::scanned(&repo.id, scan.findings, Vec::new())
            .with_skipped(scan.skipped_unparseable),
        Err(e) => errored(format!("maven tier-c scan: {e}")),
    }
}

/// Scan a GitHub Actions repo with the toolchain-free Tier-C matcher: read
/// `.github/workflows/*.yml` and match each pinned `uses:` action against the preloaded OSV
/// DB. Builds nothing, so it needs no consent and no sandbox. `ghactions_db` is the
/// once-loaded DB: `None` means no `file://` mirror was given (an honest gap), `Some(Err)` a
/// mirror that failed to load (the reason is surfaced).
fn scan_ghactions_repo(
    repo: &Repo,
    ghactions_db: Option<&Result<GhActionsDb, GhaError>>,
) -> RepoResult {
    let errored = |reason: String| RepoResult::errored(&repo.id, reason);

    let db = match ghactions_db {
        Some(Ok(db)) => db,
        Some(Err(e)) => return errored(format!("GitHub Actions OSV DB: {e}")),
        None => {
            return errored(
                "GitHub Actions repo (.github/workflows): no OSV DB mirror for the \
                 toolchain-free matcher (pass --osv-dir=<dir> or --ghactions-vuln-db=file://<path>, e.g. the \
                 osv.dev GitHub Actions export all.zip or an unzipped directory)"
                    .to_string(),
            )
        }
    };
    match fleetreach_ghactions::scan_offline(&repo.path, db, &repo.id) {
        Ok(scan) => RepoResult::scanned(&repo.id, scan.findings, Vec::new())
            .with_skipped(scan.skipped_unparseable),
        Err(e) => errored(format!("github-actions tier-c scan: {e}")),
    }
}

/// Stamp each in-repo occurrence with whether its package is in the host's
/// built set. Per-occurrence, since the same advisory may be built in one repo
/// and a phantom optional in another.
fn annotate_built(scan: &mut RepoScan, built: &BTreeSet<(String, Version)>) {
    let occurrences = scan
        .vulnerabilities
        .iter_mut()
        .flat_map(|v| v.occurrences.iter_mut())
        .chain(
            scan.warnings
                .iter_mut()
                .flat_map(|w| w.occurrences.iter_mut()),
        );
    for occurrence in occurrences {
        if let Occurrence::InRepo {
            package,
            installed,
            active,
            ..
        } = occurrence
        {
            *active = Some(built.contains(&(package.clone(), installed.clone())));
        }
    }
}

/// Resolve the lockfile(s) for a repo: a single `Cargo.lock` at the root, or —
/// when `glob = true` — every `Cargo.lock` within `glob_max_depth` of the root.
///
/// Returns the discovered paths plus any directory-walk errors. A swallowed walk
/// error (e.g. an unreadable subdir) could hide a `Cargo.lock`, so the caller treats
/// a non-empty error list as a gap (fail closed) rather than reporting the repo clean.
pub fn discover_lockfiles(repo: &Repo) -> (Vec<PathBuf>, Vec<String>) {
    if !repo.glob {
        let lock = repo.path.join("Cargo.lock");
        return (if lock.is_file() { vec![lock] } else { vec![] }, Vec::new());
    }

    let mut paths = Vec::new();
    let mut errors = Vec::new();
    for entry in WalkDir::new(&repo.path).max_depth(repo.glob_max_depth) {
        match entry {
            Ok(e) if e.file_type().is_file() && e.file_name() == "Cargo.lock" => {
                paths.push(e.into_path());
            }
            Ok(_) => {}
            Err(e) => errors.push(e.to_string()),
        }
    }
    (paths, errors)
}
