//! The multi-repo scan loop (§10, step 4).
//!
//! Repos are scanned **serially** (no async in v1). Each repo degrades
//! independently: a missing or unreadable lockfile becomes an `Errored`
//! [`RepoOutcome`] and the run continues — but that gap is what later forces a
//! non-clean exit (§8), since we cannot claim a repo is clean without reading it.
//!
//! Output here is **pre-correlation**: every finding carries a single
//! occurrence. Grouping across the fleet happens in `correlate` (M4).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fleetreach_core::osv::TierCScan;
use fleetreach_core::semver::Version;
use fleetreach_core::{
    Coverage, CoverageGap, DepScope, DependencyKind, Ecosystem, Occurrence, RepoId, RepoOutcome,
    ScanStatus, VulnFinding, WarnFinding,
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
use fleetreach_scan::{
    crates_db_path, scan_lockfile, scan_toolchain, AdvisoryDb, CratesDb, RepoScan, ScanError,
};
use fleetreach_swift::{swift_db_path, SwiftDb, SwiftError};
use rayon::prelude::*;
use walkdir::WalkDir;

use crate::config::{Config, Repo};
use crate::resolve;
use crate::scancache::{Inputs, Session};

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
    /// The base of each image that has a recognizable one.
    pub images: Vec<fleetreach_core::ImageBase>,
    /// The images pulled from registries.
    pub pulled: Vec<fleetreach_core::ImagePull>,
    /// Repos whose results were reused, with `--incremental`.
    pub reused: usize,
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

/// The `file://` OSV mirror of each toolchain-free ecosystem: its matcher reads a lockfile
/// and the mirror, building nothing, so the mirror is all it needs, and without one a repo of
/// that ecosystem is an honest gap. Go, which can also run govulncheck, has [`GoScan`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Mirrors<'a> {
    pub npm: Option<&'a str>,
    pub pypi: Option<&'a str>,
    pub rubygems: Option<&'a str>,
    pub packagist: Option<&'a str>,
    pub nuget: Option<&'a str>,
    pub julia: Option<&'a str>,
    pub swift: Option<&'a str>,
    pub hex: Option<&'a str>,
    pub ghactions: Option<&'a str>,
    /// osv.dev's crates.io export, for what RustSec does not carry.
    pub crates: Option<&'a str>,
    pub maven: Option<&'a str>,
    /// Where to fetch POMs missing locally (`--maven-fetch`): the `settings.xml` mirror of
    /// Maven Central, or Central.
    pub maven_remote: Option<&'a crate::maven_repo::Remote>,
    /// Where results are kept between runs (`--incremental`).
    pub cache: Option<&'a crate::scancache::Store>,
}

/// The OSV DBs a fleet needs, each loaded ONCE and shared read-only by every repo (re-reading
/// a DB per repo is what dominated large fleets before). A DB is loaded only when the fleet
/// has a repo of its ecosystem and a mirror was given; `None` is an honest gap, and a load
/// failure is kept as the `Err` so each repo of that ecosystem reports the reason rather
/// than coming out clean.
#[derive(Default)]
struct Dbs {
    npm: Option<Result<NpmDb, NpmError>>,
    go: Option<Result<GoDb, GoError>>,
    pypi: Option<Result<PyPiDb, PyPiError>>,
    rubygems: Option<Result<RubyGemsDb, RubyGemsError>>,
    packagist: Option<Result<PackagistDb, PackagistError>>,
    nuget: Option<Result<NuGetDb, NuGetError>>,
    julia: Option<Result<JuliaDb, JuliaError>>,
    swift: Option<Result<SwiftDb, SwiftError>>,
    hex: Option<Result<HexDb, HexError>>,
    ghactions: Option<Result<GhActionsDb, GhaError>>,
    crates: Option<Result<CratesDb, ScanError>>,
    maven: Option<Result<MavenDb, MavenError>>,
}

impl Dbs {
    /// Load every DB the fleet needs at the same time: each load is parallel inside but
    /// leaves cores idle on its own, so one after another a polyglot fleet waited for the sum.
    fn load(
        has: &(dyn Fn(Ecosystem) -> bool + Sync),
        go: &GoScan,
        m: &Mirrors,
        overlay: Option<&Path>,
        rustsec: &AdvisoryDb,
    ) -> Dbs {
        // Every OSV feeder layers the organization's own records (`[settings.advisories]`)
        // over its export; Go's offline matcher reads its own format and does not.
        fn spawn<'s, D: Send>(
            scope: &rayon::Scope<'s>,
            slot: &'s mut Option<D>,
            wanted: bool,
            root: Option<PathBuf>,
            load: impl FnOnce(&Path) -> D + Send + 's,
        ) {
            if let (true, Some(root)) = (wanted, root) {
                scope.spawn(move |_| *slot = Some(load(&root)));
            }
        }
        let mut dbs = Dbs::default();
        let Dbs {
            npm,
            go: go_db,
            pypi,
            rubygems,
            packagist,
            nuget,
            julia,
            swift,
            hex,
            ghactions,
            crates,
            maven,
        } = &mut dbs;
        let root = |mirror: Option<&str>, path: fn(&str) -> Option<PathBuf>| mirror.and_then(path);
        rayon::scope(|s| {
            use Ecosystem as E;
            spawn(s, npm, has(E::Npm), root(m.npm, npm_db_path), |r: &Path| {
                NpmDb::load_with_overlay(r, overlay)
            });
            // The Go mirror is only the Tier-C fallback, unused when govulncheck runs.
            let go_wanted = go.govulncheck.is_none() && has(E::Go);
            let go_root = root(go.vuln_db, fleetreach_go::offline_db_path);
            spawn(s, go_db, go_wanted, go_root, GoDb::load);
            spawn(
                s,
                pypi,
                has(E::Pypi),
                root(m.pypi, pypi_db_path),
                |r: &Path| PyPiDb::load_with_overlay(r, overlay),
            );
            let rubygems_root = root(m.rubygems, rubygems_db_path);
            spawn(s, rubygems, has(E::RubyGems), rubygems_root, |r: &Path| {
                RubyGemsDb::load_with_overlay(r, overlay)
            });
            let packagist_root = root(m.packagist, packagist_db_path);
            spawn(
                s,
                packagist,
                has(E::Packagist),
                packagist_root,
                |r: &Path| PackagistDb::load_with_overlay(r, overlay),
            );
            spawn(
                s,
                nuget,
                has(E::NuGet),
                root(m.nuget, nuget_db_path),
                |r: &Path| NuGetDb::load_with_overlay(r, overlay),
            );
            spawn(
                s,
                julia,
                has(E::Julia),
                root(m.julia, julia_db_path),
                |r: &Path| JuliaDb::load_with_overlay(r, overlay),
            );
            spawn(
                s,
                swift,
                has(E::Swift),
                root(m.swift, swift_db_path),
                |r: &Path| SwiftDb::load_with_overlay(r, overlay),
            );
            spawn(s, hex, has(E::Hex), root(m.hex, hex_db_path), |r: &Path| {
                HexDb::load_with_overlay(r, overlay)
            });
            let gha_root = root(m.ghactions, ghactions_db_path);
            spawn(s, ghactions, has(E::GitHubActions), gha_root, |r: &Path| {
                GhActionsDb::load_with_overlay(r, overlay)
            });
            let crates_root = root(m.crates, crates_db_path);
            spawn(s, crates, has(E::Cargo), crates_root, |r: &Path| {
                CratesDb::load_with_overlay(r, overlay).map(|db| db.beside(rustsec))
            });
            spawn(
                s,
                maven,
                has(E::Maven),
                root(m.maven, maven_db_path),
                |r: &Path| MavenDb::load_with_overlay(r, overlay),
            );
        });
        dbs
    }
}

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
    mirrors: &Mirrors,
) -> ScanData {
    scan_fleet_with(
        db,
        config,
        toolchain,
        host_triple,
        go,
        mirrors,
        &Images::default(),
    )
}

/// The container images of a scan, opened, and the distro exports serving them.
#[derive(Default)]
pub(crate) struct Images<'a> {
    pub(crate) prepared: &'a [crate::images::Prepared],
    /// The resolved distro exports (`all.zip` files or record directories).
    pub(crate) exports: Vec<PathBuf>,
    /// Those read as a frozen ecosystem, and which.
    pub(crate) frozen: BTreeMap<PathBuf, String>,
    /// Distro ecosystems with no export.
    pub(crate) missing: BTreeSet<String>,
    pub(crate) opts: fleetreach_os::ScanOptions,
}

/// [`scan_fleet`], plus container images: each image's OS packages against the distro
/// exports, and its language lockfiles and installed packages with the language feeders.
pub(crate) fn scan_fleet_with(
    db: &AdvisoryDb,
    config: &Config,
    toolchain: Option<&Toolchain>,
    host_triple: Option<&str>,
    go: &GoScan,
    mirrors: &Mirrors,
    images: &Images,
) -> ScanData {
    let mut data = ScanData::default();

    // Plan every repo up front: which ecosystems it holds and where. The plans decide which
    // OSV DBs are worth loading, then drive the per-repo scan.
    let plans: Vec<RepoPlan> = config
        .repos
        .par_iter()
        .map(|repo| repo_plan(config, repo))
        .collect();
    let image_plans: Vec<Option<RepoPlan>> = images
        .prepared
        .iter()
        .map(|p| {
            p.opened
                .as_ref()
                .ok()
                .map(|o| image_lang_plan(&o.lang_repo))
        })
        .collect();
    let image_ecosystems = crate::images::language_ecosystems(images.prepared);
    let session = cache_session(db, go, mirrors, config, &plans);
    let keys: Vec<Option<String>> = plans
        .par_iter()
        .zip(&config.repos)
        .map(|(plan, repo)| cache_key(session.as_ref()?, plan, repo, go, host_triple))
        .collect();
    let mut reused: Vec<Option<RepoResult>> = keys
        .par_iter()
        .zip(&config.repos)
        .map(|(key, repo)| session.as_ref()?.store.get(repo, key.as_deref()?))
        .collect();
    data.reused = reused.iter().flatten().count();
    // What was reused needs no advisory database.
    let has = |eco: Ecosystem| {
        image_ecosystems.contains(&eco)
            || plans
                .iter()
                .zip(&reused)
                .filter(|(_, hit)| hit.is_none())
                .any(|(p, _)| p.units.iter().any(|u| u.ecosystem == eco))
    };

    let dbs = Dbs::load(&has, go, mirrors, config.osv.advisories.as_deref(), db);
    let distro_db = load_distro_db(images);

    // Each repo is independent and shares only the read-only advisory DBs, so the
    // per-repo scan (dominated by lockfile parsing) fans out across cores. Results
    // are collected in config order and merged serially, so the assembled output
    // is byte-identical to a serial scan regardless of completion order.
    let scan_unit_with = |unit: &ScanUnit| {
        if let Some(sbom) = &unit.sbom {
            return scan_sbom_unit(db, &unit.repo, unit.ecosystem, sbom, &dbs);
        }
        if unit.alongside && dbs.ghactions.is_none() {
            return RepoResult::scanned(&unit.repo.id, Vec::new(), Vec::new()).with_coverage(
                CoverageGap {
                    repo: unit.repo.id.clone(),
                    source: ".github/workflows".to_string(),
                    ecosystem: Ecosystem::GitHubActions,
                    level: Coverage::Partial,
                    reason: "workflow actions not matched: no GitHub Actions OSV mirror \
                             (fleetreach db sync --ecosystems gha, or \
                             --ghactions-vuln-db)"
                        .to_string(),
                },
            );
        }
        scan_unit(
            db,
            &unit.repo,
            unit.ecosystem,
            host_triple,
            go,
            &dbs,
            mirrors.maven_remote,
        )
    };
    let per_repo: Vec<RepoResult> = plans
        .par_iter()
        .zip(reused.par_iter_mut())
        .zip(keys.par_iter().zip(&config.repos))
        .map(|((plan, hit), (key, repo))| {
            if let Some(result) = hit.take() {
                return result;
            }
            let result = merge_units(plan, plan.units.iter().map(|u| (u, scan_unit_with(u))));
            if let (Some(session), Some(key)) = (&session, key) {
                if matches!(result.outcome.status, ScanStatus::Scanned { .. }) {
                    session.store.put(repo, key, &result);
                }
            }
            result
        })
        .collect();

    for (plan, result) in plans.iter().zip(per_repo) {
        data.vulnerabilities.extend(result.vulnerabilities);
        data.warnings.extend(result.warnings);
        data.outcomes.push(result.outcome);
        data.skipped_unparseable += result.skipped_unparseable;
        data.coverage.extend(plan.unsupported.iter().cloned());
        data.coverage.extend(result.coverage);
    }

    let per_image: Vec<(RepoResult, Vec<CoverageGap>)> = images
        .prepared
        .par_iter()
        .zip(&image_plans)
        .map(|(image, plan)| {
            scan_image(
                image,
                plan.as_ref(),
                images,
                distro_db.as_ref(),
                db,
                &dbs,
                &scan_unit_with,
            )
        })
        .collect();
    data.pulled
        .extend(images.prepared.iter().filter_map(|image| {
            Some(fleetreach_core::ImagePull {
                repo: image.id.clone(),
                reference: image.source.clone(),
                digest: image.digest.clone()?,
                vex: image.vex_attestations(),
            })
        }));
    data.images
        .extend(images.prepared.iter().filter_map(|image| {
            let opened = image.opened.as_ref().ok()?;
            opened.layers.base(&image.id, &opened.inspection)
        }));
    for (result, unsupported) in per_image {
        data.vulnerabilities.extend(result.vulnerabilities);
        data.warnings.extend(result.warnings);
        data.outcomes.push(result.outcome);
        data.skipped_unparseable += result.skipped_unparseable;
        data.coverage.extend(unsupported);
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

/// The identity of the advisory data of every ecosystem the fleet plans to scan.
fn cache_session<'a>(
    db: &AdvisoryDb,
    go: &GoScan,
    mirrors: &Mirrors<'a>,
    config: &Config,
    plans: &[RepoPlan],
) -> Option<Session<'a>> {
    let store = mirrors.cache?;
    let ecosystems: BTreeSet<Ecosystem> = plans
        .iter()
        .flat_map(|p| p.units.iter().map(|u| u.ecosystem))
        .collect();
    let advisories = ecosystems
        .into_par_iter()
        .map(|eco| {
            let mirror = match eco {
                Ecosystem::Npm => mirrors.npm,
                Ecosystem::Pypi => mirrors.pypi,
                Ecosystem::RubyGems => mirrors.rubygems,
                Ecosystem::Packagist => mirrors.packagist,
                Ecosystem::NuGet => mirrors.nuget,
                Ecosystem::Julia => mirrors.julia,
                Ecosystem::Swift => mirrors.swift,
                Ecosystem::Hex => mirrors.hex,
                Ecosystem::GitHubActions => mirrors.ghactions,
                Ecosystem::Go => go.vuln_db,
                Ecosystem::Cargo => mirrors.crates,
                Ecosystem::Maven | Ecosystem::Deb | Ecosystem::Apk | Ecosystem::Rpm => {
                    return (eco, None)
                }
            };
            let identity = crate::scancache::mirror_identity(mirror);
            let identity = if eco == Ecosystem::Cargo {
                identity.map(|id| format!("{id}:{}", db.fingerprint()))
            } else {
                identity
            };
            (eco, identity)
        })
        .collect();
    Session::open(store, config.osv.advisories.as_deref(), advisories)
}

/// What a repo's results are stored under, or `None` when they depend on more than its files
/// and the advisory data.
fn cache_key(
    session: &Session,
    plan: &RepoPlan,
    repo: &Repo,
    go: &GoScan,
    host_triple: Option<&str>,
) -> Option<String> {
    let depends_on_more = |unit: &ScanUnit| {
        unit.sbom.is_some()
            || (unit.ecosystem == Ecosystem::Go && go.govulncheck.is_some())
            || (unit.ecosystem == Ecosystem::Cargo && host_triple.is_some())
    };
    if !plan.walk_errors.is_empty() || plan.units.iter().any(depends_on_more) {
        return None;
    }
    let units: Vec<(Ecosystem, String, bool)> = plan
        .units
        .iter()
        .map(|u| (u.ecosystem, u.rel_dir.clone(), u.alongside))
        .collect();
    let mut inputs = Inputs::default();
    for unit in &plan.units {
        match unit.ecosystem {
            Ecosystem::Cargo => {
                let (lockfiles, walk_errors) = discover_lockfiles(repo);
                if !walk_errors.is_empty() {
                    return None;
                }
                // Scope comes from the workspace manifests beside each lockfile.
                for lockfile in &lockfiles {
                    let dir = lockfile.parent()?;
                    inputs.files.insert(dir.join("Cargo.toml"));
                    inputs
                        .files
                        .extend(crate::scope::cargo_manifests(dir).unwrap_or_default());
                }
                inputs.files.extend(lockfiles);
            }
            Ecosystem::GitHubActions => {
                let dir = &unit.repo.path;
                inputs.trees.insert(dir.join(".github"));
                inputs.files.insert(dir.join("action.yml"));
                inputs.files.insert(dir.join("action.yaml"));
            }
            _ => {
                inputs.trees.insert(unit.repo.path.clone());
            }
        }
    }
    session.key(repo, &units, &inputs)
}

/// The ecosystems present anywhere in the fleet, sorted. Planning only walks directories, so
/// this is cheap; it decides which OSV exports a run needs before any is loaded or fetched.
pub fn fleet_ecosystems(config: &Config) -> Vec<Ecosystem> {
    let found: BTreeSet<Ecosystem> = config
        .repos
        .par_iter()
        .map(|repo| repo_plan(config, repo))
        .collect::<Vec<_>>()
        .iter()
        .flat_map(|p| p.units.iter().map(|u| u.ecosystem))
        .collect();
    found.into_iter().collect()
}

/// The findings and outcome for a single repo, returned by the parallel map so
/// the caller can merge them in deterministic (config) order.
#[derive(serde::Serialize, serde::Deserialize)]
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

    /// Add a warning, counted in a scanned outcome.
    fn with_warning(mut self, warning: WarnFinding) -> Self {
        self.warnings.push(warning);
        if let ScanStatus::Scanned { warnings, .. } = &mut self.outcome.status {
            *warnings = self.warnings.len();
        }
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
    /// Workflows scanned alongside the repo's other ecosystems: without a GitHub Actions
    /// mirror they are a coverage gap rather than an error, so a fleet scanned with only the
    /// data its lockfiles need still scans.
    pub(crate) alongside: bool,
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

/// What a repo is scanned from: the SBOM it names, its own files, or the SBOMs it holds.
fn repo_plan(config: &Config, repo: &Repo) -> RepoPlan {
    match config.sboms.get(&repo.id) {
        Some(path) => sbom_plan(repo, std::slice::from_ref(path)),
        None => discovered_plan(config, plan_repo(repo), repo),
    }
}

/// `plan`, or with `[settings.sbom] discover` and nothing else to read, the SBOMs in the repo.
/// A lockfile is always the better source, so one never gives way to an SBOM.
fn discovered_plan(config: &Config, plan: RepoPlan, repo: &Repo) -> RepoPlan {
    if !plan.walk_errors.is_empty() || !config.discovers_sboms(&repo.id) {
        return plan;
    }
    // A repo with nothing to read still plans one Cargo unit, which reports that.
    let reads_something = plan.units.iter().any(|u| match u.ecosystem {
        Ecosystem::GitHubActions => false,
        Ecosystem::Cargo => !discover_lockfiles(repo).0.is_empty(),
        _ => true,
    });
    if reads_something {
        return plan;
    }
    let found = crate::sbom_input::discover(&repo.path);
    if found.is_empty() {
        return plan;
    }
    let mut from_sboms = sbom_plan(repo, &found);
    let has_actions = |p: &RepoPlan| {
        p.units
            .iter()
            .any(|u| u.ecosystem == Ecosystem::GitHubActions)
    };
    if !has_actions(&from_sboms) {
        let workflows = plan
            .units
            .into_iter()
            .filter(|u| u.ecosystem == Ecosystem::GitHubActions)
            .map(|u| ScanUnit {
                alongside: true,
                ..u
            });
        from_sboms.units.extend(workflows);
    }
    from_sboms.unsupported.extend(plan.unsupported);
    from_sboms
}

/// The plan of a repo scanned from its SBOMs: one unit per ecosystem they hold, plus a coverage
/// gap when they do not assert completeness, predate the lockfiles or list packages no matcher
/// takes.
fn sbom_plan(repo: &Repo, paths: &[PathBuf]) -> RepoPlan {
    let source = match paths {
        [path] => path
            .strip_prefix(&repo.path)
            .unwrap_or(path)
            .display()
            .to_string(),
        many => format!("{} SBOMs", many.len()),
    };
    let read = crate::sbom_input::read_all(paths);
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
            if let Some(reason) = crate::sbom_input::stale(&repo.path, input.created) {
                plan.unsupported.push(gap(reason));
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
            alongside: false,
        });
    }
    plan
}

/// Scan one ecosystem's packages from an SBOM with that ecosystem's matcher.
fn scan_sbom_unit(
    advisories: &AdvisoryDb,
    repo: &Repo,
    ecosystem: Ecosystem,
    sbom: &Result<crate::sbom_input::SbomInput, String>,
    dbs: &Dbs,
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
    if ecosystem == Ecosystem::Cargo {
        let crates: Vec<(String, String)> = pkgs
            .iter()
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();
        let (osv, gap) = crates_or_gap(&repo.id, "SBOM", dbs.crates.as_ref());
        let (mut scan, skipped) =
            fleetreach_scan::scan_crates(advisories, osv, &repo.id, "SBOM", &crates);
        place_in_sbom(&mut scan.vulnerabilities, pkgs, g);
        let result = RepoResult::scanned(&repo.id, scan.vulnerabilities, scan.warnings)
            .with_skipped(skipped);
        return gap.into_iter().fold(result, RepoResult::with_coverage);
    }
    let scan = (|| -> Result<TierCScan, String> {
        Ok(match ecosystem {
            Ecosystem::Go => {
                let db = db(dbs.go.as_ref(), ecosystem)?;
                let modules: Vec<(String, String, String)> = pkgs
                    .iter()
                    .flat_map(|p| {
                        let named = db.modules_named(&p.name);
                        named
                            .into_iter()
                            .map(|module| (String::new(), module, p.version.clone()))
                    })
                    .collect();
                let (mut findings, skipped_unparseable) =
                    fleetreach_go::scan_built(&modules, db, &repo.id);
                place_in_sbom(&mut findings, pkgs, g);
                TierCScan {
                    findings,
                    skipped_unparseable,
                }
            }
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
                db(dbs.npm.as_ref(), ecosystem)?,
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
                db(dbs.pypi.as_ref(), ecosystem)?,
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
                db(dbs.packagist.as_ref(), ecosystem)?,
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
                db(dbs.rubygems.as_ref(), ecosystem)?,
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
                db(dbs.nuget.as_ref(), ecosystem)?,
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
                db(dbs.julia.as_ref(), ecosystem)?,
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
                db(dbs.swift.as_ref(), ecosystem)?,
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
                db(dbs.hex.as_ref(), ecosystem)?,
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
                fleetreach_maven::scan_resolution(
                    &resolution,
                    db(dbs.maven.as_ref(), ecosystem)?,
                    &repo.id,
                )
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

/// Fills in what the SBOM says of each finding's package, for the matchers built to read
/// binaries, which know nothing of it. A name held at several versions is direct if any is, and
/// dev only if all are. Names compare without case, as Go purls may have lost theirs.
fn place_in_sbom(
    findings: &mut [VulnFinding],
    packages: &[crate::sbom_input::SbomPackage],
    graph: &fleetreach_core::DepGraph,
) {
    let mut by_name: BTreeMap<String, (&str, bool, bool)> = BTreeMap::new();
    for p in packages {
        let entry = by_name
            .entry(p.name.to_lowercase())
            .or_insert((p.name.as_str(), false, true));
        entry.1 |= p.direct;
        entry.2 &= p.dev;
    }
    for occurrence in findings.iter_mut().flat_map(|f| &mut f.occurrences) {
        if let Occurrence::InRepo {
            package,
            dependency_kind,
            dependency_path,
            scope,
            ..
        } = occurrence
        {
            let Some((name, direct, dev)) = by_name.get(&package.to_lowercase()) else {
                continue;
            };
            *dependency_path = graph.chain_to(name);
            if *direct {
                *dependency_kind = DependencyKind::Direct;
            }
            if *dev {
                *scope = DepScope::Dev;
            }
        }
    }
}

// ---- Container images ----

/// The language units of an image's written-out lockfiles: [`plan_repo`] without the Cargo
/// fallback (an image with no `Cargo.lock` has no Rust packages, which is not a gap) and
/// without workflows, which an image does not run.
pub(crate) fn image_lang_plan(repo: &Repo) -> RepoPlan {
    let mut plan = plan_repo(repo);
    let has_cargo = !discover_lockfiles(repo).0.is_empty();
    plan.units.retain(|u| match u.ecosystem {
        Ecosystem::Cargo => has_cargo,
        Ecosystem::GitHubActions => false,
        _ => true,
    });
    plan
}

/// The units [`image_lang_plan`] scans.
pub(crate) fn image_lang_units(repo: &Repo) -> Vec<ScanUnit> {
    image_lang_plan(repo).units
}

/// Load the advisories of every image's distro ecosystems once, kept to the source packages
/// the images install. `None` when no image has a matchable distro or no export resolved.
fn load_distro_db(images: &Images) -> Option<Result<fleetreach_os::db::DistroDb, String>> {
    let mut wanted = fleetreach_os::db::Wanted::default();
    let mut packages = BTreeSet::new();
    for image in images.prepared {
        let Ok(opened) = &image.opened else { continue };
        let Ok(distro) = &opened.inspection.distro else {
            continue;
        };
        for eco in distro.ecosystems() {
            wanted.ecosystems.insert(eco, distro.family);
        }
        let installed = &opened.inspection.inventory.packages;
        // Source names, and binary names for distros whose advisories or vendor VEX name
        // binaries (SUSE's VEX does, its osv.dev records do not).
        packages.extend(installed.iter().map(|p| p.source.clone()));
        // Root renames what it rebuilds, and files records under either name.
        for p in installed {
            packages.insert(fleetreach_os::distro::unrooted(&p.source).to_string());
            packages.insert(fleetreach_os::distro::rooted(&p.source));
        }
        if distro.binary_names || !distro.fallbacks.is_empty() {
            packages.extend(installed.iter().map(|p| p.name.clone()));
        }
    }
    if wanted.ecosystems.is_empty() || images.exports.is_empty() {
        return None;
    }
    wanted.packages = Some(packages);
    wanted.frozen = images.frozen.clone();
    Some(fleetreach_os::db::load(&images.exports, &wanted).map_err(|e| e.to_string()))
}

/// Scan one image: its OS packages, its installed PyPI and npm packages, and each of its
/// lockfile units, folded into one result under the image's id. The second value is the
/// image's unsupported-lockfile gaps.
fn scan_image(
    image: &crate::images::Prepared,
    plan: Option<&RepoPlan>,
    images: &Images,
    distro_db: Option<&Result<fleetreach_os::db::DistroDb, String>>,
    db: &AdvisoryDb,
    dbs: &Dbs,
    scan_unit: &(dyn Fn(&ScanUnit) -> RepoResult + Sync),
) -> (RepoResult, Vec<CoverageGap>) {
    let (Ok(opened), Some(plan)) = (&image.opened, plan) else {
        let reason = match &image.opened {
            Err(e) => e.clone(),
            Ok(_) => "the image was not planned".to_string(),
        };
        let reason = format!("image {}: {reason}", image.source);
        return (RepoResult::errored(&image.id, reason), Vec::new());
    };
    let own = |ecosystem: Ecosystem| ScanUnit {
        ecosystem,
        repo: opened.lang_repo.clone(),
        rel_dir: String::new(),
        sbom: None,
        alongside: false,
    };
    let layers = &opened.layers;
    let mut os = scan_image_os(&image.id, opened, images, distro_db);
    // The real binary names ride in the path: distro, source, then the binaries.
    attribute(&mut os.1, layers, |_, path| {
        layers.of_packages(path.get(2)?.split(", "))
    });
    let mut extra = vec![(own(os.0), os.1)];
    let graph = fleetreach_core::DepGraph::new(image.id.0.clone());
    let pypi = with_vendors(&opened.pypi, &opened.packaged_pypi, distro_db);
    let npm = with_vendors(&opened.npm, &opened.packaged_npm, distro_db);
    let composer = with_vendors(&opened.composer, &opened.packaged_composer, distro_db);
    let nuget = with_vendors(&opened.nuget, &opened.packaged_nuget, distro_db);
    let gems = with_vendors(&opened.gems, &opened.packaged_gems, distro_db);
    let java = with_vendors(&opened.java, &opened.packaged_java, distro_db);
    let go = with_vendors(&opened.go, &opened.packaged_go, distro_db);
    let rust = with_vendors(&opened.rust, &opened.packaged_rust, distro_db);
    if !pypi.is_empty() {
        let installed: Vec<fleetreach_pypi::InstalledPackage> = pypi
            .iter()
            .map(|p| fleetreach_pypi::InstalledPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                direct: false,
                dev: false,
            })
            .collect();
        let result = match tier_c_db(dbs.pypi.as_ref(), &PYPI) {
            Ok(db) => {
                let scan = fleetreach_pypi::scan_installed(&installed, &graph, db, &image.id);
                RepoResult::scanned(&image.id, scan.findings, Vec::new())
                    .with_skipped(scan.skipped_unparseable)
            }
            Err(reason) => RepoResult::errored(
                &image.id,
                format!("{} installed Python packages: {reason}", installed.len()),
            ),
        };
        let mut result = result;
        attribute_installed(&mut result, layers, &pypi);
        extra.push((own(Ecosystem::Pypi), result));
    }
    if !npm.is_empty() {
        let installed: Vec<fleetreach_npm::InstalledPackage> = npm
            .iter()
            .map(|p| fleetreach_npm::InstalledPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                direct: false,
                dev: false,
            })
            .collect();
        let result = match tier_c_db(dbs.npm.as_ref(), &NPM) {
            Ok(db) => {
                let scan = fleetreach_npm::scan_installed(&installed, &graph, db, &image.id);
                RepoResult::scanned(&image.id, scan.findings, Vec::new())
                    .with_skipped(scan.skipped_unparseable)
            }
            Err(reason) => RepoResult::errored(
                &image.id,
                format!("{} installed npm packages: {reason}", installed.len()),
            ),
        };
        let mut result = result;
        attribute_installed(&mut result, layers, &npm);
        extra.push((own(Ecosystem::Npm), result));
    }
    if !gems.is_empty() {
        let installed: Vec<fleetreach_rubygems::InstalledGem> = gems
            .iter()
            .map(|p| fleetreach_rubygems::InstalledGem {
                name: p.name.clone(),
                version: p.version.clone(),
                direct: false,
            })
            .collect();
        let result = match tier_c_db(dbs.rubygems.as_ref(), &RUBYGEMS) {
            Ok(db) => {
                let scan = fleetreach_rubygems::scan_installed(&installed, &graph, db, &image.id);
                RepoResult::scanned(&image.id, scan.findings, Vec::new())
                    .with_skipped(scan.skipped_unparseable)
            }
            Err(reason) => RepoResult::errored(
                &image.id,
                format!("{} installed gems: {reason}", installed.len()),
            ),
        };
        let mut result = result;
        attribute_installed(&mut result, layers, &gems);
        extra.push((own(Ecosystem::RubyGems), result));
    }
    if !nuget.is_empty() {
        let installed: Vec<fleetreach_nuget::InstalledPackage> = nuget
            .iter()
            .map(|p| fleetreach_nuget::InstalledPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                direct: false,
            })
            .collect();
        let result = match tier_c_db(dbs.nuget.as_ref(), &NUGET) {
            Ok(db) => {
                let scan = fleetreach_nuget::scan_installed(&installed, &graph, db, &image.id);
                RepoResult::scanned(&image.id, scan.findings, Vec::new())
                    .with_skipped(scan.skipped_unparseable)
            }
            Err(reason) => RepoResult::errored(
                &image.id,
                format!("{} .NET packages: {reason}", installed.len()),
            ),
        };
        let mut result = result;
        attribute_installed(&mut result, layers, &nuget);
        extra.push((own(Ecosystem::NuGet), result));
    }
    if !composer.is_empty() {
        let installed: Vec<fleetreach_packagist::InstalledPackage> = composer
            .iter()
            .map(|p| fleetreach_packagist::InstalledPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                direct: false,
                dev: false,
            })
            .collect();
        let result = match tier_c_db(dbs.packagist.as_ref(), &PACKAGIST) {
            Ok(db) => {
                let scan = fleetreach_packagist::scan_installed(&installed, &graph, db, &image.id);
                RepoResult::scanned(&image.id, scan.findings, Vec::new())
                    .with_skipped(scan.skipped_unparseable)
            }
            Err(reason) => RepoResult::errored(
                &image.id,
                format!("{} installed Composer packages: {reason}", installed.len()),
            ),
        };
        let mut result = result;
        attribute_installed(&mut result, layers, &composer);
        extra.push((own(Ecosystem::Packagist), result));
    }
    if !java.is_empty() {
        let result = match tier_c_db(dbs.maven.as_ref(), &MAVEN) {
            Ok(db) => scan_image_java(&image.id, &java, db),
            Err(reason) => RepoResult::errored(
                &image.id,
                format!("{} Java archive entries: {reason}", java.len()),
            ),
        };
        let mut result = result;
        attribute(&mut result, layers, |_, path| layers.of_file(path.first()?));
        extra.push((own(Ecosystem::Maven), result));
    }
    if !go.is_empty() {
        let mut result = match dbs.go.as_ref() {
            Some(Ok(db)) => scan_image_go(&image.id, &go, db),
            Some(Err(e)) => {
                RepoResult::errored(&image.id, format!("{} Go binaries: {e}", go.len()))
            }
            None => RepoResult::errored(
                &image.id,
                format!(
                    "{} Go binaries, and no Go advisories: pass --go-vuln-db or sync the Go export",
                    go.len()
                ),
            ),
        };
        attribute(&mut result, layers, |_, path| layers.of_file(path.first()?));
        extra.push((own(Ecosystem::Go), result));
    }
    if !rust.is_empty() {
        let mut result = scan_image_rust(&image.id, &rust, db, dbs.crates.as_ref());
        attribute(&mut result, layers, |_, path| layers.of_file(path.first()?));
        extra.push((own(Ecosystem::Cargo), result));
    }
    let lang: Vec<RepoResult> = plan
        .units
        .par_iter()
        .map(|unit| {
            let mut result = scan_unit(unit);
            attribute(&mut result, layers, |_, _| layers.of_dir(&unit.rel_dir));
            result
        })
        .collect();
    let (units, results): (Vec<ScanUnit>, Vec<RepoResult>) = extra.into_iter().unzip();
    let merged = merge_units(
        plan,
        units.iter().zip(results).chain(plan.units.iter().zip(lang)),
    );
    (merged, plan.unsupported.clone())
}

/// Mark each finding in `result` with the image layer `at` finds for its package and path.
fn attribute(
    result: &mut RepoResult,
    layers: &crate::images::Layers,
    at: impl Fn(&str, &[String]) -> Option<usize>,
) {
    for occurrence in result
        .vulnerabilities
        .iter_mut()
        .flat_map(|v| &mut v.occurrences)
    {
        if let Occurrence::InRepo {
            package,
            dependency_path,
            layer,
            ..
        } = occurrence
        {
            *layer = at(package, dependency_path).and_then(|i| layers.describe(i));
        }
    }
}

/// [`attribute`] for packages read from installed metadata, by name. Names compare as the
/// feeders' normalized forms do, and several installs of one name take the highest layer.
fn attribute_installed(
    result: &mut RepoResult,
    layers: &crate::images::Layers,
    installed: &[fleetreach_os::lang::Installed],
) {
    let name = |n: &str| n.to_lowercase().replace(['_', '.'], "-");
    attribute(result, layers, |package, _| {
        installed
            .iter()
            .filter(|i| name(&i.name) == name(package))
            .map(|i| layers.of_file(&i.path))
            .try_fold(None, |top: Option<usize>, l| Some(top.max(Some(l?))))?
    });
}

/// What an image holds outside OS packages, and what OS packages hold that no distribution
/// advisory could cover: a package they never name is a vendor's, not the distribution's.
fn with_vendors<T: Clone>(
    own: &[T],
    packaged: &[crate::images::Packaged<T>],
    distro_db: Option<&Result<fleetreach_os::db::DistroDb, String>>,
) -> Vec<T> {
    let known = |names: &[String; 2]| matches!(distro_db, Some(Ok(db)) if names.iter().any(|name| db.mentions(name)));
    let vendors = packaged.iter().filter(|p| !known(&p.names));
    own.iter()
        .cloned()
        .chain(vendors.map(|p| p.item.clone()))
        .collect()
}

/// Match the modules and standard library linked into an image's Go binaries.
fn scan_image_go(
    id: &RepoId,
    binaries: &[(String, fleetreach_os::gobin::GoBuild)],
    db: &GoDb,
) -> RepoResult {
    let mut modules: Vec<(String, String, String)> = Vec::new();
    for (path, build) in binaries {
        let stdlib = build
            .toolchain
            .iter()
            .map(|version| (fleetreach_os::gobin::STDLIB, version));
        let linked = build.modules.iter().map(|(m, v)| (m.as_str(), v));
        for (module, version) in stdlib.chain(linked) {
            modules.push((path.clone(), module.to_string(), version.clone()));
        }
    }
    let (findings, unreadable) = fleetreach_go::scan_built(&modules, db, id);
    RepoResult::scanned(id, findings, Vec::new()).with_skipped(unreadable)
}

/// Match the crates linked into an image's Rust binaries.
fn scan_image_rust(
    id: &RepoId,
    binaries: &[(String, fleetreach_os::rustbin::RustBuild)],
    db: &AdvisoryDb,
    crates: Option<&Result<CratesDb, ScanError>>,
) -> RepoResult {
    let source = "Rust binaries";
    let (crates, gap) = crates_or_gap(id, source, crates);
    let mut vulnerabilities = Vec::new();
    let mut warnings = Vec::new();
    let mut unreadable = 0;
    for (path, build) in binaries {
        let (scan, skipped) = fleetreach_scan::scan_crates(db, crates, id, path, &build.crates);
        vulnerabilities.extend(scan.vulnerabilities);
        warnings.extend(scan.warnings);
        unreadable += skipped;
    }
    let result = RepoResult::scanned(id, vulnerabilities, warnings).with_skipped(unreadable);
    gap.into_iter().fold(result, RepoResult::with_coverage)
}

/// The crates.io advisories, or the coverage gap of going without them: RustSec still answers,
/// so the scan stands, but a broken export is reported as much as an absent one.
fn crates_or_gap<'a>(
    repo: &RepoId,
    source: &str,
    crates: Option<&'a Result<CratesDb, ScanError>>,
) -> (Option<&'a CratesDb>, Option<CoverageGap>) {
    let reason = match crates {
        Some(Ok(db)) => return (Some(db), None),
        Some(Err(e)) => format!("the crates.io export could not be read: {e}"),
        None => "no crates.io export".to_string(),
    };
    let gap = CoverageGap {
        repo: repo.clone(),
        source: source.to_string(),
        ecosystem: Ecosystem::Cargo,
        level: Coverage::Partial,
        reason: format!(
            "{reason}, so advisories RustSec does not carry were not matched; run `fleetreach \
             db sync`, or pass --osv-dir=<dir> or --crates-vuln-db=file://<path>"
        ),
    };
    (None, Some(gap))
}

/// Match what an image's Java archives hold. A jar known only by its file name is placed by
/// [`fleetreach_maven::settle_group`]; one advisories could apply to but whose group cannot be
/// settled is a coverage gap, as an unread archive is.
fn scan_image_java(
    id: &RepoId,
    found: &[fleetreach_os::jar::Found],
    db: &fleetreach_maven::MavenDb,
) -> RepoResult {
    use fleetreach_maven::{settle_bundle, settle_group, Group, InstalledPackage};
    use fleetreach_os::jar::Found;
    let artifacts = db.artifacts();
    let mut installed: Vec<(InstalledPackage, Vec<String>)> = Vec::new();
    let mut unsettled: Vec<&str> = Vec::new();
    let mut unplaced: Vec<&str> = Vec::new();
    let package = |name: &str, version: &str, path: &str| {
        let pkg = InstalledPackage {
            name: name.to_string(),
            version: version.to_string(),
            direct: false,
        };
        (pkg, path.split('!').map(str::to_string).collect())
    };
    for f in found {
        match f {
            Found::Coordinates {
                name,
                version,
                path,
            } => installed.push(package(name, version, path)),
            Found::FileName {
                artifact,
                version,
                path,
                packages,
                bundle,
            } => {
                let candidates = artifacts.get(artifact.as_str());
                let candidates = candidates.map_or(&[][..], Vec::as_slice);
                match settle_group(candidates, packages, bundle.as_deref()) {
                    Group::NoAdvisories => {}
                    Group::Settled(name) => installed.push(package(name, version, path)),
                    Group::Unsettled => unsettled.push(path),
                }
            }
            Found::Bundle {
                name,
                version,
                path,
            } => match settle_bundle(&artifacts, name) {
                Some(coordinate) => installed.push(package(coordinate, version, path)),
                None => unplaced.push(path),
            },
            Found::Unknown { .. } | Found::Unreadable { .. } => {}
        }
    }
    installed.sort_by(|a, b| (&a.0.name, &a.0.version, &a.1).cmp(&(&b.0.name, &b.0.version, &b.1)));
    let scan = fleetreach_maven::scan_located(&installed, db, id);
    let mut result =
        RepoResult::scanned(id, scan.findings, Vec::new()).with_skipped(scan.skipped_unparseable);
    let gap = |paths: &[&str], reason: String| CoverageGap {
        repo: id.clone(),
        source: paths[0].split('!').next().unwrap_or_default().to_string(),
        ecosystem: Ecosystem::Maven,
        level: Coverage::Partial,
        reason,
    };
    if !unsettled.is_empty() {
        result = result.with_coverage(gap(
            &unsettled,
            format!(
                "{} Java archives share an artifact name with packages that have advisories, \
                 but nothing in them says which (first: {}), so they were not matched",
                unsettled.len(),
                unsettled[0]
            ),
        ));
    }
    if !unplaced.is_empty() {
        result = result.with_coverage(gap(
            &unplaced,
            format!(
                "{} Java archives have a bundle name but no Maven coordinates (first: {}), so \
                 they were not matched",
                unplaced.len(),
                unplaced[0]
            ),
        ));
    }
    result
}

/// Match an image's OS packages. Returns the ecosystem the result is filed under (dpkg, apk
/// or rpm) and the result: errored when the distro's export is missing, and with coverage gaps
/// for an unknown distro or release, an incomplete package database, image files that could
/// not be read, and language artifacts no feeder reads.
fn scan_image_os(
    id: &RepoId,
    opened: &crate::images::Opened,
    images: &Images,
    distro_db: Option<&Result<fleetreach_os::db::DistroDb, String>>,
) -> (Ecosystem, RepoResult) {
    use fleetreach_os::Family;
    let inspection = &opened.inspection;
    let family = inspection
        .inventory
        .family
        .or_else(|| inspection.distro.as_ref().ok().map(|d| d.family));
    let ecosystem = match family {
        Some(Family::Apk) => Ecosystem::Apk,
        Some(Family::Rpm) => Ecosystem::Rpm,
        _ => Ecosystem::Deb,
    };
    let source = match family {
        Some(Family::Deb) => "var/lib/dpkg/status",
        Some(Family::Apk) => "lib/apk/db/installed",
        Some(Family::Rpm) => "var/lib/rpm",
        None => "etc/os-release",
    };
    let gap = |source: &str, ecosystem: Ecosystem, reason: String| CoverageGap {
        repo: id.clone(),
        source: source.to_string(),
        ecosystem,
        level: Coverage::Partial,
        reason,
    };
    let mut gaps: Vec<CoverageGap> = inspection
        .inventory
        .problems
        .iter()
        .map(|p| gap(source, ecosystem, p.clone()))
        .collect();
    for skipped in &opened.skipped {
        gaps.push(gap(
            source,
            ecosystem,
            format!("an image file was not read ({skipped}); what it lists was not scanned"),
        ));
    }
    for (kind, n) in &opened.unread {
        let eco = if kind.contains("jar") {
            Ecosystem::Maven
        } else if *kind == fleetreach_os::lang::RUST_UNREAD {
            Ecosystem::Cargo
        } else {
            Ecosystem::RubyGems
        };
        gaps.push(gap(
            kind,
            eco,
            format!("{n} {kind} in the image are not read; their packages were not scanned"),
        ));
    }
    let result = match &inspection.distro {
        Err(_) if inspection.no_os => RepoResult::scanned(id, Vec::new(), Vec::new()),
        Err(reason) => {
            gaps.push(gap(
                source,
                ecosystem,
                format!("OS packages not matched: {reason}"),
            ));
            RepoResult::scanned(id, Vec::new(), Vec::new())
        }
        Ok(distro) if images.missing.contains(&distro.ecosystem) => RepoResult::errored(
            id,
            format!(
                "{}: no OSV export for {}; run `fleetreach db sync --distros {}` (network \
                 build), or pass --osv-dir <dir> laid out as <dir>/{}/all.zip",
                distro.name,
                distro.ecosystem,
                distro.ecosystem,
                crate::osvdb::dir_name(&distro.ecosystem),
            ),
        ),
        Ok(distro) => match distro_db {
            None => {
                RepoResult::errored(id, format!("{}: no distro advisories loaded", distro.name))
            }
            Some(Err(e)) => RepoResult::errored(id, format!("{} OSV DB: {e}", distro.name)),
            Some(Ok(db)) => {
                for eco in distro.ecosystems() {
                    // A module the image may not use, or an LTSS stream not reached yet.
                    if distro.optional.contains(&eco) {
                        continue;
                    }
                    let vendor = if fleetreach_os::distro::is_red_hat_vex(&eco) {
                        Some(("Red Hat", "redhat"))
                    } else if fleetreach_os::distro::is_suse_vex(&eco) {
                        Some(("SUSE", "suse"))
                    } else {
                        None
                    };
                    let reason = if let (Some((vendor, provider)), true) =
                        (vendor, images.missing.contains(&eco))
                    {
                        // A rebuild borrows only the open statuses (see `borrowed_opens`).
                        let fixes = if distro.borrowed_opens.contains(&eco) {
                            ""
                        } else {
                            " and fixes osv.dev has not imported yet"
                        };
                        format!(
                            "{vendor}'s CSAF VEX is not loaded, so CVEs {vendor} has not fixed \
                             in {} packages (affected, will not fix, fix deferred){fixes} were \
                             not reported; index it with `fleetreach db sync --source \
                             csaf:{provider}` (or `db import --csaf --provider {provider}`)",
                            distro.name
                        )
                    } else if images.missing.contains(&eco) {
                        format!("no OSV export for {eco}; its fixes were not applied")
                    } else if db.records(&eco) == 0 {
                        format!(
                            "the OSV export has no {eco} records, so {} packages were not \
                             matched against it",
                            distro.name
                        )
                    } else {
                        continue;
                    };
                    gaps.push(gap(source, ecosystem, reason));
                }
                let scan = fleetreach_os::scan::scan(
                    distro,
                    &inspection.inventory.packages,
                    db,
                    id,
                    images.opts,
                );
                RepoResult::scanned(id, scan.findings, Vec::new())
                    .with_skipped(scan.skipped_unparseable)
            }
        },
    };
    // A release past its end of life gets no new advisories, so its findings only shrink.
    let today = crate::history::now().date().to_string();
    let frozen = match (&inspection.distro, distro_db) {
        (Ok(distro), Some(Ok(db))) => distro
            .supplements
            .iter()
            .any(|e| fleetreach_os::distro::frozen_export(e).is_some() && db.records(e) > 0),
        _ => false,
    };
    gaps.extend(
        inspection
            .os_release
            .as_ref()
            .and_then(|os| fleetreach_os::eol::withdrawn(os, &today, frozen))
            .map(|reason| gap(source, ecosystem, reason)),
    );
    let mut result = gaps.into_iter().fold(result, RepoResult::with_coverage);
    if let Some(warning) = inspection
        .os_release
        .as_ref()
        .and_then(|os| fleetreach_os::eol::warning(os, id, &today))
    {
        result = result.with_warning(warning);
    }
    (ecosystem, result)
}

/// Lockfile formats fleetreach cannot read; reported when no readable lockfile sits beside them.
const UNSUPPORTED_LOCKFILES: &[&str] = &["bun.lockb"];

/// Directories never searched for lockfiles: installed third-party packages and VCS metadata
/// are not the project's own dependency set.
pub(crate) const SKIPPED_DIRS: &[&str] = &["node_modules", ".git"];

/// Decide what to scan in `repo`.
///
/// An explicit `ecosystem` scans exactly that, as before. Otherwise every ecosystem is
/// detected in the root and, with `glob = true`, in every directory whose lockfile lies within
/// `glob_max_depth` (the same bound the `Cargo.lock` glob uses), so a polyglot repo or a
/// monorepo whose lockfiles live below the root is scanned in full instead of as its first
/// detected ecosystem. Root workflows (`.github/workflows`) are scanned too, alongside
/// whatever else is found, and a repo with nothing at all falls back to Cargo, whose missing
/// lockfile is the honest gap.
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
            alongside: false,
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
            alongside: false,
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

    if repo.path.join(".github").join("workflows").is_dir() {
        let alongside = !plan.units.is_empty();
        plan.units.push(ScanUnit {
            alongside,
            ..unit(Ecosystem::GitHubActions, &repo.path)
        });
    } else if plan.units.is_empty() {
        plan.units.push(unit(Ecosystem::Cargo, &repo.path));
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
    // Below the root a `build.gradle` is a subproject unless a settings file makes it a build.
    let gradle = has("settings.gradle")
        || has("settings.gradle.kts")
        || (is_root && fleetreach_maven::has_gradle_build(dir));
    if has("gradle.lockfile") || (is_root && has("pom.xml")) || gradle {
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
fn scan_unit(
    db: &AdvisoryDb,
    repo: &Repo,
    ecosystem: Ecosystem,
    host_triple: Option<&str>,
    go: &GoScan,
    dbs: &Dbs,
    maven_remote: Option<&crate::maven_repo::Remote>,
) -> RepoResult {
    match ecosystem {
        Ecosystem::Go => return scan_go_repo(repo, go, dbs.go.as_ref()),
        Ecosystem::Npm => {
            return scan_tier_c(repo, ecosystem, dbs.npm.as_ref(), &NPM, |db| {
                whole(fleetreach_npm::scan_offline(&repo.path, db, &repo.id))
            })
        }
        Ecosystem::Pypi => {
            return scan_tier_c(repo, ecosystem, dbs.pypi.as_ref(), &PYPI, |db| {
                fleetreach_pypi::scan_offline_with_coverage(&repo.path, db, &repo.id).map(|s| {
                    let gaps = s.coverage.into_iter();
                    (
                        s.scan,
                        gaps.map(|g| (g.source, g.level, g.reason)).collect(),
                    )
                })
            })
        }
        Ecosystem::RubyGems => {
            return scan_tier_c(repo, ecosystem, dbs.rubygems.as_ref(), &RUBYGEMS, |db| {
                whole(fleetreach_rubygems::scan_offline(&repo.path, db, &repo.id))
            })
        }
        Ecosystem::Packagist => {
            return scan_tier_c(repo, ecosystem, dbs.packagist.as_ref(), &PACKAGIST, |db| {
                whole(fleetreach_packagist::scan_offline(&repo.path, db, &repo.id))
            })
        }
        Ecosystem::NuGet => {
            return scan_tier_c(repo, ecosystem, dbs.nuget.as_ref(), &NUGET, |db| {
                fleetreach_nuget::scan_offline_with_coverage(&repo.path, db, &repo.id).map(|s| {
                    let gaps = s.coverage.into_iter();
                    (
                        s.scan,
                        gaps.map(|g| (g.source, g.level, g.reason)).collect(),
                    )
                })
            })
        }
        Ecosystem::Julia => {
            return scan_tier_c(repo, ecosystem, dbs.julia.as_ref(), &JULIA, |db| {
                whole(fleetreach_julia::scan_offline(&repo.path, db, &repo.id))
            })
        }
        Ecosystem::Swift => {
            return scan_tier_c(repo, ecosystem, dbs.swift.as_ref(), &SWIFT, |db| {
                whole(fleetreach_swift::scan_offline(&repo.path, db, &repo.id))
            })
        }
        Ecosystem::Hex => {
            return scan_tier_c(repo, ecosystem, dbs.hex.as_ref(), &HEX, |db| {
                whole(fleetreach_hex::scan_offline(&repo.path, db, &repo.id))
            })
        }
        Ecosystem::Maven => return scan_maven_repo(repo, dbs.maven.as_ref(), maven_remote),
        Ecosystem::GitHubActions => {
            return scan_tier_c(repo, ecosystem, dbs.ghactions.as_ref(), &GHACTIONS, |db| {
                whole(fleetreach_ghactions::scan_offline(&repo.path, db, &repo.id))
            })
        }
        Ecosystem::Deb | Ecosystem::Apk | Ecosystem::Rpm => {
            return RepoResult::errored(
                &repo.id,
                "OS packages are scanned from container images ([[image]]), not repos".to_string(),
            )
        }
        Ecosystem::Cargo => {}
    }
    let (crates, crates_gap) = crates_or_gap(&repo.id, "Cargo.lock", dbs.crates.as_ref());
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
        error.get_or_insert_with(|| match repo.ecosystem {
            Some(_) => format!("no Cargo.lock found under {}", repo.path.display()),
            None => format!(
                "no recognized lockfile or manifest under {}",
                repo.path.display()
            ),
        });
    }

    for lockfile in &lockfiles {
        match scan_lockfile(db, crates, &repo.id, lockfile) {
            Ok(mut scan) => {
                // Opt-in: mark each occurrence built/phantom for the host's
                // default build. Best-effort — failures leave it unannotated.
                if let (Some(host), Some(dir)) = (host_triple, lockfile.parent()) {
                    if let Ok(built) = resolve::built_package_set(dir, host) {
                        annotate_built(&mut scan, &built);
                    }
                }
                crate::scope::mark_cargo(lockfile, &mut scan);
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

    let result = match error {
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
    };
    crates_gap
        .into_iter()
        .fold(result, RepoResult::with_coverage)
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
                Ok(mut vulnerabilities) => {
                    crate::scope::mark(Ecosystem::Go, &repo.path, &mut vulnerabilities);
                    scanned(vulnerabilities)
                }
                Err(e) => errored(format!("tier-c offline scan: {e}")),
            },
            Some(Err(e)) => errored(format!("tier-c offline DB: {e}")),
            None => errored(
                "Go repo (go.mod): no govulncheck available (needs --allow-untrusted-builds \
                 and a govulncheck binary via --govulncheck <path> or PATH), and no offline \
                 DB for the toolchain-free Tier-C fallback (run `fleetreach db sync`, pass \
                 --osv-dir <dir> with <dir>/Go/all.zip, or --go-vuln-db=file://<mirror>)"
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

/// How a toolchain-free ecosystem names itself when a repo of it cannot be scanned: what its
/// OSV DB is called, the prefix of a scan error, and the gap when no mirror was given (the
/// files it reads and how to supply a mirror).
struct TierC {
    db: &'static str,
    scan: &'static str,
    no_mirror: &'static str,
}

const NPM: TierC = TierC {
    db: "npm",
    scan: "npm",
    no_mirror: "npm repo (package-lock.json/pnpm-lock.yaml/yarn.lock/bun.lock): no OSV DB mirror for the toolchain-free \
         matcher (pass --osv-dir=<dir> or --npm-vuln-db=file://<dir>, e.g. an unzipped osv.dev npm export)",
};

const PYPI: TierC = TierC {
    db: "PyPI",
    scan: "pypi",
    no_mirror: "PyPI repo (uv.lock/poetry.lock/Pipfile.lock/pylock.toml/requirements): no OSV DB mirror for the \
         toolchain-free matcher (pass --osv-dir=<dir> or --pypi-vuln-db=file://<path>, e.g. the osv.dev \
         PyPI export all.zip or an unzipped directory)",
};

const RUBYGEMS: TierC = TierC {
    db: "RubyGems",
    scan: "rubygems",
    no_mirror: "RubyGems repo (Gemfile.lock): no OSV DB mirror for the toolchain-free \
         matcher (pass --osv-dir=<dir> or --rubygems-vuln-db=file://<path>, e.g. the osv.dev RubyGems \
         export all.zip or an unzipped directory)",
};

const PACKAGIST: TierC = TierC {
    db: "Packagist",
    scan: "packagist",
    no_mirror: "Packagist repo (composer.lock): no OSV DB mirror for the toolchain-free \
         matcher (pass --osv-dir=<dir> or --packagist-vuln-db=file://<path>, e.g. the osv.dev Packagist \
         export all.zip or an unzipped directory)",
};

const NUGET: TierC = TierC {
    db: "NuGet",
    scan: "nuget",
    no_mirror: "NuGet repo (packages.lock.json/project.assets.json/packages.config/.csproj): no OSV DB mirror for the toolchain-free \
         matcher (pass --osv-dir=<dir> or --nuget-vuln-db=file://<path>, e.g. the osv.dev NuGet export \
         all.zip or an unzipped directory)",
};

const JULIA: TierC = TierC {
    db: "Julia",
    scan: "julia",
    no_mirror: "Julia repo (Manifest.toml): no OSV DB mirror for the toolchain-free matcher \
         (pass --osv-dir=<dir> or --julia-vuln-db=file://<path>, e.g. the osv.dev Julia export all.zip or \
         an unzipped directory)",
};

const SWIFT: TierC = TierC {
    db: "Swift",
    scan: "swift",
    no_mirror: "Swift repo (Package.resolved): no OSV DB mirror for the toolchain-free matcher \
         (pass --osv-dir=<dir> or --swift-vuln-db=file://<path>, e.g. the osv.dev SwiftURL export all.zip \
         or an unzipped directory)",
};

const HEX: TierC = TierC {
    db: "Hex",
    scan: "hex",
    no_mirror: "Hex repo (mix.lock): no OSV DB mirror for the toolchain-free matcher (pass \
         --osv-dir=<dir> or --hex-vuln-db=file://<path>, e.g. the osv.dev Hex export all.zip or an \
         unzipped directory)",
};

const GHACTIONS: TierC = TierC {
    db: "GitHub Actions",
    scan: "github-actions",
    no_mirror: "GitHub Actions repo (.github/workflows): no OSV DB mirror for the \
         toolchain-free matcher (pass --osv-dir=<dir> or --ghactions-vuln-db=file://<path>, e.g. the \
         osv.dev GitHub Actions export all.zip or an unzipped directory)",
};

const MAVEN: TierC = TierC {
    db: "Maven",
    scan: "maven",
    no_mirror: "Maven repo (gradle.lockfile/pom.xml): no OSV DB mirror for the toolchain-free \
         matcher (pass --osv-dir=<dir> or --maven-vuln-db=file://<path>, e.g. the osv.dev Maven export \
         all.zip or an unzipped directory)",
};

/// The once-loaded DB, or why a repo cannot be scanned: no `file://` mirror was given (an
/// honest gap) or the mirror failed to load (surfaced, never a false-clean).
fn tier_c_db<'a, D, E: std::fmt::Display>(
    db: Option<&'a Result<D, E>>,
    eco: &TierC,
) -> Result<&'a D, String> {
    match db {
        Some(Ok(db)) => Ok(db),
        Some(Err(e)) => Err(format!("{} OSV DB: {e}", eco.db)),
        None => Err(eco.no_mirror.to_string()),
    }
}

/// A source a matcher read with less than full coverage: `(source, level, reason)`.
type Gap = (String, Coverage, String);

/// Scan a repo with a toolchain-free Tier-C matcher: it reads the repo's lockfiles and
/// matches each package version against the preloaded OSV DB, building nothing, so it needs
/// no consent and no sandbox. `scan` gives the findings and any sources read only in part.
fn scan_tier_c<D, E: std::fmt::Display, S: std::fmt::Display>(
    repo: &Repo,
    ecosystem: Ecosystem,
    db: Option<&Result<D, E>>,
    eco: &TierC,
    scan: impl FnOnce(&D) -> Result<(TierCScan, Vec<Gap>), S>,
) -> RepoResult {
    let db = match tier_c_db(db, eco) {
        Ok(db) => db,
        Err(reason) => return RepoResult::errored(&repo.id, reason),
    };
    match scan(db) {
        Ok((mut scan, gaps)) => {
            crate::scope::mark(ecosystem, &repo.path, &mut scan.findings);
            gaps.into_iter().fold(
                RepoResult::scanned(&repo.id, scan.findings, Vec::new())
                    .with_skipped(scan.skipped_unparseable),
                |result, (source, level, reason)| {
                    result.with_coverage(CoverageGap {
                        repo: repo.id.clone(),
                        source,
                        ecosystem,
                        level,
                        reason,
                    })
                },
            )
        }
        Err(e) => RepoResult::errored(&repo.id, format!("{} tier-c scan: {e}", eco.scan)),
    }
}

/// A matcher's scan with no partial sources.
fn whole<E>(scan: Result<TierCScan, E>) -> Result<(TierCScan, Vec<Gap>), E> {
    scan.map(|scan| (scan, Vec::new()))
}

pub(crate) const GRADLE_SOURCE: &str = "build.gradle";

/// A Gradle build with neither a `gradle.lockfile` nor a `pom.xml` to read instead.
pub(crate) fn is_gradle_without_lock(dir: &Path) -> bool {
    !dir.join("gradle.lockfile").is_file()
        && !dir.join("pom.xml").is_file()
        && fleetreach_maven::has_gradle_build(dir)
}

/// Resolve a Gradle build from its catalog and literal declarations, with the coverage note it
/// always carries: plugins can add dependencies nothing short of Gradle can see.
pub(crate) fn resolve_gradle(
    dir: &Path,
    remote: Option<&crate::maven_repo::Remote>,
) -> (fleetreach_maven::Resolution, String) {
    let local = crate::maven_repo::local();
    let mut sources: Vec<&dyn fleetreach_maven::PomSource> = vec![&local];
    if let Some(remote) = remote {
        sources.push(remote);
    }
    let resolution = fleetreach_maven::resolve_gradle(dir, &fleetreach_maven::Chain(sources));
    let mut reason = "read without running Gradle, so plugins can add dependencies not listed \
                      here; `gradle dependencies --write-locks` gives the exact set"
        .to_string();
    if !resolution.missing.is_empty() {
        let shown: Vec<&str> = resolution
            .missing
            .iter()
            .take(5)
            .map(String::as_str)
            .collect();
        let more = resolution.missing.len().saturating_sub(shown.len());
        reason.push_str(&format!(
            "; {} item(s) not resolved: {}",
            resolution.missing.len(),
            shown.join("; ")
        ));
        if more > 0 {
            reason.push_str(&format!(" and {more} more"));
        }
        if remote.is_none() {
            reason.push_str(
                "; pass --maven-fetch to fetch missing POMs from your settings.xml mirror or \
                 Maven Central (sends their coordinates)",
            );
        }
    }
    (resolution, reason)
}

/// Scan a Maven (Java) repo with the toolchain-free Tier-C matcher: read `gradle.lockfile` or
/// `pom.xml` and match each dependency against the preloaded OSV DB. Builds nothing, so it
/// needs no consent and no sandbox. `maven_db` is the once-loaded DB: `None` means no `file://`
/// mirror was given (an honest gap), `Some(Err)` a mirror that failed to load (surfaced).
fn scan_maven_repo(
    repo: &Repo,
    maven_db: Option<&Result<MavenDb, MavenError>>,
    remote: Option<&crate::maven_repo::Remote>,
) -> RepoResult {
    let errored = |reason: String| RepoResult::errored(&repo.id, reason);

    let db = match tier_c_db(maven_db, &MAVEN) {
        Ok(db) => db,
        Err(reason) => return errored(reason),
    };
    if is_gradle_without_lock(&repo.path) {
        let (resolution, reason) = resolve_gradle(&repo.path, remote);
        let scan = fleetreach_maven::scan_resolution(&resolution, db, &repo.id);
        return RepoResult::scanned(&repo.id, scan.findings, Vec::new())
            .with_skipped(scan.skipped_unparseable)
            .with_coverage(CoverageGap {
                repo: repo.id.clone(),
                source: GRADLE_SOURCE.to_string(),
                ecosystem: Ecosystem::Maven,
                level: Coverage::Partial,
                reason,
            });
    }
    // `gradle.lockfile` is the resolved closure. A `pom.xml` is resolved like Maven would
    // (parents, BOMs, mediation) from local repositories, plus Maven Central with
    // `--maven-fetch`; whatever cannot be resolved is named as partial coverage. A POM that
    // cannot be parsed falls back to its declared dependencies, labelled direct-only.
    if !repo.path.join("gradle.lockfile").is_file() {
        let local = crate::maven_repo::local();
        let mut sources: Vec<&dyn fleetreach_maven::PomSource> = vec![&local];
        if let Some(remote) = remote {
            sources.push(remote);
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
            let hint = if remote.is_some() {
                ""
            } else {
                "; pass --maven-fetch to fetch missing POMs from your settings.xml mirror or Maven Central (sends their coordinates), or build once so ~/.m2 has them"
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
        Err(e) => errored(format!("{} tier-c scan: {e}", MAVEN.scan)),
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_toolchain_free_repo_without_a_usable_mirror_says_how_to_get_one() {
        let ecosystems = [
            (&NPM, "--npm-vuln-db"),
            (&PYPI, "--pypi-vuln-db"),
            (&RUBYGEMS, "--rubygems-vuln-db"),
            (&PACKAGIST, "--packagist-vuln-db"),
            (&NUGET, "--nuget-vuln-db"),
            (&JULIA, "--julia-vuln-db"),
            (&SWIFT, "--swift-vuln-db"),
            (&HEX, "--hex-vuln-db"),
            (&GHACTIONS, "--ghactions-vuln-db"),
            (&MAVEN, "--maven-vuln-db"),
        ];
        for (eco, flag) in ecosystems {
            let missing = tier_c_db::<(), String>(None, eco).unwrap_err();
            assert!(missing.contains("no OSV DB mirror"), "{missing}");
            assert!(
                missing.contains("--osv-dir") && missing.contains(flag),
                "{missing}"
            );
            assert!(
                !missing.contains("  "),
                "a line continuation kept its indent: {missing}"
            );
            let broken = tier_c_db::<(), String>(Some(&Err("bad zip".into())), eco).unwrap_err();
            assert_eq!(broken, format!("{} OSV DB: bad zip", eco.db));
        }
    }
}
