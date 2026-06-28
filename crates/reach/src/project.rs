//! Build a project under the reach-driver wrapper, then merge + analyze.
//!
//! It compiles the target with the pinned nightly and `RUSTC_WRAPPER` set to the
//! driver, so every crate emits a fragment; the fragments merge into the whole
//! closure. A fresh `CARGO_TARGET_DIR` keeps cargo from skipping up-to-date
//! crates (which would skip their fragments). [`analyze_project_cached`] caches
//! the sink-free graph (see the `cache` module).

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::sandbox::Sandbox;
use crate::{
    analyze, analyze_paths, cache, merge, parse_graph, Analysis, CallGraph, ReachError,
    SandboxPolicy, Verdict,
};

/// Which cargo features to compile the closure with. This changes *which code
/// exists* in the graph (a feature can gate whole modules and dependency
/// edges), so it is a first-class part of the cache key: the same `Cargo.lock`
/// built with different features is a different graph. A mismatch here would be
/// a stale graph → a false `NotReachable` (a soundness defect).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeatureSelection {
    /// `--all-features`.
    pub all_features: bool,
    /// `--no-default-features`.
    pub no_default_features: bool,
    /// `--features a,b,c` (each entry one feature).
    pub features: Vec<String>,
}

impl FeatureSelection {
    /// Append the cargo feature flags this selection implies to `argv`.
    fn push_flags(&self, argv: &mut Vec<String>) {
        if self.all_features {
            argv.push("--all-features".to_string());
        }
        if self.no_default_features {
            argv.push("--no-default-features".to_string());
        }
        if !self.features.is_empty() {
            argv.push("--features".to_string());
            argv.push(self.features.join(","));
        }
    }

    /// Fold a canonical (order-independent) view of the selection into `hasher`,
    /// so two equivalent selections key the same graph regardless of CLI order.
    pub(crate) fn hash_into(&self, hasher: &mut impl Hasher) {
        self.all_features.hash(hasher);
        self.no_default_features.hash(hasher);
        let mut feats: Vec<&str> = self.features.iter().map(String::as_str).collect();
        feats.sort_unstable();
        feats.dedup();
        feats.hash(hasher);
    }
}

/// How to compile the closure: which toolchain, which features, and how to
/// confine the build. Threaded through the analysis entry points so the build
/// command and the graph cache key stay in lock-step (a `NotReachable` is only
/// sound for the exact closure that produced the graph).
#[derive(Clone)]
pub struct BuildConfig<'a> {
    /// The pinned nightly the driver was built against, e.g. `nightly-2026-06-01`.
    pub toolchain: &'a str,
    /// Which cargo features to build with. See [`FeatureSelection`].
    pub features: FeatureSelection,
    /// How to confine the (untrusted) build. See [`SandboxPolicy`].
    pub sandbox: SandboxPolicy,
}

impl<'a> BuildConfig<'a> {
    /// A config for `toolchain` with default features and no build confinement
    /// (the library default).
    pub fn new(toolchain: &'a str) -> Self {
        BuildConfig {
            toolchain,
            features: FeatureSelection::default(),
            sandbox: SandboxPolicy::Off,
        }
    }
}

/// Inputs for analyzing a buildable project.
pub struct ProjectOptions<'a> {
    /// Directory containing the target `Cargo.toml`.
    pub manifest_dir: &'a Path,
    /// Path to the built `fleetreach-reach-driver` binary.
    pub driver: &'a Path,
    /// Toolchain + build-confinement settings.
    pub build: BuildConfig<'a>,
    /// Sink paths in crate-qualified (RustSec affected-function) form.
    pub sinks: &'a [String],
}

/// The merged whole-closure graph plus its per-sink analysis.
pub struct ProjectAnalysis {
    /// The merged whole-closure call graph.
    pub graph: CallGraph,
    /// Per-sink verdicts over `graph` (keyed by node label).
    pub analysis: Analysis,
}

/// Build the project under the wrapper and analyze the whole closure (no cache;
/// sinks are marked in the driver). Kept for direct, one-shot analysis.
pub fn analyze_project(opts: &ProjectOptions) -> Result<ProjectAnalysis, ReachError> {
    let graph = build_and_merge(opts.manifest_dir, opts.driver, &opts.build, opts.sinks)?;
    let analysis = analyze(&graph)?;
    Ok(ProjectAnalysis { graph, analysis })
}

/// Result of a cached analysis: the (sink-free) whole-closure graph, a verdict
/// per requested advisory path, and whether the graph came from cache.
pub struct CachedAnalysis {
    /// The sink-free whole-closure call graph (built or loaded from cache).
    pub graph: CallGraph,
    /// One verdict per requested advisory path, keyed by that path.
    pub verdicts: BTreeMap<String, Verdict>,
    /// `true` if `graph` was loaded from the cache rather than rebuilt.
    pub from_cache: bool,
    /// Cache key for the analyzed closure (`Cargo.lock`, features, toolchain,
    /// source), or `None` without a `Cargo.lock`. The witness anchor for a
    /// `NotReachable` verdict (§9.2): valid exactly for these inputs.
    pub cache_key: Option<String>,
}

/// Analyze a project against `advisory_paths`, reusing a cached sink-free graph
/// keyed by `(Cargo.lock, features, toolchain, source)` when present. Only sink
/// resolution runs on a cache hit — no rebuild. A stale/unreadable/incompatible
/// cache entry is transparently rebuilt.
pub fn analyze_project_cached(
    manifest_dir: &Path,
    driver: &Path,
    build: &BuildConfig,
    advisory_paths: &[String],
) -> Result<CachedAnalysis, ReachError> {
    let key = cache::key(manifest_dir, build, driver);

    if let Some(graph) = key.as_deref().and_then(cache::load) {
        let verdicts = analyze_paths(&graph, advisory_paths)?;
        return Ok(CachedAnalysis {
            graph,
            verdicts,
            from_cache: true,
            cache_key: key,
        });
    }

    // Miss: build the sink-free graph and (best-effort) cache it.
    let graph = build_and_merge(manifest_dir, driver, build, &[])?;
    if let Some(k) = &key {
        cache::store(k, &graph);
    }
    let verdicts = analyze_paths(&graph, advisory_paths)?;
    Ok(CachedAnalysis {
        graph,
        verdicts,
        from_cache: false,
        cache_key: key,
    })
}

/// Run the wrapped build and merge the per-crate fragments. `sinks` empty ⇒ the
/// driver emits a sink-free graph (what the cache stores).
fn build_and_merge(
    manifest_dir: &Path,
    driver: &Path,
    build: &BuildConfig,
    sinks: &[String],
) -> Result<CallGraph, ReachError> {
    // A secure working dir: random name, 0700, O_EXCL, auto-removed on drop — not
    // a predictable /tmp path that a local attacker could pre-create as a symlink.
    let work = tempfile::Builder::new()
        .prefix("fleetreach-reach-")
        .tempdir()
        .map_err(|e| ReachError::Io(format!("create work dir: {e}")))?;
    let frags = work.path().join("frags");
    let target = work.path().join("target");
    std::fs::create_dir_all(&frags)
        .map_err(|e| ReachError::Io(format!("create fragment dir {}: {e}", frags.display())))?;

    // Decide how to confine this build (defense-in-depth for untrusted repos).
    let sandbox = Sandbox::resolve(build.sandbox, work.path())?;

    // A confined build runs with the network denied, so its dependencies must
    // already be in the cargo cache. `cargo fetch` only *downloads* — it never
    // runs a build script — so it is safe to run unconfined (network) before we
    // drop into the sandbox and build `--frozen` (offline + locked).
    if sandbox.is_confined() {
        prefetch(manifest_dir, build.toolchain);
    }

    // `build`, not `check`: the bin's mono collector recurses into dependency
    // functions and needs their MIR, which `cargo check` does not emit
    // (metadata-only) — so check fails with "missing optimized MIR".
    let mut argv = vec![
        "cargo".to_string(),
        format!("+{}", build.toolchain),
        "build".to_string(),
        // The cache key fingerprints `Cargo.lock`, so the build must not rewrite
        // it (a mutated lock shifts the key between runs and could desync a graph
        // from its key). A stale lock fails the build → Unknown.
        "--locked".to_string(),
    ];
    // The feature set must match what the cache key was computed from, or a hit
    // would serve a graph built with different code.
    build.features.push_flags(&mut argv);
    // A confined build also runs offline (the sandbox denies the network);
    // `--locked --offline` is `--frozen`.
    if sandbox.is_confined() {
        argv.push("--offline".to_string());
    }
    let mut cmd = sandbox.command(&argv);
    cmd.current_dir(manifest_dir);
    // The build runs the target's build.rs / proc-macros (arbitrary code). Scrub
    // the environment to a minimal allowlist FIRST so operator secrets
    // (NVD_API_KEY, *_TOKEN, AWS_*, SSH_AUTH_SOCK, …) never reach attacker code —
    // the network-deny sandbox stops exfil, but secrets must not even be readable.
    scrub_build_env(&mut cmd);
    cmd.env("RUSTC_WRAPPER", driver)
        .env("REACH_OUT", &frags)
        .env("CARGO_TARGET_DIR", &target);
    if !sinks.is_empty() {
        cmd.env("REACH_SINKS", sinks.join("\n"));
    }
    // A wall-clock timeout so a malicious (or merely broken) build script cannot
    // hang the whole fleet scan; a timeout surfaces as a build failure → Unknown.
    run_to_completion(&mut cmd, build_timeout())?;

    let fragments = read_fragments(&frags)?;
    if fragments.is_empty() {
        return Err(ReachError::Build(
            "the build emitted no graph fragments".to_string(),
        ));
    }
    // `work` (and its `target`/`frags`) is removed when it drops here.
    merge(&fragments)
}

/// Pre-download the dependency closure so the confined (offline) build can find
/// it in the cargo cache. `cargo fetch` resolves + downloads but does **not**
/// compile or run any build script, so it is safe to run unconfined. Best
/// effort: if it fails (offline with a cold cache, or a stale lock), the
/// `--frozen` build that follows fails with a clear cargo error → `Unknown`.
fn prefetch(manifest_dir: &Path, toolchain: &str) {
    let _ = Command::new("cargo")
        .arg(format!("+{toolchain}"))
        .arg("fetch")
        .arg("--locked")
        .current_dir(manifest_dir)
        .status();
}

/// Reset `cmd`'s environment to a minimal allowlist before it runs the untrusted
/// build. `env_clear` drops everything (operator secrets included); only the
/// variables the toolchain genuinely needs to locate and run cargo/rustc are
/// re-added from the current process. The build is offline under confinement, so
/// no proxy/credential variables are needed. Anything this caller sets afterward
/// (`RUSTC_WRAPPER`, `REACH_OUT`, …) survives because it is added after this call.
fn scrub_build_env(cmd: &mut Command) {
    // Locate cargo/rustc/the rustup `+toolchain` shim and its toolchain dirs;
    // basic locale/term so cargo output is well-formed; scratch dir for rustc.
    const ALLOW: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "TERM",
        "LANG",
        "TMPDIR",
        "RUSTUP_HOME",
        "CARGO_HOME",
        "RUSTUP_TOOLCHAIN",
    ];
    cmd.env_clear();
    for key in ALLOW {
        if let Some(val) = std::env::var_os(key) {
            cmd.env(key, val);
        }
    }
}

/// The build timeout (default 10 minutes; override with `REACH_BUILD_TIMEOUT_SECS`).
fn build_timeout() -> Duration {
    let secs = std::env::var("REACH_BUILD_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(600);
    Duration::from_secs(secs)
}

/// Run `cmd` to completion, killing it (→ `Build` error) if it exceeds `timeout`.
///
/// On timeout we `kill()` the spawned leader. Under the recommended Linux
/// confinement the build runs in a bwrap PID namespace (`--unshare-pid`), so
/// killing bwrap reaps every process it forked; firejail likewise tears down its
/// sandbox. Residual (documented, availability-only — a timeout is always
/// `Unknown`, never a false `NotReachable`): a build that double-forks/`setsid`s
/// under `--build-sandbox=off` or the macOS sandbox can orphan a process, since a
/// full process-group `killpg` would require `unsafe`, which this crate forbids.
fn run_to_completion(cmd: &mut Command, timeout: Duration) -> Result<(), ReachError> {
    let mut child = cmd
        .spawn()
        .map_err(|e| ReachError::Build(format!("could not spawn cargo: {e}")))?;
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(ReachError::Build(format!("cargo build failed ({status})")))
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ReachError::Build(format!(
                        "cargo build timed out after {}s (a build script may be hanging)",
                        timeout.as_secs()
                    )));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(ReachError::Build(format!("waiting on cargo: {e}"))),
        }
    }
}

fn read_fragments(dir: &Path) -> Result<Vec<CallGraph>, ReachError> {
    let mut fragments = Vec::new();
    // Track embedded crate identities to reject a build.rs that overwrites a
    // sibling's fragment or plants a duplicate (H-4): an identity that disagrees
    // with the filename, or repeats, fails closed to a rebuild → `Unknown`.
    let mut seen_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|e| ReachError::Io(format!("read fragment dir {}: {e}", dir.display())))?;
    for entry in entries {
        let path = entry
            .map_err(|e| ReachError::Io(format!("read fragment dir {}: {e}", dir.display())))?
            .path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            // Bound the read: a fragment is written by the driver during the build,
            // so a hostile build.rs could try to plant an enormous one. Over the
            // cap fails closed (→ Build/Unknown), never a multi-GB allocation.
            let too_big = std::fs::metadata(&path)
                .map(|m| m.len() > crate::MAX_GRAPH_BYTES)
                .unwrap_or(false);
            if too_big {
                return Err(ReachError::Malformed(format!(
                    "fragment {} exceeds the {}-byte cap",
                    path.display(),
                    crate::MAX_GRAPH_BYTES
                )));
            }
            let json = std::fs::read_to_string(&path)
                .map_err(|e| ReachError::Io(format!("read fragment {}: {e}", path.display())))?;
            let fragment = parse_graph(&json)?;
            // The driver stamps each fragment with its crate identity, equal to the
            // filename stem it writes. A mismatch or a repeat means something other
            // than the wrapped rustc wrote (or overwrote) this file.
            if let Some(crate_id) = &fragment.crate_id {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default();
                if crate_id != stem {
                    return Err(ReachError::Malformed(format!(
                        "fragment {} claims crate identity {crate_id} but is named {stem}",
                        path.display()
                    )));
                }
                if !seen_ids.insert(crate_id.clone()) {
                    return Err(ReachError::Malformed(format!(
                        "duplicate fragment identity {crate_id}"
                    )));
                }
            }
            fragments.push(fragment);
        }
    }
    Ok(fragments)
}
