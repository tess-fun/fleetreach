use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use fleetreach_core::{RepoId, VulnFinding};
use fleetreach_reach::{Confinement, SandboxPolicy};

use crate::{direct_modules, parse_findings, GoError};

/// How to run govulncheck against a Go module: the binary, the build confinement,
/// the vulnerability DB, and whether the scan must stay fully offline. Bundled so
/// [`scan_module`] takes one self-documenting argument instead of a long positional
/// list, and so the implicit coupling between the fields is stated in one place:
/// `offline` forces confined-offline regardless of `sandbox`, and a confined scan
/// needs `vuln_db` to be a `file://` mirror or it fails closed
/// ([`GoError::MirrorRequired`]).
#[derive(Debug, Clone, Copy)]
pub struct GoScanOptions<'a> {
    /// Path to the `govulncheck` binary.
    pub govulncheck: &'a Path,
    /// Build confinement policy (`govulncheck` compiles the module).
    pub sandbox: SandboxPolicy,
    /// Vulnerability DB passed to govulncheck as `-db`. A `file://<mirror>` lets a
    /// network-denied scan run offline; `None` uses govulncheck's default (online).
    pub vuln_db: Option<&'a str>,
    /// Require zero network I/O: forces confined-offline and skips the dep prefetch.
    pub offline: bool,
}

/// Run `govulncheck -format json ./...` in `module_dir` per `opts` and parse the
/// result into Go-tagged findings for `repo`.
///
/// **This compiles the target module** (running its build / code generation, like
/// the Rust reach driver), so the build is confined under [`opts.sandbox`](GoScanOptions)
/// through the *same* mechanism as `--reachability=static` (see [`Confinement`]).
/// Confinement denies the network, but govulncheck needs its vuln DB, so a confined
/// scan must read a local `file://` mirror via [`opts.vuln_db`](GoScanOptions); the
/// policy and the mirror together decide the mode (see [`effective_policy`]):
///
/// - **`Off`** runs govulncheck unconfined — the only mode that reaches `vuln.go.dev`
///   online.
/// - **`Auto`** confines only when an offline mirror makes it useful; without one it
///   degrades to an unconfined online scan (a warning, not a refusal).
/// - **`Require`** (also forced by [`opts.offline`](GoScanOptions)) always confines,
///   scrubs the environment, denies the network, and — without a mirror — fails closed
///   ([`GoError::MirrorRequired`]) rather than scan online.
///
/// In `-format json` mode govulncheck exits **zero** on both a clean and a vulns-found
/// scan, so any non-zero exit is a genuine error ([`GoError::Failed`], or
/// [`GoError::NoOutput`] for empty stdout); the build is also bounded by a wall-clock
/// timeout ([`GoError::Timeout`]). This is what makes a confined, network-denied scan
/// fail closed instead of masquerading as a clean result.
///
/// # Errors
///
/// - [`GoError::MirrorRequired`] — confined/offline but no `file://` mirror.
/// - [`GoError::Timeout`] — the build exceeded the wall-clock limit and was killed.
/// - [`GoError::Failed`] / [`GoError::NoOutput`] — govulncheck exited non-zero / wrote
///   no JSON (stderr captured).
/// - [`GoError::Spawn`] / [`GoError::Sandbox`] / [`GoError::Parse`] — could not start the
///   subprocess, set up confinement, or parse the output stream.
pub fn scan_module(
    module_dir: &Path,
    repo: &RepoId,
    opts: &GoScanOptions,
) -> Result<Vec<VulnFinding>, GoError> {
    // Only a `file://` mirror is usable once confinement denies the network; an
    // `http(s)://` DB drives no confinement decision (it would be unreachable).
    let offline_db = opts.vuln_db.filter(|d| is_offline_db(d));
    // Under `--offline` the Go path must do ZERO network I/O: force the confined-offline
    // policy (deny network, require a `file://` mirror, fail closed without one) and skip
    // the unconfined prefetch below — regardless of `--build-sandbox`. Otherwise `auto`
    // confines only when a mirror makes the offline scan viable, else degrades to online.
    let policy = if opts.offline {
        SandboxPolicy::Require
    } else {
        effective_policy(opts.sandbox, offline_db.is_some())
    };

    // A throwaway work dir the confined build may write into (its Go build cache
    // and temp dirs), mirroring the reach driver's CARGO_TARGET_DIR. Random, 0700,
    // auto-removed when `work` drops. Created even when unconfined so both paths
    // share one shape; it is only *used* under confinement.
    let work = tempfile::Builder::new()
        .prefix("fleetreach-go-")
        .tempdir()
        .map_err(|e| GoError::Sandbox(format!("create work dir: {e}")))?;

    // Resolve confinement (deny network + confine writes to the work dir + system
    // temp), or fail/warn per policy. Same mechanism as `--reachability=static`.
    // A persistent, content-addressed Go build cache is added as an extra writable
    // root so the offline build is incremental across scans rather than recompiling
    // cold each run (no-op when unconfined).
    let go_cache = persistent_go_cache();
    let confinement = Confinement::resolve(policy, work.path())
        .map_err(|e| GoError::Sandbox(e.to_string()))?
        .with_writable(&[go_cache.as_path()]);

    if confinement.is_confined() && offline_db.is_none() {
        // Confinement (from `--offline` or `--build-sandbox=require`) denies the network
        // but no offline DB was given. Fail closed with an actionable, flag-accurate
        // message rather than letting govulncheck die on a buried DNS error.
        return Err(GoError::MirrorRequired);
    }
    if opts.sandbox == SandboxPolicy::Auto && !confinement.is_confined() && offline_db.is_none() {
        eprintln!(
            "warning: scanning Go repo UNCONFINED (online): --build-sandbox=auto can only \
             confine govulncheck offline, which needs a local vulnerability DB. Pass \
             --go-vuln-db=file://<mirror> (or GOVULNDB) to confine it offline, or \
             --build-sandbox=require to require confinement."
        );
    }

    if confinement.is_confined() && !opts.offline {
        // Pre-download the module deps unconfined — `go mod download` resolves and
        // fetches modules but runs no build script, so it is safe to run with the
        // network *before* dropping into the offline sandbox. The `cargo fetch`
        // analog; best-effort, like the reach path (a miss → the offline build
        // fails → an honest gap). Skipped under `--offline` (it would touch the proxy):
        // the confined build then relies on the existing module cache or fails closed.
        prefetch_modules(module_dir);
    }

    // The govulncheck argv. A configured DB (`file://` mirror, or an `http(s)://`
    // mirror for an online run) is passed as `-db`. Under confinement the program
    // is transparently replaced by the sandbox wrapper; the args are unchanged.
    let argv = govulncheck_argv(opts.govulncheck, opts.vuln_db);

    let mut cmd = confinement.command(&argv);
    cmd.current_dir(module_dir);
    // Only isolate the environment under confinement; `Off` keeps the operator's
    // full environment and shared Go caches (the legacy online behavior), so
    // opting out of the sandbox does not change how govulncheck runs otherwise.
    if confinement.is_confined() {
        // Pre-create both dirs *outside* the sandbox: the toolchain needs
        // `GOTMPDIR` to exist, and it cannot create `GOCACHE` itself because the
        // sandbox only makes the cache dir (not its parents) writable. `GOTMPDIR`
        // stays in the throwaway work dir (per-build scratch); `GOCACHE` is the
        // persistent cross-scan cache.
        let gotmp = work.path().join("gotmp");
        std::fs::create_dir_all(&gotmp)
            .map_err(|e| GoError::Sandbox(format!("create build temp dir: {e}")))?;
        std::fs::create_dir_all(&go_cache).map_err(|e| {
            GoError::Sandbox(format!("create go build cache {}: {e}", go_cache.display()))
        })?;
        isolate_env(&mut cmd, &go_cache, &gotmp);
    }

    // Bound the run with a wall-clock timeout: govulncheck COMPILES the module, so a
    // hostile or merely huge module could otherwise hang the whole fleet scan. A
    // timeout kills the child and fails closed (an honest Errored gap), mirroring the
    // Rust reach path's build timeout.
    let output = run_with_timeout(cmd, go_timeout())?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Err(GoError::NoOutput {
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    // Classify direct vs. transitive from the module's own go.mod (deterministic,
    // no toolchain). Missing/unreadable go.mod → empty set → all transitive.
    let direct = read_direct_modules(module_dir);
    let findings = parse_findings(&stdout, repo, &direct)?;

    // `-format json` exits 0 on a clean scan AND on a vulns-found scan, so a
    // non-zero status is a genuine error — most importantly a confined scan whose
    // denied network blocked the DB fetch, which still streams config/SBOM (and so
    // parses to zero findings) and would otherwise masquerade as a clean "0 vulns"
    // result. A non-zero exit is ALWAYS abnormal here and fails closed — even with
    // some findings already parsed, because a subprocess killed mid-stream (OOM /
    // timeout) can leave a *partial* findings set that would otherwise be reported as
    // a complete clean scan of the unanalyzed packages.
    if !output.status.success() {
        return Err(GoError::Failed {
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(findings)
}

/// Build the govulncheck argv: JSON source-mode scan of the whole module, with an
/// explicit `-db` when an offline mirror is supplied (so a network-denied build
/// can still consult the DB).
fn govulncheck_argv(govulncheck: &Path, govulndb: Option<&str>) -> Vec<String> {
    let mut argv = vec![
        govulncheck.to_string_lossy().into_owned(),
        "-format".to_string(),
        "json".to_string(),
    ];
    if let Some(db) = govulndb {
        argv.push("-db".to_string());
        argv.push(db.to_string());
    }
    argv.push("./...".to_string());
    argv
}

/// A `GOVULNDB` value usable under network confinement: only a `file://` mirror
/// works once the network is denied (an `http(s)://` DB would be unreachable).
fn is_offline_db(db: &str) -> bool {
    db.starts_with("file:")
}

/// The policy to actually confine under, given the requested one and whether an
/// offline DB mirror is available. `auto` confines only when a mirror makes the
/// network-denied scan viable; without one it degrades to an unconfined online
/// scan (auto's "proceed rather than refuse" contract). `require` and `off` are
/// honored as-is — `require` without a mirror fails closed downstream.
fn effective_policy(requested: SandboxPolicy, has_offline_db: bool) -> SandboxPolicy {
    match requested {
        SandboxPolicy::Auto if !has_offline_db => SandboxPolicy::Off,
        other => other,
    }
}

/// A fleetreach-owned, persistent Go build cache, reused across confined scans so
/// the offline build is incremental instead of recompiling cold every run. Kept
/// separate from the operator's own `GOCACHE` so an untrusted build never writes
/// their primary cache; Go's cache is content-addressed, so cross-scan reuse is
/// safe (a planted entry fails hash validation and is ignored, not trusted).
fn persistent_go_cache() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("fleetreach").join("go-build")
}

/// The govulncheck wall-clock timeout (default 10 minutes; override with
/// `FLEETREACH_GO_TIMEOUT_SECS`). govulncheck compiles the module, so an untrusted
/// module must not be able to hang the scan indefinitely.
fn go_timeout() -> Duration {
    let secs = std::env::var("FLEETREACH_GO_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(600);
    Duration::from_secs(secs)
}

/// Run `cmd` to completion capturing stdout/stderr, killing it (→ [`GoError::Failed`])
/// if it exceeds `timeout`. stdout/stderr are drained from reader threads so a full
/// pipe buffer cannot deadlock the child while we poll. On timeout the child is killed
/// (under bwrap's `--unshare-pid` this reaps the forked build).
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<Output, GoError> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let mut stdout_pipe = child.stdout.take().ok_or_else(|| GoError::Failed {
        stderr: "govulncheck: no stdout pipe".into(),
    })?;
    let mut stderr_pipe = child.stderr.take().ok_or_else(|| GoError::Failed {
        stderr: "govulncheck: no stderr pipe".into(),
    })?;
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(GoError::Timeout {
                secs: timeout.as_secs(),
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    // Readers finish once the pipes hit EOF (process exited). join() returns the bytes;
    // a panicked reader degrades to empty output rather than failing the scan.
    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

/// Read the module's `go.mod` and return its direct module paths (see
/// [`direct_modules`]). Best effort: a missing or unreadable manifest yields an empty
/// set, which classifies every finding transitive rather than failing the scan.
fn read_direct_modules(module_dir: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(module_dir.join("go.mod"))
        .map(|src| direct_modules(&src))
        .unwrap_or_default()
}

/// Pre-download the module dependency closure so the confined (offline) build can
/// resolve it from the module cache. `go mod download` fetches modules but does
/// **not** compile or run any build code, so it is safe to run unconfined. Best
/// effort: a failure (offline with a cold cache, or a bad `go.sum`) just lets the
/// offline build that follows fail with a clear error → an honest gap.
fn prefetch_modules(module_dir: &Path) {
    let _ = Command::new("go")
        .arg("mod")
        .arg("download")
        .current_dir(module_dir)
        .status();
}

/// Reset `cmd`'s environment to a minimal allowlist before the confined build
/// runs the untrusted module's code. `env_clear` drops everything (operator
/// secrets included); only the variables the Go toolchain needs to locate itself
/// and the prefetched module cache are re-added. `GOCACHE` points at a persistent
/// fleetreach-owned build cache (incremental across scans, never the operator's
/// own `GOCACHE`) and `GOTMPDIR` at the throwaway work dir; both are writable
/// under the sandbox, and the network is forced fully off.
fn isolate_env(cmd: &mut Command, gocache: &Path, gotmp: &Path) {
    // Locate the toolchain + the (read-only, prefetched) module cache; basic
    // locale/term so go's output is well-formed.
    const ALLOW: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "TERM",
        "LANG",
        "GOPATH",
        "GOROOT",
        "GOMODCACHE",
    ];
    cmd.env_clear();
    for key in ALLOW {
        if let Some(val) = std::env::var_os(key) {
            cmd.env(key, val);
        }
    }
    // Build cache + temp into the writable scratch dir, not the shared `GOCACHE`.
    cmd.env("GOCACHE", gocache);
    cmd.env("GOTMPDIR", gotmp);
    // Network is denied, so force resolution fully offline: no module proxy, no
    // checksum-DB lookups, and no on-demand toolchain download (use the installed
    // one). A genuinely missing input then fails fast and clearly.
    cmd.env("GOPROXY", "off");
    cmd.env("GOSUMDB", "off");
    cmd.env("GOTOOLCHAIN", "local");
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::*;

    #[test]
    fn argv_is_json_source_scan_without_a_db_by_default() {
        let argv = govulncheck_argv(Path::new("/bin/govulncheck"), None);
        assert_eq!(
            argv,
            vec!["/bin/govulncheck", "-format", "json", "./..."],
            "online scan uses govulncheck's default DB (no -db)"
        );
    }

    #[test]
    fn argv_threads_an_offline_db_mirror_as_minus_db() {
        let argv = govulncheck_argv(
            Path::new("/bin/govulncheck"),
            Some("file:///opt/vulndb-mirror"),
        );
        // The `-db` flag must immediately precede the mirror url, and the package
        // pattern stays last.
        assert_eq!(
            argv,
            vec![
                "/bin/govulncheck",
                "-format",
                "json",
                "-db",
                "file:///opt/vulndb-mirror",
                "./...",
            ]
        );
    }

    #[test]
    fn auto_degrades_to_off_without_an_offline_mirror() {
        use SandboxPolicy::{Auto, Off, Require};
        // auto: confine only when a mirror makes the offline scan viable.
        assert_eq!(
            effective_policy(Auto, false),
            Off,
            "auto + no mirror → online"
        );
        assert_eq!(
            effective_policy(Auto, true),
            Auto,
            "auto + mirror → confined"
        );
        // require + off are honored verbatim (require fails closed downstream).
        assert_eq!(effective_policy(Require, false), Require);
        assert_eq!(effective_policy(Require, true), Require);
        assert_eq!(effective_policy(Off, false), Off);
        assert_eq!(effective_policy(Off, true), Off);
    }

    #[test]
    fn only_a_file_url_counts_as_an_offline_db() {
        assert!(is_offline_db("file:///opt/vulndb"));
        assert!(is_offline_db("file://./local"));
        // A network DB is useless once confinement denies the network.
        assert!(!is_offline_db("https://vuln.go.dev"));
        assert!(!is_offline_db("http://internal/db"));
        assert!(!is_offline_db(""));
    }

    /// The command's explicitly-set environment as a UTF-8 map. After
    /// `env_clear()` this is exactly what the child will see, so it doubles as a
    /// check that nothing leaks past the allowlist.
    fn set_envs(cmd: &Command) -> BTreeMap<String, String> {
        cmd.get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
            .collect()
    }

    #[test]
    fn isolate_env_redirects_caches_and_forces_offline() {
        let gocache = PathBuf::from("/scratch/work/gocache");
        let gotmp = PathBuf::from("/scratch/work/gotmp");
        let mut cmd = Command::new("govulncheck");
        isolate_env(&mut cmd, &gocache, &gotmp);
        let env = set_envs(&cmd);

        // Build cache + temp are redirected into the writable scratch dir, never
        // the operator's shared `GOCACHE`.
        assert_eq!(
            env.get("GOCACHE").map(String::as_str),
            Some("/scratch/work/gocache")
        );
        assert_eq!(
            env.get("GOTMPDIR").map(String::as_str),
            Some("/scratch/work/gotmp")
        );
        // Network is forced fully off for the offline build.
        assert_eq!(env.get("GOPROXY").map(String::as_str), Some("off"));
        assert_eq!(env.get("GOSUMDB").map(String::as_str), Some("off"));
        assert_eq!(env.get("GOTOOLCHAIN").map(String::as_str), Some("local"));

        // The scrub is a strict allowlist: every var the child sees is either a
        // toolchain-locating passthrough or one of our overrides — an operator
        // secret (e.g. AWS_SECRET_ACCESS_KEY) can never reach the untrusted build.
        const ALLOWED: &[&str] = &[
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "TERM",
            "LANG",
            "GOPATH",
            "GOROOT",
            "GOMODCACHE",
            "GOCACHE",
            "GOTMPDIR",
            "GOPROXY",
            "GOSUMDB",
            "GOTOOLCHAIN",
        ];
        for key in env.keys() {
            assert!(
                ALLOWED.contains(&key.as_str()),
                "unexpected env var leaked into the confined build: {key}"
            );
        }
    }
}
