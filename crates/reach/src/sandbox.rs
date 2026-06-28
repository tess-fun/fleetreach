//! Confine the untrusted build (defense-in-depth for `--reachability=static`,
//! which compiles scanned repos and so runs their `build.rs` / proc-macros).
//!
//! When a platform sandbox is available we wrap `cargo build` to **deny the
//! network** (no exfiltration / C2) and **confine writes** to the throwaway work
//! dir (no touching `$HOME` or the source we fingerprinted). Reads stay broad
//! (toolchain, registry, repo source). A confinement-induced build failure is
//! `Unknown`, never a false `NotReachable`.
//!
//! Mechanisms: macOS `sandbox-exec` (verified, see `tests/sandbox.rs`); Linux
//! `bwrap`/`firejail` (fail-closed, not yet host-verified).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::ReachError;

/// Absolute path to macOS `sandbox-exec`. Invoked by absolute path (not bare name)
/// so a `PATH`-shadowing shim cannot pose as the sandbox under `--build-sandbox=require`.
const MAC_SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// How aggressively to confine the build.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SandboxPolicy {
    /// No confinement — the build runs with the user's full privileges. The
    /// library default, so existing callers and tests are unchanged; the cli
    /// opts up to [`Auto`](SandboxPolicy::Auto).
    #[default]
    Off,
    /// Confine if a platform mechanism is available; otherwise warn (once) and
    /// proceed unconfined rather than refuse to scan. The cli default.
    Auto,
    /// Confine, or fail the build (→ `Unknown`) if no mechanism is available.
    /// For callers who would rather get no verdict than an unconfined build.
    Require,
}

/// A resolved confinement decision for one build.
pub(crate) enum Sandbox {
    /// Run the command as-is, unconfined.
    None,
    /// Wrap the command with `mechanism`, confining writes to `writable`.
    Confined {
        mechanism: Mechanism,
        /// Roots the build may write to (the work dir and the system temp dir).
        writable: Vec<PathBuf>,
    },
}

/// A platform confinement mechanism we detected on `PATH`. Which variants are
/// ever constructed is platform-conditional (`detect`), so each looks dead on
/// the *other* platform — hence the crate-local allow.
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) enum Mechanism {
    /// macOS `sandbox-exec` (profile-based).
    MacSandbox,
    /// Linux `bwrap` (bubblewrap).
    Bubblewrap,
    /// Linux `firejail`.
    Firejail,
}

impl Sandbox {
    /// Decide how to confine a build under `policy`, given the throwaway
    /// `work_dir` the build writes its target/fragments into. May print a
    /// one-line warning to stderr (Auto, no mechanism).
    pub(crate) fn resolve(policy: SandboxPolicy, work_dir: &Path) -> Result<Self, ReachError> {
        if policy == SandboxPolicy::Off {
            return Ok(Sandbox::None);
        }
        match detect() {
            Some(mechanism) => {
                // Canonicalize so the profile's subpaths match the realpaths the
                // build actually uses (`/tmp` → `/private/tmp` on macOS, etc.).
                let mut writable = vec![canonical(work_dir)];
                let tmp = canonical(&std::env::temp_dir());
                if !writable.iter().any(|w| tmp.starts_with(w)) {
                    writable.push(tmp);
                }
                Ok(Sandbox::Confined {
                    mechanism,
                    writable,
                })
            }
            None if policy == SandboxPolicy::Require => Err(ReachError::Build(
                "no build sandbox available (need sandbox-exec on macOS, or bwrap/firejail on \
                 Linux) and --build-sandbox=require was set"
                    .to_string(),
            )),
            None => {
                eprintln!(
                    "warning: no build sandbox available (sandbox-exec / bwrap / firejail); the \
                     untrusted build will run UNCONFINED. Install one, or pass \
                     --build-sandbox=require to fail instead."
                );
                Ok(Sandbox::None)
            }
        }
    }

    /// `true` when the build will run offline — confinement denies the network,
    /// so dependencies must be pre-fetched and the build run `--frozen`.
    pub(crate) fn is_confined(&self) -> bool {
        matches!(self, Sandbox::Confined { .. })
    }

    /// Build the `Command` that runs `inner` (a full argv, e.g.
    /// `["cargo", "+nightly-…", "build", "--frozen"]`) under this confinement.
    /// The caller still sets the env, working directory, and timeout.
    pub(crate) fn command(&self, inner: &[String]) -> Command {
        match self {
            Sandbox::None => {
                let mut cmd = Command::new(&inner[0]);
                cmd.args(&inner[1..]);
                cmd
            }
            Sandbox::Confined {
                mechanism,
                writable,
            } => mechanism.wrap(inner, writable),
        }
    }
}

/// A resolved build confinement other feeders can reuse to wrap their own
/// untrusted subprocess with the *same* mechanism the reach build uses.
///
/// This is the public face of [`Sandbox`]: the Go feeder runs `govulncheck`,
/// which compiles the scanned module exactly as our cargo build does, so it
/// confines that subprocess through this handle rather than re-deriving a
/// platform profile. `resolve` denies the network and confines writes to
/// `work_dir` (plus the system temp dir); `command` wraps an argv with that
/// confinement (or returns it verbatim when [`Off`](SandboxPolicy::Off) / no
/// mechanism); `is_confined` reports whether the network is actually denied so
/// the caller can switch its subprocess to offline mode.
pub struct Confinement(Sandbox);

impl Confinement {
    /// Resolve `policy` for a build that writes into the throwaway `work_dir`.
    /// May warn once to stderr (Auto with no mechanism); errors only under
    /// [`Require`](SandboxPolicy::Require) when no mechanism is available.
    pub fn resolve(policy: SandboxPolicy, work_dir: &Path) -> Result<Self, ReachError> {
        Ok(Self(Sandbox::resolve(policy, work_dir)?))
    }

    /// `true` when the wrapped command will run with the network denied — the
    /// caller must then have pre-fetched everything the subprocess needs and run
    /// it offline.
    pub fn is_confined(&self) -> bool {
        self.0.is_confined()
    }

    /// Add extra roots the confined build may write to, beyond the throwaway
    /// `work_dir` and the system temp dir. A no-op when unconfined.
    ///
    /// For a build whose *only* writes are throwaway, the default work dir is
    /// enough. But a caller may want one persistent writable root — e.g. a
    /// content-addressed build cache reused across runs so the (offline) build is
    /// incremental instead of recompiling cold every time. Such a root is the
    /// caller's responsibility to keep isolated from the operator's own state.
    pub fn with_writable(mut self, roots: &[&Path]) -> Self {
        if let Sandbox::Confined { writable, .. } = &mut self.0 {
            for root in roots {
                let c = canonical(root);
                if !writable.iter().any(|w| c.starts_with(w)) {
                    writable.push(c);
                }
            }
        }
        self
    }

    /// Build a [`Command`] that runs `argv` under this confinement (or verbatim
    /// when unconfined). The caller still sets the env, working directory, etc.
    pub fn command(&self, argv: &[String]) -> Command {
        self.0.command(argv)
    }
}

impl Mechanism {
    fn wrap(&self, inner: &[String], writable: &[PathBuf]) -> Command {
        match self {
            Mechanism::MacSandbox => {
                let mut cmd = Command::new(MAC_SANDBOX_EXEC);
                cmd.arg("-p").arg(mac_profile(writable));
                cmd.args(inner);
                cmd
            }
            Mechanism::Bubblewrap => {
                // Read-only view of the whole filesystem, with the work + temp
                // dirs re-bound read-write, no network, dies with the parent.
                let mut cmd = Command::new("bwrap");
                cmd.arg("--ro-bind").arg("/").arg("/");
                cmd.arg("--dev").arg("/dev");
                cmd.arg("--proc").arg("/proc");
                for w in writable {
                    let s = w.to_string_lossy().to_string();
                    cmd.arg("--bind").arg(&s).arg(&s);
                }
                // `--unshare-pid` (with `--proc`) puts the build in its own PID
                // namespace, so a forking/daemonizing build script cannot leak a
                // process that survives the timeout: killing bwrap tears down the
                // whole namespace. `--die-with-parent` covers the parent-death case.
                cmd.arg("--unshare-net")
                    .arg("--unshare-pid")
                    .arg("--die-with-parent")
                    .arg("--");
                cmd.args(inner);
                cmd
            }
            Mechanism::Firejail => {
                let mut cmd = Command::new("firejail");
                cmd.arg("--quiet").arg("--noprofile").arg("--net=none");
                cmd.arg("--read-only=/");
                for w in writable {
                    cmd.arg(format!("--read-write={}", w.to_string_lossy()));
                }
                cmd.arg("--");
                cmd.args(inner);
                cmd
            }
        }
    }
}

/// Detect an available confinement mechanism for the current platform. Exactly
/// one `cfg` block survives compilation, so it is the function's tail expression.
fn detect() -> Option<Mechanism> {
    #[cfg(target_os = "macos")]
    {
        // sandbox-exec ships with macOS, but probe for it (at its absolute path)
        // rather than assume: under `--build-sandbox=require` a missing/removed
        // binary must fail closed, not silently run the build unconfined.
        Path::new(MAC_SANDBOX_EXEC)
            .is_file()
            .then_some(Mechanism::MacSandbox)
    }
    #[cfg(target_os = "linux")]
    {
        if on_path("bwrap") {
            Some(Mechanism::Bubblewrap)
        } else if on_path("firejail") {
            Some(Mechanism::Firejail)
        } else {
            None
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

/// A `sandbox-exec` profile: deny by default, allow process exec + broad reads,
/// confine writes to `writable`, and deny the network. `(allow mach*)` /
/// `(allow sysctl-read)` are needed for cargo/rustc to spawn at all.
#[cfg(any(target_os = "macos", test))]
fn mac_profile(writable: &[PathBuf]) -> String {
    let mut p = String::from(
        "(version 1)\n(deny default)\n(allow process*)\n(allow sysctl-read)\n\
         (allow mach*)\n(allow file-read*)\n(allow file-write*\n",
    );
    for w in writable {
        // Scheme-quote the path so spaces / odd chars in the realpath are safe.
        p.push_str(&format!("  (subpath {})\n", quote_sb(&w.to_string_lossy())));
    }
    // Devices a normal build touches; without these even writing /dev/null fails.
    p.push_str(
        "  (literal \"/dev/null\")\n  (literal \"/dev/dtracehelper\")\n  (subpath \"/dev/tty\"))\n\
         (deny network*)\n",
    );
    p
}

/// Quote a string as a Scheme/TinyScheme string literal for the SBPL profile.
#[cfg(any(target_os = "macos", test))]
fn quote_sb(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Canonicalize a path, falling back to the input if it does not yet exist.
fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

#[cfg(target_os = "linux")]
fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn off_policy_never_confines() {
        let sb = Sandbox::resolve(SandboxPolicy::Off, Path::new("/tmp")).unwrap();
        assert!(!sb.is_confined());
        // command() returns the inner argv verbatim.
        let cmd = sb.command(&["cargo".into(), "build".into()]);
        assert_eq!(cmd.get_program(), "cargo");
    }

    #[test]
    fn confinement_off_runs_verbatim() {
        // The public handle other feeders reuse: Off resolves to no confinement
        // and wraps an argv unchanged, so an opted-out caller runs its subprocess
        // exactly as it would have.
        let c = Confinement::resolve(SandboxPolicy::Off, Path::new("/tmp")).unwrap();
        assert!(!c.is_confined());
        let cmd = c.command(&["govulncheck".into(), "-format".into(), "json".into()]);
        assert_eq!(cmd.get_program(), "govulncheck");
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args, ["-format", "json"]);
    }

    #[test]
    fn with_writable_is_a_noop_when_unconfined() {
        // Off resolves to no confinement, so extra writable roots are irrelevant
        // and the command still runs verbatim — a feeder can call with_writable
        // unconditionally without changing the unconfined path.
        let c = Confinement::resolve(SandboxPolicy::Off, Path::new("/tmp"))
            .unwrap()
            .with_writable(&[Path::new("/some/persistent/cache")]);
        assert!(!c.is_confined());
        assert_eq!(c.command(&["go".into()]).get_program(), "go");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn with_writable_adds_a_root_to_a_confined_profile() {
        // On macOS the sandbox is always available, so Auto confines; the extra
        // root must appear as a writable subpath in the emitted profile.
        let c = Confinement::resolve(SandboxPolicy::Auto, Path::new("/tmp"))
            .unwrap()
            .with_writable(&[Path::new("/tmp")]); // /tmp canonicalizes under the work/temp roots already
        assert!(c.is_confined());
        if let Sandbox::Confined { writable, .. } = &c.0 {
            // The default work + temp roots are present; adding an already-covered
            // path does not duplicate it.
            assert!(!writable.is_empty());
        } else {
            panic!("Auto on macOS should confine");
        }
    }

    #[test]
    fn mac_profile_denies_network_and_confines_writes() {
        let prof = mac_profile(&[PathBuf::from("/work dir")]);
        assert!(prof.contains("(deny network*)"));
        assert!(prof.contains("(deny default)"));
        // The space in the path must be inside a quoted literal, not bare.
        assert!(prof.contains("(subpath \"/work dir\")"));
    }

    #[test]
    fn sb_quoting_escapes_quotes_and_backslashes() {
        assert_eq!(quote_sb(r#"a"b\c"#), r#""a\"b\\c""#);
    }
}
