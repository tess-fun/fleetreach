//! Consented Python resolution (spec 16, row 9): `scan --resolve-python` runs a pinned
//! `uv pip compile --no-build` on each unlocked Python dependency set so its scan sees the
//! full transitive set instead of only the declared names.
//!
//! uv contacts the package index to resolve, which is why this needs the flag, but it never
//! builds or runs package code: `--no-build` refuses source distributions, so resolution
//! reads only wheel metadata. The repo's own uv configuration (`uv.toml`,
//! `[tool.uv]`, `[tool.uv.sources]`) is ignored, so a scanned repo cannot point uv at a
//! local path or a build. A file uv cannot resolve stays as it was read before, with a
//! coverage gap naming uv's error.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The oldest uv whose `pip compile` has every flag this module passes.
pub const MIN_UV: (u64, u64) = (0, 5);

/// The Python version resolution targets (`--python-version`); with `--universal` it is the
/// lowest version the resolution must hold for, and markers cover the rest.
pub const PYTHON_VERSION: &str = "3.12";

/// How long one compile may take before it is stopped and reported as a gap.
const TIMEOUT: Duration = Duration::from_secs(300);

/// A located, version-checked uv.
#[derive(Debug, Clone)]
pub struct PyResolver {
    uv: PathBuf,
    version: String,
    offline: bool,
}

impl PyResolver {
    /// Find uv (`explicit`, else `uv` on `PATH` or `~/.local/bin`) and check its version.
    ///
    /// # Errors
    ///
    /// No uv, one that does not run, or one older than [`MIN_UV`].
    pub fn locate(explicit: Option<&Path>, offline: bool) -> Result<Self, String> {
        let uv = match explicit {
            Some(path) if path.is_file() => path.to_path_buf(),
            Some(path) => return Err(format!("--uv {} is not a file", path.display())),
            None => find_on_path().ok_or_else(|| {
                "--resolve-python needs uv on PATH (or --uv PATH); install it from \
                 https://docs.astral.sh/uv/"
                    .to_string()
            })?,
        };
        let out = Command::new(&uv)
            .arg("--version")
            .env("UV_NO_CONFIG", "1")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run {}: {e}", uv.display()))?;
        let text = String::from_utf8_lossy(&out.stdout);
        let version = parse_version(&text)
            .ok_or_else(|| format!("{} --version printed {:?}", uv.display(), text.trim()))?;
        if !out.status.success() || version_tuple(&version) < Some(MIN_UV) {
            return Err(format!(
                "--resolve-python needs uv {}.{} or later; {} is {version}",
                MIN_UV.0,
                MIN_UV.1,
                uv.display()
            ));
        }
        Ok(Self {
            uv,
            version,
            offline,
        })
    }

    /// The uv version, for the report.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Compile each of `inputs` (from [`fleetreach_pypi::resolution_inputs`]). uv gets the
    /// set on stdin and runs in an empty scratch directory, so it opens no file of the repo.
    /// Returns uv's output per input path, and an error per input uv could not resolve.
    #[must_use]
    pub fn compile_all(
        &self,
        inputs: &[fleetreach_pypi::ResolutionInput],
    ) -> (BTreeMap<PathBuf, String>, Vec<(PathBuf, String)>) {
        let mut resolved = BTreeMap::new();
        let mut failed = Vec::new();
        for input in inputs {
            match self.compile(input) {
                Ok(text) => {
                    resolved.insert(input.path.clone(), text);
                }
                Err(e) => failed.push((input.path.clone(), e)),
            }
        }
        (resolved, failed)
    }

    fn compile(&self, input: &fleetreach_pypi::ResolutionInput) -> Result<String, String> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let scratch =
            std::env::temp_dir().join(format!("fleetreach-uv-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&scratch).map_err(|e| format!("scratch dir: {e}"))?;
        let result = self.compile_in(&scratch, input);
        let _ = std::fs::remove_dir_all(&scratch);
        result
    }

    fn compile_in(
        &self,
        scratch: &Path,
        input: &fleetreach_pypi::ResolutionInput,
    ) -> Result<String, String> {
        let mut cmd = Command::new(&self.uv);
        cmd.args(["pip", "compile", "-"]);
        if !input.constraints.trim().is_empty() {
            std::fs::write(scratch.join("constraints.txt"), &input.constraints)
                .map_err(|e| format!("constraints file: {e}"))?;
            cmd.args(["-c", "constraints.txt"]);
        }
        cmd.args(compile_flags(self.offline))
            .current_dir(scratch)
            .env("UV_NO_CONFIG", "1")
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("cannot run {}: {e}", self.uv.display()))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(input.requirements.as_bytes())
                .map_err(|e| format!("cannot write to uv: {e}"))?;
        }
        let stdout = child.stdout.take().map(drain);
        let stderr = child.stderr.take().map(drain);
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() > TIMEOUT => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("uv pip compile ran over {}s", TIMEOUT.as_secs()));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => return Err(format!("waiting for uv: {e}")),
            }
        };
        let stdout = stdout.and_then(|h| h.join().ok()).unwrap_or_default();
        let stderr = stderr.and_then(|h| h.join().ok()).unwrap_or_default();
        if status.success() {
            Ok(stdout)
        } else {
            Err(first_error(&stderr))
        }
    }
}

/// The flags every compile passes, after the input.
#[must_use]
pub fn compile_flags(offline: bool) -> Vec<&'static str> {
    let mut flags = vec![
        "--no-build",
        "--no-config",
        "--no-sources",
        "--universal",
        "--python-version",
        PYTHON_VERSION,
        "--no-progress",
        "--quiet",
        "--color",
        "never",
    ];
    if offline {
        flags.push("--offline");
    }
    flags
}

fn drain(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    })
}

/// uv's error, cut to the lines that say why: it prints `error:` and then a cause chain.
fn first_error(stderr: &str) -> String {
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let start = lines
        .iter()
        .position(|l| l.starts_with("error:") || l.starts_with("×"))
        .unwrap_or(0);
    let text = lines[start..]
        .iter()
        .take(4)
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    if text.is_empty() {
        "uv pip compile failed with no message".to_string()
    } else if text.len() > 400 {
        let mut cut = 400;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}...", &text[..cut])
    } else {
        text
    }
}

fn find_on_path() -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".local").join("bin"));
    }
    dirs.into_iter().map(|d| d.join("uv")).find(|p| p.is_file())
}

fn parse_version(text: &str) -> Option<String> {
    let word = text.split_whitespace().nth(1)?;
    version_tuple(word).map(|_| word.to_string())
}

fn version_tuple(v: &str) -> Option<(u64, u64)> {
    let mut parts = v.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn reads_uv_version_lines() {
        assert_eq!(
            parse_version("uv 0.11.25 (Homebrew 2026-10-01)\n").as_deref(),
            Some("0.11.25")
        );
        assert_eq!(parse_version("uv\n"), None);
        assert!(version_tuple("0.4.30") < Some(MIN_UV));
        assert!(version_tuple("0.11.25") >= Some(MIN_UV));
        assert!(version_tuple("1.0.0") >= Some(MIN_UV));
    }

    #[test]
    fn keeps_the_error_and_its_causes() {
        let stderr = "Resolved in 3ms\n  × No solution found when resolving dependencies:\n  ╰─▶ Because foo was not found in the package registry\n";
        let e = first_error(stderr);
        assert!(e.starts_with("× No solution found"), "{e}");
        assert!(e.contains("foo was not found"), "{e}");
        assert_eq!(first_error(""), "uv pip compile failed with no message");
    }

    #[test]
    fn never_builds_and_ignores_repo_config() {
        let flags = compile_flags(true);
        for f in ["--no-build", "--no-config", "--no-sources", "--offline"] {
            assert!(flags.contains(&f), "{f}");
        }
        assert!(!compile_flags(false).contains(&"--offline"));
    }
}
