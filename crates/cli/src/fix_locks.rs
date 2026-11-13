//! Lock edits for Swift, Hex and Julia (spec 16, row 5). Their manifests are code
//! (`Package.swift`, `mix.exs`) or need a resolver run (`Pkg`), so nothing is asked of the
//! package manager: the lockfile entry is rewritten as text from registry metadata, and only
//! when every constraint the lockfile and manifest show still holds.
//!
//! | Lockfile | New entry from | Checked before the edit |
//! |----------|----------------|-------------------------|
//! | `Package.resolved` | the tag's commit, by `git ls-remote` | the range in `Package.swift` |
//! | `mix.lock` | `repo.hex.pm/packages/<name>`: checksums and requirements | same dependencies; their locked versions meet the new requirements; every dependent's and `mix.exs` requirement takes the new version |
//! | `Manifest.toml` | the General registry: tree hash, `Deps.toml`, `Compat.toml` | same dependencies; their locked versions meet the new compat; every dependent's and `Project.toml`'s compat takes the new version |
//!
//! What stays out, with a reason in the plan: a pin that comes in only through another
//! package (Swift's lockfile has no graph, and the range is in that package's manifest), a
//! new version whose dependency list differs (a resolver run is needed), pins from git, a
//! path, another registry or a non-hexpm organization, and pre-release targets. Nothing is
//! downloaded but metadata; no package archive and no package code.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::process::Command;

use fleetreach_core::semver::Version;

use crate::fix::{dirs_with, run, Edit};
use crate::health::Fetch;

const HEX_REPO: &str = "https://repo.hex.pm";
const GENERAL: &str = "https://raw.githubusercontent.com/JuliaRegistries/General/master";
/// The largest registry file read after decompression.
const MAX_REGISTRY: u64 = 64 << 20;

/// The target as a release version: these lockfiles never pin a pre-release on purpose.
fn release(to: &str) -> Result<Version, String> {
    let v = Version::parse(to).map_err(|_| format!("{to} is not a version to pin"))?;
    if v.pre.is_empty() {
        Ok(v)
    } else {
        Err(format!(
            "{to} is a pre-release; pin it by hand if it is wanted"
        ))
    }
}

/// Up to three numeric components, `v` prefix and build metadata dropped.
fn components(s: &str) -> Option<Vec<u64>> {
    let s = s.trim();
    let s = s.strip_prefix('v').unwrap_or(s);
    let core = s.split('+').next()?;
    if core.is_empty() {
        return Some(Vec::new());
    }
    let parts: Vec<u64> = core
        .split('.')
        .map(|p| p.parse::<u64>().ok())
        .collect::<Option<_>>()?;
    (parts.len() <= 3).then_some(parts)
}

/// A version from one to three components, the missing ones zero.
fn padded(s: &str) -> Option<Version> {
    let s = s.trim();
    if let Ok(v) = Version::parse(s.strip_prefix('v').unwrap_or(s)) {
        return Some(v);
    }
    let c = components(s).filter(|c| !c.is_empty())?;
    Some(Version::new(
        c[0],
        c.get(1).copied().unwrap_or(0),
        c.get(2).copied().unwrap_or(0),
    ))
}

fn triple(v: &Version) -> [u64; 3] {
    [v.major, v.minor, v.patch]
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn text(fetch: &dyn Fetch, url: &str) -> Result<Option<String>, String> {
    match fetch.get(url)? {
        Some(body) => String::from_utf8(body)
            .map(Some)
            .map_err(|_| format!("{url} is not UTF-8")),
        None => Ok(None),
    }
}

// ---- Swift ----

/// A version requirement from `Package.swift`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SwiftReq {
    /// `from:` and `.upToNextMajor(from:)`.
    Major(Version),
    Minor(Version),
    Exact(Version),
    /// `"a"..<"b"` (`false`) or `"a"..."b"` (`true`).
    Range(Version, Version, bool),
}

impl SwiftReq {
    fn allows(&self, v: &Version) -> bool {
        match self {
            SwiftReq::Major(lo) => v >= lo && *v < Version::new(lo.major + 1, 0, 0),
            SwiftReq::Minor(lo) => v >= lo && *v < Version::new(lo.major, lo.minor + 1, 0),
            SwiftReq::Exact(x) => v == x,
            SwiftReq::Range(lo, hi, inclusive) => {
                v >= lo && if *inclusive { v <= hi } else { v < hi }
            }
        }
    }

    fn describe(&self) -> String {
        match self {
            SwiftReq::Major(lo) => format!("from: \"{lo}\""),
            SwiftReq::Minor(lo) => format!(".upToNextMinor(from: \"{lo}\")"),
            SwiftReq::Exact(x) => format!("exact: \"{x}\""),
            SwiftReq::Range(lo, hi, true) => format!("\"{lo}\"...\"{hi}\""),
            SwiftReq::Range(lo, hi, false) => format!("\"{lo}\"..<\"{hi}\""),
        }
    }
}

/// Swift source with comments blanked out, string literals kept, so offsets still line up.
fn without_swift_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut in_string = false;
    let mut chars = src.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        if at < i {
            continue;
        }
        if in_string {
            out.push(c);
            if c == '\\' {
                if let Some((_, n)) = chars.next() {
                    out.push(n);
                }
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match (c, b.get(at + 1)) {
            ('"', _) => {
                in_string = true;
                out.push(c);
            }
            ('/', Some(b'/')) => {
                let end = src[at..].find('\n').map_or(src.len(), |e| at + e);
                out.extend(std::iter::repeat_n(' ', src[at..end].chars().count()));
                i = end;
            }
            ('/', Some(b'*')) => {
                let end = src[at + 2..]
                    .find("*/")
                    .map_or(src.len(), |e| at + 2 + e + 2);
                out.extend(
                    src[at..end]
                        .chars()
                        .map(|c| if c == '\n' { '\n' } else { ' ' }),
                );
                i = end;
            }
            _ => out.push(c),
        }
    }
    out
}

/// The string literal starting at or after `from`, and the offset just past it.
fn next_string(src: &str, from: usize) -> Option<(String, usize)> {
    let start = from + src.get(from..)?.find('"')? + 1;
    let mut out = String::new();
    let mut chars = src[start..].char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                if let Some((_, n)) = chars.next() {
                    out.push(n);
                }
            }
            '"' => return Some((out, start + i + 1)),
            _ => out.push(c),
        }
    }
    None
}

/// The text between the parenthesis at `open` and its match, strings respected.
fn balanced(src: &str, open: usize) -> Option<&str> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (i, c) in src[open..].char_indices() {
        if in_string {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return src.get(open + 1..open + i);
                }
            }
            _ => {}
        }
    }
    None
}

/// The requirement in one `.package(...)` argument list.
fn swift_req(args: &str) -> Result<SwiftReq, String> {
    let version_after = |key: &str| -> Result<Version, String> {
        let at = args.find(key).ok_or("no version")?;
        let (raw, _) = next_string(args, at + key.len()).ok_or("no version")?;
        padded(&raw).ok_or_else(|| format!("\"{raw}\" is not a version"))
    };
    if ["branch:", "revision:", ".branch(", ".revision("]
        .iter()
        .any(|k| args.contains(k))
    {
        return Err("it follows a branch or revision".to_string());
    }
    if args.contains(".upToNextMinor(") {
        return version_after(".upToNextMinor(").map(SwiftReq::Minor);
    }
    if args.contains(".upToNextMajor(") {
        return version_after(".upToNextMajor(").map(SwiftReq::Major);
    }
    if args.contains(".exact(") {
        return version_after(".exact(").map(SwiftReq::Exact);
    }
    if args.contains("exact:") {
        return version_after("exact:").map(SwiftReq::Exact);
    }
    if args.contains("from:") {
        return version_after("from:").map(SwiftReq::Major);
    }
    for (op, inclusive) in [("..<", false), ("...", true)] {
        if let Some(at) = args.find(op) {
            let lo = args[..at]
                .rfind('"')
                .and_then(|end| args[..end].rfind('"').map(|s| &args[s + 1..end]));
            let hi = next_string(args, at + op.len()).map(|(s, _)| s);
            if let (Some(lo), Some(hi)) = (lo.and_then(padded), hi.as_deref().and_then(padded)) {
                return Ok(SwiftReq::Range(lo, hi, inclusive));
            }
        }
    }
    Err("its requirement is not one fleetreach reads".to_string())
}

/// Every requirement `Package.swift` puts on `package` (a normalized URL).
fn swift_manifest_reqs(manifest: &str, package: &str) -> Result<Vec<SwiftReq>, String> {
    let src = without_swift_comments(manifest);
    let mut reqs = Vec::new();
    let mut from = 0;
    while let Some(at) = src[from..].find(".package(") {
        let open = from + at + ".package".len();
        from = open + 1;
        let Some(args) = balanced(&src, open) else {
            return Err("Package.swift has an unbalanced .package(".to_string());
        };
        let Some(url_at) = args.find("url:") else {
            continue;
        };
        let Some((url, _)) = next_string(args, url_at + "url:".len()) else {
            continue;
        };
        if fleetreach_swift::normalize_package_url(&url) != package {
            continue;
        }
        reqs.push(swift_req(args).map_err(|e| format!("Package.swift's {package}: {e}"))?);
    }
    Ok(reqs)
}

/// One pin of `Package.resolved`, any format version.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SwiftPin {
    location: String,
    version: String,
    revision: String,
}

fn swift_pins(resolved: &str) -> Result<Vec<SwiftPin>, String> {
    let json: serde_json::Value =
        serde_json::from_str(resolved).map_err(|e| format!("Package.resolved: {e}"))?;
    let pins = json
        .get("pins")
        .or_else(|| json.get("object").and_then(|o| o.get("pins")))
        .and_then(serde_json::Value::as_array)
        .ok_or("Package.resolved has no pins")?;
    Ok(pins
        .iter()
        .filter_map(|p| {
            let location = p
                .get("location")
                .or_else(|| p.get("repositoryURL"))?
                .as_str()?;
            let state = p.get("state")?;
            Some(SwiftPin {
                location: location.to_string(),
                version: state.get("version")?.as_str()?.to_string(),
                revision: state.get("revision")?.as_str()?.to_string(),
            })
        })
        .collect())
}

/// The value range of the string after `"key"`, searched in `text[from..to]`.
fn json_value_after(
    text: &str,
    key: &str,
    from: usize,
    to: usize,
) -> Option<std::ops::Range<usize>> {
    let quoted = format!("\"{key}\"");
    let at = from + text.get(from..to)?.find(&quoted)? + quoted.len();
    let rest = &text[at..to];
    let colon = rest.find(':')?;
    if !rest[..colon].trim().is_empty() {
        return None;
    }
    let after = at + colon + 1;
    let open = after + text[after..to].find(|c: char| !c.is_whitespace())?;
    if text.as_bytes().get(open) != Some(&b'"') {
        return None;
    }
    let close = open + 1 + text[open + 1..to].find('"')?;
    Some(open + 1..close)
}

/// `Package.resolved` with one pin moved, everything else byte for byte.
fn swift_rewrite(
    resolved: &str,
    pin: &SwiftPin,
    version: &str,
    revision: &str,
) -> Result<String, String> {
    let literals = [
        serde_json::to_string(&pin.location).map_err(|e| e.to_string())?,
        serde_json::to_string(&pin.location)
            .map_err(|e| e.to_string())?
            .replace('/', "\\/"),
    ];
    let mut starts = literals
        .iter()
        .flat_map(|l| resolved.match_indices(l.as_str()).map(|(i, m)| i + m.len()))
        .collect::<BTreeSet<_>>()
        .into_iter();
    let (Some(start), None) = (starts.next(), starts.next()) else {
        return Err(format!("{} is pinned more than once", pin.location));
    };
    let end = [
        "\"identity\"",
        "\"location\"",
        "\"repositoryURL\"",
        "\"package\"",
    ]
    .iter()
    .filter_map(|k| resolved[start..].find(k).map(|e| start + e))
    .min()
    .unwrap_or(resolved.len());
    let rev = json_value_after(resolved, "revision", start, end);
    let ver = json_value_after(resolved, "version", start, end);
    match (rev, ver) {
        (Some(rev), Some(ver))
            if resolved[rev.clone()] == pin.revision && resolved[ver.clone()] == pin.version =>
        {
            let mut out = String::with_capacity(resolved.len() + 8);
            let (first, second, first_to, second_to) = if rev.start < ver.start {
                (rev, ver, revision, version)
            } else {
                (ver, rev, version, revision)
            };
            out.push_str(&resolved[..first.start]);
            out.push_str(first_to);
            out.push_str(&resolved[first.end..second.start]);
            out.push_str(second_to);
            out.push_str(&resolved[second.end..]);
            Ok(out)
        }
        _ => Err(format!(
            "cannot find the state of {} in Package.resolved",
            pin.location
        )),
    }
}

/// Whether git may be pointed at this location: no option, no command transports.
fn plain_location(location: &str) -> bool {
    !location.starts_with('-')
        && !location.contains("::")
        && !location.starts_with("ext:")
        && !location.starts_with("fd:")
}

/// The commit a release tag names, from `git ls-remote --tags`. `1.2.3` and `v1.2.3` are both
/// tried, and a short `1.2` for a `.0` patch; tags that disagree are refused.
fn tag_revision(location: &str, to: &Version) -> Result<String, String> {
    if !plain_location(location) {
        return Err(format!(
            "{location} is not a repository URL fleetreach will ask git about"
        ));
    }
    let out = run(Command::new("git")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "protocol.fd.allow=never",
        ])
        .args(["ls-remote", "--tags", "--", location]))
    .map_err(|e| format!("git ls-remote {location}: {e}"))?;
    swift_tag_commit(&out, to).map_err(|e| format!("{location}: {e}"))
}

fn swift_tag_commit(listing: &str, to: &Version) -> Result<String, String> {
    let mut names = vec![to.to_string(), format!("v{to}")];
    if to.patch == 0 {
        names.push(format!("{}.{}", to.major, to.minor));
        names.push(format!("v{}.{}", to.major, to.minor));
    }
    let mut direct: BTreeMap<&str, &str> = BTreeMap::new();
    let mut peeled: BTreeMap<&str, &str> = BTreeMap::new();
    for line in listing.lines() {
        let Some((sha, name)) = line.split_once('\t') else {
            continue;
        };
        let Some(tag) = name.strip_prefix("refs/tags/") else {
            continue;
        };
        if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        match tag.strip_suffix("^{}") {
            Some(tag) => peeled.insert(tag, sha),
            None => direct.insert(tag, sha),
        };
    }
    let found: BTreeSet<&str> = names
        .iter()
        .filter_map(|n| {
            peeled
                .get(n.as_str())
                .or_else(|| direct.get(n.as_str()))
                .copied()
        })
        .collect();
    let mut found = found.into_iter();
    match (found.next(), found.next()) {
        (Some(sha), None) => Ok(sha.to_string()),
        (None, _) => Err(format!("no tag {to}")),
        (Some(_), Some(_)) => Err(format!("tags for {to} name different commits")),
    }
}

/// Move a Swift package's pin to the tag of `to`, when `Package.swift` allows it.
pub(crate) fn swift_bump(work: &Path, edit: &Edit) -> Result<String, String> {
    swift_bump_with(work, edit, &tag_revision)
}

type TagLookup<'a> = &'a dyn Fn(&str, &Version) -> Result<String, String>;

fn swift_bump_with(work: &Path, edit: &Edit, lookup: TagLookup<'_>) -> Result<String, String> {
    let to = release(&edit.to)?;
    let package = fleetreach_swift::normalize_package_url(&edit.package);
    let mut moved = 0usize;
    for dir in dirs_with(work, "Package.resolved") {
        let path = dir.join("Package.resolved");
        let resolved = fleetreach_core::repofile::read_to_string(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let pins: Vec<SwiftPin> = swift_pins(&resolved)?
            .into_iter()
            .filter(|p| {
                fleetreach_swift::normalize_package_url(&p.location) == package
                    && edit.from.iter().any(|f| padded(f) == padded(&p.version))
            })
            .collect();
        let Some(pin) = pins.first() else {
            continue;
        };
        let manifest = fleetreach_core::repofile::read_to_string(dir.join("Package.swift"))
            .map_err(|_| {
                "no Package.swift beside Package.resolved to read the range from".to_string()
            })?;
        let reqs = swift_manifest_reqs(&manifest, &package)?;
        if reqs.is_empty() {
            return Err(format!(
                "{} comes in through another package, whose own Package.swift sets its range; \
                 update that package",
                edit.package
            ));
        }
        if let Some(req) = reqs.iter().find(|r| !r.allows(&to)) {
            return Err(format!(
                "Package.swift requires {} {}, which leaves out {to}",
                edit.package,
                req.describe()
            ));
        }
        let revision = lookup(&pin.location, &to)?;
        let new = swift_rewrite(&resolved, pin, &to.to_string(), &revision)?;
        let check = swift_pins(&new)?;
        if !check.iter().any(|p| {
            p.location == pin.location && p.version == to.to_string() && p.revision == revision
        }) {
            return Err("the rewritten Package.resolved does not read back".to_string());
        }
        std::fs::write(&path, new).map_err(|e| format!("{}: {e}", path.display()))?;
        moved += 1;
    }
    if moved == 0 {
        return Err(format!(
            "no Package.resolved pins {} at a vulnerable version",
            edit.package
        ));
    }
    Ok(format!(
        "{moved} Package.resolved pin(s) moved to {to} (the tag's commit, from git ls-remote)"
    ))
}

// ---- Hex ----

/// An Elixir term as `mix.lock` writes them.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Term {
    Atom(String),
    Str(String),
    List(Vec<Term>),
    Tuple(Vec<Term>),
    /// `key: value` in a keyword list.
    Pair(String, Box<Term>),
    /// `true`, `false`, `nil`, numbers.
    Bare(String),
}

struct TermParser<'a> {
    s: &'a str,
    i: usize,
}

fn ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '@' | '?' | '!')
}

impl TermParser<'_> {
    fn ws(&mut self) {
        loop {
            let rest = &self.s[self.i..];
            let trimmed = rest.trim_start();
            self.i += rest.len() - trimmed.len();
            if trimmed.starts_with('#') {
                self.i += trimmed.find('\n').unwrap_or(trimmed.len());
            } else {
                return;
            }
        }
    }

    fn eat(&mut self, token: &str) -> Result<(), String> {
        self.ws();
        if self.s[self.i..].starts_with(token) {
            self.i += token.len();
            Ok(())
        } else {
            Err(format!("mix.lock: expected `{token}` at byte {}", self.i))
        }
    }

    fn peek(&mut self) -> Option<char> {
        self.ws();
        self.s[self.i..].chars().next()
    }

    fn string(&mut self) -> Result<String, String> {
        self.eat("\"")?;
        let mut out = String::new();
        let mut chars = self.s[self.i..].char_indices();
        while let Some((at, c)) = chars.next() {
            match c {
                '\\' => {
                    if let Some((_, n)) = chars.next() {
                        out.push(n);
                    }
                }
                '"' => {
                    self.i += at + 1;
                    return Ok(out);
                }
                _ => out.push(c),
            }
        }
        Err("mix.lock: unterminated string".to_string())
    }

    fn word(&mut self) -> String {
        let rest = &self.s[self.i..];
        let end = rest.find(|c: char| !ident_char(c)).unwrap_or(rest.len());
        self.i += end;
        rest[..end].to_string()
    }

    fn items(&mut self, close: char) -> Result<Vec<Term>, String> {
        let mut out = Vec::new();
        loop {
            if self.peek() == Some(close) {
                self.i += 1;
                return Ok(out);
            }
            out.push(self.term()?);
            match self.peek() {
                Some(',') => self.i += 1,
                Some(c) if c == close => {}
                _ => {
                    return Err(format!(
                        "mix.lock: expected `,` or `{close}` at byte {}",
                        self.i
                    ))
                }
            }
        }
    }

    fn term(&mut self) -> Result<Term, String> {
        match self.peek() {
            Some('{') => {
                self.i += 1;
                self.items('}').map(Term::Tuple)
            }
            Some('[') => {
                self.i += 1;
                self.items(']').map(Term::List)
            }
            Some('"') => self.string().map(Term::Str),
            Some(':') => {
                self.i += 1;
                if self.s[self.i..].starts_with('"') {
                    self.string().map(Term::Atom)
                } else {
                    Ok(Term::Atom(self.word()))
                }
            }
            Some(c) if ident_char(c) || c == '-' => {
                let start = self.i;
                if c == '-' {
                    self.i += 1;
                }
                let word = self.word();
                if self.s[self.i..].starts_with(':') && !self.s[self.i..].starts_with("::") {
                    self.i += 1;
                    return Ok(Term::Pair(word, Box::new(self.term()?)));
                }
                Ok(Term::Bare(self.s[start..self.i].to_string()))
            }
            _ => Err(format!("mix.lock: unexpected input at byte {}", self.i)),
        }
    }
}

/// `mix.lock`'s entries: key, value, and the value's byte range.
fn mix_entries(lock: &str) -> Result<Vec<(String, Term, std::ops::Range<usize>)>, String> {
    let mut p = TermParser { s: lock, i: 0 };
    p.eat("%{")?;
    let mut out = Vec::new();
    loop {
        if p.peek() == Some('}') {
            return Ok(out);
        }
        let key = p.string()?;
        p.eat(":")?;
        p.ws();
        let start = p.i;
        let value = p.term()?;
        out.push((key, value, start..p.i));
        match p.peek() {
            Some(',') => p.i += 1,
            Some('}') => {}
            _ => return Err(format!("mix.lock: expected `,` or `}}` at byte {}", p.i)),
        }
    }
}

/// One requirement a Hex release puts on a dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HexDep {
    app: String,
    package: String,
    requirement: Option<String>,
    repository: String,
    optional: bool,
}

/// A `:hex` lock entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HexEntry {
    name: String,
    version: String,
    build_tools: Vec<String>,
    deps: Vec<HexDep>,
    repository: String,
}

fn hex_entry(term: &Term) -> Option<HexEntry> {
    let Term::Tuple(items) = term else {
        return None;
    };
    match items.as_slice() {
        [Term::Atom(tag), Term::Atom(name), Term::Str(version), Term::Str(_), Term::List(tools), Term::List(deps), Term::Str(repository), Term::Str(_)]
            if tag == "hex" =>
        {
            let build_tools = tools
                .iter()
                .map(|t| match t {
                    Term::Atom(a) => Some(a.clone()),
                    _ => None,
                })
                .collect::<Option<_>>()?;
            let deps = deps.iter().map(hex_lock_dep).collect::<Option<_>>()?;
            Some(HexEntry {
                name: name.clone(),
                version: version.clone(),
                build_tools,
                deps,
                repository: repository.clone(),
            })
        }
        _ => None,
    }
}

fn hex_lock_dep(term: &Term) -> Option<HexDep> {
    let Term::Tuple(items) = term else {
        return None;
    };
    let [Term::Atom(app), requirement, Term::List(opts)] = items.as_slice() else {
        return None;
    };
    let requirement = match requirement {
        Term::Str(r) => Some(r.clone()),
        Term::Bare(n) if n == "nil" => None,
        _ => return None,
    };
    let mut dep = HexDep {
        app: app.clone(),
        package: app.clone(),
        requirement,
        repository: "hexpm".to_string(),
        optional: false,
    };
    for opt in opts {
        match opt {
            Term::Pair(k, v) => match (k.as_str(), v.as_ref()) {
                ("hex", Term::Atom(p)) => dep.package.clone_from(p),
                ("repo", Term::Str(r)) => dep.repository.clone_from(r),
                ("optional", Term::Bare(b)) => dep.optional = b == "true",
                _ => {}
            },
            _ => return None,
        }
    }
    Some(dep)
}

fn atom(name: &str) -> String {
    if !name.is_empty()
        && name.chars().all(ident_char)
        && !name.starts_with(|c: char| c.is_ascii_digit())
    {
        format!(":{name}")
    } else {
        format!(":{}", quoted(name))
    }
}

fn quoted(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The lock tuple mix writes, deps sorted by app.
fn render_hex(entry: &HexEntry, inner: &str, outer: &str) -> String {
    let tools: Vec<String> = entry.build_tools.iter().map(|t| atom(t)).collect();
    let deps: Vec<String> = entry
        .deps
        .iter()
        .map(|d| {
            format!(
                "{{{}, {}, [hex: {}, repo: {}, optional: {}]}}",
                atom(&d.app),
                d.requirement
                    .as_deref()
                    .map_or_else(|| "nil".to_string(), quoted),
                atom(&d.package),
                quoted(&d.repository),
                d.optional
            )
        })
        .collect();
    format!(
        "{{:hex, {}, {}, {}, [{}], [{}], {}, {}}}",
        atom(&entry.name),
        quoted(&entry.version),
        quoted(inner),
        tools.join(", "),
        deps.join(", "),
        quoted(&entry.repository),
        quoted(outer)
    )
}

/// Whether an Elixir requirement (`~> 1.2 and >= 1.2.3 or == 2.0.0`) takes `v`.
fn elixir_allows(requirement: &str, v: &Version) -> Result<bool, String> {
    let bad = || format!("cannot read the requirement \"{requirement}\"");
    let mut any = false;
    for alternative in requirement.split(" or ") {
        let mut all = true;
        for clause in alternative.split(" and ") {
            let clause = clause.trim();
            let (op, rest) = ["~>", ">=", "<=", "==", "!=", ">", "<"]
                .iter()
                .find_map(|op| clause.strip_prefix(op).map(|r| (*op, r.trim())))
                .unwrap_or(("==", clause));
            let parts = components(rest.split('-').next().unwrap_or(rest)).ok_or_else(bad)?;
            let bound = padded(rest).ok_or_else(bad)?;
            let ok = match op {
                "~>" => {
                    let upper = match parts.len() {
                        2 => Version::new(bound.major + 1, 0, 0),
                        3 => Version::new(bound.major, bound.minor + 1, 0),
                        _ => return Err(bad()),
                    };
                    *v >= bound && *v < upper
                }
                ">=" => *v >= bound,
                "<=" => *v <= bound,
                ">" => *v > bound,
                "<" => *v < bound,
                "!=" => *v != bound,
                _ => *v == bound,
            };
            all &= ok;
        }
        any |= all;
    }
    Ok(any)
}

/// A protobuf field: a varint or a length-delimited body.
enum Pb<'a> {
    Int(u64),
    Bytes(&'a [u8]),
}

fn varint(b: &[u8], i: &mut usize) -> Result<u64, String> {
    let mut out = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *b.get(*i).ok_or("registry: truncated varint")?;
        *i += 1;
        out |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(out);
        }
    }
    Err("registry: varint too long".to_string())
}

fn pb_fields(b: &[u8]) -> Result<Vec<(u64, Pb<'_>)>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let key = varint(b, &mut i)?;
        let field = key >> 3;
        match key & 7 {
            0 => out.push((field, Pb::Int(varint(b, &mut i)?))),
            1 => i += 8,
            2 => {
                let len = usize::try_from(varint(b, &mut i)?).map_err(|e| e.to_string())?;
                let body = b
                    .get(i..i.checked_add(len).ok_or("registry: bad length")?)
                    .ok_or("registry: truncated field")?;
                i += len;
                out.push((field, Pb::Bytes(body)));
            }
            5 => i += 4,
            other => return Err(format!("registry: wire type {other}")),
        }
    }
    if i > b.len() {
        return Err("registry: truncated field".to_string());
    }
    Ok(out)
}

fn pb_string(bytes: &[u8]) -> Result<String, String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| "registry: a string is not UTF-8".to_string())
}

/// One release from Hex's registry: checksums and requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HexRelease {
    version: String,
    inner: Vec<u8>,
    outer: Vec<u8>,
    deps: Vec<HexDep>,
}

/// The releases in `repo.hex.pm/packages/<name>`: gzip of a signed `Package` message. The
/// signature is not checked here; mix checks both checksums against what it downloads.
fn hex_releases(gz: &[u8], name: &str) -> Result<Vec<HexRelease>, String> {
    let mut body = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .take(MAX_REGISTRY)
        .read_to_end(&mut body)
        .map_err(|e| format!("registry for {name}: {e}"))?;
    let payload = pb_fields(&body)?
        .into_iter()
        .find_map(|(f, v)| match (f, v) {
            (1, Pb::Bytes(b)) => Some(b),
            _ => None,
        })
        .ok_or("registry: no payload")?;
    let mut releases = Vec::new();
    let mut package_name = None;
    for (field, value) in pb_fields(payload)? {
        match (field, value) {
            (1, Pb::Bytes(release)) => releases.push(hex_release(release)?),
            (2, Pb::Bytes(n)) => package_name = Some(pb_string(n)?),
            _ => {}
        }
    }
    if package_name.as_deref() != Some(name) {
        return Err(format!(
            "the registry answered for {package_name:?}, not {name}"
        ));
    }
    Ok(releases)
}

fn hex_release(b: &[u8]) -> Result<HexRelease, String> {
    let mut release = HexRelease {
        version: String::new(),
        inner: Vec::new(),
        outer: Vec::new(),
        deps: Vec::new(),
    };
    for (field, value) in pb_fields(b)? {
        match (field, value) {
            (1, Pb::Bytes(v)) => release.version = pb_string(v)?,
            (2, Pb::Bytes(v)) => release.inner = v.to_vec(),
            (5, Pb::Bytes(v)) => release.outer = v.to_vec(),
            (3, Pb::Bytes(d)) => {
                let mut dep = HexDep {
                    app: String::new(),
                    package: String::new(),
                    requirement: None,
                    repository: "hexpm".to_string(),
                    optional: false,
                };
                for (field, value) in pb_fields(d)? {
                    match (field, value) {
                        (1, Pb::Bytes(v)) => dep.package = pb_string(v)?,
                        (2, Pb::Bytes(v)) => dep.requirement = Some(pb_string(v)?),
                        (3, Pb::Int(v)) => dep.optional = v != 0,
                        (4, Pb::Bytes(v)) => dep.app = pb_string(v)?,
                        (5, Pb::Bytes(v)) => dep.repository = pb_string(v)?,
                        _ => {}
                    }
                }
                if dep.app.is_empty() {
                    dep.app.clone_from(&dep.package);
                }
                release.deps.push(dep);
            }
            _ => {}
        }
    }
    Ok(release)
}

/// Every literal requirement `mix.exs` files under `dir` put on `app`. `None` when one names
/// the app without a string requirement (git, path, a module attribute).
fn mix_exs_reqs(dir: &Path, app: &str) -> Result<Vec<String>, String> {
    let mut reqs = Vec::new();
    let files = walkdir::WalkDir::new(dir)
        .max_depth(4)
        .into_iter()
        .filter_entry(|e| {
            !(e.file_type().is_dir()
                && matches!(
                    e.file_name().to_str(),
                    Some("deps" | "_build" | ".git" | "node_modules")
                ))
        })
        .flatten()
        .filter(|e| e.file_type().is_file() && e.file_name() == "mix.exs");
    let needle = format!("{{:{app}");
    for file in files {
        let src = fleetreach_core::repofile::read_to_string(file.path())
            .map_err(|e| format!("{}: {e}", file.path().display()))?;
        for (at, _) in src.match_indices(&needle) {
            let rest = &src[at + needle.len()..];
            if rest.starts_with(ident_char) {
                continue;
            }
            let rest = rest.trim_start();
            let Some(rest) = rest.strip_prefix(',') else {
                continue;
            };
            let rest = rest.trim_start();
            match next_string(rest, 0) {
                Some((req, _)) if rest.starts_with('"') => reqs.push(req),
                _ => {
                    return Err(format!(
                        "{} names {app} without a version requirement fleetreach reads",
                        file.path()
                            .strip_prefix(dir)
                            .unwrap_or(file.path())
                            .display()
                    ))
                }
            }
        }
    }
    Ok(reqs)
}

/// The checks that keep a `mix.lock` consistent after `entry` moves to `release`.
fn hex_consistent(
    entries: &BTreeMap<String, HexEntry>,
    entry: &HexEntry,
    release: &HexRelease,
    root_reqs: &[String],
    to: &Version,
) -> Result<(), String> {
    let old: BTreeSet<&str> = entry.deps.iter().map(|d| d.app.as_str()).collect();
    let new: BTreeSet<&str> = release.deps.iter().map(|d| d.app.as_str()).collect();
    if old != new {
        return Err(format!(
            "{} {to} changes its dependencies; run `mix deps.update {}`",
            entry.name, entry.name
        ));
    }
    for dep in &release.deps {
        let (Some(req), Some(locked)) = (&dep.requirement, entries.get(&dep.app)) else {
            continue;
        };
        let version = padded(&locked.version)
            .ok_or_else(|| format!("{} {} is not a version", dep.app, locked.version))?;
        if !elixir_allows(req, &version)? {
            return Err(format!(
                "{} {to} requires {} {req}, and the lock has {}",
                entry.name, dep.app, locked.version
            ));
        }
    }
    let mut constraints: Vec<(String, String)> = root_reqs
        .iter()
        .map(|r| ("mix.exs".to_string(), r.clone()))
        .collect();
    for other in entries.values() {
        for dep in &other.deps {
            if dep.package == entry.name {
                if let Some(req) = &dep.requirement {
                    constraints.push((format!("{} {}", other.name, other.version), req.clone()));
                }
            }
        }
    }
    if constraints.is_empty() {
        return Err(format!(
            "no mix.exs or locked package states a requirement on {}",
            entry.name
        ));
    }
    for (who, req) in constraints {
        if !elixir_allows(&req, to)? {
            return Err(format!(
                "{who} requires {} {req}, which leaves out {to}",
                entry.name
            ));
        }
    }
    Ok(())
}

/// Move a Hex package's `mix.lock` entry to `to`, with checksums and requirements from
/// `repo.hex.pm`.
pub(crate) fn hex_bump(
    work: &Path,
    edit: &Edit,
    fetch: Option<&dyn Fetch>,
) -> Result<String, String> {
    let to = release(&edit.to)?;
    let mut moved = 0usize;
    let mut registry: Option<Vec<HexRelease>> = None;
    for dir in dirs_with(work, "mix.lock") {
        let path = dir.join("mix.lock");
        let lock = fleetreach_core::repofile::read_to_string(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if !lock.contains(&format!("{{:hex, :{},", edit.package)) {
            continue;
        }
        let parsed = mix_entries(&lock)?;
        let entries: BTreeMap<String, HexEntry> = parsed
            .iter()
            .filter_map(|(key, term, _)| hex_entry(term).map(|e| (key.clone(), e)))
            .collect();
        let Some((key, entry, span)) = parsed.iter().find_map(|(key, term, span)| {
            hex_entry(term)
                .filter(|e| e.name == edit.package && edit.from.contains(&e.version))
                .map(|e| (key.clone(), e, span.clone()))
        }) else {
            continue;
        };
        if entry.repository != "hexpm" {
            return Err(format!(
                "{} comes from the {} repository, not hexpm",
                edit.package, entry.repository
            ));
        }
        if registry.is_none() {
            let fetch = fetch.ok_or(
                "updating mix.lock reads checksums from repo.hex.pm, and this build has no \
                 network feature",
            )?;
            let url = format!("{HEX_REPO}/packages/{}", edit.package);
            let body = fetch
                .get(&url)?
                .ok_or_else(|| format!("{} is not on repo.hex.pm", edit.package))?;
            registry = Some(hex_releases(&body, &edit.package)?);
        }
        let release = registry
            .as_ref()
            .and_then(|r| r.iter().find(|r| r.version == to.to_string()))
            .ok_or_else(|| format!("repo.hex.pm has no {} {to}", edit.package))?;
        if release.inner.len() != 32 || release.outer.len() != 32 {
            return Err(format!(
                "repo.hex.pm has no checksums for {} {to}",
                edit.package
            ));
        }
        let root_reqs = mix_exs_reqs(&dir, &key)?;
        hex_consistent(&entries, &entry, release, &root_reqs, &to)?;
        let mut deps = release.deps.clone();
        deps.sort_by(|a, b| a.app.cmp(&b.app));
        let moved_entry = HexEntry {
            version: to.to_string(),
            deps,
            ..entry
        };
        let rendered = render_hex(
            &moved_entry,
            &hex_string(&release.inner),
            &hex_string(&release.outer),
        );
        let new = format!("{}{rendered}{}", &lock[..span.start], &lock[span.end..]);
        let back = mix_entries(&new)?;
        if !back
            .iter()
            .any(|(k, t, _)| *k == key && hex_entry(t).is_some_and(|e| e == moved_entry))
        {
            return Err("the rewritten mix.lock does not read back".to_string());
        }
        std::fs::write(&path, new).map_err(|e| format!("{}: {e}", path.display()))?;
        moved += 1;
    }
    if moved == 0 {
        return Err(format!(
            "no mix.lock holds {} at a vulnerable version",
            edit.package
        ));
    }
    Ok(format!(
        "{moved} mix.lock entr{} moved to {to} (checksums from repo.hex.pm)",
        if moved == 1 { "y" } else { "ies" }
    ))
}

// ---- Julia ----

/// A registry range, `1.2-1.5`, `0.4.1-0`, `1` or `*`: bounds compare by their components only.
fn registry_range_has(range: &str, v: [u64; 3]) -> Result<bool, String> {
    let range = range.trim();
    if range == "*" {
        return Ok(true);
    }
    let (lo, hi) = range.split_once('-').unwrap_or((range, range));
    let bad = || format!("cannot read the registry range \"{range}\"");
    let lo = components(lo).ok_or_else(bad)?;
    let hi = components(hi).ok_or_else(bad)?;
    let mut low = [0u64; 3];
    low[..lo.len()].copy_from_slice(&lo);
    Ok(v >= low && v[..hi.len()] <= hi[..])
}

/// A `Compat.toml` value: one range or a list of them.
fn registry_spec_has(spec: &toml::Value, v: [u64; 3]) -> Result<bool, String> {
    match spec {
        toml::Value::String(s) => registry_range_has(s, v),
        toml::Value::Array(items) => {
            for item in items {
                if registry_spec_has(item, v)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => Err("a Compat.toml value is neither a range nor a list".to_string()),
    }
}

/// The merged entries of a `Deps.toml` or `Compat.toml` whose range holds `v`.
fn registry_for(file: &toml::Table, v: [u64; 3]) -> Result<toml::Table, String> {
    let mut out = toml::Table::new();
    for (range, entries) in file {
        if registry_range_has(range, v)? {
            if let Some(entries) = entries.as_table() {
                out.extend(entries.iter().map(|(k, v)| (k.clone(), v.clone())));
            }
        }
    }
    Ok(out)
}

/// Whether a `Project.toml` `[compat]` spec takes `v` (caret by default, `~`, `=`, `>=`,
/// `<`, hyphen ranges, comma unions).
fn julia_compat_allows(spec: &str, v: [u64; 3]) -> Result<bool, String> {
    let bad = || format!("cannot read the compat \"{spec}\"");
    for part in spec.split(',') {
        let part = part.trim();
        let bound = |s: &str| components(s).filter(|c| !c.is_empty()).ok_or_else(bad);
        let pad = |c: &[u64]| {
            let mut out = [0u64; 3];
            out[..c.len()].copy_from_slice(c);
            out
        };
        let ok = if let Some((lo, hi)) = part.split_once(" - ") {
            let (lo, hi) = (bound(lo)?, bound(hi)?);
            v >= pad(&lo) && v[..hi.len()] <= hi[..]
        } else if let Some(rest) = part.strip_prefix(">=").or_else(|| part.strip_prefix('≥')) {
            v >= pad(&bound(rest)?)
        } else if let Some(rest) = part.strip_prefix('<') {
            v < pad(&bound(rest)?)
        } else if let Some(rest) = part.strip_prefix('=') {
            let b = bound(rest)?;
            v[..b.len()] == b[..]
        } else if let Some(rest) = part.strip_prefix('~') {
            let b = bound(rest)?;
            let upper = match b.len() {
                1 => [b[0] + 1, 0, 0],
                _ => [b[0], b[1] + 1, 0],
            };
            v >= pad(&b) && v < upper
        } else {
            let b = bound(part.strip_prefix('^').unwrap_or(part))?;
            let upper = if b[0] > 0 || b.len() == 1 {
                [b[0] + 1, 0, 0]
            } else if b[1] > 0 || b.len() == 2 {
                [0, b[1] + 1, 0]
            } else {
                [0, 0, b[2] + 1]
            };
            v >= pad(&b) && v < upper
        };
        if ok {
            return Ok(true);
        }
    }
    Ok(false)
}

/// One `Manifest.toml` entry.
#[derive(Debug, Clone)]
struct JlEntry {
    name: String,
    uuid: String,
    version: Option<String>,
    deps: BTreeSet<String>,
    weakdeps: BTreeSet<String>,
    /// From git, a path, or pinned: not the registry's to move.
    elsewhere: bool,
}

fn names_of(item: Option<&toml_edit::Item>) -> BTreeSet<String> {
    match item {
        Some(toml_edit::Item::Value(toml_edit::Value::Array(a))) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Some(item) => item
            .as_table_like()
            .map(|t| t.iter().map(|(k, _)| k.to_string()).collect())
            .unwrap_or_default(),
        None => BTreeSet::new(),
    }
}

fn jl_entries(table: &toml_edit::Table) -> Vec<JlEntry> {
    let mut out = Vec::new();
    for (name, item) in table {
        let Some(list) = item.as_array_of_tables() else {
            continue;
        };
        for t in list {
            out.push(JlEntry {
                name: name.to_string(),
                uuid: t
                    .get("uuid")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                version: t
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                deps: names_of(t.get("deps")),
                weakdeps: names_of(t.get("weakdeps")),
                elsewhere: ["repo-url", "repo-rev", "path"]
                    .iter()
                    .any(|k| t.contains_key(k))
                    || t.get("pinned").and_then(toml_edit::Item::as_bool) == Some(true),
            });
        }
    }
    out
}

/// The General registry's files for one package, fetched once.
struct General<'a> {
    fetch: &'a dyn Fetch,
    files: BTreeMap<(String, &'static str), Option<toml::Table>>,
}

impl General<'_> {
    fn dir(name: &str) -> String {
        let first: String = name.chars().take(1).flat_map(char::to_uppercase).collect();
        if name.ends_with("_jll") {
            format!("jll/{first}/{name}")
        } else {
            format!("{first}/{name}")
        }
    }

    fn file(&mut self, name: &str, file: &'static str) -> Result<Option<&toml::Table>, String> {
        let key = (name.to_string(), file);
        if !self.files.contains_key(&key) {
            let url = format!("{GENERAL}/{}/{file}", Self::dir(name));
            let parsed = match text(self.fetch, &url)? {
                Some(t) => Some(toml::from_str(&t).map_err(|e| format!("{url}: {e}"))?),
                None => None,
            };
            self.files.insert(key.clone(), parsed);
        }
        Ok(self.files.get(&key).and_then(Option::as_ref))
    }

    /// Fails unless General's `name` is the package with this uuid.
    fn check_uuid(&mut self, name: &str, uuid: &str) -> Result<(), String> {
        let found = self
            .file(name, "Package.toml")?
            .ok_or_else(|| format!("{name} is not in the General registry"))?
            .get("uuid")
            .and_then(toml::Value::as_str)
            .map(str::to_string);
        if found.as_deref() == Some(uuid) {
            Ok(())
        } else {
            Err(format!(
                "the General registry's {name} is another package than the manifest's ({uuid})"
            ))
        }
    }

    fn table_for(
        &mut self,
        name: &str,
        file: &'static str,
        v: [u64; 3],
    ) -> Result<toml::Table, String> {
        match self.file(name, file)? {
            Some(t) => registry_for(t, v),
            None => Ok(toml::Table::new()),
        }
    }
}

/// The checks that keep a `Manifest.toml` consistent after `entry` moves to `to`.
fn julia_consistent(
    general: &mut General<'_>,
    entries: &[JlEntry],
    entry: &JlEntry,
    to: [u64; 3],
    project: Option<&toml::Table>,
    julia_version: Option<[u64; 3]>,
) -> Result<(), String> {
    let shown = |v: [u64; 3]| format!("{}.{}.{}", v[0], v[1], v[2]);
    let deps: BTreeSet<String> = general
        .table_for(&entry.name, "Deps.toml", to)?
        .keys()
        .cloned()
        .collect();
    let weak: BTreeSet<String> = general
        .table_for(&entry.name, "WeakDeps.toml", to)?
        .keys()
        .cloned()
        .collect();
    if deps != entry.deps || weak != entry.weakdeps {
        return Err(format!(
            "{} {} changes its dependencies; run `Pkg.update(\"{}\")`",
            entry.name,
            shown(to),
            entry.name
        ));
    }
    let locked = |name: &str| -> Option<[u64; 3]> {
        entries
            .iter()
            .find(|e| e.name == name)
            .and_then(|e| e.version.as_deref())
            .and_then(padded)
            .map(|v| triple(&v))
    };
    for (dep, spec) in &general.table_for(&entry.name, "Compat.toml", to)? {
        let have = if dep == "julia" {
            julia_version
        } else {
            locked(dep)
        };
        let Some(have) = have else {
            continue;
        };
        if !registry_spec_has(spec, have)? {
            return Err(format!(
                "{} {} needs {dep} {spec}, and the manifest has {}",
                entry.name,
                shown(to),
                shown(have)
            ));
        }
    }
    let mut stated = false;
    if let Some(project) = project {
        let direct = project
            .get("deps")
            .and_then(toml::Value::as_table)
            .is_some_and(|d| d.contains_key(&entry.name));
        stated |= direct;
        if let Some(spec) = project
            .get("compat")
            .and_then(toml::Value::as_table)
            .and_then(|c| c.get(&entry.name))
            .and_then(toml::Value::as_str)
        {
            if !julia_compat_allows(spec, to)? {
                return Err(format!(
                    "Project.toml's compat for {} is \"{spec}\", which leaves out {}",
                    entry.name,
                    shown(to)
                ));
            }
        }
    }
    for dependent in entries
        .iter()
        .filter(|e| e.deps.contains(&entry.name) || e.weakdeps.contains(&entry.name))
    {
        stated = true;
        let Some(version) = dependent.version.as_deref() else {
            continue;
        };
        if dependent.elsewhere {
            return Err(format!(
                "{} depends on {} and is not from the registry, so its compat is unknown",
                dependent.name, entry.name
            ));
        }
        let at = padded(version)
            .map(|v| triple(&v))
            .ok_or_else(|| format!("{} {version} is not a version", dependent.name))?;
        general.check_uuid(&dependent.name, &dependent.uuid)?;
        if let Some(spec) = general
            .table_for(&dependent.name, "Compat.toml", at)?
            .get(&entry.name)
        {
            if !registry_spec_has(spec, to)? {
                return Err(format!(
                    "{} {version} needs {} {spec}, which leaves out {}",
                    dependent.name,
                    entry.name,
                    shown(to)
                ));
            }
        }
    }
    if stated {
        Ok(())
    } else {
        Err(format!(
            "nothing in the manifest or Project.toml depends on {}",
            entry.name
        ))
    }
}

/// Move a Julia package's `Manifest.toml` entry to `to`, with the tree hash from the General
/// registry.
pub(crate) fn julia_bump(
    work: &Path,
    edit: &Edit,
    fetch: Option<&dyn Fetch>,
) -> Result<String, String> {
    let to = release(&edit.to)?;
    let mut moved = 0usize;
    let mut general: Option<General<'_>> = None;
    for dir in dirs_with(work, "Manifest.toml") {
        let path = dir.join("Manifest.toml");
        let text_now = fleetreach_core::repofile::read_to_string(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let mut doc: toml_edit::DocumentMut = text_now
            .parse()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let v2 = doc.contains_key("manifest_format");
        let julia_version = doc
            .get("julia_version")
            .and_then(|v| v.as_str())
            .and_then(padded)
            .map(|v| triple(&v));
        let table = if v2 {
            doc.get("deps").and_then(toml_edit::Item::as_table)
        } else {
            Some(doc.as_table())
        };
        let entries = table.map(jl_entries).unwrap_or_default();
        let hits: Vec<&JlEntry> = entries
            .iter()
            .filter(|e| {
                e.name == edit.package
                    && e.version
                        .as_deref()
                        .is_some_and(|v| edit.from.iter().any(|f| f == v))
            })
            .collect();
        let entry = match hits.as_slice() {
            [] => continue,
            [one] => (*one).clone(),
            _ => return Err(format!("the manifest has {} more than once", edit.package)),
        };
        if entry.elsewhere {
            return Err(format!(
                "{} is pinned, or tracks a git repository or a path",
                edit.package
            ));
        }
        if general.is_none() {
            let fetch = fetch.ok_or(
                "updating Manifest.toml reads the General registry, and this build has no \
                 network feature",
            )?;
            general = Some(General {
                fetch,
                files: BTreeMap::new(),
            });
        }
        let Some(registry) = general.as_mut() else {
            continue;
        };
        registry.check_uuid(&entry.name, &entry.uuid)?;
        let release = registry
            .file(&entry.name, "Versions.toml")?
            .and_then(|v| v.get(&to.to_string()))
            .and_then(toml::Value::as_table)
            .cloned()
            .ok_or_else(|| format!("the General registry has no {} {to}", entry.name))?;
        if release.get("yanked").and_then(toml::Value::as_bool) == Some(true) {
            return Err(format!("{} {to} is yanked", entry.name));
        }
        let tree = release
            .get("git-tree-sha1")
            .and_then(toml::Value::as_str)
            .filter(|t| t.len() == 40 && t.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| format!("no tree hash for {} {to}", entry.name))?
            .to_string();
        let project = ["Project.toml", "JuliaProject.toml"]
            .iter()
            .find_map(|f| fleetreach_core::repofile::read_to_string(dir.join(f)).ok())
            .map(|t| toml::from_str::<toml::Table>(&t).map_err(|e| format!("Project.toml: {e}")))
            .transpose()?;
        julia_consistent(
            registry,
            &entries,
            &entry,
            triple(&to),
            project.as_ref(),
            julia_version,
        )?;
        let table = if v2 {
            doc.get_mut("deps").and_then(toml_edit::Item::as_table_mut)
        } else {
            Some(doc.as_table_mut())
        };
        let target = table
            .and_then(|t| t.get_mut(&edit.package))
            .and_then(toml_edit::Item::as_array_of_tables_mut)
            .and_then(|list| {
                list.iter_mut()
                    .find(|t| t.get("version").and_then(|v| v.as_str()) == entry.version.as_deref())
            })
            .ok_or("cannot find the manifest entry to edit")?;
        for (key, value) in [("version", to.to_string()), ("git-tree-sha1", tree.clone())] {
            let mut new = toml_edit::Value::from(value);
            if let Some(old) = target.get(key).and_then(toml_edit::Item::as_value) {
                *new.decor_mut() = old.decor().clone();
            }
            target.insert(key, toml_edit::Item::Value(new));
        }
        std::fs::write(&path, doc.to_string()).map_err(|e| format!("{}: {e}", path.display()))?;
        moved += 1;
    }
    if moved == 0 {
        return Err(format!(
            "no Manifest.toml holds {} at a vulnerable version",
            edit.package
        ));
    }
    Ok(format!(
        "{moved} Manifest.toml entr{} moved to {to} (tree hash from the General registry)",
        if moved == 1 { "y" } else { "ies" }
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::fix::Strategy;
    use fleetreach_core::Ecosystem;
    use std::sync::Mutex;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn edit(ecosystem: Ecosystem, package: &str, from: &str, to: &str) -> Edit {
        Edit {
            campaign: "c".into(),
            repo: "r".into(),
            ecosystem,
            package: package.into(),
            from: vec![from.into()],
            to: to.into(),
            advisories: vec!["GHSA-x".into()],
            breaking: false,
            strategy: Strategy::LockBump,
            reason: None,
            risk: None,
            risk_reasons: Vec::new(),
            ssvc: None,
        }
    }

    #[derive(Default)]
    struct Fake {
        bodies: BTreeMap<String, Vec<u8>>,
        asked: Mutex<Vec<String>>,
    }

    impl Fake {
        fn with(mut self, url: &str, body: impl Into<Vec<u8>>) -> Self {
            self.bodies.insert(url.to_string(), body.into());
            self
        }
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

    // ---- Swift ----

    #[test]
    fn swift_requirements_are_read_as_spm_means_them() {
        let manifest = r#"
// .package(url: "https://github.com/old/commented.git", from: "9.0.0"),
let package = Package(
  dependencies: [
    .package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.4.0"),
    .package(url: "https://github.com/a/minor", .upToNextMinor(from: "1.2.0")),
    .package(url: "https://github.com/a/exact.git", exact: "2.0.1"),
    .package(url: "https://github.com/a/range.git", "1.0.0"..<"1.5.0"),
    .package(url: "https://github.com/a/branch.git", branch: "main"),
    /* .package(url: "https://github.com/a/range.git", from: "0.1.0"), */
  ]
)"#;
        let reqs = |p: &str| swift_manifest_reqs(manifest, p);
        let major = reqs("github.com/alamofire/alamofire").unwrap();
        assert_eq!(major, vec![SwiftReq::Major(v("5.4.0"))]);
        assert!(major[0].allows(&v("5.9.1")) && !major[0].allows(&v("6.0.0")));
        let minor = &reqs("github.com/a/minor").unwrap()[0];
        assert!(minor.allows(&v("1.2.9")) && !minor.allows(&v("1.3.0")));
        assert_eq!(
            reqs("github.com/a/exact").unwrap(),
            vec![SwiftReq::Exact(v("2.0.1"))]
        );
        let range = reqs("github.com/a/range").unwrap();
        assert_eq!(range.len(), 1, "the commented-out package is not read");
        assert!(range[0].allows(&v("1.4.9")) && !range[0].allows(&v("1.5.0")));
        assert!(reqs("github.com/a/branch")
            .unwrap_err()
            .contains("branch or revision"));
        assert!(reqs("github.com/old/commented").unwrap().is_empty());
        assert!(reqs("github.com/not/there").unwrap().is_empty());
    }

    #[test]
    fn swift_tags_prefer_the_peeled_commit_and_refuse_disagreement() {
        let a = "a".repeat(40);
        let b = "b".repeat(40);
        let listing =
            format!("{a}\trefs/tags/v1.2.3\n{b}\trefs/tags/v1.2.3^{{}}\n{a}\trefs/tags/1.2.2\n");
        assert_eq!(swift_tag_commit(&listing, &v("1.2.3")).unwrap(), b);
        assert!(swift_tag_commit(&listing, &v("1.2.4"))
            .unwrap_err()
            .contains("no tag"));
        let short = format!("{a}\trefs/tags/2.0\n");
        assert_eq!(swift_tag_commit(&short, &v("2.0.0")).unwrap(), a);
        let split = format!("{a}\trefs/tags/3.0.0\n{b}\trefs/tags/v3.0.0\n");
        assert!(swift_tag_commit(&split, &v("3.0.0"))
            .unwrap_err()
            .contains("different commits"));
    }

    const RESOLVED_V2: &str = r#"{
  "pins" : [
    {
      "identity" : "alamofire",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/Alamofire/Alamofire.git",
      "state" : {
        "revision" : "f96b619bcb2383b43d898402283924b80e2c4bae",
        "version" : "5.4.3"
      }
    },
    {
      "identity" : "other",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/a/other.git",
      "state" : {
        "revision" : "0630439888c94657a235ffcd5977d6047ef3c87b",
        "version" : "5.4.3"
      }
    }
  ],
  "version" : 2
}
"#;

    fn swift_repo(resolved: &str, manifest: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Package.resolved"), resolved).unwrap();
        std::fs::write(dir.path().join("Package.swift"), manifest).unwrap();
        dir
    }

    #[test]
    fn a_swift_pin_moves_alone_with_the_tag_commit() {
        let manifest =
            r#".package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.0.0")"#;
        let dir = swift_repo(RESOLVED_V2, manifest);
        let new_rev = "c".repeat(40);
        let lookup = |loc: &str, to: &Version| {
            assert_eq!(loc, "https://github.com/Alamofire/Alamofire.git");
            assert_eq!(to.to_string(), "5.4.4");
            Ok(new_rev.clone())
        };
        let e = edit(
            Ecosystem::Swift,
            "github.com/alamofire/alamofire",
            "5.4.3",
            "5.4.4",
        );
        let note = swift_bump_with(dir.path(), &e, &lookup).unwrap();
        assert!(note.contains("1 Package.resolved"), "{note}");
        let after = std::fs::read_to_string(dir.path().join("Package.resolved")).unwrap();
        let expected = RESOLVED_V2
            .replacen("f96b619bcb2383b43d898402283924b80e2c4bae", &new_rev, 1)
            .replacen("\"version\" : \"5.4.3\"", "\"version\" : \"5.4.4\"", 1);
        assert_eq!(after, expected, "only the one pin changes, formatting kept");
        assert!(after.contains(
            "0630439888c94657a235ffcd5977d6047ef3c87b\",\n        \"version\" : \"5.4.3\""
        ));
    }

    #[test]
    fn a_swift_pin_outside_the_manifest_range_or_transitive_is_refused() {
        let lookup = |_: &str, _: &Version| -> Result<String, String> { panic!("not asked") };
        let e = edit(
            Ecosystem::Swift,
            "github.com/alamofire/alamofire",
            "5.4.3",
            "6.0.0",
        );
        let manifest = r#".package(url: "https://github.com/Alamofire/Alamofire", from: "5.0.0")"#;
        let dir = swift_repo(RESOLVED_V2, manifest);
        let err = swift_bump_with(dir.path(), &e, &lookup).unwrap_err();
        assert!(err.contains("leaves out 6.0.0"), "{err}");
        let dir = swift_repo(RESOLVED_V2, "let package = Package()");
        let e = edit(
            Ecosystem::Swift,
            "github.com/alamofire/alamofire",
            "5.4.3",
            "5.4.4",
        );
        let err = swift_bump_with(dir.path(), &e, &lookup).unwrap_err();
        assert!(err.contains("another package"), "{err}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("Package.resolved")).unwrap(),
            RESOLVED_V2
        );
    }

    #[test]
    fn a_v1_resolved_file_moves_too() {
        let v1 = r#"{
  "object": {
    "pins": [
      {
        "package": "Alamofire",
        "repositoryURL": "https:\/\/github.com\/Alamofire\/Alamofire.git",
        "state": {
          "branch": null,
          "revision": "f96b619bcb2383b43d898402283924b80e2c4bae",
          "version": "5.4.3"
        }
      }
    ]
  },
  "version": 1
}"#;
        let manifest = r#".package(url: "https://github.com/Alamofire/Alamofire.git", .upToNextMajor(from: "5.4.0"))"#;
        let dir = swift_repo(v1, manifest);
        let lookup = |_: &str, _: &Version| Ok("d".repeat(40));
        let e = edit(
            Ecosystem::Swift,
            "github.com/alamofire/alamofire",
            "5.4.3",
            "5.6.0",
        );
        swift_bump_with(dir.path(), &e, &lookup).unwrap();
        let after = std::fs::read_to_string(dir.path().join("Package.resolved")).unwrap();
        assert!(after.contains(&format!(
            "\"revision\": \"{}\",\n          \"version\": \"5.6.0\"",
            "d".repeat(40)
        )));
        assert!(after.contains("https:\\/\\/github.com"), "escapes kept");
    }

    #[test]
    fn git_is_never_given_an_option_or_a_command_transport() {
        assert!(!plain_location("--upload-pack=touch x"));
        assert!(!plain_location("ext::sh -c touch% x"));
        assert!(plain_location("https://github.com/a/b.git"));
        assert!(plain_location("git@github.com:a/b.git"));
    }

    #[test]
    fn swift_tags_come_from_a_real_git_repository() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("pkg");
        let git = |args: &[&str]| {
            let ok = Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args([
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@t",
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "tag.gpgsign=false",
                ])
                .args(args)
                .output()
                .unwrap();
            assert!(
                ok.status.success(),
                "{}",
                String::from_utf8_lossy(&ok.stderr)
            );
            String::from_utf8_lossy(&ok.stdout).trim().to_string()
        };
        std::fs::create_dir(&repo).unwrap();
        git(&["init", "-q"]);
        git(&["commit", "-q", "--allow-empty", "-m", "one"]);
        git(&["tag", "-a", "v1.0.1", "-m", "annotated"]);
        let head = git(&["rev-parse", "HEAD"]);
        let found = tag_revision(repo.to_str().unwrap(), &v("1.0.1")).unwrap();
        assert_eq!(found, head, "the annotated tag resolves to its commit");
    }

    // ---- Hex ----

    #[test]
    fn elixir_requirements_follow_version_match() {
        let ok = |r: &str, s: &str| elixir_allows(r, &v(s)).unwrap();
        assert!(ok("~> 1.2", "1.9.0") && !ok("~> 1.2", "2.0.0") && !ok("~> 1.2", "1.1.9"));
        assert!(ok("~> 1.2.3", "1.2.9") && !ok("~> 1.2.3", "1.3.0"));
        assert!(ok("~> 1.0 or ~> 2.0", "2.4.1"));
        assert!(ok(">= 1.0.0 and < 1.5.0", "1.4.0") && !ok(">= 1.0.0 and < 1.5.0", "1.5.0"));
        assert!(ok("1.2.3", "1.2.3") && !ok("== 1.2.3", "1.2.4"));
        assert!(elixir_allows("~> banana", &v("1.0.0")).is_err());
    }

    const LOCK: &str = r#"%{
  "mime": {:hex, :mime, "2.0.5", "dc34c8efd439abe6ae0343edbb8556f4d63f178594894720607772a041b04b02", [:mix], [], "hexpm", "da0d64a365c45bc9935cc5c8a7fc5e49a0e0f9932a761c55d6c52b142780a05c"},
  "plug": {:hex, :plug, "1.14.0", "ba4f558468f69cbd9f6b356d25443d0b796fbdc887e03fa89001384a9cac638f", [:mix], [{:mime, "~> 1.0 or ~> 2.0", [hex: :mime, repo: "hexpm", optional: false]}, {:telemetry, "~> 0.4.3 or ~> 1.0", [hex: :telemetry, repo: "hexpm", optional: false]}], "hexpm", "bf020432c7d4feb7b3af16a0c2701455cbbbb95e5b6866132cb09eb0c29adc14"},
  "phoenix": {:hex, :phoenix, "1.7.0", "aaaa", [:mix], [{:plug, "~> 1.14", [hex: :plug, repo: "hexpm", optional: false]}], "hexpm", "bbbb"},
  "private": {:git, "https://github.com/a/b.git", "1234", []},
  "telemetry": {:hex, :telemetry, "1.2.1", "68fdfe8d8f05a8428483a97d7aab2f268aaff24b49e0f599faa091f1d4e7f61c", [:rebar3], [], "hexpm", "dad9ce9d8effc621708f99eac538ef1cbe05d6a874dd741de2e689c47feafed5"},
}
"#;

    fn pb_key(field: u64, wire: u64) -> Vec<u8> {
        pb_varint((field << 3) | wire)
    }

    fn pb_varint(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn pb_bytes(field: u64, body: &[u8]) -> Vec<u8> {
        let mut out = pb_key(field, 2);
        out.extend(pb_varint(body.len() as u64));
        out.extend(body);
        out
    }

    fn pb_release(version: &str, inner: u8, outer: u8, deps: &[(&str, &str, bool)]) -> Vec<u8> {
        let mut r = pb_bytes(1, version.as_bytes());
        r.extend(pb_bytes(2, &[inner; 32]));
        for (pkg, req, optional) in deps {
            let mut d = pb_bytes(1, pkg.as_bytes());
            d.extend(pb_bytes(2, req.as_bytes()));
            if *optional {
                d.extend(pb_key(3, 0));
                d.push(1);
            }
            r.extend(pb_bytes(3, &d));
        }
        r.extend(pb_bytes(5, &[outer; 32]));
        r
    }

    fn registry(name: &str, releases: &[Vec<u8>]) -> Vec<u8> {
        let mut package = Vec::new();
        for r in releases {
            package.extend(pb_bytes(1, r));
        }
        package.extend(pb_bytes(2, name.as_bytes()));
        package.extend(pb_bytes(3, b"hexpm"));
        let mut signed = pb_bytes(1, &package);
        signed.extend(pb_bytes(2, b"signature"));
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, &signed).unwrap();
        gz.finish().unwrap()
    }

    fn hex_repo(lock: &str, mix_exs: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mix.lock"), lock).unwrap();
        std::fs::write(dir.path().join("mix.exs"), mix_exs).unwrap();
        dir
    }

    const MIX_EXS: &str = r#"defp deps do
    [{:phoenix, "~> 1.7.0"}, {:plug, "~> 1.14"}, {:plug_cowboy, "~> 2.0"}]
  end"#;

    #[test]
    fn a_hex_entry_moves_with_registry_checksums_and_nothing_else_changes() {
        let dir = hex_repo(LOCK, MIX_EXS);
        let body = registry(
            "plug",
            &[
                pb_release(
                    "1.14.0",
                    1,
                    2,
                    &[
                        ("mime", "~> 1.0 or ~> 2.0", false),
                        ("telemetry", "~> 0.4.3 or ~> 1.0", false),
                    ],
                ),
                pb_release(
                    "1.14.2",
                    0xab,
                    0xcd,
                    &[
                        ("telemetry", "~> 0.4.3 or ~> 1.0", false),
                        ("mime", "~> 1.0 or ~> 2.0", false),
                    ],
                ),
            ],
        );
        let fake = Fake::default().with("https://repo.hex.pm/packages/plug", body);
        let e = edit(Ecosystem::Hex, "plug", "1.14.0", "1.14.2");
        let note = hex_bump(dir.path(), &e, Some(&fake)).unwrap();
        assert!(note.contains("1 mix.lock entry"), "{note}");
        let after = std::fs::read_to_string(dir.path().join("mix.lock")).unwrap();
        let line = format!(
            "  \"plug\": {{:hex, :plug, \"1.14.2\", \"{}\", [:mix], [{{:mime, \"~> 1.0 or ~> 2.0\", [hex: :mime, repo: \"hexpm\", optional: false]}}, {{:telemetry, \"~> 0.4.3 or ~> 1.0\", [hex: :telemetry, repo: \"hexpm\", optional: false]}}], \"hexpm\", \"{}\"}},",
            "ab".repeat(32),
            "cd".repeat(32)
        );
        let expected: String = LOCK
            .lines()
            .map(|l| {
                if l.starts_with("  \"plug\"") {
                    line.clone()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        assert_eq!(after, expected);
        let (installed, _) = fleetreach_hex::installed_packages(&after);
        assert!(installed
            .iter()
            .any(|p| p.name == "plug" && p.version == "1.14.2"));
    }

    #[test]
    fn a_hex_move_that_breaks_a_constraint_is_refused() {
        let releases = |deps: &[(&str, &str, bool)]| {
            registry(
                "plug",
                &[
                    pb_release("1.15.0", 1, 2, deps),
                    pb_release("2.0.0", 1, 2, deps),
                ],
            )
        };
        let same = [
            ("mime", "~> 1.0 or ~> 2.0", false),
            ("telemetry", "~> 0.4.3 or ~> 1.0", false),
        ];
        let try_with = |mix_exs: &str, body: Vec<u8>, to: &str| {
            let dir = hex_repo(LOCK, mix_exs);
            let fake = Fake::default().with("https://repo.hex.pm/packages/plug", body);
            let err = hex_bump(
                dir.path(),
                &edit(Ecosystem::Hex, "plug", "1.14.0", to),
                Some(&fake),
            )
            .unwrap_err();
            assert_eq!(
                std::fs::read_to_string(dir.path().join("mix.lock")).unwrap(),
                LOCK
            );
            err
        };
        let err = try_with(MIX_EXS, releases(&same), "2.0.0");
        assert!(
            err.contains("phoenix 1.7.0 requires plug ~> 1.14")
                || err.contains("mix.exs requires plug"),
            "{err}"
        );
        let err = try_with(r#"[{:plug, "~> 1.14.0"}]"#, releases(&same), "1.15.0");
        assert!(err.contains("mix.exs requires plug ~> 1.14.0"), "{err}");
        let err = try_with(MIX_EXS, releases(&[("mime", "~> 2.0", false)]), "1.15.0");
        assert!(err.contains("changes its dependencies"), "{err}");
        let err = try_with(
            MIX_EXS,
            releases(&[("mime", "~> 3.0", false), ("telemetry", "~> 1.0", false)]),
            "1.15.0",
        );
        assert!(
            err.contains("requires mime ~> 3.0, and the lock has 2.0.5"),
            "{err}"
        );
        let err = try_with(
            r#"[{:plug, github: "elixir-plug/plug"}]"#,
            releases(&same),
            "1.15.0",
        );
        assert!(err.contains("without a version requirement"), "{err}");
    }

    #[test]
    fn hex_without_network_says_so() {
        let dir = hex_repo(LOCK, MIX_EXS);
        let err = hex_bump(
            dir.path(),
            &edit(Ecosystem::Hex, "plug", "1.14.0", "1.14.2"),
            None,
        )
        .unwrap_err();
        assert!(err.contains("no network feature"), "{err}");
    }

    #[test]
    fn the_registry_must_answer_for_the_package_asked() {
        let body = registry("plugx", &[pb_release("1.0.0", 1, 2, &[])]);
        assert!(hex_releases(&body, "plug")
            .unwrap_err()
            .contains("not plug"));
        let got = hex_releases(
            &registry(
                "plug",
                &[pb_release("1.0.0", 1, 2, &[("x", "~> 1.0", true)])],
            ),
            "plug",
        )
        .unwrap();
        assert_eq!(got[0].deps[0].app, "x");
        assert!(got[0].deps[0].optional);
    }

    // ---- Julia ----

    #[test]
    fn registry_ranges_compare_by_their_own_components() {
        let has = |r: &str, s: [u64; 3]| registry_range_has(r, s).unwrap();
        assert!(has("1", [1, 9, 9]) && !has("1", [2, 0, 0]));
        assert!(has("0.4.1-0", [0, 9, 0]) && !has("0.4.1-0", [0, 4, 0]));
        assert!(has("1.2-1.5", [1, 5, 7]) && !has("1.2-1.5", [1, 6, 0]));
        assert!(has("*", [7, 0, 0]));
    }

    #[test]
    fn project_compat_follows_pkg() {
        let ok = |s: &str, v: [u64; 3]| julia_compat_allows(s, v).unwrap();
        assert!(ok("1.2", [1, 9, 0]) && !ok("1.2", [2, 0, 0]) && !ok("1.2", [1, 1, 0]));
        assert!(ok("0.2.3", [0, 2, 9]) && !ok("0.2.3", [0, 3, 0]));
        assert!(ok("0.0.3", [0, 0, 3]) && !ok("0.0.3", [0, 0, 4]));
        assert!(ok("~1.2.3", [1, 2, 9]) && !ok("~1.2.3", [1, 3, 0]));
        assert!(ok("=1.2", [1, 2, 7]) && !ok("=1.2", [1, 3, 0]));
        assert!(ok(">= 1.5", [3, 0, 0]) && !ok("< 1.5", [1, 5, 0]));
        assert!(ok("1.2.3 - 1.4", [1, 4, 9]) && !ok("1.2.3 - 1.4", [1, 5, 0]));
        assert!(ok("0.5, 1", [1, 3, 0]) && !ok("0.5, 1", [0, 6, 0]));
        assert!(julia_compat_allows("", [1, 0, 0]).is_err());
    }

    const MANIFEST: &str = r#"# This file is machine-generated - editing it directly is not advised

julia_version = "1.10.4"
manifest_format = "2.0"
project_hash = "0123"

[[deps.Base64]]
uuid = "2a0f44e3-6c83-55bd-87e4-b1978d98bd5f"

[[deps.HTTP]]
deps = ["Base64", "URIs"]
git-tree-sha1 = "1111111111111111111111111111111111111111"
uuid = "cd3eb016-35fb-5094-929b-558a96fad6f3"
version = "1.10.0"

[[deps.Uses]]
deps = ["HTTP"]
git-tree-sha1 = "2222222222222222222222222222222222222222"
uuid = "aaaaaaaa-0000-0000-0000-000000000000"
version = "0.3.1"

[[deps.URIs]]
git-tree-sha1 = "3333333333333333333333333333333333333333"
uuid = "5c2747f8-b7ea-4ff2-ba2e-563bfd36b1d4"
version = "1.5.1"
"#;

    const PROJECT: &str = r#"[deps]
HTTP = "cd3eb016-35fb-5094-929b-558a96fad6f3"
Uses = "aaaaaaaa-0000-0000-0000-000000000000"

[compat]
HTTP = "1.7"
"#;

    fn general() -> Fake {
        Fake::default()
            .with(
                &format!("{GENERAL}/H/HTTP/Package.toml"),
                "name = \"HTTP\"\nuuid = \"cd3eb016-35fb-5094-929b-558a96fad6f3\"\nrepo = \"x\"\n",
            )
            .with(
                &format!("{GENERAL}/H/HTTP/Versions.toml"),
                "[\"1.10.0\"]\ngit-tree-sha1 = \"1111111111111111111111111111111111111111\"\n\n[\"1.10.9\"]\ngit-tree-sha1 = \"9999999999999999999999999999999999999999\"\n\n[\"1.10.5\"]\ngit-tree-sha1 = \"5555555555555555555555555555555555555555\"\nyanked = true\n\n[\"2.0.0\"]\ngit-tree-sha1 = \"8888888888888888888888888888888888888888\"\n",
            )
            .with(
                &format!("{GENERAL}/H/HTTP/Deps.toml"),
                "[\"0-1\"]\nBase64 = \"2a0f44e3-6c83-55bd-87e4-b1978d98bd5f\"\nURIs = \"5c2747f8-b7ea-4ff2-ba2e-563bfd36b1d4\"\n\n[\"2-2\"]\nURIs = \"5c2747f8-b7ea-4ff2-ba2e-563bfd36b1d4\"\nBase64 = \"2a0f44e3-6c83-55bd-87e4-b1978d98bd5f\"\n",
            )
            .with(
                &format!("{GENERAL}/H/HTTP/Compat.toml"),
                "[\"1\"]\nURIs = \"1.3.0-1\"\njulia = \"1.6.0-1\"\n\n[\"2-2\"]\nURIs = \"1.3-1\"\njulia = \"1.6.0-1\"\n",
            )
            .with(
                &format!("{GENERAL}/U/Uses/Package.toml"),
                "name = \"Uses\"\nuuid = \"aaaaaaaa-0000-0000-0000-000000000000\"\n",
            )
            .with(&format!("{GENERAL}/U/Uses/Compat.toml"), "[\"0.3\"]\nHTTP = \"1\"\n")
    }

    fn julia_repo(manifest: &str, project: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Manifest.toml"), manifest).unwrap();
        std::fs::write(dir.path().join("Project.toml"), project).unwrap();
        dir
    }

    #[test]
    fn a_julia_entry_moves_with_the_registry_tree_hash() {
        let dir = julia_repo(MANIFEST, PROJECT);
        let fake = general();
        let note = julia_bump(
            dir.path(),
            &edit(Ecosystem::Julia, "HTTP", "1.10.0", "1.10.9"),
            Some(&fake),
        )
        .unwrap();
        assert!(note.contains("1 Manifest.toml entry"), "{note}");
        let after = std::fs::read_to_string(dir.path().join("Manifest.toml")).unwrap();
        let expected = MANIFEST
            .replacen(
                "1111111111111111111111111111111111111111",
                "9999999999999999999999999999999999999999",
                1,
            )
            .replacen("version = \"1.10.0\"", "version = \"1.10.9\"", 1);
        assert_eq!(after, expected, "two values change, the rest byte for byte");
        let (installed, _) = fleetreach_julia::installed_packages(&after, Some(PROJECT)).unwrap();
        assert!(installed
            .iter()
            .any(|p| p.name == "HTTP" && p.version == "1.10.9"));
    }

    #[test]
    fn a_julia_move_that_breaks_compat_is_refused() {
        let refused = |manifest: &str, project: &str, to: &str, fake: Fake| {
            let dir = julia_repo(manifest, project);
            let err = julia_bump(
                dir.path(),
                &edit(Ecosystem::Julia, "HTTP", "1.10.0", to),
                Some(&fake),
            )
            .unwrap_err();
            assert_eq!(
                std::fs::read_to_string(dir.path().join("Manifest.toml")).unwrap(),
                manifest
            );
            err
        };
        let err = refused(MANIFEST, PROJECT, "2.0.0", general());
        assert!(err.contains("leaves out 2.0.0"), "{err}");
        let err = refused(MANIFEST, PROJECT, "1.10.5", general());
        assert!(err.contains("yanked"), "{err}");
        let old_uris = MANIFEST.replace("version = \"1.5.1\"", "version = \"1.2.0\"");
        let err = refused(&old_uris, PROJECT, "1.10.9", general());
        assert!(err.contains("needs URIs"), "{err}");
        let tight = PROJECT.replace("HTTP = \"1.7\"", "HTTP = \"=1.10.0, 0.9\"");
        let err = refused(MANIFEST, &tight, "1.10.9", general());
        assert!(err.contains("Project.toml's compat for HTTP"), "{err}");
        let fake = general().with(
            &format!("{GENERAL}/U/Uses/Compat.toml"),
            "[\"0.3\"]\nHTTP = \"1.0-1.10.1\"\n",
        );
        let dir = julia_repo(MANIFEST, PROJECT);
        assert!(julia_bump(
            dir.path(),
            &edit(Ecosystem::Julia, "HTTP", "1.10.0", "1.10.9"),
            Some(&fake)
        )
        .unwrap_err()
        .contains("Uses 0.3.1 needs HTTP"));
        let impostor = general().with(
            &format!("{GENERAL}/H/HTTP/Package.toml"),
            "uuid = \"00000000-0000-0000-0000-000000000000\"\n",
        );
        let err = refused(MANIFEST, PROJECT, "1.10.9", impostor);
        assert!(err.contains("another package"), "{err}");
        let pinned = MANIFEST.replace(
            "version = \"1.10.0\"",
            "version = \"1.10.0\"\npinned = true",
        );
        let err = refused(&pinned, PROJECT, "1.10.9", general());
        assert!(err.contains("pinned"), "{err}");
    }

    #[test]
    fn jll_packages_live_in_their_own_directory() {
        assert_eq!(General::dir("OpenSSL_jll"), "jll/O/OpenSSL_jll");
        assert_eq!(General::dir("HTTP"), "H/HTTP");
    }

    /// A live lock edit on a real project, against the real registries: run with
    /// `FR_LIVE=<dir>:<swift|hex|julia>:<package>:<from>:<to>` and `--ignored`, then check the
    /// result with the package manager's own frozen install.
    #[test]
    #[ignore = "network: edits a real project against the real registries"]
    fn live_lock_edit() {
        let spec = std::env::var("FR_LIVE").unwrap();
        let parts: Vec<&str> = spec.split(':').collect();
        let [dir, eco, package, from, to] = parts.as_slice() else {
            panic!("FR_LIVE=<dir>:<eco>:<package>:<from>:<to>")
        };
        let client = crate::health::registry_client();
        let path = Path::new(dir);
        let out = match *eco {
            "swift" => swift_bump(path, &edit(Ecosystem::Swift, package, from, to)),
            "hex" => hex_bump(
                path,
                &edit(Ecosystem::Hex, package, from, to),
                client.as_deref(),
            ),
            _ => julia_bump(
                path,
                &edit(Ecosystem::Julia, package, from, to),
                client.as_deref(),
            ),
        };
        println!("LIVE {eco} {package} {from}->{to}: {out:?}");
    }
}
