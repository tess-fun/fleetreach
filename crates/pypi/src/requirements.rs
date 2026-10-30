//! Read pip requirements files (`requirements.txt` and friends) without pip.
//!
//! A requirements file is not a lockfile: it holds whatever its author wrote. Each file
//! therefore carries a coverage level (spec 00, C1) alongside its packages:
//!
//! - every requirement pinned to one version (`name==X`) **and** evidence the file was
//!   produced by a resolver (a pip-compile / uv header, `# via` annotations, or hashes on
//!   every line): `full`, the resolved transitive set;
//! - every requirement pinned but no such evidence (`pip freeze` output, or hand-written
//!   pins of direct dependencies only): `partial`, since dependencies of these packages may
//!   be missing;
//! - any requirement not pinned to one version (`>=`, `~=`, a bare name): `direct-only`. Its
//!   version is never guessed; the name is listed as unresolved, and only pinned
//!   requirements are matched.
//!
//! Parsing follows pip's format: `\` continuations, comments, `--hash` options, environment
//! markers (kept and not evaluated: a marker can only hide a finding, so matching ignores
//! it), `-r` includes (followed within the repo, cycle-safe), `-c` constraints (they pin an
//! unpinned requirement of the same name), and `-e` / URL / path requirements, which have no
//! registry release to match and are counted, not matched.
//!
//! Direct versus transitive comes from pip-compile's `# via` annotations when present
//! (`# via -r requirements.in` is direct); a generated file without them reports everything
//! transitive (conservative), and a hand-written file reports everything direct. Files named
//! for development (`requirements-dev.txt`, `dev-requirements.txt`, `requirements/test.txt`)
//! are dev scope, a filename heuristic.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fleetreach_core::{Coverage, DepGraph};

use crate::error::PyPiError;
use crate::lockfile::InstalledPackage;
use crate::version::normalize_name;

/// How deep `-r` includes are followed (pip has no limit; a cycle is caught separately).
const MAX_INCLUDE_DEPTH: usize = 8;

/// The root of the requirements dependency graph.
pub(crate) const ROOT: &str = "(root)";

/// One source read with less than full coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SourceCoverage {
    /// The file, relative to the scanned directory.
    pub source: String,
    pub level: Coverage,
    /// Why coverage is incomplete, naming what was not read.
    pub reason: String,
}

/// Everything read from a directory's requirements files.
#[derive(Debug, Default)]
pub(crate) struct Requirements {
    pub packages: Vec<InstalledPackage>,
    pub graph: DepGraph,
    pub coverage: Vec<SourceCoverage>,
    /// `-e`, URL and path requirements: no registry release, so not matched.
    pub non_registry: u32,
}

/// The requirements files of `dir`: `requirements*.txt`, `*requirements.txt` (including
/// `dev-requirements.txt`), and every `.txt` in a `requirements/` subdirectory. Sorted.
pub(crate) fn requirements_files(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = txt_files(dir)
        .into_iter()
        .filter(|path| {
            let name = file_name_lower(path);
            name.starts_with("requirements") || name.ends_with("requirements.txt")
        })
        .collect();
    found.extend(txt_files(&dir.join("requirements")));
    found.sort();
    found
}

/// The regular `*.txt` files directly in `dir` (empty if it cannot be read).
fn txt_files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| file_name_lower(p).ends_with(".txt"))
        .collect()
}

fn file_name_lower(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// Whether a requirements file is for development, by its name or its directory's
/// convention: a `dev` or `test` word in the file stem (`requirements-dev.txt`,
/// `dev-requirements.txt`, `requirements/test.txt`, `requirements_tests.txt`).
fn is_dev_file(path: &Path) -> bool {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    stem.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| {
            matches!(
                word,
                "dev" | "develop" | "development" | "test" | "tests" | "testing"
            )
        })
}

/// Read every requirements file in `dir` (and what they include) into one package set.
///
/// # Errors
///
/// A top-level file that exists but cannot be read is an error (fail closed). Problems
/// further in (a missing include, an include outside `dir`, an unparseable line) are
/// coverage gaps naming what was not read, not errors.
pub(crate) fn read_dir(dir: &Path) -> Result<Requirements, PyPiError> {
    let root = dir.canonicalize().map_err(|e| PyPiError::db(dir, e))?;
    let mut reader = Reader {
        root,
        dir: dir.to_path_buf(),
        visited: BTreeMap::new(),
        out: Requirements {
            graph: DepGraph::new(ROOT),
            ..Requirements::default()
        },
        constraints: BTreeMap::new(),
        unresolved: Vec::new(),
    };
    for path in requirements_files(dir) {
        let text = std::fs::read_to_string(&path).map_err(|e| PyPiError::db(&path, e))?;
        reader.read_file(&path, &text, is_dev_file(&path), 0);
    }
    reader.finish();
    Ok(reader.out)
}

/// A pinned requirement on its way to an [`InstalledPackage`].
struct Pinned {
    name: String,
    version: String,
    /// `# via` entries naming the packages that require it.
    via_parents: Vec<String>,
    /// `# via -r file` (or the project itself): declared directly.
    via_declared: bool,
}

/// An unpinned requirement, remembered with the file that declared it so a `-c` constraint
/// can pin it and an unresolved one is reported against its file.
struct Unpinned {
    name: String,
    file: String,
    dev: bool,
}

struct Reader {
    root: PathBuf,
    dir: PathBuf,
    /// Files read so far, with whether they were read as dev. A file read as dev (through a
    /// dev file's `-r`) is read again if it turns up as runtime.
    visited: BTreeMap<PathBuf, bool>,
    out: Requirements,
    /// `name -> version` from `-c` constraint files.
    constraints: BTreeMap<String, String>,
    unresolved: Vec<Unpinned>,
}

impl Reader {
    fn rel(&self, path: &Path) -> String {
        path.strip_prefix(&self.dir)
            .unwrap_or(path)
            .display()
            .to_string()
    }

    fn gap(&mut self, path: &Path, level: Coverage, reason: String) {
        let source = self.rel(path);
        self.out.coverage.push(SourceCoverage {
            source,
            level,
            reason,
        });
    }

    /// Read one file's text (already loaded), following its `-r` includes.
    fn read_file(&mut self, path: &Path, text: &str, dev: bool, depth: usize) {
        let Ok(canonical) = path.canonicalize() else {
            return;
        };
        // Already read as runtime, or as dev again (a file listed twice, an include cycle).
        match self.visited.get(&canonical) {
            Some(false) => return,
            Some(true) if dev => return,
            _ => {}
        }
        self.visited.insert(canonical, dev);
        let file = self.rel(path);
        let parsed = parse(text);

        for include in &parsed.includes {
            self.include(path, include, dev, depth, false);
        }
        for constraint in &parsed.constraints {
            self.include(path, constraint, dev, depth, true);
        }
        if !parsed.bad_lines.is_empty() {
            let reason = format!(
                "{} line(s) could not be read as requirements and were not matched: {}",
                parsed.bad_lines.len(),
                sample(&parsed.bad_lines)
            );
            self.gap(path, Coverage::Partial, reason);
        }
        if parsed.non_registry > 0 {
            let reason = format!(
                "{} editable, URL or path requirement(s) have no registry release to match, and \
                 their own dependencies were not read",
                parsed.non_registry
            );
            self.gap(path, Coverage::Partial, reason);
        }
        self.out.non_registry += parsed.non_registry;

        // Direct versus transitive: `# via` annotations decide when present; otherwise a
        // generated file is all transitive (conservative) and a hand-written one all direct.
        for req in &parsed.pinned {
            let direct = if parsed.annotated {
                req.via_declared
            } else {
                !parsed.generated
            };
            if direct {
                self.out.graph.add_edges(ROOT, [req.name.clone()]);
            }
            for parent in &req.via_parents {
                self.out.graph.add_edges(parent, [req.name.clone()]);
            }
            self.out.packages.push(InstalledPackage {
                name: req.name.clone(),
                version: req.version.clone(),
                direct,
                dev,
            });
        }
        let pinned_unproven =
            !parsed.pinned.is_empty() && !parsed.has_unpinned() && !parsed.generated;
        for name in parsed.unpinned {
            self.unresolved.push(Unpinned {
                name,
                file: file.clone(),
                dev,
            });
        }

        // A file whose requirements are all pinned is complete only if a resolver wrote it.
        if pinned_unproven {
            self.gap(
                path,
                Coverage::Partial,
                "every requirement is pinned, but nothing shows the file lists the full \
                 transitive set (no pip-compile or uv header, `# via` annotations or hashes); \
                 dependencies of these packages may be missing"
                    .to_string(),
            );
        }
    }

    /// Follow a `-r` include or read a `-c` constraint file named in `from`.
    fn include(&mut self, from: &Path, target: &str, dev: bool, depth: usize, constraint: bool) {
        let base = from.parent().unwrap_or(&self.dir);
        let path = base.join(target);
        let kind = if constraint { "constraint" } else { "include" };
        if depth + 1 > MAX_INCLUDE_DEPTH {
            let reason = format!("{kind} {target} is nested too deeply; it was not read");
            self.gap(from, Coverage::Partial, reason);
            return;
        }
        let inside = path.canonicalize().is_ok_and(|c| c.starts_with(&self.root));
        if !inside {
            let reason = if path.exists() {
                format!("{kind} {target} is outside the scanned directory; it was not read")
            } else {
                format!("{kind} {target} does not exist; its requirements were not read")
            };
            self.gap(from, Coverage::Partial, reason);
            return;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            let reason = format!("{kind} {target} could not be read");
            self.gap(from, Coverage::Partial, reason);
            return;
        };
        if constraint {
            for req in parse(&text).pinned {
                self.constraints.insert(req.name, req.version);
            }
        } else {
            self.read_file(&path, &text, dev || is_dev_file(&path), depth + 1);
        }
    }

    /// Pin unpinned requirements that a constraint file pins; report the rest per file.
    fn finish(&mut self) {
        let mut unresolved_by_file: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for req in std::mem::take(&mut self.unresolved) {
            if let Some(version) = self.constraints.get(&req.name) {
                self.out.graph.add_edges(ROOT, [req.name.clone()]);
                self.out.packages.push(InstalledPackage {
                    name: req.name,
                    version: version.clone(),
                    direct: true,
                    dev: req.dev,
                });
            } else {
                unresolved_by_file
                    .entry(req.file)
                    .or_default()
                    .push(req.name);
            }
        }
        for (file, mut names) in unresolved_by_file {
            names.sort();
            names.dedup();
            self.out.coverage.push(SourceCoverage {
                source: file,
                level: Coverage::DirectOnly,
                reason: format!(
                    "{} requirement(s) not pinned to one version, so not matched: {}; \
                     pinned ones were matched, but transitive dependencies were not resolved \
                     (compile the file with pip-compile or uv pip compile)",
                    names.len(),
                    sample(&names)
                ),
            });
        }
        // A file read twice (as dev, then as runtime) reports its gaps once.
        self.out
            .coverage
            .sort_by(|a, b| (&a.source, &a.reason).cmp(&(&b.source, &b.reason)));
        self.out
            .coverage
            .dedup_by(|a, b| a.source == b.source && a.reason == b.reason);
    }
}

/// At most five items, then a count of the rest.
fn sample(items: &[String]) -> String {
    let shown: Vec<&str> = items.iter().take(5).map(String::as_str).collect();
    let more = items.len().saturating_sub(shown.len());
    if more == 0 {
        shown.join(", ")
    } else {
        format!("{} and {more} more", shown.join(", "))
    }
}

/// One requirements file, parsed but not yet resolved against includes or constraints.
#[derive(Default)]
struct Parsed {
    pinned: Vec<Pinned>,
    unpinned: Vec<String>,
    includes: Vec<String>,
    constraints: Vec<String>,
    bad_lines: Vec<String>,
    non_registry: u32,
    /// Any `# via` annotation was seen.
    annotated: bool,
    /// Written by a resolver: a pip-compile/uv header, `# via` annotations, or hashes on
    /// every pinned requirement.
    generated: bool,
}

impl Parsed {
    fn has_unpinned(&self) -> bool {
        !self.unpinned.is_empty()
    }
}

/// Parse one requirements file's text.
fn parse(text: &str) -> Parsed {
    let mut out = Parsed::default();
    let mut header_generated = false;
    let mut all_hashed = true;
    // Index into `out.pinned` of the requirement that `# via` lines below belong to.
    let mut current: Option<usize> = None;
    let mut in_via = false;

    for raw in logical_lines(text) {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            let comment = comment.trim();
            if out.pinned.is_empty() && comment.contains("autogenerated by") {
                header_generated = true;
            }
            let indented = raw.starts_with(char::is_whitespace);
            match (current, comment.strip_prefix("via")) {
                // `# via a, b` or `# via` opening a multi-line list; only directly under a
                // requirement (pip-compile indents these), so trailing notes are not taken.
                (Some(i), Some(rest)) if indented && (rest.is_empty() || rest.starts_with(' ')) => {
                    out.annotated = true;
                    in_via = true;
                    add_via(&mut out.pinned[i], rest);
                }
                (Some(i), _) if in_via && indented => add_via(&mut out.pinned[i], comment),
                _ => in_via = false,
            }
            continue;
        }
        current = None;
        in_via = false;
        if line.starts_with('-') {
            option(line, &mut out);
            continue;
        }
        // Inline comments start at a `#` preceded by whitespace.
        let line = line.split(" #").next().unwrap_or(line).trim();
        let hashed = line.contains("--hash");
        let line = line.split(" --").next().unwrap_or(line).trim();
        match requirement(line) {
            Req::Pinned(name, version) => {
                all_hashed &= hashed;
                out.pinned.push(Pinned {
                    name,
                    version,
                    via_parents: Vec::new(),
                    via_declared: false,
                });
                current = Some(out.pinned.len() - 1);
            }
            Req::Unpinned(name) => out.unpinned.push(name),
            Req::NonRegistry => out.non_registry += 1,
            Req::Bad => out.bad_lines.push(line.to_string()),
        }
    }
    out.generated = header_generated || out.annotated || (all_hashed && !out.pinned.is_empty());
    out
}

/// Join `\`-continued lines.
fn logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut pending = String::new();
    for line in text.lines() {
        if let Some(head) = line.strip_suffix('\\') {
            pending.push_str(head);
            pending.push(' ');
        } else {
            pending.push_str(line);
            lines.push(std::mem::take(&mut pending));
        }
    }
    if !pending.is_empty() {
        lines.push(pending);
    }
    lines
}

/// Record `# via` entries: `-r file` and `name (pyproject.toml)` mean declared directly,
/// anything else names a package that requires this one.
fn add_via(req: &mut Pinned, entries: &str) {
    for entry in entries.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if entry.starts_with("-r") || entry.starts_with("--requirement") || entry.ends_with(')') {
            req.via_declared = true;
        } else if entry.starts_with('-') {
            // `-c constraints.txt`: a constraint does not install anything.
        } else if let Some(name) = entry.split_whitespace().next() {
            req.via_parents.push(normalize_name(name));
        }
    }
}

/// Handle an option line (`-r`, `-c`, `-e`, index options, ...).
fn option(line: &str, out: &mut Parsed) {
    let (flag, value) = match line.split_once(|c: char| c == '=' || c.is_whitespace()) {
        Some((flag, value)) => (flag, value.trim()),
        None => (line, ""),
    };
    // `-rfile` with no separator.
    let (flag, value) = match flag {
        f if f.len() > 2
            && (f.starts_with("-r") || f.starts_with("-c"))
            && !f.starts_with("--") =>
        {
            (&f[..2], f[2..].trim())
        }
        f => (f, value),
    };
    let value = value.split(" #").next().unwrap_or(value).trim().to_string();
    match flag {
        "-r" | "--requirement" if !value.is_empty() => out.includes.push(value),
        "-c" | "--constraint" if !value.is_empty() => out.constraints.push(value),
        "-e" | "--editable" => out.non_registry += 1,
        // Index, build and resolver options change where or how packages come from, not
        // which versions are listed.
        _ => {}
    }
}

enum Req {
    Pinned(String, String),
    Unpinned(String),
    NonRegistry,
    Bad,
}

/// Classify one requirement line (comments and options already removed).
fn requirement(line: &str) -> Req {
    // Environment markers are not evaluated: a marker can only hide a finding.
    let spec = line.split(';').next().unwrap_or(line).trim();
    if spec.contains("://")
        || spec.contains(" @ ")
        || spec.starts_with(['.', '/', '~'])
        || spec.ends_with(".whl")
        || spec.ends_with(".tar.gz")
        || spec.ends_with(".zip")
    {
        return Req::NonRegistry;
    }
    let name_end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(spec.len());
    let name = &spec[..name_end];
    if name.is_empty() || !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Req::Bad;
    }
    let mut rest = spec[name_end..].trim_start();
    if rest.starts_with('[') {
        let Some(close) = rest.find(']') else {
            return Req::Bad;
        };
        rest = rest[close + 1..].trim_start();
    }
    let rest = rest.trim_start_matches('(').trim_end_matches(')').trim();
    let name = normalize_name(name);
    let pinned = rest
        .strip_prefix("===")
        .or_else(|| rest.strip_prefix("=="))
        .map(str::trim)
        .filter(|v| !v.is_empty() && !v.contains([',', '*', ' ', '<', '>', '!', '~', '=']));
    match pinned {
        Some(version) => Req::Pinned(name, version.to_string()),
        None if rest.is_empty()
            || rest.starts_with(['<', '>', '=', '!', '~'])
            || rest.starts_with(',') =>
        {
            Req::Unpinned(name)
        }
        None => Req::Bad,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn pins(p: &Parsed) -> Vec<(&str, &str)> {
        p.pinned
            .iter()
            .map(|r| (r.name.as_str(), r.version.as_str()))
            .collect()
    }

    #[test]
    fn classifies_requirement_lines() {
        let p = parse(
            "Flask==2.0.1\n\
             requests[socks] >= 2.20\n\
             ruamel.yaml===0.17.21\n\
             colorama==0.4.6 ; sys_platform == 'win32'\n\
             urllib3==1.*\n\
             idna\n\
             django>=3,<4  # inline comment\n\
             -e ./local\n\
             git+https://github.com/a/b.git#egg=b\n\
             pkg @ https://example.com/pkg.whl\n\
             ./wheels/thing.whl\n\
             ;;not a requirement\n",
        );
        assert_eq!(
            pins(&p),
            vec![
                ("flask", "2.0.1"),
                ("ruamel-yaml", "0.17.21"),
                ("colorama", "0.4.6")
            ]
        );
        assert_eq!(p.unpinned, vec!["requests", "urllib3", "idna", "django"]);
        assert_eq!(p.non_registry, 4);
        assert_eq!(p.bad_lines, vec![";;not a requirement"]);
        assert!(!p.generated);
    }

    #[test]
    fn pip_compile_output_is_generated_with_via_edges() {
        let p = parse(
            "# This file was autogenerated by uv via the following command:\n\
             #    uv pip compile requirements.in -o requirements.txt\n\
             certifi==2026.10.23 \\\n    --hash=sha256:aaaa \\\n    --hash=sha256:bbbb\n    # via requests\n\
             flask==2.0.1\n    # via -r requirements.in\n\
             markupsafe==3.0.4\n    # via\n    #   jinja2\n    #   werkzeug\n\
             demo-dep==1.0\n    # via demo (pyproject.toml)\n\
             \n\
             # The following packages are considered to be unsafe in a requirements file:\n\
             # setuptools\n",
        );
        assert!(p.generated && p.annotated);
        assert_eq!(
            pins(&p),
            vec![
                ("certifi", "2026.10.23"),
                ("flask", "2.0.1"),
                ("markupsafe", "3.0.4"),
                ("demo-dep", "1.0")
            ]
        );
        assert_eq!(p.pinned[0].via_parents, vec!["requests"]);
        assert!(p.pinned[1].via_declared);
        assert_eq!(p.pinned[2].via_parents, vec!["jinja2", "werkzeug"]);
        assert!(p.pinned[3].via_declared);
    }

    #[test]
    fn hashes_on_every_line_count_as_generated() {
        let p = parse("a==1 --hash=sha256:x\nb==2 \\\n  --hash=sha256:y\n");
        assert!(p.generated && !p.annotated);
        let p = parse("a==1 --hash=sha256:x\nb==2\n");
        assert!(!p.generated);
    }

    #[test]
    fn options_are_recognized() {
        let p = parse(
            "-r base.txt\n--requirement=more.txt\n-rdev.txt\n-c constraints.txt\n\
             --index-url https://pypi.example/simple\n--editable .\n",
        );
        assert_eq!(p.includes, vec!["base.txt", "more.txt", "dev.txt"]);
        assert_eq!(p.constraints, vec!["constraints.txt"]);
        assert_eq!(p.non_registry, 1);
    }

    #[test]
    fn dev_files_by_name() {
        for dev in [
            "requirements-dev.txt",
            "dev-requirements.txt",
            "requirements/test.txt",
            "requirements_tests.txt",
        ] {
            assert!(is_dev_file(Path::new(dev)), "{dev}");
        }
        for runtime in [
            "requirements.txt",
            "requirements/base.txt",
            "requirements-prod.txt",
        ] {
            assert!(!is_dev_file(Path::new(runtime)), "{runtime}");
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fr-pypi-req-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn rows(r: &Requirements) -> Vec<(String, String, bool, bool)> {
        let mut rows: Vec<_> = r
            .packages
            .iter()
            .map(|p| (p.name.clone(), p.version.clone(), p.direct, p.dev))
            .collect();
        rows.sort();
        rows
    }

    #[test]
    fn compiled_file_is_full_coverage_with_paths() {
        let dir = scratch("compiled");
        std::fs::write(
            dir.join("requirements.txt"),
            "flask==2.0.1\n    # via -r requirements.in\njinja2==3.1.6\n    # via flask\n",
        )
        .unwrap();
        let r = read_dir(&dir).unwrap();
        assert!(r.coverage.is_empty(), "{:?}", r.coverage);
        assert_eq!(
            rows(&r),
            vec![
                ("flask".into(), "2.0.1".into(), true, false),
                ("jinja2".into(), "3.1.6".into(), false, false)
            ]
        );
        assert_eq!(r.graph.chain_to("jinja2"), vec![ROOT, "flask", "jinja2"]);
    }

    #[test]
    fn hand_pinned_file_is_partial_and_direct() {
        let dir = scratch("handpinned");
        std::fs::write(dir.join("requirements.txt"), "requests==2.30.0\n").unwrap();
        let r = read_dir(&dir).unwrap();
        assert_eq!(
            rows(&r),
            vec![("requests".into(), "2.30.0".into(), true, false)]
        );
        assert_eq!(r.coverage.len(), 1);
        assert_eq!(r.coverage[0].level, Coverage::Partial);
        assert_eq!(r.coverage[0].source, "requirements.txt");
    }

    #[test]
    fn unpinned_is_direct_only_unless_a_constraint_pins_it() {
        let dir = scratch("unpinned");
        std::fs::write(
            dir.join("requirements.txt"),
            "-c constraints.txt\nflask\nrequests>=2\nidna==3.4\n",
        )
        .unwrap();
        std::fs::write(dir.join("constraints.txt"), "flask==2.0.1\n").unwrap();
        let r = read_dir(&dir).unwrap();
        assert_eq!(
            rows(&r),
            vec![
                ("flask".into(), "2.0.1".into(), true, false),
                ("idna".into(), "3.4".into(), true, false)
            ]
        );
        assert_eq!(r.coverage.len(), 1);
        assert_eq!(r.coverage[0].level, Coverage::DirectOnly);
        assert!(
            r.coverage[0].reason.contains("requests"),
            "{}",
            r.coverage[0].reason
        );
        assert!(!r.coverage[0].reason.contains("flask"));
    }

    #[test]
    fn includes_are_followed_inside_the_repo_only() {
        let dir = scratch("includes");
        std::fs::create_dir_all(dir.join("requirements")).unwrap();
        std::fs::write(
            dir.join("requirements-dev.txt"),
            "-r requirements/base.txt\n-r ../outside.txt\n-r missing.txt\n-r requirements-dev.txt\npytest==7.0.0 --hash=sha256:x\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("requirements/base.txt"),
            "flask==2.0.1 --hash=sha256:y\n",
        )
        .unwrap();
        let r = read_dir(&dir).unwrap();
        // Hashes on every line mark both files as resolver output without `# via`, so their
        // packages are reported transitive. base.txt is runtime in its own right (read as
        // requirements/*.txt), so flask stays runtime although the dev file includes it too.
        let r_rows = rows(&r);
        assert!(r_rows.contains(&("pytest".into(), "7.0.0".into(), false, true)));
        assert!(r_rows.contains(&("flask".into(), "2.0.1".into(), false, false)));
        assert!(!r_rows.contains(&("flask".into(), "2.0.1".into(), false, true)));
        let reasons: Vec<&str> = r.coverage.iter().map(|c| c.reason.as_str()).collect();
        assert_eq!(reasons.len(), 2, "{reasons:?}");
        assert!(reasons.iter().any(|r| r.contains("../outside.txt")));
        assert!(reasons.iter().any(|r| r.contains("missing.txt")));
    }

    #[test]
    fn discovers_conventional_names() {
        let dir = scratch("discover");
        std::fs::create_dir_all(dir.join("requirements")).unwrap();
        for f in [
            "requirements.txt",
            "requirements-dev.txt",
            "dev-requirements.txt",
            "requirements/prod.txt",
            "notes.txt",
            "requirements.in",
        ] {
            std::fs::write(dir.join(f), "").unwrap();
        }
        let names: Vec<String> = requirements_files(&dir)
            .iter()
            .map(|p| p.strip_prefix(&dir).unwrap().display().to_string())
            .collect();
        assert_eq!(
            names,
            vec![
                "dev-requirements.txt",
                "requirements/prod.txt",
                "requirements-dev.txt",
                "requirements.txt"
            ]
        );
    }
}
