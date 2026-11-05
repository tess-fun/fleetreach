//! `diff --base <ref>`: which new findings this change brought in.
//!
//! A new finding is new per occurrence (repo, advisory, package, version). Git then places
//! it: a package at that version in a file at HEAD but not in the same file at the merge base
//! is `introduced`, with the entry's line and, when a changed manifest line names the direct
//! dependency, that line as the cause. One the merge base already had in every file is
//! `existing`: the advisory is what changed, not the branch. Anything not found anywhere is
//! `unknown`, and gates like `introduced`, so a format this cannot read never hides a finding.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use fleetreach_core::{DepScope, FleetReport, Occurrence, Severity};
use serde::Serialize;

use crate::assemble::{is_malware, DevGate};
use crate::lockline;

/// Where a new finding came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    Introduced,
    Unknown,
    Existing,
}

/// A place in a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Place {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

impl std::fmt::Display for Place {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.line {
            Some(line) => write!(f, "{}:{line}", self.file),
            None => f.write_str(&self.file),
        }
    }
}

/// One occurrence the baseline does not have.
#[derive(Debug, Clone, Serialize)]
pub struct Attributed {
    pub origin: Origin,
    pub advisory_id: String,
    /// `None` for a supply-chain warning.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    pub package: String,
    pub version: String,
    /// The lockfile entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<Place>,
    /// The changed manifest line that names the direct dependency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<Place>,
    /// On a dev or build-only package. Never set on known malware.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub dev: bool,
    #[serde(skip)]
    direct: Option<String>,
}

impl Attributed {
    /// Whether this counts against the gate at `floor`, or at `dev` for a dev package. Unknown
    /// severity fails closed unless dev findings never gate.
    pub fn gates(&self, floor: Severity, dev: DevGate, warnings: bool) -> bool {
        let floor = if self.dev {
            dev.floor(floor)
        } else {
            Some(floor)
        };
        let Some(floor) = floor else {
            return false;
        };
        self.origin != Origin::Existing
            && match self.severity {
                Some(s) => s == Severity::Unknown || s >= floor,
                None => warnings,
            }
    }
}

type OccurrenceKey = (String, String, String, String);

fn occurrences(
    report: &FleetReport,
) -> impl Iterator<Item = (&str, Option<Severity>, bool, &Occurrence)> {
    let vulns = report.vulnerabilities.iter().flat_map(|v| {
        let malware = is_malware(v);
        v.occurrences
            .iter()
            .map(move |o| (v.advisory_id.as_str(), Some(v.severity), malware, o))
    });
    let warnings = report.warnings.iter().flat_map(|w| {
        let id = w.advisory_id.as_deref();
        w.occurrences
            .iter()
            .filter_map(move |o| Some((id?, None, false, o)))
    });
    vulns.chain(warnings)
}

fn key(advisory: &str, occurrence: &Occurrence) -> OccurrenceKey {
    match occurrence {
        Occurrence::InRepo {
            repo,
            package,
            installed,
            ..
        } => (
            repo.0.clone(),
            advisory.to_string(),
            package.clone(),
            installed.to_string(),
        ),
        Occurrence::Toolchain { channel, .. } => (
            String::new(),
            advisory.to_string(),
            channel.clone(),
            String::new(),
        ),
    }
}

/// The occurrences of `current` that `baseline` lacks, unplaced.
pub fn new_occurrences(baseline: &FleetReport, current: &FleetReport) -> Vec<Attributed> {
    let known: BTreeSet<OccurrenceKey> = occurrences(baseline)
        .map(|(id, _, _, o)| key(id, o))
        .collect();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (id, severity, malware, occurrence) in occurrences(current) {
        let k = key(id, occurrence);
        if known.contains(&k) || !seen.insert(k.clone()) {
            continue;
        }
        let (direct, scope) = match occurrence {
            Occurrence::InRepo {
                dependency_path,
                scope,
                ..
            } => (dependency_path.get(1).cloned(), *scope),
            Occurrence::Toolchain { .. } => (None, DepScope::Runtime),
        };
        let (repo, _, package, version) = k;
        out.push(Attributed {
            origin: Origin::Unknown,
            advisory_id: id.to_string(),
            severity,
            repo: (!repo.is_empty()).then_some(repo),
            package,
            version,
            at: None,
            cause: None,
            dev: scope == DepScope::Dev && !malware,
            direct,
        });
    }
    out
}

/// The one repo these findings are in, or `Err` naming them when there are several.
pub fn single_repo(findings: &[Attributed]) -> Result<Option<String>, String> {
    let repos: BTreeSet<&str> = findings.iter().filter_map(|f| f.repo.as_deref()).collect();
    if repos.len() > 1 {
        let list: Vec<&str> = repos.into_iter().take(5).collect();
        return Err(format!(
            "new findings span several repos ({}); name the checked-out one with --repo",
            list.join(", ")
        ));
    }
    Ok(repos.into_iter().next().map(str::to_string))
}

/// A git checkout and the commit a change branched from.
pub struct Checkout {
    dir: PathBuf,
    merge_base: String,
}

impl Checkout {
    /// # Errors
    ///
    /// `dir` is not a git checkout, `base` names no commit, or the history is too shallow to
    /// reach the merge base.
    pub fn open(dir: &Path, base: &str) -> Result<Self, String> {
        let probe = Checkout {
            dir: dir.to_path_buf(),
            merge_base: String::new(),
        };
        let spec = format!("{base}^{{commit}}");
        let commit = probe
            .git(&[
                "rev-parse",
                "--verify",
                "--quiet",
                "--end-of-options",
                &spec,
            ])
            .map_err(|_| {
                format!(
                    "`{base}` is not a commit in {}; fetch it first",
                    dir.display()
                )
            })?;
        let commit = String::from_utf8_lossy(&commit).trim().to_string();
        let merge_base = probe.git(&["merge-base", &commit, "HEAD"]).map_err(|_| {
            format!("no merge base of `{base}` and HEAD; is the clone shallow? fetch more history")
        })?;
        Ok(Checkout {
            dir: dir.to_path_buf(),
            merge_base: String::from_utf8_lossy(&merge_base).trim().to_string(),
        })
    }

    fn git(&self, args: &[&str]) -> Result<Vec<u8>, String> {
        let output = Command::new("git")
            .current_dir(&self.dir)
            .args([
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
            ])
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .output()
            .map_err(|e| format!("running git: {e}"))?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    }

    fn tracked(&self) -> Result<Vec<String>, String> {
        let out = self.git(&["ls-files", "-z"])?;
        Ok(out
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect())
    }

    /// The file now. A symlink is not followed: a change could point one anywhere.
    fn at_head(&self, file: &str) -> Option<String> {
        let path = self.dir.join(file);
        let meta = std::fs::symlink_metadata(&path).ok()?;
        meta.is_file()
            .then(|| fleetreach_core::repofile::read_to_string(path).ok())?
    }

    /// The file at the merge base; `None` when it did not exist there.
    fn at_base(&self, file: &str) -> Option<String> {
        let object = format!("{}:{file}", self.merge_base);
        let bytes = self.git(&["cat-file", "blob", &object]).ok()?;
        String::from_utf8(bytes).ok()
    }

    /// The lines of `file` this change added, as (line, text).
    fn added_lines(&self, file: &str) -> Vec<(u32, String)> {
        self.git(&[
            "diff",
            "--unified=0",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            &self.merge_base,
            "--",
            file,
        ])
        .map(|out| parse_added(&String::from_utf8_lossy(&out)))
        .unwrap_or_default()
    }
}

/// The added lines of a `--unified=0` diff.
fn parse_added(diff: &str) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let mut next = 0u32;
    for line in diff.lines() {
        if let Some(hunk) = line.strip_prefix("@@ ") {
            next = hunk
                .split_whitespace()
                .find_map(|part| part.strip_prefix('+'))
                .and_then(|r| r.split(',').next())
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
        } else if next > 0 {
            if let Some(text) = line.strip_prefix('+') {
                out.push((next, text.to_string()));
                next += 1;
            }
        }
    }
    out
}

/// Whether `name` stands alone in `line`, not as part of a longer name.
fn names(line: &str, name: &str) -> bool {
    let line = line.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();
    let part = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || "-_.".contains(c));
    line.match_indices(&name).any(|(i, _)| {
        !part(line[..i].chars().next_back()) && !part(line[i + name.len()..].chars().next())
    })
}

/// The last part of a coordinate: `group:artifact`, `github.com/owner/name`.
fn short_name(name: &str) -> &str {
    name.rsplit([':', '/']).next().unwrap_or(name)
}

/// Sets each finding's origin from what git holds. Findings of other repos stay `unknown`.
///
/// # Errors
///
/// The tracked files cannot be listed.
pub fn place(
    checkout: &Checkout,
    repo: Option<&str>,
    findings: &mut [Attributed],
) -> Result<(), String> {
    if findings.is_empty() {
        return Ok(());
    }
    let tracked = checkout.tracked()?;
    let locks: Vec<&String> = tracked.iter().filter(|f| lockline::reads(f)).collect();
    let manifests: Vec<&String> = tracked
        .iter()
        .filter(|f| lockline::is_manifest(f))
        .collect();
    let mut heads = BTreeMap::new();
    let mut bases = BTreeMap::new();
    let mut added = BTreeMap::new();
    for finding in findings.iter_mut() {
        if finding.repo.is_none() || finding.repo.as_deref() != repo {
            continue;
        }
        let (package, version) = (finding.package.clone(), finding.version.clone());
        for file in &locks {
            let head = heads
                .entry(file.as_str())
                .or_insert_with(|| checkout.at_head(file));
            let Some(line) = head
                .as_deref()
                .and_then(|t| lockline::exact_line(file, t, &package, &version))
            else {
                continue;
            };
            let base = bases
                .entry(file.as_str())
                .or_insert_with(|| checkout.at_base(file));
            let before = base
                .as_deref()
                .and_then(|t| lockline::exact_line(file, t, &package, &version));
            let at = Place {
                file: (*file).clone(),
                line: Some(line),
            };
            if before.is_none() {
                finding.origin = Origin::Introduced;
                finding.at = Some(at);
                break;
            }
            finding.origin = Origin::Existing;
            finding.at.get_or_insert(at);
        }
        if finding.origin != Origin::Introduced {
            continue;
        }
        let Some(direct) = finding.direct.clone().or(Some(package)) else {
            continue;
        };
        let lock_dir = finding
            .at
            .as_ref()
            .and_then(|p| Path::new(&p.file).parent().map(Path::to_path_buf))
            .unwrap_or_default();
        // A manifest beside the lockfile explains it before one elsewhere in the repo.
        let (near, far): (Vec<&&String>, Vec<&&String>) = manifests
            .iter()
            .partition(|m| Path::new(m.as_str()).parent() == Some(lock_dir.as_path()));
        finding.cause = near.iter().chain(&far).find_map(|file| {
            if finding.at.as_ref().is_some_and(|at| at.file == ***file) {
                return None;
            }
            let lines = added
                .entry(file.as_str())
                .or_insert_with(|| checkout.added_lines(file));
            let hit = lines
                .iter()
                .find(|(_, text)| names(text, &direct) || names(text, short_name(&direct)))?;
            Some(Place {
                file: (***file).clone(),
                line: Some(hit.0),
            })
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .current_dir(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@t"])
            .args(args)
            .output()
            .unwrap();
        assert!(status.status.success(), "{status:?}");
    }

    fn finding(repo: &str, package: &str, version: &str, direct: Option<&str>) -> Attributed {
        Attributed {
            origin: Origin::Unknown,
            advisory_id: "GHSA-x".to_string(),
            severity: Some(Severity::High),
            repo: Some(repo.to_string()),
            package: package.to_string(),
            version: version.to_string(),
            at: None,
            cause: None,
            dev: false,
            direct: direct.map(str::to_string),
        }
    }

    #[test]
    fn a_dev_finding_gates_at_the_dev_floor() {
        let mut f = finding("r", "p", "1", None);
        f.dev = true;
        let critical = DevGate::At(Severity::Critical);
        assert!(f.gates(Severity::Low, DevGate::Same, false));
        assert!(!f.gates(Severity::Low, critical, false));
        assert!(!f.gates(Severity::Low, DevGate::Never, false));
    }

    const LOCK: &str = "{\n  \"packages\": {\n    \"node_modules/old\": {\n      \"version\": \"1.0.0\"\n    },\n    \"node_modules/tar\": {\n      \"version\": \"VERSION\"\n    }\n  }\n}\n";

    /// A repo whose branch moves `tar` to 6.0.0 under a new direct dependency.
    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        git(root, &["init", "-q", "-b", "main"]);
        std::fs::write(
            root.join("package-lock.json"),
            LOCK.replace("VERSION", "7.0.0"),
        )
        .unwrap();
        std::fs::write(
            root.join("package.json"),
            "{\n  \"dependencies\": {\n  }\n}\n",
        )
        .unwrap();
        git(root, &["add", "-A"]);
        git(root, &["commit", "-qm", "base"]);
        git(root, &["checkout", "-qb", "pr"]);
        std::fs::write(
            root.join("package-lock.json"),
            LOCK.replace("VERSION", "6.0.0"),
        )
        .unwrap();
        std::fs::write(
            root.join("package.json"),
            "{\n  \"dependencies\": {\n    \"giget\": \"1\"\n  }\n}\n",
        )
        .unwrap();
        git(root, &["add", "-A"]);
        git(root, &["commit", "-qm", "pr"]);
        dir
    }

    #[test]
    fn git_says_which_findings_the_change_brought_in() {
        let dir = repo();
        let checkout = Checkout::open(dir.path(), "main").unwrap();
        let mut findings = vec![
            finding("r", "tar", "6.0.0", Some("giget")),
            finding("r", "old", "1.0.0", None),
            finding("r", "ghost", "1.0.0", None),
            finding("other", "tar", "6.0.0", None),
        ];
        place(&checkout, Some("r"), &mut findings).unwrap();
        let origins: Vec<Origin> = findings.iter().map(|f| f.origin).collect();
        assert_eq!(
            origins,
            vec![
                Origin::Introduced,
                Origin::Existing,
                Origin::Unknown,
                Origin::Unknown
            ]
        );
        assert_eq!(
            findings[0].at.as_ref().unwrap().to_string(),
            "package-lock.json:6"
        );
        assert_eq!(
            findings[0].cause.as_ref().unwrap().to_string(),
            "package.json:3"
        );
        assert!(findings[1].cause.is_none());
        let same = DevGate::Same;
        assert!(findings[0].gates(Severity::High, same, false));
        assert!(!findings[0].gates(Severity::Critical, same, false));
        assert!(!findings[1].gates(Severity::Low, same, false));
        assert!(findings[2].gates(Severity::Low, same, false));
    }

    #[test]
    fn a_later_commit_on_the_base_branch_is_not_part_of_the_change() {
        let dir = repo();
        let root = dir.path();
        git(root, &["checkout", "-q", "main"]);
        std::fs::write(
            root.join("package-lock.json"),
            LOCK.replace("VERSION", "6.0.0"),
        )
        .unwrap();
        git(root, &["commit", "-qam", "main moved on"]);
        git(root, &["checkout", "-q", "pr"]);
        let checkout = Checkout::open(root, "main").unwrap();
        let mut findings = vec![finding("r", "tar", "6.0.0", None)];
        place(&checkout, Some("r"), &mut findings).unwrap();
        assert_eq!(findings[0].origin, Origin::Introduced);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_lockfile_is_not_read() {
        let dir = repo();
        let root = dir.path();
        std::fs::remove_file(root.join("package-lock.json")).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("lock");
        std::fs::write(&target, LOCK.replace("VERSION", "6.0.0")).unwrap();
        std::os::unix::fs::symlink(&target, root.join("package-lock.json")).unwrap();
        let checkout = Checkout::open(root, "main").unwrap();
        let mut findings = vec![finding("r", "tar", "6.0.0", None)];
        place(&checkout, Some("r"), &mut findings).unwrap();
        assert_eq!(findings[0].origin, Origin::Unknown);
    }

    #[test]
    fn a_ref_that_is_not_a_commit_stops_the_run() {
        let dir = repo();
        for base in ["no-such-ref", "--output=/tmp/x", "-h"] {
            let error = Checkout::open(dir.path(), base).err().unwrap();
            assert!(error.contains("is not a commit"), "{error}");
        }
    }

    #[test]
    fn several_repos_need_naming() {
        let one = [finding("a", "x", "1", None), finding("a", "y", "1", None)];
        assert_eq!(single_repo(&one).unwrap().as_deref(), Some("a"));
        let two = [finding("a", "x", "1", None), finding("b", "x", "1", None)];
        assert!(single_repo(&two).unwrap_err().contains("--repo"));
    }

    #[test]
    fn added_lines_carry_their_new_numbers() {
        let diff = "diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -2 +2,2 @@ ctx\n-old\n+new\n+next\n@@ -9,0 +11 @@\n+last\n";
        assert_eq!(
            parse_added(diff),
            vec![
                (2, "new".to_string()),
                (3, "next".to_string()),
                (11, "last".to_string())
            ]
        );
    }

    #[test]
    fn a_name_inside_a_longer_name_does_not_count() {
        assert!(names(r#"    "tar": "^6.0.0","#, "tar"));
        assert!(names("serde = \"1\"", "Serde"));
        assert!(!names(r#"    "tar-fs": "^6.0.0","#, "tar"));
        assert!(!names(r#"    "avatar": "1""#, "tar"));
    }

    #[test]
    fn coordinates_shorten_to_their_last_part() {
        assert_eq!(short_name("org.apache:commons-text"), "commons-text");
        assert_eq!(short_name("github.com/a/b"), "b");
        assert_eq!(short_name("rack"), "rack");
    }
}
