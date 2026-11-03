//! Write a `proposed` sink record for an advisory from its fix commits.
//!
//! From a local clone (only `git` runs, reading objects; nothing in the repository runs):
//!
//! `cargo run -p fleetreach-sinks --example sinkpropose -- --id GHSA-... [--alias CVE-...]
//!  --package group:artifact [--text FILE] --git REPO --commit SHA [--commit SHA ...]`
//!
//! Or from a manifest of already-fetched files (`--manifest FILE`), a JSON object with
//! `id`, `aliases`, `packages`, `text`, `commits` and `files: [{path, old, new}]`, where `old`
//! and `new` are paths to the file's contents before and after (null when absent).
//!
//! The record is printed to stdout; review it before committing it under the data directory.

use std::path::{Path, PathBuf};
use std::process::Command;

use fleetreach_sinks::propose::{propose, Advisory, FileChange};

fn main() {
    match run(std::env::args().skip(1).collect()) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}

fn run(args: Vec<String>) -> Result<String, String> {
    let mut advisory = Advisory::default();
    let (mut git, mut manifest, mut commits) = (None, None, Vec::new());
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--id" => advisory.id = value()?,
            "--alias" => advisory.aliases.push(value()?),
            "--package" => advisory.packages.push(value()?),
            "--text" => {
                let path = value()?;
                advisory.text =
                    std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
            }
            "--git" => git = Some(PathBuf::from(value()?)),
            "--commit" => commits.push(value()?),
            "--manifest" => manifest = Some(PathBuf::from(value()?)),
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    let files = match (git, manifest) {
        (Some(repo), None) => {
            let mut files = Vec::new();
            for sha in &commits {
                files.extend(git_files(&repo, sha)?);
                advisory.commits.push(sha.clone());
            }
            files
        }
        (None, Some(path)) => read_manifest(&path, &mut advisory)?,
        _ => return Err("pass either --git REPO --commit SHA, or --manifest FILE".into()),
    };
    let record = propose(&advisory, &files);
    record.validate()?;
    serde_json::to_string_pretty(&record).map_err(|e| e.to_string())
}

fn git(repo: &Path, args: &[&str]) -> Result<Option<String>, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| format!("running git: {e}"))?;
    Ok(out
        .status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned()))
}

/// The Java files a commit changes, before (first parent) and after.
fn git_files(repo: &Path, sha: &str) -> Result<Vec<FileChange>, String> {
    if !sha.chars().all(|c| c.is_ascii_hexdigit()) || sha.len() < 7 {
        return Err(format!("`{sha}` is not a commit hash"));
    }
    let listing = git(
        repo,
        &[
            "diff-tree",
            "--no-commit-id",
            "-r",
            "-M",
            "--name-status",
            sha,
            "--",
        ],
    )?
    .ok_or_else(|| format!("commit {sha} not found in {}", repo.display()))?;
    let parent = format!("{sha}^");
    let mut files = Vec::new();
    for line in listing.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let (old_path, new_path) = match fields.as_slice() {
            [status, path] if status.starts_with('A') => (None, Some(*path)),
            [status, path] if status.starts_with('D') => (Some(*path), None),
            [_, path] => (Some(*path), Some(*path)),
            [_, from, to] => (Some(*from), Some(*to)),
            _ => continue,
        };
        let path = new_path.or(old_path).unwrap_or_default();
        if !path.ends_with(".java") {
            continue;
        }
        let show = |rev: &str, p: Option<&str>| -> Result<Option<String>, String> {
            match p {
                Some(p) => git(repo, &["show", &format!("{rev}:{p}")]),
                None => Ok(None),
            }
        };
        files.push(FileChange {
            path: path.to_string(),
            old: show(&parent, old_path)?,
            new: show(sha, new_path)?,
        });
    }
    Ok(files)
}

#[derive(serde::Deserialize)]
struct Manifest {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    packages: Vec<String>,
    #[serde(default)]
    text: String,
    #[serde(default)]
    commits: Vec<String>,
    files: Vec<ManifestFile>,
}

#[derive(serde::Deserialize)]
struct ManifestFile {
    path: String,
    old: Option<PathBuf>,
    new: Option<PathBuf>,
}

fn read_manifest(path: &Path, advisory: &mut Advisory) -> Result<Vec<FileChange>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let m: Manifest =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    *advisory = Advisory {
        id: m.id,
        aliases: m.aliases,
        packages: m.packages,
        text: m.text,
        commits: m.commits,
    };
    let base = path.parent().unwrap_or(Path::new("."));
    let read = |p: Option<PathBuf>| -> Result<Option<String>, String> {
        p.map(|p| {
            let p = base.join(p);
            std::fs::read(&p)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .map_err(|e| format!("{}: {e}", p.display()))
        })
        .transpose()
    };
    m.files
        .into_iter()
        .map(|f| {
            Ok(FileChange {
                path: f.path,
                old: read(f.old)?,
                new: read(f.new)?,
            })
        })
        .collect()
}
