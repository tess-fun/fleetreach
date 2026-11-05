//! Reading files from a repo, which is untrusted input. A checkout can hold a symlink to
//! `/dev/zero`, which never ends, or to a file of the machine's owner, so the plain `std::fs`
//! calls are not safe on a path built from a repo's directory.
//!
//! These read only regular files, up to [`MAX_SIZE`], and refuse a path under a repo that
//! resolves outside every repo (a link, or a linked directory on the way). To a caller the
//! refusal is an ordinary read error, which each reader already treats as it treats a missing or
//! unreadable file.

use std::collections::BTreeSet;
use std::fs;
use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// Far above any real manifest. npm's largest lockfiles are tens of megabytes.
pub const MAX_SIZE: u64 = 512 * 1024 * 1024;

static ROOTS: RwLock<BTreeSet<PathBuf>> = RwLock::new(BTreeSet::new());

/// Adds the directories of a fleet's repos, as written and as they resolve.
pub fn confine<'a>(repos: impl IntoIterator<Item = &'a Path>) {
    let Ok(mut roots) = ROOTS.write() else {
        return;
    };
    for repo in repos {
        roots.extend(std::path::absolute(repo));
        roots.extend(fs::canonicalize(repo));
    }
}

/// Whether a read of `path` that resolves to `real` stays inside: a path under no root is the
/// machine's own (a cache, a registry directory) and is not the repo's to redirect.
fn stays_inside(roots: &BTreeSet<PathBuf>, path: &Path, real: &Path) -> bool {
    // By ancestor, not by root: a fleet has thousands of roots and a scan reads every manifest.
    let under = |p: &Path| p.ancestors().any(|dir| roots.contains(dir));
    !under(path) || under(real)
}

fn check(path: &Path) -> Result<()> {
    let refuse = |why: &str| Error::new(ErrorKind::InvalidInput, why.to_string());
    let meta = fs::metadata(path)?;
    if !meta.is_file() {
        return Err(refuse("not a regular file"));
    }
    if meta.len() > MAX_SIZE {
        return Err(refuse("too large to be a manifest"));
    }
    if let Ok(roots) = ROOTS.read() {
        let (written, real) = (std::path::absolute(path)?, fs::canonicalize(path)?);
        if !roots.is_empty() && !stays_inside(&roots, &written, &real) {
            return Err(refuse("resolves outside the repo"));
        }
    }
    Ok(())
}

/// [`std::fs::read`] for a repo's file.
///
/// # Errors
///
/// As [`std::fs::read`], and for a path this module refuses.
pub fn read(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    check(path.as_ref())?;
    fs::read(path)
}

/// [`std::fs::read_to_string`] for a repo's file.
///
/// # Errors
///
/// As [`std::fs::read_to_string`], and for a path this module refuses.
pub fn read_to_string(path: impl AsRef<Path>) -> Result<String> {
    check(path.as_ref())?;
    fs::read_to_string(path)
}

/// [`std::fs::File::open`] for a repo's file.
///
/// # Errors
///
/// As [`std::fs::File::open`], and for a path this module refuses.
pub fn open(path: impl AsRef<Path>) -> Result<fs::File> {
    check(path.as_ref())?;
    fs::File::open(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn a_device_is_not_read() {
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let link = dir.path().join("Cargo.toml");
            std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
            let refused = read_to_string(&link).unwrap_err();
            assert_eq!(refused.kind(), ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn a_directory_and_a_missing_file_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(dir.path()).is_err());
        let missing = read(dir.path().join("x")).unwrap_err();
        assert_eq!(missing.kind(), ErrorKind::NotFound);
    }

    #[test]
    fn a_path_under_a_repo_must_resolve_under_one() {
        let roots = BTreeSet::from([PathBuf::from("/fleet/a"), PathBuf::from("/fleet/b")]);
        let file = Path::new("/fleet/a/Cargo.toml");
        assert!(stays_inside(&roots, file, file));
        assert!(stays_inside(&roots, file, Path::new("/fleet/b/Cargo.toml")));
        assert!(!stays_inside(
            &roots,
            file,
            Path::new("/home/me/.ssh/config")
        ));
        // The machine's own files are not the repo's to redirect.
        let cache = Path::new("/home/me/.cargo/registry/x/Cargo.toml");
        assert!(stays_inside(
            &roots,
            cache,
            Path::new("/elsewhere/Cargo.toml")
        ));
    }
}
