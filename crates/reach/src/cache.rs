//! The reach graph cache.
//!
//! The whole-closure graph depends only on `(Cargo.lock, features, toolchain,
//! schema, repo source)` — not on which sinks are queried — so it is cached and
//! only sink resolution re-runs on a hit. The cache is a *correctness* input (a
//! verdict can be served straight from it), so it is treated as untrusted at
//! rest: a local attacker must not be able to plant a graph that forges a
//! `NotReachable`. Three defenses enforce that:
//!
//! 1. **Keyed MAC.** Every entry is authenticated with HMAC-SHA256 under a
//!    per-user secret stored 0600 in the cache dir. `load` recomputes the tag and
//!    rejects (→ rebuild) any entry that does not verify, so a graph written by
//!    anyone who cannot read the secret is ignored.
//! 2. **Private location only.** The cache lives under `XDG_CACHE_HOME`/`HOME`
//!    and *never* falls back to the world-/sandbox-writable system temp dir;
//!    caching is simply disabled when no private home exists.
//! 3. **Perm checks.** The dir/file are refused at read time if they are a
//!    symlink or are group/other-writable.
//!
//! Every check fails *closed* — to a rebuild, never to a served `NotReachable`.

use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

mod integrity;
use integrity::{
    constant_time_eq, create_private_dir, decode_hex32, encode_hex, hmac_sha256, mac_key,
    world_or_group_writable, write_private_bytes,
};

use crate::model::CallGraph;
use crate::{parse_graph, BuildConfig, SUPPORTED_SCHEMA};

/// Cache generation, independent of the wire [`SUPPORTED_SCHEMA`]. Bump it when a
/// *consumer-side* (merge/analyze) graph-producing change is additive on the wire
/// (old entries still parse and are sound) yet a stale entry would be less precise
/// — so old entries are retired without a schema bump that would invalidate the
/// committed fixtures. A *driver-side* change needs no bump: `driver_fingerprint`
/// already invalidates entries whenever the driver binary is rebuilt.
/// Gen 2: the merged graph began carrying `generic_fns`/`scanned_crates`, which
/// let an uninstantiated-generic sink resolve to `NotReachable` instead of the
/// (still sound) `Unknown` a pre-gen-2 entry would yield.
/// Gen 3: entries became MAC-authenticated (a tag-prefixed file format) and the
/// key began covering `RUSTFLAGS`/`.cargo/config`; old plain-JSON entries no
/// longer verify and are rebuilt.
/// Gen 4: `merge` now wires the global opaque frontier (H-1), so a pre-gen-4
/// cached graph could carry a false `NotReachable` for a cross-crate opaque sink
/// — retire it. (The driver-fingerprint already invalidates on a rebuilt driver;
/// this covers a consumer-side rebuild against an old cached graph.)
const CACHE_EPOCH: u32 = 4;

/// Cache key from the inputs the graph depends on; `None` (⇒ no caching) when
/// there is no `Cargo.lock`, so the dependency closure is unpinned.
///
/// A source edit (same lock) changes the graph, so the repo's `.rs` files are
/// hashed too; a different feature set is a different graph, so features are in
/// the key. The graph is also a product of the *driver* that emitted it and the
/// *target* it was built for, so both are folded in: a rebuilt driver (new graph
/// logic, like added edges) or a different host triple must not be served a stale
/// graph — that could be a false `NotReachable`. Miss any of these and a stale
/// graph could survive. Path deps *outside* the manifest dir are not
/// fingerprinted — a narrow gap.
pub fn key(manifest_dir: &Path, build: &BuildConfig, driver: &Path) -> Option<String> {
    let lock = std::fs::read(manifest_dir.join("Cargo.lock")).ok()?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    lock.hash(&mut hasher);
    build.toolchain.hash(&mut hasher);
    build.features.hash_into(&mut hasher);
    SUPPORTED_SCHEMA.hash(&mut hasher);
    CACHE_EPOCH.hash(&mut hasher);
    driver_fingerprint(driver).hash(&mut hasher);
    host_target().hash(&mut hasher);
    // RUSTFLAGS / encoded rustflags change codegen and `cfg`, so they change which
    // code (and which call edges) exist — a different value is a different graph.
    std::env::var_os("RUSTFLAGS").hash(&mut hasher);
    std::env::var_os("CARGO_ENCODED_RUSTFLAGS").hash(&mut hasher);
    // A repo-local `.cargo/config(.toml)` can set rustflags / cfg / target, which
    // the `.rs` source hash does not capture. Fold its bytes in (the strongest leg
    // of the build-config gap; parent-dir / CARGO_HOME configs remain a noted gap).
    for cfg in [".cargo/config.toml", ".cargo/config"] {
        if let Ok(bytes) = std::fs::read(manifest_dir.join(cfg)) {
            bytes.hash(&mut hasher);
        }
    }
    hash_repo_sources(manifest_dir, &mut hasher);
    Some(format!("reach-{:016x}", hasher.finish()))
}

/// A cheap fingerprint of the driver binary: `(len, mtime)`. A rebuild rewrites the
/// file, changing both, so a graph produced by an older driver is never served to a
/// newer one — the same trust model cargo uses for its own rebuild detection. This
/// is the *automatic* counterpart to the manual [`CACHE_EPOCH`] bump: an additive
/// driver change invalidates stale entries without a hand edit. Falls back to a
/// constant when the driver cannot be stat'd (the build that follows will fail
/// → `Unknown`, never a false hit).
fn driver_fingerprint(driver: &Path) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    if let Ok(meta) = std::fs::metadata(driver) {
        meta.len().hash(&mut h);
        if let Ok(mtime) = meta.modified() {
            if let Ok(since) = mtime.duration_since(std::time::UNIX_EPOCH) {
                since.as_nanos().hash(&mut h);
            }
        }
    }
    h.finish()
}

/// The host target triple the closure is built for (no `--target` is passed, so
/// it is always the host default), from `rustc -vV`. Memoized: one process spawn
/// per run, not one per repo. Empty if `rustc` cannot be queried — the cache then
/// just omits the target, no worse than before. Folding it in keeps a cache shared
/// across hosts (or a future `--target`) from colliding two different graphs.
fn host_target() -> &'static str {
    static HOST: OnceLock<String> = OnceLock::new();
    HOST.get_or_init(|| {
        std::process::Command::new("rustc")
            .arg("-vV")
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("host: ").map(str::to_string))
            })
            .unwrap_or_default()
    })
}

/// The cached graph for `key`, if present, MAC-authentic, parseable, and
/// schema-compatible. Any failure (missing/poisoned/tampered entry, unsafe perms,
/// no MAC secret) returns `None` so the caller rebuilds — never a served verdict.
pub fn load(key: &str) -> Option<CallGraph> {
    let dir = private_dir()?;
    let mac = mac_key(&dir)?;
    let file = dir.join(format!("{key}.json"));
    // Refuse a symlinked or group/other-writable entry: someone else must not be
    // able to swap in a graph we would trust.
    let md = std::fs::symlink_metadata(&file).ok()?;
    if md.file_type().is_symlink()
        || world_or_group_writable(&md)
        || md.len() > crate::MAX_GRAPH_BYTES
    {
        return None;
    }
    let raw = std::fs::read(&file).ok()?;
    // Format: <64 hex chars of HMAC-SHA256 tag>\n<graph JSON>.
    let nl = raw.iter().position(|&b| b == b'\n')?;
    let (tag_hex, rest) = raw.split_at(nl);
    let json = &rest[1..];
    let want = hmac_sha256(&mac, json);
    let got = decode_hex32(tag_hex)?;
    if !constant_time_eq(&got, &want) {
        return None;
    }
    let graph = parse_graph(std::str::from_utf8(json).ok()?).ok()?;
    (graph.schema == SUPPORTED_SCHEMA).then_some(graph)
}

/// Best-effort store of `graph` under `key`: MAC-authenticated, in a private
/// (0700) dir as a private (0600) file. No-op if there is no private cache home
/// or no MAC secret can be established.
pub fn store(key: &str, graph: &CallGraph) {
    let Some(dir) = private_dir() else {
        return;
    };
    if create_private_dir(&dir).is_err() {
        return;
    }
    let Some(mac) = mac_key(&dir) else {
        return;
    };
    let Ok(json) = serde_json::to_string(graph) else {
        return;
    };
    let tag = hmac_sha256(&mac, json.as_bytes());
    let mut content = Vec::with_capacity(65 + json.len());
    content.extend_from_slice(encode_hex(&tag).as_bytes());
    content.push(b'\n');
    content.extend_from_slice(json.as_bytes());
    let _ = write_private_bytes(&dir.join(format!("{key}.json")), &content);
}

/// The private cache directory, or `None` when caching must be disabled. Unlike a
/// scratch cache, this is correctness-bearing, so it must live somewhere only the
/// current user can write: `XDG_CACHE_HOME` or `HOME/.cache`. It deliberately does
/// **not** fall back to the system temp dir — that dir is granted to the untrusted
/// build by the sandbox, which would let an analyzed repo plant a forged graph.
/// An existing dir that is a symlink or is group/other-writable is also refused.
fn dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    Some(base.join("fleetreach").join("reach"))
}

/// [`dir`], but `None` if it exists and is unsafe (a symlink, or group/other-
/// writable). A not-yet-existing dir is allowed: `create_private_dir` makes it 0700.
fn private_dir() -> Option<PathBuf> {
    let d = dir()?;
    match std::fs::symlink_metadata(&d) {
        Ok(md) if md.file_type().is_symlink() => None,
        Ok(md) if !md.is_dir() || world_or_group_writable(&md) => None,
        _ => Some(d),
    }
}

/// Hash the path + content of every `.rs` file under `dir` (sorted, so
/// deterministic), excluding `target/` and hidden dirs. Hardened against hostile
/// layouts: no symlink following (loop-safe), bounded depth + file count, and an
/// oversized file is hashed by length only.
fn hash_repo_sources(dir: &Path, hasher: &mut impl Hasher) {
    const MAX_DEPTH: u32 = 64;
    const MAX_FILES: usize = 200_000;
    const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

    let mut files: Vec<PathBuf> = Vec::new();
    collect_rs_files(dir, 0, MAX_DEPTH, MAX_FILES, &mut files);
    files.sort();
    for file in files {
        file.to_string_lossy().hash(hasher);
        match std::fs::metadata(&file) {
            Ok(meta) if meta.len() <= MAX_FILE_BYTES => {
                if let Ok(bytes) = std::fs::read(&file) {
                    bytes.hash(hasher);
                }
            }
            Ok(meta) => meta.len().hash(hasher),
            Err(_) => {}
        }
    }
}

fn collect_rs_files(
    dir: &Path,
    depth: u32,
    max_depth: u32,
    max_files: usize,
    out: &mut Vec<PathBuf>,
) {
    if depth > max_depth || out.len() >= max_files {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        // `file_type()` from a dir entry does not follow symlinks, so a symlink
        // is classified as such and never recursed into — this is the loop guard.
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if ft.is_dir() {
            if name != "target" && !name.starts_with('.') {
                collect_rs_files(&path, depth + 1, max_depth, max_files, out);
            }
        } else if ft.is_file() && path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
            if out.len() >= max_files {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::FeatureSelection;

    #[test]
    fn key_tracks_repo_source() {
        let dir = std::env::temp_dir().join(format!("reach-keytest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("Cargo.lock"), b"lock").unwrap();
        std::fs::write(dir.join("src/main.rs"), b"fn main() {}").unwrap();
        let driver = dir.join("driver");
        std::fs::write(&driver, b"driver-v1").unwrap();

        let cfg = BuildConfig::new("tc");
        let k1 = key(&dir, &cfg, &driver).unwrap();

        // A source edit (same lock) must change the key.
        std::fs::write(dir.join("src/main.rs"), b"fn main() { boom(); }").unwrap();
        let k2 = key(&dir, &cfg, &driver).unwrap();
        assert_ne!(k1, k2, "source edit must invalidate the cache");

        // Identical content ⇒ identical key (a real hit).
        std::fs::write(dir.join("src/main.rs"), b"fn main() { boom(); }").unwrap();
        assert_eq!(key(&dir, &cfg, &driver).unwrap(), k2);

        // No lockfile ⇒ no caching.
        let nolock = std::env::temp_dir().join(format!("reach-keytest2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&nolock);
        std::fs::create_dir_all(&nolock).unwrap();
        assert!(key(&nolock, &cfg, &driver).is_none());

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&nolock);
    }

    #[test]
    fn key_tracks_driver_binary() {
        // A rebuilt driver (different bytes ⇒ different len) must invalidate the
        // cache: a graph from an older driver could be a false NotReachable.
        let dir = std::env::temp_dir().join(format!("reach-driverkey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("Cargo.lock"), b"lock").unwrap();
        std::fs::write(dir.join("src/main.rs"), b"fn main() {}").unwrap();

        let cfg = BuildConfig::new("tc");
        let driver = dir.join("driver");
        std::fs::write(&driver, b"driver-v1").unwrap();
        let k1 = key(&dir, &cfg, &driver).unwrap();

        // Rewrite the driver with a different length ⇒ different fingerprint.
        std::fs::write(&driver, b"driver-version-2-longer").unwrap();
        let k2 = key(&dir, &cfg, &driver).unwrap();
        assert_ne!(k1, k2, "a rebuilt driver must invalidate the cache");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_tracks_features() {
        let dir = std::env::temp_dir().join(format!("reach-featkey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("Cargo.lock"), b"lock").unwrap();
        std::fs::write(dir.join("src/main.rs"), b"fn main() {}").unwrap();
        let driver = dir.join("driver");
        std::fs::write(&driver, b"driver-v1").unwrap();

        let base = key(&dir, &BuildConfig::new("tc"), &driver).unwrap();

        let with_feat = BuildConfig {
            features: FeatureSelection {
                features: vec!["extra".into()],
                ..Default::default()
            },
            ..BuildConfig::new("tc")
        };
        assert_ne!(base, key(&dir, &with_feat, &driver).unwrap());

        let no_default = BuildConfig {
            features: FeatureSelection {
                no_default_features: true,
                ..Default::default()
            },
            ..BuildConfig::new("tc")
        };
        assert_ne!(base, key(&dir, &no_default, &driver).unwrap());
        assert_ne!(
            key(&dir, &with_feat, &driver).unwrap(),
            key(&dir, &no_default, &driver).unwrap()
        );

        // Feature order / duplicates don't matter — the key is canonical.
        let ab = BuildConfig {
            features: FeatureSelection {
                features: vec!["a".into(), "b".into()],
                ..Default::default()
            },
            ..BuildConfig::new("tc")
        };
        let ba = BuildConfig {
            features: FeatureSelection {
                features: vec!["b".into(), "a".into(), "a".into()],
                ..Default::default()
            },
            ..BuildConfig::new("tc")
        };
        assert_eq!(
            key(&dir, &ab, &driver).unwrap(),
            key(&dir, &ba, &driver).unwrap()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // One test owns all process-global env mutation (HOME/XDG_CACHE_HOME) so the
    // two cases below can't race each other or other tests.
    #[test]
    fn cache_integrity_and_private_home() {
        let saved_xdg = std::env::var_os("XDG_CACHE_HOME");
        let saved_home = std::env::var_os("HOME");

        // (1) No private home => caching disabled; NEVER fall back to temp.
        std::env::remove_var("XDG_CACHE_HOME");
        std::env::remove_var("HOME");
        assert!(
            dir().is_none(),
            "no private home => no cache dir (never temp)"
        );

        // (2) Round-trip authenticity + tamper rejection under a private home.
        let home = std::env::temp_dir().join(format!("reach-mac-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::env::set_var("XDG_CACHE_HOME", &home);

        let g = parse_graph(
            r#"{"schema":2,"nodes":[{"id":0,"label":"main","symbol":"s0"}],"edges":[],"roots":[0],"sinks":[]}"#,
        )
        .unwrap();
        let k = "reach-deadbeef";

        assert!(load(k).is_none(), "empty cache is a miss");
        store(k, &g);
        assert_eq!(load(k).expect("authentic entry loads").nodes.len(), 1);

        // Tamper with the JSON body, keeping the old tag → MAC must reject (rebuild).
        let file = dir().unwrap().join(format!("{k}.json"));
        let raw = std::fs::read(&file).unwrap();
        let nl = raw.iter().position(|&b| b == b'\n').unwrap();
        let mut forged = raw[..=nl].to_vec(); // original tag + newline
        forged.extend_from_slice(br#"{"schema":2,"nodes":[],"edges":[]}"#);
        std::fs::write(&file, &forged).unwrap();
        assert!(
            load(k).is_none(),
            "a tampered body must fail the MAC and be rejected"
        );

        // Restore the environment for any other test in this binary.
        let _ = std::fs::remove_dir_all(&home);
        std::env::remove_var("XDG_CACHE_HOME");
        std::env::remove_var("HOME");
        if let Some(v) = saved_xdg {
            std::env::set_var("XDG_CACHE_HOME", v);
        }
        if let Some(v) = saved_home {
            std::env::set_var("HOME", v);
        }
    }
}
