//! Authentication and private-storage primitives for the reach cache.
//!
//! The cache is a *correctness* input (a verdict is served straight from it), so
//! entries are authenticated with a keyed MAC under a per-user secret and written
//! to owner-only files. This module holds the self-contained crypto/IO building
//! blocks — a pure-Rust HMAC-SHA256 (no C dependency), hex + constant-time compare,
//! the OS CSPRNG read, the MAC-secret store, and the unix permission checks — so
//! [`super`]'s `load`/`store` read as cache logic, not crypto. Everything here is
//! pure and unit-tested; the policy (when to trust/reject) lives in the parent.

use std::path::Path;

use sha2::{Digest, Sha256};

/// Whether a file/dir is writable by group or other (the planting risk). Always
/// `false` off unix (no mode bits).
pub(super) fn world_or_group_writable(md: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o022 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        false
    }
}

/// The per-user MAC secret (32 bytes) in `<dir>/.mac-key`, created 0600 on first
/// use from the OS CSPRNG. `None` if it cannot be read or generated (→ no cache),
/// so a missing secret fails closed to a rebuild rather than an unauthenticated
/// trust. The secret never leaves the private cache dir, so a planter who cannot
/// read it cannot forge a valid tag.
pub(super) fn mac_key(dir: &Path) -> Option<[u8; 32]> {
    let path = dir.join(".mac-key");
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            return Some(k);
        }
    }
    let mut k = [0u8; 32];
    fill_random(&mut k)?;
    create_private_dir(dir).ok()?;
    write_private_bytes(&path, &k).ok()?;
    Some(k)
}

/// Fill `buf` with cryptographically random bytes from the OS. `None` if no CSPRNG
/// is available (→ caching disabled, never a weak key).
fn fill_random(buf: &mut [u8]) -> Option<()> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom").ok()?;
        f.read_exact(buf).ok()?;
        Some(())
    }
    #[cfg(not(unix))]
    {
        let _ = buf;
        None
    }
}

/// HMAC-SHA256 (RFC 2104) over `data` with a 32-byte key, implemented on the
/// pure-Rust `sha2` so the cache MAC adds no C dependency.
pub(super) fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for (i, &k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

/// Lowercase hex of a 32-byte tag.
pub(super) fn encode_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse exactly 64 lowercase/uppercase hex chars into a 32-byte tag; `None` on
/// any malformed input.
pub(super) fn decode_hex32(hex: &[u8]) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.chunks_exact(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Constant-time equality for two 32-byte tags (no early-out timing leak).
pub(super) fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b.iter()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Create `dir` recursively, owner-only (0700 on unix).
pub(super) fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Write `data` to `file`, created owner-only (0600 on unix) — no world-readable
/// window before a later chmod.
pub(super) fn write_private_bytes(file: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(file)?.write_all(data)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn hmac_hex_and_eq_helpers() {
        let key = [7u8; 32];
        let a = hmac_sha256(&key, b"hello");
        assert_eq!(a, hmac_sha256(&key, b"hello"), "deterministic");
        assert_ne!(a, hmac_sha256(&key, b"hellp"), "message changes tag");
        assert_ne!(a, hmac_sha256(&[8u8; 32], b"hello"), "key changes tag");
        // hex round-trips; malformed hex is rejected.
        assert_eq!(decode_hex32(encode_hex(&a).as_bytes()).unwrap(), a);
        assert!(decode_hex32(b"not-hex").is_none());
        assert!(decode_hex32(b"zz").is_none());
        // constant_time_eq agrees with ==.
        assert!(constant_time_eq(&a, &a));
        assert!(!constant_time_eq(&a, &hmac_sha256(&key, b"hellp")));
    }
}
