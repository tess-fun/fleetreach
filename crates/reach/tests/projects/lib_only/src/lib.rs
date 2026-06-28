// No `main`. The audit entry surface is the public API.
pub fn public_api(n: u32) -> u32 {
    if n > 0 { internal_vuln() } else { 0 }
}
fn internal_vuln() -> u32 { 42 }

// A private fn reachable from nothing public — must come out NotReachable.
#[allow(dead_code)]
fn orphan() -> u32 { internal_vuln() }
