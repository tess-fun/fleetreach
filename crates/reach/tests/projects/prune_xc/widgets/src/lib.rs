pub trait Draw {
    fn draw(&self) -> u32;
}
pub struct Real;
pub struct Decoy;
impl Draw for Real {
    fn draw(&self) -> u32 {
        real_vuln()
    }
}
impl Draw for Decoy {
    fn draw(&self) -> u32 {
        decoy_vuln()
    }
}
pub fn real_vuln() -> u32 {
    1
}
pub fn decoy_vuln() -> u32 {
    2
}
// Real IS coerced to `dyn Draw` here → its vtable (and Real::draw) is collected
// as a coercion; the dyn call reaches it.
pub fn use_real(n: u32) -> u32 {
    let r = Real;
    let d: &dyn Draw = &r;
    d.draw() + n
}
// Decoy::draw is collected only via a DIRECT call — Decoy is never coerced to
// `dyn Draw`. So `dyn Draw::draw` must NOT resolve to Decoy::draw (the prune),
// yet decoy_vuln stays reachable through this direct edge.
pub fn use_decoy_direct() -> u32 {
    Decoy.draw()
}
