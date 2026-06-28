pub fn trigger(n: u32) -> u32 {
    if n > 0 { vulnerable_fn() } else { 0 }
}
pub fn vulnerable_fn() -> u32 {
    42
}
