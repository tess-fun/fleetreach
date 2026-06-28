fn target_a() -> u32 { vuln_via_ptr() }
fn target_b() -> u32 { 7 }
fn vuln_via_ptr() -> u32 { 99 }
fn main() {
    let table: [fn() -> u32; 2] = [target_a, target_b];
    let i = std::env::args().count() % 2;
    let _ = table[i]();
}
