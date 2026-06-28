// Calls only the non-generic `safe`; the generic `vulnerable_generic` is never
// instantiated, so the mono collector never produces a node for it.
fn main() {
    println!("{}", vuln_gen::safe(std::env::args().count() as u32));
}
