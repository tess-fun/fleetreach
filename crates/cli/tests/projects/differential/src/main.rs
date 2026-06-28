// `boom` is the advisory's "affected function". Its NAME appears in this source
// (the grep heuristic will match), but it is only address-taken, never CALLED —
// so static reachability soundly proves it NotReachable.
fn boom() -> u32 { 42 }
fn safe() -> u32 { 1 }
fn main() {
    let _unused: fn() -> u32 = boom; // address-taken (collected) but never invoked
    std::hint::black_box(_unused);
    let _ = safe();
}
