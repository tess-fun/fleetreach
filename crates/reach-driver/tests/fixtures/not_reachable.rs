// Soundness-corpus fixture for the dangerous direction. `cold_fn` is COLLECTED
// (its address is taken) but never called — so it must come out NotReachable,
// not Unknown and certainly not falsely tied to a path. `warm_fn` is reachable.
fn warm_fn() -> u32 { 1 }
fn cold_fn() -> u32 { 2 }
fn main() {
    let _ = warm_fn();
    let p: fn() -> u32 = cold_fn; // address-taken (collected) but never invoked
    std::hint::black_box(p);
}
