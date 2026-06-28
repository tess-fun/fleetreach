// Soundness guard for any future coercion-tracked RTA prune.
//
// `B` implements `T` (so `<B as T>::m` is a virtual target of `dyn T::m`), but
// `B` is NEVER coerced to `dyn T` — its `m` is collected only because of a
// DIRECT call `B.m()`. A coercion-tracked refinement may legitimately drop the
// over-approximating `dyn T -> <B as T>::m` virtual edge, but `direct_only` must
// remain Reachable through the *direct* edge from `main`. If a prune ever makes
// it NotReachable, that is a soundness violation (spec §1).
trait T {
    fn m(&self) -> u32;
}
struct A;
struct B;
impl T for A {
    fn m(&self) -> u32 {
        via_dyn()
    }
}
impl T for B {
    fn m(&self) -> u32 {
        direct_only()
    }
}
fn via_dyn() -> u32 {
    1
}
fn direct_only() -> u32 {
    2
}
fn main() {
    let d: &dyn T = &A; // only A is coerced to the trait object
    let _ = d.m();
    let _ = B.m(); // B reached by a direct call, never via dyn
}
