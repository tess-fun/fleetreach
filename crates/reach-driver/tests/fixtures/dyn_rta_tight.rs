trait Greet { fn hi(&self) -> u32; }
struct A;
struct B;
impl Greet for A { fn hi(&self) -> u32 { reached() } }
impl Greet for B { fn hi(&self) -> u32 { never_reached() } }
fn reached() -> u32 { 1 }
fn never_reached() -> u32 { 2 }
fn main() {
    let g: &dyn Greet = &A; // only A is ever coerced to a trait object
    let _ = g.hi();
}
