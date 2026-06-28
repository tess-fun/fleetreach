// R4 fixture: dyn dispatch to two impls. `vulnerable_dog` is reachable only
// through <Dog as Animal>::speak via a virtual call.
trait Animal {
    fn speak(&self) -> u32;
}
struct Dog;
struct Cat;
impl Animal for Dog {
    fn speak(&self) -> u32 { vulnerable_dog() }
}
impl Animal for Cat {
    fn speak(&self) -> u32 { 2 }
}
fn vulnerable_dog() -> u32 { 42 }

fn make(which: bool) -> Box<dyn Animal> {
    if which { Box::new(Dog) } else { Box::new(Cat) }
}
fn main() {
    let a = make(std::env::args().count() % 2 == 0);
    let _ = a.speak();
}
