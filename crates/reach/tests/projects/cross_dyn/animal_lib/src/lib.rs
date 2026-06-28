pub trait Animal {
    fn speak(&self) -> u32;
}
pub struct Dog;
impl Animal for Dog {
    fn speak(&self) -> u32 { lib_vuln() }
}
pub fn lib_vuln() -> u32 { 42 }
// The coercion to `dyn Animal` happens HERE (in the lib), so the vtable method
// <Dog as Animal>::speak is collected in the lib's fragment — not the bin's.
pub fn make(_n: u32) -> Box<dyn Animal> {
    Box::new(Dog)
}
