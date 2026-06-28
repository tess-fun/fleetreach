fn main() {
    let a = animal_lib::make(std::env::args().count() as u32);
    let _ = a.speak();
}
