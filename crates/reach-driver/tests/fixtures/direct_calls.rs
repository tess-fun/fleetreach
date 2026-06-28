// R1 fixture: a generic instantiated at two types, a normal call, and a
// deliberately-unused fn that lazy collection must NOT include.

fn used_directly() -> u32 {
    identity::<u32>(7) + identity::<u8>(3) as u32
}

fn identity<T>(x: T) -> T {
    x
}

#[allow(dead_code)]
fn never_called() {
    println!("unreachable from main");
}

fn main() {
    let _ = used_directly();
}
