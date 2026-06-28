// R5 fixture: `vuln` is reachable ONLY through `callback`, which is handed to
// an opaque FFI function. No analyzable (clean) path reaches it → Unknown.
extern "C" {
    fn external_thing(cb: extern "C" fn());
}
extern "C" fn callback() {
    let _ = vuln();
}
fn vuln() -> u32 { 42 }

fn main() {
    unsafe { external_thing(callback); }
}
