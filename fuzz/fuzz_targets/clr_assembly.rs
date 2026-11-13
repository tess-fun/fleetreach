#![no_main]
//! .NET assemblies in an image are attacker-supplied PE files, parsed as data. Whatever they
//! hold, reading one ends with an assembly or an error, and its graph finishes: no panic, no
//! allocation past what the file's own tables can hold.
use fleetreach_clr::graph::{analyze, Role};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fleetreach_clr::read_interfaces(data);
    if let Ok(assembly) = fleetreach_clr::read(data) {
        let inputs = vec![(assembly, Role::App)];
        let _ = analyze(&inputs).reached();
    }
});
