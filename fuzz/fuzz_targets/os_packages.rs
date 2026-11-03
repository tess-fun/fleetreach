#![no_main]
//! The text package databases of an image, which any layer can replace.
use fleetreach_os::packages;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = packages::parse_dpkg_status(data, true);
    let _ = packages::parse_dpkg_status(data, false);
    let _ = packages::parse_apk_installed(data);
    let _ = packages::parse_bottlerocket_inventory(data);
    let _ = packages::parse_module_state(data);
});
