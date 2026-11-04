#![no_main]
//! Rust binaries in an image are attacker-supplied ELF files, and their section table holds
//! offsets and lengths read from the file, in front of a zlib stream and JSON. A random file
//! has neither, so the input is also tried as the section of a minimal ELF, raw and compressed.
use std::io::Write;

use fleetreach_os::rustbin;
use libfuzzer_sys::fuzz_target;

fn elf(section: &[u8]) -> Vec<u8> {
    let names = b"\0.shstrtab\0.dep-v0\0";
    let strings_at = 64_u64;
    let body_at = strings_at + names.len() as u64;
    let table = body_at + section.len() as u64;
    let mut out = vec![0_u8; 64];
    out[..4].copy_from_slice(b"\x7fELF");
    out[4] = 2;
    out[5] = 1;
    out[40..48].copy_from_slice(&table.to_le_bytes());
    out[58..60].copy_from_slice(&64_u16.to_le_bytes());
    out[60..62].copy_from_slice(&3_u16.to_le_bytes());
    out[62..64].copy_from_slice(&1_u16.to_le_bytes());
    out.extend_from_slice(names);
    out.extend_from_slice(section);
    for (name, offset, size) in [
        (0_u32, 0_u64, 0_u64),
        (1, strings_at, names.len() as u64),
        (11, body_at, section.len() as u64),
    ] {
        let mut h = [0_u8; 64];
        h[..4].copy_from_slice(&name.to_le_bytes());
        h[24..32].copy_from_slice(&offset.to_le_bytes());
        h[32..40].copy_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&h);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let _ = rustbin::read(data);
    let _ = rustbin::read(&elf(data));
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    if z.write_all(data).is_ok() {
        if let Ok(compressed) = z.finish() {
            let _ = rustbin::read(&elf(&compressed));
        }
    }
});
