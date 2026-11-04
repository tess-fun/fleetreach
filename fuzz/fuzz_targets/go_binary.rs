#![no_main]
//! Go binaries in an image are attacker-supplied ELF files, and their build info holds offsets
//! and lengths read from the file. A random file rarely has the magic, so the input is also
//! tried behind a one-segment ELF and the build info's magic.
use fleetreach_os::gobin;
use libfuzzer_sys::fuzz_target;

const MAGIC: &[u8] = b"\xff Go buildinf:";

fuzz_target!(|data: &[u8]| {
    let _ = gobin::read(data);
    let mut elf = vec![0_u8; 128];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
    elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1_u32.to_le_bytes());
    elf.extend_from_slice(MAGIC);
    elf.resize(elf.len().next_multiple_of(16), 0);
    elf.extend_from_slice(data);
    let size = elf.len() as u64;
    elf[96..104].copy_from_slice(&size.to_le_bytes());
    let _ = gobin::read(&elf);
});
