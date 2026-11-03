#![no_main]
//! An image's rpm database is attacker-supplied bytes read by our own SQLite, Berkeley DB and
//! NDB readers. Whatever they hold, the readers return packages or an error: no panic, and no
//! loop that does not end (cycles of pages must be caught).
use fleetreach_os::rpmdb::{read, Backend};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let backend = match pick % 3 {
        0 => Backend::Sqlite,
        1 => Backend::BerkeleyDb,
        _ => Backend::Ndb,
    };
    // The high bits say how much of the tail is a write-ahead log.
    let wal = usize::from(pick >> 2) * rest.len() / 64;
    let (file, wal) = rest.split_at(rest.len() - wal);
    let _ = read(backend, file, (!wal.is_empty()).then_some(wal));
});
