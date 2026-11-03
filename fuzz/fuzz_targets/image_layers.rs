#![no_main]
//! Layers merge attacker-supplied tar streams. Random bytes rarely reach the merge, so the
//! input is a program: each 4-byte step adds one entry (file, directory, symlink, hard link or
//! whiteout) over a handful of names, and a step can start a new layer. Paths that collide,
//! links that cycle and whiteouts of anything are the point. Every path is then looked up.
//! Odd inputs go to the tar reader as they are, so its parsing is covered as well.
use fleetreach_os::image::ImageFs;
use libfuzzer_sys::fuzz_target;

const NAMES: [&str; 8] = ["a", "b", "c", "a/b", "a/b/c", "b/c", ".wh.b", "a/.wh..wh..opq"];
const TARGETS: [&str; 8] = ["a", "b", "/a/b", "../a", "a/b/c", "c", "..", "b/../a"];

fn entry(out: &mut Vec<u8>, path: &str, kind: u8, link: &str, body: &[u8]) {
    let mut h = [0u8; 512];
    h[..path.len()].copy_from_slice(path.as_bytes());
    h[100..107].copy_from_slice(b"0000644");
    let size = format!("{:011o}", body.len());
    h[124..135].copy_from_slice(size.as_bytes());
    h[156] = kind;
    h[157..157 + link.len()].copy_from_slice(link.as_bytes());
    h[257..263].copy_from_slice(b"ustar\0");
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(body);
    out.resize(out.len().div_ceil(512) * 512, 0);
}

fuzz_target!(|data: &[u8]| {
    if data.len() % 2 == 1 {
        let _ = ImageFs::from_layers(&[data], &|_| true);
        return;
    }
    let mut layers: Vec<Vec<u8>> = vec![Vec::new()];
    for step in data.chunks_exact(4) {
        let (path, target) = (NAMES[usize::from(step[0] % 8)], TARGETS[usize::from(step[1] % 8)]);
        let tar = layers.last_mut().expect("never empty");
        match step[2] % 5 {
            0 => entry(tar, path, b'0', "", &step[3..]),
            1 => entry(tar, path, b'5', "", b""),
            2 => entry(tar, path, b'2', target, b""),
            3 => entry(tar, path, b'1', target, b""),
            _ => entry(tar, target.trim_start_matches('/'), b'0', "", b""),
        }
        if step[3] % 4 == 0 {
            layers.push(Vec::new());
        }
    }
    for tar in &mut layers {
        tar.resize(tar.len() + 1024, 0);
    }
    let layers: Vec<&[u8]> = layers.iter().map(Vec::as_slice).collect();
    let Ok(fs) = ImageFs::from_layers(&layers, &|_| true) else {
        return;
    };
    for path in NAMES.iter().chain(&TARGETS) {
        let _ = fs.canonical(path);
        let _ = fs.read(path);
        let _ = fs.is_file(path);
        let _ = fs.list_dir(path);
    }
    let _ = fs.files().count();
});
