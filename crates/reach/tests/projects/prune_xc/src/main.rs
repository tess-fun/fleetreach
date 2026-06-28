fn main() {
    let n = std::env::args().count() as u32;
    let _ = widgets::use_real(n);
    let _ = widgets::use_decoy_direct();
}
