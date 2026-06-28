fn main() {
    // The only path to vuln_lib::vulnerable_fn — gated behind a cargo feature.
    #[cfg(feature = "enable-vuln")]
    {
        vuln_lib::trigger(std::env::args().count() as u32);
    }
    println!("{}", std::env::args().count());
}
