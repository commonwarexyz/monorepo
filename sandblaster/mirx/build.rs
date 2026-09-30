//! Links the driver against the pinned nightly's `librustc_driver` by an
//! rpath, so it runs without `DYLD_LIBRARY_PATH`/`LD_LIBRARY_PATH`.
fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let out = std::process::Command::new(rustc).args(["--print", "sysroot"]).output().expect("rustc --print sysroot");
    let sysroot = String::from_utf8(out.stdout).expect("utf-8 sysroot");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}/lib", sysroot.trim());
}
