//! Compiles the vendored mimalloc sources into the crate when the `mimalloc`
//! feature is enabled.

use std::env;

fn main() {
    println!("cargo:rerun-if-changed=mimalloc");
    if env::var_os("CARGO_FEATURE_MIMALLOC").is_none() {
        return;
    }

    let mut build = cc::Build::new();
    build
        .include("mimalloc/include")
        .file("mimalloc/src/static.c")
        .opt_level(3)
        .warnings(false);

    // Skip collecting every heap at exit. That only matters when mimalloc is
    // repeatedly loaded and unloaded as a shared library.
    build.define("MI_SKIP_COLLECT_ON_EXIT", "1");

    // Scale the arena slice for the `large-objects-*` features. The large
    // object limit is eight slices, and the largest enabled feature wins.
    let slice_shift = [("4MB", "19"), ("2MB", "18"), ("1MB", "17")]
        .into_iter()
        .find(|(name, _)| env::var_os(format!("CARGO_FEATURE_LARGE_OBJECTS_{name}")).is_some())
        .map(|(_, shift)| shift);
    if let Some(shift) = slice_shift {
        build.define("MI_ARENA_SLICE_SHIFT", shift);
    }

    // Build with release semantics in every profile (no internal assertions,
    // padding, or guard sampling), so tests see the same size classes and
    // alignment as release binaries.
    build.define("MI_DEBUG", "0").define("NDEBUG", None);

    // Initial-exec TLS makes the thread-local heap lookup a direct load.
    // musl's static TLS block is fixed-size, so a later dlopen can fail under
    // initial-exec. musl builds use local-dynamic, as mimalloc's own musl
    // support does.
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("musl") {
        build
            .define("MI_LIBC_MUSL", "1")
            .flag_if_supported("-ftls-model=local-dynamic");
    } else {
        build.flag_if_supported("-ftls-model=initial-exec");
    }
    build.compile("mimalloc");
}
