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

    // Processes exit without walking every heap; that collection only
    // matters when mimalloc is repeatedly loaded and unloaded as part of
    // a shared library.
    build.define("MI_SKIP_COLLECT_ON_EXIT", "1");

    // Arena slice size behind the `large-objects-*` features (the limit is
    // eight slices): the largest enabled one wins, so dependents asking for
    // different limits get the largest.
    let slice_shift = [("4M", "19"), ("2M", "18"), ("1M", "17")]
        .into_iter()
        .find(|(name, _)| env::var_os(format!("CARGO_FEATURE_LARGE_OBJECTS_{name}")).is_some())
        .map(|(_, shift)| shift);
    if let Some(shift) = slice_shift {
        build.define("MI_ARENA_SLICE_SHIFT", shift);
    }

    // Production allocator semantics in every cargo profile: no internal
    // assertions, padding, or guard sampling, so size classes and alignment
    // are the same in tests and release binaries.
    build.define("MI_DEBUG", "0").define("NDEBUG", None);

    // Static TLS keeps mimalloc's thread-local heap lookup a direct load.
    // musl's static TLS block is fixed-size, so a later dlopen can fault
    // under initial-exec; mimalloc's own musl support uses local-dynamic.
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("musl") {
        build
            .define("MI_LIBC_MUSL", "1")
            .flag_if_supported("-ftls-model=local-dynamic");
    } else {
        build.flag_if_supported("-ftls-model=initial-exec");
    }
    build.compile("mimalloc");
}
