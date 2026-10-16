//! Compiles the vendored mimalloc sources into the crate when the `mimalloc`
//! feature is enabled.

use std::env;

fn main() {
    println!("cargo:rerun-if-changed=mimalloc");
    println!("cargo:rerun-if-changed=src/mimalloc/options.c");
    if env::var_os("CARGO_FEATURE_MIMALLOC").is_none() {
        return;
    }

    let mut build = cc::Build::new();
    build
        .include("mimalloc/include")
        .include("mimalloc/src")
        .file("mimalloc/src/static.c")
        .file("src/mimalloc/options.c")
        .opt_level(3)
        .warnings(false)
        .flag_if_supported("-Wno-error=date-time")
        // Processes exit without walking every heap; that collection only
        // matters when mimalloc is repeatedly loaded and unloaded as part of
        // a shared library.
        .define("MI_SKIP_COLLECT_ON_EXIT", "1");

    if env::var_os("CARGO_FEATURE_DEBUG").is_some() {
        // Internal assertions, guard bytes, freed-memory poisoning, and
        // double-free detection.
        build.define("MI_DEBUG", "3").define("MI_SHOW_ERRORS", "1");
    } else {
        // Production allocator semantics in every cargo profile.
        build
            .define("MI_DEBUG", "0")
            .define("MI_BUILD_RELEASE", None)
            .define("NDEBUG", None);
    }

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
