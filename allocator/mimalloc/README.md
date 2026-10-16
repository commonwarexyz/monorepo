# Vendored mimalloc

This directory is an unmodified copy of the `src` and `include` trees of
[mimalloc](https://github.com/microsoft/mimalloc) at the tag recorded in
`VERSION`, plus its `LICENSE`. `build.rs` compiles `src/static.c` (the
upstream amalgamation) into the `commonware-allocator` crate, and
`src/mimalloc/ffi.rs` declares the handful of functions the wrapper uses.

To update, download the release tarball for the new tag, replace `src`,
`include`, and `LICENSE` with the copies from the tarball, update `VERSION`,
and run the crate's tests: they check the linked version and exercise every
binding, and one derives the option enum values and alignment constant the
wrapper mirrors from the new headers, so a renumbering is caught there.
