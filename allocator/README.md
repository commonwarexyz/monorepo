# commonware-allocator

[![Crates.io](https://img.shields.io/crates/v/commonware-allocator.svg)](https://crates.io/crates/commonware-allocator)
[![Docs.rs](https://docs.rs/commonware-allocator/badge.svg)](https://docs.rs/commonware-allocator)

Configure and observe the global allocator.

The `mimalloc` module builds a vendored copy of [mimalloc](https://github.com/microsoft/mimalloc)
(MIT licensed; version in `mimalloc/VERSION`) and declares its own bindings, so it replaces
both the `mimalloc` and `libmimalloc-sys` crates: link it as the global allocator, apply a
configuration from the binary instead of environment variables, and read allocator statistics.
The `large-objects-*` features raise the largest allocation served from thread-local pages
(512 KiB by default) by building mimalloc with larger pages.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.
