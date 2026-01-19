# commonware-macros

[![Crates.io](https://img.shields.io/crates/v/commonware-macros.svg)](https://crates.io/crates/commonware-macros)
[![Docs.rs](https://docs.rs/commonware-macros/badge.svg)](https://docs.rs/commonware-macros)

Augment the development of primitives with procedural macros.

## Status

`commonware-macros` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Macros

### `#[ready(N)]`

Marks an item with a readiness level (0-4). When building with `RUSTFLAGS="--cfg min_readiness_N"`, items with readiness less than N are excluded.

```rust
use commonware_macros::ready;

#[ready(2)]
pub mod stable_api {
    // All items in this module are at readiness level 2
}
```

Apply at whatever granularity makes sense (individual items, impl blocks, or modules). Building with `min_readiness_3` will exclude items marked `#[ready(0)]`, `#[ready(1)]`, or `#[ready(2)]`.

See the [Readiness section](https://github.com/commonwarexyz/monorepo#readiness) in the main README for level definitions.

### `#[test_async]`

Run a test function asynchronously without binding to a particular executor.

```rust
use commonware_macros::test_async;

#[test_async]
async fn test_async_fn() {
    assert_eq!(2 + 2, 4);
}
```

### `select!`

A re-export of `futures::select_biased!` for consistent select behavior across the codebase.