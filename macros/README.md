# commonware-macros

[![Crates.io](https://img.shields.io/crates/v/commonware-macros.svg)](https://crates.io/crates/commonware-macros)
[![Docs.rs](https://docs.rs/commonware-macros/badge.svg)](https://docs.rs/commonware-macros)

Augment the development of primitives with procedural macros.

## Status

`commonware-macros` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Macros

### `#[ready(N)]`

Marks a public item with a readiness level (0-4). This annotation:

1. Adds a doc comment showing the readiness level with a link to the definition
2. Enables compile-time filtering via `--cfg min_readiness_N`

```rust
use commonware_macros::ready;

#[ready(2)]
pub struct StableApi {
    // ...
}

#[ready(2)]
impl StableApi {
    #[ready(2)]
    pub fn new() -> Self {
        // ...
    }
}
```

When building with `RUSTFLAGS="--cfg min_readiness_2"`, items with readiness < 2 are excluded. This enforces that stable code cannot depend on experimental code at compile time.

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