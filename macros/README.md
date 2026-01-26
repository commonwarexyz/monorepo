# commonware-macros

[![Crates.io](https://img.shields.io/crates/v/commonware-macros.svg)](https://crates.io/crates/commonware-macros)
[![Docs.rs](https://docs.rs/commonware-macros/badge.svg)](https://docs.rs/commonware-macros)

Augment the development of primitives with procedural macros.

## Status

`commonware-macros` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Readiness Macros

### Readiness Levels

| Level | Name | Description |
|-------|------|-------------|
| 0 | `ALPHA` | Little testing, breaking changes expected |
| 1 | `BETA` | Decent coverage, wire format unstable |
| 2 | `GAMMA` | Wire/storage format stable, API may change |
| 3 | `DELTA` | API + wire stable |
| 4 | `EPSILON` | Audited, deployed in production |

### `#[ready(LEVEL)]`

Marks an item with a readiness level. When building with `RUSTFLAGS="--cfg min_readiness_X"`, items with readiness less than X are excluded.

```rust
use commonware_macros::ready;

#[ready(GAMMA)]
pub mod stable_api {
    // Excluded when building with min_readiness_DELTA or higher
}
```

### `ready_mod!`

Marks a file module with a readiness level:

```rust
use commonware_macros::ready_mod;

ready_mod!(GAMMA, pub mod stable_module);
```

### `ready_scope!`

Groups multiple items under a single readiness level:

```rust
use commonware_macros::ready_scope;

ready_scope!(GAMMA {
    pub struct Config { }
    pub fn process() { }
});
```

### Raw `#[cfg(...)]` for `#[macro_export]` Modules

For modules containing `#[macro_export]` macros, you **must** use raw `#[cfg(...)]` attributes. Due to a Rust limitation, macro-expanded modules cannot have their exported macros referenced by absolute paths. The readiness macros above won't work for these modules.

Use one `#[cfg(not(...))]` per level above the item's readiness:

```rust
// GAMMA: excluded at DELTA or EPSILON
#[cfg(not(min_readiness_DELTA))]
#[cfg(not(min_readiness_EPSILON))]
pub mod module_with_exported_macros;
```

See the [Readiness section](https://github.com/commonwarexyz/monorepo#readiness) in the main README for more details.

## Other Macros

### `#[test_async]`

Run a test function asynchronously without binding to a particular executor.

```rust
#[commonware_macros::test_async]
async fn test_async_fn() {
    assert_eq!(2 + 2, 4);
}
```

### `select!`

A re-export of `futures::select_biased!` for consistent select behavior across the codebase.
