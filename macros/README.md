# commonware-macros

[![Crates.io](https://img.shields.io/crates/v/commonware-macros.svg)](https://crates.io/crates/commonware-macros)
[![Docs.rs](https://docs.rs/commonware-macros/badge.svg)](https://docs.rs/commonware-macros)

Augment the development of primitives with procedural macros.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

## Stability Macros

### Stability Levels

| Level | Name | Description |
|-------|------|-------------|
| 0 | `ALPHA` | Little testing, breaking changes expected |
| 1 | `BETA` | Decent coverage, wire format unstable |
| 2 | `GAMMA` | Wire/storage format stable, API may change |
| 3 | `DELTA` | API + wire stable |
| 4 | `EPSILON` | Audited, deployed in production |

### `#[stability(LEVEL)]`

Marks an item with a stability level. When building with `RUSTFLAGS="--cfg commonware_stability_X"`, items with stability less than X are excluded.

```rust
use commonware_macros::stability;

#[stability(GAMMA)]
pub mod stable_api {
    // Excluded when building with commonware_stability_DELTA or higher
}
```

### `stability_mod!`

Marks a file module with a stability level:

```rust
use commonware_macros::stability_mod;

stability_mod!(GAMMA, pub mod stable_module);
```

### `stability_scope!`

Groups multiple items under a single stability level:

```rust
use commonware_macros::stability_scope;

stability_scope!(GAMMA {
    pub struct Config { }
    pub fn process() { }
});
```

### `stability_cfg!` for `#[macro_export]` Modules

For modules containing `#[macro_export]` macros, proc macros don't work. Use the `stability_cfg!` declarative macro from `commonware_utils`:

```rust
commonware_utils::stability_cfg!(GAMMA, pub mod module_with_exported_macros;);
```

See the [Stability section](https://github.com/commonwarexyz/monorepo#stability) in the main README for more details.

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
