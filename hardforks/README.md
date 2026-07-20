# commonware-hardforks

[![Crates.io](https://img.shields.io/crates/v/commonware-hardforks.svg)](https://crates.io/crates/commonware-hardforks)
[![Docs.rs](https://docs.rs/commonware-hardforks/badge.svg)](https://docs.rs/commonware-hardforks)

Coordinate protocol upgrades at epoch boundaries.

Commonware defines one ordered set of hardforks. Applications choose the epoch at which each
hardfork activates:

```rust
use commonware_hardforks::{Hardfork, Schedule};

let schedule = Schedule::builder()
    .activate(Hardfork::Alameda, 10u64)
    .build()?;

assert!(!schedule.is_active(Hardfork::Alameda, 9));
assert!(schedule.is_active(Hardfork::Alameda, 10));
# Ok::<(), commonware_hardforks::Error>(())
```

Activating a hardfork also activates every hardfork before it. A schedule may omit earlier
hardforks; they activate with the first configured descendant.

## Status

`commonware-hardforks` is **BETA** software. See the [workspace stability
policy](https://github.com/commonwarexyz/monorepo#stability) for details.
