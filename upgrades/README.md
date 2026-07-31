# commonware-upgrades

[![Crates.io](https://img.shields.io/crates/v/commonware-upgrades.svg)](https://crates.io/crates/commonware-upgrades)
[![Docs.rs](https://docs.rs/commonware-upgrades/badge.svg)](https://docs.rs/commonware-upgrades)

Coordinate upgrades at synchronized boundaries.

Commonware defines one ordered set of upgrades. Applications choose the epoch at which each
upgrade activates:

```rust
use commonware_upgrades::{Schedule, Upgrade};

let schedule = Schedule::builder()
    .activate(Upgrade::Alameda, 10u64)
    .build()?;

assert!(!schedule.is_active(Upgrade::Alameda, 9));
assert!(schedule.is_active(Upgrade::Alameda, 10));
# Ok::<(), commonware_upgrades::Error>(())
```

Activating an upgrade also activates every upgrade before it. A schedule may omit earlier
upgrades; they activate with the first configured descendant.

## Status

`commonware-upgrades` is **ALPHA** software. See the [workspace stability
policy](https://github.com/commonwarexyz/monorepo#stability) for details.
