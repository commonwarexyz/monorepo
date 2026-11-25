//! P2: `Config::total_shards` is the sum of the two fields and does not overflow.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! `kani_config_total_shards`: for EVERY `Config` (built by decoding EVERY 4-byte input, so
//! both fields take every nonzero value), `total_shards` returns `minimum_shards +
//! extra_shards` as a `u32`, without overflow.
//!
//! coding/src/lib.rs, `Config::total_shards`: "Returns the total number of shards produced by
//! this configuration."; `Config::extra_shards`: "Alternatively, one can think of the
//! configuration as having a total number `N = extra_shards + minimum_shards`".
//!
//! # Implementation consistency
//!
//! None. The bounds below follow from the sum of two nonzero `u16` values; they are stated as
//! checks of the gate, not as separate claims.
//!
//! # Bounds
//!
//! None: every `Config`.

use commonware_codec::{Copying, DecodeExt};
use commonware_coding::Config;

#[kani::proof]
fn kani_config_total_shards() {
    let bytes: [u8; 4] = kani::any();
    let Ok(cfg) = Config::decode(Copying(&bytes[..])) else {
        return;
    };
    let minimum_shards = u32::from(cfg.minimum_shards.get());
    let extra_shards = u32::from(cfg.extra_shards.get());
    let total_shards = cfg.total_shards();
    assert_eq!(minimum_shards + extra_shards, total_shards);
    assert!(total_shards >= 2);
    assert!(total_shards <= 2 * u32::from(u16::MAX));
    assert!(total_shards > minimum_shards && total_shards > extra_shards);

    kani::cover!(total_shards == 2, "the smallest configuration");
    kani::cover!(
        total_shards == 2 * u32::from(u16::MAX),
        "the largest configuration"
    );
}
