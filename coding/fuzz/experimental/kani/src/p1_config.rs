//! P1: every 4-byte input either decodes to a `Config` that re-encodes to the same bytes, or
//! is rejected because a field is zero.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! `kani_config_decode_roundtrip`: for EVERY 4-byte input, decoding succeeds exactly when
//! both 2-byte fields are nonzero, and a decoded `Config` encodes to the same 4 bytes.
//!
//! 1. A `Config` is two `NonZeroU16` fields. coding/src/lib.rs, `Config::minimum_shards`: "The
//!    minimum number of shards needed to encode the data."; `Config::extra_shards`: "Extra
//!    shards beyond the minimum number."
//! 2. The minimum comes first on the wire. The documentation does not give the field order;
//!    this item rests on the code. coding/src/lib.rs, `Write for Config`:
//!    "self.minimum_shards.write(buf); self.extra_shards.write(buf);"; `Read for Config`:
//!    "minimum_shards: NonZeroU16::read_cfg(buf, cfg)?, extra_shards:
//!    NonZeroU16::read_cfg(buf, cfg)?,"
//! 3. A `Config` is 4 bytes. coding/src/lib.rs, `FixedSize for Config`: "const SIZE: usize =
//!    2 * <NonZeroU16 as FixedSize>::SIZE;". codec/src/types/primitives.rs, module docs: "All
//!    fixed-size integers and floats are written big-endian to avoid host- endian ambiguity."
//!
//! From the crate's own tests, not from API documentation:
//!
//! 4. A zero does not decode as a `NonZeroU16`. codec/src/types/primitives.rs, the test
//!    `test_nonzero_u16`: "assert!(NonZeroU16::decode(0u16.encode()).is_err());". The test
//!    asserts that decoding fails, not with which error.
//!
//! # Implementation consistency
//!
//! None.
//!
//! # Bounds
//!
//! None: every 4-byte input.

use commonware_codec::{Copying, DecodeExt, Encode, FixedSize};
use commonware_coding::Config;

#[kani::proof]
fn kani_config_decode_roundtrip() {
    let bytes: [u8; 4] = kani::any();
    let minimum_shards = u16::from_be_bytes([bytes[0], bytes[1]]);
    let extra_shards = u16::from_be_bytes([bytes[2], bytes[3]]);
    assert_eq!(Config::SIZE, 4);

    match Config::decode(Copying(&bytes[..])) {
        Ok(cfg) => {
            assert!(minimum_shards != 0 && extra_shards != 0);
            assert_eq!(cfg.minimum_shards.get(), minimum_shards);
            assert_eq!(cfg.extra_shards.get(), extra_shards);
            assert_eq!(cfg.encode().as_ref(), &bytes[..]);
            kani::cover!(true, "a config decodes");
        }
        Err(_) => {
            assert!(minimum_shards == 0 || extra_shards == 0);
            kani::cover!(minimum_shards == 0, "a zero minimum is rejected");
            kani::cover!(
                minimum_shards != 0 && extra_shards == 0,
                "a zero extra count is rejected"
            );
        }
    }
}
