//! P3: a `Config` decodes only from exactly 4 bytes.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! `kani_config_exact_size`: for EVERY input of 0 to 6 bytes, decoding succeeds only when the
//! input is exactly 4 bytes (and then exactly when both fields are nonzero, as in P1).
//!
//! 1. A `Config` is 4 bytes: coding/src/lib.rs, `FixedSize for Config` (see P1).
//!    codec/src/codec.rs, `FixedSize`: "Implementing this trait signifies that the encoded
//!    representation of this type *always* has the same byte length, regardless of the
//!    specific value."
//! 2. `decode` reads the value and refuses leftover bytes. codec/src/codec.rs, `Decode`:
//!    "Trait combining [Read] with a check for remaining bytes. Ensures that *all* bytes from
//!    the input buffer were consumed during decoding."; `Decode::decode_cfg`: "Returns [Error]
//!    if decoding fails via [Read::read_cfg] or if there are leftover bytes in `buf` after
//!    reading."
//! 3. A read of a value from too few bytes fails. codec/src/codec.rs, `Read::read_cfg`:
//!    "Implementations must return [Error] if decoding fails due to invalid data, insufficient
//!    bytes in the buffer, or violation of constraints imposed by the `cfg`."
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! - fewer than 4 bytes fail with `EndOfBuffer`; 5 or 6 bytes whose first 4 decode fail with
//!   `ExtraData` of the extra count (the codec's error type describes both kinds, but the docs
//!   of `Config` do not say which kind it returns).
//!
//! # Bounds
//!
//! Inputs of 0 to 6 bytes, every content.

use crate::common::consistency;
use commonware_codec::{Copying, DecodeExt, Error};
use commonware_coding::Config;

#[kani::proof]
#[kani::unwind(8)]
fn kani_config_exact_size() {
    let bytes: [u8; 6] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 6);
    let fields_nonzero = len >= 4
        && u16::from_be_bytes([bytes[0], bytes[1]]) != 0
        && u16::from_be_bytes([bytes[2], bytes[3]]) != 0;

    match Config::decode(Copying(&bytes[..len])) {
        Ok(_) => {
            assert_eq!(len, 4);
            assert!(fields_nonzero);
            kani::cover!(true, "exactly 4 bytes decode");
        }
        Err(error) => {
            assert!(len != 4 || !fields_nonzero);
            consistency!(len >= 4 || matches!(error, Error::EndOfBuffer));
            consistency!(
                !(len > 4 && fields_nonzero)
                    || matches!(error, Error::ExtraData(n) if n == len - 4)
            );
            kani::cover!(len < 4, "too few bytes");
            kani::cover!(len > 4 && fields_nonzero, "leftover bytes");
            kani::cover!(len == 4, "a zero field");
        }
    }
}
