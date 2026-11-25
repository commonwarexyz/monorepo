//! P10: the `bool` tag and the `Option` tag.
//!
//! A `bool` encodes as one byte, `0` for false and `1` for true, and reads back as `false`
//! for `0`, `true` for `1`, and `InvalidBool` for anything else. `Option<T>` encodes as a
//! `bool` tag in front of the payload, so `None` is one byte and `Some(v)` is one byte
//! more than `v`. This proof is about those two tags and nothing else.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! 1. Decoding does not panic, a failure is an error, and an accepted input is read to the
//!    end of the value and no further. codec/src/codec.rs, `Read::read_cfg`:
//!    "Implementations should consume the exact number of bytes required from `buf` to
//!    reconstruct the value." "Implementations must return [Error] if decoding fails due to
//!    invalid data, insufficient bytes in the buffer" and "Parsing a message (often
//!    untrusted) should never result in a panic."
//! 2. A byte that is not `0` or `1` is `InvalidBool`. codec/src/error.rs,
//!    `Error::InvalidBool`: "A byte representing a boolean was expected to be `0` (false) or
//!    `1` (true), but a different value was encountered during decoding."
//! 3. A `bool` writes as one byte and reads back as the same value.
//!    codec/src/types/primitives.rs, `Write for bool` and `Read for bool`: "buf.put_u8(if
//!    *self { 1 } else { 0 })" and "0 => Ok(false), 1 => Ok(true), _ =>
//!    Err(Error::InvalidBool)". The crate's own test codec/src/types/primitives.rs,
//!    `test_bool`, asserts the same round trip and an `encode_size` of 1.
//! 4. An `Option` writes as a tag byte plus the payload, and `encode_size` is the number of
//!    bytes written. codec/src/types/primitives.rs, `Write for Option<T>` and `EncodeSize for
//!    Option<T>`: "self.is_some().write(buf)" and "self.as_ref().map_or(1, |inner| 1 +
//!    inner.encode_size())". codec/src/codec.rs, `EncodeSize::encode_size`: "Returns the
//!    encoded size of this value (in bytes)." The crate's own tests
//!    codec/src/types/primitives.rs, `test_option` and `test_option_length`, assert the same
//!    for `Some(42u32)` and `None`.
//! 5. An `Option` reads as `None` for a tag of `0` and as `Some(v)` for a tag of `1` plus
//!    `v`'s encoding. codec/src/types/primitives.rs, `Read for Option<T>`: "if
//!    bool::read(buf)? { Ok(Some(T::read_cfg(buf, cfg)?)) } else { Ok(None) }".
//!
//! # What is proven
//!
//! `kani_p10_bool_tag`: for EVERY byte `b`, `bool::read` on `[b]` returns `Ok(false)` exactly
//! when `b == 0`, `Ok(true)` exactly when `b == 1`, and `Err(Error::InvalidBool)` for every
//! other byte. `write` of `false` and `true` gives `[0]` and `[1]`, and `encode_size` is 1.
//!
//! `kani_p10_option_tag`: for EVERY tag byte `t` and payload byte `p`, `Option::<u8>::read`
//! on `[t, p]` returns `Ok(None)` exactly when `t == 0`, `Ok(Some(p))` exactly when `t == 1`,
//! and `Err(Error::InvalidBool)` for every other byte. `write` of `None` gives `[0]`, `write`
//! of `Some(p)` gives `[1, p]`, and `encode_size` matches the written length in both cases.
//!
//! # Bounds
//!
//! `bool`: one input byte, one output byte. `Option<u8>`: two input bytes (tag and payload),
//! one or two output bytes. The proofs hold for these sizes only.

use crate::common::write_into;
use bytes::Buf as _;
use commonware_codec::{Copying, EncodeSize, Error, ReadExt, Write};

#[kani::proof]
fn kani_p10_bool_tag() {
    let b: u8 = kani::any();

    let mut buf = Copying(&[b][..]);
    let result = bool::read(&mut buf);

    match result {
        Ok(v) => {
            assert!(b == 0 || b == 1);
            assert!(v == (b == 1));
            if v {
                kani::cover!(b == 1, "accepts 1 as true");
            } else {
                kani::cover!(b == 0, "accepts 0 as false");
            }
        }
        Err(e) => {
            assert!(matches!(e, Error::InvalidBool));
            assert!(b != 0 && b != 1);
            kani::cover!(b > 1, "rejects every other byte");
        }
    }

    let mut out = [0u8; 1];
    let written = write_into(&false, &mut out);
    assert!(written == 1 && out == [0]);
    assert!(false.encode_size() == 1);
    let written = write_into(&true, &mut out);
    assert!(written == 1 && out == [1]);
    assert!(true.encode_size() == 1);
}

#[kani::proof]
fn kani_p10_option_tag() {
    let t: u8 = kani::any();
    let p: u8 = kani::any();

    let mut buf = Copying(&[t, p][..]);
    let result = Option::<u8>::read(&mut buf);

    match result {
        Ok(None) => {
            assert!(t == 0);
            kani::cover!(t == 0, "accepts a tag of 0 as None");
        }
        Ok(Some(v)) => {
            assert!(t == 1 && v == p);
            kani::cover!(t == 1, "accepts a tag of 1 as Some(payload)");
        }
        Err(e) => {
            assert!(matches!(e, Error::InvalidBool));
            assert!(t != 0 && t != 1);
            kani::cover!(t > 1, "rejects every other tag");
        }
    }

    let mut out = [0u8; 2];
    let none: Option<u8> = None;
    let written = write_into(&none, &mut out);
    assert!(written == 1 && out[0] == 0);
    assert!(none.encode_size() == written);
    let some = Some(p);
    let written = write_into(&some, &mut out);
    assert!(written == 2 && out == [1, p]);
    assert!(some.encode_size() == written);
}
