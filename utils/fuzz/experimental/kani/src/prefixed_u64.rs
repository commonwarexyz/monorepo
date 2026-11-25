//! `sequence::prefixed_u64::U64`: a prefix byte and a `u64`, as a fixed-size key.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! The functions `U64::new`, `prefix` and `value` have no documentation of their own. The
//! module and the type state what the key is, and the crate's tests state what they do:
//!
//! 1. A key carries a prefix and a `u64`. utils/src/sequence/prefixed_u64.rs, module docs:
//!    "A `u64` array type with a prefix byte to allow for multiple key contexts."
//! 2. `new` keeps both parts, and they survive an encode and a decode. The crate's test
//!    `test_prefixed_u64`: `U64::new(prefix, value)`, `U64::decode(Copying(&array))`, then
//!    "assert_eq!(value, decoded.value());" and "assert_eq!(prefix, decoded.prefix());".
//! 3. The encoding is the key's bytes, `U64::SIZE` of them, and decodes back to an equal key.
//!    The crate's test `test_prefixed_u64_codec`: "assert_eq!(encoded.len(), U64::SIZE);",
//!    "assert_eq!(encoded, original.as_ref());" and "assert_eq!(original, decoded);".
//! 4. A key built from any byte array gives back its parts. The crate's test
//!    `test_prefixed_u64`: `U64::from(array.0)`, then the same two assertions as item 2.
//! 5. Decoding peer bytes does not panic, a failure is an error, and an accepted input is read
//!    to the end of the value and no further. codec/src/codec.rs, `Read::read_cfg`:
//!    "Implementations should consume the exact number of bytes required from `buf` to
//!    reconstruct the value.", "Implementations must return [Error] if decoding fails due to
//!    invalid data, insufficient bytes in the buffer" and "Parsing a message (often untrusted)
//!    should never result in a panic."
//!
//! # What is proven
//!
//! `kani_prefixed_u64_new`: for EVERY prefix and EVERY value, `U64::new` keeps both (item 2),
//! the encoding is `U64::SIZE` bytes equal to `as_ref`, and decoding it gives an equal key with
//! the same parts (items 2 and 3).
//!
//! `kani_prefixed_u64_decode`: for EVERY input of up to `U64::SIZE + 1` bytes, decoding fails
//! with an error when the input is shorter than `U64::SIZE`, and otherwise accepts it,
//! reads exactly `U64::SIZE` bytes, keeps them as the key's bytes, and `U64::new` of the key's
//! parts rebuilds an equal key (items 3 to 5).
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! - The bytes of `U64::new(prefix, value)` are the prefix and then the value big-endian.
//! - `kani_prefixed_u64_decode`: an input shorter than `U64::SIZE` fails with `EndOfBuffer`.
//!   The quoted contract requires an error for insufficient bytes, not this kind.
//! - Keys order by prefix first, then by value. The order of keys is not documented; this
//!   follows from the derived `Ord` over that byte layout.
//!
//! # Bounds
//!
//! No bound on the prefix or the value. Inputs of 0 to 10 bytes. Loops unwind once more than
//! their longest run. `usize` is 64 bits.

use crate::common::{big_endian_u64, consistency, write_into};
use commonware_codec::{Copying, Error, FixedSize, Read};
use commonware_utils::sequence::prefixed_u64::U64;

const SIZE: usize = U64::SIZE;
const INPUT: usize = SIZE + 1;

#[kani::proof]
#[kani::unwind(11)]
fn kani_prefixed_u64_new() {
    let prefix: u8 = kani::any();
    let value: u64 = kani::any();
    let key = U64::new(prefix, value);
    assert!(key.prefix() == prefix);
    assert!(key.value() == value);

    let mut out = [0u8; SIZE];
    let written = write_into(&key, &mut out);
    assert!(written == SIZE);
    assert!(out[..] == key.as_ref()[..]);
    let mut buf = Copying(&out[..]);
    let decoded = U64::read_cfg(&mut buf, &()).expect("an encoded key decodes");
    assert!(buf.0.is_empty());
    assert!(decoded == key);
    assert!(decoded.prefix() == prefix && decoded.value() == value);

    consistency!(out[0] == prefix);
    consistency!(big_endian_u64(&out[1..]) == value);
    let other = U64::new(kani::any(), kani::any());
    consistency!(key.cmp(&other) == (prefix, value).cmp(&(other.prefix(), other.value())));

    kani::cover!(prefix == 0 && value == 0, "the zero key");
    kani::cover!(prefix == u8::MAX && value == u64::MAX, "the largest key");
}

#[kani::proof]
#[kani::unwind(11)]
fn kani_prefixed_u64_decode() {
    let data: [u8; INPUT] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= INPUT);
    let mut buf = Copying(&data[..n]);
    let result = U64::read_cfg(&mut buf, &());

    if n < SIZE {
        assert!(result.is_err());
        consistency!(matches!(result, Err(Error::EndOfBuffer)));
        kani::cover!(n == 0, "an empty input ends the buffer");
        kani::cover!(n == SIZE - 1, "one byte short ends the buffer");
        return;
    }
    let key = match result {
        Ok(key) => key,
        Err(_) => panic!("refused an input of a whole key"),
    };
    assert!(buf.0.len() == n - SIZE);
    assert!(key.as_ref()[..] == data[..SIZE]);
    let from = U64::from(<[u8; SIZE]>::try_from(&data[..SIZE]).expect("SIZE bytes"));
    assert!(from == key);
    assert!(U64::new(key.prefix(), key.value()) == key);

    consistency!(key.prefix() == data[0]);
    consistency!(key.value() == big_endian_u64(&data[1..]));

    kani::cover!(n == SIZE, "a whole key and nothing more");
    kani::cover!(n == INPUT, "a whole key and one byte more");
}
