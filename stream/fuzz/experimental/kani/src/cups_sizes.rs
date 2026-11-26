//! `Cups::header_len` and `Cups::record_len` give the sizes of a CUPS record.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! The record layout, stream/src/cups/mod.rs, module documentation: "Let `m` be a message of `n`
//! bytes and `t` the cipher's fixed tag size. `seal_i(x)` denotes the ciphertext of `x` followed by
//! its tag ... Each record consists of a header followed by a body", with the header
//! `varint_u32(n + t)` for V0 and `seal_i(BE32(n))` for V1, and the body `seal_i(m)` (V0) or
//! `seal_(i+1)(m)` (V1). Further: stream/src/cups/mod.rs, module documentation: "V0's length prefix is visible and
//! canonical"; stream/src/cups/mod.rs, module documentation: "V1's header is exactly `4 + t` bytes.
//! ... the `n + t` byte body". A sealed `x` has `x`'s length plus `t`, because the cipher encrypts
//! in place (cryptography/src/lib.rs, `Cipher::seal`: "Encrypts the next message in place").
//!
//! The size of a canonical `varint_u32(v)` is the number of 7-bit groups `v` needs, at least one:
//! codec/src/varint.rs, module documentation (7 data bits and a continuation bit per byte) and
//! codec/src/varint.rs, `Decoder::feed` ("every value has exactly one unique, valid encoding", so
//! no zero group follows the last one that holds a set bit). `varint_len` below computes it from
//! these rules; it does not call the codec.
//!
//! Let `limit = u32::MAX - t`. For `C = ChaCha20Poly1305`, both versions, and EVERY `len`:
//!
//! 1. `kani_cups_header_len`: for `len <= limit`, `header_len(len)` returns `varint_len(len + t)`
//!    for V0 and `4 + t` for V1. stream/src/cups/protocol.rs, `Cups::header_len`: "Returns the size
//!    of the header that precedes a record carrying `len` payload bytes." Also `Cups::MAX_SIZE ==
//!    limit`: stream/src/cups/protocol.rs, `Cups::MAX_SIZE` ("Largest supported plaintext message
//!    ... the payload and tag must fit in a `u32`") and the test `test_max_size_fits_tag`
//!    (stream/src/cups/protocol.rs) (`MAX_SIZE + TAG_SIZE == u32::MAX`).
//! 2. `kani_cups_record_len`: for `len <= limit`, `record_len(len)` returns the header size of item
//!    1 plus `len + t`, with no overflow. stream/src/cups/protocol.rs, `Cups::record_len`: "Returns
//!    the encoded size of a record carrying `len` payload bytes."
//! 3. `kani_cups_header_len_panics`: inputs with `len > limit` make `header_len(len)` panic
//!    (`should_panic`; see below for what that shows).
//!    stream/src/cups/protocol.rs, `Cups::header_len`: "Panics if `len` exceeds the largest record
//!    payload, `u32::MAX` minus the tag size."; the test
//!    `test_header_len_rejects_oversized_payload` (stream/src/cups/protocol.rs) expects the panic
//!    at `len = u32::MAX`.
//! 4. `kani_cups_record_len_panics`: inputs with `len > limit` make `record_len(len)` panic
//!    (`should_panic`; see below for what that shows).
//!    stream/src/cups/protocol.rs, `Cups::record_len`: "Panics if `len` exceeds the largest record
//!    payload, `u32::MAX` minus the tag size, or if the record size does not fit in a `usize`."
//!
//! Items 3 and 4 use Kani's `should_panic`: the harness passes when a check related to a panic
//! fails and no other check fails. That shows that inputs of the class panic, not that EVERY
//! input of the class panics: a path that returns fails no check. Decision, 2026-11-26: these
//! harnesses carry no cover check that must stay unreachable, because the scheduled run counts
//! every unsatisfied cover as a failure. Each has a `_control` harness over a class that also
//! holds `len = limit`, which returns; its cover must be satisfied, so the boundary is where the
//! contract puts it.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! None. The contract fixes the results exactly.
//!
//! # Bounds
//!
//! None on `len` (every `usize`). Proven for `C = ChaCha20Poly1305` (`t = 16`), the cipher of the
//! crate's own tests (stream/src/cups/protocol.rs, the tests' `RecordCipher`) and the only `Cipher`
//! in the repository, and for the handshake type `()`, which the size functions do not use. `usize`
//! is 64 bits: the second panic of item 4, a record size that does not fit a `usize`, can only
//! happen when `usize` is 32 bits, and no input here reaches it.

use commonware_codec::FixedSize;
use commonware_cryptography::{ChaCha20Poly1305, Cipher};
use commonware_stream::cups::{Cups, Version};

type RecordCipher = ChaCha20Poly1305;
type TestCups = Cups<(), RecordCipher>;

/// The cipher's fixed tag size, `t`.
const TAG: usize = <<RecordCipher as Cipher>::Tag as FixedSize>::SIZE;

/// The largest payload, `u32::MAX - t`.
const LIMIT: usize = u32::MAX as usize - TAG;

/// The size of a V1 header, `4 + t`.
const V1_HEADER: usize = 4 + TAG;

/// The size of the canonical varint of `v`: the number of 7-bit groups `v` needs, at least
/// one.
fn varint_len(v: u32) -> usize {
    if v < 1 << 7 {
        1
    } else if v < 1 << 14 {
        2
    } else if v < 1 << 21 {
        3
    } else if v < 1 << 28 {
        4
    } else {
        5
    }
}

/// The header size the layout gives for a payload of `len <= LIMIT` bytes.
fn expected_header(version: Version, len: usize) -> usize {
    match version {
        Version::V0 => varint_len((len + TAG) as u32),
        Version::V1 => V1_HEADER,
    }
}

fn any_version() -> Version {
    if kani::any() {
        Version::V0
    } else {
        Version::V1
    }
}

#[kani::proof]
fn kani_cups_header_len() {
    assert!(TestCups::MAX_SIZE as usize == LIMIT);

    let len: usize = kani::any();
    kani::assume(len <= LIMIT);
    let version = any_version();

    let header = TestCups::new((), version).header_len(len);
    assert!(header == expected_header(version, len));

    let v0 = version == Version::V0;
    kani::cover!(v0 && header == 1, "V0, one-byte prefix");
    kani::cover!(v0 && header == 2, "V0, two-byte prefix");
    kani::cover!(v0 && header == 3, "V0, three-byte prefix");
    kani::cover!(v0 && header == 4, "V0, four-byte prefix");
    kani::cover!(v0 && header == 5, "V0, five-byte prefix");
    kani::cover!(v0 && len == LIMIT, "V0, the largest payload");
    kani::cover!(!v0 && len == LIMIT, "V1, the largest payload");
}

#[kani::proof]
fn kani_cups_record_len() {
    let len: usize = kani::any();
    kani::assume(len <= LIMIT);
    let version = any_version();

    let record = TestCups::new((), version).record_len(len);
    assert!(record == expected_header(version, len) + len + TAG);

    let v0 = version == Version::V0;
    kani::cover!(v0 && len == 0, "V0, an empty message");
    kani::cover!(v0 && len == LIMIT, "V0, the largest payload");
    kani::cover!(!v0 && len == 0, "V1, an empty message");
    kani::cover!(!v0 && len == LIMIT, "V1, the largest payload");
}

#[kani::proof]
#[kani::should_panic]
fn kani_cups_header_len_panics() {
    let len: usize = kani::any();
    kani::assume(len > LIMIT);
    let _ = TestCups::new((), any_version()).header_len(len);
}

#[kani::proof]
#[kani::should_panic]
fn kani_cups_header_len_panics_control() {
    let len: usize = kani::any();
    kani::assume(len >= LIMIT);
    let _ = TestCups::new((), any_version()).header_len(len);
    kani::cover!(true, "an input of the class returned (must be satisfied)");
}

#[kani::proof]
#[kani::should_panic]
fn kani_cups_record_len_panics() {
    let len: usize = kani::any();
    kani::assume(len > LIMIT);
    let _ = TestCups::new((), any_version()).record_len(len);
}

#[kani::proof]
#[kani::should_panic]
fn kani_cups_record_len_panics_control() {
    let len: usize = kani::any();
    kani::assume(len >= LIMIT);
    let _ = TestCups::new((), any_version()).record_len(len);
    kani::cover!(true, "an input of the class returned (must be satisfied)");
}
