//! `prefixed` adds room for the longest subchannel prefix to a payload size.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! p2p/src/utils/mux.rs, `prefixed`: "Returns `payload` plus the largest
//! subchannel prefix, so it covers a payload of that size on any [`Muxer`] subchannel." The
//! prefix a subchannel sender puts before a payload is `UInt(subchannel).encode()`
//! (p2p/src/utils/mux.rs, `CheckedGlobalSender::send`), and the layout gives it 1 to 10 bytes
//! (p2p/src/utils/mux.rs, module documentation: "subchannel (varint, 1-10) | payload").
//!
//! For EVERY `payload <= usize::MAX - 10` and EVERY subchannel `c` (any `u64`):
//!
//! 1. `prefixed(payload)` does not panic or overflow.
//! 2. It covers the message on subchannel `c`: `payload + UInt(c).encode_size() <=
//!    prefixed(payload)`.
//! 3. It adds the largest prefix and no more: `prefixed(payload) == payload +
//!    UInt(u64::MAX).encode_size()`, and that size is 10, the upper end of "1-10". The test
//!    `test_prefixed` (p2p/src/utils/mux.rs) asserts `prefixed(0) == 10` and `prefixed(usize::MAX -
//!    10) == usize::MAX`.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! None. The contract fixes the result exactly.
//!
//! # Bounds
//!
//! `payload <= usize::MAX - MAX_U64_VARINT_SIZE`. Above it the addition overflows: Kani
//! reports an overflow, and a release build wraps. The documentation states no domain, so the
//! proof claims nothing there. `usize` is 64 bits.

use commonware_codec::{
    EncodeSize,
    varint::{MAX_U64_VARINT_SIZE, UInt},
};
use commonware_p2p::utils::mux::prefixed;

#[kani::proof]
fn kani_mux_prefixed() {
    let payload: usize = kani::any();
    let channel: u64 = kani::any();
    kani::assume(payload <= usize::MAX - MAX_U64_VARINT_SIZE);

    // Contract 1: this call must not panic or overflow.
    let size = prefixed(payload);

    // Contract 2: the message on this subchannel fits.
    let prefix = UInt(channel).encode_size();
    assert!(payload + prefix <= size);

    // Contract 3: exactly the largest prefix, which is 10 bytes.
    let largest = UInt(u64::MAX).encode_size();
    assert!(largest == 10);
    assert!(size == payload + largest);

    kani::cover!(payload == 0, "an empty payload");
    kani::cover!(
        payload == usize::MAX - MAX_U64_VARINT_SIZE,
        "the largest payload of the domain"
    );
    kani::cover!(prefix == 1, "a subchannel with a one-byte prefix");
    kani::cover!(prefix == 10, "a subchannel with the longest prefix");
}
