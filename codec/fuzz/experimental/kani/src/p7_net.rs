//! P7: network addresses decode without a panic, accept only their own encodings, and
//! round-trip.
//!
//! The six types of codec/src/types/net.rs: `Ipv4Addr`, `Ipv6Addr`, `SocketAddrV4`,
//! `SocketAddrV6`, `IpAddr` and `SocketAddr`. A peer sends these bytes.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! From the API documentation:
//!
//! 1. Decoding does not panic. codec/src/codec.rs:226-228, on `Read::read_cfg`: "Parsing a
//!    message (often untrusted) should never result in a panic."
//! 2. A failed decoding is an error, and an input that is too short fails with `EndOfBuffer`.
//!    codec/src/codec.rs:223-224: "Implementations must return [Error] if decoding fails due
//!    to invalid data, insufficient bytes in the buffer". codec/src/error.rs:10-12:
//!    `EndOfBuffer` "Indicates that the input buffer (`Buf`) did not contain enough bytes to
//!    read the next piece of data required by a [crate::Read] implementation."
//! 3. An accepted input is read to the end of the value and no further.
//!    codec/src/codec.rs:220-221: "Implementations should consume the exact number of bytes
//!    required from `buf` to reconstruct the value." codec/src/codec.rs:39: `encode_size`
//!    "Returns the encoded size of this value (in bytes)."
//! 4. The four address types with one layout have one size. codec/src/codec.rs:12-13, on
//!    `FixedSize`: "the encoded representation of this type *always* has the same byte
//!    length, regardless of the specific value."
//! 5. The declared maximum is the sum of the parts and is never exceeded.
//!    codec/src/codec.rs:25: "An upper bound on the encoded size, in bytes."
//!    codec/src/lib.rs:48-49: "[FixedSize] types contribute their fixed size. Composite types
//!    sum their fields' bounds, and enums add their tag's bound to the largest variant
//!    bound."
//! 6. A written value decodes to itself. codec/src/lib.rs:162-167 (the crate's example):
//!    "let bytes = point.encode();" ... "let decoded_point = Point::decode(bytes).unwrap();"
//!    ... "assert_eq!(point, decoded_point);". codec/src/codec.rs:330, on `Decode`: "Ensures
//!    that *all* bytes from the input buffer were consumed during decoding."
//!
//! From the crate's own tests, not from API documentation. The documentation says nothing on
//! the byte layout of an address or on its tag. These tests are the only statement of it:
//!
//! 7. Only the tags 4 and 6 are accepted, and any other tag fails with `Error::Invalid`.
//!    codec/src/types/net.rs:281-286, in `test_ip_addr`: "Test invalid version", with the
//!    input `[5]` and the expected result "Err(Error::Invalid(_, _))". The same for
//!    `SocketAddr`: codec/src/types/net.rs:321-326, in `test_socket_addr`.
//! 8. The byte layout. An IPv4 address is its 4 octets in order, an IPv6 address its 16
//!    octets in order, a port is 2 bytes with the most significant first, a socket address
//!    is the address and then the port, and `IpAddr` and `SocketAddr` start with one tag
//!    byte: 4 for IPv4, 6 for IPv6. codec/src/types/net.rs:340-395, `test_conformity`, for
//!    example "assert_eq!(sa_v4.encode(), &[0x04, 127, 0, 0, 1, 0x1F, 0x90][..]);". The
//!    sizes 5 and 17 (`IpAddr`) and 7 and 19 (`SocketAddr`): codec/src/types/net.rs:264-279
//!    and :299-319.
//! 9. `SocketAddrV6` round-trips with flow information 0 and scope id 0.
//!    codec/src/types/net.rs:243-256, `test_socket_addr_v6`, builds every value it
//!    round-trips with "SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)" and the like. The
//!    18 bytes of item 8 have no room for the two fields.
//!
//! # What is proven
//!
//! `kani_p7_*_decode`, for EVERY byte string of length `0..=MAX+1` (`MAX` = the largest
//! encoding of the type): `read` does not panic, and its result is the one the layout fixes:
//!
//! - `Ok(value)`: exactly the bytes of the value were read, `value.encode_size()` is that
//!   count, the value is the one the bytes spell (items 7 and 8), and writing the value gives
//!   the same bytes back. A decoded `SocketAddrV6` has flow information 0 and scope id 0 (this
//!   follows from items 8 and 9: every 18-byte string is the encoding of one such value).
//! - `Err(EndOfBuffer)`: only when the input is shorter than the encoding its first byte
//!   announces (for the four fixed types: shorter than the size).
//! - `Err(Invalid)`: only for `IpAddr` and `SocketAddr`, and only when the first byte is
//!   neither 4 nor 6.
//! - no other error.
//!
//! So an input of at least `MAX` bytes is never answered with `EndOfBuffer`, a tag other than
//! 4 or 6 is never accepted, and an accepted input is the one encoding of its value.
//!
//! `kani_p7_*_roundtrip`, for EVERY value of the type: `write` writes exactly
//! `encode_size()` bytes, at most `MAX_ENCODE_SIZE`, in the layout of item 8; `read` and
//! `decode` on those bytes give the value back and leave nothing. For `SocketAddrV6` and the
//! IPv6 arm of `SocketAddr` the value has flow information 0 and scope id 0 (item 9).
//!
//! `kani_p7_sizes`: the size constants are the sums that item 5 states.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! `kani_p7_socket_addr_v6_roundtrip` also takes values with a flow information or a scope id
//! other than 0. No document and no test says what happens to them. The code drops both
//! fields: the bytes are those of the address and the port alone, and the decoded value is
//! the input with both fields set to 0. So `decode(encode(x)) == x` does not hold for such a
//! value. The default build proves only that writing such a value does not panic and writes
//! 18 bytes.
//!
//! # Bounds
//!
//! Input length `<= MAX + 1` bytes: 5, 17, 7, 19, 18 and 20. Values: every value of the
//! type, with one exception. An IPv6 socket address has flow information 0 and scope id 0
//! in `kani_p7_socket_addr_roundtrip`, and `kani_p7_socket_addr_v6_roundtrip` asserts the
//! layout and the round trip only for such a value (item 9). Loops are unwound up to 22
//! times. `usize` is 64 bits.

use crate::common::{consistency, same_bytes, write_into};
use bytes::Buf as _;
use commonware_codec::{Copying, DecodeExt, EncodeSize, Error, FixedSize, MaxEncodeSize, ReadExt};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Bytes of an IPv4 address, of an IPv6 address, of a port and of a tag.
const V4: usize = 4;
const V6: usize = 16;
const PORT: usize = 2;
const TAG: usize = 1;

/// The tag bytes of the two address families.
const TAG_V4: u8 = 4;
const TAG_V6: u8 = 6;

fn any_ipv4() -> Ipv4Addr {
    Ipv4Addr::from(kani::any::<[u8; V4]>())
}

fn any_ipv6() -> Ipv6Addr {
    Ipv6Addr::from(kani::any::<[u8; V6]>())
}

/// The port that two bytes spell, the most significant byte first.
fn port_of(bytes: &[u8]) -> u16 {
    ((bytes[0] as u16) << 8) | bytes[1] as u16
}

// The layout of item 8, one function per type: `true` when `bytes` is the encoding of `value`.
// None of them calls the codec.

fn spells_ipv4(value: &Ipv4Addr, bytes: &[u8]) -> bool {
    same_bytes(&value.octets(), bytes)
}

fn spells_ipv6(value: &Ipv6Addr, bytes: &[u8]) -> bool {
    same_bytes(&value.octets(), bytes)
}

fn spells_socket_v4(value: &SocketAddrV4, bytes: &[u8]) -> bool {
    bytes.len() == V4 + PORT
        && spells_ipv4(value.ip(), &bytes[..V4])
        && value.port() == port_of(&bytes[V4..])
}

/// Flow information and scope id have no bytes: this compares the address and the port.
fn spells_socket_v6(value: &SocketAddrV6, bytes: &[u8]) -> bool {
    bytes.len() == V6 + PORT
        && spells_ipv6(value.ip(), &bytes[..V6])
        && value.port() == port_of(&bytes[V6..])
}

fn spells_ip(value: &IpAddr, bytes: &[u8]) -> bool {
    match value {
        IpAddr::V4(v4) => {
            bytes.len() == TAG + V4 && bytes[0] == TAG_V4 && spells_ipv4(v4, &bytes[TAG..])
        }
        IpAddr::V6(v6) => {
            bytes.len() == TAG + V6 && bytes[0] == TAG_V6 && spells_ipv6(v6, &bytes[TAG..])
        }
    }
}

fn spells_socket(value: &SocketAddr, bytes: &[u8]) -> bool {
    let ip = match value {
        SocketAddr::V4(_) => TAG + V4,
        SocketAddr::V6(_) => TAG + V6,
    };
    bytes.len() == ip + PORT
        && spells_ip(&value.ip(), &bytes[..ip])
        && value.port() == port_of(&bytes[ip..])
}

/// A fixed-size address read from every byte string.
macro_rules! fixed_decode {
    ($name:ident, $ty:ty, $size:expr, $spells:ident, $extra:expr) => {
        #[kani::proof]
        #[kani::unwind(22)]
        fn $name() {
            const SIZE: usize = $size;
            const N: usize = SIZE + 1;
            let bytes: [u8; N] = kani::any();
            let len: usize = kani::any();
            kani::assume(len <= N);
            let input = &bytes[..len];

            // Item 1: this call must not panic.
            let mut buf = Copying(input);
            let result = <$ty>::read(&mut buf);
            let consumed = len - buf.remaining();

            match result {
                Ok(value) => {
                    // Items 3 and 4: the bytes of one value, no more.
                    assert!(consumed == SIZE);
                    assert!(value.encode_size() == consumed);

                    // Item 8: the value is the one the bytes spell.
                    assert!($spells(&value, &input[..consumed]));
                    let extra: fn(&$ty) -> bool = $extra;
                    assert!(extra(&value));

                    // Writing it gives the same bytes back.
                    let mut out = [0u8; SIZE];
                    let written = write_into(&value, &mut out);
                    assert!(same_bytes(&out[..written], &input[..consumed]));

                    kani::cover!(len == SIZE, "accepts an input of exactly the size");
                    kani::cover!(len == N, "accepts with a byte left in the buffer");
                }
                Err(Error::EndOfBuffer) => {
                    // Item 2: only an input that is too short.
                    assert!(len < SIZE);

                    kani::cover!(len == 0, "empty input ends the buffer");
                    kani::cover!(len == SIZE - 1, "one byte short ends the buffer");
                }
                Err(_) => panic!("unexpected error kind"),
            }
        }
    };
}

fn no_extra<T>(_: &T) -> bool {
    true
}

/// Items 8 and 9: a decoded value carries no flow information and no scope id.
fn zero_flow_and_scope(value: &SocketAddrV6) -> bool {
    value.flowinfo() == 0 && value.scope_id() == 0
}

fixed_decode!(kani_p7_ipv4_decode, Ipv4Addr, V4, spells_ipv4, no_extra);
fixed_decode!(kani_p7_ipv6_decode, Ipv6Addr, V6, spells_ipv6, no_extra);
fixed_decode!(
    kani_p7_socket_addr_v4_decode,
    SocketAddrV4,
    V4 + PORT,
    spells_socket_v4,
    no_extra
);
fixed_decode!(
    kani_p7_socket_addr_v6_decode,
    SocketAddrV6,
    V6 + PORT,
    spells_socket_v6,
    zero_flow_and_scope
);

/// A fixed-size address written, read and decoded, for every value.
macro_rules! fixed_roundtrip {
    ($name:ident, $ty:ty, $size:expr, $spells:ident, $any:expr) => {
        #[kani::proof]
        #[kani::unwind(22)]
        fn $name() {
            const SIZE: usize = $size;
            let value: $ty = $any;

            // Items 4 and 5. `write_into` panics if more than SIZE bytes are written.
            let mut out = [0u8; SIZE];
            let written = write_into(&value, &mut out);
            assert!(written == SIZE);
            assert!(value.encode_size() == written);
            assert!(<$ty as FixedSize>::SIZE == SIZE);
            assert!(<$ty as MaxEncodeSize>::MAX_ENCODE_SIZE == SIZE);

            // Item 8.
            assert!($spells(&value, &out));

            // Item 6: reading gives the value back and leaves nothing.
            let mut buf = Copying(&out[..]);
            let decoded = <$ty>::read(&mut buf);
            assert!(matches!(decoded, Ok(v) if v == value));
            assert!(buf.remaining() == 0);
            assert!(matches!(<$ty>::decode(Copying(&out[..])), Ok(v) if v == value));

            kani::cover!(written == SIZE, "a value is written and read back");
        }
    };
}

fixed_roundtrip!(
    kani_p7_ipv4_roundtrip,
    Ipv4Addr,
    V4,
    spells_ipv4,
    any_ipv4()
);
fixed_roundtrip!(
    kani_p7_ipv6_roundtrip,
    Ipv6Addr,
    V6,
    spells_ipv6,
    any_ipv6()
);
fixed_roundtrip!(
    kani_p7_socket_addr_v4_roundtrip,
    SocketAddrV4,
    V4 + PORT,
    spells_socket_v4,
    SocketAddrV4::new(any_ipv4(), kani::any())
);

#[kani::proof]
#[kani::unwind(22)]
fn kani_p7_socket_addr_v6_roundtrip() {
    const SIZE: usize = V6 + PORT;
    let ip = any_ipv6();
    let port: u16 = kani::any();
    let flow: u32 = kani::any();
    let scope: u32 = kani::any();
    let value = SocketAddrV6::new(ip, port, flow, scope);

    // Items 4 and 5, for every value: also one with a flow information or a scope id.
    let mut out = [0u8; SIZE];
    let written = write_into(&value, &mut out);
    assert!(written == SIZE);
    assert!(value.encode_size() == written);
    assert!(SocketAddrV6::SIZE == SIZE);
    assert!(SocketAddrV6::MAX_ENCODE_SIZE == SIZE);

    let mut buf = Copying(&out[..]);
    let decoded = SocketAddrV6::read(&mut buf);

    if flow == 0 && scope == 0 {
        // Items 8, 9 and 6.
        assert!(spells_socket_v6(&value, &out));
        assert!(matches!(decoded, Ok(v) if v == value));
        assert!(buf.remaining() == 0);
        assert!(matches!(SocketAddrV6::decode(Copying(&out[..])), Ok(v) if v == value));
    } else {
        // The two fields are dropped: the bytes and the decoded value do not hold them.
        consistency!(spells_socket_v6(&value, &out));
        consistency!(matches!(decoded, Ok(v) if v == SocketAddrV6::new(ip, port, 0, 0)));
    }

    kani::cover!(
        flow == 0 && scope == 0,
        "a value the encoding carries in full"
    );
    kani::cover!(flow != 0, "a value with flow information");
    kani::cover!(scope != 0, "a value with a scope id");
}

#[kani::proof]
#[kani::unwind(22)]
fn kani_p7_ip_addr_decode() {
    const MAX: usize = TAG + V6;
    const N: usize = MAX + 1;
    assert!(IpAddr::MAX_ENCODE_SIZE == MAX);

    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let input = &bytes[..len];

    // Item 1: this call must not panic.
    let mut buf = Copying(input);
    let result = IpAddr::read(&mut buf);
    let consumed = len - buf.remaining();

    match result {
        Ok(value) => {
            // Item 3.
            assert!(value.encode_size() == consumed);

            // Items 7 and 8: the tag names the family, and the value is the one the bytes
            // spell.
            assert!(spells_ip(&value, &input[..consumed]));

            // Writing it gives the same bytes back.
            let mut out = [0u8; MAX];
            let written = write_into(&value, &mut out);
            assert!(same_bytes(&out[..written], &input[..consumed]));

            kani::cover!(value.is_ipv4(), "accepts an IPv4 address");
            kani::cover!(value.is_ipv6(), "accepts an IPv6 address");
            kani::cover!(consumed < len, "accepts with bytes left in the buffer");
        }
        Err(Error::EndOfBuffer) => {
            // Item 2: no tag, or fewer bytes than the tag announces.
            assert!(
                len == 0
                    || (input[0] == TAG_V4 && len < TAG + V4)
                    || (input[0] == TAG_V6 && len < TAG + V6)
            );

            kani::cover!(len == 0, "empty input ends the buffer");
            kani::cover!(len == TAG + V4 - 1, "an IPv4 address one byte short");
            kani::cover!(len == TAG + V6 - 1, "an IPv6 address one byte short");
        }
        Err(Error::Invalid(_, _)) => {
            // Item 7: only a tag that is neither 4 nor 6.
            assert!(len >= 1 && input[0] != TAG_V4 && input[0] != TAG_V6);

            kani::cover!(input[0] == 0, "rejects the tag 0");
            kani::cover!(input[0] == 5, "rejects the tag 5");
            kani::cover!(len == N, "rejects a bad tag in front of a full input");
        }
        Err(_) => panic!("unexpected error kind"),
    }
}

#[kani::proof]
#[kani::unwind(22)]
fn kani_p7_socket_addr_decode() {
    const MAX: usize = TAG + V6 + PORT;
    const N: usize = MAX + 1;
    assert!(SocketAddr::MAX_ENCODE_SIZE == MAX);

    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let input = &bytes[..len];

    // Item 1: this call must not panic.
    let mut buf = Copying(input);
    let result = SocketAddr::read(&mut buf);
    let consumed = len - buf.remaining();

    match result {
        Ok(value) => {
            // Item 3.
            assert!(value.encode_size() == consumed);

            // Items 7 and 8.
            assert!(spells_socket(&value, &input[..consumed]));
            if let SocketAddr::V6(v6) = &value {
                assert!(zero_flow_and_scope(v6));
            }

            // Writing it gives the same bytes back.
            let mut out = [0u8; MAX];
            let written = write_into(&value, &mut out);
            assert!(same_bytes(&out[..written], &input[..consumed]));

            kani::cover!(value.is_ipv4(), "accepts an IPv4 socket address");
            kani::cover!(value.is_ipv6(), "accepts an IPv6 socket address");
            kani::cover!(consumed < len, "accepts with bytes left in the buffer");
        }
        Err(Error::EndOfBuffer) => {
            // Item 2: no tag, or fewer bytes than the tag announces.
            assert!(
                len == 0
                    || (input[0] == TAG_V4 && len < TAG + V4 + PORT)
                    || (input[0] == TAG_V6 && len < TAG + V6 + PORT)
            );

            kani::cover!(len == 0, "empty input ends the buffer");
            kani::cover!(len == TAG + V4, "an IPv4 socket address with no port");
            kani::cover!(
                len == TAG + V6 + 1,
                "an IPv6 socket address with half a port"
            );
        }
        Err(Error::Invalid(_, _)) => {
            // Item 7: only a tag that is neither 4 nor 6.
            assert!(len >= 1 && input[0] != TAG_V4 && input[0] != TAG_V6);

            kani::cover!(input[0] == 0, "rejects the tag 0");
            kani::cover!(input[0] == 5, "rejects the tag 5");
            kani::cover!(len == N, "rejects a bad tag in front of a full input");
        }
        Err(_) => panic!("unexpected error kind"),
    }
}

#[kani::proof]
#[kani::unwind(22)]
fn kani_p7_ip_addr_roundtrip() {
    const MAX: usize = TAG + V6;
    let v4: bool = kani::any();
    let value = if v4 {
        IpAddr::V4(any_ipv4())
    } else {
        IpAddr::V6(any_ipv6())
    };

    // Item 5. `write_into` panics if more than MAX bytes are written.
    let mut out = [0u8; MAX];
    let written = write_into(&value, &mut out);
    assert!(written == value.encode_size());
    assert!(written <= IpAddr::MAX_ENCODE_SIZE);

    // Item 8: the tag and the octets.
    assert!(written == TAG + if v4 { V4 } else { V6 });
    assert!(spells_ip(&value, &out[..written]));

    // Item 6: reading gives the value back and leaves nothing.
    let mut buf = Copying(&out[..written]);
    let decoded = IpAddr::read(&mut buf);
    assert!(matches!(decoded, Ok(v) if v == value));
    assert!(buf.remaining() == 0);
    assert!(matches!(IpAddr::decode(Copying(&out[..written])), Ok(v) if v == value));

    kani::cover!(v4, "an IPv4 address");
    kani::cover!(
        written == IpAddr::MAX_ENCODE_SIZE,
        "a value of the maximum size"
    );
}

#[kani::proof]
#[kani::unwind(22)]
fn kani_p7_socket_addr_roundtrip() {
    const MAX: usize = TAG + V6 + PORT;
    let v4: bool = kani::any();
    let port: u16 = kani::any();
    // Item 9: an IPv6 socket address with flow information 0 and scope id 0.
    let value = if v4 {
        SocketAddr::V4(SocketAddrV4::new(any_ipv4(), port))
    } else {
        SocketAddr::V6(SocketAddrV6::new(any_ipv6(), port, 0, 0))
    };

    // Item 5. `write_into` panics if more than MAX bytes are written.
    let mut out = [0u8; MAX];
    let written = write_into(&value, &mut out);
    assert!(written == value.encode_size());
    assert!(written <= SocketAddr::MAX_ENCODE_SIZE);

    // Item 8: the tag, the octets and the port.
    assert!(written == TAG + if v4 { V4 } else { V6 } + PORT);
    assert!(spells_socket(&value, &out[..written]));

    // Item 6: reading gives the value back and leaves nothing.
    let mut buf = Copying(&out[..written]);
    let decoded = SocketAddr::read(&mut buf);
    assert!(matches!(decoded, Ok(v) if v == value));
    assert!(buf.remaining() == 0);
    assert!(matches!(SocketAddr::decode(Copying(&out[..written])), Ok(v) if v == value));

    kani::cover!(v4, "an IPv4 socket address");
    kani::cover!(
        written == SocketAddr::MAX_ENCODE_SIZE,
        "a value of the maximum size"
    );
}

/// Item 5: the size constants are the sums of the parts.
#[kani::proof]
fn kani_p7_sizes() {
    assert!(Ipv4Addr::SIZE == V4);
    assert!(Ipv6Addr::SIZE == V6);
    assert!(u16::SIZE == PORT);
    assert!(u8::SIZE == TAG);
    assert!(SocketAddrV4::SIZE == Ipv4Addr::SIZE + u16::SIZE);
    assert!(SocketAddrV6::SIZE == Ipv6Addr::SIZE + u16::SIZE);
    // The tag's bound and the largest variant bound.
    assert!(Ipv6Addr::MAX_ENCODE_SIZE >= Ipv4Addr::MAX_ENCODE_SIZE);
    assert!(IpAddr::MAX_ENCODE_SIZE == u8::MAX_ENCODE_SIZE + Ipv6Addr::MAX_ENCODE_SIZE);
    assert!(SocketAddr::MAX_ENCODE_SIZE == IpAddr::MAX_ENCODE_SIZE + u16::MAX_ENCODE_SIZE);
}
