//! Property tests of `commonware-codec`, written with the `ephyra` library.
//!
//! Each of the five properties checks documented contracts of the crate
//! (rustdoc or module documentation). The contracts are quoted above the
//! property with their source: file and lines of `codec/src` as of `main` at
//! commit c2627b4132. A property asserts no more than its quoted text
//! promises; what the documentation leaves open is listed as "not asserted".
//!
//! A run without settings is deterministic: a fixed seed and a fixed number of
//! cases per property (see [`config`]). `EPHYRA_SEED`, `EPHYRA_TESTS` and
//! `EPHYRA_BUDGET_MS` change the seed and the budget without a rebuild. The
//! commands are in `codec/fuzz/experimental/README.md`.
//!
//! The name of every property test starts with `ephyra_`, so a name filter
//! selects exactly the properties. The one other test in this file is in the
//! `miri` test group: it covers the unsafe code of the `Chunks` adapter.
//!
//! - `generators.rs`: the generators, the reference models and the inputs.
//! - `checks.rs`: checks of the generators.

use bytes::{Buf as _, BufMut, Bytes, BytesMut, buf::UninitSlice};
use commonware_codec::{
    BufsMut, Codec, Copying, Decode, DecodeExt, DecodeFixed, DecodeRangeExt, Encode, EncodeFixed,
    EncodeSize, Error, FixedSize, IsUnit, MaxEncodeSize, Mode, Modes, RangeCfg, Read, ReadExt,
    U256, Uint, Viewing, Write,
    types::lazy::Lazy,
    util::max_items_size,
    varint::{
        Decoder, MAX_U16_VARINT_SIZE, MAX_U32_VARINT_SIZE, MAX_U64_VARINT_SIZE,
        MAX_U128_VARINT_SIZE, SInt, UInt,
    },
};
use ephyra::prelude::*;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
    ops::Bound,
    sync::Arc,
};

mod checks;
mod generators;
use generators::*;

/// The seed of a run that sets no `EPHYRA_SEED`.
const SEED: u64 = 0x636f_6465_6321;

/// The number of passing cases of each property in a run that sets no
/// `EPHYRA_TESTS`.
const TESTS: u64 = 1_000;

/// The configuration of every test in this file: the same inputs on every run
/// unless the environment says otherwise, and nothing written to disk (failing
/// inputs are saved and replayed only with `EPHYRA_REGRESSIONS=1`).
fn config(name: &str) -> Config {
    Config::default()
        .seed(SEED)
        .tests(TESTS)
        .name(name)
        .no_regressions()
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

type Range = RangeCfg<usize>;

fn any_len() -> Range {
    RangeCfg::new(..)
}

/// A `BufsMut` that records how many bytes were written inline and pushed.
struct Chunks {
    out: BytesMut,
    inline: usize,
}

// SAFETY: every method forwards to the inner `BytesMut`.
unsafe impl BufMut for Chunks {
    fn remaining_mut(&self) -> usize {
        self.out.remaining_mut()
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        self.out.chunk_mut()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.inline += cnt;
        // SAFETY: the caller upholds the contract of `BufMut::advance_mut`.
        unsafe { self.out.advance_mut(cnt) }
    }
}

impl BufsMut for Chunks {
    fn push(&mut self, chunk: impl Into<Bytes> + 'static) {
        let chunk: Bytes = chunk.into();
        self.out.extend_from_slice(&chunk);
    }
}

/// `Chunks` alone, without the ephyra runner, so that Miri can check its unsafe
/// code: inline writes of several widths, a write that grows the buffer, pushed
/// chunks, and one encoding through `write_bufs`.
#[commonware_macros::test_group("miri")]
#[test]
fn chunks_counts_inline_writes_and_appends_pushed_chunks() {
    let mut chunks = Chunks {
        out: BytesMut::new(),
        inline: 0,
    };
    chunks.put_u8(7);
    chunks.put_slice(&[1, 2, 3]);
    chunks.push(Bytes::from_static(b"pushed"));
    chunks.put_u64(0x0102_0304_0506_0708);
    chunks.push(vec![9u8; 5]);
    chunks.put_bytes(0xAA, 300);

    let mut expected = vec![7, 1, 2, 3];
    expected.extend_from_slice(b"pushed");
    expected.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    expected.extend_from_slice(&[9; 5]);
    expected.extend_from_slice(&[0xAA; 300]);
    assert_eq!(chunks.out.as_ref(), &expected[..]);
    assert_eq!(
        chunks.inline,
        1 + 3 + 8 + 300,
        "pushed bytes are not inline"
    );

    // `Bytes` writes its length inline and pushes its payload.
    let value = (0x0A0B_0C0Du32, Bytes::from_static(b"payload"), true);
    let mut chunks = Chunks {
        out: BytesMut::new(),
        inline: 0,
    };
    value.write_bufs(&mut chunks);
    assert_eq!(chunks.out.as_ref(), value.encode().as_ref());
    assert_eq!(chunks.inline, 4 + 1 + 1, "u32, length prefix and bool");
    assert_eq!(chunks.inline, value.encode_inline_size());
}

/// The round-trip contract for one value (property 2).
fn roundtrip<T>(what: &str, value: &T, cfg: &T::Cfg, extra: &[u8])
where
    T: Codec + PartialEq + Debug,
{
    signature(format!("roundtrip: {what}"));

    // `encode_size` is the exact size (`Encode::encode` panics otherwise).
    let encoded = value.encode();
    assert_eq!(encoded.len(), value.encode_size(), "{what}: encode_size");

    // decode(encode(x)) == x
    match T::decode_cfg(encoded.clone(), cfg) {
        Ok(decoded) => assert_eq!(&decoded, value, "{what}: decoded value differs"),
        Err(e) => panic!("{what}: a valid encoding was rejected: {e:?}"),
    }

    // `write_bufs` "must encode to the same format as `Write::write`".
    let mut chunks = Chunks {
        out: BytesMut::new(),
        inline: 0,
    };
    value.write_bufs(&mut chunks);
    assert_eq!(
        chunks.out.as_ref(),
        encoded.as_ref(),
        "{what}: write_bufs format"
    );
    // `encode_inline_size` "must not be less than the bytes written inline".
    assert!(
        chunks.inline <= value.encode_inline_size(),
        "{what}: {} bytes written inline, encode_inline_size is {}",
        chunks.inline,
        value.encode_inline_size()
    );

    // Leftover bytes are an error that says how many were left.
    if !extra.is_empty() {
        let mut longer = encoded.to_vec();
        longer.extend_from_slice(extra);
        match T::decode_cfg(longer, cfg) {
            Err(Error::ExtraData(n)) => assert_eq!(n, extra.len(), "{what}: ExtraData count"),
            other => panic!("{what}: trailing bytes not reported as ExtraData: {other:?}"),
        }
    }
}

fn roundtrip_unit<X, T>(what: &str, value: &T, extra: &[u8])
where
    X: IsUnit + Clone + Send + Sync + 'static,
    T: Codec<Cfg = X> + PartialEq + Debug,
{
    roundtrip(what, value, &X::default(), extra);
}

// ---------------------------------------------------------------------------
// Property 1: integer encodings match their reference models
// ---------------------------------------------------------------------------
//
// Contracts:
//
// - codec/src/varint.rs, module docs: "This module implements Google's Protocol
//   Buffers variable-length integer encoding. Each byte uses: 7 bits for the
//   value, 1 "continuation" bit to indicate if more bytes follow".
// - codec/src/varint.rs, module example: "Signed example (ZigZag)";
//   codec/src/varint.rs, `SPrim`: "the encoding is done using ZigZag encoding,
//   which moves the sign bit to the least significant bit".
// - codec/src/varint.rs, `MAX_U16_VARINT_SIZE` to `MAX_U128_VARINT_SIZE`:
//   "Maximum encoded size of a u16 [u32, u64, u128] varint in bytes."
// - codec/src/varint.rs, `Decoder::feed`: "`Ok(Some(value))` when the varint is
//   complete; `Ok(None)` when more bytes are needed; `Err(InvalidVarint)` if
//   the varint is malformed (overflow or invalid encoding)".
// - codec/src/varint.rs, `read`: "Returns an error if: The varint is invalid
//   (too long or malformed); The buffer ends while reading".
// - codec/src/error.rs, `Error::InvalidVarint`: "The varint encoding itself is
//   malformed (e.g., too long). The decoded varint value exceeds the capacity
//   of the target integer type."
// - codec/src/types/primitives.rs, module docs: `usize` "uses variable-length
//   (varint) encoding" and "is restricted to values that fit in a `u32`".
// - codec/src/uint.rs, `Uint`: "It encodes as its value in big-endian over the
//   fewest bytes that hold its bits. Decoding refuses an encoding with a bit
//   set beyond the width, so every value has exactly one encoding."
//
// Not asserted: what a padded varint such as `[0x80, 0x00]` decodes to. The
// documentation calls a "malformed" varint an error but does not say that a
// padded one is malformed. For such an input the reference model answers
// `Model::NonCanonical` and this property accepts any result.

macro_rules! check_value {
    ($u:ty, $s:ty, $max:expr, $wide:expr) => {{
        let x = $wide as $u;
        let bits = <$u>::BITS;

        // Unsigned: the encoding is the LEB128 of the value.
        signature(format!("varint: u{bits} encoding"));
        let expected = leb128(x as u128);
        let encoded = UInt(x).encode();
        assert_eq!(encoded.as_ref(), &expected[..], "UInt<u{bits}>({x}) bytes");
        assert_eq!(
            UInt(x).encode_size(),
            expected.len(),
            "UInt<u{bits}>({x}) size"
        );
        assert!(
            expected.len() <= $max,
            "UInt<u{bits}>({x}) longer than the maximum"
        );
        assert_eq!(<UInt<$u> as MaxEncodeSize>::MAX_ENCODE_SIZE, $max);
        match UInt::<$u>::decode(encoded.clone()) {
            Ok(UInt(back)) => assert_eq!(back, x, "UInt<u{bits}> round trip"),
            Err(e) => panic!("UInt<u{bits}>({x}): own encoding rejected: {e:?}"),
        }

        // Signed: ZigZag, then the same varint.
        signature(format!("varint: i{bits} encoding"));
        let n = x as $s;
        let zigzag = ((n << 1) ^ (n >> (bits - 1))) as $u;
        let expected = leb128(zigzag as u128);
        let encoded = SInt(n).encode();
        assert_eq!(encoded.as_ref(), &expected[..], "SInt<i{bits}>({n}) bytes");
        assert_eq!(
            SInt(n).encode_size(),
            expected.len(),
            "SInt<i{bits}>({n}) size"
        );
        match SInt::<$s>::decode(encoded) {
            Ok(SInt(back)) => assert_eq!(back, n, "SInt<i{bits}> round trip"),
            Err(e) => panic!("SInt<i{bits}>({n}): own encoding rejected: {e:?}"),
        }
    }};
}

macro_rules! check_stream {
    ($u:ty, $stream:expr) => {{
        let stream: &[u8] = $stream;
        let bits = <$u>::BITS;
        let model = model_decode(stream, bits);

        // The one-shot reader.
        signature(format!("varint: u{bits} decoding"));
        let mut buf = Copying(stream);
        let got = UInt::<$u>::read(&mut buf).map(|v| (v.0 as u128, stream.len() - buf.remaining()));
        match (&model, &got) {
            (Model::Value(v, used), Ok((g, n))) => {
                assert_eq!(
                    (*g, *n),
                    (*v, *used),
                    "u{bits}: value or length of {stream:?}"
                )
            }
            (Model::Value(..), Err(e)) => {
                panic!("u{bits}: valid varint {stream:?} rejected: {e:?}")
            }
            (Model::Overflow, Err(Error::InvalidVarint(_))) => {}
            (Model::Overflow, other) => {
                panic!("u{bits}: overflowing varint {stream:?} gave {other:?}")
            }
            (Model::Truncated, Err(Error::EndOfBuffer)) => {}
            (Model::Truncated, other) => {
                panic!("u{bits}: truncated varint {stream:?} gave {other:?}")
            }
            // A padded varint: no documented contract, so no assertion.
            (Model::NonCanonical, _) => {}
        }

        // The incremental decoder gives the same answer byte by byte.
        signature(format!("varint: Decoder<u{bits}>"));
        let mut decoder = Decoder::<$u>::new();
        let mut fed = 0usize;
        let mut incremental: Option<Result<u128, ()>> = None;
        for &b in stream {
            fed += 1;
            match decoder.feed(b) {
                Ok(None) => {}
                Ok(Some(v)) => {
                    incremental = Some(Ok(v as u128));
                    break;
                }
                Err(_) => {
                    incremental = Some(Err(()));
                    break;
                }
            }
        }
        match (&model, &incremental) {
            (Model::Value(v, used), Some(Ok(g))) => {
                assert_eq!((*g, fed), (*v, *used), "Decoder<u{bits}> on {stream:?}")
            }
            (Model::Truncated, None) => {}
            (Model::Overflow, Some(Err(()))) => {}
            // A padded varint: no documented contract, so no assertion.
            (Model::NonCanonical, _) => {}
            (m, i) => panic!("Decoder<u{bits}> on {stream:?}: model {m:?}, decoder {i:?}"),
        }
    }};
}

/// `Uint<BITS, LIMBS>` against a big-endian model of its fixed-width encoding.
fn check_uint<const BITS: usize, const LIMBS: usize>(raw: &[u8]) {
    signature(format!("Uint<{BITS}>"));
    let size = BITS.div_ceil(8);
    assert_eq!(<Uint<BITS, LIMBS> as FixedSize>::SIZE, size, "fewest bytes");
    let bytes = &raw[..size];

    // Limbs of the big-endian integer, least significant first.
    let mut limbs = [0u64; LIMBS];
    for (j, b) in bytes.iter().rev().enumerate() {
        limbs[j / 8] |= u64::from(*b) << (8 * (j % 8));
    }
    let beyond = !BITS.is_multiple_of(8) && bytes[0] >> (BITS % 8) != 0;

    let decoded = Uint::<BITS, LIMBS>::decode(Bytes::copy_from_slice(bytes));
    if beyond {
        assert!(
            matches!(decoded, Err(Error::Invalid(_, _))),
            "Uint<{BITS}>: a bit beyond the width was accepted: {bytes:?} gave {decoded:?}"
        );
    } else {
        let value = match decoded {
            Ok(value) => value,
            Err(e) => panic!("Uint<{BITS}>: {bytes:?} rejected: {e:?}"),
        };
        assert_eq!(value.as_limbs(), &limbs, "Uint<{BITS}> value");
        assert_eq!(value, Uint::<BITS, LIMBS>::from_limbs(limbs));
        assert_eq!(
            value.encode().as_ref(),
            bytes,
            "Uint<{BITS}> has one encoding"
        );
    }
}

#[ephyra::test(
    config = config("ephyra_p1_integer_encodings_match_reference_models"),
    gen = (wide(), varint_like(), raw(32))
)]
fn ephyra_p1_integer_encodings_match_reference_models(value: u128, stream: Vec<u8>, raw: Vec<u8>) {
    check_value!(u16, i16, MAX_U16_VARINT_SIZE, value);
    check_value!(u32, i32, MAX_U32_VARINT_SIZE, value);
    check_value!(u64, i64, MAX_U64_VARINT_SIZE, value);
    check_value!(u128, i128, MAX_U128_VARINT_SIZE, value);

    // `usize` is a varint of a `u32`.
    signature("varint: usize");
    let small = value as u32;
    let encoded = (small as usize).encode();
    assert_eq!(encoded, UInt(small).encode(), "usize is a u32 varint");
    assert_eq!((small as usize).encode_size(), encoded.len());
    match usize::decode_cfg(encoded, &any_len()) {
        Ok(back) => assert_eq!(back, small as usize),
        Err(e) => panic!("usize {small}: own encoding rejected: {e:?}"),
    }

    // Arbitrary bytes, and the value's own encoding with a changed last byte.
    check_stream!(u16, &stream);
    check_stream!(u32, &stream);
    check_stream!(u64, &stream);
    check_stream!(u128, &stream);
    let mut near = leb128(value);
    if let (Some(last), Some(first)) = (near.last_mut(), stream.first()) {
        *last = *first;
    }
    check_stream!(u16, &near);
    check_stream!(u32, &near);
    check_stream!(u64, &near);
    check_stream!(u128, &near);

    // Fixed-width integers: the raw bytes, and the same bytes with the top
    // byte cleared so that most widths accept them.
    let mut masked = raw.clone();
    masked[0] &= 0x01;
    for bytes in [&raw, &masked] {
        check_uint::<64, 1>(bytes);
        check_uint::<65, 2>(bytes);
        check_uint::<100, 2>(bytes);
        check_uint::<129, 3>(bytes);
        check_uint::<256, 4>(bytes);
    }
}

// ---------------------------------------------------------------------------
// Property 2: round trip, exact size, and full consumption
// ---------------------------------------------------------------------------
//
// Contracts:
//
// - codec/src/codec.rs, `EncodeSize::encode_size`: "Returns the encoded size of
//   this value (in bytes)."
// - codec/src/codec.rs, `Encode::encode`: "Panics if `encode_size()` does not
//   return the same number of bytes actually written by `write()`".
// - codec/src/lib.rs, module docs, Examples 1 and 2: "let decoded_point =
//   Point::decode(bytes).unwrap(); assert_eq!(point, decoded_point);".
// - codec/src/codec.rs, `Decode::decode_cfg`: "Decodes a value from `buf` using
//   `cfg`, ensuring the entire buffer is consumed. [...] Returns [Error] if
//   decoding fails via [Read::read_cfg] or if there are leftover bytes in `buf`
//   after reading."
// - codec/src/error.rs, `Error::ExtraData`: "The contained `usize` is the
//   number of bytes that remained unconsumed."
// - codec/src/codec.rs, `Write::write_bufs`: "Must encode to the same format as
//   [`Write::write`]."
// - codec/src/codec.rs, `EncodeSize::encode_inline_size`: "it must not be less
//   than the bytes written inline".
// - codec/src/lib.rs, module docs, Supported Types: "`Arc<T>` (delegates to
//   `T`)".
// - codec/src/types/primitives.rs, module docs: "All fixed-size integers and
//   floats are written big-endian".
// - codec/src/mode.rs, `Modes`: "The high bit indicates that another mode
//   follows, and trailing zero-valued modes are omitted." codec/src/mode.rs,
//   `Modes::new`: "Returns `None` when every mode is zero."
// - codec/fuzz/fuzz_targets/codec_roundtrip.rs, `roundtrip_socket_v6`, and
//   codec/src/types/net.rs, `Read for SocketAddrV6`: a decoded `SocketAddrV6`
//   has flowinfo and scope id 0, so the generator keeps them 0.

struct Net {
    ip4: Ipv4Addr,
    ip6: Ipv6Addr,
    ip: IpAddr,
    sock: SocketAddr,
    sock4: SocketAddrV4,
    sock6: SocketAddrV6,
}

fn net(s: &Sample) -> Net {
    let ip4 = Ipv4Addr::new(s.ip[0], s.ip[1], s.ip[2], s.ip[3]);
    let ip6 = Ipv6Addr::from(<[u8; 16]>::try_from(&s.ip[..]).unwrap());
    let ip: IpAddr = if s.v6 { ip6.into() } else { ip4.into() };
    Net {
        ip4,
        ip6,
        ip,
        sock: SocketAddr::new(ip, s.port),
        sock4: SocketAddrV4::new(ip4, s.port),
        sock6: SocketAddrV6::new(ip6, s.port, 0, 0),
    }
}

#[ephyra::test(config = config("ephyra_p2_roundtrip_exact_size_full_consumption"))]
fn ephyra_p2_roundtrip_exact_size_full_consumption(s: Sample) {
    let extra = &s.extra[..];
    let r = any_len();
    let n = net(&s);

    // Scalars and tuples.
    roundtrip_unit("8-tuple of integers", &s.ints, extra);
    roundtrip(
        "(u128, i128, bool, usize)",
        &(s.big, s.big as i128, s.flag, s.ints.2 as usize),
        &((), (), (), r),
        extra,
    );

    // Floats: compared by bits, and written big-endian.
    signature("roundtrip: floats");
    let (f, d) = (f32::from_bits(s.floats.0), f64::from_bits(s.floats.1));
    let encoded = (f, d).encode();
    let mut expected = s.floats.0.to_be_bytes().to_vec();
    expected.extend_from_slice(&s.floats.1.to_be_bytes());
    assert_eq!(encoded.as_ref(), &expected[..], "floats are big-endian");
    match <(f32, f64)>::decode(encoded) {
        Ok((f2, d2)) => assert_eq!((f2.to_bits(), d2.to_bits()), s.floats),
        Err(e) => panic!("floats rejected: {e:?}"),
    }

    // Byte containers.
    roundtrip("Vec<u8>", &s.blob, &(r, ()), extra);
    roundtrip("Bytes", &Bytes::from(s.blob.clone()), &r, extra);
    signature("roundtrip: Arc delegates");
    assert_eq!(Arc::new(s.blob.clone()).encode(), s.blob.encode());

    // Sequences.
    roundtrip("Vec<Option<u32>>", &s.opts, &(r, ()), extra);
    roundtrip("Vec<Vec<u16>>", &s.nested, &(r, (r, ())), extra);
    let varints: Vec<UInt<u64>> = s.keys.iter().map(|k| UInt(u64::from(*k) << 13)).collect();
    roundtrip("Vec<UInt<u64>>", &varints, &(r, ()), extra);
    roundtrip_unit(
        "(UInt<u128>, SInt<i64>, Option<SInt<i32>>)",
        &(
            UInt(s.big),
            SInt(s.ints.7),
            s.flag.then_some(SInt(s.ints.6)),
        ),
        extra,
    );

    // Maps and sets.
    let btree: BTreeMap<u16, Vec<u8>> = s.pairs.iter().cloned().collect();
    let hash: HashMap<u16, Vec<u8>> = s.pairs.iter().cloned().collect();
    let bset: BTreeSet<u32> = s.keys.iter().copied().collect();
    let hset: HashSet<u32> = s.keys.iter().copied().collect();
    roundtrip("BTreeMap<u16, Vec<u8>>", &btree, &(r, ((), (r, ()))), extra);
    roundtrip("HashMap<u16, Vec<u8>>", &hash, &(r, ((), (r, ()))), extra);
    roundtrip("BTreeSet<u32>", &bset, &(r, ()), extra);
    roundtrip("HashSet<u32>", &hset, &(r, ()), extra);

    // Arrays and network types.
    let bytes16: [u8; 16] = s.ip[..].try_into().unwrap();
    roundtrip_unit("[u8; 16]", &bytes16, extra);
    roundtrip_unit("[u16; 4]", &[s.ints.1, s.port, !s.ints.1, 0], extra);
    roundtrip_unit("Ipv4Addr", &n.ip4, extra);
    roundtrip_unit("Ipv6Addr", &n.ip6, extra);
    roundtrip_unit("IpAddr", &n.ip, extra);
    roundtrip_unit("SocketAddr", &n.sock, extra);
    roundtrip_unit("SocketAddrV4", &n.sock4, extra);
    roundtrip_unit("SocketAddrV6", &n.sock6, extra);
    roundtrip_unit("Option<SocketAddr>", &s.flag.then_some(n.sock), extra);

    // Lazy and fixed-width integers.
    roundtrip_unit("Lazy<u64>", &Lazy::new(s.ints.3), extra);
    let u256 = U256::from_limbs([s.ints.3, s.big as u64, (s.big >> 64) as u64, s.floats.1]);
    roundtrip_unit("U256", &u256, extra);

    // A composite with a composite configuration.
    roundtrip(
        "composite tuple",
        &(
            s.ints,
            s.blob.clone(),
            btree.clone(),
            hset.clone(),
            s.flag.then_some(n.sock),
            Bytes::from(s.blob.clone()),
        ),
        &(
            Default::default(),
            (r, ()),
            (r, ((), (r, ()))),
            (r, ()),
            (),
            r,
        ),
        extra,
    );

    // Modes: the documented packet format.
    signature("roundtrip: Modes<4>");
    let modes: [Mode; 4] = std::array::from_fn(|i| Mode::new(s.modes[i]).unwrap());
    match Modes::new(modes) {
        None => assert!(s.modes.iter().all(|m| *m == 0), "None for a non-zero list"),
        Some(packet) => {
            let last = s
                .modes
                .iter()
                .rposition(|m| *m != 0)
                .expect("a non-zero mode");
            let expected: Vec<u8> = (0..=last)
                .map(|i| {
                    if i < last {
                        s.modes[i] | 0x80
                    } else {
                        s.modes[i]
                    }
                })
                .collect();
            assert_eq!(
                packet.encode().as_ref(),
                &expected[..],
                "Modes packet format"
            );
            roundtrip_unit("Modes<4>", &packet, extra);
        }
    }
}

// ---------------------------------------------------------------------------
// Property 3: length limits are enforced
// ---------------------------------------------------------------------------
//
// Contracts:
//
// - codec/src/lib.rs, module docs: "Deserialization of untrusted data is made
//   safer via the `Cfg` associated type in the [Read] trait, allowing users to
//   impose limits (like maximum lengths)".
// - codec/src/config.rs, `RangeCfg`: "Configuration for limiting the range of a
//   value. This is often used to configure length limits for variable-length
//   types or collections."
// - codec/src/config.rs, `RangeCfg::contains`: "Returns true if the value is
//   within this range."
// - codec/src/error.rs, `Error::InvalidLength`: "A length prefix (e.g., for
//   `Vec<T>`, `Bytes`, `HashMap<K, V>`) was decoded, but its value fell outside
//   the permitted range. [...] The contained `usize` is the invalid length that
//   was decoded."
// - codec/src/types/primitives.rs, module docs: "When decoding a `usize`,
//   callers must supply a [RangeCfg] to bound the allowable value." Together
//   with codec/src/codec.rs, `Read::read_cfg` ("Implementations must return
//   [Error] if decoding fails due to [...] violation of constraints imposed by
//   the `cfg`") this promises an error for a bare `usize` outside its range,
//   but not which one: `InvalidLength` is documented for a length prefix. So
//   the bare `usize` is only required to fail.
// - codec/src/extensions.rs, `DecodeRangeExt::decode_range`: "Decodes a value
//   using only a range configuration."

/// Reference: is `n` inside the two bounds?
fn within(n: usize, start: Bound<usize>, end: Bound<usize>) -> bool {
    let above = match start {
        Bound::Included(s) => n >= s,
        Bound::Excluded(s) => n > s,
        Bound::Unbounded => true,
    };
    let below = match end {
        Bound::Included(e) => n <= e,
        Bound::Excluded(e) => n < e,
        Bound::Unbounded => true,
    };
    above && below
}

fn limited<T>(what: &str, n: usize, ok: bool, value: &T, cfg: &T::Cfg)
where
    T: Codec + PartialEq + Debug,
{
    signature(format!("limits: {what}"));
    let decoded = T::decode_cfg(value.encode(), cfg);
    if ok {
        match decoded {
            Ok(back) => assert_eq!(&back, value, "{what}: length {n} is in range"),
            Err(e) => panic!("{what}: length {n} is in range but was rejected: {e:?}"),
        }
    } else {
        match decoded {
            Err(Error::InvalidLength(len)) => assert_eq!(len, n, "{what}: reported length"),
            other => panic!("{what}: length {n} is out of range but gave {other:?}"),
        }
    }
}

#[ephyra::test(config = config("ephyra_p3_length_limits_are_enforced"))]
fn ephyra_p3_length_limits_are_enforced(l: Limits) {
    let n = l.n;
    let ok = within(n, l.start, l.end);
    cover(ok, "length in range");
    cover(!ok, "length out of range");
    let range: Range = RangeCfg::new((l.start, l.end));

    signature("limits: RangeCfg::contains");
    assert_eq!(
        range.contains(&n),
        ok,
        "contains({n}) for {:?}..{:?}",
        l.start,
        l.end
    );

    // `n` distinct keys.
    let keys: Vec<u16> = (0..n as u16)
        .map(|i| i.wrapping_mul(257).wrapping_add(l.salt))
        .collect();
    let bytes: Vec<u8> = keys.iter().map(|k| *k as u8).collect();

    // A bare `usize` is not a length prefix: inside the range it decodes,
    // outside it fails, and the error variant is not asserted.
    signature("limits: usize");
    match usize::decode_cfg(n.encode(), &range) {
        Ok(back) => assert!(
            ok && back == n,
            "usize {n} outside its range decoded as {back}"
        ),
        Err(e) => assert!(!ok, "usize {n} is in range but was rejected: {e:?}"),
    }
    limited("Vec<u8>", n, ok, &bytes, &(range, ()));
    limited("Bytes", n, ok, &Bytes::from(bytes.clone()), &range);
    limited("Vec<u16>", n, ok, &keys, &(range, ()));
    let varints: Vec<UInt<u16>> = keys.iter().map(|k| UInt(*k)).collect();
    limited("Vec<UInt<u16>>", n, ok, &varints, &(range, ()));
    let btree: BTreeMap<u16, u8> = keys.iter().map(|k| (*k, *k as u8)).collect();
    limited("BTreeMap<u16, u8>", n, ok, &btree, &(range, ((), ())));
    let hash: HashMap<u16, u8> = keys.iter().map(|k| (*k, *k as u8)).collect();
    limited("HashMap<u16, u8>", n, ok, &hash, &(range, ((), ())));
    let bset: BTreeSet<u16> = keys.iter().copied().collect();
    limited("BTreeSet<u16>", n, ok, &bset, &(range, ()));
    let hset: HashSet<u16> = keys.iter().copied().collect();
    limited("HashSet<u16>", n, ok, &hset, &(range, ()));

    // A nested limit: the outer length is 1, the inner length is `n`.
    limited(
        "Vec<Vec<u16>> inner",
        n,
        ok,
        &vec![keys.clone()],
        &(any_len(), (range, ())),
    );

    // The extension gives the same answer as the full configuration.
    signature("limits: decode_range");
    let short = Vec::<u8>::decode_range(bytes.encode(), (l.start, l.end));
    match short {
        Ok(back) => assert!(ok && back == bytes, "decode_range accepted length {n}"),
        Err(Error::InvalidLength(len)) => assert!(!ok && len == n, "decode_range rejected {n}"),
        Err(e) => panic!("decode_range: {e:?}"),
    }
}

// ---------------------------------------------------------------------------
// Property 4: untrusted bytes
// ---------------------------------------------------------------------------
//
// Contracts:
//
// - codec/src/codec.rs, `Read::read_cfg`: "Parsing a message (often untrusted)
//   should never result in a panic."
// - codec/src/codec.rs, `Read::read_cfg`: "Implementations must return [Error]
//   if decoding fails due to invalid data, insufficient bytes in the buffer, or
//   violation of constraints imposed by the `cfg`."
// - codec/src/error.rs, `Error::EndOfBuffer`: "the input buffer (`Buf`) did not
//   contain enough bytes to read the next piece of data [...] This suggests the
//   input data is truncated or incomplete."
// - codec/src/util.rs, `read_fixed_vec`: "Checks that the buffer contains all
//   `len * SIZE` bytes before allocating or decoding, so a maliciously large
//   `len` fails fast with [Error::EndOfBuffer]."
// - codec/src/lib.rs, module docs, Decode Inputs: owned `Bytes`, `Viewing`, an
//   owned `Vec<u8>` and `Copying` are four inputs to the same decoder; they
//   differ in who owns the bytes, so the decoded value must be the same.
// - The round-trip contract of property 2, applied to every value that the
//   decoder accepts.
//
// Not asserted (the docs do not promise it for every type): that an accepted
// input is the only encoding of its value. It is only counted with `classify`.

type Wire = (
    Vec<Option<u32>>,
    BTreeMap<u16, Vec<u8>>,
    HashSet<u32>,
    Bytes,
    Option<SocketAddr>,
    (UInt<u64>, SInt<i32>, usize, bool),
);

fn wire_cfg() -> <Wire as Read>::Cfg {
    let r: Range = RangeCfg::new(0..=LIMIT);
    ((r, ()), (r, ((), (r, ()))), (r, ()), r, (), ((), (), r, ()))
}

fn apply(bytes: &mut Vec<u8>, m: &Mutation) {
    match m {
        Mutation::Keep => {}
        Mutation::Truncate(n) => bytes.truncate(bytes.len().saturating_sub(*n)),
        Mutation::Flip(at, bit) if !bytes.is_empty() => {
            let i = at % bytes.len();
            bytes[i] ^= 1 << bit;
        }
        Mutation::Set(at, value) if !bytes.is_empty() => {
            let i = at % bytes.len();
            bytes[i] = *value;
        }
        Mutation::Insert(at, value) => bytes.insert(at % (bytes.len() + 1), *value),
        Mutation::Remove(at) if !bytes.is_empty() => {
            bytes.remove(at % bytes.len());
        }
        Mutation::Append(more) => bytes.extend_from_slice(more),
        _ => {}
    }
}

/// Decodes `bytes` as `T` through every input adapter and checks the answers.
fn untrusted<T>(what: &str, bytes: &[u8], cfg: &T::Cfg)
where
    T: Codec + PartialEq + Debug,
{
    signature(format!("untrusted: {what}"));
    let shared = Bytes::copy_from_slice(bytes);
    let owned = T::decode_cfg(shared.clone(), cfg);
    let others = [
        ("Vec<u8>", T::decode_cfg(bytes.to_vec(), cfg)),
        ("Copying", T::decode_cfg(Copying(bytes), cfg)),
        ("Viewing", T::decode_cfg(Viewing::new(&shared), cfg)),
    ];
    for (adapter, other) in &others {
        assert_eq!(
            owned.as_ref().ok(),
            other.as_ref().ok(),
            "{what}: Bytes and {adapter} inputs disagree: {owned:?} and {other:?}"
        );
        assert_eq!(
            owned.is_ok(),
            other.is_ok(),
            "{what}: Bytes and {adapter} disagree"
        );
    }

    let Ok(value) = owned else {
        return;
    };
    classify(true, format!("accepted: {what}"));
    let again = value.encode();
    assert_eq!(
        again.len(),
        value.encode_size(),
        "{what}: encode_size of an accepted value"
    );
    match T::decode_cfg(again.clone(), cfg) {
        Ok(back) => assert_eq!(back, value, "{what}: accepted value does not round trip"),
        Err(e) => panic!("{what}: re-encoding of an accepted value was rejected: {e:?}"),
    }
    classify(
        again.as_ref() != bytes,
        format!("accepted, not canonical: {what}"),
    );
}

#[ephyra::test(config = config("ephyra_p4_untrusted_bytes_never_panic_and_accepted_values_roundtrip"))]
fn ephyra_p4_untrusted_bytes_never_panic_and_accepted_values_roundtrip(h: Hostile) {
    // A valid message, then up to four edits.
    let ip: IpAddr = if h.addr.0 {
        Ipv6Addr::from(<[u8; 16]>::try_from(&h.ip[..]).unwrap()).into()
    } else {
        Ipv4Addr::new(h.ip[0], h.ip[1], h.ip[2], h.ip[3]).into()
    };
    let wire: Wire = (
        h.opts.clone(),
        h.pairs.iter().cloned().collect(),
        h.keys.iter().copied().collect(),
        Bytes::from(h.blob.clone()),
        h.addr.1.then_some(SocketAddr::new(ip, h.addr.2)),
        (UInt(h.scalars.0), SInt(h.scalars.1), h.count, h.scalars.2),
    );
    let mut bytes = wire.encode().to_vec();
    for m in &h.mutations {
        apply(&mut bytes, m);
    }
    let edited = h.mutations.iter().any(|m| !matches!(m, Mutation::Keep));
    cover(!edited, "unedited message");

    let r: Range = RangeCfg::new(0..=LIMIT);
    untrusted::<Wire>("Wire", &bytes, &wire_cfg());
    untrusted::<Vec<u64>>("Vec<u64>", &bytes, &(r, ()));
    untrusted::<Vec<UInt<u16>>>("Vec<UInt<u16>>", &bytes, &(r, ()));
    untrusted::<Vec<Option<u32>>>("Vec<Option<u32>>", &bytes, &(r, ()));
    untrusted::<HashMap<u8, u16>>("HashMap<u8, u16>", &bytes, &(r, ((), ())));
    untrusted::<BTreeSet<u16>>("BTreeSet<u16>", &bytes, &(r, ()));
    untrusted::<(SocketAddr, Vec<bool>)>("(SocketAddr, Vec<bool>)", &bytes, &((), (r, ())));
    untrusted::<(Modes<3>, Bytes)>("(Modes<3>, Bytes)", &bytes, &((), r));
    untrusted::<(Uint<100, 2>, Lazy<u32>, Vec<u8>)>(
        "(Uint<100>, Lazy<u32>, Vec<u8>)",
        &bytes,
        &((), (), (r, ())),
    );

    // A forged length prefix with too few bytes behind it, and no length limit.
    signature("untrusted: forged length");
    let len = h.forged_len as usize;
    let mut forged = UInt(h.forged_len).encode().to_vec();
    forged.extend_from_slice(&h.tail);
    let open = any_len();
    if len > h.tail.len() {
        let bytes = Vec::<u8>::decode_cfg(forged.clone(), &(open, ()));
        assert!(
            matches!(bytes, Err(Error::EndOfBuffer)),
            "Vec<u8> len {len}: {bytes:?}"
        );
        let bytes = Bytes::decode_cfg(forged.clone(), &open);
        assert!(
            matches!(bytes, Err(Error::EndOfBuffer)),
            "Bytes len {len}: {bytes:?}"
        );
    }
    if len as u64 * 8 > h.tail.len() as u64 {
        let words = Vec::<u64>::decode_cfg(forged.clone(), &(open, ()));
        assert!(
            matches!(words, Err(Error::EndOfBuffer)),
            "Vec<u64> len {len}: {words:?}"
        );
        let words = Vec::<[u8; 8]>::decode_cfg(forged.clone(), &(open, ()));
        assert!(
            matches!(words, Err(Error::EndOfBuffer)),
            "Vec<[u8; 8]> len {len}: {words:?}"
        );
    }
    if len as u64 * 16 > h.tail.len() as u64 {
        let map = BTreeMap::<u64, u64>::decode_cfg(forged.clone(), &(open, ((), ())));
        assert!(map.is_err(), "BTreeMap len {len}: {map:?}");
        let map = HashMap::<u64, u64>::decode_cfg(forged.clone(), &(open, ((), ())));
        assert!(map.is_err(), "HashMap len {len}: {map:?}");
    }
    if len as u64 * 8 > h.tail.len() as u64 {
        let set = HashSet::<u64>::decode_cfg(forged.clone(), &(open, ()));
        assert!(set.is_err(), "HashSet len {len}: {set:?}");
        let set = BTreeSet::<u64>::decode_cfg(forged, &(open, ()));
        assert!(set.is_err(), "BTreeSet len {len}: {set:?}");
    }
}

// ---------------------------------------------------------------------------
// Property 5: declared sizes are honoured
// ---------------------------------------------------------------------------
//
// Contracts:
//
// - codec/src/codec.rs, `FixedSize`: "the encoded representation of this type
//   *always* has the same byte length, regardless of the specific value."
// - codec/src/codec.rs, `EncodeFixed::encode_fixed`: "Encodes `self` into a
//   fixed-size byte array `[u8; N]`."; codec/src/codec.rs,
//   `DecodeFixed::decode_fixed`: "Decodes a value from a fixed-size byte array
//   `[u8; N]`, ensuring all bytes are consumed."
// - codec/src/codec.rs, `MaxEncodeSize`: "An upper bound on the encoded size,
//   in bytes."
// - codec/src/lib.rs, module docs, Size Bounds: "a `UInt<u64>` field
//   contributes ten bytes even when its valid values fit in one";
//   "`util::max_items_size` gives a 133-byte bound for a `Vec<u8>` limited to
//   128 bytes: 128 bytes of data and a five-byte `UInt<u32>` length prefix";
//   "[FixedSize] types contribute their fixed size. Composite types sum their
//   fields' bounds, and enums add their tag's bound to the largest variant
//   bound."
// - codec/src/util.rs, `max_items_size`: "Returns an upper bound on the encoded
//   size of a `Vec` or other length-prefixed sequence of `len` items that each
//   encode to at most `item_size` bytes, with the length prefix at its widest."
//
// Not asserted: what `max_items_size` does when that bound (the items plus a
// five-byte prefix) does not fit a `usize`. The check below runs on arguments
// whose bound is representable.

macro_rules! fixed {
    ($ty:ty, $n:literal, $value:expr) => {{
        signature(concat!("sizes: fixed ", stringify!($ty)));
        let value: $ty = $value;
        assert_eq!(<$ty as FixedSize>::SIZE, $n, "SIZE");
        assert_eq!(
            <$ty as MaxEncodeSize>::MAX_ENCODE_SIZE,
            $n,
            "the bound of a fixed type"
        );
        let encoded = value.encode();
        assert_eq!(encoded.len(), $n, "encoded length");
        let array: [u8; $n] = value.encode_fixed();
        assert_eq!(&array[..], encoded.as_ref(), "encode_fixed");
        match <$ty>::decode_fixed(array) {
            Ok(back) => assert_eq!(back, value, "decode_fixed"),
            Err(e) => panic!("decode_fixed rejected an encoding: {e:?}"),
        }
    }};
}

fn bounded<T: Encode + MaxEncodeSize>(what: &str, value: &T) {
    signature(format!("sizes: bound of {what}"));
    assert!(
        value.encode_size() <= T::MAX_ENCODE_SIZE,
        "{what}: size {} is over the bound {}",
        value.encode_size(),
        T::MAX_ENCODE_SIZE
    );
    assert_eq!(
        value.encode().len(),
        value.encode_size(),
        "{what}: encode_size"
    );
}

fn items<T: Encode + MaxEncodeSize>(what: &str, values: &Vec<T>, limit: usize) {
    signature(format!("sizes: max_items_size of {what}"));
    let bound = max_items_size(limit, T::MAX_ENCODE_SIZE);
    assert!(
        values.encode_size() <= bound,
        "{what}: {} items take {} bytes, the bound for {limit} items is {bound}",
        values.len(),
        values.encode_size()
    );
}

#[ephyra::test(config = config("ephyra_p5_declared_sizes_are_honoured"))]
fn ephyra_p5_declared_sizes_are_honoured(input: Sized) {
    let s = &input.sample;
    let n = net(s);

    // Fixed-size types always take SIZE bytes.
    fixed!(u8, 1, s.ints.0);
    fixed!(u16, 2, s.ints.1);
    fixed!(u32, 4, s.ints.2);
    fixed!(u64, 8, s.ints.3);
    fixed!(u128, 16, s.big);
    fixed!(i8, 1, s.ints.4);
    fixed!(i16, 2, s.ints.5);
    fixed!(i32, 4, s.ints.6);
    fixed!(i64, 8, s.ints.7);
    fixed!(i128, 16, s.big as i128);
    fixed!(bool, 1, s.flag);
    fixed!(NonZeroU16, 2, NonZeroU16::new(s.ints.1 | 1).unwrap());
    fixed!(NonZeroU32, 4, NonZeroU32::new(s.ints.2 | 1).unwrap());
    fixed!(NonZeroU64, 8, NonZeroU64::new(s.ints.3 | 1).unwrap());
    fixed!([u8; 16], 16, s.ip[..].try_into().unwrap());
    fixed!([u16; 3], 6, [s.ints.1, s.port, 0]);
    fixed!(Ipv4Addr, 4, n.ip4);
    fixed!(Ipv6Addr, 16, n.ip6);
    fixed!(SocketAddrV4, 6, n.sock4);
    fixed!(SocketAddrV6, 18, n.sock6);
    fixed!(
        U256,
        32,
        U256::from_limbs([s.ints.3, s.big as u64, (s.big >> 64) as u64, s.floats.1])
    );
    fixed!(Uint<100, 2>, 13, Uint::from_limbs([s.big as u64, (s.big >> 64) as u64 & 0xF_FFFF_FFFF]));

    // Documented bounds.
    signature("sizes: documented constants");
    assert_eq!(<UInt<u64> as MaxEncodeSize>::MAX_ENCODE_SIZE, 10);
    assert_eq!(max_items_size(128, 1), 133);
    assert_eq!(
        <(UInt<u32>, Option<IpAddr>, u8) as MaxEncodeSize>::MAX_ENCODE_SIZE,
        <UInt<u32> as MaxEncodeSize>::MAX_ENCODE_SIZE + (1 + (1 + 16)) + 1,
        "composite types sum their fields' bounds"
    );
    assert_eq!(<SocketAddr as MaxEncodeSize>::MAX_ENCODE_SIZE, 1 + 16 + 2);

    // No value is larger than its type's bound.
    bounded("UInt<u16>", &UInt(s.ints.1));
    bounded("UInt<u32>", &UInt(s.ints.2));
    bounded("UInt<u64>", &UInt(s.ints.3));
    bounded("UInt<u128>", &UInt(s.big));
    bounded(
        "UInt<U256>",
        &UInt(U256::from_limbs([s.ints.3, s.big as u64, 0, s.floats.1])),
    );
    bounded("IpAddr", &n.ip);
    bounded("SocketAddr", &n.sock);
    bounded("Option<SocketAddr>", &s.flag.then_some(n.sock));
    bounded("Option<UInt<u64>>", &s.flag.then_some(UInt(s.ints.3)));
    bounded(
        "(UInt<u32>, Option<IpAddr>, u8)",
        &(UInt(s.ints.2), s.flag.then_some(n.ip), s.ints.0),
    );

    // A sequence of at most `limit` bounded items fits `max_items_size`.
    let limit = s.blob.len() + input.slack;
    items("Vec<u8>", &s.blob, limit);
    signature("sizes: max_items_size of Bytes");
    assert!(Bytes::from(s.blob.clone()).encode_size() <= max_items_size(limit, 1));
    let limit = s.keys.len() + input.slack;
    items("Vec<u32>", &s.keys, limit);
    items(
        "Vec<UInt<u64>>",
        &s.keys
            .iter()
            .map(|k| UInt(u64::from(*k) << (k % 33)))
            .collect(),
        limit,
    );
    items(
        "Vec<Option<SocketAddr>>",
        &s.keys
            .iter()
            .map(|k| (k % 3 != 0).then_some(n.sock))
            .collect(),
        limit,
    );
    let limit = s.opts.len() + input.slack;
    items("Vec<Option<u32>>", &s.opts, limit);

    // The bound against the exact size of `len` items of `item_size` bytes,
    // computed in 128 bits, wherever the bound is representable.
    signature("sizes: max_items_size against the exact size");
    let len = input.bound_len as usize;
    let payload = len as u128 * input.bound_item as u128;
    let widest = payload + <UInt<u32> as MaxEncodeSize>::MAX_ENCODE_SIZE as u128;
    let representable = widest <= usize::MAX as u128;
    cover(representable, "bound fits a usize");
    if representable {
        let exact = payload + leb128(len as u128).len() as u128;
        let bound = max_items_size(len, input.bound_item);
        assert!(
            bound as u128 >= exact,
            "max_items_size({len}, {}) = {bound} is below the real size {exact}",
            input.bound_item
        );
    }
}
