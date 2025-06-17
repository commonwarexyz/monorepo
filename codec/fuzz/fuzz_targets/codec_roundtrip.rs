#![no_main]

use arbitrary::Arbitrary;
use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Encode, EncodeSize, Error, RangeCfg, Read, Write};
use libfuzzer_sys::fuzz_target;
use std::{collections::HashMap, hash::Hash, net::SocketAddr};

fn roundtrip_socket(socket: SocketAddr) {
    let encoded = socket.encode();
    let decoded = SocketAddr::decode(encoded.clone())
        .expect("Failed to decode a successfully encoded input!");

    // Check encoding length was correct
    // NOTE: We add 1 to the length here since this is a full `SocketAddr`, the first byte represents the address type (e.g. IPv4 or IPv6)
    match socket {
        SocketAddr::V4(_) => {
            assert_eq!(encoded.len(), 6 + 1);
        }
        SocketAddr::V6(_) => {
            assert_eq!(encoded.len(), 18 + 1);
        }
    };

    assert_eq!(socket.ip(), decoded.ip());
    assert_eq!(socket.port(), decoded.port());
}

fn roundtrip_bytes(input_data_bytes: Bytes) {
    let input_len = input_data_bytes.len();
    let encoded_bytes = input_data_bytes.encode();

    // Decode with too long length
    assert!(matches!(
        Bytes::decode_cfg(encoded_bytes.clone(), &(0..input_len).into()),
        Err(Error::InvalidLength(_))
    ));

    // Decode with too short length
    assert!(matches!(
        Bytes::decode_cfg(encoded_bytes.clone(), &(input_len + 1..).into()),
        Err(Error::InvalidLength(_))
    ));

    // Decode with full length
    let decoded_bytes = Bytes::decode_cfg(encoded_bytes, &(input_len..=input_len).into())
        .expect("Failed to decode bytes!");

    // Check matching
    assert_eq!(input_data_bytes, decoded_bytes);
}

fn roundtrip_primitive<T, X>(v: T)
where
    X: std::default::Default,
    T: Encode + Decode + PartialEq + DecodeExt<X> + std::fmt::Debug,
{
    let encoded = v.encode();
    assert_eq!(v.encode_size(), encoded.len());
    let decoded = T::decode(&mut &*encoded).expect("Failed to decode primitive!");
    assert_eq!(v, decoded);
}

// NOTE: Separate float cases to handle NaN comparisons
// TODO should combine these functions with better generics
fn roundtrip_primitive_f32(v: f32) {
    let encoded = v.encode();
    let decoded: f32 = f32::decode(&mut &*encoded).expect("Failed to decode f32!");
    if v.is_nan() && decoded.is_nan() {
        // Ignore the NaN case
        return;
    }
    assert_eq!(v, decoded);
}

fn roundtrip_primitive_f64(v: f64) {
    let encoded = v.encode();
    let decoded: f64 = f64::decode(&mut &*encoded).expect("Failed to decode f64!");
    if v.is_nan() && decoded.is_nan() {
        // Ignore the NaN case
        return;
    }
    assert_eq!(v, decoded);
}

fn roundtrip_map<K, V>(map: &HashMap<K, V>, range_cfg: RangeCfg, k_cfg: K::Cfg, v_cfg: V::Cfg)
where
    K: Write + EncodeSize + Read + Clone + Ord + Hash + Eq + std::fmt::Debug + PartialEq,
    V: Write + EncodeSize + Read + Clone + std::fmt::Debug + PartialEq,
    HashMap<K, V>:
        Read<Cfg = (RangeCfg, (K::Cfg, V::Cfg))> + std::fmt::Debug + PartialEq + Write + EncodeSize,
{
    let encoded = map.encode();
    assert_eq!(encoded.len(), map.encode_size());
    let config_tuple = (range_cfg, (k_cfg, v_cfg));
    // TODO could also assert encoded size here with type info
    let decoded =
        HashMap::<K, V>::decode_cfg(encoded, &config_tuple).expect("Failed to decode map!");
    assert_eq!(map, &decoded);
}

fn roundtrip_vec<T>(vec: Vec<T>)
where
    T: Encode + Decode + PartialEq + DecodeExt<()> + std::fmt::Debug,
{
    let input_len = vec.len();
    let encoded_vec = vec.encode();
    assert_eq!(encoded_vec.len(), vec.encode_size());

    // Decode with too long length
    assert!(matches!(
        Vec::<T>::decode_cfg(encoded_vec.clone(), &((0..input_len).into(), ())),
        Err(Error::InvalidLength(_))
    ));

    // Decode with too short length
    assert!(matches!(
        Vec::<T>::decode_cfg(encoded_vec.clone(), &((input_len + 1..).into(), ())),
        Err(Error::InvalidLength(_))
    ));

    let decoded = Vec::<T>::decode_cfg(encoded_vec, &((input_len..=input_len).into(), ()))
        .expect("Failed to decode Vec<T>!");

    assert_eq!(vec, decoded);
}

// Wrapped socket for arbitrary
#[derive(Arbitrary, Debug)]
struct WrappedSocketAddr(SocketAddr);

#[derive(Arbitrary, Debug)]
enum FuzzInput<'a> {
    Bytes(&'a [u8]),
    Socket(WrappedSocketAddr),

    // NOTE: Ignored tuple for the time being due to additional arbitrary generics
    Map(HashMap<u64, u64>), // TODO use arbitrary types as well
    Vec(Vec<u8>),           // TODO use arbitrary types as well

    // TODO need to add Var[U]Int types, also need to add support for arbitrary generics

    // Primitive inputs!
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    F32(f32),
    F64(f64),
}

fuzz_target!(|input_data: FuzzInput| {
    match input_data {
        FuzzInput::Socket(it) => roundtrip_socket(it.0),
        FuzzInput::Bytes(it) => roundtrip_bytes(Bytes::from(it.to_vec())),
        FuzzInput::Map(it) => roundtrip_map(&it, (..).into(), (), ()), // TODO this needs proper length specifiers for the type if doing dynamic lengths!
        FuzzInput::Vec(it) => roundtrip_vec(it),

        // Primitive roundtrips
        FuzzInput::U8(v) => roundtrip_primitive(v),
        FuzzInput::U16(v) => roundtrip_primitive(v),
        FuzzInput::U32(v) => roundtrip_primitive(v),
        FuzzInput::U64(v) => roundtrip_primitive(v),
        FuzzInput::U128(v) => roundtrip_primitive(v),
        FuzzInput::I8(v) => roundtrip_primitive(v),
        FuzzInput::I16(v) => roundtrip_primitive(v),
        FuzzInput::I32(v) => roundtrip_primitive(v),
        FuzzInput::I64(v) => roundtrip_primitive(v),
        FuzzInput::I128(v) => roundtrip_primitive(v),

        // Float primitive roundtrips
        FuzzInput::F32(v) => roundtrip_primitive_f32(v),
        FuzzInput::F64(v) => roundtrip_primitive_f64(v),
    };
});
