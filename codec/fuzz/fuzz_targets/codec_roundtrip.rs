#![no_main]

use arbitrary::Arbitrary;
use bytes::Bytes;
use commonware_codec::{
    varint::{SInt, UInt},
    Decode, DecodeExt, DecodeRangeExt, Encode, EncodeSize, Error, RangeCfg, Read, Write,
};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    hash::Hash,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

const MAX_INPUT_SIZE: usize = 10000;
const MIN_COLLECTION_SIZE: usize = 0;
const MAX_COLLECTION_SIZE: usize = 10000;

fn roundtrip_socket(socket: SocketAddr) {
    let encoded = socket.encode();
    let decoded = SocketAddr::decode(encoded.clone())
        .expect("Failed to decode a successfully encoded input!");

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

fn roundtrip_primitive_f32(v: f32) {
    let encoded = v.encode();
    let decoded: f32 = f32::decode(&mut &*encoded).expect("Failed to decode f32!");
    if v.is_nan() && decoded.is_nan() {
        return;
    }
    assert_eq!(v, decoded);
}

fn roundtrip_primitive_f64(v: f64) {
    let encoded = v.encode();
    let decoded: f64 = f64::decode(&mut &*encoded).expect("Failed to decode f64!");
    if v.is_nan() && decoded.is_nan() {
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

#[derive(Arbitrary, Debug)]
struct WrappedSocketAddr(SocketAddr);

#[derive(Arbitrary, Debug)]
enum FuzzOperation {
    // Roundtrip operations (encode then decode with validation)
    RoundtripPrimitive(PrimitiveValue),
    RoundtripSocket(WrappedSocketAddr),
    RoundtripBytes(Vec<u8>),
    RoundtripVec(Vec<u8>),
    RoundtripMap(HashMap<u64, u64>),

    // Decode-only operations (fuzz arbitrary bytes)
    DecodeRawData {
        data: Vec<u8>,
        target: DecodeTarget,
        min_size: u16,
        max_size: u16,
    },
}

#[derive(Arbitrary, Debug)]
enum PrimitiveValue {
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
    Bool(bool),
}

#[derive(Arbitrary, Debug)]
enum DecodeTarget {
    // Primitives
    U8,
    U16,
    U32,
    U64,
    U128,
    I8,
    I16,
    I32,
    I64,
    I128,
    Bool,

    // Network types
    Ipv4Addr,
    Ipv6Addr,
    SocketAddrV4,
    SocketAddrV6,

    // Collections
    VecU8,
    VecU32,
    VecU64,
    BTreeMapU32U64,
    BTreeSetU32,
    HashMapU32U64,
    HashSetU32,

    // Bytes
    Bytes,

    // Tuples
    Tuple2U32U64,
    Tuple3U8U16U32,
    Tuple4BoolU32I32U64,

    // VarInts
    UIntU16,
    UIntU32,
    UIntU64,
    UIntU128,
    SIntI16,
    SIntI32,
    SIntI64,
    SIntI128,

    // Options
    OptionU8,
    OptionU32,
    OptionU64,
    OptionBool,

    // Complex collections
    VecU8Range,
    OptionVecU8,
    BTreeMapU8U8,
}

fn fuzz_decode_raw(data: &[u8], target: DecodeTarget, min_size: u16, max_size: u16) {
    if data.len() > MAX_INPUT_SIZE {
        return;
    }

    let min_size = (min_size as usize).clamp(MIN_COLLECTION_SIZE, MAX_COLLECTION_SIZE);
    let max_size = (max_size as usize).clamp(MIN_COLLECTION_SIZE, MAX_COLLECTION_SIZE);
    let range_cfg: RangeCfg = (min_size..=max_size).into();

    match target {
        // Primitives
        DecodeTarget::U8 => {
            let _ = u8::decode(data);
        }
        DecodeTarget::U16 => {
            let _ = u16::decode(data);
        }
        DecodeTarget::U32 => {
            let _ = u32::decode(data);
        }
        DecodeTarget::U64 => {
            let _ = u64::decode(data);
        }
        DecodeTarget::U128 => {
            let _ = u128::decode(data);
        }
        DecodeTarget::I8 => {
            let _ = i8::decode(data);
        }
        DecodeTarget::I16 => {
            let _ = i16::decode(data);
        }
        DecodeTarget::I32 => {
            let _ = i32::decode(data);
        }
        DecodeTarget::I64 => {
            let _ = i64::decode(data);
        }
        DecodeTarget::I128 => {
            let _ = i128::decode(data);
        }
        DecodeTarget::Bool => {
            let _ = bool::decode(data);
        }

        // Network types
        DecodeTarget::Ipv4Addr => {
            let _ = Ipv4Addr::decode(data);
        }
        DecodeTarget::Ipv6Addr => {
            let _ = Ipv6Addr::decode(data);
        }
        DecodeTarget::SocketAddrV4 => {
            let _ = SocketAddrV4::decode(data);
        }
        DecodeTarget::SocketAddrV6 => {
            let _ = SocketAddrV6::decode(data);
        }

        // Collections
        DecodeTarget::VecU8 => {
            let _ = Vec::<u8>::decode_range(data, range_cfg);
        }
        DecodeTarget::VecU32 => {
            let _ = Vec::<u32>::decode_range(data, range_cfg);
        }
        DecodeTarget::VecU64 => {
            let _ = Vec::<u64>::decode_range(data, range_cfg);
        }
        DecodeTarget::BTreeMapU32U64 => {
            let _ = BTreeMap::<u32, u64>::decode_range(data, range_cfg);
        }
        DecodeTarget::BTreeSetU32 => {
            let _ = BTreeSet::<u32>::decode_range(data, range_cfg);
        }
        DecodeTarget::HashMapU32U64 => {
            let _ = HashMap::<u32, u64>::decode_range(data, range_cfg);
        }
        DecodeTarget::HashSetU32 => {
            let _ = HashSet::<u32>::decode_range(data, range_cfg);
        }

        // Bytes
        DecodeTarget::Bytes => {
            let _ = Bytes::decode_cfg(data, &range_cfg);
        }

        // Tuples
        DecodeTarget::Tuple2U32U64 => {
            let _ = <(u32, u64)>::decode(data);
        }
        DecodeTarget::Tuple3U8U16U32 => {
            let _ = <(u8, u16, u32)>::decode(data);
        }
        DecodeTarget::Tuple4BoolU32I32U64 => {
            let _ = <(bool, u32, i32, u64)>::decode(data);
        }

        // VarInts
        DecodeTarget::UIntU16 => {
            let _ = UInt::<u16>::decode(data);
        }
        DecodeTarget::UIntU32 => {
            let _ = UInt::<u32>::decode(data);
        }
        DecodeTarget::UIntU64 => {
            let _ = UInt::<u64>::decode(data);
        }
        DecodeTarget::UIntU128 => {
            let _ = UInt::<u128>::decode(data);
        }
        DecodeTarget::SIntI16 => {
            let _ = SInt::<i16>::decode(data);
        }
        DecodeTarget::SIntI32 => {
            let _ = SInt::<i32>::decode(data);
        }
        DecodeTarget::SIntI64 => {
            let _ = SInt::<i64>::decode(data);
        }
        DecodeTarget::SIntI128 => {
            let _ = SInt::<i128>::decode(data);
        }

        // Options
        DecodeTarget::OptionU8 => {
            let _ = Option::<u8>::decode(data);
        }
        DecodeTarget::OptionU32 => {
            let _ = Option::<u32>::decode(data);
        }
        DecodeTarget::OptionU64 => {
            let _ = Option::<u64>::decode(data);
        }
        DecodeTarget::OptionBool => {
            let _ = Option::<bool>::decode(data);
        }

        // Complex collections
        DecodeTarget::VecU8Range => {
            let _ = Vec::<u8>::decode_cfg(data, &(range_cfg, ()));
        }
        DecodeTarget::OptionVecU8 => {
            let option_cfg = (range_cfg, ());
            let _ = Option::<Vec<u8>>::decode_cfg(data, &option_cfg);
        }
        DecodeTarget::BTreeMapU8U8 => {
            let _ = BTreeMap::<u8, u8>::decode_range(data, range_cfg);
        }
    }
}

fn fuzz(operation: FuzzOperation) {
    match operation {
        // Roundtrip operations
        FuzzOperation::RoundtripSocket(wrapped) => roundtrip_socket(wrapped.0),
        FuzzOperation::RoundtripBytes(data) => roundtrip_bytes(Bytes::from(data)),
        FuzzOperation::RoundtripVec(vec) => roundtrip_vec(vec),
        FuzzOperation::RoundtripMap(map) => roundtrip_map(&map, (..).into(), (), ()),

        FuzzOperation::RoundtripPrimitive(prim) => match prim {
            PrimitiveValue::U8(v) => roundtrip_primitive(v),
            PrimitiveValue::U16(v) => roundtrip_primitive(v),
            PrimitiveValue::U32(v) => roundtrip_primitive(v),
            PrimitiveValue::U64(v) => roundtrip_primitive(v),
            PrimitiveValue::U128(v) => roundtrip_primitive(v),
            PrimitiveValue::I8(v) => roundtrip_primitive(v),
            PrimitiveValue::I16(v) => roundtrip_primitive(v),
            PrimitiveValue::I32(v) => roundtrip_primitive(v),
            PrimitiveValue::I64(v) => roundtrip_primitive(v),
            PrimitiveValue::I128(v) => roundtrip_primitive(v),
            PrimitiveValue::F32(v) => roundtrip_primitive_f32(v),
            PrimitiveValue::F64(v) => roundtrip_primitive_f64(v),
            PrimitiveValue::Bool(v) => roundtrip_primitive(v),
        },

        // Decode-only operations
        FuzzOperation::DecodeRawData {
            data,
            target,
            min_size,
            max_size,
        } => {
            fuzz_decode_raw(&data, target, min_size, max_size);
        }
    }
}

fuzz_target!(|operation: FuzzOperation| {
    fuzz(operation);
});
