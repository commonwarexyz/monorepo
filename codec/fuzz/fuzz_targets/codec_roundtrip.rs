#![no_main]

use arbitrary::Arbitrary;
use bytes::{buf::UninitSlice, BufMut, Bytes, BytesMut};
use commonware_codec::{
    types::lazy::Lazy,
    varint::{SInt, UInt},
    BufsMut, Decode, DecodeExt, DecodeRangeExt, Encode, EncodeFixed, EncodeSize, Error, IsUnit,
    RangeCfg, Read, ReadRangeExt, Write,
};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU8, NonZeroUsize},
    ops::{
        Bound, Range, RangeBounds, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive,
    },
    sync::Once,
};

static BASELINE: Once = Once::new();

struct FuzzBufsMut {
    inner: BytesMut,
}

impl FuzzBufsMut {
    fn new() -> Self {
        Self {
            inner: BytesMut::new(),
        }
    }

    fn freeze(self) -> Bytes {
        self.inner.freeze()
    }
}

unsafe impl BufMut for FuzzBufsMut {
    fn remaining_mut(&self) -> usize {
        self.inner.remaining_mut()
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        self.inner.chunk_mut()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        unsafe { self.inner.advance_mut(cnt) }
    }
}

impl BufsMut for FuzzBufsMut {
    fn push(&mut self, bytes: impl Into<Bytes>) {
        self.inner.extend_from_slice(&bytes.into());
    }
}

struct ExcludedRange<T> {
    start: T,
    end: T,
}

impl<T> RangeBounds<T> for ExcludedRange<T> {
    fn start_bound(&self) -> Bound<&T> {
        Bound::Excluded(&self.start)
    }

    fn end_bound(&self) -> Bound<&T> {
        Bound::Excluded(&self.end)
    }
}

fn roundtrip_socket(socket: SocketAddr) {
    let encoded = socket.encode();
    let decoded = SocketAddr::decode(encoded.clone())
        .expect("Failed to decode a successfully encoded input!");

    // Check encoding length was correct
    // NOTE: We add 1 to the length here since this is a full `SocketAddr`,
    // the first byte represents the address type (e.g., IPv4 or IPv6)
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

fn roundtrip_ipv4(addr: Ipv4Addr) {
    let encoded = addr.encode();
    assert_eq!(addr.encode_size(), encoded.len());
    let decoded = Ipv4Addr::decode(&mut &*encoded).expect("Failed to decode Ipv4Addr!");
    assert_eq!(addr, decoded);
}

fn roundtrip_ipv6(addr: Ipv6Addr) {
    let encoded = addr.encode();
    assert_eq!(addr.encode_size(), encoded.len());
    let decoded = Ipv6Addr::decode(&mut &*encoded).expect("Failed to decode Ipv6Addr!");
    assert_eq!(addr, decoded);
}

fn roundtrip_ip_addr(addr: IpAddr) {
    let encoded = addr.encode();
    assert_eq!(addr.encode_size(), encoded.len());
    let decoded = IpAddr::decode(&mut &*encoded).expect("Failed to decode IpAddr!");
    assert_eq!(addr, decoded);
}

fn roundtrip_socket_v4(addr: SocketAddrV4) {
    let encoded = addr.encode();
    assert_eq!(addr.encode_size(), encoded.len());
    let decoded = SocketAddrV4::decode(&mut &*encoded).expect("Failed to decode SocketAddrV4!");
    assert_eq!(addr, decoded);
}

fn roundtrip_socket_v6(addr: SocketAddrV6) {
    let encoded = addr.encode();
    assert_eq!(addr.encode_size(), encoded.len());
    let decoded = SocketAddrV6::decode(&mut &*encoded).expect("Failed to decode SocketAddrV6!");

    // The codec intentionally discards flowinfo and scope_id (see codec/src/types/net.rs),
    // so we only compare ip and port, and verify flowinfo/scope_id are zeroed.
    assert_eq!(addr.ip(), decoded.ip());
    assert_eq!(addr.port(), decoded.port());
    assert_eq!(decoded.flowinfo(), 0);
    assert_eq!(decoded.scope_id(), 0);
}

fn roundtrip_byte_array<const N: usize>(arr: [u8; N]) {
    let encoded = arr.encode();
    assert_eq!(arr.encode_size(), encoded.len());
    let decoded = <[u8; N]>::decode(&mut &*encoded).expect("Failed to decode byte array!");
    assert_eq!(arr, decoded);
}

fn roundtrip_bytes(input_data_bytes: Bytes) {
    let input_len = input_data_bytes.len();
    let encoded_bytes = input_data_bytes.encode();

    // Decode with too long a length
    assert!(matches!(
        Bytes::decode_cfg(encoded_bytes.clone(), &(0..input_len).into()),
        Err(Error::InvalidLength(_))
    ));

    // Decode with too short a length
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
    X: IsUnit,
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

fn roundtrip_map<K, V>(
    map: &HashMap<K, V>,
    range_cfg: RangeCfg<usize>,
    k_cfg: K::Cfg,
    v_cfg: V::Cfg,
) where
    K: Write + EncodeSize + Read + Clone + Ord + Hash + Eq + std::fmt::Debug + PartialEq,
    V: Write + EncodeSize + Read + Clone + std::fmt::Debug + PartialEq,
    HashMap<K, V>: Read<Cfg = (RangeCfg<usize>, (K::Cfg, V::Cfg))>
        + std::fmt::Debug
        + PartialEq
        + Write
        + EncodeSize,
{
    let encoded = map.encode();
    assert_eq!(encoded.len(), map.encode_size());
    let mut bufs = FuzzBufsMut::new();
    map.write_bufs(&mut bufs);
    assert_eq!(encoded, bufs.freeze());
    assert_eq!(encoded.len(), map.encode_inline_size());
    let config_tuple = (range_cfg, (k_cfg, v_cfg));
    // TODO could also assert encoded size here with type info
    let decoded =
        HashMap::<K, V>::decode_cfg(encoded, &config_tuple).expect("Failed to decode map!");
    assert_eq!(map, &decoded);
}

fn roundtrip_set<K>(set: &HashSet<K>, range_cfg: RangeCfg<usize>, k_cfg: K::Cfg)
where
    K: Write + EncodeSize + Read + Clone + Hash + Eq + std::fmt::Debug + PartialEq,
    HashSet<K>:
        Read<Cfg = (RangeCfg<usize>, K::Cfg)> + std::fmt::Debug + PartialEq + Write + EncodeSize,
{
    let encoded = set.encode();
    assert_eq!(encoded.len(), set.encode_size());
    let mut bufs = FuzzBufsMut::new();
    set.write_bufs(&mut bufs);
    assert_eq!(encoded, bufs.freeze());
    assert_eq!(encoded.len(), set.encode_inline_size());
    let config_tuple = (range_cfg, k_cfg);
    let decoded = HashSet::<K>::decode_cfg(encoded, &config_tuple).expect("Failed to decode set!");
    assert_eq!(set, &decoded);
}

fn roundtrip_btree_map<K, V>(
    map: &BTreeMap<K, V>,
    range_cfg: RangeCfg<usize>,
    k_cfg: K::Cfg,
    v_cfg: V::Cfg,
) where
    K: Write + EncodeSize + Read + Clone + Ord + Eq + std::fmt::Debug + PartialEq,
    V: Write + EncodeSize + Read + Clone + std::fmt::Debug + PartialEq,
    BTreeMap<K, V>: Read<Cfg = (RangeCfg<usize>, (K::Cfg, V::Cfg))>
        + std::fmt::Debug
        + PartialEq
        + Write
        + EncodeSize,
{
    let encoded = map.encode();
    assert_eq!(encoded.len(), map.encode_size());
    let mut bufs = FuzzBufsMut::new();
    map.write_bufs(&mut bufs);
    assert_eq!(encoded, bufs.freeze());
    assert_eq!(encoded.len(), map.encode_inline_size());
    let config_tuple = (range_cfg, (k_cfg, v_cfg));
    let decoded =
        BTreeMap::<K, V>::decode_cfg(encoded, &config_tuple).expect("Failed to decode btree map!");
    assert_eq!(map, &decoded);
}

fn roundtrip_btree_set<K>(set: &BTreeSet<K>, range_cfg: RangeCfg<usize>, k_cfg: K::Cfg)
where
    K: Write + EncodeSize + Read + Clone + Ord + Eq + std::fmt::Debug + PartialEq,
    BTreeSet<K>:
        Read<Cfg = (RangeCfg<usize>, K::Cfg)> + std::fmt::Debug + PartialEq + Write + EncodeSize,
{
    let encoded = set.encode();
    assert_eq!(encoded.len(), set.encode_size());
    let mut bufs = FuzzBufsMut::new();
    set.write_bufs(&mut bufs);
    assert_eq!(encoded, bufs.freeze());
    assert_eq!(encoded.len(), set.encode_inline_size());
    let config_tuple = (range_cfg, k_cfg);
    let decoded =
        BTreeSet::<K>::decode_cfg(encoded, &config_tuple).expect("Failed to decode btree set!");
    assert_eq!(set, &decoded);
}

fn roundtrip_vec<T>(vec: Vec<T>)
where
    T: Encode + Decode + PartialEq + DecodeExt<()> + std::fmt::Debug,
{
    let input_len = vec.len();
    let encoded_vec = vec.encode();
    assert_eq!(encoded_vec.len(), vec.encode_size());

    // Decode with too long a length
    assert!(matches!(
        Vec::<T>::decode_cfg(encoded_vec.clone(), &((0..input_len).into(), ())),
        Err(Error::InvalidLength(_))
    ));

    // Decode with too short a length
    assert!(matches!(
        Vec::<T>::decode_cfg(encoded_vec.clone(), &((input_len + 1..).into(), ())),
        Err(Error::InvalidLength(_))
    ));

    let decoded = Vec::<T>::decode_cfg(encoded_vec, &((input_len..=input_len).into(), ()))
        .expect("Failed to decode Vec<T>!");

    assert_eq!(vec, decoded);
}

fn roundtrip_vec_range_ext(vec: Vec<u8>) {
    let input_len = vec.len();
    let encoded_vec = vec.encode();
    assert_eq!(vec.encode_inline_size(), vec.encode_size());
    let decoded = Vec::<u8>::decode_range(encoded_vec, input_len..=input_len)
        .expect("Failed to decode Vec<u8>!");
    assert_eq!(vec, decoded);
}

fn roundtrip_varint_vec(values: Vec<u16>) {
    let vec = values.into_iter().map(UInt).collect::<Vec<_>>();
    let encoded = vec.encode();
    assert_eq!(encoded.len(), vec.encode_size());
    assert_eq!(
        vec.encode_inline_size(),
        vec.len().encode_size()
            + vec
                .iter()
                .map(EncodeSize::encode_inline_size)
                .sum::<usize>()
    );

    let mut bufs = FuzzBufsMut::new();
    vec.write_bufs(&mut bufs);
    assert_eq!(encoded, bufs.freeze());

    let decoded = Vec::<UInt<u16>>::decode_cfg(encoded, &((vec.len()..=vec.len()).into(), ()))
        .expect("Failed to decode Vec<UInt<u16>>!");
    assert_eq!(vec, decoded);
}

fn roundtrip_varint_array(values: [u16; 4]) {
    let array = values.map(UInt);
    let mut encoded = BytesMut::new();
    array.write(&mut encoded);
    let encoded = encoded.freeze();

    let mut bufs = FuzzBufsMut::new();
    array.write_bufs(&mut bufs);
    assert_eq!(encoded, bufs.freeze());

    let decoded =
        <[UInt<u16>; 4]>::decode(&mut &*encoded).expect("Failed to decode [UInt<u16>; 4]!");
    assert_eq!(array, decoded);
}

fn roundtrip_option<T>(opt: Option<T>)
where
    T: Encode + Read<Cfg = ()> + PartialEq + std::fmt::Debug + EncodeSize,
    Option<T>: Decode<Cfg = T::Cfg>,
{
    let encoded = opt.encode();
    assert_eq!(opt.encode_size(), encoded.len());
    assert_eq!(opt.encode_inline_size(), encoded.len());
    let mut bufs = FuzzBufsMut::new();
    opt.write_bufs(&mut bufs);
    assert_eq!(encoded, bufs.freeze());
    let decoded = Option::<T>::decode(&mut &*encoded).expect("Failed to decode Option<T>!");
    assert_eq!(opt, decoded);
}

fn roundtrip_option_bytes(opt: Option<Bytes>) {
    let len = opt.as_ref().map_or(0, Bytes::len);
    let encoded = opt.encode();
    assert_eq!(opt.encode_size(), encoded.len());
    assert_eq!(
        opt.encode_inline_size(),
        opt.as_ref()
            .map_or(1, |bytes| 1 + bytes.len().encode_size())
    );
    let mut bufs = FuzzBufsMut::new();
    opt.write_bufs(&mut bufs);
    assert_eq!(encoded, bufs.freeze());
    let decoded = Option::<Bytes>::decode_cfg(encoded, &(len..=len).into())
        .expect("Failed to decode Option<Bytes>!");
    assert_eq!(opt, decoded);
}

fn roundtrip_tuple_2<T1, T2>(tuple: (T1, T2))
where
    T1: Encode + Read<Cfg = ()> + PartialEq + std::fmt::Debug + EncodeSize,
    T2: Encode + Read<Cfg = ()> + PartialEq + std::fmt::Debug + EncodeSize,
    (T1, T2): Encode + Decode<Cfg = (T1::Cfg, T2::Cfg)> + PartialEq + std::fmt::Debug + EncodeSize,
{
    let encoded = tuple.encode();
    assert_eq!(tuple.encode_size(), encoded.len());
    assert_eq!(tuple.encode_inline_size(), encoded.len());
    let mut bufs = FuzzBufsMut::new();
    tuple.write_bufs(&mut bufs);
    assert_eq!(encoded, bufs.freeze());
    let decoded = <(T1, T2)>::decode(&mut &*encoded).expect("Failed to decode tuple!");
    assert_eq!(tuple, decoded);
}

fn roundtrip_tuple_3<T1, T2, T3>(tuple: (T1, T2, T3))
where
    T1: Encode + Read<Cfg = ()> + PartialEq + std::fmt::Debug + EncodeSize,
    T2: Encode + Read<Cfg = ()> + PartialEq + std::fmt::Debug + EncodeSize,
    T3: Encode + Read<Cfg = ()> + PartialEq + std::fmt::Debug + EncodeSize,
    (T1, T2, T3): Encode
        + Decode<Cfg = (T1::Cfg, T2::Cfg, T3::Cfg)>
        + PartialEq
        + std::fmt::Debug
        + EncodeSize,
{
    let encoded = tuple.encode();
    assert_eq!(tuple.encode_size(), encoded.len());
    assert_eq!(tuple.encode_inline_size(), encoded.len());
    let mut bufs = FuzzBufsMut::new();
    tuple.write_bufs(&mut bufs);
    assert_eq!(encoded, bufs.freeze());
    let decoded = <(T1, T2, T3)>::decode(&mut &*encoded).expect("Failed to decode tuple!");
    assert_eq!(tuple, decoded);
}

fn roundtrip_usize(v: usize) {
    let encoded = v.encode();
    assert_eq!(v.encode_size(), encoded.len());
    let decoded = usize::decode_cfg(encoded, &(..).into()).expect("Failed to decode usize!");
    assert_eq!(v, decoded);
}

fn roundtrip_overflow(continuation_bytes: u8, last_byte: u8) {
    let mut buf = Vec::new();
    for _ in 0..continuation_bytes.min(20) {
        buf.put_u8(0xFF);
    }
    buf.put_u8(last_byte);
    let _ = UInt::<u16>::decode(Bytes::from(buf.clone()));
    let _ = UInt::<u32>::decode(Bytes::from(buf.clone()));
    let _ = UInt::<u64>::decode(Bytes::from(buf.clone()));
    let _ = UInt::<u128>::decode(Bytes::from(buf.clone()));
    // Also test signed varint overflow
    let _ = SInt::<i16>::decode(Bytes::from(buf.clone()));
    let _ = SInt::<i32>::decode(Bytes::from(buf.clone()));
    let _ = SInt::<i64>::decode(Bytes::from(buf.clone()));
    let _ = SInt::<i128>::decode(Bytes::from(buf));
}

fn exercise_range_cfg(value: u8) {
    let start = NonZeroU8::new(value % 127 + 1).unwrap();
    let end = NonZeroU8::new(start.get() + 1).unwrap();
    let excluded = RangeCfg::new(ExcludedRange { start, end });

    let cfg_u8: RangeCfg<u8> = excluded.into();
    assert!(!cfg_u8.contains(&start.get()));
    assert!(cfg_u8.contains(&(start.get() + 1)) == (start.get() + 1 < end.get()));

    let cfg_usize: RangeCfg<usize> = excluded.into();
    assert!(!cfg_usize.contains(&usize::from(start.get())));

    let cfg_nonzero_usize: RangeCfg<NonZeroUsize> = excluded.into();
    assert!(!cfg_nonzero_usize.contains(&NonZeroUsize::from(start)));

    let exact = RangeCfg::exact(NonZeroU16::new(u16::from(value) + 1).unwrap());
    let _: RangeCfg<u16> = exact.into();
    let _: RangeCfg<usize> = exact.into();
    let _: RangeCfg<NonZeroUsize> = exact.into();

    let unbounded: RangeCfg<NonZeroU32> = (..).into();
    let _: RangeCfg<u32> = unbounded.into();
    let _: RangeCfg<usize> = unbounded.into();
    let _: RangeCfg<NonZeroUsize> = unbounded.into();

    let to_cfg: RangeCfg<usize> = (..usize::from(value)).into();
    let _ = to_cfg.contains(&usize::from(value));
}

fn exercise_zeros(bytes: &[u8], size: u8) {
    let len = bytes.len().min(usize::from(size));
    let mut buf = &bytes[..len];
    let result = commonware_codec::util::ensure_zeros(&mut buf, len);
    if bytes[..len].iter().any(|byte| *byte != 0) {
        assert!(matches!(
            result,
            Err(Error::Invalid("codec", "non-zero bytes"))
        ));
    } else {
        assert!(result.is_ok());
    }
}

fn exercise_varint(value: i16, bytes: &[u8]) {
    let _ = commonware_codec::varint::Decoder::<u16>::default();
    let _: u16 = UInt(value.unsigned_abs()).into();
    let _: i16 = SInt(value).into();

    let mut unstructured = arbitrary::Unstructured::new(bytes);
    let _ = UInt::<u16>::arbitrary(&mut unstructured);
    let mut unstructured = arbitrary::Unstructured::new(bytes);
    let _ = SInt::<i16>::arbitrary(&mut unstructured);
}

fn roundtrip_range<T>(range: T)
where
    T: Encode + Decode + DecodeExt<()> + PartialEq + std::fmt::Debug,
{
    let encoded = range.encode();
    assert_eq!(encoded.len(), range.encode_size());
    assert_eq!(encoded.len(), range.encode_inline_size());
    let mut bufs = FuzzBufsMut::new();
    range.write_bufs(&mut bufs);
    assert_eq!(encoded, bufs.freeze());
    let decoded = T::decode(encoded).expect("Failed to decode range!");
    assert_eq!(range, decoded);
}

fn exercise_ranges(a: u16, b: u16) {
    let start = a.min(b);
    let end = a.max(b);
    roundtrip_range::<Range<u16>>(start..end);
    roundtrip_range::<RangeInclusive<u16>>(start..=end);
    roundtrip_range::<RangeFrom<u16>>(start..);
    roundtrip_range::<RangeTo<u16>>(..end);
    roundtrip_range::<RangeToInclusive<u16>>(..=end);
    roundtrip_range::<RangeFull>(..);
}

fn exercise_lazy(value: u64) {
    let encoded = value.encode();
    let mut pending_bytes = encoded.clone();
    let pending = Lazy::<u64>::deferred(&mut pending_bytes, ());
    assert_eq!(pending.encode_size(), encoded.len());
    assert_eq!(pending.encode_inline_size(), 0);
    assert_eq!(pending.get(), Some(&value));
    let mut bufs = FuzzBufsMut::new();
    pending.write_bufs(&mut bufs);
    assert_eq!(encoded, bufs.freeze());

    let initialized = Lazy::new(value);
    assert_eq!(initialized.encode_inline_size(), value.encode_inline_size());
    let mut bufs = FuzzBufsMut::new();
    initialized.write_bufs(&mut bufs);
    assert_eq!(encoded, bufs.freeze());
    assert_eq!(pending, initialized);
    assert_eq!(
        pending.partial_cmp(&initialized),
        Some(std::cmp::Ordering::Equal)
    );
    assert_eq!(pending.cmp(&initialized), std::cmp::Ordering::Equal);
    let _ = format!("{pending:?}");
}

fn exercise_primitives(value: u64, byte: u8, data: &[u8]) {
    if let Some(nz) = NonZeroU16::new(value as u16) {
        let encoded = nz.encode();
        assert_eq!(
            NonZeroU16::decode(encoded).expect("Failed to decode NonZeroU16!"),
            nz
        );
    }
    if let Some(nz) = NonZeroU32::new(value as u32) {
        let encoded = nz.encode();
        assert_eq!(
            NonZeroU32::decode(encoded).expect("Failed to decode NonZeroU32!"),
            nz
        );
    }
    if let Some(nz) = NonZeroU64::new(value) {
        let encoded = nz.encode();
        assert_eq!(
            NonZeroU64::decode(encoded).expect("Failed to decode NonZeroU64!"),
            nz
        );
    }

    if byte > 1 {
        assert!(matches!(
            bool::decode(Bytes::copy_from_slice(&[byte])),
            Err(Error::InvalidBool)
        ));
    }

    let len = data.len().min(64);
    let bytes = Bytes::copy_from_slice(&data[..len]);
    roundtrip_option_bytes(Some(bytes));

    let mut bufs = FuzzBufsMut::new();
    (&data[..len]).write_bufs(&mut bufs);
    assert_eq!((&data[..len]).encode(), bufs.freeze());
}

fn exercise_invalid_ordered() {
    let dup_map = Bytes::from_static(&[2, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 8]);
    assert!(matches!(
        HashMap::<u32, u32>::decode_cfg(dup_map.clone(), &((..).into(), ((), ()))),
        Err(Error::Invalid("HashMap", "Duplicate key"))
    ));
    assert!(matches!(
        BTreeMap::<u32, u32>::decode_cfg(dup_map, &((..).into(), ((), ()))),
        Err(Error::Invalid("BTreeMap", "Duplicate key"))
    ));

    let desc_map = Bytes::from_static(&[2, 0, 0, 0, 2, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 8]);
    assert!(matches!(
        HashMap::<u32, u32>::decode_cfg(desc_map.clone(), &((..).into(), ((), ()))),
        Err(Error::Invalid("HashMap", "Keys must ascend"))
    ));
    assert!(matches!(
        BTreeMap::<u32, u32>::decode_cfg(desc_map, &((..).into(), ((), ()))),
        Err(Error::Invalid("BTreeMap", "Keys must ascend"))
    ));

    let dup_set = Bytes::from_static(&[2, 0, 0, 0, 1, 0, 0, 0, 1]);
    assert!(matches!(
        HashSet::<u32>::decode_cfg(dup_set.clone(), &((..).into(), ())),
        Err(Error::Invalid("HashSet", "Duplicate item"))
    ));
    assert!(matches!(
        BTreeSet::<u32>::decode_cfg(dup_set, &((..).into(), ())),
        Err(Error::Invalid("BTreeSet", "Duplicate item"))
    ));

    let desc_set = Bytes::from_static(&[2, 0, 0, 0, 2, 0, 0, 0, 1]);
    assert!(matches!(
        HashSet::<u32>::decode_cfg(desc_set.clone(), &((..).into(), ())),
        Err(Error::Invalid("HashSet", "Items must ascend"))
    ));
    assert!(matches!(
        BTreeSet::<u32>::decode_cfg(desc_set, &((..).into(), ())),
        Err(Error::Invalid("BTreeSet", "Items must ascend"))
    ));
}

fn exercise_invalid_ip(version: u8) {
    if version != 4 && version != 6 {
        assert!(matches!(
            IpAddr::decode(Bytes::copy_from_slice(&[version])),
            Err(Error::Invalid("IpAddr", "Invalid version"))
        ));
    }
}

fn exercise_baseline() {
    let value = 7u64;
    let encoded = value.encode();

    let from = Lazy::from(value);
    assert_eq!(from.encode_size(), encoded.len());
    let mut buf = BytesMut::new();
    from.write(&mut buf);
    assert_eq!(encoded, buf.freeze());

    let mut pending_bytes = encoded.clone();
    let pending = Lazy::<u64>::deferred(&mut pending_bytes, ());
    let mut buf = BytesMut::new();
    pending.write(&mut buf);
    assert_eq!(encoded, buf.freeze());

    let read = Lazy::<u64>::read_cfg(&mut encoded.clone(), &()).expect("Failed to read Lazy<u64>!");
    assert_eq!(read.get(), Some(&value));
    assert!(matches!(
        Lazy::<u64>::read_cfg(&mut Bytes::from_static(&[1, 2]), &()),
        Err(Error::EndOfBuffer)
    ));

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&read, &mut hasher);
    let _ = hasher.finish();

    let vec = vec![1u8, 2, 3];
    let mut encoded_vec = vec.encode();
    let read_vec = Vec::<u8>::read_range(&mut encoded_vec, 3..=3).expect("Failed to read Vec<u8>!");
    assert_eq!(vec, read_vec);
    roundtrip_option_bytes(None);

    let mut extra = 1u8.encode().to_vec();
    extra.push(2);
    assert!(matches!(
        u8::decode(Bytes::from(extra)),
        Err(Error::ExtraData(1))
    ));

    let fixed: [u8; 4] = 7u32.encode_fixed();
    assert_eq!(fixed, 7u32.encode().as_ref());

    let cfg: RangeCfg<usize> = (..=3).into();
    assert_eq!(cfg.start_bound(), Bound::Unbounded);
    assert_eq!(cfg.end_bound(), Bound::Included(&3));
}

// Wrapped network types for arbitrary
#[derive(Arbitrary, Debug)]
struct WrappedSocketAddr(SocketAddr);

#[derive(Arbitrary, Debug)]
struct WrappedIpAddr(IpAddr);

#[derive(Arbitrary, Debug)]
struct WrappedIpv4Addr(Ipv4Addr);

#[derive(Arbitrary, Debug)]
struct WrappedIpv6Addr(Ipv6Addr);

#[derive(Arbitrary, Debug)]
struct WrappedSocketAddrV4(SocketAddrV4);

#[derive(Arbitrary, Debug)]
struct WrappedSocketAddrV6(SocketAddrV6);

#[derive(Arbitrary, Debug)]
enum FuzzInput<'a> {
    Bytes(&'a [u8]),

    // Network types
    Socket(WrappedSocketAddr),
    Ip(WrappedIpAddr),
    Ipv4(WrappedIpv4Addr),
    Ipv6(WrappedIpv6Addr),
    SocketV4(WrappedSocketAddrV4),
    SocketV6(WrappedSocketAddrV6),

    // Collections
    Map(HashMap<u64, u64>),
    Set(HashSet<u64>),
    BTreeMap(BTreeMap<u32, u32>),
    BTreeSet(BTreeSet<u32>),
    Vec(Vec<u8>),
    VecRangeExt(Vec<u8>),
    VarIntVec(Vec<u16>),

    // Arrays
    ByteArray4([u8; 4]),
    ByteArray8([u8; 8]),
    ByteArray16([u8; 16]),
    ByteArray32([u8; 32]),
    VarIntArray([u16; 4]),

    // Option type
    OptionSome(u32),
    OptionNone,

    // Tuples
    Tuple2(u8, u16),
    Tuple3(u32, u64, u128),

    VarIntOverflow {
        // Number of continuation bytes before the last byte
        continuation_bytes: u8,
        // Value for the last byte (will test if it has too many bits)
        last_byte: u8,
    },
    VarIntExercise(i16, &'a [u8]),
    RangeCfg(u8),
    EnsureZeros(&'a [u8], u8),
    RangeTypes(u16, u16),
    Lazy(u64),
    PrimitiveExercise(u64, u8, &'a [u8]),
    InvalidOrdered,
    InvalidIp(u8),

    // Unsigned varints
    UVarInt16(u16),
    UVarInt32(u32),
    UVarInt64(u64),
    UVarInt128(u128),

    // Signed varints (ZigZag encoding)
    SVarInt16(i16),
    SVarInt32(i32),
    SVarInt64(i64),
    SVarInt128(i128),

    // Primitive inputs!
    Bool(bool),
    Unit,
    Usize(usize),
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

fn fuzz(input: FuzzInput) {
    BASELINE.call_once(exercise_baseline);

    match input {
        FuzzInput::Bytes(it) => roundtrip_bytes(Bytes::from(it.to_vec())),
        // Network types
        FuzzInput::Socket(it) => roundtrip_socket(it.0),
        FuzzInput::Ip(it) => roundtrip_ip_addr(it.0),
        FuzzInput::Ipv4(it) => roundtrip_ipv4(it.0),
        FuzzInput::Ipv6(it) => roundtrip_ipv6(it.0),
        FuzzInput::SocketV4(it) => roundtrip_socket_v4(it.0),
        FuzzInput::SocketV6(it) => roundtrip_socket_v6(it.0),
        // Collections
        FuzzInput::Map(it) => roundtrip_map(&it, (..).into(), (), ()),
        FuzzInput::Set(it) => roundtrip_set(&it, (..).into(), ()),
        FuzzInput::BTreeMap(it) => roundtrip_btree_map(&it, (..).into(), (), ()),
        FuzzInput::BTreeSet(it) => roundtrip_btree_set(&it, (..).into(), ()),
        FuzzInput::Vec(it) => roundtrip_vec(it),
        FuzzInput::VecRangeExt(it) => roundtrip_vec_range_ext(it),
        FuzzInput::VarIntVec(it) => roundtrip_varint_vec(it),
        // Arrays
        FuzzInput::ByteArray4(arr) => roundtrip_byte_array(arr),
        FuzzInput::ByteArray8(arr) => roundtrip_byte_array(arr),
        FuzzInput::ByteArray16(arr) => roundtrip_byte_array(arr),
        FuzzInput::ByteArray32(arr) => roundtrip_byte_array(arr),
        FuzzInput::VarIntArray(arr) => roundtrip_varint_array(arr),
        // Option types
        FuzzInput::OptionSome(v) => roundtrip_option(Some(v)),
        FuzzInput::OptionNone => roundtrip_option::<u32>(None),
        // Tuples
        FuzzInput::Tuple2(a, b) => roundtrip_tuple_2((a, b)),
        FuzzInput::Tuple3(a, b, c) => roundtrip_tuple_3((a, b, c)),
        FuzzInput::VarIntOverflow {
            continuation_bytes,
            last_byte,
        } => roundtrip_overflow(continuation_bytes, last_byte),
        FuzzInput::VarIntExercise(value, bytes) => exercise_varint(value, bytes),
        FuzzInput::RangeCfg(value) => exercise_range_cfg(value),
        FuzzInput::EnsureZeros(bytes, size) => exercise_zeros(bytes, size),
        FuzzInput::RangeTypes(a, b) => exercise_ranges(a, b),
        FuzzInput::Lazy(value) => exercise_lazy(value),
        FuzzInput::PrimitiveExercise(value, byte, data) => exercise_primitives(value, byte, data),
        FuzzInput::InvalidOrdered => exercise_invalid_ordered(),
        FuzzInput::InvalidIp(version) => exercise_invalid_ip(version),
        // Unsigned varints
        FuzzInput::UVarInt16(v) => roundtrip_primitive(UInt(v)),
        FuzzInput::UVarInt32(v) => roundtrip_primitive(UInt(v)),
        FuzzInput::UVarInt64(v) => roundtrip_primitive(UInt(v)),
        FuzzInput::UVarInt128(v) => roundtrip_primitive(UInt(v)),
        // Signed varints
        FuzzInput::SVarInt16(v) => roundtrip_primitive(SInt(v)),
        FuzzInput::SVarInt32(v) => roundtrip_primitive(SInt(v)),
        FuzzInput::SVarInt64(v) => roundtrip_primitive(SInt(v)),
        FuzzInput::SVarInt128(v) => roundtrip_primitive(SInt(v)),
        // Fixed-width primitives
        FuzzInput::Bool(v) => roundtrip_primitive(v),
        FuzzInput::Unit => roundtrip_primitive(()),
        FuzzInput::Usize(v) => {
            // Limit to u32::MAX for testing (since usize encodes as u32)
            let v = v.min(u32::MAX as usize);
            roundtrip_usize(v)
        }
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
        FuzzInput::F32(v) => roundtrip_primitive_f32(v),
        FuzzInput::F64(v) => roundtrip_primitive_f64(v),
    };
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
