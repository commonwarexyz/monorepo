use crate::{
    Decode, DecodeExt, Encode, EncodeSize, Error, FixedSize, RangeCfg, Read, Read as Reader, Write,
    types::tests::TrackingWriteBuf,
};
use bytes::{BufMut, Bytes};
use core::fmt::Debug;

fn assert_roundtrip<T: Encode + Decode + Debug + PartialEq>(
    value: T,
    cfg: &T::Cfg,
    expected: &[u8],
) {
    let encoded = value.encode();
    assert_eq!(encoded.as_ref(), expected);
    assert_eq!(value.encode_size(), expected.len());
    assert_eq!(T::decode_cfg(encoded.clone(), cfg).unwrap(), value);

    let mut chunks = TrackingWriteBuf::new();
    value.write_bufs(&mut chunks);
    let pushed: usize = chunks.pushed.iter().map(Bytes::len).sum();
    assert_eq!(value.encode_inline_size() + pushed, expected.len());
    assert_eq!(chunks.freeze(), encoded);

    for end in 0..encoded.len() {
        assert!(T::decode_cfg(encoded.slice(..end), cfg).is_err());
    }
    let mut extra = encoded.to_vec();
    extra.push(0);
    assert!(matches!(
        T::decode_cfg(extra, cfg),
        Err(Error::ExtraData(1))
    ));
}

#[derive(Debug, PartialEq, Write, Read, FixedSize)]
struct Header {
    version: u8,
    sequence: u16,
}

#[derive(Debug, PartialEq, Write, Read, FixedSize)]
struct Tuple<T, const N: usize>(T, [u8; N]);

#[derive(Debug, PartialEq, Write, Read, FixedSize)]
struct Unit;

#[derive(Debug, PartialEq, Write, Read, FixedSize)]
struct EmptyTuple();

#[derive(Debug, PartialEq, Write, Read, FixedSize)]
struct EmptyNamed {}

#[test]
fn fixed_structs() {
    assert_eq!(Header::SIZE, 3);
    assert_roundtrip(
        Header {
            version: 2,
            sequence: 0x1234,
        },
        &(),
        &[2, 0x12, 0x34],
    );
    assert_eq!(Tuple::<u16, 2>::SIZE, 4);
    assert_roundtrip(Tuple(0x1234u16, [5, 6]), &(), &[0x12, 0x34, 5, 6]);
    assert_eq!(Unit::SIZE, 0);
    assert_roundtrip(Unit, &(), &[]);
    assert_roundtrip(EmptyTuple(), &(), &[]);
    assert_roundtrip(EmptyNamed {}, &(), &[]);
}

#[derive(Debug, PartialEq, Encode, Read)]
#[read_cfg(RangeCfg<usize>)]
struct Message {
    #[codec(cfg = &())]
    header: Header,
    payload: Bytes,
}

#[test]
fn read_configuration_and_buffer_sharing() {
    let payload = Bytes::from_static(&[7, 8, 9]);
    let message = Message {
        header: Header {
            version: 1,
            sequence: 2,
        },
        payload: payload.clone(),
    };
    let cfg = RangeCfg::new(..=3);
    let mut chunks = TrackingWriteBuf::new();
    message.write_bufs(&mut chunks);
    assert_eq!(chunks.pushed.len(), 1);
    assert_eq!(chunks.pushed[0].as_ptr(), payload.as_ptr());
    assert!(matches!(
        Message::decode_cfg(message.encode(), &RangeCfg::new(..=2)),
        Err(Error::InvalidLength(3))
    ));
    assert_roundtrip(message, &cfg, &[1, 0, 2, 3, 7, 8, 9]);
}

#[derive(Debug, PartialEq, Encode, Read)]
#[read_cfg(RangeCfg<usize>)]
struct InlineField(#[codec(encode_size = value.encode_size())] Bytes);

#[derive(Debug, PartialEq, Encode, Read)]
#[codec(read_cfg = RangeCfg<usize>, encode_size = self.0.encode_size())]
struct InlineContainer(Bytes);

#[test]
fn size_overrides_keep_buffer_sharing_accounting_consistent() {
    let payload = Bytes::from_static(&[7, 8]);
    let cfg = RangeCfg::new(..=2);
    assert_roundtrip(InlineField(payload.clone()), &cfg, &[2, 7, 8]);
    assert_roundtrip(InlineContainer(payload), &cfg, &[2, 7, 8]);
}

#[derive(Clone)]
struct Limits {
    maximum: usize,
}

#[derive(Debug, PartialEq, Write, EncodeSize, Read)]
#[codec(read_cfg = Limits)]
struct Configured {
    #[codec(cfg = &((..=cfg.maximum).into(), ()))]
    items: Vec<u16>,
    #[codec(cfg = &())]
    tail: u8,
}

#[test]
fn read_cfg_expression() {
    let value = Configured {
        items: vec![0x1234, 0x5678],
        tail: 9,
    };
    assert!(matches!(
        Configured::decode_cfg(value.encode(), &Limits { maximum: 1 }),
        Err(Error::InvalidLength(2))
    ));
    assert_roundtrip(
        value,
        &Limits { maximum: 2 },
        &[2, 0x12, 0x34, 0x56, 0x78, 9],
    );
}

#[derive(Debug, PartialEq, Write, EncodeSize, Read)]
#[codec(read_cfg = RangeCfg<usize>)]
enum Packet {
    Empty,
    Pair(#[codec(cfg = &())] u16, #[codec(cfg = &())] u8),
    Data {
        payload: Bytes,
    },
    #[codec(tag = 255)]
    Last,
}

#[derive(Debug, PartialEq, Write, Read, FixedSize)]
enum FixedPacket<T> {
    Left(T),
    Right { value: T },
}

#[derive(Debug, PartialEq, Write, Read, FixedSize)]
enum Flag {
    Off,
    On,
}

#[derive(Debug, PartialEq, Write, Read, FixedSize)]
enum EqualLayouts {
    Word(u16),
    Bytes { high: u8, low: u8 },
}

#[test]
fn enum_tags_sizes_and_invalid_input() {
    let cfg = RangeCfg::new(..=2);
    assert_roundtrip(Packet::Empty, &cfg, &[0]);
    assert_roundtrip(Packet::Pair(0x1234, 5), &cfg, &[1, 0x12, 0x34, 5]);
    assert_roundtrip(
        Packet::Data {
            payload: Bytes::from_static(&[7, 8]),
        },
        &cfg,
        &[2, 2, 7, 8],
    );
    assert_roundtrip(Packet::Last, &cfg, &[255]);
    assert!(matches!(
        Packet::decode_cfg(Bytes::from_static(&[3]), &cfg),
        Err(Error::InvalidEnum(3))
    ));
    assert_eq!(FixedPacket::<u16>::SIZE, 3);
    assert_roundtrip(FixedPacket::Left(0x1234u16), &(), &[0, 0x12, 0x34]);
    assert_roundtrip(
        FixedPacket::Right { value: 0x1234u16 },
        &(),
        &[1, 0x12, 0x34],
    );
    assert_eq!(Flag::SIZE, 1);
    assert_roundtrip(Flag::Off, &(), &[0]);
    assert_roundtrip(Flag::On, &(), &[1]);
    assert_eq!(EqualLayouts::SIZE, 3);
    assert_roundtrip(EqualLayouts::Word(0x1234), &(), &[0, 0x12, 0x34]);
    assert_roundtrip(
        EqualLayouts::Bytes {
            high: 0x12,
            low: 0x34,
        },
        &(),
        &[1, 0x12, 0x34],
    );
}

struct Opaque(u16);

fn write_opaque(value: &Opaque, buf: &mut impl BufMut) {
    value.0.write(buf);
}

#[derive(Encode)]
struct Custom {
    #[codec(encode_with = write_opaque, encode_size = 2)]
    first: Opaque,
    #[codec(encode_with = { value.0.write(buf); }, encode_size = 1 + 1)]
    second: Opaque,
}

#[derive(Write, EncodeSize)]
#[encode_size(1 + self.data.len())]
struct CustomSize {
    prefix: u8,
    #[codec(encode_with = { buf.put_slice(value); })]
    data: Vec<u8>,
}

#[derive(Encode)]
enum CustomVariant {
    Data(
        #[codec(encode_with = |value: &Opaque, buf| write_opaque(value, buf), encode_size = 2)]
        Opaque,
    ),
}

#[test]
fn custom_encoder_without_field_traits() {
    let value = Custom {
        first: Opaque(0x1234),
        second: Opaque(0x5678),
    };
    assert_eq!(value.encode().as_ref(), &[0x12, 0x34, 0x56, 0x78]);
    let mut chunks = TrackingWriteBuf::new();
    value.write_bufs(&mut chunks);
    assert_eq!(chunks.freeze(), value.encode());
    assert_eq!(value.encode_inline_size(), 4);

    let value = CustomSize {
        prefix: 9,
        data: vec![1, 2],
    };
    assert_eq!(value.encode().as_ref(), &[9, 1, 2]);
    assert_eq!(value.encode_inline_size(), 3);
    assert_eq!(
        CustomVariant::Data(Opaque(0x1234)).encode().as_ref(),
        &[0, 0x12, 0x34]
    );
}

#[derive(Debug, PartialEq, Encode, Read)]
struct Names {
    buf: u8,
    cfg: u8,
    value: u8,
    __codec_field_0: u8,
    r#type: u8,
}

#[test]
fn field_names_do_not_shadow_generated_bindings() {
    assert_roundtrip(
        Names {
            buf: 1,
            cfg: 2,
            value: 3,
            __codec_field_0: 4,
            r#type: 5,
        },
        &(),
        &[1, 2, 3, 4, 5],
    );
}

trait Associated {
    type Item;
}

struct Owner;
impl Associated for Owner {
    type Item = u16;
}

#[derive(Write, FixedSize, Read)]
struct AssociatedField<T: Associated>
where
    T::Item: Sized,
{
    item: T::Item,
}

#[derive(Encode)]
struct Lifetime<'a> {
    #[codec(encode_with = { buf.put_slice(value); }, encode_size = value.len())]
    bytes: &'a [u8],
}

#[test]
fn bounds_apply_to_field_types() {
    let value = AssociatedField::<Owner> { item: 0x1234 };
    assert_eq!(AssociatedField::<Owner>::SIZE, 2);
    assert_eq!(value.encode().as_ref(), &[0x12, 0x34]);
    assert_eq!(
        AssociatedField::<Owner>::decode(value.encode())
            .unwrap()
            .item,
        value.item
    );
    let value = Lifetime { bytes: &[7] };
    assert_eq!(value.encode().as_ref(), &[7]);
}

#[derive(Write)]
struct WriteOnly(crate::types::tests::Byte);

#[derive(Debug, PartialEq, Write, Read)]
#[encode_size(Self::SIZE)]
struct FixedLazy(crate::types::lazy::Lazy<u32>);

impl FixedSize for FixedLazy {
    const SIZE: usize = u32::SIZE;
}

#[test]
fn fixed_wrapper_of_shared_bytes_writes_inline() {
    let value = FixedLazy::decode(Bytes::from_static(&[0, 0, 0, 7])).unwrap();
    assert_roundtrip(value, &(), &[0, 0, 0, 7]);
}

#[derive(Write, EncodeSize, Read)]
#[read_cfg(<T as Read>::Cfg)]
struct ForwardCfg<T: Read>(T);

#[derive(Write, EncodeSize, Read)]
#[read_cfg(T::Cfg)]
struct ForwardShortCfg<T: Read>(T);

#[derive(Write, EncodeSize, Read)]
#[read_cfg(<T as Reader>::Cfg)]
struct ForwardAlias<T: Reader>(T);

#[derive(Debug, PartialEq, Write, EncodeSize, Read)]
#[read_cfg((RangeCfg<usize>, T::Cfg))]
struct ConfiguredCollection<T: Read> {
    #[codec(cfg = cfg)]
    values: Vec<T>,
    #[codec(cfg = &cfg.1)]
    pair: [T; 2],
}

#[test]
fn configured_generic_fields_keep_their_configuration() {
    assert_roundtrip(
        ConfiguredCollection {
            values: vec![3u8],
            pair: [4, 5],
        },
        &((..=2).into(), ()),
        &[1, 3, 4, 5],
    );
}

#[test]
fn associated_read_configuration() {
    let cfg = RangeCfg::new(..=2);
    let payload = Bytes::from_static(&[7, 8]);
    let value = ForwardCfg(payload.clone());
    assert_eq!(
        ForwardCfg::<Bytes>::decode_cfg(value.encode(), &cfg)
            .unwrap()
            .0,
        payload
    );
    let value = ForwardShortCfg(payload.clone());
    assert_eq!(
        ForwardShortCfg::<Bytes>::decode_cfg(value.encode(), &cfg)
            .unwrap()
            .0,
        payload
    );
    let value = ForwardAlias(payload.clone());
    assert_eq!(
        ForwardAlias::<Bytes>::decode_cfg(value.encode(), &cfg)
            .unwrap()
            .0,
        payload
    );
}

#[derive(Debug, PartialEq, Encode, Read)]
#[read_cfg(RangeCfg<usize>)]
struct Node {
    #[codec(cfg = &())]
    value: u8,
    #[codec(cfg = &(*cfg, *cfg))]
    children: Vec<Self>,
}

#[derive(Debug, PartialEq, Encode, Read)]
#[read_cfg((T::Cfg, RangeCfg<usize>))]
// Exercise recursion through the explicit type path as well as through `Self`.
#[allow(clippy::use_self)]
struct GenericNode<T: Read> {
    #[codec(cfg = &cfg.0)]
    value: T,
    #[codec(cfg = &(cfg.1, cfg.clone()))]
    children: Vec<GenericNode<T>>,
}

#[test]
fn recursive_codecs() {
    let value = Node {
        value: 1,
        children: vec![Node {
            value: 2,
            children: vec![],
        }],
    };
    assert_roundtrip(value, &RangeCfg::new(..=2), &[1, 1, 2, 0]);
    let value = GenericNode {
        value: 1u16,
        children: vec![GenericNode {
            value: 2,
            children: vec![],
        }],
    };
    assert_roundtrip(value, &((), RangeCfg::new(..=2)), &[0, 1, 1, 0, 2, 0]);
}

#[allow(non_upper_case_globals)]
#[derive(Debug, PartialEq, Encode, Read)]
struct ConstNames<const buf: usize, const cfg: usize, const value: usize, const tag: usize> {
    first: [u8; buf],
    second: [u8; cfg],
    third: [u8; value],
    fourth: [u8; tag],
}

#[test]
fn const_generic_names_do_not_shadow_generated_bindings() {
    assert_roundtrip(
        ConstNames {
            first: [1],
            second: [2],
            third: [3],
            fourth: [4],
        },
        &(),
        &[1, 2, 3, 4],
    );
}

mod other {
    use crate::{EncodeSize, Write};

    #[derive(Write, EncodeSize)]
    pub struct Node<T>(pub T);
}

mod qualified {
    use crate::{EncodeSize, Write};

    #[derive(Write, EncodeSize)]
    pub struct Node<T>(pub super::other::Node<T>);
}

trait OtherCfg {
    type Cfg;
}
impl OtherCfg for u8 {
    type Cfg = ();
}

#[derive(Read)]
#[read_cfg(<T as OtherCfg>::Cfg)]
struct ForeignCfg<T: OtherCfg>(T);

mod limits {
    #[derive(Clone)]
    pub struct Cfg;
}

#[derive(Read)]
#[read_cfg(limits::Cfg)]
struct ModuleCfg(#[codec(cfg = &())] u8);

#[derive(EncodeSize)]
#[encode_size(tag)]
#[allow(non_upper_case_globals, dead_code)]
struct SizedArray<const tag: usize>([u8; tag]);

#[test]
fn qualified_field_bounds_and_attribute_const_references() {
    assert_eq!(qualified::Node(other::Node(7u8)).encode().as_ref(), &[7]);
    assert_eq!(
        ForeignCfg::<u8>::decode(Bytes::from_static(&[7]))
            .unwrap()
            .0,
        7
    );
    assert_eq!(
        ModuleCfg::decode_cfg(Bytes::from_static(&[8]), &limits::Cfg)
            .unwrap()
            .0,
        8
    );
    assert_eq!(SizedArray([0; 3]).encode_size(), 3);
}

#[test]
fn write_does_not_require_size() {
    let mut buf = Vec::new();
    WriteOnly(crate::types::tests::Byte(7)).write(&mut buf);
    assert_eq!(buf, [7]);
}
