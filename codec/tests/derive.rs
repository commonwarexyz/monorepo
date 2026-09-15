use commonware_codec::{
    Buf, Copying, DecodeExt, Encode, EncodeSize, Error, FixedSize, Read, Write,
};
use core::marker::PhantomData;

#[derive(Debug, PartialEq, Write, Read, FixedSize)]
struct Header(u16);

#[test]
fn derive_from_codec_integration_target() {
    let header = Header(0x1234);
    assert_eq!(Header::SIZE, 2);
    assert_eq!(header.encode().as_ref(), &[0x12, 0x34]);
    assert_eq!(Header::decode(header.encode()).unwrap(), header);
}

#[derive(Encode)]
#[codec(
    write_bounds(T: AsRef<[u8]>),
    encode_size_bounds(T: AsRef<[u8]>)
)]
struct Raw<T>(
    #[codec(
    encode_with = { buf.put_slice(value.as_ref()); },
    encode_size = value.as_ref().len()
)]
    T,
);

#[test]
fn encode_bound_overrides_apply_independently() {
    let value = Raw([3u8, 7]);
    assert_eq!(value.encode().as_ref(), &[3, 7]);
    assert_eq!(value.encode_size(), 2);
}

struct ReadMarker<T>(u8, PhantomData<T>);

impl<T> Read for ReadMarker<T> {
    type Cfg = u8;

    fn read_cfg(buf: &mut impl Buf, cfg: &u8) -> Result<Self, Error> {
        Ok(Self(u8::read_cfg(buf, &())? ^ cfg, PhantomData))
    }
}

#[derive(Read)]
#[read_cfg(u8)]
#[codec(read_bounds())]
struct ReadContainer<T>(#[codec(cfg = &(*cfg + 1))] ReadMarker<T>);

#[test]
fn empty_read_bounds_allow_non_read_marker_generics() {
    let mut input = Copying(&[7]);
    assert_eq!(
        ReadContainer::<PhantomData<fn()>>::read_cfg(&mut input, &7)
            .unwrap()
            .0
            .0,
        15
    );
}

#[derive(Debug, PartialEq, Read)]
#[read_cfg(u8)]
struct CustomReadFunction(#[codec(cfg = &(*cfg + 1), read_with = read_u8)] u8);

fn read_u8(buf: &mut impl Buf, cfg: &u8) -> Result<u8, Error> {
    let value = u8::read_cfg(buf, &())?;
    (value == *cfg)
        .then_some(value)
        .ok_or(Error::Invalid("CustomReadFunction", "bad value"))
}

#[derive(Debug, PartialEq, Read)]
#[read_cfg(u8)]
struct CustomReadClosure(
    #[codec(read_with = |buf: &mut dyn Buf, cfg: &u8| {
    if !buf.has_remaining() { return Err(Error::EndOfBuffer); }
    let value = buf.get_u8();
    if value == *cfg { Ok(value) } else { Err(Error::Invalid("CustomReadClosure", "bad value")) }
})]
    u8,
);

#[derive(Debug, PartialEq, Read)]
#[read_cfg(u8)]
struct CustomReadBlock(
    #[codec(cfg = &(*cfg + 2), read_with = {
    let value = u8::read_cfg(buf, &())?;
    if value == *cfg { Ok(value) } else { Err(Error::Invalid("CustomReadBlock", "bad value")) }
})]
    u8,
);

#[test]
fn custom_readers_receive_projected_config_and_propagate_errors() {
    let mut input = Copying(&[8]);
    assert_eq!(
        CustomReadFunction::read_cfg(&mut input, &7).unwrap(),
        CustomReadFunction(8)
    );
    let mut input = Copying(&[9]);
    assert_eq!(
        CustomReadClosure::read_cfg(&mut input, &9).unwrap(),
        CustomReadClosure(9)
    );
    let mut input = Copying(&[9]);
    assert_eq!(
        CustomReadBlock::read_cfg(&mut input, &7).unwrap(),
        CustomReadBlock(9)
    );
    let mut input = Copying(&[1]);
    assert!(matches!(
        CustomReadClosure::read_cfg(&mut input, &2),
        Err(Error::Invalid("CustomReadClosure", "bad value"))
    ));
}

#[test]
fn custom_readers_propagate_truncation() {
    let mut input = Copying(&[]);
    assert!(matches!(
        CustomReadFunction::read_cfg(&mut input, &0),
        Err(Error::EndOfBuffer)
    ));
    assert!(matches!(
        CustomReadClosure::read_cfg(&mut input, &0),
        Err(Error::EndOfBuffer)
    ));
    assert!(matches!(
        CustomReadBlock::read_cfg(&mut input, &0),
        Err(Error::EndOfBuffer)
    ));
}

const fn invalid_tag(tag: u8) -> Error {
    Error::Invalid(
        "Tagged",
        if tag == 9 {
            "unsupported tag"
        } else {
            "wrong tag"
        },
    )
}

#[derive(Read)]
#[codec(invalid_tag = invalid_tag)]
enum Tagged {
    Value,
}

#[derive(Read)]
#[codec(invalid_tag = { Error::Invalid("TaggedBlock", "unsupported tag") })]
enum TaggedBlock {
    Value,
}

#[derive(Read)]
#[codec(invalid_tag = |tag| Error::Invalid("TaggedClosure", if tag == 3 { "bad" } else { "other" }))]
enum TaggedClosure {
    Value,
}

#[test]
fn custom_invalid_tag_handlers_return_their_errors() {
    let mut input = Copying(&[9]);
    assert!(matches!(
        Tagged::read_cfg(&mut input, &()),
        Err(Error::Invalid("Tagged", "unsupported tag"))
    ));
    let mut input = Copying(&[4]);
    assert!(matches!(
        TaggedBlock::read_cfg(&mut input, &()),
        Err(Error::Invalid("TaggedBlock", "unsupported tag"))
    ));
    let mut input = Copying(&[3]);
    assert!(matches!(
        TaggedClosure::read_cfg(&mut input, &()),
        Err(Error::Invalid("TaggedClosure", "bad"))
    ));
    let mut input = Copying(&[]);
    assert!(matches!(
        Tagged::read_cfg(&mut input, &()),
        Err(Error::EndOfBuffer)
    ));
}

#[derive(FixedSize)]
#[codec(fixed_size_bounds())]
struct FixedGeneric<T: FixedSize>(T);

#[test]
fn fixed_size_bounds_preserve_declared_bounds() {
    assert_eq!(FixedGeneric::<u16>::SIZE, 2);
}

#[derive(Read)]
#[read_cfg(T::Cfg)]
#[codec(read_bounds(T: Read))]
struct Projected<T: Read>(T);

#[allow(non_upper_case_globals)]
#[derive(Write, Read)]
#[codec(write_bounds([u8; buf]: Write), read_bounds([u8; buf]: Read<Cfg = ()>))]
struct Reserved<const buf: usize>([u8; buf]);

#[test]
fn overrides_support_projected_configs_and_reserved_const_names() {
    let mut input = Copying(&[4u8]);
    assert_eq!(Projected::<u8>::read_cfg(&mut input, &()).unwrap().0, 4);
    let mut bytes = Vec::new();
    Reserved([3, 7]).write(&mut bytes);
    let mut input = Copying(bytes.as_slice());
    assert_eq!(Reserved::<2>::read_cfg(&mut input, &()).unwrap().0, [3, 7]);
}
