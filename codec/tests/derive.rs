use commonware_codec::{DecodeExt, Encode, FixedSize, Read, Write};

#[derive(Debug, PartialEq, Write, Read, FixedSize)]
struct Header(u16);

#[test]
fn derive_from_codec_integration_target() {
    let header = Header(0x1234);
    assert_eq!(Header::SIZE, 2);
    assert_eq!(header.encode().as_ref(), &[0x12, 0x34]);
    assert_eq!(Header::decode(header.encode()).unwrap(), header);
}
