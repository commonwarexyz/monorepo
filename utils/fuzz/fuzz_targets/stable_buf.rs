#![no_main]

use arbitrary::Arbitrary;
use bytes::{Bytes, BytesMut};
use commonware_utils::StableBuf;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    Default,
    FromVec(Vec<u8>),
    FromBytesMut(Vec<u8>),
    PutSlice(Vec<u8>),
    Truncate(Vec<u8>, usize, StableBufFuzz),
    GetMut(Vec<u8>, StableBufFuzz),
    GetMutPtr(Vec<u8>, StableBufFuzz),
    Len(Vec<u8>, StableBufFuzz),
    IsEmpty(Vec<u8>, StableBufFuzz),
    Index(Vec<u8>, usize, StableBufFuzz),
    ConvertToBytes(Vec<u8>, StableBufFuzz),
    ConvertToVec(Vec<u8>, StableBufFuzz),
}

#[derive(Arbitrary, Debug)]
enum StableBufFuzz {
    Vec,
    BytesMut,
}

fn fuzz(input: Vec<FuzzInput>) {
    for op in input {
        match op {
            FuzzInput::Default => {
                let b = StableBuf::default();
                assert_eq!(b.len(), 0);
            }

            FuzzInput::FromVec(data) => {
                let len = data.len();
                let buf = StableBuf::from(data.clone());
                assert_eq!(buf.len(), len);

                let stable_buf_vec = StableBuf::Vec(data.clone());
                let stable_buf_bytes_mut = StableBuf::BytesMut(BytesMut::from(&data[..]));
                assert_eq!(stable_buf_vec.len(), len);
                assert_eq!(stable_buf_bytes_mut.len(), len);

                let bytes_from_vec: Bytes = stable_buf_vec.into();
                let bytes_from_bytes_mut: Bytes = stable_buf_bytes_mut.into();

                assert_eq!(bytes_from_vec, bytes_from_bytes_mut);
            }

            FuzzInput::FromBytesMut(data) => {
                let len = data.len();
                let buf = BytesMut::from(data.as_slice());
                assert_eq!(buf.len(), len);

                let stable_buf: StableBuf = buf.into();
                assert_eq!(stable_buf.len(), len);
            }

            FuzzInput::PutSlice(data) => {
                let mut buf: Option<StableBuf> = None;
                if buf.is_none() {
                    buf = Some(StableBuf::from(Vec::new()));
                }

                if let Some(ref mut b) = buf {
                    let data = if data.len() > 10_000 {
                        &data[..10_000]
                    } else {
                        &data
                    };

                    if b.len() < data.len() {
                        return;
                    }
                    b.put_slice(data);
                }
            }

            FuzzInput::Truncate(data, new_len, kind) => {
                let mut buf = match kind {
                    StableBufFuzz::Vec => StableBuf::Vec(data.clone()),
                    StableBufFuzz::BytesMut => StableBuf::BytesMut(BytesMut::from(&data[..])),
                };
                if new_len <= buf.len() {
                    buf.truncate(new_len);
                    assert_eq!(buf.len(), new_len);
                }
            }

            FuzzInput::GetMutPtr(data, kind) => {
                let mut buf = match kind {
                    StableBufFuzz::Vec => StableBuf::Vec(data.clone()),
                    StableBufFuzz::BytesMut => StableBuf::BytesMut(BytesMut::from(&data[..])),
                };

                let ptr1 = buf.as_mut_ptr();
                let ptr2 = buf.as_mut_ptr();

                assert_eq!(ptr1, ptr2);

                if !buf.is_empty() {
                    assert!(!ptr1.is_null());
                }
            }

            FuzzInput::GetMut(data, kind) => {
                let mut buf = match kind {
                    StableBufFuzz::Vec => StableBuf::Vec(data.clone()),
                    StableBufFuzz::BytesMut => StableBuf::BytesMut(BytesMut::from(&data[..])),
                };
                let b = buf.as_mut();
                if b.len() > 0 {
                    b[0] = 0;
                    assert_eq!(buf[0], 0);
                }
            }

            FuzzInput::Len(data, kind) => {
                let buf = match kind {
                    StableBufFuzz::Vec => StableBuf::Vec(data.clone()),
                    StableBufFuzz::BytesMut => StableBuf::BytesMut(BytesMut::from(&data[..])),
                };
                let len = data.len();
                assert_eq!(buf.len(), len);
            }

            FuzzInput::IsEmpty(data, kind) => {
                let is_empty = data.is_empty();
                let buf = match kind {
                    StableBufFuzz::Vec => StableBuf::Vec(data.clone()),
                    StableBufFuzz::BytesMut => StableBuf::BytesMut(BytesMut::from(&data[..])),
                };
                assert_eq!(buf.is_empty(), is_empty);
            }

            FuzzInput::Index(data, idx, kind) => {
                let buf = match kind {
                    StableBufFuzz::Vec => StableBuf::Vec(data.clone()),
                    StableBufFuzz::BytesMut => StableBuf::BytesMut(BytesMut::from(&data[..])),
                };

                if idx < buf.len() {
                    let byte = buf[idx];

                    let as_ref: &[u8] = buf.as_ref();
                    assert_eq!(byte, as_ref[idx]);
                }
            }

            FuzzInput::ConvertToBytes(data, kind) => {
                let buf = match kind {
                    StableBufFuzz::Vec => StableBuf::Vec(data.clone()),
                    StableBufFuzz::BytesMut => StableBuf::BytesMut(BytesMut::from(&data[..])),
                };
                let bytes: Bytes = buf.into();
                assert_eq!(bytes.to_vec(), data);
            }

            FuzzInput::ConvertToVec(data, kind) => {
                let buf = match kind {
                    StableBufFuzz::Vec => StableBuf::Vec(data.clone()),
                    StableBufFuzz::BytesMut => StableBuf::BytesMut(BytesMut::from(&data[..])),
                };
                let vec: Vec<u8> = buf.into();
                assert_eq!(vec, data);
            }
        }
    }
}

fuzz_target!(|input: Vec<FuzzInput>| {
    fuzz(input);
});
