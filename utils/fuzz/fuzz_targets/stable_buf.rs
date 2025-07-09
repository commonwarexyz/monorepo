#![no_main]

use arbitrary::Arbitrary;
use bytes::{Bytes, BytesMut};
use commonware_utils::StableBuf;
use libfuzzer_sys::fuzz_target;

const MAX_SIZE: usize = 100_000;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    FromVec(Vec<u8>),
    FromBytesMut(Vec<u8>),
    PutSlice(Vec<u8>),
    Truncate(Vec<u8>, usize),
    GetMutPtr(Vec<u8>),
    Len(Vec<u8>),
    IsEmpty(Vec<u8>),
    Index(Vec<u8>, usize),
    ConvertToBytes(Vec<u8>),
    ConvertToVec(Vec<u8>),
}

fn fuzz(input: Vec<FuzzInput>) {
    for op in input {
        match op {
            FuzzInput::FromVec(data) => {
                let mut buf: Option<StableBuf> = None;
                let len = data.len();
                buf = Some(StableBuf::from(data));

                if let Some(ref b) = buf {
                    assert_eq!(b.len(), len);
                    assert_eq!(b.is_empty(), len == 0);
                }
            }

            FuzzInput::FromBytesMut(data) => {
                let mut buf: Option<StableBuf> = None;
                let data = if data.len() > 100_000 {
                    data[..100_000].to_vec()
                } else {
                    data
                };

                let len = data.len();
                let bytes_mut = BytesMut::from(data.as_slice());
                buf = Some(StableBuf::from(bytes_mut));

                if let Some(ref b) = buf {
                    assert_eq!(b.len(), len);
                    assert_eq!(b.is_empty(), len == 0);
                }
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

            FuzzInput::Truncate(data, new_len) => {
                let mut buf = StableBuf::from(data);
                if new_len <= buf.len() {
                    buf.truncate(new_len);
                    assert_eq!(buf.len(), new_len);
                }
            }

            FuzzInput::GetMutPtr(data) => {
                let mut buf = StableBuf::from(data);

                let ptr1 = buf.as_mut_ptr();
                let ptr2 = buf.as_mut_ptr();

                assert_eq!(ptr1, ptr2);

                if !buf.is_empty() {
                    assert!(!ptr1.is_null());
                }
            }

            FuzzInput::Len(data) => {
                let buf = StableBuf::from(data.clone());
                assert_eq!(buf.len(), data.len());
            }

            FuzzInput::IsEmpty(data) => {
                let buf = StableBuf::from(data.clone());
                assert_eq!(buf.is_empty(), data.is_empty());
            }

            FuzzInput::Index(data, idx) => {
                let buf = StableBuf::from(data);
                if idx < buf.len() {
                    let byte = buf[idx];

                    let as_ref: &[u8] = buf.as_ref();
                    assert_eq!(byte, as_ref[idx]);
                }
            }

            FuzzInput::ConvertToBytes(data) => {
                let buf = StableBuf::from(data.clone());
                let bytes: Bytes = buf.into();
                assert_eq!(bytes.to_vec(), data);
            }

            FuzzInput::ConvertToVec(data) => {
                let buf = StableBuf::from(data.clone());
                let vec: Vec<u8> = buf.into();
                assert_eq!(vec, data);
            }
        }
    }
}

fuzz_target!(|input: Vec<FuzzInput>| {
    fuzz(input);
});
