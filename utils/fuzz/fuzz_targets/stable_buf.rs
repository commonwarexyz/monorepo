#![no_main]

use arbitrary::Arbitrary;
use bytes::{Bytes, BytesMut};
use commonware_utils::StableBuf;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    FromVec(Vec<u8>),
    FromBytesMut(Vec<u8>),
    PutSlice(Vec<u8>),
    Truncate(usize),
    GetMutPtr,
    Len,
    IsEmpty,
    Index(usize),
    ConvertToBytes,
    ConvertToVec,
}

fn fuzz(input: Vec<FuzzInput>) {
    let mut buf: Option<StableBuf> = None;

    for op in input {
        match op {
            FuzzInput::FromVec(data) => {
                let data = if data.len() > 100_000 {
                    data[..100_000].to_vec()
                } else {
                    data
                };

                let len = data.len();
                buf = Some(StableBuf::from(data));

                if let Some(ref b) = buf {
                    assert_eq!(b.len(), len);
                    assert_eq!(b.is_empty(), len == 0);
                }
            }

            FuzzInput::FromBytesMut(data) => {
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

            FuzzInput::Truncate(new_len) => {
                if let Some(ref mut b) = buf {
                    b.truncate(new_len);
                }
            }

            FuzzInput::GetMutPtr => {
                if let Some(ref mut b) = buf {
                    let ptr1 = b.as_mut_ptr();
                    let ptr2 = b.as_mut_ptr();

                    assert_eq!(ptr1, ptr2);

                    if !b.is_empty() {
                        assert!(!ptr1.is_null());
                    }
                }
            }

            FuzzInput::Len => {
                if let Some(ref b) = buf {
                    let len = b.len();
                    assert_eq!(b.is_empty(), len == 0);

                    let as_ref: &[u8] = b.as_ref();
                    assert_eq!(as_ref.len(), len);
                }
            }

            FuzzInput::IsEmpty => {
                if let Some(ref b) = buf {
                    let is_empty = b.is_empty();
                    assert_eq!(is_empty, b.is_empty());
                }
            }

            FuzzInput::Index(idx) => {
                if let Some(ref b) = buf {
                    if idx < b.len() {
                        let byte = b[idx];

                        let as_ref: &[u8] = b.as_ref();
                        assert_eq!(byte, as_ref[idx]);
                    }
                }
            }

            FuzzInput::ConvertToBytes => {
                if let Some(b) = buf.take() {
                    let len = b.len();
                    let bytes: Bytes = b.into();
                    assert_eq!(bytes.len(), len);

                    buf = Some(StableBuf::from(bytes.to_vec()));
                }
            }

            FuzzInput::ConvertToVec => {
                if let Some(b) = buf.take() {
                    let len = b.len();
                    let vec: Vec<u8> = b.into();
                    assert_eq!(vec.len(), len);

                    buf = Some(StableBuf::from(vec));
                }
            }
        }
    }
}

fuzz_target!(|input: Vec<FuzzInput>| {
    fuzz(input);
});
