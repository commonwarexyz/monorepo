#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::StableBuf;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    initial_buffer_size: u8,
    initial_buffer_content: Vec<u8>,
    slice_to_put: Vec<u8>,
    use_vec_variant: bool,
}

fuzz_target!(|input: FuzzInput| {
    let buffer_size = input.initial_buffer_size as usize;

    if buffer_size == 0 {
        return;
    }

    let mut initial_content = input.initial_buffer_content;
    initial_content.resize(buffer_size, 0);

    let mut stable_buf = if input.use_vec_variant {
        StableBuf::from(initial_content)
    } else {
        use bytes::BytesMut;
        let bytes_mut = BytesMut::from(&initial_content[..]);
        StableBuf::from(bytes_mut)
    };

    stable_buf.put_slice(&input.slice_to_put);

    for (i, &byte) in input.slice_to_put.iter().enumerate() {
        if i < stable_buf.len() {
            assert_eq!(stable_buf[i], byte);
        }
    }
});
