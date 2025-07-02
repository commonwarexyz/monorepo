#![no_main]

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use commonware_codec::{DecodeExt, Encode};
use commonware_stream::public_key::handshake::Confirmation;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, arbitrary::Arbitrary)]
struct FuzzInput {
    create_key: [u8; 32],
    create_transcript: Vec<u8>,
    verify_transcript: Vec<u8>,
    raw_decode_bytes: Vec<u8>,
}

fn fuzz(input: FuzzInput) {
    let cipher = ChaCha20Poly1305::new(&input.create_key.into());

    let confirmation = Confirmation::create(cipher.clone(), &input.create_transcript)
        .expect("confirmation create failed");
    confirmation
        .verify(cipher.clone(), &input.create_transcript)
        .expect("confirmation verification failed");

    let _ = confirmation.verify(cipher.clone(), &input.verify_transcript);

    let encoded = confirmation.encode();
    let decoded =
        Confirmation::decode(encoded.clone()).expect("Decoding valid data should succeed");
    decoded
        .verify(cipher, &input.create_transcript)
        .expect("Decoded confirmation should verify with original parameters");

    let _ = Confirmation::decode(input.raw_decode_bytes.as_slice());
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
