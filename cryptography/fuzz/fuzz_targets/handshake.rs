#![no_main]

use arbitrary::Arbitrary;
use bytes::Bytes;
use commonware_codec::{Encode, Read};
use commonware_cryptography::{
    ed25519::{PrivateKey, Signature as Ed25519Signature},
    handshake::{
        dial_end, dial_start, listen_end, listen_start, Ack, Context, RecvCipher, SendCipher, Syn,
        SynAck,
    },
    transcript::Transcript,
    Signer,
};
use libfuzzer_sys::fuzz_target;
use std::ops::Range;

const MAX_FRAME_BYTES: usize = 4096;
const MAX_MESSAGE_BYTES: usize = 2048;
const MAX_TWEAK_BYTES: usize = 128;
const PRIVATE_KEY_SIZE: usize = 32;

#[derive(Debug, Arbitrary)]
pub struct FuzzInput {
    syn_frame: Vec<u8>,
    synack_frame: Vec<u8>,
    ack_frame: Vec<u8>,
    message: Vec<u8>,
    dial_key_bytes: [u8; PRIVATE_KEY_SIZE],
    listen_key_bytes: [u8; PRIVATE_KEY_SIZE],
    dial_random_bytes: Vec<u8>,
    listen_random_bytes: Vec<u8>,
    range_start: u64,
    range_len: u16,
    time_offset: u16,
    out_of_range: bool,
    tamper_synack: bool,
    tamper_ack: bool,
    role_selector: bool,
    case_selector: u8,
}

fn clamp_vec(mut data: Vec<u8>, max: usize) -> Vec<u8> {
    if data.len() > max {
        data.truncate(max);
    }
    data
}

fn read_syn(frame: &[u8]) {
    let mut buf = Bytes::from(clamp_vec(frame.to_vec(), MAX_FRAME_BYTES));
    let _ = Syn::<Ed25519Signature>::read_cfg(&mut buf, &());
}

fn read_synack(frame: &[u8]) {
    let mut buf = Bytes::from(clamp_vec(frame.to_vec(), MAX_FRAME_BYTES));
    let _ = SynAck::<Ed25519Signature>::read_cfg(&mut buf, &());
}

fn read_ack(frame: &[u8]) {
    let mut buf = Bytes::from(clamp_vec(frame.to_vec(), MAX_FRAME_BYTES));
    let _ = Ack::read_cfg(&mut buf, &());
}

fn make_range(start: u64, len: u16) -> Option<(Range<u64>, u64)> {
    let desired_span = (len as u64).saturating_add(1);
    let end = start.saturating_add(desired_span);
    if end <= start {
        return None;
    }
    // Calculate actual span based on the actual range
    let actual_span = end.saturating_sub(start);
    Some((start..end, actual_span))
}

fn choose_time(range: &Range<u64>, span: u64, offset: u16, out_of_range: bool) -> u64 {
    if out_of_range {
        return range.end.saturating_add(offset as u64).saturating_add(1);
    }

    let offset_in_range = (offset as u64) % span.max(1);
    let result = range.start.saturating_add(offset_in_range);

    if result >= range.end {
        range.start
    } else {
        result
    }
}

fn mutate_message<T>(original: &T, mask: &[u8]) -> Option<T>
where
    T: Encode + Read<Cfg = ()>,
{
    if mask.is_empty() {
        return None;
    }
    let mut encoded = original.encode().to_vec();
    for (byte, tweak) in encoded.iter_mut().zip(mask.iter().take(MAX_TWEAK_BYTES)) {
        *byte ^= *tweak;
    }
    let mut buf = Bytes::from(encoded);
    T::read_cfg(&mut buf, &()).ok()
}

struct FuzzRng {
    bytes: Vec<u8>,
    index: usize,
}

impl FuzzRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, index: 0 }
    }
}

impl rand::RngCore for FuzzRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            if self.index >= self.bytes.len() {
                self.index = 0;
            }
            if self.bytes.is_empty() {
                *byte = 0;
            } else {
                *byte = self.bytes[self.index];
                self.index = (self.index + 1) % self.bytes.len();
            }
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand::CryptoRng for FuzzRng {}

fn private_key_from_bytes(bytes: &[u8; PRIVATE_KEY_SIZE]) -> Option<PrivateKey> {
    use commonware_codec::ReadExt;
    let mut buf = bytes.as_slice();
    PrivateKey::read(&mut buf).ok()
}

fn fuzz_handshake(input: &FuzzInput) {
    let Some((range, span)) = make_range(input.range_start, input.range_len) else {
        return;
    };

    let dial_secret = match private_key_from_bytes(&input.dial_key_bytes) {
        Some(key) => key,
        None => return,
    };
    let listen_secret = match private_key_from_bytes(&input.listen_key_bytes) {
        Some(key) => key,
        None => return,
    };

    let mut dial_rng = if input.dial_random_bytes.is_empty() {
        FuzzRng::new(vec![0u8; 32])
    } else {
        FuzzRng::new(input.dial_random_bytes.clone())
    };

    let mut listen_rng = if input.listen_random_bytes.is_empty() {
        FuzzRng::new(vec![0u8; 32])
    } else {
        FuzzRng::new(input.listen_random_bytes.clone())
    };

    let current_time = choose_time(&range, span, input.time_offset, input.out_of_range);

    let base_transcript = Transcript::new(b"handshake_fuzz");
    let dial_ctx = Context::new(
        &base_transcript,
        current_time,
        range.clone(),
        dial_secret.clone(),
        listen_secret.public_key(),
    );
    let (dial_state, syn) = dial_start(&mut dial_rng, dial_ctx);

    let listen_ctx = Context::new(
        &base_transcript,
        current_time,
        range.clone(),
        listen_secret.clone(),
        dial_secret.public_key(),
    );
    let Ok((listen_state, synack)) = listen_start(&mut listen_rng, listen_ctx, syn) else {
        return;
    };

    let synack_msg = if input.tamper_synack {
        mutate_message(&synack, &input.synack_frame).unwrap_or(synack)
    } else {
        synack
    };

    let Ok((ack, mut dial_send, mut dial_recv)) = dial_end(dial_state, synack_msg) else {
        return;
    };

    let ack_msg = if input.tamper_ack {
        mutate_message(&ack, &input.ack_frame).unwrap_or(ack)
    } else {
        ack
    };

    let Ok((mut listen_send, mut listen_recv)) = listen_end(listen_state, ack_msg) else {
        return;
    };

    let payload = clamp_vec(input.message.clone(), MAX_MESSAGE_BYTES);
    if let Ok(ciphertext) = dial_send.send(&payload) {
        let _ = listen_recv.recv(&ciphertext);
    }

    if let Ok(response) = listen_send.send(&payload) {
        let _ = dial_recv.recv(&response);
    }
}

fn fuzz_listen_with_random_syn(input: &FuzzInput) {
    let mut buf = Bytes::from(clamp_vec(input.syn_frame.clone(), MAX_FRAME_BYTES));
    let Ok(msg) = Syn::<Ed25519Signature>::read_cfg(&mut buf, &()) else {
        return;
    };
    let Some((range, span)) = make_range(input.range_start, input.range_len) else {
        return;
    };

    let dial_secret = match private_key_from_bytes(&input.dial_key_bytes) {
        Some(key) => key,
        None => return,
    };
    let listen_secret = match private_key_from_bytes(&input.listen_key_bytes) {
        Some(key) => key,
        None => return,
    };

    let mut listen_rng = if input.listen_random_bytes.is_empty() {
        FuzzRng::new(vec![0u8; 32])
    } else {
        FuzzRng::new(input.listen_random_bytes.clone())
    };

    let current_time = choose_time(&range, span, input.time_offset, input.out_of_range);

    let base_transcript = Transcript::new(b"handshake_fuzz");
    let ctx = Context::new(
        &base_transcript,
        current_time,
        range,
        listen_secret,
        dial_secret.public_key(),
    );
    let _ = listen_start(&mut listen_rng, ctx, msg);
}

fn fuzz_dial_with_random_synack(input: &FuzzInput) {
    let mut buf = Bytes::from(clamp_vec(input.synack_frame.clone(), MAX_FRAME_BYTES));
    let Ok(msg) = SynAck::<Ed25519Signature>::read_cfg(&mut buf, &()) else {
        return;
    };
    let Some((range, span)) = make_range(input.range_start, input.range_len) else {
        return;
    };

    let dial_secret = match private_key_from_bytes(&input.dial_key_bytes) {
        Some(key) => key,
        None => return,
    };
    let listen_secret = match private_key_from_bytes(&input.listen_key_bytes) {
        Some(key) => key,
        None => return,
    };

    let mut dial_rng = if input.dial_random_bytes.is_empty() {
        FuzzRng::new(vec![0u8; 32])
    } else {
        FuzzRng::new(input.dial_random_bytes.clone())
    };

    let current_time = choose_time(&range, span, input.time_offset, input.out_of_range);

    let base_transcript = Transcript::new(b"handshake_fuzz");
    let ctx = Context::new(
        &base_transcript,
        current_time,
        range.clone(),
        dial_secret.clone(),
        listen_secret.public_key(),
    );
    let (state, _syn) = dial_start(&mut dial_rng, ctx);
    let _ = dial_end(state, msg);
}

fn fuzz_listen_with_random_ack(input: &FuzzInput) {
    let mut buf = Bytes::from(clamp_vec(input.ack_frame.clone(), MAX_FRAME_BYTES));
    let Ok(ack_msg) = Ack::read_cfg(&mut buf, &()) else {
        return;
    };
    let Some((range, span)) = make_range(input.range_start, input.range_len) else {
        return;
    };

    let dial_secret = match private_key_from_bytes(&input.dial_key_bytes) {
        Some(key) => key,
        None => return,
    };
    let listen_secret = match private_key_from_bytes(&input.listen_key_bytes) {
        Some(key) => key,
        None => return,
    };

    let mut dial_rng = if input.dial_random_bytes.is_empty() {
        FuzzRng::new(vec![0u8; 32])
    } else {
        FuzzRng::new(input.dial_random_bytes.clone())
    };

    let mut listen_rng = if input.listen_random_bytes.is_empty() {
        FuzzRng::new(vec![0u8; 32])
    } else {
        FuzzRng::new(input.listen_random_bytes.clone())
    };

    let current_time = choose_time(&range, span, input.time_offset, input.out_of_range);

    let base_transcript = Transcript::new(b"handshake_fuzz");
    let dial_ctx = Context::new(
        &base_transcript,
        current_time,
        range.clone(),
        dial_secret.clone(),
        listen_secret.public_key(),
    );
    let (_dial_state, syn) = dial_start(&mut dial_rng, dial_ctx);

    let listen_ctx = Context::new(
        &base_transcript,
        current_time,
        range.clone(),
        listen_secret.clone(),
        dial_secret.public_key(),
    );
    let Ok((listen_state, _synack)) = listen_start(&mut listen_rng, listen_ctx, syn) else {
        return;
    };

    let _ = listen_end(listen_state, ack_msg);
}

fn fuzz_cipher_exchange(input: &FuzzInput) {
    let payload = clamp_vec(input.message.clone(), MAX_MESSAGE_BYTES);

    let mut rng = if input.role_selector {
        if input.dial_random_bytes.is_empty() {
            FuzzRng::new(vec![0u8; 32])
        } else {
            FuzzRng::new(input.dial_random_bytes.clone())
        }
    } else if input.listen_random_bytes.is_empty() {
        FuzzRng::new(vec![0u8; 32])
    } else {
        FuzzRng::new(input.listen_random_bytes.clone())
    };

    let mut send = SendCipher::new(&mut rng);
    let mut recv = RecvCipher::new(&mut rng);

    if let Ok(encrypted) = send.send(&payload) {
        let _ = recv.recv(&encrypted);
    }
}

fn fuzz(input: FuzzInput) {
    match input.case_selector % 8 {
        0 => read_syn(&input.syn_frame),
        1 => read_synack(&input.synack_frame),
        2 => read_ack(&input.ack_frame),
        3 => fuzz_handshake(&input),
        4 => fuzz_listen_with_random_syn(&input),
        5 => fuzz_dial_with_random_synack(&input),
        6 => fuzz_listen_with_random_ack(&input),
        7 => fuzz_cipher_exchange(&input),
        _ => unreachable!(),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
