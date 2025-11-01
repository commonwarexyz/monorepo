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
    PrivateKeyExt as _, Signer,
};
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::ops::Range;

const MAX_FRAME_BYTES: usize = 4096;
const MAX_MESSAGE_BYTES: usize = 2048;
const MAX_TWEAK_BYTES: usize = 128;

#[derive(Debug, Arbitrary)]
pub struct FuzzInput {
    syn_frame: Vec<u8>,
    synack_frame: Vec<u8>,
    ack_frame: Vec<u8>,
    message: Vec<u8>,
    dial_seed: u64,
    listen_seed: u64,
    range_start: u64,
    range_len: u16,
    time_offset: u16,
    out_of_range: bool,
    tamper_synack: bool,
    tamper_ack: bool,
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
    let span = (len as u64).saturating_add(1);
    let end = start.saturating_add(span);
    if end <= start {
        return None;
    }
    Some((start..end, span))
}

fn choose_time(range: &Range<u64>, span: u64, offset: u16, out_of_range: bool) -> u64 {
    if out_of_range {
        return range.end.saturating_add(offset as u64 + 1);
    }
    range.start.saturating_add((offset as u64) % span.max(1))
}

fn mutate_synack(
    original: &SynAck<Ed25519Signature>,
    mask: &[u8],
) -> Option<SynAck<Ed25519Signature>> {
    if mask.is_empty() {
        return None;
    }
    let mut encoded = original.encode().to_vec();
    for (byte, tweak) in encoded.iter_mut().zip(mask.iter().take(MAX_TWEAK_BYTES)) {
        *byte ^= *tweak;
    }
    let mut buf = Bytes::from(encoded);
    SynAck::<Ed25519Signature>::read_cfg(&mut buf, &()).ok()
}

fn mutate_ack(original: &Ack, mask: &[u8]) -> Option<Ack> {
    if mask.is_empty() {
        return None;
    }
    let mut encoded = original.encode().to_vec();
    for (byte, tweak) in encoded.iter_mut().zip(mask.iter().take(MAX_TWEAK_BYTES)) {
        *byte ^= *tweak;
    }
    let mut buf = Bytes::from(encoded);
    Ack::read_cfg(&mut buf, &()).ok()
}

fn fuzz_handshake(input: &FuzzInput, tamper_synack: bool, tamper_ack: bool) {
    let Some((range, span)) = make_range(input.range_start, input.range_len) else {
        return;
    };
    let mut dial_rng = ChaCha8Rng::seed_from_u64(input.dial_seed);
    let mut listen_rng = ChaCha8Rng::seed_from_u64(input.listen_seed);
    let dial_secret = PrivateKey::from_rng(&mut dial_rng);
    let listen_secret = PrivateKey::from_rng(&mut listen_rng);
    let current_time = choose_time(&range, span, input.time_offset, input.out_of_range);

    let dial_ctx = Context::new(
        current_time,
        range.clone(),
        dial_secret.clone(),
        listen_secret.public_key(),
    );
    let (dial_state, syn) = dial_start(&mut dial_rng, dial_ctx);

    let listen_ctx = Context::new(
        current_time,
        range.clone(),
        listen_secret.clone(),
        dial_secret.public_key(),
    );
    let Ok((listen_state, synack)) = listen_start(&mut listen_rng, listen_ctx, syn) else {
        return;
    };

    let synack_msg = if tamper_synack && input.tamper_synack {
        match mutate_synack(&synack, &input.synack_frame) {
            Some(mutated) => mutated,
            None => synack,
        }
    } else {
        synack
    };

    let Ok((ack, mut dial_send, mut dial_recv)) = dial_end(dial_state, synack_msg) else {
        return;
    };

    let ack_msg = if tamper_ack && input.tamper_ack {
        match mutate_ack(&ack, &input.ack_frame) {
            Some(mutated) => mutated,
            None => ack,
        }
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
    let mut dial_rng = ChaCha8Rng::seed_from_u64(input.dial_seed);
    let mut listen_rng = ChaCha8Rng::seed_from_u64(input.listen_seed);
    let dial_secret = PrivateKey::from_rng(&mut dial_rng);
    let listen_secret = PrivateKey::from_rng(&mut listen_rng);
    let current_time = choose_time(&range, span, input.time_offset, input.out_of_range);

    let ctx = Context::new(current_time, range, listen_secret, dial_secret.public_key());
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
    let mut dial_rng = ChaCha8Rng::seed_from_u64(input.dial_seed);
    let mut listen_rng = ChaCha8Rng::seed_from_u64(input.listen_seed);
    let dial_secret = PrivateKey::from_rng(&mut dial_rng);
    let listen_secret = PrivateKey::from_rng(&mut listen_rng);
    let current_time = choose_time(&range, span, input.time_offset, input.out_of_range);

    let dial_ctx = Context::new(
        current_time,
        range,
        dial_secret.clone(),
        listen_secret.public_key(),
    );
    let (dial_state, _) = dial_start(&mut dial_rng, dial_ctx);
    let _ = dial_end(dial_state, msg);
}

fn fuzz_direct_ciphers(input: &FuzzInput) {
    let mut rng = ChaCha8Rng::seed_from_u64(input.dial_seed);
    let mut send = SendCipher::new(&mut rng);
    let mut recv = RecvCipher::new(&mut rng);
    let payload = clamp_vec(input.message.clone(), MAX_MESSAGE_BYTES);
    if let Ok(ciphertext) = send.send(&payload) {
        let _ = recv.recv(&ciphertext);
    }

    let tweaks = clamp_vec(input.synack_frame.clone(), MAX_TWEAK_BYTES);
    for chunk in tweaks.chunks(4) {
        let mut data = payload.clone();
        data.extend_from_slice(chunk);
        if let Ok(ciphertext) = send.send(&data) {
            let _ = recv.recv(&ciphertext);
        } else {
            break;
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    match input.case_selector % 8 {
        0 => read_syn(&input.syn_frame),
        1 => read_synack(&input.synack_frame),
        2 => read_ack(&input.ack_frame),
        3 => fuzz_handshake(&input, false, false),
        4 => fuzz_handshake(&input, true, true),
        5 => fuzz_listen_with_random_syn(&input),
        6 => fuzz_dial_with_random_synack(&input),
        7 => fuzz_direct_ciphers(&input),
        _ => unreachable!(),
    }
});
