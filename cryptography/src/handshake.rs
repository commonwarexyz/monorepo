use chacha20poly1305::{aead::AeadMut, ChaCha20Poly1305, KeyInit};
use commonware_codec::Encode;
use rand_core::CryptoRngCore;

use crate::{
    transcript::{Summary, Transcript},
    PublicKey, Signer, Verifier,
};

const NAMESPACE: &'static [u8] = b"commonware/handshake";

pub struct Msg1<S> {
    time_ms: u64,
    epk: x25519_dalek::PublicKey,
    sig: S,
}

pub struct Msg2<S> {
    time_ms: u64,
    epk: x25519_dalek::PublicKey,
    sig: S,
    confirmation: Summary,
}

pub struct Msg3 {
    confirmation: Summary,
}

pub struct DialState<P> {
    esk: x25519_dalek::EphemeralSecret,
    peer_identity: P,
    transcript: Transcript,
}

pub struct ListenState {
    confirmation: Summary,
    send: SendCipher,
    recv: RecvCipher,
}

struct CounterNonce {
    inner: u128,
}

impl CounterNonce {
    pub fn new() -> Self {
        Self { inner: 0 }
    }

    pub fn inc(&mut self) -> [u8; 16] {
        if self.inner >= 1 << 96 {
            panic!("overflowed nonce");
        }
        let out = self.inner.to_le_bytes();
        self.inner += 1;
        out
    }
}

pub struct SendCipher {
    nonce: CounterNonce,
    inner: ChaCha20Poly1305,
}

impl SendCipher {
    fn new(mut rng: impl CryptoRngCore) -> Self {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key[..]);
        Self {
            nonce: CounterNonce::new(),
            inner: ChaCha20Poly1305::new(&key.into()),
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Vec<u8> {
        self.inner
            .encrypt((&self.nonce.inc()[..12]).into(), data)
            .unwrap()
    }
}

pub struct RecvCipher {
    nonce: CounterNonce,
    inner: ChaCha20Poly1305,
}

impl RecvCipher {
    fn new(mut rng: impl CryptoRngCore) -> Self {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key[..]);
        Self {
            nonce: CounterNonce::new(),
            inner: ChaCha20Poly1305::new(&key.into()),
        }
    }

    pub fn recv(&mut self, encrypted_data: &[u8]) -> Vec<u8> {
        self.inner
            .decrypt((&self.nonce.inc()[..12]).into(), encrypted_data)
            .unwrap()
    }
}

pub struct Context<S, P> {
    current_time: u64,
    my_identity: S,
    peer_identity: P,
}

impl<S, P> Context<S, P> {
    pub fn new(current_time_ms: u64, my_identity: S, peer_identity: P) -> Self {
        Self {
            current_time: current_time_ms,
            my_identity,
            peer_identity,
        }
    }
}

pub fn dial_start<S: Signer, P: PublicKey>(
    rng: impl CryptoRngCore,
    ctx: Context<S, P>,
) -> (DialState<P>, Msg1<<S as Signer>::Signature>) {
    let Context {
        current_time,
        my_identity,
        peer_identity,
    } = ctx;
    let esk = x25519_dalek::EphemeralSecret::random_from_rng(rng);
    let epk = x25519_dalek::PublicKey::from(&esk);
    let mut transcript = Transcript::new(NAMESPACE);
    let sig = transcript
        .commit(peer_identity.encode())
        .commit(current_time.encode())
        .commit(epk.as_bytes().as_slice())
        .sign(&my_identity);
    transcript.commit(my_identity.public_key().encode());
    (
        DialState {
            esk,
            peer_identity,
            transcript,
        },
        Msg1 {
            time_ms: current_time,
            epk,
            sig,
        },
    )
}

pub fn dial_end<P: PublicKey>(
    state: DialState<P>,
    msg: Msg2<<P as Verifier>::Signature>,
) -> Result<(Msg3, SendCipher, RecvCipher), ()> {
    let DialState {
        esk,
        peer_identity,
        mut transcript,
    } = state;
    if !transcript
        .commit(msg.time_ms.encode())
        .commit(msg.epk.as_bytes().as_slice())
        .verify(&peer_identity, &msg.sig)
    {
        return Err(());
    }
    let secret = esk.diffie_hellman(&msg.epk);
    if !secret.was_contributory() {
        return Err(());
    }
    transcript.commit(secret.as_bytes().as_slice());
    let recv = RecvCipher::new(transcript.noise(b"cipher_l2d"));
    let send = SendCipher::new(transcript.noise(b"cipher_d2l"));
    let confirmation_l2d = transcript.fork(b"confirmation_l2d").summarize();
    let confirmation_d2l = transcript.fork(b"confirmation_d2l").summarize();
    if msg.confirmation != confirmation_l2d {
        return Err(());
    }

    Ok((
        Msg3 {
            confirmation: confirmation_d2l,
        },
        send,
        recv,
    ))
}

pub fn listen_start<S: Signer, P: PublicKey>(
    rng: &mut impl CryptoRngCore,
    ctx: Context<S, P>,
    msg: Msg1<<P as Verifier>::Signature>,
) -> Result<(ListenState, Msg2<<S as Signer>::Signature>), ()> {
    let Context {
        current_time,
        my_identity,
        peer_identity,
    } = ctx;
    let mut transcript = Transcript::new(NAMESPACE);
    if !transcript
        .commit(msg.time_ms.encode())
        .commit(my_identity.public_key().encode())
        .commit(msg.epk.as_bytes().as_slice())
        .verify(&peer_identity, &msg.sig)
    {
        return Err(());
    }
    let esk = x25519_dalek::EphemeralSecret::random_from_rng(rng);
    let epk = x25519_dalek::PublicKey::from(&esk);
    let sig = transcript
        .commit(peer_identity.encode())
        .commit(current_time.encode())
        .commit(epk.as_bytes().as_slice())
        .sign(&my_identity);
    let secret = esk.diffie_hellman(&msg.epk);
    if !secret.was_contributory() {
        return Err(());
    }
    transcript.commit(secret.as_bytes().as_slice());
    let send = SendCipher::new(transcript.noise(b"cipher_l2d"));
    let recv = RecvCipher::new(transcript.noise(b"cipher_d2l"));
    let confirmation_l2d = transcript.fork(b"confirmation_l2d").summarize();
    let confirmation_d2l = transcript.fork(b"confirmation_d2l").summarize();

    Ok((
        ListenState {
            confirmation: confirmation_d2l,
            send,
            recv,
        },
        Msg2 {
            time_ms: current_time,
            epk,
            sig,
            confirmation: confirmation_l2d,
        },
    ))
}

pub fn listen_end(state: ListenState, msg: Msg3) -> Result<(SendCipher, RecvCipher), ()> {
    if msg.confirmation != state.confirmation {
        return Err(());
    }
    Ok((state.send, state.recv))
}
