use chacha20poly1305::{aead::AeadMut as _, ChaCha20Poly1305, KeyInit as _};
use rand_core::CryptoRngCore;

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
    pub fn new(mut rng: impl CryptoRngCore) -> Self {
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
    pub fn new(mut rng: impl CryptoRngCore) -> Self {
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
