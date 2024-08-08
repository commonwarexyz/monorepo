//! TODO

use bytes::Bytes;

pub mod ed25519;

pub type PublicKey = Bytes;
pub type Signature = Bytes;

pub trait Crypto: Send + Sync + Clone + 'static {
    fn me(&self) -> PublicKey;
    fn sign(&mut self, data: Vec<u8>) -> Signature;

    fn validate(public_key: &PublicKey) -> bool;
    fn verify(data: Vec<u8>, public_key: &PublicKey, signature: &Signature) -> bool;
}
