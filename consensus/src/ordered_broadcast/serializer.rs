//! Serializes and deserializes messages.

use super::{parsed, Epoch};
use bytes::BufMut;
use commonware_codec::FixedSize;
use commonware_cryptography::Digest;
use commonware_utils::Array;

/// Serializes an Ack message into a byte array.
pub fn ack<D: Digest, P: Array>(chunk: &parsed::Chunk<D, P>, epoch: Epoch) -> Vec<u8> {
    let len = P::SIZE + u64::SIZE + D::SIZE + u64::SIZE;
    let mut buf = Vec::with_capacity(len);

    buf.put_slice(&chunk.sequencer);
    buf.put_u64(chunk.height);
    buf.put_slice(&chunk.payload);
    buf.put_u64(epoch);

    assert!(buf.len() == len);
    buf
}

/// Serializes a Chunk message into a byte array.
pub fn chunk<D: Digest, P: Array>(chunk: &parsed::Chunk<D, P>) -> Vec<u8> {
    let len = P::SIZE + u64::SIZE + D::SIZE;
    let mut buf = Vec::with_capacity(len);

    buf.put_slice(&chunk.sequencer);
    buf.put_u64(chunk.height);
    buf.put_slice(&chunk.payload);

    assert!(buf.len() == len);
    buf
}
