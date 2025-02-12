use super::{parsed, Epoch};
use bytes::BufMut;
use commonware_cryptography::Array;
use commonware_utils::SizedSerialize;

/// Serializes an Ack message into a byte array.
pub fn ack<D: Array, P: Array>(chunk: &parsed::Chunk<D, P>, epoch: Epoch) -> Vec<u8> {
    let len = P::SERIALIZED_LEN + u64::SERIALIZED_LEN + D::SERIALIZED_LEN + u64::SERIALIZED_LEN;
    let mut buf = Vec::with_capacity(len);

    buf.put_slice(&chunk.sequencer);
    buf.put_u64(chunk.height);
    buf.put_slice(&chunk.payload);
    buf.put_u64(epoch);
    buf
}

/// Serializes a Chunk message into a byte array.
pub fn chunk<D: Array, P: Array>(chunk: &parsed::Chunk<D, P>) -> Vec<u8> {
    let len = P::SERIALIZED_LEN + u64::SERIALIZED_LEN + D::SERIALIZED_LEN;
    let mut buf = Vec::with_capacity(len);

    buf.put_slice(&chunk.sequencer);
    buf.put_u64(chunk.height);
    buf.put_slice(&chunk.payload);
    buf
}
