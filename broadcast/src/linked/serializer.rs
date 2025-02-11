use super::{safe, Epoch};
use bytes::BufMut;
use commonware_cryptography::Array;

/// Serializes an Ack message into a byte array.
pub fn ack<D: Array, P: Array>(chunk: &safe::Chunk<D, P>, epoch: Epoch) -> Vec<u8> {
    let len = chunk.sequencer.len() + size_of::<u64>() + chunk.payload.len() + size_of::<u64>();
    let mut buf = Vec::with_capacity(len);

    buf.put_slice(&chunk.sequencer);
    buf.put_u64(chunk.height);
    buf.put_slice(&chunk.payload);
    buf.put_u64(epoch);
    buf
}

/// Serializes a Chunk message into a byte array.
pub fn chunk<D: Array, P: Array>(chunk: &safe::Chunk<D, P>) -> Vec<u8> {
    let len = chunk.sequencer.len() + size_of::<u64>() + chunk.payload.len();
    let mut buf = Vec::with_capacity(len);

    buf.put_slice(&chunk.sequencer);
    buf.put_u64(chunk.height);
    buf.put_slice(&chunk.payload);
    buf
}
