use bytes::BufMut;

use super::{wire, Epoch};

/// Serializes an Ack message into a byte array.
pub fn ack(chunk: &wire::Chunk, epoch: Epoch) -> Vec<u8> {
    let len = chunk.sequencer.len() + 8 + chunk.payload_digest.len() + 8;
    let mut buf = Vec::with_capacity(len);

    buf.put(chunk.sequencer.clone());
    buf.put_u64(chunk.height);
    buf.put(chunk.payload_digest.clone());
    buf.put_u64(epoch);
    buf
}

/// Serializes a Chunk message into a byte array.
pub fn chunk(chunk: &wire::Chunk) -> Vec<u8> {
    let len = chunk.sequencer.len() + 8 + chunk.payload_digest.len();
    let mut buf = Vec::with_capacity(len);

    buf.put(chunk.sequencer.clone());
    buf.put_u64(chunk.height);
    buf.put(chunk.payload_digest.clone());
    buf
}
