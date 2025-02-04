use super::{wire, Epoch};
use bytes::BufMut;

/// Serializes an Ack message into a byte array.
pub fn ack(chunk: &wire::Chunk, epoch: Epoch) -> Vec<u8> {
    let len = chunk.sequencer.len() + size_of::<u64>() + chunk.payload.len() + size_of::<u64>();
    let mut buf = Vec::with_capacity(len);

    buf.put(chunk.sequencer.clone());
    buf.put_u64(chunk.height);
    buf.put_slice(&chunk.payload);
    buf.put_u64(epoch);
    buf
}

/// Serializes a Chunk message into a byte array.
pub fn chunk(chunk: &wire::Chunk) -> Vec<u8> {
    let len = chunk.sequencer.len() + size_of::<u64>() + chunk.payload.len();
    let mut buf = Vec::with_capacity(len);

    buf.put(chunk.sequencer.clone());
    buf.put_u64(chunk.height);
    buf.put_slice(&chunk.payload);
    buf
}
