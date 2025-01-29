use bytes::BufMut;
use commonware_utils::union;

use super::{wire, Epoch};

pub const CHUNK_SUFFIX: &[u8] = b"_CHUNK";
pub const ACK_SUFFIX: &[u8] = b"_ACK";

pub fn serialize(chunk: &wire::Chunk, epoch: Option<Epoch>) -> Vec<u8> {
    let len = chunk.sequencer.len()
        + 8
        + chunk.payload_digest.len()
        + if epoch.is_some() { 8 } else { 0 };
    let mut buf = Vec::with_capacity(len);

    buf.put(chunk.sequencer.clone());
    buf.put_u64(chunk.height);
    buf.put(chunk.payload_digest.clone());
    if let Some(epoch) = epoch {
        buf.put_u64(epoch);
    }
    buf
}

pub fn chunk_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, CHUNK_SUFFIX)
}

pub fn ack_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, ACK_SUFFIX)
}
