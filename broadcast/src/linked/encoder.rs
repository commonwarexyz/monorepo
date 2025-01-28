use super::wire;
use bytes::BufMut;
use commonware_utils::union;

pub const ACK_SUFFIX: &[u8] = b"_ACK";
pub const CAR_SUFFIX: &[u8] = b"_CAR";

/// Serialize an ack into a byte array deterministically.
///
/// If `with_signature` is true, the signature is included in the serialization.
pub fn serialize_ack(ack: &wire::Ack, with_signature: bool) -> Vec<u8> {
    // Initialize the length of the serialized ack
    let mut len = ack.sequencer.len() + 8 + ack.chunk_digest.len() + 8;
    if with_signature {
        len += ack.partial.len();
    }
    let mut result = Vec::with_capacity(len);

    // Serialize the ack
    result.extend_from_slice(&ack.sequencer);
    result.put_u64(ack.height);
    result.extend_from_slice(&ack.chunk_digest);
    result.put_u64(ack.epoch);
    if with_signature {
        result.extend_from_slice(&ack.partial);
    }
    result
}

/// Serialize a chunk into a byte array deterministically.
///
/// If `with_signature` is true, the signature is included in the serialization.
pub fn serialize_chunk(chunk: &wire::Chunk, with_signature: bool) -> Vec<u8> {
    // Initialize the length of the serialized chunk
    let mut len = chunk.sequencer.len() + 8 + 8 + chunk.payload_digest.len();
    if let Some(parent) = &chunk.parent {
        len += parent.chunk_digest.len() + parent.threshold.len();
    }
    if with_signature {
        len += chunk.signature.len();
    }
    let mut result = Vec::with_capacity(len);

    // Serialize the chunk
    result.extend_from_slice(&chunk.sequencer);
    result.put_u64(chunk.height);
    result.extend_from_slice(&chunk.payload_digest);
    if let Some(parent) = &chunk.parent {
        result.extend_from_slice(&parent.chunk_digest);
        result.extend_from_slice(&parent.threshold);
    }
    if with_signature {
        result.extend_from_slice(&chunk.signature);
    }
    result
}

pub fn ack_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, ACK_SUFFIX)
}

pub fn chunk_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, CAR_SUFFIX)
}
