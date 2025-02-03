use commonware_utils::union;

const CHUNK_SUFFIX: &[u8] = b"_CHUNK";
const ACK_SUFFIX: &[u8] = b"_ACK";

/// Returns a suffixed namespace for signing a chunk.
pub fn chunk_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, CHUNK_SUFFIX)
}

/// Returns a suffixed namespace for signing an ack.
pub fn ack_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, ACK_SUFFIX)
}
