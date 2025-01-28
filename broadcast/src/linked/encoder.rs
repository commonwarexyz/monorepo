use commonware_utils::union;

pub const CHUNK_SUFFIX: &[u8] = b"_CHUNK";
pub const ACK_SUFFIX: &[u8] = b"_ACK";

pub fn chunk_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, CHUNK_SUFFIX)
}

pub fn ack_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, ACK_SUFFIX)
}
