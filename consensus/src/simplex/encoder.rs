use super::View;
use bytes::{BufMut, Bytes};
use commonware_cryptography::Hasher;
use commonware_utils::union;

pub const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
pub const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
pub const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

pub fn proposal_message<H: Hasher>(view: View, parent: View, payload: &H::Digest) -> Bytes {
    let mut msg = Vec::with_capacity(8 + 8 + H::DIGEST_LENGTH);
    msg.put_u64(view);
    msg.put_u64(parent);
    msg.extend_from_slice(payload.as_ref());
    msg.into()
}

pub fn nullify_message(nullify: View) -> Bytes {
    nullify.to_be_bytes().to_vec().into()
}

pub fn notarize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NOTARIZE_SUFFIX)
}

pub fn nullify_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NULLIFY_SUFFIX)
}

pub fn finalize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, FINALIZE_SUFFIX)
}
