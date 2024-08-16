/// Concatenates the namespace and message into a single payload for signing.
pub fn payload(namespace: &[u8], message: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(namespace.len() + message.len());
    payload.extend_from_slice(namespace);
    payload.extend_from_slice(message);
    payload
}
