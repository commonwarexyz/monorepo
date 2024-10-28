pub type Digest = Bytes;

/// Hasher is provided by the application for hashing.
///
/// In practice, the hasher is not bundled with the application so that
/// it can be cheaply copied for concurrent hashing.
///
/// This is configurable because some hash functions are better suited for
/// SNARK/STARK proofs than others.
pub trait Hasher: Clone + Send + 'static {
    /// Append the message to the recorded data.
    fn update(&mut self, message: &[u8]);

    /// Hash all recorded data and reset
    /// the hasher to the initial state.
    fn finalize(&mut self) -> Digest;

    /// Reset the hasher without generating a hash.
    ///
    /// This is not required to call before calling `record`.
    fn reset(&mut self);

    /// Validate the hash.
    fn validate(digest: &Digest) -> bool;

    /// Size of the hash in bytes.
    fn size() -> usize;
}
