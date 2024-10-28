pub type Hash = Bytes; // use fixed size bytes

/// Digest is provided by the application for hashing.
///
/// In practice, the hasher is not bundled with the application so that
/// it can be cheaply copied for concurrent hashing.
///
/// This is configurable because some hash functions are better suited for
/// SNARK/STARK proofs than others.
pub trait Digest: Clone + Send + 'static {
    /// Append the digest to the recorded data.
    fn update(&mut self, digest: &[u8]);

    /// Hash all recorded data and reset
    /// the hasher to the initial state.
    fn finalize(&mut self) -> Hash;

    /// Reset the hasher without generating a hash.
    ///
    /// This is not required to call before calling `record`.
    fn reset(&mut self);

    /// Validate the hash.
    fn validate(hash: &Hash) -> bool;

    /// Size of the hash in bytes.
    fn size() -> usize;
}
