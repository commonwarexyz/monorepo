//! Input decoding shared by the fuzz targets.

use arbitrary::Unstructured;
use commonware_utils::FuzzRng;
use rand::Rng as _;

/// Bytes of an input's head that seed its stream.
pub const SEED_BYTES: usize = 8;

/// Expand an input into a stream of at least `len` bytes to sample a session
/// from.
///
/// libFuzzer starts from inputs of a few bytes and lengthens them slowly, and a
/// session sampled from so few bytes would draw the minimum of every control.
/// The input's head therefore seeds a stream of [`FuzzRng`] output that the
/// rest of the input overwrites from its start, so every input, even an empty
/// one, samples a whole session, and a byte mutated past the head changes only
/// what is sampled from it.
pub fn stream(u: &mut Unstructured<'_>, len: usize) -> arbitrary::Result<Vec<u8>> {
    let seed = u.bytes(u.len().min(SEED_BYTES))?.to_vec();
    let mut stream = vec![0; len.max(u.len())];
    FuzzRng::new(seed).fill_bytes(&mut stream);
    let literal = u.bytes(u.len())?;
    stream[..literal.len()].copy_from_slice(literal);
    Ok(stream)
}
