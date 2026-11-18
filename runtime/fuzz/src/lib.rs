//! Shared input decoding and storage models for the runtime fuzz targets.

pub mod storage_faults;
// `BlobModel::len` is the view length; the model has no emptiness query.
#[allow(clippy::len_without_is_empty)]
pub mod storage_model;

use arbitrary::{Result, Unstructured};
use commonware_utils::{Entropy, FuzzRng};
use rand::Rng as _;

/// Input bytes that seed the [`FuzzRng`] stream.
pub const SEED_BYTES: usize = 8;

/// Length of the stream operations are sampled from, entropy included.
pub const STREAM_BYTES: usize = 1 << 12;

/// Stream bytes reserved for the deterministic runtime's [`Entropy`].
pub const ENTROPY_BYTES: usize = 32;

/// Decode the input into the stream operations are sampled from and the deterministic runtime's
/// [`Entropy`].
///
/// libFuzzer starts from inputs of a few bytes and lengthens them slowly. The input's head
/// therefore seeds a [`STREAM_BYTES`] stream of [`FuzzRng`] output that the rest of the input
/// overwrites from its start, so every input, even an empty one, samples a whole operation
/// sequence, and a byte mutated past the head changes only what is sampled from it. Input past
/// the stream is ignored, so the entropy always comes from the same stream bytes.
pub fn decode(u: &mut Unstructured<'_>) -> Result<(Vec<u8>, Entropy)> {
    let seed = u.bytes(u.len().min(SEED_BYTES))?.to_vec();
    let mut stream = vec![0; STREAM_BYTES];
    FuzzRng::new(seed).fill_bytes(&mut stream);
    let literal = u.bytes(u.len())?;
    let literal = &literal[..literal.len().min(STREAM_BYTES)];
    stream[..literal.len()].copy_from_slice(literal);
    let entropy = Unstructured::new(&stream[STREAM_BYTES - ENTROPY_BYTES..]).arbitrary()?;
    stream.truncate(STREAM_BYTES - ENTROPY_BYTES);
    Ok((stream, entropy))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(input: &[u8]) -> (Vec<u8>, u64) {
        let (stream, entropy) = decode(&mut Unstructured::new(input)).unwrap();
        (stream, FuzzRng::from(entropy).next_u64())
    }

    #[test]
    fn test_stream_has_fixed_length() {
        for len in [
            0,
            4,
            SEED_BYTES + STREAM_BYTES - 1,
            SEED_BYTES + STREAM_BYTES,
            SEED_BYTES + STREAM_BYTES + 1,
            4 * STREAM_BYTES,
        ] {
            let (stream, _) = decoded(&vec![7; len]);
            assert_eq!(
                stream.len(),
                STREAM_BYTES - ENTROPY_BYTES,
                "input length {len}"
            );
        }
    }

    #[test]
    fn test_input_past_stream_is_ignored() {
        let input: Vec<u8> = (0..SEED_BYTES + STREAM_BYTES).map(|i| i as u8).collect();
        let mut longer = input.clone();
        longer.extend_from_slice(&[0xaa; 100]);
        assert_eq!(decoded(&input), decoded(&longer));
    }

    #[test]
    fn test_literal_overwrites_stream_start() {
        let input: Vec<u8> = (0..SEED_BYTES + 16).map(|i| i as u8 + 1).collect();
        let (stream, _) = decoded(&input);
        assert_eq!(&stream[..16], &input[SEED_BYTES..]);
    }
}
