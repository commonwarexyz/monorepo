//! Input decoding shared by the DKG fuzz targets.

use arbitrary::Unstructured;
use commonware_utils::FuzzRng;
use rand::Rng as _;

/// Bytes of an input's head that seed its stream.
pub const SEED_BYTES: usize = 8;

/// Expand an input into a stream of exactly `len` bytes to sample a session
/// from.
///
/// libFuzzer starts from inputs of a few bytes and lengthens them slowly, and a
/// session sampled from so few bytes would draw the minimum of every control.
/// The input's head, at most [`SEED_BYTES`] bytes, therefore seeds a stream of
/// [`FuzzRng`] output, and the input overwrites that stream from its start, at
/// the same offsets, so every input, even an empty one, samples a whole
/// session, and a byte mutated past the head changes only what is sampled from
/// it. Bytes of an input longer than the stream are not read.
pub fn stream(u: &mut Unstructured<'_>, len: usize) -> arbitrary::Result<Vec<u8>> {
    let input = u.bytes(u.len())?;
    let mut stream = vec![0; len];
    FuzzRng::new(input[..input.len().min(SEED_BYTES)].to_vec()).fill_bytes(&mut stream);
    let literal = input.len().min(len);
    stream[..literal].copy_from_slice(&input[..literal]);
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stream `input` expands into.
    fn expanded(input: &[u8], len: usize) -> Vec<u8> {
        stream(&mut Unstructured::new(input), len).expect("every input expands")
    }

    /// `len` bytes of the output of [`FuzzRng`] seeded with `seed`.
    fn seeded(seed: &[u8], len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        FuzzRng::new(seed.to_vec()).fill_bytes(&mut bytes);
        bytes
    }

    #[test]
    fn empty_input_is_the_stream_of_an_empty_seed() {
        for len in [1 << 10, 1 << 11] {
            assert_eq!(expanded(&[], len), seeded(&[], len));
        }
    }

    /// The head seeds the stream and the whole input overwrites it at the
    /// same offsets, the head included.
    #[test]
    fn short_input_overwrites_the_stream_its_head_seeds() {
        let input: Vec<u8> = (1..=9).collect();
        for len in [1 << 10, 1 << 11] {
            let stream = expanded(&input, len);
            assert_eq!(stream.len(), len);
            assert_eq!(stream[..9], input[..]);
            assert_eq!(stream[9..], seeded(&input[..SEED_BYTES], len)[9..]);
        }

        // An input no longer than the head seeds with all of itself.
        let stream = expanded(&input[..3], 1 << 10);
        assert_eq!(stream[..3], input[..3]);
        assert_eq!(stream[3..], seeded(&input[..3], 1 << 10)[3..]);
    }

    /// The stream has the length asked for, however long the input: an
    /// input longer than it is cut to it.
    #[test]
    fn long_input_is_cut_to_the_stream() {
        let input: Vec<u8> = (0..4_096u16).map(|at| (at % 251) as u8).collect();
        for len in [1 << 10, 1 << 11] {
            assert_eq!(expanded(&input, len), input[..len]);
        }
    }

    /// A byte past the head changes the stream at its own offset only.
    #[test]
    fn byte_past_the_head_changes_only_itself() {
        let mut input = vec![7u8; 40];
        let base = expanded(&input, 1 << 10);
        input[SEED_BYTES] ^= 0xff;
        let changed = expanded(&input, 1 << 10);
        let differ: Vec<usize> = (0..base.len())
            .filter(|at| base[*at] != changed[*at])
            .collect();
        assert_eq!(differ, vec![SEED_BYTES]);
    }
}
