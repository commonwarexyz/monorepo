//! Utilities for random number generation.

use rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng};

/// Returns a seeded RNG for deterministic testing.
///
/// Uses seed 0 by default to ensure reproducible test results.
pub fn test_rng() -> StdRng {
    StdRng::seed_from_u64(0)
}

/// Returns a seeded RNG with a custom seed for deterministic testing.
///
/// Use this when you need multiple independent RNG streams in the same test,
/// or when a helper function needs its own RNG that won't collide with the caller's.
pub fn test_rng_seeded(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// Domain-separation constant for the mixing step. This ensures the mixed stream
/// is not derived from `word ^ ctr` alone and helps avoid accidental fixed points
/// when fuzz input has low structure (for example empty or repeated bytes).
const FUZZ_RNG_MIX_DOMAIN: u64 = 0x9e3779b97f4a7c15;
/// Width of each source window in bytes.
///
/// This is derived from `u64` so the loaded window maps directly to one output
/// block before mixing.
const BLOCK_BYTES: usize = (u64::BITS as usize) / (u8::BITS as usize);

/// An RNG that expands a fuzzer byte slice into an infinite deterministic stream.
///
/// # Design
///
/// `FuzzRng` maps a fuzzer-controlled byte slice to output blocks.
///
/// For each block counter `ctr`, it:
/// 1. Reads a wrapping `u64`-wide window from the input bytes.
/// 2. Xors in `ctr` and a domain constant.
/// 3. Applies a SplitMix64-style finalizer.
///
/// ```text
/// input bytes (len = N):
///   [b0 b1 b2 ... b(N-1)]
///
/// block ctr = i:
///   word_i bytes = [b(i+0)%N, b(i+1)%N, ... b(i+7)%N]
///   word_i       = little-endian u64 of those bytes
///   out_i        = mix64(word_i ^ i ^ DOMAIN)
/// ```
///
/// # Why this mapping
///
/// Hashing the full input once and then seeding a PRNG makes tiny input changes
/// look globally unrelated. This adapter avoids that by using a sliding window
/// keyed by the block counter.
///
/// ```text
/// byte k affects anchors:
///   i in [k-(BLOCK_BYTES-1), ..., k] (mod N)
/// ```
///
/// # Worked Example
///
/// With `N = 4`, input bytes repeat inside each block:
///
/// ```text
/// input: [a b c d]
///
/// ctr=0: word bytes [a b c d a b c d]
/// ctr=1: word bytes [b c d a b c d a]
/// ctr=2: word bytes [c d a b c d a b]
/// ...
/// ```
///
/// Even for low-entropy input like `[0 0 0 0]`, output still changes because
/// `ctr` is mixed into every block before finalization.
///
/// `fill_bytes` serves output from cached block bytes so callers get a stable
/// byte stream regardless of whether they request randomness as `next_u64`,
/// `next_u32`, or arbitrary byte slices.
pub struct FuzzRng {
    bytes: Vec<u8>,
    ctr: u64,
    cache: [u8; BLOCK_BYTES],
    cache_pos: usize,
}

impl FuzzRng {
    /// Creates a new `FuzzRng` from a byte buffer.
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            ctr: 0,
            cache: [0u8; BLOCK_BYTES],
            cache_pos: BLOCK_BYTES,
        }
    }

    /// Generates the next mixed `u64` block from the fuzz input.
    ///
    /// Conceptually:
    /// 1. Build `word` from a wrapping `BLOCK_BYTES` window anchored at `ctr`.
    /// 2. Compute `mixed = mix64(word ^ ctr ^ FUZZ_RNG_MIX_DOMAIN)`.
    /// 3. Increment `ctr`.
    ///
    /// This keeps the output deterministic while preserving local mutation
    /// influence: one input-byte mutation only affects nearby anchor counters.
    #[inline]
    fn next_block_u64(&mut self) -> u64 {
        // Build a wrapping u64-width source word anchored at this block counter.
        // A single fuzz-byte mutation only impacts nearby anchors.
        let mut bytes = [0u8; BLOCK_BYTES];
        if !self.bytes.is_empty() {
            let len = self.bytes.len() as u64;
            for (i, byte) in bytes.iter_mut().enumerate().take(BLOCK_BYTES) {
                *byte = self.bytes[(self.ctr.wrapping_add(i as u64) % len) as usize];
            }
        }
        let word = u64::from_le_bytes(bytes);

        // Mix the structured word into a high-quality output block without
        // hashing the entire seed into an avalanche-style global state.
        let mut out = word ^ self.ctr ^ FUZZ_RNG_MIX_DOMAIN;
        out ^= out >> 30;
        out = out.wrapping_mul(0xbf58476d1ce4e5b9);
        out ^= out >> 27;
        out = out.wrapping_mul(0x94d049bb133111eb);
        out ^= out >> 31;

        self.ctr = self.ctr.wrapping_add(1);
        out
    }
}

impl RngCore for FuzzRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; BLOCK_BYTES];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut written = 0;
        while written < dest.len() {
            if self.cache_pos == self.cache.len() {
                // Cache block bytes so outputs are stable regardless of whether
                // callers pull randomness as bytes or words:
                //
                // next_u64() stream bytes == fill_bytes() stream bytes.
                self.cache = self.next_block_u64().to_le_bytes();
                self.cache_pos = 0;
            }

            let available = self.cache.len() - self.cache_pos;
            let need = dest.len() - written;
            let take = available.min(need);
            dest[written..written + take]
                .copy_from_slice(&self.cache[self.cache_pos..self.cache_pos + take]);
            self.cache_pos += take;
            written += take;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FuzzRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_bytes_not_constant() {
        let mut rng = FuzzRng::new(vec![]);

        let values: Vec<_> = (0..BLOCK_BYTES).map(|_| rng.next_u64()).collect();
        assert!(values.windows(2).any(|w| w[0] != w[1]));
    }

    #[test]
    fn test_empty_bytes_deterministic() {
        let mut rng1 = FuzzRng::new(vec![]);
        let mut rng2 = FuzzRng::new(vec![]);

        for _ in 0..256 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn test_all_zero_bytes_not_constant() {
        let bytes = vec![0; BLOCK_BYTES];
        let mut rng = FuzzRng::new(bytes);
        let values: Vec<_> = (0..BLOCK_BYTES).map(|_| rng.next_u64()).collect();
        assert!(values.windows(2).any(|w| w[0] != w[1]));
    }

    #[test]
    fn test_deterministic_with_same_input() {
        let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let mut rng1 = FuzzRng::new(bytes.clone());
        let mut rng2 = FuzzRng::new(bytes);

        for _ in 0..1000 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn test_short_input_wraparound() {
        for len in 1..=3 {
            let bytes = vec![0xAB; len];
            let mut rng1 = FuzzRng::new(bytes.clone());
            let mut rng2 = FuzzRng::new(bytes);
            let out1: Vec<_> = (0..32).map(|_| rng1.next_u64()).collect();
            let out2: Vec<_> = (0..32).map(|_| rng2.next_u64()).collect();
            assert_eq!(out1, out2);
            assert!(out1.windows(2).any(|w| w[0] != w[1]));
        }
    }

    #[test]
    fn test_small_mutation_locality() {
        let mut base = vec![0u8; 64];
        for (i, byte) in base.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let mut mutated = base.clone();
        let mutated_pos = 20usize;
        mutated[mutated_pos] ^= 0x01;

        let mut rng_a = FuzzRng::new(base);
        let mut rng_b = FuzzRng::new(mutated);

        let draws = 40usize;
        let mut diff_indices = Vec::new();
        for i in 0..draws {
            if rng_a.next_u64() != rng_b.next_u64() {
                diff_indices.push(i);
            }
        }

        let expected: Vec<usize> = ((mutated_pos - 7)..=mutated_pos).collect();
        assert_eq!(diff_indices, expected);
    }

    #[test]
    fn test_small_mutation_locality_wraparound() {
        let mut base = vec![0u8; 64];
        for (i, byte) in base.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let mut mutated = base.clone();
        let mutated_pos = 2usize;
        mutated[mutated_pos] ^= 0x01;

        let mut rng_a = FuzzRng::new(base);
        let mut rng_b = FuzzRng::new(mutated);

        let draws = 64usize;
        let mut diff_indices = Vec::new();
        for i in 0..draws {
            if rng_a.next_u64() != rng_b.next_u64() {
                diff_indices.push(i);
            }
        }

        assert_eq!(diff_indices, vec![0, 1, 2, 59, 60, 61, 62, 63]);
    }

    #[test]
    fn test_fill_bytes_shape_stability() {
        let bytes: Vec<u8> = (0..32u8).collect();

        let mut from_u64_rng = FuzzRng::new(bytes.clone());
        let mut from_u64 = Vec::with_capacity(128);
        for _ in 0..16 {
            from_u64.extend_from_slice(&from_u64_rng.next_u64().to_le_bytes());
        }

        let mut from_fill_rng = FuzzRng::new(bytes);
        let mut from_fill = vec![0u8; from_u64.len()];
        let chunk_sizes = [3usize, 1, 7, 2, 11, 5, 13, 17];
        let mut offset = 0;
        let mut idx = 0;
        while offset < from_fill.len() {
            let chunk = chunk_sizes[idx % chunk_sizes.len()].min(from_fill.len() - offset);
            from_fill_rng.fill_bytes(&mut from_fill[offset..offset + chunk]);
            offset += chunk;
            idx += 1;
        }
        assert_eq!(from_u64, from_fill);
    }

    #[test]
    fn test_next_u32_consistency_with_fill_bytes() {
        let bytes: Vec<u8> = (0..16u8).collect();

        let mut from_u32_rng = FuzzRng::new(bytes.clone());
        let mut from_u32 = Vec::with_capacity(64);
        for _ in 0..16 {
            from_u32.extend_from_slice(&from_u32_rng.next_u32().to_le_bytes());
        }

        let mut from_fill_rng = FuzzRng::new(bytes);
        let mut from_fill = vec![0u8; from_u32.len()];
        from_fill_rng.fill_bytes(&mut from_fill);
        assert_eq!(from_u32, from_fill);
    }

    #[test]
    fn test_try_fill_bytes_consistency_with_fill_bytes() {
        let bytes: Vec<u8> = (0..16u8).collect();

        let mut fill_rng = FuzzRng::new(bytes.clone());
        let mut try_fill_rng = FuzzRng::new(bytes);

        let mut fill_out = vec![0u8; 257];
        fill_rng.fill_bytes(&mut fill_out);

        let mut try_out = vec![0u8; 257];
        try_fill_rng
            .try_fill_bytes(&mut try_out)
            .expect("try_fill_bytes should never fail");

        assert_eq!(fill_out, try_out);
    }

    #[test]
    fn test_next_u64_includes_counter_in_mix_input() {
        // Use a constant source window so any change between blocks comes from
        // counter mixing, not from different window bytes.
        let bytes = vec![0xAA; BLOCK_BYTES];
        let mut rng = FuzzRng::new(bytes.clone());

        let mut source = [0u8; BLOCK_BYTES];
        source.copy_from_slice(&bytes[..BLOCK_BYTES]);
        let word = u64::from_le_bytes(source);

        let mix = |mut x: u64| {
            x ^= x >> 30;
            x = x.wrapping_mul(0xbf58476d1ce4e5b9);
            x ^= x >> 27;
            x = x.wrapping_mul(0x94d049bb133111eb);
            x ^= x >> 31;
            x
        };

        #[allow(clippy::identity_op)]
        let expected0 = mix(word ^ 0 ^ FUZZ_RNG_MIX_DOMAIN);
        let expected1 = mix(word ^ 1 ^ FUZZ_RNG_MIX_DOMAIN);

        assert_eq!(rng.next_u64(), expected0);
        assert_eq!(rng.next_u64(), expected1);
    }

    mod conformance {
        use super::*;
        use commonware_conformance::Conformance;

        /// Conformance wrapper for FuzzRng that tests output stability.
        ///
        /// This ensures that counter-mixed expansion behavior
        /// remains stable across versions.
        struct FuzzRngConformance;

        impl Conformance for FuzzRngConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let mut rng = FuzzRng::new(seed.to_be_bytes().to_vec());
                const CONFORMANCE_BLOCKS: usize = 32;

                // Generate enough output to exercise wrapping and mixing.
                let mut output = Vec::with_capacity(CONFORMANCE_BLOCKS * BLOCK_BYTES);
                for _ in 0..CONFORMANCE_BLOCKS {
                    output.extend_from_slice(&rng.next_u64().to_le_bytes());
                }
                output
            }
        }

        commonware_conformance::conformance_tests! {
            FuzzRngConformance => 1024,
        }
    }
}
