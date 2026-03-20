//! Fiat-Shamir transcript implementations.
//!
//! Provides a SHA-256 transcript backend that implements the
//! [`Transcript`](crate::Transcript) trait. The transcript is the "thread"
//! that binds prover and verifier to the same randomness.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::field::BinaryFieldElement;
use sha2::{Digest, Sha256};

/// SHA-256-based Fiat-Shamir transcript.
///
/// Uses deterministic hash-based expansion for all random values.
/// This ensures identical behavior across native, WASM, and all platforms.
pub struct Sha256Transcript {
    hasher: Sha256,
    counter: u32,
    /// When true, absorb methods include type labels and length prefixes
    /// to prevent message boundary confusion. Enabled by default.
    domain_separated: bool,
}

impl Sha256Transcript {
    /// Create a new transcript seeded with the given value.
    pub fn new(seed: i32) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(seed.to_le_bytes());

        Self {
            hasher,
            counter: 0,
            domain_separated: true,
        }
    }

    /// Create a raw transcript without domain separation labels.
    ///
    /// Use this when you need plain SHA-256 absorbs without type tags or
    /// length prefixes (e.g. for third-party interop).
    pub fn new_raw(seed: i32) -> Self {
        let mut t = Self::new(seed);
        t.domain_separated = false;
        t
    }

    /// Squeeze deterministic bytes from the transcript.
    ///
    /// Uses pure SHA-256 expansion with no external RNG dependencies.
    fn squeeze_bytes(&mut self, count: usize) -> Vec<u8> {
        self.hasher.update(self.counter.to_le_bytes());
        self.counter += 1;

        let digest = self.hasher.clone().finalize();

        if count <= 32 {
            digest[..count].to_vec()
        } else {
            let mut result = Vec::with_capacity(count);
            result.extend_from_slice(&digest[..]);

            while result.len() < count {
                self.hasher.update(self.counter.to_le_bytes());
                self.counter += 1;
                let digest = self.hasher.clone().finalize();
                let needed = count - result.len();
                result.extend_from_slice(&digest[..needed.min(32)]);
            }

            result
        }
    }
}

impl crate::Transcript for Sha256Transcript {
    fn absorb_root(&mut self, root: &[u8]) {
        if self.domain_separated {
            self.hasher.update(b"merkle_root");
            self.hasher.update(&(root.len() as u64).to_le_bytes());
        }
        self.hasher.update(root);
    }

    fn absorb_elems<F: BinaryFieldElement>(&mut self, elems: &[F]) {
        // SAFETY: `BinaryFieldElement` types are plain data (integers) with no
        // padding or invariants beyond their bit pattern. Reinterpreting a
        // contiguous slice of such elements as `&[u8]` is safe because the
        // pointer is aligned (from the original slice) and the byte length
        // equals `size_of::<F>() * elems.len()`.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                elems.as_ptr() as *const u8,
                core::mem::size_of_val(elems),
            )
        };
        if self.domain_separated {
            self.hasher.update(b"field_elements");
            self.hasher.update(&(bytes.len() as u64).to_le_bytes());
        }
        self.hasher.update(bytes);
    }

    fn absorb_elem<F: BinaryFieldElement>(&mut self, elem: F) {
        // SAFETY: Same rationale as `absorb_elems` -- `F` is a plain-data
        // field element with no padding. We view its bytes for hashing.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &elem as *const F as *const u8,
                core::mem::size_of::<F>(),
            )
        };
        if self.domain_separated {
            self.hasher.update(b"field_element");
            self.hasher.update(&(bytes.len() as u64).to_le_bytes());
        }
        self.hasher.update(bytes);
    }

    fn absorb_bytes(&mut self, label: &[u8], data: &[u8]) {
        self.hasher.update(label);
        self.hasher.update(&(data.len() as u64).to_le_bytes());
        self.hasher.update(data);
    }

    fn challenge<F: BinaryFieldElement>(&mut self) -> F {
        let bytes = self.squeeze_bytes(core::mem::size_of::<F>());

        match core::mem::size_of::<F>() {
            2 => {
                let value = u16::from_le_bytes([bytes[0], bytes[1]]);
                F::from_bits(value as u64)
            }
            4 => {
                let value =
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                F::from_bits(value as u64)
            }
            16 => {
                let mut low_bytes = [0u8; 8];
                let mut high_bytes = [0u8; 8];
                low_bytes.copy_from_slice(&bytes[0..8]);
                high_bytes.copy_from_slice(&bytes[8..16]);

                let low = u64::from_le_bytes(low_bytes);
                let high = u64::from_le_bytes(high_bytes);

                let mut result = F::zero();

                // Set bits 0-63
                for i in 0..64 {
                    if (low >> i) & 1 == 1 {
                        let bit_value = F::from_bits(1u64 << i);
                        result = result.add(&bit_value);
                    }
                }

                // Set bits 64-127
                let mut power_of_2_64 = F::from_bits(1u64 << 63);
                power_of_2_64 = power_of_2_64.add(&power_of_2_64); // 2^64

                let mut current_power = power_of_2_64;
                for i in 0..64 {
                    if (high >> i) & 1 == 1 {
                        result = result.add(&current_power);
                    }
                    if i < 63 {
                        current_power = current_power.add(&current_power);
                    }
                }

                result
            }
            _ => {
                let mut result = F::zero();
                for (byte_idx, &byte) in bytes.iter().enumerate() {
                    for bit_idx in 0..8 {
                        if (byte >> bit_idx) & 1 == 1 {
                            let global_bit = byte_idx * 8 + bit_idx;
                            if global_bit < 64 {
                                result =
                                    result.add(&F::from_bits(1u64 << global_bit));
                            }
                        }
                    }
                }
                result
            }
        }
    }

    fn query(&mut self, max: usize) -> usize {
        let bytes = self.squeeze_bytes(8);
        let value = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
            bytes[7],
        ]);
        (value as usize) % max
    }

    fn distinct_queries(&mut self, max: usize, count: usize) -> Vec<usize> {
        let actual_count = count.min(max);
        let mut queries = Vec::with_capacity(actual_count);

        while queries.len() < actual_count {
            let q = self.query(max);
            if !queries.contains(&q) {
                queries.push(q);
            }
        }

        queries.sort_unstable();
        queries
    }
}
