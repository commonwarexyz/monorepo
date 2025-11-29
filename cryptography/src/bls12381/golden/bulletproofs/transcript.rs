//! Fiat-Shamir transcript for Bulletproofs.
//!
//! Provides a domain-separated transcript for generating challenges
//! in non-interactive zero-knowledge proofs.

use crate::bls12381::primitives::group::{Scalar, G1};
use crate::Hasher;
use commonware_codec::Encode;

/// Domain separation tags for different transcript operations.
const DST_BULLETPROOFS: &[u8] = b"GOLDEN_BULLETPROOFS_V1";
const DST_CHALLENGE: &[u8] = b"challenge";
const DST_POINT: &[u8] = b"point";
const DST_SCALAR: &[u8] = b"scalar";
const DST_BYTES: &[u8] = b"bytes";

/// A Fiat-Shamir transcript for generating deterministic challenges.
///
/// The transcript accumulates all public data and generates
/// challenges that depend on the entire history.
#[derive(Clone)]
pub struct Transcript {
    /// The running hash state (we use repeated hashing for simplicity).
    state: Vec<u8>,
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new(b"default")
    }
}

impl Transcript {
    /// Creates a new transcript with the given domain separator.
    pub fn new(domain: &[u8]) -> Self {
        let mut state = Vec::new();
        state.extend_from_slice(DST_BULLETPROOFS);
        state.extend_from_slice(&(domain.len() as u32).to_le_bytes());
        state.extend_from_slice(domain);
        Self { state }
    }

    /// Appends a point to the transcript.
    pub fn append_point(&mut self, label: &[u8], point: &G1) {
        self.state.extend_from_slice(DST_POINT);
        self.state.extend_from_slice(&(label.len() as u32).to_le_bytes());
        self.state.extend_from_slice(label);
        self.state.extend_from_slice(&point.encode());
    }

    /// Appends a scalar to the transcript.
    pub fn append_scalar(&mut self, label: &[u8], scalar: &Scalar) {
        self.state.extend_from_slice(DST_SCALAR);
        self.state.extend_from_slice(&(label.len() as u32).to_le_bytes());
        self.state.extend_from_slice(label);
        self.state.extend_from_slice(&scalar.encode());
    }

    /// Appends arbitrary bytes to the transcript.
    pub fn append_bytes(&mut self, label: &[u8], data: &[u8]) {
        self.state.extend_from_slice(DST_BYTES);
        self.state.extend_from_slice(&(label.len() as u32).to_le_bytes());
        self.state.extend_from_slice(label);
        self.state.extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.state.extend_from_slice(data);
    }

    /// Appends a u64 to the transcript.
    pub fn append_u64(&mut self, label: &[u8], value: u64) {
        self.append_bytes(label, &value.to_le_bytes());
    }

    /// Generates a challenge scalar from the current transcript state.
    pub fn challenge_scalar(&mut self, label: &[u8]) -> Scalar {
        self.state.extend_from_slice(DST_CHALLENGE);
        self.state.extend_from_slice(&(label.len() as u32).to_le_bytes());
        self.state.extend_from_slice(label);

        // Hash the state to get a challenge
        let mut hasher = crate::Sha256::new();
        hasher.update(&self.state);
        let digest = hasher.finalize();

        // Map to scalar using domain separation
        Scalar::map(b"BULLETPROOFS_CHALLENGE", digest.as_ref())
    }

    /// Generates multiple challenge scalars.
    pub fn challenge_scalars(&mut self, label: &[u8], count: usize) -> Vec<Scalar> {
        let mut challenges = Vec::with_capacity(count);
        for i in 0..count {
            let mut extended_label = label.to_vec();
            extended_label.extend_from_slice(&(i as u32).to_le_bytes());
            challenges.push(self.challenge_scalar(&extended_label));
        }
        challenges
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::group::Element;

    #[test]
    fn test_transcript_determinism() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");

        let point = G1::one();
        t1.append_point(b"P", &point);
        t2.append_point(b"P", &point);

        let c1 = t1.challenge_scalar(b"c");
        let c2 = t2.challenge_scalar(b"c");

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_transcript_different_domains() {
        let mut t1 = Transcript::new(b"domain1");
        let mut t2 = Transcript::new(b"domain2");

        let c1 = t1.challenge_scalar(b"c");
        let c2 = t2.challenge_scalar(b"c");

        assert_ne!(c1, c2);
    }
}
