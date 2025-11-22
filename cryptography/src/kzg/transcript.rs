use super::KzgError;
use crate::bls12381::primitives::group::{G1, G2};
use bytes::Bytes;
use commonware_codec::ReadExt;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Powers of tau derived from the public Ethereum KZG ceremony transcript.
#[derive(Clone)]
pub struct TrustedSetup {
    g1_powers: Vec<G1>,
    g2_powers: Vec<G2>,
}

impl TrustedSetup {
    /// Loads the Ethereum KZG ceremony transcript bundled with this crate.
    ///
    /// The transcript bundles the Ethereum KZG monomial powers in compressed
    /// form (4,096 G1 powers and 65 G2 powers), supporting G1 commitments up to
    /// degree 4,095 and G2 commitments up to degree 64.
    pub fn ethereum_kzg() -> Result<Self, KzgError> {
        Self::from_bytes(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/trusted_setup.bin"
        )))
    }

    /// Returns the maximum supported polynomial degree for G1 commitments.
    pub fn max_degree_supported(&self) -> usize {
        self.g1_powers.len().saturating_sub(1)
    }

    /// Returns the G1 powers of tau.
    pub fn g1_powers(&self) -> &[G1] {
        &self.g1_powers
    }

    /// Returns the G2 powers of tau.
    pub fn g2_powers(&self) -> &[G2] {
        &self.g2_powers
    }

    fn from_bytes(mut raw: &[u8]) -> Result<Self, KzgError> {
        // Read G1 count
        if raw.len() < 4 {
            return Err(KzgError::InvalidSetup("truncated header"));
        }
        let g1_count = u32::from_be_bytes(raw[0..4].try_into().unwrap()) as usize;
        raw = &raw[4..];

        // Read G1 powers
        let mut g1_powers = Vec::with_capacity(g1_count);
        for _ in 0..g1_count {
            if raw.len() < 48 {
                return Err(KzgError::InvalidSetup("truncated g1 section"));
            }
            let (bytes, rest) = raw.split_at(48);
            raw = rest;
            g1_powers.push(parse_g1_bytes(bytes)?);
        }

        // Read G2 count
        if raw.len() < 4 {
            return Err(KzgError::InvalidSetup("truncated g2 header"));
        }
        let g2_count = u32::from_be_bytes(raw[0..4].try_into().unwrap()) as usize;
        raw = &raw[4..];

        // Read G2 powers
        let mut g2_powers = Vec::with_capacity(g2_count);
        for _ in 0..g2_count {
            if raw.len() < 96 {
                return Err(KzgError::InvalidSetup("truncated g2 section"));
            }
            let (bytes, rest) = raw.split_at(96);
            raw = rest;
            g2_powers.push(parse_g2_bytes(bytes)?);
        }

        Ok(Self {
            g1_powers,
            g2_powers,
        })
    }
}

fn parse_g1_bytes(bytes: &[u8]) -> Result<G1, KzgError> {
    let mut buf = Bytes::copy_from_slice(bytes);
    G1::read(&mut buf).map_err(|_| KzgError::InvalidSetup("invalid g1 point"))
}

fn parse_g2_bytes(bytes: &[u8]) -> Result<G2, KzgError> {
    let mut buf = Bytes::copy_from_slice(bytes);
    G2::read(&mut buf).map_err(|_| KzgError::InvalidSetup("invalid g2 point"))
}
