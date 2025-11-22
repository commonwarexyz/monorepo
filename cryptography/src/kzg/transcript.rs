use super::Error;
use crate::bls12381::primitives::group::{Element, G1, G2};
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
    /// form, supporting polynomials up to degree 4,095.
    pub fn ethereum_kzg() -> Result<Self, Error> {
        Self::from_bytes(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/trusted_setup.bin"
        )))
    }

    /// Returns the maximum supported polynomial degree.
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

    fn from_bytes(mut raw: &[u8]) -> Result<Self, Error> {
        // Read counts
        if raw.len() < 8 {
            return Err(Error::InvalidSetup("truncated header"));
        }
        let g1_count = u32::from_le_bytes(raw[0..4].try_into().unwrap()) as usize;
        let g2_count = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
        raw = &raw[8..];

        // Read G2 powers
        let mut g2_powers = Vec::with_capacity(g2_count);
        for _ in 0..g2_count {
            if raw.len() < 96 {
                return Err(Error::InvalidSetup("truncated g2 section"));
            }
            let (bytes, rest) = raw.split_at(96);
            raw = rest;
            g2_powers.push(parse_g2_bytes(bytes)?);
        }

        // Read G1 powers
        let mut g1_powers = Vec::with_capacity(g1_count);
        for _ in 0..g1_count {
            if raw.len() < 48 {
                return Err(Error::InvalidSetup("truncated g1 section"));
            }
            let (bytes, rest) = raw.split_at(48);
            raw = rest;
            g1_powers.push(parse_g1_bytes(bytes)?);
        }

        Ok(Self {
            g1_powers,
            g2_powers,
        })
    }
}

fn parse_g1_bytes(bytes: &[u8]) -> Result<G1, Error> {
    // The c-kzg format uses compressed points without a `0x` prefix.
    if bytes.first() == Some(&0xc0) && bytes.iter().skip(1).all(|b| *b == 0) {
        return Ok(G1::zero());
    }

    let mut buf = Bytes::copy_from_slice(bytes);
    G1::read(&mut buf).map_err(|_| Error::InvalidSetup("g1 decompress"))
}

fn parse_g2_bytes(bytes: &[u8]) -> Result<G2, Error> {
    if bytes.first() == Some(&0xc0) && bytes.iter().skip(1).all(|b| *b == 0) {
        return Ok(G2::zero());
    }

    let mut buf = Bytes::copy_from_slice(bytes);
    G2::read(&mut buf).map_err(|_| Error::InvalidSetup("g2 decompress"))
}
