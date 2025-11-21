use super::Error;
use crate::bls12381::primitives::group::{Element, G1, G2};
use bytes::Bytes;
use commonware_codec::ReadExt;
use commonware_utils::from_hex;

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
        Self::from_str(include_str!("eth_trusted_setup.txt"))
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

    fn from_str(raw: &str) -> Result<Self, Error> {
        let mut lines = raw.lines();
        let g1_count = lines
            .next()
            .ok_or(Error::InvalidSetup("missing g1 count"))?
            .parse::<usize>()
            .map_err(|_| Error::InvalidSetup("invalid g1 count"))?;
        let g2_count = lines
            .next()
            .ok_or(Error::InvalidSetup("missing g2 count"))?
            .parse::<usize>()
            .map_err(|_| Error::InvalidSetup("invalid g2 count"))?;

        // Skip the lagrange-form G1 powers provided by the c-kzg text format.
        for _ in 0..g1_count {
            lines
                .next()
                .ok_or(Error::InvalidSetup("truncated g1 lagrange section"))?;
        }

        let mut g2_powers = Vec::with_capacity(g2_count);
        for _ in 0..g2_count {
            let line = lines
                .next()
                .ok_or(Error::InvalidSetup("truncated g2 monomial section"))?;
            g2_powers.push(parse_g2(line)?);
        }

        let mut g1_powers = Vec::with_capacity(g1_count);
        for _ in 0..g1_count {
            let line = lines
                .next()
                .ok_or(Error::InvalidSetup("truncated g1 monomial section"))?;
            g1_powers.push(parse_g1(line)?);
        }

        Ok(Self { g1_powers, g2_powers })
    }
}

fn parse_g1(line: &str) -> Result<G1, Error> {
    let bytes = from_hex(line).ok_or(Error::Hex)?;
    // The c-kzg format uses compressed points without a `0x` prefix.
    if bytes.first() == Some(&0xc0) && bytes.iter().skip(1).all(|b| *b == 0) {
        return Ok(G1::zero());
    }

    let mut buf = Bytes::from(bytes);
    G1::read(&mut buf).map_err(|_| Error::InvalidSetup("g1 decompress"))
}

fn parse_g2(line: &str) -> Result<G2, Error> {
    let bytes = from_hex(line).ok_or(Error::Hex)?;
    if bytes.first() == Some(&0xc0) && bytes.iter().skip(1).all(|b| *b == 0) {
        return Ok(G2::zero());
    }

    let mut buf = Bytes::from(bytes);
    G2::read(&mut buf).map_err(|_| Error::InvalidSetup("g2 decompress"))
}
