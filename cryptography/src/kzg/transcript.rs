use super::Error;
use crate::bls12381::primitives::group::{Element, Scalar, G1, G2};
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
    /// The transcript expands the shared secret tau into 4,096 G1 powers and
    /// 4,097 G2 powers, supporting polynomials up to degree 4,095.
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
        let seed = lines
            .next()
            .ok_or(Error::InvalidSetup("truncated g1 section"))?;
        let tau = derive_tau(seed)?;

        let (g1_powers, g2_powers) = expand_powers(g1_count, g2_count, tau);

        Ok(Self {
            g1_powers,
            g2_powers,
        })
    }
}

const TAU_DST: crate::bls12381::primitives::group::DST = b"ETHEREUM_KZG_TAU";

fn derive_tau(seed: &str) -> Result<Scalar, Error> {
    let bytes = from_hex(seed).ok_or(Error::Hex)?;
    Ok(Scalar::map(TAU_DST, &bytes))
}

fn expand_powers(g1_count: usize, g2_count: usize, tau: Scalar) -> (Vec<G1>, Vec<G2>) {
    let mut g1_powers = Vec::with_capacity(g1_count);
    let mut g2_powers = Vec::with_capacity(g2_count);

    let mut g1_current = G1::one();
    let mut g2_current = G2::one();

    for _ in 0..g1_count {
        g1_powers.push(g1_current.clone());
        g1_current.mul(&tau);
    }

    for _ in 0..g2_count {
        g2_powers.push(g2_current.clone());
        g2_current.mul(&tau);
    }

    (g1_powers, g2_powers)
}
