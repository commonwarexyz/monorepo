use crate::bls12381::primitives::group::{G1, G2};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use commonware_codec::ReadExt;

/// Powers of tau used to create and verify KZG commitments.
pub trait Setup {
    /// Returns the G1 powers of tau.
    fn g1_powers(&self) -> &[G1];

    /// Returns the G2 powers of tau.
    fn g2_powers(&self) -> &[G2];
}

/// Powers of tau derived from the public Ethereum KZG ceremony transcript.
#[derive(Clone, Default)]
pub struct Ethereum {
    g1_powers: Vec<G1>,
    g2_powers: Vec<G2>,
}

impl Ethereum {
    /// Loads the Ethereum KZG ceremony transcript bundled with this crate.
    ///
    /// The transcript bundles the Ethereum KZG monomial powers in compressed
    /// form (4,096 G1 powers and 65 G2 powers), supporting G1 commitments up to
    /// degree 4,095 and G2 commitments up to degree 64.
    ///
    /// Source: https://github.com/ethereum/consensus-specs/blob/6070972f148bc3d9417e90418f97cb7f5a9a6417/presets/mainnet/trusted_setups/trusted_setup_4096.json
    pub fn new() -> Self {
        Self::from_bytes(include_bytes!("ethereum.bin"))
    }

    fn from_bytes(mut raw: &[u8]) -> Self {
        // Read G1 count
        let g1_count = u32::from_be_bytes(raw[0..4].try_into().unwrap()) as usize;
        raw = &raw[4..];

        // Read G1 powers
        let mut g1_powers = Vec::with_capacity(g1_count);
        for _ in 0..g1_count {
            let (mut bytes, rest) = raw.split_at(48);
            raw = rest;
            let g1 = G1::read(&mut bytes).expect("invalid g1 point");
            g1_powers.push(g1);
        }

        // Read G2 count
        let g2_count = u32::from_be_bytes(raw[0..4].try_into().unwrap()) as usize;
        raw = &raw[4..];

        // Read G2 powers
        let mut g2_powers = Vec::with_capacity(g2_count);
        for _ in 0..g2_count {
            let (mut bytes, rest) = raw.split_at(96);
            let g2 = G2::read(&mut bytes).expect("invalid g2 point");
            raw = rest;
            g2_powers.push(g2);
        }

        Self {
            g1_powers,
            g2_powers,
        }
    }
}

impl Setup for Ethereum {
    fn g1_powers(&self) -> &[G1] {
        &self.g1_powers
    }

    fn g2_powers(&self) -> &[G2] {
        &self.g2_powers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethereum_kzg() {
        let setup = Ethereum::new();
        assert_eq!(setup.g1_powers().len(), 4096, "Expected 4096 G1 powers");
        assert_eq!(setup.g2_powers().len(), 65, "Expected 65 G2 powers");
    }
}
