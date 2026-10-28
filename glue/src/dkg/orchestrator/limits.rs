//! Size limits for the payloads the orchestrator sends.

use commonware_consensus::simplex::{self, scheme::Scheme};
use commonware_cryptography::Digest;
use commonware_p2p::{Footprint, utils::mux::Prefixed};

/// Largest payloads the orchestrator sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest Simplex message, with room for its epoch subchannel prefix.
    message: usize,
}

impl Limits {
    /// Returns the limits for committees of at most `participants` under `S` with payload digest
    /// `D`.
    pub fn new<S: Scheme<D>, D: Digest>(participants: usize) -> Self {
        // Every Simplex message travels on the subchannel of its epoch.
        let simplex = simplex::Limits::new::<S, D>(participants);
        Self {
            message: Prefixed(simplex).footprint(),
        }
    }
}

impl Footprint for Limits {
    fn footprint(&self) -> usize {
        self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::simplex::scheme::ed25519;
    use commonware_cryptography::sha256::Digest as Sha256;

    #[test]
    fn footprint_prefixes_simplex() {
        for participants in [1, 4, 128] {
            let limits = Limits::new::<ed25519::Scheme, Sha256>(participants);
            let simplex = simplex::Limits::new::<ed25519::Scheme, Sha256>(participants);
            assert_eq!(limits.footprint(), Prefixed(simplex).footprint());
            assert_eq!(limits.footprint(), simplex.footprint() + 10);
        }
    }
}
