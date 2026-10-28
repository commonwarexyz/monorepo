//! Size limits for the payloads the orchestrator sends.

use commonware_consensus::simplex::{self, scheme::Scheme};
use commonware_cryptography::Digest;
use commonware_p2p::utils::mux::prefixed;

/// Returns the largest payload the orchestrator sends for committees of at most `participants`
/// members.
pub fn max_payload_size<S: Scheme<D>, D: Digest>(participants: u32) -> usize {
    // Every Simplex message travels on the subchannel of its epoch.
    prefixed(simplex::max_payload_size::<S, D>(participants))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::simplex::scheme::ed25519;
    use commonware_cryptography::sha256::Digest as Sha256;

    #[test]
    fn prefixes_simplex() {
        for participants in [1, 4, 128] {
            let bound = max_payload_size::<ed25519::Scheme, Sha256>(participants);
            let simplex = simplex::max_payload_size::<ed25519::Scheme, Sha256>(participants);
            assert_eq!(bound, prefixed(simplex));
            assert_eq!(bound, simplex + 10);
        }
    }
}
