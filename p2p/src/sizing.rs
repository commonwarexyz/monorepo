use crate::{AddressableTrackedPeers, TrackedPeers};
use commonware_cryptography::PublicKey;
use std::num::NonZeroUsize;

pub(crate) fn max_retained_peers(
    max_peers_per_set: NonZeroUsize,
    tracked_peer_sets: NonZeroUsize,
    persistent_peers: usize,
) -> NonZeroUsize {
    max_peers_per_set
        .get()
        .checked_mul(tracked_peer_sets.get())
        .and_then(|count| count.checked_add(persistent_peers))
        .and_then(NonZeroUsize::new)
        .expect("maximum retained peer count overflow")
}

pub(crate) fn peer_set_size<P: PublicKey>(peers: &TrackedPeers<P>) -> usize {
    checked_peer_set_size(
        peers.primary.len(),
        peers
            .secondary
            .iter()
            .filter(|peer| peers.primary.position(peer).is_none())
            .count(),
    )
}

pub(crate) fn peer_set_size_including<P: PublicKey>(
    peers: &TrackedPeers<P>,
    required: &P,
) -> usize {
    let peer_count = peer_set_size(peers);
    if peers.primary.position(required).is_some() || peers.secondary.position(required).is_some() {
        peer_count
    } else {
        checked_peer_set_size(peer_count, 1)
    }
}

pub(crate) fn addressable_peer_set_size<P: PublicKey>(peers: &AddressableTrackedPeers<P>) -> usize {
    checked_peer_set_size(
        peers.primary.len(),
        peers
            .secondary
            .keys()
            .iter()
            .filter(|peer| peers.primary.position(peer).is_none())
            .count(),
    )
}

pub(crate) fn addressable_peer_set_size_including<P: PublicKey>(
    peers: &AddressableTrackedPeers<P>,
    required: &P,
) -> usize {
    let peer_count = addressable_peer_set_size(peers);
    if peers.primary.position(required).is_some()
        || peers.secondary.keys().position(required).is_some()
    {
        peer_count
    } else {
        checked_peer_set_size(peer_count, 1)
    }
}

const fn checked_peer_set_size(primary: usize, secondary_only: usize) -> usize {
    primary
        .checked_add(secondary_only)
        .expect("peer set size overflow")
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::NZUsize;

    #[test]
    fn test_max_retained_peers() {
        assert_eq!(max_retained_peers(NZUsize!(3), NZUsize!(4), 2).get(), 14);
    }

    #[test]
    #[should_panic(expected = "maximum retained peer count overflow")]
    fn test_max_retained_peers_overflow() {
        max_retained_peers(NonZeroUsize::MAX, NZUsize!(2), 0);
    }

    #[test]
    #[should_panic(expected = "peer set size overflow")]
    fn test_peer_set_size_overflow() {
        checked_peer_set_size(usize::MAX, 1);
    }
}
