use std::{cmp::Ordering, num::NonZeroUsize};

/// Returns the smallest `max_peers_per_set` that admits every peer set drawn
/// from distinct `participants` when the network runs as `local`.
///
/// The trackers count the local identity in every peer set whether or not it
/// is registered, so a `local` outside `participants` consumes one extra slot.
/// Duplicate participants are counted conservatively as separate slots.
///
/// # Panics
///
/// Panics if the resulting size does not fit in a `usize`.
pub fn peer_set_limit<'a, P: Eq + 'a>(
    participants: impl IntoIterator<Item = &'a P>,
    local: &P,
) -> NonZeroUsize {
    let mut peer_count = 0usize;
    let mut contains_local = false;
    for participant in participants {
        peer_count = peer_count.checked_add(1).expect("peer set size overflow");
        contains_local |= participant == local;
    }
    if !contains_local {
        peer_count = peer_count.checked_add(1).expect("peer set size overflow");
    }
    NonZeroUsize::new(peer_count).expect("local identity ensures at least one peer")
}

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

/// Counts identities across primary and secondary roles.
///
/// Each iterator must be sorted and deduplicated. Identities in both roles count once, and
/// `extension` counts once when absent from both roles.
pub(crate) fn peer_set_size<'a, P: Ord + 'a>(
    primary: impl Iterator<Item = &'a P>,
    secondary: impl Iterator<Item = &'a P>,
    extension: Option<&P>,
) -> usize {
    let mut primary = primary.peekable();
    let mut secondary = secondary.peekable();
    let mut peer_count = 0usize;
    let mut contains_extension = extension.is_none();

    loop {
        let peer = match (primary.peek(), secondary.peek()) {
            (Some(primary_peer), Some(secondary_peer)) => match primary_peer.cmp(secondary_peer) {
                Ordering::Less => primary.next(),
                Ordering::Equal => {
                    secondary.next();
                    primary.next()
                }
                Ordering::Greater => secondary.next(),
            },
            (Some(_), None) => primary.next(),
            (None, Some(_)) => secondary.next(),
            (None, None) => break,
        }
        .expect("peeked peer must exist");

        peer_count = peer_count.checked_add(1).expect("peer set size overflow");
        contains_extension |= extension == Some(peer);
    }

    if !contains_extension {
        peer_count = peer_count.checked_add(1).expect("peer set size overflow");
    }
    peer_count
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
    fn test_peer_set_limit_counts_included_local_identity() {
        let participants = [1, 2];
        assert_eq!(peer_set_limit(&participants, &1).get(), 2);
    }

    #[test]
    fn test_peer_set_limit_counts_omitted_local_identity() {
        let participants = [1, 2];
        assert_eq!(peer_set_limit(&participants, &3).get(), 3);
    }

    #[test]
    fn test_peer_set_size_deduplicates_roles_and_includes_extension() {
        let primary = [1, 3];
        let secondary = [2, 3];

        assert_eq!(peer_set_size(primary.iter(), secondary.iter(), None), 3);
        assert_eq!(peer_set_size(primary.iter(), secondary.iter(), Some(&2)), 3);
        assert_eq!(peer_set_size(primary.iter(), secondary.iter(), Some(&4)), 4);
    }

    #[test]
    #[should_panic(expected = "maximum retained peer count overflow")]
    fn test_max_retained_peers_overflow() {
        max_retained_peers(NonZeroUsize::MAX, NZUsize!(2), 0);
    }
}
