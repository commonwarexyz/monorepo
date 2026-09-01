//! Peer L-QC verifications: at most one per key, and a bounded number at once.

use super::{Error, staging::Ready};
use crate::multimmit::{marshal::wire::BackfillKey, types::Body};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::futures::Pool;
use std::{collections::BTreeSet, future::Future};

/// Whether a verified L-QC may complete its waiters.
pub(super) enum Verdict {
    /// The proof verified and the catalog admitted it.
    Admitted,
    /// The proof failed verification.
    Invalid,
}

/// A finished L-QC verification for one delivery.
pub(super) struct Verification<H: Hasher, V: Variant, B: Body<H>> {
    pub ready: Ready<H, V, B>,
    pub result: Result<Verdict, Error>,
}

/// L-QC verifications in flight.
///
/// A key stays reserved until its verification finishes, so a delivery that arrives meanwhile does
/// not start a second verification, even after its waiters were canceled and requested again.
pub(super) struct Verifications<H: Hasher, V: Variant, B: Body<H>> {
    active: Pool<'static, Verification<H, V, B>>,
    keys: BTreeSet<BackfillKey<H::Digest>>,
    capacity: usize,
}

impl<H: Hasher, V: Variant, B: Body<H>> Verifications<H, V, B> {
    /// Creates an empty set that runs at most `capacity` verifications at once.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            active: Pool::default(),
            keys: BTreeSet::new(),
            capacity,
        }
    }

    /// Returns whether a delivery for `key` is being verified.
    pub(super) fn is_active(&self, key: &BackfillKey<H::Digest>) -> bool {
        self.keys.contains(key)
    }

    /// Returns whether no further verification may start.
    pub(super) fn is_saturated(&self) -> bool {
        self.keys.len() >= self.capacity
    }

    /// Returns whether no verification is in flight.
    pub(super) fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Starts `verification` for a delivery of `key`.
    pub(super) fn start(
        &mut self,
        key: BackfillKey<H::Digest>,
        verification: impl Future<Output = Verification<H, V, B>> + Send + 'static,
    ) {
        debug_assert!(!self.is_saturated());
        let inserted = self.keys.insert(key);
        debug_assert!(inserted);
        self.active.push(verification);
    }

    /// Waits for the next verification to finish. Pends while none is in flight.
    pub(super) fn next_completed(
        &mut self,
    ) -> impl Future<Output = Verification<H, V, B>> + Send + '_ {
        self.active.next_completed()
    }

    /// Releases the key of a finished verification, returning whether it was reserved.
    pub(super) fn finish(&mut self, key: &BackfillKey<H::Digest>) -> bool {
        self.keys.remove(key)
    }
}
