//! Bounded durable signing reservations, and the DA signing choices the chain state reserves.
//!
//! A [`ReservationBook`] installs each durable signing subject under its effect identifier before
//! any signing capability is issued, so replay reinstalls the same subject and a completion is
//! matched against exactly what was reserved.

use super::{
    chain::{ChainError, ChainState},
    durability::{EffectId, SignEffect, SignRequest},
    job::{Generation, Issued},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Debug)]
struct ReservationEntry<S> {
    subject: S,
    issued_generation: Option<Generation>,
}

/// Bounded active durable signing reservations and their volatile capabilities.
#[derive(Clone, Debug)]
pub(crate) struct ReservationBook<S> {
    capacity: usize,
    entries: BTreeMap<u64, ReservationEntry<S>>,
}

/// A signing reservation operation that contradicts the book's durable or volatile state.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ReservationError {
    /// The active reservation bound is saturated.
    #[error("signing reservation capacity is saturated")]
    Full,
    /// A stable id was replayed with a different subject.
    #[error("signing reservation subject conflicts with durable history")]
    Conflict,
    /// The reservation does not exist.
    #[error("signing reservation is missing")]
    Missing,
    /// The reservation has no issued capability.
    #[error("signing reservation has no issued capability")]
    NoLiveCapability,
    /// The completion does not match the issued generation.
    #[error("signing completion generation is stale")]
    StaleGeneration,
}

impl<S: Eq> ReservationBook<S> {
    /// Creates an empty book holding at most `capacity` reservations.
    pub(crate) const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: BTreeMap::new(),
        }
    }

    /// Installs the durable subject before a signing capability can be issued.
    pub(crate) fn reserve(&mut self, id: u64, subject: S) -> Result<(), ReservationError> {
        if let Some(existing) = self.entries.get(&id) {
            return if existing.subject == subject {
                Ok(())
            } else {
                Err(ReservationError::Conflict)
            };
        }
        if self.entries.len() >= self.capacity {
            return Err(ReservationError::Full);
        }
        self.entries.insert(
            id,
            ReservationEntry {
                subject,
                issued_generation: None,
            },
        );
        Ok(())
    }

    /// Issues a volatile capability for the durable reservation.
    ///
    /// The first issue wins: a later call keeps the generation already issued.
    pub(crate) fn issue(
        &mut self,
        id: u64,
        generation: Generation,
    ) -> Result<(), ReservationError> {
        let entry = self.entries.get_mut(&id).ok_or(ReservationError::Missing)?;
        entry.issued_generation.get_or_insert(generation);
        Ok(())
    }

    /// Completes and removes an active reservation after the signed-artifact event is staged.
    pub(crate) fn complete(
        &mut self,
        id: u64,
        generation: Generation,
        subject: &S,
    ) -> Result<(), ReservationError> {
        let entry = self.entries.get(&id).ok_or(ReservationError::Missing)?;
        if &entry.subject != subject {
            return Err(ReservationError::Conflict);
        }
        let issued = entry
            .issued_generation
            .ok_or(ReservationError::NoLiveCapability)?;
        if issued != generation {
            return Err(ReservationError::StaleGeneration);
        }
        self.entries.remove(&id);
        Ok(())
    }

    /// Applies a journaled completion during replay, where no volatile capability exists.
    pub(crate) fn replay_complete(&mut self, id: u64, subject: &S) -> Result<(), ReservationError> {
        let entry = self.entries.get(&id).ok_or(ReservationError::Missing)?;
        if &entry.subject != subject {
            return Err(ReservationError::Conflict);
        }
        self.entries.remove(&id);
        Ok(())
    }

    /// Returns whether reservation `id` holds `subject` with a capability issued in
    /// `generation`.
    pub(crate) fn is_issued(&self, id: u64, generation: Generation, subject: &S) -> bool {
        self.entries.get(&id).is_some_and(|entry| {
            &entry.subject == subject && entry.issued_generation == Some(generation)
        })
    }

    /// Returns the reserved subject when its volatile capability belongs to `generation`.
    pub(crate) fn issued_subject(&self, id: u64, generation: Generation) -> Option<&S> {
        self.entries.get(&id).and_then(|entry| {
            (entry.issued_generation == Some(generation)).then_some(&entry.subject)
        })
    }

    /// Returns the number of active reservations.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

impl<V: Variant, D: Digest> ChainState<V, D> {
    /// Returns the requests of a DA signing choice: a producer header, a DA vote, or a run of
    /// DA votes. Other signing choices hold no chain reservation.
    fn signing_subject(effect: &SignEffect<V, D>) -> Option<Arc<[SignRequest<V, D>]>> {
        let requests = effect.requests();
        let reserved = match requests {
            [SignRequest::TransactionBlock(_) | SignRequest::DaVote(_)] => true,
            [_, _, ..] => requests
                .iter()
                .all(|request| matches!(request, SignRequest::DaVote(_))),
            _ => false,
        };
        reserved.then(|| Arc::clone(effect.shared()))
    }

    /// Reserves the durable DA signing subject represented by a signing-reservation row.
    pub(crate) fn reserve_signing(
        &mut self,
        id: EffectId,
        effect: &SignEffect<V, D>,
    ) -> Result<(), ChainError> {
        let Some(subject) = Self::signing_subject(effect) else {
            return Ok(());
        };
        self.signing
            .reserve(id.get(), subject)
            .map_err(ChainError::Reservation)
    }

    /// Issues a volatile capability without changing the durable subject.
    pub(crate) fn issue_signing(
        &mut self,
        issued: Issued<EffectId>,
        effect: &SignEffect<V, D>,
    ) -> Result<(), ChainError> {
        if Self::signing_subject(effect).is_none() {
            return Ok(());
        }
        self.signing
            .issue(issued.id().get(), issued.generation())
            .map_err(ChainError::Reservation)
    }

    /// Returns whether the DA signing choice of `effect` was issued as `issued`; other signing
    /// effects hold no choice and always match.
    pub(crate) fn signing_issued(
        &self,
        issued: Issued<EffectId>,
        effect: &SignEffect<V, D>,
    ) -> bool {
        let Some(subject) = Self::signing_subject(effect) else {
            return true;
        };
        self.signing
            .is_issued(issued.id().get(), issued.generation(), &subject)
    }

    /// Returns request `index` of the DA signing choice issued as `issued`.
    pub(crate) fn issued_signing_request(
        &self,
        issued: Issued<EffectId>,
        index: usize,
    ) -> Option<&SignRequest<V, D>> {
        self.signing
            .issued_subject(issued.id().get(), issued.generation())?
            .get(index)
    }

    /// Returns the number of requests in the DA signing choice issued as `issued`.
    pub(crate) fn issued_signing_batch_len(&self, issued: Issued<EffectId>) -> Option<usize> {
        Some(
            self.signing
                .issued_subject(issued.id().get(), issued.generation())?
                .len(),
        )
    }

    /// Completes the active slot issued as `issued`.
    pub(crate) fn complete_signing(
        &mut self,
        issued: Issued<EffectId>,
        effect: &SignEffect<V, D>,
    ) -> Result<(), ChainError> {
        let Some(subject) = Self::signing_subject(effect) else {
            return Ok(());
        };
        self.signing
            .complete(issued.id().get(), issued.generation(), &subject)
            .map_err(ChainError::Reservation)
    }

    /// Consumes the reserved subject during replay, where no volatile capability exists.
    pub(crate) fn replay_signing(
        &mut self,
        id: EffectId,
        effect: &SignEffect<V, D>,
    ) -> Result<(), ChainError> {
        let Some(subject) = Self::signing_subject(effect) else {
            return Ok(());
        };
        self.signing
            .replay_complete(id.get(), &subject)
            .map_err(ChainError::Reservation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_completions_preserve_the_exact_issued_reservation() {
        let mut book = ReservationBook::new(1);
        assert_eq!(
            book.issue(7, Generation::new(3)),
            Err(ReservationError::Missing)
        );
        book.reserve(7, "subject").unwrap();
        book.reserve(7, "subject").unwrap();
        assert_eq!(
            book.complete(7, Generation::new(3), &"subject"),
            Err(ReservationError::NoLiveCapability)
        );
        assert_eq!(book.len(), 1);
        assert_eq!(book.issued_subject(7, Generation::new(3)), None);
        book.issue(7, Generation::new(3)).unwrap();
        for generation in [2, 3, 4] {
            book.issue(7, Generation::new(generation)).unwrap();
            assert!(book.is_issued(7, Generation::new(3), &"subject"));
        }
        assert_eq!(
            book.complete(7, Generation::new(3), &"other"),
            Err(ReservationError::Conflict)
        );
        assert_eq!(
            book.complete(7, Generation::new(4), &"subject"),
            Err(ReservationError::StaleGeneration)
        );
        assert_eq!(book.issued_subject(7, Generation::new(3)), Some(&"subject"));
        assert_eq!(book.issued_subject(7, Generation::new(4)), None);
        assert!(!book.is_issued(7, Generation::new(3), &"other"));
        book.complete(7, Generation::new(3), &"subject").unwrap();
        assert_eq!(book.len(), 0);
        assert_eq!(
            book.complete(7, Generation::new(3), &"subject"),
            Err(ReservationError::Missing)
        );

        book.reserve(8, "replayed").unwrap();
        assert_eq!(
            book.replay_complete(8, &"other"),
            Err(ReservationError::Conflict)
        );
        assert_eq!(book.len(), 1);
        book.replay_complete(8, &"replayed").unwrap();
        assert_eq!(book.len(), 0);
    }

    #[test]
    fn reservations_replay_restart_and_saturate_exactly() {
        let mut book = ReservationBook::new(2);
        book.reserve(7, "first").unwrap();
        book.reserve(8, "second").unwrap();
        assert_eq!(book.reserve(9, "third"), Err(ReservationError::Full));
        assert_eq!(book.reserve(7, "conflict"), Err(ReservationError::Conflict));

        book.issue(7, Generation::new(3)).unwrap();
        book.complete(7, Generation::new(3), &"first").unwrap();

        let mut restarted = ReservationBook::new(2);
        restarted.reserve(8, "second").unwrap();
        restarted.issue(8, Generation::new(4)).unwrap();
        restarted
            .complete(8, Generation::new(4), &"second")
            .unwrap();
        assert_eq!(restarted.len(), 0);

        let mut replayed = ReservationBook::new(1);
        replayed.reserve(11, "journaled").unwrap();
        replayed.replay_complete(11, &"journaled").unwrap();
        assert_eq!(replayed.len(), 0);
    }
}
