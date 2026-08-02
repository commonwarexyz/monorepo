//! Bounded data-availability component contracts.

use super::contracts::{SigningCapability, SigningReservation, SigningSlot, SigningSlotError};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
struct ReservationEntry<S: Clone + Eq> {
    subject: S,
    slot: SigningSlot<S>,
    capability: Option<SigningCapability<S>>,
}

/// Bounded active durable signing reservations and their volatile capabilities.
#[derive(Clone, Debug)]
pub(crate) struct ReservationBook<S: Clone + Eq> {
    capacity: usize,
    entries: BTreeMap<u64, ReservationEntry<S>>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ReservationError {
    /// The active reservation bound is saturated.
    #[error("DA signing reservation capacity is saturated")]
    Full,
    /// A stable id was replayed with another exact subject.
    #[error("DA signing reservation subject conflicts with durable history")]
    Conflict,
    /// The reservation does not exist.
    #[error("DA signing reservation is missing")]
    Missing,
    /// The slot lifecycle rejected the operation.
    #[error("DA signing slot lifecycle rejected the operation")]
    Slot(SigningSlotError),
}

impl From<SigningSlotError> for ReservationError {
    fn from(error: SigningSlotError) -> Self {
        Self::Slot(error)
    }
}

impl<S: Clone + Eq> ReservationBook<S> {
    pub(crate) const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: BTreeMap::new(),
        }
    }

    /// Installs the exact durable subject before a signing capability can be issued.
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
        let mut slot = SigningSlot::new();
        slot.reserve(SigningReservation { id }, subject.clone())?;
        self.entries.insert(
            id,
            ReservationEntry {
                subject,
                slot,
                capability: None,
            },
        );
        Ok(())
    }

    /// Issues the current process's volatile capability for the exact durable reservation.
    pub(crate) fn issue(&mut self, id: u64, generation: u64) -> Result<(), ReservationError> {
        let entry = self.entries.get_mut(&id).ok_or(ReservationError::Missing)?;
        if entry.capability.is_some() {
            return Ok(());
        }
        entry.capability = Some(entry.slot.issue(generation)?);
        Ok(())
    }

    /// Completes and removes an active reservation after the signed-artifact event is staged.
    pub(crate) fn complete(
        &mut self,
        id: u64,
        generation: u64,
        subject: &S,
    ) -> Result<(), ReservationError> {
        let entry = self.entries.get_mut(&id).ok_or(ReservationError::Missing)?;
        if &entry.subject != subject {
            return Err(ReservationError::Conflict);
        }
        let capability = entry
            .capability
            .take()
            .ok_or(SigningSlotError::NoLiveCapability)?;
        if capability.generation() != generation {
            entry.capability = Some(capability);
            return Err(SigningSlotError::StaleGeneration.into());
        }
        entry.slot.complete(capability)?;
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

    pub(crate) fn is_issued(&self, id: u64, generation: u64, subject: &S) -> bool {
        self.entries.get(&id).is_some_and(|entry| {
            &entry.subject == subject
                && entry
                    .capability
                    .as_ref()
                    .is_some_and(|capability| capability.generation() == generation)
        })
    }

    /// Returns the reserved subject when its volatile capability belongs to `generation`.
    pub(crate) fn issued_subject(&self, id: u64, generation: u64) -> Option<&S> {
        self.entries.get(&id).and_then(|entry| {
            entry
                .capability
                .as_ref()
                .is_some_and(|capability| capability.generation() == generation)
                .then_some(&entry.subject)
        })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_replay_restart_and_saturate_exactly() {
        let mut book = ReservationBook::new(2);
        book.reserve(7, "first").unwrap();
        book.reserve(8, "second").unwrap();
        assert_eq!(book.reserve(9, "third"), Err(ReservationError::Full));
        assert_eq!(book.reserve(7, "conflict"), Err(ReservationError::Conflict));

        book.issue(7, 3).unwrap();
        book.complete(7, 3, &"first").unwrap();

        let mut restarted = ReservationBook::new(2);
        restarted.reserve(8, "second").unwrap();
        restarted.issue(8, 4).unwrap();
        restarted.complete(8, 4, &"second").unwrap();
        assert_eq!(restarted.len(), 0);

        let mut replayed = ReservationBook::new(1);
        replayed.reserve(11, "journaled").unwrap();
        replayed.replay_complete(11, &"journaled").unwrap();
        assert_eq!(replayed.len(), 0);
    }
}
