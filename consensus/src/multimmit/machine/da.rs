//! Bounded data-availability component contracts.

use std::collections::BTreeMap;

#[derive(Clone, Debug)]
struct ReservationEntry<S> {
    subject: S,
    issued_generation: Option<u64>,
}

/// Bounded active durable signing reservations and their volatile capabilities.
#[derive(Clone, Debug)]
pub(crate) struct ReservationBook<S> {
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
    /// The reservation has no issued capability.
    #[error("DA signing reservation has no issued capability")]
    NoLiveCapability,
    /// The completion does not match the issued generation.
    #[error("DA signing completion generation is stale")]
    StaleGeneration,
}

impl<S: Eq> ReservationBook<S> {
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
        self.entries.insert(
            id,
            ReservationEntry {
                subject,
                issued_generation: None,
            },
        );
        Ok(())
    }

    /// Issues the current process's volatile capability for the exact durable reservation.
    pub(crate) fn issue(&mut self, id: u64, generation: u64) -> Result<(), ReservationError> {
        let entry = self.entries.get_mut(&id).ok_or(ReservationError::Missing)?;
        entry.issued_generation.get_or_insert(generation);
        Ok(())
    }

    /// Completes and removes an active reservation after the signed-artifact event is staged.
    pub(crate) fn complete(
        &mut self,
        id: u64,
        generation: u64,
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

    pub(crate) fn is_issued(&self, id: u64, generation: u64, subject: &S) -> bool {
        self.entries.get(&id).is_some_and(|entry| {
            &entry.subject == subject && entry.issued_generation == Some(generation)
        })
    }

    /// Returns the reserved subject when its volatile capability belongs to `generation`.
    pub(crate) fn issued_subject(&self, id: u64, generation: u64) -> Option<&S> {
        self.entries.get(&id).and_then(|entry| {
            (entry.issued_generation == Some(generation)).then_some(&entry.subject)
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
    fn failed_completions_preserve_the_exact_issued_reservation() {
        let mut book = ReservationBook::new(1);
        assert_eq!(book.issue(7, 3), Err(ReservationError::Missing));
        book.reserve(7, "subject").unwrap();
        book.reserve(7, "subject").unwrap();
        assert_eq!(
            book.complete(7, 3, &"subject"),
            Err(ReservationError::NoLiveCapability)
        );
        assert_eq!(book.len(), 1);
        assert_eq!(book.issued_subject(7, 3), None);
        book.issue(7, 3).unwrap();
        for generation in [2, 3, 4] {
            book.issue(7, generation).unwrap();
            assert!(book.is_issued(7, 3, &"subject"));
        }
        assert_eq!(
            book.complete(7, 3, &"other"),
            Err(ReservationError::Conflict)
        );
        assert_eq!(
            book.complete(7, 4, &"subject"),
            Err(ReservationError::StaleGeneration)
        );
        assert_eq!(book.issued_subject(7, 3), Some(&"subject"));
        assert_eq!(book.issued_subject(7, 4), None);
        assert!(!book.is_issued(7, 3, &"other"));
        book.complete(7, 3, &"subject").unwrap();
        assert_eq!(book.len(), 0);
        assert_eq!(
            book.complete(7, 3, &"subject"),
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
