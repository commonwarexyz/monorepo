//! Identity of volatile work: process generations, issued job identities, and identifier
//! sequences.

use core::marker::PhantomData;

/// A process generation.
///
/// Every start or recovery advances the generation, which invalidates volatile work issued by
/// earlier processes: a completion is current only if it carries the generation that issued it.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(u64);

impl Generation {
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the generation's sequence number.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next generation, or `None` on overflow.
    pub(crate) const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

/// The identity of one volatile job and the process generation that issued it.
///
/// Jobs and their completions carry the same value, so a completion correlates to its job and is
/// current only while its generation is.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Issued<Id> {
    id: Id,
    generation: Generation,
}

impl<Id: Copy> Issued<Id> {
    pub(crate) const fn new(id: Id, generation: Generation) -> Self {
        Self { id, generation }
    }

    /// Returns the job identifier.
    pub(crate) const fn id(self) -> Id {
        self.id
    }

    /// Returns the process generation that issued the job.
    pub(crate) const fn generation(self) -> Generation {
        self.generation
    }
}

/// A generation-local identifier drawn from an [`IdSequence`].
pub(crate) trait SequenceId: Copy {
    /// Returns the identifier at `sequence`.
    fn at(sequence: u64) -> Self;
}

/// Issues distinct identifiers in ascending order.
pub(crate) struct IdSequence<Id> {
    next: u64,
    marker: PhantomData<fn() -> Id>,
}

impl<Id: SequenceId> IdSequence<Id> {
    pub(crate) const fn new() -> Self {
        Self {
            next: 0,
            marker: PhantomData,
        }
    }

    /// Returns the next identifier, or `None` once the sequence is exhausted.
    pub(crate) fn issue(&mut self) -> Option<Id> {
        let id = Id::at(self.next);
        self.next = self.next.checked_add(1)?;
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct TestId(u64);

    impl SequenceId for TestId {
        fn at(sequence: u64) -> Self {
            Self(sequence)
        }
    }

    #[test]
    fn id_sequence_issues_ascending_until_exhausted() {
        let mut ids = IdSequence::<TestId>::new();
        assert_eq!(ids.issue(), Some(TestId(0)));
        assert_eq!(ids.issue(), Some(TestId(1)));

        let mut ids = IdSequence::<TestId> {
            next: u64::MAX - 1,
            marker: PhantomData,
        };
        assert_eq!(ids.issue(), Some(TestId(u64::MAX - 1)));
        assert_eq!(ids.issue(), None);
        assert_eq!(ids.issue(), None);
    }
}
