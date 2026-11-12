//! Identity of volatile work: process generations, issued job identities, identifier sequences,
//! and job tables.

use core::marker::PhantomData;
use std::collections::BTreeMap;

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

/// How a completion relates to the job table.
pub(crate) enum Admit<'a, J> {
    /// The completion's job is unknown or belongs to another generation.
    Stale,
    /// The completion's job was issued by an earlier generation and is removed.
    Abandoned(J),
    /// The completion's job is outstanding in the current generation.
    Current(&'a J),
}

/// Outstanding volatile jobs by identifier, with the generation that issued each.
pub(crate) struct JobTable<Id, J> {
    jobs: BTreeMap<Id, (Generation, J)>,
}

impl<Id: Copy + Ord, J> JobTable<Id, J> {
    pub(crate) const fn new() -> Self {
        Self {
            jobs: BTreeMap::new(),
        }
    }

    /// Records an issued job.
    pub(crate) fn insert(&mut self, issued: Issued<Id>, job: J) {
        self.jobs.insert(issued.id(), (issued.generation(), job));
    }

    /// Classifies a completion issued as `issued` against the `current` generation.
    ///
    /// A job left from an earlier generation is removed even when the completion itself is
    /// stale, so the caller can release what the job held.
    pub(crate) fn admit(&mut self, issued: Issued<Id>, current: Generation) -> Admit<'_, J> {
        if self
            .jobs
            .get(&issued.id())
            .is_some_and(|(generation, _)| *generation != current)
        {
            let (_, job) = self
                .jobs
                .remove(&issued.id())
                .expect("the job was found above");
            return Admit::Abandoned(job);
        }
        if issued.generation() != current {
            return Admit::Stale;
        }
        match self.jobs.get(&issued.id()) {
            Some((_, job)) => Admit::Current(job),
            None => Admit::Stale,
        }
    }

    /// Keeps only the jobs `keep` selects.
    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&J) -> bool) {
        self.jobs.retain(|_, (_, job)| keep(job));
    }

    /// Removes and returns the job `id`.
    pub(crate) fn remove(&mut self, id: Id) -> Option<J> {
        self.jobs.remove(&id).map(|(_, job)| job)
    }

    /// Returns the job `id`, if outstanding.
    pub(crate) fn get(&self, id: Id) -> Option<&J> {
        self.jobs.get(&id).map(|(_, job)| job)
    }

    /// Returns every outstanding job.
    pub(crate) fn values(&self) -> impl Iterator<Item = &J> {
        self.jobs.values().map(|(_, job)| job)
    }

    /// Returns how many jobs are outstanding.
    pub(crate) fn len(&self) -> usize {
        self.jobs.len()
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

    #[test]
    fn job_table_admits_only_current_jobs() {
        let old = Generation::new(1);
        let current = old.next().expect("the generation advances");
        let mut jobs = JobTable::new();
        jobs.insert(Issued::new(TestId(0), old), "abandoned");
        jobs.insert(Issued::new(TestId(1), current), "current");
        assert_eq!(jobs.len(), 2);

        // An unknown job is stale.
        assert!(matches!(
            jobs.admit(Issued::new(TestId(2), current), current),
            Admit::Stale
        ));
        // A completion from an earlier generation leaves the current job in place.
        assert!(matches!(
            jobs.admit(Issued::new(TestId(1), old), current),
            Admit::Stale
        ));
        assert!(matches!(
            jobs.admit(Issued::new(TestId(1), current), current),
            Admit::Current(&"current")
        ));
        // A job left by an earlier generation is removed even for a stale completion.
        assert!(matches!(
            jobs.admit(Issued::new(TestId(0), old), current),
            Admit::Abandoned("abandoned")
        ));
        assert!(jobs.get(TestId(0)).is_none());

        jobs.retain(|job| *job != "current");
        assert_eq!(jobs.len(), 0);
        assert_eq!(Generation::new(u64::MAX).next(), None);
    }
}
