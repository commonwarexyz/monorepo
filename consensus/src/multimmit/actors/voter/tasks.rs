//! Worker and completion-permit accounting for the voter's asynchronous tasks.
//!
//! A [`TaskPermit`] holds one worker slot and its completion reservation. Completion, failure,
//! cancellation, and a caught panic all end the same permit. Advancing the generation or shutting
//! down discards every permit, so a late completion cannot touch new capacity. Local signing and
//! aggregation each keep a reserved crypto slot that bulk verification cannot take.

use crate::multimmit::{config::Profile, machine::Generation};
use commonware_cryptography::Digest;
use std::collections::BTreeMap;

/// One class of asynchronous work issued by the serial authority.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(usize)]
pub(crate) enum TaskClass {
    LocalBuild,
    LocalCustody,
    LocalSigning,
    CriticalAggregation,
    CriticalVerification,
    BulkCrypto,
}

impl TaskClass {
    /// The number of task classes: one past the last class's counter index.
    const COUNT: usize = Self::BulkCrypto as usize + 1;

    /// Every task class, in counter-index order.
    #[cfg(test)]
    const ALL: [Self; Self::COUNT] = [
        Self::LocalBuild,
        Self::LocalCustody,
        Self::LocalSigning,
        Self::CriticalAggregation,
        Self::CriticalVerification,
        Self::BulkCrypto,
    ];
}

/// Crypto slots local signing keeps free of bulk work, and aggregation cannot take while no
/// signing task runs.
const RESERVED_SIGNING: usize = 1;

/// Crypto slots aggregation keeps free of bulk work, and signing cannot take while no aggregation
/// task runs.
const RESERVED_AGGREGATION: usize = 1;

/// The smallest crypto budget: both reserved slots and one bulk slot.
const MIN_CRYPTO_TASKS: usize = RESERVED_SIGNING + RESERVED_AGGREGATION + 1;

/// Worker and completion reservation returned when a task ends.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TaskPermit {
    id: u64,
    generation: Generation,
    class: TaskClass,
    units: usize,
}

impl TaskPermit {
    pub(crate) const fn id(&self) -> u64 {
        self.id
    }

    pub(crate) const fn generation(&self) -> Generation {
        self.generation
    }
}

/// Bounded task policy with independent view-verification capacity and two reserved crypto slots.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct TaskLimits {
    local_custody: usize,
    crypto_tasks: usize,
    critical_verification: usize,
}

impl TaskLimits {
    /// Derives the limits for `profile`: one custody slot per pipelined block, a crypto slot per
    /// cached artifact and outbox effect, and one full verification batch of view-critical
    /// verification.
    pub(crate) fn derive<D: Digest>(profile: &Profile<D>) -> Self {
        let resources = profile.resources();
        Self::new(
            profile.codec().pipeline_depth(),
            resources
                .max_cached_artifacts()
                .saturating_add(resources.max_outbox_effects())
                .max(MIN_CRYPTO_TASKS),
            resources.max_verification_batch(),
        )
    }

    pub(crate) const fn new(
        local_custody: usize,
        crypto_tasks: usize,
        critical_verification: usize,
    ) -> Self {
        Self {
            local_custody,
            crypto_tasks,
            critical_verification,
        }
    }
}

/// Synchronous worker and completion-permit accounting.
pub(crate) struct TaskReservations {
    generation: Generation,
    limits: TaskLimits,
    next_id: u64,
    active: BTreeMap<u64, (TaskClass, usize)>,
    /// Reserved units per task class.
    used: [usize; TaskClass::COUNT],
    stopped: bool,
}

impl TaskReservations {
    pub(crate) const fn new(generation: Generation, limits: TaskLimits) -> Result<Self, TaskError> {
        if limits.local_custody == 0
            || limits.crypto_tasks < MIN_CRYPTO_TASKS
            || limits.critical_verification == 0
        {
            return Err(TaskError::InvalidLimits);
        }
        Ok(Self {
            generation,
            limits,
            next_id: 0,
            active: BTreeMap::new(),
            used: [0; TaskClass::COUNT],
            stopped: false,
        })
    }

    /// Reserves both execution capacity and one completion return path.
    #[cfg(test)]
    pub(crate) fn reserve(&mut self, class: TaskClass) -> Result<TaskPermit, TaskError> {
        self.reserve_units(class, 1)
    }

    /// Reserves the actual worker fanout and one correlated completion path.
    pub(crate) fn reserve_units(
        &mut self,
        class: TaskClass,
        units: usize,
    ) -> Result<TaskPermit, TaskError> {
        if self.stopped {
            return Err(TaskError::Stopped);
        }
        if units == 0 {
            return Err(TaskError::InvalidLimits);
        }
        let used = |class: TaskClass| self.used[class as usize];
        let crypto_used = used(TaskClass::LocalSigning)
            .checked_add(used(TaskClass::CriticalAggregation))
            .and_then(|total| total.checked_add(used(TaskClass::BulkCrypto)))
            .ok_or(TaskError::Accounting)?;
        let crypto_tasks = self.limits.crypto_tasks;
        match class {
            TaskClass::LocalBuild if used(TaskClass::LocalBuild) > 0 => {
                return Err(TaskError::ClassFull);
            }
            TaskClass::LocalCustody
                if used(TaskClass::LocalCustody) >= self.limits.local_custody =>
            {
                return Err(TaskError::ClassFull);
            }
            TaskClass::LocalSigning
                if crypto_used.saturating_add(units) > crypto_tasks
                    || (used(TaskClass::CriticalAggregation) == 0
                        && crypto_used.saturating_add(units)
                            > crypto_tasks - RESERVED_AGGREGATION) =>
            {
                return Err(TaskError::ClassFull);
            }
            TaskClass::CriticalAggregation
                if units != 1
                    || crypto_used.saturating_add(units) > crypto_tasks
                    || (used(TaskClass::LocalSigning) == 0
                        && crypto_used >= crypto_tasks - RESERVED_SIGNING) =>
            {
                return Err(TaskError::ClassFull);
            }
            TaskClass::CriticalVerification
                if used(TaskClass::CriticalVerification).saturating_add(units)
                    > self.limits.critical_verification =>
            {
                return Err(TaskError::ClassFull);
            }
            TaskClass::BulkCrypto
                if used(TaskClass::BulkCrypto).saturating_add(units)
                    > crypto_tasks - RESERVED_SIGNING - RESERVED_AGGREGATION
                    || crypto_used.saturating_add(units) > crypto_tasks =>
            {
                return Err(TaskError::ClassFull);
            }
            TaskClass::LocalBuild | TaskClass::LocalCustody if units != 1 => {
                return Err(TaskError::InvalidLimits);
            }
            _ => {}
        }

        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or(TaskError::IdExhausted)?;
        self.used[class as usize] += units;
        self.active.insert(id, (class, units));
        Ok(TaskPermit {
            id,
            generation: self.generation,
            class,
            units,
        })
    }

    /// Returns the reservation of a task that completed, failed, was cancelled, or panicked.
    pub(crate) fn finish(&mut self, permit: TaskPermit) -> Result<(), TaskError> {
        if permit.generation != self.generation {
            return Err(TaskError::StaleGeneration);
        }
        let Some((class, units)) = self.active.get(&permit.id).copied() else {
            return Err(TaskError::UnknownPermit);
        };
        if (class, units) != (permit.class, permit.units) {
            return Err(TaskError::MismatchedPermit);
        }
        self.release(permit.id, class, units)
    }

    /// Starts a new process generation and invalidates all old volatile capabilities.
    pub(crate) fn advance_generation(
        &mut self,
        generation: Generation,
    ) -> Result<usize, TaskError> {
        if generation <= self.generation {
            return Err(TaskError::StaleGeneration);
        }
        let released = self.clear();
        self.generation = generation;
        self.stopped = false;
        Ok(released)
    }

    /// Reconciles every permit before the executor shuts down.
    pub(crate) fn shutdown(&mut self) -> usize {
        self.stopped = true;
        self.clear()
    }

    fn clear(&mut self) -> usize {
        let released = self.active.len();
        self.active.clear();
        self.used = [0; TaskClass::COUNT];
        released
    }

    fn release(&mut self, id: u64, class: TaskClass, units: usize) -> Result<(), TaskError> {
        if self.active.remove(&id) != Some((class, units)) {
            return Err(TaskError::MismatchedPermit);
        }
        let used = &mut self.used[class as usize];
        *used = used.checked_sub(units).ok_or(TaskError::Accounting)?;
        Ok(())
    }

    pub(crate) const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns whether work issued in `generation` belongs to a superseded task generation.
    pub(crate) fn is_stale(&self, generation: Generation) -> bool {
        generation != self.generation
    }

    /// Returns whether a local block build holds its slot.
    pub(crate) const fn local_build_active(&self) -> bool {
        self.used[TaskClass::LocalBuild as usize] > 0
    }

    /// Returns the number of local custody tasks holding slots.
    pub(crate) const fn local_custody_active(&self) -> usize {
        self.used[TaskClass::LocalCustody as usize]
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum TaskError {
    #[error("task limits are invalid")]
    InvalidLimits,
    #[error("the task class has no available worker and completion reservation")]
    ClassFull,
    #[error("the task reservation id exhausted")]
    IdExhausted,
    #[error("the task permit belongs to a stale process generation")]
    StaleGeneration,
    #[error("the task permit is unknown")]
    UnknownPermit,
    #[error("the task permit does not match its reservation")]
    MismatchedPermit,
    #[error("task permit accounting is inconsistent")]
    Accounting,
    #[error("the task executor is stopped")]
    Stopped,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_classes_index_their_counters() {
        for (index, class) in TaskClass::ALL.into_iter().enumerate() {
            assert_eq!(class as usize, index);
        }
    }

    #[test]
    fn task_saturation_preserves_named_critical_capacity() {
        let mut tasks =
            TaskReservations::new(Generation::new(7), TaskLimits::new(3, 5, 7)).unwrap();
        let bulk = (0..3)
            .map(|_| tasks.reserve(TaskClass::BulkCrypto).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            tasks.reserve(TaskClass::BulkCrypto),
            Err(TaskError::ClassFull)
        );

        let signing = tasks.reserve(TaskClass::LocalSigning).unwrap();
        let aggregation = tasks.reserve(TaskClass::CriticalAggregation).unwrap();
        tasks.finish(signing).unwrap();
        tasks.finish(aggregation).unwrap();
        for permit in bulk {
            tasks.finish(permit).unwrap();
        }
    }

    #[test]
    fn critical_verification_admits_a_full_cohort_under_crypto_saturation() {
        let mut tasks =
            TaskReservations::new(Generation::new(7), TaskLimits::new(3, 5, 7)).unwrap();
        tasks.reserve_units(TaskClass::BulkCrypto, 3).unwrap();
        tasks.reserve(TaskClass::LocalSigning).unwrap();
        tasks.reserve(TaskClass::CriticalAggregation).unwrap();
        // A finished cohort returns its full reservation, however many times it cycles.
        for _ in 0..4 {
            let cohort = tasks
                .reserve_units(TaskClass::CriticalVerification, 7)
                .unwrap();
            assert_eq!(
                tasks.reserve(TaskClass::CriticalVerification),
                Err(TaskError::ClassFull)
            );
            tasks.finish(cohort).unwrap();
        }
        assert_eq!(
            tasks.reserve_units(TaskClass::CriticalVerification, 8),
            Err(TaskError::ClassFull)
        );
        let stale = tasks
            .reserve_units(TaskClass::CriticalVerification, 7)
            .unwrap();
        tasks.advance_generation(Generation::new(8)).unwrap();
        assert_eq!(tasks.finish(stale), Err(TaskError::StaleGeneration));
        tasks
            .reserve_units(TaskClass::CriticalVerification, 7)
            .unwrap();
        assert_eq!(tasks.shutdown(), 1);
        assert_eq!(
            tasks.reserve(TaskClass::CriticalVerification),
            Err(TaskError::Stopped)
        );
    }

    #[test]
    fn local_custody_capacity_is_bounded_and_independent() {
        let mut tasks =
            TaskReservations::new(Generation::new(7), TaskLimits::new(3, 3, 7)).unwrap();
        let build = tasks.reserve(TaskClass::LocalBuild).unwrap();
        let custody = (0..3)
            .map(|_| tasks.reserve(TaskClass::LocalCustody).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            tasks.reserve(TaskClass::LocalCustody),
            Err(TaskError::ClassFull)
        );

        tasks.finish(build).unwrap();
        for permit in custody {
            tasks.finish(permit).unwrap();
        }
    }

    #[test]
    fn stale_generation_cannot_release_current_capacity() {
        let mut tasks =
            TaskReservations::new(Generation::new(11), TaskLimits::new(3, 3, 7)).unwrap();
        let old = tasks.reserve(TaskClass::LocalBuild).unwrap();
        assert_eq!(tasks.advance_generation(Generation::new(12)).unwrap(), 1);
        let current = tasks.reserve(TaskClass::LocalBuild).unwrap();
        assert_eq!(tasks.finish(old), Err(TaskError::StaleGeneration));
        tasks.finish(current).unwrap();
    }

    #[test]
    fn shutdown_reconciles_every_permit_and_rejects_new_work() {
        let mut tasks =
            TaskReservations::new(Generation::new(3), TaskLimits::new(3, 4, 7)).unwrap();
        tasks.reserve(TaskClass::LocalBuild).unwrap();
        tasks.reserve(TaskClass::LocalCustody).unwrap();
        tasks.reserve(TaskClass::LocalSigning).unwrap();
        assert_eq!(tasks.shutdown(), 3);
        assert_eq!(
            tasks.reserve(TaskClass::CriticalAggregation),
            Err(TaskError::Stopped)
        );
    }

    #[test]
    fn local_build_is_independent_of_custody_saturation() {
        let mut tasks =
            TaskReservations::new(Generation::new(1), TaskLimits::new(2, 3, 7)).unwrap();
        let first = tasks.reserve(TaskClass::LocalCustody).unwrap();
        let second = tasks.reserve(TaskClass::LocalCustody).unwrap();
        assert_eq!(
            tasks.reserve(TaskClass::LocalCustody),
            Err(TaskError::ClassFull)
        );
        tasks.reserve(TaskClass::LocalBuild).unwrap();
        tasks.finish(first).unwrap();
        let replacement = tasks.reserve(TaskClass::LocalCustody).unwrap();
        tasks.finish(second).unwrap();
        tasks.finish(replacement).unwrap();
    }
}
