//! Test queries over machine steps and capabilities, and test entry points into the machine's
//! durability path.

use crate::multimmit::{
    machine::{
        capability::{Capabilities, Capability},
        durability::{Change, DurableEffect, DurableJob, PersistDirective, PersistJob},
        input::{PollResult, Step, StepError, StepStatus},
        reducer::machine::Machine,
        verification::VerifyJob,
    },
    types::Activity,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};

/// Test queries over the capabilities a step, a poll, or a drain returned.
pub(crate) trait CapabilitiesExt<V: Variant, D: Digest> {
    /// Returns the capabilities in issuance order.
    fn effects(&self) -> &[Capability<V, D>];

    /// Returns the barriers, in issuance order.
    fn journals(&self) -> Vec<&PersistDirective<V, D>> {
        self.effects()
            .iter()
            .filter_map(|capability| match capability {
                Capability::Journal(directive) => Some(directive),
                _ => None,
            })
            .collect()
    }

    /// Returns the persistence job of the only barrier.
    ///
    /// # Panics
    ///
    /// Panics unless exactly one barrier was issued.
    fn persist_job(&self) -> PersistJob<V, D> {
        match self.journals().as_slice() {
            [directive] => directive.job.clone(),
            other => panic!("expected exactly one barrier, found {}", other.len()),
        }
    }

    /// Returns the released outbox effects, in release order.
    fn released(&self) -> Vec<&DurableJob<V, D>> {
        self.effects()
            .iter()
            .filter_map(|capability| match capability {
                Capability::Released(job) => Some(job),
                _ => None,
            })
            .collect()
    }

    /// Returns the released signing jobs, in release order.
    fn released_signing(&self) -> Vec<&DurableJob<V, D>> {
        self.released()
            .into_iter()
            .filter(|job| matches!(job.request(), DurableEffect::Sign(_)))
            .collect()
    }

    /// Returns the released publications, in release order.
    fn released_publications(&self) -> Vec<&DurableJob<V, D>> {
        self.released()
            .into_iter()
            .filter(|job| matches!(job.request(), DurableEffect::Publish(_)))
            .collect()
    }

    /// Returns the only verification job.
    ///
    /// # Panics
    ///
    /// Panics unless exactly one verification job was issued.
    fn verify_job(&self) -> VerifyJob<V, D> {
        let jobs = self
            .effects()
            .iter()
            .filter_map(|capability| match capability {
                Capability::Verify(job) => Some(job.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        match <[_; 1]>::try_from(jobs) {
            Ok([job]) => job,
            Err(jobs) => panic!(
                "expected exactly one verification job, found {}",
                jobs.len()
            ),
        }
    }
}

impl<V: Variant, D: Digest> CapabilitiesExt<V, D> for [Capability<V, D>] {
    fn effects(&self) -> &[Capability<V, D>] {
        self
    }
}

impl<V: Variant, D: Digest> CapabilitiesExt<V, D> for Vec<Capability<V, D>> {
    fn effects(&self) -> &[Capability<V, D>] {
        self
    }
}

impl<V: Variant, D: Digest> CapabilitiesExt<V, D> for Step<V, D> {
    fn effects(&self) -> &[Capability<V, D>] {
        self.capabilities()
    }
}

impl<V: Variant, D: Digest> CapabilitiesExt<V, D> for PollResult<V, D> {
    fn effects(&self) -> &[Capability<V, D>] {
        self.capabilities()
    }
}

/// Construction of steps merged across several machine turns.
pub(crate) trait StepExt<V: Variant, D: Digest> {
    /// Builds a step from merged parts.
    fn for_tests(
        status: StepStatus<D>,
        capabilities: Capabilities<V, D>,
        activities: Vec<Activity<V, D>>,
    ) -> Self;
}

impl<V: Variant, D: Digest> StepExt<V, D> for Step<V, D> {
    fn for_tests(
        status: StepStatus<D>,
        capabilities: Capabilities<V, D>,
        activities: Vec<Activity<V, D>>,
    ) -> Self {
        Self {
            status,
            capabilities,
            activities,
        }
    }
}

/// Test entry points into the machine's durability path, standing in for the components that
/// stage these changes in production.
pub(crate) trait MachineExt<V: Variant, D: Digest> {
    /// Queues `effect` in the outbox and hands any eligible barrier to the journal.
    fn reserve_test_effect(&mut self, effect: DurableEffect<V, D>)
    -> Result<Step<V, D>, StepError>;

    /// Stages `change` and hands any eligible barrier to the journal.
    fn stage_test_change(&mut self, change: Change<V, D>) -> Result<Step<V, D>, StepError>;
}

impl<H: Hasher, V: Variant> MachineExt<V, H::Digest> for Machine<H, V> {
    fn reserve_test_effect(
        &mut self,
        effect: DurableEffect<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let mut capabilities = self.reserve_effect(effect)?;
        capabilities.extend(self.emit_staged());
        Ok(Step::new(StepStatus::Accepted, capabilities))
    }

    fn stage_test_change(
        &mut self,
        change: Change<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let mut capabilities = self.reserve_change(change)?;
        capabilities.extend(self.emit_staged());
        Ok(Step::new(StepStatus::Accepted, capabilities))
    }
}
