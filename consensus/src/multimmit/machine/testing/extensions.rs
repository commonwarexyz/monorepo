//! Test views and constructors over machine steps, capabilities, effects, and jobs.

use crate::multimmit::{
    machine::{
        capability::{AppJob, Capabilities, Capability, CryptoJob},
        durability::{
            DurableEffect, OutboxEntry, PersistDirective, PersistJob, ProposalPublication,
            Publication, SendRequest, SignRequest,
        },
        finality::LqcAggregateJob,
        input::{PollResult, Step, StepError, StepStatus},
        producer::{BuildJob, CustodyJob},
        reducer::machine::Machine,
        verification::VerifyJob,
    },
    scheme::Scheme,
    types::{Activity, Artifact, ArtifactBatch},
};
use commonware_cryptography::{Digest, Hasher};
use std::sync::Arc;

/// Test queries over the capabilities a step, a poll, or a drain returned.
pub(crate) trait CapabilitiesExt<S: Scheme, D: Digest> {
    /// Returns the capabilities in issuance order.
    fn effects(&self) -> &[Capability<S, D>];

    /// Returns whether any capability satisfies `predicate`.
    fn has(&self, predicate: impl FnMut(&Capability<S, D>) -> bool) -> bool {
        self.effects().iter().any(predicate)
    }

    /// Returns the first value `select` extracts from a capability.
    fn find<'a, T>(&'a self, select: impl FnMut(&'a Capability<S, D>) -> Option<T>) -> Option<T>
    where
        S: 'a,
        D: 'a,
    {
        self.effects().iter().find_map(select)
    }

    /// Returns the persistence directive of the only barrier.
    ///
    /// # Panics
    ///
    /// Panics unless exactly one barrier was issued.
    fn persist_directive(&self) -> PersistDirective<S, D> {
        let mut directives = self.effects().iter().filter_map(|effect| match effect {
            Capability::Journal(directive) => Some(directive),
            _ => None,
        });
        let directive = directives
            .next()
            .expect("one durable reservation must emit a persistence job")
            .clone();
        assert!(
            directives.next().is_none(),
            "expected exactly one persistence barrier"
        );
        directive
    }

    /// Returns the persistence job of the only barrier.
    ///
    /// # Panics
    ///
    /// Panics unless exactly one barrier was issued.
    fn persist_job(&self) -> PersistJob<S, D> {
        self.persist_directive().job
    }

    /// Returns the first verification job.
    ///
    /// # Panics
    ///
    /// Panics if no verification job was issued.
    fn verify_job(&self) -> VerifyJob<S, D> {
        self.find(|effect| match effect {
            Capability::Verify(job) => Some(job.clone()),
            _ => None,
        })
        .expect("a verification job must be issued")
    }

    /// Returns the first L-QC aggregation job, if one was issued.
    fn aggregate_lqc(&self) -> Option<LqcAggregateJob<S, D>> {
        self.find(|effect| match effect {
            Capability::Crypto(CryptoJob::AggregateLqc(job)) => Some(job.clone()),
            _ => None,
        })
    }

    /// Returns the first application build job.
    ///
    /// # Panics
    ///
    /// Panics if no build job was issued.
    fn build_job(&self) -> BuildJob<D> {
        self.find(|effect| match effect {
            Capability::Application(AppJob::Build(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("ready work must emit a build job")
    }

    /// Returns the first application custody job.
    ///
    /// # Panics
    ///
    /// Panics if no custody job was issued.
    fn custody_job(&self) -> CustodyJob<D> {
        self.find(|effect| match effect {
            Capability::Application(AppJob::Custody(job)) => Some(job.clone()),
            _ => None,
        })
        .expect("a completed build must emit a custody job")
    }
}

impl<S: Scheme, D: Digest> CapabilitiesExt<S, D> for [Capability<S, D>] {
    fn effects(&self) -> &[Capability<S, D>] {
        self
    }
}

impl<S: Scheme, D: Digest> CapabilitiesExt<S, D> for Step<S, D> {
    fn effects(&self) -> &[Capability<S, D>] {
        self.capabilities()
    }
}

impl<S: Scheme, D: Digest> CapabilitiesExt<S, D> for PollResult<S, D> {
    fn effects(&self) -> &[Capability<S, D>] {
        self.capabilities()
    }
}

/// Test-only construction of merged machine steps.
pub(crate) trait StepExt<S: Scheme, D: Digest> {
    /// Builds a step from parts collected across several machine turns.
    fn for_tests(
        status: StepStatus<D>,
        capabilities: impl Into<Capabilities<S, D>>,
        activities: Vec<Activity<S, D>>,
    ) -> Self;
}

impl<S: Scheme, D: Digest> StepExt<S, D> for Step<S, D> {
    fn for_tests(
        status: StepStatus<D>,
        capabilities: impl Into<Capabilities<S, D>>,
        activities: Vec<Activity<S, D>>,
    ) -> Self {
        Self {
            status,
            capabilities: capabilities.into(),
            activities,
        }
    }
}

/// Test views of a durable effect or queued publication by its one-item or several-item form.
pub(crate) trait EffectExt<S: Scheme, D: Digest> {
    /// Returns the signing requests, if the value signs.
    fn signing(&self) -> Option<&[SignRequest<S, D>]>;

    /// Returns the publication, if the value publishes.
    fn published(&self) -> Option<&Publication<S, D>>;

    /// Returns the request of a one-request signing effect.
    fn sign_one(&self) -> Option<&SignRequest<S, D>> {
        match self.signing()? {
            [request] => Some(request),
            _ => None,
        }
    }

    /// Returns the requests of a signing effect with several requests.
    fn sign_many(&self) -> Option<&[SignRequest<S, D>]> {
        self.signing().filter(|requests| requests.len() > 1)
    }

    /// Returns the artifact of a one-artifact broadcast.
    fn broadcast_one(&self) -> Option<&Arc<Artifact<S, D>>> {
        match self.published()? {
            Publication::Broadcast(artifacts) => match artifacts.as_ref() {
                [artifact] => Some(artifact),
                _ => None,
            },
            Publication::Propose(_) | Publication::Send(_) => None,
        }
    }

    /// Returns the artifacts of a broadcast with several artifacts.
    fn broadcast_many(&self) -> Option<&ArtifactBatch<S, D>> {
        match self.published()? {
            Publication::Broadcast(artifacts) if artifacts.len() > 1 => Some(artifacts),
            _ => None,
        }
    }

    /// Returns the request of a one-request send.
    fn send_one(&self) -> Option<&SendRequest<S, D>> {
        match self.published()? {
            Publication::Send(requests) => match requests.as_ref() {
                [request] => Some(request),
                _ => None,
            },
            Publication::Broadcast(_) | Publication::Propose(_) => None,
        }
    }

    /// Returns the requests of a send with several requests.
    fn send_many(&self) -> Option<&[SendRequest<S, D>]> {
        match self.published()? {
            Publication::Send(requests) if requests.len() > 1 => Some(requests),
            _ => None,
        }
    }

    /// Returns the proposal publication.
    fn proposal(&self) -> Option<&ProposalPublication<S, D>> {
        match self.published()? {
            Publication::Propose(proposal) => Some(proposal),
            Publication::Broadcast(_) | Publication::Send(_) => None,
        }
    }
}

impl<S: Scheme, D: Digest> EffectExt<S, D> for DurableEffect<S, D> {
    fn signing(&self) -> Option<&[SignRequest<S, D>]> {
        self.sign_requests()
    }

    fn published(&self) -> Option<&Publication<S, D>> {
        self.publication()
    }
}

impl<S: Scheme, D: Digest> EffectExt<S, D> for OutboxEntry<S, D> {
    fn signing(&self) -> Option<&[SignRequest<S, D>]> {
        None
    }

    fn published(&self) -> Option<&Publication<S, D>> {
        Some(self.publication())
    }
}

/// Test-only entry points into the machine's durability path.
pub(crate) trait MachineExt<S: Scheme, D: Digest> {
    /// Reserves a synthetic durable action and emits its persistence barrier when one is ready.
    fn reserve_test_effect(&mut self, effect: DurableEffect<S, D>)
    -> Result<Step<S, D>, StepError>;
}

impl<H: Hasher, S: Scheme> MachineExt<S, H::Digest> for Machine<H, S> {
    fn reserve_test_effect(
        &mut self,
        effect: DurableEffect<S, H::Digest>,
    ) -> Result<Step<S, H::Digest>, StepError> {
        let mut capabilities = self.reserve_effect(effect)?;
        capabilities.extend(self.emit_staged());
        Ok(Step::new(StepStatus::Accepted, capabilities))
    }
}
