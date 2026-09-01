//! Synchronous drivers for the state the actors own.

use super::verifier::verify;
use crate::multimmit::{
    machine::{
        Capability, CoreState, CoreTurn, CryptoCompletion, CryptoJob, Input,
        LqcAggregateCompletion, PersistDirective, VerifyJob, VqcAggregateCompletion,
    },
    scheme::bls12381_threshold::Scheme,
    types::Artifact,
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::MinPk, ed25519, sha256::Digest as Sha256Digest,
};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;

/// Runs Core one bounded turn at a time, the way the voter does, and completes each capability
/// inline.
///
/// Persistence is acknowledged at once, and verification and leader aggregation run with real
/// cryptography on the calling thread; a driver built with [`Self::holding_verifications`] keeps
/// verification jobs for the test instead. Every other capability is dropped: publications,
/// timers, resolution, and application work change Core state only through completions these
/// schedules never deliver.
pub(crate) struct CoreDriver<'a> {
    verifier: &'a Scheme<ed25519::PublicKey, MinPk>,
    held: Option<Vec<VerifyJob<MinPk, Sha256Digest>>>,
}

impl<'a> CoreDriver<'a> {
    /// Creates a driver that verifies and aggregates with `verifier`.
    pub(crate) const fn new(verifier: &'a Scheme<ed25519::PublicKey, MinPk>) -> Self {
        Self {
            verifier,
            held: None,
        }
    }

    /// Keeps every verification job Core issues, for [`Self::take_held`], instead of running it.
    pub(crate) fn holding_verifications(mut self) -> Self {
        self.held = Some(Vec::new());
        self
    }

    /// Takes the verification jobs held so far.
    pub(crate) fn take_held(&mut self) -> Vec<VerifyJob<MinPk, Sha256Digest>> {
        self.held.as_mut().map(std::mem::take).unwrap_or_default()
    }

    /// Runs one Core turn and completes its capabilities. Returns `false` once Core is idle.
    pub(crate) fn step(&mut self, core: &mut CoreState<Sha256, MinPk>) -> bool {
        let capabilities = match core.next_action(|_| {}).expect("Core advances") {
            CoreTurn::Input(serviced) => serviced.transition.into_parts().0,
            CoreTurn::Work(work) => work.into_parts().0,
            CoreTurn::YieldRequired => {
                core.resume_after_yield().expect("Core resumes after yield");
                return true;
            }
            CoreTurn::Idle => return false,
        };
        for capability in capabilities {
            self.complete(core, capability);
        }
        true
    }

    /// Runs Core until it is idle.
    pub(crate) fn settle(&mut self, core: &mut CoreState<Sha256, MinPk>) {
        while self.step(core) {}
    }

    /// Hands `artifacts` to Core as one peer observation.
    pub(crate) fn observe(
        &self,
        core: &mut CoreState<Sha256, MinPk>,
        artifacts: Vec<Artifact<MinPk, Sha256Digest>>,
    ) {
        let identified = artifacts
            .into_iter()
            .map(|artifact| artifact.identify::<Sha256>(&mut Vec::new()))
            .collect::<Vec<_>>();
        let resident_bytes = identified
            .iter()
            .map(|identified| identified.id.encode_size() + identified.artifact.encode_size())
            .sum();
        core.observe(identified, resident_bytes)
            .expect("Core accepts the observation");
    }

    /// Runs Core until it is idle, handing it `artifacts` as soon as it is live.
    ///
    /// # Panics
    ///
    /// Panics if Core idles before it goes live.
    pub(crate) fn settle_observing(
        &mut self,
        core: &mut CoreState<Sha256, MinPk>,
        artifacts: Vec<Artifact<MinPk, Sha256Digest>>,
    ) {
        let mut pending = Some(artifacts);
        while self.step(core) {
            if core.machine().inspect().is_live()
                && let Some(artifacts) = pending.take()
            {
                self.observe(core, artifacts);
            }
        }
        assert!(pending.is_none(), "Core idled before it went live");
    }

    fn complete(
        &mut self,
        core: &mut CoreState<Sha256, MinPk>,
        capability: Capability<MinPk, Sha256Digest>,
    ) {
        match capability {
            Capability::Journal(PersistDirective { job, .. }) => {
                core.enqueue(Input::Persisted(job.ack()))
                    .expect("Core accepts the acknowledgement");
            }
            Capability::Verify(job) => {
                if let Some(held) = &mut self.held {
                    held.push(job);
                    return;
                }
                let completion =
                    verify::<Sha256, _, _>(&job, &mut test_rng(), self.verifier, &Sequential);
                core.enqueue(Input::Verified(completion))
                    .expect("Core accepts the verification");
            }
            Capability::Crypto(CryptoJob::AggregateVqc(job)) => {
                let messages = job.messages().collect::<Vec<_>>();
                let certificate = self
                    .verifier
                    .assemble_vqc::<Sha256, _>(job.leader().clone(), &messages, &Sequential)
                    .expect("aggregation succeeds");
                core.enqueue(Input::Crypto(CryptoCompletion::Vqc(Box::new(
                    VqcAggregateCompletion::prepare::<Sha256>(
                        &job,
                        certificate,
                        core.machine().profile().codec(),
                    )
                    .expect("assembled V-QCs match their transcripts"),
                ))))
                .expect("Core accepts the V-QC aggregation");
            }
            Capability::Crypto(CryptoJob::AggregateLqc(job)) => {
                let votes = job.votes().cloned().collect::<Vec<_>>();
                let certificate = self
                    .verifier
                    .assemble_lqc::<Sha256, _>(job.leader().clone(), &votes, &Sequential)
                    .expect("aggregation succeeds");
                core.enqueue(Input::Crypto(CryptoCompletion::Lqc(Box::new(
                    LqcAggregateCompletion::prepare::<Sha256>(
                        &job,
                        certificate,
                        core.machine().profile().codec(),
                    )
                    .expect("assembled L-QCs match their votes"),
                ))))
                .expect("Core accepts the L-QC aggregation");
            }
            _ => {}
        }
    }
}
