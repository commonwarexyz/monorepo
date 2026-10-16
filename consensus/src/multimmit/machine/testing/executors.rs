//! Symbolic executors that complete machine capabilities without I/O.

use crate::multimmit::{
    machine::{
        capability::{AppJob, Capability, ChainCommand, CryptoJob, TimerCommand},
        durability::{DurableEffect, EffectCompletion, PersistDirective, PersistJob},
        input::{
            Aggregated, BlockValidity, BuildCompletion, CryptoCompletion, CustodyCompletion, Input,
            Now, TimerFamily, ValidationCompletion,
        },
        job::Generation,
        verification::{Verdict, VerificationCompletion, VerifyJob},
    },
    scheme::bls12381::{Scheme, SignatureVerification},
    types::{Artifact, ArtifactId},
};
use commonware_cryptography::{
    Digest, Hasher as _, Sha256, bls12381::primitives::variant::Variant, ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_parallel::Sequential;
use commonware_utils::TestRng;
use std::collections::BTreeMap;

/// What an executor did with one capability.
#[derive(Clone, Debug)]
pub(crate) enum Execution<V: Variant, D: Digest> {
    /// Submit this completion through the production input path.
    Input(Input<V, D>),
    /// Durably append and acknowledge this barrier.
    Persist(PersistJob<V, D>),
    /// The capability was consumed and completes later, or never.
    Absorbed,
}

/// A policy that completes some of the capabilities a machine issues.
pub(crate) trait Executor<V: Variant, D: Digest> {
    /// Returns what this executor does with `capability`, or `None` when it does not handle it.
    ///
    /// `generation` is the machine's current process generation, which volatile executors stamp
    /// on the completions they produce.
    fn execute(
        &mut self,
        capability: &Capability<V, D>,
        generation: Generation,
    ) -> Option<Execution<V, D>>;
}

/// Tries `self.0` first, then `self.1`.
impl<V: Variant, D: Digest, A: Executor<V, D>, B: Executor<V, D>> Executor<V, D> for (A, B) {
    fn execute(
        &mut self,
        capability: &Capability<V, D>,
        generation: Generation,
    ) -> Option<Execution<V, D>> {
        self.0
            .execute(capability, generation)
            .or_else(|| self.1.execute(capability, generation))
    }
}

/// Returns scripted verdicts: a fallback, overridden per artifact.
#[derive(Clone, Debug)]
pub(crate) struct SymbolicVerifier<D: Digest> {
    default: bool,
    verdicts: BTreeMap<ArtifactId<D>, bool>,
}

impl<D: Digest> SymbolicVerifier<D> {
    /// Creates a verifier answering `default` for every artifact.
    pub(crate) const fn new(default: bool) -> Self {
        Self {
            default,
            verdicts: BTreeMap::new(),
        }
    }

    /// Completes `job` with one verdict per item, in item order.
    pub(crate) fn complete<V: Variant>(&self, job: &VerifyJob<V, D>) -> VerificationCompletion<D> {
        let verdicts = job
            .items()
            .iter()
            .map(|item| {
                let ticket = item.ticket();
                let valid = self
                    .verdicts
                    .get(&ticket.artifact())
                    .copied()
                    .unwrap_or(self.default);
                Verdict::new(ticket, valid)
            })
            .collect();
        VerificationCompletion::new(job.issued(), verdicts)
    }
}

impl<V: Variant, D: Digest> Executor<V, D> for SymbolicVerifier<D> {
    fn execute(&mut self, capability: &Capability<V, D>, _: Generation) -> Option<Execution<V, D>> {
        let Capability::Verify(job) = capability else {
            return None;
        };
        Some(Execution::Input(Input::Verified(self.complete(job))))
    }
}

/// Appends and acknowledges every journal barrier at once.
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct SymbolicPersistence;

impl<V: Variant, D: Digest> Executor<V, D> for SymbolicPersistence {
    fn execute(&mut self, capability: &Capability<V, D>, _: Generation) -> Option<Execution<V, D>> {
        let Capability::Journal(PersistDirective { job, .. }) = capability else {
            return None;
        };
        Some(Execution::Persist(job.clone()))
    }
}

/// Signs released signing requests with one participant's keys and acknowledges released
/// publications, recording them in release order.
pub(crate) struct SymbolicSigner<V: Variant> {
    scheme: Scheme<ed25519::PublicKey, V>,
    /// Every released publication, in release order.
    pub(crate) published: Vec<Artifact<V, Sha256Digest>>,
}

impl<V: Variant> SymbolicSigner<V> {
    /// Creates a signer holding `scheme`'s keys.
    pub(crate) const fn new(scheme: Scheme<ed25519::PublicKey, V>) -> Self {
        Self {
            scheme,
            published: Vec::new(),
        }
    }
}

impl<V: Variant> Executor<V, Sha256Digest> for SymbolicSigner<V> {
    fn execute(
        &mut self,
        capability: &Capability<V, Sha256Digest>,
        _: Generation,
    ) -> Option<Execution<V, Sha256Digest>> {
        let Capability::Released(job) = capability else {
            return None;
        };
        let completion = match job.request() {
            DurableEffect::Sign(effect) => EffectCompletion::signed(
                job.issued(),
                effect
                    .requests()
                    .iter()
                    .map(|request| {
                        request
                            .sign(&self.scheme)
                            .expect("the signer owns the reserved subject")
                            .into()
                    })
                    .collect(),
            ),
            DurableEffect::Publish(publication) => {
                self.published.extend(
                    publication
                        .artifacts()
                        .iter()
                        .map(|artifact| (**artifact).clone()),
                );
                EffectCompletion::delivered(job.issued())
            }
        };
        Some(Execution::Input(Input::EffectCompleted(completion)))
    }
}

/// Builds a block above every requested parent, custodies every built block, and returns a
/// fixed verdict for every block a chain plane validates.
#[derive(Copy, Clone, Debug)]
pub(crate) struct SymbolicApplication {
    validity: BlockValidity,
}

impl SymbolicApplication {
    /// Creates an application answering `validity` for every validated block.
    pub(crate) const fn new(validity: BlockValidity) -> Self {
        Self { validity }
    }
}

impl<V: Variant> Executor<V, Sha256Digest> for SymbolicApplication {
    fn execute(
        &mut self,
        capability: &Capability<V, Sha256Digest>,
        generation: Generation,
    ) -> Option<Execution<V, Sha256Digest>> {
        let input = match capability {
            Capability::Application(AppJob::Build(job)) => {
                let parent = job.parent();
                let body = Sha256::hash(&[parent.digest().as_ref()]);
                Input::BlockBuilt(BuildCompletion::new(job.issued(), parent, Some(body)))
            }
            Capability::Application(AppJob::Custody(job)) => {
                Input::BlockCustodied(CustodyCompletion::new(job.issued(), job.header().clone()))
            }
            Capability::Application(AppJob::Recall(_)) => return Some(Execution::Absorbed),
            Capability::Chain(_, ChainCommand::Validate(block)) => {
                Input::Validated(ValidationCompletion::new(
                    generation,
                    block.header().block_ref::<Sha256>(),
                    self.validity,
                ))
            }
            Capability::Chain(_, ChainCommand::Accepted(_)) => return Some(Execution::Absorbed),
            _ => return None,
        };
        Some(Execution::Input(input))
    }
}

/// Aggregates every requested certificate with a committee's keyless verifier.
pub(crate) struct SymbolicCrypto<V: Variant> {
    verifier: Scheme<ed25519::PublicKey, V>,
}

impl<V: Variant> SymbolicCrypto<V> {
    /// Creates an aggregator over `verifier`.
    pub(crate) const fn new(verifier: Scheme<ed25519::PublicKey, V>) -> Self {
        Self { verifier }
    }
}

impl<V: Variant> Executor<V, Sha256Digest> for SymbolicCrypto<V> {
    fn execute(
        &mut self,
        capability: &Capability<V, Sha256Digest>,
        _: Generation,
    ) -> Option<Execution<V, Sha256Digest>> {
        let Capability::Crypto(job) = capability else {
            return None;
        };
        let rng = &mut TestRng::new(0);
        let completion = match job {
            CryptoJob::AggregateVqc(job) => CryptoCompletion::Vqc(Box::new(Aggregated::new(
                job.issued(),
                self.verifier
                    .assemble_vqc(
                        rng,
                        job.parent(),
                        job.votes(),
                        job.paths().to_vec(),
                        SignatureVerification::Preverified,
                        &Sequential,
                    )
                    .expect("the machine selects votes that form a V-QC"),
            ))),
            CryptoJob::AggregateLqc(job) => CryptoCompletion::Lqc(Box::new(Aggregated::new(
                job.issued(),
                self.verifier
                    .assemble_lqc::<_, Sha256, _>(
                        rng,
                        job.leader().clone(),
                        job.votes(),
                        SignatureVerification::Preverified,
                        &Sequential,
                    )
                    .expect("the machine selects votes that form an L-QC"),
            ))),
        };
        Some(Execution::Input(Input::Crypto(completion)))
    }
}

/// A manual clock holding the deadline armed per timer family.
#[derive(Clone, Debug, Default)]
pub(crate) struct ManualClock {
    now: Now,
    deadlines: BTreeMap<TimerFamily, Now>,
}

impl ManualClock {
    /// Returns the current reading.
    pub(crate) const fn now(&self) -> Now {
        self.now
    }

    /// Returns the deadline armed for `family`.
    pub(crate) fn deadline(&self, family: TimerFamily) -> Option<Now> {
        self.deadlines.get(&family).copied()
    }

    /// Advances the clock by `millis` and returns a tick for every deadline reached, in
    /// deadline order.
    pub(crate) fn advance<V: Variant, D: Digest>(&mut self, millis: u64) -> Vec<Input<V, D>> {
        self.now = self.now.saturating_add(millis);
        let mut due = self
            .deadlines
            .iter()
            .filter(|(_, at)| **at <= self.now)
            .map(|(family, at)| (*at, *family))
            .collect::<Vec<_>>();
        due.sort_unstable();
        for (_, family) in &due {
            self.deadlines.remove(family);
        }
        due.into_iter()
            .map(|(_, family)| Input::Tick(family))
            .collect()
    }
}

impl<V: Variant, D: Digest> Executor<V, D> for ManualClock {
    fn execute(&mut self, capability: &Capability<V, D>, _: Generation) -> Option<Execution<V, D>> {
        let Capability::Timer(command) = capability else {
            return None;
        };
        match *command {
            TimerCommand::Arm { family, at } => {
                self.deadlines.insert(family, at);
            }
            TimerCommand::Cancel(family) => {
                self.deadlines.remove(&family);
            }
        }
        Some(Execution::Absorbed)
    }
}
