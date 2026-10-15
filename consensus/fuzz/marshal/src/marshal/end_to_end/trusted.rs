//! Trusted entries for target-state scaffolds on the marshal disrupter bases: the
//! drivers of [fuzz_marshal_standard_disrupter](super::fuzz_marshal_standard_disrupter),
//! [fuzz_marshal_standard_certificate_poison](super::fuzz_marshal_standard_certificate_poison),
//! [fuzz_marshal_standard_block_dissemination](super::fuzz_marshal_standard_block_dissemination),
//! [fuzz_marshal_coding_disrupter](super::fuzz_marshal_coding_disrupter) and
//! [fuzz_marshal_coding_block_poison](super::fuzz_marshal_coding_block_poison) with a
//! prefix hook (see [commonware_consensus_fuzz_core::continuation]); and on the marshal
//! Twins bases, through the core Twins driver's hook (see
//! [commonware_consensus_fuzz_core::run_twins_with_backend_and_hook]).
//!
//! The driver starts the network and the honest marshal stacks behind the runner's
//! taps: engine gates on channels 3/4/5, marshal gates on backfill (1) and broadcast
//! (2: buffered blocks on standard, shards on coding), the elector and every blocker
//! recorded, the automaton and reporter recorded on standard (coding's carry
//! commitments, which the taps do not record), and bounded reads of each replica's
//! marshal. The prefix acts as the byzantine node (participant 0) on its engine and
//! marshal channels and signs only as it. At the release the driver applies the
//! sampled partition, arms the certificate poison, and starts exactly the base's actor
//! for the byzantine node; it then holds the partition for the fault phase, heals, runs
//! one more window and runs its safety oracles, without waiting for progress. A marshal
//! replica cannot be crashed or restarted.
//!
//! On a Twins base B is the case's compromised identity. The honest replicas run behind
//! engine gates, the elector recorder, the automaton and reporter recorders (standard)
//! or the finalization reporter (coding), and the marshal reads; no blocker and no
//! marshal channel is tapped, and B's marshal channels stay with B's own marshal stack.
//! The prefix acts as B on its engine channels; the twin pair starts at the release, and
//! the driver runs one window and its safety oracles, without waiting for progress.

use super::{
    MarshalDisrupterInput, MarshalTwinsInput,
    block_disrupter::{self, Attack, Live, MarshalBroadcastFault},
    coding_disrupter::{self, CodingFaults},
    coding_stack::{CodingVariant, CommitmentOf},
    runner::{
        byzantine_led, degraded_link, force_poison, run_coding_disrupter, run_standard_disrupter,
    },
    twins::{
        B, PublicKeyOf, SchemeOf, force_split_header, run_coding_twins, run_split_header_twins,
        run_standard_twins,
        stack::{DeferredMarshal, InlineMarshal, MarshalChoice},
    },
};
use commonware_consensus::{
    Handoff,
    marshal::{
        core::{Mailbox, Variant},
        mocks::harness::{LINK, TEST_QUOTA},
        standard::Standard,
    },
    simplex::scheme::Scheme as SimplexScheme,
    types::{Epoch, Height, TermLength, View},
};
use commonware_consensus_fuzz_core::{
    BYZANTINE_IDX, BlockFilterChoice, CertifyChoice, DEFAULT_MAILBOX_SIZE, FAULT_PHASE, FuzzInput,
    MAX_SLEEP_DURATION, N4F1C3, NetworkChannels, PINNED_OPTIMISTIC_VIEWS, ReporterWiring,
    SimplexCertificateMock,
    continuation::{self, Hook, MarshalReads, Observer, Prefix, Role, Runner, Topology},
    network::CertificatePoison,
    simplex::Simplex,
    utils::{Partition, SetPartition, apply_partition},
};
use commonware_cryptography::{
    Digestible, certificate::Scheme as CertificateScheme, sha256::Digest as Sha256Digest,
};
use commonware_p2p::simulated::Oracle;
use commonware_runtime::{Clock as _, Supervisor as _, deterministic};
use commonware_utils::FuzzRng;
use std::{
    future::Future,
    panic,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// [super::fuzz_marshal_standard_disrupter] with `prefix` building the target state and
/// `observer` watching. B's actor from the release: one Disrupter for participant 0.
pub fn fuzz_marshal_standard_disrupter_with_prefix<P, X, O>(
    mut input: MarshalDisrupterInput,
    prefix: X,
    observer: O,
) where
    P: Simplex,
    X: Prefix<P>,
    O: Observer,
{
    let observer: Arc<dyn Observer> = Arc::new(observer);
    let hook = plan(&mut input, Box::new(prefix), observer.clone(), false);
    let raw_bytes = input.raw_bytes.clone();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let _ = run_standard_disrupter::<P>(input, None, None, Some(hook));
    }));
    finish(result, raw_bytes, observer.as_ref());
}

/// [super::fuzz_marshal_standard_certificate_poison] with a prefix. The base's forced
/// fields (a connected network with the last participant's links degraded) hold
/// whatever the prefix pins. The poison stays disarmed until the release, which arms
/// it; from then on it may answer the last participant's certificate backfill with a
/// notarization it forges, as the base does. B's actor from the release: one Disrupter
/// for participant 0.
pub fn fuzz_marshal_standard_certificate_poison_with_prefix<P, X, O>(
    mut input: MarshalDisrupterInput,
    prefix: X,
    observer: O,
) where
    P: Simplex,
    X: Prefix<P>,
    O: Observer,
{
    let observer: Arc<dyn Observer> = Arc::new(observer);
    // Forced before the plan, so the prefix's pins see the base's fields; the plan
    // takes back only the raw bytes.
    force_poison(&mut input);
    let hook = plan(&mut input, Box::new(prefix), observer.clone(), false);
    let raw_bytes = input.raw_bytes.clone();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let _ = run_standard_disrupter::<P>(
            input,
            Some(CertificatePoison::disarmed()),
            None,
            Some(hook),
        );
    }));
    finish(result, raw_bytes, observer.as_ref());
}

/// [super::fuzz_marshal_standard_block_dissemination] with a prefix, which may pin the
/// term length up to [continuation::MARSHAL_MAX_TERM_LENGTH]. The dissemination fault is
/// sampled from the raw bytes the prefix leaves. B's actor from the release: the block
/// disseminator for participant 0, which attacks the first term B leads after the
/// release, once B receives an honest vote for the view before it, on that vote's block
/// (see [block_disrupter::Live]). A release after the cluster reached the last height of
/// epoch 0 leaves no view to attack: a run whose disseminator never attacked fails the
/// `end` actor check with `base=no-dissemination`.
pub fn fuzz_marshal_standard_block_dissemination_with_prefix<P, X, O>(
    mut input: MarshalDisrupterInput,
    prefix: X,
    observer: O,
) where
    P: Simplex,
    X: Prefix<P>,
    O: Observer,
{
    let observer: Arc<dyn Observer> = Arc::new(observer);
    let hook = plan(&mut input, Box::new(prefix), observer.clone(), true);
    let fault = MarshalBroadcastFault::sample(&mut FuzzRng::new(input.raw_bytes.clone()));
    let raw_bytes = input.raw_bytes.clone();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let _ = run_standard_disrupter::<P>(input, None, Some(fault), Some(hook));
    }));
    finish(result, raw_bytes, observer.as_ref());
}

/// [super::fuzz_marshal_coding_disrupter] with `prefix` building the target state and
/// `observer` watching. B's actor from the release: the coding disrupter for participant
/// 0, in epoch 0, its sampled views moved past the highest view finalized at the release,
/// with the shard faults on its broadcast channel.
pub fn fuzz_marshal_coding_disrupter_with_prefix<P, X, O>(
    mut input: MarshalDisrupterInput,
    prefix: X,
    observer: O,
) where
    P: Simplex,
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
    X: Prefix<P>,
    O: Observer,
{
    let observer: Arc<dyn Observer> = Arc::new(observer);
    let hook = plan(&mut input, Box::new(prefix), observer.clone(), false);
    let raw_bytes = input.raw_bytes.clone();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let _ = run_coding_disrupter::<P>(input, false, Some(hook));
    }));
    finish(result, raw_bytes, observer.as_ref());
}

/// [super::fuzz_marshal_coding_block_poison] with a prefix. The base's forced fields (a
/// connected network with the last participant's links degraded) hold whatever the
/// prefix pins. B's actor from the release: the backfill poisoner for participant 0 on
/// its backfill channel, which then answers block requests with blocks that do not match
/// and notarized-block requests under a notarization it forges, as the base does.
pub fn fuzz_marshal_coding_block_poison_with_prefix<P, X, O>(
    mut input: MarshalDisrupterInput,
    prefix: X,
    observer: O,
) where
    P: Simplex,
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
    X: Prefix<P>,
    O: Observer,
{
    let observer: Arc<dyn Observer> = Arc::new(observer);
    // Forced before the plan, so the prefix's pins see the base's fields; the plan
    // takes back only the raw bytes.
    force_poison(&mut input);
    let hook = plan(&mut input, Box::new(prefix), observer.clone(), false);
    let raw_bytes = input.raw_bytes.clone();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let _ = run_coding_disrupter::<P>(input, true, Some(hook));
    }));
    finish(result, raw_bytes, observer.as_ref());
}

/// [super::fuzz_marshal_standard_twins] with `prefix` building the target state and
/// `observer` watching. The stack selector is the last raw byte the prefix leaves, and
/// no node is held back for a floor. B's actors from the release: the twin pair, a primary
/// engine over B's own marshal, whose actor starts then, and a Disrupter in epoch 0 with
/// its faulty views moved past the highest view finalized at the release.
pub fn fuzz_marshal_standard_twins_with_prefix<X, O>(
    mut input: MarshalTwinsInput,
    prefix: X,
    observer: O,
) where
    X: Prefix<SimplexCertificateMock>,
    O: Observer,
{
    let observer: Arc<dyn Observer> = Arc::new(observer);
    let hook = plan_twins(&mut input, Box::new(prefix), observer.clone());
    let raw_bytes = input.raw_bytes.clone();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let _ = run_standard_twins(input, Some(hook));
    }));
    finish(result, raw_bytes, observer.as_ref());
}

/// [super::fuzz_marshal_standard_deferred_cert_mock_twins_split_header] with a prefix. The
/// base's forced `SplitHeader` strategy holds whatever the prefix pins. Its layout's
/// verification delays stay at the views the case chose, which the prefix usually passes.
/// B's actors from the release: the twin pair, as on
/// [fuzz_marshal_standard_twins_with_prefix].
pub fn fuzz_marshal_standard_deferred_cert_mock_twins_split_header_with_prefix<X, O>(
    input: MarshalTwinsInput,
    prefix: X,
    observer: O,
) where
    X: Prefix<SimplexCertificateMock>,
    O: Observer,
{
    split_header_with_prefix(input, prefix, observer, |input, hook| {
        let _ = run_split_header_twins::<DeferredMarshal>(input, MarshalChoice::Deferred, hook);
    });
}

/// [super::fuzz_marshal_standard_inline_cert_mock_twins_split_header] with a prefix, as
/// [fuzz_marshal_standard_deferred_cert_mock_twins_split_header_with_prefix] over the
/// inline wrapper.
pub fn fuzz_marshal_standard_inline_cert_mock_twins_split_header_with_prefix<X, O>(
    input: MarshalTwinsInput,
    prefix: X,
    observer: O,
) where
    X: Prefix<SimplexCertificateMock>,
    O: Observer,
{
    split_header_with_prefix(input, prefix, observer, |input, hook| {
        let _ = run_split_header_twins::<InlineMarshal>(input, MarshalChoice::Inline, hook);
    });
}

/// A split-header base with a prefix: `run` runs its driver with the hook.
fn split_header_with_prefix<X, O>(
    mut input: MarshalTwinsInput,
    prefix: X,
    observer: O,
    run: impl FnOnce(MarshalTwinsInput, Option<Hook<SimplexCertificateMock>>),
) where
    X: Prefix<SimplexCertificateMock>,
    O: Observer,
{
    let observer: Arc<dyn Observer> = Arc::new(observer);
    // Forced before the plan, so the prefix's pins see the base's strategy; the driver
    // forces it again.
    force_split_header(&mut input);
    let hook = plan_twins(&mut input, Box::new(prefix), observer.clone());
    let raw_bytes = input.raw_bytes.clone();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| run(input, Some(hook))));
    finish(result, raw_bytes, observer.as_ref());
}

/// [super::fuzz_marshal_coding_twins] with a prefix. The stack selector is the last raw
/// byte the prefix leaves. B's actors from the release: the twin pair, a primary coding
/// engine over B's own coding marshal, which runs from the start, and the coding
/// double-voter as its secondary, its sampled views moved past the highest view finalized
/// at the release.
pub fn fuzz_marshal_coding_twins_with_prefix<P, X, O>(
    mut input: MarshalTwinsInput,
    prefix: X,
    observer: O,
) where
    P: Simplex,
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
    X: Prefix<P>,
    O: Observer,
{
    let observer: Arc<dyn Observer> = Arc::new(observer);
    let hook = plan_twins(&mut input, Box::new(prefix), observer.clone());
    let raw_bytes = input.raw_bytes.clone();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let _ = run_coding_twins::<P>(input, Some(hook));
    }));
    finish(result, raw_bytes, observer.as_ref());
}

/// Plans `prefix` against a scratch [FuzzInput] that mirrors what a marshal Twins base
/// runs (its required containers are the trailing blocks the base's liveness check
/// waits for), then takes back the raw bytes the prefix left. No pin reaches the base.
fn plan_twins<P: Simplex>(
    input: &mut MarshalTwinsInput,
    prefix: Box<dyn Prefix<P>>,
    observer: Arc<dyn Observer>,
) -> Hook<P> {
    let mut scratch = FuzzInput {
        raw_bytes: std::mem::take(&mut input.raw_bytes),
        required_containers: input.trailing_blocks.into(),
        term_length: TermLength::ONE,
        optimistic_views: PINNED_OPTIMISTIC_VIEWS,
        heterogeneous_optimism: false,
        handoff: Handoff::Wait,
        degraded_network: false,
        configuration: N4F1C3,
        partition: Partition::Connected,
        strategy: input.strategy,
        mailbox_size: DEFAULT_MAILBOX_SIZE,
        forwarding: input.forwarding,
        certify: CertifyChoice::Always,
        block_filter: BlockFilterChoice::None,
        reporting: ReporterWiring::Solo,
    };
    let hook = Hook::plan_marshal(prefix, observer, &mut scratch, false);
    input.raw_bytes = scratch.raw_bytes;
    hook
}

/// Plans `prefix` against a scratch [FuzzInput] that mirrors what the base runs, then
/// takes back the raw bytes the prefix left and, for a base that honors one (`term`),
/// the term length it pinned. No other pin reaches the base.
fn plan<P: Simplex>(
    input: &mut MarshalDisrupterInput,
    prefix: Box<dyn Prefix<P>>,
    observer: Arc<dyn Observer>,
    term: bool,
) -> Hook<P> {
    let mut scratch = scratch_input(input, term);
    let hook = Hook::plan_marshal(prefix, observer, &mut scratch, term);
    input.raw_bytes = scratch.raw_bytes;
    if term {
        input.term_length = scratch.term_length;
    }
    hook
}

/// The [FuzzInput] a marshal disrupter base runs: its own fields, the term length its
/// engines run, and the fixed rest of the marshal stack.
fn scratch_input(input: &mut MarshalDisrupterInput, term: bool) -> FuzzInput {
    FuzzInput {
        raw_bytes: std::mem::take(&mut input.raw_bytes),
        required_containers: input.required_containers,
        term_length: if term {
            input.term_length
        } else {
            TermLength::ONE
        },
        optimistic_views: PINNED_OPTIMISTIC_VIEWS,
        heterogeneous_optimism: false,
        handoff: Handoff::Wait,
        degraded_network: input.degraded_network,
        configuration: N4F1C3,
        partition: input.partition.clone(),
        strategy: input.strategy,
        mailbox_size: DEFAULT_MAILBOX_SIZE,
        forwarding: input.forwarding,
        certify: CertifyChoice::Always,
        block_filter: BlockFilterChoice::None,
        reporting: ReporterWiring::Solo,
    }
}

/// Rethrows a run's panic as the base entries do, or reports the end of the run.
fn finish(result: std::thread::Result<()>, raw_bytes: Vec<u8>, observer: &dyn Observer) {
    if let Err(payload) = result {
        println!("Panicked with raw_bytes: {raw_bytes:?}");
        panic::resume_unwind(payload);
    }
    observer.done();
}

/// Bounded, read-only queries of an honest replica's marshal, through its mailbox:
/// every answer comes from the actor's task.
pub(super) struct Reads<S: CertificateScheme, V: Variant> {
    mailbox: Mailbox<S, V>,
}

/// [Reads] of a standard marshal.
pub(super) type StandardReads<P> = Reads<SchemeOf<P>, Standard<B<P>>>;

/// [Reads] of a coding marshal: the digests are those of the blocks it codes.
pub(super) type CodingReads<P> = Reads<SchemeOf<P>, CodingVariant<P>>;

impl<S: CertificateScheme, V: Variant> Reads<S, V> {
    pub(super) const fn new(mailbox: Mailbox<S, V>) -> Self {
        Self { mailbox }
    }
}

impl<S, V> MarshalReads for Reads<S, V>
where
    S: CertificateScheme,
    V: Variant,
    V::Block: Digestible<Digest = Sha256Digest>,
{
    fn finalized(&self, height: u64) -> Pin<Box<dyn Future<Output = Option<Sha256Digest>> + Send>> {
        let mailbox = self.mailbox.clone();
        Box::pin(async move {
            mailbox
                .get_info(Height::new(height))
                .await
                .map(|(_, digest)| digest)
        })
    }

    fn processed(&self) -> Pin<Box<dyn Future<Output = Option<u64>> + Send>> {
        let mailbox = self.mailbox.clone();
        Box::pin(async move {
            mailbox
                .get_processed()
                .await
                .map(|processed| processed.height().get())
        })
    }
}

/// Starts the runner of a marshal disrupter base after its links exist and before any
/// engine starts: participant 0 is B, and the base starts one actor for it. The base's
/// link is the ordinary marshal link, or the degraded one on the last participant's
/// edges.
pub(super) fn start_runner<P: Simplex>(
    hook: Hook<P>,
    context: &deterministic::Context,
    participants: &[PublicKeyOf<P>],
    schemes: &[SchemeOf<P>],
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    term_length: TermLength,
    degraded: bool,
) -> Runner<P> {
    let last = participants.len().checked_sub(1);
    Runner::start(
        hook,
        context,
        Topology {
            participants: participants.to_vec(),
            schemes: schemes.to_vec(),
            byzantine: Some(BYZANTINE_IDX),
            required: vec![Role::Disrupter],
            term_length,
            optimistic_views: PINNED_OPTIMISTIC_VIEWS,
            scripted_views: 0,
            epoch: Epoch::zero(),
            relay: None,
            oracle: oracle.clone(),
            base_link: Box::new(move |from, to| {
                Some(if degraded && (Some(from) == last || Some(to) == last) {
                    degraded_link()
                } else {
                    LINK
                })
            }),
        },
        P::elector(term_length, PINNED_OPTIMISTIC_VIEWS),
    )
}

/// Hands the byzantine node's engine `channels`, which the caller registered, to the
/// runner, and registers and hands over its marshal channels, which nothing else
/// registers for it under a continuation.
pub(super) async fn adopt_byzantine<P: Simplex>(
    runner: &mut Runner<P>,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    validator: &PublicKeyOf<P>,
    channels: NetworkChannels<PublicKeyOf<P>>,
) {
    let control = oracle.control(validator.clone());
    let backfill = control
        .register(1, TEST_QUOTA)
        .await
        .expect("byzantine backfill channel registration failed");
    let broadcast = control
        .register(2, TEST_QUOTA)
        .await
        .expect("byzantine broadcast channel registration failed");
    runner.adopt(channels);
    runner.adopt_marshal((backfill, broadcast));
}

/// The actor a standard marshal base starts for the byzantine node.
pub(super) enum StandardActor {
    /// The Disrupter on its engine channels (the disrupter and poison bases).
    Disrupter,
    /// The block disseminator on its broadcast channel, announcing on its vote channel
    /// and watching the honest votes it receives there.
    Disseminator(MarshalBroadcastFault),
}

/// The release of a standard marshal base: runs the prefix and the release, applies the
/// partition the base applies at its start, arms `poison`, and starts B's `actor` with
/// its faults moved past the release. A channel the release did not return leaves the
/// actor unstarted, which the release check reports. Returns the flag a started block
/// disseminator sets when it attacks.
#[allow(clippy::too_many_arguments)]
pub(super) async fn release_standard<P: Simplex>(
    runner: &mut Runner<P>,
    context: &deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    schemes: &[SchemeOf<P>],
    input: &MarshalDisrupterInput,
    term_length: TermLength,
    partition: Option<&SetPartition>,
    poison: Option<&CertificatePoison<PublicKeyOf<P>>>,
    actor: StandardActor,
) -> Option<Arc<AtomicBool>> {
    let (channels, release) = runner.run().await;
    let lanes = runner.marshal_channels();
    if let Some(partition) = partition {
        apply_partition(oracle, participants, Some(partition), &LINK).await;
    }
    if let Some(poison) = poison {
        poison.arm();
    }
    let index = BYZANTINE_IDX;
    let registry = runner.registry();
    let context = context
        .child("validator")
        .with_attribute("public_key", &participants[index]);
    let mut attacked = None;
    match actor {
        StandardActor::Disrupter => {
            if let Some(channels) = channels {
                let handle = continuation::start_disrupter::<P>(
                    context.child("disrupter"),
                    schemes[index].clone(),
                    &input.strategy,
                    input.required_containers,
                    channels,
                    None,
                    release.base,
                    registry.marker(index, Role::Disrupter),
                    Epoch::zero(),
                );
                registry.register(index, Role::Disrupter, handle);
            }
        }
        StandardActor::Disseminator(fault) => {
            if let (Some(((vote_sender, votes), _, _)), Some((_, broadcast))) = (channels, lanes) {
                let flag = Arc::new(AtomicBool::new(false));
                let live = Live {
                    votes,
                    after: View::new(release.view),
                    term_length,
                    led: Box::new(byzantine_led::<P>(&schemes[index], term_length)),
                    attacked: flag.clone(),
                };
                let handle = block_disrupter::start_with::<P>(
                    context.child("block_disrupter"),
                    oracle,
                    schemes[index].clone(),
                    participants[index].clone(),
                    participants.to_vec(),
                    vote_sender,
                    broadcast,
                    Some(registry.marker(index, Role::Disrupter)),
                    Attack::Live(live),
                    fault,
                    true,
                );
                registry.register(index, Role::Disrupter, handle);
                attacked = Some(flag);
            }
        }
    }
    runner.check_release().await;
    attacked
}

/// The actor a coding marshal base starts for the byzantine node.
pub(super) enum CodingActor {
    /// The coding disrupter on its engine channels, with the shard faults on its
    /// broadcast channel (the disrupter base).
    Disrupter,
    /// The backfill poisoner on its backfill channel (the block-poison base).
    Poisoner,
}

/// The release of a coding marshal base: runs the prefix and the release, applies the
/// partition the base applies at its start, and starts B's `actor` with the fault
/// sampler `rng` (the coding disrupter with its views moved past the highest view
/// finalized by then). A channel the release did not return leaves the actor unstarted,
/// which the release check reports.
#[allow(clippy::too_many_arguments)]
pub(super) async fn release_coding<P>(
    runner: &mut Runner<P>,
    context: &deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    schemes: &[SchemeOf<P>],
    input: &MarshalDisrupterInput,
    partition: Option<&SetPartition>,
    actor: CodingActor,
    rng: FuzzRng,
) where
    P: Simplex,
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let (channels, release) = runner.run().await;
    let lanes = runner.marshal_channels();
    if let Some(partition) = partition {
        apply_partition(oracle, participants, Some(partition), &LINK).await;
    }
    let index = BYZANTINE_IDX;
    let registry = runner.registry();
    let context = context
        .child("validator")
        .with_attribute("public_key", &participants[index]);
    match actor {
        CodingActor::Disrupter => {
            if let (Some((vote, certificate, resolver)), Some((_, shards))) = (channels, lanes) {
                let scheme = schemes[index].clone();
                let leads = Box::new(byzantine_led::<P>(&scheme, TermLength::ONE));
                let handle = coding_disrupter::start::<P>(
                    context.child("disrupter"),
                    scheme,
                    input.strategy,
                    input.required_containers,
                    vote,
                    certificate,
                    resolver,
                    CodingFaults {
                        shards: Some((shards, leads)),
                        rng,
                    },
                    release.base,
                    Some(registry.marker(index, Role::Disrupter)),
                );
                registry.register(index, Role::Disrupter, handle);
            }
        }
        CodingActor::Poisoner => {
            if let Some((backfill, _)) = lanes {
                let handle = coding_disrupter::start_backfill_poison::<P>(
                    context.child("poisoner"),
                    schemes.to_vec(),
                    backfill,
                    rng,
                    Some(registry.marker(index, Role::Disrupter)),
                );
                registry.register(index, Role::Disrupter, handle);
            }
        }
    }
    runner.check_release().await;
}

/// The fixed window of a marshal disrupter continuation: the partition held for the
/// fault phase, then healed with the degraded links, then one more window, then the end
/// check, failed with `base=no-dissemination` when a block disseminator's `attacked`
/// flag is still unset.
pub(super) async fn fixed_window<P: Simplex>(
    runner: &Runner<P>,
    context: &deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    attacked: Option<&AtomicBool>,
) {
    context.sleep(FAULT_PHASE).await;
    apply_partition(oracle, participants, None, &LINK).await;
    context.sleep(MAX_SLEEP_DURATION).await;
    let base = attacked
        .is_some_and(|attacked| !attacked.load(Ordering::Relaxed))
        .then_some("no-dissemination");
    runner.check_with("end", base);
}

#[cfg(test)]
mod tests;
