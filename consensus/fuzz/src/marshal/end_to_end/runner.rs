//! Multi-node marshal end-to-end harness runner.
//!
//! Runs `N4F1C3` (three honest validators plus one byzantine `Disrupter`)
//! over the simulated network and reuses the shared fuzz infrastructure
//! (`setup_network`-style helpers, the byzantine `Disrupter`, strategy
//! sampling) with [`MarshalDisrupterInput`]. The honest validators are
//! parametrized by the *marshal sink* instead of the reporter sink: each runs a
//! Simplex engine whose `reporter` is a marshal mailbox, and marshal delivers
//! ordered finalized blocks to a downstream [`Application`] sink.
//!
//! Liveness check uses simulated-network topology changes ([`apply_partition`])
//! rather than MITM message interception:
//!
//! - Phase 1 (pre-GST): a sampled network partition is held for [`FAULT_PHASE`]
//!   while the byzantine `Disrupter` runs. If every honest marshal delivers the
//!   target number of ordered finalized blocks (`required_containers`, sampled
//!   within a single-epoch bound; see `MAX_REQUIRED`) during this phase, the
//!   run passes.
//! - GST: the network heals (`apply_partition(None)`); the `Disrupter` stays
//!   active (its faults are not gated by GST).
//! - Phase 2 (post-GST): each honest marshal must reach its target (`required`,
//!   or baseline + 1 unless already at `MAX_REQUIRED`) within the marshal
//!   runner's post-GST budget;
//!   failure to make progress panics with a per-node diagnostic.
//!
//! Safety invariants then assert in-order delivery and cross-node agreement.
//!
//! Generic over the consensus scheme `P`, so the same driver serves every
//! certificate scheme (the fuzz targets use the cheap `SimplexCertificateMock`
//! rather than real threshold signatures).
//!
//! # Adversary scope
//!
//! The marshal-backed honest engines run at `Epoch::zero()`: marshal's epoch
//! check ties the consensus epoch to `epocher.containing(height)`, and the
//! harness `FixedEpocher(20)` maps the low test heights to epoch 0. So the
//! standard Byzantine actor is started via [`start_disrupter_with_epoch`] with
//! `Epoch::zero()` (the consensus-wide `crate::EPOCH` is left unchanged).
//! Coding uses the Commitment-typed [`coding_disrupter`] actor, which also emits
//! messages at epoch 0.
//!
//! Each actor's votes share both the epoch and payload type with its honest
//! engines, so both are fully in-epoch equivocating adversaries. The three
//! honest validators must still deliver the target number of ordered blocks.

use super::{
    MAX_REQUIRED,
    app::{
        AlwaysAcceptBlockBuilderApp, ApplicationChoice, BlockContextRegistry, DeliveryReporter,
        FaultyConfig,
    },
    block_disrupter, coding_disrupter,
    coding_stack::{
        CodingB, CodingCtx, coding_genesis, coding_marshaled, setup_validator_coding,
        start_engine_coding_with_networks,
    },
    input::MarshalDisrupterInput,
    invariants::{self, CertificationAgreementInvariant, HeaderMismatchInvariant},
    twins::{
        B, Ctx, ObservedMarshal, PublicKeyOf, SchemeOf,
        stack::{
            DeferredMarshal, MarshalChoice, TwinsBlockBuilder, TwinsMarshal, genesis_block,
            register_engine_networks, setup_network, setup_network_links, setup_validator,
            start_engine,
        },
    },
};
use crate::{
    BYZANTINE_IDX, FAULT_PHASE,
    network::{CertificatePoison, CertificatePoisonReceiver},
    simplex::Simplex,
    start_disrupter_with_epoch,
    utils::{Partition, SetPartition, apply_partition},
};
use commonware_consensus::{
    Block,
    marshal::{
        Start,
        mocks::{
            application::Application,
            harness::{LINK, NUM_VALIDATORS},
        },
    },
    simplex::scheme::Scheme as SimplexScheme,
    types::{Epoch, TermLength, View, coding::Commitment},
};
use commonware_cryptography::{
    Committable as _, Digestible as _, certificate::ConstantProvider,
    sha256::Digest as Sha256Digest,
};
use commonware_p2p::simulated::Link;
use commonware_runtime::{Clock, Runner, Supervisor as _, deterministic};
use commonware_utils::{FuzzRng, NZUsize, probability, sync::Mutex};
use std::{
    fmt::{self, Write as _},
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};

/// Marshal backlog for the disrupter and coding configurations.
///
/// Pending-ack invariant coverage uses the Twins target's reachable windows.
const MAX_PENDING_ACKS: NonZeroUsize = NZUsize!(64);
/// Marshal's post-GST recovery budget on its ordinary simulated links.
const MARSHAL_LIVENESS_WINDOW: Duration = Duration::from_secs(360);

/// Poll interval for observing marshal delivery progress.
const POLL: Duration = Duration::from_millis(50);

/// Reports a post-GST stall: the honest nodes that missed their target, and the
/// per-node progress diagnostic.
type StallReport<'a> = &'a dyn Fn(&[usize], &str);

/// Honest validator whose certificate backfill the poison target attacks. The
/// degraded-network path degrades the last participant's links, so this is the
/// node that falls behind and backfills.
const POISON_IDX: usize = NUM_VALIDATORS as usize - 1;

/// Payload of the notarization the poisoned response serves. No node proposes
/// it, so no node can supply the block behind it.
const UNAVAILABLE_PAYLOAD: Sha256Digest = Sha256Digest([0xEE; 32]);

struct MarshalDisrupterInputDebug<'a>(&'a MarshalDisrupterInput);

impl fmt::Debug for MarshalDisrupterInputDebug<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let input = self.0;
        formatter
            .debug_struct("MarshalDisrupterInput")
            .field("raw_bytes_len", &input.raw_bytes.len())
            .field("required_containers", &input.required_containers)
            .field("term_length", &input.term_length)
            .field("degraded_network", &input.degraded_network)
            .field("partition", &input.partition)
            .field("strategy", &input.strategy)
            .field("forwarding", &input.forwarding)
            .finish()
    }
}

fn always_accepts<C>(_choice: ApplicationChoice, _config: FaultyConfig, _context: &C) -> bool {
    false
}

async fn apply_degraded_network<P: Simplex>(
    oracle: &mut commonware_p2p::simulated::Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
) {
    let Some(victim) = participants.last() else {
        return;
    };
    let degraded = Link {
        latency: Duration::from_millis(50),
        jitter: Duration::from_millis(50),
        success_rate: probability!(0.6),
    };
    for peer in participants
        .iter()
        .take(participants.len().saturating_sub(1))
    {
        oracle.remove_link(victim.clone(), peer.clone()).await.ok();
        oracle.remove_link(peer.clone(), victim.clone()).await.ok();
        oracle
            .add_link(victim.clone(), peer.clone(), degraded.clone())
            .await
            .unwrap();
        oracle
            .add_link(peer.clone(), victim.clone(), degraded.clone())
            .await
            .unwrap();
    }
}

/// Highest finalized-block height marshal has delivered to `app`'s sink. The
/// height-0 genesis floor block does not count as progress, so an empty/genesis
/// sink reports 0.
pub(super) fn highest_delivered<B: Block>(app: &Application<B>) -> u64 {
    app.blocks().keys().next_back().map_or(0, |h| h.get())
}

fn targets_reached<B: Block>(apps: &[(usize, Application<B>)], targets: &[(usize, u64)]) -> bool {
    targets.iter().all(|(target_idx, target)| {
        apps.iter()
            .find(|(idx, _)| idx == target_idx)
            .is_some_and(|(_, app)| highest_delivered(app) >= *target)
    })
}

async fn wait_for_targets<B: Block>(
    context: &deterministic::Context,
    apps: &[(usize, Application<B>)],
    targets: &[(usize, u64)],
    timeout: Duration,
) -> bool {
    let deadline = context.current() + timeout;
    loop {
        if targets_reached(apps, targets) {
            return true;
        }
        let Ok(remaining) = deadline.duration_since(context.current()) else {
            return false;
        };
        if remaining.is_zero() {
            return false;
        }
        context.sleep(POLL.min(remaining)).await;
    }
}

/// Shared pre-GST / GST / post-GST liveness window, used by both the standard
/// and coding liveness runners.
async fn run_liveness_phases<BL, KEY>(
    context: &deterministic::Context,
    oracle: &commonware_p2p::simulated::Oracle<KEY, deterministic::Context>,
    participants: &[KEY],
    honest_apps: &[(usize, Application<BL>)],
    required: u64,
    on_stall: Option<StallReport<'_>>,
) where
    BL: Block,
    KEY: commonware_cryptography::PublicKey,
{
    // Phase 1: hold the pre-GST network fault until either every honest
    // marshal reaches `required` or the fault phase expires. The root
    // future polls progress directly so timed-out phase-1 watchers do not
    // keep running into the post-GST phase.
    let phase1_targets: Vec<(usize, u64)> = honest_apps
        .iter()
        .map(|(idx, _)| (*idx, required))
        .collect();
    let phase1_early_complete =
        wait_for_targets(context, honest_apps, &phase1_targets, FAULT_PHASE).await;

    if !phase1_early_complete {
        // Highest height deliverable in this single-epoch harness (the
        // epoch-0 boundary). A fast honest node can reach it during the
        // fault phase, so the post-GST target must not exceed it.
        let max_live_height = MAX_REQUIRED;
        // Record post-GST targets before healing (stable diagnostics): a
        // node below `required` must reach it; one already at/above must
        // advance by one, unless it is already at the epoch boundary.
        let mut watch_targets: Vec<(usize, u64, u64)> = Vec::with_capacity(honest_apps.len());
        for (idx, app) in honest_apps.iter().cloned() {
            let baseline = highest_delivered(&app);
            let target = if baseline < required {
                required
            } else if baseline < max_live_height {
                baseline + 1
            } else {
                baseline
            };
            watch_targets.push((idx, baseline, target));
        }

        // GST heals the network topology. The byzantine `Disrupter` stays
        // active (its process faults are not gated by GST).
        apply_partition(oracle, participants, None, &LINK).await;

        // Phase 2: each honest marshal must reach its target within the
        // post-GST window.
        let phase2_targets: Vec<(usize, u64)> = watch_targets
            .iter()
            .map(|(idx, _, target)| (*idx, *target))
            .collect();
        let phase2_complete = wait_for_targets(
            context,
            honest_apps,
            &phase2_targets,
            MARSHAL_LIVENESS_WINDOW,
        )
        .await;

        if !phase2_complete {
            let mut diag = String::new();
            let mut missed = Vec::new();
            for &(idx, baseline, target) in &watch_targets {
                let current = honest_apps
                    .iter()
                    .find(|(i, _)| *i == idx)
                    .map_or(0, |(_, app)| highest_delivered(app));
                if current < target {
                    missed.push(idx);
                }
                let _ = write!(
                    diag,
                    " node{idx}={{baseline={baseline} target={target} current={current}}}"
                );
            }
            if let Some(on_stall) = on_stall {
                on_stall(&missed, &diag);
            }
            panic!("marshal: no post-GST progress within {MARSHAL_LIVENESS_WINDOW:?};{diag}");
        }
    }
}

/// Crypto: `P` (target uses `SimplexCertificateMock`). Marshal: standard,
/// deferred. Cluster: `N4F1C3`, disrupter only (no Twins). Liveness: checked.
/// App: fixed always-accept.
pub fn fuzz_marshal_standard_disrupter<P: Simplex>(input: MarshalDisrupterInput) {
    run_standard_disrupter::<P>(input, None, None);
}

/// The cluster of [`fuzz_marshal_standard_disrupter`] with the byzantine node
/// additionally acting as a faulty block-gossip leader on its pinned view.
///
/// The byzantine node leads view 1 (its parent is genesis) and disseminates the
/// block it proposes under a fuzzer-selected `MarshalBroadcastFault`: it
/// withholds the block, delivers it to only a partition, or delivers two
/// conflicting blocks to disjoint replica sets. Honest nodes must still route
/// around the byzantine-led view and deliver the target number of ordered
/// blocks. Instantiate with a `P` whose elector pins the byzantine index to
/// view 1 (see `SimplexCertificateMockByzantineFirstLeader`).
pub fn fuzz_marshal_standard_block_dissemination<P: Simplex>(input: MarshalDisrupterInput) {
    let mut mode_rng = FuzzRng::new(input.raw_bytes.clone());
    let fault = block_disrupter::MarshalBroadcastFault::sample(&mut mode_rng);
    run_standard_disrupter::<P>(input, None, Some(fault));
}

/// The cluster of [`fuzz_marshal_standard_disrupter`] with one honest node's
/// certificate backfill poisoned once.
///
/// The covering nullification that node fetches is replaced by a valid
/// notarization whose block no node holds, so its certification can never
/// complete. Marshal is the automaton here, so that stall is the real one: it
/// asks for a block nobody can serve. The node must still obtain the
/// certificate it is missing (by re-fetching the view) or it can never vote
/// again, and the cluster loses the quorum it needs to finalize.
pub fn fuzz_marshal_standard_certificate_poison<P: Simplex>(mut input: MarshalDisrupterInput) {
    // A backfill fetch needs a certificate gap at one node while the others
    // move on. With n=4 every topology partition also breaks the quorum that
    // would move on, so lossy links are the only fault that produces one.
    input.partition = Partition::Connected;
    input.degraded_network = true;
    run_standard_disrupter::<P>(input, Some(CertificatePoison::new()), None);
}

fn run_standard_disrupter<P: Simplex>(
    input: MarshalDisrupterInput,
    poison: Option<CertificatePoison<PublicKeyOf<P>>>,
    broadcast_fault: Option<block_disrupter::MarshalBroadcastFault>,
) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    // Only the block-dissemination target honors the fuzzed term length (its
    // elector makes the byzantine a stable leader of the first term); the plain
    // disrupter and poison targets keep single-view rotating terms.
    let term_length = if broadcast_fault.is_some() {
        input.term_length
    } else {
        TermLength::ONE
    };

    executor.start(|mut context| async move {
        // Shared fixture: the same participants/schemes drive the byzantine
        // disrupter, the honest engines, and the marshal providers.
        let (participants, schemes) = P::setup(&mut context, crate::NAMESPACE, NUM_VALIDATORS);

        let mut oracle = setup_network::<P>(context.child("network"), participants.clone()).await;
        setup_network_links::<P>(&mut oracle, &participants).await;
        if input.degraded_network {
            apply_degraded_network::<P>(&mut oracle, &participants).await;
        }

        let required = input.required_containers;

        // Pre-GST network fault held for the bounded fault phase, applied via
        // the simulated-network topology (not byzzfuzz interceptors).
        // `Connected` means no topology fault.
        let pre_gst_partition: Option<SetPartition> = input.partition.set_partition().copied();
        if let Some(partition) = pre_gst_partition.as_ref() {
            apply_partition(&oracle, &participants, Some(partition), &LINK).await;
        }

        // Consensus genesis commitment must equal the marshal genesis block's
        // commitment so view-1 proposals link to the block marshal already
        // holds via `Start::Genesis`.
        let genesis_marshal_block = genesis_block::<P>(participants[0].clone());
        let genesis_commitment = genesis_marshal_block.digest();
        let block_contexts = BlockContextRegistry::<Ctx<P>>::default();
        block_contexts.record(genesis_commitment, genesis_marshal_block.context.clone());

        // Honest applications always accept, so the liveness oracle observes
        // marshal progress rather than application-induced rejection.
        let mut fault_rng = FuzzRng::new(input.raw_bytes.clone());
        let faulty_config = FaultyConfig::new(&mut fault_rng, View::new(0));
        let stack_label: Arc<str> =
            "application=always-accept marshal=deferred max_pending_acks=64".into();
        let probe_input: Arc<str> = format!("{:?}", MarshalDisrupterInputDebug(&input)).into();
        let certification_agreement =
            CertificationAgreementInvariant::new(stack_label.clone(), MarshalChoice::Deferred);

        // Spawned marshal actors run until the root future completes; their
        // handles detach on drop (they do not abort), so we don't retain them.
        let mut honest_apps: Vec<(usize, Application<B<P>>)> = Vec::new();

        for (idx, validator) in participants.iter().enumerate() {
            let scheme = schemes[idx].clone();
            let (vote, certificate, resolver) =
                register_engine_networks::<P>(&oracle, validator.clone()).await;

            if idx == BYZANTINE_IDX {
                let validator_ctx = context
                    .child("validator")
                    .with_attribute("public_key", validator);
                if let Some(fault) = broadcast_fault {
                    // Block-dissemination leader: the byzantine acts solely as a
                    // faulty block-gossip leader over its stable term. Running the
                    // generic Disrupter alongside would let its view-1 proposal
                    // shadow the coordinated one (the batcher makes the first
                    // leader proposal authoritative), silently degrading the
                    // dissemination fault; vote/certificate/resolver faults are
                    // covered by the sibling disrupter target instead. The
                    // byzantine is silent past view 1, so honest nodes nullify the
                    // first view of its term on the per-view timeout and that
                    // term-covering nullification advances them past the rest.
                    let (vote_sender, _vote_receiver) = vote;
                    block_disrupter::start::<P>(
                        validator_ctx.child("block_disrupter"),
                        &oracle,
                        scheme,
                        validator.clone(),
                        participants.clone(),
                        vote_sender,
                        genesis_commitment,
                        View::new(1),
                        fault,
                    )
                    .await;
                } else {
                    start_disrupter_with_epoch::<P>(
                        validator_ctx.child("disrupter"),
                        scheme,
                        &input.strategy,
                        required,
                        Epoch::zero(),
                        vote,
                        certificate,
                        resolver,
                    );
                }
                continue;
            }

            // Honest validator: end-to-end marshal stack plus Simplex engine.
            let (resolver_sender, resolver_receiver) = resolver;
            let resolver = (
                resolver_sender,
                if idx == POISON_IDX {
                    CertificatePoisonReceiver::<SchemeOf<P>, Sha256Digest, _>::new(
                        resolver_receiver,
                        schemes.clone(),
                        Epoch::zero(),
                        UNAVAILABLE_PAYLOAD,
                        poison.clone(),
                    )
                } else {
                    CertificatePoisonReceiver::<SchemeOf<P>, Sha256Digest, _>::observer(
                        resolver_receiver,
                        validator.clone(),
                        participants[POISON_IDX].clone(),
                        poison.clone(),
                    )
                },
            );
            let validator_ctx = context
                .child("validator")
                .with_attribute("public_key", validator);
            let provider = ConstantProvider::new(scheme.clone());
            let mut node = setup_validator::<P>(
                validator_ctx.child("marshal"),
                &mut oracle,
                validator.clone(),
                provider,
                Start::Genesis(genesis_marshal_block.clone()),
                None,
                MAX_PENDING_ACKS,
                None,
            )
            .await;
            honest_apps.push((idx, node.application.clone()));

            let application =
                <AlwaysAcceptBlockBuilderApp<Ctx<P>, SchemeOf<P>> as TwinsBlockBuilder<P>>::create(
                    ApplicationChoice::AlwaysAccept,
                    faulty_config,
                    None,
                    block_contexts.clone(),
                    DeliveryReporter::new(idx, node.application.clone(), None, stack_label.clone()),
                );
            let builder = <DeferredMarshal as TwinsMarshal<P, _>>::create(
                MarshalChoice::Deferred,
                &validator_ctx,
                application,
                node.mailbox.clone(),
            );
            node.start(builder.clone());
            let observed = ObservedMarshal {
                validator: idx,
                probe_input: probe_input.clone(),
                context: Arc::new(Mutex::new(validator_ctx.child("automaton_invariants"))),
                inner: builder.clone(),
                certification_agreement: certification_agreement.clone(),
                header_mismatch: HeaderMismatchInvariant::<P, FaultyConfig>::new(
                    ApplicationChoice::AlwaysAccept,
                    faulty_config,
                    always_accepts::<Ctx<P>>,
                    block_contexts.clone(),
                    MarshalChoice::Deferred,
                    stack_label.clone(),
                ),
            };

            start_engine::<P, _, _, _>(
                validator_ctx,
                &oracle,
                validator.clone(),
                scheme,
                P::elector(term_length, crate::PINNED_OPTIMISTIC_VIEWS),
                observed,
                builder,
                node.mailbox.clone(),
                genesis_commitment,
                format!("marshal-liveness-{idx}"),
                input.forwarding,
                vote,
                certificate,
                resolver,
            );
        }

        let on_stall = |missed: &[usize], diag: &str| {
            if let Some(poison) = poison.as_ref().filter(|_| missed.contains(&POISON_IDX)) {
                invariants::check_certificate_backfill_retry(poison, diag);
            }
        };
        run_liveness_phases(
            &context,
            &oracle,
            &participants,
            &honest_apps,
            required,
            Some(&on_stall),
        )
        .await;

        invariants::check_all_blocks(
            &honest_apps,
            genesis_commitment,
            commonware_consensus::types::Height::zero(),
            None,
        );
    });
}

/// Crypto: `P`. Marshal: coding. Cluster: `N4F1C3`,
/// disrupter only (no Twins). Liveness: checked. App: fixed always-accept.
///
/// The Commitment-typed disrupter signs conflicting coding proposals with the
/// Byzantine identity's key, so notarize and finalize equivocations reach the
/// honest engines instead of being discarded during decoding.
pub fn fuzz_marshal_coding_disrupter<P>(input: MarshalDisrupterInput)
where
    P: Simplex,
    SchemeOf<P>: SimplexScheme<Commitment>,
{
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let (participants, schemes) = P::setup(&mut context, crate::NAMESPACE, NUM_VALIDATORS);

        let mut oracle = setup_network::<P>(context.child("network"), participants.clone()).await;
        setup_network_links::<P>(&mut oracle, &participants).await;
        if input.degraded_network {
            apply_degraded_network::<P>(&mut oracle, &participants).await;
        }

        let required = input.required_containers;

        let pre_gst_partition: Option<SetPartition> = input.partition.set_partition().copied();
        if let Some(partition) = pre_gst_partition.as_ref() {
            apply_partition(&oracle, &participants, Some(partition), &LINK).await;
        }

        let genesis = coding_genesis::<P>(participants[0].clone());
        let genesis_digest = genesis.inner().digest();
        let genesis_commitment = genesis.commitment();
        let block_contexts = BlockContextRegistry::<CodingCtx<P>>::default();
        block_contexts.record(genesis_digest, genesis.inner().context.clone());
        let mut fault_rng = FuzzRng::new(input.raw_bytes.clone());
        let faulty_config = FaultyConfig::new(&mut fault_rng, View::new(0));
        let stack_label: Arc<str> =
            "application=always-accept marshal=coding max_pending_acks=64".into();
        let probe_input: Arc<str> = format!("{:?}", MarshalDisrupterInputDebug(&input)).into();
        let certification_agreement = CertificationAgreementInvariant::coding(stack_label.clone());

        let mut honest_apps: Vec<(usize, Application<CodingB<P>>)> = Vec::new();

        for (idx, validator) in participants.iter().enumerate() {
            let scheme = schemes[idx].clone();
            let (vote, certificate, resolver) =
                register_engine_networks::<P>(&oracle, validator.clone()).await;

            if idx == BYZANTINE_IDX {
                coding_disrupter::start::<P>(
                    context
                        .child("validator")
                        .with_attribute("public_key", validator)
                        .child("disrupter"),
                    scheme,
                    input.strategy,
                    required,
                    vote,
                    certificate,
                    resolver,
                );
                continue;
            }

            let validator_ctx = context
                .child("validator")
                .with_attribute("public_key", validator);
            let provider = ConstantProvider::new(scheme.clone());
            let node = setup_validator_coding::<P>(
                validator_ctx.child("marshal"),
                &mut oracle,
                validator.clone(),
                provider.clone(),
                genesis.clone(),
                MAX_PENDING_ACKS,
                None,
                idx,
                stack_label.clone(),
            )
            .await;
            honest_apps.push((idx, node.application.clone()));

            let marshaled = coding_marshaled::<P, _>(
                &validator_ctx,
                provider,
                AlwaysAcceptBlockBuilderApp::<CodingCtx<P>, SchemeOf<P>>::default()
                    .with_block_contexts(block_contexts.clone()),
                node.mailbox.clone(),
                node.shards,
            );
            let observed = ObservedMarshal {
                validator: idx,
                probe_input: probe_input.clone(),
                context: Arc::new(Mutex::new(validator_ctx.child("automaton_invariants"))),
                inner: marshaled.clone(),
                certification_agreement: certification_agreement.clone(),
                header_mismatch: HeaderMismatchInvariant::<P, FaultyConfig, Commitment>::coding(
                    ApplicationChoice::AlwaysAccept,
                    faulty_config,
                    always_accepts::<CodingCtx<P>>,
                    block_contexts.clone(),
                    stack_label.clone(),
                ),
            };
            start_engine_coding_with_networks::<P, _, _, _>(
                validator_ctx,
                &oracle,
                validator.clone(),
                scheme,
                P::elector(TermLength::ONE, crate::PINNED_OPTIMISTIC_VIEWS),
                observed,
                marshaled,
                node.mailbox,
                genesis_commitment,
                input.forwarding,
                vote,
                certificate,
                resolver,
            );
        }

        run_liveness_phases(
            &context,
            &oracle,
            &participants,
            &honest_apps,
            required,
            None,
        )
        .await;

        invariants::check_all_blocks(
            &honest_apps,
            genesis_digest,
            commonware_consensus::types::Height::zero(),
            None,
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SimplexCertificateMock, strategy::StrategyChoice, utils::Partition};
    use commonware_consensus::simplex::ForwardPolicy;

    #[cfg(feature = "mocks")]
    #[test]
    fn block_dissemination_runs_under_byzantine_first_leader() {
        use commonware_consensus::types::TermLength;
        for term_length in [
            TermLength::ONE,
            TermLength::new(commonware_utils::NZU32!(2)),
        ] {
            fuzz_marshal_standard_block_dissemination::<
                crate::SimplexCertificateMockByzantineFirstLeader,
            >(MarshalDisrupterInput {
                raw_bytes: vec![],
                required_containers: 1,
                term_length,
                degraded_network: true,
                partition: Partition::Connected,
                strategy: StrategyChoice::AnyScope,
                forwarding: ForwardPolicy::Disabled,
            });
        }
    }

    #[test]
    fn coding_disrupter_runs_under_certificate_mock() {
        fuzz_marshal_coding_disrupter::<SimplexCertificateMock>(MarshalDisrupterInput {
            raw_bytes: vec![0],
            required_containers: 1,
            term_length: commonware_consensus::types::TermLength::ONE,
            degraded_network: false,
            partition: Partition::Connected,
            strategy: StrategyChoice::SmallScope {
                fault_rounds: 1,
                fault_rounds_bound: 1,
            },
            forwarding: ForwardPolicy::Disabled,
        });
    }
}
