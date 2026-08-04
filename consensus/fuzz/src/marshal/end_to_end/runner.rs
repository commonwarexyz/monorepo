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
//!   or baseline + 1 unless already at `MAX_REQUIRED`) within [`POST_GST_WINDOW`];
//!   failure to make progress panics with a per-node diagnostic.
//!
//! Safety invariants then assert in-order delivery and cross-node agreement.
//!
//! Generic over the consensus scheme `P`, so the same driver serves every
//! certificate scheme (the fuzz targets use the cheap `SimplexCertificateMock`
//! and `SimplexId` mocks rather than real threshold signatures).
//!
//! # Adversary scope
//!
//! The marshal-backed honest engines run at `Epoch::zero()`: marshal's epoch
//! check ties the consensus epoch to `epocher.containing(height)`, and the
//! harness `FixedEpocher(20)` maps the low test heights to epoch 0. So the
//! byzantine `Disrupter` is started via [`start_disrupter_with_epoch`] with
//! `Epoch::zero()` (the consensus-wide `crate::EPOCH` is left unchanged) so it
//! emits messages in the same epoch the honest engines run in.
//!
//! The disrupter's `Sha256Digest` votes share both the epoch and the payload
//! type with the honest engines, so it is a fully in-epoch equivocating and
//! mutating adversary. The three honest validators must still deliver the
//! target number of ordered blocks.

use super::{
    MAX_REQUIRED,
    app::{
        AlwaysAcceptBlockBuilderApp, ApplicationChoice, BlockContextRegistry, DeliveryReporter,
        FaultyConfig,
    },
    coding_stack::{CodingB, coding_genesis, setup_validator_coding, start_engine_coding},
    input::MarshalDisrupterInput,
    invariants,
    twins::{
        B, Ctx, PublicKeyOf, SchemeOf,
        stack::{
            DeferredMarshal, MarshalChoice, TwinsBlockBuilder, TwinsMarshal, genesis_block,
            register_engine_networks, setup_network, setup_network_links, setup_validator,
            start_engine,
        },
    },
};
use crate::{
    BYZANTINE_IDX, FAULT_PHASE, POST_GST_WINDOW, SimplexCertificateMock,
    network::{CertificatePoison, CertificatePoisonReceiver},
    simplex::Simplex,
    start_disrupter_with_epoch,
    utils::{Partition, SetPartition, apply_partition},
};
use commonware_consensus::{
    Block,
    marshal::mocks::{
        application::Application,
        harness::{LINK, NUM_VALIDATORS},
    },
    types::{Epoch, TermLength, View},
};
use commonware_cryptography::{
    Committable as _, Digestible as _, certificate::ConstantProvider,
    sha256::Digest as Sha256Digest,
};
use commonware_p2p::simulated::Link;
use commonware_runtime::{Clock, Runner, Supervisor as _, deterministic};
use commonware_utils::{FuzzRng, NZUsize};
use std::{fmt::Write as _, num::NonZeroUsize, time::Duration};

/// Generous backlog so marshal never blocks on ack pressure; the downstream
/// application auto-acks.
const MAX_PENDING_ACKS: NonZeroUsize = NZUsize!(64);

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
        success_rate: 0.6,
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
fn highest_delivered<B: Block>(app: &Application<B>) -> u64 {
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
        let phase2_complete =
            wait_for_targets(context, honest_apps, &phase2_targets, POST_GST_WINDOW).await;

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
            panic!("marshal: no post-GST progress within {POST_GST_WINDOW:?};{diag}");
        }
    }
}

/// Crypto: `P` (target uses `SimplexCertificateMock`). Marshal: standard,
/// deferred. Cluster: `N4F1C3`, disrupter only (no Twins). Liveness: checked.
/// App: fixed always-accept.
pub fn fuzz_marshal_standard_disrupter<P: Simplex>(input: MarshalDisrupterInput) {
    run_standard_disrupter::<P>(input, None);
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
    run_standard_disrupter::<P>(input, Some(CertificatePoison::new()));
}

fn run_standard_disrupter<P: Simplex>(
    input: MarshalDisrupterInput,
    poison: Option<CertificatePoison<PublicKeyOf<P>>>,
) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

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

        // Spawned marshal actors run until the root future completes; their
        // handles detach on drop (they do not abort), so we don't retain them.
        let mut honest_apps: Vec<(usize, Application<B<P>>)> = Vec::new();

        for (idx, validator) in participants.iter().enumerate() {
            let scheme = schemes[idx].clone();
            let (vote, certificate, resolver) =
                register_engine_networks::<P>(&oracle, validator.clone()).await;

            if idx == BYZANTINE_IDX {
                start_disrupter_with_epoch::<P>(
                    context
                        .child("validator")
                        .with_attribute("public_key", validator)
                        .child("disrupter"),
                    scheme,
                    &input.strategy,
                    required,
                    Epoch::zero(),
                    vote,
                    certificate,
                    resolver,
                );
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
                genesis_marshal_block.clone(),
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
                    DeliveryReporter::new(
                        idx,
                        node.application.clone(),
                        None,
                        "marshal-liveness".into(),
                    ),
                );
            let builder = <DeferredMarshal as TwinsMarshal<P, _>>::create(
                MarshalChoice::Deferred,
                &validator_ctx,
                application,
                node.mailbox.clone(),
            );
            node.start(builder.clone());

            start_engine::<P, _, _, _>(
                validator_ctx,
                &oracle,
                validator.clone(),
                scheme,
                P::elector(TermLength::ONE),
                builder.clone(),
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

        invariants::check_all_blocks(&honest_apps, None);
    });
}

/// Crypto: `SimplexCertificateMock`. Marshal: coding. Cluster: `N4F1C3`,
/// disrupter only (no Twins). Liveness: checked. App: fixed always-accept.
///
/// The disrupter signs `Sha256Digest`, but coding's payload is `Commitment`, so
/// its notarize/finalize votes degrade to withholding; nullify stays effective.
pub fn fuzz_marshal_coding_disrupter(input: MarshalDisrupterInput) {
    type P = SimplexCertificateMock;

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

        let genesis = coding_genesis();
        let genesis_commitment = genesis.commitment();

        let mut honest_apps: Vec<(usize, Application<CodingB>)> = Vec::new();

        for (idx, validator) in participants.iter().enumerate() {
            let scheme = schemes[idx].clone();

            if idx == BYZANTINE_IDX {
                let (vote, certificate, resolver) =
                    register_engine_networks::<P>(&oracle, validator.clone()).await;
                start_disrupter_with_epoch::<P>(
                    context
                        .child("validator")
                        .with_attribute("public_key", validator)
                        .child("disrupter"),
                    scheme,
                    &input.strategy,
                    required,
                    Epoch::zero(),
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
            let node = setup_validator_coding(
                validator_ctx.child("marshal"),
                &mut oracle,
                validator.clone(),
                provider.clone(),
                genesis.clone(),
                MAX_PENDING_ACKS,
            )
            .await;
            honest_apps.push((idx, node.application.clone()));

            start_engine_coding::<_>(
                validator_ctx,
                &oracle,
                validator.clone(),
                scheme,
                P::elector(TermLength::ONE),
                provider,
                node.mailbox,
                node.shards,
                genesis_commitment,
                input.forwarding,
            )
            .await;
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

        invariants::check_all_blocks(&honest_apps, None);
    });
}

/// Reproduction of the split-notarization wedge.
///
/// Not a fuzz target: the schedule is fixed and the oracle is expected to fire,
/// so it is driven from tests rather than from a fuzz entry point.
#[cfg(test)]
pub(super) mod wedge {
    use super::*;
    use crate::network::{
        ByzantineFirstReceiver, Router, Wedge, WedgeChannel, WedgeDrop, WedgeEvent, WedgeNode,
        WedgePhase, WedgeReceiver, WedgeRequest, WedgeRole, drop_rate_cell,
    };
    use commonware_consensus::{simplex::ForwardingPolicy, types::Round};

    /// Participant index of the first block holder.
    const WEDGE_HOLDER_A: usize = 0;
    /// Participant index of the byzantine node. The round-robin elector picks
    /// `(epoch + view) % n`, so at epoch 0 this index leads the attack view.
    const WEDGE_BYZANTINE: usize = 1;
    /// Participant index of the second block holder.
    const WEDGE_HOLDER_B: usize = 2;
    /// Participant index of the victim.
    const WEDGE_VICTIM: usize = 3;
    /// View the byzantine node leads and alone notarizes.
    const WEDGE_ATTACK_VIEW: View = View::new(1);

    /// Pre-GST window in which the victim is unreachable from every peer.
    const WEDGE_ISOLATION: Duration = Duration::from_secs(8);
    /// Pre-GST window in which every link is up but holder answers are slow.
    const WEDGE_ASYNC: Duration = Duration::from_secs(25);
    /// Post-GST settling window the cluster has to make progress in.
    const WEDGE_SETTLE: Duration = Duration::from_secs(60);

    /// Holder-to-victim link during the asynchronous window. Nothing is dropped:
    /// the latency simply exceeds the certificate-backfill timeout, so a holder
    /// answer arrives after the fetch that asked for it was retried elsewhere.
    const WEDGE_SLOW_LINK: Link = Link {
        latency: Duration::from_secs(4),
        jitter: Duration::from_millis(10),
        success_rate: 1.0,
    };

    /// Recovery path enabled after GST, if any.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum WedgeControl {
        /// The byzantine node keeps withholding.
        None,
        /// The byzantine node serves its attack-round block after GST.
        ServeNotarized,
        /// The attack-view nullification is delivered to the victim once after GST.
        DeliverNullification,
    }

    impl WedgeControl {
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::None => "wedge",
                Self::ServeNotarized => "control-serve-notarized",
                Self::DeliverNullification => "control-deliver-nullification",
            }
        }
    }

    /// What one split-notarization run produced.
    pub struct WedgeOutcome {
        pub seed: u64,
        pub control: WedgeControl,
        /// Highest finalized block height each correct node's marshal delivered.
        pub heights: Vec<(String, u64)>,
        pub honest_drops_pre_gst: usize,
        pub honest_drops_post_gst: usize,
        pub byzantine_withholds: usize,
        /// Messages the harness withheld on the certificate-backfill channel.
        pub resolver_drops: usize,
        pub ledger: Vec<(WedgeDrop, WedgePhase, usize)>,
        pub events: Vec<WedgeEvent>,
        /// Attack-view certificate requests the victim sent, as seen by the peers
        /// it asked.
        pub requests: Vec<WedgeRequest>,
        /// Attack-view proposal payload, learned from the notarization the victim
        /// was served.
        pub attack_payload: Option<Sha256Digest>,
    }

    impl WedgeOutcome {
        /// Observations the victim made, in arrival order.
        pub fn victim_events(&self) -> impl Iterator<Item = &WedgeEvent> {
            self.events.iter().filter(|event| event.node == "V")
        }

        /// Observations the victim made at or after GST.
        pub fn victim_events_post_gst(&self) -> impl Iterator<Item = &WedgeEvent> {
            self.victim_events()
                .filter(|event| event.phase == WedgePhase::PostGst)
        }
    }

    /// Runs the split-notarization scenario.
    ///
    /// Cluster: `N4F1C3` with `TermLength::ONE` and the deferred marshal wrapper,
    /// every node a full engine. The byzantine node leads the attack view and is
    /// byzantine only through what the network layer lets it withhold (see
    /// [`WedgeReceiver`]).
    ///
    /// Phases:
    /// - isolation: the victim is unreachable from every peer, so it never sees the
    ///   attack block, the attack notarization, or the attack view's nullification.
    ///   Its own messages still reach everyone, so the cluster nullifies the attack
    ///   view with its vote and moves on;
    /// - asynchronous: every link is restored, holder-to-victim links slower than
    ///   the backfill timeout. The victim backfills the attack view and the
    ///   byzantine node's answer wins;
    /// - post-GST: every link is healed and every honest-message rule is disarmed.
    pub fn run_split_notarization<P: Simplex>(seed: u64, control: WedgeControl) -> WedgeOutcome {
        let cfg = deterministic::Config::new().with_seed(seed);
        let executor = deterministic::Runner::new(cfg);

        executor.start(|mut context| async move {
            let (participants, schemes) = P::setup(&mut context, crate::NAMESPACE, NUM_VALIDATORS);
            let labels = [
                (participants[WEDGE_HOLDER_A].clone(), "H0".to_string()),
                (participants[WEDGE_BYZANTINE].clone(), "B".to_string()),
                (participants[WEDGE_HOLDER_B].clone(), "H1".to_string()),
                (participants[WEDGE_VICTIM].clone(), "V".to_string()),
            ];
            let victim = participants[WEDGE_VICTIM].clone();

            let mut oracle = setup_network::<P>(context.child("network"), participants.clone()).await;
            setup_network_links::<P>(&mut oracle, &participants).await;

            // Step 1: the victim is unreachable from its peers before any message
            // is sent, so nothing is in flight to it when the links go down. Its
            // outbound links stay up, which is what lets the cluster nullify the
            // attack view without it ever collecting those votes itself.
            for peer in [WEDGE_HOLDER_A, WEDGE_BYZANTINE, WEDGE_HOLDER_B] {
                oracle
                    .remove_link(participants[peer].clone(), victim.clone())
                    .await
                    .ok();
            }

            let wedge = Wedge::new(
                context.child("wedge"),
                participants[WEDGE_BYZANTINE].clone(),
                victim.clone(),
                labels,
                Round::new(Epoch::zero(), WEDGE_ATTACK_VIEW),
            );
            match control {
                WedgeControl::None => {}
                WedgeControl::ServeNotarized => wedge.enable_serve_after_gst(),
                WedgeControl::DeliverNullification => wedge.enable_nullification_injection(),
            }

            let genesis_marshal_block = genesis_block::<P>(participants[0].clone());
            let genesis_commitment = genesis_marshal_block.digest();
            let block_contexts = BlockContextRegistry::<Ctx<P>>::default();
            block_contexts.record(genesis_commitment, genesis_marshal_block.context.clone());
            let mut fault_rng = FuzzRng::new(vec![0u8; 32]);
            let faulty_config = FaultyConfig::new(&mut fault_rng, View::new(0));

            // Byzantine-first delivery ordering, cluster-wide: whenever a byzantine
            // message and an honest message are both ready, the byzantine one is
            // serviced first. Ordering is legal at every point in the run, so this
            // is never disarmed.
            let router = Router::new(
                context.child("byzantine_router"),
                [participants[WEDGE_BYZANTINE].clone()],
                drop_rate_cell(),
            );

            let mut apps: Vec<(String, Application<B<P>>)> = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                let scheme = schemes[idx].clone();
                let role = match idx {
                    WEDGE_BYZANTINE => WedgeRole::Byzantine,
                    WEDGE_VICTIM => WedgeRole::Victim,
                    _ => WedgeRole::Holder,
                };
                let node = WedgeNode::new(wedge.clone(), validator.clone(), role, scheme.clone());

                let (vote, certificate, resolver) =
                    register_engine_networks::<P>(&oracle, validator.clone()).await;
                let (vote_sender, vote_receiver) = vote;
                let (certificate_sender, certificate_receiver) = certificate;
                let (resolver_sender, resolver_receiver) = resolver;

                let vote_router = router.clone();
                let (vote_primary, vote_secondary) = vote_receiver
                    .split_with(context.child("byzantine_first_vote"), move |message| {
                        vote_router.route(message)
                    });
                let vote = (
                    vote_sender,
                    WedgeReceiver::<SchemeOf<P>, Sha256Digest, B<P>, _>::new(
                        ByzantineFirstReceiver::new(vote_primary, vote_secondary),
                        Some(node.clone()),
                        WedgeChannel::Vote,
                    ),
                );

                let certificate_router = router.clone();
                let (certificate_primary, certificate_secondary) = certificate_receiver.split_with(
                    context.child("byzantine_first_certificate"),
                    move |message| certificate_router.route(message),
                );
                let certificate = (
                    certificate_sender,
                    WedgeReceiver::<SchemeOf<P>, Sha256Digest, B<P>, _>::new(
                        ByzantineFirstReceiver::new(certificate_primary, certificate_secondary),
                        Some(node.clone()),
                        WedgeChannel::Certificate,
                    ),
                );

                let resolver_router = router.clone();
                let (resolver_primary, resolver_secondary) = resolver_receiver
                    .split_with(context.child("byzantine_first_resolver"), move |message| {
                        resolver_router.route(message)
                    });
                let resolver = (
                    resolver_sender,
                    WedgeReceiver::<SchemeOf<P>, Sha256Digest, B<P>, _>::new(
                        ByzantineFirstReceiver::new(resolver_primary, resolver_secondary),
                        Some(node.clone()),
                        WedgeChannel::Resolver,
                    ),
                );

                let validator_ctx = context
                    .child("validator")
                    .with_attribute("public_key", validator);
                let provider = ConstantProvider::new(scheme.clone());
                let mut marshal_node = setup_validator::<P>(
                    validator_ctx.child("marshal"),
                    &mut oracle,
                    validator.clone(),
                    provider,
                    genesis_marshal_block.clone(),
                    MAX_PENDING_ACKS,
                    Some(node),
                )
                .await;
                let label = match idx {
                    WEDGE_HOLDER_A => "H0",
                    WEDGE_BYZANTINE => "B",
                    WEDGE_HOLDER_B => "H1",
                    _ => "V",
                };
                apps.push((label.to_string(), marshal_node.application.clone()));

                let application =
                    <AlwaysAcceptBlockBuilderApp<Ctx<P>, SchemeOf<P>> as TwinsBlockBuilder<P>>::create(
                        ApplicationChoice::AlwaysAccept,
                        faulty_config,
                        None,
                        block_contexts.clone(),
                        DeliveryReporter::new(
                            idx,
                            marshal_node.application.clone(),
                            None,
                            "marshal-wedge".into(),
                        ),
                    );
                let builder = <DeferredMarshal as TwinsMarshal<P, _>>::create(
                    MarshalChoice::Deferred,
                    &validator_ctx,
                    application,
                    marshal_node.mailbox.clone(),
                );
                marshal_node.start(builder.clone());

                start_engine::<P, _, _, _>(
                    validator_ctx,
                    &oracle,
                    validator.clone(),
                    scheme,
                    P::elector(TermLength::ONE),
                    builder.clone(),
                    builder,
                    marshal_node.mailbox.clone(),
                    genesis_commitment,
                    format!("marshal-wedge-{idx}"),
                    // The most aggressive forwarding policy: any correct node that
                    // certifies the attack view pushes its block to every peer that
                    // did not vote for it, the victim included.
                    ForwardingPolicy::SilentVoters,
                    vote,
                    certificate,
                    resolver,
                );
            }

            context.sleep(WEDGE_ISOLATION).await;

            // The victim becomes reachable again. Holder links are slower than the
            // certificate-backfill timeout for the rest of the pre-GST phase; every
            // message they carry is still delivered.
            for peer in [WEDGE_HOLDER_A, WEDGE_HOLDER_B] {
                oracle
                    .add_link(
                        participants[peer].clone(),
                        victim.clone(),
                        WEDGE_SLOW_LINK.clone(),
                    )
                    .await
                    .unwrap();
            }
            oracle
                .add_link(
                    participants[WEDGE_BYZANTINE].clone(),
                    victim.clone(),
                    LINK.clone(),
                )
                .await
                .unwrap();
            wedge.set_phase(WedgePhase::Asynchronous);

            context.sleep(WEDGE_ASYNC).await;

            // GST: every link healed, every honest-message rule disarmed.
            apply_partition(&oracle, &participants, None, &LINK).await;
            wedge.set_phase(WedgePhase::PostGst);

            context.sleep(WEDGE_SETTLE).await;

            WedgeOutcome {
                seed,
                control,
                heights: apps
                    .iter()
                    .map(|(label, app)| (label.clone(), highest_delivered(app)))
                    .collect(),
                honest_drops_pre_gst: wedge.honest_drops(WedgePhase::Isolated)
                    + wedge.honest_drops(WedgePhase::Asynchronous),
                honest_drops_post_gst: wedge.honest_drops(WedgePhase::PostGst),
                byzantine_withholds: wedge.byzantine_withholds(),
                resolver_drops: wedge.channel_drops(WedgeChannel::Resolver),
                ledger: wedge.drop_ledger(),
                events: wedge.events(),
                requests: wedge.victim_requests(),
                attack_payload: wedge.attack_payload(),
            }
        })
    }

    #[cfg(test)]
    mod wedge_repro {
        use super::*;

        fn seeds() -> Vec<u64> {
            std::env::var("WEDGE_SEEDS").map_or_else(
                |_| vec![0, 1, 2, 3, 4, 5],
                |raw| {
                    raw.split(',')
                        .filter_map(|seed| seed.trim().parse().ok())
                        .collect()
                },
            )
        }

        fn report(outcome: &WedgeOutcome, verbose: bool) {
            println!(
                "\n=== seed={} scenario={} heights={:?}",
                outcome.seed,
                outcome.control.as_str(),
                outcome.heights
            );
            println!(
                "    drops honest(pre)={} honest(post)={} byzantine={} resolver-channel={}",
                outcome.honest_drops_pre_gst,
                outcome.honest_drops_post_gst,
                outcome.byzantine_withholds,
                outcome.resolver_drops
            );
            for (drop, phase, count) in &outcome.ledger {
                println!("    ledger {drop:?} {phase:?} = {count}");
            }
            println!("    attack payload = {:?}", outcome.attack_payload);
            println!(
                "    victim attack-view requests ({}):",
                outcome.requests.len()
            );
            for request in &outcome.requests {
                println!(
                    "      t={:>8.3}s -> {} id={} view={}",
                    request.at.as_secs_f64(),
                    request.responder,
                    request.id,
                    request.view
                );
            }
            let answered_by = outcome.events.iter().find(|event| {
                event.node == "V" && event.detail.contains("ANSWER notarization view=1")
            });
            println!(
                "    byzantine answer: {}",
                answered_by.map_or_else(|| "none".to_string(), std::string::ToString::to_string)
            );
            if let Some(answer) = answered_by {
                let before = outcome.requests.iter().filter(|r| r.at < answer.at).count();
                let after = outcome.requests.iter().filter(|r| r.at > answer.at).count();
                println!("    attack-view requests before/after that answer: {before}/{after}");
            }
            let holder_nullifications: Vec<_> = outcome
                .events
                .iter()
                .filter(|event| {
                    event.node == "V" && event.detail.contains("ANSWER nullification view=1")
                })
                .collect();
            println!(
                "    attack-view nullifications delivered to the victim: {} ({} after GST)",
                holder_nullifications.len(),
                holder_nullifications
                    .iter()
                    .filter(|event| event.phase == WedgePhase::PostGst)
                    .count()
            );
            println!(
                "    attack block arrivals at the victim: {}",
                outcome
                    .victim_events()
                    .filter(|event| event.detail.contains("ATTACK BLOCK"))
                    .count()
            );
            println!(
                "    post-GST victim observations: {}",
                outcome.victim_events_post_gst().count()
            );
            let events: Vec<_> = if verbose {
                outcome.events.iter().collect()
            } else {
                outcome.victim_events().collect()
            };
            println!("    events ({}):", events.len());
            for event in events {
                println!("      {event}");
            }
        }

        #[test]
        fn split_notarization_wedge() {
            let verbose = std::env::var("WEDGE_VERBOSE").is_ok();
            let mut stalled = 0usize;
            let seeds = seeds();
            for seed in seeds.iter().copied() {
                let outcome =
                    run_split_notarization::<SimplexCertificateMock>(seed, WedgeControl::None);
                report(&outcome, verbose);
                invariants::check_split_notarization_phases(&outcome);
                match invariants::split_notarization_progress(&outcome) {
                    Ok(()) => println!("    VERDICT: cluster progressed (no wedge)"),
                    Err(diagnostic) => {
                        stalled += 1;
                        println!("    VERDICT: ORACLE FIRED: {diagnostic}");
                    }
                }
            }
            println!("\nSUMMARY wedge stalls {stalled}/{}", seeds.len());
        }

        #[test]
        fn split_notarization_controls() {
            let verbose = std::env::var("WEDGE_VERBOSE").is_ok();
            for control in [
                WedgeControl::ServeNotarized,
                WedgeControl::DeliverNullification,
            ] {
                let mut progressed = 0usize;
                let seeds = seeds();
                for seed in seeds.iter().copied() {
                    let outcome = run_split_notarization::<SimplexCertificateMock>(seed, control);
                    report(&outcome, verbose);
                    invariants::check_split_notarization_phases(&outcome);
                    invariants::check_split_notarization_progress(&outcome);
                    progressed += 1;
                    println!("    VERDICT: recovered");
                }
                println!(
                    "\nSUMMARY {} recovered {progressed}/{}",
                    control.as_str(),
                    seeds.len()
                );
            }
        }
    }
}
