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
    simplex::Simplex,
    start_disrupter_with_epoch,
    utils::{SetPartition, apply_partition},
};
use commonware_consensus::{
    Block,
    marshal::mocks::{
        application::Application,
        harness::{LINK, NUM_VALIDATORS},
    },
    types::{Epoch, TermLength, View},
};
use commonware_cryptography::{Committable as _, Digestible as _, certificate::ConstantProvider};
use commonware_p2p::simulated::Link;
use commonware_runtime::{Clock, Runner, Supervisor as _, deterministic};
use commonware_utils::{FuzzRng, NZUsize};
use std::{fmt::Write as _, num::NonZeroUsize, time::Duration};

/// Tight backlog so manual acknowledgements and backpressure stay observable.
const MAX_PENDING_ACKS: NonZeroUsize = NZUsize!(2);

/// Poll interval for observing marshal delivery progress.
const POLL: Duration = Duration::from_millis(50);

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
            for &(idx, baseline, target) in &watch_targets {
                let current = honest_apps
                    .iter()
                    .find(|(i, _)| *i == idx)
                    .map_or(0, |(_, app)| highest_delivered(app));
                let _ = write!(
                    diag,
                    " node{idx}={{baseline={baseline} target={target} current={current}}}"
                );
            }
            panic!("marshal: no post-GST progress within {POST_GST_WINDOW:?};{diag}");
        }
    }
}

/// Crypto: `P` (target uses `SimplexCertificateMock`). Marshal: standard,
/// deferred. Cluster: `N4F1C3`, disrupter only (no Twins). Liveness: checked.
/// App: fixed always-accept.
pub fn fuzz_marshal_standard_disrupter<P: Simplex>(input: MarshalDisrupterInput) {
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
                        Some(MAX_PENDING_ACKS),
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

        run_liveness_phases(&context, &oracle, &participants, &honest_apps, required).await;

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
                idx,
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

        run_liveness_phases(&context, &oracle, &participants, &honest_apps, required).await;

        invariants::check_all_blocks(&honest_apps, None);
    });
}
