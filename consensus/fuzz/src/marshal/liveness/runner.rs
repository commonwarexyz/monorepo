//! Multi-node marshal liveness driver.
//!
//! Runs `N4F1C3` (three honest validators plus one byzantine `Disrupter`)
//! over the simulated network and reuses the shared fuzz infrastructure
//! (`setup_network`-style helpers, the byzantine `Disrupter`, strategy
//! sampling, [`FuzzInput`]) exactly as the general harness does. The honest
//! validators are parametrized by the *marshal sink* instead of the reporter
//! sink (see [`LiveMarshal`]): each runs a live simplex engine whose `reporter`
//! is a marshal mailbox, and marshal delivers ordered finalized blocks to a
//! downstream [`Application`] sink.
//!
//! Liveness (the design borrowed from ByzzFuzz, not its code): every honest
//! node's marshal must deliver `required_containers` ordered finalized blocks
//! within a bounded window; a stall panics with a per-node diagnostic. Safety
//! invariants then assert in-order delivery and cross-node agreement.
//!
//! Generic over the marshal variant `H`, so the same driver serves the standard
//! and coding fuzz targets.
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
//! - Standard: the disrupter's `Sha256Digest` votes share both the epoch and
//!   the payload type with the honest engines, so it is a fully in-epoch
//!   equivocating/mutating adversary.
//! - Coding: the consensus payload is `Commitment`, not `Sha256Digest`, so the
//!   disrupter's votes remain undecodable by honest coding engines and it
//!   degrades to a withholding fault. (A coding-aware disrupter is future work.)
//!
//! Either way the three honest validators (`QUORUM = 3`) must still deliver
//! `required_containers` ordered blocks.

use super::{engine::LiveMarshal, invariant, ENGINE_CERTIFICATE, ENGINE_RESOLVER, ENGINE_VOTE};
use crate::{simplex::Simplex, start_disrupter_with_epoch, FuzzInput, SimplexBls12381MinPk};
use commonware_consensus::{
    marshal::mocks::{
        application::Application,
        harness::{
            setup_network_links, setup_network_with_participants, K, LINK, NUM_VALIDATORS, S,
            TEST_QUOTA,
        },
    },
    types::Epoch,
};
use commonware_cryptography::certificate::ConstantProvider;
use commonware_macros::select;
use commonware_runtime::{deterministic, Clock, Runner, Spawner, Supervisor as _};
use commonware_utils::{FuzzRng, NZUsize};
use futures::future::join_all;
use std::{num::NonZeroUsize, time::Duration};

/// Byzantine validator index; the other three run honest marshal validators.
const BYZANTINE_IDX: usize = 0;

/// Upper bound on the delivery target. Kept well below the epoch-0 boundary
/// (`FixedEpocher::new(20)` makes height 19 the last block in epoch 0, after
/// which the wrappers re-propose the boundary block) so the run stays single
/// epoch and never stalls on an epoch transition.
const MAX_REQUIRED: u64 = 12;

/// Generous backlog so marshal never blocks on ack pressure; the downstream
/// application auto-acks.
const MAX_PENDING_ACKS: NonZeroUsize = NZUsize!(64);

/// Bounded liveness window (simulated time). A stall panics with a diagnostic.
const LIVENESS_WINDOW: Duration = Duration::from_secs(600);

/// Poll interval for observing marshal delivery progress.
const POLL: Duration = Duration::from_millis(50);

/// Run a single multi-node marshal liveness iteration for variant `H`.
pub fn fuzz_marshal_liveness<H: LiveMarshal>(input: FuzzInput) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        // Shared threshold fixture: the same participants/schemes drive the
        // byzantine disrupter, the honest engines, and the marshal providers.
        let (participants, schemes): (Vec<K>, Vec<S>) =
            SimplexBls12381MinPk::setup(&mut context, crate::NAMESPACE, NUM_VALIDATORS);

        let mut oracle = setup_network_with_participants(
            context.child("network"),
            NZUsize!(1),
            participants.clone(),
        )
        .await;
        setup_network_links(&mut oracle, &participants, LINK).await;

        let required = input.required_containers.clamp(1, MAX_REQUIRED);

        // Consensus genesis commitment must equal the marshal genesis block's
        // commitment so view-1 proposals link to the block marshal already
        // holds via `Start::Genesis`.
        let genesis_commitment = H::commitment(&H::genesis_block(NUM_VALIDATORS as u16));

        // Spawned marshal actors run until the root future completes; their
        // handles detach on drop (they do not abort), so we don't retain them.
        let mut honest_apps: Vec<(usize, Application<H::ApplicationBlock>)> = Vec::new();

        for (idx, validator) in participants.iter().enumerate() {
            let scheme = schemes[idx].clone();

            if idx == BYZANTINE_IDX {
                let control = oracle.control(validator.clone());
                let vote = control.register(ENGINE_VOTE, TEST_QUOTA).await.unwrap();
                let certificate = control
                    .register(ENGINE_CERTIFICATE, TEST_QUOTA)
                    .await
                    .unwrap();
                let resolver = control.register(ENGINE_RESOLVER, TEST_QUOTA).await.unwrap();
                start_disrupter_with_epoch::<SimplexBls12381MinPk>(
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

            // Honest validator: marshal stack (channels 1, 2) + live engine.
            let validator_ctx = context
                .child("validator")
                .with_attribute("public_key", validator);
            let provider = ConstantProvider::new(scheme.clone());
            let setup = H::setup_validator_with(
                validator_ctx.child("marshal"),
                &mut oracle,
                validator.clone(),
                provider.clone(),
                MAX_PENDING_ACKS,
                Application::<H::ApplicationBlock>::default(),
            )
            .await;
            honest_apps.push((idx, setup.application));

            H::spawn_engine(
                validator_ctx,
                &oracle,
                validator.clone(),
                scheme,
                provider,
                setup.mailbox,
                setup.extra,
                genesis_commitment,
            )
            .await;
        }

        // Liveness (ByzzFuzz design): every honest marshal must deliver
        // `required` ordered finalized blocks within the window.
        let mut watchers = Vec::new();
        for (idx, app) in honest_apps.iter().cloned() {
            watchers.push(
                context
                    .child("liveness_watcher")
                    .with_attribute("index", idx)
                    .spawn(move |context| async move {
                        while (app.blocks().len() as u64) < required {
                            context.sleep(POLL).await;
                        }
                    }),
            );
        }

        // Every watcher must return `Ok(())`; an aborted or panicked watcher
        // (an `Err`) must not be mistaken for satisfied liveness.
        let delivered = select! {
            results = join_all(watchers) => results.iter().all(|r| matches!(r, Ok(()))),
            _ = context.sleep(LIVENESS_WINDOW) => false,
        };
        if !delivered {
            let diag: Vec<String> = honest_apps
                .iter()
                .map(|(idx, app)| format!("node{idx}={}", app.blocks().len()))
                .collect();
            panic!(
                "marshal liveness violation: honest nodes did not deliver {required} blocks \
                 within {LIVENESS_WINDOW:?}; delivered={diag:?}"
            );
        }

        invariant::check_all::<H>(required, &honest_apps);
    });
}
