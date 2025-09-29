//! A wrapper around an [Application] that intercepts messages from consensus and marshal,
//! hiding details of erasure coded broadcast and shard verification.

use crate::{
    marshal::{self, ingress::coding::types::CodedBlock},
    threshold_simplex::types::Context,
    types::{CodingCommitment, Round, View},
    Application, Automaton, Block, Epochable, Relay, Reporter, Supervisor, Viewable,
};
use commonware_coding::{Config as CodingConfig, Scheme};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Committable, PublicKey};
use commonware_runtime::{Clock, Metrics, Spawner};
use futures::{channel::oneshot, lock::Mutex};
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use std::{sync::Arc, time::Instant};
use tracing::{debug, info, warn};

/// An [Application] adapter that handles erasure coding and shard verification for consensus.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct CodingAdapter<E, A, V, B, S, P, Z>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    V: Variant,
    B: Block<Commitment = CodingCommitment>,
    S: Scheme,
    P: PublicKey,
    Z: Supervisor<Index = View, PublicKey = P>,
{
    context: E,
    application: A,
    marshal: marshal::Mailbox<V, B, S, P>,
    identity: P,
    supervisor: Z,
    last_built: Arc<Mutex<Option<(View, CodedBlock<B, S>)>>>,

    parent_fetch_duration: Gauge,
    build_duration: Gauge,
    erasure_code_duration: Gauge,
}

impl<E, A, V, B, S, P, Z> CodingAdapter<E, A, V, B, S, P, Z>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E, Block = B, Context = Context<B::Commitment>>,
    V: Variant,
    B: Block<Commitment = CodingCommitment>,
    S: Scheme,
    P: PublicKey,
    Z: Supervisor<Index = View, PublicKey = P>,
{
    pub fn new(
        context: E,
        application: A,
        marshal: marshal::Mailbox<V, B, S, P>,
        identity: P,
        supervisor: Z,
    ) -> Self {
        let parent_fetch_duration = Gauge::default();
        context.register(
            "parent_fetch_duration",
            "Time taken to fetch a parent block from marshal to build on top of, in milliseconds",
            parent_fetch_duration.clone(),
        );

        let build_duration = Gauge::default();
        context.register(
            "build_duration",
            "Time taken for the application to build a new block, in milliseconds",
            build_duration.clone(),
        );

        let erasure_code_duration = Gauge::default();
        context.register(
            "erasure_code_duration",
            "Time taken to erasure code a built block, in milliseconds",
            erasure_code_duration.clone(),
        );

        Self {
            context,
            application,
            marshal,
            identity,
            supervisor,
            last_built: Arc::new(Mutex::new(None)),

            parent_fetch_duration,
            build_duration,
            erasure_code_duration,
        }
    }
}

impl<E, A, V, B, S, P, Z> Automaton for CodingAdapter<E, A, V, B, S, P, Z>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E, Block = B, Context = Context<B::Commitment>>,
    V: Variant,
    B: Block<Commitment = CodingCommitment>,
    S: Scheme,
    P: PublicKey,
    Z: Supervisor<Index = View, PublicKey = P>,
{
    type Digest = B::Commitment;
    type Context = A::Context;

    async fn genesis(&mut self, epoch: <Self::Context as Epochable>::Epoch) -> Self::Digest {
        self.application.genesis(epoch).await.commitment()
    }

    async fn propose(&mut self, context: Context<Self::Digest>) -> oneshot::Receiver<Self::Digest> {
        let (parent_view, parent_commitment) = context.parent;
        let genesis = self.application.genesis(context.epoch()).await;
        let mut marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let last_built = self.last_built.clone();

        let participants = self
            .supervisor
            .participants(context.view())
            .expect("failed to get participants for round");

        // Compute the coding configuration from the number of participants.
        //
        // Currently, `CodingAdapter` mandates the use of `threshold_simplex`,
        // which requires at least `3f + 1` participants to tolerate `f` faults.
        let n_participants = participants.len() as u16;
        let coding_config = coding_config_for_participants(n_participants);

        // Metrics
        let parent_fetch_duration = self.parent_fetch_duration.clone();
        let build_duration = self.build_duration.clone();
        let erasure_code_duration = self.erasure_code_duration.clone();

        let (tx, rx) = oneshot::channel();
        self.context
            .with_label("propose")
            .spawn(move |r_ctx| async move {
                let start = Instant::now();
                let parent_block = if parent_commitment == genesis.commitment() {
                    genesis
                } else {
                    let block_request = marshal
                        .subscribe(
                            Some(Round::new(context.epoch(), parent_view)),
                            parent_commitment,
                        )
                        .await
                        .await;

                    if let Ok(block) = block_request {
                        block
                    } else {
                        warn!("propose job aborted");
                        return;
                    }
                };
                parent_fetch_duration.set(start.elapsed().as_millis() as i64);

                let start = Instant::now();
                let built_block = application
                    .build(r_ctx.with_label("build"), parent_commitment, parent_block)
                    .await;
                build_duration.set(start.elapsed().as_millis() as i64);

                let start = Instant::now();
                let coded_block = CodedBlock::new(built_block, coding_config);
                erasure_code_duration.set(start.elapsed().as_millis() as i64);

                let commitment = coded_block.commitment();

                // Update the latest built block.
                {
                    let mut lock = last_built.lock().await;
                    *lock = Some((context.view(), coded_block));
                }

                let result = tx.send(commitment);
                info!(
                    round = %context.round,
                    ?commitment,
                    success = result.is_ok(),
                    "proposed new block"
                );
            });
        rx
    }

    async fn verify(
        &mut self,
        context: Context<Self::Digest>,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let participants = self
            .supervisor
            .participants(context.view())
            .expect("failed to get participants for round");

        let coding_config = coding_config_for_participants(participants.len() as u16);
        let config_matches = payload.config() == coding_config;
        if !config_matches {
            warn!(
                round = %context.round,
                got = ?payload.config(),
                expected = ?coding_config,
                "rejected proposal with unexpected coding configuration"
            );

            let (tx, rx) = oneshot::channel();
            tx.send(false).expect("failed to send verify result");
            return rx;
        }

        let mut marshal = self.marshal.clone();
        let self_index = self
            .supervisor
            .is_participant(context.view(), &self.identity)
            .expect("failed to get self index among participants");

        #[allow(clippy::async_yields_async)]
        self.context
            .with_label("verify")
            .spawn(move |_| async move { marshal.verify_shard(payload, self_index as usize).await })
            .await
            .expect("failed to spawn verify task")
    }
}

impl<E, A, V, B, S, P, Z> Relay for CodingAdapter<E, A, V, B, S, P, Z>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E, Block = B, Context = Context<B::Commitment>>,
    V: Variant,
    B: Block<Commitment = CodingCommitment>,
    S: Scheme,
    P: PublicKey,
    Z: Supervisor<Index = View, PublicKey = P>,
{
    type Digest = B::Commitment;

    async fn broadcast(&mut self, _commitment: Self::Digest) {
        let Some((round, block)) = self.last_built.lock().await.clone() else {
            warn!("missing block to broadcast");
            return;
        };

        let participants = self
            .supervisor
            .participants(round)
            .cloned()
            .expect("failed to get participants for round");

        debug!(
            round = %round,
            commitment = %block.commitment(),
            height = block.height(),
            "requested broadcast of built block"
        );
        self.marshal.broadcast(block, participants).await;
    }
}

impl<E, A, V, B, S, P, Z> Reporter for CodingAdapter<E, A, V, B, S, P, Z>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E, Block = B, Context = Context<B::Commitment>>,
    V: Variant,
    B: Block<Commitment = CodingCommitment>,
    S: Scheme,
    P: PublicKey,
    Z: Supervisor<Index = View, PublicKey = P>,
{
    type Activity = B;

    async fn report(&mut self, block: Self::Activity) {
        self.application.finalize(block).await
    }
}

/// Compute the [CodingConfig] for a given number of participants.
///
/// Currently, [CodingAdapter] mandates the use of `threshold_simplex`,
/// which requires at least `3f + 1` participants to tolerate `f` faults.
///
/// The generated coding configuration facilitates any `f + 1` parts to reconstruct the data.
fn coding_config_for_participants(n_participants: u16) -> CodingConfig {
    assert!(
        n_participants >= 4,
        "Need at least 4 participants to maintain fault tolerance with threshold_simplex"
    );
    let max_faults = (n_participants - 1) / 3;
    CodingConfig {
        minimum_shards: max_faults + 1,
        extra_shards: n_participants - (max_faults + 1),
    }
}
