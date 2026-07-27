//! Per-variant Simplex engine wiring for the multi-node liveness harness.
//!
//! [`EndToEndMarshal`] extends the marshal [`TestHarness`] with the one piece the
//! harness lacks: standing up a Simplex [`Engine`] whose automaton/relay
//! produce fetchable blocks and whose `reporter` is the marshal mailbox. The
//! two implementations differ only in the wrapper: standard wraps
//! [`AlwaysAcceptBlockBuilderApp`] in [`Deferred`]; coding wraps it in [`Marshaled`] and
//! threads the shards mailbox and coding scheme provider. The engine's
//! consensus payload type follows the variant (`Digest` for standard,
//! `Commitment` for coding).
//!
//! Engine p2p channels use ids 3/4/5 because marshal hardcodes backfill=1
//! and broadcast=2 in `setup_validator_with`.

use super::{ENGINE_CERTIFICATE, ENGINE_RESOLVER, ENGINE_VOTE, app::AlwaysAcceptBlockBuilderApp};
use commonware_consensus::{
    marshal::{
        coding::{Marshaled, MarshaledConfig},
        core::Mailbox,
        mocks::harness::{
            BLOCKS_PER_EPOCH, CodingCtx, CodingHarness, Ctx, K, PAGE_CACHE_SIZE, PAGE_SIZE, S,
            StandardHarness, TEST_QUOTA, TestHarness,
        },
        standard::Deferred,
    },
    simplex::{Engine, Floor, ForwardingPolicy, config, elector::RoundRobin},
    types::{Delta, Epoch, FixedEpocher},
};
use commonware_cryptography::{Sha256, certificate::ConstantProvider};
use commonware_p2p::simulated::Oracle;
use commonware_parallel::Sequential;
use commonware_runtime::{Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_utils::NZUsize;
use std::{future::Future, time::Duration};

/// Marshal variant that can stand up an end-to-end stack wired through Simplex.
pub trait EndToEndMarshal: TestHarness {
    /// Register engine channels (3/4/5), build the variant automaton/relay over
    /// `marshal_mailbox`, and start a Simplex engine reporting to marshal.
    #[allow(clippy::too_many_arguments, clippy::manual_async_fn)]
    fn spawn_engine(
        context: deterministic::Context,
        oracle: &Oracle<K, deterministic::Context>,
        validator: K,
        scheme: S,
        provider: ConstantProvider<S, Epoch>,
        marshal_mailbox: Mailbox<S, Self::Variant>,
        extra: Self::ValidatorExtra,
        genesis_commitment: Self::Commitment,
        forwarding: ForwardingPolicy,
    ) -> impl Future<Output = ()> + Send;
}

impl EndToEndMarshal for StandardHarness {
    #[allow(clippy::too_many_arguments, clippy::manual_async_fn)]
    fn spawn_engine(
        context: deterministic::Context,
        oracle: &Oracle<K, deterministic::Context>,
        validator: K,
        scheme: S,
        _provider: ConstantProvider<S, Epoch>,
        marshal_mailbox: Mailbox<S, Self::Variant>,
        _extra: Self::ValidatorExtra,
        genesis_commitment: Self::Commitment,
        forwarding: ForwardingPolicy,
    ) -> impl Future<Output = ()> + Send {
        async move {
            let control = oracle.control(validator.clone());
            let vote = control.register(ENGINE_VOTE, TEST_QUOTA).await.unwrap();
            let certificate = control
                .register(ENGINE_CERTIFICATE, TEST_QUOTA)
                .await
                .unwrap();
            let resolver = control.register(ENGINE_RESOLVER, TEST_QUOTA).await.unwrap();

            let deferred = Deferred::new(
                context.child("deferred"),
                AlwaysAcceptBlockBuilderApp::<Ctx>::default(),
                marshal_mailbox.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );
            let cfg = config::Config {
                blocker: oracle.control(validator.clone()),
                scheme,
                elector: RoundRobin::<Sha256>::default(),
                automaton: deferred.clone(),
                relay: deferred,
                reporter: marshal_mailbox,
                partition: format!("engine-{validator}"),
                mailbox_size: NZUsize!(1024),
                epoch: Epoch::zero(),
                floor: Floor::Genesis(genesis_commitment),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                view_retention: Delta::new(10),
                skip_timeout: Duration::from_secs(11),
                fetch_concurrent: NZUsize!(1),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forwarding,
            };
            let engine = Engine::new(context.child("engine"), cfg);
            engine.start(vote, certificate, resolver);
        }
    }
}

impl EndToEndMarshal for CodingHarness {
    #[allow(clippy::too_many_arguments, clippy::manual_async_fn)]
    fn spawn_engine(
        context: deterministic::Context,
        oracle: &Oracle<K, deterministic::Context>,
        validator: K,
        scheme: S,
        provider: ConstantProvider<S, Epoch>,
        marshal_mailbox: Mailbox<S, Self::Variant>,
        extra: Self::ValidatorExtra,
        genesis_commitment: Self::Commitment,
        forwarding: ForwardingPolicy,
    ) -> impl Future<Output = ()> + Send {
        async move {
            let control = oracle.control(validator.clone());
            let vote = control.register(ENGINE_VOTE, TEST_QUOTA).await.unwrap();
            let certificate = control
                .register(ENGINE_CERTIFICATE, TEST_QUOTA)
                .await
                .unwrap();
            let resolver = control.register(ENGINE_RESOLVER, TEST_QUOTA).await.unwrap();

            let marshaled = Marshaled::new(
                context.child("marshaled"),
                MarshaledConfig {
                    application: AlwaysAcceptBlockBuilderApp::<CodingCtx>::default(),
                    marshal: marshal_mailbox.clone(),
                    shards: extra,
                    scheme_provider: provider,
                    strategy: Sequential,
                    epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                },
            );
            let cfg = config::Config {
                blocker: oracle.control(validator.clone()),
                scheme,
                elector: RoundRobin::<Sha256>::default(),
                automaton: marshaled.clone(),
                relay: marshaled,
                reporter: marshal_mailbox,
                partition: format!("engine-{validator}"),
                mailbox_size: NZUsize!(1024),
                epoch: Epoch::zero(),
                floor: Floor::Genesis(genesis_commitment),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                view_retention: Delta::new(10),
                skip_timeout: Duration::from_secs(11),
                fetch_concurrent: NZUsize!(1),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forwarding,
            };
            let engine = Engine::new(context.child("engine"), cfg);
            engine.start(vote, certificate, resolver);
        }
    }
}
