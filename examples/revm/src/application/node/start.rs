use super::{
    channels::{register_channels, NodeChannels},
    config::{
        block_codec_cfg, default_page_cache, default_quota, Peer, ThresholdScheme, EPOCH_LENGTH,
        MAILBOX_SIZE, PARTITION_PREFIX,
    },
    env::{NodeEnvironment, TransportControl},
    marshal::{start_marshal, MarshalStart},
};
use crate::{
    application::{
        FinalizedReporter, LedgerObservers, LedgerService, LedgerView, NodeHandle, RevmApplication,
        SeedReporter,
    },
    domain::LedgerEvent,
    BootstrapConfig, FinalizationEvent,
};
use anyhow::Context as _;
use commonware_consensus::{
    application::marshaled::Marshaled,
    simplex::{self, elector::Random},
    types::{Epoch, FixedEpocher, ViewDelta},
    Reporters,
};
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use commonware_p2p::simulated;
use commonware_parallel::Sequential;
use commonware_runtime::{tokio, Metrics as _, Spawner as _};
use commonware_utils::{NZUsize, NZU64};
use futures::{channel::mpsc, StreamExt as _};
use std::time::Duration;

/// Initialize and run a single node (QMDB/state + marshal + simplex engine).
pub(crate) async fn start_node<E>(
    env: &mut E,
    index: usize,
    public_key: Peer,
    scheme: ThresholdScheme,
    finalized_tx: mpsc::UnboundedSender<FinalizationEvent>,
    bootstrap: &BootstrapConfig,
) -> anyhow::Result<NodeHandle>
where
    E: NodeEnvironment,
    E::Transport: TransportControl<
        Control = simulated::Control<Peer, tokio::Context>,
        Manager = simulated::Manager<Peer, tokio::Context>,
    >,
{
    let context = env.context();
    let quota = default_quota();
    let page_cache = default_page_cache();
    let partition_prefix = PARTITION_PREFIX;

    let (mut control, manager) = {
        let transport = env.transport();
        (transport.control(public_key.clone()), transport.manager())
    };
    let blocker = control.clone();

    let NodeChannels {
        votes,
        certs,
        resolver,
        blocks,
        backfill,
    } = register_channels(&mut control, quota).await?;

    let block_cfg = block_codec_cfg();
    let state = LedgerView::init(
        context.with_label(&format!("state_{index}")),
        page_cache.clone(),
        format!("{partition_prefix}-qmdb-{index}"),
        bootstrap.genesis_alloc.clone(),
    )
    .await
    .context("init qmdb")?;

    let ledger = LedgerService::new(state.clone());
    LedgerObservers::spawn(ledger.clone(), context.clone());
    let mut domain_events = ledger.subscribe();
    let finalized_tx_clone = finalized_tx.clone();
    let node_id = index as u32;
    let event_context = context.clone();
    event_context.spawn(move |_| async move {
        while let Some(event) = domain_events.next().await {
            if let LedgerEvent::SnapshotPersisted(digest) = event {
                let _ = finalized_tx_clone.unbounded_send((node_id, digest));
            }
        }
    });
    let handle = NodeHandle::new(ledger.clone());
    let app = RevmApplication::<ThresholdScheme>::new(block_cfg.max_txs, state.clone());

    let finalized_reporter = FinalizedReporter::new(ledger.clone(), context.clone());

    let marshal_mailbox = start_marshal(
        &context,
        MarshalStart {
            index,
            partition_prefix: partition_prefix.to_string(),
            public_key: public_key.clone(),
            control: control.clone(),
            manager,
            scheme: scheme.clone(),
            page_cache: page_cache.clone(),
            block_codec_config: block_cfg,
            blocks,
            backfill,
            application: finalized_reporter,
        },
    )
    .await?;

    // Adapt the application to simplex by delegating full-block dissemination/backfill to marshal.
    let epocher = FixedEpocher::new(NZU64!(EPOCH_LENGTH));
    let marshaled = Marshaled::new(
        context.with_label(&format!("marshaled_{index}")),
        app,
        marshal_mailbox.clone(),
        epocher,
    );

    let seed_reporter = SeedReporter::<MinSig>::new(ledger.clone());
    // Feed both the application-specific reporter (seed hashing) and marshal itself with simplex
    // activity (notarizations/finalizations).
    let reporter = Reporters::from((seed_reporter, marshal_mailbox.clone()));

    // Submit bootstrap transactions before starting consensus so the first leader can
    // include them without relying on a hardcoded "height == 1" rule.
    for tx in &bootstrap.bootstrap_txs {
        let _ = handle.submit_tx(tx.clone()).await;
    }

    let engine = simplex::Engine::new(
        context.with_label(&format!("engine_{index}")),
        simplex::Config {
            scheme,
            elector: Random,
            blocker,
            automaton: marshaled.clone(),
            relay: marshaled,
            reporter,
            strategy: Sequential,
            partition: format!("{partition_prefix}-{index}"),
            mailbox_size: MAILBOX_SIZE,
            epoch: Epoch::zero(),
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            leader_timeout: Duration::from_secs(1),
            notarization_timeout: Duration::from_secs(2),
            nullify_retry: Duration::from_secs(5),
            fetch_timeout: Duration::from_secs(1),
            activity_timeout: ViewDelta::new(20),
            skip_timeout: ViewDelta::new(10),
            fetch_concurrent: 8,
            page_cache,
        },
    );
    engine.start(votes, certs, resolver);

    Ok(handle)
}
