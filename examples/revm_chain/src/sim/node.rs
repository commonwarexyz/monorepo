use super::{
    consensus, genesis, simplex, Mailbox, ThresholdScheme, BLOCK_CODEC_MAX_CALLDATA,
    BLOCK_CODEC_MAX_TXS, CHANNEL_BLOCKS, CHANNEL_CERTS, CHANNEL_RESOLVER, CHANNEL_VOTES, MAILBOX_SIZE,
};
use anyhow::Context as _;
use commonware_consensus::types::{Epoch, ViewDelta};
use commonware_cryptography::ed25519;
use commonware_p2p::{simulated, Receiver as _};
use commonware_runtime::{
    buffer::PoolRef, deterministic, Metrics as _, Spawner as _,
};
use commonware_utils::{NZU32, NZUsize};
use futures::channel::mpsc;
use governor::Quota;
use std::time::Duration;

pub(super) async fn start_all_nodes(
    context: &deterministic::Context,
    oracle: &mut simulated::Oracle<ed25519::PublicKey>,
    participants: &[ed25519::PublicKey],
    schemes: &[ThresholdScheme],
    genesis: &genesis::GenesisTransfer,
) -> anyhow::Result<(
    Vec<Mailbox>,
    mpsc::UnboundedReceiver<consensus::FinalizationEvent>,
)> {
    let quota = Quota::per_second(NZU32!(1_000));
    let buffer_pool = PoolRef::new(NZUsize!(16_384), NZUsize!(10_000));

    let (finalized_tx, finalized_rx) = mpsc::unbounded::<consensus::FinalizationEvent>();
    let mut mailboxes = Vec::with_capacity(participants.len());

    for (i, pk) in participants.iter().cloned().enumerate() {
        let mailbox = start_node(
            context,
            oracle,
            i,
            pk,
            schemes[i].clone(),
            quota,
            buffer_pool.clone(),
            finalized_tx.clone(),
            genesis,
        )
        .await?;
        mailboxes.push(mailbox);
    }

    Ok((mailboxes, finalized_rx))
}

async fn start_node(
    context: &deterministic::Context,
    oracle: &mut simulated::Oracle<ed25519::PublicKey>,
    index: usize,
    public_key: ed25519::PublicKey,
    scheme: ThresholdScheme,
    quota: Quota,
    buffer_pool: PoolRef,
    finalized_tx: mpsc::UnboundedSender<consensus::FinalizationEvent>,
    genesis: &genesis::GenesisTransfer,
) -> anyhow::Result<Mailbox> {
    let mut control = oracle.control(public_key.clone());
    let blocker = control.clone();

    let (vote_sender, vote_receiver) = control
        .register(CHANNEL_VOTES, quota)
        .await
        .context("register votes channel")?;
    let (cert_sender, cert_receiver) = control
        .register(CHANNEL_CERTS, quota)
        .await
        .context("register certs channel")?;
    let (resolver_sender, resolver_receiver) = control
        .register(CHANNEL_RESOLVER, quota)
        .await
        .context("register resolver channel")?;
    let (block_sender, mut block_receiver) = control
        .register(CHANNEL_BLOCKS, quota)
        .await
        .context("register blocks channel")?;

    let (application, mailbox, inbox) = consensus::Application::new(
        index as u32,
        consensus::BlockCodecCfg {
            max_txs: BLOCK_CODEC_MAX_TXS,
            max_calldata_bytes: BLOCK_CODEC_MAX_CALLDATA,
        },
        MAILBOX_SIZE,
        block_sender,
        finalized_tx,
        genesis.alloc.clone(),
        Some(genesis.tx.clone()),
    );

    let mailbox_for_blocks = mailbox.clone();
    context
        .with_label(&format!("block_receiver_{index}"))
        .spawn(move |_ctx| async move {
            while let Ok((from, bytes)) = block_receiver.recv().await {
                mailbox_for_blocks.deliver_block(from, bytes).await;
            }
        });

    context
        .with_label(&format!("application_{index}"))
        .spawn(move |_ctx| async move {
            application.run(inbox).await;
        });

    let engine = simplex::Engine::new(
        context.with_label(&format!("engine_{index}")),
        simplex::Config {
            scheme,
            blocker,
            automaton: mailbox.clone(),
            relay: mailbox.clone(),
            reporter: mailbox.clone(),
            partition: format!("revm-chain-{index}"),
            mailbox_size: MAILBOX_SIZE,
            epoch: Epoch::zero(),
            namespace: b"revm-chain-consensus".to_vec(),
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            leader_timeout: Duration::from_millis(50),
            notarization_timeout: Duration::from_millis(100),
            nullify_retry: Duration::from_millis(200),
            fetch_timeout: Duration::from_millis(200),
            activity_timeout: ViewDelta::new(10),
            skip_timeout: ViewDelta::new(5),
            fetch_concurrent: 16,
            fetch_rate_per_peer: Quota::per_second(NZU32!(10)),
            buffer_pool,
        },
    );
    engine.start(
        (vote_sender, vote_receiver),
        (cert_sender, cert_receiver),
        (resolver_sender, resolver_receiver),
    );

    Ok(mailbox)
}
