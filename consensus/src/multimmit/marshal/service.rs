//! Opening, starting and stopping marshal.

use super::{
    config::{Config, ConfigError, Limits},
    input::{Bridge, Lane, Message},
    ledger::{Inputs, Ledger, Services, Stores},
    mailbox::Mailbox,
    relay::{Relay, Staged},
    store::{
        Buffers, Error as StoreError,
        blocks::{self, Blocks},
        meta::{Ack, Meta, State},
        proofs::{self, Proofs},
    },
    types::{Error, LqcVerifier, Update},
    wire::Key,
};
use crate::{
    Reporter,
    multimmit::{
        config::max_outbox_effects,
        scheme::Scheme,
        types::{Body, ChainId, CodecConfig, TransactionBlock, genesis_history},
    },
    types::Height,
};
use commonware_broadcast::buffered;
use commonware_cryptography::{Hasher, PublicKey};
use commonware_resolver::Resolver;
use commonware_runtime::{Handle, Spawner};
use commonware_storage::Context;
use commonware_utils::{channel::mpsc, sync::Mutex};
use std::{num::NonZeroUsize, sync::Arc};

/// Opening marshal failed.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The configuration cannot run.
    #[error("invalid configuration: {0}")]
    Config(#[from] ConfigError),
    /// A store could not be opened.
    #[error("storage failed: {0}")]
    Storage(#[source] super::types::Failure),
    /// Stored progress belongs to another epoch.
    #[error("stored progress belongs to another epoch")]
    Epoch,
}

impl From<StoreError> for OpenError {
    fn from(error: StoreError) -> Self {
        Self::Storage(super::types::Failure::from(super::types::Cause::Storage(
            error,
        )))
    }
}

/// Requests a peer delivery or serving queue holds before the bridge drops more.
const PEER_QUEUE: usize = 1024;

/// An opened marshal, not yet started.
pub struct Service<E, H, S, B, P>
where
    E: Context + Spawner,
    H: Hasher,
    S: Scheme,
    B: Body<H>,
    P: PublicKey,
{
    context: E,
    codec: CodecConfig,
    limits: Limits,
    stores: Stores<E, H, S, B>,
    inputs: Inputs<H, S, B>,
    sender: mpsc::Sender<Message<H, S, B>>,
    buffer: buffered::Mailbox<P, TransactionBlock<H, B>>,
    staged: Option<Arc<Mutex<Staged<H, B>>>>,
}

/// Opens marshal's stores and returns the service and the bridge to attach to a network
/// resolver, as its consumer and producer.
///
/// `buffer` is the broadcast engine whose recently received blocks satisfy subscriptions and
/// spare fetches.
pub async fn open<E, H, S, B, P>(
    context: E,
    config: Config<H::Digest, B::Cfg>,
    buffer: buffered::Mailbox<P, TransactionBlock<H, B>>,
) -> Result<(Service<E, H, S, B, P>, Bridge<H, S, B>), OpenError>
where
    E: Context + Spawner,
    H: Hasher,
    S: Scheme,
    B: Body<H>,
    P: PublicKey,
{
    config.validate()?;
    let Config {
        genesis,
        partition_prefix: prefix,
        page_cache,
        codec_config: codec,
        body_codec_config: body_codec,
        limits,
    } = config;
    let chains = codec.chains();
    let buffers = Buffers {
        page_cache,
        index_write_buffer: limits.write_buffer,
        value_write_buffer: limits.write_buffer,
        replay_buffer: limits.replay_buffer,
    };
    let history = genesis_history::<H>(&genesis);
    let initial = State {
        epoch: genesis.epoch(),
        ack: Ack {
            history,
            ordered: genesis.tips().to_vec(),
            emitted: genesis.tips().to_vec(),
        },
        floor: None,
        base: history,
        retained: vec![Height::zero(); chains],
    };
    // The stores open behind boxes so that callers' futures stay small.
    let meta = Box::pin(Meta::open(
        context.child("meta"),
        format!("{prefix}_meta"),
        chains,
        initial,
    ))
    .await?;
    let state = meta.durable().clone();
    if state.epoch != genesis.epoch() {
        return Err(OpenError::Epoch);
    }
    // Segments are named in their manifests; generous bounds keep a manifest decodable even
    // when retention lags far behind.
    let max_segments = NonZeroUsize::new(1 << 20).expect("nonzero");
    let blocks = Box::pin(Blocks::open(
        context.child("blocks"),
        blocks::Config {
            prefix: format!("{prefix}_blocks"),
            buffers: buffers.clone(),
            body_codec: body_codec.clone(),
            epoch: genesis.epoch(),
            segment_capacity: limits.blocks_per_segment,
            max_segments,
        },
        state.retained.clone(),
    ))
    .await?;
    let proofs = Box::pin(Proofs::open(
        context.child("proofs"),
        proofs::Config {
            prefix: format!("{prefix}_proofs"),
            buffers,
            codec,
            segment_capacity: limits.proofs_per_segment,
            max_segments,
        },
        state.base,
        state.floor,
    ))
    .await?;

    let (sender, mailbox) = mpsc::channel(limits.mailbox_size.get());
    let (lane, signal) = Lane::new(chains, limits.max_record_backlog_bytes.get());
    let (deliveries_sender, deliveries) = mpsc::channel(PEER_QUEUE);
    let (requests_sender, requests) = mpsc::channel(PEER_QUEUE);
    let bridge = Bridge::new(
        deliveries_sender,
        requests_sender,
        codec,
        body_codec.clone(),
    );
    Ok((
        Service {
            context,
            codec,
            limits,
            stores: Stores {
                blocks,
                proofs,
                meta,
            },
            inputs: Inputs {
                mailbox,
                lane,
                signal,
                deliveries,
                requests,
            },
            sender,
            buffer,
            staged: None,
        },
        bridge,
    ))
}

impl<E, H, S, B, P> Service<E, H, S, B, P>
where
    E: Context + Spawner,
    H: Hasher,
    S: Scheme,
    B: Body<H>,
    P: PublicKey,
{
    /// Returns a relay that broadcasts blocks staged through this service's mailbox.
    ///
    /// The relay keeps as many of this node's blocks (those of `chain`) as an engine of this
    /// committee keeps publications awaiting acknowledgement. Call before [`Self::start`]; later
    /// calls share the first call's settings.
    pub fn relay(&mut self, chain: Option<ChainId>) -> Relay<H, B, P> {
        let retention = max_outbox_effects(self.codec.participants());
        let staged = self
            .staged
            .get_or_insert_with(|| Arc::new(Mutex::new(Staged::new(retention, chain))));
        Relay::new(Arc::clone(staged), self.buffer.clone())
    }

    /// Starts marshal after the bridge is attached to the network resolver.
    pub fn start<R, V, A>(
        self,
        resolver: R,
        verifier: V,
        application: A,
    ) -> (Mailbox<H, S, B>, ServiceHandle)
    where
        R: Resolver<Key = Key<H::Digest>, Subscriber = ()>,
        V: LqcVerifier<H, S> + Clone,
        A: Reporter<Activity = Update<TransactionBlock<H, B>>>,
    {
        let mailbox = Mailbox::new(
            self.sender,
            Arc::clone(&self.inputs.lane),
            self.staged,
            self.limits.max_pending_acks,
        );
        let codec = self.codec;
        let limits = self.limits;
        let stores = self.stores;
        let inputs = self.inputs;
        let buffer = self.buffer;
        let task = self
            .context
            .child("ledger")
            .spawn(move |context| async move {
                let ledger = Ledger::new(
                    context,
                    codec,
                    limits,
                    stores,
                    inputs,
                    Services {
                        resolver,
                        verifier,
                        application,
                        buffer,
                    },
                )?;
                ledger.run().await
            });
        (
            mailbox,
            ServiceHandle {
                task,
                stopping: false,
            },
        )
    }
}

/// Stops a running marshal and reports how it stopped.
pub struct ServiceHandle {
    task: Handle<Result<(), Error>>,
    stopping: bool,
}

impl ServiceHandle {
    /// Stops marshal.
    pub fn abort(&mut self) {
        self.stopping = true;
        self.task.abort();
    }

    /// Waits until marshal stops and returns the failure that stopped it, if any.
    pub async fn join(self) -> Result<(), Error> {
        match self.task.await {
            Ok(result) => result,
            Err(commonware_runtime::Error::Closed | commonware_runtime::Error::Aborted)
                if self.stopping =>
            {
                Ok(())
            }
            Err(error) => Err(Error::Failed(super::types::Failure::from(
                super::types::Cause::Task(error),
            ))),
        }
    }
}
