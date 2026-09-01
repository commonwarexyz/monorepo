//! Bounded, concurrent serving of peer requests from local custody.
//!
//! Serving is independent of backfill intake. Requests for one key share a single lookup,
//! while different keys are scheduled in a rolling pool so a slow storage read cannot block an
//! unrelated response.

use crate::multimmit::{
    actors::util::{Waiters, gated},
    marshal::{
        actors::{catalog, metrics},
        bodies::{self, Bodies},
        wire::{BackfillKey, MAX_SEGMENT_ITEMS, max_block_segment_items, segment_fits},
    },
    types::{BlockRef, Body},
};
use bytes::Bytes;
use commonware_actor::mailbox::{self, UnreliablePolicy, UnreliableReceiver};
use commonware_codec::{Encode as _, EncodeSize as _};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select_loop;
use commonware_runtime::{ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::{
    channel::{fallible::OneshotExt as _, oneshot},
    futures::Pool,
};
use std::{collections::VecDeque, num::NonZeroUsize};
use tracing::debug;

/// Resolver serving failed.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum Error {
    /// A catalog read failed.
    #[error("catalog request failed: {0}")]
    Catalog(#[from] catalog::Error),
    /// A body lookup across temporary and immutable custody failed.
    #[error("body lookup failed: {0}")]
    Bodies(#[from] bodies::Error),
    /// Local storage returned data that does not match the requested range.
    #[error("stored data is inconsistent: {0}")]
    Inconsistent(&'static str),
}

/// One serve request from `commonware-resolver`.
struct Message<D: Digest> {
    key: BackfillKey<D>,
    response: oneshot::Sender<Bytes>,
}

impl<D: Digest> UnreliablePolicy for Message<D> {
    type Overflow = VecDeque<Self>;

    fn handle(_: &mut Self::Overflow, _: Self) -> bool {
        false
    }
}

/// Serving mailbox used by the backfill bridge.
pub(crate) struct Mailbox<D: Digest> {
    commands: mailbox::UnreliableSender<Message<D>>,
}

impl<D: Digest> Clone for Mailbox<D> {
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
        }
    }
}

impl<D: Digest> Mailbox<D> {
    /// Requests the encoded value for `key`; the receiver closes when none is held locally.
    pub(super) fn produce(&self, key: BackfillKey<D>) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let _ = self.commands.enqueue(Message { key, response });
        receiver
    }
}

/// Configuration for the serving actor.
pub(crate) struct Config<H: Hasher, V: Variant, B: Body<H>> {
    /// Catalog read for L-QCs, tip histories and headers.
    pub catalog: catalog::Mailbox<H, V, B>,
    /// Body lookups across temporary and immutable custody.
    pub bodies: Bodies<H, V, B>,
    /// Maximum encoded size of one block.
    pub max_block_bytes: NonZeroUsize,
    /// Maximum size of one served value.
    pub max_value_bytes: NonZeroUsize,
    /// Capacity of the serving mailbox.
    pub mailbox_size: NonZeroUsize,
    /// Maximum number of callers awaiting a value.
    pub max_pending: NonZeroUsize,
    /// Maximum number of keys looked up concurrently.
    pub max_active: NonZeroUsize,
}

struct Completion<D: Digest> {
    key: BackfillKey<D>,
    value: Result<Option<Bytes>, Error>,
}

/// Serves peer requests from local custody.
///
/// Requests for one key share a single lookup, and different keys run in a rolling pool so a slow
/// storage read does not block an unrelated response.
pub(crate) struct Actor<E, H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    context: ContextCell<E>,
    catalog: catalog::Mailbox<H, V, B>,
    bodies: Bodies<H, V, B>,
    receiver: UnreliableReceiver<Message<H::Digest>>,
    /// Whether every mailbox sender is gone; the actor then drains its callers and stops.
    closed: bool,
    waiters: Waiters<BackfillKey<H::Digest>, Bytes>,
    queued: VecDeque<BackfillKey<H::Digest>>,
    active: Pool<'static, Completion<H::Digest>>,
    max_pending: usize,
    max_active: usize,
    max_blocks_per_value: usize,
    max_value_bytes: usize,
    metrics: metrics::Serve,
}

impl<E, H, V, B> Actor<E, H, V, B>
where
    E: Spawner + Metrics,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Creates the serving actor and its mailbox.
    ///
    /// `context` is marshal's: the actor registers its metrics under `resolver_producer` and its
    /// mailbox under `resolver_producer_bridge`.
    pub(crate) fn new(context: &E, config: Config<H, V, B>) -> (Self, Mailbox<H::Digest>) {
        let (sender, receiver) = mailbox::new_unreliable(
            context.child("resolver_producer_bridge"),
            config.mailbox_size,
        );
        let context = context.child("resolver").child("producer");
        let metrics = metrics::Serve::new(&context);
        let actor = Self {
            context: ContextCell::new(context),
            catalog: config.catalog,
            bodies: config.bodies,
            receiver,
            closed: false,
            waiters: Waiters::new(),
            queued: VecDeque::new(),
            active: Pool::default(),
            max_pending: config.max_pending.get(),
            max_active: config.max_active.get(),
            max_blocks_per_value: max_block_segment_items(
                config.max_block_bytes.get(),
                config.max_value_bytes.get(),
            ),
            max_value_bytes: config.max_value_bytes.get(),
            metrics,
        };
        (actor, Mailbox { commands: sender })
    }

    /// Starts serving.
    pub(crate) fn start(mut self) -> Handle<Result<(), Error>> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) -> Result<(), Error> {
        select_loop! {
            self.context,
            on_start => {
                self.schedule();
                self.metrics
                    .update(self.active.len(), self.queued.len(), self.waiters.pending());
                if self.closed && self.waiters.pending() == 0 {
                    break;
                }
                let receive = !self.closed && self.waiters.pending() < self.max_pending;
            },
            on_stopped => {
                debug!("backfill serving stopped");
            },
            completion = self.active.next_completed() => self.complete(completion)?,
            message = gated(receive, self.receiver.recv()) => match message {
                Some(message) => self.accept(message),
                None => self.closed = true,
            },
        }
        Ok(())
    }

    fn accept(&mut self, message: Message<H::Digest>) {
        if message.response.is_closed() {
            return;
        }
        if self.waiters.insert(message.key, message.response, || ()) {
            self.queued.push_back(message.key);
        } else {
            self.metrics.coalesced.inc();
        }
    }

    fn schedule(&mut self) {
        while self.active.len() < self.max_active {
            let Some(key) = self.queued.pop_front() else {
                break;
            };
            if !self
                .waiters
                .retain_open(&key)
                .expect("queued producer key remains registered")
            {
                continue;
            }
            let catalog = self.catalog.clone();
            let bodies = self.bodies.clone();
            let max_blocks_per_value = self.max_blocks_per_value;
            let max_value_bytes = self.max_value_bytes;
            self.active.push(async move {
                let value =
                    produce(catalog, bodies, key, max_blocks_per_value, max_value_bytes).await;
                Completion { key, value }
            });
        }
    }

    fn complete(&mut self, completion: Completion<H::Digest>) -> Result<(), Error> {
        let waiters = self
            .waiters
            .remove(&completion.key)
            .expect("completed producer key remains registered");
        match completion.value? {
            Some(value) => {
                for response in waiters {
                    response.send_lossy(value.clone());
                }
            }
            None => {
                self.metrics.misses.inc();
                drop(waiters);
            }
        }
        Ok(())
    }
}

async fn produce<H, V, B>(
    catalog: catalog::Mailbox<H, V, B>,
    bodies: Bodies<H, V, B>,
    key: BackfillKey<H::Digest>,
    max_blocks_per_value: usize,
    max_value_bytes: usize,
) -> Result<Option<Bytes>, Error>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    let value = match key {
        BackfillKey::LqcById { id } => catalog
            .lqc(id)
            .await?
            .filter(|value| value.encode_size() <= max_value_bytes)
            .map(|value| value.encode()),
        BackfillKey::TipRecord { commitment } => {
            let values = catalog
                .history_segment(commitment, MAX_SEGMENT_ITEMS, max_value_bytes)
                .await?;
            (!values.is_empty()).then(|| values.encode())
        }
        BackfillKey::ProducerBlock { chain, digest } => bodies
            .block_by_digest(chain, digest)
            .await?
            .filter(|value| value.encode_size() <= max_value_bytes)
            .map(|value| value.encode()),
        BackfillKey::ProducerHeaders { head } => {
            let headers = catalog
                .header_segments(vec![(head, MAX_SEGMENT_ITEMS)], max_value_bytes)
                .await?
                .pop()
                .unwrap_or_default();
            (!headers.is_empty()).then(|| headers.encode())
        }
        BackfillKey::ProducerBlocks { head, max_items } => {
            let max_items = usize::from(max_items.get()).min(max_blocks_per_value);
            produce_blocks(catalog, bodies, head, max_items, max_value_bytes).await?
        }
    };
    Ok(value)
}

/// Encodes the longest locally held run of consecutive blocks, newest first from `head`, that
/// fits in one resolver value.
async fn produce_blocks<H, V, B>(
    catalog: catalog::Mailbox<H, V, B>,
    bodies: Bodies<H, V, B>,
    head: BlockRef<H::Digest>,
    max_items: usize,
    max_value_bytes: usize,
) -> Result<Option<Bytes>, Error>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    let headers = catalog
        .header_segments(vec![(head, max_items)], max_value_bytes)
        .await?
        .pop()
        .unwrap_or_default();
    let mut references = Vec::with_capacity(headers.len());
    let mut expected = head;
    for header in headers {
        if header.block_ref::<H>() != expected {
            return Err(Error::Inconsistent(
                "stored producer header does not match its range coordinate",
            ));
        }
        references.push(expected);
        expected = header.parent_ref();
        if expected.height().is_zero() {
            break;
        }
    }
    let values = bodies.blocks(references.clone()).await?;
    if values.len() != references.len() {
        return Err(Error::Inconsistent(
            "producer body range response has invalid cardinality",
        ));
    }
    let mut blocks = Vec::with_capacity(values.len());
    let mut block_bytes = 0usize;
    for (reference, block) in references.into_iter().zip(values) {
        let Some(block) = block else {
            break;
        };
        if block.reference() != reference {
            return Err(Error::Inconsistent(
                "stored producer block does not match its range coordinate",
            ));
        }
        let Some(next_block_bytes) = block_bytes.checked_add(block.encode_size()) else {
            break;
        };
        if !segment_fits(blocks.len() + 1, next_block_bytes, max_value_bytes) {
            break;
        }
        block_bytes = next_block_bytes;
        blocks.push(block);
    }
    Ok((!blocks.is_empty()).then(|| blocks.encode()))
}
