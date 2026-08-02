//! Bounded, concurrent serving of resolver requests.
//!
//! Network serving is independent of resolver intake. Requests for one exact key share a single
//! lookup, while different keys are scheduled in a rolling pool so a slow storage read cannot
//! block an unrelated response.

use super::{catalog::CatalogClient, metrics, promoter};
use crate::multimmit::{
    marshal::wire::{Key, MAX_SEGMENT_ITEMS},
};
use bytes::Bytes;
use commonware_actor::mailbox::{self, UnreliablePolicy};
use commonware_codec::{Codec, Encode as _, EncodeSize as _};
use commonware_cryptography::{Digest, Digestible, Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select;
use commonware_runtime::{Handle, Metrics as RuntimeMetrics, Spawner};
use commonware_utils::{channel::oneshot, futures::Pool};
use std::{
    collections::{BTreeMap, VecDeque, btree_map::Entry},
    future::{Future, pending},
    num::NonZeroUsize,
    sync::Arc,
};

/// Resolver serving failed.
#[derive(Clone, Debug, thiserror::Error)]
pub(in crate::multimmit::marshal) enum Error {
    #[error("resolver storage access failed: {0}")]
    Storage(Arc<str>),
}

fn storage_error(error: impl std::fmt::Display) -> Error {
    Error::Storage(Arc::from(error.to_string()))
}

struct Command<D: Digest> {
    key: Key<D>,
    response: oneshot::Sender<Bytes>,
}

impl<D: Digest> UnreliablePolicy for Command<D> {
    type Overflow = VecDeque<Self>;

    fn handle(_: &mut Self::Overflow, _: Self) -> bool {
        false
    }
}

/// Producer endpoint used by `commonware-resolver`.
pub(super) struct Mailbox<D: Digest> {
    commands: mailbox::UnreliableSender<Command<D>>,
}

impl<D: Digest> Clone for Mailbox<D> {
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
        }
    }
}

impl<D: Digest> Mailbox<D> {
    pub(super) fn produce(&self, key: Key<D>) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let _ = self.commands.enqueue(Command { key, response });
        receiver
    }

    pub(super) fn try_produce(&self, key: Key<D>) -> Option<oneshot::Receiver<Bytes>> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .enqueue(Command { key, response })
            .accepted()
            .then_some(receiver)
    }
}

pub(super) struct Receiver<D: Digest> {
    commands: mailbox::UnreliableReceiver<Command<D>>,
}

/// Allocates the bounded serving lane before the network resolver is constructed.
pub(super) fn channel<D: Digest>(
    metrics: impl RuntimeMetrics,
    capacity: NonZeroUsize,
) -> (Mailbox<D>, Receiver<D>) {
    let (commands, receiver) = mailbox::new_unreliable(metrics, capacity);
    (Mailbox { commands }, Receiver { commands: receiver })
}

struct Completion<D: Digest> {
    key: Key<D>,
    value: Result<Option<Bytes>, Error>,
}

enum Event<D: Digest> {
    Completion(Completion<D>),
    Command(Option<Command<D>>),
}

async fn next_event<J, C, D>(
    completion: J,
    command: C,
    receive: bool,
) -> Event<D>
where
    J: Future<Output = Completion<D>>,
    C: Future<Output = Option<Command<D>>>,
    D: Digest,
{
    let command = async move {
        if receive {
            command.await
        } else {
            pending().await
        }
    };
    select! {
        completion = completion => Event::Completion(completion),
        command = command => Event::Command(command),
    }
}

struct Actor<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    catalog: CatalogClient<H, V, B>,
    bodies: promoter::Bodies<H, V, B>,
    receiver: Receiver<H::Digest>,
    waiters: BTreeMap<Key<H::Digest>, Vec<oneshot::Sender<Bytes>>>,
    queued: VecDeque<Key<H::Digest>>,
    active: Pool<Completion<H::Digest>>,
    pending: usize,
    max_pending: usize,
    max_active: usize,
    max_value_bytes: usize,
    metrics: metrics::Producer,
}

impl<H, V, B> Actor<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn accept(&mut self, command: Command<H::Digest>) {
        if command.response.is_closed() {
            return;
        }
        match self.waiters.entry(command.key) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().push(command.response);
                self.metrics.coalesced.inc();
            }
            Entry::Vacant(entry) => {
                self.queued.push_back(command.key);
                entry.insert(vec![command.response]);
            }
        }
        self.pending += 1;
    }

    fn schedule(&mut self) {
        while self.active.len() < self.max_active {
            let Some(key) = self.queued.pop_front() else {
                break;
            };
            let waiters = self
                .waiters
                .get_mut(&key)
                .expect("queued producer key remains registered");
            let before = waiters.len();
            waiters.retain(|response| !response.is_closed());
            self.pending = self
                .pending
                .checked_sub(before - waiters.len())
                .expect("queued producer waiters were counted as pending");
            if waiters.is_empty() {
                self.waiters.remove(&key);
                continue;
            }
            let catalog = self.catalog.clone();
            let bodies = self.bodies.clone();
            let max_value_bytes = self.max_value_bytes;
            self.active.push(async move {
                let value = produce(catalog, bodies, key, max_value_bytes).await;
                Completion { key, value }
            });
        }
    }

    fn complete(&mut self, completion: Completion<H::Digest>) -> Result<(), Error> {
        let waiters = self
            .waiters
            .remove(&completion.key)
            .expect("completed producer key remains registered");
        self.pending = self
            .pending
            .checked_sub(waiters.len())
            .expect("completed producer waiters were counted as pending");
        match completion.value? {
            Some(value) => {
                for response in waiters {
                    drop(response.send(value.clone()));
                }
            }
            None => {
                self.metrics.misses.inc();
                drop(waiters);
            }
        }
        Ok(())
    }

    fn update_metrics(&self) {
        self.metrics
            .update(self.active.len(), self.queued.len(), self.pending);
    }

    async fn run(mut self) -> Result<(), Error> {
        let mut commands_open = true;
        loop {
            self.schedule();
            self.update_metrics();
            if !commands_open && self.pending == 0 {
                return Ok(());
            }
            match next_event(
                self.active.next_completed(),
                self.receiver.commands.recv(),
                commands_open && self.pending < self.max_pending,
            )
            .await
            {
                Event::Completion(completion) => self.complete(completion)?,
                Event::Command(Some(command)) => self.accept(command),
                Event::Command(None) => commands_open = false,
            }
        }
    }
}

async fn produce<H, V, B>(
    catalog: CatalogClient<H, V, B>,
    bodies: promoter::Bodies<H, V, B>,
    key: Key<H::Digest>,
    max_value_bytes: usize,
) -> Result<Option<Bytes>, Error>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    let value = match key {
        Key::LqcById { id } => catalog
            .lqc(id)
            .await
            .map_err(storage_error)?
            .filter(|value| value.encode_size() <= max_value_bytes)
            .map(|value| value.encode()),
        Key::TipRecord { commitment } => {
            let values = catalog
                .history_segment(commitment, MAX_SEGMENT_ITEMS, max_value_bytes)
                .await
                .map_err(storage_error)?
                .into_iter()
                .map(|value| value.as_ref().clone())
                .collect::<Vec<_>>();
            (!values.is_empty()).then(|| values.encode())
        }
        Key::ProducerBlock { chain, digest } => bodies
            .block_by_digest(chain, digest)
            .await
            .map_err(storage_error)?
            .filter(|value| value.encode_size() <= max_value_bytes)
            .map(|value| value.encode()),
        Key::ProducerHeaders { head } => {
            let headers = catalog
                .header_segments(vec![(head, MAX_SEGMENT_ITEMS)], max_value_bytes)
                .await
                .map_err(storage_error)?
                .pop()
                .unwrap_or_default();
            (!headers.is_empty()).then(|| headers.encode())
        }
    };
    Ok(value)
}

/// Starts bounded resolver serving independently from fetch and delivery intake.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn<E, H, V, B>(
    context: E,
    receiver: Receiver<H::Digest>,
    catalog: CatalogClient<H, V, B>,
    bodies: promoter::Bodies<H, V, B>,
    max_value_bytes: NonZeroUsize,
    max_pending: NonZeroUsize,
    max_active: NonZeroUsize,
) -> Handle<Result<(), Error>>
where
    E: Spawner + RuntimeMetrics,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    let metrics = metrics::Producer::new(&context);
    let actor_context = context.child("actor");
    let actor = Actor {
        catalog,
        bodies,
        receiver,
        waiters: BTreeMap::new(),
        queued: VecDeque::new(),
        active: Pool::default(),
        pending: 0,
        max_pending: max_pending.get(),
        max_active: max_active.get(),
        max_value_bytes: max_value_bytes.get(),
        metrics,
    };
    actor_context.shared(false).spawn(move |_| actor.run())
}
