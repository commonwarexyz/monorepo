//! Durable application-owned aggregation certificate history.
//!
//! Certificates are immutable and indexed by their global [`Height`]. Resolver
//! responses and locally recovered certificates enter through the same bounded
//! mailbox. Work rejected under backpressure must be retried. A successful response
//! is sent only after the archive has synced.
//!
//! Retirement first syncs and semantically verifies every certificate in the
//! authenticated epoch range. It then atomically persists an exact range marker
//! and journal-cleanup intent. The intent survives a crash until the application
//! confirms journal removal, at which point the discovery floor may advance.
//! This module does not determine how a private journal is named or stored.

use bytes::{Buf, BufMut, Bytes};
use commonware_actor::{
    Feedback,
    mailbox::{self, Overflow, Policy, Sender},
};
use commonware_codec::{
    Decode, Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    aggregation::{
        scheme::Scheme,
        types::{Certificate, RecoveryKey, RecoveryNamespace},
    },
    types::{Epoch, Height},
};
use commonware_cryptography::{Digest, Hasher as _, Sha256};
use commonware_macros::select_loop;
use commonware_parallel::Strategy;
use commonware_resolver::{Consumer, Delivery, Outcome, p2p::Producer};
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use commonware_storage::{
    Context,
    archive::{Archive as _, Identifier, immutable},
    metadata,
};
use commonware_utils::{Span, channel::oneshot};
use rand_core::CryptoRng;
use std::{
    fmt::{self, Display, Formatter},
    marker::PhantomData,
    num::NonZeroUsize,
    sync::Arc,
};
use thiserror::Error;

type Archive<E, S, D> =
    immutable::Archive<E, commonware_cryptography::sha256::Digest, Certificate<S, D>>;

/// Authenticated verification material for one epoch.
#[derive(Clone)]
pub struct AuthenticatedEpoch<S> {
    scheme: Arc<S>,
    first: Height,
    last: Height,
}

impl<S> AuthenticatedEpoch<S> {
    /// Creates authenticated epoch material for an inclusive, non-empty range.
    pub fn new(scheme: Arc<S>, first: Height, last: Height) -> Option<Self> {
        (first <= last).then_some(Self {
            scheme,
            first,
            last,
        })
    }

    /// Returns the inclusive first height.
    pub const fn first(&self) -> Height {
        self.first
    }

    /// Returns the inclusive last height.
    pub const fn last(&self) -> Height {
        self.last
    }
}

/// Supplies authenticated epoch ranges and their aggregation schemes.
///
/// Implementations must derive this material from authenticated application
/// history. The archive rejects a certificate if this provider cannot resolve
/// its namespace and epoch.
pub trait Provider<S>: Clone + Send + Sync + 'static {
    /// Returns the authenticated scheme and range for `namespace` and `epoch`.
    fn epoch(&self, namespace: RecoveryNamespace, epoch: Epoch) -> Option<AuthenticatedEpoch<S>>;

    /// Returns the first epoch that may still require discovery.
    ///
    /// This seeds a namespace whose floor has not yet been persisted.
    fn oldest_epoch(&self, namespace: RecoveryNamespace) -> Option<Epoch>;
}

/// Exact identity of a retired aggregation range.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Retirement {
    /// Aggregation recovery namespace.
    pub namespace: RecoveryNamespace,
    /// Epoch that owns the range.
    pub epoch: Epoch,
    /// Inclusive first global height.
    pub first: Height,
    /// Inclusive last global height.
    pub last: Height,
}

/// Permission to clean up an application-owned aggregation journal.
///
/// This value is emitted only after the corresponding exact retirement marker
/// is durable. Journal cleanup is intentionally an application callback/hook.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cleanup {
    /// Exact range whose journal may now be removed.
    pub retirement: Retirement,
}

/// Result of a direct certificate archival request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveStatus {
    /// The certificate was validated, written, and synced.
    Stored,
    /// A valid certificate for the same recovery key was already durable.
    ///
    /// The retained certificate may use a different valid quorum encoding for
    /// the same recovery key.
    Duplicate,
    /// The bytes or authenticated key semantics were invalid.
    Rejected,
}

/// Fatal aggregation history storage error.
#[derive(Debug, Error)]
pub enum Error {
    /// Immutable archive failure.
    #[error("archive error: {0}")]
    Archive(#[from] commonware_storage::archive::Error),
    /// Retirement metadata failure.
    #[error("metadata error: {0}")]
    Metadata(#[from] commonware_storage::metadata::Error),
}

/// Failure to submit or complete a direct history request.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RequestError {
    /// The bounded history mailbox could not accept the request.
    #[error("aggregation history is backpressured")]
    Backpressured,
    /// The history actor closed before completing the request.
    #[error("aggregation history is closed")]
    Closed,
}

/// Persistent storage and ingress configuration.
pub struct Config<C> {
    /// Recovery namespace exclusively owned by this archive.
    ///
    /// Global heights are unique only within one aggregation namespace, so separate namespaces
    /// must use separate actors and archive partitions.
    pub namespace: RecoveryNamespace,
    /// Immutable certificate archive configuration.
    pub archive: immutable::Config<C>,
    /// Retirement marker and namespace-floor metadata configuration.
    pub metadata: metadata::Config<()>,
    /// Capacity of the ingress queue. Overflowed resolver deliveries are retried;
    /// other overflowed requests receive a canceled response and must also be retried.
    pub mailbox_size: NonZeroUsize,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum MetadataKey {
    Marker(Retirement),
    Floor(RecoveryNamespace),
    Cleanup(Retirement),
}

impl Display for MetadataKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Marker(r) => write!(
                f,
                "marker/{}/{}/{}/{}",
                r.namespace, r.epoch, r.first, r.last
            ),
            Self::Floor(namespace) => write!(f, "floor/{namespace}"),
            Self::Cleanup(r) => {
                write!(
                    f,
                    "cleanup/{}/{}/{}/{}",
                    r.namespace, r.epoch, r.first, r.last
                )
            }
        }
    }
}

impl Write for MetadataKey {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Marker(r) => {
                0u8.write(buf);
                r.namespace.write(buf);
                r.epoch.write(buf);
                r.first.write(buf);
                r.last.write(buf);
            }
            Self::Floor(namespace) => {
                1u8.write(buf);
                namespace.write(buf);
            }
            Self::Cleanup(r) => {
                2u8.write(buf);
                r.namespace.write(buf);
                r.epoch.write(buf);
                r.first.write(buf);
                r.last.write(buf);
            }
        }
    }
}

impl Read for MetadataKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Marker(Retirement {
                namespace: RecoveryNamespace::read(buf)?,
                epoch: Epoch::read(buf)?,
                first: Height::read(buf)?,
                last: Height::read(buf)?,
            })),
            1 => Ok(Self::Floor(RecoveryNamespace::read(buf)?)),
            2 => Ok(Self::Cleanup(Retirement {
                namespace: RecoveryNamespace::read(buf)?,
                epoch: Epoch::read(buf)?,
                first: Height::read(buf)?,
                last: Height::read(buf)?,
            })),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for MetadataKey {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Marker(r) => {
                r.namespace.encode_size()
                    + r.epoch.encode_size()
                    + r.first.encode_size()
                    + r.last.encode_size()
            }
            Self::Floor(namespace) => namespace.encode_size(),
            Self::Cleanup(r) => {
                r.namespace.encode_size()
                    + r.epoch.encode_size()
                    + r.first.encode_size()
                    + r.last.encode_size()
            }
        }
    }
}

impl Span for MetadataKey {}

#[derive(Clone, Copy, Debug)]
enum MetadataValue {
    Marker,
    Floor(Epoch),
    Exhausted,
}

impl Write for MetadataValue {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Marker => 0u8.write(buf),
            Self::Floor(epoch) => {
                1u8.write(buf);
                epoch.write(buf);
            }
            Self::Exhausted => 2u8.write(buf),
        }
    }
}

impl Read for MetadataValue {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Marker),
            1 => Ok(Self::Floor(Epoch::read(buf)?)),
            2 => Ok(Self::Exhausted),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for MetadataValue {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Marker => 0,
            Self::Floor(epoch) => epoch.encode_size(),
            Self::Exhausted => 0,
        }
    }
}

struct DeliveryResponse(Option<oneshot::Sender<Outcome>>);

impl DeliveryResponse {
    const fn new(response: oneshot::Sender<Outcome>) -> Self {
        Self(Some(response))
    }

    fn send(mut self, outcome: Outcome) {
        let _ = self
            .0
            .take()
            .expect("delivery response missing")
            .send(outcome);
    }
}

impl Drop for DeliveryResponse {
    fn drop(&mut self) {
        if let Some(response) = self.0.take() {
            let _ = response.send(Outcome::Ignored);
        }
    }
}

enum Message {
    Archive {
        key: RecoveryKey,
        value: Bytes,
        response: oneshot::Sender<ArchiveStatus>,
    },
    Deliver {
        key: RecoveryKey,
        value: Bytes,
        response: DeliveryResponse,
    },
    Produce {
        key: RecoveryKey,
        response: oneshot::Sender<Bytes>,
    },
    Retire {
        retirement: Retirement,
        response: oneshot::Sender<Option<Cleanup>>,
    },
    Oldest {
        namespace: RecoveryNamespace,
        response: oneshot::Sender<Option<Epoch>>,
    },
    Retired {
        retirement: Retirement,
        response: oneshot::Sender<bool>,
    },
    Missing {
        retirement: Retirement,
        maximum: NonZeroUsize,
        response: oneshot::Sender<Vec<Height>>,
    },
    PendingCleanups {
        namespace: RecoveryNamespace,
        maximum: NonZeroUsize,
        response: oneshot::Sender<Vec<Cleanup>>,
    },
    CleanupComplete {
        retirement: Retirement,
        response: oneshot::Sender<bool>,
    },
}

#[derive(Default)]
struct Pending;

impl Overflow<Message> for Pending {
    fn is_empty(&self) -> bool {
        true
    }

    fn drain<F>(&mut self, _push: F)
    where
        F: FnMut(Message) -> Option<Message>,
    {
    }
}

impl Policy for Message {
    type Overflow = Pending;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        let _ = overflow;
        if let Self::Deliver { response, .. } = message {
            response.send(Outcome::Ambiguous);
        }
    }
}

/// Cloneable ingress, resolver consumer, and resolver producer.
#[derive(Clone)]
pub struct Handler {
    sender: Sender<Message>,
}

impl Handler {
    /// Archives a locally recovered certificate.
    ///
    /// `Stored` and `Duplicate` are returned only after an archive sync succeeds.
    pub async fn archive(
        &mut self,
        key: RecoveryKey,
        value: Bytes,
    ) -> Result<ArchiveStatus, RequestError> {
        let (response, receiver) = oneshot::channel();
        let feedback = self.sender.enqueue(Message::Archive {
            key,
            value,
            response,
        });
        receive(feedback, receiver).await
    }

    /// Retires one exact authenticated epoch range.
    ///
    /// The returned cleanup intent is the journal-cleanup gate.
    pub async fn retire(
        &mut self,
        retirement: Retirement,
    ) -> Result<Option<Cleanup>, RequestError> {
        let (response, receiver) = oneshot::channel();
        let feedback = self.sender.enqueue(Message::Retire {
            retirement,
            response,
        });
        receive(feedback, receiver).await
    }

    /// Reads the persisted or authenticated initial discovery floor.
    pub async fn oldest_unretired(
        &mut self,
        namespace: RecoveryNamespace,
    ) -> Result<Option<Epoch>, RequestError> {
        let (response, receiver) = oneshot::channel();
        let feedback = self.sender.enqueue(Message::Oldest {
            namespace,
            response,
        });
        receive(feedback, receiver).await
    }

    /// Returns whether the exact retirement marker is durable.
    pub async fn retired(&mut self, retirement: Retirement) -> Result<bool, RequestError> {
        let (response, receiver) = oneshot::channel();
        let feedback = self.sender.enqueue(Message::Retired {
            retirement,
            response,
        });
        receive(feedback, receiver).await
    }

    /// Returns up to `maximum` missing heights in an authenticated range.
    pub async fn missing(
        &mut self,
        retirement: Retirement,
        maximum: NonZeroUsize,
    ) -> Result<Vec<Height>, RequestError> {
        let (response, receiver) = oneshot::channel();
        let feedback = self.sender.enqueue(Message::Missing {
            retirement,
            maximum,
            response,
        });
        receive(feedback, receiver).await
    }

    /// Returns durable journal-cleanup intents in epoch order.
    pub async fn pending_cleanups(
        &mut self,
        namespace: RecoveryNamespace,
        maximum: NonZeroUsize,
    ) -> Result<Vec<Cleanup>, RequestError> {
        let (response, receiver) = oneshot::channel();
        let feedback = self.sender.enqueue(Message::PendingCleanups {
            namespace,
            maximum,
            response,
        });
        receive(feedback, receiver).await
    }

    /// Confirms removal of the journal named by a durable cleanup intent.
    pub async fn cleanup_complete(&mut self, retirement: Retirement) -> Result<bool, RequestError> {
        let (response, receiver) = oneshot::channel();
        let feedback = self.sender.enqueue(Message::CleanupComplete {
            retirement,
            response,
        });
        receive(feedback, receiver).await
    }
}

async fn receive<T>(feedback: Feedback, receiver: oneshot::Receiver<T>) -> Result<T, RequestError> {
    match feedback {
        Feedback::Ok => receiver.await.map_err(|_| RequestError::Closed),
        Feedback::Backoff => Err(RequestError::Backpressured),
        Feedback::Closed => Err(RequestError::Closed),
    }
}

impl Consumer for Handler {
    type Key = RecoveryKey;
    type Value = Bytes;
    type Subscriber = ();
    type Outcome = Outcome;

    fn deliver(
        &mut self,
        delivery: Delivery<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<Self::Outcome> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Deliver {
            key: delivery.key,
            value,
            response: DeliveryResponse::new(response),
        });
        receiver
    }
}

impl Producer for Handler {
    type Key = RecoveryKey;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Produce { key, response });
        receiver
    }
}

/// Storage-owning aggregation history actor.
pub struct Actor<E, S, D, P, T>
where
    E: Context,
    S: Scheme<D>,
    D: Digest,
    P: Provider<S>,
    T: Strategy,
{
    context: ContextCell<E>,
    namespace: RecoveryNamespace,
    archive: Option<Archive<E, S, D>>,
    metadata: Option<metadata::Metadata<E, MetadataKey, MetadataValue>>,
    provider: P,
    strategy: T,
    receiver: mailbox::Receiver<Message>,
    _digest: PhantomData<D>,
}

impl<E, S, D, P, T> Actor<E, S, D, P, T>
where
    E: Context + CryptoRng + Spawner,
    S: Scheme<D>,
    D: Digest,
    P: Provider<S>,
    T: Strategy,
{
    /// Initializes durable history and its bounded ingress.
    pub async fn init(
        context: E,
        config: Config<<S::Certificate as Read>::Cfg>,
        provider: P,
        strategy: T,
    ) -> Result<(Self, Handler), Error> {
        let archive = immutable::Archive::init(context.child("archive"), config.archive).await?;
        let metadata = metadata::Metadata::init(context.child("metadata"), config.metadata).await?;
        let (sender, receiver) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        Ok((
            Self {
                context: ContextCell::new(context),
                namespace: config.namespace,
                archive: Some(archive),
                metadata: Some(metadata),
                provider,
                strategy,
                receiver,
                _digest: PhantomData,
            },
            Handler { sender },
        ))
    }

    /// Starts the storage actor. Any mutation failure terminates it permanently.
    pub fn start(self) -> Handle<Result<(), Error>> {
        let mut actor = self;
        spawn_cell!(actor.context, actor.run())
    }

    async fn run(mut self) -> Result<(), Error> {
        select_loop! {
            self.context,
            on_stopped => {},
            Some(message) = self.receiver.recv() else break => match message {
                Message::Archive { key, value, response } => {
                    let status = self.archive_certificate(key, value).await?;
                    let _ = response.send(status);
                }
                Message::Deliver { key, value, response } => {
                    let status = match self.archive_certificate(key, value).await {
                        Ok(status) => status,
                        Err(error) => {
                            response.send(Outcome::Ignored);
                            return Err(error);
                        }
                    };
                    response.send(if status == ArchiveStatus::Rejected {
                        Outcome::Invalid
                    } else {
                        Outcome::Complete
                    });
                }
                Message::Produce { key, response } => {
                    if let Some(value) = self.produce(key).await? {
                        let _ = response.send(value);
                    }
                }
                Message::Retire { retirement, response } => {
                    let cleanup = self.retire_range(retirement).await?;
                    let _ = response.send(cleanup);
                }
                Message::Oldest { namespace, response } => {
                    let _ = response.send(self.oldest(namespace));
                }
                Message::Retired { retirement, response } => {
                    let _ = response.send(self.is_retired(retirement));
                }
                Message::Missing { retirement, maximum, response } => {
                    let _ = response.send(self.missing_heights(retirement, maximum));
                }
                Message::PendingCleanups { namespace, maximum, response } => {
                    let _ = response.send(self.pending_cleanups(namespace, maximum));
                }
                Message::CleanupComplete { retirement, response } => {
                    let completed = self.cleanup_complete(retirement).await?;
                    let _ = response.send(completed);
                }
            },
        }
        Ok(())
    }

    fn authenticated(&self, key: RecoveryKey) -> Option<AuthenticatedEpoch<S>> {
        if key.namespace != self.namespace {
            return None;
        }
        let epoch = self.provider.epoch(key.namespace, key.epoch)?;
        (epoch.scheme.recovery_namespace() == key.namespace
            && key.position >= epoch.first
            && key.position <= epoch.last)
            .then_some(epoch)
    }

    fn decode_verify(&mut self, key: RecoveryKey, value: &Bytes) -> Option<Certificate<S, D>> {
        let epoch = self.authenticated(key)?;
        let certificate = Certificate::<S, D>::decode_cfg(
            value.clone(),
            &epoch.scheme.certificate_codec_config(),
        )
        .ok()?;
        (certificate.item.position == key.position
            && certificate.verify_for(
                self.context.as_present_mut(),
                &epoch.scheme,
                key.epoch,
                epoch.first,
                epoch.last,
                &self.strategy,
            ))
        .then_some(certificate)
    }

    async fn archive_certificate(
        &mut self,
        key: RecoveryKey,
        value: Bytes,
    ) -> Result<ArchiveStatus, Error> {
        let Some(certificate) = self.decode_verify(key, &value) else {
            return Ok(ArchiveStatus::Rejected);
        };
        let index = key.position.get();
        let archive = self.archive.as_ref().expect("archive unavailable");
        if let Some(existing) = archive.get(Identifier::Index(index)).await? {
            let _ = existing;
            return Ok(ArchiveStatus::Duplicate);
        }
        let archive = self.archive.take().expect("archive unavailable");
        let key_hash = Sha256::hash(&[key.encode().as_ref()]);
        let archive = archive.put(index, key_hash, certificate).await?;
        self.archive = Some(archive.sync().await?);
        Ok(ArchiveStatus::Stored)
    }

    async fn produce(&self, key: RecoveryKey) -> Result<Option<Bytes>, Error> {
        if key.namespace != self.namespace {
            return Ok(None);
        }
        let certificate = self
            .archive
            .as_ref()
            .expect("archive unavailable")
            .get(Identifier::Index(key.position.get()))
            .await?;
        Ok(certificate.and_then(|certificate| {
            (certificate.epoch == key.epoch && certificate.item.position == key.position)
                .then(|| certificate.encode())
        }))
    }

    async fn retire_range(&mut self, retirement: Retirement) -> Result<Option<Cleanup>, Error> {
        if retirement.namespace != self.namespace {
            return Ok(None);
        }
        let Some(epoch) = self.provider.epoch(retirement.namespace, retirement.epoch) else {
            return Ok(None);
        };
        if epoch.scheme.recovery_namespace() != retirement.namespace
            || epoch.first != retirement.first
            || epoch.last != retirement.last
        {
            return Ok(None);
        }

        // Sync first, then confirm exact semantic coverage of the durable view.
        let archive = self.archive.take().expect("archive unavailable");
        self.archive = Some(archive.sync().await?);
        for index in retirement.first.get()..=retirement.last.get() {
            let Some(certificate) = self
                .archive
                .as_ref()
                .expect("archive unavailable")
                .get(Identifier::Index(index))
                .await?
            else {
                return Ok(None);
            };
            let key = RecoveryKey {
                namespace: retirement.namespace,
                epoch: retirement.epoch,
                position: Height::new(index),
            };
            if certificate.item.position != key.position
                || !certificate.verify_for(
                    self.context.as_present_mut(),
                    &epoch.scheme,
                    retirement.epoch,
                    retirement.first,
                    retirement.last,
                    &self.strategy,
                )
            {
                return Ok(None);
            }
        }

        let marker = MetadataKey::Marker(retirement);
        let mut metadata = self.metadata.take().expect("metadata unavailable");
        metadata.put(marker, MetadataValue::Marker);
        metadata.put(MetadataKey::Cleanup(retirement), MetadataValue::Marker);
        self.metadata = Some(metadata.sync().await?);
        Ok(Some(Cleanup { retirement }))
    }

    fn oldest(&self, namespace: RecoveryNamespace) -> Option<Epoch> {
        if namespace != self.namespace {
            return None;
        }
        match self
            .metadata
            .as_ref()
            .expect("metadata unavailable")
            .get(&MetadataKey::Floor(namespace))
        {
            Some(MetadataValue::Floor(epoch)) => Some(*epoch),
            Some(MetadataValue::Exhausted) => None,
            Some(MetadataValue::Marker) | None => self.provider.oldest_epoch(namespace),
        }
    }

    fn is_retired(&self, retirement: Retirement) -> bool {
        retirement.namespace == self.namespace
            && self
                .metadata
                .as_ref()
                .expect("metadata unavailable")
                .get(&MetadataKey::Marker(retirement))
                .is_some()
    }

    fn missing_heights(&self, retirement: Retirement, maximum: NonZeroUsize) -> Vec<Height> {
        if retirement.namespace != self.namespace || self.is_retired(retirement) {
            return Vec::new();
        }
        let Some(epoch) = self.provider.epoch(retirement.namespace, retirement.epoch) else {
            return Vec::new();
        };
        if epoch.scheme.recovery_namespace() != retirement.namespace
            || epoch.first != retirement.first
            || epoch.last != retirement.last
        {
            return Vec::new();
        }
        let archive = self.archive.as_ref().expect("archive unavailable");
        let mut missing = Vec::with_capacity(maximum.get());
        let mut cursor = retirement.first.get();
        let last = retirement.last.get();
        for (start, end) in archive.ranges_from(cursor) {
            if start > last {
                break;
            }
            while cursor < start && cursor <= last && missing.len() < maximum.get() {
                missing.push(Height::new(cursor));
                let Some(next) = cursor.checked_add(1) else {
                    return missing;
                };
                cursor = next;
            }
            if missing.len() == maximum.get() {
                return missing;
            }
            if end >= cursor {
                let Some(next) = end.checked_add(1) else {
                    return missing;
                };
                cursor = next;
            }
            if cursor > last {
                return missing;
            }
        }
        while cursor <= last && missing.len() < maximum.get() {
            missing.push(Height::new(cursor));
            let Some(next) = cursor.checked_add(1) else {
                break;
            };
            cursor = next;
        }
        missing
    }

    fn pending_cleanups(
        &self,
        namespace: RecoveryNamespace,
        maximum: NonZeroUsize,
    ) -> Vec<Cleanup> {
        if namespace != self.namespace {
            return Vec::new();
        }
        self.metadata
            .as_ref()
            .expect("metadata unavailable")
            .keys()
            .filter_map(|key| match key {
                MetadataKey::Cleanup(retirement) if retirement.namespace == namespace => {
                    Some(Cleanup {
                        retirement: *retirement,
                    })
                }
                _ => None,
            })
            .take(maximum.get())
            .collect()
    }

    async fn cleanup_complete(&mut self, retirement: Retirement) -> Result<bool, Error> {
        if retirement.namespace != self.namespace {
            return Ok(false);
        }
        let key = MetadataKey::Cleanup(retirement);
        let mut metadata = self.metadata.take().expect("metadata unavailable");
        let removed = metadata.remove(&key).is_some();
        self.metadata = Some(if removed {
            self.advance_floor(&mut metadata, retirement.namespace);
            metadata.sync().await?
        } else {
            metadata
        });
        Ok(removed)
    }

    fn advance_floor(
        &self,
        metadata: &mut metadata::Metadata<E, MetadataKey, MetadataValue>,
        namespace: RecoveryNamespace,
    ) {
        let mut floor = match metadata.get(&MetadataKey::Floor(namespace)) {
            Some(MetadataValue::Floor(epoch)) => Some(*epoch),
            Some(MetadataValue::Exhausted) => return,
            Some(MetadataValue::Marker) | None => self.provider.oldest_epoch(namespace),
        };
        while let Some(current) = floor {
            let Some(current_epoch) = self.provider.epoch(namespace, current) else {
                break;
            };
            let exact = Retirement {
                namespace,
                epoch: current,
                first: current_epoch.first,
                last: current_epoch.last,
            };
            if metadata.get(&MetadataKey::Marker(exact)).is_none()
                || metadata.get(&MetadataKey::Cleanup(exact)).is_some()
            {
                break;
            }
            if current.get() == u64::MAX {
                floor = None;
                break;
            }
            floor = Some(Epoch::new(current.get() + 1));
        }
        metadata.put(
            MetadataKey::Floor(namespace),
            floor.map_or(MetadataValue::Exhausted, MetadataValue::Floor),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_actor::Feedback;
    use commonware_codec::DecodeExt as _;
    use commonware_consensus::aggregation::{
        scheme,
        types::{Ack, Certificate, Item},
    };
    use commonware_cryptography::{Sha256, certificate::Verifier as _};
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_resolver::{Delivery, Outcome};
    use commonware_runtime::{Runner, Supervisor as _, buffer::paged::CacheRef, deterministic};
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty, non_empty_vec};
    use std::{collections::BTreeMap, sync::Arc};

    type TestScheme = scheme::ed25519::Scheme;
    type TestDigest = commonware_cryptography::sha256::Digest;

    #[derive(Clone)]
    struct TestProvider {
        namespace: RecoveryNamespace,
        epochs: Arc<BTreeMap<Epoch, AuthenticatedEpoch<TestScheme>>>,
        oldest: Epoch,
    }

    impl Provider<TestScheme> for TestProvider {
        fn epoch(
            &self,
            namespace: RecoveryNamespace,
            epoch: Epoch,
        ) -> Option<AuthenticatedEpoch<TestScheme>> {
            (namespace == self.namespace)
                .then(|| self.epochs.get(&epoch).cloned())
                .flatten()
        }

        fn oldest_epoch(&self, namespace: RecoveryNamespace) -> Option<Epoch> {
            (namespace == self.namespace).then_some(self.oldest)
        }
    }

    fn storage_config(
        context: &deterministic::Context,
        namespace: RecoveryNamespace,
        codec_config: <<TestScheme as commonware_cryptography::certificate::Verifier>::Certificate as Read>::Cfg,
    ) -> Config<
        <<TestScheme as commonware_cryptography::certificate::Verifier>::Certificate as Read>::Cfg,
    > {
        Config {
            namespace,
            archive: immutable::Config {
                metadata_partition: "aggregation_archive_metadata".into(),
                freezer_table_partition: "aggregation_archive_table".into(),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 4,
                freezer_table_resize_chunk_size: 32,
                freezer_key_partition: "aggregation_archive_keys".into(),
                freezer_key_page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
                freezer_value_partition: "aggregation_archive_values".into(),
                freezer_value_target_size: 1024 * 1024,
                freezer_value_compression: None,
                ordinal_partition: "aggregation_archive_ordinal".into(),
                items_per_section: NZU64!(64),
                freezer_key_write_buffer: NZUsize!(1024),
                freezer_value_write_buffer: NZUsize!(1024),
                ordinal_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                codec_config,
            },
            metadata: metadata::Config {
                partition: "aggregation_retirement".into(),
                codec_config: (),
            },
            mailbox_size: NZUsize!(1),
        }
    }

    fn certificate(
        schemes: &[TestScheme],
        epoch: Epoch,
        position: Height,
    ) -> Certificate<TestScheme, TestDigest> {
        certificate_from(
            schemes,
            &(0..schemes.len()).collect::<Vec<_>>(),
            epoch,
            position,
        )
    }

    fn certificate_from(
        schemes: &[TestScheme],
        signers: &[usize],
        epoch: Epoch,
        position: Height,
    ) -> Certificate<TestScheme, TestDigest> {
        let item = Item {
            position,
            digest: Sha256::hash(&[&position.get().to_be_bytes()]),
        };
        let acks: Vec<_> = signers
            .iter()
            .filter_map(|index| Ack::sign(&schemes[*index], item.clone()))
            .collect();
        Certificate::from_acks(&schemes[0], epoch, non_empty![@acks.iter()], &Sequential).unwrap()
    }

    fn key(namespace: RecoveryNamespace, epoch: u64, position: u64) -> RecoveryKey {
        RecoveryKey {
            namespace,
            epoch: Epoch::new(epoch),
            position: Height::new(position),
        }
    }

    #[test]
    fn retirement_metadata_codec_and_labels_are_stable() {
        let namespace = RecoveryNamespace::derive(b"metadata-codec");
        let retirement = Retirement {
            namespace,
            epoch: Epoch::new(3),
            first: Height::new(10),
            last: Height::new(19),
        };
        let keys = [
            MetadataKey::Marker(retirement),
            MetadataKey::Floor(namespace),
            MetadataKey::Cleanup(retirement),
        ];
        for key in keys {
            let encoded = key.encode();
            assert_eq!(MetadataKey::decode(encoded).unwrap(), key);
            assert!(!key.to_string().is_empty());
        }
        assert!(MetadataKey::decode(Bytes::from_static(&[3])).is_err());

        for value in [
            MetadataValue::Marker,
            MetadataValue::Floor(Epoch::new(4)),
            MetadataValue::Exhausted,
        ] {
            let encoded = value.encode();
            assert_eq!(
                MetadataValue::decode(encoded.clone()).unwrap().encode(),
                encoded
            );
        }
        assert!(MetadataValue::decode(Bytes::from_static(&[3])).is_err());
    }

    #[test_traced]
    fn durable_history_retirement_and_restart() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme::ed25519::fixture(&mut context, b"aggregation-history", 4);
            let schemes = fixture.schemes;
            let namespace =
                <TestScheme as scheme::Scheme<TestDigest>>::recovery_namespace(&schemes[0]);
            let mut epochs = BTreeMap::new();
            epochs.insert(
                Epoch::new(1),
                AuthenticatedEpoch::new(
                    Arc::new(schemes[0].clone()),
                    Height::new(10),
                    Height::new(11),
                )
                .unwrap(),
            );
            epochs.insert(
                Epoch::new(2),
                AuthenticatedEpoch::new(
                    Arc::new(schemes[0].clone()),
                    Height::new(12),
                    Height::new(12),
                )
                .unwrap(),
            );
            let provider = TestProvider {
                namespace,
                epochs: Arc::new(epochs),
                oldest: Epoch::new(1),
            };
            let codec = schemes[0].certificate_codec_config();
            let (actor, mut handler) = Actor::<_, TestScheme, TestDigest, _, _>::init(
                context.child("first"),
                storage_config(&context, namespace, codec),
                provider.clone(),
                Sequential,
            )
            .await
            .unwrap();
            let task = actor.start();

            let epoch_one = Retirement {
                namespace,
                epoch: Epoch::new(1),
                first: Height::new(10),
                last: Height::new(11),
            };
            assert_eq!(
                handler.missing(epoch_one, NZUsize!(10)).await.unwrap(),
                vec![Height::new(10), Height::new(11)]
            );

            // Invalid bytes are rejected before the immutable height is occupied.
            assert_eq!(
                handler
                    .archive(key(namespace, 1, 10), Bytes::from_static(b"invalid"))
                    .await
                    .unwrap(),
                ArchiveStatus::Rejected
            );
            let ten = certificate(&schemes, Epoch::new(1), Height::new(10)).encode();
            assert_eq!(
                handler
                    .archive(key(RecoveryNamespace::derive(b"other"), 1, 10), ten.clone(),)
                    .await
                    .unwrap(),
                ArchiveStatus::Rejected
            );
            assert_eq!(
                handler
                    .archive(key(namespace, 1, 10), ten.clone())
                    .await
                    .unwrap(),
                ArchiveStatus::Stored
            );
            assert_eq!(
                handler
                    .archive(key(namespace, 1, 10), ten.clone())
                    .await
                    .unwrap(),
                ArchiveStatus::Duplicate
            );

            // Different valid quorum encodings satisfy the same resolver key.
            let alternate_ten =
                certificate_from(&schemes, &[0, 1, 3], Epoch::new(1), Height::new(10)).encode();
            let delivery = Delivery {
                key: key(namespace, 1, 10),
                subscribers: non_empty_vec![((), tracing::Span::none())],
            };
            assert_eq!(
                Consumer::deliver(&mut handler, delivery, alternate_ten)
                    .await
                    .unwrap(),
                Outcome::Complete
            );
            assert_eq!(
                handler.missing(epoch_one, NZUsize!(10)).await.unwrap(),
                vec![Height::new(11)]
            );

            // A missing height prevents the exact range marker and cleanup intent.
            assert_eq!(handler.retire(epoch_one).await.unwrap(), None);

            let eleven = certificate(&schemes, Epoch::new(1), Height::new(11)).encode();
            let delivery = Delivery {
                key: key(namespace, 1, 11),
                subscribers: non_empty_vec![((), tracing::Span::none())],
            };
            assert_eq!(
                Consumer::deliver(&mut handler, delivery, eleven)
                    .await
                    .unwrap(),
                Outcome::Complete
            );
            assert_eq!(
                Producer::produce(&mut handler, key(namespace, 1, 10))
                    .await
                    .unwrap(),
                ten
            );

            // A future exact marker does not skip the oldest unretired epoch.
            let twelve = certificate(&schemes, Epoch::new(2), Height::new(12)).encode();
            assert_eq!(
                handler
                    .archive(key(namespace, 2, 12), twelve)
                    .await
                    .unwrap(),
                ArchiveStatus::Stored
            );
            let epoch_two = Retirement {
                namespace,
                epoch: Epoch::new(2),
                first: Height::new(12),
                last: Height::new(12),
            };
            assert_eq!(
                handler.retire(epoch_two).await.unwrap(),
                Some(Cleanup {
                    retirement: epoch_two
                })
            );
            assert!(handler.retired(epoch_two).await.unwrap());
            assert!(!handler.retired(epoch_one).await.unwrap());
            assert_eq!(
                handler.oldest_unretired(namespace).await.unwrap(),
                Some(Epoch::new(1))
            );
            assert_eq!(
                handler.retire(epoch_one).await.unwrap(),
                Some(Cleanup {
                    retirement: epoch_one
                })
            );
            assert_eq!(
                handler.oldest_unretired(namespace).await.unwrap(),
                Some(Epoch::new(1))
            );
            assert!(handler.retired(epoch_one).await.unwrap());
            assert!(
                handler
                    .missing(epoch_one, NZUsize!(10))
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                handler
                    .pending_cleanups(namespace, NZUsize!(10))
                    .await
                    .unwrap(),
                vec![
                    Cleanup {
                        retirement: epoch_one
                    },
                    Cleanup {
                        retirement: epoch_two
                    }
                ]
            );

            // Crossing both durability boundaries survives actor restart.
            drop(handler);
            task.await.unwrap().unwrap();
            let (actor, mut handler) = Actor::<_, TestScheme, TestDigest, _, _>::init(
                context.child("second"),
                storage_config(&context, namespace, codec),
                provider,
                Sequential,
            )
            .await
            .unwrap();
            let task = actor.start();
            assert_eq!(
                handler.oldest_unretired(namespace).await.unwrap(),
                Some(Epoch::new(1))
            );
            assert_eq!(
                Producer::produce(&mut handler, key(namespace, 1, 10))
                    .await
                    .unwrap(),
                ten
            );
            assert_eq!(
                handler
                    .pending_cleanups(namespace, NZUsize!(10))
                    .await
                    .unwrap(),
                vec![
                    Cleanup {
                        retirement: epoch_one
                    },
                    Cleanup {
                        retirement: epoch_two
                    }
                ]
            );
            assert!(handler.cleanup_complete(epoch_one).await.unwrap());
            assert!(!handler.cleanup_complete(epoch_one).await.unwrap());
            assert_eq!(
                handler.oldest_unretired(namespace).await.unwrap(),
                Some(Epoch::new(2))
            );
            assert_eq!(
                handler
                    .pending_cleanups(namespace, NZUsize!(10))
                    .await
                    .unwrap(),
                vec![Cleanup {
                    retirement: epoch_two
                }]
            );
            assert!(handler.cleanup_complete(epoch_two).await.unwrap());
            assert_eq!(
                handler.oldest_unretired(namespace).await.unwrap(),
                Some(Epoch::new(3))
            );
            context.child("stop").stop(0, None).await.unwrap();
            task.await.unwrap().unwrap();
            drop(handler);
        });
    }

    #[test_traced]
    fn bounded_ingress_retries_delivery_on_backpressure() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, _receiver) = mailbox::new(context, NZUsize!(1));
            let mut handler = Handler { sender };
            let namespace = RecoveryNamespace::derive(b"bounded-history");

            let _pending = Producer::produce(&mut handler, key(namespace, 1, 1));
            let delivery = Delivery {
                key: key(namespace, 1, 2),
                subscribers: non_empty_vec![((), tracing::Span::none())],
            };
            assert_eq!(
                Consumer::deliver(&mut handler, delivery, Bytes::new())
                    .await
                    .unwrap(),
                Outcome::Ambiguous
            );
            assert_eq!(
                handler.sender.enqueue(Message::Produce {
                    key: key(namespace, 1, 3),
                    response: oneshot::channel().0,
                }),
                Feedback::Backoff
            );
        });
    }

    #[test_traced]
    fn authenticated_requests_reject_untrusted_identity() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme::ed25519::fixture(&mut context, b"authenticated-history", 4);
            let schemes = fixture.schemes;
            let rogue = scheme::ed25519::fixture(&mut context, b"rogue-history", 4).schemes;
            let namespace =
                <TestScheme as scheme::Scheme<TestDigest>>::recovery_namespace(&schemes[0]);
            let rogue_namespace =
                <TestScheme as scheme::Scheme<TestDigest>>::recovery_namespace(&rogue[0]);
            assert_ne!(namespace, rogue_namespace);
            assert!(
                AuthenticatedEpoch::new(
                    Arc::new(schemes[0].clone()),
                    Height::new(11),
                    Height::new(10),
                )
                .is_none()
            );

            let mut epochs = BTreeMap::new();
            epochs.insert(
                Epoch::new(1),
                AuthenticatedEpoch::new(
                    Arc::new(schemes[0].clone()),
                    Height::new(10),
                    Height::new(11),
                )
                .unwrap(),
            );
            // The provider is application-owned, but the actor still verifies that its scheme
            // derives the configured namespace.
            epochs.insert(
                Epoch::new(2),
                AuthenticatedEpoch::new(
                    Arc::new(rogue[0].clone()),
                    Height::new(20),
                    Height::new(20),
                )
                .unwrap(),
            );
            let provider = TestProvider {
                namespace,
                epochs: Arc::new(epochs),
                oldest: Epoch::new(1),
            };
            let (actor, mut handler) = Actor::<_, TestScheme, TestDigest, _, _>::init(
                context.child("history"),
                storage_config(&context, namespace, schemes[0].certificate_codec_config()),
                provider,
                Sequential,
            )
            .await
            .unwrap();
            let task = actor.start();

            let ten = certificate(&schemes, Epoch::new(1), Height::new(10)).encode();
            for rejected in [
                key(namespace, 9, 10),
                key(namespace, 1, 9),
                key(namespace, 1, 12),
                key(namespace, 1, 11),
                key(rogue_namespace, 1, 10),
            ] {
                assert_eq!(
                    handler.archive(rejected, ten.clone()).await.unwrap(),
                    ArchiveStatus::Rejected
                );
            }
            let rogue_twenty = certificate(&rogue, Epoch::new(2), Height::new(20)).encode();
            assert_eq!(
                handler
                    .archive(key(namespace, 2, 20), rogue_twenty)
                    .await
                    .unwrap(),
                ArchiveStatus::Rejected
            );

            let delivery = Delivery {
                key: key(namespace, 9, 10),
                subscribers: non_empty_vec![((), tracing::Span::none())],
            };
            assert_eq!(
                Consumer::deliver(&mut handler, delivery, ten.clone())
                    .await
                    .unwrap(),
                Outcome::Invalid
            );
            assert_eq!(
                handler
                    .archive(key(namespace, 1, 10), ten.clone())
                    .await
                    .unwrap(),
                ArchiveStatus::Stored
            );
            assert!(
                Producer::produce(&mut handler, key(rogue_namespace, 1, 10))
                    .await
                    .is_err()
            );
            assert!(
                Producer::produce(&mut handler, key(namespace, 2, 10))
                    .await
                    .is_err()
            );
            assert_eq!(
                Producer::produce(&mut handler, key(namespace, 1, 10))
                    .await
                    .unwrap(),
                ten
            );

            drop(handler);
            task.await.unwrap().unwrap();
        });
    }

    #[test_traced]
    fn sparse_missing_height_discovery_honors_range_and_limit() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme::ed25519::fixture(&mut context, b"sparse-history", 4);
            let schemes = fixture.schemes;
            let namespace =
                <TestScheme as scheme::Scheme<TestDigest>>::recovery_namespace(&schemes[0]);
            let ranges = [(0, 5, 5), (1, 10, 15), (2, 20, 20)];
            let epochs = ranges
                .into_iter()
                .map(|(epoch, first, last)| {
                    (
                        Epoch::new(epoch),
                        AuthenticatedEpoch::new(
                            Arc::new(schemes[0].clone()),
                            Height::new(first),
                            Height::new(last),
                        )
                        .unwrap(),
                    )
                })
                .collect();
            let provider = TestProvider {
                namespace,
                epochs: Arc::new(epochs),
                oldest: Epoch::new(0),
            };
            let (actor, mut handler) = Actor::<_, TestScheme, TestDigest, _, _>::init(
                context.child("history"),
                storage_config(&context, namespace, schemes[0].certificate_codec_config()),
                provider,
                Sequential,
            )
            .await
            .unwrap();
            let task = actor.start();

            for (epoch, position) in [(0, 5), (1, 10), (1, 12), (1, 13), (1, 15), (2, 20)] {
                let value =
                    certificate(&schemes, Epoch::new(epoch), Height::new(position)).encode();
                assert_eq!(
                    handler
                        .archive(key(namespace, epoch, position), value)
                        .await
                        .unwrap(),
                    ArchiveStatus::Stored
                );
            }
            let target = Retirement {
                namespace,
                epoch: Epoch::new(1),
                first: Height::new(10),
                last: Height::new(15),
            };
            assert_eq!(
                handler.missing(target, NZUsize!(1)).await.unwrap(),
                vec![Height::new(11)]
            );
            assert_eq!(
                handler.missing(target, NZUsize!(2)).await.unwrap(),
                vec![Height::new(11), Height::new(14)]
            );
            assert_eq!(
                handler.missing(target, NZUsize!(10)).await.unwrap(),
                vec![Height::new(11), Height::new(14)]
            );

            for mismatched in [
                Retirement {
                    first: Height::new(9),
                    ..target
                },
                Retirement {
                    last: Height::new(16),
                    ..target
                },
                Retirement {
                    epoch: Epoch::new(9),
                    ..target
                },
            ] {
                assert!(
                    handler
                        .missing(mismatched, NZUsize!(10))
                        .await
                        .unwrap()
                        .is_empty()
                );
            }

            drop(handler);
            task.await.unwrap().unwrap();
        });
    }

    #[test_traced]
    fn cleanup_and_retirement_require_exact_namespace_and_range() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme::ed25519::fixture(&mut context, b"scoped-cleanup-history", 4);
            let schemes = fixture.schemes;
            let namespace =
                <TestScheme as scheme::Scheme<TestDigest>>::recovery_namespace(&schemes[0]);
            let other = RecoveryNamespace::derive(b"other-cleanup-history");
            let mut epochs = BTreeMap::new();
            epochs.insert(
                Epoch::new(1),
                AuthenticatedEpoch::new(
                    Arc::new(schemes[0].clone()),
                    Height::new(10),
                    Height::new(10),
                )
                .unwrap(),
            );
            epochs.insert(
                Epoch::new(2),
                AuthenticatedEpoch::new(
                    Arc::new(schemes[0].clone()),
                    Height::new(20),
                    Height::new(20),
                )
                .unwrap(),
            );
            let provider = TestProvider {
                namespace,
                epochs: Arc::new(epochs),
                oldest: Epoch::new(1),
            };
            let (actor, mut handler) = Actor::<_, TestScheme, TestDigest, _, _>::init(
                context.child("history"),
                storage_config(&context, namespace, schemes[0].certificate_codec_config()),
                provider,
                Sequential,
            )
            .await
            .unwrap();
            let task = actor.start();

            let epoch_one = Retirement {
                namespace,
                epoch: Epoch::new(1),
                first: Height::new(10),
                last: Height::new(10),
            };
            let epoch_two = Retirement {
                namespace,
                epoch: Epoch::new(2),
                first: Height::new(20),
                last: Height::new(20),
            };
            for retirement in [epoch_one, epoch_two] {
                let value = certificate(&schemes, retirement.epoch, retirement.first).encode();
                assert_eq!(
                    handler
                        .archive(
                            RecoveryKey {
                                namespace,
                                epoch: retirement.epoch,
                                position: retirement.first,
                            },
                            value,
                        )
                        .await
                        .unwrap(),
                    ArchiveStatus::Stored
                );
                assert_eq!(
                    handler.retire(retirement).await.unwrap(),
                    Some(Cleanup { retirement })
                );
            }

            let wrong_range = Retirement {
                last: Height::new(11),
                ..epoch_one
            };
            let wrong_namespace = Retirement {
                namespace: other,
                ..epoch_one
            };
            assert_eq!(handler.retire(wrong_range).await.unwrap(), None);
            assert_eq!(handler.retire(wrong_namespace).await.unwrap(), None);
            assert!(!handler.retired(wrong_range).await.unwrap());
            assert!(!handler.retired(wrong_namespace).await.unwrap());
            assert!(!handler.cleanup_complete(wrong_range).await.unwrap());
            assert!(!handler.cleanup_complete(wrong_namespace).await.unwrap());
            assert_eq!(handler.oldest_unretired(other).await.unwrap(), None);
            assert!(
                handler
                    .pending_cleanups(other, NZUsize!(10))
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                handler
                    .pending_cleanups(namespace, NZUsize!(1))
                    .await
                    .unwrap(),
                vec![Cleanup {
                    retirement: epoch_one
                }]
            );
            assert!(handler.cleanup_complete(epoch_two).await.unwrap());
            assert_eq!(
                handler.oldest_unretired(namespace).await.unwrap(),
                Some(Epoch::new(1))
            );
            assert_eq!(
                handler
                    .pending_cleanups(namespace, NZUsize!(10))
                    .await
                    .unwrap(),
                vec![Cleanup {
                    retirement: epoch_one
                }]
            );
            assert!(handler.cleanup_complete(epoch_one).await.unwrap());
            assert_eq!(
                handler.oldest_unretired(namespace).await.unwrap(),
                Some(Epoch::new(3))
            );

            drop(handler);
            task.await.unwrap().unwrap();
        });
    }

    #[test_traced]
    fn terminal_epoch_retirement_exhausts_discovery() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme::ed25519::fixture(&mut context, b"terminal-history", 4);
            let schemes = fixture.schemes;
            let namespace =
                <TestScheme as scheme::Scheme<TestDigest>>::recovery_namespace(&schemes[0]);
            let terminal = Epoch::new(u64::MAX);
            let mut epochs = BTreeMap::new();
            epochs.insert(
                terminal,
                AuthenticatedEpoch::new(
                    Arc::new(schemes[0].clone()),
                    Height::new(1),
                    Height::new(1),
                )
                .unwrap(),
            );
            let provider = TestProvider {
                namespace,
                epochs: Arc::new(epochs),
                oldest: terminal,
            };
            let codec = schemes[0].certificate_codec_config();
            let (actor, mut handler) = Actor::<_, TestScheme, TestDigest, _, _>::init(
                context.child("history"),
                storage_config(&context, namespace, codec),
                provider,
                Sequential,
            )
            .await
            .unwrap();
            let task = actor.start();
            let retirement = Retirement {
                namespace,
                epoch: terminal,
                first: Height::new(1),
                last: Height::new(1),
            };
            let value = certificate(&schemes, terminal, Height::new(1)).encode();
            assert_eq!(
                handler
                    .archive(key(namespace, u64::MAX, 1), value)
                    .await
                    .unwrap(),
                ArchiveStatus::Stored
            );
            assert_eq!(
                handler.retire(retirement).await.unwrap(),
                Some(Cleanup { retirement })
            );
            assert_eq!(
                handler.oldest_unretired(namespace).await.unwrap(),
                Some(terminal)
            );
            assert!(handler.cleanup_complete(retirement).await.unwrap());
            assert_eq!(handler.oldest_unretired(namespace).await.unwrap(), None);
            drop(handler);
            task.await.unwrap().unwrap();
        });
    }
}
