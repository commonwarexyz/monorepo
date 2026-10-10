//! The probe actor.

use super::{
    Checkpoint, Sampled, Source,
    mailbox::{Mailbox, Message},
    wire,
};
use crate::executor::checkpoints;
use bytes::{Buf as _, Bytes};
use commonware_actor::mailbox::{self as actor_mailbox, Policy, Receiver as MailboxReceiver};
use commonware_codec::{Codec, Copying, Decode as _, Encode as _, Read, ReadExt as _};
use commonware_consensus::{Block, Roundable, aggregation::scheme::Scheme, types::Height};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, ContextCell, Error as RuntimeError, Handle, IoBuf, Metrics, Spawner, spawn_cell,
};
use commonware_utils::{
    Faults, NonZeroDuration,
    channel::{fallible::OneshotExt as _, oneshot},
};
use futures::future::{self, Either};
use rand_core::CryptoRng;
use std::{
    cmp::Reverse,
    collections::BTreeMap,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};
use tracing::{debug, warn};

/// Configuration of a [`Probe`].
pub struct Config<E, S, B, F, T, K>
where
    S: Scheme<B::Digest>,
    B: Block,
    F: Codec,
{
    /// The runtime context.
    pub context: E,
    /// Verifies checkpoint certificates. Its participants are the validators a sample asks.
    pub scheme: S,
    /// Strategy for verifying certificates.
    pub strategy: T,
    /// Blocks peers that send invalid messages.
    pub blocker: K,
    /// Codec configuration of executed blocks.
    pub block_codec: B::Cfg,
    /// Codec configuration of floors.
    pub floor_codec: F::Cfg,
    /// How long a sample waits for enough replies before asking the rest again.
    pub retry_timeout: NonZeroDuration,
    /// The largest response this node serves, at most the channel's maximum message size.
    pub max_response_size: NonZeroUsize,
    /// Capacity of the probe's mailbox.
    pub mailbox_size: NonZeroUsize,
}

/// The response this node serves, for the checkpoint it names.
struct Served {
    /// Height of the checkpoint.
    checkpoint: Height,
    /// The encoded response, or `None` if it is too large to serve.
    response: Option<Bytes>,
}

/// Why a reply does not count toward a sample.
enum Rejection {
    /// No honest validator sends it, so its sender is blocked.
    Invalid(&'static str),
    /// It may come from a validator set this node does not know, so it is ignored.
    Unverifiable(&'static str),
}

/// Samples validators for the newest checkpoint, and serves this node's checkpoint to peers.
///
/// See the [module documentation](super).
pub struct Probe<E, S, B, F, T, K>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<B::Digest>,
    B: Block,
    F: Roundable + Codec + Clone + Send + Sync + 'static,
    T: Strategy,
    K: Blocker<PublicKey = S::PublicKey>,
{
    context: ContextCell<E>,
    /// Requests for samples, until every [`Mailbox`] is dropped.
    mailbox: Option<MailboxReceiver<Message<S, B, F>>>,
    scheme: S,
    strategy: T,
    blocker: K,
    codec: <wire::Message<S, B, F> as Read>::Cfg,
    retry_timeout: NonZeroDuration,
    max_response_size: NonZeroUsize,
    /// Callers awaiting the sample in progress.
    subscribers: Vec<oneshot::Sender<Sampled<S, B, F>>>,
    /// Verified replies to the sample in progress, at most one per validator.
    replies: BTreeMap<S::PublicKey, Checkpoint<S, B, F>>,
    /// The response this node serves, once it has a certified checkpoint.
    served: Option<Served>,
    /// Builds the response for a newer checkpoint, if one is being built.
    refresh: Option<Handle<Option<Served>>>,
}

impl<E, S, B, F, T, K> Probe<E, S, B, F, T, K>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<B::Digest>,
    B: Block,
    F: Roundable + Codec + Clone + Send + Sync + 'static,
    T: Strategy,
    K: Blocker<PublicKey = S::PublicKey>,
{
    /// Creates the probe and its [`Mailbox`].
    pub fn new(config: Config<E, S, B, F, T, K>) -> (Self, Mailbox<S, B, F>) {
        let (sender, mailbox) =
            actor_mailbox::new(config.context.child("mailbox"), config.mailbox_size);
        let codec =
            wire::Message::<S, B, F>::codec(&config.scheme, config.block_codec, config.floor_codec);
        (
            Self {
                context: ContextCell::new(config.context),
                mailbox: Some(mailbox),
                scheme: config.scheme,
                strategy: config.strategy,
                blocker: config.blocker,
                codec,
                retry_timeout: config.retry_timeout,
                max_response_size: config.max_response_size,
                subscribers: Vec::new(),
                replies: BTreeMap::new(),
                served: None,
                refresh: None,
            },
            Mailbox::new(sender),
        )
    }

    /// Starts the probe on `network`, serving the newest checkpoint of `source`, whose interval
    /// also checks the checkpoints validators reply with.
    pub fn start<R>(
        mut self,
        network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        source: R,
    ) -> Handle<()>
    where
        R: Source<Scheme = S, Block = B, Floor = F>,
    {
        spawn_cell!(self.context, self.run(network, source))
    }

    async fn run<R>(
        mut self,
        (mut sender, mut receiver): (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        source: R,
    ) where
        R: Source<Scheme = S, Block = B, Floor = F>,
    {
        let interval = source.interval();
        let mut deadline = self.context.current();
        select_loop! {
            self.context,
            on_start => {
                self.subscribers.retain(|subscriber| !subscriber.is_closed());
                let retry = if self.subscribers.is_empty() {
                    Either::Left(future::pending())
                } else {
                    Either::Right(self.context.sleep_until(deadline))
                };
            },
            on_stopped => {
                debug!("probe stopped");
            },
            message = next_message(&mut self.mailbox) => match message {
                Some(Message::Sample { response }) => {
                    let sampling = !self.subscribers.is_empty();
                    self.subscribers.push(response);
                    if !sampling {
                        // Replies to an abandoned sample may be arbitrarily old.
                        self.replies.clear();
                        self.request(&mut sender);
                        deadline = self.context.current() + self.retry_timeout.get();
                    }
                }
                // Nobody can ask for samples anymore, but peers still ask this node.
                None => self.mailbox = None,
            },
            Ok((peer, message)) = receiver.recv() else break => {
                self.receive(peer, message, &mut sender, &source, interval);
            },
            served = next_refresh(&mut self.refresh) => {
                self.refresh = None;
                if let Ok(Some(served)) = served {
                    self.served = Some(served);
                }
            },
            _ = retry => {
                debug!("too few validators replied, asking the rest again");
                self.request(&mut sender);
                deadline = self.context.current() + self.retry_timeout.get();
            },
        }
    }

    /// Asks every validator without a verified reply to the sample in progress for its newest
    /// checkpoint.
    fn request(&mut self, sender: &mut impl Sender<PublicKey = S::PublicKey>) {
        let validators = self
            .scheme
            .participants()
            .iter()
            .filter(|validator| !self.replies.contains_key(validator))
            .cloned()
            .collect();
        sender.send(
            Recipients::Some(validators),
            wire::Message::<S, B, F>::Request.encode(),
            false,
        );
    }

    /// Serves a request, or records a reply to the sample in progress.
    fn receive<R>(
        &mut self,
        peer: S::PublicKey,
        message: IoBuf,
        sender: &mut impl Sender<PublicKey = S::PublicKey>,
        source: &R,
        interval: NonZeroU64,
    ) where
        R: Source<Scheme = S, Block = B, Floor = F>,
    {
        // A reply nobody awaits, or from a non-validator, is skipped before it is decoded or
        // verified.
        let tag = wire::Tag::read(&mut Copying(message.chunk()));
        if tag.is_ok_and(|tag| tag == wire::Tag::Response) {
            if self.subscribers.is_empty() || self.replies.contains_key(&peer) {
                return;
            }
            if self.scheme.participants().position(&peer).is_none() {
                debug!(?peer, "reply from a peer that is not a validator");
                return;
            }
        }
        let message = match wire::Message::<S, B, F>::decode_cfg(message, &self.codec) {
            Ok(message) => message,
            Err(err) => {
                commonware_p2p::block!(self.blocker, peer, ?err, "invalid probe message");
                return;
            }
        };
        match message {
            wire::Message::Request => self.serve(peer, sender, source),
            wire::Message::Response(checkpoint) => match self.verify(&checkpoint, interval) {
                Ok(()) => {
                    self.replies.insert(peer, checkpoint);
                    self.select();
                }
                Err(Rejection::Invalid(reason)) => {
                    commonware_p2p::block!(self.blocker, peer, reason, "invalid checkpoint");
                }
                Err(Rejection::Unverifiable(reason)) => {
                    debug!(?peer, reason, "ignoring checkpoint");
                }
            },
        }
    }

    /// Answers `peer` with the response this node serves, if any, and builds a response for a
    /// newer checkpoint in the background. A request never waits on `source`.
    fn serve<R>(
        &mut self,
        peer: S::PublicKey,
        sender: &mut impl Sender<PublicKey = S::PublicKey>,
        source: &R,
    ) where
        R: Source<Scheme = S, Block = B, Floor = F>,
    {
        if let Some(response) = self
            .served
            .as_ref()
            .and_then(|served| served.response.clone())
        {
            sender.send(Recipients::One(peer), response, false);
        }
        let Some(latest) = source.latest() else {
            return;
        };
        if self.refresh.is_some()
            || self
                .served
                .as_ref()
                .is_some_and(|served| served.checkpoint == latest)
        {
            return;
        }
        let source = source.clone();
        let max_response_size = self.max_response_size.get();
        self.refresh = Some(self.context.child("refresh").spawn(move |_| async move {
            let checkpoint = source.newest().await?;
            let height = checkpoint.certificate.item.height;
            let response = wire::Message::Response(checkpoint).encode();
            let response = if response.len() <= max_response_size {
                Some(response)
            } else {
                warn!(
                    size = response.len(),
                    max_response_size, "checkpoint response is too large to serve"
                );
                None
            };
            Some(Served {
                checkpoint: height,
                response,
            })
        }));
    }

    /// Checks that `checkpoint`, with checkpoints taken every `interval` blocks, may count
    /// toward a sample.
    fn verify(
        &mut self,
        checkpoint: &Checkpoint<S, B, F>,
        interval: NonZeroU64,
    ) -> Result<(), Rejection> {
        let item = &checkpoint.certificate.item;
        let height = checkpoints::height(item.height, interval)
            .ok_or(Rejection::Invalid("checkpoint exceeds the height space"))?;
        if checkpoint.block.height() != height {
            return Err(Rejection::Invalid(
                "block is not at the checkpoint's height",
            ));
        }
        if checkpoint.block.digest() != item.digest {
            return Err(Rejection::Invalid("block is not the certified one"));
        }
        if !checkpoint.certificate.verify(
            self.context.as_present_mut(),
            &self.scheme,
            &self.strategy,
        ) {
            return Err(Rejection::Unverifiable("certificate does not verify"));
        }
        Ok(())
    }

    /// Answers the sample in progress once `f + 1` validators replied.
    fn select(&mut self) {
        let validators = self.scheme.participants().len();
        if self.replies.len() <= S::Faults::max_faults(validators) as usize {
            return;
        }
        let newest = self
            .replies
            .values()
            .max_by_key(|checkpoint| checkpoint.certificate.item.height)
            .expect("replies are not empty");
        let mut floors: Vec<_> = self
            .replies
            .values()
            .filter_map(|checkpoint| checkpoint.floor.clone())
            .collect();
        floors.sort_by_key(|floor| Reverse(floor.round()));
        let sampled = Sampled {
            certificate: newest.certificate.clone(),
            block: Arc::clone(&newest.block),
            floors,
        };
        self.replies.clear();
        for subscriber in self.subscribers.drain(..) {
            subscriber.send_lossy(sampled.clone());
        }
    }
}

/// Waits for the next request, or forever once every [`Mailbox`] is dropped.
async fn next_message<M: Policy>(mailbox: &mut Option<MailboxReceiver<M>>) -> Option<M> {
    match mailbox {
        Some(mailbox) => mailbox.recv().await,
        None => future::pending().await,
    }
}

/// Waits for the response being built, if any.
async fn next_refresh(
    refresh: &mut Option<Handle<Option<Served>>>,
) -> Result<Option<Served>, RuntimeError> {
    match refresh {
        Some(refresh) => refresh.await,
        None => future::pending().await,
    }
}
