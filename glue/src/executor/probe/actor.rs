//! The probe actor.

use super::{
    Checkpoint, FloorVerifier, Sampled, Source,
    mailbox::{Mailbox, Message},
    wire,
};
use crate::executor::checkpoints;
use bytes::Buf as _;
use commonware_actor::mailbox::{self as actor_mailbox, Policy, Receiver as MailboxReceiver};
use commonware_codec::{Codec, Copying, Decode as _, Encode as _, Read, ReadExt as _};
use commonware_consensus::{Block, Roundable, aggregation::scheme::Scheme};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, ContextCell, Handle, IoBuf, Metrics, Spawner, spawn_cell};
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
use tracing::debug;

/// Configuration of a [`Probe`].
pub struct Config<E, S, B, F, T, K, V>
where
    S: Scheme<B::Digest>,
    B: Block,
    F: Codec,
{
    /// The runtime context.
    pub context: E,
    /// Verifies checkpoint certificates. Its participants are the validators a sample asks.
    pub scheme: S,
    /// Verifies the consensus certificate of each floor a validator serves.
    pub floor_verifier: V,
    /// Strategy for verifying certificates.
    pub strategy: T,
    /// Blocks peers that send invalid messages.
    pub blocker: K,
    /// Blocks per checkpoint: checkpoint `k` certifies the block at height
    /// `(k + 1) * interval - 1`.
    pub interval: NonZeroU64,
    /// Codec configuration of executed blocks.
    pub block_codec: B::Cfg,
    /// Codec configuration of floors.
    pub floor_codec: F::Cfg,
    /// How long a sample waits for enough replies before requesting again.
    pub retry_timeout: NonZeroDuration,
    /// Capacity of the probe's mailbox.
    pub mailbox_size: NonZeroUsize,
}

/// Samples validators for the newest checkpoint, and serves this node's checkpoint to peers.
///
/// See the [module documentation](super).
pub struct Probe<E, S, B, F, T, P, K, V>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<B::Digest, PublicKey = P>,
    B: Block,
    F: Roundable + Codec + Clone + Send + Sync + 'static,
    T: Strategy,
    P: PublicKey,
    K: Blocker<PublicKey = P>,
    V: FloorVerifier<F>,
{
    context: ContextCell<E>,
    /// Requests for samples, until every [`Mailbox`] is dropped.
    mailbox: Option<MailboxReceiver<Message<S, B, F>>>,
    scheme: S,
    floor_verifier: V,
    strategy: T,
    blocker: K,
    interval: NonZeroU64,
    codec: <wire::Message<S, B, F> as Read>::Cfg,
    retry_timeout: NonZeroDuration,
    /// Callers awaiting the sample in progress.
    subscribers: Vec<oneshot::Sender<Sampled<S, B, F>>>,
    /// Verified replies to the sample in progress, at most one per validator.
    replies: BTreeMap<P, Checkpoint<S, B, F>>,
}

impl<E, S, B, F, T, P, K, V> Probe<E, S, B, F, T, P, K, V>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<B::Digest, PublicKey = P>,
    B: Block,
    F: Roundable + Codec + Clone + Send + Sync + 'static,
    T: Strategy,
    P: PublicKey,
    K: Blocker<PublicKey = P>,
    V: FloorVerifier<F>,
{
    /// Creates the probe and its [`Mailbox`].
    pub fn new(config: Config<E, S, B, F, T, K, V>) -> (Self, Mailbox<S, B, F>) {
        let (sender, mailbox) =
            actor_mailbox::new(config.context.child("mailbox"), config.mailbox_size);
        let codec =
            wire::Message::<S, B, F>::codec(&config.scheme, config.block_codec, config.floor_codec);
        (
            Self {
                context: ContextCell::new(config.context),
                mailbox: Some(mailbox),
                scheme: config.scheme,
                floor_verifier: config.floor_verifier,
                strategy: config.strategy,
                blocker: config.blocker,
                interval: config.interval,
                codec,
                retry_timeout: config.retry_timeout,
                subscribers: Vec::new(),
                replies: BTreeMap::new(),
            },
            Mailbox::new(sender),
        )
    }

    /// Starts the probe on `network`, serving the newest checkpoint of `source`.
    pub fn start<R>(
        mut self,
        network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        source: R,
    ) -> Handle<()>
    where
        R: Source<Scheme = S, Block = B, Floor = F>,
    {
        spawn_cell!(self.context, self.run(network, source))
    }

    async fn run<R>(
        mut self,
        (mut sender, mut receiver): (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        source: R,
    ) where
        R: Source<Scheme = S, Block = B, Floor = F>,
    {
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
                self.receive(peer, message, &mut sender, &source).await;
            },
            _ = retry => {
                debug!("too few validators replied, requesting again");
                self.request(&mut sender);
                deadline = self.context.current() + self.retry_timeout.get();
            },
        }
    }

    /// Asks every validator for its newest checkpoint. Replies the sample in progress already
    /// verified still count.
    fn request(&mut self, sender: &mut impl Sender<PublicKey = P>) {
        sender.send(
            Recipients::Some(self.scheme.participants().iter().cloned().collect()),
            wire::Message::<S, B, F>::Request.encode(),
            false,
        );
    }

    /// Serves a request, or records a reply to the sample in progress.
    async fn receive<R>(
        &mut self,
        peer: P,
        message: IoBuf,
        sender: &mut impl Sender<PublicKey = P>,
        source: &R,
    ) where
        R: Source<Scheme = S, Block = B, Floor = F>,
    {
        // A reply nobody awaits is skipped, and one from a non-validator is blocked, before it
        // is decoded or verified.
        let tag = wire::Tag::read(&mut Copying(message.chunk()));
        if tag.is_ok_and(|tag| tag == wire::Tag::Response) {
            if self.subscribers.is_empty() || self.replies.contains_key(&peer) {
                return;
            }
            if self.scheme.participants().position(&peer).is_none() {
                commonware_p2p::block!(self.blocker, peer, "sender is not a validator");
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
            wire::Message::Request => {
                if let Some(checkpoint) = source.newest().await {
                    sender.send(
                        Recipients::One(peer),
                        wire::Message::Response(checkpoint).encode(),
                        false,
                    );
                }
            }
            wire::Message::Response(checkpoint) => {
                if let Err(reason) = self.verify(&checkpoint) {
                    commonware_p2p::block!(self.blocker, peer, reason, "invalid checkpoint");
                    return;
                }
                self.replies.insert(peer, checkpoint);
                self.select();
            }
        }
    }

    /// Checks that `checkpoint` may count toward a sample.
    fn verify(&mut self, checkpoint: &Checkpoint<S, B, F>) -> Result<(), &'static str> {
        let item = &checkpoint.certificate.item;
        let height = checkpoints::height(item.height, self.interval)
            .ok_or("checkpoint exceeds the height space")?;
        if checkpoint.block.height() != height {
            return Err("block is not at the checkpoint's height");
        }
        if checkpoint.block.digest() != item.digest {
            return Err("block is not the certified one");
        }
        if !checkpoint.certificate.verify(
            self.context.as_present_mut(),
            &self.scheme,
            &self.strategy,
        ) {
            return Err("certificate does not verify");
        }
        if let Some(floor) = &checkpoint.floor
            && !self.floor_verifier.verify(floor)
        {
            return Err("floor does not verify");
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
