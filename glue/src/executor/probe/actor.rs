//! The probe actor.

use super::{
    Checkpoint, Sampled, Source,
    mailbox::{Mailbox, Message},
    wire,
};
use crate::{executor::checkpoints, probe::sample::Sample};
use bytes::{Buf as _, Bytes};
use commonware_actor::mailbox::{self as actor_mailbox, Policy, Receiver as MailboxReceiver};
use commonware_codec::{Codec, Copying, Decode as _, Encode as _, Read, ReadExt as _};
use commonware_consensus::{Block, Roundable, aggregation::scheme::Scheme, types::Height};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, ContextCell, Error as RuntimeError, Handle, IoBuf, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use commonware_utils::{
    NonZeroDuration,
    channel::{fallible::OneshotExt as _, oneshot},
    futures::Pool,
};
use futures::future::{self, Either};
use rand_core::CryptoRng;
use std::{
    cmp::Reverse,
    num::{NonZeroU64, NonZeroUsize},
};
use tracing::{debug, warn};

type Verifications<P, R> = Pool<'static, (P, Option<R>)>;

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
    sample: Sample<S::PublicKey, Checkpoint<S, B, F>>,
    /// Certificate checks owned by the sample in progress. Cancellation drops their task guards.
    verifications: Verifications<S::PublicKey, Checkpoint<S, B, F>>,
    /// The response this node serves, once it has a certified checkpoint.
    served: Option<Served>,
    /// Builds the response for a newer checkpoint, if one is being built.
    refresh: Option<Handle<Option<Served>>>,

    samples_started: Counter,
    samples_completed: Counter,
    replies_recorded: Counter,
    replies_ignored: Counter,
    peers_blocked: Counter,
    requests_served: Counter,
    responses_too_large: Counter,
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
        let samples_started = config
            .context
            .counter("samples_started", "Number of samples started");
        let samples_completed = config
            .context
            .counter("samples_completed", "Number of samples completed");
        let replies_recorded = config
            .context
            .counter("replies_recorded", "Number of verified replies recorded");
        let replies_ignored = config
            .context
            .counter("replies_ignored", "Number of replies ignored");
        let peers_blocked = config
            .context
            .counter("peers_blocked", "Number of peer blocking decisions");
        let requests_served = config.context.counter(
            "requests_served",
            "Number of requests answered with a checkpoint",
        );
        let responses_too_large = config.context.counter(
            "responses_too_large",
            "Number of checkpoint responses exceeding the serving limit",
        );
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
                sample: Sample::new(),
                verifications: Pool::default(),
                served: None,
                refresh: None,
                samples_started,
                samples_completed,
                replies_recorded,
                replies_ignored,
                peers_blocked,
                requests_served,
                responses_too_large,
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
            (peer, verified) = self.verifications.next_completed() => {
                self.sample.release(&peer);
                match verified {
                    Some(checkpoint) if !self.subscribers.is_empty() => {
                        self.sample.record(peer, checkpoint);
                        self.replies_recorded.inc();
                        self.select();
                    }
                    _ => {
                        self.replies_ignored.inc();
                        debug!(?peer, "ignoring checkpoint");
                    }
                }
            },
            message = next_message(&mut self.mailbox) => match message {
                Some(Message::Sample { response }) => {
                    let sampling = self.subscribers.iter().any(|subscriber| !subscriber.is_closed());
                    self.subscribers.push(response);
                    if !sampling {
                        // Each sample owns its replies and pending certificate checks.
                        self.verifications.cancel_all();
                        self.sample.reset();
                        self.samples_started.inc();
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

    /// Asks validators whose replies are neither recorded nor under verification for their
    /// newest checkpoint.
    fn request(&mut self, sender: &mut impl Sender<PublicKey = S::PublicKey>) {
        let validators = self
            .scheme
            .participants()
            .iter()
            .filter(|validator| self.sample.awaits(validator))
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
            if self.subscribers.is_empty() || !self.sample.awaits(&peer) {
                self.replies_ignored.inc();
                return;
            }
            if self.scheme.participants().position(&peer).is_none() {
                self.replies_ignored.inc();
                debug!(?peer, "reply from a peer that is not a validator");
                return;
            }
        }
        let message = match wire::Message::<S, B, F>::decode_cfg(message, &self.codec) {
            Ok(message) => message,
            Err(err) => {
                self.peers_blocked.inc();
                commonware_p2p::block!(self.blocker, peer, ?err, "invalid probe message");
                return;
            }
        };
        match message {
            wire::Message::Request => self.serve(peer, sender, source),
            wire::Message::Response(checkpoint) => match Self::validate(&checkpoint, interval) {
                Ok(()) => {
                    self.sample.reserve(peer.clone());
                    let scheme = self.scheme.clone();
                    let strategy = self.strategy.clone();
                    let verification = self
                        .context
                        .child("verify")
                        .shared(true)
                        .spawn(move |mut context| async move {
                            checkpoint
                                .certificate
                                .verify(&mut context, &scheme, &strategy)
                                .then_some(checkpoint)
                        })
                        .abort_on_drop();
                    self.verifications
                        .push(async move { (peer, verification.join().await.ok().flatten()) });
                }
                Err(reason) => {
                    self.peers_blocked.inc();
                    commonware_p2p::block!(self.blocker, peer, reason, "invalid checkpoint");
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
            self.requests_served.inc();
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
        let responses_too_large = self.responses_too_large.clone();
        self.refresh = Some(self.context.child("refresh").spawn(move |_| async move {
            let checkpoint = source.newest().await?;
            let height = checkpoint.certificate.item.height;
            let response = wire::Message::Response(checkpoint).encode();
            let response = if response.len() <= max_response_size {
                Some(response)
            } else {
                responses_too_large.inc();
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

    /// Checks the checkpoint's height and block before scheduling certificate verification.
    fn validate(
        checkpoint: &Checkpoint<S, B, F>,
        interval: NonZeroU64,
    ) -> Result<(), &'static str> {
        let item = &checkpoint.certificate.item;
        let height = checkpoints::height(item.height, interval)
            .ok_or("checkpoint exceeds the height space")?;
        if checkpoint.block.height() != height {
            return Err("block is not at the checkpoint's height");
        }
        if checkpoint.block.digest() != item.digest {
            return Err("block is not the certified one");
        }
        Ok(())
    }

    /// Answers the sample in progress once `f + 1` validators replied.
    fn select(&mut self) {
        let validators = self.scheme.participants().len();
        let Some(newest) = self.sample.select::<S::Faults, _>(
            validators,
            |_| true,
            |checkpoint| checkpoint.certificate.item.height,
        ) else {
            return;
        };
        let mut floors: Vec<_> = self
            .sample
            .replies()
            .filter_map(|checkpoint| checkpoint.floor.clone())
            .collect();
        floors.sort_by_key(|floor| Reverse(floor.round()));
        let sampled = Sampled {
            certificate: newest.certificate,
            block: newest.block,
            floors,
        };
        self.verifications.cancel_all();
        self.sample.reset();
        self.samples_completed.inc();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::probe::tests::Validators;
    use commonware_cryptography::ed25519::PublicKey;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{NZDuration, NZUsize};
    use std::{io, time::Duration};

    /// A ready request backlog followed by a closed network receiver.
    #[derive(Debug)]
    struct Backlog {
        peer: PublicKey,
        requests: usize,
    }

    impl Receiver for Backlog {
        type PublicKey = PublicKey;
        type Error = io::Error;

        async fn recv(&mut self) -> Result<(PublicKey, IoBuf), io::Error> {
            if self.requests == 0 {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            self.requests -= 1;
            Ok((self.peer.clone(), IoBuf::from(vec![0])))
        }
    }

    #[test]
    fn completed_checks_resolve_a_sample_before_a_ready_network_backlog() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
            let validators = Validators::start(&mut context, 4).await;
            let (mut probe, _mailbox) = Probe::new(Config {
                context: context.child("backlogged"),
                scheme: validators.schemes[0].clone(),
                strategy: Sequential,
                blocker: validators
                    .oracle
                    .control(validators.participants[0].clone()),
                block_codec: (),
                floor_codec: (),
                retry_timeout: NZDuration!(Duration::from_millis(100)),
                max_response_size: NZUsize!(1024 * 1024),
                mailbox_size: NZUsize!(16),
            });
            let (response, sampled) = oneshot::channel();
            probe.subscribers.push(response);
            for (index, height) in [(1, 1), (2, 3)] {
                let peer = validators.participants[index].clone();
                probe.sample.reserve(peer.clone());
                probe.verifications.push(future::ready((
                    peer,
                    Some(validators.checkpoint(height, height * 10, None)),
                )));
            }
            probe
                .start(
                    (
                        validators.senders[0].clone(),
                        Backlog {
                            peer: validators.participants[1].clone(),
                            requests: 32,
                        },
                    ),
                    validators.sources[0].clone(),
                )
                .await
                .unwrap();
            assert_eq!(
                sampled
                    .await
                    .expect("completed checks resolve the sample")
                    .certificate
                    .item
                    .height,
                Height::new(3)
            );
        });
    }
}
