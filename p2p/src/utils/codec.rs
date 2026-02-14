//! Codec wrapper for [Sender] and [Receiver].

use crate::{Blocker, CheckedSender, Receiver, Recipients, Sender};
use commonware_codec::{Codec, Error};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_parallel::Strategy;
use commonware_runtime::{iobuf::EncodeExt, spawn_cell, BufferPool, ContextCell, Handle, Spawner};
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc},
    futures::Pool,
};
use std::time::SystemTime;
use tracing::warn;

/// Wrap a [Sender] and [Receiver] with some [Codec].
pub const fn wrap<S: Sender, R: Receiver, V: Codec>(
    config: V::Cfg,
    pool: BufferPool,
    sender: S,
    receiver: R,
) -> (WrappedSender<S, V>, WrappedReceiver<R, V>) {
    (
        WrappedSender::new(pool, sender),
        WrappedReceiver::new(config, receiver),
    )
}

/// Tuple representing a message received from a given public key.
pub type WrappedMessage<P, V> = (P, Result<V, Error>);

/// Wrapper around a [Sender] that encodes messages using a [Codec].
#[derive(Clone)]
pub struct WrappedSender<S: Sender, V: Codec> {
    pool: BufferPool,
    sender: S,
    _phantom_v: std::marker::PhantomData<V>,
}

impl<S: Sender, V: Codec> WrappedSender<S, V> {
    /// Create a new [WrappedSender] with the given [Sender] and [BufferPool] for encoding.
    pub const fn new(pool: BufferPool, sender: S) -> Self {
        Self {
            pool,
            sender,
            _phantom_v: std::marker::PhantomData,
        }
    }

    /// Send a message to a set of recipients.
    pub async fn send(
        &mut self,
        recipients: Recipients<S::PublicKey>,
        message: V,
        priority: bool,
    ) -> Result<Vec<S::PublicKey>, <S::Checked<'_> as CheckedSender>::Error> {
        let encoded = message.encode_with_pool(&self.pool);
        self.sender.send(recipients, encoded, priority).await
    }

    /// Check if a message can be sent to a set of recipients, returning a [CheckedWrappedSender]
    /// or the time at which the send can be retried.
    pub async fn check(
        &mut self,
        recipients: Recipients<S::PublicKey>,
    ) -> Result<CheckedWrappedSender<'_, S, V>, SystemTime> {
        self.sender
            .check(recipients)
            .await
            .map(|checked| CheckedWrappedSender {
                pool: &self.pool,
                sender: checked,
                _phantom_v: std::marker::PhantomData,
            })
    }
}

/// Checked sender that wraps a [`crate::LimitedSender::Checked`] and encodes messages using a [Codec].
#[derive(Debug)]
pub struct CheckedWrappedSender<'a, S: Sender, V: Codec> {
    pool: &'a BufferPool,
    sender: S::Checked<'a>,
    _phantom_v: std::marker::PhantomData<V>,
}

impl<'a, S: Sender, V: Codec> CheckedWrappedSender<'a, S, V> {
    pub async fn send(
        self,
        message: V,
        priority: bool,
    ) -> Result<Vec<S::PublicKey>, <S::Checked<'a> as CheckedSender>::Error> {
        let encoded = message.encode_with_pool(self.pool);
        self.sender.send(encoded, priority).await
    }
}

/// Wrapper around a [Receiver] that decodes messages using a [Codec].
pub struct WrappedReceiver<R: Receiver, V: Codec> {
    config: V::Cfg,
    receiver: R,
}

impl<R: Receiver, V: Codec> WrappedReceiver<R, V> {
    /// Create a new [WrappedReceiver] with the given [Receiver].
    pub const fn new(config: V::Cfg, receiver: R) -> Self {
        Self { config, receiver }
    }

    /// Receive a message from an arbitrary recipient.
    pub async fn recv(&mut self) -> Result<WrappedMessage<R::PublicKey, V>, R::Error> {
        let (pk, bytes) = self.receiver.recv().await?;
        let decoded = match V::decode_cfg(bytes.as_ref(), &self.config) {
            Ok(decoded) => decoded,
            Err(e) => {
                return Ok((pk, Err(e)));
            }
        };
        Ok((pk, Ok(decoded)))
    }
}

/// A background receiver that receives raw bytes from a [`Receiver`] and spawns concurrent
/// decode tasks using a [`Codec`].
///
/// This pipelines network I/O (receiving bytes) with CPU work (decoding messages) by spawning
/// a separate task for each decode operation, rather than decoding sequentially on the receive
/// loop. This is particularly useful when decoding large messages that would otherwise create
/// backpressure on the event loop, such as signature verification, decryption, or intensive
/// validity checks.
///
/// Concurrency is bounded by the provided [`Strategy`]'s
/// [`parallelism_hint`](Strategy::parallelism_hint): when the number of in-flight decode
/// tasks reaches this limit, the receiver stops accepting new messages until an in-flight
/// task completes, providing natural backpressure.
pub struct WrappedBackgroundReceiver<E, P, B, R, V>
where
    E: Spawner,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
    R: Receiver<PublicKey = P>,
    V: Codec + Send,
{
    context: ContextCell<E>,
    receiver: R,
    codec_config: V::Cfg,
    blocker: B,
    sender: mpsc::Sender<(P, V)>,
    max_concurrency: usize,
}

impl<E, P, B, R, V> WrappedBackgroundReceiver<E, P, B, R, V>
where
    E: Spawner,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
    R: Receiver<PublicKey = P>,
    V: Codec + Send + 'static,
{
    /// Create a new [`WrappedBackgroundReceiver`].
    ///
    /// `channel_capacity` controls the size of the internal channel to the consumer.
    /// The `strategy`'s [`parallelism_hint`](Strategy::parallelism_hint) bounds the
    /// number of in-flight decode tasks.
    pub fn new(
        context: E,
        receiver: R,
        codec_config: V::Cfg,
        blocker: B,
        channel_capacity: usize,
        strategy: &impl Strategy,
    ) -> (Self, mpsc::Receiver<(P, V)>) {
        let (tx, rx) = mpsc::channel(channel_capacity);
        (
            Self {
                context: ContextCell::new(context),
                receiver,
                codec_config,
                blocker,
                sender: tx,
                max_concurrency: strategy.parallelism_hint().max(1),
            },
            rx,
        )
    }

    /// Start the background receiver.
    ///
    /// Returns a [`Handle`] that must be kept alive for the background receiver to continue
    /// running. Dropping the handle will abort the background receiver.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    /// Run the background receiver's event loop.
    ///
    /// Each incoming message is decoded in a separate spawned task, allowing
    /// the receive loop to continue draining the network buffer while decodes
    /// proceed concurrently. The number of concurrent decode tasks is bounded
    /// by the strategy's parallelism hint provided at construction.
    async fn run(mut self) {
        let mut decode_pool = Pool::default();

        select_loop! {
            self.context,
            on_start => {
                while decode_pool.len() >= self.max_concurrency {
                    let Ok(result) = decode_pool.next_completed().await else {
                        break;
                    };
                    self.handle_decode_result(result).await;
                }
            },
            on_stopped => {},
            Ok(result) = decode_pool.next_completed() else break => {
                self.handle_decode_result(result).await;
            },
            Ok((peer, bytes)) = self.receiver.recv() else break => {
                let config = self.codec_config.clone();
                let sender = self.sender.clone();
                let handle = self.context.clone().shared(true).spawn(|_| async move {
                    let result = V::decode_cfg(bytes.as_ref(), &config);
                    (peer, result, sender)
                });
                decode_pool.push(handle);
            }
        }
    }

    async fn handle_decode_result(
        &mut self,
        result: (P, Result<V, commonware_codec::Error>, mpsc::Sender<(P, V)>),
    ) {
        let (peer, decode_result, mut sender) = result;
        match decode_result {
            Ok(value) => {
                sender.send_lossy((peer, value)).await;
            }
            Err(err) => {
                warn!(?peer, ?err, "received invalid message, blocking peer");
                self.blocker.block(peer).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simulated::{self, Link, Network, Oracle},
        Recipients,
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer,
    };
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, IoBuf, Metrics, Quota, Runner};
    use std::{num::NonZeroU32, time::Duration};

    const LINK: Link = Link {
        latency: Duration::from_millis(0),
        jitter: Duration::from_millis(0),
        success_rate: 1.0,
    };

    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    fn start_network(context: deterministic::Context) -> Oracle<PublicKey, deterministic::Context> {
        let (network, oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: None,
            },
        );
        network.start();
        oracle
    }

    fn pk(seed: u64) -> PublicKey {
        PrivateKey::from_seed(seed).public_key()
    }

    async fn link_bidirectional(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        a: PublicKey,
        b: PublicKey,
    ) {
        oracle.add_link(a.clone(), b.clone(), LINK).await.unwrap();
        oracle.add_link(b, a, LINK).await.unwrap();
    }

    #[test_traced]
    fn test_valid_messages_forwarded() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let pk1 = pk(0);
            let pk2 = pk(1);
            let control1 = oracle.control(pk1.clone());
            let control2 = oracle.control(pk2.clone());
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            let (mut sender1, _) = control1.register(0, TEST_QUOTA).await.unwrap();
            let (_, receiver2) = control2.register(0, TEST_QUOTA).await.unwrap();

            let (bg, mut rx) = WrappedBackgroundReceiver::<_, _, _, _, u32>::new(
                context.with_label("bg"),
                receiver2,
                (),
                control2.clone(),
                16,
                &Sequential,
            );
            let _handle = bg.start();

            let msg: u32 = 42;
            let _ = sender1
                .send(Recipients::One(pk2.clone()), msg.encode(), true)
                .await;

            let (from, value) = rx.recv().await.unwrap();
            assert_eq!(from, pk1);
            assert_eq!(value, 42u32);
        });
    }

    #[test_traced]
    fn test_invalid_codec_blocks_peer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let pk1 = pk(0);
            let pk2 = pk(1);
            let control1 = oracle.control(pk1.clone());
            let control2 = oracle.control(pk2.clone());
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            let (mut sender1, _) = control1.register(0, TEST_QUOTA).await.unwrap();
            let (_, receiver2) = control2.register(0, TEST_QUOTA).await.unwrap();

            let (bg, mut rx) = WrappedBackgroundReceiver::<_, _, _, _, u32>::new(
                context.with_label("bg"),
                receiver2,
                (),
                control2.clone(),
                16,
                &Sequential,
            );
            let _handle = bg.start();

            // Send a truncated payload (1 byte, but u32 needs 4).
            let invalid = IoBuf::from(vec![0xFFu8]);
            let _ = sender1
                .send(Recipients::One(pk2.clone()), invalid, true)
                .await;

            // Then send a valid message from a different peer to confirm
            // the receiver is still running.
            let pk3 = pk(2);
            let control3 = oracle.control(pk3.clone());
            link_bidirectional(&mut oracle, pk3.clone(), pk2.clone()).await;
            let (mut sender3, _) = control3.register(0, TEST_QUOTA).await.unwrap();

            let msg: u32 = 99;
            let _ = sender3
                .send(Recipients::One(pk2.clone()), msg.encode(), true)
                .await;

            let (from, value) = rx.recv().await.unwrap();
            assert_eq!(from, pk3);
            assert_eq!(value, 99u32);

            // Verify pk1 was blocked.
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.contains(&(pk2.clone(), pk1.clone())),
                "expected pk1 to be blocked by pk2, blocked list: {:?}",
                blocked
            );
        });
    }

    #[test_traced]
    fn test_multiple_valid_messages() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let pk1 = pk(0);
            let pk2 = pk(1);
            let control1 = oracle.control(pk1.clone());
            let control2 = oracle.control(pk2.clone());
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            let (mut sender1, _) = control1.register(0, TEST_QUOTA).await.unwrap();
            let (_, receiver2) = control2.register(0, TEST_QUOTA).await.unwrap();

            let (bg, mut rx) = WrappedBackgroundReceiver::<_, _, _, _, u32>::new(
                context.with_label("bg"),
                receiver2,
                (),
                control2.clone(),
                16,
                &Sequential,
            );
            let _handle = bg.start();

            let count = 20;
            for i in 0..count {
                let msg: u32 = i;
                let _ = sender1
                    .send(Recipients::One(pk2.clone()), msg.encode(), true)
                    .await;
            }

            let mut received = Vec::new();
            for _ in 0..count {
                let (from, value) = rx.recv().await.unwrap();
                assert_eq!(from, pk1);
                received.push(value);
            }
            received.sort();
            assert_eq!(received, (0..count).collect::<Vec<u32>>());
        });
    }

    #[test_traced]
    fn test_concurrency_bounded_by_strategy() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let pk1 = pk(0);
            let pk2 = pk(1);
            let control1 = oracle.control(pk1.clone());
            let control2 = oracle.control(pk2.clone());
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            let (mut sender1, _) = control1.register(0, TEST_QUOTA).await.unwrap();
            let (_, receiver2) = control2.register(0, TEST_QUOTA).await.unwrap();

            // Sequential has parallelism_hint() == 1, so at most 1 concurrent
            // decode task. Send many messages and verify all are delivered (the
            // backpressure mechanism drains tasks before accepting new ones).
            let (bg, mut rx) = WrappedBackgroundReceiver::<_, _, _, _, u32>::new(
                context.with_label("bg"),
                receiver2,
                (),
                control2.clone(),
                16,
                &Sequential,
            );
            let _handle = bg.start();

            let count = 50u32;
            for i in 0..count {
                let _ = sender1
                    .send(Recipients::One(pk2.clone()), i.encode(), true)
                    .await;
            }

            let mut received = Vec::new();
            for _ in 0..count {
                let (from, value) = rx.recv().await.unwrap();
                assert_eq!(from, pk1);
                received.push(value);
            }
            received.sort();
            assert_eq!(received, (0..count).collect::<Vec<u32>>());
        });
    }

    #[test_traced]
    fn test_invalid_among_valid_only_blocks_offender() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let pk1 = pk(0);
            let pk2 = pk(1);
            let pk3 = pk(2);
            let control1 = oracle.control(pk1.clone());
            let control2 = oracle.control(pk2.clone());
            let control3 = oracle.control(pk3.clone());
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;
            link_bidirectional(&mut oracle, pk3.clone(), pk2.clone()).await;

            let (mut sender1, _) = control1.register(0, TEST_QUOTA).await.unwrap();
            let (_, receiver2) = control2.register(0, TEST_QUOTA).await.unwrap();
            let (mut sender3, _) = control3.register(0, TEST_QUOTA).await.unwrap();

            let (bg, mut rx) = WrappedBackgroundReceiver::<_, _, _, _, u32>::new(
                context.with_label("bg"),
                receiver2,
                (),
                control2.clone(),
                16,
                &Sequential,
            );
            let _handle = bg.start();

            // pk3 sends valid message.
            let _ = sender3
                .send(Recipients::One(pk2.clone()), 10u32.encode(), true)
                .await;

            // pk1 sends invalid message.
            let _ = sender1
                .send(Recipients::One(pk2.clone()), IoBuf::from(vec![0xFF]), true)
                .await;

            // pk3 sends another valid message.
            let _ = sender3
                .send(Recipients::One(pk2.clone()), 20u32.encode(), true)
                .await;

            // Collect the two valid messages.
            let mut values = Vec::new();
            for _ in 0..2 {
                let (from, value) = rx.recv().await.unwrap();
                assert_eq!(from, pk3);
                values.push(value);
            }
            values.sort();
            assert_eq!(values, vec![10u32, 20]);

            // Only pk1 should be blocked.
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.contains(&(pk2.clone(), pk1.clone())));
            assert!(!blocked.contains(&(pk2.clone(), pk3.clone())));
        });
    }
}
