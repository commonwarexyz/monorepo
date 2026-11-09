//! A [Receiver] wrapper that drops received messages at random, for loss experiments.
//!
//! Wrapping an application channel's receiver drops complete messages after transport delivery
//! and before the application processes them, so the transport never repairs the loss. Messages
//! the network exchanges internally, such as peer discovery and connection maintenance, never
//! reach channel receivers and are unaffected.

use crate::{Message, Receiver};
use commonware_runtime::telemetry::metrics::Counter;
use commonware_utils::Probability;
use core::{fmt, num::NonZeroUsize};
use rand::Rng;

/// A [Receiver] that drops each received message independently with a fixed probability.
pub struct LossyReceiver<R: Receiver, G> {
    inner: R,
    loss: Probability,
    rng: G,
    dropped: Counter,
}

impl<R: Receiver, G> fmt::Debug for LossyReceiver<R, G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LossyReceiver")
            .field("inner", &self.inner)
            .field("loss", &self.loss)
            .field("dropped", &self.dropped)
            .finish_non_exhaustive()
    }
}

impl<R: Receiver, G: Rng + Send + 'static> LossyReceiver<R, G> {
    /// Wraps `inner`, dropping each message it delivers with probability `loss`, sampled from
    /// `rng`, and counting each drop in `dropped`.
    ///
    /// Receivers may share one `dropped` counter to report their total loss.
    pub const fn new(inner: R, loss: Probability, rng: G, dropped: Counter) -> Self {
        Self {
            inner,
            loss,
            rng,
            dropped,
        }
    }

    /// Returns how many messages the counter of this receiver has recorded as dropped.
    pub fn dropped(&self) -> u64 {
        self.dropped.get()
    }
}

impl<R: Receiver, G: Rng + Send + 'static> Receiver for LossyReceiver<R, G> {
    type Error = R::Error;
    type PublicKey = R::PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        loop {
            let message = self.inner.recv().await?;
            if !self.loss.sample(&mut self.rng) {
                return Ok(message);
            }
            self.dropped.inc();
        }
    }

    fn capacity(&self) -> NonZeroUsize {
        self.inner.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_runtime::IoBuf;
    use commonware_utils::{NZUsize, TestRng};
    use std::collections::VecDeque;

    /// A receiver yielding numbered messages from one peer, then failing once exhausted.
    #[derive(Debug)]
    struct Numbered {
        peer: ed25519::PublicKey,
        queue: VecDeque<u64>,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("exhausted")]
    struct Exhausted;

    impl Receiver for Numbered {
        type Error = Exhausted;
        type PublicKey = ed25519::PublicKey;

        async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
            let index = self.queue.pop_front().ok_or(Exhausted)?;
            Ok((self.peer.clone(), IoBuf::from(index.to_be_bytes().to_vec())))
        }

        fn capacity(&self) -> NonZeroUsize {
            NZUsize!(7)
        }
    }

    fn numbered(count: u64) -> Numbered {
        Numbered {
            peer: ed25519::PrivateKey::from_seed(0).public_key(),
            queue: (0..count).collect(),
        }
    }

    fn detached() -> Counter {
        Counter::detached(Default::default())
    }

    fn drain(receiver: &mut LossyReceiver<Numbered, TestRng>) -> u64 {
        let mut delivered = 0;
        while futures::executor::block_on(receiver.recv()).is_ok() {
            delivered += 1;
        }
        delivered
    }

    #[test]
    fn drops_about_the_configured_fraction_and_counts_them() {
        const MESSAGES: u64 = 100_000;
        let loss = Probability::new(1, 10).unwrap();
        let mut receiver =
            LossyReceiver::new(numbered(MESSAGES), loss, TestRng::new(7), detached());
        assert_eq!(receiver.capacity(), NZUsize!(7));
        let delivered = drain(&mut receiver);
        assert_eq!(delivered + receiver.dropped(), MESSAGES);
        // 10% of 100k: the binomial standard deviation is about 95.
        assert!(
            (9_500..=10_500).contains(&receiver.dropped()),
            "dropped {}",
            receiver.dropped()
        );
    }

    #[test]
    fn zero_loss_delivers_every_message_in_order() {
        let mut receiver = LossyReceiver::new(
            numbered(100),
            Probability::new(0, 1).unwrap(),
            TestRng::new(7),
            detached(),
        );
        for index in 0..100u64 {
            let (_, message) = futures::executor::block_on(receiver.recv()).unwrap();
            assert_eq!(message.as_ref(), index.to_be_bytes());
        }
        assert_eq!(receiver.dropped(), 0);
    }
}
