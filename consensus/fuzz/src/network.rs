//! Helpers for preferential delivery of Byzantine messages in fuzz tests emulating
//! an adversarial network.
//!
//! This module provides a simple wrapper around the simulated p2p receiver split
//! functionality.
//!
//! Messages originating from a configured set of Byzantine public keys are routed to the
//! "primary" receiver; all other messages are routed to the "secondary" receiver and may be dropped.
//! A [`ByzantineFirstReceiver`] then uses a biased select to always service the primary
//! receiver first when both have buffered messages.
//!
//! Note: this is not a global total-order guarantee (the underlying network can still deliver
//! honest messages before Byzantine messages arrive). It does guarantee that, whenever both a
//! Byzantine message and an honest message are simultaneously available to be received, the
//! Byzantine message is delivered first.

use commonware_cryptography::PublicKey;
use commonware_macros::select;
use commonware_p2p::{simulated::SplitTarget, Message, Receiver};
use commonware_utils::sync::Mutex;
use rand::Rng;
use rand_core::CryptoRngCore;
use std::{
    collections::HashSet,
    fmt::{self, Debug},
    sync::Arc,
};

/// A filtering split-router that routes messages by origin public key.
pub struct Router<P: PublicKey, E: CryptoRngCore + Send + 'static> {
    byzantine: Arc<HashSet<P>>,
    honest_messages_drop_ratio: u8,
    context: Arc<Mutex<E>>,
}

impl<P: PublicKey, E: CryptoRngCore + Send + 'static> Router<P, E> {
    pub fn new(
        context: E,
        byzantine: impl IntoIterator<Item = P>,
        honest_messages_drop_ratio: u8,
    ) -> Self {
        Self {
            byzantine: Arc::new(byzantine.into_iter().collect()),
            honest_messages_drop_ratio: honest_messages_drop_ratio.min(90),
            context: Arc::new(Mutex::new(context)),
        }
    }

    /// Route by message sender.
    pub fn route(&self, message: &Message<P>) -> SplitTarget {
        let (sender, _) = message;
        if self.byzantine.contains(sender) {
            SplitTarget::Primary
        } else {
            if self.honest_messages_drop_ratio > 0 && self.should_drop_honest_message() {
                return SplitTarget::None;
            }
            SplitTarget::Secondary
        }
    }

    fn should_drop_honest_message(&self) -> bool {
        let mut context = self.context.lock();
        let sample = context.gen::<u8>() % 100;
        sample < self.honest_messages_drop_ratio
    }
}

impl<P: PublicKey, E: CryptoRngCore + Send + 'static> Clone for Router<P, E> {
    fn clone(&self) -> Self {
        Self {
            byzantine: self.byzantine.clone(),
            honest_messages_drop_ratio: self.honest_messages_drop_ratio,
            context: self.context.clone(),
        }
    }
}

/// A receiver that preferentially yields messages from the "primary" (Byzantine) lane.
pub struct ByzantineFirstReceiver<P, R>
where
    P: PublicKey,
    R: Receiver<PublicKey = P>,
{
    primary: R,
    secondary: R,
    primary_closed: bool,
    secondary_closed: bool,
}

impl<P, R> Debug for ByzantineFirstReceiver<P, R>
where
    P: PublicKey,
    R: Receiver<PublicKey = P> + Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ByzantineFirstReceiver")
            .field("primary_closed", &self.primary_closed)
            .field("secondary_closed", &self.secondary_closed)
            .finish_non_exhaustive()
    }
}

impl<P, R> ByzantineFirstReceiver<P, R>
where
    P: PublicKey,
    R: Receiver<PublicKey = P>,
{
    pub const fn new(primary: R, secondary: R) -> Self {
        Self {
            primary,
            secondary,
            primary_closed: false,
            secondary_closed: false,
        }
    }
}

impl<P, R> Receiver for ByzantineFirstReceiver<P, R>
where
    P: PublicKey,
    R: Receiver<PublicKey = P>,
    R::Error: Send + Sync,
{
    type Error = R::Error;
    type PublicKey = P;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        loop {
            match (self.primary_closed, self.secondary_closed) {
                (true, true) => {
                    return self.primary.recv().await;
                }
                (false, true) => return self.primary.recv().await,
                (true, false) => return self.secondary.recv().await,
                (false, false) => {
                    let result = select! {
                        msg = self.primary.recv() => (true, msg),
                        msg = self.secondary.recv() => (false, msg),
                    };

                    let (was_primary, msg) = result;
                    match msg {
                        Ok(m) => return Ok(m),
                        Err(e) => {
                            if was_primary {
                                self.primary_closed = true;
                            } else {
                                self.secondary_closed = true;
                            }
                            if self.primary_closed && self.secondary_closed {
                                return Err(e);
                            }
                        }
                    }
                }
            }
        }
    }
}
