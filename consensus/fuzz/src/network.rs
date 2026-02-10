//! Helpers for preferential delivery of Byzantine messages in fuzz tests emulating
//! an adversarial network.
//!
//! This module provides a simple wrapper around the simulated p2p receiver split
//! functionality.
//!
//! Messages originating from a configured set of Byzantine public keys are routed to the
//! "primary" receiver; all other messages are routed to the "secondary" receiver.
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
use std::{
    collections::HashSet,
    fmt::{self, Debug},
    sync::Arc,
};

/// A split-router that routes messages by origin public key.
#[derive(Clone)]
pub struct Router<P: PublicKey> {
    byzantine: Arc<HashSet<P>>,
}

impl<P: PublicKey> Router<P> {
    pub fn new(byzantine: impl IntoIterator<Item = P>) -> Self {
        Self {
            byzantine: Arc::new(byzantine.into_iter().collect()),
        }
    }

    /// Route by message sender.
    pub fn route(&self, message: &Message<P>) -> SplitTarget {
        let (sender, _) = message;
        if self.byzantine.contains(sender) {
            SplitTarget::Primary
        } else {
            SplitTarget::Secondary
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
                    // Both closed; delegate to primary for the canonical error.
                    return self.primary.recv().await;
                }
                (false, true) => return self.primary.recv().await,
                (true, false) => return self.secondary.recv().await,
                (false, false) => {
                    // Biased select: if both have a buffered message, primary wins.
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
                            // Keep looping; if the other lane is open, it may still yield.
                            // Otherwise we will fall through to the both-closed case.
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
