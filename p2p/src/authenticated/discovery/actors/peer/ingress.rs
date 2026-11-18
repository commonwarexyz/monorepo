use crate::authenticated::discovery::types;
use commonware_actor::mailbox::{self, UnreliablePolicy};
use commonware_cryptography::PublicKey;
use commonware_runtime::Metrics;
use commonware_utils::{NZUsize, channel::ring};
use std::{collections::VecDeque, fmt, num::NonZeroUsize};

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message<C: PublicKey> {
    /// Send a bit vector to the peer.
    BitVec(types::BitVec),

    /// Send a list of [types::Info] to the peer.
    Peers(Vec<types::Info<C>>),
}

impl<C: PublicKey> UnreliablePolicy for Message<C> {
    type Overflow = VecDeque<Self>;

    fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
        false
    }
}

/// Handle to the connection of a peer [super::Actor].
///
/// The connection ends once any clone calls [Mailbox::kill] or every clone is dropped.
/// [Mailbox::bit_vec] and [Mailbox::peers] drop their message while the gossip queue is full.
pub struct Mailbox<C: PublicKey> {
    gossip: mailbox::UnreliableSender<Message<C>>,
    kill: ring::Sender<()>,
}

impl<C: PublicKey> Mailbox<C> {
    pub fn new(
        metrics: impl Metrics,
        size: NonZeroUsize,
    ) -> (
        Self,
        mailbox::UnreliableReceiver<Message<C>>,
        ring::Receiver<()>,
    ) {
        let (gossip, gossip_receiver) = mailbox::new_unreliable(metrics, size);
        let (kill, kill_receiver) = ring::channel(NZUsize!(1));
        (Self { gossip, kill }, gossip_receiver, kill_receiver)
    }

    pub fn bit_vec(&self, bit_vec: types::BitVec) {
        let _ = self.gossip.enqueue(Message::BitVec(bit_vec));
    }

    pub fn peers(&self, peers: Vec<types::Info<C>>) {
        let _ = self.gossip.enqueue(Message::Peers(peers));
    }

    /// Signals the peer task to end the connection.
    pub fn kill(&self) {
        let _ = self.kill.send_lossy(());
    }
}

impl<C: PublicKey> Clone for Mailbox<C> {
    fn clone(&self) -> Self {
        Self {
            gossip: self.gossip.clone(),
            kill: self.kill.clone(),
        }
    }
}

impl<C: PublicKey> fmt::Debug for Mailbox<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Mailbox").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::ed25519;
    use commonware_utils::bitmap::BitMap;

    /// A full gossip queue drops a new message and keeps the queued one.
    #[test]
    fn gossip_dropped_on_overflow() {
        let (mailbox, mut gossip, _kill) =
            Mailbox::<ed25519::PublicKey>::new(crate::utils::mocks::Metrics, NZUsize!(1));
        mailbox.peers(Vec::new());
        mailbox.bit_vec(types::BitVec {
            index: 0,
            bits: BitMap::zeroes(0),
        });

        assert!(matches!(gossip.try_recv(), Ok(Message::Peers(_))));
        assert!(gossip.try_recv().is_err());
    }
}
