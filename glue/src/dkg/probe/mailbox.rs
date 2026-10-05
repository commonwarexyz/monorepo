use super::ActorArtifact;
use crate::dkg::ReshareBlock;
use commonware_actor::mailbox::{Policy, Sender};
use commonware_consensus::{
    marshal::core::{Mailbox as MarshalMailbox, Variant},
    simplex::scheme::Scheme,
    types::Epoch,
};
use commonware_cryptography::Signer;
use commonware_utils::channel::oneshot;
use std::collections::VecDeque;

/// Messages sent to the DKG probe actor.
pub(crate) enum Message<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
{
    /// Subscribe to the probe artifact (see [`Mailbox::subscribe`]).
    Subscribe {
        /// Channel used to resolve the subscriber.
        response: oneshot::Sender<ActorArtifact<S, V>>,
    },
    /// Attach marshal to serve boundary requests (see [`Mailbox::attach`]).
    Attach {
        /// Marshal mailbox used to serve boundary requests.
        marshal: MarshalMailbox<S, V>,
    },
    /// Discover the finalization of the active epoch's final block (see
    /// [`Mailbox::catch_up`]).
    CatchUp {
        /// Locally active epoch, whose final block's finalization is wanted.
        epoch: Epoch,
        /// Peer asked first, which has advanced past `epoch`.
        peer: S::PublicKey,
    },
}

impl<S, V> Policy for Message<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // The orchestrator's active epoch only increases, so overflow retains
        // one catch-up, for the highest epoch requested.
        if let Self::CatchUp { epoch, .. } = &message
            && let Some(retained) = overflow
                .iter_mut()
                .find(|retained| matches!(retained, Self::CatchUp { .. }))
        {
            if matches!(retained, Self::CatchUp { epoch: current, .. } if *current < *epoch) {
                *retained = message;
            }
            return;
        }
        overflow.push_back(message);
    }
}

/// Mailbox for a running DKG probe actor.
#[derive(Clone)]
pub struct Mailbox<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
{
    sender: Sender<Message<S, V>>,
}

impl<S, V> Mailbox<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
{
    pub(crate) const fn new(sender: Sender<Message<S, V>>) -> Self {
        Self { sender }
    }

    /// Subscribes to the probe artifact.
    ///
    /// The first live subscriber starts discovery. Dropping the returned
    /// receiver cancels the subscription. If discovery has already resolved, the
    /// receiver gets the cached artifact immediately. If the actor has stopped,
    /// or is serving without an artifact, the receiver closes without a value.
    pub fn subscribe(&self) -> oneshot::Receiver<ActorArtifact<S, V>> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Subscribe { response });
        receiver
    }

    /// Attaches marshal so the actor can serve peers' requests.
    ///
    /// If subscribers are pending, the actor starts serving once they are
    /// resolved or dropped. A source node can attach marshal without ever
    /// subscribing, so it starts serving without running discovery.
    pub fn attach(&self, marshal: MarshalMailbox<S, V>) {
        let _ = self.sender.enqueue(Message::Attach { marshal });
    }

    /// Discovers the finalization of `epoch`'s final block, asking `peer` first.
    ///
    /// The probe retries with every peer until marshal stores or has processed
    /// the boundary. Verified certificates enter marshal's normal
    /// commitment-based body acquisition.
    pub(crate) fn catch_up(&self, epoch: Epoch, peer: S::PublicKey) {
        let _ = self.sender.enqueue(Message::CatchUp { epoch, peer });
    }
}

#[cfg(test)]
mod tests {
    use super::{Mailbox, Message};
    use crate::dkg::tests::mocks;
    use commonware_actor::mailbox;
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::Signer as _;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;

    #[test]
    fn overflow_retains_only_the_highest_catch_up() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = mailbox::new(context.child("probe"), NZUsize!(1));
            let mailbox = Mailbox::<mocks::TestScheme, mocks::TestMarshalVariant>::new(sender);
            let peer = mocks::TestSigner::from_seed(0).public_key();

            // The first request fills the ready queue. Repeated, later, and
            // earlier requests then collapse into one retained request for the
            // highest epoch, while subscribers keep their own entries.
            for epoch in 0..100 {
                for _ in 0..10 {
                    mailbox.catch_up(Epoch::new(epoch), peer.clone());
                }
            }
            let _first = mailbox.subscribe();
            mailbox.catch_up(Epoch::new(5), peer);
            let _second = mailbox.subscribe();

            let mut epochs = Vec::new();
            let mut subscribers = 0;
            while let Ok(message) = receiver.try_recv() {
                match message {
                    Message::CatchUp { epoch, .. } => epochs.push(epoch),
                    Message::Subscribe { .. } => subscribers += 1,
                    Message::Attach { .. } => panic!("unexpected attach"),
                }
            }
            assert_eq!(epochs, [Epoch::zero(), Epoch::new(99)]);
            assert_eq!(subscribers, 2);
        });
    }
}
