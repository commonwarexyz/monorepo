use super::actors::Messenger;
use crate::authenticated::channels as shared;

pub use shared::Error;

pub type Sender<P, C> = shared::Sender<Messenger<P>, C>;
pub type Receiver<P> = shared::Receiver<P>;
pub type Channels<P> = shared::Channels<Messenger<P>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authenticated::{discovery::actors::router, primary::PrimaryPeers, Mailbox},
        Receiver as _,
    };
    use commonware_cryptography::{ed25519, Signer as _};
    use commonware_runtime::{deterministic, BufferPooler, IoBuf, Quota, Runner};
    use commonware_utils::{ordered::Set, NZU32};

    #[test]
    fn test_receiver_prioritizes_live_primary_peers() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (router_mailbox, _router_receiver) = Mailbox::<router::Message<_>>::new(10);
            let messenger =
                router::Messenger::new(context.network_buffer_pool().clone(), router_mailbox);
            let primary_peers = PrimaryPeers::default();
            let mut channels =
                shared::Channels::with_primary_peers(messenger, 1024, primary_peers.clone());
            let (_sender, mut receiver) = channels.register(
                0,
                Quota::per_second(NZU32!(100)),
                2,
                context.clone(),
            );
            let (_, sender) = channels.collect().remove(&0).unwrap();
            let secondary_peer = ed25519::PrivateKey::from_seed(1).public_key();
            let primary_peer = ed25519::PrivateKey::from_seed(2).public_key();

            sender
                .try_send((secondary_peer, IoBuf::from(b"secondary")))
                .unwrap();
            primary_peers.replace(Set::try_from([primary_peer.clone()]).unwrap());
            sender
                .try_send((primary_peer, IoBuf::from(b"primary")))
                .unwrap();

            let (_, first) = receiver.recv().await.unwrap();
            assert_eq!(first.as_ref(), b"primary");
            let (_, second) = receiver.recv().await.unwrap();
            assert_eq!(second.as_ref(), b"secondary");
        });
    }

    #[test]
    fn test_receiver_preserves_fifo_when_peer_priority_changes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (router_mailbox, _router_receiver) = Mailbox::<router::Message<_>>::new(10);
            let messenger =
                router::Messenger::new(context.network_buffer_pool().clone(), router_mailbox);
            let primary_peers = PrimaryPeers::default();
            let mut channels =
                shared::Channels::with_primary_peers(messenger, 1024, primary_peers.clone());
            let (_sender, mut receiver) = channels.register(
                0,
                Quota::per_second(NZU32!(100)),
                2,
                context.clone(),
            );
            let (_, sender) = channels.collect().remove(&0).unwrap();
            let peer = ed25519::PrivateKey::from_seed(3).public_key();

            sender
                .try_send((peer.clone(), IoBuf::from(b"first")))
                .unwrap();
            primary_peers.replace(Set::try_from([peer.clone()]).unwrap());
            sender.try_send((peer, IoBuf::from(b"second"))).unwrap();

            let (_, first) = receiver.recv().await.unwrap();
            assert_eq!(first.as_ref(), b"first");
            let (_, second) = receiver.recv().await.unwrap();
            assert_eq!(second.as_ref(), b"second");
        });
    }
}
