use commonware_cryptography::PublicKey;
use commonware_utils::{ordered::Set, sync::RwLock};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

#[derive(Debug)]
struct Inner<P: PublicKey> {
    generation: AtomicU64,
    peers: RwLock<Set<P>>,
}

#[derive(Clone, Debug)]
pub(crate) struct PrimaryPeers<P: PublicKey>(Arc<Inner<P>>);

impl<P: PublicKey> Default for PrimaryPeers<P> {
    fn default() -> Self {
        Self(Arc::new(Inner {
            generation: AtomicU64::new(0),
            peers: RwLock::new(Set::default()),
        }))
    }
}

impl<P: PublicKey> PrimaryPeers<P> {
    pub(crate) fn contains(&self, peer: &P) -> bool {
        self.0.peers.read().position(peer).is_some()
    }

    pub(crate) fn generation(&self) -> u64 {
        self.0.generation.load(Ordering::Acquire)
    }

    pub(crate) fn replace(&self, peers: Set<P>) {
        *self.0.peers.write() = peers;
        self.0.generation.fetch_add(1, Ordering::Release);
    }
}
