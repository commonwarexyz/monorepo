use commonware_cryptography::PublicKey;
use commonware_utils::{ordered::Set, sync::RwLock};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub(crate) struct PrimaryPeers<P: PublicKey>(Arc<RwLock<Set<P>>>);

impl<P: PublicKey> Default for PrimaryPeers<P> {
    fn default() -> Self {
        Self(Arc::new(RwLock::new(Set::default())))
    }
}

impl<P: PublicKey> PrimaryPeers<P> {
    pub(crate) fn contains(&self, peer: &P) -> bool {
        self.0.read().position(peer).is_some()
    }

    pub(crate) fn replace(&self, peers: Set<P>) {
        *self.0.write() = peers;
    }
}
