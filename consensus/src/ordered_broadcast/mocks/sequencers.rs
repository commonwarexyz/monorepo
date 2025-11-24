use crate::{ordered_broadcast::types::SequencersProvider, types::Epoch};
use commonware_cryptography::PublicKey;
use commonware_utils::set::Ordered;
use std::sync::Arc;

#[derive(Clone)]
pub struct Sequencers<P: PublicKey> {
    sequencers: Arc<Ordered<P>>,
}

impl<P: PublicKey> Sequencers<P> {
    pub fn new(participants: Vec<P>) -> Self {
        Self {
            sequencers: Arc::new(Ordered::from_iter(participants)),
        }
    }
}

impl<P: PublicKey> SequencersProvider for Sequencers<P> {
    type PublicKey = P;

    fn sequencers(&self, _: Epoch) -> Option<Arc<Ordered<Self::PublicKey>>> {
        Some(self.sequencers.clone())
    }
}
