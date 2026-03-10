//! MMR-specific storage trait re-export and implementations.

pub use crate::merkle::storage::Storage;
use crate::mmr::{mem::CleanMmr, Mmr, Position};
use commonware_cryptography::Digest;

impl<D: Digest> Storage<Mmr, D> for CleanMmr<D> {
    async fn size(&self) -> Position {
        self.size()
    }

    async fn get_node(&self, position: Position) -> Result<Option<D>, crate::merkle::Error<Mmr>> {
        Ok(Self::get_node(self, position))
    }
}
