//! MMB-specific storage trait re-export and implementations.

pub use crate::merkle::storage::Storage;
use crate::mmb::{mem::CleanMmb, Mmb, Position};
use commonware_cryptography::Digest;

impl<D: Digest> Storage<Mmb, D> for CleanMmb<D> {
    async fn size(&self) -> Position {
        self.size()
    }

    async fn get_node(&self, position: Position) -> Result<Option<D>, crate::merkle::Error<Mmb>> {
        Ok(Self::get_node(self, position))
    }
}
