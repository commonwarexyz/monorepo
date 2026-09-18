//! Async read-only trait for merkleized data structures.

use crate::merkle::{Error, Family, Position, mem::Mem};
use commonware_cryptography::Digest;
use core::future::Future;

/// An async trait for accessing Merkle node digests from storage.
pub trait Storage<F: Family>: Send + Sync {
    /// The digest type used by this storage.
    type Digest: Digest;

    /// Return the number of nodes in the structure.
    fn size(&self) -> Position<F>;

    /// Return the specified node of the structure if it exists and hasn't been pruned.
    fn get_node(
        &self,
        position: Position<F>,
    ) -> impl Future<Output = Result<Option<Self::Digest>, Error<F>>> + Send;

    /// Return the specified nodes of the structure. `positions` must be strictly increasing.
    ///
    /// Slot `i` of the result holds the node at `positions[i]`. Unlike [`Storage::get_node`],
    /// an unavailable node is an error rather than an absent value: this serves callers that
    /// require every requested node. The default reads each node individually; implementations
    /// backed by a batched read path should override it so cache hits are served in bulk and
    /// misses are fetched concurrently rather than faulted one at a time.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ElementPruned`] for the first of `positions` where [`Storage::get_node`]
    /// would yield `None`.
    fn get_nodes(
        &self,
        positions: &[Position<F>],
    ) -> impl Future<Output = Result<Vec<Self::Digest>, Error<F>>> + Send {
        async move {
            assert!(
                positions.is_sorted_by(|a, b| a < b),
                "positions must be strictly increasing"
            );
            let mut nodes = Vec::with_capacity(positions.len());
            for &position in positions {
                let node = self
                    .get_node(position)
                    .await?
                    .ok_or(Error::ElementPruned(position))?;
                nodes.push(node);
            }
            Ok(nodes)
        }
    }
}

impl<F, D> Storage<F> for Mem<F, D>
where
    F: Family,
    D: Digest,
{
    type Digest = D;

    fn size(&self) -> Position<F> {
        self.size()
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<D>, Error<F>> {
        Ok(Self::get_node(self, position))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{Bagging::ForwardFold, Location, hasher::Standard, mmr};
    use commonware_cryptography::{Sha256, sha256};
    use commonware_runtime::{Runner as _, deterministic};

    type D = sha256::Digest;
    type F = mmr::Family;

    /// The default [`Storage::get_nodes`] serves retained positions and rejects pruned ones, so
    /// implementations that do not override it inherit the strict contract. Exercised through
    /// [`Mem`], which prunes and takes the default.
    #[test]
    fn test_default_get_nodes_rejects_pruned() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new(ForwardFold);
            let mut mem = Mem::<F, D>::new();
            let batch = {
                let mut batch = mem.new_batch();
                for i in 0u64..64 {
                    batch = batch.add(&hasher, &hasher.digest(&i.to_be_bytes()));
                }
                batch.merkleize(&mem, &hasher)
            };
            mem.apply_batch(&batch).unwrap();
            mem.prune(Location::new(20)).unwrap();

            // Partition by what `get_node` reports, so both methods are judged against the
            // same notion of availability.
            let mut absent = Vec::new();
            let mut available = Vec::new();
            for position in (0..*mem.size()).map(Position::new) {
                match Mem::get_node(&mem, position) {
                    Some(node) => available.push((position, node)),
                    None => absent.push(position),
                }
            }
            assert!(!absent.is_empty(), "expected some pruned positions");
            assert!(!available.is_empty(), "expected some available positions");

            // Retained positions come back in slot order.
            let positions: Vec<Position<F>> = available.iter().map(|&(pos, _)| pos).collect();
            let nodes = Storage::get_nodes(&mem, &positions).await.unwrap();
            assert_eq!(nodes.len(), available.len());
            for (slot, &(position, node)) in available.iter().enumerate() {
                assert_eq!(nodes[slot], node, "position {position}");
            }

            // A pruned position is rejected by name, alone and alongside retained positions.
            let pruned = absent[0];
            let mut mixed = vec![pruned, *positions.last().unwrap()];
            mixed.sort();
            for request in [vec![pruned], mixed] {
                match Storage::get_nodes(&mem, &request).await {
                    Err(Error::ElementPruned(position)) => assert_eq!(position, pruned),
                    other => panic!("expected ElementPruned({pruned}), got {other:?}"),
                }
            }
        });
    }
}
