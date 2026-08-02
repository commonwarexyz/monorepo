use crate::{Heightable, marshal::store::Blocks, types::Height};
use commonware_cryptography::Digestible;
use commonware_runtime::Handle;
use commonware_storage::archive::Identifier;
use commonware_utils::sync::Mutex;
use std::sync::Arc;

/// A finalized-block store operation observed by [`Recording`].
#[derive(Debug, PartialEq, Eq)]
pub enum Op {
    /// A `put` of the block at this height and the payload address passed to storage.
    Put(Height, usize),
    /// A `get` by height, or by digest when `None`.
    Get(Option<Height>),
}

/// A finalized-block store that records `put` and `get` calls in order.
pub struct Recording<T: Blocks> {
    inner: T,
    ops: Arc<Mutex<Vec<Op>>>,
    payload_address: fn(&T::Block) -> usize,
}

impl<T: Blocks> Recording<T> {
    /// Wraps `inner`, recording payload addresses with `payload_address`.
    pub fn new(inner: T, payload_address: fn(&T::Block) -> usize) -> Self {
        Self {
            inner,
            ops: Arc::new(Mutex::new(Vec::new())),
            payload_address,
        }
    }

    /// Returns the shared operation log.
    pub fn ops(&self) -> Arc<Mutex<Vec<Op>>> {
        Arc::clone(&self.ops)
    }
}

impl<T: Blocks> Blocks for Recording<T> {
    type Block = T::Block;
    type Error = T::Error;

    async fn put(mut self, block: &Self::Block) -> Result<Self, Self::Error> {
        self.ops
            .lock()
            .push(Op::Put(block.height(), (self.payload_address)(block)));
        self.inner = self.inner.put(block).await?;
        Ok(self)
    }

    async fn sync(mut self) -> Result<Self, Self::Error> {
        self.inner = self.inner.sync().await?;
        Ok(self)
    }

    async fn start_sync(mut self) -> Result<(Self, Handle<()>), Self::Error> {
        let handle;
        (self.inner, handle) = self.inner.start_sync().await?;
        Ok((self, handle))
    }

    async fn get(
        &self,
        id: Identifier<'_, <Self::Block as Digestible>::Digest>,
    ) -> Result<Option<Self::Block>, Self::Error> {
        let height = match &id {
            Identifier::Index(index) => Some(Height::new(*index)),
            Identifier::Key(_) => None,
        };
        self.ops.lock().push(Op::Get(height));
        self.inner.get(id).await
    }

    async fn prune(mut self, min: Height) -> Result<Self, Self::Error> {
        self.inner = self.inner.prune(min).await?;
        Ok(self)
    }

    fn missing_items(&self, start: Height, max: usize) -> Vec<Height> {
        self.inner.missing_items(start, max)
    }

    fn next_gap(&self, value: Height) -> (Option<Height>, Option<Height>) {
        self.inner.next_gap(value)
    }

    fn last_index(&self) -> Option<Height> {
        self.inner.last_index()
    }
}
