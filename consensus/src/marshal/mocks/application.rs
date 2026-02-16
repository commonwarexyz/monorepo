use crate::{marshal::Update, types::Height, Block, Reporter};
use commonware_utils::{sync::Mutex, Acknowledgement};
use std::{collections::BTreeMap, sync::Arc};

/// A mock application that stores finalized blocks.
#[derive(Clone)]
pub struct Application<B: Block> {
    blocks: Arc<Mutex<BTreeMap<Height, B>>>,
    #[allow(clippy::type_complexity)]
    tip: Arc<Mutex<Option<(Height, B::Commitment)>>>,
}

impl<B: Block> Default for Application<B> {
    fn default() -> Self {
        Self {
            blocks: Default::default(),
            tip: Default::default(),
        }
    }
}

impl<B: Block> Application<B> {
    /// Returns the finalized blocks.
    pub fn blocks(&self) -> BTreeMap<Height, B> {
        self.blocks.lock().clone()
    }

    /// Returns the tip.
    pub fn tip(&self) -> Option<(Height, B::Commitment)> {
        *self.tip.lock()
    }
}

impl<B: Block> Reporter for Application<B> {
    type Activity = Update<B>;

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            Update::Block(block, ack_tx) => {
                self.blocks.lock().insert(block.height(), block);
                ack_tx.acknowledge();
            }
            Update::Tip(_, height, commitment) => {
                *self.tip.lock() = Some((height, commitment));
            }
        }
    }
}
