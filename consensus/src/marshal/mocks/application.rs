use crate::{marshal::Update, types::Height, Block, Reporter};
use commonware_utils::Acknowledgement;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

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
        self.blocks.lock().unwrap().clone()
    }

    /// Returns the tip.
    pub fn tip(&self) -> Option<(Height, B::Commitment)> {
        *self.tip.lock().unwrap()
    }
}

impl<B: Block> Reporter for Application<B> {
    type Activity = Update<B>;

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            Update::Block(block, ack_tx) => {
                self.blocks.lock().unwrap().insert(block.height(), block);
                ack_tx.acknowledge();
            }
            Update::Tip(height, commitment, _) => {
                *self.tip.lock().unwrap() = Some((height, commitment));
            }
        }
    }
}
