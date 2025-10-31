use crate::{marshal::Update, Block, Reporter};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

/// A mock application that stores finalized blocks.
#[derive(Clone)]
pub struct Application<B: Block> {
    blocks: Arc<Mutex<BTreeMap<u64, B>>>,
    tip: Arc<Mutex<Option<(u64, B::Commitment)>>>,
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
    pub fn blocks(&self) -> BTreeMap<u64, B> {
        self.blocks.lock().unwrap().clone()
    }

    /// Returns the tip.
    pub fn tip(&self) -> Option<(u64, B::Commitment)> {
        self.tip.lock().unwrap().clone()
    }
}

impl<B: Block> Reporter for Application<B> {
    type Activity = Update<B>;

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            Update::Block(block) => {
                self.blocks.lock().unwrap().insert(block.height(), block);
            }
            Update::Tip(height, commitment) => {
                *self.tip.lock().unwrap() = Some((height, commitment));
            }
        }
    }
}
