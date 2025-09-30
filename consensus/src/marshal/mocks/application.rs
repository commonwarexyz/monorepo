use crate::{Block, Reporter};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

/// A mock application that stores finalized blocks.
#[derive(Clone)]
pub struct Application<B: Block> {
    blocks: Arc<Mutex<BTreeMap<u64, B>>>,
}

impl<B: Block> Default for Application<B> {
    fn default() -> Self {
        Self {
            blocks: Default::default(),
        }
    }
}

impl<B: Block> Application<B> {
    /// Returns the finalized blocks.
    pub fn blocks(&self) -> BTreeMap<u64, B> {
        self.blocks
            .lock()
            .expect("application mutex should not be poisoned on blocks()")
            .clone()
    }
}

impl<B: Block> Reporter for Application<B> {
    type Activity = B;

    async fn report(&mut self, activity: Self::Activity) {
        self.blocks
            .lock()
            .expect("application mutex should not be poisoned on report()")
            .insert(activity.height(), activity);
    }
}
