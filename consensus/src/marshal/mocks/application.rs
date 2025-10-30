use crate::{
    marshal::Update,
    simplex::{signing_scheme::Scheme, types::Finalization},
    types::Round,
    Block, Reporter,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

/// A mock application that stores finalized blocks.
#[derive(Clone)]
pub struct Application<B: Block, S: Scheme> {
    blocks: Arc<Mutex<BTreeMap<u64, B>>>,
    finalizations: Arc<Mutex<BTreeMap<Round, Finalization<S, B::Commitment>>>>,
}

impl<B: Block, S: Scheme> Default for Application<B, S> {
    fn default() -> Self {
        Self {
            blocks: Default::default(),
            finalizations: Default::default(),
        }
    }
}

impl<B: Block, S: Scheme> Application<B, S> {
    /// Returns the finalized blocks.
    pub fn blocks(&self) -> BTreeMap<u64, B> {
        self.blocks.lock().unwrap().clone()
    }

    /// Returns the finalization certificates.
    pub fn finalizations(&self) -> BTreeMap<Round, Finalization<S, B::Commitment>> {
        self.finalizations.lock().unwrap().clone()
    }
}

impl<B: Block, S: Scheme> Reporter for Application<B, S> {
    type Activity = Update<B, S>;

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            Update::Block(block) => {
                self.blocks.lock().unwrap().insert(block.height(), block);
            }
            Update::Finalization(finalization) => {
                self.finalizations
                    .lock()
                    .unwrap()
                    .insert(finalization.round(), finalization);
            }
        }
    }
}
