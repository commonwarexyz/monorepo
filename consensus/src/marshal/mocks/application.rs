use crate::{marshal::Update, types::Height, Block, Reporter};
use commonware_utils::{acknowledgement::Exact, sync::Mutex, Acknowledgement};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

/// A mock application that stores finalized blocks.
#[derive(Clone)]
pub struct Application<B: Block> {
    blocks: Arc<Mutex<BTreeMap<Height, B>>>,
    #[allow(clippy::type_complexity)]
    tip: Arc<Mutex<Option<(Height, B::Commitment)>>>,
    pending_acks: Arc<Mutex<VecDeque<(Height, Exact)>>>,
    auto_ack: bool,
}

impl<B: Block> Default for Application<B> {
    fn default() -> Self {
        Self {
            blocks: Default::default(),
            tip: Default::default(),
            pending_acks: Default::default(),
            auto_ack: true,
        }
    }
}

impl<B: Block> Application<B> {
    /// Returns an application that stores acks for manual release.
    pub fn manual_ack() -> Self {
        Self {
            auto_ack: false,
            ..Default::default()
        }
    }

    /// Returns the finalized blocks.
    pub fn blocks(&self) -> BTreeMap<Height, B> {
        self.blocks.lock().clone()
    }

    /// Returns the tip.
    pub fn tip(&self) -> Option<(Height, B::Commitment)> {
        *self.tip.lock()
    }

    /// Returns pending ack heights in arrival order.
    pub fn pending_ack_heights(&self) -> Vec<Height> {
        self.pending_acks
            .lock()
            .iter()
            .map(|(height, _)| *height)
            .collect()
    }

    /// Acknowledges the oldest pending block and returns its height.
    pub fn acknowledge_next(&self) -> Option<Height> {
        let (height, ack) = self.pending_acks.lock().pop_front()?;
        ack.acknowledge();
        Some(height)
    }
}

impl<B: Block> Reporter for Application<B> {
    type Activity = Update<B>;

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            Update::Block(block, ack_tx) => {
                let height = block.height();
                self.blocks.lock().insert(height, block);
                if self.auto_ack {
                    ack_tx.acknowledge();
                } else {
                    self.pending_acks.lock().push_back((height, ack_tx));
                }
            }
            Update::Tip(_, height, commitment) => {
                *self.tip.lock() = Some((height, commitment));
            }
        }
    }
}
