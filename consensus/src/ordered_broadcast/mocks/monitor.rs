use crate::ordered_broadcast::Epoch;
use crate::Monitor as M;

#[derive(Clone)]
pub struct Monitor {
    epoch: Epoch,
}

impl Monitor {
    pub fn new(epoch: Epoch) -> Self {
        Self { epoch }
    }
}

impl M for Monitor {
    type Index = Epoch;

    fn latest(&self) -> Epoch {
        self.epoch
    }
}
