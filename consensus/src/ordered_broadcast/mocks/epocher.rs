use super::super::{Epoch, Epocher as E};

#[derive(Clone)]
pub struct Epocher {
    epoch: Epoch,
}

impl Epocher {
    pub fn new(epoch: Epoch) -> Self {
        Self { epoch }
    }
}

impl E for Epocher {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}
