use std::collections::HashMap;

use bytes::Bytes;
use commonware_cryptography::Digest;
use tracing::debug;

use crate::{linked::Context, Collector as Z, Proof};

#[derive(Clone)]
pub struct Collector {
    map: HashMap<Context, (Digest, Bytes)>,
}

impl Collector {
    pub fn new() -> Self {
        Collector {
            map: HashMap::new(),
        }
    }
}

impl Collector {
    pub fn get(&self, context: &Context) -> Option<&(Digest, Bytes)> {
        self.map.get(context)
    }
}

impl Z for Collector {
    type Context = Context;
    async fn acknowledged(&mut self, context: Self::Context, payload: Digest, proof: Proof) {
        debug!("acknowledged");
        self.map.insert(context, (payload, proof));
    }
}
