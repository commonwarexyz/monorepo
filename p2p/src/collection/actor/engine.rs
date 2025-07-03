use super::{Collector, Endpoint, Originator};
use bytes::Bytes;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::Handle;
use futures::channel::{mpsc, oneshot};
use std::collections::HashMap;

/// Engine that will disperse messages and collect responses.
pub struct Engine<O: Originator, E: Endpoint> {
    originator: O,
    endpoint: E,
    mailbox: mpsc::Receiver<_>,
}

impl<O: Originator, E: Endpoint> Engine<O, E> {
    pub fn new(cfg: Config<O, E>) -> (Self, Mailbox) {
        let (tx, rx) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(tx);
        (
            Self {
                originator: cfg.originator,
                endpoint: cfg.endpoint,
                mailbox: rx,
            },
            mailbox,
        )
    }

    pub fn start(
        self,
        request_network: (impl Sender, impl Receiver),
        response_network: (impl Sender, impl Receiver),
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(request_network, response_network))
    }

    async fn run(
        mut self,
        request_network: (impl Sender, impl Receiver),
        response_network: (impl Sender, impl Receiver),
    ) {
        Ok(())
    }
}
