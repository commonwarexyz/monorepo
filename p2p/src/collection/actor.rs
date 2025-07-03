use super::{Collector, Endpoint, Originator};
use bytes::Bytes;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::Handle;
use futures::channel::oneshot;
use std::collections::HashMap;

pub struct Mailbox<M: Idable> {}

impl Collector for Mailbox {
    type Message = E::Message;
    type PublicKey = E::Message::PublicKey;

    fn send(
        &mut self,
        message: Self::Message,
        transformer: fn(Self::Message, Self::PublicKey) -> Bytes,
    ) -> impl Future<Output = ()> + Send {
        todo!()
    }

    fn peek(
        &mut self,
        id: <Self::Message as Idable>::ID,
    ) -> impl Future<Output = oneshot::Receiver<HashMap<Self::PublicKey, Bytes>>> + Send {
        todo!()
    }

    fn cancel(&mut self, id: <Self::Message as Idable>::ID) -> impl Future<Output = ()> + Send {
        todo!()
    }
}

/// Actor that will disperse messages and collect responses.
pub struct Actor<O: Originator, E: Endpoint> {
    originator: O,
    endpoint: E,
    mailbox: Mailbox<E::Message>,
}

impl<O: Originator, E: Endpoint> Actor<O, E> {
    pub fn new(originator: O, endpoint: E) -> Self {
        Self {
            originator,
            endpoint,
        }
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
