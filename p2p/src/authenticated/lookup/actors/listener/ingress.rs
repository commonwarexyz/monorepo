use std::net::SocketAddr;

use futures::channel::oneshot;

use crate::authenticated::mailbox::UnboundedMailbox;

#[derive(Debug)]
pub(in crate::authenticated) enum Message {
    GetLocalAddr {
        response: oneshot::Sender<Option<SocketAddr>>,
    },
}

#[derive(Debug, Clone)]
pub struct Info {
    inner: UnboundedMailbox<Message>,
}

impl Info {
    pub(in crate::authenticated) fn new(inner: UnboundedMailbox<Message>) -> Self {
        Self { inner }
    }

    pub async fn get_local_addr(&mut self) -> Option<SocketAddr> {
        let (response, rx) = oneshot::channel();
        self.inner
            .send(Message::GetLocalAddr { response })
            .expect("network lookup actor must always be running");
        rx.await.expect("actor must not drop channel without responding; at runtime, it must have bound an address")
    }
}
