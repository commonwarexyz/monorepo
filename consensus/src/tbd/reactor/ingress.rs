use bytes::Bytes;
use futures::channel::oneshot;

pub enum Message {
    Payload {
        timestamp: u64,
        height: u64,
        parent: Bytes,
        payload: oneshot::Sender<Bytes>,
    },
    Verify {
        timestamp: u64,
        height: u64,
        parent: Bytes,
        payload: Bytes,
        // TODO: add validator set changes to this response
        result: oneshot::Sender<Option<Bytes>>,
    },
    Notarized {
        // Can be used to offer optimistic confirmation
        seed: Bytes,
        payload: Bytes,
    },
    Finalized {
        seed: Bytes,
        payload: Bytes,
        // TODO: pass partial signatures for h-1
    },
}
