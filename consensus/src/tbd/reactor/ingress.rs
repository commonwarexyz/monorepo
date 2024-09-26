use bytes::Bytes;
use futures::channel::oneshot;

pub enum Message {
    Payload {
        timestamp: u64,
        height: u64,
        parent: Bytes,
        payload: oneshot::Sender<(Bytes, Bytes)>,
    },
    Verify {
        timestamp: u64,
        height: u64,
        parent: Bytes,
        payload: Bytes,
        result: oneshot::Sender<Option<Bytes>>,
    },
    Notarized {
        seed: Bytes,
        payload: Bytes,
    },
    Finalized {
        seed: Bytes,
        payload: Bytes,
    },
}
