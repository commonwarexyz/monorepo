use crate::tbd::block::Hash;
use bytes::Bytes;
use futures::channel::oneshot;

pub enum Message {
    Payload {
        timestamp: u64,
        parent: Hash,
        payload: oneshot::Sender<Bytes>,
    },
    Verify {
        timestamp: u64,
        parent: Hash,
        payload: Bytes,
        result: oneshot::Sender<Option<Hash>>,
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
