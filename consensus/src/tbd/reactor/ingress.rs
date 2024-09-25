use crate::tbd::block::Block;
use crate::Hash;
use bytes::Bytes;
use commonware_cryptography::Signature;
use futures::channel::mpsc;

pub enum Message {
    // Block Notarization
    Propose {
        epoch: u64,
        view: u64,
        block: Block,
        payload: Bytes,
        signature: Signature,
    },
    Vote {
        epoch: u64,
        view: u64,
        block: Hash,
        signature: Signature,
    },
    Finalize {
        epoch: u64,
        view: u64,
        block: Hash,
        notarization: Bytes,
        signature: Signature,
    },

    // View Change
    Advance {
        epoch: u64,
        view: u64,
        block: Hash,
        notarization: Bytes,
    },
    Lock {
        epoch: u64,
        view: u64,
        block: Hash,
        notarization: Bytes,
        finalization: Bytes,
    },
    // TODO: backfill (propose + lock + seed)?
    // start with full sync and in the future add state sync

    // Beacon
    Seed {
        epoch: u64,
        view: u64,
        signature: Signature,
    },
    // Faults
    // TODO: add verification of conflicting messages (signature by same person for different blocks)
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }
}
