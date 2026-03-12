//! Handler types for compact resolver actor coordination.

use bytes::{Buf, BufMut, Bytes};
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_cryptography::Digest;
use commonware_resolver::{self as resolver, p2p::Producer, Delivery};
use commonware_storage::{merkle::Family, qmdb::sync::compact};
use commonware_utils::{channel::oneshot, Span};
use std::{
    collections::VecDeque,
    fmt,
    hash::{Hash, Hasher},
};

#[derive(Clone, Debug)]
pub(super) struct Request<F: Family, D: Digest> {
    root: D,
    leaf_count: commonware_storage::merkle::Location<F>,
}

impl<F: Family, D: Digest> Request<F, D> {
    pub(super) const fn from_target(target: compact::Target<F, D>) -> Self {
        Self {
            root: target.root,
            leaf_count: target.leaf_count,
        }
    }

    pub(super) const fn to_target(&self) -> compact::Target<F, D> {
        compact::Target {
            root: self.root,
            leaf_count: self.leaf_count,
        }
    }
}

impl<F: Family, D: Digest> PartialEq for Request<F, D> {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root && self.leaf_count == other.leaf_count
    }
}

impl<F: Family, D: Digest> Eq for Request<F, D> {}

impl<F: Family, D: Digest> PartialOrd for Request<F, D> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: Family, D: Digest> Ord for Request<F, D> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.root
            .cmp(&other.root)
            .then_with(|| self.leaf_count.cmp(&other.leaf_count))
    }
}

impl<F: Family, D: Digest> Hash for Request<F, D> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.root.hash(state);
        self.leaf_count.hash(state);
    }
}

impl<F: Family, D: Digest> fmt::Display for Request<F, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CompactRequest(root={}, leaf_count={})",
            self.root, self.leaf_count
        )
    }
}

impl<F: Family, D: Digest> Write for Request<F, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.leaf_count.write(buf);
    }
}

impl<F: Family, D: Digest> EncodeSize for Request<F, D> {
    fn encode_size(&self) -> usize {
        self.root.encode_size() + self.leaf_count.encode_size()
    }
}

impl<F: Family, D: Digest> Read for Request<F, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let root = D::read(buf)?;
        let leaf_count = commonware_storage::merkle::Location::<F>::read(buf)?;
        let target = compact::Target { root, leaf_count };
        target.validate().map_err(|reason| {
            CodecError::Invalid(
                "commonware_glue::stateful::db::compact_p2p::Request",
                reason,
            )
        })?;
        Ok(Self::from_target(target))
    }
}

impl<F: Family, D: Digest> Span for Request<F, D> {}

pub(super) enum EngineMessage<F: Family, D: Digest> {
    Deliver {
        key: Request<F, D>,
        value: Bytes,
        response: oneshot::Sender<bool>,
    },
    Produce {
        key: Request<F, D>,
        response: oneshot::Sender<Bytes>,
    },
}

impl<F: Family, D: Digest> EngineMessage<F, D> {
    fn response_closed(&self) -> bool {
        match self {
            Self::Deliver { response, .. } => response.is_closed(),
            Self::Produce { response, .. } => response.is_closed(),
        }
    }
}

pub(super) struct EnginePending<F: Family, D: Digest>(VecDeque<EngineMessage<F, D>>);

impl<F: Family, D: Digest> Default for EnginePending<F, D> {
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<F: Family, D: Digest> Overflow<EngineMessage<F, D>> for EnginePending<F, D> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<P>(&mut self, mut push: P)
    where
        P: FnMut(EngineMessage<F, D>) -> Option<EngineMessage<F, D>>,
    {
        while let Some(message) = self.0.pop_front() {
            if message.response_closed() {
                continue;
            }

            if let Some(message) = push(message) {
                self.0.push_front(message);
                break;
            }
        }
    }
}

impl<F: Family, D: Digest> Policy for EngineMessage<F, D> {
    type Overflow = EnginePending<F, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) -> bool {
        if message.response_closed() {
            return true;
        }
        overflow.0.push_back(message);
        true
    }
}

#[derive(Clone)]
pub(super) struct Handler<F: Family, D: Digest> {
    sender: Sender<EngineMessage<F, D>>,
}

impl<F: Family, D: Digest> Handler<F, D> {
    pub(super) const fn new(sender: Sender<EngineMessage<F, D>>) -> Self {
        Self { sender }
    }
}

impl<F: Family, D: Digest> resolver::Consumer for Handler<F, D> {
    type Key = Request<F, D>;
    type Value = Bytes;
    type Subscriber = ();

    fn deliver(
        &mut self,
        delivery: Delivery<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(EngineMessage::Deliver {
            key: delivery.key,
            value,
            response,
        });
        receiver
    }
}

impl<F: Family, D: Digest> Producer for Handler<F, D> {
    type Key = Request<F, D>;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(EngineMessage::Produce { key, response });
        receiver
    }
}
