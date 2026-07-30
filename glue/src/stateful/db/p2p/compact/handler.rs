//! Handler types for compact resolver actor coordination.

use bytes::{Buf, BufMut, Bytes};
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_resolver::{self as resolver, Delivery, p2p::Producer};
use commonware_storage::{
    merkle::{Family, Location},
    qmdb::sync,
};
use commonware_utils::{NZU64, Span, channel::oneshot};
use std::{collections::VecDeque, fmt};

/// The wire key for one compact state: the committed operation count it belongs to.
///
/// The target root does not travel with the request; the client verifies the response against
/// its own target and reports validity, exactly as replay sync does.
#[derive(Clone, Debug)]
pub(super) struct Request<F: Family> {
    leaf_count: Location<F>,
}

impl<F: Family> PartialEq for Request<F> {
    fn eq(&self, other: &Self) -> bool {
        self.leaf_count == other.leaf_count
    }
}

impl<F: Family> Eq for Request<F> {}

impl<F: Family> PartialOrd for Request<F> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: Family> Ord for Request<F> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.leaf_count.cmp(&other.leaf_count)
    }
}

impl<F: Family> std::hash::Hash for Request<F> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.leaf_count.hash(state);
    }
}

impl<F: Family> Request<F> {
    pub(super) const fn new(leaf_count: Location<F>) -> Self {
        Self { leaf_count }
    }

    pub(super) const fn leaf_count(&self) -> Location<F> {
        self.leaf_count
    }

    /// The request this key stands for: the final commit proven at `leaf_count`, plus the pins
    /// at that boundary.
    pub(super) fn to_request(&self) -> sync::Request<F> {
        sync::Request {
            size: self.leaf_count,
            start: Location::new(*self.leaf_count - 1),
            max_ops: NZU64!(1),
            retain_from: Some(self.leaf_count),
        }
    }
}

impl<F: Family> fmt::Display for Request<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CompactRequest(leaf_count={})", self.leaf_count)
    }
}

impl<F: Family> Write for Request<F> {
    fn write(&self, buf: &mut impl BufMut) {
        self.leaf_count.write(buf);
    }
}

impl<F: Family> EncodeSize for Request<F> {
    fn encode_size(&self) -> usize {
        self.leaf_count.encode_size()
    }
}

impl<F: Family> Read for Request<F> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let leaf_count = Location::<F>::read(buf)?;
        if !leaf_count.is_valid() || leaf_count == 0 {
            return Err(CodecError::Invalid(
                "commonware_glue::stateful::db::p2p::compact::Request",
                "leaf_count must be in 1..=MAX_LEAVES",
            ));
        }
        Ok(Self { leaf_count })
    }
}

impl<F: Family> Span for Request<F> {}

#[cfg(feature = "arbitrary")]
impl<F: Family> arbitrary::Arbitrary<'_> for Request<F> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let leaf_count = Location::new(u.int_in_range(1..=*F::MAX_LEAVES)?);
        Ok(Self { leaf_count })
    }
}

pub(super) enum EngineMessage<F: Family> {
    Deliver {
        key: Request<F>,
        value: Bytes,
        response: oneshot::Sender<bool>,
    },
    Produce {
        key: Request<F>,
        response: oneshot::Sender<Bytes>,
    },
}

impl<F: Family> EngineMessage<F> {
    fn response_closed(&self) -> bool {
        match self {
            Self::Deliver { response, .. } => response.is_closed(),
            Self::Produce { response, .. } => response.is_closed(),
        }
    }
}

pub(super) struct EnginePending<F: Family>(VecDeque<EngineMessage<F>>);

impl<F: Family> Default for EnginePending<F> {
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<F: Family> Overflow<EngineMessage<F>> for EnginePending<F> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<P>(&mut self, mut push: P)
    where
        P: FnMut(EngineMessage<F>) -> Option<EngineMessage<F>>,
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

impl<F: Family> Policy for EngineMessage<F> {
    type Overflow = EnginePending<F>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.response_closed() {
            return;
        }
        overflow.0.push_back(message);
    }
}

#[derive(Clone)]
pub(super) struct Handler<F: Family> {
    sender: Sender<EngineMessage<F>>,
}

impl<F: Family> Handler<F> {
    pub(super) const fn new(sender: Sender<EngineMessage<F>>) -> Self {
        Self { sender }
    }
}

impl<F: Family> resolver::Consumer for Handler<F> {
    type Key = Request<F>;
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

impl<F: Family> Producer for Handler<F> {
    type Key = Request<F>;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(EngineMessage::Produce { key, response });
        receiver
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_storage::merkle::mmr;

        commonware_conformance::conformance_tests! {
            CodecConformance<Request<mmr::Family>>,
        }
    }
}
