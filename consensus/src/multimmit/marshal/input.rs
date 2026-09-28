//! What reaches the owner: public requests, the consensus feed, and peer traffic.

use super::{
    store::blocks::Block,
    types::{Custody, Error, Floor, MarshalProgress},
    wire::{self, Committed, Key, Records},
};
use crate::{
    multimmit::{
        scheme::Scheme,
        types::{
            Activity, ArtifactKind, BlockRef, Body, CertificateId, CodecConfig, FinalityFact, Lqc,
            LqcProof, Placement, TipRecord, artifact_digest,
        },
    },
    types::{Height, OutputIndex},
};
use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_codec::{Decode as _, Encode as _, EncodeSize as _};
use commonware_cryptography::{Digest, Hasher};
use commonware_resolver::{Consumer, Delivery, Outcome, p2p::Producer};
use commonware_utils::{
    channel::{mpsc, oneshot},
    sync::Mutex,
};
use std::{collections::VecDeque, num::NonZeroU16, sync::Arc};

/// A reply channel.
pub(crate) type Reply<T> = oneshot::Sender<Result<T, Error>>;

/// The reply to a certificate request.
pub(crate) type CertificateReply<S, D> = Reply<Option<Arc<Lqc<S, D>>>>;

/// The reply to a floor request.
pub(crate) type FloorReply<S, D> = Reply<Option<(OutputIndex, Floor<S, D>)>>;

/// A public request.
pub(crate) enum Message<H: Hasher, S: Scheme, B: Body<H>> {
    /// Hold a block durably in custody.
    Stage {
        block: Block<H, B>,
        reply: Reply<Custody>,
    },
    /// Return a held block.
    Get {
        block: BlockRef<H::Digest>,
        reply: Reply<Option<Block<H, B>>>,
    },
    /// Return a block, fetching it from peers when not held.
    Fetch {
        block: BlockRef<H::Digest>,
        reply: Reply<Block<H, B>>,
    },
    /// Return a block once it is held durably, from custody or the broadcast buffer.
    Subscribe {
        block: BlockRef<H::Digest>,
        reply: Reply<Block<H, B>>,
    },
    /// Return a retained L-QC, fetching it from peers when `fetch` is set.
    Certificate {
        id: CertificateId<H::Digest>,
        fetch: bool,
        reply: CertificateReply<S, H::Digest>,
    },
    /// Return the newest retained floor at or below an output index.
    FloorAt {
        at: OutputIndex,
        reply: FloorReply<S, H::Digest>,
    },
    /// Install a floor.
    Install {
        floor: Floor<S, H::Digest>,
        reply: Reply<()>,
    },
    /// Drop what the newest floor at or below an output index makes obsolete.
    Prune {
        below: OutputIndex,
        reply: Reply<()>,
    },
    /// Return progress.
    Progress {
        reply: Reply<MarshalProgress<H::Digest>>,
    },
}

/// Most verified L-QCs the feed holds; older ones are dropped first.
const LANE_PROOFS: usize = 16;

/// Most placement runs the feed holds; older ones are dropped first.
const LANE_PLACEMENTS: usize = 4096;

/// What consensus reported since the owner last drained the feed.
pub(crate) struct Fed<S: Scheme, D: Digest> {
    /// History records, oldest first. Never dropped.
    pub(crate) records: Vec<Arc<TipRecord<D>>>,
    /// Verified L-QCs with the finality each proves, oldest first.
    pub(crate) proofs: VecDeque<(LqcProof<S, D>, FinalityFact<D>)>,
    /// Placement runs, oldest first.
    pub(crate) placed: VecDeque<Placement<D>>,
    /// The newest released height reported per chain.
    pub(crate) released: Vec<Option<Height>>,
    /// Bytes of the records held.
    record_bytes: usize,
    /// Whether the record backlog overflowed.
    pub(crate) overflowed: bool,
}

/// The consensus feed: a lane that never blocks consensus.
///
/// Placement runs and older L-QCs are dropped under pressure: placement only hints at fetches,
/// and the newest L-QC authenticates every record below it. Records are never dropped; when
/// their backlog exceeds its bound, marshal stops rather than lose a link of the history.
pub(crate) struct Lane<S: Scheme, D: Digest> {
    fed: Mutex<Fed<S, D>>,
    signal: mpsc::Sender<()>,
    max_record_bytes: usize,
}

impl<S: Scheme, D: Digest> Lane<S, D> {
    /// Creates a lane for `chains` chains and the receiver that signals new reports.
    pub(crate) fn new(chains: usize, max_record_bytes: usize) -> (Arc<Self>, mpsc::Receiver<()>) {
        let (signal, receiver) = mpsc::channel(1);
        let lane = Self {
            fed: Mutex::new(Fed {
                records: Vec::new(),
                proofs: VecDeque::new(),
                placed: VecDeque::new(),
                released: vec![None; chains],
                record_bytes: 0,
                overflowed: false,
            }),
            signal,
            max_record_bytes,
        };
        (Arc::new(lane), receiver)
    }

    /// Takes everything reported so far.
    pub(crate) fn take(&self) -> Fed<S, D> {
        let mut fed = self.fed.lock();
        let chains = fed.released.len();
        std::mem::replace(
            &mut *fed,
            Fed {
                records: Vec::new(),
                proofs: VecDeque::new(),
                placed: VecDeque::new(),
                released: vec![None; chains],
                record_bytes: 0,
                overflowed: false,
            },
        )
    }

    /// Records one activity.
    pub(crate) fn report(&self, activity: Activity<S, D>) -> Feedback {
        {
            let mut fed = self.fed.lock();
            match activity {
                Activity::Proven {
                    proof,
                    fact,
                    records,
                } => {
                    for record in records.iter() {
                        fed.record_bytes += record.encode_size();
                        fed.records.push(Arc::clone(record));
                    }
                    if fed.record_bytes > self.max_record_bytes {
                        fed.overflowed = true;
                    }
                    if fed.proofs.len() == LANE_PROOFS {
                        fed.proofs.pop_front();
                    }
                    fed.proofs.push_back((proof, fact));
                }
                Activity::Placed { placed, .. } => {
                    for run in placed {
                        if fed.placed.len() == LANE_PLACEMENTS {
                            fed.placed.pop_front();
                        }
                        fed.placed.push_back(run);
                    }
                }
                Activity::CertificateRecorded {
                    certified,
                    released,
                } => {
                    let chain = certified.chain().get() as usize;
                    if let Some(slot) = fed.released.get_mut(chain) {
                        *slot = Some(slot.map_or(released, |known| known.max(released)));
                    }
                }
                _ => return Feedback::Ok,
            }
        }
        match self.signal.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => Feedback::Ok,
            Err(mpsc::error::TrySendError::Closed(())) => Feedback::Closed,
        }
    }
}

/// A peer response, decoded and authenticated against its key.
pub(crate) enum Delivered<H: Hasher, S: Scheme, B: Body<H>> {
    /// Blocks newest first, starting at `head`, answering the request for `len` blocks.
    Blocks {
        head: BlockRef<H::Digest>,
        len: NonZeroU16,
        blocks: Vec<Block<H, B>>,
        verdict: oneshot::Sender<Outcome>,
    },
    /// Records newest first, starting at `before`, with their commitments.
    Records {
        before: H::Digest,
        records: Vec<Committed<H::Digest>>,
        verdict: oneshot::Sender<Outcome>,
    },
    /// The server no longer retains `before`.
    Pruned {
        before: H::Digest,
        verdict: oneshot::Sender<Outcome>,
    },
    /// An unverified L-QC and its leader's history record.
    Proof {
        after: Option<H::Digest>,
        id: CertificateId<H::Digest>,
        lqc: Lqc<S, H::Digest>,
        record: Arc<TipRecord<H::Digest>>,
        verdict: oneshot::Sender<Outcome>,
    },
    /// The unverified L-QC with `id`.
    Lqc {
        id: CertificateId<H::Digest>,
        lqc: Lqc<S, H::Digest>,
        verdict: oneshot::Sender<Outcome>,
    },
}

/// A peer request to serve.
pub(crate) struct Request<D: Digest> {
    pub(crate) key: Key<D>,
    pub(crate) reply: oneshot::Sender<Bytes>,
}

/// Attaches marshal to a network resolver, as its consumer and producer.
///
/// Responses are decoded and authenticated against their keys here, on the resolver's task,
/// so the owner never hashes peer bytes.
pub struct Bridge<H: Hasher, S: Scheme, B: Body<H>> {
    deliveries: mpsc::Sender<Delivered<H, S, B>>,
    requests: mpsc::Sender<Request<H::Digest>>,
    codec: CodecConfig,
    body: B::Cfg,
}

impl<H: Hasher, S: Scheme, B: Body<H>> Clone for Bridge<H, S, B> {
    fn clone(&self) -> Self {
        Self {
            deliveries: self.deliveries.clone(),
            requests: self.requests.clone(),
            codec: self.codec,
            body: self.body.clone(),
        }
    }
}

impl<H: Hasher, S: Scheme, B: Body<H>> Bridge<H, S, B> {
    pub(crate) const fn new(
        deliveries: mpsc::Sender<Delivered<H, S, B>>,
        requests: mpsc::Sender<Request<H::Digest>>,
        codec: CodecConfig,
        body: B::Cfg,
    ) -> Self {
        Self {
            deliveries,
            requests,
            codec,
            body,
        }
    }

    /// Decodes `value` for `key`, returning `None` when it does not answer the key.
    fn decode(
        &self,
        key: Key<H::Digest>,
        value: Bytes,
        verdict: oneshot::Sender<Outcome>,
    ) -> Result<Delivered<H, S, B>, oneshot::Sender<Outcome>> {
        match key {
            Key::Blocks { head, len } => {
                match wire::decode_blocks::<H, B>(value, head, len, &self.body) {
                    Some(blocks) => Ok(Delivered::Blocks {
                        head,
                        len,
                        blocks,
                        verdict,
                    }),
                    None => Err(verdict),
                }
            }
            Key::Records { before } => match Records::<H::Digest>::decode_cfg(value, &self.codec) {
                Ok(Records::Records(records)) => {
                    match wire::authenticate_records::<H>(records, before) {
                        Some(records) => Ok(Delivered::Records {
                            before,
                            records,
                            verdict,
                        }),
                        None => Err(verdict),
                    }
                }
                Ok(Records::Pruned) => Ok(Delivered::Pruned { before, verdict }),
                Err(_) => Err(verdict),
            },
            Key::Proofs { after } => {
                match wire::Proof::<S, H::Digest>::decode_cfg(value, &self.codec) {
                    Ok(proof) => {
                        if proof.record.commitment::<H>() != proof.lqc.leader().history() {
                            return Err(verdict);
                        }
                        let id = CertificateId::new(artifact_digest::<H>(
                            ArtifactKind::Lqc,
                            &proof.lqc.encode(),
                        ));
                        Ok(Delivered::Proof {
                            after,
                            id,
                            lqc: Arc::unwrap_or_clone(proof.lqc),
                            record: proof.record,
                            verdict,
                        })
                    }
                    Err(_) => Err(verdict),
                }
            }
            Key::Lqc { id } => {
                // The value is the certificate's canonical encoding, so its identifier is the
                // digest of the value itself.
                if CertificateId::new(artifact_digest::<H>(ArtifactKind::Lqc, &value)) != id {
                    return Err(verdict);
                }
                match Lqc::<S, H::Digest>::decode_cfg(value, &self.codec) {
                    Ok(lqc) => Ok(Delivered::Lqc { id, lqc, verdict }),
                    Err(_) => Err(verdict),
                }
            }
        }
    }
}

impl<H: Hasher, S: Scheme, B: Body<H>> Consumer for Bridge<H, S, B> {
    type Key = Key<H::Digest>;
    type Value = Bytes;
    type Subscriber = ();
    type Outcome = Outcome;

    fn deliver(
        &mut self,
        delivery: Delivery<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<Self::Outcome> {
        let (verdict, receiver) = oneshot::channel();
        match self.decode(delivery.key, value, verdict) {
            Ok(delivered) => {
                if let Err(error) = self.deliveries.try_send(delivered) {
                    // A busy owner retries later, attributing nothing to the peer.
                    let delivered = match error {
                        mpsc::error::TrySendError::Full(delivered)
                        | mpsc::error::TrySendError::Closed(delivered) => delivered,
                    };
                    let verdict = match delivered {
                        Delivered::Blocks { verdict, .. }
                        | Delivered::Records { verdict, .. }
                        | Delivered::Pruned { verdict, .. }
                        | Delivered::Proof { verdict, .. }
                        | Delivered::Lqc { verdict, .. } => verdict,
                    };
                    let _ = verdict.send(Outcome::Unresolved);
                }
            }
            Err(verdict) => {
                let _ = verdict.send(Outcome::Invalid);
            }
        }
        receiver
    }
}

impl<H: Hasher, S: Scheme, B: Body<H>> Producer for Bridge<H, S, B> {
    type Key = Key<H::Digest>;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (reply, receiver) = oneshot::channel();
        // A busy owner drops the request: the peer asks another server.
        let _ = self.requests.try_send(Request { key, reply });
        receiver
    }
}
