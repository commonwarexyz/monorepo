//! Serving peers.
//!
//! Requests are answered from what marshal holds, never by fetching. The owner only locates the
//! parts; reads and encoding run on another task through snapshot readers. A request whose parts
//! live in a segment without an open snapshot opens it for later requests and is dropped; the
//! peer asks another server.

use super::{Event, Ledger};
use crate::{
    Reporter,
    multimmit::{
        marshal::{
            input::Request,
            store::{
                blocks::Block,
                log::{Access, Reader},
                proofs::{Part, Stored},
            },
            types::{LqcVerifier, Update},
            wire::{self, Key, MAX_RECORDS, Records},
        },
        scheme::Scheme,
        types::{Artifact, Body, CertificateId, TipRecord, TransactionBlock},
    },
};
use bytes::Bytes;
use commonware_codec::{EncodeSize as _, FixedSize as _};
use commonware_cryptography::{Hasher, PublicKey, crc32};
use commonware_resolver::Resolver;
use commonware_runtime::Spawner;
use commonware_storage::Context;
use std::sync::Arc;

/// Where one served value comes from.
enum Source<E: Context, V: commonware_codec::CodecShared> {
    Held(V),
    Read(Reader<E, V>, (u64, u32)),
}

impl<E: Context, V: commonware_codec::CodecShared> Source<E, V> {
    async fn get(self) -> Result<V, crate::multimmit::marshal::store::Error> {
        match self {
            Self::Held(value) => Ok(value),
            Self::Read(reader, (offset, size)) => reader.get(offset, size).await,
        }
    }
}

/// Bytes a stored frame adds to its value: the kind tag of a part is part of the value, the
/// checksum is not.
const CHECKSUM: u64 = crc32::Digest::SIZE as u64;

impl<E, H, S, B, P, R, V, A> Ledger<E, H, S, B, P, R, V, A>
where
    E: Context + Spawner,
    H: Hasher,
    S: Scheme,
    B: Body<H>,
    P: PublicKey,
    R: Resolver<Key = Key<H::Digest>, Subscriber = ()>,
    V: LqcVerifier<H, S> + Clone,
    A: Reporter<Activity = Update<TransactionBlock<H, B>>>,
{
    /// Answers a peer request, or drops it. A request for data marshal holds but cannot read yet
    /// (its segment is opening, or its rows are not yet cut) is parked until storage progresses.
    pub(super) fn on_request(&mut self, request: Request<H::Digest>) {
        if self.serving >= self.limits.max_serving.get() || request.reply.is_closed() {
            return;
        }
        let Request { key, reply } = request;
        let budget = self.limits.max_response_bytes.get() as u64;
        let job = match key {
            Key::Blocks { head, len } => {
                let mut sources = Vec::new();
                let mut bytes = 0u64;
                let mut cursor = head;
                for _ in 0..len.get() {
                    let Some(held) = self.blocks.index().get(cursor) else {
                        break;
                    };
                    let size = held.encoded_len();
                    if !sources.is_empty() && bytes + size > budget {
                        break;
                    }
                    let parent = held.header.parent_ref();
                    let Some(source) = self.block_source(cursor) else {
                        break;
                    };
                    bytes += size;
                    sources.push(source);
                    cursor = parent;
                }
                if sources.is_empty() {
                    if self.blocks.index().get(head).is_some() {
                        self.park(Request { key, reply });
                    }
                    return;
                }
                Box::pin(async move {
                    let mut blocks: Vec<Block<H, B>> = Vec::with_capacity(sources.len());
                    for source in sources {
                        blocks.push(source.get().await.ok()?);
                    }
                    Some(wire::encode_blocks::<H, B>(&blocks))
                }) as futures::future::BoxFuture<'static, Option<Bytes>>
            }
            Key::Records { before } => {
                let index = self.proofs.index();
                if index.record(&before).is_none() {
                    // A server that pruned or installed a floor no longer holds older history.
                    if self.meta.durable().floor.is_some() && index.ordinal(&before).is_none() {
                        let pruned = wire::encode(&Records::<H::Digest>::Pruned);
                        let _ = reply.send(pruned);
                        self.metrics.served.inc();
                    }
                    return;
                }
                let mut sources = Vec::new();
                let mut bytes = 0u64;
                let mut cursor = before;
                while sources.len() < MAX_RECORDS {
                    let Some(entry) = self.proofs.index().record(&cursor).copied() else {
                        break;
                    };
                    let size = u64::from(entry.stored.location.1).saturating_sub(CHECKSUM);
                    if !sources.is_empty() && bytes + size > budget {
                        break;
                    }
                    let source = match self.records.get(&cursor) {
                        Some(record) => Source::Held(Part::Record(Arc::clone(record))),
                        None => match self.part_source(entry.stored) {
                            Some(source) => source,
                            None => break,
                        },
                    };
                    bytes += size;
                    sources.push(source);
                    cursor = entry.parent;
                }
                if sources.is_empty() {
                    self.park(Request { key, reply });
                    return;
                }
                Box::pin(async move {
                    let mut records: Vec<Arc<TipRecord<H::Digest>>> =
                        Vec::with_capacity(sources.len());
                    for source in sources {
                        match source.get().await.ok()? {
                            Part::Record(record) => records.push(record),
                            _ => return None,
                        }
                    }
                    Some(wire::encode(&Records::Records(records)))
                })
            }
            Key::Proofs { after } => {
                let Some((id, history)) = self.served_proof(after) else {
                    return;
                };
                let Some(lqc) = self.lqc_source(id) else {
                    self.park(Request { key, reply });
                    return;
                };
                let record = match self.records.get(&history) {
                    Some(record) => Source::Held(Part::Record(Arc::clone(record))),
                    None => {
                        let Some(entry) = self.proofs.index().record(&history).copied() else {
                            return;
                        };
                        let Some(source) = self.part_source(entry.stored) else {
                            self.park(Request { key, reply });
                            return;
                        };
                        source
                    }
                };
                Box::pin(async move {
                    let (Part::Lqc(artifact), Part::Record(record)) =
                        (lqc.get().await.ok()?, record.get().await.ok()?)
                    else {
                        return None;
                    };
                    let Artifact::Lqc(lqc) = artifact.as_ref() else {
                        return None;
                    };
                    let mut buf = Vec::with_capacity(lqc.encode_size() + record.encode_size());
                    commonware_codec::Write::write(lqc, &mut buf);
                    commonware_codec::Write::write(record.as_ref(), &mut buf);
                    Some(Bytes::from(buf))
                })
            }
            Key::Lqc { id } => {
                let Some(lqc) = self.lqc_source(id) else {
                    if self.proofs.index().lqc(&id).is_some() {
                        self.park(Request { key, reply });
                    }
                    return;
                };
                Box::pin(async move {
                    let Part::Lqc(artifact) = lqc.get().await.ok()? else {
                        return None;
                    };
                    let Artifact::Lqc(lqc) = artifact.as_ref() else {
                        return None;
                    };
                    Some(wire::encode(lqc))
                })
            }
        };
        self.serving += 1;
        self.metrics.served.inc();
        self.spawn(
            "serve",
            async move {
                if let Some(bytes) = job.await {
                    let _ = reply.send(bytes);
                }
            },
            |()| Event::Served,
        );
    }

    /// Returns the L-QC a `Proofs` request is answered with, and its leader history.
    ///
    /// Without `after`, the strongest durable one whose history is connected; with it, the
    /// first one whose history is `after` or descends from it.
    fn served_proof(
        &self,
        after: Option<H::Digest>,
    ) -> Option<(CertificateId<H::Digest>, H::Digest)> {
        let index = self.proofs.index();
        // A client asking after a history holds that history's proofs: serve a later one.
        let from = match after {
            Some(after) => index.ordinal(&after)? + 1,
            None => 0,
        };
        // The newest durable L-QC of an ordinal's history.
        let newest = |ids: &[CertificateId<H::Digest>]| {
            ids.iter()
                .filter_map(|id| index.lqc(id).map(|entry| (*id, *entry)))
                .filter(|(_, entry)| self.proofs.durable(entry.stored))
                .max_by_key(|(_, entry)| entry.view)
                .map(|(id, entry)| (id, entry.history))
        };
        let mut levels = index.connected_from(from);
        match after {
            // The nearest proof.
            Some(_) => levels.find_map(|(_, ids)| newest(ids)),
            // The newest proof.
            None => levels.rev().find_map(|(_, ids)| newest(ids)),
        }
    }

    /// Keeps a request whose data cannot be read yet, while there is room.
    fn park(&mut self, request: Request<H::Digest>) {
        if self.parked.len() < self.limits.max_serving.get() {
            self.parked.push(request);
        }
    }

    /// Retries the parked requests, after storage progressed.
    pub(super) fn retry_parked(&mut self) {
        for request in std::mem::take(&mut self.parked) {
            self.on_request(request);
        }
    }

    /// Returns where a held block can be read for serving.
    fn block_source(
        &mut self,
        block: crate::multimmit::types::BlockRef<H::Digest>,
    ) -> Option<Source<E, Block<H, B>>> {
        if let Some(body) = self.hot.get(block) {
            return Some(Source::Held(Arc::clone(body)));
        }
        let stream = self.blocks.index().get(block)?.stream;
        let (access, location) = self.blocks.access(block)?;
        match access {
            Access::Ready(reader) => Some(Source::Read(reader, location)),
            Access::Open(open) => {
                self.spawn("open_blocks", open.run(), move |opened| {
                    Event::OpenedBlocks(stream, opened)
                });
                None
            }
            Access::Opening | Access::Uncut => None,
        }
    }

    /// Returns where a stored part can be read for serving.
    fn part_source(&mut self, stored: Stored) -> Option<Source<E, Part<S, H::Digest>>> {
        match self.proofs.access(stored) {
            Access::Ready(reader) => Some(Source::Read(reader, stored.location)),
            Access::Open(open) => {
                self.spawn("open_proofs", open.run(), Event::OpenedProofs);
                None
            }
            Access::Opening | Access::Uncut => None,
        }
    }

    /// Returns where an L-QC can be read for serving.
    fn lqc_source(
        &mut self,
        id: CertificateId<H::Digest>,
    ) -> Option<Source<E, Part<S, H::Digest>>> {
        if let Some(proof) = self.lqcs.get(&id) {
            return Some(Source::Held(Part::Lqc(Arc::clone(proof.artifact()))));
        }
        let stored = self.proofs.index().lqc(&id)?.stored;
        self.part_source(stored)
    }
}
