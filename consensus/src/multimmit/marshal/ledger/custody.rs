//! Custody and lookups: staged and subscribed blocks, block and certificate lookups, progress.
//!
//! A staged block is written to the custody stream at once and its token resolves when the cut
//! covering it is durable. A subscription resolves when the exact block is held durably; the
//! broadcast buffer can supply it, but a subscription never starts a peer fetch.

use super::{Error, Event, Ledger, PartKey};
use crate::{
    Reporter,
    multimmit::{
        actors::util::Completion,
        marshal::{
            input::{Message, Reply},
            store::blocks::{Inserted, Stream},
            types::{LqcVerifier, MarshalProgress, Update},
            wire::Key,
        },
        scheme::Scheme,
        types::{Artifact, BlockRef, Body, CertificateId, Lqc, TransactionBlock},
    },
    types::OutputIndex,
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Hasher, PublicKey};
use commonware_macros::select;
use commonware_resolver::Resolver;
use commonware_runtime::Spawner;
use commonware_storage::Context;
use commonware_utils::channel::oneshot;
use std::sync::Arc;

/// A certificate request waiting for its L-QC.
pub(super) struct CertificateWaiter<S: Scheme, D: commonware_cryptography::Digest> {
    id: CertificateId<D>,
    fetch: bool,
    reply: Reply<Option<Arc<Lqc<S, D>>>>,
}

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
    /// Takes a public request.
    pub(super) fn on_message(&mut self, message: Message<H, S, B>) -> Result<(), Error> {
        match message {
            Message::Stage { block, reply } => {
                let reference = block.reference();
                let pending = self.blocks.pending_bytes(Stream::Custody);
                if pending > 0
                    && !self.blocks.known(reference)
                    && pending + block.encode_size() as u64
                        > self.limits.max_staged_bytes.get() as u64
                {
                    let _ = reply.send(Err(Error::Busy));
                    return Ok(());
                }
                match self.blocks.insert(Stream::Custody, Arc::clone(&block)) {
                    Inserted::Refused => {
                        let _ = reply.send(Err(Error::Rejected(
                            "the block is of another epoch or chain, or below retention",
                        )));
                        return Ok(());
                    }
                    Inserted::Queued | Inserted::Known => {}
                }
                self.on_block(block);
                let (token, custody) = Completion::channel(|| Error::Closed);
                if self.blocks.durable(reference) {
                    let _ = token.send(Ok(()));
                } else {
                    self.custody.entry(reference).or_default().push(token);
                }
                let _ = reply.send(Ok(custody));
            }
            Message::Get { block, reply } => self.lookup(block, false, reply),
            Message::Fetch { block, reply } => {
                let (sender, receiver) = commonware_utils::channel::oneshot::channel();
                self.lookup(block, true, sender);
                // A fetch always answers with a block: forward once it is found.
                self.spawn(
                    "fetch_reply",
                    async move {
                        let result = match receiver.await {
                            Ok(Ok(Some(block))) => Ok(block),
                            Ok(Ok(None)) | Err(_) => Err(Error::Closed),
                            Ok(Err(error)) => Err(error),
                        };
                        let _ = reply.send(result);
                    },
                    |()| Event::Nothing,
                );
            }
            Message::Subscribe { block, reply } => {
                if self.blocks.durable(block) {
                    if let Some(body) = self.hot.get(block).cloned() {
                        let _ = reply.send(Ok(body));
                        return Ok(());
                    }
                }
                self.subscribers.entry(block).or_default().push(reply);
                // The broadcast buffer may hold the block; a subscription never fetches it
                // from peers.
                if !self.blocks.known(block) && !self.subscribing.contains_key(&block) {
                    let receiver = self.buffer.subscribe(block.digest());
                    let (cancel, canceled) = oneshot::channel::<()>();
                    self.subscribing.insert(block, cancel);
                    self.spawn(
                        "subscribe",
                        async move {
                            select! {
                                found = receiver => found.ok(),
                                _ = canceled => None,
                            }
                        },
                        move |found| {
                            Event::Buffered(
                                block,
                                None,
                                found.map(|digested| digested.inner_shared()),
                            )
                        },
                    );
                }
            }
            Message::Certificate { id, fetch, reply } => {
                self.certificate_waiters
                    .push(CertificateWaiter { id, fetch, reply });
            }
            Message::FloorAt { at, reply } => self.floor_at(at, reply),
            Message::Install { floor, reply } => self.install_floor(floor, reply),
            Message::Prune { below, reply } => self.prune(below, reply),
            Message::Progress { reply } => {
                let durable = self.meta.durable();
                let _ = reply.send(Ok(MarshalProgress {
                    floor: durable.floor,
                    proven: OutputIndex::new(self.order.cut().index()),
                    delivered: OutputIndex::new(
                        self.delivered
                            .iter()
                            .map(|block| block.height().get())
                            .sum(),
                    ),
                    acknowledged: OutputIndex::new(durable.ack.index()),
                }));
            }
        }
        Ok(())
    }

    /// Answers with the exact block when it is held or, with `fetch`, once peers supply it.
    fn lookup(
        &mut self,
        block: BlockRef<H::Digest>,
        fetch: bool,
        reply: Reply<Option<Arc<TransactionBlock<H, B>>>>,
    ) {
        if let Some(body) = self.hot.get(block).or_else(|| self.blocks.pending(block)) {
            let _ = reply.send(Ok(Some(Arc::clone(body))));
            return;
        }
        if self.blocks.index().get(block).is_some() {
            self.waiting.entry(block).or_default().push(reply);
            self.read_body(block);
            return;
        }
        if !fetch {
            let _ = reply.send(Ok(None));
            return;
        }
        self.waiting.entry(block).or_default().push(reply);
        self.fetch_block(block);
    }

    /// Fetches exactly `block` from peers.
    pub(super) fn fetch_block(&mut self, block: BlockRef<H::Digest>) {
        self.fetching.insert(block);
        self.fetch_range(block, block.height());
    }

    /// Resolves custody tokens and subscriptions whose blocks are durable, and answers
    /// certificate requests.
    pub(super) fn drive_custody(&mut self) {
        let blocks = &self.blocks;
        let durable = self
            .custody
            .keys()
            .chain(self.subscribers.keys())
            .filter(|block| blocks.durable(**block))
            .copied()
            .collect::<Vec<_>>();
        for block in durable {
            if let Some(tokens) = self.custody.remove(&block) {
                for token in tokens {
                    let _ = token.send(Ok(()));
                }
            }
            if self.subscribers.contains_key(&block) {
                match self.hot.get(block).cloned() {
                    Some(body) => {
                        for reply in self.subscribers.remove(&block).into_iter().flatten() {
                            let _ = reply.send(Ok(Arc::clone(&body)));
                        }
                    }
                    None => self.read_body(block),
                }
            }
        }
        // Dropped callers no longer wait.
        self.subscribers.retain(|_, replies| {
            replies.retain(|reply| !reply.is_closed());
            !replies.is_empty()
        });
        let (subscribers, blocks) = (&self.subscribers, &self.blocks);
        self.subscribing
            .retain(|block, _| subscribers.contains_key(block) && !blocks.known(*block));
        self.waiting.retain(|_, replies| {
            replies.retain(|reply| !reply.is_closed());
            !replies.is_empty()
        });

        let waiters = std::mem::take(&mut self.certificate_waiters);
        for waiter in waiters {
            if waiter.reply.is_closed() {
                continue;
            }
            if let Some(proof) = self.lqcs.get(&waiter.id) {
                let Artifact::Lqc(lqc) = proof.artifact().as_ref() else {
                    unreachable!("proofs hold L-QCs");
                };
                let _ = waiter.reply.send(Ok(Some(Arc::new(lqc.clone()))));
                continue;
            }
            if let Some(entry) = self.proofs.index().lqc(&waiter.id).copied() {
                self.read_part(PartKey::Lqc(waiter.id), entry.stored);
            } else if waiter.fetch {
                self.fetch(Key::Lqc { id: waiter.id }, 0);
            } else {
                let _ = waiter.reply.send(Ok(None));
                continue;
            }
            self.certificate_waiters.push(waiter);
        }
    }

    /// Takes a block found in the broadcast buffer, or fetches it from peers when it was not
    /// there and is wanted down to `low`.
    pub(super) fn on_buffered(
        &mut self,
        block: BlockRef<H::Digest>,
        low: Option<crate::types::Height>,
        found: Option<Arc<TransactionBlock<H, B>>>,
    ) {
        match low {
            Some(_) => self.buffering.remove(&block),
            None => self.subscribing.remove(&block).is_some(),
        };
        match found {
            Some(body) if body.reference() == block => {
                self.metrics.buffered_blocks.inc();
                self.insert_block(Stream::Custody, body);
            }
            _ => {
                if let Some(low) = low {
                    self.fetch_range(block, low);
                }
            }
        }
    }
}
