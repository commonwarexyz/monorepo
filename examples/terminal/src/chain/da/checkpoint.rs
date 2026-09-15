//! A private native QMDB owns the replica boundary and immutable signer decision.

use super::{Ballot, NativeReplica, sync::Transfer};
use crate::{
    chain::validator::{IO_BUFFER_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE},
    protocol::Deployment,
};
use anyhow::{Context as _, Result, ensure};
use bytes::BufMut;
use commonware_clearing::bajillion::{qmdb::StateRoot, replica::ReplicaHead};
use commonware_codec::{Buf, EncodeSize, Error, Read, ReadExt as _, Write};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{Spawner, buffer::paged::CacheRef};
use commonware_storage::{Context, journal::contiguous, merkle::mmr, qmdb::keyless};
use commonware_utils::NZU64;
use std::sync::Arc;

#[cfg(test)]
mod tests;

/// Native reconstruction starts protecting the finalized and pending suffix.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Retention {
    pub(crate) epoch: u64,
    pub(crate) state: u64,
    pub(crate) activity: u64,
    pub(crate) payouts: u64,
}
impl Write for Retention {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.state.write(buf);
        self.activity.write(buf);
        self.payouts.write(buf);
    }
}
impl commonware_codec::FixedSize for Retention {
    const SIZE: usize = 32;
}
impl Read for Retention {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            epoch: u64::read(buf)?,
            state: u64::read(buf)?,
            activity: u64::read(buf)?,
            payouts: u64::read(buf)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Checkpoint {
    pub(crate) deployment: Digest,
    pub(crate) genesis: StateRoot<Digest>,
    pub(crate) genesis_operations: u64,
    pub(crate) generation: u64,
    pub(crate) next: u64,
    pub(crate) batch: Option<Digest>,
    pub(crate) head: ReplicaHead<Digest>,
    pub(crate) retained: Retention,
}
impl Checkpoint {
    pub(crate) fn genesis<E: Context + Spawner>(
        deployment: &Deployment,
        replica: &NativeReplica<E>,
    ) -> Self {
        Self {
            deployment: *deployment.digest(),
            genesis: deployment.genesis().root(),
            genesis_operations: deployment.genesis().operations(),
            generation: 0,
            next: 0,
            batch: None,
            head: replica.head(),
            retained: Retention::default(),
        }
    }
    pub(crate) fn check(&self, deployment: &Deployment) -> Result<()> {
        ensure!(
            self.deployment == *deployment.digest()
                && self.genesis == deployment.genesis().root()
                && self.genesis_operations == deployment.genesis().operations()
                && self.batch.is_some() == (self.next != 0)
                && self.retained.epoch <= self.next
                && self.retained.state <= self.head.state.sync_boundary()
                && self.retained.activity <= self.head.logs.activity.floor
                && self.retained.payouts <= self.head.logs.payouts.floor,
            "replica checkpoint context mismatch"
        );
        Ok(())
    }
}
impl Write for Checkpoint {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        self.genesis.write(buf);
        self.genesis_operations.write(buf);
        self.generation.write(buf);
        self.next.write(buf);
        self.batch.write(buf);
        self.head.write(buf);
        self.retained.write(buf);
    }
}
impl EncodeSize for Checkpoint {
    fn encode_size(&self) -> usize {
        self.deployment.encode_size()
            + self.genesis.encode_size()
            + 24
            + self.batch.encode_size()
            + self.head.encode_size()
            + self.retained.encode_size()
    }
}
impl Read for Checkpoint {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            deployment: Digest::read(buf)?,
            genesis: StateRoot::read(buf)?,
            genesis_operations: u64::read(buf)?,
            generation: u64::read(buf)?,
            next: u64::read(buf)?,
            batch: Option::read(buf)?,
            head: ReplicaHead::read(buf)?,
            retained: Retention::read(buf)?,
        })
    }
}

/// A decision outlives disposal of its candidate until canonical epoch advancement.
/// Both complete targets are durable before this metadata can select them.
#[derive(Clone)]
pub(super) struct Manifest {
    pub(super) canonical: Transfer,
    pub(super) candidate: Option<Transfer>,
    pub(super) decision: Option<Ballot>,
    pub(super) garbage: Option<u64>,
}
impl Manifest {
    pub(super) fn complete(&self) -> &Transfer {
        self.candidate.as_ref().unwrap_or(&self.canonical)
    }
    pub(super) fn check(&self, deployment: &Deployment) -> Result<()> {
        self.canonical.check(deployment)?;
        if let Some(candidate) = &self.candidate {
            candidate.check(deployment)?;
            let decision = self
                .decision
                .as_ref()
                .context("candidate has no voting decision")?;
            ensure!(
                candidate.checkpoint.generation == self.canonical.checkpoint.generation
                    && candidate.checkpoint.next
                        == self
                            .canonical
                            .checkpoint
                            .next
                            .checked_add(1)
                            .context("epoch overflow")?
                    && candidate.checkpoint.batch
                        == Some(decision.header.batch_id::<Sha256>().into_digest())
                    && decision.epoch == self.canonical.checkpoint.next
                    && decision.context.predecessor_root()
                        == &self.canonical.checkpoint.head.state.root()
                    && decision.context.predecessor_logs() == &self.canonical.checkpoint.head.logs
                    && decision.roots.successor == candidate.checkpoint.head.state.root()
                    && decision.roots.successor_operations
                        == candidate.checkpoint.head.state.operations()
                    && decision.roots.successor_sync_boundary
                        == candidate.checkpoint.head.state.sync_boundary()
                    && decision.roots.logs() == candidate.checkpoint.head.logs,
                "candidate checkpoint does not match its voting decision"
            );
        }
        if let Some(decision) = &self.decision {
            decision.check()?;
            ensure!(
                decision.deployment == *deployment.digest()
                    && decision.epoch >= self.canonical.checkpoint.next,
                "obsolete voting decision"
            );
        }
        ensure!(
            self.garbage != Some(self.canonical.checkpoint.generation),
            "active generation marked disposable"
        );
        Ok(())
    }
}
impl Write for Manifest {
    fn write(&self, buf: &mut impl BufMut) {
        self.canonical.write(buf);
        self.candidate.write(buf);
        self.decision.write(buf);
        self.garbage.write(buf);
    }
}
impl EncodeSize for Manifest {
    fn encode_size(&self) -> usize {
        self.canonical.encode_size()
            + self.candidate.encode_size()
            + self.decision.encode_size()
            + self.garbage.encode_size()
    }
}
impl Read for Manifest {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            canonical: Transfer::read(buf)?,
            candidate: Option::read(buf)?,
            decision: Option::read(buf)?,
            garbage: Option::read(buf)?,
        })
    }
}

type Native<E> =
    keyless::variable::CompactDb<mmr::Family, E, Arc<Manifest>, Sha256, (), Sequential>;

pub(super) struct Store<E: Context>(Native<E>);
impl<E: Context> Store<E> {
    pub(super) async fn open(context: E, prefix: &str, deployment: &Digest) -> Result<Self> {
        let cfg = keyless::variable::CompactConfig {
            strategy: Sequential,
            witness: contiguous::variable::Config {
                partition: format!("{prefix}-{deployment}-ack-control"),
                items_per_section: NZU64!(16),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: IO_BUFFER_SIZE,
                replay_buffer: IO_BUFFER_SIZE,
            },
            commit_codec_config: (),
        };
        let db = Native::init(context, cfg).await?;
        let size = db.size();
        Ok(Self(db.prune(size).await?))
    }
    pub(super) fn get(&self) -> Option<Arc<Manifest>> {
        self.0.get_metadata()
    }
    pub(super) async fn put(self, manifest: Manifest) -> Result<Self> {
        let batch = self
            .0
            .new_batch()
            .merkleize(&self.0, Some(Arc::new(manifest)), self.0.size())
            .await;
        let (db, _) = self.0.apply_batch(batch).await?;

        // Native pruning makes the surviving Commit durable before deleting older sections.
        // The private decision remains available even when the three public stores rewind.
        let size = db.size();
        Ok(Self(db.prune(size).await?))
    }
    /// Reserve the disposable generation before its first native write.
    pub(super) async fn stage(self, generation: u64) -> Result<Self> {
        let mut manifest = self.get().context("missing checkpoint")?.as_ref().clone();
        ensure!(
            manifest.garbage.is_none() && generation != manifest.canonical.checkpoint.generation,
            "generation already owned"
        );
        manifest.garbage = Some(generation);
        self.put(manifest).await
    }
    /// Clear a disposable generation after all of its native partitions are gone.
    pub(super) async fn retired(self) -> Result<Self> {
        let mut manifest = self.get().context("missing checkpoint")?.as_ref().clone();
        manifest.garbage = None;
        self.put(manifest).await
    }
}
