//! Owned immutable proof snapshot of a database's operations log.

use crate::{
    Context,
    journal::{authenticated, contiguous::Contiguous},
    merkle::{Family, Location, Proof},
    qmdb::{Error, operation::Floored},
};
use commonware_cryptography::Hasher;
use core::num::NonZeroU64;
use std::ops::Range;

/// Owned immutable proof snapshot of a database's operations log, with bounds frozen at capture.
///
/// Produced by a database's `snapshot`. It serves proofs against the captured state while
/// the source database continues to append, sync, and prune, and it exposes no mutation. It
/// carries only the operations log: no keyed index, activity bitmap, or grafted tree.
///
/// Rewinding the source database in place while a snapshot is alive leaves reads from the rewound
/// range observing unspecified contents.
#[commonware_macros::stability(ALPHA)]
pub struct Snapshot<F, E, Op, R, H>
where
    F: Family,
    E: Context,
    R: Contiguous<Item = Op>,
    H: Hasher,
{
    /// Owned view of the operations log.
    log: authenticated::Snapshot<F, E, R, H>,

    /// Root of the database at capture.
    root: H::Digest,
}

impl<F, E, Op, R, H> Snapshot<F, E, Op, R, H>
where
    F: Family,
    E: Context,
    Op: Floored<F> + Send,
    R: Contiguous<Item = Op>,
    H: Hasher,
{
    /// Wrap a frozen log view and the root committed at capture.
    pub(crate) const fn new(log: authenticated::Snapshot<F, E, R, H>, root: H::Digest) -> Self {
        Self { log, root }
    }

    /// Return the root of the database at capture.
    pub const fn root(&self) -> H::Digest {
        self.root
    }

    /// Return the number of operations visible to this snapshot.
    pub fn op_count(&self) -> Location<F> {
        self.log.size()
    }

    /// Return [start, end) where `start` and `end - 1` are the Locations of the oldest and
    /// newest operations visible to this snapshot.
    pub fn bounds(&self) -> Range<Location<F>> {
        let bounds = Contiguous::bounds(&self.log);
        Location::new(bounds.start)..Location::new(bounds.end)
    }

    /// Generate a proof of operations starting at `start_loc`, against this snapshot's frozen
    /// state.
    #[allow(clippy::type_complexity)]
    pub async fn proof(
        &self,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<Op>), Error<F>> {
        self.historical_proof(self.op_count(), start_loc, max_ops)
            .await
    }

    /// Analogous to [Self::proof], but with respect to the state of the database when it had
    /// `op_count` operations, bounded by this snapshot's frozen size.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb.snapshot.historical_proof",
        level = "info",
        skip_all,
        fields(
            op = std::any::type_name::<Op>(),
            op_count = *op_count,
            start_loc = *start_loc,
            max_ops = max_ops.get(),
        ),
    )]
    pub async fn historical_proof(
        &self,
        op_count: Location<F>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<Op>), Error<F>> {
        if op_count > self.log.size() {
            return Err(crate::merkle::Error::RangeOutOfBounds(op_count).into());
        }

        let inactive_peaks = crate::qmdb::inactive_peaks_at::<F, _>(&self.log, op_count).await?;

        Ok(self
            .log
            .historical_proof(op_count, start_loc, max_ops, inactive_peaks)
            .await?)
    }

    /// Return the pinned Merkle nodes for a lower operation boundary of `loc`, bounded by this
    /// snapshot's frozen state.
    pub async fn pinned_nodes_at(&self, loc: Location<F>) -> Result<Vec<H::Digest>, Error<F>> {
        Ok(self.log.pinned_nodes_at(loc).await?)
    }
}
