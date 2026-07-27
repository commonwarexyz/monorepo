//! Owned immutable snapshot of a compact database's durable compact state.

use crate::{
    Context,
    merkle::{Family, Location},
    qmdb::{
        Error,
        compact::witness::{self, VerifiedWitness, Witness},
        sync::compact::{ServeError, State, Target},
    },
};
use commonware_codec::{Decode as _, Read};
use commonware_cryptography::Digest;
use core::marker::PhantomData;

/// Owned immutable snapshot of a compact database's durable compact state, frozen at capture.
///
/// Produced by a compact database's `compact_snapshot`. It serves compact-sync state requests
/// against the captured tip witness and, for targets below the tip, against a frozen reader
/// over the witness journal's entries retained at capture — matching the live serve path,
/// whose below-tip serving covers syncing clients whose targets trail the source by their
/// fetch latency. Owned blob handles keep captured entries readable across later prunes.
/// Compact databases discard historical operations, so this snapshot serves only retained
/// commits' compact state — not operation ranges.
///
/// Matching is by leaf count alone, exactly like the live path: every served entry is this
/// database's own checksummed durable write, and the client verifies the payload against its
/// own target root, so a divergent target at a retained leaf count surfaces as client-side
/// rejection rather than a serve-time check.
#[commonware_macros::stability(ALPHA)]
pub struct StateSnapshot<F: Family, E: Context, D: Digest, Op, Cfg> {
    /// The captured verified witness, the last durably persisted commit at capture.
    witness: VerifiedWitness<F, D>,

    /// Frozen reader over the witness journal's retained entries at capture. `None` when a
    /// compact-sync import was pending at capture (the journal still held the previous
    /// partition's contents), leaving only the tip servable.
    retained: Option<witness::Reader<E, F, D>>,

    /// Codec configuration for decoding a served entry's commit operation.
    codec_config: Cfg,

    /// Marker for the operation type served by [Self::compact_state].
    _op: PhantomData<Op>,
}

impl<F, E, D, Op, Cfg> StateSnapshot<F, E, D, Op, Cfg>
where
    F: Family,
    E: Context,
    D: Digest,
    Op: Read<Cfg = Cfg>,
{
    /// Wrap a captured tip witness, the frozen journal reader (if capturable), and the codec
    /// configuration needed to decode served commits.
    pub(crate) const fn new(
        witness: VerifiedWitness<F, D>,
        retained: Option<witness::Reader<E, F, D>>,
        codec_config: Cfg,
    ) -> Self {
        Self {
            witness,
            retained,
            codec_config,
            _op: PhantomData,
        }
    }

    /// Return the root committed by the captured witness.
    pub const fn root(&self) -> D {
        self.witness.root
    }

    /// Return the committed leaf count of the captured witness.
    pub const fn leaf_count(&self) -> Location<F> {
        self.witness.leaf_count()
    }

    /// Return the compact-sync target described by the captured witness.
    pub const fn target(&self) -> Target<F, D> {
        self.witness.target()
    }

    /// Return the compact-sync state for `target`, or a stale-target error if neither the
    /// captured tip nor a retained below-tip entry commits it. Semantics match the live
    /// database's serve path at capture.
    pub async fn compact_state(
        &self,
        target: Target<F, D>,
    ) -> Result<State<F, Op, D>, ServeError<F, D>> {
        let stale = || ServeError::StaleTarget {
            requested: target.clone(),
            current: self.target(),
        };
        let entry = if target.leaf_count == self.witness.leaf_count() {
            self.witness.witness.clone()
        } else {
            let Some(retained) = &self.retained else {
                return Err(stale());
            };
            witness::entry_at(retained, target.leaf_count)
                .await
                .map_err(ServeError::Database)?
                .ok_or_else(stale)?
        };
        let Witness {
            op_bytes,
            proof: last_commit_proof,
            pinned_nodes,
        } = entry;
        let op = Op::decode_cfg(op_bytes.as_ref(), &self.codec_config)
            .map_err(|_| ServeError::Database(Error::DataCorrupted("invalid commit operation")))?;
        Ok(State {
            leaf_count: target.leaf_count,
            pinned_nodes,
            last_commit_op: op,
            last_commit_proof,
        })
    }
}
