//! Owned immutable snapshot of a compact database's durable compact state.

use crate::{
    merkle::{Family, Location},
    qmdb::{
        Error,
        compact::witness::{VerifiedWitness, Witness},
        sync::compact::{ServeError, State, Target},
    },
};
use commonware_codec::{Decode as _, Read};
use commonware_cryptography::Digest;
use core::marker::PhantomData;

/// Owned immutable snapshot of a compact database's durable compact state, frozen at capture.
///
/// Produced by a compact database's `compact_snapshot`. It serves compact-sync state requests
/// against the captured witness while the source database continues to mutate and persist, and
/// it exposes no mutation. Compact databases discard historical operations, so this snapshot
/// serves only the captured commit's compact state — not operation ranges.
#[commonware_macros::stability(ALPHA)]
pub struct StateSnapshot<F: Family, D: Digest, Op, Cfg> {
    /// The captured verified witness, the last durably persisted commit at capture.
    witness: VerifiedWitness<F, D>,

    /// Codec configuration for decoding the witness's commit operation.
    codec_config: Cfg,

    /// Marker for the operation type served by [Self::compact_state].
    _op: PhantomData<Op>,
}

impl<F, D, Op, Cfg> StateSnapshot<F, D, Op, Cfg>
where
    F: Family,
    D: Digest,
    Op: Read<Cfg = Cfg>,
{
    /// Wrap a captured witness and the codec configuration needed to decode its commit.
    pub(crate) const fn new(witness: VerifiedWitness<F, D>, codec_config: Cfg) -> Self {
        Self {
            witness,
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

    /// Return the compact-sync state for `target`, or a stale-target error if the captured
    /// witness does not match. Semantics match the live database's serve path at capture.
    pub fn compact_state(&self, target: Target<F, D>) -> Result<State<F, Op, D>, ServeError<F, D>> {
        if target.root != self.witness.root || target.leaf_count != self.witness.leaf_count() {
            return Err(ServeError::StaleTarget {
                requested: target,
                current: self.target(),
            });
        }
        let Witness {
            op_bytes,
            proof: last_commit_proof,
            pinned_nodes,
        } = self.witness.witness.clone();
        let op = Op::decode_cfg(op_bytes.as_ref(), &self.codec_config)
            .map_err(|_| ServeError::Database(Error::DataCorrupted("invalid commit operation")))?;
        Ok(State {
            leaf_count: self.witness.leaf_count(),
            pinned_nodes,
            last_commit_op: op,
            last_commit_proof,
        })
    }
}
