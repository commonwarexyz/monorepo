//! One failure boundary for balance state and both native flat logs.

use super::{
    logs::{self, ActivityInput, Floors, Heads, Logs, PreparedLogs},
    qmdb::{self, Mutations, PreparedState, State, StateHead},
    transition::WithdrawalOutput,
};
use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::{Sequential, Strategy};
use commonware_runtime::Spawner;
use commonware_storage::Context;
use thiserror::Error;

/// Physical configuration for all three native stores.
///
/// Every explicit partition and native-derived partition name must be unique across the state and
/// both logs.
#[derive(Clone)]
pub struct Config<S: Strategy = Sequential> {
    /// Current Ordered balance state.
    pub state: qmdb::Config<S>,
    /// Activity and payout logs.
    pub logs: logs::Config<S>,
}

/// Observed heads of the three native stores.
///
/// The application may persist this tuple as an authenticated checkpoint after completing all
/// native durability barriers.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ReplicaHead<D: Digest> {
    /// Current Ordered balance head.
    pub state: StateHead<D>,
    /// Both flat-log heads.
    pub logs: Heads<D>,
}

impl<D: Digest> Write for ReplicaHead<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.state.write(buf);
        self.logs.write(buf);
    }
}

impl<D: Digest> FixedSize for ReplicaHead<D> {
    const SIZE: usize = StateHead::<D>::SIZE + Heads::<D>::SIZE;
}

impl<D: Digest> Read for ReplicaHead<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            state: StateHead::read(buf)?,
            logs: Heads::read(buf)?,
        })
    }
}

/// The three native stores governed by one application checkpoint.
pub struct Replica<E, H, P, S = Sequential>
where
    E: Context + Spawner,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    state: State<E, H, S>,
    logs: Logs<E, H, P, S>,
}

/// Independently owned state and log handles.
pub type Parts<E, H, P, S> = (State<E, H, S>, Logs<E, H, P, S>);

impl<E, H, P, S> Replica<E, H, P, S>
where
    E: Context + Spawner,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    /// Open all native stores and report their independently recovered heads.
    pub async fn open(context: E, config: Config<S>) -> Result<Self, Error> {
        let mut partitions = qmdb::physical_partitions(&config.state);
        partitions.extend(logs::physical_partitions(&config.logs));
        partitions.sort_unstable();
        if partitions.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::Partition);
        }
        let state = State::open(context.child("state"), config.state).await?;
        let logs = Logs::open(context.child("logs"), config.logs).await?;
        Ok(Self { state, logs })
    }

    /// Assemble already-open stores without introducing another storage representation.
    pub const fn from_parts(state: State<E, H, S>, logs: Logs<E, H, P, S>) -> Self {
        Self { state, logs }
    }

    /// Return the Current Ordered state.
    pub const fn state(&self) -> &State<E, H, S> {
        &self.state
    }

    /// Return the two flat logs.
    pub const fn logs(&self) -> &Logs<E, H, P, S> {
        &self.logs
    }

    /// Return the independently observed native heads.
    pub const fn head(&self) -> ReplicaHead<H::Digest> {
        ReplicaHead {
            state: *self.state.head(),
            logs: *self.logs.head(),
        }
    }

    /// Return the independently native store owners.
    pub fn into_parts(self) -> Parts<E, H, P, S> {
        (self.state, self.logs)
    }

    /// Prepare one aligned candidate without mutating any store.
    pub async fn prepare(
        &self,
        predecessor: &ReplicaHead<H::Digest>,
        mutations: Mutations,
        activity: ActivityInput<P, H::Digest>,
        outputs: Vec<WithdrawalOutput>,
        floors: Floors,
    ) -> Result<PreparedReplica<P, H::Digest, S>, Error> {
        if predecessor != &self.head() {
            return Err(Error::Predecessor);
        }
        let (state, logs) = logs::join(
            self.state.prepare(&predecessor.state, mutations),
            self.logs
                .prepare(&predecessor.logs, activity, outputs, floors),
        )
        .await;
        Ok(PreparedReplica::new(state?, logs?))
    }

    /// Apply all three candidates. Any error consumes the entire replica owner.
    pub async fn apply(self, prepared: PreparedReplica<P, H::Digest, S>) -> Result<Self, Error> {
        if prepared.predecessor() != self.head() {
            return Err(Error::Predecessor);
        }
        let (prepared_state, prepared_logs) = prepared.into_parts();
        let (state, logs) = logs::join(
            self.state.apply(prepared_state),
            self.logs.apply(prepared_logs),
        )
        .await;
        Ok(Self {
            state: state?,
            logs: logs?,
        })
    }

    /// Durably commit applied operations in all three stores.
    ///
    /// Native recovery reconstructs auxiliary state that has not been synchronized. Every commit
    /// completes before this call returns; any error consumes the entire replica owner.
    pub async fn commit(self) -> Result<Self, Error> {
        let (state, logs) = logs::join(self.state.commit(), self.logs.commit()).await;
        Ok(Self {
            state: state?,
            logs: logs?,
        })
    }

    /// Fully synchronize all three stores, including their auxiliary recovery state.
    pub async fn sync(self) -> Result<Self, Error> {
        let (state, logs) = logs::join(self.state.sync(), self.logs.sync()).await;
        Ok(Self {
            state: state?,
            logs: logs?,
        })
    }

    /// Rewind every ahead store to a shared checkpoint and make the alignment durable.
    ///
    /// A store already at the target takes its native no-op path. Any error consumes the entire
    /// replica; reopen before retrying.
    pub async fn rewind(mut self, target: &ReplicaHead<H::Digest>) -> Result<Self, Error> {
        self.state = self.state.rewind(&target.state).await?;
        self.logs = self.logs.rewind(&target.logs).await?;
        if self.head() != *target {
            return Err(Error::Predecessor);
        }
        self.sync().await
    }

    /// Prune all stores only after the application has published this live shared checkpoint.
    pub async fn prune(
        mut self,
        checkpoint: &ReplicaHead<H::Digest>,
        state_cut: u64,
        log_cuts: Floors,
    ) -> Result<Self, Error> {
        if self.head() != *checkpoint {
            return Err(Error::Predecessor);
        }
        self.state = self.state.prune(state_cut).await?;
        self.logs = self.logs.prune(log_cuts).await?;
        Ok(self)
    }

    /// Destroy all three native partitions in an obsolete physical generation.
    pub async fn destroy(self) -> Result<(), Error> {
        let (state, logs) = self.into_parts();
        let state_result = state.destroy().await;
        let logs_result = logs.destroy().await;
        state_result?;
        logs_result?;
        Ok(())
    }
}

/// Prepared candidates for all three native stores.
pub struct PreparedReplica<P: PublicKey, D: Digest, S: Strategy = Sequential> {
    state: PreparedState<D, S>,
    logs: PreparedLogs<P, D, S>,
}

impl<P: PublicKey, D: Digest, S: Strategy> PreparedReplica<P, D, S> {
    /// Bind independently prepared batches into one application transition.
    pub const fn new(state: PreparedState<D, S>, logs: PreparedLogs<P, D, S>) -> Self {
        Self { state, logs }
    }

    /// Return the prepared balance state.
    pub const fn state(&self) -> &PreparedState<D, S> {
        &self.state
    }

    /// Return both prepared logs.
    pub const fn logs(&self) -> &PreparedLogs<P, D, S> {
        &self.logs
    }

    /// Return the complete candidate head.
    pub const fn head(&self) -> ReplicaHead<D> {
        ReplicaHead {
            state: *self.state.head(),
            logs: *self.logs.head(),
        }
    }

    /// Return the exact common predecessor.
    pub const fn predecessor(&self) -> ReplicaHead<D> {
        ReplicaHead {
            state: *self.state.predecessor(),
            logs: *self.logs.predecessor(),
        }
    }

    /// Split into the native prepared batches for evidence extraction or application.
    pub fn into_parts(self) -> (PreparedState<D, S>, PreparedLogs<P, D, S>) {
        (self.state, self.logs)
    }
}

/// Failure to prepare or mutate the combined native replica.
#[derive(Debug, Error)]
pub enum Error {
    /// Physical state and log partitions overlap.
    #[error("replica partitions must be distinct")]
    Partition,
    /// Current Ordered balance storage failed.
    #[error("replica state: {0}")]
    State(#[from] qmdb::Error),
    /// A flat log failed.
    #[error("replica logs: {0}")]
    Logs(#[from] logs::Error),
    /// The candidate or recovery target does not identify this exact replica prefix.
    #[error("replica predecessor does not match")]
    Predecessor,
}
