//! Points around the persistence actor's storage operations where a test can observe or pause it.

use crate::multimmit::machine::PersistJob;
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_runtime::Clock;
use std::{
    future::{Future, ready},
    time::SystemTime,
};

/// Points around the persistence actor's storage operations where a test can observe or pause it.
pub(crate) trait Hooks: Clone + Send + Sync + 'static {
    /// Identifies one append to the hooks that follow it.
    type Point: Copy + Send + Sync + 'static;

    /// Observes one append before it is written.
    fn appending<V: Variant, D: Digest>(&self, job: &PersistJob<V, D>) -> Self::Point;

    /// Runs immediately before the append at `point` is written.
    fn before_append(
        &self,
        _point: Self::Point,
        _clock: &impl Clock,
    ) -> impl Future<Output = ()> + Send {
        ready(())
    }

    /// Runs immediately after the append at `point` was written at `appended_at`.
    fn after_append(
        &self,
        _point: Self::Point,
        _appended_at: SystemTime,
    ) -> impl Future<Output = ()> + Send {
        ready(())
    }

    /// Runs immediately before the sync covering through `point` starts at `started_at`.
    fn before_start_sync(
        &self,
        _point: Self::Point,
        _started_at: SystemTime,
    ) -> impl Future<Output = ()> + Send {
        ready(())
    }

    /// Runs immediately after the sync covering through `point` completed.
    fn after_sync(
        &self,
        _point: Self::Point,
        _clock: &impl Clock,
    ) -> impl Future<Output = ()> + Send {
        ready(())
    }

    /// Runs immediately before the journal rolls.
    fn before_roll(&self, _clock: &impl Clock) -> impl Future<Output = ()> + Send {
        ready(())
    }

    /// Runs immediately before the journal prunes, returning the prune's ordinal.
    fn before_prune(&self, _clock: &impl Clock) -> impl Future<Output = u64> + Send {
        ready(0)
    }

    /// Runs immediately after the prune with `ordinal` completed.
    fn after_prune(&self, _ordinal: u64, _clock: &impl Clock) -> impl Future<Output = ()> + Send {
        ready(())
    }
}

/// Hooks that observe nothing and never pause.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NoHooks;

impl Hooks for NoHooks {
    type Point = ();

    fn appending<V: Variant, D: Digest>(&self, _job: &PersistJob<V, D>) {}
}
