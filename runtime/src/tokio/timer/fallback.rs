//! Tokio-backed fallback timers for unsupported native targets.

use crate::utils::Panicker;
use futures::future::Either;
use std::{
    convert::Infallible,
    future::Future,
    time::{Duration, SystemTime},
};
use tokio::runtime::{Builder as TokioBuilder, Runtime};

/// Descriptor-free timer builder for targets that use Tokio timers.
pub(crate) struct Builder;

impl Builder {
    /// Leaves the Tokio builder unchanged and retains no affinity state.
    pub(crate) fn install(_runtime_builder: &mut TokioBuilder, _worker_threads: usize) -> Self {
        Self
    }

    /// Creates the descriptor-free fallback timer facade.
    pub(crate) fn build(
        self,
        _runtime: &Runtime,
        _panicker: Panicker,
    ) -> Result<Timer, Infallible> {
        Ok(Timer)
    }
}

/// Tokio-backed timer facade for unsupported native targets.
pub(crate) struct Timer;

impl Timer {
    /// Eagerly constructs a Tokio sleep for nonzero durations.
    pub(crate) fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        if duration.is_zero() {
            Either::Left(tokio::task::coop::consume_budget())
        } else {
            Either::Right(tokio::time::sleep(duration))
        }
    }

    /// Snapshots a wall-clock deadline once before constructing its sleep.
    pub(crate) fn sleep_until(
        &self,
        deadline: SystemTime,
    ) -> impl Future<Output = ()> + Send + 'static {
        let remaining = deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        self.sleep(remaining)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    /// Creates the descriptor-free fallback timer facade.
    fn timer() -> Timer {
        Timer
    }

    #[test]
    fn builder_constructs_descriptor_free_timer() {
        // Exercise the same two-phase builder sequence as runtime startup.
        let mut runtime_builder = TokioBuilder::new_current_thread();
        let timer_builder = Builder::install(&mut runtime_builder, 1);
        let runtime = runtime_builder.build().unwrap();
        let (panicker, _panicked) = Panicker::new(false);

        // Fallback construction requires no active reactor or driver state.
        timer_builder.build(&runtime, panicker).unwrap();
    }

    #[test]
    fn zero_and_past_sleeps_are_ready_on_first_poll() {
        // Construct the fallback facade without native driver state.
        let timer = timer();

        // Zero relative durations and past wall deadlines take the immediate
        // representation instead of constructing a Tokio timer.
        let zero = timer.sleep(Duration::ZERO);
        let past = timer.sleep_until(SystemTime::UNIX_EPOCH);

        // Both complete with fresh scheduler budget.
        assert_eq!(zero.now_or_never(), Some(()));
        assert_eq!(past.now_or_never(), Some(()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn immediate_sleep_loop_cooperates_with_other_tasks() {
        // Queue a peer behind a task that repeatedly awaits immediate sleeps.
        let timer = timer();
        let peer_ran = Arc::new(AtomicBool::new(false));
        let peer_flag = Arc::clone(&peer_ran);
        let peer = tokio::spawn(async move {
            peer_flag.store(true, Ordering::Release);
        });

        // Await more immediate sleeps than one Tokio cooperative budget.
        for _ in 0..1_024 {
            timer.sleep(Duration::ZERO).await;
            if peer_ran.load(Ordering::Acquire) {
                break;
            }
        }

        // Budget exhaustion yields to the already-runnable peer.
        assert!(peer_ran.load(Ordering::Acquire));
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn relative_and_wall_sleeps_start_at_construction() {
        // Construct relative and wall-clock sleeps without polling either.
        let timer = timer();
        let duration = Duration::from_millis(20);
        let wall_deadline = SystemTime::now()
            .checked_add(duration)
            .expect("test wall deadline must be representable");
        let relative = timer.sleep(duration);
        let wall = timer.sleep_until(wall_deadline);

        // Let both eagerly created deadlines elapse through another timer.
        tokio::time::sleep(duration.saturating_mul(3)).await;

        // Their first polls observe the construction-time deadlines.
        assert_eq!(relative.now_or_never(), Some(()));
        assert_eq!(wall.now_or_never(), Some(()));
    }
}
