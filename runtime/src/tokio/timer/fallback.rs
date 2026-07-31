//! Tokio-backed fallback timers for unsupported native targets.

use crate::utils::Panicker;
use std::{
    future::Future,
    time::{Duration, SystemTime},
};
use thiserror::Error;
use tokio::runtime::{Builder as TokioBuilder, Runtime};

/// Descriptor-free timer builder for targets that use Tokio timers.
pub(crate) struct Builder;

impl Builder {
    /// Leaves the Tokio builder unchanged and retains no affinity state.
    pub(crate) fn install(_runtime_builder: &mut TokioBuilder, _worker_threads: usize) -> Self {
        Self
    }

    /// Creates the descriptor-free fallback timer facade.
    pub(crate) fn build(self, _runtime: &Runtime, _panicker: Panicker) -> Result<Timer, InitError> {
        Ok(Timer)
    }
}

/// Tokio-backed timer facade for unsupported native targets.
pub(crate) struct Timer;

impl Timer {
    /// Eagerly constructs a Tokio sleep for nonzero durations.
    pub(crate) fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        // Construct outside the async block so Tokio fixes the monotonic
        // deadline now, even when the returned future is polled later.
        let sleep = if duration.is_zero() {
            None
        } else {
            Some(tokio::time::sleep(duration))
        };

        async move {
            match sleep {
                Some(sleep) => sleep.await,
                None => tokio::task::coop::consume_budget().await,
            }
        }
    }

    /// Snapshots a wall-clock deadline once before constructing its sleep.
    pub(crate) fn sleep_until(
        &self,
        deadline: SystemTime,
    ) -> impl Future<Output = ()> + Send + 'static {
        // Wall time is read once, so later clock adjustments cannot move the
        // monotonic deadline retained by Tokio's sleep.
        let remaining = deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        self.sleep(remaining)
    }
}

/// Infallible fallback initialization error.
#[derive(Debug, Error)]
pub(crate) enum InitError {}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::task::noop_waker;
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
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

    /// Polls a fallback sleep exactly once without driving the executor.
    fn poll_once<F: Future<Output = ()>>(sleep: Pin<&mut F>) -> Poll<()> {
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        sleep.poll(&mut context)
    }

    /// Checks the future bounds promised by the runtime Clock facade.
    const fn assert_send_static<T: Send + 'static>(_value: &T) {}

    #[test]
    fn zero_and_past_sleeps_are_ready_on_first_poll() {
        // Construct the fallback facade without native driver state.
        let timer = timer();

        // Zero relative durations and past wall deadlines take the immediate
        // representation instead of constructing a Tokio timer.
        let zero = timer.sleep(Duration::ZERO);
        let past = timer.sleep_until(SystemTime::UNIX_EPOCH);

        // Both futures satisfy the facade bounds and complete with fresh scheduler budget.
        assert_send_static(&zero);
        assert_send_static(&past);
        let mut zero = std::pin::pin!(zero);
        let mut past = std::pin::pin!(past);
        assert_eq!(poll_once(zero.as_mut()), Poll::Ready(()));
        assert_eq!(poll_once(past.as_mut()), Poll::Ready(()));
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
        assert_send_static(&relative);
        assert_send_static(&wall);

        // Let both eagerly created deadlines elapse through another timer.
        tokio::time::sleep(duration.saturating_mul(3)).await;

        // Their first polls observe the construction-time deadlines.
        let mut relative = std::pin::pin!(relative);
        let mut wall = std::pin::pin!(wall);
        assert_eq!(poll_once(relative.as_mut()), Poll::Ready(()));
        assert_eq!(poll_once(wall.as_mut()), Poll::Ready(()));
    }
}
