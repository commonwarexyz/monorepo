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
    // Exercise the same builder configuration sequence as runtime startup.
    let setup = Setup::new(1);
    let mut builder = Builder::new_current_thread();
    setup.configure(&mut builder);

    // Fallback initialization consumes setup without creating driver state.
    let (panicker, _panicked) = Panicker::new(false);
    Timer::new(setup, panicker).unwrap()
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
    // Setup: Queue a peer behind a task that repeatedly awaits immediate sleeps.
    let timer = timer();
    let peer_ran = Arc::new(AtomicBool::new(false));
    let peer_flag = Arc::clone(&peer_ran);
    let peer = tokio::spawn(async move {
        peer_flag.store(true, Ordering::Release);
    });

    // Action: Await more immediate sleeps than one Tokio cooperative budget.
    for _ in 0..1_024 {
        timer.sleep(Duration::ZERO).await;
        if peer_ran.load(Ordering::Acquire) {
            break;
        }
    }

    // Assertion: Budget exhaustion yields to the already-runnable peer.
    assert!(peer_ran.load(Ordering::Acquire));
    peer.await.unwrap();
}

#[tokio::test]
async fn relative_and_wall_sleeps_start_at_construction() {
    // Setup: Construct relative and wall-clock sleeps without polling either.
    let timer = timer();
    let duration = Duration::from_millis(20);
    let wall_deadline = SystemTime::now()
        .checked_add(duration)
        .expect("test wall deadline must be representable");
    let relative = timer.sleep(duration);
    let wall = timer.sleep_until(wall_deadline);
    assert_send_static(&relative);
    assert_send_static(&wall);

    // Action: Let both eagerly created deadlines elapse through another timer.
    tokio::time::sleep(duration.saturating_mul(3)).await;

    // Assertion: Their first polls observe the construction-time deadlines.
    let mut relative = std::pin::pin!(relative);
    let mut wall = std::pin::pin!(wall);
    assert_eq!(poll_once(relative.as_mut()), Poll::Ready(()));
    assert_eq!(poll_once(wall.as_mut()), Poll::Ready(()));
}
