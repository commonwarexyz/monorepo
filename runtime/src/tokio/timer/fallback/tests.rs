use super::*;
use futures::task::noop_waker;
use std::task::Context;

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
fn poll_once(sleep: &mut Sleep) -> Poll<()> {
    let waker = noop_waker();
    let mut context = Context::from_waker(&waker);
    Pin::new(sleep).poll(&mut context)
}

/// Checks the future bounds promised by the runtime Clock facade.
const fn assert_send_static<T: Send + 'static>(_value: &T) {}

#[test]
fn zero_and_past_sleeps_are_ready_on_first_poll() {
    // Construct the fallback facade without native driver state.
    let timer = timer();

    // Zero relative durations and past wall deadlines take the immediate
    // representation instead of constructing a Tokio timer.
    let mut zero = timer.sleep(Duration::ZERO);
    let mut past = timer.sleep_until(SystemTime::UNIX_EPOCH);

    // Both futures satisfy the facade bounds and complete on their first poll
    // without a scheduler yield.
    assert_send_static(&zero);
    assert_send_static(&past);
    assert_eq!(poll_once(&mut zero), Poll::Ready(()));
    assert_eq!(poll_once(&mut past), Poll::Ready(()));
    assert!(zero.inner.is_none());
    assert!(past.inner.is_none());
}

#[tokio::test]
async fn nonzero_sleep_starts_at_construction() {
    // Construct a nonzero fallback sleep but do not poll it yet.
    let timer = timer();
    let duration = Duration::from_millis(20);
    let mut sleep = timer.sleep(duration);
    let fixed_deadline = sleep.inner.as_ref().unwrap().deadline();

    // Let the eagerly created Tokio deadline elapse through another timer.
    tokio::time::sleep(duration.saturating_mul(3)).await;

    // The original sleep is ready on its next poll and retained the deadline
    // chosen when Timer::sleep was called.
    assert_eq!(sleep.inner.as_ref().unwrap().deadline(), fixed_deadline);
    assert_eq!(poll_once(&mut sleep), Poll::Ready(()));
}

#[tokio::test]
async fn sleep_until_retains_one_monotonic_snapshot() {
    // Convert one future wall deadline into the Tokio monotonic clock.
    let timer = timer();
    let duration = Duration::from_millis(50);
    let wall_deadline = SystemTime::now()
        .checked_add(duration)
        .expect("test wall deadline must be representable");
    let sleep = timer.sleep_until(wall_deadline);
    let fixed_deadline = sleep.inner.as_ref().unwrap().deadline();

    // Time passing after construction must not recompute the wall-clock
    // conversion or move the retained monotonic deadline.
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(sleep.inner.as_ref().unwrap().deadline(), fixed_deadline);

    // Awaiting the same future completes against that original snapshot.
    tokio::time::timeout(Duration::from_secs(2), sleep)
        .await
        .expect("fallback wall-clock sleep timed out");
}
