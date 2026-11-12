//! Deadlines for sleeping tasks.
//!
//! A sleep that has to wait registers its deadline in one ordered map. A single driver owns the
//! runtime's only browser timeout and keeps it armed no later than the earliest deadline:
//!
//! ```text
//!  tasks (Send)                 shared state                    driver (owns the JS callback)
//!  ------------                 ------------                    -----------------------------
//!  Sleep::poll  -- insert -->   sleepers: deadline -> waker
//!               -- wake ----->  driver waker  ------------->    setTimeout(earliest deadline)
//!                                                                         |
//!  task resumes <-- wake ---    expired sleepers removed  <--   timeout fires, driver polls
//!  Sleep::drop  -- remove -->   sleepers
//! ```
//!
//! A timeout armed for a dropped sleep is left to fire. The driver then finds nothing expired
//! and arms the next deadline. Dropping a sleep and creating a later one therefore make no
//! browser calls.

use commonware_utils::sync::Mutex;
use std::{
    collections::BTreeMap,
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use wasm_bindgen::prelude::{Closure, wasm_bindgen};

#[wasm_bindgen]
extern "C" {
    /// Milliseconds elapsed on the page's monotonic clock.
    #[wasm_bindgen(js_namespace = performance, js_name = now)]
    fn performance_now() -> f64;

    /// Runs `callback` once after `delay` milliseconds and returns the timeout's identifier.
    #[wasm_bindgen(js_name = setTimeout)]
    fn set_timeout(callback: &Closure<dyn FnMut()>, delay: i32) -> i32;

    /// Cancels the timeout with identifier `id` if it has not run yet.
    #[wasm_bindgen(js_name = clearTimeout)]
    fn clear_timeout(id: i32);
}

/// A sleep's deadline on the monotonic clock, then a sequence number that keeps sleeps sharing
/// a deadline distinct.
type Key = (Duration, u64);

#[derive(Default)]
struct State {
    /// Sequence number given to the next registered sleep.
    next: u64,
    /// Wakers of pending sleeps, ordered by deadline.
    sleepers: BTreeMap<Key, Waker>,
    /// Deadline the pending timeout was armed for and its identifier, if one is pending.
    armed: Option<(Duration, i32)>,
    /// Waker of the driver while it waits for a timeout, an earlier deadline, or a stop.
    driver: Option<Waker>,
    /// Whether the runtime stopped, after which no sleep is woken.
    stopped: bool,
}

/// Registry of sleeping tasks shared by every context of a runtime.
#[derive(Clone, Default)]
pub(super) struct Timer {
    state: Arc<Mutex<State>>,
}

impl Timer {
    /// Returns the time elapsed on the page's monotonic clock.
    fn now() -> Duration {
        Duration::try_from_secs_f64(performance_now() / 1_000.0).unwrap_or_default()
    }

    /// Returns a future that completes once `duration` has elapsed.
    pub(super) fn sleep(&self, duration: Duration) -> Sleep {
        let state = if duration.is_zero() {
            SleepState::Done
        } else {
            SleepState::Unregistered(Self::now().saturating_add(duration))
        };
        Sleep {
            timer: self.clone(),
            state,
        }
    }

    /// Wakes sleeps as their deadlines pass, until [Timer::stop] is called.
    pub(super) async fn run(self) {
        // The timeout only reports that it fired. The driver decides what expired.
        let callback = Closure::<dyn FnMut()>::new({
            let state = self.state.clone();
            move || {
                let driver = {
                    let mut state = state.lock();
                    state.armed = None;
                    state.driver.take()
                };
                if let Some(driver) = driver {
                    driver.wake();
                }
            }
        });

        poll_fn(|cx| {
            let now = Self::now();
            let mut state = self.state.lock();

            // After a stop, cancel the pending timeout before its callback is dropped.
            if state.stopped {
                if let Some((_, timeout)) = state.armed.take() {
                    clear_timeout(timeout);
                }
                return Poll::Ready(());
            }

            // Collect the sleeps whose deadlines passed.
            let mut expired = Vec::new();
            while let Some(sleeper) = state.sleepers.first_entry() {
                if sleeper.key().0 > now {
                    break;
                }
                expired.push(sleeper.remove());
            }

            // Arm a timeout when none is pending or the pending one fires too late. Browsers
            // cap the delay, so a distant deadline is reached through several timeouts.
            let next = state.sleepers.first_key_value().map(|(key, _)| key.0);
            if let Some(next) = next
                && state.armed.is_none_or(|(armed, _)| next < armed)
            {
                if let Some((_, timeout)) = state.armed.take() {
                    clear_timeout(timeout);
                }
                let delay = (next - now).as_secs_f64() * 1_000.0;
                let timeout = set_timeout(&callback, delay.ceil().min(f64::from(i32::MAX)) as i32);
                state.armed = Some((next, timeout));
            }
            state.driver = Some(cx.waker().clone());
            drop(state);

            // Wake outside the lock so a waker that polls inline cannot re-enter it.
            for sleeper in expired {
                sleeper.wake();
            }
            Poll::Pending
        })
        .await
    }

    /// Stops the driver. Sleeps still pending never complete.
    pub(super) fn stop(&self) {
        let driver = {
            let mut state = self.state.lock();
            state.stopped = true;
            state.driver.take()
        };
        if let Some(driver) = driver {
            driver.wake();
        }
    }
}

enum SleepState {
    /// Created with this deadline and not yet waiting in the timer.
    Unregistered(Duration),
    /// Waiting in the timer under this key.
    Registered(Key),
    /// Completed.
    Done,
}

/// Future returned by [Timer::sleep].
pub(super) struct Sleep {
    timer: Timer,
    state: SleepState,
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        match this.state {
            SleepState::Done => Poll::Ready(()),
            SleepState::Unregistered(deadline) => {
                if deadline <= Timer::now() {
                    this.state = SleepState::Done;
                    return Poll::Ready(());
                }

                // Register the deadline, and have the driver arm a timeout for it when the
                // pending timeout would fire too late.
                let driver = {
                    let mut state = this.timer.state.lock();
                    let key = (deadline, state.next);
                    state.next += 1;
                    state.sleepers.insert(key, cx.waker().clone());
                    this.state = SleepState::Registered(key);
                    if state.armed.is_none_or(|(armed, _)| deadline < armed) {
                        state.driver.take()
                    } else {
                        None
                    }
                };
                if let Some(driver) = driver {
                    driver.wake();
                }
                Poll::Pending
            }
            SleepState::Registered(key) => {
                // The driver removes a sleep when its deadline passes.
                let mut state = this.timer.state.lock();
                match state.sleepers.get_mut(&key) {
                    Some(waker) => {
                        waker.clone_from(cx.waker());
                        Poll::Pending
                    }
                    None => {
                        drop(state);
                        this.state = SleepState::Done;
                        Poll::Ready(())
                    }
                }
            }
        }
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let SleepState::Registered(key) = self.state {
            self.timer.state.lock().sleepers.remove(&key);
        }
    }
}
