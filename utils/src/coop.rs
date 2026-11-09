//! Cooperative polling budget, shared by every resource a task polls.
//!
//! A task fed by fast producers can stay inside one poll for as long as they
//! keep up, holding its worker and delaying every other task there. An
//! executor that takes part installs a fresh budget of [`BUDGET`] operations
//! on the thread before each task poll, with a [`Scope`] or a [`refill`].
//! Each resource operation that may make progress asks [`exhausted`] first.
//! If the budget is spent, the resource wakes its task and returns pending
//! without taking anything. Otherwise an operation that makes progress spends
//! one unit with [`charge`]. Once the budget is spent, every further budgeted
//! operation in that poll finds it spent, whatever branch of whatever
//! combinator asks, so a task whose progress comes from budgeted operations
//! returns pending and its worker moves on. The next poll starts with a full
//! budget again. Work that is ready without the budget, such as a ready
//! fallback branch, a completed future or CPU work, is not stopped by it.
//!
//! The budgeted operations are receives that complete, with a value or by
//! reporting that the senders are gone, from the [`crate::channel::mpsc`],
//! [`crate::channel::oneshot`], [`crate::channel::watch`] and
//! [`crate::channel::ring`] receivers, and the operations of other resources
//! that ask the same questions: actor mailbox receives, and on the io_uring and
//! deterministic runtimes, sleeps that complete and the io_uring listener's
//! accepts. Sends, `try_recv`, waits on runtime handles and CPU work
//! between operations are not counted. A resource takes part through
//! [`poll_budgeted`], or through [`exhausted`] and [`charge`] when it
//! already delegates to a tokio primitive.
//!
//! Outside a scope this budget is unconstrained and never refuses. The tokio
//! runtime installs none, because tokio budgets its own task polls: there the
//! mpsc, oneshot and watch receivers spend tokio's budget through the tokio
//! channels they delegate to, tokio's own sleeps and sockets spend it too,
//! and [`poll_budgeted`] makes ring and mailbox receives spend it as well.
//! Each runtime thus bounds these operations with one budget, this one on the
//! io_uring and deterministic runtimes and tokio's on tokio. A runtime that
//! runs its root on the caller's thread holds the thread's [`Ownership`]
//! while it runs, so a runtime started from inside another executor's poll
//! does not inherit that poll's budget.
//!
//! This follows tokio's `task::coop`: a thread-local budget and a guard that
//! restores the previous value when the poll ends. Where tokio charges before
//! the operation and refunds a pending one, the charge here follows progress,
//! which comes to the same count: an empty receiver costs nothing, and a
//! ready one behind many empty ones is still reached in the same poll.
//!
//! # Synchronous probes
//!
//! A budgeted receive polled once with a throwaway context (for example with
//! `now_or_never`) inside a poll that has spent its budget returns pending
//! even when values are queued, and its wake goes to the throwaway waker.
//! Code that probes a receiver without waiting must use the receiver's
//! `try_recv` (`has_changed` or `borrow` for a watch), which is never
//! budgeted.
//!
//! The same holds for a nested executor: `block_on(rx.recv())` inside a poll
//! that has spent its budget polls a receive that keeps returning pending, so
//! it spins without progress. Hold [`Ownership::take`] around the nested
//! executor, or use `try_recv` or a blocking receive instead.
//! [`Ownership`] clears only this module's budget: inside a tokio task poll,
//! tokio's budget still applies to the receives that spend it, so a nested
//! executor there also needs `tokio::task::coop::unconstrained`.
//!
//! The workspace's `receive_probe` and `block_on_in_async` lints reject both
//! patterns.
//!
//! # Ordered selects
//!
//! A biased select tries its branches in order, but once the budget is spent
//! a budgeted receive in an early branch returns pending, and a later branch
//! that is ready without the budget (such as a completed future) would win in
//! its place. `commonware_macros::select!` and `select_loop!` prevent this:
//! every branch defers while the budget is spent, so the whole select waits
//! for the next poll and tries its branches in order there. Hand-written code
//! that polls several futures in priority order must do the same, by checking
//! [`exhausted`] before polling them or awaiting [`proceed`] first.
//! A direct `tokio::select!` has no such guard, and the workspace's
//! `direct_tokio_select` lint rejects it.

use commonware_macros::{
    __coop::{REMAINING, UNCONSTRAINED},
    stability,
};
use std::{
    future::{Future, poll_fn},
    marker::PhantomData,
    task::{Context, Poll, ready},
};

/// Operations one task poll may complete before it yields.
///
/// Small enough that a poll delivering a full budget of values to cheap
/// handlers returns within tens of microseconds, so timers and other tasks
/// on the same worker are not held up behind a fed receive loop, and large
/// enough that the yield costs little next to the work it bounds.
/// The bound is a count, not a time: a poll whose handlers are expensive
/// takes as long as a budget of them. The value is a tuning parameter that may
/// change, so refer to the constant rather than its value.
#[stability(BETA)]
pub const BUDGET: u32 = 32;

/// An executor's hold on this thread's budget, taken when the executor
/// starts on the thread and released when it gives the thread back: on
/// normal return and on unwinding alike. Taking it leaves the thread
/// unconstrained, and dropping it restores whatever was in force before, so
/// a caller that runs the executor from inside another executor's poll finds
/// its own budget afterwards, not one nobody refills.
///
/// Thread-bound: the budget lives in this thread's locals, so the hold
/// cannot be released from another thread.
/// Hold it only around synchronous code, never across an `await`, since
/// the executor installs a new budget for the next poll under the hold.
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<commonware_utils::coop::Ownership>();
/// ```
#[stability(BETA)]
#[must_use = "the budget is restored when this is dropped, so bind it to a local"]
pub struct Ownership {
    /// Budget in force before the hold, restored on drop.
    previous: u32,
    /// Keeps the hold on the thread whose budget it saved.
    _thread: PhantomData<*const ()>,
}

#[stability(BETA)]
impl Ownership {
    /// Take the thread's budget, leaving it unconstrained until the
    /// executor installs one, and restore it on drop.
    pub fn take() -> Self {
        let previous = REMAINING.replace(UNCONSTRAINED);
        Self {
            previous,
            _thread: PhantomData,
        }
    }
}

#[stability(BETA)]
impl Drop for Ownership {
    fn drop(&mut self) {
        REMAINING.set(self.previous);
    }
}

/// A task poll in progress on this thread, holding a fresh budget. Dropping
/// it restores the budget in force before, so scopes nest inside another
/// executor's poll without refilling it, and unwinding leaves nothing
/// behind. Thread-bound like [`Ownership`].
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<commonware_utils::coop::Scope>();
/// ```
#[stability(ALPHA)]
#[must_use = "the budget is restored when this is dropped, so bind it to a local"]
pub struct Scope {
    /// Budget in force before this scope, restored on drop.
    previous: u32,
    /// Keeps the scope on the thread whose budget it saved.
    _thread: PhantomData<*const ()>,
}

#[stability(ALPHA)]
impl Scope {
    /// Start a task poll with a full budget.
    #[inline(always)]
    pub fn enter() -> Self {
        let previous = REMAINING.replace(BUDGET);
        Self {
            previous,
            _thread: PhantomData,
        }
    }
}

#[stability(ALPHA)]
impl Drop for Scope {
    #[inline(always)]
    fn drop(&mut self) {
        REMAINING.set(self.previous);
    }
}

/// Install a full budget for the poll about to start, without restoring
/// anything afterwards: one store per poll for an executor that runs a batch
/// of polls inside one [`Scope`]. Dropping that scope at the end of the
/// batch, not the refill, restores the budget in force before, so a budget a
/// poll left behind never reaches code outside the batch.
#[stability(ALPHA)]
#[inline(always)]
pub fn refill() {
    REMAINING.set(BUDGET);
}

/// Whether a budget is installed on this thread, spent or not. An executor
/// that takes part installs one around each poll it runs, but any caller
/// can install one with a [`Scope`] or [`refill`], so this does not identify
/// the executor.
#[stability(ALPHA)]
pub fn active() -> bool {
    REMAINING.get() != UNCONSTRAINED
}

/// Whether the current poll's budget is spent. A resource asks before an
/// operation that may make progress and, if so, wakes the task and returns
/// pending instead. Outside a scope the budget is never spent.
#[stability(BETA)]
#[inline(always)]
pub fn exhausted() -> bool {
    REMAINING.get() == 0
}

/// Count one unit of progress in the current poll. Outside a scope nothing
/// is counted. One load and at most one store, with no call and no panic, so
/// a resource that charges for the result it holds keeps that result in
/// place. A charge on a spent budget leaves it spent.
#[stability(BETA)]
#[inline(always)]
pub fn charge() {
    REMAINING.with(|remaining| {
        let left = remaining.get();
        if left != UNCONSTRAINED {
            remaining.set(left.saturating_sub(1));
        }
    });
}

/// Wait until the current poll's budget allows another operation: pending
/// with a self-wake while it is spent, ready at once otherwise. Spends
/// nothing. See [Ordered selects](self#ordered-selects).
#[stability(BETA)]
pub fn proceed() -> impl Future<Output = ()> + Send + 'static {
    poll_fn(|cx| {
        if exhausted() {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
}

/// Poll a resource operation under the budget that bounds this thread's
/// current poll, and spend one unit if it completes.
///
/// With this module's budget installed (the io_uring and deterministic
/// runtimes), a spent budget wakes the task and returns pending without
/// polling, so nothing is taken. Otherwise the operation takes part in
/// tokio's own budget, which a tokio runtime installs around each task poll
/// and which is unconstrained elsewhere. Pending results spend nothing.
///
/// A resource that delegates to a tokio primitive, which already spends
/// tokio's budget, uses [`exhausted`] and [`charge`] instead, so that tokio's
/// budget is not spent twice.
#[stability(BETA)]
#[inline(always)]
pub fn poll_budgeted<T>(
    cx: &mut Context<'_>,
    poll: impl FnOnce(&mut Context<'_>) -> Poll<T>,
) -> Poll<T> {
    // This module's budget, when installed, is the only one that applies.
    let left = REMAINING.get();
    if left != UNCONSTRAINED {
        if left == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let polled = poll(cx);
        if polled.is_ready() {
            charge();
        }
        return polled;
    }

    // Otherwise tokio's budget applies. A spent one defers the wake until the
    // task returns to tokio, and a pending result refunds the unit taken here.
    let progress = ready!(tokio::task::coop::poll_proceed(cx));
    let polled = poll(cx);
    if polled.is_ready() {
        progress.made_progress();
    }
    polled
}

/// Poll a resource operation under this module's budget only, and spend one
/// unit if it completes.
///
/// For resources that delegate to a tokio primitive: tokio's primitive spends
/// tokio's budget itself where one is installed, so checking it again would
/// spend it twice. Outside a scope this never refuses.
#[inline(always)]
pub(crate) fn poll_counted<T>(
    cx: &mut Context<'_>,
    poll: impl FnOnce(&mut Context<'_>) -> Poll<T>,
) -> Poll<T> {
    // Decide before polling, so a spent budget never takes a value or
    // registers a waker. The wake makes the next poll retry.
    if exhausted() {
        cx.waker().wake_by_ref();
        return Poll::Pending;
    }

    // A value or the end of the channel is progress. An empty one costs nothing.
    let polled = poll(cx);
    if polled.is_ready() {
        charge();
    }
    polled
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        pin::pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Wake, Waker},
    };

    /// Ask, then charge, the way a resource does for each value it delivers.
    fn deliver(values: u32) {
        for _ in 0..values {
            assert!(!exhausted());
            charge();
        }
    }

    #[test]
    fn test_unconstrained_outside_a_scope() {
        assert!(!active());

        // Charge far more than one budget without a scope.
        for _ in 0..10 * BUDGET {
            charge();
        }

        // Nothing was counted.
        assert!(!exhausted());
        assert!(!active());
    }

    #[test]
    fn test_budget_is_sticky_within_a_scope() {
        // Spend the whole budget.
        let _scope = Scope::enter();
        deliver(BUDGET);

        // Every further request in this poll fails, whoever asks.
        for _ in 0..3 {
            assert!(exhausted());
        }
    }

    #[test]
    fn test_no_progress_costs_nothing() {
        // Ask many times without making progress.
        let _scope = Scope::enter();
        for _ in 0..10 * BUDGET {
            assert!(!exhausted());
        }

        // Empty operations left the whole budget for the one that has work.
        deliver(BUDGET);
        assert!(exhausted());
    }

    #[test]
    fn test_charges_past_the_budget_stay_spent() {
        // Charge up to the budget.
        let _scope = Scope::enter();
        for _ in 0..BUDGET - 1 {
            charge();
        }
        assert!(!exhausted());
        charge();
        assert!(exhausted());

        // Charges without asking never wrap around to unconstrained.
        for _ in 0..2 * BUDGET {
            charge();
        }
        assert!(exhausted());
        assert!(active());
    }

    #[test]
    fn test_ownership_leaves_the_thread_unconstrained_and_restores_it() {
        // Spend part of an outer poll's budget.
        let _outer = Scope::enter();
        for _ in 0..3 {
            charge();
        }

        // A nested executor starts unconstrained and installs its own budget.
        {
            let _hold = Ownership::take();
            assert!(!active());
            deliver(2 * BUDGET);
            refill();
            deliver(BUDGET);
            assert!(exhausted());
        }

        // The outer poll's remaining units are back as it left them.
        deliver(BUDGET - 3);
        assert!(exhausted());
    }

    #[test]
    fn test_ownership_restores_after_unwinding() {
        // Spend one unit of an outer poll's budget.
        let _outer = Scope::enter();
        charge();

        // A nested executor spends its own budget and panics.
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _hold = Ownership::take();
            refill();
            deliver(BUDGET);
            panic!("executor failed");
        }));
        assert!(result.is_err());

        // The outer poll still has its own remaining units.
        deliver(BUDGET - 1);
        assert!(exhausted());
    }

    #[test]
    fn test_refill_installs_a_full_budget_without_restoring() {
        // Spend the budget, then refill it.
        let outer = Scope::enter();
        deliver(BUDGET);
        assert!(exhausted());
        refill();
        assert!(!exhausted());

        // Leaving the scope restores the unconstrained state, not the refill.
        drop(outer);
        assert!(!active());
    }

    #[test]
    fn test_scopes_nest_and_restore() {
        // Spend the outer poll's budget.
        let outer = Scope::enter();
        deliver(BUDGET);
        assert!(exhausted());

        // An inner poll starts with a full budget.
        {
            let _inner = Scope::enter();
            assert!(!exhausted());
            charge();
        }

        // The inner poll's fresh budget did not refill the outer one.
        assert!(exhausted());
        drop(outer);
        assert!(!active());
    }

    #[test]
    fn test_unwinding_restores_the_previous_budget() {
        // Spend one unit of an outer poll's budget.
        let _outer = Scope::enter();
        charge();

        // An inner poll spends its budget and panics.
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _inner = Scope::enter();
            deliver(BUDGET);
            panic!("poll panicked");
        }));
        assert!(result.is_err());

        // The outer poll still has its own remaining units.
        deliver(BUDGET - 1);
        assert!(exhausted());
    }

    /// Counts the wakes it receives.
    struct Wakes(
        /// Number of wakes received so far.
        AtomicUsize,
    );

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_proceed_waits_only_while_the_budget_is_spent() {
        let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);

        // Outside a scope it never waits.
        assert!(pin!(proceed()).poll(&mut cx).is_ready());

        // With one unit left it proceeds without spending it.
        let _scope = Scope::enter();
        deliver(BUDGET - 1);
        assert!(pin!(proceed()).poll(&mut cx).is_ready());
        assert!(!exhausted(), "proceeding spends nothing");

        // With the budget spent it waits and wakes itself once.
        charge();
        let mut waiting = pin!(proceed());
        assert!(waiting.as_mut().poll(&mut cx).is_pending());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);

        // The next poll's fresh budget lets it through.
        refill();
        assert!(waiting.as_mut().poll(&mut cx).is_ready());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    }
}
