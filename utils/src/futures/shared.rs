//! A cloneable future whose clones share one output (see [Shared]).

use crate::sync::Mutex;
use futures::task::{ArcWake, waker_ref};
use std::{
    future::Future,
    mem,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

/// Number of wakers collected without allocating when waking several clones at once.
const INLINE_WAKES: usize = 4;

/// A cloneable future that drives `F` through whichever clone is polled and resolves every clone
/// to a clone of its output.
///
/// Several tasks can wait on one future without a task of its own, and each completes even if the
/// clone that created the future is never polled again. Clones complete together, and a clone
/// polled after completion resolves immediately. Dropping the last clone drops the inner future,
/// or its output, after which no [WeakShared] handle can recover it.
///
/// Polling requires `F` to be [Unpin] (box it first otherwise) and its output to be [Clone].
/// The shared state is itself the inner future's waker, and a waker must be `'static`, [Send],
/// and [Sync], so `F` must also be [Send] and `'static`, and its output [Send] and [Sync].
///
/// # Liveness
///
/// Exactly one clone polls the inner future at a time. A clone polled meanwhile registers its
/// waker and returns [Poll::Pending] without waiting for that poll. A clone's waker stays
/// registered until the clone completes or is dropped, and waking the inner future wakes every
/// registered clone. If the inner future is woken while a clone polls it, or another clone finds
/// it busy meanwhile, the polling clone wakes every other clone again once it stops polling, so a
/// clone that went back to sleep after finding the inner future busy observes what that poll did
/// and polls the inner future if it was woken. Progress therefore never depends on any particular
/// clone being polled again. A clone may stop polling, because it is dropped or finished through
/// another path, without stranding the others. A clone polled when the inner future was not woken
/// since its last poll only registers, so the inner future is polled about once per wake however
/// many clones are woken.
///
/// # Panics
///
/// A panic while polling the inner future propagates to the polling clone and poisons the future.
/// Every waiting clone is woken, and polling any clone afterwards panics.
///
/// # Wakers
///
/// Registered wakers are cloned while the shared state is locked, and that lock is not reentrant,
/// so cloning a registered waker must not wake this future's inner future, or poll or drop one of
/// its clones. Wakes, and drops of displaced wakers, happen after unlocking.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct Shared<F: Future> {
    inner: Arc<Inner<F>>,
    /// This clone's slot in [State::wakers], assigned when it first waits.
    key: Option<usize>,
}

/// A weak handle to a [Shared] that does not keep its future alive.
pub struct WeakShared<F: Future>(Weak<Inner<F>>);

/// The state every clone of a [Shared] refers to.
///
/// It is also the inner future's waker, so wakers the inner future hands out keep this allocation
/// alive, possibly after every clone is dropped. The clones therefore count themselves, and the
/// last one releases the future or its output (see [Stage::Released]).
struct Inner<F: Future> {
    /// Number of live [Shared] clones. Once zero, it never increases again.
    clones: AtomicUsize,
    state: Mutex<State<F>>,
}

struct State<F: Future> {
    stage: Stage<F>,
    /// Whether the inner future was woken since a clone last started polling it, or was never
    /// polled. While it is unset, the inner future cannot make progress, so clones only register.
    woken: bool,
    /// Whether a clone found the inner future busy since a clone last started polling it.
    contended: bool,
    /// The waker of each clone waiting on the future, indexed by the clone's key. Completion
    /// takes them all.
    wakers: Vec<Option<Waker>>,
    /// Keys of vacant slots in `wakers`.
    free: Vec<usize>,
}

enum Stage<F: Future> {
    /// No clone is polling the inner future.
    Idle(F),
    /// A clone took the inner future out of the state to poll it without holding the lock.
    Polling,
    /// The inner future completed. Clones of the output are made outside the lock, since
    /// cloning it may wake the inner future, which locks the state.
    Ready(Arc<F::Output>),
    /// The inner future panicked.
    Poisoned,
    /// Every clone was dropped, and the last one dropped the future or its output.
    Released,
}

/// Clones of registered wakers, collected under the lock and woken after releasing it. The first
/// few are stored inline, so waking a few clones does not allocate.
struct Wakes {
    inline: [Option<Waker>; INLINE_WAKES],
    spilled: Vec<Waker>,
}

impl Wakes {
    fn wake(self) {
        for waker in self.inline.into_iter().flatten().chain(self.spilled) {
            waker.wake();
        }
    }
}

impl<F: Future> State<F> {
    /// Register `waker` for the clone with `key`, assigning the clone a key if it has none.
    ///
    /// Returns the waker it replaces, if any, for the caller to drop after releasing the lock,
    /// since a waker's destructor may run arbitrary code, including dropping another clone.
    #[must_use]
    fn register(&mut self, key: &mut Option<usize>, waker: &Waker) -> Option<Waker> {
        let key = *key.get_or_insert_with(|| {
            self.free.pop().unwrap_or_else(|| {
                self.wakers.push(None);
                self.wakers.len() - 1
            })
        });
        let slot = &mut self.wakers[key];
        if slot
            .as_ref()
            .is_some_and(|registered| registered.will_wake(waker))
        {
            return None;
        }
        slot.replace(waker.clone())
    }

    /// Remove the registration of the clone with `key`, returning its waker for the caller to
    /// drop after releasing the lock (see [Self::register]).
    #[must_use]
    fn deregister(&mut self, key: usize) -> Option<Waker> {
        // Completion and poisoning take every registration, leaving no slot to vacate.
        let waker = self.wakers.get_mut(key)?.take();
        self.free.push(key);
        waker
    }

    /// Clone every registered waker except the one with key `except`.
    fn wakes(&self, except: Option<usize>) -> Wakes {
        let mut wakes = Wakes {
            inline: Default::default(),
            spilled: Vec::new(),
        };
        let mut inline = wakes.inline.iter_mut();
        let registered = self.wakers.iter().enumerate();
        let others = registered.filter(|&(key, _)| except != Some(key));
        for waker in others.filter_map(|(_, waker)| waker.as_ref()) {
            match inline.next() {
                Some(slot) => *slot = Some(waker.clone()),
                None => wakes.spilled.push(waker.clone()),
            }
        }
        wakes
    }

    /// Move to the terminal `stage`, returning every registered waker for the caller to wake
    /// after releasing the lock.
    fn finish(&mut self, stage: Stage<F>) -> Vec<Option<Waker>> {
        self.stage = stage;
        mem::take(&mut self.wakers)
    }
}

impl<F: Future> Shared<F> {
    /// Share `future` among the clones of the returned [Shared].
    pub fn new(future: F) -> Self {
        Self {
            inner: Arc::new(Inner {
                clones: AtomicUsize::new(1),
                state: Mutex::new(State {
                    stage: Stage::Idle(future),
                    woken: true,
                    contended: false,
                    wakers: Vec::new(),
                    free: Vec::new(),
                }),
            }),
            key: None,
        }
    }

    /// Create a [WeakShared] handle to this future.
    pub fn downgrade(&self) -> WeakShared<F> {
        WeakShared(Arc::downgrade(&self.inner))
    }

    /// Whether `self` and `other` are clones of the same future, whether or not it completed.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl<F: Future> Clone for Shared<F> {
    fn clone(&self) -> Self {
        self.inner.clones.fetch_add(1, Ordering::Relaxed);
        Self {
            inner: self.inner.clone(),
            key: None,
        }
    }
}

impl<F: Future> Drop for Shared<F> {
    fn drop(&mut self) {
        if let Some(key) = self.key {
            // Drop the waker only after releasing the lock (see [State::register]).
            let waker = self.inner.state.lock().deregister(key);
            drop(waker);
        }
        if self.inner.clones.fetch_sub(1, Ordering::AcqRel) == 1 {
            // Drop the future or output only after releasing the lock.
            let stage = mem::replace(&mut self.inner.state.lock().stage, Stage::Released);
            drop(stage);
        }
    }
}

impl<F> Future for Shared<F>
where
    F: Future + Send + Unpin + 'static,
    F::Output: Clone + Send + Sync,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.get_mut();

        // Register this clone, and take the inner future out to poll it unless another clone is
        // polling it.
        let (mut future, replaced) = {
            let mut guard = this.inner.state.lock();
            let state = &mut *guard;
            match &state.stage {
                Stage::Idle(_) if state.woken => {}
                Stage::Idle(_) | Stage::Polling => {
                    state.contended |= matches!(state.stage, Stage::Polling);
                    let replaced = state.register(&mut this.key, cx.waker());
                    drop(guard);
                    drop(replaced);
                    return Poll::Pending;
                }
                Stage::Ready(output) => {
                    // Completion removed every registration.
                    this.key = None;
                    let output = Arc::clone(output);
                    drop(guard);
                    return Poll::Ready((*output).clone());
                }
                Stage::Poisoned => panic!("Shared future polled after its inner future panicked"),
                Stage::Released => unreachable!("a live clone keeps the future"),
            }
            let replaced = state.register(&mut this.key, cx.waker());
            state.woken = false;
            state.contended = false;
            let Stage::Idle(future) = mem::replace(&mut state.stage, Stage::Polling) else {
                unreachable!("stage checked above");
            };
            (future, replaced)
        };

        // Poll, and clone any output, without holding the lock, so wakes and other clones never
        // wait on the inner future. Unwinding out of either, or out of dropping the replaced
        // waker, poisons the future, which another clone could otherwise never find idle again.
        let poison = Poison(&this.inner);
        drop(replaced);
        let waker = waker_ref(&this.inner);
        let poll = Pin::new(&mut future)
            .poll(&mut Context::from_waker(&waker))
            .map(|output| {
                let shared = Arc::new(output);
                ((*shared).clone(), shared)
            });
        mem::forget(poison);

        let mut state = this.inner.state.lock();
        match poll {
            Poll::Pending => {
                state.stage = Stage::Idle(future);
                if !state.woken && !state.contended {
                    return Poll::Pending;
                }

                // Clones that found the inner future busy went back to sleep without observing
                // this poll or any wake during it, so wake them now. A wake during the poll also
                // woke this clone's own waker.
                let wakes = state.wakes(this.key);
                drop(state);
                wakes.wake();
                Poll::Pending
            }
            Poll::Ready((output, shared)) => {
                let own = this.key.take().and_then(|key| state.wakers[key].take());
                let wakers = state.finish(Stage::Ready(shared));
                drop(state);
                drop(own);
                for waker in wakers.into_iter().flatten() {
                    waker.wake();
                }
                Poll::Ready(output)
            }
        }
    }
}

impl<F: Future> WeakShared<F> {
    /// Recover a [Shared] clone, unless every [Shared] clone has been dropped.
    pub fn upgrade(&self) -> Option<Shared<F>> {
        let inner = self.0.upgrade()?;
        inner
            .clones
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |clones| {
                (clones != 0).then_some(clones + 1)
            })
            .ok()?;
        Some(Shared { inner, key: None })
    }
}

impl<F: Future> Clone for WeakShared<F> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<F> ArcWake for Inner<F>
where
    F: Future + Send,
    F::Output: Send + Sync,
{
    fn wake_by_ref(arc_self: &Arc<Self>) {
        let wakes = {
            let mut state = arc_self.state.lock();
            state.woken = true;
            state.wakes(None)
        };
        wakes.wake();
    }
}

/// Poisons a [Shared] when dropped, which happens only if polling its inner future unwinds.
struct Poison<'a, F: Future>(&'a Inner<F>);

impl<F: Future> Drop for Poison<'_, F> {
    fn drop(&mut self) {
        // Wake every waiting clone so it observes the panic instead of waiting forever.
        let wakers = self.0.state.lock().finish(Stage::Poisoned);
        for waker in wakers.into_iter().flatten() {
            waker.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{
        FutureExt as _,
        executor::block_on,
        future::{self, BoxFuture},
        task,
    };
    use std::{
        panic::{self, AssertUnwindSafe},
        sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
        thread,
        time::Duration,
    };

    /// A waker that counts its wakes.
    struct Counter(AtomicUsize);

    impl Counter {
        fn count(&self) -> usize {
            self.0.load(SeqCst)
        }
    }

    impl ArcWake for Counter {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, SeqCst);
        }
    }

    /// A waker and the counter of its wakes.
    fn counter() -> (Arc<Counter>, Waker) {
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        (counter.clone(), task::waker(counter))
    }

    fn poll<F>(shared: &mut Shared<F>, waker: &Waker) -> Poll<F::Output>
    where
        F: Future + Send + Unpin + 'static,
        F::Output: Clone + Send + Sync,
    {
        Pin::new(shared).poll(&mut Context::from_waker(waker))
    }

    /// Controls an inner future that the tests wake and complete by hand.
    #[derive(Default)]
    struct Control {
        /// The waker of the inner future's latest poll.
        waker: Mutex<Option<Waker>>,
        /// Runs once during the next poll of the inner future, after it decides its result.
        hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
        /// Whether the inner future's next poll resolves.
        ready: AtomicBool,
        /// Polls of the inner future.
        polls: AtomicUsize,
    }

    impl Control {
        /// The inner future, which resolves to 7 once [Self::ready] is set.
        fn future(self: &Arc<Self>) -> BoxFuture<'static, u32> {
            let control = self.clone();
            future::poll_fn(move |cx| {
                control.polls.fetch_add(1, SeqCst);
                *control.waker.lock() = Some(cx.waker().clone());
                let ready = control.ready.load(SeqCst);
                let hook = control.hook.lock().take();
                if let Some(hook) = hook {
                    hook();
                }
                if ready { Poll::Ready(7) } else { Poll::Pending }
            })
            .boxed()
        }

        /// Wake the inner future, as the event it waits on would.
        fn wake(&self) {
            self.waker
                .lock()
                .as_ref()
                .expect("inner future never polled")
                .wake_by_ref();
        }
    }

    #[test]
    fn test_clones_share_output_and_poll_one_at_a_time() {
        const CLONES: usize = 8;
        const POLLS: usize = 1_000;

        // The inner future wakes itself until its last poll, so every clone keeps polling it from
        // its own thread.
        let polls = Arc::new(AtomicUsize::new(0));
        let shared = {
            let active = AtomicBool::new(false);
            let polls = polls.clone();
            Shared::new(future::poll_fn(move |cx| {
                assert!(
                    !active.swap(true, SeqCst),
                    "inner future polled concurrently"
                );
                thread::yield_now();
                let polled = polls.fetch_add(1, SeqCst) + 1;
                active.store(false, SeqCst);
                if polled == POLLS {
                    return Poll::Ready(Arc::new(polled));
                }
                cx.waker().wake_by_ref();
                Poll::Pending
            }))
        };
        let outputs: Vec<_> = (0..CLONES)
            .map(|_| {
                let shared = shared.clone();
                thread::spawn(move || block_on(shared))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        // Every clone resolved to a clone of the one output.
        for output in &outputs {
            assert!(Arc::ptr_eq(output, &outputs[0]));
        }
        assert_eq!(*outputs[0], POLLS);
        assert_eq!(polls.load(SeqCst), POLLS);
    }

    #[test]
    fn test_clone_after_completion_resolves() {
        let shared = Shared::new(future::ready(5u32));
        assert_eq!(block_on(shared.clone()), 5);
        let (wakes, waker) = counter();
        let mut late = shared.clone();
        assert_eq!(poll(&mut late, &waker), Poll::Ready(5));
        assert_eq!(poll(&mut late, &waker), Poll::Ready(5));
        let mut upgraded = shared.downgrade().upgrade().expect("strong clone alive");
        assert_eq!(poll(&mut upgraded, &waker), Poll::Ready(5));
        assert_eq!(wakes.count(), 0);

        // Completion does not change identity.
        assert!(late.ptr_eq(&shared));
        assert!(!late.ptr_eq(&Shared::new(future::ready(5))));
    }

    #[test]
    fn test_wake_during_poll_rewakes_clone_polled_meanwhile() {
        let control = Arc::new(Control::default());
        let a = Arc::new(Mutex::new(Shared::new(control.future())));
        let mut b = a.lock().clone();
        let (a_wakes, a_waker) = counter();
        let (b_wakes, b_waker) = counter();

        // A polls the inner future, which waits. An earlier event then wakes it, which wakes A.
        assert!(poll(&mut a.lock(), &a_waker).is_pending());
        control.wake();
        assert_eq!(a_wakes.count(), 1);

        // B polls the inner future before A does. After the inner future decides to wait, its
        // final event arrives and wakes it, and A, polled meanwhile, finds B polling and goes
        // back to sleep.
        let parked = Arc::new(AtomicUsize::new(0));
        *control.hook.lock() = Some(Box::new({
            let (control, a, a_waker, a_wakes, parked) = (
                control.clone(),
                a.clone(),
                a_waker.clone(),
                a_wakes.clone(),
                parked.clone(),
            );
            move || {
                control.ready.store(true, SeqCst);
                control.wake();
                assert!(poll(&mut a.lock(), &a_waker).is_pending());
                parked.store(a_wakes.count(), SeqCst);
            }
        }));
        assert!(poll(&mut b, &b_waker).is_pending());
        assert_eq!(control.polls.load(SeqCst), 2);

        // Finishing that poll wakes A again, but not B, whose own waker the final event already
        // woke. B can leave without polling again and A still completes the inner future.
        assert!(a_wakes.count() > parked.load(SeqCst));
        assert_eq!(b_wakes.count(), 1);
        drop(b);
        assert_eq!(poll(&mut a.lock(), &a_waker), Poll::Ready(7));
        assert_eq!(control.polls.load(SeqCst), 3);
    }

    #[test]
    fn test_clone_finding_future_busy_is_woken_after_poll() {
        let control = Arc::new(Control::default());
        let a = Arc::new(Mutex::new(Shared::new(control.future())));
        let mut b = a.lock().clone();
        let (a_wakes, a_waker) = counter();
        let (b_wakes, b_waker) = counter();

        // While B polls the inner future, which is not woken, A finds it busy and waits.
        *control.hook.lock() = Some(Box::new({
            let a = a.clone();
            move || assert!(poll(&mut a.lock(), &a_waker).is_pending())
        }));
        assert!(poll(&mut b, &b_waker).is_pending());

        // B's poll may have done what A waits for, so finishing it wakes A, but not B.
        assert_eq!((a_wakes.count(), b_wakes.count()), (1, 0));
    }

    #[test]
    fn test_dropped_woken_clone_leaves_others_woken() {
        let control = Arc::new(Control::default());
        let mut a = Shared::new(control.future());
        let mut b = a.clone();
        let (a_wakes, a_waker) = counter();
        let (b_wakes, b_waker) = counter();
        assert!(poll(&mut a, &a_waker).is_pending());
        assert!(poll(&mut b, &b_waker).is_pending());

        // The event the inner future waits on wakes both clones, and A is dropped before it is
        // polled again.
        control.ready.store(true, SeqCst);
        control.wake();
        assert_eq!((a_wakes.count(), b_wakes.count()), (1, 1));
        drop(a);

        // The dropped clone is no longer registered, and B completes the inner future.
        control.wake();
        assert_eq!((a_wakes.count(), b_wakes.count()), (1, 2));
        assert_eq!(poll(&mut b, &b_waker), Poll::Ready(7));
    }

    #[test]
    fn test_last_clone_drops_future_despite_retained_waker() {
        struct DropFlag(Arc<AtomicBool>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, SeqCst);
            }
        }

        // The inner future hands its waker to a registration that outlives it, as an event source
        // would.
        let dropped = Arc::new(AtomicBool::new(false));
        let registration: Arc<Mutex<Option<Waker>>> = Arc::default();
        let mut shared = {
            let flag = DropFlag(dropped.clone());
            let registration = registration.clone();
            Shared::new(
                async move {
                    let _flag = flag;
                    future::poll_fn(|cx| {
                        *registration.lock() = Some(cx.waker().clone());
                        Poll::<u32>::Pending
                    })
                    .await
                }
                .boxed(),
            )
        };
        let (_, waker) = counter();
        assert!(poll(&mut shared, &waker).is_pending());
        let weak = shared.downgrade();
        let upgraded = weak.upgrade().expect("strong clone alive");
        assert!(upgraded.ptr_eq(&shared));

        // Only the last clone drops the future, after which upgrading fails and the retained waker
        // wakes nothing.
        drop(shared);
        assert!(!dropped.load(SeqCst));
        drop(upgraded);
        assert!(dropped.load(SeqCst));
        assert!(weak.clone().upgrade().is_none());
        registration.lock().take().unwrap().wake();
        assert!(weak.upgrade().is_none());
    }

    #[test]
    #[should_panic(expected = "Shared future polled after its inner future panicked")]
    fn test_panic_poisons_every_clone() {
        // The inner future wakes itself before waiting, so the next clone polled polls it again.
        let mut polled = false;
        let mut a = Shared::new(future::poll_fn(move |cx| -> Poll<u32> {
            assert!(!polled, "inner future failed");
            polled = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }));
        let mut b = a.clone();
        let (_, a_waker) = counter();
        let (b_wakes, b_waker) = counter();
        assert!(poll(&mut b, &b_waker).is_pending());
        let woken = b_wakes.count();

        // The panic reaches the polling clone and wakes the waiting one, which then panics too.
        let panicked = panic::catch_unwind(AssertUnwindSafe(|| poll(&mut a, &a_waker)));
        assert!(panicked.is_err());
        assert_eq!(b_wakes.count(), woken + 1);
        let _ = poll(&mut b, &b_waker);
    }

    #[test]
    fn test_clones_poll_inner_future_once_per_wake() {
        const CLONES: usize = 8;

        let control = Arc::new(Control::default());
        let shared = Shared::new(control.future());
        let mut clones: Vec<_> = (0..CLONES).map(|_| shared.clone()).collect();
        drop(shared);
        let (wakes, waker) = counter();

        // Only the first clone polls the inner future, which is not woken afterwards.
        for clone in &mut clones {
            assert!(poll(clone, &waker).is_pending());
        }
        assert_eq!(control.polls.load(SeqCst), 1);

        // A wake reaches every clone, and only the first clone polled afterwards polls the inner
        // future.
        control.wake();
        assert_eq!(wakes.count(), CLONES);
        for clone in &mut clones {
            assert!(poll(clone, &waker).is_pending());
        }
        assert_eq!(control.polls.load(SeqCst), 2);

        // Every clone resolves after the final wake, which the first clone polls through.
        control.ready.store(true, SeqCst);
        control.wake();
        for clone in &mut clones {
            assert_eq!(poll(clone, &waker), Poll::Ready(7));
        }
        assert_eq!(control.polls.load(SeqCst), 3);
    }

    /// A waker whose destructor panics.
    struct PanicsOnDrop;

    impl ArcWake for PanicsOnDrop {
        fn wake_by_ref(_: &Arc<Self>) {}
    }

    impl Drop for PanicsOnDrop {
        fn drop(&mut self) {
            panic!("waker destructor failed");
        }
    }

    #[test]
    #[should_panic(expected = "Shared future polled after its inner future panicked")]
    fn test_panicking_replaced_waker_poisons_every_clone() {
        // The inner future wakes itself before waiting, so A polls it again below.
        let mut a = Shared::new(future::poll_fn(|cx| -> Poll<u32> {
            cx.waker().wake_by_ref();
            Poll::Pending
        }));
        let mut b = a.clone();
        let (_, plain) = counter();
        assert!(poll(&mut a, &task::waker(Arc::new(PanicsOnDrop))).is_pending());
        assert!(poll(&mut b, &plain).is_pending());

        // Re-registering A drops its replaced waker, whose destructor panics while A holds the
        // inner future. B observes the panic instead of finding the future busy forever.
        let panicked = panic::catch_unwind(AssertUnwindSafe(|| poll(&mut a, &plain)));
        assert!(panicked.is_err());
        let _ = poll(&mut b, &plain);
    }

    /// Runs `f` on its own thread and fails instead of waiting forever if it does not return, since
    /// a regression that re-enters the state lock would otherwise deadlock the test.
    fn completes(f: impl FnOnce() + Send + 'static) {
        let (done, finished) = std::sync::mpsc::channel();
        thread::spawn(move || {
            f();
            let _ = done.send(());
        });
        finished
            .recv_timeout(Duration::from_secs(10))
            .expect("call re-entered the shared state and deadlocked");
    }

    /// An output whose clones wake the inner future that produced it.
    struct WakingOutput(Arc<Mutex<Option<Waker>>>);

    impl Clone for WakingOutput {
        fn clone(&self) -> Self {
            if let Some(waker) = self.0.lock().as_ref() {
                waker.wake_by_ref();
            }
            Self(self.0.clone())
        }
    }

    #[test]
    fn test_output_clone_may_wake_inner_future() {
        completes(|| {
            let registered = Arc::new(Mutex::new(None));
            let mut a = Shared::new(future::poll_fn(move |cx| {
                *registered.lock() = Some(cx.waker().clone());
                Poll::Ready(WakingOutput(registered.clone()))
            }));
            let mut b = a.clone();
            let (_, waker) = counter();

            // Both the completing clone and a clone polled afterwards clone the output, which
            // wakes the inner future's retained waker.
            assert!(poll(&mut a, &waker).is_ready());
            assert!(poll(&mut b, &waker).is_ready());
        });
    }

    /// A waker that drops a registered clone of a [Shared] when it is dropped.
    struct DropsClone(Mutex<Option<Shared<BoxFuture<'static, ()>>>>);

    impl ArcWake for DropsClone {
        fn wake_by_ref(_: &Arc<Self>) {}
    }

    impl Drop for DropsClone {
        fn drop(&mut self) {
            drop(self.0.lock().take());
        }
    }

    /// A registered waker whose destructor drops `sibling`, a registered clone of the future.
    fn dropping_waker(sibling: Shared<BoxFuture<'static, ()>>) -> Waker {
        task::waker(Arc::new(DropsClone(Mutex::new(Some(sibling)))))
    }

    #[rstest::rstest]
    #[case::replaced(true)]
    #[case::dropped(false)]
    fn test_destroyed_waker_may_drop_a_registered_clone(#[case] replaced: bool) {
        completes(move || {
            let mut a = Shared::new(future::pending::<()>().boxed());
            let mut b = a.clone();
            let (_, plain) = counter();
            assert!(poll(&mut b, &plain).is_pending());
            let waker = dropping_waker(b);
            assert!(poll(&mut a, &waker).is_pending());
            drop(waker);

            // Re-registering A with another waker, or dropping A, destroys its registered waker,
            // which drops the other clone and removes its registration.
            if replaced {
                assert!(poll(&mut a, &plain).is_pending());
            } else {
                drop(a);
            }
        });
    }
}
