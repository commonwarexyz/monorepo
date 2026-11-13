//! Thread-bound contexts and `!Send` tasks on runtime threads.
//!
//! A [Local] proves that its holder runs on a runtime thread. It holds an [Rc] to the thread's
//! [Owner], which only the thread creates, so a [Local] cannot leave the thread. The owner keeps
//! the thread-bound state shared code needs: the factories [Local::spawn_local] parks until its
//! task runs, and the result slots of [LocalHandle]s.
//!
//! [Local::spawn_local] is built on [Spawner::spawn_on]. It parks the `!Send` factory with the
//! owner under a fresh id and sends a `Send` shim carrying only that id and the identity of
//! its thread. The shim takes the factory back when it runs on that thread. A shim dropped
//! unrun pushes its id onto the owner's orphan list, and the thread drops the orphaned factory,
//! so parked factories are always dropped on their thread.

use super::Thread;
use crate::{Error, Handle, Spawner, utils::Panicker};
use commonware_utils::sync::Mutex;
use std::{
    any::Any,
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fmt::Display,
    future::{Future, ready},
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    pin::Pin,
    rc::{Rc, Weak},
    sync::Arc,
    task::{Context, Poll, ready},
};

/// A context proven to be on its runtime thread.
///
/// Only the runtime creates one, on the thread, and hands it to the closures of
/// [crate::ThreadBuilder::spawn], [Spawner::spawn_on] and [Local::spawn_local]. It is `!Send`
/// and `!Sync`, because it holds an [Rc] to the thread's owner state, and holding one is what
/// allows spawning `!Send` work with [Local::spawn_local].
///
/// A [Local] dereferences to its context, so `&C` and `&mut C` methods (such as the RNG) work
/// directly. It cannot implement the runtime traits, which require `Send + Sync`, so generic
/// helpers take `&*local` or `&mut *local`, and code that needs an owned context uses
/// [Local::into_inner], or `.into()` where the target type is known. Both give up the proof.
///
/// The context inside is replaceable through [DerefMut]. The proof is the owner, not the
/// context, so [Local::spawn_local] always runs its task on [Local::home], supervised by the
/// context held at the call.
///
/// A [Local] holds a context, so drop it before its runtime returns from
/// [crate::Runner::start].
///
/// # Examples
///
/// A [Local] cannot leave its thread:
///
/// ```compile_fail
/// use commonware_runtime::{Runner, Spawner, Supervisor, deterministic};
///
/// deterministic::Runner::default().start(|context| async move {
///     context.child("t").thread().spawn(|local| async move {
///         std::thread::spawn(move || drop(local)).join().unwrap();
///     }).unwrap().await.unwrap();
/// });
/// ```
///
/// The plain context it holds can:
///
/// ```
/// use commonware_runtime::{Runner, Spawner, Supervisor, deterministic};
///
/// deterministic::Runner::default().start(|context| async move {
///     context.child("t").thread().spawn(|local| async move {
///         let local = local.into_inner();
///         std::thread::spawn(move || drop(local)).join().unwrap();
///     }).unwrap().await.unwrap();
/// });
/// ```
///
/// A [Local] cannot move into an ordinary spawn:
///
/// ```compile_fail
/// use commonware_runtime::{Runner, Spawner, Supervisor, deterministic};
///
/// deterministic::Runner::default().start(|context| async move {
///     context.child("t").thread().spawn(|local| async move {
///         let context = local.child("task").into_inner();
///         context.spawn(move |_| async move { drop(local) }).await.unwrap();
///     }).unwrap().await.unwrap();
/// });
/// ```
///
/// Its plain context can:
///
/// ```
/// use commonware_runtime::{Runner, Spawner, Supervisor, deterministic};
///
/// deterministic::Runner::default().start(|context| async move {
///     context.child("t").thread().spawn(|local| async move {
///         let context = local.child("task").into_inner();
///         let local = local.into_inner();
///         context.spawn(move |_| async move { drop(local) }).await.unwrap();
///     }).unwrap().await.unwrap();
/// });
/// ```
///
/// A [LocalHandle] cannot leave its thread either:
///
/// ```compile_fail
/// use commonware_runtime::{Runner, Spawner, Supervisor, deterministic};
///
/// deterministic::Runner::default().start(|context| async move {
///     context.child("t").thread().spawn(|local| async move {
///         let handle = local.child("task").spawn_local(|_| async {});
///         std::thread::spawn(move || drop(handle)).join().unwrap();
///     }).unwrap().await.unwrap();
/// });
/// ```
///
/// The [Handle] of an ordinary spawn can:
///
/// ```
/// use commonware_runtime::{Runner, Spawner, Supervisor, deterministic};
///
/// deterministic::Runner::default().start(|context| async move {
///     context.child("t").thread().spawn(|local| async move {
///         let handle = local.child("task").into_inner().spawn(|_| async {});
///         std::thread::spawn(move || drop(handle)).join().unwrap();
///     }).unwrap().await.unwrap();
/// });
/// ```
pub struct Local<C> {
    /// The context, parked on the thread unless the holder replaced it.
    context: C,
    /// The owner state of the thread this value lives on.
    owner: Rc<Owner>,
}

impl<C> Local<C> {
    /// A proof for `context` on the thread that owns `owner`.
    pub(crate) const fn new(context: C, owner: Rc<Owner>) -> Self {
        Self { context, owner }
    }

    /// Rewrap the context while keeping the proof.
    ///
    /// This exists for implementing [Spawner] on a wrapper context that delegates to an inner
    /// one. The wrapper's [Spawner::spawn_on] maps the inner [Local] back to the wrapper type.
    ///
    /// ```ignore
    /// fn spawn_on<F, Fut, T>(self, thread: &Thread, f: F) -> Handle<T>
    /// where
    ///     F: FnOnce(Local<Self>) -> Fut + Send + 'static,
    ///     Fut: Future<Output = T> + 'static,
    ///     T: Send + 'static,
    /// {
    ///     let state = self.state;
    ///     self.inner
    ///         .spawn_on(thread, move |local| f(local.map(|inner| Self { inner, state })))
    /// }
    /// ```
    pub fn map<D>(self, f: impl FnOnce(C) -> D) -> Local<D> {
        let Self { context, owner } = self;
        Local {
            context: f(context),
            owner,
        }
    }
}

impl<C: Spawner> Local<C> {
    /// Like [crate::Supervisor::child], keeping the proof.
    pub fn child(&self, label: &'static str) -> Self {
        Self {
            context: self.context.child(label),
            owner: self.owner.clone(),
        }
    }

    /// Like [crate::Supervisor::with_attribute], keeping the proof.
    #[must_use]
    pub fn with_attribute(self, key: &'static str, value: impl Display) -> Self {
        let Self { context, owner } = self;
        Self {
            context: context.with_attribute(key, value),
            owner,
        }
    }

    /// Spawn a resident on this thread. Nothing needs to be `Send`.
    ///
    /// The task always runs on [Local::home], is supervised by the context this value holds,
    /// and receives a [Local] on the thread, whose context is parked like any context a spawn
    /// hands out. `f` runs on this thread after this call returns and before the task's first
    /// poll, so it may borrow state the caller holds borrowed now. The returned [LocalHandle]
    /// cannot leave the thread either.
    ///
    /// If the thread already closed, or the held context belongs to another runner, the
    /// handle resolves [Error::Closed] and `f` is dropped unrun before this returns.
    pub fn spawn_local<F, Fut, T>(self, f: F) -> LocalHandle<T>
    where
        F: FnOnce(Self) -> Fut + 'static,
        Fut: Future<Output = T> + 'static,
        T: 'static,
    {
        let Self { context, owner } = self;
        let home = owner.home().clone();
        let id = owner.next_id();
        let slot = Rc::new(Slot(RefCell::new(None)));
        let parked = Parked {
            factory: f,
            slot: slot.clone(),
        };
        let registered: Weak<dyn SlotAny> = Rc::downgrade(&slot) as Weak<Slot<T>>;
        let handle = match owner.park(id, registered, parked) {
            Ok(orphans) => {
                let shim = Shim::<F, T> {
                    id,
                    runner: home.inner().runner(),
                    thread: home.inner().id(),
                    orphans,
                    armed: true,
                    parked: PhantomData,
                };
                let handle = context.spawn_on(&home, move |local| shim.run(local));

                // A rejected submission has already dropped its armed shim, so this drops the
                // parked factory on the spot.
                owner.reap();
                handle
            }
            Err(parked) => {
                // The thread closed, so nothing can take a parked factory. The runtime rejects
                // the spawn and closes the context's node.
                owner.dispose(parked);
                context.spawn_on(&home, |_| ready(()))
            }
        };
        LocalHandle {
            handle,
            slot,
            owner,
            id,
        }
    }

    /// The thread this value lives on.
    pub fn home(&self) -> &Thread {
        self.owner.home()
    }

    /// Return the plain context, giving up the proof. Unless the holder replaced it, it is
    /// parked on this thread, so its spawns run on the shared executor until
    /// [crate::Spawner::placed] unparks it.
    pub fn into_inner(self) -> C {
        self.context
    }

    /// The owner state of the thread this value lives on.
    #[cfg(test)]
    pub(crate) const fn owner(&self) -> &Rc<Owner> {
        &self.owner
    }
}

impl<C> Deref for Local<C> {
    type Target = C;

    fn deref(&self) -> &C {
        &self.context
    }
}

impl<C> DerefMut for Local<C> {
    fn deref_mut(&mut self) -> &mut C {
        &mut self.context
    }
}

/// Join handle for a [Local::spawn_local] task.
///
/// It is `!Send` and `!Sync` for every `T`, and resolves on the task's thread. Dropping it
/// detaches the task, whose output is then dropped on the thread. If the thread closes before
/// the handle takes a finished task's output, the output is dropped on the thread and the
/// handle resolves [Error::Closed].
pub struct LocalHandle<T> {
    /// Handle of the task, which resolves once the output is in `slot`.
    handle: Handle<()>,
    /// Holds the task's output until the handle takes it.
    slot: Rc<Slot<T>>,
    /// The owner the slot is registered with.
    owner: Rc<Owner>,
    /// The slot's id in the owner's registry.
    id: u64,
}

impl<T: 'static> LocalHandle<T> {
    /// Abort the task. Has no effect once it completed. Finishes the running-task metric at
    /// once, like [Handle::abort].
    pub fn abort(&self) {
        self.handle.abort();
    }
}

impl<T: 'static> Future for LocalHandle<T> {
    type Output = Result<T, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        ready!(Pin::new(&mut this.handle).poll(cx))?;

        // The task completed, so its output is in the slot unless the thread discarded it.
        this.owner.remove_slot(this.id);
        let output = this.slot.0.borrow_mut().take();
        Poll::Ready(output.ok_or(Error::Closed))
    }
}

impl<T> Drop for LocalHandle<T> {
    fn drop(&mut self) {
        // An output the handle never took is the runtime's to dispose of. A task still running
        // keeps the slot and drops its output with itself.
        self.owner.remove_slot(self.id);
        let output = self.slot.0.borrow_mut().take();
        if let Some(output) = output {
            self.owner.dispose(output);
        }
    }
}

/// The thread-bound state shared code keeps for a runtime thread.
///
/// The backend creates one on the thread. The home thread, the panicker and the disposal policy
/// stay for its whole life. The parked factories, the orphan list and the result slots sit in an
/// [Option] that the thread's close takes.
pub(crate) struct Owner {
    /// The thread this owner belongs to.
    home: Thread,
    /// Reports panics of the thread's tasks.
    panicker: Panicker,
    /// Whether disposal panics are reported through `panicker` (otherwise contained).
    report_disposals: bool,
    /// Id of the next parked factory.
    next: Cell<u64>,
    /// State the thread's close takes.
    state: RefCell<Option<OwnerState>>,
}

/// The parts of an [Owner] that the thread's close takes.
struct OwnerState {
    /// Factories of [Local::spawn_local] tasks that have not started, by id.
    parked: BTreeMap<u64, Box<dyn Any>>,
    /// Ids whose shims were dropped unrun, shared with the shims.
    orphans: Arc<Mutex<Vec<u64>>>,
    /// Result slots of live [LocalHandle]s, by id.
    slots: BTreeMap<u64, Weak<dyn SlotAny>>,
}

impl Owner {
    /// The owner of `home`, reporting task panics through `panicker`, and disposal panics too
    /// if `report_disposals` is set.
    pub(crate) fn new(home: Thread, panicker: Panicker, report_disposals: bool) -> Rc<Self> {
        Rc::new(Self {
            home,
            panicker,
            report_disposals,
            next: Cell::new(0),
            state: RefCell::new(Some(OwnerState {
                parked: BTreeMap::new(),
                orphans: Arc::new(Mutex::new(Vec::new())),
                slots: BTreeMap::new(),
            })),
        })
    }

    /// The thread this owner belongs to.
    pub(crate) const fn home(&self) -> &Thread {
        &self.home
    }

    /// Reports panics of the thread's tasks.
    pub(crate) const fn panicker(&self) -> &Panicker {
        &self.panicker
    }

    /// A parked factory id this owner has not used.
    fn next_id(&self) -> u64 {
        let id = self.next.get();
        self.next.set(id + 1);
        id
    }

    /// Drop `value` in its own panic boundary, reporting a panic through the panicker or
    /// containing it, as the backend's disposal policy says.
    pub(crate) fn dispose<V>(&self, value: V) {
        if let Err(panic) = catch_unwind(AssertUnwindSafe(move || drop(value))) {
            if self.report_disposals {
                self.panicker.notify(panic);
            } else {
                contain(panic);
            }
        }
    }

    /// Park `factory` under `id` and register `slot`, returning the orphan list, or return
    /// `factory` if the thread's close already took the state.
    fn park<P: 'static>(
        &self,
        id: u64,
        slot: Weak<dyn SlotAny>,
        factory: P,
    ) -> Result<Arc<Mutex<Vec<u64>>>, P> {
        let mut state = self.state.borrow_mut();
        let Some(state) = state.as_mut() else {
            return Err(factory);
        };
        state.parked.insert(id, Box::new(factory));
        state.slots.insert(id, slot);
        Ok(state.orphans.clone())
    }

    /// Take the factory parked under `id`, if it is still there.
    fn take_parked(&self, id: u64) -> Option<Box<dyn Any>> {
        self.state
            .borrow_mut()
            .as_mut()
            .and_then(|state| state.parked.remove(&id))
    }

    /// Unregister the result slot `id`.
    fn remove_slot(&self, id: u64) {
        if let Some(state) = self.state.borrow_mut().as_mut() {
            state.slots.remove(&id);
        }
    }

    /// Drop the factories whose shims were dropped unrun, each in its own panic boundary. When
    /// nothing was orphaned this is one uncontended lock and a length check.
    pub(crate) fn reap(&self) {
        let orphans = {
            let state = self.state.borrow();
            let Some(state) = state.as_ref() else {
                return;
            };
            let mut orphans = state.orphans.lock();
            if orphans.is_empty() {
                return;
            }
            mem::take(&mut *orphans)
        };
        for id in orphans {
            if let Some(factory) = self.take_parked(id) {
                self.dispose(factory);
            }
        }
    }

    /// Take the close-time state, then drop every parked factory and clear every result slot,
    /// each in its own panic boundary. Later calls do nothing, and a later
    /// [Local::spawn_local] parks nothing.
    pub(crate) fn close(&self) {
        let state = self.state.borrow_mut().take();
        let Some(OwnerState { parked, slots, .. }) = state else {
            return;
        };
        for factory in parked.into_values() {
            self.dispose(factory);
        }
        for slot in slots.into_values() {
            if let Some(slot) = slot.upgrade() {
                slot.clear(self);
            }
        }
    }

    /// Number of parked factories.
    #[cfg(test)]
    pub(crate) fn parked(&self) -> usize {
        self.state
            .borrow()
            .as_ref()
            .map_or(0, |state| state.parked.len())
    }
}

/// Discard a caught panic payload, containing any panic its destructor raises.
fn contain(panic: Box<dyn Any + Send>) {
    if let Err(secondary) = catch_unwind(AssertUnwindSafe(move || drop(panic))) {
        mem::forget(secondary);
    }
}

/// A [Local::spawn_local] factory parked with the owner, with the slot its output goes to.
struct Parked<F, T> {
    /// The user's factory.
    factory: F,
    /// The task's result slot.
    slot: Rc<Slot<T>>,
}

/// The `Send` factory [Local::spawn_local] sends to the thread, carrying only the id of the
/// parked factory and the identity of the thread it is parked on.
struct Shim<F, T> {
    /// Id of the parked factory in its owner.
    id: u64,
    /// Runner instance of the thread the factory is parked on.
    runner: u64,
    /// Id of that thread in its runner.
    thread: u64,
    /// Where the shim records its id if it is dropped unrun.
    orphans: Arc<Mutex<Vec<u64>>>,
    /// Whether the shim was dropped unrun.
    armed: bool,
    /// The parked factory's type, without owning one.
    parked: PhantomData<fn() -> (F, T)>,
}

impl<F, T> Shim<F, T> {
    /// Take the parked factory back through `local`'s owner, run it, and return the task's
    /// future. A factory that is missing, for example because a wrapper delivered the shim to
    /// another thread, gives a future that completes at once with an empty slot.
    fn run<C, Fut>(mut self, local: Local<C>) -> ShimFuture<Fut>
    where
        F: FnOnce(Local<C>) -> Fut + 'static,
        Fut: Future<Output = T> + 'static,
        T: 'static,
    {
        // A shim delivered elsewhere stays armed, so its home thread reaps the parked factory.
        let home = local.owner.home().inner();
        if home.runner() != self.runner || home.id() != self.thread {
            return ShimFuture::Missing;
        }
        self.armed = false;
        let Some(parked) = local.owner.take_parked(self.id) else {
            return ShimFuture::Missing;
        };
        match parked.downcast::<Parked<F, T>>() {
            Ok(parked) => {
                let Parked { factory, slot } = *parked;
                let owner = local.owner.clone();
                let future = Some(Box::pin(factory(local)));
                ShimFuture::Job(LocalJob {
                    future,
                    slot,
                    owner,
                })
            }
            Err(other) => {
                local.owner.dispose(other);
                ShimFuture::Missing
            }
        }
    }
}

/// The future a [Shim] builds on its thread.
enum ShimFuture<Fut: Future> {
    /// The parked factory's task.
    Job(LocalJob<Fut>),
    /// The parked factory was not there, so the task completes at once with an empty slot.
    Missing,
}

impl<Fut: Future> Future for ShimFuture<Fut> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        match self.get_mut() {
            Self::Job(job) => Pin::new(job).poll(cx),
            Self::Missing => Poll::Ready(()),
        }
    }
}

impl<F, T> Drop for Shim<F, T> {
    fn drop(&mut self) {
        if self.armed {
            self.orphans.lock().push(self.id);
        }
    }
}

/// The future of a [Local::spawn_local] task: the user's future, whose output goes to the
/// task's slot.
///
/// It keeps the completed future in its field, so the task wrapper drops it after the poll that
/// completed it, and a destructor panic there is a disposal panic. If that destructor panics,
/// the job disposes of the output, which can no longer be delivered, in a boundary of its own.
struct LocalJob<Fut: Future> {
    /// The user's future, taken only by the job's drop.
    future: Option<Pin<Box<Fut>>>,
    /// Receives the output.
    slot: Rc<Slot<Fut::Output>>,
    /// Disposes of an output the job owns.
    owner: Rc<Owner>,
}

impl<Fut: Future> Future for LocalJob<Fut> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let future = this.future.as_mut().expect("a local job keeps its future");
        let output = ready!(future.as_mut().poll(cx));
        *this.slot.0.borrow_mut() = Some(output);
        Poll::Ready(())
    }
}

impl<Fut: Future> Drop for LocalJob<Fut> {
    fn drop(&mut self) {
        let future = self.future.take();
        if let Err(panic) = catch_unwind(AssertUnwindSafe(move || drop(future))) {
            // The unwind resolves the handle Closed, so the output can never be delivered.
            // Dispose of it in its own boundary, since dropping it during this unwind could
            // panic a second time and abort the process, then continue the unwind as a
            // disposal panic of the task.
            let output = self.slot.0.borrow_mut().take();
            self.owner.dispose(output);
            resume_unwind(panic);
        }
    }
}

/// The output of a [Local::spawn_local] task, until its handle takes it.
struct Slot<T>(RefCell<Option<T>>);

/// A result slot, without its output type.
trait SlotAny {
    /// Drop the slot's output, if any, through `owner`'s disposal policy.
    fn clear(&self, owner: &Owner);
}

impl<T> SlotAny for Slot<T> {
    fn clear(&self, owner: &Owner) {
        let output = self.0.borrow_mut().take();
        if let Some(output) = output {
            owner.dispose(output);
        }
    }
}
