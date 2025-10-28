//! Source adapters and source composition for actor services.
//!
//! # Writing custom sources
//!
//! - Use [`poll_fn`] for lightweight, actor-local behavior.
//! - Implement [`Source`] directly for reusable source types.
//! - Return [`Poll::Pending`] for temporarily idle sources.
//! - Return [`Poll::Ready`] with `None` only when a source is permanently exhausted.
//!
//! Exhausted sources shut down the actor service loop.

use commonware_runtime::{Clock, Handle};
use commonware_utils::{
    channel::mpsc,
    futures::{AbortablePool, OptionFuture},
};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use futures::future::Aborted;
use std::time::SystemTime;

/// A poll-based event source for actors.
///
/// Sources are polled by the actor driver and convert external events into actor ingress.
///
/// # Semantics
///
/// - Return [`Poll::Ready`] with `Some(ingress)` to emit one ingress event.
/// - Return [`Poll::Pending`] to remain active without emitting an event.
/// - Return [`Poll::Ready`] with `None` only when the source is permanently exhausted.
///
/// Once a source reports `None`, the service shuts down the actor loop.
///
/// Multiple sources can be composed into a tuple via [`sources!`](crate::sources!).
/// Tuple-based source sets poll in declaration order.
pub trait Source<E, A, I>: Send + 'static {
    /// Poll the source for the next ingress message.
    ///
    /// - [`Poll::Ready`] with `Some(_)` yields a message.
    /// - [`Poll::Ready`] with `None` indicates the source is closed.
    /// - [`Poll::Pending`] indicates no message is currently ready.
    fn poll_next(&mut self, actor: &mut A, context: &E, cx: &mut Context<'_>) -> Poll<Option<I>>;
}

/// Composed set of sources polled by the actor driver.
///
/// This trait is the composition counterpart to [`Source`]. Individual sources
/// implement [`Source`]; tuples of sources implement [`SourceSet`] and poll
/// their elements in declaration order.
///
/// Most users do not implement [`SourceSet`] directly and instead use
/// [`sources!`](crate::sources!).
pub trait SourceSet<E, A, I>: Send + 'static {
    /// Poll the source set for the next ingress message.
    fn poll_next(&mut self, actor: &mut A, context: &E, cx: &mut Context<'_>) -> Poll<Option<I>>;
}

/// Empty source set.
pub struct NoSources;

impl<E, A, I> Source<E, A, I> for NoSources {
    fn poll_next(
        &mut self,
        _actor: &mut A,
        _context: &E,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<I>> {
        Poll::Pending
    }
}

impl<E, A, I> SourceSet<E, A, I> for NoSources {
    fn poll_next(
        &mut self,
        _actor: &mut A,
        _context: &E,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<I>> {
        Poll::Pending
    }
}

/// Generates a [`SourceSet`] impl that delegates to [`Source`] for the given type.
///
/// Usage: `source_is_source_set!({ params } for Type where { bounds });`
macro_rules! source_is_source_set {
    ({ $($params:tt)* } for $ty:ty where { $($bounds:tt)* }) => {
        impl<E, A, I, $($params)*> SourceSet<E, A, I> for $ty
        where
            $($bounds)*
        {
            fn poll_next(
                &mut self,
                actor: &mut A,
                context: &E,
                cx: &mut Context<'_>,
            ) -> Poll<Option<I>> {
                Source::poll_next(self, actor, context, cx)
            }
        }
    };
}

/// Wraps a simple `FnMut(T) -> I` closure to match the full
/// `FnMut(T, &mut A, &E) -> I` signature expected by source adapters.
pub struct Map<F>(pub F);

/// Source adapter for a channel receiver.
pub struct ReceiverSource<T, F> {
    receiver: mpsc::Receiver<T>,
    map: F,
    closed: bool,
}

/// Source adapter for a bounded receiver stored in actor state.
pub struct ReceiverFieldSource<A, T, F>
where
    A: 'static,
{
    get: fn(&mut A) -> &mut mpsc::Receiver<T>,
    map: F,
}

/// Build a source from a bounded receiver stored in actor state.
pub fn recv_field<A, T, F>(
    get: fn(&mut A) -> &mut mpsc::Receiver<T>,
    map: F,
) -> ReceiverFieldSource<A, T, F>
where
    A: 'static,
{
    ReceiverFieldSource { get, map }
}

/// Source adapter for a bounded receiver stored in actor state that emits on close.
pub struct ReceiverFieldOrClosedSource<A, T, F, C>
where
    A: 'static,
{
    get: fn(&mut A) -> &mut mpsc::Receiver<T>,
    map: F,
    closed: C,
    exhausted: bool,
}

/// Build a source from a bounded receiver stored in actor state that emits one close event.
pub fn recv_field_or_closed<A, T, F, C>(
    get: fn(&mut A) -> &mut mpsc::Receiver<T>,
    map: F,
    closed: C,
) -> ReceiverFieldOrClosedSource<A, T, F, C>
where
    A: 'static,
{
    ReceiverFieldOrClosedSource {
        get,
        map,
        closed,
        exhausted: false,
    }
}

/// Source adapter for an unbounded receiver stored in actor state.
pub struct UnboundedReceiverFieldSource<A, T, F>
where
    A: 'static,
{
    get: fn(&mut A) -> &mut mpsc::UnboundedReceiver<T>,
    map: F,
}

/// Build a source from an unbounded receiver stored in actor state.
pub fn recv_unbounded_field<A, T, F>(
    get: fn(&mut A) -> &mut mpsc::UnboundedReceiver<T>,
    map: F,
) -> UnboundedReceiverFieldSource<A, T, F>
where
    A: 'static,
{
    UnboundedReceiverFieldSource { get, map }
}

/// Source adapter for an unbounded receiver stored in actor state that emits on close.
pub struct UnboundedReceiverFieldOrClosedSource<A, T, F, C>
where
    A: 'static,
{
    get: fn(&mut A) -> &mut mpsc::UnboundedReceiver<T>,
    map: F,
    closed: C,
    exhausted: bool,
}

/// Build a source from an unbounded receiver stored in actor state that emits one close event.
pub fn recv_unbounded_field_or_closed<A, T, F, C>(
    get: fn(&mut A) -> &mut mpsc::UnboundedReceiver<T>,
    map: F,
    closed: C,
) -> UnboundedReceiverFieldOrClosedSource<A, T, F, C>
where
    A: 'static,
{
    UnboundedReceiverFieldOrClosedSource {
        get,
        map,
        closed,
        exhausted: false,
    }
}

/// Build a source from a channel receiver.
pub const fn recv<T, F>(receiver: mpsc::Receiver<T>, map: F) -> ReceiverSource<T, F> {
    ReceiverSource {
        receiver,
        map,
        closed: false,
    }
}

impl<E, A, I, T, F> Source<E, A, I> for ReceiverSource<T, F>
where
    T: Send + 'static,
    F: FnMut(T, &mut A, &E) -> I + Send + 'static,
{
    fn poll_next(&mut self, actor: &mut A, context: &E, cx: &mut Context<'_>) -> Poll<Option<I>> {
        if self.closed {
            return Poll::Ready(None);
        }

        match Pin::new(&mut self.receiver).poll_recv(cx) {
            Poll::Ready(Some(message)) => Poll::Ready(Some((self.map)(message, actor, context))),
            Poll::Ready(None) => {
                self.closed = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

source_is_source_set!({ T, F } for ReceiverSource<T, F>
    where { T: Send + 'static, F: FnMut(T, &mut A, &E) -> I + Send + 'static, }
);

impl<E, A, I, T, F> Source<E, A, I> for ReceiverSource<T, Map<F>>
where
    T: Send + 'static,
    F: FnMut(T) -> I + Send + 'static,
{
    fn poll_next(&mut self, _actor: &mut A, _context: &E, cx: &mut Context<'_>) -> Poll<Option<I>> {
        if self.closed {
            return Poll::Ready(None);
        }

        match Pin::new(&mut self.receiver).poll_recv(cx) {
            Poll::Ready(Some(message)) => Poll::Ready(Some((self.map.0)(message))),
            Poll::Ready(None) => {
                self.closed = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

source_is_source_set!({ T, F } for ReceiverSource<T, Map<F>>
    where { T: Send + 'static, F: FnMut(T) -> I + Send + 'static, }
);

impl<E, A, I, T, F> Source<E, A, I> for ReceiverFieldSource<A, T, F>
where
    A: 'static,
    T: Send + 'static,
    F: FnMut(T, &mut A, &E) -> I + Send + 'static,
{
    fn poll_next(&mut self, actor: &mut A, context: &E, cx: &mut Context<'_>) -> Poll<Option<I>> {
        let receiver = (self.get)(actor);
        match Pin::new(receiver).poll_recv(cx) {
            Poll::Ready(Some(message)) => Poll::Ready(Some((self.map)(message, actor, context))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

source_is_source_set!({ T, F } for ReceiverFieldSource<A, T, F>
    where { A: 'static, T: Send + 'static, F: FnMut(T, &mut A, &E) -> I + Send + 'static, }
);

impl<E, A, I, T, F> Source<E, A, I> for ReceiverFieldSource<A, T, Map<F>>
where
    A: 'static,
    T: Send + 'static,
    F: FnMut(T) -> I + Send + 'static,
{
    fn poll_next(&mut self, actor: &mut A, _context: &E, cx: &mut Context<'_>) -> Poll<Option<I>> {
        let receiver = (self.get)(actor);
        match Pin::new(receiver).poll_recv(cx) {
            Poll::Ready(Some(message)) => Poll::Ready(Some((self.map.0)(message))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

source_is_source_set!({ T, F } for ReceiverFieldSource<A, T, Map<F>>
    where { A: 'static, T: Send + 'static, F: FnMut(T) -> I + Send + 'static, }
);

impl<E, A, I, T, F, C> Source<E, A, I> for ReceiverFieldOrClosedSource<A, T, F, C>
where
    A: 'static,
    T: Send + 'static,
    F: FnMut(T, &mut A, &E) -> I + Send + 'static,
    C: FnMut(&mut A, &E) -> I + Send + 'static,
{
    fn poll_next(&mut self, actor: &mut A, context: &E, cx: &mut Context<'_>) -> Poll<Option<I>> {
        if self.exhausted {
            return Poll::Ready(None);
        }

        let receiver = (self.get)(actor);
        match Pin::new(receiver).poll_recv(cx) {
            Poll::Ready(Some(message)) => Poll::Ready(Some((self.map)(message, actor, context))),
            Poll::Ready(None) => {
                self.exhausted = true;
                Poll::Ready(Some((self.closed)(actor, context)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

source_is_source_set!({ T, F, C } for ReceiverFieldOrClosedSource<A, T, F, C>
    where { A: 'static, T: Send + 'static, F: FnMut(T, &mut A, &E) -> I + Send + 'static, C: FnMut(&mut A, &E) -> I + Send + 'static, }
);

impl<E, A, I, T, F> Source<E, A, I> for UnboundedReceiverFieldSource<A, T, F>
where
    A: 'static,
    T: Send + 'static,
    F: FnMut(T, &mut A, &E) -> I + Send + 'static,
{
    fn poll_next(&mut self, actor: &mut A, context: &E, cx: &mut Context<'_>) -> Poll<Option<I>> {
        let receiver = (self.get)(actor);
        match Pin::new(receiver).poll_recv(cx) {
            Poll::Ready(Some(message)) => Poll::Ready(Some((self.map)(message, actor, context))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

source_is_source_set!({ T, F } for UnboundedReceiverFieldSource<A, T, F>
    where { A: 'static, T: Send + 'static, F: FnMut(T, &mut A, &E) -> I + Send + 'static, }
);

impl<E, A, I, T, F, C> Source<E, A, I> for UnboundedReceiverFieldOrClosedSource<A, T, F, C>
where
    A: 'static,
    T: Send + 'static,
    F: FnMut(T, &mut A, &E) -> I + Send + 'static,
    C: FnMut(&mut A, &E) -> I + Send + 'static,
{
    fn poll_next(&mut self, actor: &mut A, context: &E, cx: &mut Context<'_>) -> Poll<Option<I>> {
        if self.exhausted {
            return Poll::Ready(None);
        }

        let receiver = (self.get)(actor);
        match Pin::new(receiver).poll_recv(cx) {
            Poll::Ready(Some(message)) => Poll::Ready(Some((self.map)(message, actor, context))),
            Poll::Ready(None) => {
                self.exhausted = true;
                Poll::Ready(Some((self.closed)(actor, context)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

source_is_source_set!({ T, F, C } for UnboundedReceiverFieldOrClosedSource<A, T, F, C>
    where { A: 'static, T: Send + 'static, F: FnMut(T, &mut A, &E) -> I + Send + 'static, C: FnMut(&mut A, &E) -> I + Send + 'static, }
);

/// Source adapter from a custom poll function.
///
/// Prefer [`PollFnSource`] for one-off custom source behavior before defining a reusable type.
pub struct PollFnSource<F>(F);

/// Build a source from a custom polling function.
///
/// # When to use
///
/// Use [`poll_fn`] when built-in adapters are close but not exact and custom behavior is local
/// to one actor.
///
/// # Pitfalls
///
/// - Do not block in the polling closure.
/// - Return [`Poll::Ready`] with `None` only when the source is truly exhausted.
/// - Keep behavior deterministic.
///
/// # Example
///
/// ```rust,no_run
/// use commonware_actor::source;
/// use core::task::Poll;
///
/// #[derive(Default)]
/// struct State {
///     armed: bool,
/// }
///
/// enum Ingress {
///     Tick,
/// }
///
/// let _source = source::poll_fn(
///     |state: &mut State, _context: &(), _cx: &mut core::task::Context<'_>| {
///     if state.armed {
///         state.armed = false;
///         Poll::Ready(Some(Ingress::Tick))
///     } else {
///         Poll::Pending
///     }
/// });
/// ```
pub const fn poll_fn<F>(f: F) -> PollFnSource<F> {
    PollFnSource(f)
}

impl<E, A, I, F> Source<E, A, I> for PollFnSource<F>
where
    F: FnMut(&mut A, &E, &mut Context<'_>) -> Poll<Option<I>> + Send + 'static,
{
    fn poll_next(&mut self, actor: &mut A, context: &E, cx: &mut Context<'_>) -> Poll<Option<I>> {
        (self.0)(actor, context, cx)
    }
}

source_is_source_set!({ F } for PollFnSource<F>
    where { F: FnMut(&mut A, &E, &mut Context<'_>) -> Poll<Option<I>> + Send + 'static, }
);

/// Source adapter for an optional future that can be re-armed.
///
/// This adapter stores the in-flight future statically using [`OptionFuture`], avoiding heap
/// allocation per arm.
pub struct OptionFutureSource<Fut: Future, Arm, Map> {
    future: OptionFuture<Fut>,
    arm: Arm,
    map: Map,
}

/// Build a source from an optional future and a re-arm closure.
///
/// `arm` is called when there is no in-flight future. `Some(future)` arms it,
/// while `None` leaves the source pending.
///
/// Note: `Fut` must be [`Unpin`] for in-place polling.
pub fn option_future<Fut: Future, Arm, Map>(
    arm: Arm,
    map: Map,
) -> OptionFutureSource<Fut, Arm, Map> {
    OptionFutureSource {
        future: None.into(),
        arm,
        map,
    }
}

impl<E, A, I, Fut, Arm, Map> Source<E, A, I> for OptionFutureSource<Fut, Arm, Map>
where
    Fut: Future + Unpin + Send + 'static,
    Arm: FnMut(&mut A, &E) -> Option<Fut> + Send + 'static,
    Map: FnMut(Fut::Output, &mut A, &E) -> I + Send + 'static,
{
    fn poll_next(&mut self, actor: &mut A, context: &E, cx: &mut Context<'_>) -> Poll<Option<I>> {
        if self.future.is_none() {
            self.future = (self.arm)(actor, context).into();
        }

        let polled = Pin::new(&mut self.future).poll(cx);
        match polled {
            Poll::Ready(value) => {
                self.future = None.into();
                Poll::Ready(Some((self.map)(value, actor, context)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

source_is_source_set!({ Fut, Arm, Map } for OptionFutureSource<Fut, Arm, Map>
    where {
        Fut: Future + Unpin + Send + 'static,
        Arm: FnMut(&mut A, &E) -> Option<Fut> + Send + 'static,
        Map: FnMut(Fut::Output, &mut A, &E) -> I + Send + 'static,
    }
);

/// Source adapter for the next completion in an [`AbortablePool`].
///
/// The `get` accessor is a function pointer so source storage stays static and capture-free.
pub struct PoolNextSource<A, T, Map>
where
    A: 'static,
    T: Send + 'static,
{
    get: fn(&mut A) -> &mut AbortablePool<T>,
    map: Map,
}

/// Build a source that polls `AbortablePool::next_completed()`.
///
/// `map` receives either `Ok(T)` for completion or `Err(Aborted)` when an entry was aborted.
pub fn pool_next<A, T, Map>(
    get: fn(&mut A) -> &mut AbortablePool<T>,
    map: Map,
) -> PoolNextSource<A, T, Map>
where
    A: 'static,
    T: Send + 'static,
{
    PoolNextSource { get, map }
}

impl<E, A, I, T, Map> Source<E, A, I> for PoolNextSource<A, T, Map>
where
    A: 'static,
    T: Send + 'static,
    Map: FnMut(Result<T, Aborted>, &mut A, &E) -> I + Send + 'static,
{
    fn poll_next(&mut self, actor: &mut A, context: &E, cx: &mut Context<'_>) -> Poll<Option<I>> {
        let pool = (self.get)(actor);
        let next = pool.next_completed();
        futures::pin_mut!(next);
        match next.poll(cx) {
            Poll::Ready(result) => Poll::Ready(Some((self.map)(result, actor, context))),
            Poll::Pending => Poll::Pending,
        }
    }
}

source_is_source_set!({ T, Map } for PoolNextSource<A, T, Map>
    where { A: 'static, T: Send + 'static, Map: FnMut(Result<T, Aborted>, &mut A, &E) -> I + Send + 'static, }
);

impl<E, A, I, T, F> Source<E, A, I> for PoolNextSource<A, T, Map<F>>
where
    A: 'static,
    T: Send + 'static,
    F: FnMut(Result<T, Aborted>) -> I + Send + 'static,
{
    fn poll_next(&mut self, actor: &mut A, _context: &E, cx: &mut Context<'_>) -> Poll<Option<I>> {
        let pool = (self.get)(actor);
        let next = pool.next_completed();
        futures::pin_mut!(next);
        match next.poll(cx) {
            Poll::Ready(result) => Poll::Ready(Some((self.map.0)(result))),
            Poll::Pending => Poll::Pending,
        }
    }
}

source_is_source_set!({ T, F } for PoolNextSource<A, T, Map<F>>
    where { A: 'static, T: Send + 'static, F: FnMut(Result<T, Aborted>) -> I + Send + 'static, }
);

/// Source adapter for an optional [`Handle`].
///
/// The `get` accessor is a function pointer so source storage stays static and capture-free.
pub struct HandleSource<A, T, Map>
where
    A: 'static,
    T: Send + 'static,
{
    get: fn(&mut A) -> &mut Option<Handle<T>>,
    map: Map,
}

/// Build a source that polls an optional runtime handle.
///
/// When a handle resolves, it is removed from actor state and converted to ingress via `map`.
pub fn handle<A, T, Map>(
    get: fn(&mut A) -> &mut Option<Handle<T>>,
    map: Map,
) -> HandleSource<A, T, Map>
where
    A: 'static,
    T: Send + 'static,
{
    HandleSource { get, map }
}

impl<E, A, I, T, Map> Source<E, A, I> for HandleSource<A, T, Map>
where
    A: 'static,
    T: Send + 'static,
    Map: FnMut(Result<T, commonware_runtime::Error>, &mut A, &E) -> I + Send + 'static,
{
    fn poll_next(&mut self, actor: &mut A, context: &E, cx: &mut Context<'_>) -> Poll<Option<I>> {
        let output = {
            let slot = (self.get)(actor);
            let Some(handle) = slot.as_mut() else {
                return Poll::Pending;
            };

            match Pin::new(handle).poll(cx) {
                Poll::Ready(output) => {
                    slot.take();
                    output
                }
                Poll::Pending => return Poll::Pending,
            }
        };

        Poll::Ready(Some((self.map)(output, actor, context)))
    }
}

source_is_source_set!({ T, Map } for HandleSource<A, T, Map>
    where { A: 'static, T: Send + 'static, Map: FnMut(Result<T, commonware_runtime::Error>, &mut A, &E) -> I + Send + 'static, }
);

impl<E, A, I, T, F> Source<E, A, I> for HandleSource<A, T, Map<F>>
where
    A: 'static,
    T: Send + 'static,
    F: FnMut(Result<T, commonware_runtime::Error>) -> I + Send + 'static,
{
    fn poll_next(&mut self, actor: &mut A, _context: &E, cx: &mut Context<'_>) -> Poll<Option<I>> {
        let output = {
            let slot = (self.get)(actor);
            let Some(handle) = slot.as_mut() else {
                return Poll::Pending;
            };

            match Pin::new(handle).poll(cx) {
                Poll::Ready(output) => {
                    slot.take();
                    output
                }
                Poll::Pending => return Poll::Pending,
            }
        };

        Poll::Ready(Some((self.map.0)(output)))
    }
}

source_is_source_set!({ T, F } for HandleSource<A, T, Map<F>>
    where { A: 'static, T: Send + 'static, F: FnMut(Result<T, commonware_runtime::Error>) -> I + Send + 'static, }
);

/// Source adapter for dynamic deadlines.
///
/// Deadlines are armed lazily from actor state. The adapter emits exactly one ingress message
/// per armed deadline.
pub struct DeadlineSource<Arm, Emit> {
    arm: Arm,
    emit: Emit,
    deadline: Option<SystemTime>,
}

/// Build a source from a dynamic deadline function.
///
/// `arm` should return the currently armed deadline (if any), and `emit` constructs ingress when
/// the deadline fires.
pub const fn deadline<Arm, Emit>(arm: Arm, emit: Emit) -> DeadlineSource<Arm, Emit> {
    DeadlineSource {
        arm,
        emit,
        deadline: None,
    }
}

impl<E, A, I, Arm, Emit> Source<E, A, I> for DeadlineSource<Arm, Emit>
where
    E: Clock,
    Arm: FnMut(&mut A, &E) -> Option<SystemTime> + Send + 'static,
    Emit: FnMut(&mut A, &E) -> I + Send + 'static,
{
    fn poll_next(&mut self, actor: &mut A, context: &E, cx: &mut Context<'_>) -> Poll<Option<I>> {
        let armed = (self.arm)(actor, context);
        if armed != self.deadline {
            self.deadline = armed;
        }

        let Some(deadline) = self.deadline else {
            return Poll::Pending;
        };

        if context.current() >= deadline {
            self.deadline = None;
            return Poll::Ready(Some((self.emit)(actor, context)));
        }

        let sleep = context.sleep_until(deadline);
        futures::pin_mut!(sleep);
        match sleep.poll(cx) {
            Poll::Ready(()) => {
                self.deadline = None;
                Poll::Ready(Some((self.emit)(actor, context)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

source_is_source_set!({ Arm, Emit } for DeadlineSource<Arm, Emit>
    where {
        E: Clock,
        Arm: FnMut(&mut A, &E) -> Option<SystemTime> + Send + 'static,
        Emit: FnMut(&mut A, &E) -> I + Send + 'static,
    }
);

macro_rules! impl_source_set_tuple {
    ($len:expr; $($idx:tt:$name:ident),+) => {
        impl<E, A, I, $($name),+> SourceSet<E, A, I> for ($($name,)+)
        where
            $($name: Source<E, A, I>,)+
        {
            fn poll_next(
                &mut self,
                actor: &mut A,
                context: &E,
                cx: &mut Context<'_>,
            ) -> Poll<Option<I>> {
                for idx in 0..$len {
                    match idx {
                        $(
                            $idx => {
                                match self.$idx.poll_next(actor, context, cx) {
                                    Poll::Ready(Some(event)) => {
                                        return Poll::Ready(Some(event));
                                    }
                                    Poll::Ready(None) => {
                                        return Poll::Ready(None);
                                    }
                                    Poll::Pending => {}
                                }
                            }
                        )+
                        _ => unreachable!(),
                    }
                }

                Poll::Pending
            }
        }
    };
}

impl_source_set_tuple!(2; 0:S0, 1:S1);
impl_source_set_tuple!(3; 0:S0, 1:S1, 2:S2);
impl_source_set_tuple!(4; 0:S0, 1:S1, 2:S2, 3:S3);
impl_source_set_tuple!(5; 0:S0, 1:S1, 2:S2, 3:S3, 4:S4);
impl_source_set_tuple!(6; 0:S0, 1:S1, 2:S2, 3:S3, 4:S4, 5:S5);
impl_source_set_tuple!(7; 0:S0, 1:S1, 2:S2, 3:S3, 4:S4, 5:S5, 6:S6);
impl_source_set_tuple!(8; 0:S0, 1:S1, 2:S2, 3:S3, 4:S4, 5:S5, 6:S6, 7:S7);
