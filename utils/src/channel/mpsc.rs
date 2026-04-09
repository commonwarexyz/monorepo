//! Tokio-compatible MPSC wrappers with a transparent local fast path.

use crate::sync::{Condvar, Mutex};
use futures::{future::poll_fn, task::AtomicWaker};
use std::{
    cell::UnsafeCell,
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
};
use tokio::sync::{mpsc as tokio_mpsc, Notify};

pub mod error {
    pub use tokio::sync::mpsc::error::{SendError, TryRecvError, TrySendError};
}

use error::{SendError, TryRecvError, TrySendError};

const MODE_UNINITIALIZED: u8 = 0;
const MODE_BINDING_LOCAL: u8 = 1;
const MODE_BINDING_SHARED: u8 = 2;
const MODE_LOCAL: u8 = 3;
const MODE_PROMOTING: u8 = 4;
const MODE_SHARED: u8 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Uninitialized,
    BindingLocal,
    BindingShared,
    Local,
    Promoting,
    Shared,
}

impl Mode {
    const fn as_u8(self) -> u8 {
        match self {
            Self::Uninitialized => MODE_UNINITIALIZED,
            Self::BindingLocal => MODE_BINDING_LOCAL,
            Self::BindingShared => MODE_BINDING_SHARED,
            Self::Local => MODE_LOCAL,
            Self::Promoting => MODE_PROMOTING,
            Self::Shared => MODE_SHARED,
        }
    }

    #[inline(always)]
    const fn from_u8(mode: u8) -> Self {
        match mode {
            MODE_UNINITIALIZED => Self::Uninitialized,
            MODE_BINDING_LOCAL => Self::BindingLocal,
            MODE_BINDING_SHARED => Self::BindingShared,
            MODE_LOCAL => Self::Local,
            MODE_PROMOTING => Self::Promoting,
            MODE_SHARED => Self::Shared,
            _ => panic!("invalid channel mode"),
        }
    }
}

struct LocalQueue<T> {
    queue: VecDeque<T>,
}

struct Common<T> {
    mode: AtomicU8,
    owner_id: AtomicU64,
    owner: Mutex<Option<runtime::OwnerHandle>>,
    sender_count: AtomicUsize,
    closed: AtomicBool,
    receiver_alive: AtomicBool,
    local: UnsafeCell<LocalQueue<T>>,
    local_recv_waker: UnsafeCell<Option<Waker>>,
    recv_waker: AtomicWaker,
    state_lock: Mutex<()>,
    state_condvar: Condvar,
    state_notify: Notify,
    closed_notify: Notify,
}

impl<T> Common<T> {
    #[inline]
    fn new(local_capacity: usize) -> Self {
        Self {
            mode: AtomicU8::new(Mode::Uninitialized.as_u8()),
            owner_id: AtomicU64::new(0),
            owner: Mutex::new(None),
            sender_count: AtomicUsize::new(1),
            closed: AtomicBool::new(false),
            receiver_alive: AtomicBool::new(true),
            local: UnsafeCell::new(LocalQueue {
                queue: VecDeque::with_capacity(local_capacity),
            }),
            local_recv_waker: UnsafeCell::new(None),
            recv_waker: AtomicWaker::new(),
            state_lock: Mutex::new(()),
            state_condvar: Condvar::new(),
            state_notify: Notify::new(),
            closed_notify: Notify::new(),
        }
    }

    #[inline]
    fn load_mode(&self) -> Mode {
        Mode::from_u8(self.mode.load(Ordering::Acquire))
    }

    #[inline(always)]
    fn load_mode_raw_relaxed(&self) -> u8 {
        self.mode.load(Ordering::Relaxed)
    }

    #[inline]
    fn current_is_owner(&self) -> bool {
        runtime::current_owner_id_raw() == self.owner_id.load(Ordering::Relaxed)
    }

    fn set_closed(&self) -> bool {
        let changed = !self.closed.swap(true, Ordering::AcqRel);
        if changed {
            self.closed_notify.notify_waiters();
            self.wake_owner_if_local();
            self.notify_state_change();
        }
        changed
    }

    fn mark_receiver_dropped(&self) {
        self.receiver_alive.store(false, Ordering::Release);
        self.set_closed();
    }

    #[inline]
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    #[inline]
    fn no_senders(&self) -> bool {
        self.sender_count.load(Ordering::Acquire) == 0
    }

    fn sender_cloned(&self) {
        self.sender_count.fetch_add(1, Ordering::AcqRel);
    }

    fn sender_dropped(&self) {
        if self.sender_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.wake_owner_if_local();
            self.notify_state_change();
        }
    }

    #[inline]
    fn should_terminate_after_empty(&self) -> bool {
        self.is_closed() || self.no_senders()
    }

    fn notify_state_change(&self) {
        self.state_notify.notify_waiters();
        self.state_condvar.notify_all();
        self.recv_waker.wake();
    }

    fn publish_shared(&self) {
        *self.owner.lock() = None;
        self.owner_id.store(0, Ordering::Release);
        self.mode.store(Mode::Shared.as_u8(), Ordering::Release);
        self.notify_state_change();
    }

    fn wait_binding_complete(&self) {
        while matches!(self.load_mode(), Mode::BindingLocal | Mode::BindingShared) {
            std::hint::spin_loop();
        }
    }

    fn wait_mode_change_blocking(&self, mode: Mode) {
        let mut guard = self.state_lock.lock();
        while self.load_mode() == mode {
            self.state_condvar.wait(&mut guard);
        }
    }

    async fn wait_closed_async(&self) {
        loop {
            let notified = self.closed_notify.notified();
            if self.is_closed() {
                return;
            }
            notified.await;
        }
    }

    async fn wait_mode_change_async(&self, mode: Mode) {
        poll_fn(|cx| {
            let mut notified = std::pin::pin!(self.state_notify.notified());
            if self.load_mode() != mode {
                return Poll::Ready(());
            }
            match notified.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(()),
                Poll::Pending if self.load_mode() != mode => Poll::Ready(()),
                Poll::Pending => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        })
        .await
    }

    #[inline]
    fn local_queue_ptr(&self) -> *mut VecDeque<T> {
        // SAFETY: callers that dereference the pointer guarantee only the owner
        // thread accesses the queue while the channel is in local mode, or
        // after the owner loop has exited.
        unsafe { std::ptr::addr_of_mut!((*self.local.get()).queue) }
    }

    fn clear_local_queue(&self) {
        // SAFETY: callers uphold the local-queue access invariant.
        unsafe {
            (*self.local_queue_ptr()).clear();
        }
    }

    #[inline]
    const fn local_recv_waker_ptr(&self) -> *mut Option<Waker> {
        // SAFETY: callers that dereference the pointer guarantee only the owner
        // thread accesses the local receiver waker while the channel is in
        // local mode, or after the owner loop has exited.
        self.local_recv_waker.get()
    }

    #[inline]
    fn register_local_recv_waker(&self, waker: &Waker) {
        // SAFETY: owner-thread-only local mode access.
        unsafe {
            let slot = &mut *self.local_recv_waker_ptr();
            if slot.as_ref().is_none_or(|existing| !existing.will_wake(waker)) {
                *slot = Some(waker.clone());
            }
        }
    }

    #[inline]
    fn wake_local_recv(&self) {
        // SAFETY: owner-thread-only local mode access.
        unsafe {
            if let Some(waker) = (&*self.local_recv_waker_ptr()).as_ref() {
                waker.wake_by_ref();
            }
        }
    }

    fn wake_owner_if_local(&self) {
        if self.current_is_owner() {
            self.wake_local_recv();
            return;
        }
        if !matches!(self.load_mode(), Mode::Local | Mode::Promoting) {
            return;
        }
        if let Some(owner) = self.owner.lock().clone() {
            runtime::wake_owner(&owner);
        }
    }
}

// SAFETY: foreign threads never access the local queue directly. Access is
// restricted to the bound owner thread, or after the owner loop has exited.
unsafe impl<T: Send> Send for Common<T> {}
// SAFETY: shared access is synchronized except for the owner-thread-affine
// queue, which follows the invariant described above.
unsafe impl<T: Send> Sync for Common<T> {}

struct BoundedInner<T> {
    common: Common<T>,
    capacity: usize,
    promotion_fallback: Mutex<Option<tokio_mpsc::Sender<T>>>,
    space_notify: Notify,
}

impl<T> BoundedInner<T> {
    fn new(capacity: usize, fallback: tokio_mpsc::Sender<T>) -> Self {
        Self {
            common: Common::new(capacity),
            capacity,
            promotion_fallback: Mutex::new(Some(fallback)),
            space_notify: Notify::new(),
        }
    }

    fn try_initialize(&self) {
        let owner = runtime::current_owner();
        let binding = if owner.is_some() {
            Mode::BindingLocal
        } else {
            Mode::BindingShared
        };
        if self
            .common
            .mode
            .compare_exchange(
                Mode::Uninitialized.as_u8(),
                binding.as_u8(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }

        match owner {
            Some(owner) => {
                self.common.owner_id.store(owner.id, Ordering::Release);
                *self.common.owner.lock() = Some(owner);
                self.common.mode.store(Mode::Local.as_u8(), Ordering::Release);
                self.common.notify_state_change();
            }
            None => {
                self.promotion_fallback.lock().take();
                self.common.publish_shared();
            }
        }
    }

    fn notify_space(&self) {
        self.space_notify.notify_one();
    }

    fn notify_space_all(&self) {
        self.space_notify.notify_waiters();
    }

    #[inline]
    fn try_send_local(&self, value: T) -> Result<(), TrySendError<T>> {
        if self.common.is_closed() {
            return Err(TrySendError::Closed(value));
        }

        // SAFETY: local mode only permits owner-thread access.
        let queue = unsafe { &mut *self.common.local_queue_ptr() };
        if queue.len() >= self.capacity {
            return Err(TrySendError::Full(value));
        }
        let was_empty = queue.is_empty();
        queue.push_back(value);
        if was_empty {
            self.common.wake_local_recv();
        }
        Ok(())
    }

    #[inline(always)]
    fn try_send_shared(
        &self,
        fallback: &tokio_mpsc::Sender<T>,
        value: T,
    ) -> Result<(), TrySendError<T>> {
        match fallback.try_send(value) {
            Ok(()) => Ok(()),
            Err(TrySendError::Closed(value)) => {
                self.common.set_closed();
                Err(TrySendError::Closed(value))
            }
            Err(TrySendError::Full(value)) => Err(TrySendError::Full(value)),
        }
    }

    #[inline]
    fn try_recv_local(&self) -> Result<T, TryRecvError> {
        // SAFETY: local mode only permits owner-thread access.
        let queue = unsafe { &mut *self.common.local_queue_ptr() };
        let was_full = queue.len() == self.capacity;
        if let Some(value) = queue.pop_front() {
            if was_full {
                self.notify_space();
            }
            return Ok(value);
        }
        if self.common.should_terminate_after_empty() {
            Err(TryRecvError::Disconnected)
        } else {
            Err(TryRecvError::Empty)
        }
    }

    fn promote_if_owner(&self) {
        if self.common.load_mode() == Mode::Promoting && self.common.current_is_owner() {
            self.run_promotion();
        }
    }

    fn start_promotion(this: &Arc<Self>) {
        if this
            .common
            .mode
            .compare_exchange(
                Mode::Local.as_u8(),
                Mode::Promoting.as_u8(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }

        let Some(owner) = this.common.owner.lock().clone() else {
            // The owner already finished draining or tearing down the local
            // state and is in the middle of publishing shared mode.
            this.common.clear_local_queue();
            this.promotion_fallback.lock().take();
            this.common.publish_shared();
            this.notify_space_all();
            return;
        };
        let request = BoundedPromotion {
            inner: Arc::clone(this),
        };

        if runtime::enqueue_promotion(&owner, request).is_err() {
            // The owner loop is gone, so no thread will touch the local queue.
            this.common.clear_local_queue();
            this.promotion_fallback.lock().take();
            this.common.publish_shared();
            this.notify_space_all();
            return;
        }

        this.common.notify_state_change();
    }

    fn run_promotion(&self) {
        if self.common.load_mode() != Mode::Promoting {
            return;
        }

        // SAFETY: promotion runs only on the owner thread, or after the owner
        // loop has exited and no further local access can occur.
        let queue = unsafe { &mut *self.common.local_queue_ptr() };
        let fallback = self
            .promotion_fallback
            .lock()
            .clone()
            .expect("promoting channel must retain fallback sender");
        if !self.common.receiver_alive.load(Ordering::Acquire) {
            queue.clear();
        } else {
            let mut fallback_closed = false;
            while let Some(value) = queue.pop_front() {
                match fallback.try_send(value) {
                    Ok(()) => {}
                    Err(TrySendError::Closed(_)) => {
                        fallback_closed = true;
                        break;
                    }
                    Err(TrySendError::Full(_)) => {
                        unreachable!("fallback must stay empty until promotion")
                    }
                }
            }
            if fallback_closed {
                queue.clear();
                self.common.mark_receiver_dropped();
            }
        }

        self.promotion_fallback.lock().take();
        self.common.publish_shared();
        self.notify_space_all();
    }
}

struct BoundedPromotion<T> {
    inner: Arc<BoundedInner<T>>,
}

impl<T> runtime::PromotionJob for BoundedPromotion<T> {
    fn run(self: Box<Self>) {
        self.inner.run_promotion();
    }
}

struct BoundedRecvFuture<'a, T> {
    receiver: &'a mut Receiver<T>,
}

impl<T> Future for BoundedRecvFuture<'_, T> {
    type Output = Option<T>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().receiver.poll_recv(cx)
    }
}

pub struct Sender<T> {
    inner: Arc<BoundedInner<T>>,
    fallback: tokio_mpsc::Sender<T>,
}

impl<T> core::fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sender")
            .field("mode", &self.inner.common.load_mode())
            .field("is_closed", &self.is_closed())
            .finish()
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        self.inner.common.sender_cloned();
        Self {
            inner: Arc::clone(&self.inner),
            fallback: self.fallback.clone(),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        self.inner.common.sender_dropped();
    }
}

impl<T> Sender<T> {
    #[inline]
    pub async fn send(&self, value: T) -> Result<(), SendError<T>> {
        let mode = self.inner.common.load_mode_raw_relaxed();
        if mode == MODE_SHARED {
            return match self.fallback.send(value).await {
                Ok(()) => Ok(()),
                Err(err) => {
                    self.inner.common.set_closed();
                    Err(err)
                }
            };
        }
        if mode == MODE_LOCAL && self.inner.common.current_is_owner() {
            return self.send_local_owner(value).await;
        }
        self.send_slow_async(value).await
    }
}

impl<T> Sender<T> {
    async fn send_local_owner(&self, mut value: T) -> Result<(), SendError<T>> {
        loop {
            match self.inner.try_send_local(value) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Closed(value)) => return Err(SendError(value)),
                Err(TrySendError::Full(full)) => {
                    value = full;
                    if self.is_closed() {
                        return Err(SendError(value));
                    }
                    self.inner.space_notify.notified().await;
                    if self.inner.common.load_mode() != Mode::Local
                        || !self.inner.common.current_is_owner()
                    {
                        return self.send_slow_async(value).await;
                    }
                }
            }
        }
    }

    async fn send_slow_async(&self, value: T) -> Result<(), SendError<T>> {
        let mut value = Some(value);
        loop {
            match self.try_send_fast_local(value.take().expect("value must be present")) {
                Ok(result) => {
                    match result {
                        Ok(()) => return Ok(()),
                        Err(TrySendError::Closed(value)) => return Err(SendError(value)),
                        Err(TrySendError::Full(full)) => {
                            value = Some(full);
                            if self.is_closed() {
                                return Err(SendError(
                                    value.take().expect("value must be present"),
                                ));
                            }
                            self.inner.space_notify.notified().await;
                        }
                    }
                    continue;
                }
                Err(pending) => value = Some(pending),
            }

            self.inner.promote_if_owner();
            match self.inner.common.load_mode() {
                Mode::Uninitialized => self.inner.try_initialize(),
                Mode::BindingLocal | Mode::BindingShared => {
                    self.inner.common.wait_binding_complete();
                }
                Mode::Local if self.inner.common.current_is_owner() => {
                    match self
                        .inner
                        .try_send_local(value.take().expect("value must be present"))
                    {
                        Ok(()) => return Ok(()),
                        Err(TrySendError::Closed(value)) => return Err(SendError(value)),
                        Err(TrySendError::Full(full)) => {
                            value = Some(full);
                            if self.is_closed() {
                                return Err(SendError(value.take().expect("value must be present")));
                            }
                            self.inner.space_notify.notified().await;
                        }
                    }
                }
                Mode::Local => {
                    if self.inner.common.is_closed() {
                        return Err(SendError(value.take().expect("value must be present")));
                    }
                    BoundedInner::start_promotion(&self.inner);
                    let mode = self.inner.common.load_mode();
                    match mode {
                        Mode::Local | Mode::Promoting => {
                            self.inner.common.wait_mode_change_async(mode).await;
                        }
                        _ => {}
                    }
                }
                Mode::Promoting if self.inner.common.current_is_owner() => {
                    self.inner.run_promotion();
                }
                Mode::Promoting => {
                    if self.inner.common.is_closed() {
                        return Err(SendError(value.take().expect("value must be present")));
                    }
                    self.inner.common.wait_mode_change_async(Mode::Promoting).await;
                }
                Mode::Shared => {
                    return match self.fallback.send(value.take().expect("value must be present")).await
                    {
                        Ok(()) => Ok(()),
                        Err(err) => {
                            self.inner.common.set_closed();
                            Err(err)
                        }
                    };
                }
            }
        }
    }
}

impl<T> Sender<T> {
    pub fn try_send(&self, value: T) -> Result<(), TrySendError<T>> {
        match self.try_send_fast(value) {
            Ok(result) => result,
            Err(value) => self.try_send_slow(value),
        }
    }

    pub async fn closed(&self) {
        self.inner.common.wait_closed_async().await;
    }

    pub fn is_closed(&self) -> bool {
        self.inner.common.is_closed()
    }

    #[inline]
    fn try_send_fast_local(&self, value: T) -> Result<Result<(), TrySendError<T>>, T> {
        let mode = self.inner.common.load_mode_raw_relaxed();
        if mode == MODE_LOCAL && self.inner.common.current_is_owner() {
            Ok(self.inner.try_send_local(value))
        } else {
            Err(value)
        }
    }

    #[inline]
    fn try_send_fast(&self, value: T) -> Result<Result<(), TrySendError<T>>, T> {
        let mode = self.inner.common.load_mode_raw_relaxed();
        if mode == MODE_SHARED {
            Ok(self.inner.try_send_shared(&self.fallback, value))
        } else if mode == MODE_LOCAL && self.inner.common.current_is_owner() {
            Ok(self.inner.try_send_local(value))
        } else {
            Err(value)
        }
    }

    #[cold]
    fn try_send_slow(&self, value: T) -> Result<(), TrySendError<T>> {
        loop {
            self.inner.promote_if_owner();
            match self.inner.common.load_mode() {
                Mode::Uninitialized => self.inner.try_initialize(),
                Mode::BindingLocal | Mode::BindingShared => self.inner.common.wait_binding_complete(),
                Mode::Local if self.inner.common.current_is_owner() => {
                    return self.inner.try_send_local(value);
                }
                Mode::Local => {
                    if self.inner.common.is_closed() {
                        return Err(TrySendError::Closed(value));
                    }
                    BoundedInner::start_promotion(&self.inner);
                    self.inner.common.wait_mode_change_blocking(Mode::Promoting);
                }
                Mode::Promoting if self.inner.common.current_is_owner() => {
                    self.inner.run_promotion();
                }
                Mode::Promoting => {
                    if self.inner.common.is_closed() {
                        return Err(TrySendError::Closed(value));
                    }
                    self.inner.common.wait_mode_change_blocking(Mode::Promoting);
                }
                Mode::Shared => {
                    return self.inner.try_send_shared(&self.fallback, value);
                }
            }
        }
    }
}

pub struct Receiver<T> {
    inner: Arc<BoundedInner<T>>,
    fallback: tokio_mpsc::Receiver<T>,
    fallback_closed: bool,
}

impl<T> core::fmt::Debug for Receiver<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Receiver")
            .field("mode", &self.inner.common.load_mode())
            .field("is_closed", &self.inner.common.is_closed())
            .finish()
    }
}

impl<T> Receiver<T> {
    #[inline]
    pub fn recv(&mut self) -> impl Future<Output = Option<T>> + '_ {
        BoundedRecvFuture { receiver: self }
    }

    #[inline]
    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
        let mode = self.inner.common.load_mode_raw_relaxed();
        if mode == MODE_SHARED {
            self.try_recv_shared()
        } else if mode == MODE_LOCAL && self.inner.common.current_is_owner() {
            self.inner.try_recv_local()
        } else {
            self.try_recv_slow()
        }
    }

    #[inline]
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mode = self.inner.common.load_mode_raw_relaxed();
        if mode == MODE_SHARED {
            self.poll_recv_shared(cx)
        } else if mode == MODE_LOCAL && self.inner.common.current_is_owner() {
            self.poll_recv_fast_local(cx)
        } else {
            self.poll_recv_slow(cx)
        }
    }

    #[inline]
    fn try_recv_shared(&mut self) -> Result<T, TryRecvError> {
        self.fallback.try_recv()
    }

    #[inline]
    fn poll_recv_fast_local(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        if let Ok(value) = self.inner.try_recv_local() {
            return Poll::Ready(Some(value));
        }
        self.inner.common.register_local_recv_waker(cx.waker());
        self.inner.promote_if_owner();
        if self.inner.common.load_mode() != Mode::Local {
            return self.poll_recv_slow(cx);
        }
        match self.inner.try_recv_local() {
            Ok(value) => Poll::Ready(Some(value)),
            Err(TryRecvError::Disconnected) => Poll::Ready(None),
            Err(TryRecvError::Empty) => Poll::Pending,
        }
    }

    #[inline]
    fn poll_recv_shared(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        Pin::new(&mut self.fallback).poll_recv(cx)
    }

    #[cold]
    fn try_recv_slow(&mut self) -> Result<T, TryRecvError> {
        loop {
            self.inner.promote_if_owner();
            match self.inner.common.load_mode() {
                Mode::Uninitialized => self.inner.try_initialize(),
                Mode::BindingLocal | Mode::BindingShared => {
                    self.inner
                        .common
                        .wait_mode_change_blocking(self.inner.common.load_mode());
                }
                Mode::Local if self.inner.common.current_is_owner() => {
                    return self.inner.try_recv_local();
                }
                Mode::Local => {
                    BoundedInner::start_promotion(&self.inner);
                    self.inner.common.wait_mode_change_blocking(Mode::Promoting);
                }
                Mode::Promoting if self.inner.common.current_is_owner() => {
                    self.inner.run_promotion();
                }
                Mode::Promoting => self.inner.common.wait_mode_change_blocking(Mode::Promoting),
                Mode::Shared => return self.try_recv_shared(),
            }
        }
    }

    #[cold]
    fn poll_recv_slow(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        loop {
            self.inner.promote_if_owner();
            match self.inner.common.load_mode() {
                Mode::Uninitialized => self.inner.try_initialize(),
                Mode::BindingLocal | Mode::BindingShared => {
                    let mode = self.inner.common.load_mode();
                    self.inner.common.recv_waker.register(cx.waker());
                    if self.inner.common.load_mode() != mode {
                        continue;
                    }
                    return Poll::Pending;
                }
                Mode::Local if self.inner.common.current_is_owner() => {
                    return self.poll_recv_fast_local(cx);
                }
                Mode::Local => {
                    BoundedInner::start_promotion(&self.inner);
                }
                Mode::Promoting if self.inner.common.current_is_owner() => {
                    self.inner.run_promotion();
                }
                Mode::Promoting => {
                    self.inner.common.recv_waker.register(cx.waker());
                    if self.inner.common.load_mode() != Mode::Promoting {
                        continue;
                    }
                    return Poll::Pending;
                }
                Mode::Shared => return self.poll_recv_shared(cx),
            }
        }
    }

    pub fn close(&mut self) {
        self.inner.common.set_closed();
        self.inner.notify_space_all();
        loop {
            self.inner.promote_if_owner();
            match self.inner.common.load_mode() {
                Mode::Uninitialized => {
                    self.inner.try_initialize();
                    return;
                }
                Mode::BindingLocal | Mode::BindingShared => {
                    self.inner
                        .common
                        .wait_mode_change_blocking(self.inner.common.load_mode());
                }
                Mode::Local if self.inner.common.current_is_owner() => return,
                Mode::Local => {
                    BoundedInner::start_promotion(&self.inner);
                    self.inner.common.wait_mode_change_blocking(Mode::Promoting);
                }
                Mode::Promoting if self.inner.common.current_is_owner() => {
                    self.inner.run_promotion();
                    return;
                }
                Mode::Promoting => self.inner.common.wait_mode_change_blocking(Mode::Promoting),
                Mode::Shared => {
                    if !self.fallback_closed {
                        self.fallback.close();
                        self.fallback_closed = true;
                    }
                    return;
                }
            }
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.inner.common.mark_receiver_dropped();
        self.inner.notify_space_all();

        match self.inner.common.load_mode() {
            Mode::Local | Mode::Promoting if self.inner.common.current_is_owner() => {
                self.inner.common.clear_local_queue();
                self.inner.promotion_fallback.lock().take();
                self.inner.common.publish_shared();
            }
            Mode::Local => BoundedInner::start_promotion(&self.inner),
            _ => {}
        }
    }
}

struct UnboundedInner<T> {
    common: Common<T>,
    promotion_fallback: Mutex<Option<tokio_mpsc::UnboundedSender<T>>>,
}

impl<T> UnboundedInner<T> {
    fn new(fallback: tokio_mpsc::UnboundedSender<T>) -> Self {
        Self {
            common: Common::new(0),
            promotion_fallback: Mutex::new(Some(fallback)),
        }
    }

    fn try_initialize(&self) {
        let owner = runtime::current_owner();
        let binding = if owner.is_some() {
            Mode::BindingLocal
        } else {
            Mode::BindingShared
        };
        if self
            .common
            .mode
            .compare_exchange(
                Mode::Uninitialized.as_u8(),
                binding.as_u8(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }

        match owner {
            Some(owner) => {
                self.common.owner_id.store(owner.id, Ordering::Release);
                *self.common.owner.lock() = Some(owner);
                self.common.mode.store(Mode::Local.as_u8(), Ordering::Release);
                self.common.notify_state_change();
            }
            None => {
                self.promotion_fallback.lock().take();
                self.common.publish_shared();
            }
        }
    }

    #[inline]
    fn try_send_local(&self, value: T) -> Result<(), SendError<T>> {
        if self.common.is_closed() {
            return Err(SendError(value));
        }

        // SAFETY: local mode only permits owner-thread access.
        let queue = unsafe { &mut *self.common.local_queue_ptr() };
        let was_empty = queue.is_empty();
        queue.push_back(value);
        if was_empty {
            self.common.wake_local_recv();
        }
        Ok(())
    }

    fn try_send_shared(
        &self,
        fallback: &tokio_mpsc::UnboundedSender<T>,
        value: T,
    ) -> Result<(), SendError<T>> {
        match fallback.send(value) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.common.set_closed();
                Err(err)
            }
        }
    }

    #[inline]
    fn try_recv_local(&self) -> Result<T, TryRecvError> {
        // SAFETY: local mode only permits owner-thread access.
        let queue = unsafe { &mut *self.common.local_queue_ptr() };
        if let Some(value) = queue.pop_front() {
            return Ok(value);
        }
        if self.common.should_terminate_after_empty() {
            Err(TryRecvError::Disconnected)
        } else {
            Err(TryRecvError::Empty)
        }
    }

    fn promote_if_owner(&self) {
        if self.common.load_mode() == Mode::Promoting && self.common.current_is_owner() {
            self.run_promotion();
        }
    }

    fn start_promotion(this: &Arc<Self>) {
        if this
            .common
            .mode
            .compare_exchange(
                Mode::Local.as_u8(),
                Mode::Promoting.as_u8(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }

        let Some(owner) = this.common.owner.lock().clone() else {
            // The owner already finished draining or tearing down the local
            // state and is in the middle of publishing shared mode.
            this.common.clear_local_queue();
            this.promotion_fallback.lock().take();
            this.common.publish_shared();
            return;
        };
        let request = UnboundedPromotion {
            inner: Arc::clone(this),
        };

        if runtime::enqueue_promotion(&owner, request).is_err() {
            // The owner loop is gone, so no thread will touch the local queue.
            this.common.clear_local_queue();
            this.promotion_fallback.lock().take();
            this.common.publish_shared();
            return;
        }

        this.common.notify_state_change();
    }

    fn run_promotion(&self) {
        if self.common.load_mode() != Mode::Promoting {
            return;
        }

        // SAFETY: promotion runs only on the owner thread, or after the owner
        // loop has exited and no further local access can occur.
        let queue = unsafe { &mut *self.common.local_queue_ptr() };
        let fallback = self
            .promotion_fallback
            .lock()
            .clone()
            .expect("promoting channel must retain fallback sender");
        if !self.common.receiver_alive.load(Ordering::Acquire) {
            queue.clear();
        } else {
            let mut fallback_closed = false;
            while let Some(value) = queue.pop_front() {
                if fallback.send(value).is_err() {
                    fallback_closed = true;
                    break;
                }
            }
            if fallback_closed {
                queue.clear();
                self.common.mark_receiver_dropped();
            }
        }

        self.promotion_fallback.lock().take();
        self.common.publish_shared();
    }
}

struct UnboundedPromotion<T> {
    inner: Arc<UnboundedInner<T>>,
}

impl<T> runtime::PromotionJob for UnboundedPromotion<T> {
    fn run(self: Box<Self>) {
        self.inner.run_promotion();
    }
}

struct UnboundedRecvFuture<'a, T> {
    receiver: &'a mut UnboundedReceiver<T>,
}

impl<T> Future for UnboundedRecvFuture<'_, T> {
    type Output = Option<T>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().receiver.poll_recv(cx)
    }
}

pub struct UnboundedSender<T> {
    inner: Arc<UnboundedInner<T>>,
    fallback: tokio_mpsc::UnboundedSender<T>,
}

impl<T> core::fmt::Debug for UnboundedSender<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnboundedSender")
            .field("mode", &self.inner.common.load_mode())
            .field("is_closed", &self.is_closed())
            .finish()
    }
}

impl<T> Clone for UnboundedSender<T> {
    fn clone(&self) -> Self {
        self.inner.common.sender_cloned();
        Self {
            inner: Arc::clone(&self.inner),
            fallback: self.fallback.clone(),
        }
    }
}

impl<T> Drop for UnboundedSender<T> {
    fn drop(&mut self) {
        self.inner.common.sender_dropped();
    }
}

impl<T> UnboundedSender<T> {
    #[inline]
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        let mode = self.inner.common.load_mode_raw_relaxed();
        if mode == MODE_SHARED {
            return self.inner.try_send_shared(&self.fallback, value);
        }
        if mode == MODE_LOCAL && self.inner.common.current_is_owner() {
            return self.inner.try_send_local(value);
        }
        loop {
            self.inner.promote_if_owner();
            match self.inner.common.load_mode() {
                Mode::Uninitialized => self.inner.try_initialize(),
                Mode::BindingLocal | Mode::BindingShared => self.inner.common.wait_binding_complete(),
                Mode::Local if self.inner.common.current_is_owner() => {
                    return self.inner.try_send_local(value);
                }
                Mode::Local => {
                    if self.inner.common.is_closed() {
                        return Err(SendError(value));
                    }
                    UnboundedInner::start_promotion(&self.inner);
                    self.inner.common.wait_mode_change_blocking(Mode::Promoting);
                }
                Mode::Promoting if self.inner.common.current_is_owner() => {
                    self.inner.run_promotion();
                }
                Mode::Promoting => {
                    if self.inner.common.is_closed() {
                        return Err(SendError(value));
                    }
                    self.inner.common.wait_mode_change_blocking(Mode::Promoting);
                }
                Mode::Shared => {
                    return self.inner.try_send_shared(&self.fallback, value);
                }
            }
        }
    }

    pub async fn closed(&self) {
        self.inner.common.wait_closed_async().await;
    }

    pub fn is_closed(&self) -> bool {
        self.inner.common.is_closed()
    }
}

pub struct UnboundedReceiver<T> {
    inner: Arc<UnboundedInner<T>>,
    fallback: tokio_mpsc::UnboundedReceiver<T>,
    fallback_closed: bool,
}

impl<T> core::fmt::Debug for UnboundedReceiver<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnboundedReceiver")
            .field("mode", &self.inner.common.load_mode())
            .field("is_closed", &self.inner.common.is_closed())
            .finish()
    }
}

impl<T> UnboundedReceiver<T> {
    #[inline]
    pub fn recv(&mut self) -> impl Future<Output = Option<T>> + '_ {
        UnboundedRecvFuture { receiver: self }
    }

    #[inline]
    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
        let mode = self.inner.common.load_mode_raw_relaxed();
        if mode == MODE_SHARED {
            return self.fallback.try_recv();
        }
        if mode == MODE_LOCAL && self.inner.common.current_is_owner() {
            return self.inner.try_recv_local();
        }
        loop {
            self.inner.promote_if_owner();
            match self.inner.common.load_mode() {
                Mode::Uninitialized => self.inner.try_initialize(),
                Mode::BindingLocal | Mode::BindingShared => {
                    self.inner
                        .common
                        .wait_mode_change_blocking(self.inner.common.load_mode());
                }
                Mode::Local if self.inner.common.current_is_owner() => {
                    return self.inner.try_recv_local();
                }
                Mode::Local => {
                    UnboundedInner::start_promotion(&self.inner);
                    self.inner.common.wait_mode_change_blocking(Mode::Promoting);
                }
                Mode::Promoting if self.inner.common.current_is_owner() => {
                    self.inner.run_promotion();
                }
                Mode::Promoting => self.inner.common.wait_mode_change_blocking(Mode::Promoting),
                Mode::Shared => return self.fallback.try_recv(),
            }
        }
    }

    #[inline]
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mode = self.inner.common.load_mode_raw_relaxed();
        if mode == MODE_SHARED {
            return Pin::new(&mut self.fallback).poll_recv(cx);
        }
        loop {
            self.inner.promote_if_owner();
            match self.inner.common.load_mode() {
                Mode::Uninitialized => self.inner.try_initialize(),
                Mode::BindingLocal | Mode::BindingShared => {
                    let mode = self.inner.common.load_mode();
                    self.inner.common.recv_waker.register(cx.waker());
                    if self.inner.common.load_mode() != mode {
                        continue;
                    }
                    return Poll::Pending;
                }
                Mode::Local if self.inner.common.current_is_owner() => {
                    if let Ok(value) = self.inner.try_recv_local() {
                        return Poll::Ready(Some(value));
                    }
                    self.inner.common.register_local_recv_waker(cx.waker());
                    self.inner.promote_if_owner();
                    if self.inner.common.load_mode() != Mode::Local {
                        continue;
                    }
                    match self.inner.try_recv_local() {
                        Ok(value) => return Poll::Ready(Some(value)),
                        Err(TryRecvError::Disconnected) => return Poll::Ready(None),
                        Err(TryRecvError::Empty) => return Poll::Pending,
                    }
                }
                Mode::Local => {
                    UnboundedInner::start_promotion(&self.inner);
                }
                Mode::Promoting if self.inner.common.current_is_owner() => {
                    self.inner.run_promotion();
                }
                Mode::Promoting => {
                    self.inner.common.recv_waker.register(cx.waker());
                    if self.inner.common.load_mode() != Mode::Promoting {
                        continue;
                    }
                    return Poll::Pending;
                }
                Mode::Shared => return Pin::new(&mut self.fallback).poll_recv(cx),
            }
        }
    }

    pub fn close(&mut self) {
        self.inner.common.set_closed();
        loop {
            self.inner.promote_if_owner();
            match self.inner.common.load_mode() {
                Mode::Uninitialized => {
                    self.inner.try_initialize();
                    return;
                }
                Mode::BindingLocal | Mode::BindingShared => {
                    self.inner
                        .common
                        .wait_mode_change_blocking(self.inner.common.load_mode());
                }
                Mode::Local if self.inner.common.current_is_owner() => return,
                Mode::Local => {
                    UnboundedInner::start_promotion(&self.inner);
                    self.inner.common.wait_mode_change_blocking(Mode::Promoting);
                }
                Mode::Promoting if self.inner.common.current_is_owner() => {
                    self.inner.run_promotion();
                    return;
                }
                Mode::Promoting => self.inner.common.wait_mode_change_blocking(Mode::Promoting),
                Mode::Shared => {
                    if !self.fallback_closed {
                        self.fallback.close();
                        self.fallback_closed = true;
                    }
                    return;
                }
            }
        }
    }
}

impl<T> Drop for UnboundedReceiver<T> {
    fn drop(&mut self) {
        self.inner.common.mark_receiver_dropped();

        match self.inner.common.load_mode() {
            Mode::Local | Mode::Promoting if self.inner.common.current_is_owner() => {
                self.inner.common.clear_local_queue();
                self.inner.promotion_fallback.lock().take();
                self.inner.common.publish_shared();
            }
            Mode::Local => UnboundedInner::start_promotion(&self.inner),
            _ => {}
        }
    }
}

pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    let (fallback_tx, fallback_rx) = tokio_mpsc::channel(capacity);
    let inner = Arc::new(BoundedInner::new(capacity, fallback_tx.clone()));
    (
        Sender {
            inner: Arc::clone(&inner),
            fallback: fallback_tx,
        },
        Receiver {
            inner,
            fallback: fallback_rx,
            fallback_closed: false,
        },
    )
}

pub fn unbounded_channel<T>() -> (UnboundedSender<T>, UnboundedReceiver<T>) {
    let (fallback_tx, fallback_rx) = tokio_mpsc::unbounded_channel();
    let inner = Arc::new(UnboundedInner::new(fallback_tx.clone()));
    (
        UnboundedSender {
            inner: Arc::clone(&inner),
            fallback: fallback_tx,
        },
        UnboundedReceiver {
            inner,
            fallback: fallback_rx,
            fallback_closed: false,
        },
    )
}

#[doc(hidden)]
pub mod runtime {
    use futures::{future::poll_fn, pin_mut};
    use std::{
        cell::{Cell, RefCell},
        future::Future,
        pin::Pin,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc,
        },
        task::Poll,
    };
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

    static NEXT_OWNER_ID: AtomicU64 = AtomicU64::new(1);

    thread_local! {
        static CURRENT_OWNER_ID: Cell<u64> = const { Cell::new(0) };
        static CURRENT_OWNER: RefCell<Option<OwnerHandle>> = const { RefCell::new(None) };
    }

    pub(super) trait PromotionJob {
        fn run(self: Box<Self>);
    }

    struct PromotionThunk {
        data: *mut (),
        run: unsafe fn(*mut ()),
    }

    struct WakeOwner;

    impl PromotionJob for WakeOwner {
        fn run(self: Box<Self>) {}
    }

    #[derive(Clone)]
    pub(super) struct OwnerHandle {
        pub(super) id: u64,
        pub(super) promotions: UnboundedSender<usize>,
        alive: Arc<AtomicBool>,
    }

    pub struct LocalOwner {
        previous: Option<OwnerHandle>,
        previous_id: u64,
        promotions: UnboundedReceiver<usize>,
        alive: Arc<AtomicBool>,
    }

    impl LocalOwner {
        pub fn install() -> Self {
            let id = NEXT_OWNER_ID.fetch_add(1, Ordering::Relaxed);
            let (promotions, receiver) = unbounded_channel();
            let alive = Arc::new(AtomicBool::new(true));
            let current = OwnerHandle {
                id,
                promotions,
                alive: Arc::clone(&alive),
            };
            let previous_id = CURRENT_OWNER_ID.with(|slot| slot.replace(id));
            let previous = CURRENT_OWNER.with(|slot| slot.replace(Some(current.clone())));
            Self {
                previous,
                previous_id,
                promotions: receiver,
                alive,
            }
        }

        pub async fn run<F: Future>(mut self, future: F) -> F::Output {
            pin_mut!(future);
            poll_fn(|cx| {
                while let Poll::Ready(Some(job)) = Pin::new(&mut self.promotions).poll_recv(cx) {
                    run_promotion(job);
                }
                match future.as_mut().poll(cx) {
                    Poll::Ready(output) => {
                        self.alive.store(false, Ordering::Release);
                        self.promotions.close();
                        while let Poll::Ready(Some(job)) =
                            Pin::new(&mut self.promotions).poll_recv(cx)
                        {
                            run_promotion(job);
                        }
                        Poll::Ready(output)
                    }
                    Poll::Pending => Poll::Pending,
                }
            })
            .await
        }
    }

    impl Drop for LocalOwner {
        fn drop(&mut self) {
            self.alive.store(false, Ordering::Release);
            CURRENT_OWNER_ID.with(|slot| {
                slot.set(self.previous_id);
            });
            CURRENT_OWNER.with(|slot| {
                *slot.borrow_mut() = self.previous.take();
            });
        }
    }

    #[inline]
    pub fn current_owner_id_raw() -> u64 {
        CURRENT_OWNER_ID.with(Cell::get)
    }

    #[inline]
    pub fn current_owner_id() -> Option<u64> {
        match current_owner_id_raw() {
            0 => None,
            id => Some(id),
        }
    }

    pub(super) fn current_owner() -> Option<OwnerHandle> {
        CURRENT_OWNER.with(|slot| slot.borrow().clone())
    }

    pub(super) fn enqueue_promotion<P: PromotionJob>(
        owner: &OwnerHandle,
        job: P,
    ) -> Result<(), ()> {
        let data = Box::into_raw(Box::new(job)) as *mut ();
        let thunk = Box::new(PromotionThunk {
            data,
            run: run_typed_promotion::<P>,
        });
        let raw = Box::into_raw(thunk) as usize;
        if owner.alive.load(Ordering::Acquire) && owner.promotions.send(raw).is_ok() {
            Ok(())
        } else {
            // SAFETY: `raw` came from `Box::into_raw` above and ownership was
            // not transferred to the queue because send failed.
            unsafe {
                let thunk = Box::from_raw(raw as *mut PromotionThunk);
                (thunk.run)(thunk.data);
            }
            Err(())
        }
    }

    pub(super) fn wake_owner(owner: &OwnerHandle) {
        let _ = enqueue_promotion(owner, WakeOwner);
    }

    fn run_promotion(raw: usize) {
        // SAFETY: every queued token comes from `enqueue_promotion`, which
        // transfers ownership of exactly one promotion thunk to the
        // owner loop.
        let thunk = unsafe { Box::from_raw(raw as *mut PromotionThunk) };
        // SAFETY: the thunk owns a valid heap allocation of the right type for
        // its `run` function pointer.
        unsafe {
            (thunk.run)(thunk.data);
        }
    }

    unsafe fn run_typed_promotion<P: PromotionJob>(data: *mut ()) {
        // SAFETY: `enqueue_promotion` created `data` from `Box<P>` and paired
        // it with this exact monomorphized function.
        let job = unsafe { Box::from_raw(data.cast::<P>()) };
        job.run();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{future::poll_fn, pin_mut, Future, FutureExt};
    use std::thread;

    fn owner() -> runtime::LocalOwner {
        runtime::LocalOwner::install()
    }

    fn block_on_owner<F: Future>(future: F) -> F::Output {
        let owner = owner();
        let future = owner.run(future);
        pin_mut!(future);
        futures::executor::block_on(poll_fn(|cx| {
            cx.waker().wake_by_ref();
            future.as_mut().poll(cx)
        }))
    }

    #[test]
    fn test_local_bind_on_first_send() {
        block_on_owner(async {
            let (tx, mut rx) = channel(4);
            tx.try_send(1).unwrap();
            assert_eq!(tx.inner.common.load_mode(), Mode::Local);
            assert_eq!(rx.recv().await, Some(1));
        });
    }

    #[test]
    fn test_local_bind_on_first_recv() {
        block_on_owner(async {
            let (tx, mut rx) = channel::<u64>(4);
            let recv = poll_fn(|cx| {
                assert!(matches!(rx.poll_recv(cx), Poll::Pending));
                Poll::Ready(())
            });
            recv.await;
            assert_eq!(tx.inner.common.load_mode(), Mode::Local);
        });
    }

    #[test]
    fn test_first_non_local_use_binds_shared() {
        futures::executor::block_on(async {
            let (tx, mut rx) = channel::<u64>(4);
            assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
            assert_eq!(tx.inner.common.load_mode(), Mode::Shared);
        });
    }

    #[test]
    fn test_bounded_full_wake_retry_behavior() {
        block_on_owner(async {
            let (tx, mut rx) = channel(1);
            tx.send(1).await.unwrap();

            let blocked = tx.send(2);
            futures::pin_mut!(blocked);
            assert!(blocked.as_mut().now_or_never().is_none());

            assert_eq!(rx.recv().await, Some(1));
            blocked.await.unwrap();
            assert_eq!(rx.recv().await, Some(2));
        });
    }

    #[test]
    fn test_close_semantics() {
        block_on_owner(async {
            let (tx, mut rx) = channel(4);
            tx.send(1).await.unwrap();
            tx.send(2).await.unwrap();
            rx.close();

            assert!(matches!(tx.try_send(3), Err(TrySendError::Closed(3))));
            assert_eq!(rx.recv().await, Some(1));
            assert_eq!(rx.recv().await, Some(2));
            assert_eq!(rx.recv().await, None);
        });
    }

    #[test]
    fn test_sender_drop_termination() {
        block_on_owner(async {
            let (tx, mut rx) = channel::<u64>(1);
            drop(tx);
            assert_eq!(rx.recv().await, None);
        });
    }

    #[test]
    fn test_foreign_sender_promotes_and_preserves_order() {
        block_on_owner(async {
            let (tx, mut rx) = channel(8);
            tx.send(1).await.unwrap();

            let (ready_tx, ready_rx) = futures::channel::oneshot::channel();
            let foreign = tx.clone();
            let handle = thread::spawn(move || {
                ready_tx.send(()).unwrap();
                foreign.try_send(2).unwrap();
            });

            ready_rx.await.unwrap();
            assert_eq!(rx.recv().await, Some(1));
            assert_eq!(rx.recv().await, Some(2));
            handle.join().unwrap();
            assert_eq!(tx.inner.common.load_mode(), Mode::Shared);
        });
    }

    #[test]
    fn test_foreign_receiver_operation_promotes() {
        block_on_owner(async {
            let (tx, rx) = channel(4);
            tx.send(7).await.unwrap();

            let (done_tx, done_rx) = futures::channel::oneshot::channel();
            let handle = thread::spawn(move || {
                let mut rx = rx;
                assert_eq!(futures::executor::block_on(rx.recv()), Some(7));
                assert_eq!(rx.inner.common.load_mode(), Mode::Shared);
                done_tx.send(()).unwrap();
            });
            done_rx.await.unwrap();
            handle.join().unwrap();
        });
    }

    #[test]
    fn test_unbounded_local_and_promotion() {
        block_on_owner(async {
            let (tx, mut rx) = unbounded_channel();
            tx.send(1).unwrap();

            let (ready_tx, ready_rx) = futures::channel::oneshot::channel();
            let foreign = tx.clone();
            let handle = thread::spawn(move || {
                ready_tx.send(()).unwrap();
                foreign.send(2).unwrap();
            });
            ready_rx.await.unwrap();
            assert_eq!(rx.recv().await, Some(1));
            assert_eq!(rx.recv().await, Some(2));
            handle.join().unwrap();
        });
    }

    #[test]
    fn test_closed_future_resolves() {
        block_on_owner(async {
            let (tx, mut rx) = channel::<u64>(1);
            let closed = tx.closed();
            futures::pin_mut!(closed);
            assert!(closed.as_mut().now_or_never().is_none());
            rx.close();
            closed.await;
        });
    }
}
