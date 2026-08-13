//! Synchronization facade: std primitives in production, loom primitives under the `loom`
//! feature.
//!
//! The pool's park/wake and publication protocols are loom-modeled. Everything they touch
//! must go through this facade so loom explores the real transitions rather than a stand-in
//! program.

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "loom")] {
        pub(super) use loom::sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Ordering},
        };

        /// Yields in spin-wait loops so the loom scheduler can interleave other threads.
        pub(super) fn spin() {
            loom::thread::yield_now();
        }

        /// Spawns a worker thread. Loom threads cannot be named.
        pub(super) fn spawn_worker<F: FnOnce() + Send + 'static>(_id: usize, f: F) {
            loom::thread::spawn(f);
        }
    } else {
        pub(super) use std::sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Ordering},
        };

        /// Hint to the CPU that we are in a short spin-wait.
        pub(super) fn spin() {
            core::hint::spin_loop();
        }

        /// Spawns a named worker thread.
        pub(super) fn spawn_worker<F: FnOnce() + Send + 'static>(id: usize, f: F) {
            std::thread::Builder::new()
                .name(format!("commonware-parked-{id}"))
                .spawn(f)
                .expect("failed to spawn pool worker");
        }
    }
}

/// A token parker: `unpark` deposits a token, `park` consumes one (waiting if absent).
///
/// An unpark that races ahead of the park is absorbed as an immediate wakeup rather than a
/// missed wake. Built on Mutex + Condvar in both production and loom so the modeled program
/// is the shipped program.
pub(super) struct Parker {
    token: Mutex<bool>,
    cv: Condvar,
}

impl Parker {
    pub(super) fn new() -> Self {
        Self {
            token: Mutex::new(false),
            cv: Condvar::new(),
        }
    }

    /// Blocks until a token is available, then consumes it.
    pub(super) fn park(&self) {
        let mut token = self.token.lock().unwrap();
        while !*token {
            token = self.cv.wait(token).unwrap();
        }
        *token = false;
    }

    /// Deposits a token and wakes the parked thread, if any.
    pub(super) fn unpark(&self) {
        let mut token = self.token.lock().unwrap();
        *token = true;
        self.cv.notify_one();
    }
}
