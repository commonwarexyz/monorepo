//! High-resolution timers for the Tokio runtime.
//!
//! Linux uses one monotonic timerfd per Tokio worker. macOS uses one kqueue
//! descriptor and one Mach absolute timer per worker. Other targets retain
//! Tokio timers. The runtime-independent [`crate::Clock`] interface does not
//! expose these implementation details.
//!
//! Registration and expiry follow this flow:
//!
//! ```text
//! Context::sleep
//!       |
//!       v
//! worker-local shard -> mutex -> indexed 4-ary heap
//!                          |             |
//!                    minimum changed   exact cancellation
//!                          |
//!                          v
//!               coalesced driver signal
//!                          |
//! native readiness -> driver -> pop 32 -> entry waker
//! ```
//!
//! Each entry has exactly one terminal transition:
//!
//! ```text
//!                 WAITING
//!                /    |    \
//!               v     v     v
//!            FIRED QUIESCENT FAILED
//! ```
//!
//! The heap mutex owns registration and alarm intent. Native alarm operations
//! and sleeper callbacks always run after releasing that mutex. This prevents
//! kernel latency and arbitrary waker code from blocking producers. Sharding
//! by worker keeps unrelated registration and cancellation paths independent.
//! Each sleep remembers its construction-time shard through a weak reference,
//! so migration cancels against the original shard without keeping its native
//! alarm alive. The future owns the entry while the heap or driver scratch
//! storage holds another shared owner as needed. Expiry removes elapsed entries
//! and attempts `FIRED` while holding the shard mutex, then invokes a waker only
//! for entries whose transition won. Callback work runs after unlocking.
//! `QUIESCENT` covers both a dropped sleep and orderly scheduler shutdown.
//!
//! Wall-clock deadlines are converted once to a fixed monotonic deadline.
//! Later wall-clock changes do not move a registered sleep. A 50 nanosecond
//! tolerance suppresses only a slightly earlier rearm. Drivers remove at most
//! 32 expired entries per lock acquisition and yield after 512 entries only
//! when more expired work is ready.
//!
//! Driver errors and panics claim root interruption before waking failed
//! sleepers, so an ordinary task panic cannot replace the infrastructure
//! diagnostic. Failed sleepers unwind with an already-reported marker so they
//! do not duplicate that diagnostic. Orderly scheduler teardown instead marks
//! queued sleeps stopped without waking them and signals drivers before the
//! owning Tokio runtime tears down their tasks.

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "macos"))] {
        #[cfg(test)]
        mod fallback;
        mod heap;
        mod scheduler;
        mod sync;

        cfg_if::cfg_if! {
            if #[cfg(target_os = "linux")] {
                mod linux;
            } else {
                mod macos;
            }
        }

        #[cfg(test)]
        pub(crate) use scheduler::AssignmentKind;
        pub(super) use scheduler::{Builder, Timer};
    } else {
        mod fallback;

        pub(super) use fallback::{Builder, Timer};
    }
}
