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
//!              /    |    \    \
//!             v     v     v    v
//!          FIRED CANCELED FAILED STOPPED
//! ```
//!
//! The heap mutex owns registration and alarm intent. Native alarm operations
//! and sleeper callbacks always run after releasing that mutex. This prevents
//! kernel latency and arbitrary waker code from blocking producers. Sharding
//! by worker keeps unrelated registration and cancellation paths independent.
//! Each sleep retains its construction-time shard, while the future and that
//! shard share the entry until one terminal transition wins.
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
//! do not duplicate that diagnostic. Orderly service teardown instead marks
//! queued sleeps stopped without waking them, signals drivers, and aborts
//! their tasks.

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "macos"))] {
        #[cfg(test)]
        mod fallback;
        mod heap;
        mod service;

        cfg_if::cfg_if! {
            if #[cfg(target_os = "linux")] {
                mod linux;
            } else {
                mod macos;
            }
        }

        #[cfg(test)]
        pub(crate) use service::AssignmentKind;
        pub(super) use service::{Setup, Timer};
    } else {
        mod fallback;

        pub(super) use fallback::{Setup, Timer};
    }
}
