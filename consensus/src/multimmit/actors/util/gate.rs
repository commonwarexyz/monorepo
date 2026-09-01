//! Awaits a source only while it is enabled.

use std::future::{Future, pending};

/// Awaits `future` when `enabled`, and never completes otherwise.
///
/// In a `select!` arm this keeps a disabled source from completing without changing the order of
/// the other arms.
pub(crate) async fn gated<F: Future>(enabled: bool, future: F) -> F::Output {
    if enabled {
        future.await
    } else {
        pending().await
    }
}

/// Awaits `future` and returns its value, never completing when it yields `None`.
///
/// In a `select!` arm this lets a closed optional source (such as an inspection mailbox) go quiet
/// instead of ending the loop.
pub(crate) async fn some_or_pending<T, F: Future<Output = Option<T>>>(future: F) -> T {
    match future.await {
        Some(value) => value,
        None => pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{FutureExt as _, future::ready};

    #[test]
    fn gated_awaits_only_when_enabled() {
        assert_eq!(gated(true, ready(7)).now_or_never(), Some(7));
        assert_eq!(gated(false, ready(7)).now_or_never(), None);
    }

    #[test]
    fn some_or_pending_stays_pending_on_none() {
        assert_eq!(some_or_pending(ready(Some(3))).now_or_never(), Some(3));
        assert_eq!(some_or_pending(ready(None::<u8>)).now_or_never(), None);
    }
}
