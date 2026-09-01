//! Sends one request that carries its own reply channel and awaits the reply.

use commonware_actor::{Feedback, Unreliable};
use commonware_utils::channel::oneshot;

/// Enqueues `make(reply)` through `send` and awaits the reply.
///
/// A closed endpoint or a dropped reply resolves to `closed`.
pub(crate) async fn ask<M, T, E>(
    send: impl FnOnce(M) -> Feedback,
    make: impl FnOnce(oneshot::Sender<Result<T, E>>) -> M,
    closed: E,
) -> Result<T, E> {
    let (reply, receiver) = oneshot::channel();
    if send(make(reply)) == Feedback::Closed {
        return Err(closed);
    }
    receiver.await.unwrap_or(Err(closed))
}

/// Like [`ask`] for an unreliable endpoint, where a rejected request resolves to `busy`.
pub(crate) async fn ask_unreliable<M, T, E>(
    send: impl FnOnce(M) -> Unreliable<Feedback>,
    make: impl FnOnce(oneshot::Sender<Result<T, E>>) -> M,
    closed: E,
    busy: E,
) -> Result<T, E> {
    let (reply, receiver) = oneshot::channel();
    match send(make(reply)) {
        Unreliable::Rejected => return Err(busy),
        Unreliable::Outcome(Feedback::Closed) => return Err(closed),
        Unreliable::Outcome(Feedback::Ok | Feedback::Backoff) => {}
    }
    receiver.await.unwrap_or(Err(closed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt as _;

    #[derive(Debug, PartialEq, Eq)]
    enum Error {
        Closed,
        Busy,
    }

    type Reply = oneshot::Sender<Result<u8, Error>>;

    #[test]
    fn ask_returns_the_reply() {
        let reply = ask(
            |reply: Reply| {
                drop(reply.send(Ok(5)));
                Feedback::Ok
            },
            |reply| reply,
            Error::Closed,
        )
        .now_or_never()
        .expect("the reply is ready");
        assert_eq!(reply, Ok(5));
    }

    #[test]
    fn ask_maps_a_closed_endpoint_or_dropped_reply_to_closed() {
        let closed = ask(|_: Reply| Feedback::Closed, |reply| reply, Error::Closed)
            .now_or_never()
            .expect("the reply is ready");
        assert_eq!(closed, Err(Error::Closed));
        let dropped = ask(
            |reply: Reply| {
                drop(reply);
                Feedback::Backoff
            },
            |reply| reply,
            Error::Closed,
        )
        .now_or_never()
        .expect("the reply is ready");
        assert_eq!(dropped, Err(Error::Closed));
    }

    #[test]
    fn ask_unreliable_maps_rejection_to_busy() {
        let busy = ask_unreliable(
            |_: Reply| Unreliable::Rejected,
            |reply| reply,
            Error::Closed,
            Error::Busy,
        )
        .now_or_never()
        .expect("the reply is ready");
        assert_eq!(busy, Err(Error::Busy));
        let closed = ask_unreliable(
            |_: Reply| Unreliable::Outcome(Feedback::Closed),
            |reply| reply,
            Error::Closed,
            Error::Busy,
        )
        .now_or_never()
        .expect("the reply is ready");
        assert_eq!(closed, Err(Error::Closed));
        let reply = ask_unreliable(
            |reply: Reply| {
                drop(reply.send(Ok(9)));
                Unreliable::Outcome(Feedback::Ok)
            },
            |reply| reply,
            Error::Closed,
            Error::Busy,
        )
        .now_or_never()
        .expect("the reply is ready");
        assert_eq!(reply, Ok(9));
    }
}
