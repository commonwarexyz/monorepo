//! A token that resolves when an accepted request finishes.

use commonware_utils::channel::oneshot;

/// Resolves when an accepted request finishes.
///
/// The actor that accepted the request holds the sender. If it drops the sender without
/// resolving it, [`Completion::wait`] returns the error chosen when the channel was created.
#[must_use = "the request has not finished until the completion resolves"]
pub struct Completion<E> {
    receiver: oneshot::Receiver<Result<(), E>>,
    closed: fn() -> E,
}

impl<E> Completion<E> {
    /// Returns the sender that resolves a new completion, and the completion.
    ///
    /// `closed` builds the error returned when the sender is dropped unresolved.
    pub(crate) fn channel(closed: fn() -> E) -> (oneshot::Sender<Result<(), E>>, Self) {
        let (sender, receiver) = oneshot::channel();
        (sender, Self { receiver, closed })
    }

    /// Waits until the request finishes.
    pub async fn wait(self) -> Result<(), E> {
        self.receiver.await.unwrap_or_else(|_| Err((self.closed)()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt as _;

    #[derive(Debug, PartialEq, Eq)]
    enum Error {
        Closed,
        Failed,
    }

    #[test]
    fn wait_returns_the_sent_result() {
        let (sender, completion) = Completion::channel(|| Error::Closed);
        drop(sender.send(Err(Error::Failed)));
        assert_eq!(
            completion
                .wait()
                .now_or_never()
                .expect("the reply is ready"),
            Err(Error::Failed)
        );

        let (sender, completion) = Completion::channel(|| Error::Closed);
        drop(sender.send(Ok(())));
        assert_eq!(
            completion
                .wait()
                .now_or_never()
                .expect("the reply is ready"),
            Ok(())
        );
    }

    #[test]
    fn dropped_sender_resolves_to_the_closed_error() {
        let (sender, completion) = Completion::<Error>::channel(|| Error::Closed);
        drop(sender);
        assert_eq!(
            completion
                .wait()
                .now_or_never()
                .expect("the reply is ready"),
            Err(Error::Closed)
        );
    }
}
