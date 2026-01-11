//! Shared ingress primitive for actors.
//!
//! # Overview
//!
//! Provides a shared [`Mailbox`] primitive for communication with actors. Callers package
//! work into [`Message`] types and submit them through a [`Mailbox`], while the actor
//! executes the corresponding [`Handler`] implementation. The pattern mirrors an
//! Erlang-style inbox: tasks can "tell" an actor to do work (fire-and-forget), or "ask"
//! the actor to do work and wait for a response.
//!
//! # Examples
//!
//! See [`crate::actor`] module documentation for a complete example that wires an
//! actor, its control loop, and its mailbox together.

use crate::actor::{Envelope, Handler, Message};
use futures::{
    channel::{
        mpsc::{self, SendError},
        oneshot,
    },
    FutureExt, SinkExt,
};
use std::ops::ControlFlow;
use thiserror::Error;

/// An error that can occur when sending a message to an actor.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MailboxError {
    /// The underlying channel to the actor was closed or rejected the send.
    #[error(transparent)]
    Send(#[from] SendError),
    /// The actor dropped its response handle.
    #[error("response channel was cancelled")]
    Cancelled,
    /// The caller waited longer than the configured timeout for the response.
    #[error("request timed out")]
    Timeout,
}

/// Mailbox endpoint used by callers to deliver messages to an actor.
///
/// A mailbox is typically cloned and shared across tasks that wish to interact with an
/// actor instance. Every message is wrapped in an [`Envelope`] before being forwarded to
/// the actor's receive loop.
///
/// # Examples
///
/// See [`Mailbox::ask`] and [`Mailbox::tell`] for complete usage snippets.
#[derive(Clone)]
pub struct Mailbox<A> {
    tx: mpsc::Sender<Envelope<A>>,
}

impl<A> Mailbox<A> {
    /// Create a new [`Mailbox`] with the given sender.
    pub fn new(tx: mpsc::Sender<Envelope<A>>) -> Self {
        Self { tx }
    }

    /// Send a [`Message`] to the actor and await a response.
    ///
    /// The handler executes on the actor thread and the produced response is forwarded
    /// through a oneshot channel back to the caller.
    ///
    /// This function can also be used to track delivery, even if the response isn't
    /// consumed.
    ///
    /// ## Returns
    /// - [`Message::Response`] if the request is successful.
    ///
    /// ## Errors
    /// - [`MailboxError::Send`] if the actor has dropped the mailbox receiver.
    /// - [`MailboxError::Cancelled`] if the response channel is cancelled.
    ///
    /// See the module-level example for an end-to-end workflow that uses `ask`.
    pub async fn ask<M>(&mut self, msg: M) -> Result<M::Response, MailboxError>
    where
        M: Message,
        A: Handler<M>,
    {
        let (tx, rx) = oneshot::channel::<M::Response>();
        self.tx
            .send(Box::new(move |actor: &mut A| {
                async move {
                    match actor.handle(msg).await {
                        ControlFlow::Continue(reply) => {
                            let _ = tx.send(reply);
                            ControlFlow::Continue(())
                        }
                        ControlFlow::Break(reply) => {
                            let _ = tx.send(reply);
                            ControlFlow::Break(())
                        }
                    }
                }
                .boxed()
            }))
            .await?;

        rx.await.map_err(|_| MailboxError::Cancelled)
    }

    /// Send a [`Message`] to the actor without waiting for a response.
    ///
    /// ## Returns
    /// - `()` once the message has been enqueued for delivery.
    ///
    /// ## Errors
    /// - [`MailboxError::Send`] if the actor has shut down or the channel is otherwise closed.
    ///
    /// See the module-level example for a walkthrough of `tell` in practice.
    pub async fn tell<M>(&mut self, msg: M) -> Result<(), MailboxError>
    where
        M: Message<Response = ()>,
        A: Handler<M>,
    {
        self.tx
            .send(Box::new(move |actor: &mut A| {
                async move {
                    match actor.handle(msg).await {
                        ControlFlow::Continue(_) => ControlFlow::Continue(()),
                        ControlFlow::Break(_) => ControlFlow::Break(()),
                    }
                }
                .boxed()
            }))
            .await
            .map_err(Into::into)
    }
}
