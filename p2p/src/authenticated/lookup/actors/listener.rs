//! Accepts transport connections and submits them to the shared attachment engine.

use crate::authenticated::{
    admission::InboundAdmission,
    attachment::{Attachments, Error},
};
use commonware_macros::select_loop;
use commonware_runtime::{Acceptor, ContextCell, Handle, Listener, Scheduler, spawn_cell};
use tracing::debug;

/// Configuration for a transport listener.
pub struct Config<B> {
    /// Transport-specific binding instructions.
    pub bind: B,
}

/// Actor that accepts connections without waiting for their handshakes to finish.
pub struct Actor<R: Scheduler, A: Acceptor> {
    context: ContextCell<R>,
    acceptor: A,
    bind: A::Bind,
}

impl<R: Scheduler, A: Acceptor> Actor<R, A> {
    /// Creates a listener using an explicitly supplied acceptor.
    pub fn new(context: R, acceptor: A, cfg: Config<A::Bind>) -> Self {
        Self {
            context: ContextCell::new(context),
            acceptor,
            bind: cfg.bind,
        }
    }

    /// Starts accepting connections for the attachment engine.
    pub fn start<P, I>(mut self, attachments: Attachments<A::Connection, P, I>) -> Handle<()>
    where
        P: commonware_cryptography::PublicKey,
        I: InboundAdmission<P, <A::Connection as commonware_runtime::Connection>::Origin>,
    {
        spawn_cell!(self.context, self.run(attachments))
    }

    async fn run<P, I>(self, attachments: Attachments<A::Connection, P, I>)
    where
        P: commonware_cryptography::PublicKey,
        I: InboundAdmission<P, <A::Connection as commonware_runtime::Connection>::Origin>,
    {
        let mut listener = self
            .acceptor
            .bind(&self.bind)
            .await
            .expect("failed to bind listener");

        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping listener");
            },
            connection = listener.accept() => {
                let connection = match connection {
                    Ok(connection) => connection,
                    Err(error) => {
                        debug!(?error, "failed to accept connection");
                        continue;
                    }
                };

                match attachments.submit_inbound(connection) {
                    Ok(_) => {}
                    Err(Error::Busy) => {
                        debug!("attachment engine busy, dropping connection");
                    }
                    Err(Error::Rejected(error)) => {
                        debug!(?error, "connection rejected before authentication");
                    }
                    Err(error) => {
                        debug!(?error, "attachment engine unavailable");
                        break;
                    }
                }
            },
        }
    }
}
