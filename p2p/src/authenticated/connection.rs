//! Connection management for authenticated peers.
//!
//! This module provides a `Connection` wrapper that handles connection lifecycle,
//! including support for abrupt close (RST instead of FIN) when blocking peers.

use commonware_runtime::{Disconnect, Sink, Stream};
use commonware_stream::encrypted::{Receiver, Sender};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// Type alias for the abrupt close callback.
type AbruptCloseFn<S> = Arc<dyn Fn(&Sender<S>) + Send + Sync>;

/// A wrapper around `Sender` that supports abrupt close.
///
/// When dropped, if the abrupt close flag is set and the underlying transport
/// supports it, SO_LINGER=0 will be set to send RST instead of FIN.
pub struct ManagedSender<S: Sink> {
    sender: Sender<S>,
    abrupt: Arc<AtomicBool>,
    on_abrupt: Option<AbruptCloseFn<S>>,
}

impl<S: Sink> ManagedSender<S> {
    /// Mark this connection for abrupt close.
    ///
    /// When dropped, will send RST instead of FIN (if supported).
    pub fn mark_abrupt(&self) {
        self.abrupt.store(true, Ordering::SeqCst);
    }

    /// Get a mutable reference to the underlying sender.
    pub const fn inner(&mut self) -> &mut Sender<S> {
        &mut self.sender
    }
}

impl<S: Sink> Drop for ManagedSender<S> {
    fn drop(&mut self) {
        if self.abrupt.load(Ordering::SeqCst) {
            if let Some(ref on_abrupt) = self.on_abrupt {
                on_abrupt(&self.sender);
            }
        }
    }
}

/// A managed connection to a peer.
///
/// This wrapper handles connection lifecycle, including support for abrupt close
/// (sending RST instead of FIN) when the connection should be terminated immediately.
pub struct Connection<S: Sink, R: Stream> {
    sender: ManagedSender<S>,
    receiver: Receiver<R>,
}

impl<S: Sink, R: Stream> Connection<S, R> {
    /// Create a new connection without TCP-specific close handling.
    ///
    /// Use this for non-TCP transports (QUIC, simulated, etc.) where abrupt close
    /// is either not supported or handled differently.
    pub fn new(sender: Sender<S>, receiver: Receiver<R>) -> Self {
        Self {
            sender: ManagedSender {
                sender,
                abrupt: Arc::new(AtomicBool::new(false)),
                on_abrupt: None,
            },
            receiver,
        }
    }

    /// Consume the connection and return its parts.
    ///
    /// The returned `ManagedSender` handles abrupt close automatically on drop.
    pub fn into_parts(self) -> (ManagedSender<S>, Receiver<R>) {
        (self.sender, self.receiver)
    }
}

impl<S: Sink + Disconnect, R: Stream> Connection<S, R> {
    /// Create a new connection with forced disconnect support.
    ///
    /// When `mark_abrupt()` is called on the sender and it is dropped,
    /// the connection will be forcefully reset (RST instead of FIN for TCP).
    pub fn new_abrupt(sender: Sender<S>, receiver: Receiver<R>) -> Self {
        Self {
            sender: ManagedSender {
                sender,
                abrupt: Arc::new(AtomicBool::new(false)),
                on_abrupt: Some(Arc::new(|sender| {
                    sender.sink().force_close();
                })),
            },
            receiver,
        }
    }
}
