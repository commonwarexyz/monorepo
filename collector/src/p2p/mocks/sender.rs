//! Mock sender implementations for testing.

use commonware_codec::Codec;
use commonware_cryptography::PublicKey;
use commonware_p2p::{Recipients, Sender};
use thiserror::Error;

/// Errors that can be returned by [Failing].
#[derive(Debug, Error)]
pub enum Error {
    #[error("send failed")]
    Failed,
}

/// A sender that always fails with [Error::Canceled].
#[derive(Clone)]
pub struct Failing<P: PublicKey, M: Codec + Clone + Send + Sync + 'static> {
    _phantom_p: std::marker::PhantomData<P>,
    _phantom_m: std::marker::PhantomData<M>,
}

impl<P: PublicKey, M: Codec + Clone + Send + Sync + 'static> Failing<P, M> {
    /// Creates a new failing sender.
    pub fn new() -> Self {
        Self {
            _phantom_p: std::marker::PhantomData,
            _phantom_m: std::marker::PhantomData,
        }
    }
}

impl<P: PublicKey, M: Codec + Clone + Send + Sync + 'static> std::fmt::Debug for Failing<P, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Failing").finish()
    }
}

impl<P: PublicKey, M: Codec + Clone + Send + Sync + 'static> Sender for Failing<P, M> {
    type PublicKey = P;
    type Message = M;
    type Error = Error;

    async fn send(
        &mut self,
        _recipients: Recipients<P>,
        _message: M,
        _priority: bool,
    ) -> Result<Vec<P>, Self::Error> {
        Err(Error::Failed)
    }
}

