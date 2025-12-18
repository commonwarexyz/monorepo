//! Mock sender implementations for testing.

use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_p2p::{CheckedSender, LimitedSender, Recipients};
use std::time::SystemTime;
use thiserror::Error;

/// Errors that can be returned by [Failing].
#[derive(Debug, Error)]
pub enum Error {
    #[error("send failed")]
    Failed,
}

/// A sender that always fails with [Error::Canceled].
#[derive(Clone, Debug)]
pub struct Failing<P: PublicKey> {
    _phantom: std::marker::PhantomData<P>,
}

impl<P: PublicKey> Failing<P> {
    /// Creates a new failing sender.
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<P: PublicKey> LimitedSender for Failing<P> {
    type PublicKey = P;
    type Checked<'a> = CheckedFailing<P>;

    async fn check(&mut self, _recipients: Recipients<P>) -> Result<Self::Checked<'_>, SystemTime> {
        Ok(CheckedFailing {
            _phantom: std::marker::PhantomData,
        })
    }
}

pub struct CheckedFailing<P: PublicKey> {
    _phantom: std::marker::PhantomData<P>,
}

impl<P: PublicKey> CheckedSender for CheckedFailing<P> {
    type PublicKey = P;
    type Error = Error;

    async fn send(self, _message: Bytes, _priority: bool) -> Result<Vec<P>, Self::Error> {
        Err(Error::Failed)
    }
}
