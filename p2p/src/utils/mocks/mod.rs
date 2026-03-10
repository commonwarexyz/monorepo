//! Mock implementations for testing.

use crate::{CheckedSender, LimitedSender, Receiver, Recipients};
use commonware_cryptography::PublicKey;
use commonware_runtime::{IoBuf, IoBufs};
use core::future;
use std::{convert::Infallible, marker::PhantomData, time::SystemTime};

/// Sender that accepts messages without delivering them.
#[derive(Clone, Debug, Default)]
pub struct InertSender<P> {
    _phantom: PhantomData<P>,
}

/// Checked sender returned by [`InertSender`].
#[derive(Debug)]
pub struct InertCheckedSender<P> {
    recipients: Vec<P>,
}

/// Receiver that never yields a message.
#[derive(Debug, Default)]
pub struct InertReceiver<P> {
    _phantom: PhantomData<P>,
}

impl<P: PublicKey> LimitedSender for InertSender<P> {
    type PublicKey = P;
    type Checked<'a>
        = InertCheckedSender<P>
    where
        Self: 'a;

    async fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        Ok(InertCheckedSender {
            recipients: match recipients {
                Recipients::All => Vec::new(),
                Recipients::Some(recipients) => recipients,
                Recipients::One(recipient) => vec![recipient],
            },
        })
    }
}

impl<P: PublicKey> CheckedSender for InertCheckedSender<P> {
    type PublicKey = P;
    type Error = Infallible;

    async fn send(
        self,
        _: impl Into<IoBufs> + Send,
        _: bool,
    ) -> Result<Vec<Self::PublicKey>, Self::Error> {
        Ok(self.recipients)
    }
}

impl<P: PublicKey> Receiver for InertReceiver<P> {
    type Error = Infallible;
    type PublicKey = P;

    async fn recv(&mut self) -> Result<(P, IoBuf), Self::Error> {
        future::pending().await
    }
}

/// Construct an inert point-to-point channel.
pub fn inert_channel<P: PublicKey>() -> (InertSender<P>, InertReceiver<P>) {
    (
        InertSender {
            _phantom: PhantomData,
        },
        InertReceiver {
            _phantom: PhantomData,
        },
    )
}
