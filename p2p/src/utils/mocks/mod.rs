//! Mock implementations for testing.

use crate::{CheckedSender, LimitedSender, Receiver, Recipients};
use commonware_actor::Feedback;
use commonware_cryptography::PublicKey;
use commonware_runtime::{
    telemetry::metrics::{Metric, Registered, Registration},
    IoBuf, IoBufs, Metrics as RuntimeMetrics, Name, Supervisor,
};
use core::future;
use std::{convert::Infallible, marker::PhantomData, sync::Arc, time::SystemTime};

/// Metrics implementation that registers nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics;

impl Supervisor for Metrics {
    fn name(&self) -> Name {
        Name::default()
    }

    fn child(&self, _label: &'static str) -> Self {
        Self
    }

    fn with_attribute(self, _key: &'static str, _value: impl std::fmt::Display) -> Self {
        self
    }
}

impl RuntimeMetrics for Metrics {
    fn register<N: Into<String>, H: Into<String>, M: Metric>(
        &self,
        _name: N,
        _help: H,
        metric: M,
    ) -> Registered<M> {
        Registered::with_registration(metric, Registration::from(()))
    }

    fn encode(&self) -> String {
        String::new()
    }
}

/// Sender that accepts messages without delivering them.
///
/// The sender retains a static peer set so that [`Recipients::All`] can be
/// expanded consistently with the [`crate::Sender`] contract.
#[derive(Clone, Debug, Default)]
pub struct InertSender<P> {
    peers: Arc<[P]>,
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

    fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        Ok(InertCheckedSender {
            recipients: match recipients {
                Recipients::All => self.peers.iter().cloned().collect(),
                Recipients::Some(recipients) => recipients,
                Recipients::One(recipient) => vec![recipient],
            },
        })
    }
}

impl<P: PublicKey> CheckedSender for InertCheckedSender<P> {
    type PublicKey = P;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        self.recipients.clone()
    }

    fn send(self, _: impl Into<IoBufs> + Send, _: bool) -> Feedback {
        Feedback::Ok
    }
}

impl<P: PublicKey> Receiver for InertReceiver<P> {
    type Error = Infallible;
    type PublicKey = P;

    async fn recv(&mut self) -> Result<(P, IoBuf), Self::Error> {
        future::pending().await
    }
}

/// Construct an inert point-to-point channel over a static peer set.
pub fn inert_channel<P: PublicKey>(peers: impl AsRef<[P]>) -> (InertSender<P>, InertReceiver<P>) {
    (
        InertSender {
            peers: Arc::from(peers.as_ref()),
        },
        InertReceiver {
            _phantom: PhantomData,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sender;
    use commonware_cryptography::{ed25519::PrivateKey, Signer};
    use commonware_math::algebra::Random;
    use commonware_utils::test_rng;

    #[test]
    fn inert_sender_expands_all_recipients() {
        let mut rng = test_rng();
        let peers = vec![
            PrivateKey::random(&mut rng).public_key(),
            PrivateKey::random(&mut rng).public_key(),
            PrivateKey::random(&mut rng).public_key(),
        ];

        let (mut sender, _) = inert_channel(peers.as_slice());
        let sent = sender.send(Recipients::All, b"hello".to_vec(), false);
        assert_eq!(sent, peers);
    }
}
