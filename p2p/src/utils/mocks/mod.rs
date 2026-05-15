//! Mock implementations for testing.

use crate::{CheckedSender, LimitedSender, Receiver, Recipients};
use commonware_actor::Feedback;
use commonware_cryptography::PublicKey;
use commonware_runtime::{IoBuf, IoBufs};
use core::future;
use std::{convert::Infallible, marker::PhantomData, sync::Arc, time::SystemTime};

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
    type Error = Infallible;

    fn is_empty(&self) -> bool {
        self.recipients.is_empty()
    }

    fn recipients(&self) -> Vec<Self::PublicKey> {
        self.recipients.clone()
    }

    fn send(self, _: impl Into<IoBufs> + Send, _: bool) -> Result<Feedback, Self::Error> {
        Ok(Feedback::Ok)
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
        let sent = sender
            .send(Recipients::All, b"hello".to_vec(), false)
            .unwrap();
        assert_eq!(sent, peers);
    }
}
