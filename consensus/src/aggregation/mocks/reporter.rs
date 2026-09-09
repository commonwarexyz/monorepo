use crate::aggregation::types::Certificate;
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy, Receiver, Sender},
};
use commonware_cryptography::{Digest, certificate::Scheme};
use commonware_runtime::{ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::{NZUsize, channel::oneshot};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, VecDeque},
    marker::PhantomData,
};

enum Message<S: Scheme, D: Digest> {
    Certificate(Certificate<S, D>),
    Get(oneshot::Sender<BTreeMap<crate::types::Height, Certificate<S, D>>>),
}

impl<S: Scheme, D: Digest> Policy for Message<S, D> {
    type Overflow = VecDeque<Self>;
    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

pub struct Reporter<R: CryptoRng, S: Scheme, D: Digest> {
    context: ContextCell<R>,
    mailbox: Receiver<Message<S, D>>,
    certificates: BTreeMap<crate::types::Height, Certificate<S, D>>,
    _scheme: PhantomData<S>,
}

impl<R: CryptoRng + Metrics, S: Scheme, D: Digest> Reporter<R, S, D> {
    pub fn new(context: R, _scheme: S) -> (Self, Mailbox<S, D>) {
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), NZUsize!(1024));
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                certificates: BTreeMap::new(),
                _scheme: PhantomData,
            },
            Mailbox { sender },
        )
    }

    pub fn start(mut self) -> Handle<()>
    where
        R: Spawner,
    {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        while let Some(message) = self.mailbox.recv().await {
            match message {
                Message::Certificate(certificate) => {
                    self.certificates
                        .insert(certificate.item.position, certificate);
                }
                Message::Get(sender) => {
                    sender.send(self.certificates.clone()).unwrap();
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> crate::Reporter for Mailbox<S, D> {
    type Activity = Certificate<S, D>;
    fn report(&mut self, certificate: Self::Activity) -> Feedback {
        self.sender.enqueue(Message::Certificate(certificate))
    }
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    pub async fn get(&mut self) -> BTreeMap<crate::types::Height, Certificate<S, D>> {
        let (sender, receiver) = oneshot::channel();
        assert!(self.sender.enqueue(Message::Get(sender)).accepted());
        receiver.await.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Reporter as _,
        aggregation::{
            scheme::ed25519,
            types::{Ack, Item},
        },
        types::{Epoch, Height},
    };
    use commonware_cryptography::{Hasher as _, Sha256, certificate::mocks::Fixture};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::{N3f1, non_empty, ordered::Quorum as _, test_rng};

    #[test]
    fn reports_and_replaces_certificates_by_height() {
        deterministic::Runner::default().start(|context| async move {
            let mut rng = test_rng();
            let Fixture { schemes, .. } = ed25519::fixture(&mut rng, b"reporter", 4);
            let item = Item {
                position: Height::new(7),
                digest: Sha256::hash(&[b"digest"]),
            };
            let acks: Vec<_> = schemes
                .iter()
                .take(
                    usize::try_from(schemes[0].participants().quorum_count::<N3f1>())
                        .expect("quorum count must fit in usize"),
                )
                .map(|scheme| Ack::sign(scheme, item.clone()).unwrap())
                .collect();
            let certificate = Certificate::from_acks(
                &schemes[0],
                Epoch::new(1),
                non_empty![@acks.iter()],
                &Sequential,
            )
            .unwrap();
            let (reporter, mut mailbox) = Reporter::new(context, schemes[0].clone());
            let handle = reporter.start();

            assert!(mailbox.report(certificate.clone()).accepted());
            let reported = mailbox.get().await.remove(&item.position).unwrap();
            assert_eq!(reported.epoch, certificate.epoch);
            assert_eq!(reported.item, certificate.item);
            assert_eq!(reported.certificate, certificate.certificate);

            drop(mailbox);
            handle.await.unwrap();
        });
    }
}
