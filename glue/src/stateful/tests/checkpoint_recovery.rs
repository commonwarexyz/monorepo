//! Durable certificate serving for the ordered committee tests.

use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_codec::Encode as _;
use commonware_consensus::{
    Reporter,
    aggregation::{
        self,
        scheme::Scheme,
        types::{Certificate, RecoveryKey},
    },
    types::{Epoch, Height},
};
use commonware_cryptography::Digest;
use commonware_parallel::Sequential;
use commonware_resolver::{Consumer, Delivery, Outcome, p2p::Producer};
use commonware_runtime::{
    Handle, ReadOptions, Spawner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::journal::segmented::variable::{Config, Journal};
use commonware_utils::{
    NZUsize,
    channel::{mpsc, oneshot},
    sync::Mutex,
};
use std::{collections::BTreeMap, sync::Arc};

/// Queues certificates for durable archival and forwards them to the checkpoint reporter.
///
/// The checkpoint reporter can see a certificate before the archive syncs it. Aggregation replays
/// every journaled certificate to this reporter on restart, so the archive catches up as long as
/// the aggregation journal outlives it.
#[derive(Clone)]
pub(super) struct ArchiveReporter<
    S: Scheme<D>,
    D: Digest,
    R: Reporter<Activity = Certificate<S, D>>,
> {
    sender: mpsc::UnboundedSender<Certificate<S, D>>,
    reporter: R,
}

impl<S: Scheme<D>, D: Digest, R: Reporter<Activity = Certificate<S, D>>> Reporter
    for ArchiveReporter<S, D, R>
{
    type Activity = Certificate<S, D>;

    fn report(&mut self, certificate: Self::Activity) -> Feedback {
        self.sender
            .send(certificate.clone())
            .expect("certificate archive is running");
        self.reporter.report(certificate)
    }
}

/// Only certificates synced to the independent archive are visible to the resolver.
#[derive(Clone)]
pub(super) struct Archive {
    certificates: Arc<Mutex<BTreeMap<RecoveryKey, Bytes>>>,
}

impl Producer for Archive {
    type Key = RecoveryKey;

    fn produce(&mut self, key: RecoveryKey) -> oneshot::Receiver<Bytes> {
        let (sender, receiver) = oneshot::channel();
        if let Some(certificate) = self.certificates.lock().get(&key) {
            let _ = sender.send(certificate.clone());
        }
        receiver
    }
}

/// Replays all archived positions before starting the serving resolver. No block pruning applies
/// to this partition, so a late validator can recover checkpoints below its state-sync base.
/// The tests retain the archive for the validator lifetime and never automatically retire it.
pub(super) async fn archive<S, D, R>(
    mut context: deterministic::Context,
    partition: String,
    page_cache: CacheRef,
    scheme: &S,
    scope: (Epoch, Height, Height),
    reporter: R,
) -> (ArchiveReporter<S, D, R>, Archive, Handle<()>)
where
    S: Scheme<D>,
    D: Digest,
    R: Reporter<Activity = Certificate<S, D>>,
{
    let namespace = scheme.recovery_namespace();
    let journal = Journal::<_, Certificate<S, D>>::init(
        context.child("journal"),
        Config {
            partition,
            compression: None,
            codec_config: scheme.certificate_codec_config(),
            page_cache,
            write_buffer: NZUsize!(4_096),
        },
    )
    .await
    .expect("certificate archive opens");
    let certificates = Arc::new(Mutex::new(BTreeMap::new()));
    let mut replay = journal
        .replay(0, 0, NZUsize!(4_096), ReadOptions::DONT_CACHE)
        .await
        .expect("certificate archive replays");
    while let Some(record) = replay.next().await {
        let (_, _, _, certificate) = record.expect("certificate archive record decodes");
        assert!(
            certificate.verify_for(&mut context, scheme, scope.0, scope.1, scope.2, &Sequential),
            "archived certificate belongs to the configured checkpoint scope"
        );
        let key = RecoveryKey {
            namespace,
            epoch: certificate.epoch,
            position: certificate.item.position,
        };
        certificates.lock().insert(key, certificate.encode());
    }
    let mut journal = replay
        .finish()
        .expect("certificate archive replay finishes");
    let (sender, mut receiver) = mpsc::unbounded_channel::<Certificate<S, D>>();
    let archive = Archive {
        certificates: certificates.clone(),
    };
    let handle = context.child("writer").spawn(move |_| async move {
        while let Some(certificate) = receiver.recv().await {
            let key = RecoveryKey {
                namespace,
                epoch: certificate.epoch,
                position: certificate.item.position,
            };
            if certificates.lock().contains_key(&key) {
                continue;
            }
            let (next, _, _) = journal
                .append(0, &certificate)
                .await
                .expect("certificate archive appends");
            journal = next.sync(0).await.expect("certificate archive syncs");
            certificates.lock().insert(key, certificate.encode());
        }
    });
    (ArchiveReporter { sender, reporter }, archive, handle)
}

/// A resolver consumer is constructed before its engine, then bound before the resolver starts.
#[derive(Clone)]
pub(super) struct Ingress<S: Scheme<D>, D: Digest> {
    context: Arc<deterministic::Context>,
    mailbox: Arc<Mutex<Option<aggregation::Mailbox<S, D>>>>,
}

impl<S: Scheme<D>, D: Digest> Ingress<S, D> {
    pub(super) fn new(context: deterministic::Context) -> Self {
        Self {
            context: Arc::new(context),
            mailbox: Arc::new(Mutex::new(None)),
        }
    }

    pub(super) fn bind(&self, mailbox: aggregation::Mailbox<S, D>) {
        assert!(self.mailbox.lock().replace(mailbox).is_none());
    }
}

impl<S: Scheme<D>, D: Digest> Consumer for Ingress<S, D> {
    type Key = RecoveryKey;
    type Value = Bytes;
    type Subscriber = ();
    type Outcome = Outcome;

    fn deliver(
        &mut self,
        delivery: Delivery<RecoveryKey, ()>,
        value: Bytes,
    ) -> oneshot::Receiver<Outcome> {
        let (sender, receiver) = oneshot::channel();
        let mut mailbox = self
            .mailbox
            .lock()
            .clone()
            .expect("recovery ingress is bound");
        self.context.child("delivery").spawn(move |_| async move {
            let _ = sender.send(mailbox.submit(delivery.key, value).await.into());
        });
        receiver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::{
        aggregation::{
            scheme::ed25519,
            types::{Ack, Item},
        },
        types::{Epoch, Height},
    };
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
    use commonware_runtime::{Clock as _, Runner as _};
    use commonware_utils::{NZU16, non_empty};
    use std::time::Duration;

    #[derive(Clone)]
    struct Sink;

    impl Reporter for Sink {
        type Activity = Certificate<ed25519::Scheme, Digest>;

        fn report(&mut self, _: Self::Activity) -> Feedback {
            Feedback::Ok
        }
    }

    #[test]
    fn archive_serves_older_certificates_after_reopening() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
            let fixture =
                ed25519::fixture(&mut context, b"_COMMONWARE_GLUE_CHECKPOINT_ARCHIVE_TEST", 4);
            let scheme = &fixture.schemes[0];
            let scope = (Epoch::new(7), Height::zero(), Height::new(1));
            let page_cache = CacheRef::new(NZU16!(1024), NZUsize!(10));
            let certificates: Vec<_> = (0..2)
                .map(|position| {
                    let item = Item {
                        position: Height::new(position),
                        digest: Sha256::hash(&[&position.to_be_bytes()]),
                    };
                    let acks: Vec<_> = fixture.schemes[..3]
                        .iter()
                        .map(|scheme| Ack::sign(scheme, item.clone()).unwrap())
                        .collect();
                    Certificate::from_acks(scheme, scope.0, non_empty![@acks.iter()], &Sequential)
                        .unwrap()
                })
                .collect();
            let (mut reporter, served, writer) = archive(
                context.child("first"),
                "certificates".into(),
                page_cache.clone(),
                scheme,
                scope,
                Sink,
            )
            .await;
            for certificate in &certificates {
                reporter.report(certificate.clone());
            }
            while served.certificates.lock().len() != 2 {
                context.sleep(Duration::from_millis(1)).await;
            }
            drop(reporter);
            writer.await.unwrap();
            drop(served);

            let (reporter, mut served, writer) = archive(
                context.child("reopened"),
                "certificates".into(),
                page_cache,
                scheme,
                scope,
                Sink,
            )
            .await;
            for certificate in certificates {
                let key = RecoveryKey {
                    namespace: Scheme::<Digest>::recovery_namespace(scheme),
                    epoch: scope.0,
                    position: certificate.item.position,
                };
                assert_eq!(served.produce(key).await.unwrap(), certificate.encode());
            }
            drop(reporter);
            writer.await.unwrap();
        });
    }
}
