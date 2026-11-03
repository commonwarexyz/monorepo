//! Durable certificate serving for the ordered committee tests.

use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_codec::Encode as _;
use commonware_consensus::{
    Reporter,
    aggregation::{
        scheme::Scheme,
        types::{Certificate, RecoveryKey},
    },
    types::{Epoch, Height},
};
use commonware_cryptography::Digest;
use commonware_parallel::Sequential;
use commonware_resolver::p2p::Producer;
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
/// The checkpoint reporter can see a certificate before the archive syncs it, and queue acceptance
/// does not mean the certificate is archived. Aggregation journals a certificate before reporting
/// it and replays every journaled certificate to its reporter on engine restart. A restarted
/// archive therefore catches up only if the application retains the aggregation journal until the
/// archive durably holds the full range. The archive stores no coverage marker, so the caller must
/// establish completeness from authenticated scope.
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

/// Only certificates synced to the independent archive are visible to the resolver. Opening syncs
/// replayed records before publishing them, because a retained tail can be readable without being
/// durable.
#[derive(Clone)]
pub(super) struct Archive {
    certificates: Arc<Mutex<BTreeMap<RecoveryKey, Bytes>>>,
}

impl Archive {
    /// Returns the encoded certificate archived for `key`, if any.
    pub(super) fn get(&self, key: &RecoveryKey) -> Option<Bytes> {
        self.certificates.lock().get(key).cloned()
    }
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
/// to this partition and its retention is independent of QMDB and marshal prune floors, so a late
/// validator can recover checkpoints below its state-sync base. This test helper retains the
/// archive for the validator lifetime. A production application must retain its archive for as
/// long as old-epoch recovery is required. Once signing duties end, a durably complete archive
/// permits retiring that epoch's aggregation journal and signing keys. The archive must remain
/// available for recovery. Storage failures are fatal.
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
    let mut recovered = BTreeMap::new();
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
        recovered.insert(key, certificate.encode());
    }
    let journal = replay
        .finish()
        .expect("certificate archive replay finishes");
    let mut journal = journal.sync_all().await.expect("certificate archive syncs");
    let certificates = Arc::new(Mutex::new(recovered));
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

    fn certificates(
        schemes: &[ed25519::Scheme],
        scope: (Epoch, Height, Height),
    ) -> Vec<Certificate<ed25519::Scheme, Digest>> {
        (0..2)
            .map(|position| {
                let item = Item {
                    position: Height::new(position),
                    digest: Sha256::hash(&[&position.to_be_bytes()]),
                };
                let acks: Vec<_> = schemes[..3]
                    .iter()
                    .map(|scheme| Ack::sign(scheme, item.clone()).unwrap())
                    .collect();
                Certificate::from_acks(&schemes[0], scope.0, non_empty![@acks.iter()], &Sequential)
                    .unwrap()
            })
            .collect()
    }

    fn key(
        scheme: &ed25519::Scheme,
        epoch: Epoch,
        certificate: &Certificate<ed25519::Scheme, Digest>,
    ) -> RecoveryKey {
        RecoveryKey {
            namespace: Scheme::<Digest>::recovery_namespace(scheme),
            epoch,
            position: certificate.item.position,
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
            let certificates = certificates(&fixture.schemes, scope);
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
                let key = key(scheme, scope.0, &certificate);
                assert_eq!(served.produce(key).await.unwrap(), certificate.encode());
            }
            drop(reporter);
            writer.await.unwrap();
        });
    }

    /// A crash may lose a queued certificate, but never publishes it before sync. The replayed
    /// reports below simulate aggregation's journal replay after engine restart; this test does not
    /// run an aggregation engine.
    #[test]
    fn archive_catches_up_from_replayed_reports_after_crash() {
        let scope = (Epoch::new(7), Height::zero(), Height::new(1));
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        let (state, checkpoint) = runner.start_and_recover(|mut context| async move {
            let fixture =
                ed25519::fixture(&mut context, b"_COMMONWARE_GLUE_CHECKPOINT_ARCHIVE_TEST", 4);
            let scheme = &fixture.schemes[0];
            let page_cache = CacheRef::new(NZU16!(1024), NZUsize!(10));
            let certificates = certificates(&fixture.schemes, scope);
            let (mut reporter, mut served, _writer) = archive(
                context.child("first"),
                "certificates".into(),
                page_cache,
                scheme,
                scope,
                Sink,
            )
            .await;
            reporter.report(certificates[0].clone());
            while served.certificates.lock().len() != 1 {
                context.sleep(Duration::from_millis(1)).await;
            }
            // The queue accepts the report synchronously, so no writer step can have synced it.
            reporter.report(certificates[1].clone());
            let key = key(scheme, scope.0, &certificates[1]);
            assert!(served.get(&key).is_none());
            // A missing key drops the response sender immediately, so this does not yield.
            assert!(served.produce(key).await.is_err());
            // Crash while the second certificate may be queued or unsynced.
            (fixture, certificates)
        });
        let (fixture, certificates) = state;

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let scheme = &fixture.schemes[0];
            let page_cache = CacheRef::new(NZU16!(1024), NZUsize!(10));
            let (mut reporter, mut served, writer) = archive(
                context.child("recovered"),
                "certificates".into(),
                page_cache.clone(),
                scheme,
                scope,
                Sink,
            )
            .await;
            // The first was synced. The second was still queued when the runtime crashed.
            let first = key(scheme, scope.0, &certificates[0]);
            assert_eq!(
                served.produce(first).await.unwrap(),
                certificates[0].encode()
            );
            let second = key(scheme, scope.0, &certificates[1]);
            assert!(served.get(&second).is_none());
            // Simulated engine replay reports the full journaled range, including duplicates.
            // Serving must be idempotent.
            for certificate in certificates.iter().chain(&certificates) {
                reporter.report(certificate.clone());
            }
            drop(reporter);
            writer.await.unwrap();
            for certificate in &certificates {
                let key = key(scheme, scope.0, certificate);
                assert_eq!(served.produce(key).await.unwrap(), certificate.encode());
            }
            drop(served);

            // A clean reopen still serves both. Journal duplicate counts are not observable here.
            let (reporter, mut served, writer) = archive(
                context.child("reopened"),
                "certificates".into(),
                page_cache,
                scheme,
                scope,
                Sink,
            )
            .await;
            assert_eq!(served.certificates.lock().len(), 2);
            for certificate in &certificates {
                let key = key(scheme, scope.0, certificate);
                assert_eq!(served.produce(key).await.unwrap(), certificate.encode());
            }
            drop(reporter);
            writer.await.unwrap();
        });
    }
}
