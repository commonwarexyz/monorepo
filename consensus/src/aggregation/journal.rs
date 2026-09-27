//! Durable aggregation certificate journal.

use super::{
    scheme,
    types::{Certificate, RecoveryNamespace},
};
use crate::types::{Epoch, Height};
use bytes::BufMut;
use commonware_codec::{Buf, Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{
    Digest, Hasher, Sha256, certificate::Scheme as CertificateScheme,
    sha256::Digest as Sha256Digest,
};
use commonware_parallel::Strategy;
use commonware_runtime::{Metrics, ReadOptions, Storage, buffer::paged::CacheRef};
use commonware_storage::journal::{
    Error as StorageError,
    segmented::variable::{Config as StorageConfig, Journal as StorageJournal},
};
use commonware_utils::futures::rebind;
use rand_core::CryptoRng;
use std::num::{NonZeroU64, NonZeroUsize};

const VERSION: u8 = 3;
const COMMITTEE_DOMAIN: &[u8] = b"_COMMONWARE_CONSENSUS_AGGREGATION_JOURNAL_COMMITTEE_V1";

/// Scope and identity durably bound to an aggregation journal.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    namespace: RecoveryNamespace,
    committee: Sha256Digest,
    epoch: Epoch,
    first: Height,
    last: Height,
    window: NonZeroU64,
}

impl Identity {
    fn new<S: scheme::Scheme<D>, D: Digest>(scheme: &S, config: &JournalConfig) -> Self {
        let participants = scheme.participants().encode();
        Self {
            namespace: scheme.recovery_namespace(),
            committee: Sha256::hash(&[COMMITTEE_DOMAIN, participants.as_ref()]),
            epoch: config.epoch,
            first: config.first,
            last: config.last,
            window: config.window,
        }
    }
}

impl Write for Identity {
    fn write(&self, writer: &mut impl BufMut) {
        self.namespace.write(writer);
        self.committee.write(writer);
        self.epoch.write(writer);
        self.first.write(writer);
        self.last.write(writer);
        self.window.get().write(writer);
    }
}

impl Read for Identity {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            namespace: RecoveryNamespace::read(reader)?,
            committee: Sha256Digest::read(reader)?,
            epoch: Epoch::read(reader)?,
            first: Height::read(reader)?,
            last: Height::read(reader)?,
            window: NonZeroU64::new(u64::read(reader)?).ok_or(CodecError::Invalid(
                "consensus::aggregation::journal::Identity",
                "zero window",
            ))?,
        })
    }
}

impl EncodeSize for Identity {
    fn encode_size(&self) -> usize {
        self.namespace.encode_size()
            + self.committee.encode_size()
            + self.epoch.encode_size()
            + self.first.encode_size()
            + self.last.encode_size()
            + self.window.get().encode_size()
    }
}

/// Storage and scope configuration for an aggregation journal.
#[derive(Clone)]
pub(crate) struct JournalConfig {
    /// Storage partition.
    pub partition: String,
    /// Epoch represented by the journal.
    pub epoch: Epoch,
    /// First mandatory position, inclusive.
    pub first: Height,
    /// Last mandatory position, inclusive.
    pub last: Height,
    /// Maximum number of live positions.
    pub window: NonZeroU64,
    /// Write-buffer size.
    pub write_buffer: NonZeroUsize,
    /// Replay-buffer size.
    pub replay_buffer: NonZeroUsize,
    /// Number of positions assigned to each journal section.
    pub heights_per_section: NonZeroU64,
    /// Compression level.
    pub compression: Option<u8>,
    /// Page cache.
    pub page_cache: CacheRef,
}

/// Errors returned when opening or writing an aggregation journal.
#[derive(Debug, thiserror::Error)]
pub(crate) enum JournalError {
    /// The journal storage operation failed.
    #[error("aggregation journal storage error: {0}")]
    Storage(#[from] StorageError),
    /// The journal does not begin with an identity header.
    #[error("aggregation journal header missing")]
    MissingHeader,
    /// The journal contains more than one identity header.
    #[error("duplicate aggregation journal header")]
    DuplicateHeader,
    /// The format version differs.
    #[error("aggregation journal version mismatch")]
    VersionMismatch,
    /// The namespace, committee, epoch, range, or window differs.
    #[error("aggregation journal identity mismatch")]
    IdentityMismatch,
    /// A certificate does not belong to the configured scope or fails verification.
    #[error("aggregation journal certificate verification failed")]
    InvalidCertificate,
}

#[derive(Clone, Debug)]
enum Record<S: CertificateScheme, D: Digest> {
    Header(u8, Identity),
    Certificate(Certificate<S, D>),
}

impl<S: CertificateScheme, D: Digest> Write for Record<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Header(version, identity) => {
                0u8.write(writer);
                version.write(writer);
                identity.write(writer);
            }
            Self::Certificate(certificate) => {
                1u8.write(writer);
                certificate.write(writer);
            }
        }
    }
}

impl<S: CertificateScheme, D: Digest> Read for Record<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            0 => Ok(Self::Header(u8::read(reader)?, Identity::read(reader)?)),
            1 => Ok(Self::Certificate(Certificate::read_cfg(reader, cfg)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl<S: CertificateScheme, D: Digest> EncodeSize for Record<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Header(version, identity) => version.encode_size() + identity.encode_size(),
            Self::Certificate(value) => value.encode_size(),
        }
    }
}

/// Identity-checked journal of aggregation certificates.
pub(crate) struct Journal<E, S, D>
where
    E: Storage + Metrics,
    S: CertificateScheme,
    D: Digest,
{
    inner: Option<StorageJournal<E, Record<S, D>>>,
    heights_per_section: NonZeroU64,
    restarted: bool,
}

impl<E, S, D> Journal<E, S, D>
where
    E: Storage + Metrics,
    S: scheme::Scheme<D>,
    D: Digest,
{
    /// Opens a journal, returning its fully verified certificates.
    ///
    /// An empty partition is initialized with the identity derived from `scheme` and `config`,
    /// then synced before return. An existing partition with a different identity is rejected.
    pub async fn init<R, T>(
        context: E,
        config: JournalConfig,
        verifier: &mut R,
        scheme: &S,
        strategy: &T,
    ) -> Result<(Self, Vec<Certificate<S, D>>), JournalError>
    where
        R: CryptoRng,
        T: Strategy,
    {
        let identity = Identity::new(scheme, &config);
        let storage_config = StorageConfig {
            partition: config.partition,
            compression: config.compression,
            codec_config: S::certificate_codec_config_unbounded(),
            page_cache: config.page_cache,
            write_buffer: config.write_buffer,
        };
        let journal = StorageJournal::init(context, storage_config).await?;
        let empty = journal.is_empty();
        let mut replay = journal
            .replay(0, 0, config.replay_buffer, ReadOptions::DONT_CACHE)
            .await?;
        let mut header = false;
        let mut certificates = Vec::new();
        while let Some(record) = replay.next().await {
            let (_, _, _, record) = record?;
            match (header, record) {
                (false, Record::Header(version, stored)) => {
                    if version != VERSION {
                        return Err(JournalError::VersionMismatch);
                    }
                    if stored != identity {
                        return Err(JournalError::IdentityMismatch);
                    }
                    header = true;
                }
                (false, Record::Certificate(_)) => return Err(JournalError::MissingHeader),
                (true, Record::Header(..)) => return Err(JournalError::DuplicateHeader),
                (true, Record::Certificate(certificate)) => {
                    if !certificate.verify_for(
                        verifier,
                        scheme,
                        identity.epoch,
                        identity.first,
                        identity.last,
                        strategy,
                    ) {
                        return Err(JournalError::InvalidCertificate);
                    }
                    certificates.push(certificate);
                }
            }
        }
        let mut journal = replay.finish()?;
        if empty {
            let (next, _, _) = journal
                .append(0, &Record::Header(VERSION, identity))
                .await?;
            journal = next.sync(0).await?;
        } else if !header {
            return Err(JournalError::MissingHeader);
        }
        Ok((
            Self {
                inner: Some(journal),
                heights_per_section: config.heights_per_section,
                restarted: !empty,
            },
            certificates,
        ))
    }

    pub const fn restarted(&self) -> bool {
        self.restarted
    }

    pub async fn append(&mut self, certificate: Certificate<S, D>) -> Result<(), JournalError> {
        let section = certificate.item.position.get() / self.heights_per_section.get();
        let record = Record::Certificate(certificate);
        rebind(&mut self.inner, |journal| journal.append(section, &record)).await?;
        rebind(&mut self.inner, |journal| journal.sync(section)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregation::{
        scheme::ed25519,
        types::{Ack, Item},
    };
    use commonware_cryptography::certificate::{Verifier, mocks::Fixture};
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{NZU16, NZUsize, non_empty, ordered::Quorum as _};

    const NAMESPACE: &[u8] = b"aggregation journal test";
    const EPOCH: Epoch = Epoch::new(3);
    const FIRST: Height = Height::new(10);
    const LAST: Height = Height::new(12);

    fn config(context: &deterministic::Context, partition: &str) -> JournalConfig {
        JournalConfig {
            partition: partition.into(),
            epoch: EPOCH,
            first: FIRST,
            last: LAST,
            window: NonZeroU64::new(2).unwrap(),
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
            heights_per_section: NonZeroU64::new(2).unwrap(),
            compression: None,
            page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
        }
    }

    fn certificate(
        fixture: &Fixture<ed25519::Scheme>,
        position: Height,
    ) -> Certificate<ed25519::Scheme, Sha256Digest> {
        let item = Item {
            position,
            digest: Sha256::hash(&[&position.get().to_be_bytes()]),
        };
        let quorum = fixture.schemes[0]
            .participants()
            .quorum::<<ed25519::Scheme as Verifier>::Faults>();
        let quorum = usize::try_from(quorum).unwrap();
        let acks: Vec<_> = fixture.schemes[..quorum]
            .iter()
            .map(|scheme| Ack::sign(scheme, item.clone()).unwrap())
            .collect();
        Certificate::from_acks(
            &fixture.schemes[0],
            EPOCH,
            non_empty![@acks.iter()],
            &Sequential,
        )
        .unwrap()
    }

    async fn open(
        context: &mut deterministic::Context,
        config: JournalConfig,
        scheme: &ed25519::Scheme,
    ) -> Result<
        (
            Journal<deterministic::Context, ed25519::Scheme, Sha256Digest>,
            Vec<Certificate<ed25519::Scheme, Sha256Digest>>,
        ),
        JournalError,
    > {
        let journal_context = context.child("journal");
        Journal::init(journal_context, config, context, scheme, &Sequential).await
    }

    async fn write_raw(
        context: &deterministic::Context,
        config: &JournalConfig,
        records: &[Record<ed25519::Scheme, Sha256Digest>],
    ) {
        let storage_config = StorageConfig {
            partition: config.partition.clone(),
            compression: config.compression,
            codec_config: <ed25519::Scheme as Verifier>::certificate_codec_config_unbounded(),
            page_cache: config.page_cache.clone(),
            write_buffer: config.write_buffer,
        };
        let mut journal = StorageJournal::<_, Record<ed25519::Scheme, Sha256Digest>>::init(
            context.child("raw"),
            storage_config,
        )
        .await
        .unwrap();
        for record in records {
            let (next, _, _) = journal.append(0, record).await.unwrap();
            journal = next;
        }
        journal.sync_all().await.unwrap();
    }

    #[test_traced]
    fn test_replays_verified_certificates() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = ed25519::fixture(&mut context, NAMESPACE, 4);
            let scheme = &fixture.schemes[0];
            let config = config(&context, "replay");

            let (mut journal, certificates) =
                open(&mut context, config.clone(), scheme).await.unwrap();
            assert!(!journal.restarted());
            assert!(certificates.is_empty());
            journal.append(certificate(&fixture, FIRST)).await.unwrap();
            journal.append(certificate(&fixture, LAST)).await.unwrap();
            drop(journal);

            let (journal, certificates) = open(&mut context, config, scheme).await.unwrap();
            assert!(journal.restarted());
            let positions: Vec<_> = certificates
                .iter()
                .map(|certificate| certificate.item.position)
                .collect();
            assert_eq!(positions, [FIRST, LAST]);
        });
    }

    #[test_traced]
    fn test_rejects_identity_mismatch() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = ed25519::fixture(&mut context, NAMESPACE, 4);
            let other = ed25519::fixture(&mut context, NAMESPACE, 4);
            let scheme = &fixture.schemes[0];
            let config = config(&context, "identity");
            open(&mut context, config.clone(), scheme).await.unwrap();

            let renamespaced = ed25519::Scheme::signer(
                b"other namespace",
                scheme.participants().clone(),
                fixture.private_keys[0].clone(),
            )
            .unwrap();
            let schemes = [
                ("namespace", renamespaced),
                ("committee", other.schemes[0].clone()),
            ];
            for (name, scheme) in &schemes {
                let result = open(&mut context, config.clone(), scheme).await;
                assert!(
                    matches!(result, Err(JournalError::IdentityMismatch)),
                    "{name}"
                );
            }

            let mismatches = [
                (
                    "epoch",
                    JournalConfig {
                        epoch: EPOCH.next(),
                        ..config.clone()
                    },
                ),
                (
                    "first",
                    JournalConfig {
                        first: FIRST.next(),
                        ..config.clone()
                    },
                ),
                (
                    "last",
                    JournalConfig {
                        last: LAST.next(),
                        ..config.clone()
                    },
                ),
                (
                    "window",
                    JournalConfig {
                        window: config.window.checked_add(1).unwrap(),
                        ..config.clone()
                    },
                ),
            ];
            for (name, mismatch) in mismatches {
                let result = open(&mut context, mismatch, scheme).await;
                assert!(
                    matches!(result, Err(JournalError::IdentityMismatch)),
                    "{name}"
                );
            }

            // Rejection must not modify the journal.
            open(&mut context, config, scheme).await.unwrap();
        });
    }

    #[test_traced]
    fn test_rejects_certificate_from_other_committee() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = ed25519::fixture(&mut context, NAMESPACE, 4);
            let other = ed25519::fixture(&mut context, NAMESPACE, 4);
            let config = config(&context, "tampered");
            let (mut journal, _) = open(&mut context, config.clone(), &fixture.schemes[0])
                .await
                .unwrap();
            journal.append(certificate(&other, FIRST)).await.unwrap();
            drop(journal);

            let result = open(&mut context, config, &fixture.schemes[0]).await;
            assert!(matches!(result, Err(JournalError::InvalidCertificate)));
        });
    }

    #[test_traced]
    fn test_rejects_malformed_headers() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = ed25519::fixture(&mut context, NAMESPACE, 4);
            let scheme = &fixture.schemes[0];
            let base = config(&context, "unused");
            let identity = Identity::new::<_, Sha256Digest>(scheme, &base);
            let header = |version| Record::Header(version, identity.clone());
            let cases = [
                (
                    "missing",
                    vec![Record::Certificate(certificate(&fixture, FIRST))],
                    JournalError::MissingHeader,
                ),
                (
                    "duplicate",
                    vec![header(VERSION), header(VERSION)],
                    JournalError::DuplicateHeader,
                ),
                (
                    "version",
                    vec![header(VERSION + 1)],
                    JournalError::VersionMismatch,
                ),
            ];
            for (name, records, expected) in cases {
                let config = config(&context, name);
                write_raw(&context, &config, &records).await;
                let error = open(&mut context, config, scheme).await.err().unwrap();
                assert_eq!(
                    std::mem::discriminant(&error),
                    std::mem::discriminant(&expected),
                    "{name}: {error}"
                );
            }
        });
    }
}
