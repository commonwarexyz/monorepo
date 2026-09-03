//! Durable aggregation certificate journal.

use super::{
    scheme,
    types::{Certificate, RecoveryNamespace},
};
use crate::types::{Epoch, Height};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
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

/// Identity durably bound to an aggregation journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalIdentity {
    /// Signing namespace digest.
    pub namespace: RecoveryNamespace,
    /// Digest of the ordered committee.
    pub committee: Sha256Digest,
    /// Epoch represented by the journal.
    pub epoch: Epoch,
    /// First mandatory position, inclusive.
    pub first: Height,
    /// Last mandatory position, inclusive.
    pub last: Height,
    /// Maximum number of live positions.
    pub window: NonZeroU64,
}

impl JournalIdentity {
    /// Derives the exact journal identity from a scheme and aggregation scope.
    pub fn new<S, D>(
        scheme: &S,
        epoch: Epoch,
        first: Height,
        last: Height,
        window: NonZeroU64,
    ) -> Self
    where
        S: scheme::Scheme<D>,
        D: Digest,
    {
        let participants = scheme.participants().encode();
        Self {
            namespace: scheme.recovery_namespace(),
            committee: Sha256::hash(&[COMMITTEE_DOMAIN, participants.as_ref()]),
            epoch,
            first,
            last,
            window,
        }
    }
}

/// Storage and identity configuration for an aggregation journal.
#[derive(Clone)]
pub struct JournalConfig {
    /// Exact identity the journal must have.
    pub identity: JournalIdentity,
    /// Storage partition.
    pub partition: String,
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

/// Errors returned by an aggregation journal.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
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
    /// The signing namespace differs.
    #[error("aggregation journal namespace digest mismatch")]
    NamespaceMismatch,
    /// The ordered committee differs.
    #[error("aggregation journal committee mismatch")]
    CommitteeMismatch,
    /// The epoch differs.
    #[error("aggregation journal epoch mismatch")]
    EpochMismatch,
    /// The first position differs.
    #[error("aggregation journal first-position mismatch")]
    FirstMismatch,
    /// The last position differs.
    #[error("aggregation journal last-position mismatch")]
    LastMismatch,
    /// The live-position window differs.
    #[error(
        "aggregation journal window mismatch; durably archive the complete range before replacing the journal"
    )]
    WindowMismatch,
    /// A certificate does not belong to the configured scope or fails verification.
    #[error("aggregation journal certificate verification failed")]
    InvalidCertificate,
}

#[derive(Clone, Debug)]
struct Header {
    version: u8,
    identity: JournalIdentity,
}

impl Write for Header {
    fn write(&self, writer: &mut impl BufMut) {
        self.version.write(writer);
        self.identity.namespace.write(writer);
        self.identity.committee.write(writer);
        self.identity.epoch.write(writer);
        self.identity.first.write(writer);
        self.identity.last.write(writer);
        self.identity.window.get().write(writer);
    }
}

impl Read for Header {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let version = u8::read(reader)?;
        let namespace = RecoveryNamespace::read(reader)?;
        let committee = Sha256Digest::read(reader)?;
        let epoch = Epoch::read(reader)?;
        let first = Height::read(reader)?;
        let last = Height::read(reader)?;
        let window = NonZeroU64::new(u64::read(reader)?).ok_or(CodecError::Invalid(
            "consensus::aggregation::journal::Header",
            "zero window",
        ))?;
        Ok(Self {
            version,
            identity: JournalIdentity {
                namespace,
                committee,
                epoch,
                first,
                last,
                window,
            },
        })
    }
}

impl EncodeSize for Header {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
            + self.identity.namespace.encode_size()
            + self.identity.committee.encode_size()
            + self.identity.epoch.encode_size()
            + self.identity.first.encode_size()
            + self.identity.last.encode_size()
            + self.identity.window.get().encode_size()
    }
}

#[derive(Clone, Debug)]
enum Record<S: CertificateScheme, D: Digest> {
    Header(Header),
    Certificate(Certificate<S, D>),
}

impl<S: CertificateScheme, D: Digest> Write for Record<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Header(header) => {
                0u8.write(writer);
                header.write(writer);
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
            0 => Ok(Self::Header(Header::read(reader)?)),
            1 => Ok(Self::Certificate(Certificate::read_cfg(reader, cfg)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl<S: CertificateScheme, D: Digest> EncodeSize for Record<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Header(value) => value.encode_size(),
            Self::Certificate(value) => value.encode_size(),
        }
    }
}

/// Identity-checked journal of aggregation certificates.
///
/// A handle is returned only after every replayed certificate has been verified against the
/// configured scheme, epoch, and range. Consequently, [`Self::destroy`] can remove only the exact
/// journal opened by the caller.
pub struct Journal<E, S, D>
where
    E: Storage + Metrics,
    S: CertificateScheme,
    D: Digest,
{
    inner: Option<StorageJournal<E, Record<S, D>>>,
    identity: JournalIdentity,
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
    /// An empty partition is initialized with the configured identity and synced before return.
    /// An existing partition with a different identity is rejected without being destroyed.
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
        let derived = JournalIdentity::new(
            scheme,
            config.identity.epoch,
            config.identity.first,
            config.identity.last,
            config.identity.window,
        );
        check_identity(&config.identity, &derived)?;
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
        let mut first_record = true;
        let mut certificates = Vec::new();
        while let Some(record) = replay.next().await {
            let (_, _, _, record) = record?;
            match (first_record, record) {
                (true, Record::Header(header)) => {
                    if header.version != VERSION {
                        return Err(JournalError::VersionMismatch);
                    }
                    check_identity(&header.identity, &config.identity)?;
                }
                (true, _) => return Err(JournalError::MissingHeader),
                (false, Record::Header(_)) => return Err(JournalError::DuplicateHeader),
                (false, Record::Certificate(certificate)) => {
                    if !certificate.verify_for(
                        verifier,
                        scheme,
                        config.identity.epoch,
                        config.identity.first,
                        config.identity.last,
                        strategy,
                    ) {
                        return Err(JournalError::InvalidCertificate);
                    }
                    certificates.push(certificate);
                }
            }
            first_record = false;
        }
        let mut journal = replay.finish()?;
        if empty {
            debug_assert!(first_record);
            let header = Record::Header(Header {
                version: VERSION,
                identity: config.identity.clone(),
            });
            let (next, _, _) = journal.append(0, &header).await?;
            journal = next.sync(0).await?;
        } else if first_record {
            return Err(JournalError::MissingHeader);
        }
        Ok((
            Self {
                inner: Some(journal),
                identity: config.identity,
                heights_per_section: config.heights_per_section,
                restarted: !empty,
            },
            certificates,
        ))
    }

    /// Returns the exact identity checked when this handle was opened.
    pub const fn identity(&self) -> &JournalIdentity {
        &self.identity
    }

    pub(crate) const fn restarted(&self) -> bool {
        self.restarted
    }

    pub(crate) async fn append(
        &mut self,
        certificate: Certificate<S, D>,
    ) -> Result<(), JournalError> {
        let section = certificate.item.position.get() / self.heights_per_section.get();
        let record = Record::Certificate(certificate);
        rebind(&mut self.inner, |journal| journal.append(section, &record)).await?;
        rebind(&mut self.inner, |journal| journal.sync(section)).await?;
        Ok(())
    }

    /// Syncs all journal sections.
    pub async fn sync_all(&mut self) -> Result<(), JournalError> {
        rebind(&mut self.inner, StorageJournal::sync_all).await?;
        Ok(())
    }

    /// Destroys the exact, identity-checked journal represented by this handle.
    pub async fn destroy(mut self) -> Result<(), JournalError> {
        self.inner
            .take()
            .expect("journal unavailable")
            .destroy()
            .await?;
        Ok(())
    }
}

fn check_identity(
    actual: &JournalIdentity,
    expected: &JournalIdentity,
) -> Result<(), JournalError> {
    if actual.namespace != expected.namespace {
        return Err(JournalError::NamespaceMismatch);
    }
    if actual.committee != expected.committee {
        return Err(JournalError::CommitteeMismatch);
    }
    if actual.epoch != expected.epoch {
        return Err(JournalError::EpochMismatch);
    }
    if actual.first != expected.first {
        return Err(JournalError::FirstMismatch);
    }
    if actual.last != expected.last {
        return Err(JournalError::LastMismatch);
    }
    if actual.window != expected.window {
        return Err(JournalError::WindowMismatch);
    }
    Ok(())
}
