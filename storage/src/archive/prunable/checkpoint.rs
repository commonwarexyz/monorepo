//! Durable value-validation checkpoints for prunable archive sections.
//!
//! A checkpoint is only advanced after the corresponding index and value bytes are durable. Its
//! validated boundary is therefore a safe prefix: recovery may need to inspect a suffix, but it
//! never trusts bytes whose durability was not established first. Invalid positions are retained
//! because a valid entry after an interior torn value must not make that hole visible again.

use crate::{
    Context, SyncCompletion,
    archive::Error,
    metadata::{Config as MetadataConfig, Metadata},
};
use commonware_codec::{EncodeSize, Read, ReadExt as _, Write};
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_runtime::{Buf, BufMut, Handle};
use commonware_utils::sequence::prefixed_u64::U64;
use futures::FutureExt as _;
use std::collections::BTreeSet;

/// Domain for the archive binding stored in the checkpoint header.
const BINDING_DOMAIN: &[u8] = b"_COMMONWARE_STORAGE_PRUNABLE_ARCHIVE_CHECKPOINT";

/// Encoding version for [Record].
const VERSION: u8 = 0;

/// Metadata key prefixes.
const HEADER_PREFIX: u8 = 0;
const SECTION_PREFIX: u8 = 1;

/// Validation state for the exclusive prefix `[0, validated)` of one section.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Section {
    /// Number of index entries covered by this checkpoint.
    pub(super) validated: u64,

    /// Positions in the validated prefix whose value frames failed CRC validation.
    pub(super) invalid: Vec<u64>,
}

impl Section {
    /// Construct a checkpoint while retaining only failures covered by `validated`.
    fn new(validated: u64, invalid: &BTreeSet<u64>) -> Self {
        Self {
            validated,
            invalid: invalid.range(..validated).copied().collect(),
        }
    }

    /// Whether `position` is a known-invalid value occurrence.
    pub(super) fn invalid(&self, position: u64) -> bool {
        self.invalid.binary_search(&position).is_ok()
    }
}

impl Write for Section {
    fn write(&self, buf: &mut impl BufMut) {
        self.validated.write(buf);
        self.invalid.write(buf);
    }
}

impl EncodeSize for Section {
    fn encode_size(&self) -> usize {
        self.validated.encode_size() + self.invalid.encode_size()
    }
}

impl Read for Section {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let validated = u64::read(buf)?;
        let invalid = Vec::<u64>::read_cfg(buf, &((0..).into(), ()))?;
        if invalid.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(commonware_codec::Error::Invalid(
                "archive checkpoint",
                "invalid positions are not strictly increasing",
            ));
        }
        if invalid
            .last()
            .is_some_and(|position| *position >= validated)
        {
            return Err(commonware_codec::Error::Invalid(
                "archive checkpoint",
                "invalid position is outside the validated prefix",
            ));
        }
        Ok(Self { validated, invalid })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Section {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let validated = u64::arbitrary(u)?;
        let mut invalid = Vec::<u64>::arbitrary(u)?;
        invalid.retain(|position| *position < validated);
        invalid.sort_unstable();
        invalid.dedup();
        Ok(Self { validated, invalid })
    }
}

/// Persisted checkpoint metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Record {
    /// Identifies the archive and checkpoint schema that own all section records.
    Header(Digest),

    /// Validation state for one physical section.
    Section(Section),
}

impl Write for Record {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Header(binding) => {
                0u8.write(buf);
                binding.write(buf);
            }
            Self::Section(section) => {
                1u8.write(buf);
                section.write(buf);
            }
        }
    }
}

impl EncodeSize for Record {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Header(binding) => binding.encode_size(),
            Self::Section(section) => section.encode_size(),
        }
    }
}

impl Read for Record {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Header(Digest::read(buf)?)),
            1 => Ok(Self::Section(Section::read(buf)?)),
            tag => Err(commonware_codec::Error::InvalidEnum(tag)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Record {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        if bool::arbitrary(u)? {
            Ok(Self::Header(Digest::arbitrary(u)?))
        } else {
            Ok(Self::Section(Section::arbitrary(u)?))
        }
    }
}

/// Bind validation results to the storage whose value frames were inspected.
fn binding(key_partition: &str, value_partition: &str, items_per_section: u64) -> Digest {
    let key_len = u64::try_from(key_partition.len())
        .expect("partition name length must fit in u64")
        .to_be_bytes();
    let value_len = u64::try_from(value_partition.len())
        .expect("partition name length must fit in u64")
        .to_be_bytes();
    Sha256::hash(&[
        BINDING_DOMAIN,
        &[VERSION],
        &items_per_section.to_be_bytes(),
        &key_len,
        key_partition.as_bytes(),
        &value_len,
        value_partition.as_bytes(),
    ])
}

const fn header_key() -> U64 {
    U64::new(HEADER_PREFIX, 0)
}

const fn section_key(section: u64) -> U64 {
    U64::new(SECTION_PREFIX, section)
}

/// Per-section archive validation metadata.
pub(super) struct Checkpoint<E: Context> {
    metadata: Metadata<E, U64, Record>,
    pending: Option<SyncCompletion>,
}

impl<E: Context> Checkpoint<E> {
    /// Open the checkpoint partition and return whether its derived records were reset.
    pub(super) async fn open(
        context: E,
        partition: String,
        key_partition: &str,
        value_partition: &str,
        items_per_section: u64,
    ) -> Result<(Self, bool), Error> {
        let mut metadata: Metadata<E, U64, Record> = Metadata::init(
            context,
            MetadataConfig {
                partition,
                codec_config: (),
            },
        )
        .await?;
        let expected = binding(key_partition, value_partition, items_per_section);
        let header = header_key();
        let layout_valid = metadata.keys().all(|key| match key.prefix() {
            HEADER_PREFIX => {
                key.value() == 0 && matches!(metadata.get(key), Some(Record::Header(_)))
            }
            SECTION_PREFIX => matches!(metadata.get(key), Some(Record::Section(_))),
            _ => false,
        });
        let bound = layout_valid
            && matches!(metadata.get(&header), Some(Record::Header(actual)) if *actual == expected);
        if !bound {
            metadata.clear();
            metadata.put(header, Record::Header(expected));
        }
        Ok((
            Self {
                metadata,
                pending: None,
            },
            !bound,
        ))
    }

    /// Return the persisted state for `section`, if any.
    pub(super) fn get(&self, section: u64) -> Option<&Section> {
        match self.metadata.get(&section_key(section)) {
            Some(Record::Section(state)) => Some(state),
            _ => None,
        }
    }

    /// Stage the exact validation state below `validated`.
    pub(super) fn stage(&mut self, section: u64, validated: u64, invalid: &BTreeSet<u64>) -> bool {
        let next = Section::new(validated, invalid);
        if next.validated == 0 && next.invalid.is_empty() && self.get(section).is_none() {
            return false;
        }
        if self.get(section) == Some(&next) {
            return false;
        }
        self.metadata
            .put(section_key(section), Record::Section(next));
        true
    }

    /// Remove every checkpoint older than `min`.
    pub(super) fn remove_before(&mut self, min: u64) -> bool {
        let previous = self.metadata.keys().count();
        self.metadata.retain(|key, _| match key.prefix() {
            HEADER_PREFIX => true,
            SECTION_PREFIX => key.value() >= min,
            _ => false,
        });
        self.metadata.keys().count() != previous
    }

    /// Remove checkpoints for sections that are no longer present.
    pub(super) fn retain(&mut self, sections: &BTreeSet<u64>) -> bool {
        let previous = self.metadata.keys().count();
        self.metadata.retain(|key, _| match key.prefix() {
            HEADER_PREFIX => true,
            SECTION_PREFIX => sections.contains(&key.value()),
            _ => false,
        });
        self.metadata.keys().count() != previous
    }

    /// Persist all staged checkpoint changes.
    pub(super) async fn sync(mut self) -> Result<Self, Error> {
        self.metadata = self.metadata.sync().await?;
        self.pending = None;
        Ok(self)
    }

    /// Whether a previously started metadata sync still needs to be observed.
    pub(super) fn pending(&mut self) -> bool {
        let Some(completion) = &self.pending else {
            return false;
        };
        match completion.clone().now_or_never() {
            None | Some(Err(_)) => true,
            Some(Ok(())) => {
                self.pending = None;
                false
            }
        }
    }

    /// Begin persisting all staged checkpoint changes.
    pub(super) async fn start_sync(mut self) -> Result<(Self, Handle<()>), Error> {
        let (metadata, handle) = self.metadata.start_sync().await?;
        self.metadata = metadata;
        let completion: SyncCompletion = handle.boxed().shared();
        self.pending = Some(completion.clone());
        Ok((self, Handle::from_future(completion)))
    }

    /// Destroy the checkpoint partition.
    pub(super) async fn destroy(self) -> Result<(), Error> {
        self.metadata.destroy().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt as _, Encode as _};

    #[test]
    fn section_round_trip() {
        let section = Section {
            validated: 8,
            invalid: vec![0, 3, 7],
        };
        assert_eq!(Section::decode(section.encode()).unwrap(), section);
    }

    #[test]
    fn section_rejects_invalid_positions() {
        for invalid in [vec![2, 2], vec![3, 2], vec![8]] {
            let section = Section {
                validated: 8,
                invalid,
            };
            assert!(Section::decode(section.encode()).is_err());
        }
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<Record>
    }
}
