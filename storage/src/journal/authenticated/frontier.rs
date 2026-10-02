use super::Error;
use crate::{
    Context,
    merkle::{Family, Location},
    metadata::{self, Metadata},
};
use bytes::BufMut;
use commonware_codec::{Buf, Copying, DecodeExt, Encode, EncodeSize, Read, ReadExt, Write};
use commonware_cryptography::Digest;
use commonware_utils::sequence::prefixed_u64::U64;

const MAGIC: [u8; 8] = *b"CWAUTH01";
const KEY: U64 = U64::new(0, 0);

/// The durable boundary and its digests in [`Family::nodes_to_pin`] order.
#[derive(Clone, Debug)]
pub(crate) struct Boundary<F: Family, D: Digest> {
    pub(crate) location: Location<F>,
    pub(crate) digests: Vec<D>,
}

/// Whether the operation journal holds an authenticated database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    /// The boundary and operations form an authenticated database.
    Active,
    /// A synchronization is replacing operations and has not been authenticated.
    Importing,
    /// A completed import failed root verification. The next import must discard retained
    /// operations and the boundary.
    Rejected,
}

#[derive(Clone)]
struct Record<F: Family, D: Digest> {
    status: Status,
    boundary: Option<Boundary<F, D>>,
}

impl<F: Family, D: Digest> Write for Record<F, D> {
    fn write(&self, buf: &mut impl BufMut) {
        MAGIC.write(buf);
        (self.status as u8).write(buf);
        self.boundary.is_some().write(buf);
        if let Some(boundary) = &self.boundary {
            boundary.location.write(buf);
            for digest in &boundary.digests {
                digest.write(buf);
            }
        }
    }
}

impl<F: Family, D: Digest> EncodeSize for Record<F, D> {
    fn encode_size(&self) -> usize {
        MAGIC.len()
            + 2
            + self
                .boundary
                .as_ref()
                .map_or(0, |b| b.location.encode_size() + b.digests.len() * D::SIZE)
    }
}

impl<F: Family, D: Digest> Read for Record<F, D> {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        if <[u8; 8]>::read(buf)? != MAGIC {
            return Err(commonware_codec::Error::Invalid(
                "Frontier",
                "unsupported format",
            ));
        }
        let status = match u8::read(buf)? {
            0 => Status::Active,
            1 => Status::Importing,
            2 => Status::Rejected,
            _ => {
                return Err(commonware_codec::Error::Invalid(
                    "Frontier",
                    "unknown status",
                ));
            }
        };
        let boundary = if bool::read(buf)? {
            let location = Location::<F>::read(buf)?;
            let digests = F::nodes_to_pin(location)
                .map(|_| D::read(buf))
                .collect::<Result<_, _>>()?;
            Some(Boundary { location, digests })
        } else {
            None
        };
        match (status, &boundary) {
            (Status::Active, None) => {
                return Err(commonware_codec::Error::Invalid(
                    "Frontier",
                    "active boundary missing",
                ));
            }
            (Status::Rejected, Some(_)) => {
                return Err(commonware_codec::Error::Invalid(
                    "Frontier",
                    "rejected boundary retained",
                ));
            }
            _ => {}
        }
        Ok(Self { status, boundary })
    }
}

/// Atomic durable pruning state for an operation-backed authenticated journal.
///
/// An importing frontier prevents ordinary recovery until synchronization authenticates and
/// activates the replacement operation range.
pub struct Frontier<F: Family, E: Context, D: Digest> {
    metadata: Metadata<E, U64, Vec<u8>>,
    record: Option<Record<F, D>>,
    pub(super) metrics: super::metrics::Metrics,
}

impl<F: Family, E: Context, D: Digest> Frontier<F, E, D> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn authenticate<C, H, S>(
        &self,
        config: &super::Config<S>,
        journal: &C,
        hasher: &H,
        start: Location<F>,
        end: Location<F>,
        expected: D,
        inactive: usize,
    ) -> Result<Option<Vec<D>>, Error<F>>
    where
        C: crate::journal::contiguous::Contiguous<Item: commonware_codec::EncodeShared>,
        H: crate::merkle::hasher::Hasher<F, Digest = D> + Clone + Send + Sync + 'static,
        S: commonware_parallel::Strategy,
    {
        let Some(boundary) = self.candidate() else {
            return Ok(None);
        };
        let bounds = journal.bounds();
        if boundary.location > start || bounds.start > *boundary.location || bounds.end < *end {
            return Ok(None);
        }
        let tree = super::Tree::new(
            boundary.location,
            boundary.digests.clone(),
            &config.cache,
            config.replay_buffer,
            config.strategy.clone(),
        )?
        .replay(journal, hasher, end, super::APPLY_BATCH_SIZE)
        .await?;
        if tree.root(hasher, inactive)? != expected {
            return Ok(None);
        }
        let positions: Vec<_> = F::nodes_to_pin(start).collect();
        let mut sorted = positions.clone();
        sorted.sort_unstable();
        let digests = tree.get_nodes(journal, hasher, &sorted).await?;
        Ok(Some(
            positions
                .iter()
                .map(|p| digests[sorted.binary_search(p).expect("pin in request")])
                .collect(),
        ))
    }

    /// Validate `config`, then open the frontier [super::Journal::new] would open under `context`
    /// and mark an import in progress.
    pub(crate) async fn begin_import<S: commonware_parallel::Strategy>(
        context: E,
        config: &super::Config<S>,
    ) -> Result<Self, Error<F>> {
        config.cache.capacity::<D>().map_err(Error::InvalidConfig)?;
        Self::open(context.child("frontier"), config.metadata_partition.clone())
            .await?
            .importing()
            .await
    }

    pub(crate) async fn open(context: E, partition: String) -> Result<Self, Error<F>> {
        // MMB can pin two nodes at each of the at most 64 heights.
        let max_size = D::SIZE
            .checked_mul(128)
            .and_then(|n| n.checked_add(32))
            .ok_or(Error::InvalidConfig("frontier size overflow"))?;
        let metrics_context = context.child("digests");
        let metrics = super::metrics::Metrics::new(&metrics_context);
        let metadata = Metadata::init(
            context,
            metadata::Config {
                partition,
                codec_config: ((0..=max_size).into(), ()),
            },
        )
        .await?;
        if metadata.keys().any(|key| key != &KEY) {
            return Err(Error::UnsupportedFormat);
        }
        let record = metadata
            .get(&KEY)
            .map(|bytes: &Vec<u8>| {
                if !bytes.starts_with(&MAGIC) {
                    return Err(Error::UnsupportedFormat);
                }
                Record::decode(Copying(bytes.as_slice()))
                    .map_err(|err| Error::Journal(super::JournalError::Codec(err)))
            })
            .transpose()?;
        Ok(Self {
            metadata,
            record,
            metrics,
        })
    }

    pub(crate) const fn active(&self) -> Result<Option<&Boundary<F, D>>, Error<F>> {
        match &self.record {
            Some(Record {
                status: Status::Active,
                boundary,
            }) => Ok(boundary.as_ref()),
            Some(_) => Err(Error::IncompleteSync),
            None => Ok(None),
        }
    }

    /// Whether the last completed import failed root verification.
    pub(crate) fn rejected(&self) -> bool {
        self.record
            .as_ref()
            .is_some_and(|record| record.status == Status::Rejected)
    }

    pub(crate) fn candidate(&self) -> Option<&Boundary<F, D>> {
        self.record.as_ref()?.boundary.as_ref()
    }

    async fn store(mut self, record: Record<F, D>) -> Result<Self, Error<F>> {
        self.metadata.put(KEY, record.encode().to_vec());
        self.metadata = self.metadata.sync().await?;
        self.record = Some(record);
        Ok(self)
    }

    /// Mark an import in progress, keeping the boundary for local authentication. A rejected
    /// import stays rejected until [Self::restart].
    pub(crate) async fn importing(self) -> Result<Self, Error<F>> {
        if self.rejected() {
            return Ok(self);
        }
        let boundary = self.candidate().cloned();
        self.store(Record {
            status: Status::Importing,
            boundary,
        })
        .await
    }

    /// Require the next import to discard retained operations and the boundary.
    pub(crate) async fn reject(self) -> Result<Self, Error<F>> {
        self.store(Record {
            status: Status::Rejected,
            boundary: None,
        })
        .await
    }

    /// Resume a rejected import once its retained operations have been durably discarded.
    pub(crate) async fn restart(self) -> Result<Self, Error<F>> {
        self.store(Record {
            status: Status::Importing,
            boundary: None,
        })
        .await
    }

    pub(crate) async fn stage(
        self,
        location: Location<F>,
        digests: Vec<D>,
    ) -> Result<Self, Error<F>> {
        self.set(Status::Importing, location, digests).await
    }

    pub(crate) async fn activate(
        self,
        location: Location<F>,
        digests: Vec<D>,
    ) -> Result<Self, Error<F>> {
        self.set(Status::Active, location, digests).await
    }

    async fn set(
        self,
        status: Status,
        location: Location<F>,
        digests: Vec<D>,
    ) -> Result<Self, Error<F>> {
        if !location.is_valid() {
            return Err(crate::merkle::Error::LocationOverflow(location).into());
        }
        if F::nodes_to_pin(location).count() != digests.len() {
            return Err(crate::merkle::Error::InvalidPinnedNodes.into());
        }
        self.store(Record {
            status,
            boundary: Some(Boundary { location, digests }),
        })
        .await
    }

    /// Remove the durable frontier.
    pub async fn destroy(self) -> Result<(), Error<F>> {
        self.metadata.destroy().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{mmb, mmr};
    use commonware_cryptography::sha256::Digest as D;
    use commonware_runtime::{
        Runner as _, Supervisor as _, deterministic,
        mocks::{WriteFaultContext, WriteFaults},
    };

    fn pins<F: Family>(location: Location<F>) -> Vec<D> {
        F::nodes_to_pin(location)
            .map(|_| D::from([7; 32]))
            .collect()
    }

    fn codec<F: Family>() {
        for location in [0, 1, 31, 32, 33, 46, 47, 48, *F::MAX_LEAVES] {
            let location = Location::new(location);
            for status in [Status::Active, Status::Importing] {
                let record = Record::<F, D> {
                    status,
                    boundary: Some(Boundary {
                        location,
                        digests: pins(location),
                    }),
                };
                let encoded = record.encode();
                let decoded = Record::<F, D>::decode(encoded.clone()).unwrap();
                assert_eq!(decoded.status, status);
                assert_eq!(decoded.boundary.unwrap().digests, pins(location));
                for end in 0..encoded.len() {
                    assert!(Record::<F, D>::decode(encoded.slice(..end)).is_err());
                }
                let mut trailing = encoded.to_vec();
                trailing.push(0);
                assert!(Record::<F, D>::decode(trailing).is_err());
            }
        }
        let invalid = Record::<F, D> {
            status: Status::Active,
            boundary: None,
        };
        assert!(Record::<F, D>::decode(invalid.encode()).is_err());
        let invalid = Record::<F, D> {
            status: Status::Rejected,
            boundary: Some(Boundary {
                location: Location::new(1),
                digests: pins::<F>(Location::new(1)),
            }),
        };
        assert!(Record::<F, D>::decode(invalid.encode()).is_err());
        for status in [Status::Importing, Status::Rejected] {
            let record = Record::<F, D> {
                status,
                boundary: None,
            };
            assert_eq!(
                Record::<F, D>::decode(record.encode()).unwrap().status,
                status
            );
        }
        let mut invalid = Record::<F, D> {
            status: Status::Importing,
            boundary: None,
        }
        .encode()
        .to_vec();
        invalid[8] = 3;
        assert!(Record::<F, D>::decode(invalid).is_err());
    }

    #[test]
    fn bounded_codec_mmr() {
        codec::<mmr::Family>();
    }
    #[test]
    fn bounded_codec_mmb() {
        codec::<mmb::Family>();
    }

    #[test]
    fn import_lifecycle_and_failed_write_recovery() {
        deterministic::Runner::default().start(|context| async move {
            type F = mmb::Family;
            let faults = WriteFaults::default();
            let wrapped = WriteFaultContext {
                inner: context,
                faults: faults.clone(),
            };
            let mut frontier = Frontier::<F, _, D>::open(wrapped.child("fresh"), "frontier".into())
                .await
                .unwrap();
            assert!(frontier.active().unwrap().is_none());
            frontier = frontier
                .activate(Location::new(31), pins::<F>(Location::new(31)))
                .await
                .unwrap();
            frontier = frontier.importing().await.unwrap();
            drop(frontier);
            let frontier = Frontier::<F, _, D>::open(wrapped.child("import"), "frontier".into())
                .await
                .unwrap();
            assert!(matches!(frontier.active(), Err(Error::IncompleteSync)));
            assert_eq!(frontier.candidate().unwrap().location, Location::new(31));
            faults.arm();
            assert!(
                frontier
                    .stage(Location::new(47), pins::<F>(Location::new(47)))
                    .await
                    .is_err()
            );
            faults.disarm();
            let mut frontier =
                Frontier::<F, _, D>::open(wrapped.child("failed"), "frontier".into())
                    .await
                    .unwrap();
            assert!(matches!(frontier.active(), Err(Error::IncompleteSync)));
            assert_eq!(frontier.candidate().unwrap().location, Location::new(31));
            frontier = frontier
                .stage(Location::new(47), pins::<F>(Location::new(47)))
                .await
                .unwrap();
            drop(frontier);
            let frontier = Frontier::<F, _, D>::open(wrapped.child("staged"), "frontier".into())
                .await
                .unwrap();
            assert!(matches!(frontier.active(), Err(Error::IncompleteSync)));
            let frontier = frontier
                .activate(Location::new(47), pins::<F>(Location::new(47)))
                .await
                .unwrap();
            assert_eq!(frontier.metadata.keys().count(), 1);
            drop(frontier);
            let frontier = Frontier::<F, _, D>::open(wrapped.child("active"), "frontier".into())
                .await
                .unwrap();
            assert_eq!(
                frontier.active().unwrap().unwrap().location,
                Location::new(47)
            );
        });
    }

    #[test]
    fn rejected_import_persists_until_restart() {
        deterministic::Runner::default().start(|context| async move {
            type F = mmr::Family;
            let frontier = Frontier::<F, _, D>::open(context.child("fresh"), "frontier".into())
                .await
                .unwrap()
                .activate(Location::new(31), pins::<F>(Location::new(31)))
                .await
                .unwrap();
            drop(frontier.importing().await.unwrap().reject().await.unwrap());
            let frontier = Frontier::<F, _, D>::open(context.child("rejected"), "frontier".into())
                .await
                .unwrap();
            assert!(frontier.rejected());
            assert!(frontier.candidate().is_none());
            assert!(matches!(frontier.active(), Err(Error::IncompleteSync)));

            // A new import keeps the rejection until retained operations are discarded.
            let frontier = frontier.importing().await.unwrap();
            assert!(frontier.rejected());
            drop(frontier.restart().await.unwrap());
            let frontier = Frontier::<F, _, D>::open(context.child("restarted"), "frontier".into())
                .await
                .unwrap();
            assert!(!frontier.rejected());
            assert!(frontier.candidate().is_none());
            assert!(matches!(frontier.active(), Err(Error::IncompleteSync)));
        });
    }

    #[test]
    fn rejects_oversized_metadata() {
        deterministic::Runner::default().start(|context| async move {
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(
                context.child("oversized"),
                metadata::Config {
                    partition: "frontier".into(),
                    codec_config: ((0..=8192).into(), ()),
                },
            )
            .await
            .unwrap();
            metadata.put(KEY, vec![0; 8192]);
            drop(metadata.sync().await.unwrap());
            assert!(matches!(
                Frontier::<mmr::Family, _, D>::open(context.child("open"), "frontier".into()).await,
                Err(Error::Metadata(_))
            ));
        });
    }

    #[test]
    fn rejects_legacy_metadata() {
        deterministic::Runner::default().start(|context| async move {
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(
                context.child("legacy"),
                metadata::Config {
                    partition: "frontier".into(),
                    codec_config: ((0..=4096).into(), ()),
                },
            )
            .await
            .unwrap();
            metadata.put(KEY, vec![0; 8]);
            drop(metadata.sync().await.unwrap());
            assert!(matches!(
                Frontier::<mmr::Family, _, D>::open(context.child("open"), "frontier".into()).await,
                Err(Error::UnsupportedFormat)
            ));
        });
    }
}
