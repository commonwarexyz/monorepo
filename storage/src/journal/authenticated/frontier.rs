//! The frontier, the one record an authenticated journal persists besides its operations. It holds
//! the pruning boundary, the digests pinned there, and an import status.
//!
//! A journal opens only while its frontier is active. A sync marks the frontier importing before
//! it writes any operation, stages the target's boundary, and activates it once the synced root is
//! verified. A failed root check marks the frontier rejected instead, and it stays rejected until
//! the next sync has discarded the operations left behind.

use super::Error;
use crate::{
    Context,
    merkle::{Family, Location},
    metadata::{self, Metadata},
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Read, ReadExt, Write};
use commonware_cryptography::Digest;
use commonware_utils::sequence::prefixed_u64::U64;

const MAGIC: [u8; 8] = *b"CWAUTH01";
const KEY: U64 = U64::new(0, 0);

/// A pruning boundary and the digests pinned there, in [`Family::nodes_to_pin`] order.
#[derive(Clone, Debug)]
pub(crate) struct Boundary<F: Family, D: Digest> {
    pub(crate) location: Location<F>,
    pub(crate) pins: Vec<D>,
}

impl<F: Family, D: Digest> Boundary<F, D> {
    /// A boundary at `location`, rejecting an invalid location or the wrong number of pins.
    fn new(location: Location<F>, pins: Vec<D>) -> Result<Self, Error<F>> {
        if !location.is_valid() {
            return Err(crate::merkle::Error::LocationOverflow(location).into());
        }
        if F::nodes_to_pin(location).count() != pins.len() {
            return Err(crate::merkle::Error::InvalidPinnedNodes.into());
        }
        Ok(Self { location, pins })
    }
}

impl<F: Family, D: Digest> Write for Boundary<F, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.location.write(buf);
        for pin in &self.pins {
            pin.write(buf);
        }
    }
}

impl<F: Family, D: Digest> EncodeSize for Boundary<F, D> {
    fn encode_size(&self) -> usize {
        self.location.encode_size() + self.pins.len() * D::SIZE
    }
}

impl<F: Family, D: Digest> Read for Boundary<F, D> {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let location = Location::<F>::read(buf)?;
        let pins = F::nodes_to_pin(location)
            .map(|_| D::read(buf))
            .collect::<Result<_, _>>()?;
        Ok(Self { location, pins })
    }
}

/// The stored frontier.
enum Record<F: Family, D: Digest> {
    /// The journal can be opened, pruned to this boundary.
    Active(Boundary<F, D>),
    /// A sync is writing operations whose root hasn't been verified. The boundary is the journal's
    /// own, which can check the operations kept from before, until the sync stages the target's.
    Importing(Option<Boundary<F, D>>),
    /// A sync failed its root check. The next sync must discard the operations it left.
    Rejected,
}

impl<F: Family, D: Digest> Record<F, D> {
    const fn tag(&self) -> u8 {
        match self {
            Self::Active(_) => 0,
            Self::Importing(None) => 1,
            Self::Importing(Some(_)) => 2,
            Self::Rejected => 3,
        }
    }

    const fn boundary(&self) -> Option<&Boundary<F, D>> {
        match self {
            Self::Active(boundary) | Self::Importing(Some(boundary)) => Some(boundary),
            Self::Importing(None) | Self::Rejected => None,
        }
    }
}

impl<F: Family, D: Digest> Write for Record<F, D> {
    fn write(&self, buf: &mut impl BufMut) {
        MAGIC.write(buf);
        self.tag().write(buf);
        if let Some(boundary) = self.boundary() {
            boundary.write(buf);
        }
    }
}

impl<F: Family, D: Digest> EncodeSize for Record<F, D> {
    fn encode_size(&self) -> usize {
        MAGIC.len() + 1 + self.boundary().map_or(0, EncodeSize::encode_size)
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
        match u8::read(buf)? {
            0 => Ok(Self::Active(Boundary::read(buf)?)),
            1 => Ok(Self::Importing(None)),
            2 => Ok(Self::Importing(Some(Boundary::read(buf)?))),
            3 => Ok(Self::Rejected),
            _ => Err(commonware_codec::Error::Invalid(
                "Frontier",
                "unknown status",
            )),
        }
    }
}

/// An authenticated journal's frontier, kept in a metadata partition.
pub(crate) struct Frontier<F: Family, E: Context, D: Digest> {
    metadata: Metadata<E, U64, Record<F, D>>,
}

impl<F: Family, E: Context, D: Digest> Frontier<F, E, D> {
    /// Open the frontier, rejecting foreign and legacy records.
    pub(crate) async fn open(context: E, partition: String) -> Result<Self, Error<F>> {
        let metadata = Metadata::init(
            context,
            metadata::Config {
                partition,
                codec_config: (),
            },
        )
        .await?;
        Ok(Self { metadata })
    }

    /// The boundary of an active frontier, or [Error::IncompleteSync] during an import.
    pub(crate) fn active_boundary(&self) -> Result<Option<&Boundary<F, D>>, Error<F>> {
        match self.metadata.get(&KEY) {
            Some(Record::Active(boundary)) => Ok(Some(boundary)),
            Some(_) => Err(Error::IncompleteSync),
            None => Ok(None),
        }
    }

    /// Whether the last sync failed its root check.
    pub(crate) fn rejected(&self) -> bool {
        matches!(self.metadata.get(&KEY), Some(Record::Rejected))
    }

    /// The recorded boundary, whatever the status.
    pub(crate) fn boundary(&self) -> Option<&Boundary<F, D>> {
        self.metadata.get(&KEY)?.boundary()
    }

    async fn store(mut self, record: Record<F, D>) -> Result<Self, Error<F>> {
        self.metadata.put(KEY, record);
        self.metadata = self.metadata.sync().await?;
        Ok(self)
    }

    /// Mark a sync in progress, keeping the boundary to check operations kept from before. A
    /// rejected frontier stays rejected until [Self::restart].
    pub(crate) async fn begin_import(self) -> Result<Self, Error<F>> {
        if self.rejected() {
            return Ok(self);
        }
        let boundary = self.boundary().cloned();
        self.store(Record::Importing(boundary)).await
    }

    /// Mark the sync rejected, so the next one discards its operations.
    pub(crate) async fn reject(self) -> Result<Self, Error<F>> {
        self.store(Record::Rejected).await
    }

    /// Start a new sync once the rejected sync's operations have been durably discarded.
    pub(crate) async fn restart(self) -> Result<Self, Error<F>> {
        self.store(Record::Importing(None)).await
    }

    /// Stage `pins` at `location` as the boundary of the sync in progress.
    pub(crate) async fn stage(self, location: Location<F>, pins: Vec<D>) -> Result<Self, Error<F>> {
        let boundary = Boundary::new(location, pins)?;
        self.store(Record::Importing(Some(boundary))).await
    }

    /// Make `location` the active boundary, with `pins`.
    pub(crate) async fn activate(
        self,
        location: Location<F>,
        pins: Vec<D>,
    ) -> Result<Self, Error<F>> {
        let boundary = Boundary::new(location, pins)?;
        self.store(Record::Active(boundary)).await
    }

    /// Make the staged boundary active.
    pub(crate) async fn activate_staged(self) -> Result<Self, Error<F>> {
        let boundary = self.boundary().cloned().ok_or(Error::IncompleteSync)?;
        self.store(Record::Active(boundary)).await
    }

    /// Remove the durable frontier.
    pub(crate) async fn destroy(self) -> Result<(), Error<F>> {
        self.metadata.destroy().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{mmb, mmr};
    use commonware_codec::{DecodeExt as _, Encode as _};
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

    fn boundary<F: Family>(location: u64) -> Boundary<F, D> {
        let location = Location::new(location);
        Boundary {
            location,
            pins: pins(location),
        }
    }

    fn codec<F: Family>() {
        for location in [0, 1, 31, 32, 33, 46, 47, 48, *F::MAX_LEAVES] {
            for record in [
                Record::Active(boundary::<F>(location)),
                Record::Importing(Some(boundary(location))),
            ] {
                let encoded = record.encode();
                let decoded = Record::<F, D>::decode(encoded.clone()).unwrap();
                assert_eq!(decoded.tag(), record.tag());
                assert_eq!(
                    decoded.boundary().unwrap().pins,
                    pins(Location::<F>::new(location))
                );
                for end in 0..encoded.len() {
                    assert!(Record::<F, D>::decode(encoded.slice(..end)).is_err());
                }
                let mut trailing = encoded.to_vec();
                trailing.push(0);
                assert!(Record::<F, D>::decode(trailing).is_err());
            }
        }
        for record in [Record::<F, D>::Importing(None), Record::Rejected] {
            assert_eq!(
                Record::<F, D>::decode(record.encode()).unwrap().tag(),
                record.tag()
            );
        }

        // An unknown status is rejected.
        let mut encoded = Record::<F, D>::Rejected.encode().to_vec();
        encoded[8] = 4;
        assert!(Record::<F, D>::decode(encoded).is_err());
    }

    #[test]
    fn codec_mmr() {
        codec::<mmr::Family>();
    }
    #[test]
    fn codec_mmb() {
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
            let open = |label| Frontier::<F, _, D>::open(wrapped.child(label), "frontier".into());
            let mut frontier = open("fresh").await.unwrap();
            assert!(frontier.active_boundary().unwrap().is_none());
            frontier = frontier
                .activate(Location::new(31), pins::<F>(Location::new(31)))
                .await
                .unwrap();
            frontier = frontier.begin_import().await.unwrap();
            drop(frontier);
            let frontier = open("import").await.unwrap();
            assert!(matches!(
                frontier.active_boundary(),
                Err(Error::IncompleteSync)
            ));
            assert_eq!(frontier.boundary().unwrap().location, Location::new(31));
            faults.arm();
            assert!(
                frontier
                    .stage(Location::new(47), pins::<F>(Location::new(47)))
                    .await
                    .is_err()
            );
            faults.disarm();
            let mut frontier = open("failed").await.unwrap();
            assert!(matches!(
                frontier.active_boundary(),
                Err(Error::IncompleteSync)
            ));
            assert_eq!(frontier.boundary().unwrap().location, Location::new(31));
            frontier = frontier
                .stage(Location::new(47), pins::<F>(Location::new(47)))
                .await
                .unwrap();
            drop(frontier);
            let frontier = open("staged").await.unwrap();
            assert!(matches!(
                frontier.active_boundary(),
                Err(Error::IncompleteSync)
            ));
            let frontier = frontier
                .activate(Location::new(47), pins::<F>(Location::new(47)))
                .await
                .unwrap();
            drop(frontier);
            let frontier = open("active").await.unwrap();
            assert_eq!(
                frontier.active_boundary().unwrap().unwrap().location,
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
            drop(
                frontier
                    .begin_import()
                    .await
                    .unwrap()
                    .reject()
                    .await
                    .unwrap(),
            );
            let frontier = Frontier::<F, _, D>::open(context.child("rejected"), "frontier".into())
                .await
                .unwrap();
            assert!(frontier.rejected());
            assert!(frontier.boundary().is_none());
            assert!(matches!(
                frontier.active_boundary(),
                Err(Error::IncompleteSync)
            ));

            // A new import keeps the rejection until retained operations are discarded.
            let frontier = frontier.begin_import().await.unwrap();
            assert!(frontier.rejected());
            drop(frontier.restart().await.unwrap());
            let frontier = Frontier::<F, _, D>::open(context.child("restarted"), "frontier".into())
                .await
                .unwrap();
            assert!(!frontier.rejected());
            assert!(frontier.boundary().is_none());
            assert!(matches!(
                frontier.active_boundary(),
                Err(Error::IncompleteSync)
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
                Err(Error::Metadata(metadata::Error::Corruption(_)))
            ));
        });
    }
}
