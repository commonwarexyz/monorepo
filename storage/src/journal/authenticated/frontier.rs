//! The frontier, the one record an authenticated journal persists besides its operations. It holds
//! the pruning boundary and the digests pinned there. A journal without one was never pruned.

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
const VERSION: u8 = 0;
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
        MAGIC.write(buf);
        VERSION.write(buf);
        self.location.write(buf);
        for pin in &self.pins {
            pin.write(buf);
        }
    }
}

impl<F: Family, D: Digest> EncodeSize for Boundary<F, D> {
    fn encode_size(&self) -> usize {
        MAGIC.len() + 1 + self.location.encode_size() + self.pins.len() * D::SIZE
    }
}

impl<F: Family, D: Digest> Read for Boundary<F, D> {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        if <[u8; 8]>::read(buf)? != MAGIC {
            return Err(commonware_codec::Error::Invalid(
                "Frontier",
                "unsupported format",
            ));
        }
        if u8::read(buf)? != VERSION {
            return Err(commonware_codec::Error::Invalid(
                "Frontier",
                "unknown version",
            ));
        }
        let location = Location::<F>::read(buf)?;
        let pins = F::nodes_to_pin(location)
            .map(|_| D::read(buf))
            .collect::<Result<_, _>>()?;
        Ok(Self { location, pins })
    }
}

/// An authenticated journal's frontier, kept in a metadata partition.
pub(crate) struct Frontier<F: Family, E: Context, D: Digest> {
    metadata: Metadata<E, U64, Boundary<F, D>>,
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

    /// The pruning boundary and the digests pinned there, or genesis if none was recorded.
    pub(crate) fn boundary(&self) -> (Location<F>, Vec<D>) {
        self.metadata.get(&KEY).map_or_else(
            || (Location::new(0), Vec::new()),
            |boundary| (boundary.location, boundary.pins.clone()),
        )
    }

    /// Durably record `location` as the boundary, with `pins`.
    pub(crate) async fn set(
        mut self,
        location: Location<F>,
        pins: Vec<D>,
    ) -> Result<Self, Error<F>> {
        self.metadata.put(KEY, Boundary::new(location, pins)?);
        self.metadata = self.metadata.sync().await?;
        Ok(self)
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

    fn codec<F: Family>() {
        for location in [0, 1, 31, 32, 33, 46, 47, 48, *F::MAX_LEAVES] {
            let location = Location::<F>::new(location);
            let boundary = Boundary {
                location,
                pins: pins(location),
            };
            let encoded = boundary.encode();
            let decoded = Boundary::<F, D>::decode(encoded.clone()).unwrap();
            assert_eq!((decoded.location, decoded.pins), (location, pins(location)));
            for end in 0..encoded.len() {
                assert!(Boundary::<F, D>::decode(encoded.slice(..end)).is_err());
            }
            let mut trailing = encoded.to_vec();
            trailing.push(0);
            assert!(Boundary::<F, D>::decode(trailing).is_err());

            // An unknown version is rejected.
            let mut versioned = encoded.to_vec();
            versioned[8] = 1;
            assert!(Boundary::<F, D>::decode(versioned).is_err());
        }
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
    fn set_survives_reopen_and_failed_writes() {
        deterministic::Runner::default().start(|context| async move {
            type F = mmb::Family;
            let faults = WriteFaults::default();
            let wrapped = WriteFaultContext {
                inner: context,
                faults: faults.clone(),
            };
            let open = |label| Frontier::<F, _, D>::open(wrapped.child(label), "frontier".into());
            let frontier = open("fresh").await.unwrap();
            assert_eq!(frontier.boundary(), (Location::new(0), Vec::new()));
            drop(
                frontier
                    .set(Location::new(31), pins::<F>(Location::new(31)))
                    .await
                    .unwrap(),
            );

            // A failed write leaves the previous record.
            let frontier = open("first").await.unwrap();
            assert_eq!(frontier.boundary().0, Location::new(31));
            faults.arm();
            assert!(
                frontier
                    .set(Location::new(47), pins::<F>(Location::new(47)))
                    .await
                    .is_err()
            );
            faults.disarm();
            let frontier = open("failed").await.unwrap();
            assert_eq!(
                frontier.boundary(),
                (Location::new(31), pins::<F>(Location::new(31)))
            );
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
