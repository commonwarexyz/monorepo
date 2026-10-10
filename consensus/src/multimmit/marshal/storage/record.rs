//! A single durable record stored in one metadata partition.

use super::Error;
use commonware_codec::{Codec, EncodeSize, FixedSize as _};
use commonware_cryptography::crc32;
use commonware_runtime::Handle;
use commonware_storage::{
    Context,
    metadata::{self, Metadata},
};
use commonware_utils::sequence::Unit;
use std::num::NonZeroUsize;

/// What opening a store does when its durable record is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OnMissing {
    /// Store the supplied seed as the initial record.
    Initialize,
    /// Fail, because the rest of the namespace proves the record once existed.
    Reject,
}

/// Returns the size of the metadata blob that stores `value` as its only row.
pub(crate) fn blob_size<V: EncodeSize>(value: &V) -> Option<usize> {
    u64::SIZE
        .checked_add(Unit::SIZE)?
        .checked_add(value.encode_size())?
        .checked_add(crc32::Digest::SIZE)
}

/// One durable value in its own metadata partition.
///
/// Mutations take the metadata handle for their duration. A failed or canceled mutation leaves
/// the record without a handle, and every later operation returns [`Error::Poisoned`].
pub(crate) struct DurableRecord<E: Context, V: Codec> {
    metadata: Option<Metadata<E, Unit, V>>,
    /// Largest blob a staged value may produce, if bounded.
    max_bytes: Option<NonZeroUsize>,
}

impl<E: Context, V: Codec> DurableRecord<E, V> {
    /// Opens the record stored in `partition`.
    pub(crate) async fn init(
        context: E,
        partition: String,
        codec_config: V::Cfg,
        max_bytes: Option<NonZeroUsize>,
    ) -> Result<Self, Error> {
        let metadata = Metadata::init(
            context,
            metadata::Config {
                partition,
                codec_config,
            },
        )
        .await?;
        Ok(Self {
            metadata: Some(metadata),
            max_bytes,
        })
    }

    /// Returns the current value, if one was stored or staged.
    pub(crate) fn get(&self) -> Result<Option<&V>, Error> {
        Ok(self.metadata.as_ref().ok_or(Error::Poisoned)?.get(&Unit))
    }

    /// Returns whether `value` fits the configured blob bound.
    ///
    /// Callers that must reject an oversized value without side effects check it before
    /// mutating anything. Staging an oversized value is an [`Error::Inconsistent`] failure.
    pub(crate) fn fits(&self, value: &V) -> bool {
        self.max_bytes
            .is_none_or(|max| blob_size(value).is_some_and(|size| size <= max.get()))
    }

    fn require_fit(&self, value: &V) -> Result<(), Error> {
        if self.fits(value) {
            Ok(())
        } else {
            Err(Error::Inconsistent(
                "record exceeds its configured size bound",
            ))
        }
    }

    /// Replaces the value in memory without starting durability.
    pub(crate) fn stage(&mut self, value: V) -> Result<(), Error> {
        self.require_fit(&value)?;
        self.metadata
            .as_mut()
            .ok_or(Error::Poisoned)?
            .put(Unit, value);
        Ok(())
    }

    /// Replaces the value and waits until it is durable.
    pub(crate) async fn put_sync(&mut self, value: V) -> Result<(), Error> {
        self.require_fit(&value)?;
        let metadata = self.metadata.take().ok_or(Error::Poisoned)?;
        self.metadata = Some(metadata.put_sync(Unit, value).await?);
        Ok(())
    }

    /// Starts durability for the staged value and returns its completion handle.
    pub(crate) async fn start_sync(&mut self) -> Result<Handle<()>, Error> {
        let metadata = self.metadata.take().ok_or(Error::Poisoned)?;
        let (metadata, sync) = metadata.start_sync().await?;
        self.metadata = Some(metadata);
        Ok(sync)
    }

    /// Replaces the value and starts its durability.
    pub(crate) async fn put_start_sync(&mut self, value: V) -> Result<Handle<()>, Error> {
        self.stage(value)?;
        self.start_sync().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;

    #[test]
    fn values_persist_and_the_size_bound_rejects_before_mutation() {
        deterministic::Runner::default().start(|context| async move {
            let bound = NonZeroUsize::new(blob_size(&7u64).unwrap()).unwrap();
            let mut record = DurableRecord::<_, u64>::init(
                context.child("first"),
                "durable_record".into(),
                (),
                Some(bound),
            )
            .await
            .unwrap();
            assert_eq!(record.get().unwrap(), None);
            record.put_sync(7).await.unwrap();
            let sync = record.put_start_sync(9).await.unwrap();
            sync.await.unwrap();
            assert_eq!(record.get().unwrap(), Some(&9));
            drop(record);

            let mut record = DurableRecord::<_, (u64, u64)>::init(
                context.child("reopen"),
                "durable_record_pair".into(),
                ((), ()),
                Some(bound),
            )
            .await
            .unwrap();
            assert!(!record.fits(&(1, 2)));
            assert!(matches!(
                record.put_sync((1, 2)).await,
                Err(Error::Inconsistent(_))
            ));
            assert_eq!(record.get().unwrap(), None);
            let mut unbounded = DurableRecord::<_, (u64, u64)>::init(
                context.child("unbounded"),
                "durable_record_unbounded".into(),
                ((), ()),
                None,
            )
            .await
            .unwrap();
            unbounded.put_sync((1, 2)).await.unwrap();

            let reopened = DurableRecord::<_, u64>::init(
                context.child("second"),
                "durable_record".into(),
                (),
                Some(NZUsize!(1024)),
            )
            .await
            .unwrap();
            assert_eq!(reopened.get().unwrap(), Some(&9));
        });
    }
}
