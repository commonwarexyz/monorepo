//! Interface for a store of votes, used by [voter::Actor](super::actors::voter::Actor).

use super::types::Artifact;
use crate::types::View;
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_runtime::{Metrics, Storage};
use commonware_storage::journal::{self, segmented::variable::Journal};
use commonware_utils::NZUsize;
use futures::{Stream, TryStreamExt};
use std::{error::Error, future::Future, num::NonZeroUsize, pin::Pin};

/// Durable store for consensus [Artifacts](Artifact) keyed by view.
///
/// This trait abstracts the storage of votes and certificates in the voter actor,
/// enabling different storage backends (e.g., in-memory for testing, on-disk for production).
pub trait Votes: Send + Sync + 'static {
    /// The type of signing [Scheme] used by consensus.
    type Scheme: Scheme;

    /// The type of digest used for block commitments.
    type Digest: Digest;

    /// The type of error returned by storage operations.
    type Error: Error + Send + Sync + 'static;

    /// The stream type returned by [Self::replay].
    type ReplayStream<'a>: Stream<Item = Result<Artifact<Self::Scheme, Self::Digest>, Self::Error>>
        + Send
        + 'a
    where
        Self: 'a;

    /// Append an artifact to the store at the given view.
    ///
    /// # Arguments
    ///
    /// * `view`: The view associated with the artifact.
    /// * `artifact`: The consensus artifact (vote or certificate) to store.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `Err` if persistence fails.
    fn append(
        &mut self,
        view: View,
        artifact: Artifact<Self::Scheme, Self::Digest>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Sync all data up to and including the given view.
    ///
    /// Ensures that all appended data for the given view is durably persisted.
    ///
    /// # Arguments
    ///
    /// * `view`: The view up to which data should be synced.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the sync completes, or `Err` if syncing fails.
    fn sync(&mut self, view: View) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Sync all data across all views.
    ///
    /// Ensures that all appended data is durably persisted. This should be called
    /// before shutdown to ensure no data loss.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the sync completes, or `Err` if syncing fails.
    fn sync_all(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Prune all data for views below the given minimum.
    ///
    /// # Arguments
    ///
    /// * `min`: The minimum view to retain (exclusive). Views strictly less than `min` are pruned.
    ///
    /// # Returns
    ///
    /// `Ok(())` when pruning is complete, or `Err` if pruning fails.
    fn prune(&mut self, min: View) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Replay all stored artifacts starting from the given view and offset.
    ///
    /// Returns a stream of (section, offset, size, artifact) tuples.
    ///
    /// # Arguments
    ///
    /// * `start_view`: The view to start replaying from.
    /// * `start_offset`: The byte offset within the start view to begin at.
    /// * `buffer`: The buffer size for streaming replay.
    ///
    /// # Returns
    ///
    /// A stream of artifacts on success, or `Err` if replay initialization fails.
    fn replay(
        &mut self,
    ) -> impl Future<Output = Result<Self::ReplayStream<'_>, Self::Error>> + Send;
}

/// An Adapter for a [`Journal`] to configure how to replay its buffer.
///
/// To change it,
pub struct VotesJournal<E, S, D>
where
    E: Storage + Metrics,
    S: Scheme,
    D: Digest,
{
    inner: Journal<E, Artifact<S, D>>,
    buffer: NonZeroUsize,
}

impl<E, S, D> VotesJournal<E, S, D>
where
    E: Storage + Metrics,
    S: Scheme,
    D: Digest,
{
    pub fn from_journal(journal: Journal<E, Artifact<S, D>>) -> Self {
        Self {
            inner: journal,
            buffer: NZUsize!(1),
        }
    }

    pub fn replay_buffer(self, buffer: NonZeroUsize) -> Self {
        Self { buffer, ..self }
    }
}

impl<E, S, D> Votes for VotesJournal<E, S, D>
where
    E: Storage + Metrics,
    S: Scheme,
    D: Digest,
{
    type Scheme = S;
    type Digest = D;
    type Error = journal::Error;
    type ReplayStream<'a>
        = Pin<Box<dyn Stream<Item = Result<Artifact<S, D>, Self::Error>> + Send + 'a>>
    where
        Self: 'a;

    async fn append(
        &mut self,
        view: View,
        artifact: Artifact<Self::Scheme, Self::Digest>,
    ) -> Result<(), Self::Error> {
        self.inner.append(view.get(), artifact).await?;
        Ok(())
    }

    async fn sync(&mut self, view: View) -> Result<(), Self::Error> {
        self.inner.sync(view.get()).await
    }

    async fn sync_all(&mut self) -> Result<(), Self::Error> {
        self.inner.sync_all().await
    }

    async fn prune(&mut self, min: View) -> Result<(), Self::Error> {
        self.inner.prune(min.get()).await?;
        Ok(())
    }

    async fn replay(&mut self) -> Result<Self::ReplayStream<'_>, Self::Error> {
        let stream = self
            .inner
            .replay(0, 0, self.buffer)
            .await?
            .map_ok(|(_, _, _, artifact)| artifact);
        Ok(Box::pin(stream))
    }
}
