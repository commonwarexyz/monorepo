//! Core sync engine components that are shared across sync clients.

use crate::{
    adb::sync::{
        requests::Requests,
        resolver::{FetchResult, Resolver},
        target::validate_update,
        Database, Error, Journal, Target,
    },
    mmr::hasher,
};
use commonware_codec::Encode;
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_utils::NZU64;
use futures::{channel::mpsc, future::Either, StreamExt};
use std::{collections::BTreeMap, fmt::Debug, num::NonZeroU64};

/// Type alias for sync engine errors
type EngineError<DB, R> =
    Error<<DB as Database>::Error, <R as Resolver>::Error, <DB as Database>::Digest>;

/// Whether sync should continue or complete
#[derive(Debug)]
pub(crate) enum NextStep<C, D> {
    /// Sync should continue with the updated client
    Continue(C),
    /// Sync is complete with the final database
    Complete(D),
}

/// Events that can occur during synchronization
#[derive(Debug)]
enum Event<Data, D: Digest, P, E> {
    /// A target update was received
    TargetUpdate(Target<D>),
    /// A batch of data was received
    BatchReceived(IndexedFetchResult<Data, P, E>),
    /// The target update channel was closed
    UpdateChannelClosed,
}

/// Result of a fetch and its starting location
#[derive(Debug)]
pub(super) struct IndexedFetchResult<D, P, E> {
    /// The location of the first data item in the batch
    pub start_loc: u64,
    /// The result of the fetch
    pub result: Result<FetchResult<D, P>, E>,
}

/// Wait for the next synchronization event from either target updates or fetch results.
/// Returns `None` if the sync is stalled (there are no outstanding requests).
async fn wait_for_event<Data, D: Digest, P, E>(
    update_receiver: &mut Option<mpsc::Receiver<Target<D>>>,
    outstanding_requests: &mut Requests<Data, P, E>,
) -> Option<Event<Data, D, P, E>> {
    let target_update_fut = match update_receiver {
        Some(update_rx) => Either::Left(update_rx.next()),
        None => Either::Right(futures::future::pending()),
    };

    select! {
        target = target_update_fut => {
            match target {
                Some(target) => Some(Event::TargetUpdate(target)),
                None => Some(Event::UpdateChannelClosed),
            }
        },
        result = outstanding_requests.futures_mut().next() => {
            result.map(|fetch_result| Event::BatchReceived(fetch_result))
        },
    }
}

/// Configuration for creating a new Engine
pub struct Config<DB, R>
where
    DB: Database,
    R: Resolver<Data = DB::Data, Digest = DB::Digest>,
    DB::Data: Encode,
{
    /// Runtime context for creating database components
    pub context: DB::Context,
    /// Network resolver for fetching data and proofs
    pub resolver: R,
    /// Sync target (root digest and bounds)
    pub target: Target<DB::Digest>,
    /// Maximum number of outstanding requests for data batches
    pub max_outstanding_requests: usize,
    /// Maximum data items to fetch per batch
    pub fetch_batch_size: NonZeroU64,
    /// Number of data items to apply in a single batch
    pub apply_batch_size: usize,
    /// Database-specific configuration
    pub db_config: DB::Config,
    /// Channel for receiving sync target updates
    pub update_rx: Option<mpsc::Receiver<Target<DB::Digest>>>,
}
/// A shared sync engine that manages the core synchronization state.
pub(crate) struct Engine<DB, R>
where
    DB: Database,
    R: Resolver<Data = DB::Data, Proof = DB::Proof, Digest = DB::Digest>,
    DB::Data: Encode,
{
    /// Tracks outstanding fetch requests and their futures
    outstanding_requests: Requests<DB::Data, DB::Proof, R::Error>,

    /// Data that has been fetched but not yet applied to the log
    fetched_data: BTreeMap<u64, Vec<DB::Data>>,

    /// Pinned MMR nodes extracted from proofs, used for database construction
    pinned_nodes: Option<DB::PinnedNodes>,

    /// The current sync target (root digest and data bounds)
    target: Target<DB::Digest>,

    /// Maximum number of parallel outstanding requests
    max_outstanding_requests: usize,

    /// Maximum data items to fetch in a single batch
    fetch_batch_size: NonZeroU64,

    /// Number of data items to apply in a single batch
    apply_batch_size: usize,

    /// Journal that data is applied to during sync
    journal: DB::Journal,

    /// Resolver for fetching data and proofs from the sync source
    resolver: R,

    /// Hasher used for proof verification
    hasher: crate::mmr::hasher::Standard<DB::Hasher>,

    /// Runtime context for database operations
    context: DB::Context,

    /// Configuration for building the final database
    config: DB::Config,

    /// Optional receiver for target updates during sync
    update_receiver: Option<mpsc::Receiver<Target<DB::Digest>>>,
}

#[cfg(test)]
impl<DB, R> Engine<DB, R>
where
    DB: Database,
    R: Resolver<Data = DB::Data, Proof = DB::Proof, Digest = DB::Digest>,
    DB::Data: Encode,
{
    pub(crate) fn journal(&self) -> &DB::Journal {
        &self.journal
    }
}

impl<DB, R> Engine<DB, R>
where
    DB: Database,
    R: Resolver<Data = DB::Data, Proof = DB::Proof, Digest = DB::Digest>,
    DB::Data: Encode,
{
    /// Create a new sync engine with the given configuration
    pub async fn new(config: Config<DB, R>) -> Result<Self, EngineError<DB, R>> {
        if config.target.lower_bound > config.target.upper_bound {
            return Err(Error::InvalidTarget {
                lower_bound_pos: config.target.lower_bound,
                upper_bound_pos: config.target.upper_bound,
            });
        }

        // Create journal and verifier using the database's factory methods
        let journal = DB::create_journal(
            config.context.clone(),
            &config.db_config,
            config.target.lower_bound,
            config.target.upper_bound,
        )
        .await
        .map_err(Error::database)?;

        let mut engine = Self {
            outstanding_requests: Requests::new(),
            fetched_data: BTreeMap::new(),
            pinned_nodes: None,
            target: config.target.clone(),
            max_outstanding_requests: config.max_outstanding_requests,
            fetch_batch_size: config.fetch_batch_size,
            apply_batch_size: config.apply_batch_size,
            journal,
            resolver: config.resolver.clone(),
            hasher: hasher::Standard::<DB::Hasher>::new(),
            context: config.context,
            config: config.db_config,
            update_receiver: config.update_rx,
        };
        engine.schedule_requests().await?;
        Ok(engine)
    }

    /// Schedule new fetch requests for data in the sync range that we haven't yet fetched.
    async fn schedule_requests(&mut self) -> Result<(), EngineError<DB, R>> {
        let target_size = self.target.upper_bound + 1;

        // Special case: If we don't have pinned nodes, we need to extract them from a proof
        // for the lower sync bound.
        if self.pinned_nodes.is_none() {
            let start_loc = self.target.lower_bound;
            let resolver = self.resolver.clone();
            self.outstanding_requests.add(
                start_loc,
                Box::pin(async move {
                    let result = resolver.get_data(target_size, start_loc, NZU64!(1)).await;
                    IndexedFetchResult { start_loc, result }
                }),
            );
        }

        // Calculate the maximum number of requests to make
        let num_requests = self
            .max_outstanding_requests
            .saturating_sub(self.outstanding_requests.len());

        let log_size = self.journal.size().await.map_err(Error::database)?;

        for _ in 0..num_requests {
            // Convert fetched data to counts for shared gap detection
            let data_counts: BTreeMap<u64, u64> = self
                .fetched_data
                .iter()
                .map(|(&start_loc, data)| (start_loc, data.len() as u64))
                .collect();

            // Find the next gap in the sync range that needs to be fetched.
            let Some((start_loc, end_loc)) = crate::adb::sync::gaps::find_next(
                log_size,
                self.target.upper_bound,
                &data_counts,
                self.outstanding_requests.locations(),
                self.fetch_batch_size.get(),
            ) else {
                break; // No more gaps to fill
            };

            // Calculate batch size for this gap
            let gap_size = NZU64!(end_loc - start_loc + 1);
            let batch_size = self.fetch_batch_size.min(gap_size);

            // Schedule the request
            let resolver = self.resolver.clone();
            self.outstanding_requests.add(
                start_loc,
                Box::pin(async move {
                    let result = resolver.get_data(target_size, start_loc, batch_size).await;
                    IndexedFetchResult { start_loc, result }
                }),
            );
        }

        Ok(())
    }

    /// Clear all sync state for a target update
    pub async fn reset_for_target_update(
        self,
        new_target: Target<DB::Digest>,
    ) -> Result<Self, EngineError<DB, R>> {
        let journal = DB::resize_journal(
            self.journal,
            self.context.clone(),
            &self.config,
            new_target.lower_bound,
            new_target.upper_bound,
        )
        .await
        .map_err(Error::database)?;

        Ok(Self {
            outstanding_requests: Requests::new(),
            fetched_data: BTreeMap::new(),
            pinned_nodes: None,
            target: new_target,
            max_outstanding_requests: self.max_outstanding_requests,
            fetch_batch_size: self.fetch_batch_size,
            apply_batch_size: self.apply_batch_size,
            journal,
            resolver: self.resolver,
            hasher: self.hasher,
            context: self.context,
            config: self.config,
            update_receiver: self.update_receiver,
        })
    }

    /// Store a batch of fetched data
    pub fn store_data(&mut self, start_loc: u64, data: Vec<DB::Data>) {
        self.fetched_data.insert(start_loc, data);
    }

    /// Apply fetched data to the journal if we have it.
    ///
    /// This method finds data that is contiguous with the current journal tip
    /// and applies them in order. It removes stale batches and handles partial
    /// application of batches when needed.
    pub async fn apply_data(&mut self) -> Result<(), EngineError<DB, R>> {
        let mut next_loc = self.journal.size().await.map_err(Error::database)?;

        // Remove any batches of data with stale data.
        // That is, those whose last data item is before `next_loc`.
        self.fetched_data.retain(|&start_loc, data| {
            let end_loc = start_loc + data.len() as u64 - 1;
            end_loc >= next_loc
        });

        loop {
            // See if we have the next data item to apply (i.e. at the journal tip).
            // Find the index of the range that contains the next location.
            let range_start_loc = self
                .fetched_data
                .iter()
                .find_map(|(range_start, range_data)| {
                    let range_end = range_start + range_data.len() as u64 - 1;
                    if *range_start <= next_loc && next_loc <= range_end {
                        Some(*range_start)
                    } else {
                        None
                    }
                });

            let Some(range_start_loc) = range_start_loc else {
                // We don't have the next data item to apply (i.e. at the journal tip)
                break;
            };

            // Remove the batch of data that contains the next data item to apply.
            let data = self.fetched_data.remove(&range_start_loc).unwrap();
            // Skip data items that are before the next location.
            let skip_count = (next_loc - range_start_loc) as usize;
            let data_count = data.len() - skip_count;
            let remaining_data = data.into_iter().skip(skip_count);
            next_loc += data_count as u64;
            self.apply_data_batch(remaining_data).await?;
        }

        Ok(())
    }

    /// Apply a batch of data to the journal
    async fn apply_data_batch<I>(&mut self, data: I) -> Result<(), EngineError<DB, R>>
    where
        I: IntoIterator<Item = DB::Data>,
    {
        for item in data {
            self.journal.append(item).await.map_err(Error::database)?;
            // No need to sync here -- the journal will periodically sync its storage
            // and we will also sync when we're done applying all data.
        }
        Ok(())
    }

    /// Check if sync is complete based on the current journal size and target
    pub async fn is_complete(&self) -> Result<bool, EngineError<DB, R>> {
        let journal_size = self.journal.size().await.map_err(Error::database)?;

        // Calculate the target journal size (upper bound is inclusive)
        let target_journal_size = self.target.upper_bound + 1;

        // Check if we've completed sync
        if journal_size >= target_journal_size {
            if journal_size > target_journal_size {
                // This shouldn't happen in normal operation - indicates a bug
                return Err(Error::InvalidState);
            }
            return Ok(true);
        }

        Ok(false)
    }

    /// Handle the result of a data fetch.
    ///
    /// This method processes incoming fetch results by:
    /// 1. Removing the request from outstanding requests
    /// 2. Validating batch size
    /// 3. Verifying proofs using the configured verifier
    /// 4. Extracting pinned nodes if needed
    /// 5. Storing valid data for later application
    fn handle_fetch_result(
        &mut self,
        fetch_result: IndexedFetchResult<DB::Data, DB::Proof, R::Error>,
    ) -> Result<(), EngineError<DB, R>> {
        // Mark request as complete
        self.outstanding_requests.remove(fetch_result.start_loc);

        let start_loc = fetch_result.start_loc;
        let FetchResult {
            proof,
            data,
            success_tx,
        } = fetch_result.result.map_err(Error::Resolver)?;

        // Validate batch size
        let data_len = data.len() as u64;
        if data_len == 0 || data_len > self.fetch_batch_size.get() {
            // Invalid batch size - notify resolver of failure.
            // We will request these data again when we scan for unfetched data.
            let _ = success_tx.send(false);
            return Ok(());
        }

        let proof_valid = DB::verify_proof(&proof, &data, start_loc, self.target.root);

        // Report success or failure to the resolver
        let _ = success_tx.send(proof_valid);

        if proof_valid {
            // Extract pinned nodes if we don't have them and this is the first batch
            if self.pinned_nodes.is_none() && start_loc == self.target.lower_bound {
                if let Ok(nodes) = DB::extract_pinned_nodes(&proof, start_loc, data_len) {
                    self.pinned_nodes = Some(nodes);
                }
            }

            // Store data for later application
            self.store_data(start_loc, data);
        }

        Ok(())
    }

    /// Execute one step of the synchronization process.
    ///
    /// This is the main coordination method that:
    /// 1. Checks if sync is complete
    /// 2. Waits for the next synchronization event
    /// 3. Handles different event types (target updates, fetch results)
    /// 4. Coordinates request scheduling and data application
    ///
    /// Returns `StepResult::Complete(database)` when sync is finished, or
    /// `StepResult::Continue(self)` when more work remains.
    pub(crate) async fn step(mut self) -> Result<NextStep<Self, DB>, EngineError<DB, R>> {
        // Check if sync is complete
        if self.is_complete().await? {
            // Build the database from the completed sync
            let database = DB::from_sync_result(
                self.context,
                self.config,
                self.journal,
                self.pinned_nodes,
                self.target.lower_bound,
                self.target.upper_bound,
                self.apply_batch_size,
            )
            .await
            .map_err(Error::database)?;

            // Verify the final root digest matches the final target
            let got_root = database.root();
            let expected_root = self.target.root;
            if got_root != expected_root {
                return Err(Error::RootMismatch {
                    expected: expected_root,
                    actual: got_root,
                });
            }

            return Ok(NextStep::Complete(database));
        }

        // Wait for the next synchronization event
        let event = wait_for_event(&mut self.update_receiver, &mut self.outstanding_requests)
            .await
            .ok_or(Error::SyncStalled)?;

        match event {
            Event::TargetUpdate(new_target) => {
                // Validate and handle the target update
                validate_update(&self.target, &new_target)?;

                let mut updated_self = self.reset_for_target_update(new_target).await?;

                // Schedule new requests for the updated target
                updated_self.schedule_requests().await?;

                return Ok(NextStep::Continue(updated_self));
            }
            Event::UpdateChannelClosed => {
                self.update_receiver = None;
            }
            Event::BatchReceived(fetch_result) => {
                // Process the fetch result
                self.handle_fetch_result(fetch_result)?;

                // Request data in the sync range
                self.schedule_requests().await?;

                // Apply data that is now contiguous with the current journal
                self.apply_data().await?;
            }
        }

        Ok(NextStep::Continue(self))
    }

    /// Run sync to completion, returning the final database when done.
    ///
    /// This method repeatedly calls `step()` until sync is complete. The `step()` method
    /// handles building the final database and verifying the root digest.
    pub async fn sync(mut self) -> Result<DB, EngineError<DB, R>> {
        // Run sync loop until completion
        loop {
            match self.step().await? {
                NextStep::Continue(new_engine) => self = new_engine,
                NextStep::Complete(database) => return Ok(database),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::verification::Proof;
    use commonware_cryptography::sha256;
    use futures::channel::oneshot;

    #[test]
    fn test_outstanding_requests() {
        let mut requests: Requests<i32, Proof<sha256::Digest>, ()> = Requests::new();
        assert_eq!(requests.len(), 0);

        // Test adding requests
        let fut = Box::pin(async {
            IndexedFetchResult {
                start_loc: 0,
                result: Ok(FetchResult {
                    proof: Proof {
                        size: 0,
                        digests: vec![],
                    },
                    data: vec![],
                    success_tx: oneshot::channel().0,
                }),
            }
        });
        requests.add(10, fut);
        assert_eq!(requests.len(), 1);
        assert!(requests.locations().contains(&10));

        // Test removing requests
        requests.remove(10);
        assert!(!requests.locations().contains(&10));
    }
}
