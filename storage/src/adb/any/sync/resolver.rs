use crate::{
    adb::{
        any::{sync::Error, Any},
        operation::Operation,
    },
    mmr::verification::Proof,
    translator::Translator,
};
use commonware_cryptography::{Digest, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::channel::oneshot;
use std::{future::Future, num::NonZeroU64};

/// Result of a call to [Resolver::get_operations].
///
/// This struct encapsulates the response from a resolver when requesting operations
/// for database synchronization. It includes both the requested operations and a
/// cryptographic proof that validates their authenticity and correctness.
///
/// # Purpose
///
/// The `GetOperationsResult` is designed to support secure database synchronization
/// by providing:
/// - **Operations**: The actual database operations requested by the sync client
/// - **Proof**: A cryptographic proof that these operations were present in the
///   database at the specified state
/// - **Feedback Channel**: A mechanism for the client to report proof verification
///   results back to the resolver
///
/// # Usage Pattern
///
/// ```rust,ignore
/// // Resolver provides operations with proof
/// let result = resolver.get_operations(target_size, start_loc, batch_size).await?;
///
/// // Client verifies the proof
/// let proof_valid = verify_proof(&result.proof, &result.operations);
///
/// // Client reports verification result back to resolver
/// let _ = result.success_tx.send(proof_valid);
/// ```
///
/// # Security Model
///
/// The proof verification feedback mechanism enables:
/// - **Reputation tracking**: Resolvers can track successful/failed verification rates
/// - **Adaptive behavior**: Resolvers can adjust their behavior based on client feedback
/// - **Debugging**: Failed verifications can be logged for investigation
pub struct GetOperationsResult<D: Digest, K: Array, V: Array> {
    /// Cryptographic proof that validates the authenticity of the operations.
    ///
    /// This proof demonstrates that the provided operations were present in the
    /// database when it contained the specified number of operations. The proof
    /// is verified using the MMR (Merkle Mountain Range) structure to ensure
    /// cryptographic integrity.
    pub proof: Proof<D>,

    /// The database operations in the requested range.
    ///
    /// These operations represent the actual database changes (updates, deletions, etc.)
    /// that occurred at the specified locations in the database's operation log.
    /// The operations are provided in the order they were applied to the database.
    pub operations: Vec<Operation<K, V>>,

    /// Channel for reporting proof verification results back to the resolver.
    ///
    /// The sync client should send `true` if the proof verification succeeds,
    /// or `false` if it fails. This feedback allows the resolver to:
    /// - Track verification success rates
    /// - Implement adaptive retry logic
    /// - Log failed verifications for debugging
    ///
    /// **Note**: Clients should ignore any error when sending on this channel,
    /// as the resolver may not be waiting for the result.
    pub success_tx: oneshot::Sender<bool>,
}

/// Trait for resolving database operations during synchronization.
///
/// The `Resolver` trait defines the interface for fetching database operations
/// with cryptographic proofs during the synchronization process. This trait
/// abstracts the mechanism for obtaining operations, allowing for different
/// implementations such as:
/// - **Local resolver**: Reading from a local database instance
/// - **Network resolver**: Fetching operations from remote peers
/// - **Cached resolver**: Using cached operations with fallback to network
///
/// # Synchronization Context
///
/// During database synchronization, the sync client needs to:
/// 1. Request batches of operations from a resolver
/// 2. Verify cryptographic proofs for each batch
/// 3. Apply verified operations to the local database
/// 4. Provide feedback on verification results
///
/// The resolver plays a crucial role in this process by providing both the
/// operations and the proofs needed to ensure data integrity.
///
/// # Security Considerations
///
/// Resolvers must provide cryptographically sound proofs that:
/// - Prove the operations existed in the database at the specified state
/// - Cannot be forged or manipulated by malicious actors
/// - Are efficiently verifiable by the sync client
///
/// # Implementation Requirements
///
/// Implementors must ensure that:
/// - Operations are returned in the correct order
/// - Proofs are valid for the provided operations and database state
/// - The `success_tx` channel is properly configured for feedback
/// - Error handling is appropriate for the resolver's context
///
/// # Example Implementation
///
/// ```rust,ignore
/// impl Resolver for MyNetworkResolver {
///     type Digest = Sha256Hash;
///     type Key = MyKey;
///     type Value = MyValue;
///
///     async fn get_operations(
///         &self,
///         size: u64,
///         start_loc: u64,
///         max_ops: NonZeroU64,
///     ) -> Result<GetOperationsResult<Self::Digest, Self::Key, Self::Value>, Error> {
///         // Fetch operations from network
///         let operations = self.fetch_operations(start_loc, max_ops).await?;
///         
///         // Generate proof for the operations
///         let proof = self.generate_proof(size, &operations).await?;
///         
///         // Create feedback channel
///         let (success_tx, success_rx) = oneshot::channel();
///         
///         // Handle feedback asynchronously
///         self.handle_feedback(success_rx);
///         
///         Ok(GetOperationsResult {
///             proof,
///             operations,
///             success_tx,
///         })
///     }
/// }
/// ```
pub trait Resolver {
    /// The digest type used for cryptographic operations.
    ///
    /// This type must implement the `Digest` trait and will be used for
    /// proof generation and verification.
    type Digest: Digest;

    /// The key type for database operations.
    ///
    /// This type represents the keys used in database operations and must
    /// implement the `Array` trait for efficient serialization.
    type Key: Array;

    /// The value type for database operations.
    ///
    /// This type represents the values used in database operations and must
    /// implement the `Array` trait for efficient serialization.
    type Value: Array;

    /// Retrieve operations from the database with cryptographic proof.
    ///
    /// This method fetches a batch of database operations starting from a specific
    /// location, along with a cryptographic proof that validates their authenticity
    /// and correctness.
    ///
    /// # Arguments
    ///
    /// * `size` - The target size of the database state for proof generation.
    ///   This represents the number of operations the database should contain
    ///   when the proof is generated.
    /// * `start_loc` - The starting location (position) in the database's operation
    ///   log from which to retrieve operations.
    /// * `max_ops` - The maximum number of operations to retrieve in this batch.
    ///   The actual number returned may be less than this value.
    ///
    /// # Returns
    ///
    /// A `GetOperationsResult` containing:
    /// - The requested operations
    /// - A cryptographic proof validating the operations
    /// - A feedback channel for reporting verification results
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The requested operations cannot be retrieved
    /// - Proof generation fails
    /// - The resolver encounters a network or storage error
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let result = resolver.get_operations(1000, 100, NonZeroU64::new(50).unwrap()).await?;
    ///
    /// // This would retrieve up to 50 operations starting from location 100,
    /// // with a proof valid for a database state of 1000 operations.
    /// ```
    #[allow(clippy::type_complexity)]
    fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<GetOperationsResult<Self::Digest, Self::Key, Self::Value>, Error>>;
}

/// Implementation of [Resolver] for local database instances.
///
/// This implementation allows a local database to act as a resolver for
/// synchronization operations. It's commonly used in testing scenarios
/// or when synchronizing from a local "source of truth" database.
///
/// # Usage
///
/// This implementation is automatically available for any `Any` database
/// instance and can be used directly in sync operations:
///
/// ```rust,ignore
/// let source_db = Any::init(context, config).await?;
/// let sync_config = SyncConfig {
///     resolver: &source_db,  // Uses this implementation
///     // ... other config
/// };
/// ```
impl<E, K, V, H, T> Resolver for &Any<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    type Digest = H::Digest;
    type Key = K;
    type Value = V;

    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<GetOperationsResult<H::Digest, Self::Key, Self::Value>, Error> {
        // Generate historical proof for the requested operations
        // This creates a proof that the operations were present in the database
        // when it had the specified size
        self.historical_proof(size, start_loc, max_ops.get())
            .await
            .map_err(Error::Adb)
            .map(|(proof, operations)| GetOperationsResult {
                proof,
                operations,
                // For local database resolver, we don't need feedback since
                // we're not tracking network reliability or reputation
                success_tx: oneshot::channel().0,
            })
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::marker::PhantomData;

    pub struct FailResolver<D, K, V> {
        _digest: PhantomData<D>,
        _key: PhantomData<K>,
        _value: PhantomData<V>,
    }

    impl<D, K, V> Resolver for FailResolver<D, K, V>
    where
        D: Digest,
        K: Array,
        V: Array,
    {
        type Digest = D;
        type Key = K;
        type Value = V;

        async fn get_operations(
            &self,
            _size: u64,
            _start_loc: u64,
            _max_ops: NonZeroU64,
        ) -> Result<GetOperationsResult<Self::Digest, Self::Key, Self::Value>, Error> {
            Err(Error::AlreadyComplete)
        }
    }

    impl<D, K, V> FailResolver<D, K, V> {
        pub fn new() -> Self {
            Self {
                _digest: PhantomData,
                _key: PhantomData,
                _value: PhantomData,
            }
        }
    }
}
