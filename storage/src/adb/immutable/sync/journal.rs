use crate::{
    adb::{operation::Variable, sync},
    journal::variable,
};
use commonware_codec::Codec;
use commonware_runtime::{Metrics, Storage};
use commonware_utils::Array;

/// Sync journal wrapper for Immutable database that bridges the gap between
/// the sync engine's operation location model and Variable journal's section/offset model.
///
/// This wrapper maintains the current operation location and translates between:
/// - Sync engine expectations: sequential operation locations (0, 1, 2, 3...)
/// - Variable journal reality: section-based storage with offsets
pub struct ImmutableSyncJournal<E, K, V>
where
    E: Storage + Metrics,
    K: Array,
    V: Codec,
{
    /// The underlying Variable journal that stores the actual operations
    inner: variable::Journal<E, Variable<K, V>>,

    /// Number of operations per section (from database configuration)
    items_per_section: u64,

    /// Current operation location - the position where the next operation will be written
    /// This is what sync engine expects from size()
    current_size: u64,

    /// Lower bound of the sync range (for validation)
    lower_bound: u64,

    /// Upper bound of the sync range (for validation)  
    upper_bound: u64,
}

impl<E, K, V> ImmutableSyncJournal<E, K, V>
where
    E: Storage + Metrics,
    K: Array,
    V: Codec,
{
    /// Create a new sync journal wrapper
    ///
    /// # Arguments
    /// * `inner` - The Variable journal to wrap
    /// * `items_per_section` - Number of operations per section
    /// * `lower_bound` - Lower bound of sync range (inclusive)
    /// * `upper_bound` - Upper bound of sync range (inclusive)
    /// * `current_size` - Current operation location (where next operation will be written)
    pub fn new(
        inner: variable::Journal<E, Variable<K, V>>,
        items_per_section: u64,
        lower_bound: u64,
        upper_bound: u64,
        current_size: u64,
    ) -> Self {
        // Validate that current_size is within the expected range
        assert!(
            current_size >= lower_bound,
            "current_size ({}) must be >= lower_bound ({})",
            current_size,
            lower_bound
        );
        assert!(
            current_size <= upper_bound + 1,
            "current_size ({}) must be <= upper_bound + 1 ({})",
            current_size,
            upper_bound + 1
        );

        Self {
            inner,
            items_per_section,
            current_size,
            lower_bound,
            upper_bound,
        }
    }

    /// Get the underlying Variable journal (for database construction)
    pub fn into_inner(self) -> variable::Journal<E, Variable<K, V>> {
        self.inner
    }

    /// Get a reference to the underlying Variable journal
    pub fn inner(&self) -> &variable::Journal<E, Variable<K, V>> {
        &self.inner
    }

    /// Get a mutable reference to the underlying Variable journal
    pub fn inner_mut(&mut self) -> &mut variable::Journal<E, Variable<K, V>> {
        &mut self.inner
    }

    /// Calculate which section an operation location belongs to
    fn location_to_section(&self, location: u64) -> u64 {
        location / self.items_per_section
    }
}

impl<E, K, V> sync::Journal for ImmutableSyncJournal<E, K, V>
where
    E: Storage + Metrics,
    K: Array,
    V: Codec,
{
    type Op = Variable<K, V>;
    type Error = crate::journal::Error;

    async fn size(&self) -> Result<u64, Self::Error> {
        // Return the current operation location - this is what sync engine expects
        Ok(self.current_size)
    }

    async fn has_operations_from(&self, location: u64) -> Result<bool, Self::Error> {
        // Efficiently check if we have operations at or after the given location
        // Since we track current_size, this is trivial
        Ok(self.current_size > location)
    }

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        // Validate that we're appending at the expected location
        if self.current_size > self.upper_bound {
            return Err(crate::journal::Error::InvalidSyncRange(
                self.lower_bound,
                self.upper_bound,
            ));
        }

        // Calculate the section for this operation location
        let section = self.location_to_section(self.current_size);

        // Append to the Variable journal
        self.inner.append(section, op).await?;

        // Increment our operation location counter
        self.current_size += 1;

        Ok(())
    }

    async fn close(self) -> Result<(), Self::Error> {
        // Close the underlying Variable journal
        self.inner.close().await
    }
}
