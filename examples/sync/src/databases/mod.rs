//! Database-specific modules for the sync example.

use crate::Key;
use commonware_codec::Encode;
use commonware_storage::{
    merkle::{self, Location, Proof},
    qmdb::{self, sync::compact},
};
use std::{future::Future, num::NonZeroU64};

pub mod any;
pub mod current;
pub mod immutable;
pub mod immutable_compact;
pub mod keyless;
pub mod keyless_compact;

/// Synchronization mode to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    Full,
    Compact,
}

impl std::str::FromStr for SyncMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "full" => Ok(Self::Full),
            "compact" => Ok(Self::Compact),
            _ => Err(format!(
                "Invalid sync mode: '{s}'. Must be 'full' or 'compact'",
            )),
        }
    }
}

impl SyncMode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Compact => "compact",
        }
    }
}

/// Database family to synchronize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseType {
    Any,
    Current,
    Immutable,
    Keyless,
}

impl std::str::FromStr for DatabaseType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "any" => Ok(Self::Any),
            "current" => Ok(Self::Current),
            "immutable" => Ok(Self::Immutable),
            "keyless" => Ok(Self::Keyless),
            _ => Err(format!(
                "Invalid database family: '{s}'. Must be 'any', 'current', 'immutable', or \
                 'keyless'",
            )),
        }
    }
}

impl DatabaseType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Current => "current",
            Self::Immutable => "immutable",
            Self::Keyless => "keyless",
        }
    }

    pub const fn supports_client_mode(self, mode: SyncMode) -> bool {
        match mode {
            SyncMode::Full => matches!(
                self,
                Self::Any | Self::Current | Self::Immutable | Self::Keyless
            ),
            SyncMode::Compact => matches!(self, Self::Immutable | Self::Keyless),
        }
    }

    pub const fn supports_compact_storage(self) -> bool {
        matches!(self, Self::Immutable | Self::Keyless)
    }
}

/// Backing storage kind used by a compact-mode server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKind {
    Full,
    Compact,
}

impl std::str::FromStr for StorageKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "full" => Ok(Self::Full),
            "compact" => Ok(Self::Compact),
            _ => Err(format!(
                "Invalid storage kind: '{s}'. Must be 'full' or 'compact'",
            )),
        }
    }
}

impl StorageKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Compact => "compact",
        }
    }
}

/// Parse hidden legacy `--db` values for backward compatibility.
pub fn parse_legacy_database_type(s: &str) -> Result<(DatabaseType, Option<StorageKind>), String> {
    match s.to_lowercase().as_str() {
        "any" => Ok((DatabaseType::Any, None)),
        "current" => Ok((DatabaseType::Current, None)),
        "immutable" => Ok((DatabaseType::Immutable, None)),
        "keyless" => Ok((DatabaseType::Keyless, None)),
        "immutable-compact" => Ok((DatabaseType::Immutable, Some(StorageKind::Compact))),
        "keyless-compact" => Ok((DatabaseType::Keyless, Some(StorageKind::Compact))),
        _ => Err(format!(
            "Invalid legacy database type: '{s}'. Must be 'any', 'current', 'immutable', \
             'keyless', 'immutable-compact', or 'keyless-compact'",
        )),
    }
}

/// Common surface shared by all database adapters used by the sync example binaries.
///
/// This is intentionally the smallest shared interface: enough to create test data, mutate the
/// database during the demo, and log the resulting root. More specific sync capabilities live in
/// [`Syncable`] and [`CompactSyncable`].
#[allow(clippy::type_complexity)]
pub trait ExampleDatabase: Sized {
    /// The merkle family used by this database.
    type Family: merkle::Family;

    /// The type of operations in the database.
    type Operation: Encode + Send + Sync + 'static;

    /// Create test operations with the given count and seed.
    /// The returned operations must end with a commit operation.
    fn create_test_operations(count: usize, seed: u64) -> Vec<Self::Operation>;

    /// Add operations to the database, ignoring any input that doesn't end with a commit
    /// operation.
    fn add_operations(
        &mut self,
        operations: Vec<Self::Operation>,
    ) -> impl Future<Output = Result<(), qmdb::Error<Self::Family>>> + Send;

    /// Get the database's root digest.
    fn root(&self) -> Key;

    /// Get the database family name for logging.
    fn name() -> &'static str;
}

/// Capability trait for databases that support full replay-based sync.
///
/// These databases retain enough history to serve authenticated operations over a range, so the
/// client can fetch and replay them into the same database family.
#[allow(clippy::type_complexity)]
pub trait Syncable: ExampleDatabase {
    /// Get the total number of operations in the database (including pruned operations).
    fn size(&self) -> impl Future<Output = Location<Self::Family>> + Send;

    /// Get the most recent location from which this database can safely be synced.
    ///
    /// Callers constructing a sync target should use this value (or any earlier retained
    /// location) as the `range.start`.
    fn sync_boundary(&self) -> impl Future<Output = Location<Self::Family>> + Send;

    /// Get historical proof and operations.
    fn historical_proof(
        &self,
        op_count: Location<Self::Family>,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
    ) -> impl Future<
        Output = Result<
            (Proof<Self::Family, Key>, Vec<Self::Operation>),
            qmdb::Error<Self::Family>,
        >,
    > + Send;

    /// Get the pinned nodes for a lower operation boundary of `loc`.
    fn pinned_nodes_at(
        &self,
        loc: Location<Self::Family>,
    ) -> impl Future<Output = Result<Vec<Key>, qmdb::Error<Self::Family>>> + Send;
}

/// Capability trait for databases that can serve compact sync targets.
///
/// Compact sync does not replay historical operations. Instead, the server exposes the latest
/// authenticated target for the database family, and the client reconstructs a compact-storage
/// local database from that authenticated state.
#[allow(clippy::type_complexity)]
pub trait CompactSyncable: ExampleDatabase {
    /// Return the latest compact-sync target this database can currently serve.
    ///
    /// Full databases implement this so they can act as compact-sync sources, and compact-storage
    /// databases implement it so compact nodes can sync from each other. The client still
    /// materializes into compact storage in both cases.
    fn current_target(&self) -> impl Future<Output = compact::Target<Self::Family, Key>> + Send;
}

#[cfg(test)]
mod tests {
    use super::{parse_legacy_database_type, DatabaseType, StorageKind, SyncMode};

    #[test]
    fn test_supported_client_mode_matrix() {
        assert!(DatabaseType::Any.supports_client_mode(SyncMode::Full));
        assert!(!DatabaseType::Any.supports_client_mode(SyncMode::Compact));

        assert!(DatabaseType::Current.supports_client_mode(SyncMode::Full));
        assert!(!DatabaseType::Current.supports_client_mode(SyncMode::Compact));

        assert!(DatabaseType::Immutable.supports_client_mode(SyncMode::Full));
        assert!(DatabaseType::Immutable.supports_client_mode(SyncMode::Compact));

        assert!(DatabaseType::Keyless.supports_client_mode(SyncMode::Full));
        assert!(DatabaseType::Keyless.supports_client_mode(SyncMode::Compact));
    }

    #[test]
    fn test_compact_storage_support() {
        assert!(!DatabaseType::Any.supports_compact_storage());
        assert!(!DatabaseType::Current.supports_compact_storage());
        assert!(DatabaseType::Immutable.supports_compact_storage());
        assert!(DatabaseType::Keyless.supports_compact_storage());
    }

    #[test]
    fn test_legacy_database_type_mapping() {
        assert_eq!(
            parse_legacy_database_type("immutable").unwrap(),
            (DatabaseType::Immutable, None)
        );
        assert_eq!(
            parse_legacy_database_type("immutable-compact").unwrap(),
            (DatabaseType::Immutable, Some(StorageKind::Compact))
        );
        assert_eq!(
            parse_legacy_database_type("keyless-compact").unwrap(),
            (DatabaseType::Keyless, Some(StorageKind::Compact))
        );
    }
}
