use alloy_evm::revm::{database_interface::DBErrorMarker, primitives::B256};
use thiserror::Error;

/// Errors surfaced by the QMDB-backed REVM adapter.
#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("qmdb error: {0}")]
    Qmdb(#[from] commonware_storage::qmdb::Error),
    #[error("missing tokio runtime for WrapDatabaseAsync")]
    MissingRuntime,
    #[error("missing code for hash {0:?}")]
    MissingCode(B256),
    #[error("qmdb store unavailable: {0}")]
    StoreUnavailable(&'static str),
}

impl DBErrorMarker for Error {}
