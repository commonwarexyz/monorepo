//! REVM database adapter backed by QMDB.
//!
//! This module provides a synchronous REVM `DatabaseRef` implementation that
//! communicates with the QMDB actor for database reads. The actor isolates
//! non-Send QMDB futures from cross-crate trait boundaries.
//!
//! # Design
//!
//! Since `DatabaseRef` is a sync trait (required by REVM), we need to block somewhere
//! to get results from the async actor. This implementation uses:
//! - `try_send` on the command channel
//! - `std::sync::mpsc::recv` for responses
//!
//! Callers should run these sync reads on a blocking executor.

use super::actor::QmdbHandle;
use super::Error;
use alloy_evm::revm::{
    database_interface::DatabaseRef,
    primitives::{Address, Bytes, B256, KECCAK_EMPTY, U256},
    state::{AccountInfo, Bytecode},
};

/// Sync REVM database backed by QMDB via actor.
///
/// Uses `try_send` for commands and blocking `recv` for responses.
#[derive(Clone)]
pub(crate) struct QmdbRefDb {
    handle: QmdbHandle,
}

impl QmdbRefDb {
    /// Creates a new sync database adapter with the actor handle.
    pub(crate) const fn new(handle: QmdbHandle) -> Self {
        Self { handle }
    }
}

impl std::fmt::Debug for QmdbRefDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QmdbRefDb").finish()
    }
}

impl DatabaseRef for QmdbRefDb {
    type Error = Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let record = self.handle.get_account_sync(address)?;
        Ok(record.and_then(|record| record.as_info()))
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if code_hash == KECCAK_EMPTY || code_hash == B256::ZERO {
            return Ok(Bytecode::default());
        }

        let code = self.handle.get_code_sync(code_hash)?;
        let code = code.ok_or(Error::MissingCode(code_hash))?;
        Ok(Bytecode::new_raw(Bytes::copy_from_slice(&code)))
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.handle.get_storage_sync(address, index)
    }

    fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}
