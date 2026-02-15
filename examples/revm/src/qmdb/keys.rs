//! Key schema helpers for QMDB.
//!
//! Keys are fixed-length to keep translations simple and avoid collisions:
//! - Accounts: 20-byte address.
//! - Code: 32-byte hash.
//! - Storage: 20-byte address, 8-byte storage generation, 32-byte slot.

use alloy_evm::revm::primitives::{Address, B256, U256};
use commonware_utils::sequence::FixedBytes;

/// QMDB key for account records.
pub(crate) type AccountKey = FixedBytes<20>;
/// QMDB key for storage records.
pub(crate) type StorageKey = FixedBytes<60>;
/// QMDB key for contract bytecode.
pub(crate) type CodeKey = FixedBytes<32>;

/// Converts an address into an account key.
pub(crate) const fn account_key(address: Address) -> AccountKey {
    AccountKey::new(address.into_array())
}

/// Converts a code hash into a code key.
pub(crate) const fn code_key(hash: B256) -> CodeKey {
    CodeKey::new(hash.0)
}

/// Builds the storage key for a specific account, generation, and slot.
///
/// The storage generation is incremented when an account is recreated so
/// previous storage slots are logically discarded without needing to delete
/// every key explicitly.
pub(crate) fn storage_key(address: Address, generation: u64, slot: U256) -> StorageKey {
    let mut out = [0u8; 60];
    out[..20].copy_from_slice(address.as_slice());
    out[20..28].copy_from_slice(&generation.to_be_bytes());
    out[28..60].copy_from_slice(&slot.to_be_bytes::<32>());
    StorageKey::new(out)
}
