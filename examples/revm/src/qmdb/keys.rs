//! Key schema helpers for QMDB.

use alloy_evm::revm::primitives::{Address, B256, U256};
use commonware_utils::sequence::FixedBytes;

pub(crate) type AccountKey = FixedBytes<20>;
pub(crate) type StorageKey = FixedBytes<60>;
pub(crate) type CodeKey = FixedBytes<32>;

pub(crate) const fn account_key(address: Address) -> AccountKey {
    AccountKey::new(address.into_array())
}

pub(crate) const fn code_key(hash: B256) -> CodeKey {
    CodeKey::new(hash.0)
}

pub(crate) fn storage_key(address: Address, generation: u64, slot: U256) -> StorageKey {
    let mut out = [0u8; 60];
    out[..20].copy_from_slice(address.as_slice());
    out[20..28].copy_from_slice(&generation.to_be_bytes());
    out[28..60].copy_from_slice(&slot.to_be_bytes::<32>());
    StorageKey::new(out)
}
