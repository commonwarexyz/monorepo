//! Value encodings for QMDB.
//!
//! Records are encoded with `commonware_codec` and use fixed-size, big-endian
//! representations for Ethereum integers and hashes.

use alloy_evm::revm::{
    primitives::{B256, KECCAK_EMPTY, U256},
    state::AccountInfo,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};

/// Persisted account data stored in QMDB.
#[derive(Clone, Debug)]
pub(crate) struct AccountRecord {
    /// Whether the account exists.
    pub(crate) exists: bool,
    /// Account nonce.
    pub(crate) nonce: u64,
    /// Account balance.
    pub(crate) balance: U256,
    /// Hash of the account's contract bytecode.
    pub(crate) code_hash: B256,
    /// Storage generation for invalidating old storage slots on re-creation.
    pub(crate) storage_generation: u64,
}

impl AccountRecord {
    /// Returns an empty account marker with the given storage generation.
    pub(crate) const fn empty(storage_generation: u64) -> Self {
        Self {
            exists: false,
            nonce: 0,
            balance: U256::ZERO,
            code_hash: KECCAK_EMPTY,
            storage_generation,
        }
    }

    /// Converts the record into REVM's account info, if the account exists.
    pub(crate) const fn as_info(&self) -> Option<AccountInfo> {
        if !self.exists {
            return None;
        }
        Some(AccountInfo {
            balance: self.balance,
            nonce: self.nonce,
            code_hash: self.code_hash,
            code: None,
        })
    }
}

impl Write for AccountRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.exists.write(buf);
        self.nonce.write(buf);
        write_u256(self.balance, buf);
        write_b256(self.code_hash, buf);
        self.storage_generation.write(buf);
    }
}

impl EncodeSize for AccountRecord {
    fn encode_size(&self) -> usize {
        self.exists.encode_size()
            + self.nonce.encode_size()
            + 32
            + 32
            + self.storage_generation.encode_size()
    }
}

impl Read for AccountRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let exists = bool::read(buf)?;
        let nonce = u64::read(buf)?;
        let balance = read_u256(buf)?;
        let code_hash = read_b256(buf)?;
        let storage_generation = u64::read(buf)?;
        Ok(Self {
            exists,
            nonce,
            balance,
            code_hash,
            storage_generation,
        })
    }
}

/// Persisted storage slot value.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StorageRecord(pub(crate) U256);

impl Write for StorageRecord {
    fn write(&self, buf: &mut impl BufMut) {
        write_u256(self.0, buf);
    }
}

impl EncodeSize for StorageRecord {
    fn encode_size(&self) -> usize {
        32
    }
}

impl Read for StorageRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(read_u256(buf)?))
    }
}

/// Writes a 256-bit integer in big-endian form.
pub(crate) fn write_u256(value: U256, buf: &mut impl BufMut) {
    buf.put_slice(&value.to_be_bytes::<32>());
}

/// Reads a 256-bit integer in big-endian form.
pub(crate) fn read_u256(buf: &mut impl Buf) -> Result<U256, CodecError> {
    if buf.remaining() < 32 {
        return Err(CodecError::EndOfBuffer);
    }
    let mut out = [0u8; 32];
    buf.copy_to_slice(&mut out);
    Ok(U256::from_be_bytes(out))
}

/// Writes a 256-bit hash in big-endian form.
pub(crate) fn write_b256(value: B256, buf: &mut impl BufMut) {
    buf.put_slice(value.as_slice());
}

/// Reads a 256-bit hash in big-endian form.
pub(crate) fn read_b256(buf: &mut impl Buf) -> Result<B256, CodecError> {
    if buf.remaining() < 32 {
        return Err(CodecError::EndOfBuffer);
    }
    let mut out = [0u8; 32];
    buf.copy_to_slice(&mut out);
    Ok(B256::from(out))
}
