//! Deterministic state-change helpers for the example chain.
//!
//! `StateChanges` uses `BTreeMap` so the encoded form is canonical and deterministic.

use alloy_evm::revm::primitives::{Address, B256, U256};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug)]
/// Limits used when decoding deterministic state changes.
pub struct StateChangesCfg {
    /// Maximum number of touched accounts allowed in a delta.
    pub max_accounts: usize,
    /// Maximum number of storage slots that can be decoded per account.
    pub max_storage_slots: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Canonical representation of a touched account's post-transaction state.
pub struct AccountChange {
    pub touched: bool,
    pub created: bool,
    pub selfdestructed: bool,
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: B256,
    pub storage: BTreeMap<U256, U256>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
/// Canonical per-transaction state delta.
pub struct StateChanges {
    pub accounts: BTreeMap<Address, AccountChange>,
}

impl StateChanges {
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }
}

impl Write for AccountChange {
    fn write(&self, buf: &mut impl BufMut) {
        self.touched.write(buf);
        self.created.write(buf);
        self.selfdestructed.write(buf);
        self.nonce.write(buf);
        write_u256(&self.balance, buf);
        write_b256(&self.code_hash, buf);

        self.storage.len().write(buf);
        for (slot, value) in self.storage.iter() {
            write_u256(slot, buf);
            write_u256(value, buf);
        }
    }
}

impl EncodeSize for AccountChange {
    fn encode_size(&self) -> usize {
        self.touched.encode_size()
            + self.created.encode_size()
            + self.selfdestructed.encode_size()
            + self.nonce.encode_size()
            + 32
            + 32
            + self.storage.len().encode_size()
            + self.storage.len() * (32 + 32)
    }
}

impl Read for AccountChange {
    type Cfg = StateChangesCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let touched = bool::read(buf)?;
        let created = bool::read(buf)?;
        let selfdestructed = bool::read(buf)?;
        let nonce = u64::read(buf)?;
        let balance = read_u256(buf)?;
        let code_hash = read_b256(buf)?;

        let slots = usize::read_cfg(buf, &RangeCfg::new(0..=cfg.max_storage_slots))?;
        let mut storage = BTreeMap::new();
        for _ in 0..slots {
            let slot = read_u256(buf)?;
            let value = read_u256(buf)?;
            storage.insert(slot, value);
        }

        Ok(Self {
            touched,
            created,
            selfdestructed,
            nonce,
            balance,
            code_hash,
            storage,
        })
    }
}

impl Write for StateChanges {
    fn write(&self, buf: &mut impl BufMut) {
        self.accounts.len().write(buf);
        for (address, change) in self.accounts.iter() {
            write_address(address, buf);
            change.write(buf);
        }
    }
}

impl EncodeSize for StateChanges {
    fn encode_size(&self) -> usize {
        self.accounts.len().encode_size()
            + self
                .accounts
                .values()
                .map(|change| 20 + change.encode_size())
                .sum::<usize>()
    }
}

impl Read for StateChanges {
    type Cfg = StateChangesCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let accounts = usize::read_cfg(buf, &RangeCfg::new(0..=cfg.max_accounts))?;
        let mut map = BTreeMap::new();
        for _ in 0..accounts {
            let address = read_address(buf)?;
            let change = AccountChange::read_cfg(buf, cfg)?;
            map.insert(address, change);
        }
        Ok(Self { accounts: map })
    }
}

fn write_address(value: &Address, buf: &mut impl BufMut) {
    buf.put_slice(value.as_slice());
}

fn read_address(buf: &mut impl Buf) -> Result<Address, CodecError> {
    if buf.remaining() < 20 {
        return Err(CodecError::EndOfBuffer);
    }
    let mut out = [0u8; 20];
    buf.copy_to_slice(&mut out);
    Ok(Address::from(out))
}

fn write_b256(value: &B256, buf: &mut impl BufMut) {
    buf.put_slice(value.as_slice());
}

fn read_b256(buf: &mut impl Buf) -> Result<B256, CodecError> {
    if buf.remaining() < 32 {
        return Err(CodecError::EndOfBuffer);
    }
    let mut out = [0u8; 32];
    buf.copy_to_slice(&mut out);
    Ok(B256::from(out))
}

fn write_u256(value: &U256, buf: &mut impl BufMut) {
    buf.put_slice(&value.to_be_bytes::<32>());
}

fn read_u256(buf: &mut impl Buf) -> Result<U256, CodecError> {
    if buf.remaining() < 32 {
        return Err(CodecError::EndOfBuffer);
    }
    let mut out = [0u8; 32];
    buf.copy_to_slice(&mut out);
    Ok(U256::from_be_bytes(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_evm::revm::primitives::{Address, B256, U256};
    use commonware_codec::{Decode as _, Encode as _};
    use std::collections::BTreeMap;

    fn cfg() -> StateChangesCfg {
        StateChangesCfg {
            max_accounts: 16,
            max_storage_slots: 64,
        }
    }

    fn sample_changes_order_a() -> StateChanges {
        let mut changes = StateChanges::default();

        let mut storage1 = BTreeMap::new();
        storage1.insert(U256::from(2u64), U256::from(200u64));
        storage1.insert(U256::from(1u64), U256::from(100u64));
        changes.accounts.insert(
            Address::from([0x11u8; 20]),
            AccountChange {
                touched: true,
                created: false,
                selfdestructed: false,
                nonce: 7,
                balance: U256::from(1234u64),
                code_hash: B256::from([0xAAu8; 32]),
                storage: storage1,
            },
        );

        let mut storage2 = BTreeMap::new();
        storage2.insert(U256::from(5u64), U256::from(42u64));
        changes.accounts.insert(
            Address::from([0x22u8; 20]),
            AccountChange {
                touched: true,
                created: true,
                selfdestructed: false,
                nonce: 1,
                balance: U256::from(999u64),
                code_hash: B256::from([0xBBu8; 32]),
                storage: storage2,
            },
        );

        changes
    }

    #[test]
    fn test_state_changes_roundtrip() {
        let changes = sample_changes_order_a();
        let encoded = changes.encode();
        let decoded = StateChanges::decode_cfg(encoded, &cfg()).expect("decode changes");
        assert_eq!(changes, decoded);
    }
}
