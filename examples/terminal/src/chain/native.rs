//! Native asset ownership and the bounded operator registry.

use crate::protocol::{Account, Deployment, Key, MAX_ACCOUNTS, chain_id};
use bytes::{Buf, BufMut};
use commonware_clearing::bajillion::qmdb::StateRoot;
use commonware_codec::{EncodeSize, Error, Read, ReadExt as _, Write};
use commonware_cryptography::{ed25519, sha256::Digest};
use std::collections::BTreeSet;

/// Maximum operator deployments retained by one chain.
pub(crate) const MAX_DEPLOYMENTS: usize = 64;

/// Authenticated routing and resource limits for one immutable clearing deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RegistryEntry {
    pub(crate) deployment: Deployment,
    pub(crate) network_key: ed25519::PublicKey,
    pub(crate) max_dealing_bytes: u32,
}

impl Write for RegistryEntry {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        self.network_key.write(buf);
        self.max_dealing_bytes.write(buf);
    }
}

impl EncodeSize for RegistryEntry {
    fn encode_size(&self) -> usize {
        self.deployment.encode_size()
            + self.network_key.encode_size()
            + self.max_dealing_bytes.encode_size()
    }
}

impl Read for RegistryEntry {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            deployment: Deployment::read(buf)?,
            network_key: ed25519::PublicKey::read(buf)?,
            max_dealing_bytes: u32::read(buf)?,
        })
    }
}

/// Immutable native allocations and admission policy committed by genesis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeGenesis {
    /// Trusted setup commitment for every zero-custody runtime deployment.
    pub(crate) empty_root: StateRoot<Digest>,
    /// Native QMDB history position belonging to `empty_root`.
    pub(crate) empty_operations: u64,
    pub(crate) balances: Vec<Account>,
    pub(crate) deployments: Vec<RegistryEntry>,
    pub(crate) fee_recipient: Key,
    pub(crate) registration_fee: u64,
    pub(crate) epoch_fee: u64,
    pub(crate) max_deployments: u32,
    pub(crate) max_dealing_bytes: u32,
}

impl NativeGenesis {
    /// Checks the fixed supply and every bound used by deterministic execution.
    pub(crate) fn validate(&self) -> bool {
        let mut native_accounts = BTreeSet::new();
        let mut deployments = BTreeSet::new();
        let mut supply = 0u64;
        if self.deployments.is_empty()
            || self.max_deployments == 0
            || self.max_deployments as usize > MAX_DEPLOYMENTS
            || self.deployments.len() > self.max_deployments as usize
            || self.max_dealing_bytes == 0
            || self
                .epoch_fee
                .checked_mul(u64::from(self.max_dealing_bytes).div_ceil(1024))
                .is_none()
        {
            return false;
        }
        for account in &self.balances {
            if !native_accounts.insert(&account.key) {
                return false;
            }
            let Some(total) = supply.checked_add(account.balance) else {
                return false;
            };
            supply = total;
        }
        for entry in &self.deployments {
            if !deployments.insert(entry.deployment.digest())
                || entry.max_dealing_bytes == 0
                || entry.max_dealing_bytes > self.max_dealing_bytes
                || entry.deployment.accounts.len() > MAX_ACCOUNTS
            {
                return false;
            }
            let mut accounts = BTreeSet::new();
            for account in &entry.deployment.accounts {
                if !accounts.insert(&account.key) {
                    return false;
                }
                let Some(total) = supply.checked_add(account.balance) else {
                    return false;
                };
                supply = total;
            }
        }
        true
    }

    /// The immutable chain domain; runtime registry growth never changes it.
    pub(crate) fn chain_id(&self) -> Digest {
        chain_id(self.deployments.iter().map(|entry| &entry.deployment))
    }
}
