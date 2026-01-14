use super::{
    keys::{AccountKey, CodeKey, StorageKey},
    model::{AccountRecord, StorageRecord},
};
use commonware_cryptography::sha256::Sha256 as QmdbHasher;
use commonware_runtime::tokio;
use commonware_storage::{
    qmdb::{any, NonDurable, Unmerkleized},
    translator::EightCap,
};

pub(crate) type Context = tokio::Context;
pub(crate) type AccountStore =
    any::unordered::variable::Db<Context, AccountKey, AccountRecord, QmdbHasher, EightCap>;
pub(crate) type StorageStore =
    any::unordered::variable::Db<Context, StorageKey, StorageRecord, QmdbHasher, EightCap>;
pub(crate) type CodeStore =
    any::unordered::variable::Db<Context, CodeKey, Vec<u8>, QmdbHasher, EightCap>;
pub(crate) type AccountStoreDirty = any::unordered::variable::Db<
    Context,
    AccountKey,
    AccountRecord,
    QmdbHasher,
    EightCap,
    Unmerkleized,
    NonDurable,
>;
pub(crate) type StorageStoreDirty = any::unordered::variable::Db<
    Context,
    StorageKey,
    StorageRecord,
    QmdbHasher,
    EightCap,
    Unmerkleized,
    NonDurable,
>;
pub(crate) type CodeStoreDirty = any::unordered::variable::Db<
    Context,
    CodeKey,
    Vec<u8>,
    QmdbHasher,
    EightCap,
    Unmerkleized,
    NonDurable,
>;
