use super::{
    keys::{AccountKey, CodeKey, StorageKey},
    model::{AccountRecord, StorageRecord},
};
use commonware_cryptography::sha256::Sha256 as QmdbHasher;
use commonware_runtime::tokio;
use commonware_storage::{
    qmdb::{current, NonDurable},
    translator::EightCap,
};
use commonware_storage::qmdb::current::db::Unmerkleized;

const CURRENT_CHUNK_SIZE: usize = 32;

pub(crate) type Context = tokio::Context;
pub(crate) type AccountStore =
    current::ordered::variable::Db<Context, AccountKey, AccountRecord, QmdbHasher, EightCap, CURRENT_CHUNK_SIZE>;
pub(crate) type StorageStore =
    current::ordered::variable::Db<Context, StorageKey, StorageRecord, QmdbHasher, EightCap, CURRENT_CHUNK_SIZE>;
pub(crate) type CodeStore =
    current::ordered::variable::Db<Context, CodeKey, Vec<u8>, QmdbHasher, EightCap, CURRENT_CHUNK_SIZE>;
pub(crate) type AccountStoreDirty = current::ordered::variable::Db<
    Context,
    AccountKey,
    AccountRecord,
    QmdbHasher,
    EightCap,
    CURRENT_CHUNK_SIZE,
    Unmerkleized,
    NonDurable,
>;
pub(crate) type StorageStoreDirty = current::ordered::variable::Db<
    Context,
    StorageKey,
    StorageRecord,
    QmdbHasher,
    EightCap,
    CURRENT_CHUNK_SIZE,
    Unmerkleized,
    NonDurable,
>;
pub(crate) type CodeStoreDirty = current::ordered::variable::Db<
    Context,
    CodeKey,
    Vec<u8>,
    QmdbHasher,
    EightCap,
    CURRENT_CHUNK_SIZE,
    Unmerkleized,
    NonDurable,
>;
