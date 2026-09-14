//! Incremental account balances and retained Current Ordered proofs.
//!
//! Each epoch appends one canonical MMB batch. The application persists accepted mutations
//! and close evidence before publishing votes; committing this owner persists only its
//! database. Native commit metadata stores the balance liability. Historical Current proofs
//! use a read-only native view over retained operations.
//! Constructing that view can require work proportional to the historical active log window.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::{Sequential, Strategy};
use commonware_runtime::Spawner;
use commonware_storage::{
    Context,
    merkle::{Location, mmb},
    qmdb::{
        self,
        any::{ordered::Update, value::FixedEncoding},
        current::{
            FixedConfig,
            batch::MerkleizedBatch,
            ordered::{self, fixed::Db},
        },
    },
    translator::EightCap,
};
use commonware_utils::sequence::FixedBytes;
use core::num::NonZeroU64;
use std::sync::Arc;
use thiserror::Error;

/// Canonical bytes of a live account's public key.
pub type AccountKey = FixedBytes<32>;
/// A live account's positive balance, encoded in eight bytes.
pub type Balance = NonZeroU64;
/// Account-sorted writes, with absence represented by deletion.
pub type Mutations = Vec<(AccountKey, Option<Balance>)>;
/// Current membership proof for a balance under an MMB root.
pub type Membership<D> = ordered::fixed::KeyValueProof<mmb::Family, AccountKey, D, 32>;
/// Current ordered absence proof under an MMB root.
pub type Absence<D> =
    ordered::ExclusionProof<mmb::Family, AccountKey, FixedEncoding<Balance>, D, 32>;
type BalanceDb<E, H, S> = Db<mmb::Family, E, AccountKey, Balance, H, EightCap, 32, S>;
type Batch<D, S> =
    MerkleizedBatch<mmb::Family, D, Update<AccountKey, FixedEncoding<Balance>>, 32, S>;

/// A Current account-state commitment, independent of the lengths of per-close BMTs.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StateRoot<D: Digest> {
    /// Canonical Current root digest.
    pub digest: D,
}

impl<D: Digest> StateRoot<D> {
    /// Wrap an externally authenticated Current root.
    pub const fn new(digest: D) -> Self {
        Self { digest }
    }
}

impl<D: Digest> Write for StateRoot<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.digest.write(buf);
    }
}
impl<D: Digest> FixedSize for StateRoot<D> {
    const SIZE: usize = D::SIZE;
}
impl<D: Digest> Read for StateRoot<D> {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self::new(D::read(buf)?))
    }
}

/// Locally derived totals bound to one exact database prefix.
///
/// Construction requires canonical initialization or native recovery. A root supplied with arbitrary
/// liability and count values cannot be converted into a validated head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateHead<D: Digest> {
    root: StateRoot<D>,
    liability: u64,
    live_accounts: u64,
    operations: Location<mmb::Family>,
}

impl<D: Digest> StateHead<D> {
    /// Returns the Current root.
    pub const fn root(&self) -> StateRoot<D> {
        self.root
    }
    /// Returns the checked sum of current balances.
    pub const fn liability(&self) -> u64 {
        self.liability
    }
    /// Returns the number of positive balances.
    pub const fn live_accounts(&self) -> u64 {
        self.live_accounts
    }
    /// Returns the operation count committed by this root.
    pub fn operations(&self) -> u64 {
        *self.operations
    }
}

/// Physical configuration for the account database.
pub type Config<S> = FixedConfig<EightCap, S>;

/// A candidate balance transition bound to its exact predecessor.
///
/// Constructed by [`State::prepare`] and consumed by [`State::apply`].
pub struct PreparedState<D: Digest, S: Strategy = Sequential> {
    predecessor: StateHead<D>,
    head: StateHead<D>,
    mutations: Mutations,
    batch: Arc<Batch<D, S>>,
}

impl<D: Digest, S: Strategy> PreparedState<D, S> {
    /// Returns the predecessor against which this candidate was derived.
    pub const fn predecessor(&self) -> &StateHead<D> {
        &self.predecessor
    }
    /// Returns the candidate root and locally derived totals.
    pub const fn head(&self) -> &StateHead<D> {
        &self.head
    }
    /// Returns the candidate Current root.
    pub const fn root(&self) -> StateRoot<D> {
        self.head.root
    }
    /// Returns only writes that change a balance.
    pub fn mutations(&self) -> &[(AccountKey, Option<Balance>)] {
        &self.mutations
    }
}

/// A full balance replica with a native recovered head.
///
/// Mutable operations consume the owner. After failure or cancellation, reopen and bind the
/// recovered head to the application's accepted journal before applying its missing suffix.
/// Historical proofs use retained native operations; no pruning is exposed.
pub struct State<E: Context + Spawner, H: Hasher, S: Strategy = Sequential> {
    db: BalanceDb<E, H, S>,
    #[cfg(test)]
    pause_historical: std::sync::atomic::AtomicBool,
    head: StateHead<H::Digest>,
}

impl<E: Context + Spawner, H: Hasher, S: Strategy> State<E, H, S> {
    /// Initialize a fresh database from account-sorted positive genesis balances.
    ///
    /// Existing application state must be opened with [`Self::open`]. Applications that persist
    /// genesis before applying it can prepare that first batch against the open bootstrap head.
    pub async fn init(
        context: E,
        config: Config<S>,
        genesis: Vec<(AccountKey, Balance)>,
    ) -> Result<Self, Error> {
        let state = Self::open(context, config).await?;
        if !state.is_bootstrap() {
            return Err(Error::Initialized);
        }
        let mutations = genesis
            .into_iter()
            .map(|(key, value)| (key, Some(value)))
            .collect();
        let prepared = state.prepare(state.head(), mutations).await?;
        state.apply(prepared).await
    }

    /// Open the native database and recover its root-bound liability and active account count.
    ///
    /// Partitions belong exclusively to this owner. The application binds the recovered root
    /// and operation count to its accepted journal, then applies only the missing suffix.
    /// A fresh database exposes the empty bootstrap head until its genesis batch is applied.
    pub async fn open(context: E, config: Config<S>) -> Result<Self, Error> {
        let mut partitions = Vec::with_capacity(8);
        for journal in [
            &config.merkle_config.journal_partition,
            &config.journal_config.partition,
        ] {
            partitions.extend([
                journal.clone(),
                format!("{journal}-blobs"),
                format!("{journal}-metadata"),
            ]);
        }
        partitions.extend([
            config.merkle_config.metadata_partition.clone(),
            config.grafted_metadata_partition.clone(),
        ]);
        partitions.sort_unstable();
        if partitions.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::Partition);
        }
        let db = BalanceDb::init(context.child("balances"), config).await?;
        let head = StateHead {
            root: StateRoot::new(db.root()),
            liability: db.get_metadata().await?.map_or(0, Balance::get),
            live_accounts: u64::try_from(db.active_keys()).map_err(|_| Error::Arithmetic)?,
            operations: db.bounds().end,
        };
        Ok(Self {
            db,
            #[cfg(test)]
            pause_historical: std::sync::atomic::AtomicBool::new(false),
            head,
        })
    }

    /// Whether this database still contains only its initial native operation.
    pub fn is_bootstrap(&self) -> bool {
        self.head.operations == Location::new(1)
    }

    /// Returns the validated live head.
    pub const fn head(&self) -> &StateHead<H::Digest> {
        &self.head
    }
    /// Returns the live Current root.
    pub const fn root(&self) -> StateRoot<H::Digest> {
        self.head().root
    }
    /// Returns the sum of current balances.
    pub const fn liability(&self) -> u64 {
        self.head().liability
    }
    /// Returns the number of live accounts.
    pub const fn live_accounts(&self) -> u64 {
        self.head().live_accounts
    }
    /// Returns a balance, or absence for an account with no live balance.
    pub async fn get(&self, key: &AccountKey) -> Result<Option<Balance>, Error> {
        Ok(self.db.get(key).await?)
    }
    /// Reads balances in the requested order without scanning unrelated accounts.
    pub async fn get_many(&self, keys: &[&AccountKey]) -> Result<Vec<Option<Balance>>, Error> {
        Ok(self.db.get_many(keys).await?)
    }

    /// Prepare one epoch's account-sorted updates against the exact predecessor.
    ///
    /// The caller derives and authorizes balances from the close's signed evidence. Duplicate or
    /// unsorted keys are rejected; equal old and new balances are omitted from the QMDB writes.
    /// Empty updates still produce the epoch's single commit operation.
    pub async fn prepare(
        &self,
        predecessor: &StateHead<H::Digest>,
        updates: Mutations,
    ) -> Result<PreparedState<H::Digest, S>, Error> {
        if predecessor != self.head() {
            return Err(Error::Predecessor);
        }
        if updates.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(Error::Order);
        }
        let db = &self.db;
        let keys = updates.iter().map(|(key, _)| key).collect::<Vec<_>>();
        let previous = db.get_many(&keys).await?;
        let mut removed = 0u128;
        let mut added = 0u128;
        let mut live_accounts = i128::from(predecessor.live_accounts);
        let mut mutations = Vec::with_capacity(updates.len());
        let mut batch = db.new_batch();
        for ((key, value), old) in updates.into_iter().zip(previous) {
            if value == old {
                continue;
            }
            removed += u128::from(old.map_or(0, Balance::get));
            added += u128::from(value.map_or(0, Balance::get));
            live_accounts += i128::from(value.is_some()) - i128::from(old.is_some());
            batch = batch.write(key.clone(), value);
            mutations.push((key, value));
        }
        let liability = u128::from(predecessor.liability)
            .checked_sub(removed)
            .and_then(|value| value.checked_add(added))
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(Error::Arithmetic)?;
        let live_accounts = u64::try_from(live_accounts).map_err(|_| Error::Arithmetic)?;
        let batch = batch.merkleize(db, Balance::new(liability)).await?;
        let head = StateHead {
            root: StateRoot::new(batch.root()),
            liability,
            live_accounts,
            operations: batch.bounds().tip.size,
        };
        Ok(PreparedState {
            predecessor: *predecessor,
            head,
            mutations,
            batch,
        })
    }

    /// Apply the candidate to the account database and retain its accepted head.
    ///
    /// This does not make the state durable. A failure or cancellation consumes the owner.
    pub async fn apply(mut self, prepared: PreparedState<H::Digest, S>) -> Result<Self, Error> {
        if prepared.predecessor != *self.head() {
            return Err(Error::Predecessor);
        }
        (self.db, _) = self.db.apply_batch(prepared.batch).await?;
        self.head = prepared.head;
        Ok(self)
    }

    /// Persist the database; the application also persists history and close evidence.
    pub async fn commit(mut self) -> Result<Self, Error> {
        self.db = self.db.commit().await?;
        Ok(self)
    }

    /// Prove the current balance or absence of `key`.
    pub async fn lookup(&self, key: &AccountKey) -> Result<StateLookup<H::Digest>, Error> {
        match self.db.get(key).await? {
            Some(balance) => Ok(StateLookup::Present(StateValueOpening {
                balance,
                proof: self.db.key_value_proof(key.clone()).await?,
            })),
            None => Ok(StateLookup::Absent(self.db.exclusion_proof(key).await?)),
        }
    }

    /// Prove a live account's current balance.
    pub async fn opening<P: PublicKey>(
        &self,
        account: P,
    ) -> Result<StateOpening<P, H::Digest>, Error> {
        self.lookup(&account_key(&account)?).await?.opening(account)
    }

    /// Prove a balance or absence at a retained root without mutating the database.
    ///
    /// Historical views reconstruct native Current activity and grafted proof material on demand.
    /// Their work can grow with the historical active log window; cancellation only drops the view.
    pub async fn lookup_at(
        &self,
        root: StateRoot<H::Digest>,
        operations: u64,
        key: &AccountKey,
    ) -> Result<StateLookup<H::Digest>, Error> {
        if root == self.root() {
            if operations != self.head.operations() {
                return Err(Error::History);
            }
            return self.lookup(key).await;
        }
        let view = self.db.historical_view(Location::new(operations)).await?;
        if view.root() != root.digest {
            return Err(Error::History);
        }
        #[cfg(test)]
        if self
            .pause_historical
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            std::future::pending::<()>().await;
        }
        match view.get(key) {
            Some(balance) => Ok(StateLookup::Present(StateValueOpening {
                balance: *balance,
                proof: view.key_value_proof(key.clone()).await?,
            })),
            None => Ok(StateLookup::Absent(view.exclusion_proof(key).await?)),
        }
    }

    /// Prove a live account at a retained root, preserving live state on query errors.
    pub async fn opening_at<P: PublicKey>(
        &self,
        root: StateRoot<H::Digest>,
        operations: u64,
        account: P,
    ) -> Result<StateOpening<P, H::Digest>, Error> {
        let key = account_key(&account)?;
        self.lookup_at(root, operations, &key)
            .await?
            .opening(account)
    }
}

/// Convert the canonical account encoding without hashing, padding, or truncation.
pub fn account_key<P: PublicKey>(account: &P) -> Result<AccountKey, Error> {
    let bytes: [u8; 32] = account.as_ref().try_into().map_err(|_| Error::AccountKey)?;
    Ok(AccountKey::new(bytes))
}

/// Complete membership claim for a live account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateOpening<P: PublicKey, D: Digest> {
    /// Account whose balance is authenticated.
    pub account: P,
    /// Positive balance at the requested root.
    pub balance: Balance,
    /// Current membership proof for the account key.
    pub proof: Membership<D>,
}

impl<P: PublicKey, D: Digest> StateOpening<P, D> {
    /// Verify this account's positive balance against the caller's trusted root.
    pub fn verify<H: Hasher<Digest = D>>(&self, root: &StateRoot<D>) -> Result<Balance, Error> {
        let key = account_key(&self.account)?;
        if !self
            .proof
            .verify::<H, FixedEncoding<Balance>>(key, self.balance, &root.digest)
        {
            return Err(Error::Proof);
        }
        Ok(self.balance)
    }
}

/// Membership opening when the account key is supplied by the lookup request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateValueOpening<D: Digest> {
    /// Positive balance at the requested root.
    pub balance: Balance,
    /// Current membership proof for the request account.
    pub proof: Membership<D>,
}

/// Current membership or ordered absence for a request account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateLookup<D: Digest> {
    /// Authenticated positive balance.
    Present(StateValueOpening<D>),
    /// Authenticated absence.
    Absent(Absence<D>),
}

impl<D: Digest> StateLookup<D> {
    /// Verify the request's exact key and trusted root.
    pub fn resolve<H: Hasher<Digest = D>>(
        &self,
        root: &StateRoot<D>,
        key: &AccountKey,
    ) -> Result<Option<Balance>, Error> {
        match self {
            Self::Present(value)
                if value.proof.verify::<H, FixedEncoding<Balance>>(
                    key.clone(),
                    value.balance,
                    &root.digest,
                ) =>
            {
                Ok(Some(value.balance))
            }
            Self::Absent(proof) if proof.verify::<H>(key, &root.digest) => Ok(None),
            _ => Err(Error::Proof),
        }
    }

    fn opening<P: PublicKey>(self, account: P) -> Result<StateOpening<P, D>, Error> {
        match self {
            Self::Present(value) => Ok(StateOpening {
                account,
                balance: value.balance,
                proof: value.proof,
            }),
            Self::Absent(_) => Err(Error::Absent),
        }
    }
}

impl<P: PublicKey, D: Digest> Write for StateOpening<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.balance.write(buf);
        self.proof.write(buf);
    }
}
impl<P: PublicKey, D: Digest> EncodeSize for StateOpening<P, D> {
    fn encode_size(&self) -> usize {
        P::SIZE + Balance::SIZE + self.proof.encode_size()
    }
}
impl<P: PublicKey, D: Digest> Read for StateOpening<P, D> {
    type Cfg = usize;
    fn read_cfg(buf: &mut impl Buf, max_digests: &usize) -> Result<Self, CodecError> {
        Ok(Self {
            account: P::read(buf)?,
            balance: Balance::read(buf)?,
            proof: Membership::read_cfg(buf, &(*max_digests, ()))?,
        })
    }
}
impl<D: Digest> Write for StateValueOpening<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.balance.write(buf);
        self.proof.write(buf);
    }
}
impl<D: Digest> EncodeSize for StateValueOpening<D> {
    fn encode_size(&self) -> usize {
        Balance::SIZE + self.proof.encode_size()
    }
}
impl<D: Digest> Read for StateValueOpening<D> {
    type Cfg = usize;
    fn read_cfg(buf: &mut impl Buf, max_digests: &usize) -> Result<Self, CodecError> {
        Ok(Self {
            balance: Balance::read(buf)?,
            proof: Membership::read_cfg(buf, &(*max_digests, ()))?,
        })
    }
}
impl<D: Digest> Write for StateLookup<D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Present(value) => {
                0u8.write(buf);
                value.write(buf);
            }
            Self::Absent(proof) => {
                1u8.write(buf);
                proof.write(buf);
            }
        }
    }
}
impl<D: Digest> EncodeSize for StateLookup<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Present(value) => value.encode_size(),
            Self::Absent(proof) => proof.encode_size(),
        }
    }
}
impl<D: Digest> Read for StateLookup<D> {
    type Cfg = usize;
    fn read_cfg(buf: &mut impl Buf, max_digests: &usize) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Present(StateValueOpening::read_cfg(
                buf,
                max_digests,
            )?)),
            1 => Ok(Self::Absent(Absence::read_cfg(
                buf,
                &(*max_digests, (), ()),
            )?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(feature = "arbitrary")]
mod arbitrary_impls {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};

    impl<'a, P, D> Arbitrary<'a> for StateOpening<P, D>
    where
        P: PublicKey + Arbitrary<'a>,
        D: Digest + for<'b> Arbitrary<'b>,
    {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                account: u.arbitrary()?,
                balance: u.arbitrary()?,
                proof: u.arbitrary()?,
            })
        }
    }

    impl<'a, D: Digest + for<'b> Arbitrary<'b>> Arbitrary<'a> for StateValueOpening<D> {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                balance: u.arbitrary()?,
                proof: u.arbitrary()?,
            })
        }
    }

    impl<'a, D: Digest + for<'b> Arbitrary<'b>> Arbitrary<'a> for StateLookup<D> {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            if u.arbitrary()? {
                Ok(Self::Present(u.arbitrary()?))
            } else {
                Ok(Self::Absent(u.arbitrary()?))
            }
        }
    }
}

/// Failure to construct, advance, or prove canonical balance state.
#[derive(Debug, Error)]
pub enum Error {
    /// A database operation failed; consuming methods invalidate the entire owner.
    #[error("balance storage: {0}")]
    Storage(#[from] qmdb::Error<mmb::Family>),
    /// Account keys must contain exactly 32 canonical bytes.
    #[error("account key must contain exactly 32 bytes")]
    AccountKey,
    /// Database partitions overlap.
    #[error("database partitions must be distinct")]
    Partition,
    /// Mutations are not strictly ordered by account key.
    #[error("balance mutations are not strictly account-sorted")]
    Order,
    /// A candidate belongs to another database prefix.
    #[error("balance predecessor does not match")]
    Predecessor,
    /// Liability or live-account arithmetic is out of range.
    #[error("balance totals overflow")]
    Arithmetic,
    /// The requested root and operation count do not identify the same native prefix.
    #[error("balance root does not match operation count")]
    History,
    /// Genesis initialization was requested for an existing application prefix.
    #[error("balance state is already initialized")]
    Initialized,
    /// A membership opening was requested for an absent account.
    #[error("account is absent at the requested root")]
    Absent,
    /// A proof does not authenticate the request key and root.
    #[error("invalid balance proof")]
    Proof,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode as _, DecodeExt as _, Encode as _};
    use commonware_cryptography::{Sha256, Signer as _, ed25519, sha256::Digest as ShaDigest};
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{
        journal::contiguous::fixed::Config as JournalConfig, merkle::full::Config as MerkleConfig,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, probability};
    use std::{future::Future as _, task::Poll};

    type TestState = State<deterministic::Context, Sha256>;

    fn key(value: u64) -> AccountKey {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&value.to_be_bytes());
        AccountKey::new(bytes)
    }

    fn balance(value: u64) -> Balance {
        Balance::new(value).unwrap()
    }

    fn config(context: &deterministic::Context, prefix: &str) -> Config<Sequential> {
        let cache = CacheRef::from_pooler(context, NZU16!(4096), NZUsize!(4));
        FixedConfig {
            merkle_config: MerkleConfig {
                journal_partition: format!("{prefix}-balances-merkle"),
                metadata_partition: format!("{prefix}-balances-merkle-meta"),
                items_per_blob: NZU64!(256),
                write_buffer: NZUsize!(4096),
                strategy: Sequential,
                page_cache: cache.clone(),
            },
            journal_config: JournalConfig {
                partition: format!("{prefix}-balances-operations"),
                items_per_blob: NZU64!(256),
                write_buffer: NZUsize!(4096),
                page_cache: cache,
            },
            grafted_metadata_partition: format!("{prefix}-balances-grafts"),
            translator: EightCap,
            init_cache_size: Some(NZUsize!(64)),
            init_buffer: NZUsize!(4096),
            init_concurrency: (),
        }
    }

    async fn apply(state: TestState, updates: Mutations) -> TestState {
        let prepared = state.prepare(state.head(), updates).await.unwrap();
        state.apply(prepared).await.unwrap()
    }

    #[test]
    fn reopening_uses_recovered_head_without_application_replay() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config(&context, "native-head");
            let state = TestState::init(
                context.child("state"),
                cfg.clone(),
                vec![(key(1), balance(100))],
            )
            .await
            .unwrap();
            let state = apply(
                state,
                vec![(key(1), Some(balance(90))), (key(2), Some(balance(10)))],
            )
            .await
            .commit()
            .await
            .unwrap();
            let expected = *state.head();
            drop(state);
            let state = TestState::open(context.child("state"), cfg).await.unwrap();
            assert_eq!(*state.head(), expected);
            assert_eq!(state.db.get_metadata().await.unwrap(), Some(balance(100)));
        });
    }

    #[test]
    fn canonical_sparse_epochs_and_independent_replicas() {
        deterministic::Runner::default().start(|context| async move {
            let genesis = vec![(key(2), balance(10)), (key(4), balance(20))];
            let mut first = TestState::init(
                context.child("first"),
                config(&context, "first"),
                genesis.clone(),
            )
            .await
            .unwrap();
            let mut second =
                TestState::init(context.child("second"), config(&context, "second"), genesis)
                    .await
                    .unwrap();
            assert_eq!(first.head(), second.head());
            assert_eq!(first.liability(), 30);
            assert_eq!(first.live_accounts(), 2);
            let root = first.root();
            let initial_operations = first.head().operations();
            assert!(matches!(
                first
                    .prepare(
                        first.head(),
                        vec![(key(2), None), (key(2), Some(balance(1)))]
                    )
                    .await,
                Err(Error::Order)
            ));
            assert!(matches!(
                first
                    .prepare(first.head(), vec![(key(4), None), (key(2), None)])
                    .await,
                Err(Error::Order)
            ));
            assert_eq!(first.root(), root);

            let unchanged = first
                .prepare(
                    first.head(),
                    vec![(key(2), Some(balance(10))), (key(3), None)],
                )
                .await
                .unwrap();
            assert!(unchanged.mutations().is_empty());
            first = first.apply(unchanged).await.unwrap();
            second = apply(second, vec![]).await;
            assert_eq!(first.head(), second.head());
            assert_ne!(first.root(), root);
            assert!(first.head().operations() > initial_operations);

            for updates in [
                vec![
                    (key(1), Some(balance(7))),
                    (key(2), None),
                    (key(4), Some(balance(23))),
                ],
                vec![(key(1), None), (key(2), Some(balance(10))), (key(4), None)],
                vec![(key(2), None)],
            ] {
                first = apply(first, updates.clone()).await;
                second = apply(second, updates).await;
                assert_eq!(first.head(), second.head());
                for requested in [key(0), key(1), key(2), key(4), key(u64::MAX)] {
                    let expected = first.get(&requested).await.unwrap();
                    assert_eq!(
                        first
                            .lookup(&requested)
                            .await
                            .unwrap()
                            .resolve::<Sha256>(&first.root(), &requested)
                            .unwrap(),
                        expected
                    );
                }
            }
            assert_eq!(first.liability(), 0);
            assert_eq!(first.live_accounts(), 0);
        });
    }

    #[test]
    fn liability_checks_net_changes_without_order_dependent_overflow() {
        deterministic::Runner::default().start(|context| async move {
            let state = TestState::init(
                context.child("state"),
                config(&context, "maximum"),
                vec![(key(2), balance(u64::MAX))],
            )
            .await
            .unwrap();
            assert!(matches!(
                state
                    .prepare(state.head(), vec![(key(1), Some(balance(1)))])
                    .await,
                Err(Error::Arithmetic)
            ));
            let state = apply(
                state,
                vec![(key(1), Some(balance(u64::MAX))), (key(2), None)],
            )
            .await;
            assert_eq!(state.liability(), u64::MAX);
            assert_eq!(state.live_accounts(), 1);
        });
    }

    #[test]
    fn retained_roots_survive_updates_deletes_and_reinsertion() {
        deterministic::Runner::default().start(|context| async move {
            let genesis = (0..600)
                .map(|index| (key(index * 2), balance(100)))
                .collect();
            let mut state = TestState::init(
                context.child("state"),
                config(&context, "retained"),
                genesis,
            )
            .await
            .unwrap();
            let frozen = *state.head();
            let mut checkpoints = vec![(frozen, Some(balance(100)), None)];
            for updates in [
                vec![(key(2), Some(balance(99))), (key(3), Some(balance(1)))],
                vec![(key(2), None), (key(3), Some(balance(100)))],
                vec![(key(2), Some(balance(100))), (key(3), None)],
                vec![],
            ] {
                state = apply(state, updates).await;
                checkpoints.push((
                    *state.head(),
                    state.get(&key(2)).await.unwrap(),
                    state.get(&key(3)).await.unwrap(),
                ));
            }
            let head = *state.head();
            // Settlement may keep any of these pending after its own deadline; serving is
            // addressed by retained roots and never evicted merely because time advanced.
            for (saved, second, third) in checkpoints.into_iter().rev() {
                for (requested, expected) in [(key(2), second), (key(3), third)] {
                    let proof = state
                        .lookup_at(saved.root(), saved.operations(), &requested)
                        .await
                        .unwrap();
                    assert_eq!(
                        proof.resolve::<Sha256>(&saved.root(), &requested).unwrap(),
                        expected
                    );
                    assert_eq!(*state.head(), head);
                }
            }
            assert_eq!(
                state
                    .lookup_at(frozen.root(), frozen.operations(), &key(2))
                    .await
                    .unwrap()
                    .resolve::<Sha256>(&frozen.root(), &key(2))
                    .unwrap(),
                Some(balance(100))
            );
            let unknown = StateRoot::new(Sha256::hash(&[b"unknown root"]));
            assert!(matches!(
                state.lookup_at(unknown, frozen.operations(), &key(2)).await,
                Err(Error::History)
            ));
            assert_eq!(*state.head(), head);
            state = apply(state, vec![(key(2), Some(balance(98)))]).await;
            assert_eq!(state.get(&key(2)).await.unwrap(), Some(balance(98)));
        });
    }

    #[test]
    fn proof_codecs_bind_account_value_root_and_positive_balance() {
        deterministic::Runner::default().start(|context| async move {
            let secret = ed25519::PrivateKey::decode(&[7u8; 32][..]).unwrap();
            let account = secret.public_key();
            let account_bytes = account_key(&account).unwrap();
            let state = TestState::init(
                context.child("state"),
                config(&context, "codecs"),
                vec![(account_bytes.clone(), balance(50))],
            )
            .await
            .unwrap();
            let opening = state.opening(account.clone()).await.unwrap();
            let encoded = opening.encode();
            assert_eq!(encoded.len(), opening.encode_size());
            let decoded =
                StateOpening::<ed25519::PublicKey, ShaDigest>::decode_cfg(encoded.clone(), &128)
                    .unwrap();
            assert_eq!(decoded, opening);
            assert_eq!(
                decoded.verify::<Sha256>(&state.root()).unwrap(),
                balance(50)
            );
            let mut zero = encoded.to_vec();
            zero[32..40].fill(0);
            assert!(
                StateOpening::<ed25519::PublicKey, ShaDigest>::decode_cfg(zero.as_slice(), &128)
                    .is_err()
            );
            for len in [0, 31, 39, encoded.len() - 1] {
                assert!(
                    StateOpening::<ed25519::PublicKey, ShaDigest>::decode_cfg(
                        &encoded[..len],
                        &128
                    )
                    .is_err()
                );
            }
            let mut trailing = encoded.to_vec();
            trailing.push(0);
            assert!(
                StateOpening::<ed25519::PublicKey, ShaDigest>::decode_cfg(
                    trailing.as_slice(),
                    &128
                )
                .is_err()
            );
            assert!(
                decoded
                    .verify::<Sha256>(&StateRoot::new(Sha256::hash(&[b"other root"])))
                    .is_err()
            );
            let mut changed = decoded.clone();
            changed.balance = balance(51);
            assert!(changed.verify::<Sha256>(&state.root()).is_err());
            let other = ed25519::PrivateKey::decode(&[8u8; 32][..])
                .unwrap()
                .public_key();
            changed = decoded;
            changed.account = other.clone();
            assert!(changed.verify::<Sha256>(&state.root()).is_err());
            let root = state.root();
            assert!(matches!(
                state
                    .opening_at(root, state.head().operations(), other)
                    .await,
                Err(Error::Absent)
            ));
            assert_eq!(state.root(), root);
            for requested in [key(0), account_bytes, key(u64::MAX)] {
                let proof = state.lookup(&requested).await.unwrap();
                let bytes = proof.encode();
                let decoded = StateLookup::<ShaDigest>::decode_cfg(bytes, &128).unwrap();
                assert_eq!(proof, decoded);
                assert_eq!(
                    decoded.resolve::<Sha256>(&root, &requested).unwrap(),
                    state.get(&requested).await.unwrap()
                );
            }
        });
    }

    #[test]
    fn open_recovers_after_consuming_commit_failure() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config(&context, "sync-failure");
            let state = TestState::init(
                context.child("state"),
                cfg.clone(),
                vec![(key(1), balance(100))],
            )
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
            let old = *state.head();
            let updates = vec![(key(1), Some(balance(90))), (key(2), Some(balance(10)))];
            let state = apply(state, updates.clone()).await;
            let target = *state.head();
            *context.storage_fault_config().write() =
                deterministic::FaultConfig::default().sync(probability!(1.0));
            assert!(matches!(state.commit().await, Err(Error::Storage(_))));
            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            let state = TestState::open(context.child("reopened"), cfg)
                .await
                .unwrap();
            let state = if state.head() == &old {
                apply(state, updates).await
            } else {
                assert_eq!(*state.head(), target);
                state
            };
            assert_eq!(*state.head(), target);
            let proof = state
                .lookup_at(old.root(), old.operations(), &key(1))
                .await
                .unwrap();
            assert_eq!(
                proof.resolve::<Sha256>(&old.root(), &key(1)).unwrap(),
                Some(balance(100))
            );
        });
    }

    #[test]
    fn cancelled_history_query_leaves_live_state_usable() {
        deterministic::Runner::default().start(|context| async move {
            let genesis = (0..600).map(|index| (key(index), balance(100))).collect();
            let mut state =
                TestState::init(context.child("state"), config(&context, "cancel"), genesis)
                    .await
                    .unwrap()
                    .commit()
                    .await
                    .unwrap();
            let old = *state.head();
            state = apply(
                state,
                (0..600)
                    .map(|index| (key(index), Some(balance(99))))
                    .collect(),
            )
            .await;
            let head = *state.head();
            let requested = key(2);
            state
                .pause_historical
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let mut query = Box::pin(state.lookup_at(old.root(), old.operations(), &requested));
            std::future::poll_fn(|cx| {
                assert!(query.as_mut().poll(cx).is_pending());
                if state
                    .pause_historical
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
            drop(query);
            assert_eq!(*state.head(), head);
            assert_eq!(state.get(&requested).await.unwrap(), Some(balance(99)));
            state = apply(state, vec![(key(2), Some(balance(98)))])
                .await
                .commit()
                .await
                .unwrap();
            let proof = state
                .lookup_at(old.root(), old.operations(), &requested)
                .await
                .unwrap();
            assert_eq!(
                proof.resolve::<Sha256>(&old.root(), &requested).unwrap(),
                Some(balance(100))
            );
            assert_eq!(state.get(&requested).await.unwrap(), Some(balance(98)));
        });
    }

    #[test]
    fn historical_queries_do_not_write() {
        deterministic::Runner::default().start(|context| async move {
            let genesis = (0..600).map(|index| (key(index), balance(100))).collect();
            let mut state = TestState::init(
                context.child("state"),
                config(&context, "query-failure"),
                genesis,
            )
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
            let old = *state.head();
            state = apply(
                state,
                (0..600)
                    .map(|index| (key(index), Some(balance(99))))
                    .collect(),
            )
            .await;
            let head = *state.head();
            *context.storage_fault_config().write() =
                deterministic::FaultConfig::default().write(deterministic::WriteConfig {
                    failure_rate: probability!(1.0),
                    retention_rate: probability!(0.0),
                    mode: deterministic::PartialWriteMode::Prefix,
                });
            let proof = state
                .lookup_at(old.root(), old.operations(), &key(2))
                .await
                .unwrap();
            assert_eq!(
                proof.resolve::<Sha256>(&old.root(), &key(2)).unwrap(),
                Some(balance(100))
            );
            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            assert_eq!(*state.head(), head);
            assert_eq!(state.get(&key(2)).await.unwrap(), Some(balance(99)));
            let proof = state
                .lookup_at(old.root(), old.operations(), &key(2))
                .await
                .unwrap();
            assert_eq!(
                proof.resolve::<Sha256>(&old.root(), &key(2)).unwrap(),
                Some(balance(100))
            );
            assert_eq!(*state.head(), head);
        });
    }

    #[test]
    fn restart_retains_pending_proofs_without_replaying_applied_batches() {
        let ((expected, frozen), checkpoint) =
            deterministic::Runner::default().start_and_recover(|context| async move {
                let state = TestState::init(
                    context.child("state"),
                    config(&context, "restart"),
                    vec![(key(1), balance(100))],
                )
                .await
                .unwrap()
                .commit()
                .await
                .unwrap();
                let frozen = *state.head();
                let state = apply(
                    state,
                    vec![(key(1), Some(balance(90))), (key(2), Some(balance(10)))],
                )
                .await
                .commit()
                .await
                .unwrap();
                (*state.head(), frozen)
            });
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let state = TestState::open(context.child("reopened"), config(&context, "restart"))
                .await
                .unwrap();
            assert_eq!(*state.head(), expected);
            let proof = state
                .lookup_at(frozen.root(), frozen.operations(), &key(1))
                .await
                .unwrap();
            assert_eq!(
                proof.resolve::<Sha256>(&frozen.root(), &key(1)).unwrap(),
                Some(balance(100))
            );
            let state = apply(state, vec![(key(2), Some(balance(9)))]).await;
            assert_eq!(state.liability(), 99);
        });
    }

    #[test]
    fn zero_and_maximum_liability_recover_from_native_metadata() {
        deterministic::Runner::default().start(|context| async move {
            for total in [0, u64::MAX] {
                let cfg = config(&context, &format!("total-{total}"));
                let genesis = Balance::new(total)
                    .map(|value| (key(1), value))
                    .into_iter()
                    .collect();
                let state = TestState::init(context.child("state"), cfg.clone(), genesis)
                    .await
                    .unwrap();
                assert!(!state.is_bootstrap());
                let state = apply(state, vec![]).await.commit().await.unwrap();
                let expected = *state.head();
                drop(state);
                let state = TestState::open(context.child("reopened"), cfg)
                    .await
                    .unwrap();
                assert_eq!(*state.head(), expected);
                assert_eq!(state.liability(), total);
                assert_eq!(state.db.get_metadata().await.unwrap(), Balance::new(total));
                assert_eq!(state.live_accounts(), u64::from(total != 0));
            }
        });
    }

    #[test]
    fn latest_root_skips_historical_reconstruction() {
        deterministic::Runner::default().start(|context| async move {
            let state = TestState::init(
                context.child("state"),
                config(&context, "latest"),
                vec![(key(1), balance(10))],
            )
            .await
            .unwrap();
            state
                .pause_historical
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let proof = state
                .lookup_at(state.root(), state.head().operations(), &key(1))
                .await
                .unwrap();
            assert_eq!(
                proof.resolve::<Sha256>(&state.root(), &key(1)).unwrap(),
                Some(balance(10))
            );
            assert!(
                state
                    .pause_historical
                    .load(std::sync::atomic::Ordering::SeqCst)
            );
        });
    }

    #[test]
    fn opening_leaves_an_unapplied_candidate_for_the_application() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config(&context, "accepted-suffix");
            let state = TestState::init(
                context.child("state"),
                cfg.clone(),
                vec![(key(1), balance(10))],
            )
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
            let predecessor = *state.head();
            let candidate = state
                .prepare(
                    state.head(),
                    vec![(key(1), Some(balance(8))), (key(2), Some(balance(2)))],
                )
                .await
                .unwrap();
            let target = *candidate.head();
            let mutations = candidate.mutations().to_vec();
            drop(candidate);
            drop(state);
            let state = TestState::open(context.child("reopened"), cfg)
                .await
                .unwrap();
            assert_eq!(*state.head(), predecessor);
            let state = apply(state, mutations).await;
            assert_eq!(*state.head(), target);
        });
    }

    #[test]
    fn invalid_historical_sizes_preserve_live_state() {
        deterministic::Runner::default().start(|context| async move {
            let state = TestState::init(
                context.child("state"),
                config(&context, "sizes"),
                vec![(key(1), balance(10))],
            )
            .await
            .unwrap();
            let old = *state.head();
            let state = apply(state, vec![(key(1), Some(balance(9)))]).await;
            let head = *state.head();
            for root in [old.root(), head.root()] {
                for size in [0, old.operations() - 1, head.operations() + 1, u64::MAX] {
                    assert!(state.lookup_at(root, size, &key(1)).await.is_err());
                    assert_eq!(*state.head(), head);
                }
            }
            assert!(
                state
                    .lookup_at(old.root(), head.operations(), &key(1))
                    .await
                    .is_err()
            );
            assert!(
                state
                    .lookup_at(head.root(), old.operations(), &key(1))
                    .await
                    .is_err()
            );
            let state = apply(state, vec![(key(1), Some(balance(8)))]).await;
            assert_eq!(state.get(&key(1)).await.unwrap(), Some(balance(8)));
        });
    }

    #[test]
    fn partial_application_reopens_at_the_complete_prefix() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config(&context, "partial-apply");
            let genesis = (0..600).map(|index| (key(index), balance(100))).collect();
            let state = TestState::init(context.child("state"), cfg.clone(), genesis)
                .await
                .unwrap()
                .commit()
                .await
                .unwrap();
            let predecessor = *state.head();
            let updates: Mutations = (0..600)
                .map(|index| (key(index), Some(balance(99))))
                .collect();
            let candidate = state.prepare(state.head(), updates.clone()).await.unwrap();
            let target = *candidate.head();
            let intact_storage = context.storage_audit();
            *context.storage_fault_config().write() =
                deterministic::FaultConfig::default().write(deterministic::WriteConfig {
                    failure_rate: probability!(1.0),
                    retention_rate: probability!(0.9999),
                    mode: deterministic::PartialWriteMode::Prefix,
                });
            assert!(matches!(
                state.apply(candidate).await,
                Err(Error::Storage(_))
            ));
            assert_ne!(context.storage_audit(), intact_storage);
            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            let state = TestState::open(context.child("reopened"), cfg)
                .await
                .unwrap();
            assert_eq!(*state.head(), predecessor);
            let state = apply(state, updates).await;
            assert_eq!(*state.head(), target);
        });
    }

    #[test]
    fn constructors_reject_overlapping_partitions_and_reinitialization() {
        deterministic::Runner::default().start(|context| async move {
            let mut overlap = config(&context, "overlap");
            overlap.grafted_metadata_partition = overlap.merkle_config.metadata_partition.clone();
            assert!(matches!(
                TestState::init(context.child("overlap"), overlap, vec![]).await,
                Err(Error::Partition)
            ));
            let mut derived_overlap = config(&context, "derived-overlap");
            derived_overlap.merkle_config.metadata_partition = format!(
                "{}-metadata",
                derived_overlap.merkle_config.journal_partition
            );
            assert!(matches!(
                TestState::init(context.child("derived_overlap"), derived_overlap, vec![]).await,
                Err(Error::Partition)
            ));
            let cfg = config(&context, "reject-history");
            let state = TestState::init(
                context.child("initial"),
                cfg.clone(),
                vec![(key(1), balance(100))],
            )
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
            let expected = *state.head();
            drop(state);
            assert!(matches!(
                TestState::init(context.child("nonempty"), cfg.clone(), vec![]).await,
                Err(Error::Initialized)
            ));
            let state = TestState::open(context.child("valid"), cfg).await.unwrap();
            assert_eq!(*state.head(), expected);
            assert_eq!(state.get(&key(1)).await.unwrap(), Some(balance(100)));
        });
    }
}
