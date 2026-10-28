use super::*;
use crate::stateful::db::{DatabaseSet, Merkleized as StatefulMerkleized, Shared};
use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::{Sequential, mocks::explore};
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::{
        fixed::Config as FixedJournalConfig, variable::Config as VariableJournalConfig,
    },
    merkle::{full::Config as MerkleConfig, mmr},
    qmdb::{
        any::{
            self,
            batch::Slot,
            traits::{BatchableDb, DbAny, MerkleizedBatch},
        },
        current,
        floor::Proportional,
    },
    translator::TwoCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, TestRng, sequence::FixedBytes};
use rand::RngExt as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
};

type Key = FixedBytes<8>;

/// An account that holds only a balance, so a key spent to zero is deleted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Balance(u64);

impl Account for Balance {
    type Effect = Infallible;

    fn balance(&self) -> u64 {
        self.0
    }

    fn set_balance(&mut self, balance: u64) {
        self.0 = balance;
    }

    fn apply(&mut self, effect: Infallible) -> bool {
        match effect {}
    }
}

impl FixedSize for Balance {
    const SIZE: usize = u64::SIZE;
}

impl Write for Balance {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for Balance {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self(u64::read(buf)?))
    }
}

/// A payment from one key to another.
#[derive(Clone, Debug)]
struct Payment {
    from: Key,
    to: Key,
    amount: u64,
}

impl Transfer for Payment {
    type Key = Key;
    type Account = Balance;

    fn changes(&self) -> impl Iterator<Item = (&Key, Change)> {
        [
            (&self.from, Change::Debit(self.amount)),
            (&self.to, Change::Credit(self.amount)),
        ]
        .into_iter()
    }
}

/// A transfer with any number of changes, including repeated keys.
#[derive(Clone, Debug)]
struct Multi(Vec<(Key, Change)>);

impl Transfer for Multi {
    type Key = Key;
    type Account = Balance;

    fn changes(&self) -> impl Iterator<Item = (&Key, Change)> {
        self.0.iter().map(|(key, change)| (key, *change))
    }
}

fn key(n: u64) -> Key {
    Key::new(n.to_be_bytes())
}

fn pay(from: u64, to: u64, amount: u64) -> Payment {
    Payment {
        from: key(from),
        to: key(to),
        amount,
    }
}

/// Maps each planned key to its debit and credit sums, independent of the plan's key order.
fn sums<K: Array>(plan: &Plan<K, Balance>) -> BTreeMap<K, (u64, u64)> {
    plan.keys()
        .iter()
        .zip(&plan.debits)
        .zip(&plan.credits)
        .map(|((key, &debit), &credit)| (key.clone(), (debit, credit)))
        .collect()
}

/// What settling `transfers` from `accounts` must leave, computed one key at a time.
fn expected<T: Transfer<Key = Key>>(
    accounts: &BTreeMap<Key, T::Account>,
    transfers: &[T],
) -> Result<BTreeMap<Key, T::Account>, Rejection<Key>> {
    // Sum each key's debits and credits, rejecting a sum past `u64::MAX`, and list its effects in
    // transfer order.
    let mut debits: BTreeMap<Key, u64> = BTreeMap::new();
    let mut credits: BTreeMap<Key, u64> = BTreeMap::new();
    let mut effects: BTreeMap<Key, Vec<_>> = BTreeMap::new();
    for (key, change) in transfers.iter().flat_map(Transfer::changes) {
        match change {
            Change::Debit(amount) => {
                let sum = debits.entry(key.clone()).or_default();
                *sum = sum
                    .checked_add(amount)
                    .ok_or(Rejection::Insufficient(key.clone()))?;
            }
            Change::Credit(amount) => {
                let sum = credits.entry(key.clone()).or_default();
                *sum = sum
                    .checked_add(amount)
                    .ok_or(Rejection::Overflow(key.clone()))?;
            }
            Change::Effect(effect) => effects.entry(key.clone()).or_default().push(effect),
        }
    }

    // Settle each changed key from its starting account, writing only the accounts that change.
    let mut settled = accounts.clone();
    let keys: BTreeSet<&Key> = debits
        .keys()
        .chain(credits.keys())
        .chain(effects.keys())
        .collect();
    for key in keys {
        let start = accounts.get(key).cloned().unwrap_or_default();
        let mut account = start.clone();
        for effect in effects.get(key).into_iter().flatten() {
            if !account.apply(effect.clone()) {
                return Err(Rejection::Refused(key.clone()));
            }
        }
        let remaining = start
            .balance()
            .checked_sub(debits.get(key).copied().unwrap_or(0))
            .ok_or(Rejection::Insufficient(key.clone()))?;
        let balance = remaining
            .checked_add(credits.get(key).copied().unwrap_or(0))
            .ok_or(Rejection::Overflow(key.clone()))?;
        account.set_balance(balance);
        if account == start {
            continue;
        }
        if account == T::Account::default() {
            settled.remove(key);
        } else {
            settled.insert(key.clone(), account);
        }
    }
    Ok(settled)
}

/// Plans and settles `transfers` from `accounts` under `strategy`, returning the accounts left.
fn settle_all<T: Transfer<Key = Key> + Sync>(
    strategy: &impl Strategy,
    accounts: &BTreeMap<Key, T::Account>,
    transfers: &[T],
) -> Result<BTreeMap<Key, T::Account>, Rejection<Key>> {
    let plan = Plan::new(transfers, strategy)?;
    let reads: Vec<Option<T::Account>> = plan
        .keys()
        .iter()
        .map(|key| accounts.get(key).cloned())
        .collect();
    let mut settled = accounts.clone();
    for (key, slot) in plan.keys().iter().zip(plan.settle(&reads, strategy)?) {
        match slot {
            Slot::Put(account) => settled.insert(key.clone(), account),
            Slot::Delete => settled.remove(key),
            Slot::Keep => None,
        };
    }
    Ok(settled)
}

/// The candidates `accepted` marks, in order.
fn body<T: Clone>(candidates: &[T], accepted: &[bool]) -> Vec<T> {
    candidates
        .iter()
        .zip(accepted)
        .filter(|(_, accepted)| **accepted)
        .map(|(candidate, _)| candidate.clone())
        .collect()
}

#[test]
fn plan_sums_changes_per_key() {
    // Each key's debits and credits are summed across transfers, including a payment to itself.
    let payments = [pay(1, 2, 10), pay(2, 3, 5), pay(1, 3, 7), pay(3, 3, 2)];
    let plan = explore(|strategy| sums(&Plan::new(&payments, strategy).unwrap()));
    assert_eq!(
        plan,
        BTreeMap::from([(key(1), (17, 0)), (key(2), (5, 10)), (key(3), (2, 14)),])
    );
}

#[test]
fn plan_sums_repeated_keys_within_a_transfer() {
    // A key repeated within one transfer sums every change, and an empty transfer adds nothing.
    let transfers = [
        Multi(vec![
            (key(1), Change::Debit(3)),
            (key(1), Change::Credit(4)),
            (key(1), Change::Debit(5)),
        ]),
        Multi(Vec::new()),
        Multi(vec![(key(2), Change::Credit(1))]),
    ];
    let plan = explore(|strategy| sums(&Plan::new(&transfers, strategy).unwrap()));
    assert_eq!(plan, BTreeMap::from([(key(1), (8, 4)), (key(2), (0, 1))]));
}

#[test]
fn plan_of_nothing_is_empty() {
    // No transfers plan and settle nothing.
    let plan = Plan::<Key, Balance>::new(&[] as &[Payment], &Sequential).unwrap();
    assert!(plan.is_empty());
    assert!(plan.settle(&[], &Sequential).unwrap().is_empty());

    // A transfer without changes plans nothing.
    let plan = Plan::new(&[Multi(Vec::new())], &Sequential).unwrap();
    assert!(plan.is_empty());
}

#[test]
fn plan_rejects_overflowing_sums() {
    // Debits that sum past `u64::MAX` are unaffordable.
    let debits = [pay(1, 2, u64::MAX), pay(1, 3, 1)];
    assert_eq!(
        explore(|strategy| Plan::new(&debits, strategy).err()),
        Some(Rejection::Insufficient(key(1)))
    );

    // Credits that sum past `u64::MAX` overflow.
    let credits = [pay(1, 3, u64::MAX), pay(2, 3, 1)];
    assert_eq!(
        explore(|strategy| Plan::new(&credits, strategy).err()),
        Some(Rejection::Overflow(key(3)))
    );
}

#[test]
fn settle_matches_sequential_reference() {
    // Random affordable payments, and a zero payment from a key held at zero, settle to the
    // reference balances under every execution shape.
    let mut rng = TestRng::new(7);
    let keys = 512u64;
    let mut balances: BTreeMap<Key, Balance> = (0..keys)
        .map(|n| (key(n), Balance(rng.random_range(100..1_000))))
        .collect();
    let mut payments: Vec<Payment> = (0..4_096)
        .map(|_| {
            pay(
                rng.random_range(0..keys),
                rng.random_range(0..keys),
                rng.random_range(0..4),
            )
        })
        .collect();
    balances.insert(key(keys + 1), Balance(0));
    payments.push(pay(keys + 1, 0, 0));
    let want = expected(&balances, &payments);
    assert!(
        want.is_ok(),
        "the reference must accept the payments: {want:?}"
    );
    let got = explore(|strategy| settle_all(strategy, &balances, &payments));
    assert_eq!(got, want);

    // Keys the database does not hold afford nothing, so one more payment from such a key
    // rejects the batch and names that key.
    let mut rejected = payments;
    rejected.push(pay(keys, 0, 1));
    assert_eq!(
        explore(|strategy| settle_all(strategy, &balances, &rejected)),
        Err(Rejection::Insufficient(key(keys)))
    );
}

#[test]
fn settle_rejects_unaffordable_and_overflowing_keys() {
    // A key whose debits exceed its balance is rejected.
    let unaffordable = [pay(1, 2, 6), pay(1, 3, 5)];
    assert_eq!(
        explore(|strategy| settle_all(
            strategy,
            &BTreeMap::from([(key(1), Balance(10))]),
            &unaffordable
        )),
        Err(Rejection::Insufficient(key(1)))
    );

    // A key whose final balance exceeds `u64::MAX` is rejected.
    let balances = BTreeMap::from([(key(1), Balance(10)), (key(2), Balance(u64::MAX))]);
    let overflowing = [pay(1, 2, 1)];
    assert_eq!(
        explore(|strategy| settle_all(strategy, &balances, &overflowing)),
        Err(Rejection::Overflow(key(2)))
    );

    // Each key's debits come off before its credits are added, so a key can spend its whole
    // balance and be refilled up to `u64::MAX`.
    let refilled = [pay(2, 1, u64::MAX), pay(1, 2, 10)];
    assert_eq!(
        explore(|strategy| settle_all(strategy, &balances, &refilled)),
        Ok(BTreeMap::from([
            (key(1), Balance(u64::MAX)),
            (key(2), Balance(10)),
        ]))
    );
}

#[test]
fn settle_deletes_zero_balances_and_keeps_unchanged_keys() {
    let balances = BTreeMap::from([
        (key(1), Balance(10)),
        (key(2), Balance(5)),
        (key(5), Balance(7)),
    ]);
    let payments = [pay(1, 2, 10), pay(2, 3, 5), pay(4, 4, 0), pay(5, 5, 7)];
    let plan = Plan::new(&payments, &Sequential).unwrap();
    let reads: Vec<Option<Balance>> = plan
        .keys()
        .iter()
        .map(|key| balances.get(key).copied())
        .collect();
    let slots: BTreeMap<Key, Slot<Balance>> = plan
        .keys()
        .iter()
        .cloned()
        .zip(plan.settle(&reads, &Sequential).unwrap())
        .collect();

    // Key 1 is drained and deleted, key 2 spends its 5 and receives 10, key 3 is created, and
    // key 5 pays itself its whole balance and keeps it. Key 4 pays itself nothing, so the plan
    // leaves it out.
    assert_eq!(
        slots,
        BTreeMap::from([
            (key(1), Slot::Delete),
            (key(2), Slot::Put(Balance(10))),
            (key(3), Slot::Put(Balance(5))),
            (key(5), Slot::Keep),
        ])
    );
}

#[test]
fn settle_marks_each_kind_of_slot_and_reports_offenders() {
    // A plan over six keys with the reads covering every kind of slot.
    let keys: Vec<Key> = (0..6).map(key).collect();
    let settle = |debits: &[u64], credits: &[u64]| {
        let plan: Plan<Key, Balance> = Plan {
            keys: keys.clone(),
            debits: debits.to_vec(),
            credits: credits.to_vec(),
            effect_offsets: Vec::new(),
            effects: Vec::new(),
        };
        let reads = [
            Some(Balance(10)),
            Some(Balance(0)),
            Some(Balance(7)),
            None,
            Some(Balance(0)),
            Some(Balance(1)),
        ];
        explore(|strategy| plan.settle(&reads, strategy))
    };

    // In key order, spending everything deletes, a credit to a held zero puts, and an even
    // exchange, an absent key, a held zero left at zero, and an untouched key all keep.
    assert_eq!(
        settle(&[10, 0, 2, 0, 0, 0], &[0, 3, 2, 0, 0, 0]),
        Ok(vec![
            Slot::Delete,
            Slot::Put(Balance(3)),
            Slot::Keep,
            Slot::Keep,
            Slot::Keep,
            Slot::Keep,
        ])
    );

    // A rejected batch reports the key that cannot afford its debits or whose final balance
    // overflows.
    assert_eq!(
        settle(&[10, 0, 8, 0, 0, 0], &[0, 3, 2, 0, 0, 0]),
        Err(Rejection::Insufficient(key(2)))
    );
    assert_eq!(
        settle(&[10, 0, 2, 0, 0, 0], &[0, 3, 2, 0, 0, u64::MAX]),
        Err(Rejection::Overflow(key(5)))
    );
}

#[test]
fn settle_slots_are_identical_across_strategies() {
    // Enough keys for every execution shape to split the settle into several ranges.
    let mut rng = TestRng::new(3);
    let keys: u64 = 3 * Widen::widen(MIN_SETTLE_BATCH.get());
    let payments: Vec<Payment> = (0..keys)
        .map(|n| pay(n, rng.random_range(0..keys), 1))
        .collect();
    let plan = Plan::new(&payments, &Sequential).unwrap();
    assert_eq!(plan.len(), keys as usize);
    let reads = vec![Some(Balance(100)); plan.len()];

    // Every shape returns the same slot per key, matching a direct computation.
    let settled = explore(|strategy| plan.settle(&reads, strategy)).unwrap();
    let want: Vec<Slot<Balance>> = plan
        .debits
        .iter()
        .zip(&plan.credits)
        .map(|(debit, credit)| {
            let settled = 100 - debit + credit;
            if settled == 100 {
                Slot::Keep
            } else {
                Slot::Put(Balance(settled))
            }
        })
        .collect();
    assert_eq!(settled, want);

    // One key in the last range cannot afford its debit, whichever shape settles it.
    let offender = plan.keys()[plan.len() - 1].clone();
    let reads: Vec<Option<Balance>> = plan
        .keys()
        .iter()
        .map(|key| (*key != offender).then_some(Balance(100)))
        .collect();
    assert_eq!(
        explore(|strategy| plan.settle(&reads, strategy)),
        Err(Rejection::Insufficient(offender))
    );
}

#[test]
fn plan_leaves_out_keys_touched_only_by_zero() {
    // Key 1 sees only a zero debit and is left out, and a zero self-payment adds nothing to key 3.
    let payments = [pay(1, 2, 0), pay(2, 3, 5), pay(3, 3, 0)];
    let plan = explore(|strategy| sums(&Plan::new(&payments, strategy).unwrap()));
    assert_eq!(plan, BTreeMap::from([(key(2), (5, 0)), (key(3), (0, 5))]));
}

/// A hasher that places every key in the same slot of the same partition.
struct Collide;

impl std::hash::BuildHasher for Collide {
    type Hasher = Self;

    fn build_hasher(&self) -> Self {
        Self
    }
}

impl std::hash::Hasher for Collide {
    fn finish(&self) -> u64 {
        u64::MAX
    }

    fn write(&mut self, _: &[u8]) {}
}

/// A hasher that places key `n` in partition `n` for `n` below [`PARTITIONS`], so a test chooses
/// the shard each key falls in.
struct ByKey(u64);

impl std::hash::BuildHasher for ByKey {
    type Hasher = Self;

    fn build_hasher(&self) -> Self {
        Self(0)
    }
}

impl std::hash::Hasher for ByKey {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        // Hashing a key writes its length and then its bytes, so the last write sets the hash from
        // the key's last byte.
        self.0 = u64::from(bytes.last().copied().unwrap_or(0)) << PARTITION_SHIFT;
    }
}

#[test]
fn plan_deduplicates_keys_whose_hashes_collide() {
    // Every key shares a fingerprint and starts probing at the last slot, so only the key
    // comparison tells keys apart and probes wrap around the table.
    let mut rng = TestRng::new(9);
    let keys = 200u64;
    let payments: Vec<Payment> = (0..2_000)
        .map(|_| pay(rng.random_range(0..keys), rng.random_range(0..keys), 1))
        .collect();
    let mut want: BTreeMap<Key, (u64, u64)> = BTreeMap::new();
    for payment in &payments {
        want.entry(payment.from.clone()).or_default().0 += 1;
        want.entry(payment.to.clone()).or_default().1 += 1;
    }
    let plan = explore(|strategy| {
        let plan = Plan::with_hasher(&payments, &Collide, strategy).unwrap();
        assert_eq!(plan.len(), want.len());
        sums(&plan)
    });
    assert_eq!(plan, want);
}

#[test]
fn plan_deduplicates_many_keys() {
    // Touch each key about ten times on average, with keys in every partition, under every
    // execution shape.
    let mut rng = TestRng::new(5);
    let keys = 20_000u64;
    let payments: Vec<Payment> = (0..100_000)
        .map(|_| pay(rng.random_range(0..keys), rng.random_range(0..keys), 1))
        .collect();
    let mut want: BTreeMap<Key, (u64, u64)> = BTreeMap::new();
    for payment in &payments {
        want.entry(payment.from.clone()).or_default().0 += 1;
        want.entry(payment.to.clone()).or_default().1 += 1;
    }
    let plan = explore(|strategy| {
        let plan = Plan::new(&payments, strategy).unwrap();
        assert_eq!(plan.len(), want.len());
        sums(&plan)
    });
    assert_eq!(plan, want);
}

/// A database of `A` accounts that the tests stage, settle, merkleize, and read back.
trait TestDb<A: Account>:
    DbAny<mmr::Family, Key = Key, Value = A, Digest = Digest>
    + BatchableDb<Merkleized: MerkleizedBatch<Digest = Digest>>
{
    /// Stages `keys` in a new batch, settles their reads with `settle`, and merkleizes the slots it
    /// returns.
    fn settle<E: Send>(
        &self,
        keys: &[&Key],
        settle: impl FnOnce(Vec<Option<A>>) -> Result<Vec<Slot<A>>, E> + Send,
    ) -> impl Future<Output = Result<Self::Merkleized, E>> + Send;
}

/// Implements [`TestDb`] for each database type through the staged batch methods they share.
macro_rules! impl_test_db {
    ($($db:ty: $account:ty),* $(,)?) => {$(
        impl TestDb<$account> for $db {
            async fn settle<E: Send>(
                &self,
                keys: &[&Key],
                settle: impl FnOnce(Vec<Option<$account>>) -> Result<Vec<Slot<$account>>, E> + Send,
            ) -> Result<Self::Merkleized, E> {
                let (reads, staged) = self.new_batch().stage(keys, self).await.unwrap();
                let slots = settle(reads)?;
                Ok(staged
                    .merkleize(slots, Vec::new(), None, self, &mut Proportional)
                    .await
                    .unwrap())
            }
        }
    )*};
}

impl_test_db!(
    AnyUnordered: Balance,
    AnyOrdered: Balance,
    CurrentUnordered: Balance,
    CurrentOrdered: Balance,
    NoncedAny: Nonced,
    NoncedCurrent: Nonced,
);

/// Plans and settles `transfers` on a new batch of `db`, returning the merkleized batch.
async fn execute<D, T>(db: &D, transfers: &[T]) -> Result<D::Merkleized, Rejection<Key>>
where
    D: TestDb<T::Account>,
    T: Transfer<Key = Key> + Sync,
{
    let plan = Plan::new(transfers, &Sequential)?;
    let keys: Vec<&Key> = plan.keys().iter().collect();
    db.settle(&keys, |reads| plan.settle(&reads, &Sequential))
        .await
}

/// Selects from `candidates` on a new batch of `db`, returning the merkleized batch and whether
/// each candidate was accepted.
async fn select<D, T>(db: &D, candidates: &[T]) -> (D::Merkleized, Vec<bool>)
where
    D: TestDb<T::Account>,
    T: Transfer<Key = Key> + Sync,
{
    let mut selection = Selection::new();
    let touched = selection.touch(candidates);
    let keys = selection.keys()[touched].to_vec();
    let keys: Vec<&Key> = keys.iter().collect();
    let mut accepted = Vec::new();
    let Ok(merkleized) = db
        .settle(&keys, |reads| {
            selection.register(reads);
            accepted = selection.apply(candidates);
            Ok::<_, Infallible>(selection.settle(&Sequential))
        })
        .await;
    (merkleized, accepted)
}

type AnyUnordered = any::unordered::fixed::Db<
    mmr::Family,
    deterministic::Context,
    Key,
    Balance,
    Sha256,
    TwoCap,
    Sequential,
>;
type AnyOrdered = any::ordered::fixed::Db<
    mmr::Family,
    deterministic::Context,
    Key,
    Balance,
    Sha256,
    TwoCap,
    Sequential,
>;
type CurrentUnordered = current::unordered::fixed::Db<
    mmr::Family,
    deterministic::Context,
    Key,
    Balance,
    Sha256,
    TwoCap,
    32,
    Sequential,
>;
type CurrentOrdered = current::ordered::fixed::Db<
    mmr::Family,
    deterministic::Context,
    Key,
    Balance,
    Sha256,
    TwoCap,
    32,
    Sequential,
>;

fn any_config(suffix: &str) -> any::FixedConfig<TwoCap, Sequential> {
    let page_cache = CacheRef::new(NZU16!(101), NZUsize!(11));
    any::FixedConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("transfers-journal-{suffix}"),
            metadata_partition: format!("transfers-metadata-{suffix}"),
            items_per_blob: NZU64!(11),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: format!("transfers-log-{suffix}"),
            items_per_blob: NZU64!(7),
            page_cache,
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
        },
        translator: TwoCap,
        init_cache: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

fn current_config(suffix: &str) -> current::FixedConfig<TwoCap, Sequential> {
    let any = any_config(suffix);
    current::FixedConfig {
        merkle_config: any.merkle_config,
        journal_config: any.journal_config,
        grafted_metadata_partition: format!("transfers-grafted-{suffix}"),
        translator: TwoCap,
        init_cache: any.init_cache,
        init_buffer: any.init_buffer,
        init_concurrency: (),
    }
}

fn variable_config(suffix: &str) -> any::VariableConfig<TwoCap, ((), ()), Sequential> {
    let any = any_config(suffix);
    any::VariableConfig {
        merkle_config: any.merkle_config,
        journal_config: VariableJournalConfig {
            partition: format!("transfers-log-{suffix}"),
            items_per_section: NZU64!(7),
            compression: None,
            codec_config: ((), ()),
            page_cache: any.journal_config.page_cache,
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
        },
        translator: TwoCap,
        init_cache: any.init_cache,
        init_buffer: any.init_buffer,
        init_concurrency: (),
    }
}

/// Executes `transfers` on `db` and commits them, returning the database and the batch root.
async fn run<D, T>(db: D, transfers: &[T]) -> Result<(D, Digest), Rejection<Key>>
where
    D: TestDb<T::Account>,
    T: Transfer<Key = Key> + Sync,
{
    let merkleized = execute(&db, transfers).await?;
    let root = merkleized.root();
    let db = db.apply_batch(merkleized).await.unwrap();
    Ok((db.commit().await.unwrap(), root))
}

/// The accounts `db` holds among keys `0..keys`.
async fn accounts<A: Account, D: TestDb<A>>(db: &D, keys: u64) -> BTreeMap<Key, A> {
    let mut accounts = BTreeMap::new();
    for n in 0..keys {
        if let Some(account) = db.get(&key(n)).await.unwrap() {
            accounts.insert(key(n), account);
        }
    }
    accounts
}

/// Mints, rejects, settles, and deletes balances on `db`.
async fn exercise<D: TestDb<Balance>>(db: D) {
    // Mint balances into an empty database.
    let mint = [Multi(vec![
        (key(1), Change::Credit(100)),
        (key(2), Change::Credit(150)),
    ])];
    let (db, _) = run(db, &mint).await.unwrap();
    assert_eq!(
        accounts(&db, 5).await,
        BTreeMap::from([(key(1), Balance(100)), (key(2), Balance(150))])
    );

    // A rejected batch leaves the database unchanged.
    let before = db.root();
    let rejected = [pay(1, 3, 60), pay(1, 4, 41)];
    assert_eq!(
        execute(&db, &rejected).await.err(),
        Some(Rejection::Insufficient(key(1)))
    );
    assert_eq!(db.root(), before);
    assert_eq!(
        accounts(&db, 5).await,
        BTreeMap::from([(key(1), Balance(100)), (key(2), Balance(150))])
    );

    // A settled batch writes the changed balances. Key 1 spends its whole starting balance and is
    // refilled by key 2. Key 2 also pays itself.
    let payments = [pay(1, 3, 60), pay(1, 4, 40), pay(2, 1, 50), pay(2, 2, 100)];
    let (db, root) = run(db, &payments).await.unwrap();
    assert_ne!(root, before);
    assert_eq!(
        accounts(&db, 5).await,
        BTreeMap::from([
            (key(1), Balance(50)),
            (key(2), Balance(100)),
            (key(3), Balance(60)),
            (key(4), Balance(40)),
        ])
    );

    // Spending everything deletes the key.
    let (db, _) = run(db, &[pay(1, 2, 50)]).await.unwrap();
    assert_eq!(
        accounts(&db, 5).await,
        BTreeMap::from([
            (key(2), Balance(150)),
            (key(3), Balance(60)),
            (key(4), Balance(40)),
        ])
    );
    db.destroy().await.unwrap();
}

#[test]
fn execute_settles_batches_against_any_unordered() {
    deterministic::Runner::default().start(|context| async move {
        let db = AnyUnordered::init(context.child("db"), any_config("any-unordered"), None)
            .await
            .unwrap();
        exercise(db).await;
    });
}

#[test]
fn execute_settles_batches_against_any_ordered() {
    deterministic::Runner::default().start(|context| async move {
        let db = AnyOrdered::init(context.child("db"), any_config("any-ordered"), None)
            .await
            .unwrap();
        exercise(db).await;
    });
}

#[test]
fn execute_settles_batches_against_current_unordered() {
    deterministic::Runner::default().start(|context| async move {
        let db = CurrentUnordered::init(
            context.child("db"),
            current_config("current-unordered"),
            None,
        )
        .await
        .unwrap();
        exercise(db).await;
    });
}

#[test]
fn execute_settles_batches_against_current_ordered() {
    deterministic::Runner::default().start(|context| async move {
        let db = CurrentOrdered::init(context.child("db"), current_config("current-ordered"), None)
            .await
            .unwrap();
        exercise(db).await;
    });
}

/// Settles the same random payments in two orders on two fresh databases and checks that both reach
/// the same root and balances.
///
/// The plan's key order varies with each plan's hash key, so the root must depend on neither it
/// nor the transfer order.
async fn order_independence<D: TestDb<Balance>>(dbs: [D; 2]) {
    let mut rng = TestRng::new(11);
    let keys = 300u64;
    let mint: Vec<Multi> = (0..keys)
        .map(|n| Multi(vec![(key(n), Change::Credit(rng.random_range(100..1_000)))]))
        .collect();

    // Random payments among minted keys 2 and up, then key 0 drained to a fresh key (a delete and a
    // create) and key 1 drained into key 2 (a delete).
    let mut payments: Vec<Payment> = (0..2_000)
        .map(|_| {
            pay(
                rng.random_range(2..keys),
                rng.random_range(2..keys),
                rng.random_range(0..3),
            )
        })
        .collect();
    let minted = |n: u64| {
        let (_, Change::Credit(amount)) = mint[n as usize].0[0] else {
            unreachable!("a mint must only credit");
        };
        amount
    };
    payments.push(pay(0, keys, minted(0)));
    payments.push(pay(1, 2, minted(1)));

    // The second order shuffles the first.
    let mut shuffled = payments.clone();
    for i in (1..shuffled.len()).rev() {
        shuffled.swap(i, rng.random_range(0..=i));
    }

    // Settle each order on its own fresh database.
    let mut roots = Vec::new();
    let mut settled = Vec::new();
    for (db, payments) in dbs.into_iter().zip([&payments, &shuffled]) {
        let (db, _) = run(db, &mint).await.unwrap();
        let (db, root) = run(db, payments).await.unwrap();
        roots.push(root);
        settled.push(accounts(&db, keys + 1).await);
        db.destroy().await.unwrap();
    }

    // Both orders reach the same root and balances. The drained keys are deleted, and the fresh
    // key holds key 0's mint.
    assert_eq!(roots[0], roots[1]);
    assert_eq!(settled[0], settled[1]);
    assert!(!settled[0].contains_key(&key(0)) && !settled[0].contains_key(&key(1)));
    assert_eq!(settled[0].get(&key(keys)), Some(&Balance(minted(0))));

    // The balances match the sequential reference.
    let minted: BTreeMap<Key, Balance> = (0..keys).map(|n| (key(n), Balance(minted(n)))).collect();
    assert_eq!(settled[0], expected(&minted, &payments).unwrap());
}

#[test]
fn execute_roots_do_not_depend_on_order_in_any_unordered() {
    deterministic::Runner::default().start(|context| async move {
        let mut dbs = Vec::new();
        for suffix in ["ordered", "shuffled"] {
            dbs.push(
                AnyUnordered::init(context.child(suffix), any_config(suffix), None)
                    .await
                    .unwrap(),
            );
        }
        order_independence(dbs.try_into().ok().unwrap()).await;
    });
}

#[test]
fn execute_roots_do_not_depend_on_order_in_any_ordered() {
    deterministic::Runner::default().start(|context| async move {
        let mut dbs = Vec::new();
        for suffix in ["ordered", "shuffled"] {
            dbs.push(
                AnyOrdered::init(context.child(suffix), any_config(suffix), None)
                    .await
                    .unwrap(),
            );
        }
        order_independence(dbs.try_into().ok().unwrap()).await;
    });
}

#[test]
fn execute_roots_do_not_depend_on_order_in_current_unordered() {
    deterministic::Runner::default().start(|context| async move {
        let mut dbs = Vec::new();
        for suffix in ["ordered", "shuffled"] {
            dbs.push(
                CurrentUnordered::init(context.child(suffix), current_config(suffix), None)
                    .await
                    .unwrap(),
            );
        }
        order_independence(dbs.try_into().ok().unwrap()).await;
    });
}

#[test]
fn execute_roots_do_not_depend_on_order_in_current_ordered() {
    deterministic::Runner::default().start(|context| async move {
        let mut dbs = Vec::new();
        for suffix in ["ordered", "shuffled"] {
            dbs.push(
                CurrentOrdered::init(context.child(suffix), current_config(suffix), None)
                    .await
                    .unwrap(),
            );
        }
        order_independence(dbs.try_into().ok().unwrap()).await;
    });
}

/// Selects `candidates` in rounds of `round` transfers against `accounts`, returning which were
/// accepted and the accounts the accepted ones leave.
fn select_all<T: Transfer<Key = Key>>(
    strategy: &impl Strategy,
    accounts: &BTreeMap<Key, T::Account>,
    candidates: &[T],
    round: usize,
) -> (Vec<bool>, BTreeMap<Key, T::Account>) {
    let mut selection = Selection::new();
    let mut accepted = Vec::new();

    // Each round touches its candidates' keys, reads the new ones from `accounts`, and applies
    // the round.
    for candidates in candidates.chunks(round.max(1)) {
        let touched = selection.touch(candidates);
        let reads: Vec<Option<T::Account>> = selection.keys()[touched]
            .iter()
            .map(|key| accounts.get(key).cloned())
            .collect();
        selection.register(reads);
        accepted.extend(selection.apply(candidates));
    }

    // Settle the accepted candidates into a copy of the accounts.
    let keys = selection.keys().to_vec();
    let mut settled = accounts.clone();
    for (key, slot) in keys.iter().zip(selection.settle(strategy)) {
        match slot {
            Slot::Put(account) => settled.insert(key.clone(), account),
            Slot::Delete => settled.remove(key),
            Slot::Keep => None,
        };
    }
    (accepted, settled)
}

/// Selects `candidates` against `accounts` in rounds of several sizes, checking that some but not
/// all are accepted and that the accepted ones settle as a batch to the accounts the selection
/// leaves.
fn assert_selection_matches_plan<T: Transfer<Key = Key> + Clone + Sync>(
    accounts: &BTreeMap<Key, T::Account>,
    candidates: &[T],
) {
    for round in [1, 7, 500, 2_000] {
        let (accepted, settled) =
            explore(|strategy| select_all(strategy, accounts, candidates, round));
        assert!(accepted.iter().any(|&accepted| accepted));
        assert!(accepted.iter().any(|&accepted| !accepted));
        let body = body(candidates, &accepted);
        assert_eq!(expected(accounts, &body), Ok(settled.clone()));
        assert_eq!(settle_all(&Sequential, accounts, &body), Ok(settled));
    }
}

#[test]
fn selection_drops_candidates_that_do_not_fit_in_order() {
    let balances = BTreeMap::from([
        (key(1), Balance(10)),
        (key(5), Balance(u64::MAX)),
        (key(6), Balance(1)),
        (key(7), Balance(0)),
    ]);
    let candidates = [
        // Fits: key 1 has 10.
        pay(1, 2, 6),
        // Dropped: key 1 has only 4 left to spend.
        pay(1, 3, 5),
        // Dropped: key 2 starts at zero, since the credit it received cannot fund it.
        pay(2, 1, 6),
        // Fits: a self-payment needs the amount at the start and nets to nothing.
        pay(1, 1, 4),
        // Fits: a zero credit cannot overflow key 5.
        pay(1, 5, 0),
        // Dropped: key 2 starts at zero, so it cannot pay key 5.
        pay(2, 5, 1),
        // Dropped: the credit overflows key 5.
        pay(6, 5, 1),
        // Fits: a zero payment always does, and a held zero it touches is left alone.
        pay(7, 4, 0),
    ];
    let (accepted, settled) = explore(|strategy| select_all(strategy, &balances, &candidates, 3));
    assert_eq!(
        accepted,
        vec![true, false, false, true, true, false, false, true]
    );
    assert_eq!(
        settled,
        BTreeMap::from([
            (key(1), Balance(4)),
            (key(2), Balance(6)),
            (key(5), Balance(u64::MAX)),
            (key(6), Balance(1)),
            (key(7), Balance(0)),
        ])
    );
}

#[test]
fn selection_undoes_a_transfer_whose_later_change_does_not_fit() {
    let mut selection = Selection::new();
    let candidates = [
        Multi(vec![
            (key(1), Change::Credit(5)),
            (key(1), Change::Debit(11)),
        ]),
        Multi(vec![(key(1), Change::Debit(10))]),
    ];
    let touched = selection.touch(&candidates);
    assert_eq!(touched, 0..1);
    selection.register(vec![Some(Balance(10))]);

    // The first candidate's debit does not fit, so its credit is undone. The second spends the
    // whole starting balance, and with no credit left behind, the key is deleted.
    assert_eq!(selection.apply(&candidates), vec![false, true]);
    assert_eq!(selection.settle(&Sequential), vec![Slot::Delete]);
}

#[test]
fn selection_nets_a_transfers_changes_to_one_key() {
    let mut selection = Selection::new();
    let candidates = [
        Multi(vec![
            (key(1), Change::Credit(10)),
            (key(1), Change::Debit(10)),
        ]),
        Multi(vec![
            (key(1), Change::Debit(10)),
            (key(1), Change::Credit(10)),
        ]),
        Multi(vec![
            (key(1), Change::Credit(10)),
            (key(1), Change::Debit(4)),
        ]),
    ];
    let touched = selection.touch(&candidates);
    assert_eq!(touched, 0..1);
    let balances = BTreeMap::from([(key(1), Balance(u64::MAX - 5))]);
    selection.register(vec![balances.get(&key(1)).copied()]);

    // A credit that would overflow the key on its own is accepted with the same transfer's debit
    // of the key, in either order, since a batch adds a key's credits after subtracting all its
    // debits. The third transfer would still leave the key past `u64::MAX` and is dropped.
    assert_eq!(selection.apply(&candidates), vec![true, true, false]);
    assert_eq!(selection.settle(&Sequential), vec![Slot::Keep]);

    // The plan agrees. The first two candidates settle as a batch, and the third cannot join them.
    assert!(settle_all(&Sequential, &balances, &candidates[..2]).is_ok());
    assert_eq!(
        settle_all(&Sequential, &balances, &candidates),
        Err(Rejection::Overflow(key(1)))
    );
}

#[test]
fn selection_undoes_applied_changes_when_a_sum_overflows() {
    let mut selection = Selection::new();
    let candidates = [
        Multi(vec![(key(1), Change::Credit(u64::MAX))]),
        Multi(vec![
            (key(2), Change::Credit(5)),
            (key(1), Change::Credit(1)),
            (key(3), Change::Credit(7)),
        ]),
    ];
    let touched = selection.touch(&candidates);
    assert_eq!(touched, 0..3);
    selection.register(vec![None, None, None]);

    // The second candidate's credit to key 1 would push its credit sum past `u64::MAX`, so the
    // credit to key 2 applied before it is undone and the credit to key 3 after it is never
    // applied. Key 1 keeps exactly the first candidate's credit.
    assert_eq!(selection.apply(&candidates), vec![true, false]);
    assert_eq!(
        selection.settle(&Sequential),
        vec![Slot::Put(Balance(u64::MAX)), Slot::Keep, Slot::Keep]
    );
}

#[test]
fn selection_settles_as_the_plan_of_the_accepted_candidates() {
    // Random candidates with amounts large enough that many do not fit.
    let mut rng = TestRng::new(17);
    let keys = 64u64;
    let mut balances = BTreeMap::new();
    for n in 0..keys {
        if rng.random_bool(0.7) {
            balances.insert(key(n), Balance(rng.random_range(0..50)));
        }
    }
    let candidates: Vec<Payment> = (0..2_000)
        .map(|_| {
            pay(
                rng.random_range(0..keys),
                rng.random_range(0..keys),
                rng.random_range(0..20),
            )
        })
        .collect();
    assert_selection_matches_plan(&balances, &candidates);
}

/// Selects from `candidates` on a proposer's database holding the accounts `setup` leaves, then
/// executes exactly the accepted body on a verifier's database with the same setup, checking that
/// both reach the same root and accounts among keys `0..keys`.
async fn select_matches_execute<D, S, T>(dbs: [D; 2], setup: &[S], candidates: &[T], keys: u64)
where
    D: TestDb<T::Account>,
    S: Transfer<Key = Key, Account = T::Account> + Sync,
    T: Transfer<Key = Key> + Clone + Sync,
{
    let [proposer, verifier] = dbs;

    // A proposer selects a body from the candidates on the state the setup leaves.
    let (proposer, _) = run(proposer, setup).await.unwrap();
    let (merkleized, accepted) = select(&proposer, candidates).await;
    let proposed = merkleized.root();
    let proposer = proposer.apply_batch(merkleized).await.unwrap();
    let proposed_accounts = accounts(&proposer, keys).await;
    proposer.destroy().await.unwrap();

    // A verifier executes exactly the accepted body on the same state and reaches the same root
    // and accounts.
    let body = body(candidates, &accepted);
    assert!(body.len() < candidates.len());
    let (verifier, _) = run(verifier, setup).await.unwrap();
    let (verifier, verified) = run(verifier, &body).await.unwrap();
    assert_eq!(verified, proposed);
    assert_eq!(accounts(&verifier, keys).await, proposed_accounts);
    verifier.destroy().await.unwrap();
}

#[test]
fn select_merkleizes_the_accepted_candidates() {
    deterministic::Runner::default().start(|context| async move {
        let mut rng = TestRng::new(23);
        let keys = 100u64;

        // Each key is minted a small balance, and candidates also pay from ten unminted keys, so
        // some do not fit.
        let mint: Vec<Multi> = (0..keys)
            .map(|n| Multi(vec![(key(n), Change::Credit(rng.random_range(1..30)))]))
            .collect();
        let candidates: Vec<Payment> = (0..600)
            .map(|_| {
                pay(
                    rng.random_range(0..keys + 10),
                    rng.random_range(0..keys + 10),
                    rng.random_range(0..10),
                )
            })
            .collect();
        let mut dbs = Vec::new();
        for suffix in ["proposer", "verifier"] {
            dbs.push(
                AnyUnordered::init(context.child(suffix), any_config(suffix), None)
                    .await
                    .unwrap(),
            );
        }
        select_matches_execute(dbs.try_into().ok().unwrap(), &mint, &candidates, keys + 10).await;
    });
}

#[test]
fn selection_reads_later_rounds_through_expand() {
    deterministic::Runner::default().start(|context| async move {
        // The proposer and the verifier start from the same minted accounts.
        let mut dbs = Vec::new();
        for suffix in ["proposer", "verifier"] {
            dbs.push(
                AnyUnordered::init(context.child(suffix), any_config(suffix), None)
                    .await
                    .unwrap(),
            );
        }
        let [proposer, verifier]: [AnyUnordered; 2] = dbs.try_into().ok().unwrap();
        let mint = [Multi(vec![
            (key(1), Change::Credit(10)),
            (key(2), Change::Credit(5)),
        ])];
        let (proposer, _) = run(proposer, &mint).await.unwrap();
        let (verifier, _) = run(verifier, &mint).await.unwrap();

        // The first round reads its keys with `stage`, and each later round reads its new keys with
        // `expand` into the range `touch` returned for them. Key 3 is touched only by a dropped
        // candidate, key 4 only by a zero credit, and the second round touches no key.
        let rounds = [
            vec![pay(1, 2, 6), pay(3, 1, 1), pay(1, 4, 0)],
            Vec::new(),
            vec![pay(2, 5, 5), pay(1, 5, 4), pay(2, 3, 1)],
        ];
        let mut selection = Selection::new();
        let touched = selection.touch(&rounds[0]);
        let keys: Vec<&Key> = selection.keys()[touched].iter().collect();
        let (reads, mut staged) = proposer.new_batch().stage(&keys, &proposer).await.unwrap();
        selection.register(reads);
        let mut accepted = selection.apply(&rounds[0]);
        for round in &rounds[1..] {
            let touched = selection.touch(round);
            let keys: Vec<&Key> = selection.keys()[touched.clone()].iter().collect();
            let (range, reads, expanded) = staged.expand(&keys, &proposer).await.unwrap();
            assert_eq!(range, touched);
            selection.register(reads);
            accepted.extend(selection.apply(round));
            staged = expanded;
        }
        assert_eq!(accepted, [true, false, true, true, true, false]);

        // Settling yields one slot per staged key, in staging order. Key 1 is drained and deleted,
        // key 2 is refilled, key 5 is created, and key 3 stays absent. Key 4 is never staged.
        let slots = selection.settle(&Sequential);
        assert_eq!(
            slots,
            [
                Slot::Delete,
                Slot::Put(Balance(6)),
                Slot::Keep,
                Slot::Put(Balance(9)),
            ]
        );
        let merkleized = staged
            .merkleize(slots, Vec::new(), None, &proposer, &mut Proportional)
            .await
            .unwrap();
        let proposed = merkleized.root();
        let proposer = proposer.apply_batch(merkleized).await.unwrap();

        // A verifier executing the accepted body reaches the same root and accounts.
        let body = body(&rounds.concat(), &accepted);
        let (verifier, verified) = run(verifier, &body).await.unwrap();
        assert_eq!(verified, proposed);
        assert_eq!(accounts(&verifier, 6).await, accounts(&proposer, 6).await);
        proposer.destroy().await.unwrap();
        verifier.destroy().await.unwrap();
    });
}

/// How far past an account's lowest unused nonce it can consume nonces out of order.
const NONCE_WINDOW: u64 = u64::BITS as u64;

/// The balance of an account the database does not hold.
const DEFAULT_BALANCE: u64 = 100;

/// An account whose transfers each consume one of its nonces, in any order within a window above
/// its lowest unused nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Nonced {
    /// The balance transfers debit and credit.
    balance: u64,
    /// The lowest unused nonce.
    base: u64,
    /// The consumed nonces above `base`, bit `i` for nonce `base + 1 + i`.
    bitmap: u64,
}

impl Nonced {
    const fn new(balance: u64, base: u64, bitmap: u64) -> Self {
        Self {
            balance,
            base,
            bitmap,
        }
    }

    /// Consumes `nonce`, returning whether it was unused.
    fn consume(&mut self, nonce: u64) -> bool {
        // A nonce below the base is already consumed, and the base cannot move past `u64::MAX`.
        if nonce < self.base || nonce == u64::MAX {
            return false;
        }
        match nonce - self.base {
            // Consuming the base moves it past the run of consumed nonces right after it.
            0 => {
                let advance = self.bitmap.trailing_ones() + 1;
                let Some(base) = self.base.checked_add(advance.into()) else {
                    return false;
                };
                self.base = base;
                self.bitmap = self.bitmap.checked_shr(advance).unwrap_or(0);
            }

            // A nonce past the window moves the base past it and forgets the window.
            delta if delta > NONCE_WINDOW => {
                self.base = nonce + 1;
                self.bitmap = 0;
            }

            // A nonce within the window is consumed once.
            delta => {
                let bit = 1 << (delta - 1);
                if self.bitmap & bit != 0 {
                    return false;
                }
                self.bitmap |= bit;
            }
        }
        true
    }
}

impl Default for Nonced {
    fn default() -> Self {
        Self::new(DEFAULT_BALANCE, 0, 0)
    }
}

/// An effect on a nonced account.
#[derive(Clone, Debug)]
enum Effect {
    /// Consumes a nonce.
    Nonce(u64),
    /// Requires a balance of at least the amount.
    Floor(u64),
    /// Consumes a nonce and then refuses.
    RefuseAfterNonce(u64),
    /// Empties the balance.
    Burn,
}

impl Account for Nonced {
    type Effect = Effect;

    fn balance(&self) -> u64 {
        self.balance
    }

    fn set_balance(&mut self, balance: u64) {
        self.balance = balance;
    }

    fn apply(&mut self, effect: Effect) -> bool {
        match effect {
            Effect::Nonce(nonce) => self.consume(nonce),
            Effect::Floor(amount) => self.balance >= amount,
            Effect::RefuseAfterNonce(nonce) => {
                self.consume(nonce);
                false
            }
            Effect::Burn => {
                self.balance = 0;
                true
            }
        }
    }
}

impl FixedSize for Nonced {
    const SIZE: usize = 3 * u64::SIZE;
}

impl Write for Nonced {
    fn write(&self, buf: &mut impl BufMut) {
        self.balance.write(buf);
        self.base.write(buf);
        self.bitmap.write(buf);
    }
}

impl Read for Nonced {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            balance: u64::read(buf)?,
            base: u64::read(buf)?,
            bitmap: u64::read(buf)?,
        })
    }
}

/// A payment that consumes one of its sender's nonces.
#[derive(Clone, Debug)]
struct Signed {
    from: Key,
    to: Key,
    amount: u64,
    nonce: u64,
}

impl Transfer for Signed {
    type Key = Key;
    type Account = Nonced;

    fn changes(&self) -> impl Iterator<Item = (&Key, Change<Effect>)> {
        // A self-transfer moves nothing, but its sender must hold the amount. The nonce comes last,
        // so a selection that refuses it must undo the transfer's other changes.
        let moves = if self.from == self.to {
            [
                Some((&self.from, Change::Effect(Effect::Floor(self.amount)))),
                None,
            ]
        } else {
            [
                Some((&self.from, Change::Debit(self.amount))),
                Some((&self.to, Change::Credit(self.amount))),
            ]
        };
        let nonce = (&self.from, Change::Effect(Effect::Nonce(self.nonce)));
        moves.into_iter().flatten().chain(iter::once(nonce))
    }
}

fn signed(from: u64, to: u64, amount: u64, nonce: u64) -> Signed {
    Signed {
        from: key(from),
        to: key(to),
        amount,
        nonce,
    }
}

/// A transfer between nonced accounts with any number of changes, applied in the order listed.
#[derive(Clone, Debug)]
struct NoncedMulti(Vec<(Key, Change<Effect>)>);

impl Transfer for NoncedMulti {
    type Key = Key;
    type Account = Nonced;

    fn changes(&self) -> impl Iterator<Item = (&Key, Change<Effect>)> {
        self.0.iter().map(|(key, change)| (key, change.clone()))
    }
}

// Nonced accounts are stored in one database of each value encoding.
type NoncedAny = any::unordered::variable::Db<
    mmr::Family,
    deterministic::Context,
    Key,
    Nonced,
    Sha256,
    TwoCap,
    Sequential,
>;
type NoncedCurrent = current::ordered::fixed::Db<
    mmr::Family,
    deterministic::Context,
    Key,
    Nonced,
    Sha256,
    TwoCap,
    32,
    Sequential,
>;

#[test]
fn settle_consumes_nonces_in_transfer_order() {
    // Key 1 has consumed every nonce below 3. Nonce 70 is past its window, so consuming it moves
    // the base past it, and nonce 3 cannot be consumed after it.
    let mut accounts = BTreeMap::from([(key(1), Nonced::new(10, 3, 0))]);
    let forward = [signed(1, 2, 1, 3), signed(1, 2, 1, 70)];
    let backward = [signed(1, 2, 1, 70), signed(1, 2, 1, 3)];
    assert_eq!(
        explore(|strategy| settle_all(strategy, &accounts, &forward)),
        Ok(BTreeMap::from([
            (key(1), Nonced::new(8, 71, 0)),
            (key(2), Nonced::new(DEFAULT_BALANCE + 2, 0, 0)),
        ]))
    );
    assert_eq!(
        explore(|strategy| settle_all(strategy, &accounts, &backward)),
        Err(Rejection::Refused(key(1)))
    );

    // Between the two, key 0 pays enough fresh keys that a strategy splitting the hashing hashes
    // the two in different batches. Key 0 consumes its own nonces in order.
    let filler: u64 = 2 * Widen::widen(MIN_HASH_BATCH.get());
    accounts.insert(key(0), Nonced::new(filler, 0, 0));
    let apart = |[first, second]: [Signed; 2]| {
        let mut transfers = vec![first];
        transfers.extend((0..filler).map(|n| signed(0, n + 3, 1, n)));
        transfers.push(second);
        transfers
    };
    let (forward, backward) = (apart(forward), apart(backward));

    // Every execution shape keeps each key's effects in transfer order.
    let settled = explore(|strategy| settle_all(strategy, &accounts, &forward)).unwrap();
    assert_eq!(settled[&key(0)], Nonced::new(0, filler, 0));
    assert_eq!(settled[&key(1)], Nonced::new(8, 71, 0));
    assert_eq!(expected(&accounts, &forward), Ok(settled));
    assert_eq!(
        explore(|strategy| settle_all(strategy, &accounts, &backward)),
        Err(Rejection::Refused(key(1)))
    );
}

#[test]
fn plan_keeps_effects_in_order_across_shards() {
    // Keys 0, 64, and 224 fall in partitions 0, 64, and 224, so the most parallel split puts them
    // in three shards. Key 64 has only a credit, so its shard holds a key without effects, and the
    // effect ends of key 224's shard must be shifted past key 0's effects. Nonce 70 is past the
    // window above nonce 0, so consuming it first refuses nonce 0.
    let transfers = [
        NoncedMulti(vec![
            (key(224), Change::Effect(Effect::Nonce(0))),
            (key(0), Change::Effect(Effect::Nonce(0))),
            (key(64), Change::Credit(1)),
        ]),
        NoncedMulti(vec![
            (key(0), Change::Effect(Effect::Nonce(70))),
            (key(224), Change::Effect(Effect::Nonce(70))),
        ]),
    ];
    // Transfers without changes pad the batch, so every split shape buckets its hashing.
    let settle = |transfers: &[NoncedMulti]| {
        let mut transfers = transfers.to_vec();
        transfers.resize(3 * MIN_HASH_BATCH.get(), NoncedMulti(Vec::new()));
        explore(|strategy| {
            let plan = Plan::with_hasher(&transfers, &ByKey(0), strategy)?;
            let slots = plan.settle(&vec![None; plan.len()], strategy)?;
            Ok::<_, Rejection<Key>>(
                plan.keys()
                    .iter()
                    .cloned()
                    .zip(slots)
                    .collect::<BTreeMap<_, _>>(),
            )
        })
    };
    assert_eq!(
        settle(&transfers),
        Ok(BTreeMap::from([
            (key(0), Slot::Put(Nonced::new(DEFAULT_BALANCE, 71, 0))),
            (key(64), Slot::Put(Nonced::new(DEFAULT_BALANCE + 1, 0, 0))),
            (key(224), Slot::Put(Nonced::new(DEFAULT_BALANCE, 71, 0))),
        ]))
    );

    // Swapping the transfers refuses nonce 0 on keys 0 and 224. Key 0 is reported, since it comes
    // first in every shape's plan: its partition comes first, and the whole input touches it first.
    let swapped = [transfers[1].clone(), transfers[0].clone()];
    assert_eq!(settle(&swapped), Err(Rejection::Refused(key(0))));
}

#[test]
fn settle_applies_each_keys_effects_in_every_range() {
    // Enough keys for every execution shape to split the settle into several ranges. Each key
    // consumes a nonce of its own past the window, so its settled base shows which effect it got.
    let keys: u64 = 3 * Widen::widen(MIN_SETTLE_BATCH.get());
    let transfers: Vec<NoncedMulti> = (0..keys)
        .map(|n| {
            NoncedMulti(vec![(
                key(n),
                Change::Effect(Effect::Nonce(NONCE_WINDOW + 1 + n)),
            )])
        })
        .collect();

    // Every shape settles each key from its own effect, as the sequential reference does.
    let settled = explore(|strategy| settle_all(strategy, &BTreeMap::new(), &transfers));
    assert_eq!(settled, expected(&BTreeMap::new(), &transfers));
    assert_eq!(
        settled.map(|settled| settled[&key(keys - 1)]),
        Ok(Nonced::new(DEFAULT_BALANCE, NONCE_WINDOW + keys + 1, 0))
    );
}

#[test]
fn settle_refuses_replayed_nonces() {
    // Key 1 has consumed every nonce below 3, and nonce 5 ahead of them.
    let accounts = BTreeMap::from([(key(1), Nonced::new(10, 3, 1 << 1))]);

    // A nonce below the base, one consumed ahead of it, or one repeated within the batch is
    // refused, even by a transfer that moves nothing.
    for body in [
        vec![signed(1, 2, 0, 2)],
        vec![signed(1, 2, 0, 5)],
        vec![signed(1, 2, 1, 4), signed(1, 2, 1, 4)],
    ] {
        assert_eq!(
            explore(|strategy| settle_all(strategy, &accounts, &body)),
            Err(Rejection::Refused(key(1)))
        );
    }

    // Consuming the base and then nonce 4 moves the base past nonce 5.
    let body = [signed(1, 2, 1, 3), signed(1, 2, 1, 4)];
    let settled = explore(|strategy| settle_all(strategy, &accounts, &body));
    assert_eq!(
        settled.map(|settled| settled[&key(1)]),
        Ok(Nonced::new(8, 6, 0))
    );
}

#[test]
fn settle_deletes_only_accounts_settled_to_the_default() {
    let accounts = BTreeMap::from([
        (key(1), Nonced::new(10, 0, 0)),
        (key(3), Nonced::new(DEFAULT_BALANCE - 10, 0, 0)),
    ]);

    // Key 1 spends its whole balance but has consumed a nonce, so it is kept. Key 3 is refilled to
    // the default account and deleted. Absent keys spend from the default balance and receive on
    // top of it.
    let body = [
        signed(1, 2, 10, 0),
        signed(4, 3, 10, 0),
        signed(5, 6, 30, 0),
    ];
    assert_eq!(
        explore(|strategy| settle_all(strategy, &accounts, &body)),
        Ok(BTreeMap::from([
            (key(1), Nonced::new(0, 1, 0)),
            (key(2), Nonced::new(DEFAULT_BALANCE + 10, 0, 0)),
            (key(4), Nonced::new(DEFAULT_BALANCE - 10, 1, 0)),
            (key(5), Nonced::new(DEFAULT_BALANCE - 30, 1, 0)),
            (key(6), Nonced::new(DEFAULT_BALANCE + 30, 0, 0)),
        ]))
    );

    // An absent key cannot spend past the default balance.
    let body = [signed(5, 6, DEFAULT_BALANCE + 1, 0)];
    assert_eq!(
        explore(|strategy| settle_all(strategy, &accounts, &body)),
        Err(Rejection::Insufficient(key(5)))
    );
}

#[test]
fn settle_checks_self_transfers_against_the_starting_balance() {
    let accounts = BTreeMap::from([(key(1), Nonced::new(10, 0, 0))]);

    // A self-transfer moves nothing and needs its amount only in the starting balance, even when
    // the batch debits all of it.
    let body = [signed(1, 1, 10, 0), signed(1, 2, 10, 1)];
    let settled = explore(|strategy| settle_all(strategy, &accounts, &body));
    assert_eq!(
        settled.map(|settled| settled[&key(1)]),
        Ok(Nonced::new(0, 2, 0))
    );

    // A credit in the same batch cannot cover a self-transfer.
    let body = [signed(2, 1, 5, 0), signed(1, 1, 11, 0)];
    assert_eq!(
        explore(|strategy| settle_all(strategy, &accounts, &body)),
        Err(Rejection::Refused(key(1)))
    );
}

#[test]
fn settle_replaces_a_balance_an_effect_sets() {
    let accounts = BTreeMap::from([(key(1), Nonced::new(10, 0, 0))]);

    // An effect empties key 1's balance, but its debit still comes off the starting balance, and
    // the batch replaces the emptied balance with 10 - 4. A verifier and a proposer agree.
    let body = [NoncedMulti(vec![
        (key(1), Change::Effect(Effect::Burn)),
        (key(1), Change::Debit(4)),
        (key(2), Change::Credit(4)),
    ])];
    let settled = explore(|strategy| settle_all(strategy, &accounts, &body));
    assert_eq!(
        settled.map(|settled| settled[&key(1)]),
        Ok(Nonced::new(6, 0, 0))
    );
    let (accepted, settled) = explore(|strategy| select_all(strategy, &accounts, &body, 1));
    assert_eq!(accepted, [true]);
    assert_eq!(settled[&key(1)], Nonced::new(6, 0, 0));

    // A later effect on the key sees the balance an earlier effect set, in the same transfer or a
    // later one. A batch refuses the floor after the burn, and a proposer drops the candidate that
    // carries the floor.
    for (candidates, accepted) in [
        (
            vec![NoncedMulti(vec![
                (key(1), Change::Effect(Effect::Burn)),
                (key(1), Change::Effect(Effect::Floor(1))),
            ])],
            vec![false],
        ),
        (
            vec![
                NoncedMulti(vec![(key(1), Change::Effect(Effect::Burn))]),
                NoncedMulti(vec![(key(1), Change::Effect(Effect::Floor(1)))]),
            ],
            vec![true, false],
        ),
    ] {
        assert_eq!(
            explore(|strategy| settle_all(strategy, &accounts, &candidates)),
            Err(Rejection::Refused(key(1)))
        );
        assert_eq!(
            explore(|strategy| select_all(strategy, &accounts, &candidates, 1)),
            (accepted, accounts.clone())
        );
    }
}

#[test]
fn selection_undoes_the_effects_of_dropped_candidates() {
    let accounts = BTreeMap::from([(key(1), Nonced::new(10, 0, 0))]);
    let candidates = [
        // Fits: key 1 has 10.
        signed(1, 2, 6, 0),
        // Dropped: key 1 has only 4 left to spend, so nonce 1 stays unused.
        signed(1, 3, 5, 1),
        // Dropped: nonce 0 is consumed, so the debit and credit applied before it are undone.
        signed(1, 3, 4, 0),
        // Fits: nonce 1 is unused, and key 1 still has 4 to spend.
        signed(1, 3, 4, 1),
        // Dropped: key 2 starts at the default balance, and the credit it received cannot cover a
        // self-transfer.
        signed(2, 2, DEFAULT_BALANCE + 1, 0),
        // Fits: key 2 starts with the amount, and the dropped self-transfer left nonce 0 unused.
        signed(2, 2, DEFAULT_BALANCE, 0),
        // Fits: key 3 spends its whole default balance.
        signed(3, 1, DEFAULT_BALANCE, 0),
    ];
    let (accepted, settled) = explore(|strategy| select_all(strategy, &accounts, &candidates, 2));
    assert_eq!(accepted, [true, false, false, true, false, true, true]);
    assert_eq!(
        settled,
        BTreeMap::from([
            (key(1), Nonced::new(DEFAULT_BALANCE, 2, 0)),
            (key(2), Nonced::new(DEFAULT_BALANCE + 6, 1, 0)),
            (key(3), Nonced::new(4, 1, 0)),
        ])
    );

    // The accepted candidates settle as a batch to the same accounts.
    let body = body(&candidates, &accepted);
    assert_eq!(settle_all(&Sequential, &accounts, &body), Ok(settled));
}

#[test]
fn selection_undoes_applied_effects_when_a_sum_overflows() {
    let mut selection = Selection::new();
    let candidates = [
        NoncedMulti(vec![(key(2), Change::Credit(u64::MAX - DEFAULT_BALANCE))]),
        NoncedMulti(vec![
            (key(1), Change::Effect(Effect::Nonce(0))),
            (key(1), Change::Debit(5)),
            (key(2), Change::Credit(DEFAULT_BALANCE + 1)),
        ]),
        NoncedMulti(vec![
            (key(1), Change::Effect(Effect::Nonce(0))),
            (key(1), Change::Debit(10)),
        ]),
    ];
    let touched = selection.touch(&candidates);
    assert_eq!(touched, 0..2);
    selection.register(vec![None, Some(Nonced::new(10, 0, 0))]);

    // The second candidate's credit would push key 2's credit sum past `u64::MAX`, so the nonce and
    // debit it applied to key 1 before that are undone. The third candidate can then consume the
    // nonce and spend key 1's whole balance.
    assert_eq!(selection.apply(&candidates), vec![true, false, true]);
    assert_eq!(
        selection.settle(&Sequential),
        vec![
            Slot::Put(Nonced::new(u64::MAX, 0, 0)),
            Slot::Put(Nonced::new(0, 1, 0)),
        ]
    );
}

#[test]
fn selection_restores_repeated_effects_and_mutating_refusals() {
    let accounts = BTreeMap::from([(key(1), Nonced::new(10, 0, 0))]);

    // Each `dropped` candidate changes key 1 through its effects and is then dropped. One consumes
    // two nonces and cannot afford its debit, and the other consumes a nonce in an effect that then
    // refuses. Key 1 must be restored to its starting account, so the candidate after it can
    // consume nonce 0 and spend the whole balance.
    for dropped in [
        vec![
            (key(1), Change::Effect(Effect::Nonce(0))),
            (key(1), Change::Credit(0)),
            (key(1), Change::Effect(Effect::Nonce(1))),
            (key(1), Change::Debit(11)),
        ],
        vec![
            (key(1), Change::Credit(5)),
            (key(1), Change::Effect(Effect::RefuseAfterNonce(0))),
            (key(1), Change::Debit(1)),
        ],
    ] {
        let candidates = [
            NoncedMulti(dropped),
            NoncedMulti(vec![
                (key(1), Change::Effect(Effect::Nonce(0))),
                (key(1), Change::Debit(10)),
            ]),
        ];
        for round in [1, 2] {
            let (accepted, settled) =
                explore(|strategy| select_all(strategy, &accounts, &candidates, round));
            assert_eq!(accepted, [false, true]);
            assert_eq!(settled, BTreeMap::from([(key(1), Nonced::new(0, 1, 0))]));
            let body = body(&candidates, &accepted);
            assert_eq!(settle_all(&Sequential, &accounts, &body), Ok(settled));
        }
    }
}

#[test]
fn selection_settles_as_the_plan_of_the_accepted_signed_candidates() {
    // Random candidates from accounts that have consumed nonce 0, with nonces close enough to
    // collide and amounts large enough that many do not fit.
    let mut rng = TestRng::new(29);
    let keys = 64u64;
    let mut accounts = BTreeMap::new();
    for n in 0..keys {
        if rng.random_bool(0.7) {
            accounts.insert(key(n), Nonced::new(rng.random_range(0..50), 1, 0));
        }
    }
    let candidates: Vec<Signed> = (0..2_000)
        .map(|_| {
            signed(
                rng.random_range(0..keys),
                rng.random_range(0..keys),
                rng.random_range(0..20),
                rng.random_range(0..80),
            )
        })
        .collect();
    assert_selection_matches_plan(&accounts, &candidates);
}

#[test]
fn execute_carries_nonces_across_batches() {
    deterministic::Runner::default().start(|context| async move {
        let db = NoncedAny::init(context.child("db"), variable_config("nonced"), None)
            .await
            .unwrap();

        // Key 1 spends its whole default balance with nonce 0 and keeps its key.
        let (db, _) = run(db, &[signed(1, 2, DEFAULT_BALANCE, 0)]).await.unwrap();
        assert_eq!(
            accounts(&db, 3).await,
            BTreeMap::from([
                (key(1), Nonced::new(0, 1, 0)),
                (key(2), Nonced::new(2 * DEFAULT_BALANCE, 0, 0)),
            ])
        );

        // A later batch that replays nonce 0 is refused, though its transfer moves nothing, and
        // leaves the database unchanged.
        let before = db.root();
        let replay = [signed(1, 2, 0, 0)];
        assert_eq!(
            execute(&db, &replay).await.err(),
            Some(Rejection::Refused(key(1)))
        );
        assert_eq!(db.root(), before);

        // Key 1 consumes its next nonce while key 2 consumes its first to refill key 1.
        let (db, _) = run(db, &[signed(1, 1, 0, 1), signed(2, 1, 50, 0)])
            .await
            .unwrap();
        assert_eq!(
            accounts(&db, 3).await,
            BTreeMap::from([
                (key(1), Nonced::new(50, 2, 0)),
                (key(2), Nonced::new(2 * DEFAULT_BALANCE - 50, 1, 0)),
            ])
        );
        db.destroy().await.unwrap();
    });
}

#[test]
fn select_merkleizes_the_accepted_signed_candidates() {
    deterministic::Runner::default().start(|context| async move {
        // Every key consumes nonce 0 paying the next one, so candidates that replay it are
        // refused.
        let mut rng = TestRng::new(31);
        let keys = 100u64;
        let setup: Vec<Signed> = (0..keys)
            .map(|n| signed(n, (n + 1) % keys, rng.random_range(0..DEFAULT_BALANCE), 0))
            .collect();
        let candidates: Vec<Signed> = (0..600)
            .map(|_| {
                signed(
                    rng.random_range(0..keys + 10),
                    rng.random_range(0..keys + 10),
                    rng.random_range(0..60),
                    rng.random_range(0..8),
                )
            })
            .collect();
        let mut dbs = Vec::new();
        for suffix in ["proposer", "verifier"] {
            dbs.push(
                NoncedCurrent::init(context.child(suffix), current_config(suffix), None)
                    .await
                    .unwrap(),
            );
        }
        select_matches_execute(dbs.try_into().ok().unwrap(), &setup, &candidates, keys + 10).await;
    });
}

/// A database of `A` accounts behind a [`stateful::db`](crate::stateful::db) wrapper. The tests
/// stage, settle, and merkleize through the wrapper's batches.
trait StatefulDb<A: Account>:
    DatabaseSet<deterministic::Context, Merkleized: StatefulMerkleized<Digest = Digest>>
{
    /// Plans and settles `transfers` on a new batch, returning the merkleized batch.
    async fn execute<T>(&self, transfers: &[T]) -> Result<Self::Merkleized, Rejection<Key>>
    where
        T: Transfer<Key = Key, Account = A> + Sync;

    /// Selects from `rounds` in order on a new batch, reading the first round's keys with `stage`
    /// and each later round's new keys with `expand`, and returns the merkleized batch and whether
    /// each candidate was accepted.
    async fn select<T>(&self, rounds: &[Vec<T>]) -> (Self::Merkleized, Vec<bool>)
    where
        T: Transfer<Key = Key, Account = A>;
}

/// Implements [`StatefulDb`] for each wrapped database type through the staged batch methods the
/// wrappers share.
macro_rules! impl_stateful_db {
    ($($db:ty: $account:ty),* $(,)?) => {$(
        impl StatefulDb<$account> for Shared<$db> {
            async fn execute<T>(&self, transfers: &[T]) -> Result<Self::Merkleized, Rejection<Key>>
            where
                T: Transfer<Key = Key, Account = $account> + Sync,
            {
                let plan = Plan::new(transfers, &Sequential)?;
                let keys: Vec<&Key> = plan.keys().iter().collect();
                let (reads, staged) = self.new_batches().await.stage(&keys).await.unwrap();
                let slots = plan.settle(&reads, &Sequential)?;
                Ok(staged.merkleize(slots, Vec::new()).await.unwrap())
            }

            async fn select<T>(&self, rounds: &[Vec<T>]) -> (Self::Merkleized, Vec<bool>)
            where
                T: Transfer<Key = Key, Account = $account>,
            {
                // The first round stages the keys it touches in a new batch.
                let mut selection = Selection::new();
                let touched = selection.touch(&rounds[0]);
                let keys: Vec<&Key> = selection.keys()[touched].iter().collect();
                let (reads, mut staged) = self.new_batches().await.stage(&keys).await.unwrap();
                selection.register(reads);
                let mut accepted = selection.apply(&rounds[0]);

                // Each later round expands the batch with its new keys. They must land in the range
                // `touch` returned, so the slots line up with the selection's keys.
                for round in &rounds[1..] {
                    let touched = selection.touch(round);
                    let keys: Vec<&Key> = selection.keys()[touched.clone()].iter().collect();
                    let (range, reads, expanded) = staged.expand(&keys).await.unwrap();
                    assert_eq!(
                        range, touched,
                        "expand must stage new keys where touch placed them"
                    );
                    selection.register(reads);
                    accepted.extend(selection.apply(round));
                    staged = expanded;
                }

                // The accepted candidates settle to one slot per staged key, in staging order.
                let slots = selection.settle(&Sequential);
                (staged.merkleize(slots, Vec::new()).await.unwrap(), accepted)
            }
        }
    )*};
}

impl_stateful_db!(AnyUnordered: Balance, NoncedCurrent: Nonced);

/// Selects candidates through the [`stateful::db`](crate::stateful::db) wrapper of a proposer's
/// database, then executes exactly the accepted body through the wrapper of a verifier's database
/// and directly on a twin database, all three holding the accounts `setup` leaves. Checks that the
/// three reach the same root and that both wrapped databases hold the reference's accounts among
/// keys `0..keys`.
///
/// The candidates arrive in four rounds: `first`, a replay of `first` that touches only known
/// keys, an empty round, and `last`.
async fn stateful_select_matches_execute<D, S, T>(
    dbs: [D; 3],
    setup: &[S],
    first: Vec<T>,
    last: Vec<T>,
    keys: u64,
) where
    D: TestDb<T::Account>,
    Shared<D>: StatefulDb<T::Account>,
    S: Transfer<Key = Key, Account = T::Account> + Sync,
    T: Transfer<Key = Key> + Clone + Sync,
{
    // Every database starts from the accounts the setup leaves, and the proposer's and verifier's
    // are wrapped in the shared handle the stateful actor holds its database in.
    let mut started = Vec::new();
    for db in dbs {
        started.push(run(db, setup).await.unwrap().0);
    }
    let [proposer, verifier, twin]: [D; 3] = started.try_into().ok().unwrap();
    let start = accounts(&twin, keys).await;
    let proposer = Shared::new("proposer", proposer);
    let verifier = Shared::new("verifier", verifier);

    // The proposer selects a body in rounds and applies it.
    let rounds = [first.clone(), first, Vec::new(), last];
    let (merkleized, accepted) = proposer.select(&rounds).await;
    let proposed = merkleized.root();
    proposer.apply(merkleized).await;

    // The verifier executes exactly the accepted body through its wrapper, and the twin executes
    // it directly.
    let candidates = rounds.concat();
    let body = body(&candidates, &accepted);
    assert!(!body.is_empty() && body.len() < candidates.len());
    let merkleized = verifier.execute(&body).await.unwrap();
    let verified = merkleized.root();
    verifier.apply(merkleized).await;
    let (_, executed) = run(twin, &body).await.unwrap();

    // All three reach the same root, and both wrapped databases hold the accounts the reference
    // settles the body to.
    assert_eq!(verified, proposed);
    assert_eq!(executed, proposed);
    let want = expected(&start, &body).unwrap();
    assert_eq!(accounts(&*proposer.read().await, keys).await, want);
    assert_eq!(accounts(&*verifier.read().await, keys).await, want);
}

#[test]
fn stateful_any_batches_select_and_execute_as_qmdb() {
    deterministic::Runner::default().start(|context| async move {
        // Each key is minted a small balance, so some candidates do not fit. The last round also
        // pays from ten unminted keys that no earlier round touches.
        let mut rng = TestRng::new(37);
        let keys = 50u64;
        let mint: Vec<Multi> = (0..keys)
            .map(|n| Multi(vec![(key(n), Change::Credit(rng.random_range(1..30)))]))
            .collect();
        let mut candidates = |accounts: u64| -> Vec<Payment> {
            (0..200)
                .map(|_| {
                    pay(
                        rng.random_range(0..accounts),
                        rng.random_range(0..accounts),
                        rng.random_range(0..10),
                    )
                })
                .collect()
        };
        let (first, last) = (candidates(keys), candidates(keys + 10));

        // The proposer, the verifier, and the twin each open their own database.
        let mut dbs = Vec::new();
        for suffix in ["proposer", "verifier", "twin"] {
            dbs.push(
                AnyUnordered::init(context.child(suffix), any_config(suffix), None)
                    .await
                    .unwrap(),
            );
        }
        stateful_select_matches_execute(
            dbs.try_into().ok().unwrap(),
            &mint,
            first,
            last,
            keys + 10,
        )
        .await;
    });
}

#[test]
fn stateful_current_batches_select_and_execute_signed_candidates() {
    deterministic::Runner::default().start(|context| async move {
        // Every key consumes nonce 0 paying the next one, so candidates that reuse it are refused,
        // as are replayed candidates whose nonces an earlier round consumed. The last round also
        // pays from ten keys the database does not hold that no earlier round touches.
        let mut rng = TestRng::new(41);
        let keys = 50u64;
        let setup: Vec<Signed> = (0..keys)
            .map(|n| signed(n, (n + 1) % keys, rng.random_range(0..DEFAULT_BALANCE), 0))
            .collect();
        let mut candidates = |accounts: u64| -> Vec<Signed> {
            (0..200)
                .map(|_| {
                    signed(
                        rng.random_range(0..accounts),
                        rng.random_range(0..accounts),
                        rng.random_range(0..60),
                        rng.random_range(0..8),
                    )
                })
                .collect()
        };
        let (first, last) = (candidates(keys), candidates(keys + 10));

        // The proposer, the verifier, and the twin each open their own database.
        let mut dbs = Vec::new();
        for suffix in ["proposer", "verifier", "twin"] {
            dbs.push(
                NoncedCurrent::init(context.child(suffix), current_config(suffix), None)
                    .await
                    .unwrap(),
            );
        }
        stateful_select_matches_execute(
            dbs.try_into().ok().unwrap(),
            &setup,
            first,
            last,
            keys + 10,
        )
        .await;
    });
}

#[test]
fn selection_leaves_zero_only_keys_unstaged() {
    // A zero payment moves nothing, so neither of its keys is touched or staged, and applying it
    // accepts it without changing any account.
    let mut selection = Selection::new();
    let transfers = [pay(1, 2, 0)];
    assert_eq!(selection.touch(&transfers), 0..0);
    selection.register(Vec::new());
    assert_eq!(selection.apply(&transfers), [true]);
    assert!(selection.settle(&Sequential).is_empty());
}

#[test]
fn selection_applies_transfers_other_than_the_last_touched() {
    // The touched round caches the index of each of its changes, in order.
    let mut selection = Selection::new();
    let touched = selection.touch(&[pay(1, 2, 2), pay(3, 4, 3)]);
    assert_eq!(touched, 0..4);
    selection.register(vec![Some(Balance(10)); 4]);

    // Different transfers over the same keys match the cache only in places and look up the rest,
    // reaching the same accounts as settling them as a batch.
    let applied = [pay(4, 1, 3), pay(2, 3, 2), pay(1, 2, 1)];
    assert_eq!(selection.apply(&applied), [true; 3]);
    assert_eq!(
        selection.settle(&Sequential),
        [
            Slot::Put(Balance(12)),
            Slot::Put(Balance(9)),
            Slot::Put(Balance(12)),
            Slot::Put(Balance(7)),
        ]
    );
}

#[test]
fn seeded_plans_and_selections_reproduce_their_key_order() {
    // Enough transfers for every execution shape to split the hashing.
    let transfers: Vec<Payment> = (0..3 * MIN_HASH_BATCH.get() as u64)
        .map(|n| pay(n % 257, (n + 1) % 257, 1))
        .collect();

    // Two plans with the same seed order their keys alike under the same shape. Different shapes
    // may order them differently, so each shape compares only its own plans.
    explore(|strategy| {
        let first = Plan::with_seed(&transfers, 42, strategy).unwrap();
        let second = Plan::with_seed(&transfers, 42, strategy).unwrap();
        assert_eq!(first.keys(), second.keys());
    });

    // Two selections with the same seed touch the same keys in the same order, round by round.
    let mut first = Selection::with_seed(42);
    let mut second = Selection::with_seed(42);
    for round in transfers.chunks(17) {
        assert_eq!(first.touch(round), second.touch(round));
    }
    assert_eq!(first.keys(), second.keys());
}

#[test]
fn plan_keeps_sums_and_effect_order_with_and_without_buckets() {
    // Each of 32 keys consumes its nonces in order, one per transfer, debits 1, and credits the
    // next key 2. One hash batch of transfers deduplicates without buckets, and three are bucketed
    // by partition under every split shape.
    for len in [MIN_HASH_BATCH.get(), 3 * MIN_HASH_BATCH.get()] {
        let transfers: Vec<NoncedMulti> = (0..len as u64)
            .map(|n| {
                NoncedMulti(vec![
                    (key(n % 32), Change::Effect(Effect::Nonce(n / 32))),
                    (key(n % 32), Change::Debit(1)),
                    (key((n + 1) % 32), Change::Credit(2)),
                ])
            })
            .collect();

        // Every shape gives each key the same sums and its nonces in transfer order.
        let plan = explore(|strategy| {
            let plan = Plan::new(&transfers, strategy).unwrap();
            (0..plan.len())
                .map(|index| {
                    let nonces: Vec<u64> = plan
                        .effects_of(index)
                        .iter()
                        .map(|effect| match effect {
                            Effect::Nonce(nonce) => *nonce,
                            _ => unreachable!("every effect consumes a nonce"),
                        })
                        .collect();
                    let sums = (plan.debits[index], plan.credits[index], nonces);
                    (plan.keys()[index].clone(), sums)
                })
                .collect::<BTreeMap<_, _>>()
        });
        let rounds = len as u64 / 32;
        let want = (0..32)
            .map(|n| (key(n), (rounds, 2 * rounds, (0..rounds).collect())))
            .collect();
        assert_eq!(plan, want);
    }
}

#[test]
fn estimated_changes_samples_the_first_transfer() {
    // Payments have two changes each, and no transfers expect none.
    assert_eq!(estimated_changes(&[pay(1, 2, 1), pay(2, 3, 1)]), 4);
    assert_eq!(estimated_changes::<Payment>(&[]), 0);

    // A first transfer without changes still reserves one per transfer, and one with many changes
    // reserves at most the sampled maximum per transfer.
    let mut transfers = vec![Multi(Vec::new()); 10];
    assert_eq!(estimated_changes(&transfers), 10);
    transfers[0] = Multi(vec![(key(1), Change::Credit(1)); 1_000]);
    assert_eq!(estimated_changes(&transfers), 10 * MAX_SAMPLED_CHANGES);
}
