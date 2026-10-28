//! Settle batches of `u64` balance transfers against a [QMDB](commonware_storage::qmdb) database.
//!
//! Each key holds an [`Account`]: a `u64` balance and any state the application keeps beside it,
//! such as a nonce. A [`Transfer`] names the accounts it touches, how much it debits or credits
//! each, and any effects it has on an account's own state, such as consuming a nonce. A batch of
//! transfers settles against its starting accounts, read for its keys before any of its transfers
//! apply.
//!
//! Each key's final balance is its starting balance less the batch's debits plus the batch's
//! credits. Credits never fund debits in the same batch, even within one transfer. Every key's
//! debits must fit its starting balance, and a credit becomes spendable only in a later batch.
//! Whether the batch's debits and credits can settle, and the balances they leave, therefore depend
//! only on its transfers and starting balances, never on the order of the transfers or of their
//! changes.
//!
//! Each key's effects apply to its starting account in the order of the transfers and of their
//! changes. Each effect sees the starting account as the key's earlier effects changed it, never
//! the balance the batch's debits and credits leave. An account may refuse an effect, for example
//! one that reuses a consumed nonce.
//!
//! A batch settles all or nothing. If any account refuses an effect, any key cannot afford its
//! debits, or any final balance would exceed `u64::MAX`, the whole batch is rejected with a
//! [`Rejection`].
//!
//! A key the database does not hold reads as the default account, and settling an account to the
//! default deletes its key. The module never writes the default account, so in a database only it
//! writes, a key is present exactly when its account differs from the default. An account that
//! records a consumed nonce differs from the default, so it keeps its key even at a zero balance.
//!
//! # Pipeline
//!
//! [`Plan`] and [`Selection`] run the CPU stages. The caller reads and merkleizes through its own
//! staged batch, such as a QMDB [`any`](commonware_storage::qmdb::any) or
//! [`current`](commonware_storage::qmdb::current) batch or a [`stateful::db`](crate::stateful::db)
//! staged batch.
//!
//! ```text
//!     on the strategy's workers                  through the QMDB batch
//!
//!             transfers
//!                 |
//!                 v
//!   +----------------------------+    keys    +----------------------------+
//!   | Plan::new                  |----------->| stage                      |
//!   | one entry per key, with    |            | read every key's starting  |
//!   | its debit and credit sums  |            | account in one batch and   |
//!   | and its effects in order,  |            | keep its location          |
//!   | partitioned by key hash   |            |                            |
//!   +----------------------------+            +----------------------------+
//!                 |              starting accounts  |                |
//!                 | changes .-----------------------'                | staged batch
//!                 v         v                                        |
//!   +----------------------------+                                   v
//!   | Plan::settle               |            +----------------------------+
//!   | apply each key's effects,  |   slots    | merkleize                  |
//!   | then start - debits +      |----------->| apply each slot through    |
//!   | credits for its balance    |            | its staged read and        |---> root
//!   +----------------------------+            | compute the root           |
//!                                             +----------------------------+
//! ```
//!
//! # Examples
//!
//! ## Builders
//!
//! A builder choosing a block's body cannot settle its candidates as one batch, since one that
//! cannot settle would reject them all. [`Selection`] applies the candidates one at a time in block
//! order against the accounts the block starts from and drops each that cannot settle with the ones
//! accepted before it, so a [`Plan`] of the accepted body settles to the same accounts.
//!
//! Candidates arrive in rounds, as from a mempool. Each round, [`touch`](Selection::touch) returns
//! the range holding the keys no earlier round touched, in the order the batch must read them, so
//! the staged slots line up with [`keys`](Selection::keys). The first round reads its keys with
//! `stage` and each later round with the staged batch's `expand`. [`register`](Selection::register)
//! takes their accounts, [`apply`](Selection::apply) accepts or drops each candidate, and
//! [`settle`](Selection::settle) produces one slot per staged key for merkleize.
//!
//! ```
//! use commonware_glue::transfers::{Account, Change, Selection, Transfer};
//! use commonware_parallel::Sequential;
//! use commonware_storage::qmdb::any::batch::Slot;
//! use commonware_utils::sequence::FixedBytes;
//! use std::convert::Infallible;
//!
//! type Address = FixedBytes<4>;
//!
//! // An account that holds only a balance, so a key spent to zero is deleted.
//! #[derive(Clone, Debug, Default, PartialEq, Eq)]
//! struct Balance(u64);
//!
//! impl Account for Balance {
//!     type Effect = Infallible;
//!
//!     fn balance(&self) -> u64 {
//!         self.0
//!     }
//!
//!     fn set_balance(&mut self, balance: u64) {
//!         self.0 = balance;
//!     }
//!
//!     fn apply(&mut self, effect: Infallible) -> bool {
//!         match effect {}
//!     }
//! }
//!
//! struct Payment {
//!     from: Address,
//!     to: Address,
//!     amount: u64,
//! }
//!
//! impl Transfer for Payment {
//!     type Key = Address;
//!     type Account = Balance;
//!
//!     fn changes(&self) -> impl Iterator<Item = (&Address, Change)> {
//!         [
//!             (&self.from, Change::Debit(self.amount)),
//!             (&self.to, Change::Credit(self.amount)),
//!         ]
//!         .into_iter()
//!     }
//! }
//!
//! let [alice, bob, carol, dave] =
//!     [b"alic", b"bob!", b"carl", b"dave"].map(|name| Address::new(*name));
//!
//! // The database holds only Alice, at 10. Each round reads the keys it touches for the first
//! // time, through `stage` for the first round and `expand` for the rest.
//! let balances = |key: &Address| (*key == alice).then_some(Balance(10));
//! let mut selection = Selection::new();
//!
//! // Alice can pay Bob 6 but not Carol 5 more, so the second candidate is dropped.
//! let round = [
//!     Payment { from: alice.clone(), to: bob.clone(), amount: 6 },
//!     Payment { from: alice.clone(), to: carol.clone(), amount: 5 },
//! ];
//! let touched = selection.touch(&round);
//! let reads: Vec<Option<Balance>> = selection.keys()[touched].iter().map(balances).collect();
//! selection.register(reads);
//! assert_eq!(selection.apply(&round), vec![true, false]);
//!
//! // Bob's credit cannot fund a payment in the same block, while Alice's remaining 4 can.
//! let round = [
//!     Payment { from: bob.clone(), to: carol.clone(), amount: 1 },
//!     Payment { from: alice.clone(), to: dave.clone(), amount: 4 },
//! ];
//! let touched = selection.touch(&round);
//! assert_eq!(selection.keys()[touched.clone()], [dave.clone()]);
//! let reads: Vec<Option<Balance>> = selection.keys()[touched].iter().map(balances).collect();
//! selection.register(reads);
//! assert_eq!(selection.apply(&round), vec![false, true]);
//!
//! // The accepted body settles to one slot per staged key. Alice is spent to zero and deleted, Bob
//! // and Dave are created, and Carol, touched only by dropped candidates, is left alone.
//! let slots = selection.settle(&Sequential);
//! assert_eq!(
//!     slots,
//!     [Slot::Delete, Slot::Put(Balance(6)), Slot::Keep, Slot::Put(Balance(4))]
//! );
//! ```
//!
//! ## Verifiers
//!
//! A verifier settles a block's body as one batch. [`Plan::new`] gives the keys to stage, in the
//! order their reads must come back, and [`Plan::settle`] turns those reads into one [`Slot`] per
//! staged key for merkleize. It rejects a body that cannot settle before anything is written.
//!
//! ```
//! use commonware_glue::transfers::Plan;
//! use commonware_parallel::Sequential;
//! use commonware_storage::qmdb::any::batch::Slot;
//! # use commonware_glue::transfers::{Account, Change, Transfer};
//! # use commonware_utils::sequence::FixedBytes;
//! # use std::convert::Infallible;
//! # type Address = FixedBytes<4>;
//! # #[derive(Clone, Debug, Default, PartialEq, Eq)]
//! # struct Balance(u64);
//! # impl Account for Balance {
//! #     type Effect = Infallible;
//! #     fn balance(&self) -> u64 { self.0 }
//! #     fn set_balance(&mut self, balance: u64) { self.0 = balance; }
//! #     fn apply(&mut self, effect: Infallible) -> bool { match effect {} }
//! # }
//! # struct Payment { from: Address, to: Address, amount: u64 }
//! # impl Transfer for Payment {
//! #     type Key = Address;
//! #     type Account = Balance;
//! #     fn changes(&self) -> impl Iterator<Item = (&Address, Change)> {
//! #         [(&self.from, Change::Debit(self.amount)), (&self.to, Change::Credit(self.amount))]
//! #             .into_iter()
//! #     }
//! # }
//!
//! let alice = Address::new(*b"alic");
//! let bob = Address::new(*b"bob!");
//! let body = [
//!     Payment { from: alice.clone(), to: bob.clone(), amount: 30 },
//!     Payment { from: bob.clone(), to: alice.clone(), amount: 5 },
//! ];
//!
//! // The plan holds each key the body changes once, with its debit and credit sums.
//! let plan = Plan::new(&body, &Sequential).unwrap();
//! assert_eq!(plan.len(), 2);
//!
//! // Read the starting balances in `plan.keys()` order, as the database holds them. Bob pays
//! // from his starting balance, since Alice's payment cannot fund his within the same batch.
//! let reads: Vec<Option<Balance>> = plan
//!     .keys()
//!     .iter()
//!     .map(|key| Some(Balance(if *key == alice { 100 } else { 20 })))
//!     .collect();
//!
//! // Settling yields the slot to merkleize for each key, in the same order.
//! let slots = plan.settle(&reads, &Sequential).unwrap();
//! let settled: Vec<(Address, Slot<Balance>)> = plan.keys().iter().cloned().zip(slots).collect();
//! assert!(settled.contains(&(alice, Slot::Put(Balance(75)))));
//! assert!(settled.contains(&(bob, Slot::Put(Balance(45)))));
//! ```

use ahash::RandomState;
use commonware_parallel::Strategy;
use commonware_storage::qmdb::any::batch::Slot;
use commonware_utils::{
    Array, Widen,
    handles::{FINGERPRINT_SHIFT, Table},
    prefetch::{self, Lookahead},
};
use std::{
    convert::Infallible, fmt::Debug, hash::BuildHasher, iter, num::NonZeroUsize, ops::Range,
};
use thiserror::Error;

mod select;
pub use select::Selection;

/// A movement of `u64` value between accounts, with any effects on their own state.
///
/// Implement this for a transaction type to settle batches of it with [`Plan`] and to choose a
/// block's transfers with [`Selection`].
pub trait Transfer {
    /// The key an account is stored under.
    type Key: Array;

    /// The account each key holds.
    type Account: Account;

    /// The accounts this transfer changes, with the change to each.
    ///
    /// A key may appear more than once. Its debits and credits are summed, and its effects apply in
    /// the order listed.
    #[allow(clippy::type_complexity)]
    fn changes(
        &self,
    ) -> impl Iterator<Item = (&Self::Key, Change<<Self::Account as Account>::Effect>)>;
}

/// The value a key holds: a `u64` balance and any state the application keeps beside it.
///
/// A key the database does not hold reads as the default account, and settling a key to the
/// default deletes it. The default should therefore be the state of a fresh account, such as its
/// starting balance with no nonce consumed. Settling clones and compares accounts to decide which
/// keys to write, so a clone must be independent of its original and accounts that compare equal
/// must encode the same.
///
/// # Examples
///
/// An account whose transfers consume its nonces in sequence keeps its key after spending its
/// whole balance, since deleting it would let its nonces be replayed.
///
/// ```
/// use commonware_glue::transfers::{Account, Change, Plan, Rejection, Transfer};
/// use commonware_parallel::Sequential;
/// use commonware_storage::qmdb::any::batch::Slot;
/// use commonware_utils::sequence::FixedBytes;
///
/// type Address = FixedBytes<4>;
///
/// #[derive(Clone, Debug, Default, PartialEq, Eq)]
/// struct Sequenced {
///     balance: u64,
///     nonce: u64,
/// }
///
/// impl Account for Sequenced {
///     // The nonce a transfer consumes.
///     type Effect = u64;
///
///     fn balance(&self) -> u64 {
///         self.balance
///     }
///
///     fn set_balance(&mut self, balance: u64) {
///         self.balance = balance;
///     }
///
///     fn apply(&mut self, nonce: u64) -> bool {
///         let Some(next) = nonce.checked_add(1).filter(|_| nonce == self.nonce) else {
///             return false;
///         };
///         self.nonce = next;
///         true
///     }
/// }
///
/// struct Payment {
///     from: Address,
///     to: Address,
///     amount: u64,
///     nonce: u64,
/// }
///
/// impl Transfer for Payment {
///     type Key = Address;
///     type Account = Sequenced;
///
///     fn changes(&self) -> impl Iterator<Item = (&Address, Change<u64>)> {
///         [
///             (&self.from, Change::Effect(self.nonce)),
///             (&self.from, Change::Debit(self.amount)),
///             (&self.to, Change::Credit(self.amount)),
///         ]
///         .into_iter()
///     }
/// }
///
/// // Alice holds 10 and has consumed no nonce. Each body settles against that account.
/// let alice = Address::new(*b"alic");
/// let bob = Address::new(*b"bob!");
/// let pay = |nonce| Payment { from: alice.clone(), to: bob.clone(), amount: 5, nonce };
/// let settle = |body: &[Payment]| {
///     let plan = Plan::new(body, &Sequential)?;
///     let reads: Vec<Option<Sequenced>> = plan
///         .keys()
///         .iter()
///         .map(|key| (*key == alice).then_some(Sequenced { balance: 10, nonce: 0 }))
///         .collect();
///     let slots = plan.settle(&reads, &Sequential)?;
///     Ok::<_, Rejection<Address>>(plan.keys().iter().cloned().zip(slots).collect::<Vec<_>>())
/// };
///
/// // Spending the whole balance writes an account at zero that records both nonces.
/// let settled = settle(&[pay(0), pay(1)]).unwrap();
/// let spent = Sequenced { balance: 0, nonce: 2 };
/// assert!(settled.contains(&(alice.clone(), Slot::Put(spent))));
///
/// // Replaying a nonce rejects the batch, though Alice can afford both payments.
/// assert_eq!(settle(&[pay(0), pay(0)]), Err(Rejection::Refused(alice)));
/// ```
pub trait Account: Clone + Debug + Default + Eq + Send + Sync {
    /// A change to the account's own state that a transfer can make, such as consuming a nonce.
    /// An account with no such state uses [`Infallible`].
    type Effect: Clone + Debug + Send + Sync;

    /// Returns the account's balance.
    fn balance(&self) -> u64;

    /// Sets the account's balance.
    fn set_balance(&mut self, balance: u64);

    /// Applies `effect`, returning whether the account accepts it.
    ///
    /// The result and the account it leaves must depend only on the account and `effect`, since
    /// every builder and verifier applies the same effects and must reach the same accounts. An
    /// account that refuses may be left changed, since it is then discarded.
    ///
    /// A batch sets the balance from its debits and credits after applying the effects, so a
    /// balance set here is seen only by the key's later effects.
    fn apply(&mut self, effect: Self::Effect) -> bool;
}

/// A change to one account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Change<E = Infallible> {
    /// Removes value from the balance.
    Debit(u64),
    /// Adds value to the balance.
    Credit(u64),
    /// Applies an effect to the account's own state.
    Effect(E),
}

/// Why a batch of transfers cannot settle.
///
/// Whether a batch is rejected depends only on its transfers and starting accounts. When several
/// keys offend, any of them may be reported, so the reported key and reason must not enter
/// consensus-visible data.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Rejection<K: Debug> {
    /// The key's account refuses one of its effects.
    #[error("account {0:?} refuses an effect")]
    Refused(K),
    /// The key's debits exceed its starting balance.
    #[error("account {0:?} cannot afford its debits")]
    Insufficient(K),
    /// The key's final balance exceeds `u64::MAX`.
    #[error("the balance of account {0:?} overflows")]
    Overflow(K),
}

/// The keys a batch of transfers changes, each once, with each key's debit and credit sums and its
/// effects in transfer order.
///
/// The key order is unspecified and may differ between plans of the same transfers. Only the set
/// of keys and each key's changes are fixed. Read the accounts in [`keys`](Self::keys) order and
/// pass them to [`settle`](Self::settle), then merkleize its slots through the staged batch.
#[derive(Clone, Debug)]
pub struct Plan<K, A: Account> {
    /// Every key the batch changes, each once.
    keys: Vec<K>,
    /// The sum of each key's debits, in `keys` order.
    debits: Vec<u64>,
    /// The sum of each key's credits, in `keys` order.
    credits: Vec<u64>,
    /// Where each key's effects start in `effects`, then where the last key's end, or empty when no
    /// key has one.
    effect_offsets: Vec<usize>,
    /// Each key's effects in transfer order, grouped in `keys` order.
    effects: Vec<A::Effect>,
}

/// Partitions of the key hash space that the plan's workers split among themselves.
///
/// Every key falls in one partition, so the worker that owns it sums its changes without sharing a
/// table. Far more partitions than workers give any worker count an even share. Every hash batch
/// allocates a bucket per partition, so more partitions cost more allocations.
const PARTITIONS: usize = 256;

/// Shift that maps a key hash to its partition, using the bits just below the table fingerprint
/// and above the low bits that select its home slot.
const PARTITION_SHIFT: u32 = FINGERPRINT_SHIFT - PARTITIONS.trailing_zeros();

/// Fewest transfers a worker hashes on its own.
///
/// Each hash batch allocates a bucket per partition, and every shard later walks that batch's
/// buckets for its partitions, so a batch needs thousands of transfers before its hashing
/// outweighs those fixed costs. An input shorter than two batches is hashed on the calling thread.
const MIN_HASH_BATCH: NonZeroUsize = NonZeroUsize::new(1 << 12).expect("minimum must be nonzero");

/// Most changes per transfer that sizing extrapolates from a batch's first transfer.
///
/// Hashing reserves room for every transfer to have as many changes as the first one, so a first
/// transfer with many changes could otherwise reserve far more than the batch holds.
const MAX_SAMPLED_CHANGES: usize = 4;

/// Each bucket reserves its even share divided by this as a margin for uneven hashing.
///
/// A bucket's touch count has a standard deviation of about the square root of its even share.
/// With [`BUCKET_SPARE`], a quarter of the share covers about two standard deviations at the
/// smallest batch the pool splits off and more at larger ones, so few buckets regrow.
const BUCKET_MARGIN_DIVISOR: usize = 4;

/// Capacity each bucket reserves beyond its share and margin, so small buckets rarely grow.
const BUCKET_SPARE: usize = 4;

/// Fewest partitions a worker deduplicates on its own.
///
/// Each shard sizes a table and key arrays for its touches and walks every hash batch's buckets for
/// its partitions, so a worker takes at least a sixteenth of the partitions and at most 16 shards
/// split the plan.
const MIN_PARTITION_BATCH: NonZeroUsize =
    NonZeroUsize::new(PARTITIONS / 16).expect("minimum must be nonzero");

/// Fewest touches for which a plan too short to split its hashing offers its deduplication to the
/// strategy to split.
///
/// Fewer touches deduplicate on the calling thread, where asking costs more than a split could
/// save.
const MIN_SPLIT_TOUCHES: usize = 1 << 11;

/// Fewest keys a worker settles on its own.
///
/// Settling a key takes a few arithmetic steps and a slot write, so only a batch of many thousands
/// of keys outweighs the cost of handing it to a worker.
const MIN_SETTLE_BATCH: NonZeroUsize = NonZeroUsize::new(1 << 14).expect("minimum must be nonzero");

/// Distance, in lookups, from the lookup in progress to the one whose home slot is prefetched.
///
/// A prefetched line must arrive before its lookup runs, so the distance times the time a cached
/// lookup takes must cover a miss to memory. Much further ahead, the line can be evicted before
/// its lookup uses it.
const PREFETCH_DISTANCE: usize = 16;

/// One change of a batch, other than a zero debit or credit, with its key's hash.
struct Touch<'a, K, E> {
    hash: u64,
    key: &'a K,
    change: Change<E>,
}

/// The touches of one range of transfers, bucketed by partition.
type Buckets<'a, K, E> = Vec<Vec<Touch<'a, K, E>>>;

impl<K: Array, A: Account> Plan<K, A> {
    /// Plans `transfers`, gathering their changes for each key.
    ///
    /// Debits and credits are summed, and effects keep their transfer order. Keys touched only by
    /// zero debits and credits are left out, since nothing needs to be read or written for them.
    /// Memory and expected work are linear in the number of transfers and changes, repeated keys
    /// included.
    ///
    /// Keys are placed by a hash keyed afresh for every plan, so transfers cannot be chosen in
    /// advance to collide. `strategy` splits the hashing and the deduplication among its workers.
    ///
    /// # Errors
    ///
    /// Returns [`Rejection::Insufficient`] if a key's debits sum to more than `u64::MAX` and
    /// [`Rejection::Overflow`] if its credits do. No balance can afford such debits or hold such
    /// credits.
    ///
    /// # Panics
    ///
    /// Panics if one worker plans more than `u32::MAX` distinct keys.
    pub fn new<T>(transfers: &[T], strategy: &impl Strategy) -> Result<Self, Rejection<K>>
    where
        T: Transfer<Key = K, Account = A> + Sync,
    {
        Self::with_hasher(transfers, &RandomState::new(), strategy)
    }

    /// Plans `transfers` with a reproducible hash key.
    ///
    /// A seed adversaries can predict lets them choose colliding keys. Use this for reproducible
    /// runs, such as tests under the deterministic runtime. [`new`](Self::new) keys each plan
    /// randomly. Errors and panics are as for [`new`](Self::new).
    pub fn with_seed<T>(
        transfers: &[T],
        seed: u64,
        strategy: &impl Strategy,
    ) -> Result<Self, Rejection<K>>
    where
        T: Transfer<Key = K, Account = A> + Sync,
    {
        Self::with_hasher(transfers, &RandomState::with_seeds(seed, 0, 0, 0), strategy)
    }

    /// Plans `transfers` with `hasher` placing the keys in partitions and table slots.
    fn with_hasher<T>(
        transfers: &[T],
        hasher: &(impl BuildHasher + Sync),
        strategy: &impl Strategy,
    ) -> Result<Self, Rejection<K>>
    where
        T: Transfer<Key = K, Account = A> + Sync,
    {
        // No strategy splits the hashing of fewer than two hash batches, so such an input hashes
        // its touches on the calling thread. Unless they are few, the strategy then decides whether
        // deduplicating them is worth bucketing them by partition and splitting the partitions
        // among its workers.
        if transfers.len() < 2 * MIN_HASH_BATCH.get() {
            let mut touches = Vec::with_capacity(estimated_changes(transfers));
            for_each_touch(transfers, hasher, |touch| touches.push(touch));
            if touches.len() < MIN_SPLIT_TOUCHES {
                return Shard::build(iter::once(touches.as_slice()), hasher).map(Self::from);
            }
            let per_partition = touches.len().div_ceil(PARTITIONS);
            return strategy.try_run_batches(
                PARTITIONS,
                MIN_PARTITION_BATCH,
                per_partition,
                |batches| {
                    if batches.is_whole() {
                        return Shard::build(iter::once(touches.as_slice()), hasher)
                            .map(Self::from);
                    }

                    // Bucket the touches by partition, so each worker reads only its own.
                    let mut buckets = empty_buckets(touches.len());
                    for touch in touches {
                        buckets[partition(touch.hash)].push(touch);
                    }
                    batches
                        .try_map_collect_vec(
                            |ranges| ranges.into_iter().map(|partitions| (partitions, &buckets)),
                            |(partitions, buckets)| {
                                Shard::build(buckets[partitions].iter().map(Vec::as_slice), hasher)
                            },
                        )
                        .map(Self::from_shards)
                },
            );
        }

        // Hash the key of each change in parallel over the transfers and bucket the touches by
        // partition, so each partition's worker reads only its own buckets.
        let buckets: Vec<Buckets<'_, K, A::Effect>> =
            strategy.run_batches(transfers.len(), MIN_HASH_BATCH, 1, |batches| {
                batches.map_collect_vec(
                    |ranges| ranges.into_iter().map(|range| &transfers[range]),
                    |transfers| {
                        let mut buckets = empty_buckets(estimated_changes(transfers));
                        for_each_touch(transfers, hasher, |touch| {
                            buckets[partition(touch.hash)].push(touch);
                        });
                        buckets
                    },
                )
            });

        // Each worker owns a range of partitions and deduplicates their touches, so no two
        // workers hold the same key and the shards concatenate into the plan.
        let total: usize = buckets.iter().flatten().map(Vec::len).sum();
        let per_partition = total.div_ceil(PARTITIONS);
        let shards = strategy.try_run_batches(
            PARTITIONS,
            MIN_PARTITION_BATCH,
            per_partition,
            |batches| {
                batches.try_map_collect_vec(
                    |ranges| ranges.into_iter().map(|partitions| (partitions, &buckets)),
                    |(partitions, buckets)| {
                        Shard::build(
                            buckets.iter().flat_map(|buckets| {
                                buckets[partitions.clone()].iter().map(Vec::as_slice)
                            }),
                            hasher,
                        )
                    },
                )
            },
        )?;
        Ok(Self::from_shards(shards))
    }

    /// Concatenates `shards`, shifting effect offsets past the preceding shards.
    fn from_shards(shards: Vec<Shard<K, A::Effect>>) -> Self {
        let len = shards.iter().map(|shard| shard.keys.len()).sum();
        let effects: usize = shards.iter().map(|shard| shard.effects.len()).sum();
        let mut plan = Self {
            keys: Vec::with_capacity(len),
            debits: Vec::with_capacity(len),
            credits: Vec::with_capacity(len),
            effect_offsets: Vec::with_capacity(if effects == 0 { 0 } else { len + 1 }),
            effects: Vec::with_capacity(effects),
        };
        if effects != 0 {
            plan.effect_offsets.push(0);
        }
        for mut shard in shards {
            if effects != 0 {
                let base = plan.effects.len();
                if shard.effect_offsets.is_empty() {
                    plan.effect_offsets
                        .extend(iter::repeat_n(base, shard.keys.len()));
                } else {
                    plan.effect_offsets.extend(
                        shard
                            .effect_offsets
                            .iter()
                            .skip(1)
                            .map(|offset| base + offset),
                    );
                }
                plan.effects.append(&mut shard.effects);
            }
            plan.keys.append(&mut shard.keys);
            plan.debits.append(&mut shard.debits);
            plan.credits.append(&mut shard.credits);
        }
        plan
    }

    /// Every key the batch changes, each once.
    pub fn keys(&self) -> &[K] {
        &self.keys
    }

    /// The number of keys the batch changes.
    pub const fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the batch changes no key.
    pub const fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Settles the batch against `reads`, the starting account of each key in [`keys`](Self::keys)
    /// order, `None` for a key the database does not hold.
    ///
    /// Returns one [`Slot`] per key, in the same order, for the staged batch to merkleize: a keep
    /// for an account left as it started, a delete for a held key settled to the default account,
    /// and a put of the settled account for the rest. `strategy` splits the keys among its workers.
    ///
    /// # Errors
    ///
    /// Returns [`Rejection::Refused`] if an account refuses one of its effects,
    /// [`Rejection::Insufficient`] if a key's debits exceed its starting balance, and
    /// [`Rejection::Overflow`] if its final balance exceeds `u64::MAX`.
    ///
    /// # Panics
    ///
    /// Panics if `reads` does not hold one account per key.
    pub fn settle(
        &self,
        reads: &[Option<A>],
        strategy: &impl Strategy,
    ) -> Result<Vec<Slot<A>>, Rejection<K>> {
        assert_eq!(
            reads.len(),
            self.len(),
            "reads must hold one account per key"
        );
        settle_batches(self.len(), strategy, |range, slots| {
            let default = A::default();
            for (index, slot) in range.zip(slots) {
                // A key the database does not hold starts as the default account, and its effects
                // apply to the starting account in transfer order.
                let start = reads[index].clone().unwrap_or_default();
                let mut account = start.clone();
                for effect in self.effects_of(index) {
                    if !account.apply(effect.clone()) {
                        return Err(Rejection::Refused(self.keys[index].clone()));
                    }
                }

                // Debits come off the starting balance before credits are added, so credits never
                // fund debits. The result replaces any balance an effect set.
                let remaining = start
                    .balance()
                    .checked_sub(self.debits[index])
                    .ok_or_else(|| Rejection::Insufficient(self.keys[index].clone()))?;
                let balance = remaining
                    .checked_add(self.credits[index])
                    .ok_or_else(|| Rejection::Overflow(self.keys[index].clone()))?;
                *slot = settled_slot(account, balance, &start, &default);
            }
            Ok(())
        })
    }

    /// The effects on the key at `index`, in transfer order.
    fn effects_of(&self, index: usize) -> &[A::Effect] {
        if self.effect_offsets.is_empty() {
            return &[];
        }
        &self.effects[self.effect_offsets[index]..self.effect_offsets[index + 1]]
    }
}

impl<K, A: Account> From<Shard<K, A::Effect>> for Plan<K, A> {
    fn from(shard: Shard<K, A::Effect>) -> Self {
        Self {
            keys: shard.keys,
            debits: shard.debits,
            credits: shard.credits,
            effect_offsets: shard.effect_offsets,
            effects: shard.effects,
        }
    }
}

/// The keys of one range of partitions, each once, with their debit and credit sums and effects.
struct Shard<K, E> {
    /// Each key changed in the partitions, once.
    keys: Vec<K>,
    /// The sum of each key's debits, in `keys` order.
    debits: Vec<u64>,
    /// The sum of each key's credits, in `keys` order.
    credits: Vec<u64>,
    /// Where each key's effects start in `effects`, then where the last key's end, or empty when no
    /// key has one.
    effect_offsets: Vec<usize>,
    /// Each key's effects in transfer order, grouped in `keys` order.
    effects: Vec<E>,
}

impl<K: Array, E: Clone> Shard<K, E> {
    /// Deduplicates `touches`, sums their debits and credits, and groups their effects by key.
    ///
    /// The index is sized for every touch, so it never grows and never rehashes a key through
    /// `hasher`.
    fn build<'a>(
        touches: impl Iterator<Item = &'a [Touch<'a, K, E>]> + Clone,
        hasher: &impl BuildHasher,
    ) -> Result<Self, Rejection<K>>
    where
        K: 'a,
        E: 'a,
    {
        let expected = touches.clone().map(<[_]>::len).sum();
        let mut index = KeyIndex::with_capacity(expected);
        let mut debits: Vec<u64> = Vec::with_capacity(expected);
        let mut credits: Vec<u64> = Vec::with_capacity(expected);
        let mut effects = Vec::new();
        for run in touches {
            // Prefetch the home slot of each touch a fixed distance ahead of its lookup, so the
            // lookup waits less on memory.
            let mut ahead = Lookahead::new(PREFETCH_DISTANCE);
            let mut scan = run.iter();
            loop {
                if prefetch::ENABLED {
                    for touch in ahead.advance(scan.as_slice()) {
                        index.prefetch(touch.hash);
                    }
                }
                let Some(touch) = scan.next() else { break };
                let (position, inserted) = index.find_or_insert(touch.key, touch.hash, hasher);
                if inserted {
                    debits.push(0);
                    credits.push(0);
                }

                // No balance can afford debits that sum past `u64::MAX`, and credits that sum past
                // it overflow every balance. An effect is set aside with its key's position and
                // grouped once every touch is placed.
                match &touch.change {
                    Change::Debit(amount) => {
                        debits[position] = debits[position]
                            .checked_add(*amount)
                            .ok_or_else(|| Rejection::Insufficient(touch.key.clone()))?;
                    }
                    Change::Credit(amount) => {
                        credits[position] = credits[position]
                            .checked_add(*amount)
                            .ok_or_else(|| Rejection::Overflow(touch.key.clone()))?;
                    }
                    Change::Effect(effect) => effects.push((position, effect.clone())),
                }
            }
        }

        // Each key's touches arrive in transfer order, one hash batch after another, and the
        // grouping is stable, so each key's effects stay in transfer order.
        let keys = index.into_keys();
        let (effect_offsets, effects) = group_effects(keys.len(), effects);
        Ok(Self {
            keys,
            debits,
            credits,
            effect_offsets,
            effects,
        })
    }
}

/// Groups `effects`, each paired with its key's position below `keys`, into one run per key that
/// keeps their order. Returns the offset of each key's run, with a final offset, and the runs, or
/// two empty vectors when there are no effects.
fn group_effects<E: Clone>(keys: usize, effects: Vec<(usize, E)>) -> (Vec<usize>, Vec<E>) {
    let Some((_, filler)) = effects.first() else {
        return (Vec::new(), Vec::new());
    };

    // Count each key's effects, then sum the counts so each key's run starts after the runs of the
    // keys before it.
    let mut offsets = vec![0; keys + 1];
    for &(position, _) in &effects {
        offsets[position + 1] += 1;
    }
    for position in 0..keys {
        offsets[position + 1] += offsets[position];
    }

    // Fill each key's run from its end, walking the effects backward so each run keeps its order.
    // Every slot is written, so `filler` only initializes them.
    let mut next = offsets[1..].to_vec();
    let mut grouped = vec![filler.clone(); effects.len()];
    for (position, effect) in effects.into_iter().rev() {
        next[position] -= 1;
        grouped[next[position]] = effect;
    }
    (offsets, grouped)
}

/// Calls `touch` with each touch of `transfers` in order. Zero debits and credits move no value and
/// are left out.
fn for_each_touch<'a, T: Transfer>(
    transfers: &'a [T],
    hasher: &impl BuildHasher,
    mut touch: impl FnMut(Touch<'a, T::Key, <T::Account as Account>::Effect>),
) {
    // A plain loop over the changes compiles to a much faster scan than chained iterator adapters.
    for (key, change) in transfers.iter().flat_map(Transfer::changes) {
        if matches!(change, Change::Debit(0) | Change::Credit(0)) {
            continue;
        }
        touch(Touch {
            hash: hasher.hash_one(key.as_ref()),
            key,
            change,
        });
    }
}

/// Estimates the changes in `transfers` from the first transfer's count, between one and
/// [`MAX_SAMPLED_CHANGES`] per transfer.
fn estimated_changes<T: Transfer>(transfers: &[T]) -> usize {
    let per_transfer = transfers.first().map_or(0, |transfer| {
        transfer.changes().take(MAX_SAMPLED_CHANGES).count().max(1)
    });
    transfers.len() * per_transfer
}

/// Returns an empty bucket for each partition, sized for `expected` touches spread over them.
///
/// Each bucket reserves an even share plus a margin for uneven hashing, so most buckets never
/// grow.
fn empty_buckets<'a, K, E>(expected: usize) -> Buckets<'a, K, E> {
    let share = expected.div_ceil(PARTITIONS);
    let capacity = share + share / BUCKET_MARGIN_DIVISOR + BUCKET_SPARE;
    (0..PARTITIONS)
        .map(|_| Vec::with_capacity(capacity))
        .collect()
}

/// Returns the partition of the key whose hash is `hash`.
#[inline]
const fn partition(hash: u64) -> usize {
    (hash >> PARTITION_SHIFT) as usize % PARTITIONS
}

/// Every key placed so far, each once, with a [`Table`] from each key's hash to its position.
#[derive(Debug)]
struct KeyIndex<K> {
    table: Table<u32>,
    keys: Vec<K>,
}

impl<K: Array> KeyIndex<K> {
    /// An index that holds `capacity` keys without growing.
    fn with_capacity(capacity: usize) -> Self {
        Self {
            table: Table::with_capacity(capacity),
            keys: Vec::with_capacity(capacity),
        }
    }

    /// Every key placed so far, in placement order.
    fn keys(&self) -> &[K] {
        &self.keys
    }

    /// Takes the keys, in placement order.
    fn into_keys(self) -> Vec<K> {
        self.keys
    }

    /// The number of keys placed so far.
    const fn len(&self) -> usize {
        self.keys.len()
    }

    /// Hints the CPU to load the home slot of `hash` ahead of a lookup.
    fn prefetch(&self, hash: u64) {
        self.table.prefetch(hash);
    }

    /// The position of `key` if it is placed, given its `hash`.
    fn find(&self, key: &K, hash: u64) -> Option<usize> {
        self.table
            .get(hash)
            .map(Widen::widen)
            .find(|&position| self.keys[position] == *key)
    }

    /// The position of `key` given its `hash`, placing it last if it is new. The second value
    /// reports whether it was placed. A growing table rehashes the placed keys through `hasher`.
    ///
    /// # Panics
    ///
    /// Panics if the index would hold more than `u32::MAX` keys.
    fn find_or_insert(&mut self, key: &K, hash: u64, hasher: &impl BuildHasher) -> (usize, bool) {
        let next =
            u32::try_from(self.keys.len()).expect("an index must hold at most u32::MAX keys");
        let keys = &self.keys;
        let (position, inserted) = self.table.find_or_insert(
            hash,
            |position| keys[Widen::widen(position)] == *key,
            next,
            |position| hasher.hash_one(keys[Widen::widen(position)].as_ref()),
        );
        if inserted {
            self.keys.push(key.clone());
        }
        (Widen::widen(position), inserted)
    }

    /// Grows the index, if needed, to place `additional` more keys without growing, rehashing the
    /// placed keys through `hasher`.
    fn reserve(&mut self, additional: usize, hasher: &impl BuildHasher) {
        let keys = &self.keys;
        self.table.reserve(additional, |position| {
            hasher.hash_one(keys[Widen::widen(position)].as_ref())
        });
        self.keys.reserve(additional);
    }
}

/// Sets `account`'s settled `balance` and returns its slot.
///
/// The default account is stored as an absent key, and an account left as it started is not
/// written. An absent key starts as the default, so an account that changes and settles to the
/// default belongs to a held key, and the key is deleted.
fn settled_slot<A: Account>(mut account: A, balance: u64, start: &A, default: &A) -> Slot<A> {
    account.set_balance(balance);
    if account == *start {
        Slot::Keep
    } else if account == *default {
        Slot::Delete
    } else {
        Slot::Put(account)
    }
}

/// Returns `len` slots, splitting them among `strategy`'s workers. Each worker runs `settle` on its
/// range of indices with the slots in that range.
fn settle_batches<A: Account, E: Send>(
    len: usize,
    strategy: &impl Strategy,
    settle: impl Fn(Range<usize>, &mut [Slot<A>]) -> Result<(), E> + Sync,
) -> Result<Vec<Slot<A>>, E> {
    let mut slots = vec![Slot::Keep; len];
    strategy.try_run_batches(len, MIN_SETTLE_BATCH, 1, |batches| {
        batches.try_map_collect_vec(
            |ranges| {
                let mut rest = slots.as_mut_slice();
                let mut prepared = Vec::with_capacity(ranges.len());
                for range in ranges {
                    let (range_slots, tail) = rest.split_at_mut(range.len());
                    rest = tail;
                    prepared.push((range, range_slots));
                }
                prepared
            },
            |(range, slots)| settle(range, slots),
        )
    })?;
    Ok(slots)
}

#[cfg(test)]
mod tests;
