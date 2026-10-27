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
//!   | partitioned by key hash    |            |                            |
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
//! cannot settle would reject them all. [`select()`] applies the candidates one at a time in block
//! order against the accounts the block starts from, drops each that cannot settle with the ones
//! accepted before it, and merkleizes the accepted ones, so [`execute`] settles the accepted body
//! to the same root. Every key is staged once for the whole body, and each candidate costs a few
//! lookups in memory.
//!
//! A builder that gathers candidates in rounds, as from a mempool, drives [`Selection`] itself.
//! Each round, [`touch`](Selection::touch) returns the keys no earlier round touched, in the order
//! the batch must read them, so the staged slots line up with [`keys`](Selection::keys).
//! [`register`](Selection::register) takes their accounts, [`apply`](Selection::apply) accepts or
//! drops each candidate, and [`settle`](Selection::settle) produces one slot per staged key for
//! merkleize.
//!
//! The first round reads its keys with `stage` and each later round with the staged batch's
//! `expand`. [`Balances`] does not wrap `expand`, so a builder that reads in rounds uses the QMDB
//! batch types directly.
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
//! selection.register(&reads);
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
//! selection.register(&reads);
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
//! A verifier settles a block's body as one batch. [`execute`] runs the whole pipeline on a batch
//! of a [`Balances`] database, such as a QMDB [`any`] or [`current`] database of accounts. It
//! rejects a body that cannot settle before writing anything, and merkleizes one that can.
//!
//! A verifier that stages and merkleizes through its own batch types, such as
//! [`stateful::db`](crate::stateful::db), runs the CPU stages itself. [`Plan::new`] gives the keys
//! to stage, in the order their reads must come back, and [`Plan::settle`] turns those reads into
//! one [`Slot`] per staged key for merkleize.
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
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_storage::{
    Context,
    index::{Ordered as OrderedIndex, Unordered as UnorderedIndex},
    journal::contiguous::Mutable,
    merkle::{Family, Graftable, Location},
    qmdb::{
        Error as StorageError,
        any::{self, batch::Slot, value::ValueEncoding},
        current,
        floor::Policy,
    },
};
use commonware_utils::{Array, Widen, handles::Table};
use std::{
    convert::Infallible, fmt::Debug, future::Future, hash::BuildHasher, iter, num::NonZeroUsize,
    ops::Range, sync::Arc,
};
use thiserror::Error;

mod select;
pub use select::Selection;

/// A movement of `u64` value between accounts, with any effects on their own state.
///
/// Implement this for a transaction type to settle batches of it with [`execute`] or [`Plan`], and
/// to choose a block's transfers with [`select()`] or [`Selection`].
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
    type Effect: Copy + Debug + Send + Sync;

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
/// keys offend, which key and reason are reported depends on the plan's hash and on how the
/// strategy splits the work, so the reported key and reason must not enter consensus-visible data.
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

/// Why [`execute`] fails.
#[derive(Debug, Error)]
pub enum Error<F: Family, K: Debug> {
    /// The batch cannot settle.
    #[error(transparent)]
    Rejected(#[from] Rejection<K>),
    /// The database failed to read or merkleize the batch.
    #[error(transparent)]
    Storage(#[from] StorageError<F>),
}

/// The keys a batch of transfers changes, each once, with each key's debit and credit sums and its
/// effects in transfer order.
///
/// The key order is unspecified and may differ between plans of the same transfers. Only the set
/// of keys and each key's changes are fixed. Read the accounts in [`keys`](Self::keys) order and
/// pass them to [`settle`](Self::settle).
#[derive(Clone, Debug)]
pub struct Plan<K, A: Account> {
    /// Every key the batch changes, each once.
    keys: Vec<K>,
    /// The sum of each key's debits, in `keys` order.
    debits: Vec<u64>,
    /// The sum of each key's credits, in `keys` order.
    credits: Vec<u64>,
    /// Where each key's effects end in `effects`, in `keys` order, or empty when no key has one.
    effect_ends: Vec<usize>,
    /// Each key's effects in transfer order, grouped in `keys` order.
    effects: Vec<A::Effect>,
}

/// Partitions of the key hash space that the plan's workers split among themselves.
///
/// Every key falls in one partition, so the worker that owns it sums its changes without sharing a
/// table. Far more partitions than workers give any worker count an even share. Every hash batch
/// allocates a bucket per partition, so more partitions cost more allocations.
const PARTITIONS: usize = 256;

/// Shift that maps a key hash to its partition: the byte below the top one, since the table takes
/// the top byte as its fingerprint and the low bits as its home slot.
const PARTITION_SHIFT: u32 = u64::BITS - u8::BITS - PARTITIONS.trailing_zeros();

/// Fewest transfers a worker hashes on its own.
///
/// Each hash batch allocates a bucket per partition, and every shard later walks that batch's
/// buckets for its partitions, so a batch needs thousands of transfers before its hashing
/// outweighs those fixed costs.
const MIN_HASH_BATCH: NonZeroUsize = NonZeroUsize::new(1 << 12).expect("minimum must be nonzero");

/// Changes per transfer that bucket sizing plans for, as in a payment's debit and credit.
///
/// Transfers with more changes make buckets grow past their reservation.
const CHANGES_PER_TRANSFER: usize = 2;

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
    /// Plans `transfers`, reading each transfer's changes once and gathering them for each key.
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
    /// Panics if more than `u32::MAX` distinct keys hash to one worker's partitions.
    pub fn new<T>(transfers: &[T], strategy: &impl Strategy) -> Result<Self, Rejection<K>>
    where
        T: Transfer<Key = K, Account = A> + Sync,
    {
        Self::with_hasher(transfers, &RandomState::new(), strategy)
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
        // Hash the key of each change in parallel over the transfers and bucket the touches by
        // partition, so each partition's worker reads only its own buckets.
        let buckets: Vec<Buckets<'_, K, A::Effect>> =
            strategy.run_batches(transfers.len(), MIN_HASH_BATCH, 1, |batches| {
                batches.map_collect_vec(
                    |ranges| ranges.into_iter().map(|range| &transfers[range]),
                    |transfers| {
                        // Size each bucket for an even share of the expected changes, plus a
                        // margin for uneven hashing, so most buckets never grow.
                        let share = transfers
                            .len()
                            .saturating_mul(CHANGES_PER_TRANSFER)
                            .div_ceil(PARTITIONS);
                        let capacity = share + share / BUCKET_MARGIN_DIVISOR + BUCKET_SPARE;
                        let mut buckets: Buckets<'_, K, A::Effect> = (0..PARTITIONS)
                            .map(|_| Vec::with_capacity(capacity))
                            .collect();
                        for (key, change) in transfers.iter().flat_map(Transfer::changes) {
                            // A zero debit or credit moves no value, so a key touched only by zero
                            // debits and credits stays out of the plan.
                            if matches!(change, Change::Debit(0) | Change::Credit(0)) {
                                continue;
                            }

                            let hash = hasher.hash_one(key.as_ref());
                            buckets[(hash >> PARTITION_SHIFT) as usize % PARTITIONS].push(Touch {
                                hash,
                                key,
                                change,
                            });
                        }
                        buckets
                    },
                )
            });
        let total: usize = buckets.iter().flatten().map(Vec::len).sum();
        if total == 0 {
            return Ok(Self {
                keys: Vec::new(),
                debits: Vec::new(),
                credits: Vec::new(),
                effect_ends: Vec::new(),
                effects: Vec::new(),
            });
        }

        // Each worker owns a range of partitions and deduplicates their touches, so no two
        // workers hold the same key and the shards concatenate into the plan.
        let per_partition = total.div_ceil(PARTITIONS);
        let shards = strategy.try_run_batches(
            PARTITIONS,
            MIN_PARTITION_BATCH,
            per_partition,
            |batches| {
                batches.try_map_collect_vec(
                    |ranges| ranges.into_iter().map(|partitions| (partitions, &buckets)),
                    |(partitions, buckets)| Shard::build(&partitions, buckets, hasher),
                )
            },
        )?;

        // Concatenate the shards. When any key has an effect, every key gets an end in
        // `effect_ends`, shifted past the effects of the shards before it.
        let len = shards.iter().map(|shard| shard.keys.len()).sum();
        let effects: usize = shards.iter().map(|shard| shard.effects.len()).sum();
        let mut plan = Self {
            keys: Vec::with_capacity(len),
            debits: Vec::with_capacity(len),
            credits: Vec::with_capacity(len),
            effect_ends: Vec::with_capacity(if effects == 0 { 0 } else { len }),
            effects: Vec::with_capacity(effects),
        };
        for mut shard in shards {
            if effects != 0 {
                let base = plan.effects.len();
                if shard.effect_ends.is_empty() {
                    plan.effect_ends
                        .extend(iter::repeat_n(base, shard.keys.len()));
                } else {
                    plan.effect_ends
                        .extend(shard.effect_ends.iter().map(|end| base + end));
                }
                plan.effects.append(&mut shard.effects);
            }
            plan.keys.append(&mut shard.keys);
            plan.debits.append(&mut shard.debits);
            plan.credits.append(&mut shard.credits);
        }
        Ok(plan)
    }

    /// Every key the batch changes, each once.
    pub fn keys(&self) -> &[K] {
        &self.keys
    }

    /// The sum of the batch's debits to each key, in [`keys`](Self::keys) order.
    pub fn debits(&self) -> &[u64] {
        &self.debits
    }

    /// The sum of the batch's credits to each key, in [`keys`](Self::keys) order.
    pub fn credits(&self) -> &[u64] {
        &self.credits
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
        let len = self.keys.len();
        assert_eq!(reads.len(), len, "reads must hold one account per key");
        let mut slots = vec![Slot::Keep; len];

        // Each worker settles its own range of keys into its own range of slots.
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
                |(range, slots)| self.settle_range(range, reads, slots),
            )
        })?;
        Ok(slots)
    }

    /// Settles the keys in `range` one at a time into their slots.
    fn settle_range(
        &self,
        range: Range<usize>,
        reads: &[Option<A>],
        slots: &mut [Slot<A>],
    ) -> Result<(), Rejection<K>> {
        let default = A::default();

        // A plan without effects skips looking up each key's effects.
        if self.effect_ends.is_empty() {
            for (index, slot) in range.zip(slots) {
                *slot = self.settle_key(index, &reads[index], &[], &default)?;
            }
        } else {
            for (index, slot) in range.zip(slots) {
                *slot = self.settle_key(index, &reads[index], self.effects_of(index), &default)?;
            }
        }
        Ok(())
    }

    /// Settles the key at `index` from its starting account `read` and its `effects` in transfer
    /// order.
    #[inline(always)]
    fn settle_key(
        &self,
        index: usize,
        read: &Option<A>,
        effects: &[A::Effect],
        default: &A,
    ) -> Result<Slot<A>, Rejection<K>> {
        // A key the database does not hold starts as the default account, and its effects apply to
        // the starting account in transfer order.
        let start = read.clone().unwrap_or_default();
        let mut account = start.clone();
        for &effect in effects {
            if !account.apply(effect) {
                return Err(Rejection::Refused(self.keys[index].clone()));
            }
        }

        // Debits come off the starting balance before credits are added, so credits never fund
        // debits. The result replaces any balance an effect set.
        let Some(remaining) = start.balance().checked_sub(self.debits[index]) else {
            return Err(Rejection::Insufficient(self.keys[index].clone()));
        };
        let Some(balance) = remaining.checked_add(self.credits[index]) else {
            return Err(Rejection::Overflow(self.keys[index].clone()));
        };
        account.set_balance(balance);

        // The default account is stored as an absent key, and an account left as it started is not
        // written. An absent key starts as the default, so an account that changes and settles to
        // the default belongs to a held key, and the key is deleted.
        Ok(if account == start {
            Slot::Keep
        } else if account == *default {
            Slot::Delete
        } else {
            Slot::Put(account)
        })
    }

    /// The effects on the key at `index`, in transfer order.
    fn effects_of(&self, index: usize) -> &[A::Effect] {
        if self.effect_ends.is_empty() {
            return &[];
        }
        let start = index
            .checked_sub(1)
            .map_or(0, |previous| self.effect_ends[previous]);
        &self.effects[start..self.effect_ends[index]]
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
    /// Where each key's effects end in `effects`, in `keys` order, or empty when no key has one.
    effect_ends: Vec<usize>,
    /// Each key's effects in transfer order, grouped in `keys` order.
    effects: Vec<E>,
}

impl<K: Array, E: Copy> Shard<K, E> {
    /// Deduplicates the touches in `partitions`, sums their debits and credits, and groups their
    /// effects by key.
    ///
    /// A [`Table`] maps each key's hash to its index in the shard. It is sized for every touch, so
    /// it never grows and never rehashes a key through `hasher`.
    fn build(
        partitions: &Range<usize>,
        buckets: &[Buckets<'_, K, E>],
        hasher: &impl BuildHasher,
    ) -> Result<Self, Rejection<K>> {
        let owned = buckets
            .iter()
            .flat_map(|buckets| &buckets[partitions.clone()]);
        let expected: usize = owned.clone().map(Vec::len).sum();
        let mut shard = Self {
            keys: Vec::with_capacity(expected),
            debits: Vec::with_capacity(expected),
            credits: Vec::with_capacity(expected),
            effect_ends: Vec::new(),
            effects: Vec::new(),
        };
        let mut effects = Vec::new();
        let mut table: Table<u32> = Table::with_capacity(expected);
        for bucket in owned {
            for (position, touch) in bucket.iter().enumerate() {
                // Prefetch the home slot of a touch further down the bucket, so its lookup waits
                // less on memory.
                if let Some(ahead) = bucket.get(position + PREFETCH_DISTANCE) {
                    table.prefetch(ahead.hash);
                }

                // The key either finds its own index among the table's candidates or takes the
                // next one, in one walk.
                let next = u32::try_from(shard.keys.len())
                    .expect("a shard must hold at most u32::MAX keys");
                let (index, inserted) = table.get_or_insert_with(
                    touch.hash,
                    |index| shard.keys[Widen::widen(index)] == *touch.key,
                    next,
                    |index| hasher.hash_one(shard.keys[Widen::widen(index)].as_ref()),
                );
                let index: usize = Widen::widen(index);
                if inserted {
                    shard.keys.push(touch.key.clone());
                    shard.debits.push(0);
                    shard.credits.push(0);
                }

                // No balance can afford debits that sum past `u64::MAX`, and credits that sum past
                // it overflow every balance. An effect is set aside with its key's index and
                // grouped once every touch is placed.
                match touch.change {
                    Change::Debit(amount) => {
                        shard.debits[index] = shard.debits[index]
                            .checked_add(amount)
                            .ok_or_else(|| Rejection::Insufficient(touch.key.clone()))?;
                    }
                    Change::Credit(amount) => {
                        shard.credits[index] = shard.credits[index]
                            .checked_add(amount)
                            .ok_or_else(|| Rejection::Overflow(touch.key.clone()))?;
                    }
                    Change::Effect(effect) => effects.push((index, effect)),
                }
            }
        }

        // Each key's touches arrive in transfer order, one hash batch after another, and the
        // grouping is stable, so each key's effects stay in transfer order.
        (shard.effect_ends, shard.effects) = group_effects(shard.keys.len(), &effects);
        Ok(shard)
    }
}

/// Groups `effects`, each paired with its key's index below `keys`, into one run per key that
/// keeps their order. Returns where each key's run ends and the runs.
fn group_effects<E: Copy>(keys: usize, effects: &[(usize, E)]) -> (Vec<usize>, Vec<E>) {
    let Some(&(_, filler)) = effects.first() else {
        return (Vec::new(), Vec::new());
    };

    // Count each key's effects, then sum the counts so each key's run ends after the runs of the
    // keys before it.
    let mut ends = vec![0; keys];
    for &(index, _) in effects {
        ends[index] += 1;
    }
    let mut total = 0;
    for end in &mut ends {
        total += *end;
        *end = total;
    }

    // Fill each key's run from its end, walking the effects backward so each run keeps its order.
    // Every slot is written, so `filler` only initializes them.
    let mut next = ends.clone();
    let mut grouped = vec![filler; effects.len()];
    for &(index, effect) in effects.iter().rev() {
        next[index] -= 1;
        grouped[next[index]] = effect;
    }
    (ends, grouped)
}

/// A database of accounts with a staged batch API.
pub trait Balances<K: Array, A: Account> {
    /// The Merkle family of the database.
    type Family: Family;

    /// A batch over the database that has not been merkleized.
    type Batch: Send;

    /// A batch whose reads are staged.
    type Staged: Send;

    /// A merkleized batch.
    type Merkleized: Send;

    /// Reads `keys` through `batch`, returning their accounts in the same order, `None` for a key
    /// the database does not hold, and the batch with those keys staged.
    #[allow(clippy::type_complexity)]
    fn stage(
        &self,
        batch: Self::Batch,
        keys: &[&K],
    ) -> impl Future<Output = Result<(Vec<Option<A>>, Self::Staged), StorageError<Self::Family>>> + Send;

    /// Applies `slots`, one per staged key in the order staged, to `staged`, advances the
    /// inactivity floor under `policy`, and merkleizes the batch with `metadata`.
    fn merkleize<P>(
        &self,
        staged: Self::Staged,
        slots: Vec<Slot<A>>,
        metadata: Option<A>,
        policy: &mut P,
    ) -> impl Future<Output = Result<Self::Merkleized, StorageError<Self::Family>>> + Send
    where
        P: Policy<Self::Family, K, A> + Send + Sync;
}

/// Implements [`Balances`] for a QMDB database by forwarding to the `stage` and `merkleize`
/// methods its batch types provide.
macro_rules! impl_balances {
    (
        [$($generics:tt)*] $db:ty
        where { $($bounds:tt)* }
        Batch = $batch:ty, Staged = $staged:ty, Merkleized = $merkleized:ty
    ) => {
        impl<$($generics)*> Balances<K, V::Value> for $db
        where
            $($bounds)*
        {
            type Family = F;
            type Batch = $batch;
            type Staged = $staged;
            type Merkleized = $merkleized;

            async fn stage(
                &self,
                batch: Self::Batch,
                keys: &[&K],
            ) -> Result<(Vec<Option<V::Value>>, Self::Staged), StorageError<F>> {
                batch.stage(keys, self).await
            }

            async fn merkleize<P>(
                &self,
                staged: Self::Staged,
                slots: Vec<Slot<V::Value>>,
                metadata: Option<V::Value>,
                policy: &mut P,
            ) -> Result<Self::Merkleized, StorageError<F>>
            where
                P: Policy<F, K, V::Value> + Send + Sync,
            {
                staged
                    .merkleize(slots, Vec::new(), metadata, self, policy)
                    .await
            }
        }
    };
}

impl_balances! {
    [F, E, C, I, H, K, V, const N: usize, S]
    any::db::Db<F, E, C, I, H, any::unordered::Update<K, V>, N, S>
    where {
        F: Family,
        E: Context,
        C: Mutable<Item = any::operation::Unordered<F, K, V>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
        H: Hasher,
        K: Array,
        V: ValueEncoding,
        V::Value: Account,
        any::operation::Unordered<F, K, V>: Codec,
        S: Strategy,
    }
    Batch = any::batch::UnmerkleizedBatch<F, H, any::unordered::Update<K, V>, S>,
    Staged = any::batch::Staged<F, H, any::unordered::Update<K, V>, S>,
    Merkleized = Arc<
        any::batch::MerkleizedBatch<F, H::Digest, any::unordered::Update<K, V>, S>,
    >
}

impl_balances! {
    [F, E, C, I, H, K, V, const N: usize, S]
    any::db::Db<F, E, C, I, H, any::ordered::Update<K, V>, N, S>
    where {
        F: Family,
        E: Context,
        C: Mutable<Item = any::operation::Ordered<F, K, V>>,
        I: OrderedIndex<Value = Location<F>> + 'static,
        H: Hasher,
        K: Array,
        V: ValueEncoding,
        V::Value: Account,
        any::operation::Ordered<F, K, V>: Codec,
        S: Strategy,
    }
    Batch = any::batch::UnmerkleizedBatch<F, H, any::ordered::Update<K, V>, S>,
    Staged = any::batch::Staged<F, H, any::ordered::Update<K, V>, S>,
    Merkleized = Arc<
        any::batch::MerkleizedBatch<F, H::Digest, any::ordered::Update<K, V>, S>,
    >
}

impl_balances! {
    [F, E, C, I, H, K, V, const N: usize, S]
    current::db::Db<F, E, C, I, H, any::unordered::Update<K, V>, N, S>
    where {
        F: Graftable,
        E: Context,
        C: Mutable<Item = any::operation::Unordered<F, K, V>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
        H: Hasher,
        K: Array,
        V: ValueEncoding,
        V::Value: Account,
        any::operation::Unordered<F, K, V>: Codec,
        S: Strategy,
    }
    Batch = current::batch::UnmerkleizedBatch<
        F,
        H,
        any::unordered::Update<K, V>,
        N,
        S,
    >,
    Staged = current::batch::Staged<F, H, any::unordered::Update<K, V>, N, S>,
    Merkleized = Arc<
        current::batch::MerkleizedBatch<
            F,
            H::Digest,
            any::unordered::Update<K, V>,
            N,
            S,
        >,
    >
}

impl_balances! {
    [F, E, C, I, H, K, V, const N: usize, S]
    current::db::Db<F, E, C, I, H, any::ordered::Update<K, V>, N, S>
    where {
        F: Graftable,
        E: Context,
        C: Mutable<Item = any::operation::Ordered<F, K, V>>,
        I: OrderedIndex<Value = Location<F>> + 'static,
        H: Hasher,
        K: Array,
        V: ValueEncoding,
        V::Value: Account,
        any::operation::Ordered<F, K, V>: Codec,
        S: Strategy,
    }
    Batch = current::batch::UnmerkleizedBatch<
        F,
        H,
        any::ordered::Update<K, V>,
        N,
        S,
    >,
    Staged = current::batch::Staged<F, H, any::ordered::Update<K, V>, N, S>,
    Merkleized = Arc<
        current::batch::MerkleizedBatch<
            F,
            H::Digest,
            any::ordered::Update<K, V>,
            N,
            S,
        >,
    >
}

/// Executes `transfers` on `batch`: plans them, stages every key they change through `db`,
/// settles the accounts, and merkleizes the changed accounts under `policy` with `metadata`.
///
/// Planning and settling run on the calling task and on `strategy`'s workers. A caller that must
/// keep this work off its executor thread can run [`Plan`] itself.
///
/// `batch` is consumed on every outcome, so a rejected batch is dropped with any writes it already
/// held. `db` is left unchanged.
///
/// # Errors
///
/// Returns [`Error::Rejected`] if the batch cannot settle and [`Error::Storage`] if `db` is not at
/// a state of the batch's chain or fails to read or merkleize.
///
/// # Panics
///
/// Panics if more than `u32::MAX` distinct keys hash to one worker's partitions.
pub async fn execute<T, D, P>(
    batch: D::Batch,
    db: &D,
    transfers: &[T],
    metadata: Option<T::Account>,
    policy: &mut P,
    strategy: &impl Strategy,
) -> Result<D::Merkleized, Error<D::Family, T::Key>>
where
    T: Transfer + Sync,
    D: Balances<T::Key, T::Account>,
    P: Policy<D::Family, T::Key, T::Account> + Send + Sync,
{
    let plan = Plan::new(transfers, strategy)?;
    let keys: Vec<&T::Key> = plan.keys().iter().collect();
    let (reads, staged) = db.stage(batch, &keys).await?;
    let slots = plan.settle(&reads, strategy)?;
    Ok(db.merkleize(staged, slots, metadata, policy).await?)
}

/// Selects from `candidates` on `batch` in order, for a proposer.
///
/// Stages every key the candidates touch through `db`, applies each candidate against the starting
/// accounts as [`Selection`] does, and merkleizes the accepted ones under `policy` with
/// `metadata`. Returns the merkleized batch and whether each candidate was accepted.
///
/// # Errors
///
/// Returns an error if `db` is not at a state of the batch's chain or fails to read or merkleize.
///
/// # Panics
///
/// Panics if the candidates touch more than `u32::MAX` distinct keys.
pub async fn select<T, D, P>(
    batch: D::Batch,
    db: &D,
    candidates: &[T],
    metadata: Option<T::Account>,
    policy: &mut P,
    strategy: &impl Strategy,
) -> Result<(D::Merkleized, Vec<bool>), StorageError<D::Family>>
where
    T: Transfer + Sync,
    D: Balances<T::Key, T::Account>,
    P: Policy<D::Family, T::Key, T::Account> + Send + Sync,
{
    let mut selection = Selection::new();
    let touched = selection.touch(candidates);
    let keys: Vec<&T::Key> = selection.keys()[touched].iter().collect();
    let (reads, staged) = db.stage(batch, &keys).await?;
    selection.register(&reads);
    let accepted = selection.apply(candidates);
    let slots = selection.settle(strategy);
    Ok((
        db.merkleize(staged, slots, metadata, policy).await?,
        accepted,
    ))
}

#[cfg(test)]
mod tests;
