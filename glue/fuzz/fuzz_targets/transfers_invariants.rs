#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_glue::transfers::{Account, Change, Plan, Rejection, Selection, Transfer};
use commonware_parallel::{
    Rayon, Sequential, Strategy,
    mocks::{Explorer, TASKS, inline},
};
use commonware_runtime::{Runner, deterministic};
use commonware_storage::qmdb::any::batch::Slot;
use commonware_utils::{Entropy, FuzzRng, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;
use rand::{Rng, RngExt as _, seq::SliceRandom as _};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

type Key = FixedBytes<2>;
type Accounts = BTreeMap<Key, Nonced>;
type Slots = BTreeMap<Key, Slot<Nonced>>;
type Outcomes = BTreeMap<Key, Result<Slot<Nonced>, Vec<Rejection<Key>>>>;

const KEYS: u8 = 8;
const DEFAULT_BALANCE: u64 = 100;
const MAX_BLOCKS: usize = 8;
const MAX_TRANSFERS: usize = 24;
const MAX_CHANGES: usize = 4;

/// Bulk batches straddle the 8,192 transfers past which a plan hashes in batches, and start at
/// 2,048 transfers, enough touches for a smaller plan to offer its deduplication to the strategy.
/// Spread over two-byte keys, the largest plan the 32,768 keys past which settling splits.
const MIN_BULK_TRANSFERS: usize = 1 << 11;
const MAX_BULK_TRANSFERS: usize = 1 << 15;

/// A one-worker pool runs split batches one after another, so a split run replays exactly.
static POOL: LazyLock<Rayon> = LazyLock::new(|| inline(TASKS));

fn amount(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    Ok(match u.int_in_range(0..=9)? {
        0..=2 => 0,
        3..=7 => u.int_in_range(1..=2 * DEFAULT_BALANCE)?,
        8 => u64::MAX - u.int_in_range(0..=2 * DEFAULT_BALANCE)?,
        _ => u.arbitrary()?,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Nonced {
    balance: u64,
    nonce: u64,
}

impl Default for Nonced {
    fn default() -> Self {
        Self {
            balance: DEFAULT_BALANCE,
            nonce: 0,
        }
    }
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum Effect {
    Nonce(u8),
    Floor(#[arbitrary(with = amount)] u64),
    Burn,
    ConsumeAndRefuse,
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
            Effect::Nonce(nonce) => {
                if u64::from(nonce) != self.nonce {
                    return false;
                }
                self.nonce += 1;
                true
            }
            Effect::Floor(amount) => self.balance >= amount,
            Effect::Burn => {
                self.balance = 0;
                true
            }
            Effect::ConsumeAndRefuse => {
                self.nonce += 1;
                false
            }
        }
    }
}

#[derive(Clone, Debug)]
struct Multi(Vec<(Key, Change<Effect>)>);

impl Transfer for Multi {
    type Key = Key;
    type Account = Nonced;

    fn changes(&self) -> impl Iterator<Item = (&Key, Change<Effect>)> {
        self.0.iter().map(|(key, change)| (key, *change))
    }
}

#[derive(Arbitrary, Debug)]
enum ChangeInput {
    Empty,
    Debit(#[arbitrary(with = amount)] u64),
    Credit(#[arbitrary(with = amount)] u64),
    Effect(Effect),
    Mixed {
        #[arbitrary(with = amount)]
        debit: u64,
        #[arbitrary(with = amount)]
        credit: u64,
        effect: Option<Effect>,
    },
}

impl From<&ChangeInput> for Change<Effect> {
    fn from(input: &ChangeInput) -> Self {
        match *input {
            ChangeInput::Empty => Change::default(),
            ChangeInput::Debit(amount) => Change::debit(amount),
            ChangeInput::Credit(amount) => Change::credit(amount),
            ChangeInput::Effect(effect) => Change::effect(effect),
            ChangeInput::Mixed {
                debit,
                credit,
                effect,
            } => {
                let change = Change {
                    credit,
                    ..Change::debit(debit)
                };
                effect.map_or(change, |effect| change.with_effect(effect))
            }
        }
    }
}

type TransferInput = Vec<(u8, ChangeInput)>;

#[derive(Arbitrary, Debug)]
struct AccountInput {
    key: u8,
    #[arbitrary(with = amount)]
    balance: u64,
    nonce: u8,
}

#[derive(Debug)]
enum Block {
    Verify(Vec<TransferInput>),
    Build(Vec<TransferInput>),
    Bulk(Vec<TransferInput>),
}

impl<'a> Arbitrary<'a> for Block {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=15)? {
            0 => Self::Bulk(u.arbitrary()?),
            1..=7 => Self::Verify(u.arbitrary()?),
            _ => Self::Build(u.arbitrary()?),
        })
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    accounts: Vec<AccountInput>,
    blocks: Vec<Block>,
    entropy: Entropy,
}

fn key(n: u8, offset: u16) -> Key {
    Key::new(offset.wrapping_add(u16::from(n % KEYS)).to_be_bytes())
}

fn transfer(changes: &TransferInput, offset: u16) -> Multi {
    Multi(
        changes
            .iter()
            .take(MAX_CHANGES)
            .map(|(n, change)| (key(*n, offset), change.into()))
            .collect(),
    )
}

fn transfers(inputs: &[TransferInput]) -> Vec<Multi> {
    inputs
        .iter()
        .take(MAX_TRANSFERS)
        .map(|changes| transfer(changes, 0))
        .collect()
}

/// Repeats `inputs` into a batch of thousands of transfers, shifting each transfer's keys by a
/// random offset so the batch spreads over every key.
fn bulk(inputs: &[TransferInput], rng: &mut impl Rng) -> Vec<Multi> {
    let len = rng.random_range(MIN_BULK_TRANSFERS..=MAX_BULK_TRANSFERS);
    inputs
        .iter()
        .take(MAX_TRANSFERS)
        .cycle()
        .take(len)
        .map(|changes| transfer(changes, rng.random()))
        .collect()
}

/// Settles `transfers` against `db` one key at a time, as the module documents: debits and credits
/// summed without overflow, effects applied in order to the starting account, and the balance set
/// to the starting balance less debits plus credits. Each changed key maps to its slot or to every
/// rejection it can be reported with.
fn model(db: &Accounts, transfers: &[Multi]) -> Outcomes {
    let mut totals: BTreeMap<Key, (u128, u128, Vec<Effect>)> = BTreeMap::new();
    for (key, change) in transfers.iter().flat_map(Transfer::changes) {
        if change.debit == 0 && change.credit == 0 && change.effect.is_none() {
            continue;
        }
        let (debit, credit, effects) = totals.entry(key.clone()).or_default();
        *debit += u128::from(change.debit);
        *credit += u128::from(change.credit);
        effects.extend(change.effect);
    }

    let max = u128::from(u64::MAX);
    totals
        .into_iter()
        .map(|(key, (debit, credit, effects))| {
            let start = db.get(&key).copied().unwrap_or_default();
            let mut account = start;
            let mut reasons = Vec::new();
            if !effects.into_iter().all(|effect| account.apply(effect)) {
                reasons.push(Rejection::Refused(key.clone()));
            }
            let balance = u128::from(start.balance)
                .checked_sub(debit)
                .map(|remaining| remaining + credit);
            if balance.is_none() {
                reasons.push(Rejection::Insufficient(key.clone()));
            }
            if credit > max || balance.is_some_and(|balance| balance > max) {
                reasons.push(Rejection::Overflow(key.clone()));
            }
            if !reasons.is_empty() {
                return (key, Err(reasons));
            }

            account.balance = u64::try_from(balance.unwrap()).unwrap();
            let slot = if account == start {
                Slot::Keep
            } else if account == Nonced::default() {
                Slot::Delete
            } else {
                Slot::Put(account)
            };
            (key, Ok(slot))
        })
        .collect()
}

fn settles(outcomes: &Outcomes) -> bool {
    outcomes.values().all(Result::is_ok)
}

fn assert_offends(outcomes: &Outcomes, rejection: &Rejection<Key>) {
    let (Rejection::Refused(key) | Rejection::Insufficient(key) | Rejection::Overflow(key)) =
        rejection;
    let reasons = outcomes.get(key).and_then(|outcome| outcome.as_ref().err());
    assert!(
        reasons.is_some_and(|reasons| reasons.contains(rejection)),
        "{rejection:?} names no offense: {outcomes:?}"
    );
}

/// Plans and settles `transfers` under the hash key `seed`, checking that the seed reproduces the
/// plan, that the plan holds each changed key once, and that its slots or rejection match
/// `outcomes`. Returns the slots if the batch settles.
fn settle(
    db: &Accounts,
    transfers: &[Multi],
    seed: u64,
    strategy: &impl Strategy,
    outcomes: &Outcomes,
) -> Option<Slots> {
    let plan = match [
        Plan::with_seed(transfers, seed, strategy),
        Plan::with_seed(transfers, seed, strategy),
    ] {
        [Ok(plan), Ok(again)] => {
            assert_eq!(
                plan.keys(),
                again.keys(),
                "a seed must reproduce the key order"
            );
            plan
        }
        [Err(rejection), Err(again)] => {
            assert_eq!(rejection, again, "a seed must reproduce the rejection");
            assert_offends(outcomes, &rejection);
            return None;
        }
        plans => panic!("a seed must reproduce the plan: {plans:?}"),
    };
    let keys: BTreeSet<&Key> = plan.keys().iter().collect();
    assert_eq!(keys.len(), plan.len(), "plan repeats a key");
    assert_eq!(plan.is_empty(), keys.is_empty());
    assert!(
        keys.into_iter().eq(outcomes.keys()),
        "planned keys differ from the changed keys"
    );

    let reads: Vec<_> = plan.keys().iter().map(|key| db.get(key).copied()).collect();
    match plan.settle(&reads, strategy) {
        Ok(slots) => {
            let slots: Slots = plan.keys().iter().cloned().zip(slots).collect();
            assert_eq!(slots.len(), outcomes.len(), "a planned key has no slot");
            for (key, slot) in &slots {
                assert_eq!(
                    outcomes[key].as_ref().ok(),
                    Some(slot),
                    "slot of {key:?} differs from the model"
                );
            }
            Some(slots)
        }
        Err(rejection) => {
            assert_offends(outcomes, &rejection);
            None
        }
    }
}

/// Settles `transfers` as a verifier under two hash keys, on the calling thread and split into as
/// many batches as the explorer allows, and once more in another order split as the input chooses,
/// checking each against the model. Returns the slots if the batch settles.
fn verify(db: &Accounts, transfers: &[Multi], rng: &mut impl Rng) -> Option<Slots> {
    let outcomes = model(db, transfers);
    let settled = settle(db, transfers, rng.next_u64(), &Sequential, &outcomes);
    let split = Explorer::parallel(&POOL);
    settle(db, transfers, rng.next_u64(), &split, &outcomes);

    let mut shuffled = transfers.to_vec();
    shuffled.shuffle(rng);
    let split = Explorer::seeded(&POOL, rng.next_u64());
    settle(db, &shuffled, rng.next_u64(), &split, &model(db, &shuffled));
    settled
}

/// Randomly keyed plans and selections are checked only empty, where their hash key cannot change
/// the outcome, so every crash replays from its input.
fn check_unseeded() {
    let plan = Plan::new(&[] as &[Multi], &Sequential).unwrap();
    assert!(plan.is_empty() && plan.keys().is_empty());
    assert!(plan.settle(&[], &Sequential).unwrap().is_empty());
    for selection in [Selection::<Key, Nonced>::new(), Selection::default()] {
        assert!(selection.keys().is_empty());
        assert!(selection.settle(&Sequential).is_empty());
    }
}

/// Selects `candidates` in rounds as a builder, checking each acceptance against the model and a
/// twin under another hash key, and returns the accepted body and the slot of every staged key.
fn build(db: &Accounts, candidates: &[Multi], rng: &mut impl Rng) -> (Vec<Multi>, Slots) {
    let mut selection = Selection::with_seed(rng.next_u64());
    let mut twin = Selection::with_seed(rng.next_u64());
    let mut body = Vec::new();
    let mut remaining = candidates;
    while !remaining.is_empty() {
        let (round, rest) = remaining.split_at(rng.random_range(1..=remaining.len()));
        remaining = rest;

        let staged = selection.keys().len();
        let touched = selection.touch(round);
        let twin_touched = twin.touch(round);
        assert_eq!(touched.start, staged);
        assert_eq!(touched.end, selection.keys().len());
        let new: BTreeSet<&Key> = selection.keys()[touched.clone()].iter().collect();
        assert_eq!(new.len(), touched.len(), "a round stages a key twice");
        assert!(
            selection.keys()[..staged]
                .iter()
                .all(|key| !new.contains(key)),
            "a round restages a key"
        );
        assert_eq!(
            new,
            twin.keys()[twin_touched.clone()].iter().collect(),
            "staged keys depend on the hash key"
        );

        let reads = |keys: &[Key]| keys.iter().map(|key| db.get(key).copied()).collect();
        selection.register(reads(&selection.keys()[touched]));
        twin.register(reads(&twin.keys()[twin_touched]));

        // Applying in another order or in parts than touched bypasses the round's cached indices.
        let mut order = round.to_vec();
        if rng.random_bool(0.5) {
            order.shuffle(rng);
        }
        let (first, second) = order.split_at(rng.random_range(0..=order.len()));
        for part in [first, second] {
            let accepted = selection.apply(part);
            assert_eq!(
                accepted,
                twin.apply(part),
                "acceptance depends on the hash key"
            );
            for (candidate, accepted) in part.iter().zip(accepted) {
                body.push(candidate.clone());
                let fits = settles(&model(db, &body));
                assert_eq!(
                    accepted, fits,
                    "a candidate must be accepted exactly when it settles with the accepted ones"
                );
                if !fits {
                    body.pop();
                }
            }
        }
    }

    let keys = selection.keys().to_vec();
    assert!(
        keys.iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .eq(model(db, candidates).keys()),
        "staged keys differ from the changed keys"
    );
    let twin_keys = twin.keys().to_vec();
    let slots: Slots = keys
        .into_iter()
        .zip(selection.settle(&Sequential))
        .collect();
    let twin_slots: Slots = twin_keys
        .into_iter()
        .zip(twin.settle(&Sequential))
        .collect();
    assert_eq!(slots, twin_slots, "slots depend on the hash key");
    (body, slots)
}

/// Writes `slots` to `db`. In a database only the module writes, a key is held exactly when its
/// account differs from the default.
fn commit(db: &mut Accounts, slots: Slots) {
    for (key, slot) in slots {
        match slot {
            Slot::Keep => {}
            Slot::Put(account) => {
                assert_ne!(account, Nonced::default(), "{key:?} is put at the default");
                db.insert(key, account);
            }
            Slot::Delete => assert!(db.remove(&key).is_some(), "{key:?} is deleted unheld"),
        }
    }
}

fn fuzz(input: FuzzInput) {
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(input.entropy));
    let runner = deterministic::Runner::new(cfg);
    runner.start(|mut context| async move {
        let mut db: Accounts = input
            .accounts
            .iter()
            .map(|account| {
                let nonced = Nonced {
                    balance: account.balance,
                    nonce: account.nonce.into(),
                };
                (key(account.key, 0), nonced)
            })
            .filter(|(_, account)| *account != Nonced::default())
            .collect();

        check_unseeded();
        for block in input.blocks.iter().take(MAX_BLOCKS) {
            let settled = match block {
                Block::Verify(inputs) => verify(&db, &transfers(inputs), &mut context),
                Block::Bulk(inputs) => {
                    let transfers = bulk(inputs, &mut context);
                    verify(&db, &transfers, &mut context)
                }
                Block::Build(inputs) => {
                    let (body, slots) = build(&db, &transfers(inputs), &mut context);
                    let planned =
                        verify(&db, &body, &mut context).expect("the accepted body must settle");
                    for (key, slot) in &slots {
                        assert_eq!(
                            planned.get(key).unwrap_or(&Slot::Keep),
                            slot,
                            "builder and verifier disagree on {key:?}"
                        );
                    }
                    assert!(planned.keys().all(|key| slots.contains_key(key)));
                    Some(slots)
                }
            };
            if let Some(slots) = settled {
                commit(&mut db, slots);
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
