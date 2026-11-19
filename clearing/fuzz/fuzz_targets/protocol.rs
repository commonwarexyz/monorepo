#![no_main]

//! Stateful invariant harness for the Bajillion clearing protocol.
//!
//! A plan drives the five roles of `commonware_clearing::bajillion` through whole epochs. Users
//! deposit and queue forced withdrawals on the ledger, pay each other through the operator with
//! requests, acknowledgements and receipts, and ask for soft withdrawals. Senders and the operator
//! keep separate records, and an acknowledgement can be lost, arrive late, or arrive after a post
//! resolved its request. The operator cuts each epoch, releasing its close and opening the next
//! epoch, and keeps admitting while the close awaits its post. A validator later checks the close
//! against the ledger's queues as they then stand, settles it on its balances database and payout
//! log and applies it once posted, possibly crashing mid-apply and recovering from what it
//! persisted. A committee certifies the summary and the ledger posts it. Receivers audit every
//! post and challenge omissions, senders resolve their requests against it, accounts withdraw
//! posted payouts, and after a halt they claim. Each action is honest or adversarial: forged,
//! replayed, reordered, stale-epoch, wrong-signer, tampered-amount, over-limit, mutated or
//! arbitrary.
//!
//! The ledger is a model of the chain contract that runs the crate's checks for L1 to L3, L5 to L9
//! and L11. Authenticating the caller of a forced withdrawal (L4) and fixing the destination of a
//! transfer (L10) belong to the contract alone, since the crate supplies no check for either, so
//! this target does not cover them.
//!
//! After every action the harness checks these invariants against a model that sums balances,
//! payouts and custody with exact arithmetic:
//!
//! - I1 conservation: the ledger holds the deposits taken less the transfers paid, and that equals
//!   the posted balances not yet claimed, the deposits queued or claimable, and the posted payouts
//!   not yet withdrawn.
//! - I2 agreement: the validator's balances database, the operator's balances and the model hold
//!   the same balance for every account, both databases sit at the roots of the last post, and a
//!   sender with nothing in flight records what the operator recorded for it.
//! - I3 settlement: a close settles as the model's per-account sums say, each payout the lesser of
//!   the requests and the settled balance, and is refused with the model's `FlowError` when a
//!   balance would leave the amount range. A settled proposal, applied, holds the model's balances
//!   and appends the model's payouts and commit to the payout log, and a close cut before its post
//!   leaves every balance at or above what the next epoch admitted against it.
//! - I4 no double spend: a payout index, a balance claim and a claimable deposit pay out at most
//!   once, and a replay is refused as already paid.
//! - I5 admission: `Request::verify` and `Verified::admit` admit, retry or refuse each request, as
//!   sent or mutated, in each epoch it can name, as the operator's records predict. A retry pays
//!   nothing twice, receipts are issued for exactly the receivers of a countersigned batch, and
//!   acknowledgements and receipts verify exactly for countersigned states.
//! - I6 checking: `Close::check` accepts exactly the closes the model accepts and refuses the
//!   others with the first `CheckError` in the documented order.
//! - I7 posting: every certified honest summary verifies and chains to the last post with the
//!   model's epoch, matrix root, payouts size and running hashes, and a forged, tampered, replayed
//!   or under-certified post is refused with the documented `SummaryError`.
//! - I8 monotonicity: posted epochs advance by one per post and never after a halt, the payout log
//!   and the paid indices only grow, and a halt is permanent.
//! - I9 receipts and challenges: an honest post credits every receiver at least its largest
//!   receipt and settles exactly the map each sender recorded or had pending, a post that omits a
//!   countersigned payment is challenged and halts the ledger, and tampered or stale challenges
//!   are refused with the documented `ChallengeError`.
//! - I10 atomicity: a refused action leaves the ledger, the operator, the senders, the model and
//!   both database roots unchanged.
//! - I11 checkpoints: settling and applying refuse databases off the parent's roots and proposals
//!   that did not post, and a validator that restarts or crashes mid-apply recovers the last post
//!   from its databases and the summaries, closes and queue prefixes it persisted (V4) alone. The
//!   crate leaves how those records are stored to the deployment, so the harness holds them as
//!   durable outside the runtime, and crashes reach only the two databases.
//! - I12 wire: every honest message round-trips at its stated size under the deployment's limits,
//!   malformed encodings are refused, and arbitrary or mutated messages verify only as what the
//!   model holds.

use arbitrary::{Arbitrary, Unstructured};
use commonware_clearing::bajillion::{
    Admission, Amounts, AmountsError, ApplyError, AssemblyError, BalanceProof, Balances, Challenge,
    ChallengeError, CheckError, Checked, Checkpoint, Close, Deposit, Epoch, Flow, FlowError,
    ForcedWithdrawal, Limits, Lookup, Matrix, Namespace, Opening, Payout, PayoutProof, Payouts,
    Processed, Proposal, Queue, Receipt, Request, RequestError, Row, SettleError, Settled,
    Signatures, State, Summary, SummaryError, Withdrawal,
};
use commonware_codec::{Codec, Decode, DecodeExt as _, Encode, RangeCfg, Write, varint::UInt};
use commonware_cryptography::{
    Digest as _, Digestible as _, Hasher as _, Sha256, Signer as _, Verifier as _,
    certificate::{self, Scheme as _},
    ed25519::{PrivateKey, PublicKey, Signature},
    sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, FaultConfig},
};
use commonware_storage::{
    bmt::Proof,
    index::unordered::Index,
    journal::contiguous::fixed::Config as JournalConfig,
    merkle::{Location, full::Config as MerkleConfig, mmb, mmr},
    qmdb::{self, current::unordered::fixed, keyless},
    translator::EightCap,
};
use commonware_utils::{
    Entropy, FuzzRng, NZU16, NZU64, NZUsize, Probability, iter::NonEmpty, sequence::U64,
};
use libfuzzer_sys::fuzz_target;
use rand_core::Rng as _;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::Debug,
    iter,
    num::NonZeroU64,
};

/// Mock certificates over summaries from at least `2f + 1` of `3f + 1` validators. Signatures and
/// certificates are synthetic identifiers, so certifying costs no curve arithmetic.
mod scheme {
    use commonware_clearing::bajillion::{Namespace, Summary};
    use commonware_cryptography::{Sha256, impl_certificate_mock};
    use commonware_utils::N3f1;

    impl_certificate_mock!(&'a Summary<Sha256>, Namespace, N3f1);
}

type Map = BTreeMap<usize, u64>;
type TestAmounts = Amounts<PublicKey, u64>;
type TestState = State<PublicKey, Digest>;
type TestRequest = Request<PublicKey, Digest, u64>;
type TestReceipt = Receipt<PublicKey, PublicKey, Digest, u64>;
type TestChallenge = Challenge<PublicKey, PublicKey, Digest, u64>;
type TestOpening = Opening<PublicKey, Digest, u64>;
type TestWithdrawal = Withdrawal<PublicKey, u64>;
type TestRow = Row<PublicKey, u64>;
type TestClose = Close<PublicKey, PublicKey, u64>;
type TestQueue = Queue<PublicKey, u64>;
type TestFlows = Vec<(PublicKey, Flow<u64>)>;
type TestSummary = Summary<Sha256>;
type TestCheckpoint = Checkpoint<PublicKey, Sha256, u64>;
type TestChecked = Checked<PublicKey, Sha256, u64>;
type TestProposal = Proposal<PublicKey, Sha256, Sequential, u64>;
type TestPayoutProof = PayoutProof<PublicKey, Digest, u64>;
type TestBalanceProof = BalanceProof<Digest, u64>;
type TestBalances = Balances<
    deterministic::Context,
    PublicKey,
    Sha256,
    Index<EightCap, Location<mmb::Family>>,
    Sequential,
    u64,
>;
type TestLog = Payouts<deterministic::Context, PublicKey, Sha256, Sequential, u64>;
type Validator = scheme::Scheme<PublicKey>;

/// The model's settlement of a close: each user's balance after it, the payouts in account order,
/// and the users it touches in account order.
type Effects = (Vec<u64>, Vec<(usize, u64)>, Vec<usize>);

/// The deployment namespace every signature is made in.
const NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_BAJILLION_FUZZ";

/// Fewest and most users. Two already pay each other, and six order senders before, between and
/// after one another in every matrix and payment map while exceeding the row limit below.
const MIN_USERS: usize = 2;
const MAX_USERS: usize = 6;

/// Validators in the committee. Four tolerate one fault, so any three certify.
const VALIDATORS: u32 = 4;
const QUORUM: usize = 3;

/// Limits the operator admits within and validators decode closes with. They sit below the number
/// of users and the largest batch, so honest refusals and over-limit encodings both occur.
const LIMITS: Limits = Limits {
    rows: 4,
    receivers: 3,
    withdrawals: 3,
};

/// Most receivers a batch pays, one more than a request may carry under the limits.
const MAX_BATCH: usize = 4;

/// Actions a plan draws. Every plan first opens a runtime and four databases, and the weights
/// below draw each attack about once in this many actions, on a ledger several posts deep. The
/// few inputs a run from an empty corpus starts with therefore draw most attacks.
const MAX_OPS: usize = 128;

/// Bytes of runtime randomness one arbitrary value is drawn from. A digest alone draws up to 257
/// bytes, so a summary with five of them needs over a kilobyte to be drawn whole.
const GARBAGE_BYTES: usize = 1 << 12;

/// Most byte changes one mutation action applies. A few already reach every decoding error, and
/// more mostly yield bytes nothing decodes.
const MAX_MUTATIONS: usize = 4;

/// Payout proofs kept for later replay, enough to outlive several posts.
const MAX_PROOFS: usize = 8;

/// Deposits are shares of this base, so balances stay far from the largest amount unless a
/// deposit is sampled near it.
const DEPOSIT_BASE: u64 = 1_000;

/// Bytes of the stream a plan is sampled from, more than the largest plan draws (40 bytes for each
/// action), of each of the two seeds the input's head holds, and of the runtime's entropy.
const STREAM_BYTES: usize = 1 << 13;
const SEED_BYTES: usize = 8;
const ENTROPY_BYTES: usize = 32;

/// Weights of the amount kinds, in the order Few, Share, Over, Huge. A batch overspends if any of
/// its entries does, so overspends are drawn rarely.
const SIZE_WEIGHTS: [u8; 4] = [6, 8, 1, 1];

/// Units a few-units amount spans, starting at zero.
const FEW_SPAN: u8 = 16;

/// Units past the base an overspend spans.
const OVER_SPAN: u8 = 8;

/// Units below the largest amount a near-largest amount spans.
const HUGE_SPAN: u8 = 16;

/// Weights of the actions, in the order of the [`Op`] variants: Deposit, Force, Pay, Withdraw,
/// Cut, Close, Audit, Payout, Challenge, Halt, Claim, Restart, Garbage, Mutate. An action weighs
/// in proportion to how many attacks, arbitrary types or mutation targets it carries, so every one
/// of them is drawn about as often as any other. Deposits fund everything else, so they weigh
/// more than that, and a halt, which ends posting for good, weighs least.
const OP_WEIGHTS: [u8; 14] = [9, 4, 20, 5, 3, 22, 1, 7, 5, 1, 3, 2, 11, 8];

/// One action in this many is honest, and the others carry an attack. The protocol still
/// advances: a close posts honestly once its attack is refused, and several attacked payments are
/// admitted.
const ATTACK_ONE_IN: u8 = 4;

/// One cut in this many omits a row. An omission halts the ledger at the post, so it is drawn
/// rarely.
const OMIT_ONE_IN: u8 = 16;

/// One close in this many leaves its audits for later.
const DEFER_ONE_IN: u8 = 4;

/// Returns the index of an entry of `weights`, drawn in proportion to the entry.
fn weighted(u: &mut Unstructured<'_>, weights: &[u8]) -> arbitrary::Result<usize> {
    let sum: u8 = weights.iter().sum();
    let draw = u.int_in_range(0..=sum - 1)?;
    let mut total = 0;
    Ok(weights
        .iter()
        .position(|weight| {
            total += weight;
            draw < total
        })
        .expect("the draw is below the sum"))
}

/// An amount relative to what the account involved holds.
#[derive(Clone, Copy, Debug)]
enum Size {
    /// A few units, sometimes zero.
    Few(u8),
    /// A share of the base in 255ths, so payments stay mostly affordable.
    Share(u8),
    /// Just past the base, an overspend by a few units.
    Over(u8),
    /// Near the largest amount, where custody, maps and balances overflow.
    Huge(u8),
}

impl<'a> Arbitrary<'a> for Size {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match weighted(u, &SIZE_WEIGHTS)? {
            0 => Self::Few(u.arbitrary()?),
            1 => Self::Share(u.arbitrary()?),
            2 => Self::Over(u.arbitrary()?),
            _ => Self::Huge(u.arbitrary()?),
        })
    }
}

impl Size {
    /// Returns the amount relative to `base`.
    fn resolve(self, base: u64) -> u64 {
        match self {
            Self::Few(x) => u64::from(x % FEW_SPAN),
            Self::Share(x) => u64::try_from(u128::from(base) * u128::from(x) / u128::from(u8::MAX))
                .expect("a share fits"),
            Self::Over(x) => base.saturating_add(1 + u64::from(x % OVER_SPAN)),
            Self::Huge(x) => u64::MAX - u64::from(x % HUGE_SPAN),
        }
    }
}

/// A request a sender signs and the operator may not receive as sent.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum PayAttack {
    /// Another user's key signs the states.
    WrongSigner,
    /// The batch changes after the sender signed.
    TamperBatch,
    /// The claimed root of the new map changes after signing.
    TamperRoot,
    /// The request names an epoch the operator does not admit in.
    StaleEpoch(bool),
    /// The request arrives twice.
    Replay,
    /// The sender's oldest request of the epoch arrives again.
    ReplayOld,
    /// The batch is emptied after signing.
    EmptyBatch,
    /// A faulty operator countersigns a batch beyond the sender's balance.
    Overcommit,
    /// The sender tries to derive states the crate must refuse.
    Underivable(u8),
    /// The request is held back and delivered by a later action, possibly in a later epoch.
    Delay,
    /// A receipt is tampered with or issued from the wrong map.
    TamperReceipt(u8),
    /// A signer outside the process signs the states.
    External,
    /// The sender signs its states on a root other than its posted row.
    WrongPrevious,
    /// The operator's acknowledgement of a request, sent or sent again, is lost on the way, so the
    /// sender keeps the request pending. The acknowledgement reaches the sender at its next
    /// payment unless it restarts first, possibly after a post resolved the request.
    LoseAck,
}

/// A soft withdrawal the operator may receive.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum WithdrawAttack {
    /// Another user's key signs the request.
    WrongSigner,
    /// The amount changes after signing.
    TamperAmount,
    /// The request is for another epoch.
    StaleEpoch(bool),
    /// The request was signed for another epoch and names this one.
    Relabeled(bool),
}

/// A deviation from the honest close of an epoch.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum CloseAttack {
    /// Assembly is asked for a count outside the queue's bounds.
    Count(bool),
    /// A row that pays no receiver.
    EmptyRow,
    /// A soft withdrawal of the next epoch or of the one before.
    StaleWithdrawal(bool),
    /// An account's second row, or a repeated withdrawal request.
    Duplicate(bool),
    /// Another key signs the close.
    WrongSigner,
    /// A count, row or withdrawal changes after the operator signed.
    Tampered(u8),
    /// The close is for the next epoch, or an earlier close is replayed.
    WrongEpoch(bool),
    /// Validators read a queue of another epoch.
    StaleQueue(bool),
    /// A row its sender did not sign on its posted row.
    ForeignRow(u8),
    /// A soft withdrawal that does not verify: it has no amount, its amount changed after
    /// signing, or it was signed for another epoch.
    ForgedWithdrawal(u8),
    /// A checkpoint whose matrix is not its summary's, or whose epoch has no successor.
    Checkpoint(bool),
    /// A signed row that takes its sender's balance below zero.
    Overdraft,
    /// Validators read a queue holding a deposit the ledger never took.
    ForgedQueue(u8),
    /// A checked close of an earlier epoch settles on the current databases.
    StaleChecked,
    /// Validators also settle a sibling close the ledger does not post, and apply it.
    Sibling,
    /// The posted proposal applies twice.
    Replay,
    /// The post is under-certified, forged, tampered or replayed before the honest one.
    Certificate(u8),
    /// The operator omits a countersigned row or settles an earlier map.
    Omit(u8),
    /// Validators decode the close under limits below its size.
    Limits(u8),
    /// The validator crashes while applying the post: its payout log cannot be made durable, it
    /// stops before the balances commit, or the balances cannot commit.
    Crash(u8),
}

/// A withdrawal of a posted payout that deviates from the proof a validator serves.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum PayoutAttack {
    /// The payout is withdrawn twice.
    Replay,
    /// The amount is changed.
    Amount,
    /// The account is changed.
    Account,
    /// The proof opens the commit after the payouts.
    Commit,
    /// The withdrawal names an earlier posted close.
    OlderRoot,
    /// The withdrawal names a close that did not post.
    Unposted,
    /// A proof served before later posts is used.
    Stale,
}

/// A challenge a receiver or anyone else submits.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum ChallengeAttack {
    /// The receiver's honest challenge against the post of its receipt's epoch.
    Resubmit,
    /// The challenge names a posted epoch other than its receipt's.
    WrongEpoch,
    /// The opening is of another receiver, lacks its entry, or is mutated.
    Opening(u8),
    /// The receipt promises more than it was issued for.
    Inflate,
    /// Another key signs the receipt's state.
    Forged,
    /// The receipt is of an epoch that has not posted.
    Unposted,
}

/// A claim after a halt that deviates from the proof a validator serves.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum ClaimAttack {
    /// The proven balance is changed.
    Balance,
    /// The proof is claimed for another account.
    Account,
    /// The account claims twice.
    Twice,
}

/// The wire type an arbitrary value is drawn as.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Garbage {
    Request,
    Receipt,
    Challenge,
    Close,
    Summary,
    Opening,
    PayoutProof,
    BalanceProof,
    Withdrawal,
    Row,
    Flow,
    Amounts,
    Parts,
}

/// The honest message whose encoding a mutation changes.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Target {
    Opening,
    Receipt,
    Challenge,
    Close,
    Summary,
    Request,
    PayoutProof,
    BalanceProof,
    /// A non-canonical encoding built on purpose.
    Malformed(u8),
}

/// A change to the bytes of an encoding.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Mutation {
    Flip { position: u16, bit: u8 },
    Insert { position: u16, value: u8 },
    Delete { position: u16 },
    Replace { position: u16, value: u8 },
    Swap { first: u16, second: u16 },
}

impl Mutation {
    /// Changes `bytes` in place.
    fn apply(self, bytes: &mut Vec<u8>) {
        let len = bytes.len();
        let at = |position: u16| usize::from(position).checked_rem(len);
        match self {
            Self::Flip { position, bit } => {
                if let Some(position) = at(position) {
                    bytes[position] ^= 1 << (bit % 8);
                }
            }
            Self::Insert { position, value } => {
                bytes.insert(usize::from(position) % (len + 1), value);
            }
            Self::Delete { position } => {
                if let Some(position) = at(position) {
                    bytes.remove(position);
                }
            }
            Self::Replace { position, value } => {
                if let Some(position) = at(position) {
                    bytes[position] = value;
                }
            }
            Self::Swap { first, second } => {
                if let (Some(first), Some(second)) = (at(first), at(second)) {
                    bytes.swap(first, second);
                }
            }
        }
    }
}

#[derive(Debug)]
enum Op {
    /// A user deposits through the ledger.
    Deposit { user: u8, amount: Size },
    /// A user queues a forced withdrawal on the ledger.
    Force { user: u8, amount: Size },
    /// A sender pays a batch of receivers through the operator.
    Pay {
        sender: u8,
        batch: Vec<(u8, Size)>,
        attack: Option<PayAttack>,
    },
    /// A user asks the operator for a soft withdrawal.
    Withdraw {
        user: u8,
        amount: Size,
        tag: u8,
        attack: Option<WithdrawAttack>,
    },
    /// The operator cuts the epoch the ledger expects: it fixes the epoch's rows, its soft
    /// withdrawals and how many queued requests the close processes, releases the close, and opens
    /// the next epoch, which it admits in against what the close may take. A faulty operator omits
    /// a countersigned row or settles an earlier map of it.
    Cut {
        deposits: u8,
        forced: u8,
        omit: Option<u8>,
    },
    /// The operator cuts the epoch unless it has, then a validator checks the released close
    /// against the queues as they stand and settles it, the committee certifies it, the ledger
    /// posts it, the operator applies its flows, and the validator applies it. Receivers then
    /// audit and senders resolve every post not yet audited, unless `defer` leaves them for later.
    Close {
        deposits: u8,
        forced: u8,
        attack: Option<CloseAttack>,
        defer: bool,
    },
    /// Receivers audit, and senders resolve, the oldest post not yet audited.
    Audit,
    /// An account withdraws a posted payout with a validator's proof.
    Payout {
        pick: u8,
        attack: Option<PayoutAttack>,
    },
    /// A challenge reaches the ledger.
    Challenge { pick: u8, attack: ChallengeAttack },
    /// The deployment's policy halts the ledger.
    Halt,
    /// An account claims its balance and deposits after a halt.
    Claim {
        user: u8,
        attack: Option<ClaimAttack>,
    },
    /// The validator restarts and recovers its databases from what it persisted, and senders
    /// restart, losing the acknowledgements in flight to them.
    Restart,
    /// An arbitrary value reaches the role that consumes its type.
    Garbage { kind: Garbage },
    /// A mutated honest message reaches the role that consumes it.
    Mutate {
        target: Target,
        pick: u8,
        mutations: Vec<Mutation>,
    },
}

/// Returns `None` for the honest action one time in [`ATTACK_ONE_IN`], and an attack otherwise.
fn attack<'a, T: Arbitrary<'a>>(u: &mut Unstructured<'a>) -> arbitrary::Result<Option<T>> {
    Ok(if u.ratio(1u8, ATTACK_ONE_IN)? {
        None
    } else {
        Some(u.arbitrary()?)
    })
}

impl<'a> Arbitrary<'a> for Op {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match weighted(u, &OP_WEIGHTS)? {
            0 => Self::Deposit {
                user: u.arbitrary()?,
                amount: u.arbitrary()?,
            },
            1 => Self::Force {
                user: u.arbitrary()?,
                amount: u.arbitrary()?,
            },
            2 => Self::Pay {
                sender: u.arbitrary()?,
                batch: (0..u.int_in_range(1..=MAX_BATCH)?)
                    .map(|_| Ok((u.arbitrary()?, u.arbitrary()?)))
                    .collect::<arbitrary::Result<_>>()?,
                attack: attack(u)?,
            },
            3 => Self::Withdraw {
                user: u.arbitrary()?,
                amount: u.arbitrary()?,
                tag: u.arbitrary()?,
                attack: attack(u)?,
            },
            4 => Self::Cut {
                deposits: u.arbitrary()?,
                forced: u.arbitrary()?,
                omit: if u.ratio(1u8, OMIT_ONE_IN)? {
                    Some(u.arbitrary()?)
                } else {
                    None
                },
            },
            5 => Self::Close {
                deposits: u.arbitrary()?,
                forced: u.arbitrary()?,
                attack: attack(u)?,
                defer: u.ratio(1u8, DEFER_ONE_IN)?,
            },
            6 => Self::Audit,
            7 => Self::Payout {
                pick: u.arbitrary()?,
                attack: attack(u)?,
            },
            8 => Self::Challenge {
                pick: u.arbitrary()?,
                attack: u.arbitrary()?,
            },
            9 => Self::Halt,
            10 => Self::Claim {
                user: u.arbitrary()?,
                attack: attack(u)?,
            },
            11 => Self::Restart,
            12 => Self::Garbage {
                kind: u.arbitrary()?,
            },
            _ => Self::Mutate {
                target: u.arbitrary()?,
                pick: u.arbitrary()?,
                mutations: (0..u.int_in_range(1..=MAX_MUTATIONS)?)
                    .map(|_| u.arbitrary())
                    .collect::<arbitrary::Result<_>>()?,
            },
        })
    }
}

#[derive(Debug)]
struct FuzzInput {
    users: usize,
    ops: Vec<Op>,
    entropy: Entropy,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // libFuzzer starts from inputs of a few bytes and lengthens them slowly, and a plan
        // sampled from so few bytes would hold one action on the first user. The input's head
        // therefore seeds a fixed-size stream of [`FuzzRng`] output that the rest of the input
        // overwrites from its start, so every input, even an empty one, samples a whole plan, and
        // a byte mutated past the head changes only what is sampled from it.
        //
        // The head's even bytes seed the plan's stream and its odd bytes seed the runtime's
        // entropy, which orders accounts and draws keys, shuffles and signers. A mutated byte of
        // even the shortest input therefore changes the actions or their schedule, never both,
        // except an input of one byte, which has no odd byte and seeds both with it.
        let head = u.bytes(u.len().min(2 * SEED_BYTES))?;
        let seed: Vec<_> = head.iter().step_by(2).copied().collect();
        let mut schedule: Vec<_> = head.iter().skip(1).step_by(2).copied().collect();
        if schedule.is_empty() {
            schedule.clone_from(&seed);
        }
        let mut stream = vec![0; STREAM_BYTES.max(u.len())];
        FuzzRng::new(seed).fill_bytes(&mut stream);
        let literal = u.bytes(u.len())?;
        stream[..literal.len()].copy_from_slice(literal);
        let mut entropy = [0; ENTROPY_BYTES];
        FuzzRng::new(schedule).fill_bytes(&mut entropy);
        let u = &mut Unstructured::new(&stream);

        Ok(Self {
            users: u.int_in_range(MIN_USERS..=MAX_USERS)?,
            ops: (0..MAX_OPS)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
            entropy: Unstructured::new(&entropy).arbitrary()?,
        })
    }
}

/// Checks that `value` encodes to its stated size and decodes back to itself under `cfg`.
fn roundtrip<T: Codec + PartialEq + Debug>(value: &T, cfg: &T::Cfg) {
    let encoded = value.encode();
    assert_eq!(encoded.len(), value.encode_size());
    let decoded = T::decode_cfg(encoded, cfg).expect("an encoded message must decode");
    assert_eq!(&decoded, value);
}

/// Returns the encoding of `value` changed by `mutations`, decoded under `cfg` if it still decodes.
fn mutate<T: Codec>(value: &T, cfg: &T::Cfg, mutations: &[Mutation]) -> Option<T> {
    let mut bytes = value.encode().to_vec();
    for mutation in mutations {
        mutation.apply(&mut bytes);
    }
    T::decode_cfg(bytes, cfg).ok()
}

/// Returns `hash` extended by `H(hash || request)` for each of `requests`, as the ledger's running
/// hashes are specified.
fn chain<R: Encode>(hash: Digest, requests: &[R]) -> Digest {
    requests.iter().fold(hash, |hash, request| {
        Sha256::hash(&[hash.as_ref(), request.encode().as_ref()])
    })
}

/// Returns the bytes the operator signs for a close, rebuilt from the documented layout: the
/// epoch, the matrix root, the withdrawals, and both counts as varints.
fn close_message(
    epoch: Epoch,
    matrix: &Digest,
    withdrawals: &[TestWithdrawal],
    deposits: u64,
    forced: u64,
) -> Vec<u8> {
    let mut message = Vec::new();
    epoch.write(&mut message);
    matrix.write(&mut message);
    withdrawals.write(&mut message);
    UInt(deposits).write(&mut message);
    UInt(forced).write(&mut message);
    message
}

/// Returns the encoding of a close with the given parts, which need not be canonical or signed
/// over them.
fn close_bytes(
    epoch: Epoch,
    rows: &[TestRow],
    withdrawals: &[TestWithdrawal],
    deposits: u64,
    forced: u64,
    signature: &Signature,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    epoch.write(&mut bytes);
    rows.write(&mut bytes);
    withdrawals.write(&mut bytes);
    UInt(deposits).write(&mut bytes);
    UInt(forced).write(&mut bytes);
    signature.write(&mut bytes);
    bytes
}

/// Returns whether the close of `epoch` posted while the ledger expects the close of `expected`.
const fn named_posted(epoch: Epoch, expected: Epoch) -> bool {
    epoch != 0 && epoch < expected
}

/// Returns the exact total of a payment map.
fn total(map: &Map) -> u128 {
    map.values().map(|amount| u128::from(*amount)).sum()
}

/// Returns the empty payment map's root.
fn empty_root() -> Digest {
    TestAmounts::default().root::<Sha256>()
}

/// Returns a count between `required` and `len` selected by `choice`.
fn pick(required: usize, len: usize, choice: u8) -> u64 {
    (required + usize::from(choice) % (len - required + 1)) as u64
}

/// Reads a varint from the front of `bytes`.
fn varint(bytes: &mut &[u8]) -> u64 {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = bytes[0];
        *bytes = &bytes[1..];
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
    }
    value
}

/// Returns the exact sums a flow carries, read from its documented encoding: the epoch, then each
/// of credit, debit and withdraw as its low amount and a varint count of carries.
fn flow_sums(flow: &Flow<u64>) -> (Epoch, [u128; 3]) {
    let encoded = flow.encode();
    let mut bytes = encoded.as_ref();
    let epoch = u64::from_be_bytes(bytes[..8].try_into().expect("an epoch is eight bytes"));
    bytes = &bytes[8..];
    let sums = [(); 3].map(|_| {
        let low = u64::from_be_bytes(bytes[..8].try_into().expect("an amount is eight bytes"));
        bytes = &bytes[8..];
        u128::from(low) + (u128::from(varint(&mut bytes)) << 64)
    });
    (epoch, sums)
}

/// Returns the encoding of a flow of `epoch` with exact `sums` of credit, debit and withdraw.
fn flow_bytes(epoch: Epoch, sums: [u128; 3]) -> Vec<u8> {
    let mut bytes = Vec::new();
    epoch.write(&mut bytes);
    for sum in sums {
        let low = u64::try_from(sum & u128::from(u64::MAX)).expect("the low amount fits");
        low.write(&mut bytes);
        UInt(u64::try_from(sum >> 64).expect("the carries fit")).write(&mut bytes);
    }
    bytes
}

/// Settles exact sums on `previous` as the documented rule says: credits are added and debits
/// taken first, the result must fit an amount, and the payout is the lesser of the requests and
/// the settled balance.
fn settle_sums(
    previous: u64,
    [credit, debit, withdraw]: [u128; 3],
) -> Result<Settled<u64>, Refused> {
    let gross = u128::from(previous)
        .checked_add(credit)
        .ok_or(Refused::Overflow)?;
    let settled = gross.checked_sub(debit).ok_or(Refused::Overdraft)?;
    let settled = u64::try_from(settled).map_err(|_| Refused::Overflow)?;
    let payout = u64::try_from(withdraw.min(u128::from(settled))).expect("at most the balance");
    Ok(Settled {
        balance: settled - payout,
        payout,
    })
}

/// Why the model refuses to settle a close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refused {
    Overdraft,
    Overflow,
}

impl Refused {
    /// Returns whether `error` is the refusal the model predicts.
    const fn matches(self, error: &FlowError) -> bool {
        matches!(
            (self, error),
            (Self::Overdraft, FlowError::Overdraft) | (Self::Overflow, FlowError::Overflow)
        )
    }
}

/// Returns the configurations of a database's merkle and log journals in partitions named after
/// `name`.
fn journals(name: &str) -> (MerkleConfig<Sequential>, JournalConfig) {
    let page_cache = CacheRef::new(NZU16!(1024), NZUsize!(8));
    let merkle = MerkleConfig {
        journal_partition: format!("{name}-merkle-journal"),
        metadata_partition: format!("{name}-merkle-metadata"),
        items_per_blob: NZU64!(7),
        write_buffer: NZUsize!(1024),
        replay_buffer: NZUsize!(1024),
        strategy: Sequential,
        page_cache: page_cache.clone(),
    };
    let log = JournalConfig {
        partition: format!("{name}-log"),
        items_per_blob: NZU64!(7),
        page_cache,
        write_buffer: NZUsize!(1024),
        replay_buffer: NZUsize!(1024),
    };
    (merkle, log)
}

/// A validator's balances database and payout log.
struct Store {
    balances: TestBalances,
    log: TestLog,
}

impl Store {
    /// Opens both databases, the payout log at `size` operations if given (V2).
    async fn open(context: &deterministic::Context, size: Option<Location<mmr::Family>>) -> Self {
        Self {
            balances: Self::open_balances(context, "balances").await,
            log: Self::open_log(context, "payouts", size).await,
        }
    }

    /// Opens the balances database in partitions named after `name` at its last commit.
    async fn open_balances(context: &deterministic::Context, name: &'static str) -> TestBalances {
        let (merkle, log) = journals(name);
        let config = fixed::Config {
            merkle,
            log,
            grafted_metadata_partition: format!("{name}-grafted"),
            translator: EightCap,
            init_cache: None,
            init_buffer: NZUsize!(1024),
            init_concurrency: (),
        };
        TestBalances::init(context.child(name), config, None)
            .await
            .expect("the balances database must open")
    }

    /// Opens the payout log in partitions named after `name`, rewound to `size` operations if
    /// given (V2).
    async fn open_log(
        context: &deterministic::Context,
        name: &'static str,
        size: Option<Location<mmr::Family>>,
    ) -> TestLog {
        let (merkle, log) = journals(name);
        let config = keyless::fixed::Config { merkle, log };
        TestLog::init(context.child(name), config, size)
            .await
            .expect("the payout log must open")
    }

    /// Returns the roots of the balances database and the payout log.
    fn roots(&self) -> (Digest, Digest) {
        (self.balances.root(), self.log.root())
    }
}

/// The model's own balances database and payout log. They receive, for each posted close, exactly
/// the writes the documented settlement makes from the model's balances and payouts: a put of
/// each balance that changes, a delete of each that becomes zero, and a commit with metadata zero,
/// and the payouts in account order with a commit keeping the inactivity floor at zero. Nothing
/// the crate computes reaches them, so their roots check a proposal's roots independently.
struct Shadow {
    store: Option<Store>,
}

impl Shadow {
    async fn open(context: &deterministic::Context) -> Self {
        Self {
            store: Some(Store {
                balances: Store::open_balances(context, "shadow_balances").await,
                log: Store::open_log(context, "shadow_payouts", None).await,
            }),
        }
    }

    /// Returns the roots of the shadow's databases.
    fn roots(&self) -> (Digest, Digest) {
        self.store.as_ref().expect("open").roots()
    }

    /// Returns the roots the shadow reaches with the batches of a close that moves the balances
    /// from `before` to `after` and pays `payouts`, applying them durably if `apply`.
    async fn settle(
        &mut self,
        accounts: &[PublicKey],
        before: &[u64],
        after: &[u64],
        payouts: &[(usize, u64)],
        apply: bool,
    ) -> (Digest, Digest) {
        let Store { balances, log } = self.store.as_ref().expect("open");
        let mut batch = balances.new_batch().with_metadata(0u64);
        for (account, (old, new)) in accounts.iter().zip(before.iter().zip(after)) {
            if old != new {
                batch = batch.write(account.clone(), (*new != 0).then_some(*new));
            }
        }
        let batch = batch
            .merkleize(balances)
            .await
            .expect("the shadow balances merkleize");
        let mut appends = log.new_batch().with_inactivity_floor(Location::new(0));
        for (user, amount) in payouts {
            appends = appends.append(Payout {
                account: accounts[*user].clone(),
                amount: *amount,
            });
        }
        let appends = appends
            .merkleize(log)
            .await
            .expect("the shadow log merkleizes");
        let roots = (batch.root(), appends.root());
        if apply {
            let Store { balances, log } = self.store.take().expect("open");
            let balances = balances.apply_batch(batch).await.expect("applies");
            let balances = balances.commit().await.expect("commits");
            let log = log.apply_batch(appends).await.expect("applies");
            let log = log.commit().await.expect("commits");
            self.store = Some(Store { balances, log });
            assert_eq!(self.roots(), roots);
        }
        roots
    }
}

/// Why the ledger halted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Halt {
    Challenge(Epoch),
    Policy,
}

/// Why the ledger refused a call.
#[derive(Debug)]
enum Refusal {
    Halted,
    NotHalted,
    ZeroAmount,
    Custody,
    NotPosted,
    Withdrawn,
    InvalidProof,
    NothingToClaim,
    Summary(SummaryError),
    Challenge(ChallengeError),
}

/// A ledger following L1 to L3, L5 to L9 and L11 with the crate's checks. It tracks paid payouts
/// as a set of log indices covering every commit and every payout paid. It trusts every caller,
/// since authenticating forced withdrawals (L4) and fixing transfer destinations (L10) are the
/// chain contract's own checks.
#[derive(Clone, Debug, PartialEq)]
struct Ledger {
    /// Digest of the last posted summary.
    last: Digest,
    /// Balances root of the last post.
    balances: Digest,
    /// Matrix root of each posted close, in epoch order.
    matrices: Vec<Digest>,
    /// Payouts root of each posted close, in epoch order.
    payouts: Vec<Digest>,
    /// Funds held.
    held: u64,
    deposits: VecDeque<Deposit<PublicKey, u64>>,
    required_deposits: usize,
    forced: VecDeque<ForcedWithdrawal<PublicKey, u64>>,
    required_forced: usize,
    /// Payout log indices that hold a commit or a paid payout.
    paid: BTreeSet<u64>,
    halt: Option<Halt>,
    /// Accounts that claimed their balance after the halt.
    claimed: BTreeSet<PublicKey>,
    /// Deposits no close processed, claimable after the halt.
    claimable: BTreeMap<PublicKey, u64>,
}

impl Ledger {
    /// Returns a ledger whose last post is the genesis summary `genesis` (L1).
    fn new(genesis: &TestSummary) -> Self {
        Self {
            last: genesis.digest(),
            balances: genesis.balances,
            matrices: Vec::new(),
            payouts: Vec::new(),
            held: 0,
            deposits: VecDeque::new(),
            required_deposits: 0,
            forced: VecDeque::new(),
            required_forced: 0,
            paid: BTreeSet::from([*genesis.payouts.size - 1]),
            halt: None,
            claimed: BTreeSet::new(),
            claimable: BTreeMap::new(),
        }
    }

    /// Returns the epoch of the close the ledger expects.
    fn epoch(&self) -> Epoch {
        self.matrices.len() as Epoch + 1
    }

    /// Returns the posted root of `epoch` in `roots`.
    fn posted(roots: &[Digest], epoch: Epoch) -> Option<&Digest> {
        roots.get(usize::try_from(epoch.checked_sub(1)?).ok()?)
    }

    /// Returns the queues as the close the ledger expects must process them.
    fn queue(&self) -> TestQueue {
        Queue {
            epoch: self.epoch(),
            deposits: self.deposits.iter().cloned().collect(),
            required_deposits: self.required_deposits,
            forced_withdrawals: self.forced.iter().cloned().collect(),
            required_forced_withdrawals: self.required_forced,
        }
    }

    /// Takes custody of a deposit and queues it (L2, L3).
    fn deposit(&mut self, account: PublicKey, amount: u64) -> Result<(), Refusal> {
        if self.halt.is_some() {
            return Err(Refusal::Halted);
        }
        if amount == 0 {
            return Err(Refusal::ZeroAmount);
        }
        self.held = self.held.checked_add(amount).ok_or(Refusal::Custody)?;
        self.deposits.push_back(Deposit { account, amount });
        Ok(())
    }

    /// Queues a forced withdrawal (L2). Authenticating the account that asks for it (L4) is the
    /// chain contract's check, so every caller is trusted.
    fn force(&mut self, account: PublicKey, amount: u64) -> Result<(), Refusal> {
        if self.halt.is_some() {
            return Err(Refusal::Halted);
        }
        if amount == 0 {
            return Err(Refusal::ZeroAmount);
        }
        self.forced.push_back(ForcedWithdrawal { account, amount });
        Ok(())
    }

    /// Posts a certified summary of the close it expects (L5).
    fn post(
        &mut self,
        rng: &mut deterministic::Context,
        verifier: &Validator,
        summary: &TestSummary,
        certificate: &U64,
    ) -> Result<(), Refusal> {
        if self.halt.is_some() {
            return Err(Refusal::Halted);
        }
        summary
            .verify(
                rng,
                verifier,
                certificate,
                self.epoch(),
                &self.last,
                self.required_deposits as u64..=self.deposits.len() as u64,
                self.required_forced as u64..=self.forced.len() as u64,
                &Sequential,
            )
            .map_err(Refusal::Summary)?;
        let deposits = usize::try_from(summary.deposits.count).expect("a count within the queue");
        let forced =
            usize::try_from(summary.forced_withdrawals.count).expect("a count within the queue");
        self.deposits.drain(..deposits);
        self.forced.drain(..forced);
        self.required_deposits = self.deposits.len();
        self.required_forced = self.forced.len();
        self.paid.insert(*summary.payouts.size - 1);
        self.matrices.push(summary.matrix);
        self.payouts.push(summary.payouts.root);
        self.balances = summary.balances;
        self.last = summary.digest();
        Ok(())
    }

    /// Pays the payout `proof` proves under the payouts root of the posted close of `epoch`, once
    /// per index (L6).
    fn withdraw(&mut self, epoch: Epoch, proof: &TestPayoutProof) -> Result<u64, Refusal> {
        let root = Self::posted(&self.payouts, epoch).ok_or(Refusal::NotPosted)?;
        if !proof.verify::<Sha256>(root) {
            return Err(Refusal::InvalidProof);
        }
        if self.paid.contains(&*proof.index) {
            return Err(Refusal::Withdrawn);
        }
        self.held = self
            .held
            .checked_sub(proof.payout.amount)
            .ok_or(Refusal::Custody)?;
        self.paid.insert(*proof.index);
        Ok(proof.payout.amount)
    }

    /// Halts on a challenge against the posted close of `epoch` (L7).
    fn challenge(
        &mut self,
        namespace: &Namespace,
        operator: &PublicKey,
        epoch: Epoch,
        challenge: &TestChallenge,
    ) -> Result<(), Refusal> {
        if self.halt.is_some() {
            return Err(Refusal::Halted);
        }
        let matrix = Self::posted(&self.matrices, epoch).ok_or(Refusal::NotPosted)?;
        challenge
            .verify::<Sha256>(namespace, operator, epoch, matrix)
            .map_err(Refusal::Challenge)?;
        self.stop(Halt::Challenge(epoch));
        Ok(())
    }

    /// Halts as the deployment's policy requires (L8). Halting again keeps the first reason.
    fn halt(&mut self) {
        if self.halt.is_none() {
            self.stop(Halt::Policy);
        }
    }

    /// Records the halt, makes every queued deposit claimable, and drops the queued forced
    /// withdrawals and the required counts (L8).
    fn stop(&mut self, halt: Halt) {
        self.halt = Some(halt);
        for deposit in self.deposits.drain(..) {
            *self.claimable.entry(deposit.account).or_default() += deposit.amount;
        }
        self.forced.clear();
        self.required_deposits = 0;
        self.required_forced = 0;
    }

    /// Pays `account` its proven balance and its claimable deposits, each at most once (L9).
    fn claim(
        &mut self,
        account: &PublicKey,
        proof: Option<&TestBalanceProof>,
    ) -> Result<u64, Refusal> {
        if self.halt.is_none() {
            return Err(Refusal::NotHalted);
        }
        let balance = match proof {
            Some(proof) if !proof.verify::<Sha256, _>(&self.balances, account) => {
                return Err(Refusal::InvalidProof);
            }
            Some(proof) if !self.claimed.contains(account) => proof.balance,
            _ => 0,
        };
        let deposits = self.claimable.get(account).copied().unwrap_or(0);
        if balance == 0 && deposits == 0 {
            return Err(Refusal::NothingToClaim);
        }
        let paid = balance.checked_add(deposits).ok_or(Refusal::Custody)?;
        self.held = self.held.checked_sub(paid).ok_or(Refusal::Custody)?;
        if balance != 0 {
            self.claimed.insert(account.clone());
        }
        self.claimable.remove(account);
        Ok(paid)
    }
}

/// What the model knows independently of the crate's settlement: balances, the payout log, paid
/// payouts and the funds that moved.
#[derive(Clone, Debug, PartialEq)]
struct Model {
    /// Balance of each user as of the last post.
    balances: Vec<u64>,
    /// The payout log, a payout as its user and amount, or `None` for a commit.
    log: Vec<Option<(usize, u64)>>,
    /// Payout indices withdrawn.
    paid: BTreeSet<u64>,
    /// Users whose balance was claimed after the halt.
    claimed: BTreeSet<usize>,
    /// Funds taken in by deposits.
    deposited: u128,
    /// Funds transferred out by payout withdrawals and claims.
    transferred: u128,
    /// Running hashes of the processed deposits and forced withdrawals.
    deposits_hash: Digest,
    forced_hash: Digest,
}

/// A sender's latest countersigned state in an epoch, as the operator records it (O7).
#[derive(Clone, Debug, PartialEq)]
struct Admitted {
    state: TestState,
    payments: TestAmounts,
    signature: Signature,
    acknowledgement: Signature,
    /// The model of `payments`.
    map: Map,
    /// Requests admitted in the epoch, oldest first.
    requests: Vec<TestRequest>,
    /// Earlier countersigned states of the epoch, with their maps and signatures.
    earlier: Vec<(TestState, TestAmounts, Signature, Map)>,
}

/// The operator's records (O7).
#[derive(Clone, Debug, PartialEq)]
struct Desk {
    /// The epoch the operator admits in, the one the ledger expects a close of or the one after
    /// it once that close is cut.
    epoch: Epoch,
    /// Balance of each user as of the last close the operator applied.
    balances: Vec<u64>,
    /// Root of each user's row in the close of the epoch before `epoch` (O4).
    previous: Vec<Option<Digest>>,
    /// Each sender's latest admission in `epoch`.
    admitted: BTreeMap<usize, Admitted>,
    /// Honored soft withdrawals of `epoch`, by user, amount and tag.
    withdrawals: BTreeMap<(usize, u64, u64), TestWithdrawal>,
    /// Senders a faulty operator admitted beyond their balance in `epoch`.
    overdrawn: BTreeSet<usize>,
    /// The close of the epoch before `epoch`, released and not yet posted.
    closing: Option<Closing>,
}

/// A close the operator cut and released, with the records it was cut from (O7).
#[derive(Clone, Debug, PartialEq)]
struct Closing {
    /// The queues as the ledger held them at the cut, and how many requests the close processes.
    queue: TestQueue,
    deposits: u64,
    forced: u64,
    /// Root of each user's row in the close of the epoch before.
    previous: Vec<Option<Digest>>,
    /// The epoch's admissions, honored soft withdrawals and overdrawn senders.
    admitted: BTreeMap<usize, Admitted>,
    withdrawals: BTreeMap<(usize, u64, u64), TestWithdrawal>,
    overdrawn: BTreeSet<usize>,
    /// The released close, the flows assembly returned, and the map it settles for each sender.
    close: TestClose,
    flows: TestFlows,
    rows: BTreeMap<usize, Map>,
    /// Senders whose countersigned state the close does not settle.
    omitted: BTreeSet<usize>,
    /// What the close may take from each user: its payments, and the soft and forced withdrawals
    /// it processes (O3).
    take: Vec<u128>,
}

/// A state a sender recorded as countersigned (S2, S3).
#[derive(Clone, Debug, PartialEq)]
struct Record {
    state: TestState,
    payments: TestAmounts,
    signature: Signature,
    acknowledgement: Signature,
    /// The model of `payments`.
    map: Map,
}

/// A sender's records (S1 to S5).
#[derive(Clone, Debug, Default, PartialEq)]
struct Book {
    /// The latest countersigned state of each epoch whose post the sender has not resolved.
    records: BTreeMap<Epoch, Record>,
    /// The last epoch whose post the sender resolved, and the root of its row there.
    resolved: Epoch,
    row: Option<Digest>,
    /// The request persisted and sent, or held back, but neither acknowledged nor resolved.
    pending: Option<Pending>,
    /// An acknowledgement the operator released that has not reached the sender. Nothing
    /// persists it, so a restart loses it.
    late: Option<(TestState, Signature)>,
}

/// A request its sender persisted with its states before sending it (S3).
#[derive(Clone, Debug, PartialEq)]
struct Pending {
    request: TestRequest,
    signed: Signed,
    /// The map the state of the request's epoch commits to.
    payments: TestAmounts,
    /// How many times the request was delivered (S4).
    sent: usize,
}

/// The states a request asks for and the sender's own signatures over them.
#[derive(Clone, Debug, PartialEq)]
struct Signed {
    current: TestState,
    next: TestState,
    signatures: Signatures<PublicKey>,
}

impl Signed {
    /// Returns the states `request` names, with its signatures as the sender's.
    fn of(request: &TestRequest) -> Self {
        Self {
            current: State {
                epoch: request.epoch,
                account: request.account.clone(),
                payments: request.payments,
                previous: request.previous,
            },
            next: State {
                epoch: request.epoch + 1,
                account: request.account.clone(),
                payments: request.batch.root::<Sha256>(),
                previous: request.latest,
            },
            signatures: request.signatures.clone(),
        }
    }
}

/// What the model expects the operator to do with a request.
#[derive(Debug, PartialEq)]
enum Expect {
    WrongEpoch,
    NoReceivers,
    InvalidSignature,
    Retry,
    New(Map),
}

/// A posted close with what the model and the validator kept of it.
#[derive(Clone)]
struct Posted {
    summary: TestSummary,
    certificate: U64,
    close: TestClose,
    queue: TestQueue,
    /// The queue prefix the close processes, with each required count its length (V4).
    prefix: TestQueue,
    parent: TestCheckpoint,
    checkpoint: TestCheckpoint,
    /// The payment map of each sender with a row.
    rows: BTreeMap<usize, Map>,
    /// Senders whose countersigned state the close does not settle.
    omitted: BTreeSet<usize>,
    /// The latest state the operator countersigned in the epoch for each omitted sender whose
    /// row does not settle its map.
    unsettled: BTreeMap<usize, TestState>,
}

/// Everything a refused action must leave unchanged.
#[derive(Debug, PartialEq)]
struct Snapshot {
    ledger: Ledger,
    model: Model,
    desk: Desk,
    books: Vec<Book>,
    receipts: usize,
    roots: (Digest, Digest),
    parent: TestSummary,
}

/// What the expected close of the epoch holds.
struct Rows {
    rows: Vec<TestRow>,
    model: BTreeMap<usize, Map>,
    /// Senders whose countersigned state the close does not settle.
    omitted: BTreeSet<usize>,
}

/// What outlives a crash of the process: the harness without its runtime and database handles,
/// the actions left, and the state the action that crashed is checked against.
struct Crashed {
    harness: Harness,
    ops: VecDeque<Op>,
    before: Before,
}

/// What an action's I8 checks compare against.
struct Before {
    epoch: Epoch,
    log: usize,
    paid: BTreeSet<u64>,
    halt: Option<Halt>,
}

struct Harness {
    /// The runtime's context, gone while the process is down after a crash.
    context: Option<deterministic::Context>,
    /// Whether the process crashed during the last action.
    crashed: bool,
    /// How many payout log entries were checked against the model.
    verified: usize,
    namespace: Namespace,
    keys: Vec<PrivateKey>,
    accounts: Vec<PublicKey>,
    /// User indices in account order.
    order: Vec<usize>,
    operator: PrivateKey,
    rogue: PrivateKey,
    schemes: Vec<Validator>,
    verifier: Validator,
    store: Option<Store>,
    shadow: Option<Shadow>,
    /// Checkpoint of the last post, which the validator checks the next close against (V2).
    parent: TestCheckpoint,
    ledger: Ledger,
    model: Model,
    desk: Desk,
    books: Vec<Book>,
    /// The largest receipt each receiver holds per epoch and sender (R2).
    receipts: BTreeMap<(Epoch, usize, usize), TestReceipt>,
    history: Vec<Posted>,
    /// A checked close of the epoch before the last post.
    stale: Option<TestChecked>,
    /// Payout proofs served earlier, with the epoch whose root they are under.
    proofs: VecDeque<(Epoch, TestPayoutProof)>,
    /// Posts receivers have not audited and senders have not resolved, oldest first, as indices
    /// into `history`.
    unaudited: VecDeque<usize>,
}

impl Harness {
    async fn new(mut context: deterministic::Context, users: usize) -> Self {
        let keys: Vec<_> = (0..users)
            .map(|_| PrivateKey::from_seed(context.next_u64()))
            .collect();
        let accounts: Vec<_> = keys.iter().map(PrivateKey::public_key).collect();
        let mut order: Vec<_> = (0..users).collect();
        order.sort_by(|a, b| accounts[*a].cmp(&accounts[*b]));
        let operator = PrivateKey::from_seed(context.next_u64());
        let rogue = PrivateKey::from_seed(context.next_u64());
        let fixture = scheme::fixture(&mut context, NAMESPACE, VALIDATORS);
        let store = Store::open(&context, None).await;
        let shadow = Shadow::open(&context).await;

        // The genesis summary commits to the empty databases (L1, V2).
        let genesis = TestSummary::genesis::<PublicKey, u64>(store.balances.root());
        assert_eq!(genesis.payouts.root, store.log.root());
        assert_eq!(genesis.payouts.size, store.log.bounds().end);
        assert_eq!(shadow.roots(), store.roots());
        assert_eq!(
            genesis.matrix,
            Matrix::<PublicKey, Sha256, u64>::empty().root()
        );
        let parent = Checkpoint {
            summary: genesis,
            matrix: Matrix::empty(),
        };
        Self {
            namespace: Namespace::new(NAMESPACE),
            ledger: Ledger::new(&genesis),
            model: Model {
                balances: vec![0; users],
                log: vec![None],
                paid: BTreeSet::new(),
                claimed: BTreeSet::new(),
                deposited: 0,
                transferred: 0,
                deposits_hash: Digest::EMPTY,
                forced_hash: Digest::EMPTY,
            },
            desk: Desk {
                epoch: 1,
                balances: vec![0; users],
                previous: vec![None; users],
                admitted: BTreeMap::new(),
                withdrawals: BTreeMap::new(),
                overdrawn: BTreeSet::new(),
                closing: None,
            },
            books: vec![Book::default(); users],
            receipts: BTreeMap::new(),
            history: Vec::new(),
            stale: None,
            proofs: VecDeque::new(),
            unaudited: VecDeque::new(),
            context: Some(context),
            crashed: false,
            verified: 0,
            shadow: Some(shadow),
            keys,
            accounts,
            order,
            operator,
            rogue,
            schemes: fixture.schemes,
            verifier: fixture.verifier,
            store: Some(store),
            parent,
        }
    }

    fn users(&self) -> usize {
        self.accounts.len()
    }

    /// Returns the runtime's context.
    fn runtime(&self) -> &deterministic::Context {
        self.context.as_ref().expect("the process is up")
    }

    /// Returns the runtime's randomness.
    fn rng(&mut self) -> &mut deterministic::Context {
        self.context.as_mut().expect("the process is up")
    }

    fn user(&self, choice: u8) -> usize {
        usize::from(choice) % self.users()
    }

    /// Returns a user that can still spend in the epoch, or any user if none can. Most users hold
    /// nothing until a close processes their deposits, and a payer drawn among all of them would
    /// mostly be refused for its balance.
    fn payer(&self, choice: u8) -> usize {
        let funded: Vec<_> = (0..self.users())
            .filter(|user| self.live(*user) > 0)
            .collect();
        match funded.len() {
            0 => self.user(choice),
            len => funded[usize::from(choice) % len],
        }
    }

    fn store(&self) -> &Store {
        self.store
            .as_ref()
            .expect("the databases reopen after every refused apply")
    }

    fn index(&self, account: &PublicKey) -> Option<usize> {
        self.accounts
            .iter()
            .position(|candidate| candidate == account)
    }

    /// Returns the payment map of `map`.
    fn amounts(&self, map: &Map) -> TestAmounts {
        Amounts::new(
            map.iter()
                .map(|(user, amount)| (self.accounts[*user].clone(), *amount)),
        )
        .expect("model maps hold distinct users with nonzero amounts")
    }

    /// Returns the model of a payment map over users.
    fn map(&self, amounts: &TestAmounts) -> Map {
        amounts
            .iter()
            .map(|(account, amount)| (self.index(account).expect("a user"), amount))
            .collect()
    }

    /// Returns what `user` paid in the open epoch, its countersigned map's total.
    fn paid(&self, user: usize) -> u128 {
        self.desk
            .admitted
            .get(&user)
            .map_or(0, |latest| total(&latest.map))
    }

    /// Returns what `user` can still pay in the open epoch: its balance as of the last close
    /// applied, less what a released close may take from it and what it paid (O3). A faulty
    /// operator may have let the payments exceed it.
    fn live(&self, user: usize) -> u64 {
        let taken = self
            .desk
            .closing
            .as_ref()
            .map_or(0, |closing| closing.take[user]);
        let floor = u128::from(self.desk.balances[user]).saturating_sub(taken);
        u64::try_from(floor.saturating_sub(self.paid(user))).expect("at most the balance")
    }

    /// Returns the root the operator admits `user`'s states of the open epoch on: its row in the
    /// close of the epoch before, or the empty map (O4).
    fn previous(&self, user: usize) -> Digest {
        self.desk.previous[user].unwrap_or_else(empty_root)
    }

    /// Returns the operator's record of `user` and the root it admits on for `epoch`, while the
    /// operator can still admit or check states of it. A request names its own epoch or the next,
    /// and a state of the epoch after the open one builds on the row the honest close of the open
    /// one will hold.
    fn records(&self, user: usize, epoch: Epoch) -> Option<(Option<&Admitted>, Digest)> {
        let desk = &self.desk;
        if epoch == desk.epoch {
            return Some((desk.admitted.get(&user), self.previous(user)));
        }
        if epoch == desk.epoch + 1 {
            let root = desk
                .admitted
                .get(&user)
                .map_or_else(empty_root, |latest| latest.state.payments);
            return Some((None, root));
        }
        let closing = desk.closing.as_ref()?;
        (epoch + 1 == desk.epoch).then(|| {
            let previous = closing.previous[user].unwrap_or_else(empty_root);
            (closing.admitted.get(&user), previous)
        })
    }

    /// Returns the root `user` builds its states of `epoch` on (S1): that of its latest
    /// countersigned state of the epoch, else the row the post of the epoch before proved, else
    /// the root of its latest countersigned map of the epoch before, else the empty map's.
    fn builds_on(&self, user: usize, epoch: Epoch) -> Digest {
        let book = &self.books[user];
        if let Some(record) = book.records.get(&epoch) {
            return record.state.previous;
        }
        if book.resolved + 1 == epoch {
            return book.row.unwrap_or_else(empty_root);
        }
        book.records
            .get(&(epoch - 1))
            .map_or_else(empty_root, |record| record.state.payments)
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            ledger: self.ledger.clone(),
            model: self.model.clone(),
            desk: self.desk.clone(),
            books: self.books.clone(),
            receipts: self.receipts.len(),
            roots: self.store().roots(),
            parent: self.parent.summary,
        }
    }

    /// Returns a user other than `user`.
    fn other(&self, user: usize) -> usize {
        (user + 1) % self.users()
    }

    /// Comes back up after a crash with a new runtime, reopens the shadow and recovers the
    /// validator from what it persisted (V2), finishes checking the action that crashed, and runs
    /// the rest of the plan.
    async fn resume(context: deterministic::Context, crashed: Crashed) -> Option<Crashed> {
        let Crashed {
            mut harness,
            ops,
            before,
        } = crashed;
        harness.shadow = Some(Shadow::open(&context).await);
        harness.context = Some(context);
        harness.recover().await;
        harness.after(before).await;
        harness.run(ops).await
    }

    /// Runs `ops`, and returns what outlives the process if one of them crashes it.
    async fn run(mut self, mut ops: VecDeque<Op>) -> Option<Crashed> {
        while let Some(op) = ops.pop_front() {
            let before = Before {
                epoch: self.ledger.epoch(),
                log: self.model.log.len(),
                paid: self.ledger.paid.clone(),
                halt: self.ledger.halt,
            };
            match op {
                Op::Deposit { user, amount } => self.deposit(user, amount),
                Op::Force { user, amount } => self.force(user, amount),
                Op::Pay {
                    sender,
                    batch,
                    attack,
                } => self.pay(sender, &batch, attack),
                Op::Withdraw {
                    user,
                    amount,
                    tag,
                    attack,
                } => self.withdraw(user, amount, tag, attack),
                Op::Cut {
                    deposits,
                    forced,
                    omit,
                } => self.cut(deposits, forced, omit).await,
                Op::Close {
                    deposits,
                    forced,
                    attack,
                    defer,
                } => {
                    self.close(deposits, forced, attack).await;
                    while !defer && !self.crashed && !self.unaudited.is_empty() {
                        self.audit();
                    }
                }
                Op::Audit => {
                    if !self.unaudited.is_empty() {
                        self.audit();
                    }
                }
                Op::Payout { pick, attack } => self.payout(pick, attack).await,
                Op::Challenge { pick, attack } => self.challenge(pick, attack),
                Op::Halt => self.halt(),
                Op::Claim { user, attack } => self.claim(user, attack).await,
                Op::Restart => self.restart().await,
                Op::Garbage { kind } => self.garbage(kind),
                Op::Mutate {
                    target,
                    pick,
                    mutations,
                } => self.mutate(target, pick, &mutations).await,
            }

            // A crash loses the runtime and every database handle, and nothing else the roles
            // hold.
            if self.crashed {
                self.crashed = false;
                self.store = None;
                self.shadow = None;
                self.context = None;
                return Some(Crashed {
                    harness: self,
                    ops,
                    before,
                });
            }
            self.after(before).await;
        }

        // I9: receivers audit, and senders resolve, every post still unaudited.
        while !self.unaudited.is_empty() {
            self.audit();
        }
        self.check().await;

        // The last checkpoint renders for triage.
        let rendered = format!("{:?}", self.parent);
        assert!(rendered.contains("Checkpoint"));
        None
    }

    /// Checks an action against the state `before` it, then the invariants that hold after every
    /// action.
    async fn after(&mut self, before: Before) {
        // I8: one post at most per action, none after a halt, and nothing paid is forgotten.
        let posted = self.ledger.epoch() - before.epoch;
        assert!(posted <= 1);
        assert!(posted == 0 || before.halt.is_none());
        assert_eq!(posted == 1, self.model.log.len() > before.log);
        assert!(self.model.log.len() >= before.log);
        assert!(self.ledger.paid.is_superset(&before.paid));
        if before.halt.is_some() {
            assert_eq!(self.ledger.halt, before.halt);
        }

        // I3: the payout log holds what the model logged since the last check, and what a
        // recovery wrote again.
        let start = self.verified;
        Self::check_entries(
            &self.store().log,
            &self.accounts,
            start,
            &self.model.log[start..],
        )
        .await;
        self.verified = self.model.log.len();
        self.check().await;
    }

    /// Checks the invariants that hold after every action.
    async fn check(&self) {
        // I1: the funds held back exactly the unclaimed balances, the queued and claimable
        // deposits, and the unpaid posted payouts.
        let balances: u128 = (0..self.users())
            .filter(|user| !self.model.claimed.contains(user))
            .map(|user| u128::from(self.model.balances[user]))
            .sum();
        let queued: u128 = self
            .ledger
            .deposits
            .iter()
            .map(|d| u128::from(d.amount))
            .sum();
        let claimable: u128 = self.ledger.claimable.values().map(|a| u128::from(*a)).sum();
        let unpaid: u128 = self
            .model
            .log
            .iter()
            .enumerate()
            .filter(|(index, _)| !self.model.paid.contains(&(*index as u64)))
            .filter_map(|(_, entry)| entry.map(|(_, amount)| u128::from(amount)))
            .sum();
        let held = u128::from(self.ledger.held);
        assert_eq!(held, self.model.deposited - self.model.transferred);
        assert_eq!(held, balances + queued + claimable + unpaid);

        // I4: the ledger covers exactly the commits and the payouts paid.
        let covered: BTreeSet<u64> = self
            .model
            .log
            .iter()
            .enumerate()
            .filter(|(index, entry)| entry.is_none() || self.model.paid.contains(&(*index as u64)))
            .map(|(index, _)| index as u64)
            .collect();
        assert_eq!(self.ledger.paid, covered);

        // I2: the operator, the validator and the model agree on every balance, and the
        // databases sit at the last post.
        assert_eq!(self.desk.balances, self.model.balances);
        let store = self.store();
        assert_eq!(
            store.roots(),
            (
                self.parent.summary.balances,
                self.parent.summary.payouts.root
            )
        );
        assert_eq!(self.ledger.balances, self.parent.summary.balances);
        assert_eq!(self.ledger.last, self.parent.summary.digest());
        assert_eq!(*store.log.bounds().end, self.model.log.len() as u64);
        assert_eq!(
            *self.parent.summary.payouts.size,
            self.model.log.len() as u64
        );
        for (user, account) in self.accounts.iter().enumerate() {
            let held = store
                .balances
                .get(account)
                .await
                .expect("the balances database must read");
            let expected = self.model.balances[user];
            assert_eq!(held, (expected != 0).then_some(expected));
        }

        // I2: a sender with no request in flight records, for every epoch the operator still
        // holds records of, the state and map the operator countersigned last. A state the
        // released close does not settle is exempt: its acknowledgement may never have reached
        // the sender, whose request then paid its batch in the next epoch instead (O6).
        let closing = self.desk.closing.as_ref();
        for (user, book) in self.books.iter().enumerate() {
            if book.pending.is_some() || book.late.is_some() {
                continue;
            }
            let mut epochs = vec![(self.desk.epoch, self.desk.admitted.get(&user))];
            if let Some(closing) = closing {
                let latest = closing.admitted.get(&user);
                if latest.is_none_or(|latest| closing.rows.get(&user) == Some(&latest.map)) {
                    epochs.push((self.desk.epoch - 1, latest));
                }
            }
            for (epoch, latest) in epochs {
                let operator = latest.map(|latest| (&latest.state, &latest.map));
                let sender = book
                    .records
                    .get(&epoch)
                    .map(|record| (&record.state, &record.map));
                assert_eq!(sender, operator, "sender {user} disagrees in epoch {epoch}");
            }
        }
    }

    fn deposit(&mut self, user: u8, amount: Size) {
        let user = self.user(user);
        let amount = amount.resolve(DEPOSIT_BASE);
        let before = self.snapshot();
        let result = self.ledger.deposit(self.accounts[user].clone(), amount);
        match result {
            Ok(()) => {
                assert!(before.ledger.halt.is_none() && amount != 0);
                self.model.deposited += u128::from(amount);
            }
            Err(Refusal::Halted) => assert!(before.ledger.halt.is_some()),
            Err(Refusal::ZeroAmount) => assert_eq!(amount, 0),
            Err(Refusal::Custody) => {
                assert!(before.ledger.held.checked_add(amount).is_none());
            }
            Err(refusal) => panic!("deposit refused as {refusal:?}"),
        }
        if self.ledger.held == before.ledger.held {
            // I10: a refused deposit changes nothing.
            assert_eq!(self.snapshot(), before);
        }
    }

    fn force(&mut self, user: u8, amount: Size) {
        let user = self.payer(user);
        let amount = amount.resolve(self.model.balances[user]);
        let before = self.snapshot();
        match self.ledger.force(self.accounts[user].clone(), amount) {
            Ok(()) => assert!(before.ledger.halt.is_none() && amount != 0),
            Err(Refusal::Halted) => assert!(before.ledger.halt.is_some()),
            Err(Refusal::ZeroAmount) => assert_eq!(amount, 0),
            Err(refusal) => panic!("forced withdrawal refused as {refusal:?}"),
        }
        if self.ledger.forced.len() == before.ledger.forced.len() {
            assert_eq!(self.snapshot(), before);
        }
    }

    fn halt(&mut self) {
        let before = self.ledger.halt;
        self.ledger.halt();
        assert_eq!(self.ledger.halt, before.or(Some(Halt::Policy)));
        assert!(self.ledger.deposits.is_empty() && self.ledger.forced.is_empty());
    }

    /// Returns the request `user` signs to pay `batch` in the open epoch on its own latest
    /// countersigned state (S1), with the states it signed.
    fn sign_request(&self, user: usize, batch: &TestAmounts, external: bool) -> Pending {
        let epoch = self.desk.epoch;
        let latest = self.books[user].records.get(&epoch);
        let previous = self.builds_on(user, epoch);
        let states = TestRequest::states::<Sha256>(
            epoch,
            self.accounts[user].clone(),
            batch.clone(),
            latest.map(|latest| (&latest.state, &latest.payments)),
            &previous,
        )
        .expect("a payable batch derives its states");
        let request = states.sign(&self.keys[user], &self.namespace);
        if external {
            // A signer outside the process signs each state's encoding in the state namespace.
            let signatures = Signatures {
                current: self.keys[user].sign(&self.namespace.state, &states.current.encode()),
                next: self.keys[user].sign(&self.namespace.state, &states.next.encode()),
            };
            assert_eq!(states.request(signatures), request);
        }

        // S1: the state of the epoch extends the latest map on the posted row, and the state of
        // the next epoch pays the batch alone on the latest map.
        let latest_root = latest.map_or_else(empty_root, |latest| latest.state.payments);
        assert_eq!(states.batch, *batch);
        assert_eq!(states.current.previous, previous);
        assert_eq!(states.current.payments, states.payments.root::<Sha256>());
        assert_eq!(states.next.epoch, epoch + 1);
        assert_eq!(states.next.payments, batch.root::<Sha256>());
        assert_eq!(states.next.previous, latest_root);
        let expected = latest.map_or_else(
            || batch.clone(),
            |latest| {
                latest
                    .payments
                    .combine(batch)
                    .expect("a payable batch combines")
            },
        );
        assert_eq!(states.payments, expected);

        // S1: the sender cannot derive the states on another root than its latest state's, nor
        // from a latest state whose root already holds the batch.
        if let Some(latest) = latest {
            let derive = |latest: (&TestState, &TestAmounts), previous: &Digest| {
                TestRequest::states::<Sha256>(
                    epoch,
                    self.accounts[user].clone(),
                    batch.clone(),
                    Some(latest),
                    previous,
                )
            };
            // The new map's root, or a fixed one when the new map repeats the row it builds on.
            let elsewhere = if states.current.payments == latest.state.previous {
                Sha256::hash(&[b"elsewhere"])
            } else {
                states.current.payments
            };
            assert!(matches!(
                derive((&latest.state, &latest.payments), &elsewhere),
                Err(RequestError::InvalidPrevious)
            ));
            let holding = State {
                payments: states.current.payments,
                ..latest.state.clone()
            };
            assert!(matches!(
                derive((&holding, &latest.payments), &previous),
                Err(RequestError::InvalidLatest)
            ));
        }
        let signatures = request.signatures.clone();
        Pending {
            request,
            signed: Signed {
                current: states.current,
                next: states.next,
                signatures,
            },
            payments: states.payments,
            sent: 0,
        }
    }

    /// Returns what the operator must do with `request` admitted in `epoch` against `latest` on
    /// `previous`, when `signed` holds the states and signatures its sender made.
    fn expect(
        &self,
        epoch: Epoch,
        latest: Option<&Admitted>,
        previous: Digest,
        request: &TestRequest,
        signed: &Signed,
    ) -> Expect {
        let account = request.account.clone();
        let (state, authentic) = if request.epoch == epoch {
            let state = State {
                epoch,
                account,
                payments: request.payments,
                previous: request.previous,
            };
            let authentic =
                state == signed.current && request.signatures.current == signed.signatures.current;
            (state, authentic)
        } else if request.epoch.checked_add(1) == Some(epoch) {
            let state = State {
                epoch,
                account,
                payments: request.batch.root::<Sha256>(),
                previous: request.latest,
            };
            let authentic =
                state == signed.next && request.signatures.next == signed.signatures.next;
            (state, authentic)
        } else {
            return Expect::WrongEpoch;
        };
        if request.batch.is_empty() {
            return Expect::NoReceivers;
        }
        if !authentic {
            return Expect::InvalidSignature;
        }
        if latest.is_some_and(|latest| latest.state == state) {
            return Expect::Retry;
        }
        if state.previous != previous {
            return Expect::InvalidSignature;
        }
        let mut map = latest.map(|latest| latest.map.clone()).unwrap_or_default();
        for (account, amount) in request.batch.iter() {
            let Some(receiver) = self.index(account) else {
                return Expect::InvalidSignature;
            };
            let entry = map.entry(receiver).or_default();
            let Some(sum) = entry.checked_add(amount) else {
                return Expect::InvalidSignature;
            };
            *entry = sum;
        }
        if self.amounts(&map).root::<Sha256>() != state.payments {
            return Expect::InvalidSignature;
        }
        Expect::New(map)
    }

    /// Checks the operator's admission of `request` in `epoch` against `latest` on `previous`
    /// against the model's `expected` outcome, and returns the state, map, sender's signature and
    /// model map of a new admission.
    #[allow(clippy::type_complexity)]
    fn admission(
        &self,
        admission: Result<Admission<PublicKey, Digest, u64>, RequestError>,
        expected: Expect,
        epoch: Epoch,
        latest: Option<&Admitted>,
        previous: Digest,
        request: &TestRequest,
    ) -> Option<(TestState, TestAmounts, Signature, Map)> {
        match (admission, expected) {
            (Ok(Admission::Retry(state)), Expect::Retry) => {
                let latest = latest.expect("a retry repeats a countersigned state");
                assert_eq!(state, latest.state);
                None
            }
            (
                Ok(Admission::New {
                    state,
                    payments,
                    signature,
                }),
                Expect::New(map),
            ) => {
                // The state is the one the sender signed for the epoch, on the map the model
                // derives, with the request's signature over it.
                let expected = State {
                    epoch,
                    account: request.account.clone(),
                    payments: payments.root::<Sha256>(),
                    previous,
                };
                assert_eq!(state, expected);
                assert_eq!(payments, self.amounts(&map));
                let signed = if request.epoch == epoch {
                    &request.signatures.current
                } else {
                    &request.signatures.next
                };
                assert_eq!(&signature, signed);
                Some((state, payments, signature, map))
            }
            (Err(RequestError::WrongEpoch { expected, found }), Expect::WrongEpoch) => {
                assert_eq!((expected, found), (epoch, request.epoch));
                None
            }
            (Err(RequestError::NoReceivers), Expect::NoReceivers)
            | (Err(RequestError::InvalidSignature), Expect::InvalidSignature) => None,
            (admission, expected) => {
                panic!("admission {admission:?} where the model expects {expected:?}")
            }
        }
    }

    /// Delivers `request` from `user` to the operator, which countersigns it if it is admitted
    /// and fits the sender's balance and the limits, or repeats its countersignature on a retry.
    /// Returns the acknowledgement the operator releases, with the state it countersigns.
    fn deliver(
        &mut self,
        user: usize,
        request: &TestRequest,
        signed: &Signed,
        faulty: bool,
    ) -> Option<(TestState, Signature)> {
        let before = self.snapshot();
        let epoch = self.desk.epoch;
        let previous = self.previous(user);
        let latest = self.desk.admitted.get(&user).cloned();
        let expected = self.expect(epoch, latest.as_ref(), previous, request, signed);

        // I12: the operator decodes requests under its receiver limit, which refuses a batch
        // beyond it or empty.
        let encoded = request.encode();
        let decoded = TestRequest::decode_cfg(encoded, &LIMITS.receivers);
        if (1..=LIMITS.receivers).contains(&request.batch.len()) {
            assert_eq!(decoded.as_ref().ok(), Some(request));
        } else {
            assert!(decoded.is_err());
            return None;
        }

        // I5: the operator verifies the request before reading its records, then admits it.
        let admission = request
            .verify::<Sha256>(&self.namespace, epoch)
            .and_then(|verified| {
                verified.admit::<Sha256>(
                    latest
                        .as_ref()
                        .map(|latest| (&latest.state, &latest.payments)),
                    &previous,
                )
            });
        let retry = matches!(admission, Ok(Admission::Retry(_)));
        let admitted = self.admission(
            admission,
            expected,
            epoch,
            latest.as_ref(),
            previous,
            request,
        );
        let Some((state, payments, signature, map)) = admitted else {
            // A refusal changes nothing, and a retry is countersigned again and pays nothing
            // twice.
            assert_eq!(self.snapshot(), before);
            let latest = latest.filter(|_| retry)?;
            let acknowledgement = latest.state.acknowledge(&self.operator, &self.namespace);
            assert_eq!(acknowledgement, latest.acknowledgement);
            return Some((latest.state, acknowledgement));
        };

        // O3, O5: a new state must fit the limits and what the sender can still spend.
        let live = self.live(user);
        let total = request.batch.total();
        let full = (latest.is_none() && self.desk.admitted.len() >= LIMITS.rows)
            || payments.len() > LIMITS.receivers;
        let poor = total.is_none_or(|total| total > live);
        if full || (poor && !faulty) {
            assert_eq!(self.snapshot(), before);
            return None;
        }
        if poor {
            self.desk.overdrawn.insert(user);
        }

        // O7: the admission is recorded before its acknowledgement is released.
        let acknowledgement = state.acknowledge(&self.operator, &self.namespace);
        let mut admitted = Admitted {
            state: state.clone(),
            payments,
            signature,
            acknowledgement: acknowledgement.clone(),
            map,
            requests: vec![request.clone()],
            earlier: Vec::new(),
        };
        if let Some(latest) = latest {
            admitted.requests = latest.requests;
            admitted.requests.push(request.clone());
            admitted.earlier = latest.earlier;
            admitted
                .earlier
                .push((latest.state, latest.payments, latest.signature, latest.map));
        }
        self.desk.admitted.insert(user, admitted);
        Some((state, acknowledgement))
    }

    /// Delivers `user`'s pending request, and its acknowledgement unless `lose`. A refused
    /// request delivered once, with no copy in flight, is dropped (S4). Returns the receipts the
    /// sender issued.
    fn send(&mut self, user: usize, faulty: bool, lose: bool) -> Vec<TestReceipt> {
        let book = &mut self.books[user];
        let pending = book.pending.as_mut().expect("a pending request");
        pending.sent += 1;
        let pending = pending.clone();
        match self.deliver(user, &pending.request, &pending.signed, faulty) {
            Some(acknowledgement) if lose => {
                self.books[user].late = Some(acknowledgement);
                Vec::new()
            }
            Some((state, acknowledgement)) => self.acknowledged(user, &state, &acknowledgement),
            None => {
                if pending.sent == 1 {
                    self.books[user].pending = None;
                }
                Vec::new()
            }
        }
    }

    /// The operator's acknowledgement of `state` reaches `user`. The sender records the map of
    /// its pending request's state, in one write that clears the request (S3), only if the
    /// acknowledgement verifies and it has not resolved the state's epoch (S2). It then issues
    /// receipts, which receivers verify and keep. Returns the receipts issued.
    fn acknowledged(
        &mut self,
        user: usize,
        state: &TestState,
        acknowledgement: &Signature,
    ) -> Vec<TestReceipt> {
        let operator = self.operator.public_key();
        assert!(state.verify_acknowledgement(&self.namespace, &operator, acknowledgement));
        assert!(!state.verify_acknowledgement(
            &self.namespace,
            &self.rogue.public_key(),
            acknowledgement
        ));
        let book = &self.books[user];
        let pending = book
            .pending
            .as_ref()
            .filter(|_| state.epoch > book.resolved);
        let Some(pending) = pending else {
            // An acknowledgement repeated for a recorded state, or one arriving after the post of
            // its epoch was resolved, records nothing.
            if let Some(record) = book.records.get(&state.epoch)
                && record.state == *state
            {
                assert_eq!(&record.acknowledgement, acknowledgement);
            }
            return Vec::new();
        };
        let (payments, signature) = if *state == pending.signed.current {
            (&pending.payments, &pending.signed.signatures.current)
        } else if *state == pending.signed.next {
            (&pending.request.batch, &pending.signed.signatures.next)
        } else {
            panic!("an acknowledgement of a state the sender did not send");
        };
        let receivers: Vec<_> = pending
            .request
            .batch
            .iter()
            .map(|(account, _)| account.clone())
            .collect();
        let record = Record {
            state: state.clone(),
            payments: payments.clone(),
            signature: signature.clone(),
            acknowledgement: acknowledgement.clone(),
            map: self.map(payments),
        };
        let receipts = self.issue(user, &record, receivers);
        let book = &mut self.books[user];
        book.records.insert(state.epoch, record);
        book.pending = None;
        receipts
    }

    /// Issues `user`'s receipts of `record` to `receivers`, which verify them and keep the
    /// largest (R1, R2). A sender issues receipts of an epoch only until it resolves that epoch's
    /// post, which happens when receivers audit it, so receivers accept them until then (R3).
    fn issue(
        &mut self,
        user: usize,
        record: &Record,
        receivers: Vec<PublicKey>,
    ) -> Vec<TestReceipt> {
        let operator = self.operator.public_key();
        let issue = |payments: &TestAmounts, receivers: Vec<PublicKey>| {
            TestReceipt::issue::<Sha256>(
                &record.state,
                &record.signature,
                &record.acknowledgement,
                payments,
                receivers,
            )
        };
        let receipts = issue(&record.payments, receivers.clone())
            .expect("a countersigned map opens each receiver of its batch");

        // I5: exactly one receipt per receiver asked for, in that order, of its entry of the map.
        assert_eq!(receipts.len(), receivers.len());
        for (receipt, receiver) in receipts.iter().zip(&receivers) {
            assert_eq!(&receipt.receiver, receiver);
            assert_eq!(receipt.state, record.state);
            assert_eq!(receipt.signature, record.signature);
            assert_eq!(receipt.acknowledgement, record.acknowledgement);
            assert_eq!(receipt.amount, record.payments.get(receiver));
            let position = record.payments.position(receiver).expect("a receiver");
            assert_eq!(receipt.position as usize, position);
        }

        // Asked for every receiver of the map, it issues one receipt each, in the map's order.
        let every: Vec<_> = record
            .payments
            .iter()
            .map(|(account, _)| account.clone())
            .collect();
        let all = issue(&record.payments, every).expect("a countersigned map opens each receiver");
        assert_eq!(all.len(), record.payments.len());
        for (position, (receipt, (receiver, amount))) in
            all.iter().zip(record.payments.iter()).enumerate()
        {
            assert_eq!(&receipt.receiver, receiver);
            assert_eq!(receipt.amount, amount);
            assert_eq!(receipt.position as usize, position);
            assert_eq!(receipt.state, record.state);
            assert_eq!(receipt.signature, record.signature);
            assert_eq!(receipt.acknowledgement, record.acknowledgement);
        }

        // A map the state does not commit to issues nothing, and neither does a receiver the map
        // does not pay.
        let mut other = record.map.clone();
        let first = other.values_mut().next().expect("a countersigned map pays");
        *first = first.wrapping_add(1).max(1);
        assert!(issue(&self.amounts(&other), receivers).is_none());
        assert!(issue(&record.payments, vec![self.rogue.public_key()]).is_none());
        let epoch = record.state.epoch;
        for receipt in &receipts {
            roundtrip(receipt, &());
            assert!(receipt.verify::<Sha256>(&self.namespace, &operator));
            let receiver = self.index(&receipt.receiver).expect("a user");
            assert_eq!(receipt.amount, record.map[&receiver]);
            let held = self
                .receipts
                .entry((epoch, user, receiver))
                .or_insert_with(|| receipt.clone());
            assert!(held.amount <= receipt.amount);
            *held = receipt.clone();
        }
        receipts
    }

    fn pay(&mut self, sender: u8, entries: &[(u8, Size)], attack: Option<PayAttack>) {
        // The operator admits nothing once the ledger halts.
        if self.ledger.halt.is_some() {
            return;
        }
        // A lost acknowledgement reaches its sender late, possibly after a post resolved its
        // request (S2). Any sender can have one, funded or not.
        let user = self.user(sender);
        if let Some((state, acknowledgement)) = self.books[user].late.take() {
            self.acknowledged(user, &state, &acknowledgement);
            return;
        }

        // S1: a sender signs nothing new while a request is pending, so it sends that one again.
        if self.books[user].pending.is_some() {
            self.send(user, false, matches!(attack, Some(PayAttack::LoseAck)));
            return;
        }

        // A new payment comes from a sender that can still spend, with nothing in flight.
        let user = self.payer(sender);
        if self.books[user].late.is_some() || self.books[user].pending.is_some() {
            return;
        }

        // The batch pays each receiver a share of what the sender can still spend. Entries that
        // repeat a receiver or pay nothing do not form a batch.
        let live = self.live(user);
        let base = live / entries.len() as u64;
        let raw: Vec<_> = entries
            .iter()
            .map(|(receiver, size)| (self.user(*receiver), size.resolve(base)))
            .collect();
        let candidate = Amounts::new(raw.iter().map(|(r, a)| (self.accounts[*r].clone(), *a)));
        let zero = raw.iter().any(|(_, amount)| *amount == 0);
        let repeated = raw.iter().map(|(r, _)| *r).collect::<BTreeSet<_>>().len() < raw.len();
        match candidate {
            Err(AmountsError::ZeroAmount) => assert!(zero),
            Err(AmountsError::Duplicate) => assert!(!zero && repeated),
            Err(error) => panic!("a batch refused as {error:?}"),
            Ok(_) => assert!(!zero && !repeated),
        }
        let mut map = Map::new();
        for (receiver, amount) in raw {
            if amount != 0 {
                map.insert(receiver, amount);
            }
        }
        let mut batch = self.amounts(&map);
        if let Some(PayAttack::Overcommit) = attack {
            // The sender asks for one unit more than it can spend, split over two receivers when
            // no single amount exceeds what it can spend.
            let Some(over) = self.overspend(user, live) else {
                return;
            };
            map = over;
            batch = self.amounts(&map);
        }
        if batch.is_empty() {
            assert!(matches!(
                TestRequest::states::<Sha256>(
                    self.desk.epoch,
                    self.accounts[user].clone(),
                    batch,
                    None,
                    &empty_root(),
                ),
                Err(RequestError::NoReceivers)
            ));
            return;
        }

        // A batch that overflows the sender's map derives no states.
        let epoch = self.desk.epoch;
        let latest = self.books[user].records.get(&epoch);
        if let Some(latest) = latest
            && latest.payments.combine(&batch).is_err()
        {
            let derived = TestRequest::states::<Sha256>(
                epoch,
                self.accounts[user].clone(),
                batch,
                Some((&latest.state, &latest.payments)),
                &self.builds_on(user, epoch),
            );
            assert!(matches!(derived, Err(RequestError::Overflow)));
            return;
        }
        let external = matches!(attack, Some(PayAttack::External));
        let pending = self.sign_request(user, &batch, external);
        let (mut request, mut signed) = (pending.request.clone(), pending.signed.clone());
        let before = self.snapshot();
        match attack {
            // S3: the sender persists the request before sending it.
            None | Some(PayAttack::External) => {
                self.books[user].pending = Some(pending);
                self.send(user, false, false);
            }
            Some(PayAttack::LoseAck) => {
                self.books[user].pending = Some(pending);
                self.send(user, false, true);
            }
            Some(PayAttack::WrongSigner) => {
                let other = &self.keys[self.other(user)];
                request.signatures = Signatures {
                    current: other.sign(&self.namespace.state, &signed.current.encode()),
                    next: other.sign(&self.namespace.state, &signed.next.encode()),
                };
                self.deliver(user, &request, &signed, false);
            }
            Some(PayAttack::TamperBatch) => {
                let mut tampered = map.clone();
                let receiver = *tampered.keys().next().expect("a nonempty batch");
                let entry = tampered.get_mut(&receiver).expect("present");
                *entry = entry.wrapping_add(1).max(1);
                request.batch = self.amounts(&tampered);
                self.deliver(user, &request, &signed, false);
            }
            Some(PayAttack::TamperRoot) => {
                request.payments = empty_root();
                self.deliver(user, &request, &signed, false);
            }
            Some(PayAttack::WrongPrevious) => {
                // Derived as a first payment of the epoch on a root no post proves for it.
                let elsewhere = Sha256::hash(&[b"elsewhere"]);
                let states = TestRequest::states::<Sha256>(
                    request.epoch,
                    request.account.clone(),
                    batch,
                    None,
                    &elsewhere,
                )
                .expect("a first payment derives on any root");
                request = states.sign(&self.keys[user], &self.namespace);
                signed = Signed::of(&request);
                self.deliver(user, &request, &signed, false);
            }
            Some(PayAttack::StaleEpoch(future)) => {
                request.epoch = if future || epoch < 2 {
                    epoch + 1
                } else {
                    epoch - 2
                };
                self.deliver(user, &request, &signed, false);
            }
            Some(PayAttack::Replay) => {
                self.books[user].pending = Some(pending);
                self.send(user, false, false);
                self.replay(user, &request);
            }
            Some(PayAttack::ReplayOld) => {
                let old = self
                    .desk
                    .admitted
                    .get(&user)
                    .map(|latest| latest.requests[0].clone());
                match old {
                    // An older request's states are the sender's, signed when it was sent.
                    Some(old) => self.replay(user, &old),
                    None => {
                        self.books[user].pending = Some(pending);
                        self.send(user, false, false);
                    }
                }
            }
            Some(PayAttack::EmptyBatch) => {
                // The operator decodes no empty batch, and verifies none in process.
                request.batch = TestAmounts::default();
                assert!(TestRequest::decode_cfg(request.encode(), &LIMITS.receivers).is_err());
                for epoch in [request.epoch, request.epoch + 1] {
                    assert!(matches!(
                        request.verify::<Sha256>(&self.namespace, epoch),
                        Err(RequestError::NoReceivers)
                    ));
                }
            }
            Some(PayAttack::Overcommit) => {
                self.books[user].pending = Some(pending);
                self.send(user, true, false);
            }
            Some(PayAttack::Underivable(kind)) => self.underivable(user, &batch, kind),
            Some(PayAttack::Delay) => {
                self.books[user].pending = Some(pending);
                return;
            }
            Some(PayAttack::TamperReceipt(kind)) => {
                self.books[user].pending = Some(pending);
                let receipts = self.send(user, false, false);
                if let Some(receipt) = receipts.first() {
                    self.tamper_receipt(user, receipt, kind);
                }
                return;
            }
        }
        if !matches!(
            attack,
            None | Some(
                PayAttack::External
                    | PayAttack::Overcommit
                    | PayAttack::Replay
                    | PayAttack::ReplayOld
                    | PayAttack::LoseAck
            )
        ) {
            // I10: every other attack is refused, and the sender then pays as it signed.
            assert_eq!(self.snapshot(), before);
            self.pay(sender, entries, None);
        }
    }

    /// Delivers a copy of a request `user` sent earlier, whose acknowledgement, if the operator
    /// countersigns again, reaches the sender.
    fn replay(&mut self, user: usize, request: &TestRequest) {
        let signed = Signed::of(request);
        if let Some((state, acknowledgement)) = self.deliver(user, request, &signed, false) {
            let receipts = self.acknowledged(user, &state, &acknowledgement);
            assert!(receipts.is_empty(), "a copy pays nothing twice");
        }
    }

    /// Returns a map paying receivers other than `user` one unit more than `live` in total, or
    /// `None` if no receiver is left for the unit past the largest amount.
    fn overspend(&self, user: usize, live: u64) -> Option<Map> {
        let receiver = self.other(user);
        if let Some(over) = live.checked_add(1) {
            return Some(Map::from([(receiver, over)]));
        }
        let second = self.other(receiver);
        (second != user).then(|| Map::from([(receiver, live), (second, 1)]))
    }

    /// Checks that states the crate must refuse do not derive, and that no amounts form from
    /// entries it must refuse.
    fn underivable(&self, user: usize, batch: &TestAmounts, kind: u8) {
        let account = self.accounts[user].clone();
        let epoch = self.desk.epoch;
        let previous = self.previous(user);
        let receiver = self.accounts[self.other(user)].clone();
        let full = Amounts::new([(receiver.clone(), u64::MAX)]).expect("a nonzero amount");
        let latest = |payments: &TestAmounts| State {
            epoch,
            account: account.clone(),
            payments: payments.root::<Sha256>(),
            previous,
        };
        let derive = |epoch, latest: Option<(&TestState, &TestAmounts)>, previous: &Digest| {
            TestRequest::states::<Sha256>(epoch, account.clone(), batch.clone(), latest, previous)
        };
        match kind % 7 {
            0 => assert!(matches!(
                derive(Epoch::MAX, None, &previous),
                Err(RequestError::Overflow)
            )),
            1 => {
                let one = Amounts::new([(receiver, 1)]).expect("a nonzero amount");
                assert!(matches!(full.combine(&one), Err(AmountsError::Overflow)));
                let state = latest(&full);
                let derived = TestRequest::states::<Sha256>(
                    epoch,
                    account.clone(),
                    one,
                    Some((&state, &full)),
                    &previous,
                );
                assert!(matches!(derived, Err(RequestError::Overflow)));
            }
            2 => {
                let state = latest(&full);
                let mut elsewhere = full.root::<Sha256>();
                if elsewhere == previous {
                    elsewhere = Sha256::hash(&[b"elsewhere"]);
                }
                assert!(matches!(
                    derive(epoch, Some((&state, &full)), &elsewhere),
                    Err(RequestError::InvalidPrevious)
                ));
            }
            3 => {
                // A latest state whose root already holds the batch would let both states settle.
                let held = TestAmounts::default();
                let state = latest(batch);
                assert!(matches!(
                    derive(epoch, Some((&state, &held)), &previous),
                    Err(RequestError::InvalidLatest)
                ));
            }
            4 => assert!(matches!(
                TestRequest::states::<Sha256>(
                    epoch,
                    account.clone(),
                    TestAmounts::default(),
                    None,
                    &previous
                ),
                Err(RequestError::NoReceivers)
            )),
            5 => assert!(matches!(
                TestAmounts::new([(receiver, 0)]),
                Err(AmountsError::ZeroAmount)
            )),
            _ => assert!(matches!(
                TestAmounts::new([(receiver.clone(), 1), (receiver, 2)]),
                Err(AmountsError::Duplicate)
            )),
        }
    }

    /// Checks that a receipt changed in any field no longer verifies, and that receipts do not
    /// issue from a map the state does not commit to or for a receiver it does not pay.
    fn tamper_receipt(&self, user: usize, receipt: &TestReceipt, kind: u8) {
        let operator = self.operator.public_key();
        let admitted = &self.desk.admitted[&user];
        let mut tampered = receipt.clone();
        match kind % 8 {
            0 => tampered.amount = receipt.amount.wrapping_add(1),
            1 => tampered.receiver = self.rogue.public_key(),
            2 => tampered.position ^= 1,
            3 => tampered.acknowledgement = receipt.signature.clone(),
            4 => tampered.state.epoch += 1,
            5 => {
                assert!(!receipt.verify::<Sha256>(&self.namespace, &self.rogue.public_key()));
                return;
            }
            6 => {
                let mut map = admitted.map.clone();
                let entry = map.values_mut().next().expect("a countersigned map pays");
                *entry = entry.wrapping_add(1).max(1);
                let issued = TestReceipt::issue::<Sha256>(
                    &receipt.state,
                    &receipt.signature,
                    &receipt.acknowledgement,
                    &self.amounts(&map),
                    vec![receipt.receiver.clone()],
                );
                assert!(issued.is_none());
                return;
            }
            _ => {
                let issued = TestReceipt::issue::<Sha256>(
                    &receipt.state,
                    &receipt.signature,
                    &receipt.acknowledgement,
                    &admitted.payments,
                    vec![self.rogue.public_key()],
                );
                assert!(issued.is_none());
                return;
            }
        }
        assert!(!tampered.verify::<Sha256>(&self.namespace, &operator));
    }

    fn withdraw(&mut self, user: u8, amount: Size, tag: u8, attack: Option<WithdrawAttack>) {
        if self.ledger.halt.is_some() {
            return;
        }
        let honest = (user, amount, tag);
        let user = self.payer(user);
        let epoch = self.desk.epoch;
        let amount = amount.resolve(self.desk.balances[user]);
        let tag = u64::from(tag % 4);
        let account = self.accounts[user].clone();
        let mut withdrawal =
            TestWithdrawal::sign(&self.keys[user], &self.namespace, epoch, amount, tag);

        // The account signs the documented message in the withdrawal namespace.
        let message = TestWithdrawal::message(epoch, &account, amount, tag);
        assert!(account.verify(&self.namespace.withdrawal, &message, &withdrawal.signature));
        let mut authentic = amount != 0;
        match attack {
            None => {}
            Some(WithdrawAttack::WrongSigner) => {
                let other = self.other(user);
                withdrawal.signature = self.keys[other].sign(&self.namespace.withdrawal, &message);
                authentic = false;
            }
            Some(WithdrawAttack::TamperAmount) => {
                withdrawal.amount = amount.wrapping_add(1);
                authentic = false;
            }
            Some(WithdrawAttack::StaleEpoch(future)) => {
                let stale = if future { epoch + 1 } else { epoch - 1 };
                withdrawal =
                    TestWithdrawal::sign(&self.keys[user], &self.namespace, stale, amount, tag);
            }
            Some(WithdrawAttack::Relabeled(future)) => {
                let stale = if future { epoch + 1 } else { epoch - 1 };
                let signed =
                    TestWithdrawal::sign(&self.keys[user], &self.namespace, stale, amount, tag);
                withdrawal.signature = signed.signature;
                authentic = false;
            }
        }
        roundtrip(&withdrawal, &());

        // O5: the operator honors a withdrawal of this epoch only if it verifies and fits.
        assert_eq!(withdrawal.verify(&self.namespace), authentic);
        let before = self.snapshot();
        let key = (user, withdrawal.amount, withdrawal.tag);
        let honored = withdrawal.epoch == epoch
            && authentic
            && (self.desk.withdrawals.contains_key(&key)
                || self.desk.withdrawals.len() < LIMITS.withdrawals);
        if honored {
            self.desk.withdrawals.entry(key).or_insert(withdrawal);
        } else {
            assert_eq!(self.snapshot(), before);

            // An attack is refused, and the account then asks as it signed.
            if attack.is_some() {
                let (user, amount, tag) = honest;
                self.withdraw(user, amount, tag, None);
            }
        }
    }

    /// Returns the rows of a close of the senders `admitted`, less `skip`, with each sender in
    /// `earlier` settling its earliest countersigned map instead of its latest.
    fn rows(
        &mut self,
        admitted: &BTreeMap<usize, Admitted>,
        skip: &BTreeSet<usize>,
        earlier: Option<usize>,
    ) -> Rows {
        let mut plan = Rows {
            rows: Vec::new(),
            model: BTreeMap::new(),
            omitted: skip.clone(),
        };
        for (user, admitted) in admitted {
            if skip.contains(user) {
                continue;
            }
            let (payments, signature, map) = match admitted.earlier.first() {
                Some((_, payments, signature, map)) if earlier == Some(*user) => {
                    plan.omitted.insert(*user);
                    (payments.clone(), signature.clone(), map.clone())
                }
                _ => (
                    admitted.payments.clone(),
                    admitted.signature.clone(),
                    admitted.map.clone(),
                ),
            };
            plan.rows.push(Row {
                account: self.accounts[*user].clone(),
                payments,
                signature,
            });
            plan.model.insert(*user, map);
        }

        // Assembly orders the rows itself.
        for index in (1..plan.rows.len()).rev() {
            let other = (self.rng().next_u64() % (index as u64 + 1)) as usize;
            plan.rows.swap(index, other);
        }
        plan
    }

    /// Returns the soft withdrawals the operator honored in the epoch being closed.
    fn withdrawals(&self) -> Vec<TestWithdrawal> {
        let closing = self.desk.closing.as_ref();
        let honored = closing.map_or(&self.desk.withdrawals, |closing| &closing.withdrawals);
        honored.values().cloned().collect()
    }

    /// Returns the operator's record of the epoch being closed: its admissions and the root each
    /// sender's states of it build on.
    fn closed(&self) -> (&BTreeMap<usize, Admitted>, &[Option<Digest>]) {
        match &self.desk.closing {
            Some(closing) => (&closing.admitted, &closing.previous),
            None => (&self.desk.admitted, &self.desk.previous),
        }
    }

    /// Returns the model's settlement of a close over `rows` and the prefix of `queue` its counts
    /// select, with honored `withdrawals`.
    fn settle_model(
        &self,
        rows: &BTreeMap<usize, Map>,
        withdrawals: &[TestWithdrawal],
        queue: &TestQueue,
        deposits: u64,
        forced: u64,
    ) -> Result<Effects, Refused> {
        let users = self.users();
        let mut sums = vec![[0u128; 3]; users];
        let mut touched = vec![false; users];
        let user = |account: &PublicKey| self.index(account).expect("a user");
        for (sender, map) in rows {
            touched[*sender] = true;
            for (receiver, amount) in map {
                sums[*receiver][0] += u128::from(*amount);
                sums[*sender][1] += u128::from(*amount);
                touched[*receiver] = true;
            }
        }
        for deposit in &queue.deposits[..deposits as usize] {
            let account = user(&deposit.account);
            sums[account][0] += u128::from(deposit.amount);
            touched[account] = true;
        }
        let forced = queue.forced_withdrawals[..forced as usize]
            .iter()
            .map(|forced| (&forced.account, forced.amount));
        let soft = withdrawals.iter().map(|soft| (&soft.account, soft.amount));
        for (account, amount) in forced.chain(soft) {
            let account = user(account);
            sums[account][2] += u128::from(amount);
            touched[account] = true;
        }
        let mut balances = self.model.balances.clone();
        let mut payouts = Vec::new();
        let mut order = Vec::new();
        for &account in &self.order {
            if !touched[account] {
                continue;
            }
            let settled = settle_sums(balances[account], sums[account])?;
            balances[account] = settled.balance;
            if settled.payout != 0 {
                payouts.push((account, settled.payout));
            }
            order.push(account);
        }
        Ok((balances, payouts, order))
    }

    /// Certifies `summary` with the attestations of `signers` validators.
    fn certify(
        &mut self,
        summary: &TestSummary,
        signers: usize,
    ) -> Result<U64, certificate::AssemblyError> {
        let start = (self.rng().next_u64() % u64::from(VALIDATORS)) as usize;
        let attestations: Vec<_> = (0..signers)
            .map(|offset| {
                self.schemes[(start + offset) % self.schemes.len()]
                    .sign::<Digest>(summary)
                    .expect("a validator signs")
            })
            .collect();
        let attestations = NonEmpty::try_new(attestations.into_iter()).expect("at least one");
        self.schemes[0].assemble(attestations, &Sequential)
    }

    /// Checks `close` as a validator against `queue` on the last post.
    fn check_close(
        &self,
        close: TestClose,
        parent: &TestCheckpoint,
        queue: &TestQueue,
    ) -> Result<TestChecked, CheckError> {
        close.check::<Sha256>(
            &self.namespace,
            &self.operator.public_key(),
            parent,
            queue,
            &Sequential,
        )
    }

    /// Assembles a close of `queue`'s epoch signed by `signer`.
    #[allow(clippy::type_complexity)]
    fn assemble(
        &self,
        signer: &PrivateKey,
        queue: &TestQueue,
        rows: Vec<TestRow>,
        withdrawals: Vec<TestWithdrawal>,
        deposits: u64,
        forced: u64,
    ) -> Result<(TestClose, TestFlows), AssemblyError> {
        TestClose::assemble::<Sha256, _>(
            signer,
            &self.namespace,
            queue,
            rows,
            withdrawals,
            deposits,
            forced,
            &Sequential,
        )
    }

    /// Returns the row `user` signs for `map` in `epoch` on top of `previous`.
    fn sign_row(&self, user: usize, epoch: Epoch, map: &Map, previous: Digest) -> TestRow {
        let payments = self.amounts(map);
        let state = State {
            epoch,
            account: self.accounts[user].clone(),
            payments: payments.root::<Sha256>(),
            previous,
        };
        Row {
            signature: self.keys[user].sign(&self.namespace.state, &state.encode()),
            account: self.accounts[user].clone(),
            payments,
        }
    }

    /// Returns a user with no row in the close of the epoch being closed, if any.
    fn idle(&self, choice: usize) -> Option<usize> {
        let (admitted, _) = self.closed();
        (0..self.users())
            .map(|offset| (choice + offset) % self.users())
            .find(|user| !admitted.contains_key(user))
    }

    /// Returns the root `user`'s states of the epoch being closed build on.
    fn closed_previous(&self, user: usize) -> Digest {
        self.closed().1[user].unwrap_or_else(empty_root)
    }

    /// Runs a deviation from the honest close that the protocol must refuse, and checks that it
    /// changes nothing.
    async fn attempt(
        &mut self,
        attack: CloseAttack,
        queue: &TestQueue,
        deposits: u64,
        forced: u64,
    ) {
        let before = self.snapshot();
        let epoch = queue.epoch;
        let admitted = self.closed().0.clone();
        let plan = self.rows(&admitted, &BTreeSet::new(), None);
        let withdrawals = self.withdrawals();
        let operator = self.operator.clone();
        let parent = self.parent.clone();
        let honest = |this: &Self| {
            this.assemble(
                &operator,
                queue,
                plan.rows.clone(),
                withdrawals.clone(),
                deposits,
                forced,
            )
            .expect("the honest close assembles")
            .0
        };
        match attack {
            CloseAttack::Count(deposit) => {
                let (deposits, forced) = if deposit {
                    let below = queue.required_deposits.checked_sub(1);
                    (below.unwrap_or(queue.deposits.len() + 1) as u64, forced)
                } else {
                    (deposits, queue.forced_withdrawals.len() as u64 + 1)
                };
                assert!(queue.prefix(deposits, forced).is_none());
                let assembled =
                    self.assemble(&operator, queue, plan.rows, withdrawals, deposits, forced);
                assert!(matches!(assembled, Err(AssemblyError::InvalidCount)));
                let close = close_bytes(
                    epoch,
                    &[],
                    &[],
                    deposits,
                    forced,
                    &operator.sign(
                        &self.namespace.close,
                        &close_message(
                            epoch,
                            &Matrix::<PublicKey, Sha256, u64>::empty().root(),
                            &[],
                            deposits,
                            forced,
                        ),
                    ),
                );
                let close = TestClose::decode_cfg(close, &LIMITS).expect("a canonical close");
                assert!(matches!(
                    self.check_close(close, &parent, queue),
                    Err(CheckError::InvalidCount)
                ));
            }
            CloseAttack::EmptyRow => {
                let mut rows = plan.rows;
                rows.push(Row {
                    account: self.rogue.public_key(),
                    payments: TestAmounts::default(),
                    signature: self.rogue.sign(b"row", b"row"),
                });
                let assembled =
                    self.assemble(&operator, queue, rows, withdrawals, deposits, forced);
                assert!(matches!(assembled, Err(AssemblyError::NoReceivers)));
            }
            CloseAttack::StaleWithdrawal(next) => {
                let stale = if next { epoch + 1 } else { epoch - 1 };
                let request = TestWithdrawal::sign(&self.keys[0], &self.namespace, stale, 1, 0);
                assert!(request.verify(&self.namespace));
                let close = honest(self);
                let mut withdrawals = withdrawals;
                withdrawals.push(request.clone());
                let assembled =
                    self.assemble(&operator, queue, plan.rows, withdrawals, deposits, forced);
                assert!(matches!(
                    assembled,
                    Err(AssemblyError::WrongEpoch { expected, found }) if expected == epoch && found == stale
                ));

                // A faulty operator signs the close without assembly, and validators refuse it.
                // Requests order by epoch first.
                let mut withdrawals = close.withdrawals().to_vec();
                withdrawals.truncate(LIMITS.withdrawals - 1);
                withdrawals.insert(if next { withdrawals.len() } else { 0 }, request);
                let matrix = close.matrix::<Sha256>(&Sequential).root();
                let message = close_message(epoch, &matrix, &withdrawals, deposits, forced);
                let bytes = close_bytes(
                    epoch,
                    close.rows(),
                    &withdrawals,
                    deposits,
                    forced,
                    &operator.sign(&self.namespace.close, &message),
                );
                let close = TestClose::decode_cfg(bytes, &LIMITS).expect("a canonical close");
                assert!(matches!(
                    self.check_close(close, &parent, queue),
                    Err(CheckError::WrongEpoch { expected, found }) if expected == epoch && found == stale
                ));
            }
            CloseAttack::Duplicate(row) => {
                let (mut rows, mut withdrawals) = (plan.rows, withdrawals);
                if row {
                    // Two rows of one account, however their maps compare.
                    let duplicate = rows.first().cloned().unwrap_or_else(|| {
                        self.sign_row(0, epoch, &Map::from([(0, 1)]), self.closed_previous(0))
                    });
                    let mut second = duplicate.clone();
                    second.payments = self.amounts(&Map::from([(self.other(0), u64::MAX)]));
                    rows.extend([duplicate, second]);
                } else {
                    let duplicate = withdrawals.first().cloned().unwrap_or_else(|| {
                        TestWithdrawal::sign(&self.keys[0], &self.namespace, epoch, 1, 0)
                    });
                    let resigned = Withdrawal {
                        signature: self.rogue.sign(b"other", b"other"),
                        ..duplicate.clone()
                    };
                    withdrawals.extend([duplicate, resigned]);
                }
                let assembled =
                    self.assemble(&operator, queue, rows, withdrawals, deposits, forced);
                assert!(matches!(assembled, Err(AssemblyError::Duplicate)));
            }
            CloseAttack::WrongSigner => {
                let rogue = self.rogue.clone();
                let (close, _) = self
                    .assemble(&rogue, queue, plan.rows, withdrawals, deposits, forced)
                    .expect("assembly checks no signature");
                assert!(matches!(
                    self.check_close(close, &parent, queue),
                    Err(CheckError::InvalidOperatorSignature)
                ));
            }
            CloseAttack::Tampered(kind) => {
                let close = honest(self);
                let rows = close.rows().to_vec();
                let mut withdrawals = close.withdrawals().to_vec();
                let (mut deposits, mut forced) = (close.deposits(), close.forced_withdrawals());
                let mut rows = rows;
                let mut epoch = close.epoch();
                let mut expected = "signature";
                match kind % 4 {
                    0 if queue.deposits.len() > queue.required_deposits => {
                        deposits = if deposits as usize == queue.deposits.len() {
                            deposits - 1
                        } else {
                            deposits + 1
                        };
                    }
                    1 if !withdrawals.is_empty() => {
                        withdrawals.pop();
                    }
                    2 if !rows.is_empty() => {
                        rows.pop();
                    }
                    3 => {
                        forced = queue.forced_withdrawals.len() as u64 + 1;
                        expected = "count";
                    }
                    _ => {
                        epoch += 1;
                        expected = "epoch";
                    }
                }
                let bytes = close_bytes(
                    epoch,
                    &rows,
                    &withdrawals,
                    deposits,
                    forced,
                    close.signature(),
                );
                let tampered = TestClose::decode_cfg(bytes, &LIMITS).expect("a canonical close");
                let checked = self.check_close(tampered, &parent, queue);
                match expected {
                    "count" => assert!(matches!(checked, Err(CheckError::InvalidCount))),
                    "epoch" => assert!(matches!(checked, Err(CheckError::WrongEpoch { .. }))),
                    _ => assert!(matches!(checked, Err(CheckError::InvalidOperatorSignature))),
                }
            }
            CloseAttack::WrongEpoch(next) => {
                let (close, found) = match self.history.last() {
                    Some(posted) if !next => (posted.close.clone(), epoch - 1),
                    _ => {
                        let later = Queue {
                            epoch: epoch + 1,
                            ..queue.clone()
                        };
                        let (close, _) = self
                            .assemble(&operator, &later, plan.rows, Vec::new(), deposits, forced)
                            .expect("assembly checks no epoch but the withdrawals'");
                        (close, epoch + 1)
                    }
                };
                assert!(matches!(
                    self.check_close(close, &parent, queue),
                    Err(CheckError::WrongEpoch { expected, found: actual }) if expected == epoch && actual == found
                ));
            }
            CloseAttack::StaleQueue(next) => {
                let close = honest(self);
                let stale = if next || epoch < 2 {
                    epoch + 1
                } else {
                    epoch - 1
                };
                let stale = Queue {
                    epoch: stale,
                    ..queue.clone()
                };
                assert!(matches!(
                    self.check_close(close, &parent, &stale),
                    Err(CheckError::WrongEpoch { expected, found }) if expected == epoch && found == stale.epoch
                ));
            }
            CloseAttack::ForeignRow(kind) => {
                let mut rows = plan.rows;
                let users = self.users();
                let posted = (0..users)
                    .map(|offset| (usize::from(kind) + offset) % users)
                    .find(|user| parent.matrix.payments_root(&self.accounts[*user]).is_some())
                    .filter(|_| kind % 4 == 3);
                let user = posted.or_else(|| self.idle(usize::from(kind))).unwrap_or(0);
                rows.retain(|row| row.account != self.accounts[user]);
                let map = Map::from([(self.other(user), 1)]);
                let previous = self.closed_previous(user);
                let row = match (kind % 4, posted) {
                    // Signed on the empty root by a sender whose posted row is not empty.
                    (3, Some(_)) => self.sign_row(user, epoch, &map, empty_root()),
                    // Signed for another map than the row carries.
                    (1, _) => {
                        let mut row = self.sign_row(user, epoch, &map, previous);
                        row.payments = self.amounts(&Map::from([(self.other(user), 2)]));
                        row
                    }
                    // Signed for the previous epoch.
                    (2, _) => self.sign_row(user, epoch.saturating_sub(1), &map, previous),
                    // Signed on a root other than its posted row.
                    _ => self.sign_row(user, epoch, &map, Sha256::hash(&[b"elsewhere"])),
                };
                rows.push(row);
                let (close, _) = self
                    .assemble(&operator, queue, rows, withdrawals, deposits, forced)
                    .expect("assembly checks no row signature");
                assert!(matches!(
                    self.check_close(close, &parent, queue),
                    Err(CheckError::InvalidSignature)
                ));
            }
            CloseAttack::ForgedWithdrawal(kind) => {
                let mut withdrawals = withdrawals;
                let tag = u64::MAX;
                let sign = |epoch, amount| {
                    TestWithdrawal::sign(&self.keys[0], &self.namespace, epoch, amount, tag)
                };
                let forged = match kind % 4 {
                    0 => sign(epoch, 0),
                    1 => Withdrawal {
                        amount: 6,
                        ..sign(epoch, 5)
                    },
                    // Signed for the next epoch or the one before, and naming this one.
                    2 => Withdrawal {
                        epoch,
                        ..sign(epoch + 1, 5)
                    },
                    _ => Withdrawal {
                        epoch,
                        ..sign(epoch - 1, 5)
                    },
                };
                assert!(!forged.verify(&self.namespace));
                withdrawals.push(forged);
                let (close, _) = self
                    .assemble(&operator, queue, plan.rows, withdrawals, deposits, forced)
                    .expect("assembly checks no withdrawal signature");
                assert!(matches!(
                    self.check_close(close, &parent, queue),
                    Err(CheckError::InvalidSignature)
                ));
            }
            CloseAttack::Checkpoint(mismatch) => {
                let close = honest(self);
                if mismatch {
                    // A checkpoint whose matrix is not its summary's.
                    let row =
                        self.sign_row(0, epoch, &Map::from([(0, 1)]), self.closed_previous(0));
                    let (other, _) = self
                        .assemble(&operator, queue, vec![row], Vec::new(), deposits, forced)
                        .expect("one row assembles");
                    let matrix = if parent.matrix.is_empty() {
                        other.matrix::<Sha256>(&Sequential)
                    } else {
                        Matrix::empty()
                    };
                    let mismatched = Checkpoint {
                        summary: parent.summary,
                        matrix,
                    };
                    assert!(matches!(
                        self.check_close(close, &mismatched, queue),
                        Err(CheckError::InvalidCheckpoint)
                    ));
                } else {
                    let last = Checkpoint {
                        summary: Summary {
                            epoch: Epoch::MAX,
                            ..parent.summary
                        },
                        matrix: parent.matrix.clone(),
                    };
                    assert!(matches!(
                        self.check_close(close, &last, queue),
                        Err(CheckError::Overflow)
                    ));
                }
            }
            CloseAttack::Overdraft => {
                // A sender with no countersigned state signs a row paying more than it holds.
                let Some(user) = self.idle(0) else {
                    return;
                };
                let Some(map) = self.overspend(user, self.desk.balances[user]) else {
                    return;
                };
                let mut rows = plan.rows;
                rows.push(self.sign_row(user, epoch, &map, self.closed_previous(user)));
                let mut model = plan.model;
                model.insert(user, map);
                let predicted = self.settle_model(&model, &withdrawals, queue, deposits, forced);
                let (close, flows) = self
                    .assemble(&operator, queue, rows, withdrawals, deposits, forced)
                    .expect("a signed row assembles");
                let checked = self
                    .check_close(close.clone(), &parent, queue)
                    .expect("a signed row checks");
                let store = self.store();
                let settled = checked.settle(&store.balances, &store.log).await;
                match (settled, predicted) {
                    (Err(SettleError::Flow(error)), Err(refused)) => {
                        assert!(refused.matches(&error))
                    }
                    // Credits in the same close can cover the row, and then the close settles
                    // exactly as the model does.
                    (Ok(proposal), Ok(effects)) => {
                        self.check_flows(&flows, epoch, &effects);
                        self.check_proposal(&proposal, &close, queue, deposits, forced, &effects)
                            .await;
                    }
                    (settled, predicted) => panic!(
                        "overdraft settled as {:?} where the model expects {predicted:?}",
                        settled.map(|proposal| *proposal.summary())
                    ),
                }
            }
            CloseAttack::ForgedQueue(user) => {
                // Validators read a deposit the ledger never took, and the ledger refuses the
                // count the certified summary processes.
                let user = self.user(user);
                let mut forged = queue.clone();
                forged.deposits.push(Deposit {
                    account: self.accounts[user].clone(),
                    amount: u64::MAX,
                });
                let deposits = forged.deposits.len() as u64;
                let predicted =
                    self.settle_model(&plan.model, &withdrawals, &forged, deposits, forced);
                let (close, flows) = self
                    .assemble(&operator, &forged, plan.rows, withdrawals, deposits, forced)
                    .expect("the forged queue assembles");
                let checked = self
                    .check_close(close.clone(), &parent, &forged)
                    .expect("validators check against the queue they read");
                let store = self.store();
                let settled = checked.settle(&store.balances, &store.log).await;
                match (settled, predicted) {
                    (Err(SettleError::Flow(error)), Err(refused)) => {
                        assert!(refused.matches(&error))
                    }
                    (Ok(proposal), Ok(effects)) => {
                        // The validator settles the forged deposit exactly as the model does.
                        self.check_flows(&flows, epoch, &effects);
                        self.check_proposal(&proposal, &close, &forged, deposits, forced, &effects)
                            .await;
                        let summary = *proposal.summary();
                        assert_eq!(summary.deposits.count, deposits);
                        let certificate =
                            self.certify(&summary, QUORUM).expect("a quorum certifies");
                        let posted = self.ledger.post(
                            self.context.as_mut().expect("the process is up"),
                            &self.verifier,
                            &summary,
                            &certificate,
                        );
                        match posted {
                            Err(Refusal::Halted) => assert!(before.ledger.halt.is_some()),
                            Err(Refusal::Summary(SummaryError::InvalidCount)) => {}
                            posted => panic!("a forged queue posted as {posted:?}"),
                        }
                    }
                    (settled, predicted) => panic!(
                        "a forged queue settled as {:?} where the model expects {predicted:?}",
                        settled.map(|proposal| *proposal.summary())
                    ),
                }
            }
            CloseAttack::StaleChecked => {
                if let Some(stale) = &self.stale {
                    let store = self.store();
                    assert!(matches!(
                        stale.settle(&store.balances, &store.log).await,
                        Err(SettleError::InvalidCheckpoint)
                    ));
                }
            }
            CloseAttack::Limits(kind) => {
                // V7: validators decode a close only within their limits.
                let close = honest(self);
                let encoded = close.encode();
                let receivers = close
                    .rows()
                    .iter()
                    .map(|row| row.payments.len())
                    .max()
                    .unwrap_or(0);
                let exact = Limits {
                    rows: close.rows().len(),
                    receivers,
                    withdrawals: close.withdrawals().len(),
                };
                assert_eq!(
                    TestClose::decode_cfg(encoded.clone(), &exact).ok(),
                    Some(close)
                );
                let below = match kind % 3 {
                    0 if exact.rows > 0 => Limits {
                        rows: exact.rows - 1,
                        ..exact
                    },
                    1 if exact.receivers > 0 => Limits {
                        receivers: exact.receivers - 1,
                        ..exact
                    },
                    2 if exact.withdrawals > 0 => Limits {
                        withdrawals: exact.withdrawals - 1,
                        ..exact
                    },
                    _ => return,
                };
                assert!(TestClose::decode_cfg(encoded, &below).is_err());
            }
            CloseAttack::Sibling
            | CloseAttack::Replay
            | CloseAttack::Certificate(_)
            | CloseAttack::Omit(_)
            | CloseAttack::Crash(_) => unreachable!("handled in the honest close"),
        }

        // I10: the refused deviation changed nothing.
        assert_eq!(self.snapshot(), before);
    }

    /// Posts a deviation from the honest summary before it, and checks that the ledger refuses
    /// it with the documented error and changes nothing.
    fn attempt_post(&mut self, summary: &TestSummary, kind: u8) {
        let before = self.snapshot();
        let halted = self.ledger.halt.is_some();
        let (posted, expected) = match kind % 8 {
            0 => {
                // Fewer attestations than a quorum assemble no certificate.
                let signers = 1 + usize::from(kind / 8) % (QUORUM - 1);
                assert!(self.certify(summary, signers).is_err());
                return;
            }
            1 => {
                let forged = U64::new(u64::MAX - u64::from(kind));
                (*summary, (forged, "certificate"))
            }
            2 => {
                // The certificate covers another summary.
                let other = Summary {
                    balances: Sha256::hash(&[b"other"]),
                    ..*summary
                };
                let certificate = self.certify(&other, QUORUM).expect("a quorum certifies");
                (*summary, (certificate, "certificate"))
            }
            3 => {
                let certificate = self.certify(summary, QUORUM).expect("a quorum certifies");
                let mut tampered = *summary;
                match kind / 8 % 4 {
                    0 => tampered.balances = Sha256::hash(&[b"balances"]),
                    1 => tampered.matrix = Sha256::hash(&[b"matrix"]),
                    2 => tampered.payouts.size += 1,
                    _ => tampered.deposits.hash = Sha256::hash(&[b"deposits"]),
                }
                (tampered, (certificate, "certificate"))
            }
            4 => {
                let certificate = self.certify(summary, QUORUM).expect("a quorum certifies");
                let tampered = Summary {
                    parent: Sha256::hash(&[b"parent"]),
                    ..*summary
                };
                (tampered, (certificate, "parent"))
            }
            5 => {
                let certificate = self.certify(summary, QUORUM).expect("a quorum certifies");
                let tampered = Summary {
                    epoch: summary.epoch + 1,
                    ..*summary
                };
                (tampered, (certificate, "epoch"))
            }
            6 => {
                let certificate = self.certify(summary, QUORUM).expect("a quorum certifies");
                let mut tampered = *summary;
                let ledger = &self.ledger;
                let deposits = (kind / 8).is_multiple_of(2);
                let (required, queued) = if deposits {
                    (ledger.required_deposits, ledger.deposits.len())
                } else {
                    (ledger.required_forced, ledger.forced.len())
                };

                // One below the required count where the queue has one, else one past its length.
                let count = match required.checked_sub(1) {
                    Some(below) if (kind / 16).is_multiple_of(2) => below,
                    _ => queued + 1,
                } as u64;
                if deposits {
                    tampered.deposits.count = count;
                } else {
                    tampered.forced_withdrawals.count = count;
                }
                (tampered, (certificate, "count"))
            }
            _ => match self.history.last() {
                Some(posted) => (posted.summary, (posted.certificate.clone(), "epoch")),
                None => (self.parent.summary, (U64::new(u64::MAX), "epoch")),
            },
        };
        let (certificate, expected) = expected;
        let result = self.ledger.post(
            self.context.as_mut().expect("the process is up"),
            &self.verifier,
            &posted,
            &certificate,
        );
        match result {
            Err(Refusal::Halted) => assert!(halted),
            Err(Refusal::Summary(error)) => {
                assert!(!halted);
                let matched = match expected {
                    "certificate" => matches!(error, SummaryError::InvalidCertificate),
                    "parent" => matches!(error, SummaryError::WrongParent),
                    "count" => matches!(error, SummaryError::InvalidCount),
                    _ => matches!(error, SummaryError::WrongEpoch { .. }),
                };
                assert!(matched, "post refused as {error:?}, expected {expected}");
            }
            result => panic!("a deviating post returned {result:?}"),
        }
        assert_eq!(self.snapshot(), before);
    }

    /// The operator cuts the epoch the ledger expects, unless it already released its close (O8).
    /// It fixes the epoch's rows, soft withdrawals and processed counts by setting its records of
    /// the epoch aside, settles each flow on its own balances as validators will, and releases only
    /// a close that settles. It then opens the next epoch against what the close may take (O3, O7).
    async fn cut(&mut self, deposits: u8, forced: u8, omit: Option<u8>) {
        if self.desk.closing.is_some() {
            return;
        }
        let queue = self.ledger.queue();
        let epoch = queue.epoch;
        assert_eq!(self.desk.epoch, epoch);
        let deposits = pick(queue.required_deposits, queue.deposits.len(), deposits);
        let forced = pick(
            queue.required_forced_withdrawals,
            queue.forced_withdrawals.len(),
            forced,
        );
        assert!(queue.prefix(deposits, forced).is_some());

        // A faulty operator omits a countersigned row, or settles an earlier map of it.
        let mut skip = BTreeSet::new();
        let mut earlier = None;
        if let Some(choice) = omit
            && !self.desk.admitted.is_empty()
        {
            let user = *self
                .desk
                .admitted
                .keys()
                .nth(usize::from(choice) % self.desk.admitted.len())
                .expect("in range");
            if choice >= 128 && !self.desk.admitted[&user].earlier.is_empty() {
                earlier = Some(user);
            } else {
                skip.insert(user);
            }
        }
        let withdrawals = self.withdrawals();
        let admitted = self.desk.admitted.clone();
        let (plan, close, flows) = loop {
            let plan = self.rows(&admitted, &skip, earlier);
            let (close, flows) = self
                .assemble(
                    &self.operator.clone(),
                    &queue,
                    plan.rows.clone(),
                    withdrawals.clone(),
                    deposits,
                    forced,
                )
                .expect("the honest close assembles");
            self.inspect(&close, &plan, &withdrawals, deposits, forced);
            let predicted = self.settle_model(&plan.model, &withdrawals, &queue, deposits, forced);
            let settles = flows.iter().all(|(account, flow)| {
                let user = self.index(account).expect("a user");
                flow.settle(self.desk.balances[user]).is_ok()
            });
            assert_eq!(settles, predicted.is_ok());
            let Err(refused) = predicted else {
                break (plan, close, flows);
            };

            // O3: a faulty admission leaves no acceptable close with every countersigned row, as
            // its sender goes below zero or its receiver past the largest amount, whichever comes
            // first in account order. Validators refuse the close as the model does, and the
            // operator drops those rows and assembles again.
            let checked = self
                .check_close(close, &self.parent.clone(), &queue)
                .expect("the honest close checks");
            let store = self.store();
            match checked.settle(&store.balances, &store.log).await {
                Err(SettleError::Flow(error)) if refused.matches(&error) => {}
                settled => panic!(
                    "the close settled as {:?} where the model expects {refused:?}",
                    settled.map(|proposal| *proposal.summary())
                ),
            }
            assert!(!self.desk.overdrawn.is_subset(&skip));
            skip.extend(self.desk.overdrawn.iter().copied());
        };

        // O3: the close may take each account's payments in it and the soft and forced withdrawals
        // it processes. The next epoch's states build on its rows (O4).
        let mut take = vec![0u128; self.users()];
        for (user, map) in &plan.model {
            take[*user] += total(map);
        }
        let soft = withdrawals.iter().map(|soft| (&soft.account, soft.amount));
        let forced_withdrawals = &queue.forced_withdrawals[..forced as usize];
        let forced_withdrawals = forced_withdrawals.iter().map(|w| (&w.account, w.amount));
        for (account, amount) in soft.chain(forced_withdrawals) {
            take[self.index(account).expect("a user")] += u128::from(amount);
        }
        let matrix = close.matrix::<Sha256>(&Sequential);
        let previous = self
            .accounts
            .iter()
            .map(|account| matrix.payments_root(account))
            .collect();
        let desk = &mut self.desk;
        desk.closing = Some(Closing {
            queue,
            deposits,
            forced,
            previous: std::mem::replace(&mut desk.previous, previous),
            admitted: std::mem::take(&mut desk.admitted),
            withdrawals: std::mem::take(&mut desk.withdrawals),
            overdrawn: std::mem::take(&mut desk.overdrawn),
            close,
            flows,
            rows: plan.model,
            omitted: plan.omitted,
            take,
        });
        desk.epoch = epoch + 1;
    }

    async fn close(&mut self, deposits: u8, forced: u8, attack: Option<CloseAttack>) {
        let omit = match attack {
            Some(CloseAttack::Omit(choice)) => Some(choice),
            _ => None,
        };
        self.cut(deposits, forced, omit).await;
        let closing = self.desk.closing.clone().expect("a released close");
        let (deposits, forced) = (closing.deposits, closing.forced);

        // V3: validators read the queues as the ledger holds them now. They grew only at their
        // tails since the cut, so the close processes the same requests. A halt since the cut
        // dropped them, and the ledger expects no close, so validators keep what they read before.
        let queue = if self.ledger.halt.is_some() {
            closing.queue.clone()
        } else {
            self.ledger.queue()
        };
        let epoch = queue.epoch;
        assert_eq!(closing.close.epoch(), epoch);
        assert_eq!(
            queue.prefix(deposits, forced),
            closing.queue.prefix(deposits, forced)
        );
        if let Some(attack) = attack
            && !matches!(
                attack,
                CloseAttack::Sibling
                    | CloseAttack::Replay
                    | CloseAttack::Certificate(_)
                    | CloseAttack::Omit(_)
                    | CloseAttack::Crash(_)
            )
        {
            self.attempt(attack, &queue, deposits, forced).await;
        }

        // I3, I7: the released close checks and settles as the model says.
        let withdrawals = self.withdrawals();
        let close = closing.close.clone();
        let checked = self
            .check_close(close.clone(), &self.parent.clone(), &queue)
            .expect("the released close checks");
        let effects = self
            .settle_model(&closing.rows, &withdrawals, &queue, deposits, forced)
            .expect("the operator releases only a close that settles");
        let store = self.store();
        let proposal = checked
            .settle(&store.balances, &store.log)
            .await
            .expect("the released close settles");
        self.check_flows(&closing.flows, epoch, &effects);
        self.check_proposal(&proposal, &close, &queue, deposits, forced, &effects)
            .await;
        let summary = *proposal.summary();

        // A sibling close the ledger does not post, and a second settlement for a replay.
        let sibling = match attack {
            Some(CloseAttack::Sibling) => {
                let (sibling, _) = self
                    .assemble(
                        &self.operator.clone(),
                        &queue,
                        Vec::new(),
                        Vec::new(),
                        queue.required_deposits as u64,
                        queue.required_forced_withdrawals as u64,
                    )
                    .expect("an empty close assembles");
                let checked = self
                    .check_close(sibling, &self.parent.clone(), &queue)
                    .expect("an empty close checks");
                let store = self.store();
                Some(
                    checked
                        .settle(&store.balances, &store.log)
                        .await
                        .expect("an empty close settles"),
                )
            }
            Some(CloseAttack::Replay) => {
                let store = self.store();
                let again = checked
                    .settle(&store.balances, &store.log)
                    .await
                    .expect("settling again settles");
                assert_eq!(again.summary(), proposal.summary());
                assert_eq!(again.payouts(), proposal.payouts());
                Some(again)
            }
            _ => None,
        };

        // Deviating posts are refused before the honest one.
        if let Some(CloseAttack::Certificate(kind)) = attack {
            self.attempt_post(&summary, kind);
        }

        // The committee certifies the summary, and the ledger posts it unless it halted.
        let signers = QUORUM + (self.rng().next_u64() % 2) as usize;
        let certificate = self.certify(&summary, signers).expect("a quorum certifies");
        let halted = self.ledger.halt.is_some();
        let posted = self.ledger.post(
            self.context.as_mut().expect("the process is up"),
            &self.verifier,
            &summary,
            &certificate,
        );
        match posted {
            Ok(()) => assert!(!halted),
            Err(Refusal::Halted) => {
                assert!(halted);
                return;
            }
            Err(refusal) => panic!("an honest post refused as {refusal:?}"),
        }
        let digest = summary.digest();

        // V4: the validator persisted the close, the queue prefix it processes and its summary
        // before attesting, which is all it needs to apply the close again. `history` stands for
        // that durable record, which no crash here reaches.
        let (processed, processed_forced) = queue.prefix(deposits, forced).expect("in bounds");
        let prefix = Queue {
            epoch,
            deposits: processed.to_vec(),
            required_deposits: processed.len(),
            forced_withdrawals: processed_forced.to_vec(),
            required_forced_withdrawals: processed_forced.len(),
        };
        let posted = Posted {
            summary,
            certificate,
            checkpoint: Checkpoint {
                summary,
                matrix: close.matrix::<Sha256>(&Sequential),
            },
            close,
            queue,
            prefix,
            parent: self.parent.clone(),
            rows: closing.rows.clone(),
            omitted: closing.omitted.clone(),
            unsettled: closing
                .admitted
                .iter()
                .filter(|(user, latest)| closing.rows.get(user) != Some(&latest.map))
                .map(|(user, latest)| (*user, latest.state.clone()))
                .collect(),
        };
        self.unaudited.push_back(self.history.len());
        self.history.push(posted.clone());

        // The model, its shadow databases and the operator apply the post, which lifts the close's
        // deductions (O3).
        let (settled, payouts, _) = effects;
        let before = std::mem::replace(&mut self.model.balances, settled.clone());
        let accounts = self.accounts.clone();
        let shadow = self.shadow.as_mut().expect("open");
        let roots = shadow
            .settle(&accounts, &before, &settled, &payouts, true)
            .await;
        assert_eq!(roots, (summary.balances, summary.payouts.root));
        for (user, amount) in &payouts {
            self.model.log.push(Some((*user, *amount)));
        }
        self.model.log.push(None);
        self.model.deposits_hash = summary.deposits.hash;
        self.model.forced_hash = summary.forced_withdrawals.hash;
        for (account, flow) in &closing.flows {
            let user = self.index(account).expect("a user");
            let settled = flow.settle(self.desk.balances[user]).expect("settles");
            self.desk.balances[user] = settled.balance;
        }
        let rows: Vec<_> = accounts
            .iter()
            .map(|account| posted.checkpoint.matrix.payments_root(account))
            .collect();
        assert_eq!(self.desk.previous, rows);
        self.desk.closing = None;

        // I3: the close leaves each balance at or above what the next epoch admitted against it,
        // unless a faulty operator admitted past it.
        for user in 0..self.users() {
            if !self.desk.overdrawn.contains(&user) {
                assert!(self.paid(user) <= u128::from(self.desk.balances[user]));
            }
        }
        self.stale = Some(checked);

        // V5: the validator applies the posted close and no other.
        let (proposal, replay) = match sibling {
            Some(sibling) if matches!(attack, Some(CloseAttack::Sibling)) => {
                if sibling.summary() == &summary {
                    (sibling, Some(proposal))
                } else {
                    self.apply_refused(sibling, &digest).await;
                    (proposal, None)
                }
            }
            other => (proposal, other),
        };
        let crash = match attack {
            Some(CloseAttack::Crash(kind)) => Some(kind % 3),
            _ => None,
        };
        if !self.apply(proposal, &digest, crash).await {
            return;
        }
        assert_eq!(self.parent.summary, summary);
        assert_eq!(self.parent.matrix.root(), summary.matrix);
        if let Some(replay) = replay {
            self.apply_refused(replay, &digest).await;
        }
        let metadata = self
            .store()
            .balances
            .get_metadata()
            .await
            .expect("the balances database must read");
        assert_eq!(metadata, Some(0));
    }

    /// Applies the posted `proposal` and commits the balances (V5), or fails partway as `crash`
    /// says. Returns whether the process is still up: a failed write leaves it up to recover in
    /// place (V2), and a stop before the balances commit crashes it, losing every write not yet
    /// durable.
    async fn apply(&mut self, proposal: TestProposal, digest: &Digest, crash: Option<u8>) -> bool {
        let Store { balances, log } = self.store.take().expect("open");
        let faults = self.runtime().storage_fault_config();
        let failing = FaultConfig {
            sync_rate: Some(Probability::new(1, 1).expect("a probability")),
            ..Default::default()
        };
        match crash {
            None => {
                let (balances, log, checkpoint) = proposal
                    .apply(balances, log, digest)
                    .await
                    .expect("the posted close applies");
                let balances = balances.commit().await.expect("the balances commit");
                self.store = Some(Store { balances, log });
                self.parent = checkpoint;
                return true;
            }
            Some(0) => {
                // The payout log cannot be made durable, so apply fails before it writes to the
                // balances.
                *faults.write() = failing;
                let applied = proposal.apply(balances, log, digest).await;
                *faults.write() = FaultConfig::default();
                assert!(matches!(applied, Err(ApplyError::Log(_))));
            }
            Some(1) => {
                // The process stops once the payout log is durable, before the balances commit,
                // so the payout log is ahead of the balances when it comes back.
                let applied = proposal
                    .apply(balances, log, digest)
                    .await
                    .expect("the posted close applies");
                drop(applied);
                self.crashed = true;
                return false;
            }
            Some(_) => {
                // The balances cannot commit once the payout log is durable.
                let (balances, log, _) = proposal
                    .apply(balances, log, digest)
                    .await
                    .expect("the posted close applies");
                *faults.write() = failing;
                let committed = balances.commit().await;
                *faults.write() = FaultConfig::default();
                assert!(committed.is_err());
                drop(log);
            }
        }
        self.recover().await;
        true
    }

    /// Reopens the validator's databases as after a crash and brings them to the ledger's last
    /// post from what it persisted (V2, V4, V5): the balances at their last commit, the payout log
    /// rewound to the payouts size of the post those balances hold, and every later post applied
    /// again from its persisted close and queue prefix. The persisted records are `history`,
    /// held as durable.
    async fn recover(&mut self) {
        let balances = Store::open_balances(self.runtime(), "balances").await;
        let root = balances.root();

        // V2: the persisted summary on the chain ending at the ledger's last digest whose balances
        // root is the database's, or the genesis summary for a database that holds no close.
        let last = self
            .history
            .last()
            .map_or(self.ledger.last, |posted| posted.summary.digest());
        assert_eq!(last, self.ledger.last);
        let found = self
            .history
            .iter()
            .rposition(|posted| posted.summary.balances == root);
        let (start, mut parent) = match found {
            Some(index) => {
                let posted = &self.history[index];
                let checkpoint = Checkpoint {
                    summary: posted.summary,
                    matrix: posted.close.matrix::<Sha256>(&Sequential),
                };
                (index + 1, checkpoint)
            }
            None => {
                let metadata = balances
                    .get_metadata()
                    .await
                    .expect("the balances database must read");
                assert_eq!(metadata, None, "the balances hold a close no post holds");
                let genesis = TestSummary::genesis::<PublicKey, u64>(root);
                let first = self
                    .history
                    .first()
                    .map_or(self.ledger.last, |posted| posted.summary.parent);
                assert_eq!(genesis.digest(), first);
                let checkpoint = Checkpoint {
                    summary: genesis,
                    matrix: Matrix::empty(),
                };
                (0, checkpoint)
            }
        };
        let size = parent.summary.payouts.size;
        self.verified = self.verified.min(*size as usize);
        let log = Store::open_log(self.runtime(), "payouts", Some(size)).await;
        assert_eq!(log.bounds().end, parent.summary.payouts.size);
        assert_eq!(log.root(), parent.summary.payouts.root);
        let mut store = Store { balances, log };

        // V5: every later post applies again, checked against exactly the prefix it processed.
        for index in start..self.history.len() {
            let posted = self.history[index].clone();
            let checked = self
                .check_close(posted.close.clone(), &parent, &posted.prefix)
                .expect("a persisted post checks again");
            let proposal = checked
                .settle(&store.balances, &store.log)
                .await
                .expect("a persisted post settles again");
            assert_eq!(*proposal.summary(), posted.summary);
            let (balances, log, checkpoint) = proposal
                .apply(store.balances, store.log, &posted.summary.digest())
                .await
                .expect("a persisted post applies again");
            let balances = balances.commit().await.expect("the balances commit");
            store = Store { balances, log };
            parent = checkpoint;
        }

        // I11: the validator is back at the ledger's last post.
        assert_eq!(parent.summary.digest(), self.ledger.last);
        assert_eq!(
            store.roots(),
            (self.ledger.balances, parent.summary.payouts.root)
        );
        self.parent = parent;
        self.store = Some(store);
    }

    /// I3: the flows assembly returns settle each touched account as the model does.
    fn check_flows(&self, flows: &TestFlows, epoch: Epoch, effects: &Effects) {
        let (balances, payouts, touched) = effects;
        assert_eq!(flows.len(), touched.len());
        for ((account, flow), user) in flows.iter().zip(touched) {
            assert_eq!(account, &self.accounts[*user]);
            assert_eq!(flow.epoch(), epoch);
            let (flow_epoch, sums) = flow_sums(flow);
            assert_eq!(flow_epoch, epoch);
            let settled = flow
                .settle(self.desk.balances[*user])
                .expect("a settling close settles each flow");
            assert_eq!(Ok(settled), settle_sums(self.desk.balances[*user], sums));
            assert_eq!(settled.balance, balances[*user]);
            let payout = payouts.iter().find(|(payee, _)| payee == user);
            assert_eq!(settled.payout, payout.map_or(0, |(_, amount)| *amount));
        }
    }

    /// I3, I7: a settled proposal chains to the last post and commits to the close's matrix, the
    /// model's payouts and payouts size, the prefix of `queue` the close processes, and the
    /// balances and payout log roots the shadow reaches with the model's `effects`.
    async fn check_proposal(
        &mut self,
        proposal: &TestProposal,
        close: &TestClose,
        queue: &TestQueue,
        deposits: u64,
        forced: u64,
        effects: &Effects,
    ) {
        let (balances, payouts, _) = effects;
        let summary = *proposal.summary();
        let accounts = self.accounts.clone();
        let before = self.model.balances.clone();
        let shadow = self.shadow.as_mut().expect("open");
        let roots = shadow
            .settle(&accounts, &before, balances, payouts, false)
            .await;
        assert_eq!(roots, (summary.balances, summary.payouts.root));
        let matrix = close.matrix::<Sha256>(&Sequential);
        let size = self.model.log.len() + payouts.len() + 1;
        assert_eq!(summary.epoch, close.epoch());
        assert_eq!(summary.parent, self.ledger.last);
        assert_eq!(summary.matrix, matrix.root());
        assert_eq!(proposal.matrix().root(), matrix.root());
        assert_eq!(*summary.payouts.size, size as u64);
        let expected = Processed {
            count: deposits,
            hash: chain(
                self.model.deposits_hash,
                &queue.deposits[..deposits as usize],
            ),
        };
        assert_eq!(summary.deposits, expected);
        let expected = Processed {
            count: forced,
            hash: chain(
                self.model.forced_hash,
                &queue.forced_withdrawals[..forced as usize],
            ),
        };
        assert_eq!(summary.forced_withdrawals, expected);
        let expected = payouts
            .iter()
            .map(|(user, amount)| (self.accounts[*user].clone(), *amount));
        let expected = TestAmounts::new(expected).expect("distinct payouts");
        assert_eq!(proposal.payouts(), &expected);
        for (position, (account, amount)) in expected.iter().enumerate() {
            assert_eq!(proposal.payouts().position(account), Some(position));
            assert_eq!(proposal.payouts().get(account), amount);
        }
        assert_eq!(proposal.payouts().total().is_some(), {
            payouts
                .iter()
                .try_fold(0u64, |total, (_, amount)| total.checked_add(*amount))
                .is_some()
        });
        roundtrip(&summary, &());
    }

    /// I3: the payout log ends with `expected` from index `start` on, each payout of a close in
    /// account order and then its commit.
    async fn check_entries(
        log: &TestLog,
        accounts: &[PublicKey],
        start: usize,
        expected: &[Option<(usize, u64)>],
    ) {
        assert_eq!(*log.bounds().end, (start + expected.len()) as u64);
        let Some(count) = NonZeroU64::new(expected.len() as u64) else {
            return;
        };
        let (_, operations) = log
            .proof(Location::new(start as u64), count)
            .await
            .expect("the payout log proves its operations");
        assert_eq!(operations.len(), expected.len());
        for (operation, entry) in operations.iter().zip(expected) {
            match (operation, entry) {
                (keyless::fixed::Operation::Append(payout), Some((user, amount))) => {
                    let expected = Payout {
                        account: accounts[*user].clone(),
                        amount: *amount,
                    };
                    assert_eq!(payout, &expected);
                }
                (keyless::fixed::Operation::Commit(None, floor), None) => assert_eq!(**floor, 0),
                (operation, entry) => {
                    panic!("the payout log holds {operation:?} where the model holds {entry:?}")
                }
            }
        }
    }

    /// Checks the close the operator assembled against the rows and withdrawals it holds.
    fn inspect(
        &self,
        close: &TestClose,
        plan: &Rows,
        withdrawals: &[TestWithdrawal],
        deposits: u64,
        forced: u64,
    ) {
        assert_eq!(close.epoch(), self.ledger.epoch());
        assert_eq!(close.deposits(), deposits);
        assert_eq!(close.forced_withdrawals(), forced);
        assert!(
            close
                .rows()
                .windows(2)
                .all(|pair| pair[0].account < pair[1].account)
        );
        let mut sorted = withdrawals.to_vec();
        sorted.sort_by(|a, b| a.request().cmp(&b.request()));
        assert_eq!(close.withdrawals(), sorted.as_slice());

        // The matrix holds each sender's settled map.
        let matrix = close.matrix::<Sha256>(&Sequential);
        assert_eq!(matrix.len(), plan.model.len());
        assert_eq!(matrix.is_empty(), plan.model.is_empty());
        for (account, payments) in matrix.iter() {
            let user = self.index(account).expect("a user");
            assert_eq!(self.map(payments), plan.model[&user]);
            assert_eq!(matrix.payments(account), Some(payments));
        }

        // The operator signs the documented bytes.
        let message = close_message(
            close.epoch(),
            &matrix.root(),
            close.withdrawals(),
            deposits,
            forced,
        );
        assert!(self.operator.public_key().verify(
            &self.namespace.close,
            &message,
            close.signature()
        ));

        // I12: validators decode the close under the deployment's limits.
        let encoded = close.encode();
        let within = close.rows().len() <= LIMITS.rows
            && close
                .rows()
                .iter()
                .all(|row| row.payments.len() <= LIMITS.receivers)
            && close.withdrawals().len() <= LIMITS.withdrawals;
        let decoded = TestClose::decode_cfg(encoded, &LIMITS);
        assert_eq!(decoded.is_ok(), within);
        if let Ok(decoded) = decoded {
            assert_eq!(&decoded, close);
        }
    }

    /// Applies `proposal`, which did not post as `digest`, and reopens the dropped databases.
    async fn apply_refused(&mut self, proposal: TestProposal, digest: &Digest) {
        let roots = self.store().roots();
        let Store { balances, log } = self.store.take().expect("open");
        assert!(matches!(
            proposal.apply(balances, log, digest).await,
            Err(ApplyError::InvalidCheckpoint)
        ));

        // I11: a refusal writes to neither database.
        let store = Store::open(self.runtime(), Some(self.parent.summary.payouts.size)).await;
        assert_eq!(store.roots(), roots);
        self.store = Some(store);
    }

    /// Receivers audit the oldest post not yet audited and challenge every receipt it credits
    /// short (R3), and senders learn their rows in it (S5).
    fn audit(&mut self) {
        let index = self.unaudited.pop_front().expect("a post to audit");
        let posted = self.history[index].clone();
        let omitted = &posted.omitted;
        let epoch = posted.summary.epoch;

        // A receiver can challenge an omission only with a receipt, which its sender issues once
        // it holds the acknowledgement of the state the close does not settle, before or after
        // the post, until it resolves the post below.
        let acked: BTreeSet<usize> = posted
            .unsettled
            .iter()
            .filter(|(user, state)| {
                let record = self.books[**user].records.get(&epoch);
                record.is_some_and(|record| record.state == **state)
            })
            .map(|(user, _)| *user)
            .collect();
        let matrix = &posted.checkpoint.matrix;
        let root = matrix.root();
        let credited = |sender: usize, receiver: usize| {
            posted
                .rows
                .get(&sender)
                .and_then(|map| map.get(&receiver))
                .copied()
                .unwrap_or(0)
        };

        // Every sender learns its row, and every pair opens to what the post credits it, with or
        // without a row or an entry.
        for sender in 0..self.users() {
            let account = &self.accounts[sender];
            for (receiver, paid) in self.accounts.iter().enumerate() {
                let opening = matrix.open(account, paid);
                roundtrip(&opening, &());
                let row = opening
                    .verify_row::<Sha256>(&root, account)
                    .expect("a served opening verifies");
                assert_eq!(row, matrix.payments_root(account));
                assert_eq!(row.is_some(), posted.rows.contains_key(&sender));
                let amount = opening
                    .verify::<Sha256>(&root, account, paid)
                    .expect("a served opening verifies");
                assert_eq!(amount, credited(sender, receiver));
                if receiver != sender {
                    continue;
                }

                // An entry present exactly when the row is absent does not verify.
                let mut mismatched = opening;
                mismatched.entry = match mismatched.entry {
                    Some(_) => None,
                    None => Some(Lookup::NonMember {
                        position: 0,
                        lower: None,
                        upper: None,
                        proof: Proof::default(),
                    }),
                };
                assert!(mismatched.verify_row::<Sha256>(&root, account).is_err());
            }
        }

        // S5: each sender resolves the post against the row it proves.
        for sender in 0..self.users() {
            let row = matrix.payments_root(&self.accounts[sender]);
            self.resolve(sender, epoch, row, omitted.contains(&sender));
        }

        // I9: an honest post credits each receipt in full, and a short one is challenged.
        let held: Vec<_> = self
            .receipts
            .range((epoch, 0, 0)..(epoch + 1, 0, 0))
            .map(|(key, receipt)| (*key, receipt.clone()))
            .collect();
        let mut contradicted = BTreeSet::new();
        let operator = self.operator.public_key();
        for (index, ((_, sender, receiver), receipt)) in held.into_iter().enumerate() {
            let (account, paid) = (&self.accounts[sender], &self.accounts[receiver]);
            let opening = matrix.open(account, paid);
            let amount = opening
                .verify::<Sha256>(&root, account, paid)
                .expect("a served opening verifies");
            assert_eq!(amount, credited(sender, receiver));

            // A challenge naming another epoch, or carrying a receipt inflated past what the post
            // credits, is refused whatever the post did. An opening of another receiver is
            // refused when the post pays this one, since a row's absence alone opens any
            // receiver.
            let verify = |challenge: &TestChallenge, epoch| {
                challenge.verify::<Sha256>(&self.namespace, &operator, epoch, &root)
            };
            let mut tampered = Challenge {
                receipt: receipt.clone(),
                opening: matrix.open(account, &self.rogue.public_key()),
            };
            if amount > 0 {
                assert!(matches!(
                    verify(&tampered, epoch),
                    Err(ChallengeError::InvalidOpening)
                ));
            }
            tampered.opening = opening.clone();
            assert!(matches!(
                verify(&tampered, epoch + 1),
                Err(ChallengeError::WrongEpoch { expected, found }) if expected == epoch + 1 && found == epoch
            ));
            if index == 0
                && let Some(inflated) = amount.checked_add(1)
            {
                tampered.receipt.amount = inflated.max(receipt.amount);
                if tampered.receipt.amount != receipt.amount {
                    assert!(matches!(
                        verify(&tampered, epoch),
                        Err(ChallengeError::InvalidReceipt)
                    ));
                }
            }
            let challenge = Challenge { receipt, opening };
            if amount >= challenge.receipt.amount {
                assert!(matches!(
                    challenge.verify::<Sha256>(&self.namespace, &operator, epoch, &root),
                    Err(ChallengeError::NoContradiction)
                ));
                continue;
            }
            assert!(
                omitted.contains(&sender),
                "an honest close credits receipts"
            );
            contradicted.insert(sender);
            roundtrip(&challenge, &());
            match self
                .ledger
                .challenge(&self.namespace, &operator, epoch, &challenge)
            {
                Ok(()) => assert_eq!(self.ledger.halt, Some(Halt::Challenge(epoch))),
                Err(Refusal::Halted) => {}
                Err(refusal) => panic!("a contradicting challenge refused as {refusal:?}"),
            }
        }
        assert!(contradicted.is_subset(omitted));
        assert!(
            acked.is_subset(&contradicted),
            "an omission went unchallenged"
        );
        if !contradicted.is_empty() {
            assert!(self.ledger.halt.is_some());
        }
    }

    /// `user` resolves the post of `epoch`, which proves `row` as its row (S5). Its pending
    /// request settled if one of its states of the epoch has the row's root, and is dropped once
    /// none of its states can settle. Unless the operator `omitted` its countersigned state, the
    /// close settled exactly the map the sender recorded for the epoch or had pending.
    fn resolve(&mut self, user: usize, epoch: Epoch, row: Option<Digest>, omitted: bool) {
        let root = row.unwrap_or_else(empty_root);
        let book = &mut self.books[user];
        let mut recorded = book
            .records
            .get(&epoch)
            .map_or_else(empty_root, |record| record.state.payments);
        if let Some(pending) = &book.pending {
            let first = pending.request.epoch;
            let settled = (first == epoch && pending.signed.current.payments == root)
                || (first + 1 == epoch && pending.signed.next.payments == root);
            if settled {
                recorded = root;
            }
            let next = first == epoch && pending.signed.next.previous == root;
            if settled || (first <= epoch && !next) {
                book.pending = None;
            }
        }

        // I9: an honest close settles what the sender holds, and its states of the next epoch
        // build on the row.
        if !omitted {
            assert_eq!(recorded, root, "the post of {epoch} settled another map");
        }
        if let Some(record) = book.records.get(&(epoch + 1)) {
            assert_eq!(record.state.previous, root);
        }
        book.records.retain(|recorded, _| *recorded > epoch);
        book.resolved = epoch;
        book.row = row;
    }

    async fn payout(&mut self, pick: u8, attack: Option<PayoutAttack>) {
        let payouts: Vec<_> = self
            .model
            .log
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| entry.map(|(user, amount)| (index as u64, user, amount)))
            .collect();
        if payouts.is_empty() {
            return;
        }
        let (index, user, amount) = payouts[usize::from(pick) % payouts.len()];
        let epoch = self.ledger.epoch() - 1;

        // V6: a validator proves the payout under the payouts root of the last close applied.
        let log = &self.store().log;
        let (proof, operations) = log
            .proof(Location::new(index), NZU64!(1))
            .await
            .expect("the payout log proves its operations");
        let payout = Payout {
            account: self.accounts[user].clone(),
            amount,
        };
        assert!(matches!(
            operations.as_slice(),
            [keyless::fixed::Operation::Append(logged)] if *logged == payout
        ));
        let logged = log.get(Location::new(index)).await.expect("the log reads");
        assert_eq!(logged.as_ref(), Some(&payout));
        let mut proof = PayoutProof {
            index: Location::new(index),
            payout,
            proof,
        };
        roundtrip(&proof, &());
        self.proofs.push_back((epoch, proof.clone()));
        if self.proofs.len() > MAX_PROOFS {
            self.proofs.pop_front();
        }
        let honest = proof.clone();
        let mut named = epoch;
        let mut forged = false;
        match attack {
            None | Some(PayoutAttack::Unposted) => {
                if attack.is_some() {
                    named = epoch + 1;
                }
            }
            Some(PayoutAttack::Replay) => self.withdraw_payout(epoch, &proof),
            Some(PayoutAttack::Amount) => {
                proof.payout.amount = amount.wrapping_add(1);
                forged = true;
            }
            Some(PayoutAttack::Account) => {
                proof.payout.account = self.accounts[self.other(user)].clone();
                forged = true;
            }
            Some(PayoutAttack::Commit) => {
                let commit = self.parent.summary.payouts.size - 1;
                let (opened, _) = self
                    .store()
                    .log
                    .proof(commit, NZU64!(1))
                    .await
                    .expect("the payout log proves its commits");
                proof.index = commit;
                proof.proof = opened;
                forged = true;
            }
            Some(PayoutAttack::OlderRoot) => {
                // An earlier root holds fewer operations, so no proof under the last one opens it.
                named = epoch - 1;
                forged = true;
            }
            Some(PayoutAttack::Stale) => {
                (named, proof) = self.proofs[usize::from(pick) % self.proofs.len()].clone();
            }
        }
        if !forged {
            self.withdraw_payout(named, &proof);

            // A withdrawal naming a close that did not post is refused, and the account then
            // withdraws as the validator served it.
            if let Some(PayoutAttack::Unposted) = attack {
                self.withdraw_payout(epoch, &honest);
            }
            return;
        }
        let before = self.snapshot();
        match self.ledger.withdraw(named, &proof) {
            Err(Refusal::InvalidProof) => assert!(named != 0 && named <= epoch),
            Err(Refusal::NotPosted) => assert!(named == 0 || named > epoch),
            result => panic!("a forged payout withdrawal returned {result:?}"),
        }
        assert_eq!(self.snapshot(), before);
        self.withdraw_payout(epoch, &honest);
    }

    /// Withdraws the payout `proof` proves under the posted root of `epoch`, which the ledger pays
    /// once.
    fn withdraw_payout(&mut self, epoch: Epoch, proof: &TestPayoutProof) {
        let before = self.snapshot();
        let index = *proof.index;
        let user = self.index(&proof.payout.account).expect("a user");
        let result = self.ledger.withdraw(epoch, proof);
        let posted = epoch != 0 && epoch < self.ledger.epoch();
        match result {
            Ok(amount) => {
                assert!(posted && !before.model.paid.contains(&index));
                assert_eq!(self.model.log[index as usize], Some((user, amount)));
                self.model.paid.insert(index);
                self.model.transferred += u128::from(amount);
            }
            Err(Refusal::Withdrawn) => {
                assert!(before.model.paid.contains(&index));
                assert_eq!(self.snapshot(), before);
            }
            Err(Refusal::NotPosted) => {
                assert!(!posted);
                assert_eq!(self.snapshot(), before);
            }
            result => panic!("a payout withdrawal returned {result:?}"),
        }
    }

    fn challenge(&mut self, pick: u8, attack: ChallengeAttack) {
        let epoch = self.ledger.epoch();
        let unposted = matches!(attack, ChallengeAttack::Unposted);
        let held: Vec<_> = self
            .receipts
            .iter()
            // Receipts of posted epochs, or of the epoch the ledger expects and those after it,
            // which a cut lets senders hold before the post.
            .filter(|((held, _, _), _)| named_posted(*held, epoch) != unposted)
            .map(|(key, receipt)| (*key, receipt.clone()))
            .collect();
        if held.is_empty() {
            return;
        }
        let ((held, sender, receiver), mut receipt) = held[usize::from(pick) % held.len()].clone();
        let before = self.snapshot();
        let halted = self.ledger.halt.is_some();
        let operator = self.operator.public_key();
        let (sender_key, receiver_key) = (&self.accounts[sender], &self.accounts[receiver]);
        let posted = self.history.get(held as usize - 1).cloned();
        let (matrix, credited, omitted) = match posted {
            Some(posted) => (
                posted.checkpoint.matrix,
                posted
                    .rows
                    .get(&sender)
                    .and_then(|map| map.get(&receiver))
                    .copied()
                    .unwrap_or(0),
                posted.omitted.contains(&sender),
            ),
            None => (self.parent.matrix.clone(), 0, false),
        };

        // A held receipt the post credits short contradicts it until receivers audit it and halt
        // the ledger, which only an omission allows (I9).
        let honest = matrix.open(sender_key, receiver_key);
        let contradicts = !unposted && named_posted(held, epoch) && credited < receipt.amount;
        assert!(!contradicts || omitted, "an honest close credits receipts");
        let mut opening = honest.clone();
        let mut named = held;
        let mut halts = false;
        let mut expected: fn(&ChallengeError) -> bool =
            |error| matches!(error, ChallengeError::NoContradiction);
        match attack {
            ChallengeAttack::Resubmit => halts = contradicts,
            ChallengeAttack::WrongEpoch => {
                named = if held > 1 { held - 1 } else { held + 1 };
                expected = |error| matches!(error, ChallengeError::WrongEpoch { .. });
            }
            ChallengeAttack::Opening(kind) => {
                match kind % 3 {
                    0 => opening = matrix.open(sender_key, &self.rogue.public_key()),
                    1 => opening.entry = None,
                    _ => {
                        opening.row = matrix.open(receiver_key, sender_key).row;
                    }
                }
                expected = |error| matches!(error, ChallengeError::InvalidOpening);
                if opening == honest {
                    expected = |error| matches!(error, ChallengeError::NoContradiction);
                    halts = contradicts;
                }
            }
            ChallengeAttack::Inflate | ChallengeAttack::Forged => {
                // The receipt promises more than the post credits, which its own entry or the
                // sender's signature cannot back.
                let Some(inflated) = credited.checked_add(1) else {
                    return;
                };
                let genuine = receipt.amount >= inflated;
                receipt.amount = inflated.max(receipt.amount);
                if let ChallengeAttack::Forged = attack {
                    receipt.signature = self
                        .rogue
                        .sign(&self.namespace.state, &receipt.state.encode());
                } else if genuine {
                    // The receipt already promises more, so it is the genuine one.
                    halts = contradicts;
                }
                expected = |error| matches!(error, ChallengeError::InvalidReceipt);
            }
            ChallengeAttack::Unposted => {}
        }
        let challenge = Challenge { receipt, opening };
        roundtrip(&challenge, &());
        let result = self
            .ledger
            .challenge(&self.namespace, &operator, named, &challenge);
        match result {
            Ok(()) => {
                assert!(halts && !halted);
                assert_eq!(self.ledger.halt, Some(Halt::Challenge(named)));
                return;
            }
            Err(Refusal::Halted) => assert!(halted),
            Err(Refusal::NotPosted) => assert!(named >= epoch),
            Err(Refusal::Challenge(error)) => {
                assert!(!halts && expected(&error), "challenge refused as {error:?}")
            }
            result => panic!("a challenge returned {result:?}"),
        }
        assert_eq!(self.snapshot(), before);
    }

    async fn claim(&mut self, user: u8, attack: Option<ClaimAttack>) {
        let user = self.user(user);
        let account = self.accounts[user].clone();

        // V6: a validator proves the balance under the last posted root.
        let proof = match self.store().balances.key_value_proof(&account).await {
            Ok((proof, balance)) => Some(BalanceProof { balance, proof }),
            Err(qmdb::Error::KeyNotFound) => None,
            Err(error) => panic!("a balance proof failed: {error}"),
        };
        assert_eq!(
            proof.as_ref().map_or(0, |proof| proof.balance),
            self.model.balances[user]
        );
        if let Some(proof) = &proof {
            roundtrip(proof, &());
            assert!(proof.verify::<Sha256, _>(&self.ledger.balances, &account));
        }
        let honest = proof.clone();
        let mut claimant = user;
        let mut proof = proof;
        let mut forged = false;
        match attack {
            None => {}
            Some(ClaimAttack::Balance) => {
                if let Some(proof) = &mut proof {
                    proof.balance = proof.balance.wrapping_add(1);
                    forged = true;
                }
            }
            Some(ClaimAttack::Account) => {
                if proof.is_some() {
                    claimant = self.other(user);
                    forged = true;
                }
            }
            Some(ClaimAttack::Twice) => self.claim_once(user, proof.as_ref(), false),
        }
        self.claim_once(claimant, proof.as_ref(), forged);

        // A forged claim is refused, and the account then claims with the proof it was served.
        if forged {
            self.claim_once(user, honest.as_ref(), false);
        }
    }

    /// Claims for `user` with `proof`, which the ledger pays at most once (L9).
    fn claim_once(&mut self, user: usize, proof: Option<&TestBalanceProof>, forged: bool) {
        let before = self.snapshot();
        let account = self.accounts[user].clone();
        let balance = if self.model.claimed.contains(&user) || forged {
            0
        } else {
            self.model.balances[user]
        };
        let deposits = self.ledger.claimable.get(&account).copied().unwrap_or(0);
        let result = self.ledger.claim(&account, proof);
        match result {
            Ok(paid) => {
                assert!(!forged && before.ledger.halt.is_some());
                assert_eq!(u128::from(paid), u128::from(balance) + u128::from(deposits));
                if balance != 0 {
                    self.model.claimed.insert(user);
                }
                self.model.transferred += u128::from(paid);
                return;
            }
            Err(Refusal::NotHalted) => assert!(before.ledger.halt.is_none()),
            Err(Refusal::InvalidProof) => assert!(forged),
            Err(Refusal::NothingToClaim) => assert_eq!((balance, deposits), (0, 0)),
            Err(refusal) => panic!("a claim refused as {refusal:?}"),
        }
        assert_eq!(self.snapshot(), before);
    }

    async fn restart(&mut self) {
        // Senders lose the acknowledgements in flight to them and keep what they persisted (S3).
        for book in &mut self.books {
            book.late = None;
        }

        // V2: the validator recovers the last post from what it persisted alone.
        let (roots, parent) = (self.store().roots(), self.parent.clone());
        drop(self.store.take());
        self.recover().await;
        assert_eq!(self.store().roots(), roots);
        assert_eq!(self.parent.summary, parent.summary);
        assert_eq!(self.parent.matrix.root(), parent.matrix.root());
        let metadata = self
            .store()
            .balances
            .get_metadata()
            .await
            .expect("the balances database must read");
        assert_eq!(metadata.is_some(), self.parent.summary.epoch > 0);
    }

    /// An arbitrary value of one wire type reaches the role that consumes it, which must refuse
    /// it or agree with the model.
    fn garbage(&mut self, kind: Garbage) {
        let before = self.snapshot();
        let mut bytes = vec![0; GARBAGE_BYTES];
        self.rng().fill_bytes(&mut bytes);
        let u = &mut Unstructured::new(&bytes);
        let operator = self.operator.public_key();
        let epoch = self.ledger.epoch();
        match kind {
            Garbage::Request => {
                let Ok(request) = u.arbitrary::<TestRequest>() else {
                    return;
                };
                roundtrip(&request, &request.batch.len());
                for epoch in [epoch, epoch + 1] {
                    let admitted = request
                        .verify::<Sha256>(&self.namespace, epoch)
                        .and_then(|verified| verified.admit::<Sha256>(None, &empty_root()));
                    assert!(admitted.is_err());
                }
            }
            Garbage::Receipt => {
                let Ok(receipt) = u.arbitrary::<TestReceipt>() else {
                    return;
                };
                roundtrip(&receipt, &());
                assert!(!receipt.verify::<Sha256>(&self.namespace, &operator));
            }
            Garbage::Challenge => {
                let Ok(challenge) = u.arbitrary::<TestChallenge>() else {
                    return;
                };
                roundtrip(&challenge, &());
                let named = challenge.receipt.state.epoch;
                let result = self
                    .ledger
                    .challenge(&self.namespace, &operator, named, &challenge);
                assert!(result.is_err());
            }
            Garbage::Close => {
                let Ok(close) = u.arbitrary::<TestClose>() else {
                    return;
                };
                let limits = Limits {
                    rows: close.rows().len(),
                    receivers: close
                        .rows()
                        .iter()
                        .map(|row| row.payments.len())
                        .max()
                        .unwrap_or(0),
                    withdrawals: close.withdrawals().len(),
                };
                roundtrip(&close, &limits);
                let queue = self.ledger.queue();
                assert!(
                    self.check_close(close, &self.parent.clone(), &queue)
                        .is_err()
                );
            }
            Garbage::Summary => {
                let (Ok(summary), Ok(certificate)) =
                    (u.arbitrary::<TestSummary>(), u.arbitrary::<u64>())
                else {
                    return;
                };
                roundtrip(&summary, &());
                let certificate = U64::new(certificate);
                let result = self.ledger.post(
                    self.context.as_mut().expect("the process is up"),
                    &self.verifier,
                    &summary,
                    &certificate,
                );
                assert!(result.is_err());
            }
            Garbage::Opening => {
                let (Ok(opening), Ok(sender), Ok(receiver)) = (
                    u.arbitrary::<TestOpening>(),
                    u.arbitrary::<u8>(),
                    u.arbitrary::<u8>(),
                ) else {
                    return;
                };
                roundtrip(&opening, &());
                let (sender, receiver) = (self.user(sender), self.user(receiver));
                let (account, paid) = (&self.accounts[sender], &self.accounts[receiver]);
                let matrix = &self.parent.matrix;
                let root = matrix.root();
                if let Ok(row) = opening.verify_row::<Sha256>(&root, account) {
                    assert_eq!(row, matrix.payments_root(account));
                }
                if let Ok(amount) = opening.verify::<Sha256>(&root, account, paid) {
                    let expected = matrix
                        .payments(account)
                        .map_or(0, |payments| payments.get(paid));
                    assert_eq!(amount, expected);
                }
            }
            Garbage::PayoutProof => {
                let Ok(proof) = u.arbitrary::<TestPayoutProof>() else {
                    return;
                };
                roundtrip(&proof, &());
                assert!(self.ledger.withdraw(epoch - 1, &proof).is_err());
            }
            Garbage::BalanceProof => {
                let Ok(proof) = u.arbitrary::<TestBalanceProof>() else {
                    return;
                };
                roundtrip(&proof, &());
                for account in &self.accounts {
                    assert!(!proof.verify::<Sha256, _>(&self.ledger.balances, account));
                }
            }
            Garbage::Withdrawal => {
                let Ok(withdrawal) = u.arbitrary::<TestWithdrawal>() else {
                    return;
                };
                roundtrip(&withdrawal, &());
                assert!(!withdrawal.verify(&self.namespace));
            }
            Garbage::Row => {
                let Ok(row) = u.arbitrary::<TestRow>() else {
                    return;
                };
                roundtrip(&row, &row.payments.len());
                if self.index(&row.account).is_some() {
                    return;
                }
                let queue = self.ledger.queue();
                let (deposits, forced) = (
                    queue.required_deposits as u64,
                    queue.required_forced_withdrawals as u64,
                );
                let (close, _) = self
                    .assemble(
                        &self.operator.clone(),
                        &queue,
                        vec![row],
                        Vec::new(),
                        deposits,
                        forced,
                    )
                    .expect("one row of an unknown account assembles");
                assert!(matches!(
                    self.check_close(close, &self.parent.clone(), &queue),
                    Err(CheckError::InvalidSignature)
                ));
            }
            Garbage::Flow => {
                let (Ok(flow), Ok(previous)) = (u.arbitrary::<Flow<u64>>(), u.arbitrary::<u64>())
                else {
                    return;
                };
                roundtrip(&flow, &());
                let (epoch, sums) = flow_sums(&flow);
                assert_eq!(flow.epoch(), epoch);

                // Arbitrary carries almost never settle, so the same sums with at most one carry
                // each are settled too.
                let near = flow_bytes(epoch, sums.map(|sum| sum % (1 << 65)));
                let near = Flow::<u64>::decode(near).expect("a flow decodes");
                for flow in [flow, near] {
                    let (_, sums) = flow_sums(&flow);
                    match (flow.settle(previous), settle_sums(previous, sums)) {
                        (Ok(settled), Ok(expected)) => assert_eq!(settled, expected),
                        (Err(error), Err(refused)) => assert!(refused.matches(&error)),
                        (settled, expected) => panic!(
                            "a flow settled as {settled:?} where the model expects {expected:?}"
                        ),
                    }
                }
            }
            Garbage::Amounts => {
                let (Ok(amounts), Ok(other)) =
                    (u.arbitrary::<TestAmounts>(), u.arbitrary::<TestAmounts>())
                else {
                    return;
                };
                roundtrip(&amounts, &RangeCfg::new(..=amounts.len()));
                let entries: Vec<_> = amounts.iter().map(|(a, x)| (a.clone(), x)).collect();
                assert_eq!(amounts.len(), entries.len());
                assert_eq!(amounts.is_empty(), entries.is_empty());
                assert!(entries.windows(2).all(|pair| pair[0].0 < pair[1].0));
                let total = entries
                    .iter()
                    .try_fold(0u64, |total, (_, amount)| total.checked_add(*amount));
                assert_eq!(amounts.total(), total);
                for (position, (account, amount)) in entries.iter().enumerate() {
                    assert_eq!(amounts.position(account), Some(position));
                    assert_eq!(amounts.get(account), *amount);
                }
                assert_eq!(amounts.get(&operator), 0);
                assert_eq!(amounts.position(&operator), None);

                // Combining adds entry by entry and refuses a sum that overflows.
                let mut sums: BTreeMap<PublicKey, u128> = BTreeMap::new();
                for (account, amount) in amounts.iter().chain(other.iter()) {
                    *sums.entry(account.clone()).or_default() += u128::from(amount);
                }
                let fits = sums.values().all(|sum| *sum <= u128::from(u64::MAX));
                match amounts.combine(&other) {
                    Ok(combined) => {
                        assert!(fits);
                        assert_eq!(combined.len(), sums.len());
                        for (account, sum) in &sums {
                            assert_eq!(u128::from(combined.get(account)), *sum);
                        }
                        assert_eq!(other.combine(&amounts).ok(), Some(combined));
                    }
                    Err(AmountsError::Overflow) => assert!(!fits),
                    Err(error) => panic!("combining refused as {error:?}"),
                }
            }
            Garbage::Parts => {
                let (Ok(processed), Ok(deposit), Ok(forced), Ok(payout)) = (
                    u.arbitrary::<Processed<Digest>>(),
                    u.arbitrary::<Deposit<PublicKey, u64>>(),
                    u.arbitrary::<ForcedWithdrawal<PublicKey, u64>>(),
                    u.arbitrary::<Payout<PublicKey, u64>>(),
                ) else {
                    return;
                };
                roundtrip(&processed, &());
                roundtrip(&deposit, &());
                roundtrip(&forced, &());
                roundtrip(&payout, &());
                let (Ok(state), Ok(signatures), Ok(lookup)) = (
                    u.arbitrary::<TestState>(),
                    u.arbitrary::<Signatures<PublicKey>>(),
                    u.arbitrary::<Lookup<PublicKey, u64, Digest>>(),
                ) else {
                    return;
                };
                roundtrip(&state, &());
                roundtrip(&signatures, &());
                roundtrip(&lookup, &());
            }
        }

        // I10: no arbitrary value changes anything.
        assert_eq!(self.snapshot(), before);
    }

    /// A mutated honest message reaches the role that consumes it, which must refuse it or find it
    /// equal to the honest one.
    async fn mutate(&mut self, target: Target, pick: u8, mutations: &[Mutation]) {
        let before = self.snapshot();
        let operator = self.operator.public_key();
        let choice = usize::from(pick);
        match target {
            Target::Opening | Target::Challenge => {
                // One of the eight newest posts, since older ones may still be unaudited.
                let back = usize::from(pick >> 5) % self.history.len().max(1);
                let Some(posted) = self.history.iter().rev().nth(back) else {
                    return;
                };
                let (sender, receiver) = (self.user(pick), self.user(pick / 8));
                let (account, paid) = (&self.accounts[sender], &self.accounts[receiver]);
                let matrix = &posted.checkpoint.matrix;
                let root = matrix.root();
                let honest = matrix.open(account, paid);
                if let Target::Opening = target {
                    let Some(opening) = mutate(&honest, &(), mutations) else {
                        return;
                    };
                    if let Ok(row) = opening.verify_row::<Sha256>(&root, account) {
                        assert_eq!(row, matrix.payments_root(account));
                    }
                    if let Ok(amount) = opening.verify::<Sha256>(&root, account, paid) {
                        let expected = posted
                            .rows
                            .get(&sender)
                            .and_then(|map| map.get(&receiver))
                            .copied()
                            .unwrap_or(0);
                        assert_eq!(amount, expected);
                    }
                } else {
                    let epoch = posted.summary.epoch;
                    let Some(receipt) = self.receipts.get(&(epoch, sender, receiver)).cloned()
                    else {
                        return;
                    };
                    let challenge = Challenge {
                        receipt,
                        opening: honest,
                    };
                    let Some(mutated) = mutate(&challenge, &(), mutations) else {
                        return;
                    };
                    let result = self
                        .ledger
                        .challenge(&self.namespace, &operator, epoch, &mutated);
                    if result.is_ok() {
                        // Only a genuine receipt the post credits short, which only an omission
                        // leaves unaudited, halts the ledger.
                        let receipt = &mutated.receipt;
                        assert!(receipt.verify::<Sha256>(&self.namespace, &operator));
                        let (sender, receiver) = (
                            self.index(&receipt.state.account).expect("a user"),
                            self.index(&receipt.receiver).expect("a user"),
                        );
                        let posted = &self.history[epoch as usize - 1];
                        let credited = posted
                            .rows
                            .get(&sender)
                            .and_then(|map| map.get(&receiver))
                            .copied()
                            .unwrap_or(0);
                        assert!(credited < receipt.amount && posted.omitted.contains(&sender));
                        return;
                    }
                }
            }
            Target::Receipt => {
                if self.receipts.is_empty() {
                    return;
                }
                let honest = self
                    .receipts
                    .values()
                    .nth(choice % self.receipts.len())
                    .cloned();
                let honest = honest.expect("in range");
                let Some(receipt) = mutate(&honest, &(), mutations) else {
                    return;
                };
                if receipt.verify::<Sha256>(&self.namespace, &operator) {
                    assert_eq!(receipt.state, honest.state);
                    assert_eq!(receipt.receiver, honest.receiver);
                    assert_eq!(receipt.amount, honest.amount);
                }
            }
            Target::Close => {
                let Some(posted) = self.history.last() else {
                    return;
                };
                let honest = posted.close.clone();
                let Some(close) = mutate(&honest, &LIMITS, mutations) else {
                    return;
                };
                let (parent, queue) = (posted.parent.clone(), posted.queue.clone());
                if self.check_close(close.clone(), &parent, &queue).is_ok() {
                    assert_eq!(close, honest);
                }
            }
            Target::Summary => {
                let Some(posted) = self.history.last() else {
                    return;
                };
                let honest = posted.summary;
                let Some(summary) = mutate(&honest, &(), mutations) else {
                    return;
                };
                let parent = posted.parent.summary.digest();
                let (deposits, forced) = (honest.deposits.count, honest.forced_withdrawals.count);
                let certificate = posted.certificate.clone();
                let verified = summary.verify(
                    self.context.as_mut().expect("the process is up"),
                    &self.verifier,
                    &certificate,
                    honest.epoch,
                    &parent,
                    deposits..=deposits,
                    forced..=forced,
                    &Sequential,
                );
                if verified.is_ok() {
                    assert_eq!(summary, honest);
                }
            }
            Target::Request => {
                // An admitted request of the open epoch or of the epoch being closed.
                let closing = self.desk.closing.as_ref();
                let admitted: Vec<_> = self
                    .desk
                    .admitted
                    .iter()
                    .chain(closing.into_iter().flat_map(|closing| &closing.admitted))
                    .collect();
                if admitted.is_empty() {
                    return;
                }
                let (user, admitted) = admitted[choice % admitted.len()];
                let user = *user;
                let honest = admitted
                    .requests
                    .last()
                    .expect("an admitted request")
                    .clone();
                let Some(request) = mutate(&honest, &LIMITS.receivers, mutations) else {
                    return;
                };

                // I5: in each epoch it can name, the operator admits the mutated request exactly
                // as the model admits it against the records of that epoch.
                let signed = Signed::of(&honest);
                for epoch in [honest.epoch, honest.epoch + 1] {
                    let Some((latest, previous)) = self.records(user, epoch) else {
                        continue;
                    };
                    let expected = self.expect(epoch, latest, previous, &request, &signed);
                    let admission =
                        request
                            .verify::<Sha256>(&self.namespace, epoch)
                            .and_then(|verified| {
                                verified.admit::<Sha256>(
                                    latest.map(|latest| (&latest.state, &latest.payments)),
                                    &previous,
                                )
                            });
                    self.admission(admission, expected, epoch, latest, previous, &request);
                }
            }
            Target::PayoutProof => {
                if self.proofs.is_empty() {
                    return;
                }
                let (epoch, honest) = self.proofs[choice % self.proofs.len()].clone();
                let Some(proof) = mutate(&honest, &(), mutations) else {
                    return;
                };
                let root = Ledger::posted(&self.ledger.payouts, epoch).expect("posted");
                if proof.verify::<Sha256>(root) {
                    assert_eq!(proof.index, honest.index);
                    assert_eq!(proof.payout, honest.payout);
                }
            }
            Target::BalanceProof => {
                let user = self.user(pick);
                let account = self.accounts[user].clone();
                let Ok((proof, balance)) = self.store().balances.key_value_proof(&account).await
                else {
                    return;
                };
                let honest = BalanceProof { balance, proof };
                let Some(proof) = mutate(&honest, &(), mutations) else {
                    return;
                };
                if proof.verify::<Sha256, _>(&self.ledger.balances, &account) {
                    assert_eq!(proof.balance, honest.balance);
                }
            }
            Target::Malformed(kind) => self.malformed(kind, pick, mutations),
        }

        // I10: no mutated message changes anything.
        assert_eq!(self.snapshot(), before);
    }

    /// Checks that encodings breaking a canonical form do not decode. The accounts come from
    /// `pick`, and the amounts and the tag from the bytes of `mutations`, then from `pick`.
    fn malformed(&self, kind: u8, pick: u8, mutations: &[Mutation]) {
        let user = self.user(pick);
        let (first, second) = (
            self.accounts[user].clone(),
            self.accounts[self.other(user)].clone(),
        );
        let mut bytes = mutations
            .iter()
            .map(|mutation| match *mutation {
                Mutation::Insert { value, .. } | Mutation::Replace { value, .. } => value,
                Mutation::Flip { position, .. } | Mutation::Delete { position } => {
                    position.to_le_bytes()[0]
                }
                Mutation::Swap { first, .. } => first.to_le_bytes()[0],
            })
            .chain(iter::repeat(pick));
        let mut byte = || bytes.next().expect("the bytes never run out");
        let mut amount = || 1 + u64::from(byte());
        let (low, high) = if first < second {
            (first, second)
        } else {
            (second, first)
        };
        match kind % 5 {
            0..=2 => {
                // Unsorted, repeated or zero entries are not amounts.
                let entries: Vec<(PublicKey, u64)> = match kind % 5 {
                    0 => vec![(high, amount()), (low, amount())],
                    1 => vec![(low.clone(), amount()), (low, amount())],
                    _ => vec![(low, 0)],
                };
                let range = RangeCfg::new(..=MAX_USERS);
                assert!(TestAmounts::decode_cfg(entries.encode(), &range).is_err());
            }
            3 => {
                // Rows out of account order are not a close.
                let row = |account: PublicKey, amount: u64| Row {
                    payments: Amounts::new([(account.clone(), amount)]).expect("nonzero"),
                    account,
                    signature: self.rogue.sign(b"row", b"row"),
                };
                let rows = [row(high, amount()), row(low, amount())];
                let bytes = close_bytes(1, &rows, &[], 0, 0, &self.rogue.sign(b"c", b"c"));
                assert!(TestClose::decode_cfg(bytes, &LIMITS).is_err());
            }
            _ => {
                // An opening's row tag names neither a member nor a non-member.
                let mut bytes = self.parent.matrix.open(&low, &high).encode().to_vec();
                bytes[0] = 2 + byte() % 254;
                assert!(TestOpening::decode(bytes).is_err());
            }
        }
    }
}

fn fuzz(input: FuzzInput) {
    let FuzzInput {
        users,
        ops,
        entropy,
    } = input;
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(entropy));
    let mut runner = deterministic::Runner::new(cfg);

    // A crash ends the runtime, which drops every write not yet durable, and the plan resumes
    // in a runtime recovered from what storage kept.
    let mut ops = Some(VecDeque::from(ops));
    let mut crashed = None;
    loop {
        let (plan, resumed) = (ops.take(), crashed.take());
        let (outcome, checkpoint) = runner.start_and_recover(|context| async move {
            match resumed {
                Some(crashed) => Harness::resume(context, crashed).await,
                None => {
                    let harness = Harness::new(context, users).await;
                    harness.check().await;
                    harness.run(plan.expect("the plan")).await
                }
            }
        });
        let Some(outcome) = outcome else {
            return;
        };
        crashed = Some(outcome);
        runner = deterministic::Runner::from(checkpoint);
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
