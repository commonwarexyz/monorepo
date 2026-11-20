#![no_main]

//! Runs Bajillion next to the ideal clearing functionality it is proven to realize.
//!
//! The functionality is Figure 1 of the Bajillion paper (arXiv:2611.21883), written out over user
//! indices and exact integers as [`Functionality`] in this crate's library. It states what the
//! protocol may do to the users' funds whatever the operator and the other users do: an honest
//! sender is debited at most what it authorized, an honest receiver is credited what it was
//! promised or the ledger halts, an honest account is paid out at most what it asked for, every
//! required request is processed, and after a halt every account gets its finalized balance and
//! unprocessed deposits.
//!
//! The honest parties are the reference roles of the crate's own tests
//! (`clearing/tests/bajillion/roles`), which the library includes as they are. The validators are
//! honest, as the paper's validity oracle is. The input fixes who is corrupt for the whole plan:
//! the operator, and any set of users. The harness plays the corrupt parties with their keys and
//! with every message the honest parties sent. Requests, receipts, soft withdrawals, closes,
//! summaries, openings, challenges and proofs are encoded when they are sent, and their receiver
//! decodes them. Acknowledgements and certificates are passed as they are.
//!
//! Each action is one event of the paper's proof, and the functionality is fed as its simulator
//! feeds it:
//!
//! - an input of an honest party goes to the party and to the functionality;
//! - with an honest operator, a state or a soft withdrawal of a corrupt user that the operator
//!   admits is sent to the functionality on that user's behalf;
//! - with a corrupt operator, a close that posts is sent with its matrix and the balances the
//!   validators computed, and the functionality must accept it;
//! - a receipt an honest receiver relies on is released, and the functionality must allow it;
//! - a challenge of a corrupt party that halts the ledger is a fault, which the functionality
//!   allows only when the operator is corrupt.
//!
//! A message that a party must refuse leaves every party as it was, and the action then goes on
//! without it.
//!
//! After every action the invariants of the proof are checked: the epoch, the halt, the balances,
//! the queues and their required counts agree (I1, I2), an honest operator holds the
//! functionality's maps (I3), and every honest receiver holds the functionality's receipts (I4).
//! The outputs of honest parties are compared where they arise (I5).
//!
//! Where the crate departs from the paper, the functionality is read as follows:
//!
//! - Every request is pipelined: it carries a state of its epoch and one of the next.
//! - A close posts its payouts, and accounts withdraw them later with proofs. A posted payout is
//!   the functionality's `Paid` output, and the ledger's custody must equal the functionality's
//!   balances, the queued deposits, and the payouts not yet withdrawn.
//! - After a halt accounts claim with proofs. A claim is the functionality's `Refund` output. Every
//!   plan ends with a halt, every claim and every payout withdrawal, and then custody is zero.
//! - Limits never bind here, and deposits stay far from the largest amount, so neither refuses
//!   what the functionality accepts.
//!
//! Not covered: crashes and restarts, faulty validators, and a lossy network between honest
//! parties. The paper's theorem covers none of them.

use arbitrary::{Arbitrary, Unstructured};
use commonware_clearing::bajillion::{
    Challenge, Epoch, Limits, Namespace, Row, SettleError, State, Withdrawal,
};
use commonware_clearing_fuzz::{
    Committee, MAX_USERS, MIN_USERS, OPEN_EPOCHS, Posted, TestAmounts, TestClose, TestLedger,
    TestOperator, TestQueue, TestReceipt, TestReceiver, TestRequest, TestRow, TestSender,
    TestState, TestSummary, TestValidator, TestWithdrawal, UNIT, VALIDATORS, config,
    functionality::{Functionality, entry, zeros},
    roles::{ledger, sender, validator},
    sampling::{Shift, Size, batch, count, stream, weighted},
    scheme, wire,
};
use commonware_codec::{Decode as _, Encode as _, Write as _, varint::UInt};
use commonware_cryptography::{
    Digestible as _, Sha256, Signer as _,
    certificate::Scheme as _,
    ed25519::{PrivateKey, PublicKey, Signature},
    sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_utils::{Entropy, FuzzRng, iter::NonEmpty, sequence::U64};
use libfuzzer_sys::fuzz_target;
use rand_core::Rng as _;
use std::{collections::BTreeMap, fmt::Debug};

/// The deployment namespace every signature is made in.
const NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_FUZZ_FUNCTIONALITY";

/// Actions a plan draws, enough for several epochs with payments in each.
const MAX_OPS: usize = 96;

/// Close limits that no plan reaches: every user may have a row that pays every user, and every
/// action may be a soft withdrawal.
const LIMITS: Limits = Limits {
    rows: MAX_USERS,
    receivers: MAX_USERS,
    withdrawals: MAX_OPS,
};

/// Bytes of the stream a plan is sampled from, more than the largest plan draws (48 bytes for each
/// action).
const STREAM_BYTES: usize = 1 << 13;
/// One user in this many is corrupt, and the operator is corrupt in one plan of two.
const CORRUPT_USER_ONE_IN: u8 = 3;
const CORRUPT_OPERATOR_ONE_IN: u8 = 2;

/// One action in this many of a corrupt party deviates from what an honest one would send.
const DEVIATE_ONE_IN: u8 = 3;

/// Tag of a soft withdrawal no user signed. Users count their tags up from zero.
const FORGED_TAG: u64 = u64::MAX;

/// Weights of a corrupt operator's answers, in the order of the [`Answer`] variants. A request it
/// leaves pending blocks its sender until a close resolves it, and a state it countersigns
/// although no close can fund it ends in a halt.
const ANSWER_WEIGHTS: [u8; 5] = [5, 1, 1, 1, 1];

/// One row in this many of a corrupt operator's close is not the latest state its sender signed
/// for the epoch. The others keep what the operator countersigned, so the epochs go on.
const EARLIER_ONE_IN: u8 = 8;

/// Weights of the actions, in the order of the [`Op`] variants: Deposit, Force, Send, Withdraw,
/// Close, Answer, Deliver, Challenge, Payout. Deposits fund everything else, and several payments
/// go into each close.
const OP_WEIGHTS: [u8; 9] = [10, 3, 26, 6, 10, 4, 5, 3, 4];

/// How a corrupt operator answers the pending request of an honest sender.
#[derive(Clone, Copy, Debug)]
enum Answer {
    /// It countersigns the state of the request's epoch if it expects that a close can fund it,
    /// and refuses the request otherwise.
    Current,
    /// It countersigns the state of the next epoch.
    Next,
    /// It refuses the request.
    Refuse,
    /// It does not answer.
    Silent,
    /// It countersigns the state of the request's epoch, whatever a close can fund.
    Unfunded,
}

impl<'a> Arbitrary<'a> for Answer {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match weighted(u, &ANSWER_WEIGHTS)? {
            0 => Self::Current,
            1 => Self::Next,
            2 => Self::Refuse,
            3 => Self::Silent,
            _ => Self::Unfunded,
        })
    }
}

/// How the request of a corrupt sender deviates from the one an honest sender would sign.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Twist {
    /// An earlier request of the sender is sent again.
    Replay(u8),
    /// The request names another epoch than its states were signed for.
    Epoch(bool),
    /// The request names another root than its states build on.
    Root,
    /// The states start a new map although the sender has one in the epoch.
    Restart,
}

/// How the soft withdrawal of a corrupt user deviates from the one an honest user would sign.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum WithdrawTwist {
    /// An earlier request of any user is sent again.
    Replay(u8),
    /// The request was signed for another epoch and names the current one.
    Relabel(bool),
    /// The amount changes after signing.
    Amount,
}

/// A part of a corrupt operator's close that validators must refuse.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Deviation {
    /// A user's row is a state it signed for this epoch on another root than its posted row.
    OtherRoot(u8, u8),
    /// A user's row is a state it signed for another epoch.
    OtherEpoch(u8, u8),
    /// A soft withdrawal some user signed for another epoch, as signed.
    StaleWithdrawal(u8),
    /// A soft withdrawal some user signed for another epoch, renamed to this one.
    RelabeledWithdrawal(u8),
    /// A count one outside the queue's bounds.
    Count(bool),
    /// A user's row pays a receiver an amount, and the operator signed it in the user's place.
    ForgedState(u8, u8, Size),
    /// A soft withdrawal of a user that the operator signed in the user's place.
    ForgedWithdrawal(u8, Size),
}

/// The close a corrupt operator signs.
#[derive(Clone, Debug)]
struct Forgery {
    /// For each user, whether its row is the latest state it signed for this epoch on its posted
    /// row, or which earlier one, or none.
    rows: [u8; MAX_USERS],
    /// A map a corrupt user signs for this close.
    fresh: Option<(u8, Vec<(u8, Size)>)>,
    /// Which soft withdrawals of this epoch the close carries.
    withdrawals: u8,
    /// A part validators must refuse. The close is signed again without it when they do.
    deviation: Option<Deviation>,
}

impl<'a> Arbitrary<'a> for Forgery {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            rows: u.arbitrary()?,
            fresh: if u.ratio(1u8, DEVIATE_ONE_IN)? {
                Some((u.arbitrary()?, batch(u)?))
            } else {
                None
            },
            withdrawals: u.arbitrary()?,
            deviation: deviation(u)?,
        })
    }
}

/// Returns a deviation one time in [`DEVIATE_ONE_IN`].
fn deviation<'a, T: Arbitrary<'a>>(u: &mut Unstructured<'a>) -> arbitrary::Result<Option<T>> {
    Ok(if u.ratio(1u8, DEVIATE_ONE_IN)? {
        Some(u.arbitrary()?)
    } else {
        None
    })
}

#[derive(Debug)]
enum Op {
    /// A user deposits through the ledger.
    Deposit { user: u8, amount: u16 },
    /// A user queues a forced withdrawal on the ledger.
    Force { user: u8, amount: Size },
    /// A sender pays a batch of receivers. An honest sender signs the request, and a corrupt
    /// operator answers it as `answer` says. A corrupt sender signs what `twist` says. Receipts
    /// reach the receivers `deliver` selects.
    Send {
        sender: u8,
        batch: Vec<(u8, Size)>,
        epoch: Shift,
        answer: Answer,
        deliver: u8,
        twist: Option<Twist>,
    },
    /// A user asks for a soft withdrawal.
    Withdraw {
        user: u8,
        amount: Size,
        epoch: Shift,
        twist: Option<WithdrawTwist>,
    },
    /// The operator closes the epoch the ledger expects, validators check and settle the close,
    /// the committee certifies it, the ledger posts it, and every honest user resolves and audits
    /// it. A corrupt operator signs the close `forgery` describes.
    Close {
        deposits: u8,
        forced: u8,
        forgery: Forgery,
    },
    /// A corrupt operator answers a request it left pending.
    Answer {
        sender: u8,
        answer: Answer,
        deliver: u8,
    },
    /// A corrupt party gives a receiver a receipt from a state the sender signed.
    Deliver { sender: u8, receiver: u8, pick: u8 },
    /// A corrupt party challenges a posted close with a receipt it holds and an opening of the
    /// receipt's pair, or of another pair.
    Challenge { pick: u8, other: Option<(u8, u8)> },
    /// An account withdraws a posted payout, and the same proof is refused the second time.
    Payout { pick: u8 },
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
            2 => Self::Send {
                sender: u.arbitrary()?,
                batch: batch(u)?,
                epoch: u.arbitrary()?,
                answer: u.arbitrary()?,
                deliver: u.arbitrary()?,
                twist: deviation(u)?,
            },
            3 => Self::Withdraw {
                user: u.arbitrary()?,
                amount: u.arbitrary()?,
                epoch: u.arbitrary()?,
                twist: deviation(u)?,
            },
            4 => Self::Close {
                deposits: u.arbitrary()?,
                forced: u.arbitrary()?,
                forgery: u.arbitrary()?,
            },
            5 => Self::Answer {
                sender: u.arbitrary()?,
                answer: u.arbitrary()?,
                deliver: u.arbitrary()?,
            },
            6 => Self::Deliver {
                sender: u.arbitrary()?,
                receiver: u.arbitrary()?,
                pick: u.arbitrary()?,
            },
            7 => Self::Challenge {
                pick: u.arbitrary()?,
                other: deviation(u)?,
            },
            _ => Self::Payout {
                pick: u.arbitrary()?,
            },
        })
    }
}

#[derive(Debug)]
struct FuzzInput {
    /// Whether the operator is corrupt, and whether each user is.
    operator: bool,
    corrupt: Vec<bool>,
    ops: Vec<Op>,
    entropy: Entropy,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let (stream, entropy) = stream(u, STREAM_BYTES)?;
        let u = &mut Unstructured::new(&stream);

        let users = u.int_in_range(MIN_USERS..=MAX_USERS)?;
        Ok(Self {
            operator: u.ratio(1u8, CORRUPT_OPERATOR_ONE_IN)?,
            corrupt: (0..users)
                .map(|_| u.ratio(1u8, CORRUPT_USER_ONE_IN))
                .collect::<arbitrary::Result<_>>()?,
            ops: (0..MAX_OPS)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
            entropy: Unstructured::new(&entropy).arbitrary()?,
        })
    }
}

/// A state a user signed, with the map it commits to.
#[derive(Clone)]
struct Signed {
    state: TestState,
    payments: TestAmounts,
    signature: Signature,
}

/// One user: its key, and the reference sender and receiver that act for it while it is honest. A
/// corrupt user's sender only prepares well-formed requests for the harness to send or change.
struct User {
    key: PrivateKey,
    account: PublicKey,
    corrupt: bool,
    sender: TestSender,
    receiver: TestReceiver,
    /// The tag of its next soft withdrawal.
    tag: u64,
}

/// What every party holds, to show that a refused message changed nothing.
#[derive(PartialEq)]
struct Snapshot {
    ledger: TestLedger,
    operator: TestOperator,
    senders: Vec<TestSender>,
    receivers: Vec<TestReceiver>,
    attested: validator::Persisted<Digest>,
    summary: TestSummary,
}

/// Returns the bytes the operator signs for a close: the epoch, the matrix root, the withdrawals,
/// and both counts as varints.
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

/// Returns the encoding of a close with the given parts.
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

/// The protocol's parties, the functionality next to them, and what the corrupt parties hold.
struct World {
    context: deterministic::Context,
    namespace: Namespace,
    users: Vec<User>,
    index: BTreeMap<PublicKey, usize>,
    /// The operator's key, and the reference operator that acts while the operator is honest.
    key: PrivateKey,
    operator: TestOperator,
    validator: TestValidator,
    schemes: Vec<Committee>,
    ledger: TestLedger,
    ideal: Functionality,
    /// Every state each user signed, every acknowledgement and receipt issued, every request a
    /// corrupt sender sent, and every soft withdrawal as its user signed it. No message is
    /// private.
    states: Vec<Vec<Signed>>,
    acknowledgements: Vec<(TestState, Signature)>,
    receipts: Vec<TestReceipt>,
    requests: Vec<Vec<TestRequest>>,
    withdrawals: Vec<TestWithdrawal>,
    /// Posted payouts not yet withdrawn, as epoch, account and amount.
    owed: Vec<(Epoch, usize, u64)>,
}

impl World {
    async fn new(mut context: deterministic::Context, operator: bool, corrupt: &[bool]) -> Self {
        let namespace = Namespace::new(NAMESPACE);
        let key = PrivateKey::from_seed(context.next_u64());
        let users: Vec<_> = corrupt
            .iter()
            .map(|corrupt| {
                let user = PrivateKey::from_seed(context.next_u64());
                let account = user.public_key();
                User {
                    sender: TestSender::new(user.clone(), namespace.clone(), key.public_key()),
                    receiver: TestReceiver::new(
                        account.clone(),
                        namespace.clone(),
                        key.public_key(),
                        1,
                    ),
                    key: user,
                    account,
                    corrupt: *corrupt,
                    tag: 0,
                }
            })
            .collect();
        let index = users
            .iter()
            .enumerate()
            .map(|(index, user)| (user.account.clone(), index))
            .collect();
        let fixture = scheme::fixture(&mut context, NAMESPACE, VALIDATORS);
        let validator = TestValidator::init(
            context.child("validator"),
            config(namespace.clone(), key.public_key(), LIMITS),
            validator::Persisted::default(),
            None,
        )
        .await
        .expect("a validator opens its databases");
        let ledger = TestLedger::new(
            namespace.clone(),
            key.public_key(),
            fixture.verifier,
            validator.summary().balances,
        );
        Self {
            operator: TestOperator::new(key.clone(), namespace.clone(), LIMITS),
            states: vec![Vec::new(); users.len()],
            requests: vec![Vec::new(); users.len()],
            ideal: Functionality::new(operator, corrupt.to_vec()),
            context,
            namespace,
            users,
            index,
            key,
            validator,
            schemes: fixture.schemes,
            ledger,
            acknowledgements: Vec::new(),
            receipts: Vec::new(),
            withdrawals: Vec::new(),
            owed: Vec::new(),
        }
    }

    fn halted(&self) -> bool {
        self.ledger.halted().is_some()
    }

    /// Returns the user `choice` selects.
    fn user(&self, choice: u8) -> usize {
        usize::from(choice) % self.users.len()
    }

    /// Returns the epoch `shift` names.
    fn epoch(&self, shift: Shift) -> Epoch {
        let expected = self.ledger.epoch();
        match shift {
            Shift::Current => expected,
            Shift::Previous => expected - 1,
            Shift::Next => expected + 1,
        }
    }

    /// Returns `amounts` by user index.
    fn entries(&self, amounts: &TestAmounts) -> Vec<(usize, u128)> {
        amounts
            .iter()
            .map(|(account, amount)| (self.index[account], u128::from(amount)))
            .collect()
    }

    /// Returns `amounts` as a row of a table.
    fn row(&self, amounts: Option<&TestAmounts>) -> Vec<u128> {
        let mut row = vec![0; self.users.len()];
        for (receiver, amount) in amounts
            .map(|amounts| self.entries(amounts))
            .unwrap_or_default()
        {
            row[receiver] = amount;
        }
        row
    }

    /// Returns what `sender` can still pay in the epoch the ledger expects a close of: its
    /// finalized balance less what it asked to pay in that epoch.
    fn spendable(&self, sender: usize) -> u64 {
        let ideal = &self.ideal;
        let asked: u128 = (0..self.users.len())
            .map(|receiver| {
                entry(&ideal.auth, ideal.cur, sender, receiver)
                    + entry(&ideal.pipe, ideal.cur, sender, receiver)
            })
            .sum();
        u64::try_from(ideal.bal[sender].saturating_sub(asked)).expect("a balance fits an amount")
    }

    /// Returns the amounts `batch` pays, or `None` if they form no batch. Each is relative to an
    /// equal part of what `sender` can still pay, so most batches are affordable.
    fn batch(&self, sender: usize, batch: &[(u8, Size)]) -> Option<TestAmounts> {
        let base = self.spendable(sender) / batch.len() as u64;
        let entries: BTreeMap<_, _> = batch
            .iter()
            .map(|(receiver, amount)| (self.user(*receiver), amount.resolve(base)))
            .collect();
        TestAmounts::new(
            entries
                .into_iter()
                .map(|(receiver, amount)| (self.users[receiver].account.clone(), amount)),
        )
        .ok()
    }

    /// Returns the root of `user`'s row in the last posted close, or the empty map's root.
    fn posted_root(&self, user: usize) -> Digest {
        self.validator
            .matrix()
            .payments_root(&self.users[user].account)
            .unwrap_or_else(|| TestAmounts::empty().root::<Sha256>())
    }

    /// Records a state `user` signed.
    fn learn(
        &mut self,
        user: usize,
        state: &TestState,
        payments: &TestAmounts,
        signature: &Signature,
    ) {
        self.states[user].push(Signed {
            state: state.clone(),
            payments: payments.clone(),
            signature: signature.clone(),
        });
    }

    /// Certifies `summary` with every validator's attestation.
    fn certify(&self, summary: &TestSummary) -> U64 {
        let attestations: Vec<_> = self
            .schemes
            .iter()
            .map(|scheme| scheme.sign::<Digest>(summary).expect("a validator signs"))
            .collect();
        let attestations = NonEmpty::try_new(attestations.into_iter()).expect("at least one");
        self.schemes[0]
            .assemble(attestations, &Sequential)
            .expect("the committee certifies")
    }

    /// A user deposits through the ledger. The ledger and the functionality refuse a deposit of
    /// nothing, no party changes, and a deposit of one unit follows, which both take.
    fn deposit(&mut self, user: usize, amount: u16) {
        let account = self.users[user].account.clone();
        let before = self.snapshot();
        let real = self.ledger.deposit(account, u64::from(amount));
        let ideal = self.ideal.deposit(user, u128::from(amount));
        assert_eq!(real.is_ok(), ideal.is_ok(), "deposit: {real:?}, {ideal:?}");
        if real.is_err() {
            self.unchanged(&before, "a deposit the ledger refuses");
            if amount == 0 && !self.halted() {
                let account = self.users[user].account.clone();
                self.ledger
                    .deposit(account, u64::from(UNIT))
                    .expect("the ledger takes a deposit of one unit");
                self.ideal
                    .deposit(user, u128::from(UNIT))
                    .expect("the functionality takes a deposit of one unit");
            }
        }
    }

    /// A user queues a forced withdrawal on the ledger. The ledger and the functionality refuse a
    /// withdrawal of nothing, no party changes, and a withdrawal of one unit follows, which both
    /// queue.
    fn force(&mut self, user: usize, size: Size) {
        let base = u64::try_from(self.ideal.bal[user]).expect("a balance fits an amount");
        let amount = size.resolve(base);
        let account = self.users[user].account.clone();
        let before = self.snapshot();
        let real = self.ledger.withdraw(account, amount);
        let ideal = self.ideal.forced_withdraw(user, u128::from(amount));
        assert_eq!(
            real.is_ok(),
            ideal.is_ok(),
            "forced withdrawal: {real:?}, {ideal:?}"
        );
        if real.is_err() {
            self.unchanged(&before, "a forced withdrawal the ledger refuses");
            if amount == 0 && !self.halted() {
                let account = self.users[user].account.clone();
                self.ledger
                    .withdraw(account, u64::from(UNIT))
                    .expect("the ledger queues a withdrawal of one unit");
                self.ideal
                    .forced_withdraw(user, u128::from(UNIT))
                    .expect("the functionality queues a withdrawal of one unit");
            }
        }
    }

    /// Returns what every party holds.
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            ledger: self.ledger.clone(),
            operator: self.operator.clone(),
            senders: self.users.iter().map(|user| user.sender.clone()).collect(),
            receivers: self
                .users
                .iter()
                .map(|user| user.receiver.clone())
                .collect(),
            attested: self.validator.persisted().clone(),
            summary: *self.validator.summary(),
        }
    }

    /// Checks that no party changed since `before`, after `refused` was refused.
    fn unchanged(&self, before: &Snapshot, refused: &str) {
        assert!(
            self.snapshot() == *before,
            "{refused} changed what a party holds"
        );
    }

    /// Returns each user's balance as the validator holds it.
    async fn balances(&self) -> Vec<u128> {
        let mut balances = Vec::with_capacity(self.users.len());
        for user in &self.users {
            let balance = self.validator.balance(&user.account).await;
            balances.push(u128::from(balance.expect("a validator reads a balance")));
        }
        balances
    }

    /// Gives `receipt` to its receiver. `countersigned` says whether it carries the operator's
    /// acknowledgement. An honest receiver relies on exactly the receipts that do, name an epoch
    /// not yet finalized, and promise more than it holds from the sender, and the functionality
    /// then releases the amount the receipt promises. Any other receipt changes nothing.
    fn deliver(&mut self, receipt: TestReceipt, countersigned: bool) {
        let (sender, receiver) = (
            self.index[&receipt.state.account],
            self.index[&receipt.receiver],
        );
        let epoch = receipt.state.epoch;
        let promised = u128::from(receipt.amount);
        self.receipts.push(receipt.clone());
        if self.users[receiver].corrupt {
            return;
        }
        let held = entry(&self.ideal.rcpt, epoch, sender, receiver);
        let reliable =
            countersigned && !self.halted() && epoch >= self.ideal.cur && promised > held;
        let before = self.snapshot();
        let relied = self.users[receiver].receiver.receive(wire(receipt, &()));
        if !reliable {
            assert!(
                relied.is_err(),
                "user {receiver} relies on {promised} from user {sender} in epoch {epoch}"
            );
            self.unchanged(&before, "a receipt its receiver refuses");
            return;
        }
        assert_eq!(
            relied.ok().map(u128::from),
            Some(promised),
            "user {receiver} is promised {promised} by user {sender} in epoch {epoch}"
        );
        let released = self.ideal.release(sender, receiver, epoch, promised);
        assert_eq!(
            released,
            Ok(Some(promised)),
            "user {receiver} relies on {promised} from user {sender} in epoch {epoch}"
        );
    }

    /// Gives each of `receipts`, which the operator countersigned, to its receiver if `deliver`
    /// selects the receiver, and keeps the others for later.
    fn hand(&mut self, receipts: Vec<TestReceipt>, deliver: u8) {
        for receipt in receipts {
            let receiver = self.index[&receipt.receiver];
            if deliver & (1 << receiver) != 0 {
                self.deliver(receipt, true);
            } else {
                self.receipts.push(receipt);
            }
        }
    }

    /// Returns the most `sender` can hold before payouts in the next close: its balance, its
    /// queued deposits, and the most each other user pays it in a state validators accept, one of
    /// the epoch the ledger expects on that user's posted row. A close may settle any of them.
    fn fundable(&self, sender: usize) -> u128 {
        let (epoch, account) = (self.ledger.epoch(), &self.users[sender].account);
        let deposits: u128 = self
            .ideal
            .deposits
            .iter()
            .filter(|(depositor, _)| *depositor == sender)
            .map(|(_, amount)| amount)
            .sum();
        let incoming: u128 = (0..self.users.len())
            .filter(|other| *other != sender)
            .map(|other| {
                let root = self.posted_root(other);
                self.states[other]
                    .iter()
                    .filter(|signed| signed.state.epoch == epoch && signed.state.previous == root)
                    .map(|signed| u128::from(signed.payments.get(account)))
                    .max()
                    .unwrap_or(0)
            })
            .sum();
        self.ideal.bal[sender] + deposits + incoming
    }

    /// A corrupt operator answers the pending request of the honest `sender`.
    fn answer(&mut self, sender: usize, answer: Answer, deliver: u8) {
        if self.halted() || !self.ideal.operator || self.users[sender].corrupt {
            return;
        }
        let Some((_, states)) = self.users[sender].sender.persisted().pending.clone() else {
            return;
        };
        // A close settles only rows their senders can pay, so the operator mostly refuses what
        // it does not expect a close to fund. What a sender pays itself comes back to it in the
        // same close, so only what it pays others counts.
        let account = &self.users[sender].account;
        let outgoing: u128 = states
            .payments
            .iter()
            .filter(|(receiver, _)| *receiver != account)
            .map(|(_, amount)| u128::from(amount))
            .sum();
        let affordable = outgoing <= self.fundable(sender);
        let state = match answer {
            Answer::Current if affordable => states.current,
            Answer::Unfunded => states.current,
            Answer::Next => states.next,
            Answer::Current | Answer::Refuse => {
                self.users[sender]
                    .sender
                    .refused()
                    .expect("the request is pending");
                return;
            }
            Answer::Silent => return,
        };
        let acknowledgement = state.acknowledge(&self.key, &self.namespace);
        self.acknowledgements.push((state, acknowledgement.clone()));

        // The sender refuses a state of an epoch whose post it already resolved.
        if let Ok(receipts) = self.users[sender].sender.acknowledged(&acknowledgement) {
            self.hand(receipts, deliver);
        }
    }

    /// An honest sender signs a request to pay `batch` in `epoch`. A corrupt operator answers it
    /// as `answer` says. An honest operator admits it exactly when the functionality authorizes
    /// it. When it is not admitted, one unit to one of the batch's receivers follows in the
    /// operator's epoch. The sender can pay that unless it can pay nothing, and then nothing
    /// follows.
    fn send_honest(
        &mut self,
        sender: usize,
        epoch: Epoch,
        batch: TestAmounts,
        answer: Answer,
        deliver: u8,
    ) {
        if self.ideal.operator {
            let Some(request) = self.sign(sender, epoch, batch) else {
                return;
            };
            let batch = self.entries(&request.batch);
            self.ideal.send(sender, &batch, epoch, true);
            self.answer(sender, answer, deliver);
            return;
        }
        let receiver = batch.iter().next().map(|(receiver, _)| receiver.clone());
        if self.admit(sender, epoch, batch) || self.ideal.live(sender) == 0 {
            return;
        }
        let receiver = receiver.expect("a batch pays a receiver");
        let unit = TestAmounts::new([(receiver, u64::from(UNIT))]).expect("a batch of one unit");
        assert!(
            self.admit(sender, self.ledger.epoch(), unit),
            "an honest operator refuses one unit that user {sender} can pay"
        );
    }

    /// The honest `sender` signs a request to pay `batch` in `epoch`, and every party sees both
    /// of its states. Returns `None` if the sender signs nothing.
    fn sign(&mut self, sender: usize, epoch: Epoch, batch: TestAmounts) -> Option<TestRequest> {
        let request = self.users[sender].sender.send(epoch, batch).ok()?;
        let (_, states) = self.users[sender]
            .sender
            .persisted()
            .pending
            .clone()
            .expect("the request is pending");
        self.learn(
            sender,
            &states.current,
            &states.payments,
            &request.signatures.current,
        );
        self.learn(
            sender,
            &states.next,
            &states.batch,
            &request.signatures.next,
        );
        Some(request)
    }

    /// An honest sender asks an honest operator to pay `batch` in `epoch`. The operator admits
    /// exactly the requests the functionality authorizes, and every honest receiver then holds
    /// what the functionality says it received. Returns whether the request was admitted. A
    /// request that was not leaves every party as it was.
    fn admit(&mut self, sender: usize, epoch: Epoch, batch: TestAmounts) -> bool {
        let before = self.snapshot();
        let Some(request) = self.sign(sender, epoch, batch) else {
            self.unchanged(&before, "a request its sender does not sign");
            return false;
        };
        let batch = self.entries(&request.batch);
        let expected = self.ideal.send(sender, &batch, epoch, true);
        let request = wire(request, &LIMITS.receivers);
        match (self.operator.accept(&request), expected) {
            (Ok(acknowledgement), Some(outputs)) => {
                let receipts = self.users[sender]
                    .sender
                    .acknowledged(&acknowledgement)
                    .expect("an honest sender records an honest acknowledgement");
                let state = receipts[0].state.clone();
                self.acknowledgements.push((state, acknowledgement));
                let mut received = Vec::new();
                for receipt in receipts {
                    let receiver = self.index[&receipt.receiver];
                    self.receipts.push(receipt.clone());
                    if self.users[receiver].corrupt {
                        continue;
                    }
                    let amount = self.users[receiver]
                        .receiver
                        .receive(wire(receipt, &()))
                        .expect("an honest receiver relies on an honest receipt");
                    received.push((receiver, u128::from(amount)));
                }
                let outputs: Vec<_> = outputs
                    .into_iter()
                    .filter(|(receiver, _)| !self.users[*receiver].corrupt)
                    .collect();
                assert_eq!(received, outputs, "the receipts of user {sender}'s request");
                true
            }
            (Err(_), None) => {
                self.users[sender]
                    .sender
                    .refused()
                    .expect("the request is pending");
                self.unchanged(&before, "a request the operator refuses");
                false
            }
            (real, ideal) => panic!(
                "the operator answered user {sender}'s request with {real:?}, the functionality with {ideal:?}"
            ),
        }
    }

    /// A corrupt sender sends an honest operator a request, changed as `twist` says. Whatever the
    /// operator admits is a request the functionality authorizes on the sender's behalf.
    fn send_corrupt(
        &mut self,
        sender: usize,
        epoch: Epoch,
        batch: TestAmounts,
        deliver: u8,
        twist: Option<Twist>,
    ) {
        // The sender drops what it left pending, so that it can sign.
        let user = &mut self.users[sender];
        let account = user.account.clone();
        let _ = user.sender.refused();
        let Ok(mut request) = user.sender.send(epoch, batch) else {
            return;
        };
        let (_, states) = user.sender.persisted().pending.clone().expect("pending");
        let honest = request.clone();
        let signatures = &honest.signatures;
        self.learn(
            sender,
            &states.current,
            &states.payments,
            &signatures.current,
        );
        self.learn(sender, &states.next, &states.batch, &signatures.next);
        match twist {
            None => {}
            Some(Twist::Replay(pick)) => {
                let earlier = &self.requests[sender];
                if !earlier.is_empty() {
                    request = earlier[usize::from(pick) % earlier.len()].clone();
                }
            }
            Some(Twist::Epoch(next)) => {
                request.epoch = if next {
                    epoch + 1
                } else {
                    epoch.saturating_sub(1)
                };
            }
            Some(Twist::Root) => core::mem::swap(&mut request.previous, &mut request.latest),
            Some(Twist::Restart) => {
                let restarted = TestRequest::states::<Sha256>(
                    epoch,
                    account.clone(),
                    request.batch.clone(),
                    None,
                    &request.previous,
                );
                if let Ok(restarted) = restarted {
                    request = restarted.sign(&self.users[sender].key, &self.namespace);
                    let signatures = request.signatures.clone();
                    self.learn(
                        sender,
                        &restarted.current,
                        &restarted.payments,
                        &signatures.current,
                    );
                    self.learn(sender, &restarted.next, &restarted.batch, &signatures.next);
                }
            }
        }
        self.requests[sender].push(request.clone());

        // A request whose fields no longer match what was signed is admitted nowhere. An earlier
        // request is a choice: the operator may admit it again. Either is followed by the
        // request as signed.
        let changed = matches!(twist, Some(Twist::Epoch(_) | Twist::Root | Twist::Restart))
            && request != honest;
        let attempts = match twist {
            Some(_) if request != honest => vec![request, honest],
            _ => vec![honest],
        };
        for (attempt, request) in attempts.into_iter().enumerate() {
            let request = wire(request, &LIMITS.receivers);
            let before = self.snapshot();
            let admitted = self.operator.payments(&account).cloned();
            let answered = self.operator.accept(&request);
            if answered.is_err() || (changed && attempt == 0) {
                self.unchanged(&before, "a request the operator does not admit");
            }
            if self.operator.payments(&account) != admitted.as_ref() {
                let batch = self.entries(&request.batch);
                let authorized = self.ideal.send(sender, &batch, self.ideal.cur, false);
                assert!(
                    authorized.is_some(),
                    "the operator admitted a batch of user {sender} that the functionality refuses"
                );
            }
            let Ok(acknowledgement) = answered else {
                continue;
            };
            if let Ok(receipts) = self.users[sender].sender.acknowledged(&acknowledgement) {
                let state = receipts[0].state.clone();
                self.acknowledgements.push((state, acknowledgement));
                self.hand(receipts, deliver);
                return;
            }
        }
        let _ = self.users[sender].sender.refused();
    }

    /// A corrupt sender and a corrupt operator sign a state that pays `batch`, and hand out its
    /// receipts.
    fn fabricate(
        &mut self,
        sender: usize,
        epoch: Epoch,
        batch: TestAmounts,
        deliver: u8,
        twist: Option<Twist>,
    ) {
        let user = &self.users[sender];
        let state = State {
            epoch,
            account: user.account.clone(),
            payments: batch.root::<Sha256>(),
            previous: match twist {
                Some(_) => batch.root::<Sha256>(),
                None => self.posted_root(sender),
            },
        };
        let signature = user.key.sign(&self.namespace.state, &state.encode());
        let acknowledgement = state.acknowledge(&self.key, &self.namespace);
        let receivers = batch.iter().map(|(receiver, _)| receiver.clone());
        let receipts =
            TestReceipt::issue::<Sha256>(&state, &signature, &acknowledgement, &batch, receivers)
                .expect("the map commits to the state");
        self.learn(sender, &state, &batch, &signature);
        self.acknowledgements.push((state, acknowledgement));
        self.hand(receipts, deliver);
    }

    fn send(
        &mut self,
        sender: usize,
        batch: &[(u8, Size)],
        shift: Shift,
        answer: Answer,
        deliver: u8,
        twist: Option<Twist>,
    ) {
        if self.halted() {
            return;
        }
        let epoch = self.epoch(shift);
        let Some(batch) = self.batch(sender, batch) else {
            return;
        };
        match (self.users[sender].corrupt, self.ideal.operator) {
            (false, _) => self.send_honest(sender, epoch, batch, answer, deliver),
            (true, false) => self.send_corrupt(sender, epoch, batch, deliver, twist),
            (true, true) => self.fabricate(sender, epoch, batch, deliver, twist),
        }
    }

    fn withdraw(&mut self, user: usize, size: Size, shift: Shift, twist: Option<WithdrawTwist>) {
        if self.halted() {
            return;
        }
        let expected = self.ledger.epoch();
        let epoch = self.epoch(shift);
        let base = u64::try_from(self.ideal.bal[user]).expect("a balance fits an amount");
        let amount = size.resolve(base);
        let corrupt = self.users[user].corrupt;
        let twist = twist.filter(|_| corrupt);
        let tag = self.users[user].tag;
        self.users[user].tag += 1;
        let mut withdrawal =
            TestWithdrawal::sign(&self.users[user].key, &self.namespace, epoch, amount, tag);

        // Every party has seen the request as its user signed it, whatever is sent in its place.
        let mut signed = Some(withdrawal.clone());
        match twist {
            None => {}
            Some(WithdrawTwist::Replay(pick)) => {
                if !self.withdrawals.is_empty() {
                    let pick = usize::from(pick) % self.withdrawals.len();
                    withdrawal = self.withdrawals[pick].clone();
                    signed = None;
                }
            }
            Some(WithdrawTwist::Relabel(next)) => {
                let other = if next { expected + 1 } else { expected - 1 };
                let stale = TestWithdrawal::sign(
                    &self.users[user].key,
                    &self.namespace,
                    other,
                    amount,
                    tag,
                );
                withdrawal = Withdrawal {
                    epoch: expected,
                    ..stale.clone()
                };
                signed = Some(stale);
            }
            Some(WithdrawTwist::Amount) => withdrawal.amount = amount.wrapping_add(1),
        }
        self.withdrawals.extend(signed);
        if self.ideal.operator {
            // A corrupt operator may honor the request of an honest user in its epoch.
            if !corrupt {
                self.ideal.soft_withdraw(user, u128::from(amount), epoch);
            }
            return;
        }

        // An honest operator collects exactly the requests the functionality records, each once:
        // a request as its user signed it is collected exactly when it asks for something in the
        // operator's epoch. A request that does not verify is refused and changes nothing, and so
        // does any other refused request. The request as signed then follows a changed one.
        let before = self.snapshot();
        let held = self.operator.withdrawals().count();
        let withdrawal = wire(withdrawal, &());
        let collected = self.operator.withdraw(withdrawal.clone());
        let new = self.operator.withdrawals().count() > held;
        if matches!(
            twist,
            Some(WithdrawTwist::Relabel(_) | WithdrawTwist::Amount)
        ) {
            assert!(
                collected.is_err(),
                "the operator collects a soft withdrawal of user {user} that does not verify"
            );
        }
        if collected.is_err() {
            self.unchanged(&before, "a soft withdrawal the operator refuses");
        }
        if twist.is_none() {
            assert_eq!(
                collected.is_ok(),
                amount != 0 && epoch == expected,
                "user {user}'s soft withdrawal of {amount} in epoch {epoch}: {collected:?}"
            );
            assert_eq!(collected.is_ok(), new);
        }
        if new {
            let account = self.index[&withdrawal.account];
            let amount = u128::from(withdrawal.amount);
            assert!(self.ideal.soft_withdraw(account, amount, withdrawal.epoch));
        } else if twist.is_some() {
            self.withdraw(user, size, shift, None);
        } else if amount == 0 || epoch != expected {
            // A request of nothing or of another epoch is followed by one unit in this epoch.
            self.withdraw(user, Size::Few(UNIT), Shift::Current, None);
        }
    }

    /// Validators check and settle `close`, the committee certifies it, the ledger posts it, and
    /// the validator applies it. Returns `None` if validators refuse the close.
    async fn post(&mut self, close: &TestClose) -> Option<Posted> {
        let queue = self.ledger.queue();
        let close = &wire(close.clone(), &LIMITS);
        let proposal = match self.validator.verify(close.clone(), &queue).await {
            Ok(proposal) => proposal,
            // Validators refuse a close that fails its check, or whose flows do not settle.
            Err(
                validator::Refusal::Check(_) | validator::Refusal::Settle(SettleError::Flow(_)),
            ) => return None,
            Err(failure) => panic!("a validator failed on a close: {failure:?}"),
        };
        let summary = wire(*proposal.summary(), &());
        let payouts = proposal.payouts().clone();
        let certificate = self.certify(&summary);
        self.ledger
            .post(&mut self.context, &summary, &certificate)
            .expect("the ledger posts a close its validators certified");
        self.validator
            .apply(proposal, &summary.digest())
            .await
            .expect("a validator applies a posted close");

        let mut matrix = zeros(self.users.len());
        for row in close.rows() {
            let sender = self.index[&row.account];
            for (receiver, amount) in self.entries(&row.payments) {
                matrix[sender][receiver] += amount;
            }
        }
        let balances = self.balances().await;
        Some(Posted {
            epoch: summary.epoch,
            deposits: usize::try_from(close.deposits()).expect("a count fits"),
            forced: usize::try_from(close.forced_withdrawals()).expect("a count fits"),
            matrix,
            payouts,
            balances,
        })
    }

    /// Compares what `posted` settled with what the functionality paid and holds, then lets every
    /// honest user resolve and audit the post.
    fn settle(&mut self, posted: &Posted, paid: &[u128]) {
        let epoch = posted.epoch;
        for (user, paid) in paid.iter().enumerate() {
            let payout = posted.payouts.get(&self.users[user].account);
            assert_eq!(
                u128::from(payout),
                *paid,
                "the payout of user {user} in epoch {epoch}"
            );
            if payout != 0 {
                self.owed.push((epoch, user, payout));
            }
        }
        let owed = paid.iter().filter(|paid| **paid != 0).count();
        assert_eq!(posted.payouts.len(), owed, "a payout to an unknown account");
        assert_eq!(
            self.ideal.bal, posted.balances,
            "the balances after epoch {epoch}"
        );

        // Every honest sender resolves the post, and every honest receiver audits it and
        // challenges a close that credits it less than a receipt it holds.
        let root = *self.ledger.matrix(epoch).expect("the close posted");
        let accounts: Vec<_> = self.users.iter().map(|user| user.account.clone()).collect();
        for user in 0..self.users.len() {
            if self.users[user].corrupt {
                continue;
            }
            let account = &accounts[user];
            let opening = self.validator.open(epoch, account, account);
            let opening = wire(opening.expect("a validator opens a close it applied"), &());
            let outcome = self.users[user]
                .sender
                .posted(epoch, &root, &opening)
                .expect("a validator's opening verifies");
            if !self.ideal.operator {
                assert_eq!(
                    outcome,
                    sender::Outcome::Match,
                    "user {user} in epoch {epoch}"
                );
            }
            self.users[user].receiver.posted(epoch);
        }
        'audit: for receiver in 0..self.users.len() {
            if self.users[receiver].corrupt {
                continue;
            }
            for sender in &accounts {
                let opening = self.validator.open(epoch, sender, &accounts[receiver]);
                let opening = wire(opening.expect("a validator opens a close it applied"), &());
                let challenge = self.users[receiver]
                    .receiver
                    .audit(epoch, &root, sender, &opening)
                    .expect("a validator's opening verifies");
                if let Some(challenge) = challenge {
                    self.ledger
                        .challenge(&wire(challenge, &()))
                        .expect("the ledger halts on an honest receiver's challenge");
                    break 'audit;
                }
            }
        }
        assert_eq!(
            self.halted(),
            self.ideal.halted,
            "the halt after epoch {epoch}"
        );
        if self.halted() {
            self.stop();
        }
    }

    /// An honest operator closes its epoch. It closes exactly when the functionality does, and the
    /// close posts. Both refuse a count outside its queue's bounds, no party changes, and the close
    /// with the queue's required counts follows.
    async fn close_honest(&mut self, deposits: u8, forced: u8) {
        let queue = self.ledger.queue();
        let chosen = (
            count(queue.required_deposits, queue.deposits.len(), deposits),
            count(
                queue.required_forced_withdrawals,
                queue.forced_withdrawals.len(),
                forced,
            ),
        );
        let required = (queue.required_deposits, queue.required_forced_withdrawals);
        for (deposits, forced) in [chosen, required] {
            let before = self.snapshot();
            let ideal = self.ideal.close(deposits, forced, None);
            let real = self.operator.close(&queue, deposits as u64, forced as u64);
            match (real, ideal) {
                (Ok((close, _)), Ok(paid)) => {
                    let posted = self.post(&close).await;
                    let posted = posted.expect("validators accept an honest operator's close");
                    self.settle(&posted, &paid);
                    return;
                }
                (Err(_), Err(_)) => self.unchanged(&before, "a close the operator refuses"),
                (real, ideal) => panic!(
                    "the operator closed with {:?}, the functionality with {ideal:?}",
                    real.map(|(close, _)| close.epoch())
                ),
            }
        }
        panic!("an honest operator did not close with the required counts");
    }

    /// Returns the close of `queue`'s epoch a corrupt operator signs over `rows` and
    /// `withdrawals`, or `None` if they encode no close.
    fn sign_close(
        &self,
        queue: &TestQueue,
        rows: Vec<TestRow>,
        mut withdrawals: Vec<TestWithdrawal>,
        deposits: u64,
        forced: u64,
    ) -> Option<TestClose> {
        // Assembly orders the rows and gives the matrix root. It would refuse what follows.
        let (ordered, _) = TestClose::assemble::<Sha256, _>(
            &self.key,
            &self.namespace,
            queue,
            rows,
            Vec::new(),
            queue.required_deposits as u64,
            queue.required_forced_withdrawals as u64,
            &Sequential,
        )
        .ok()?;
        let matrix = ordered.matrix::<Sha256>(&Sequential).root();
        withdrawals.sort_by(|a, b| a.request().cmp(&b.request()));
        withdrawals.dedup_by(|a, b| a.request() == b.request());
        let message = close_message(queue.epoch, &matrix, &withdrawals, deposits, forced);
        let bytes = close_bytes(
            queue.epoch,
            ordered.rows(),
            &withdrawals,
            deposits,
            forced,
            &self.key.sign(&self.namespace.close, &message),
        );
        TestClose::decode_cfg(bytes, &LIMITS).ok()
    }

    /// Returns the close a corrupt operator signs as `forgery` says, with `deviation` or without,
    /// and whether the close carries the deviation. Without a forgery the close has no rows and
    /// no withdrawals.
    fn forge(
        &mut self,
        queue: &TestQueue,
        deposits: u8,
        forced: u8,
        forgery: Option<&Forgery>,
        deviation: Option<Deviation>,
    ) -> Option<(TestClose, bool)> {
        let epoch = queue.epoch;
        let users = self.users.len();
        let within = |required: usize, len: usize, choice: u8| {
            required + usize::from(choice) % (len - required + 1)
        };
        let mut deposits = within(queue.required_deposits, queue.deposits.len(), deposits);
        let mut forced = within(
            queue.required_forced_withdrawals,
            queue.forced_withdrawals.len(),
            forced,
        );
        let Some(forgery) = forgery else {
            let bare = self.sign_close(
                queue,
                Vec::new(),
                Vec::new(),
                deposits as u64,
                forced as u64,
            );
            return bare.map(|close| (close, false));
        };

        // A corrupt user signs a new map for this close.
        let mut fresh = None;
        if let Some((user, batch)) = &forgery.fresh {
            let user = self.user(*user);
            if self.users[user].corrupt
                && let Some(batch) = self.batch(user, batch)
            {
                let state = State {
                    epoch,
                    account: self.users[user].account.clone(),
                    payments: batch.root::<Sha256>(),
                    previous: self.posted_root(user),
                };
                let signature = self.users[user]
                    .key
                    .sign(&self.namespace.state, &state.encode());
                self.learn(user, &state, &batch, &signature);
                fresh = Some(user);
            }
        }

        // Each user's row is one of the states it signed for this epoch on its posted row, or
        // none. A deviation takes a state the user signed for another epoch or on another root.
        let mut rows = Vec::new();
        for user in 0..users {
            let root = self.posted_root(user);
            let signed = &self.states[user];
            let other: Vec<_> = match deviation {
                Some(Deviation::OtherRoot(who, _)) if self.user(who) == user => signed
                    .iter()
                    .filter(|signed| signed.state.epoch == epoch && signed.state.previous != root)
                    .collect(),
                Some(Deviation::OtherEpoch(who, _)) if self.user(who) == user => signed
                    .iter()
                    .filter(|signed| signed.state.epoch != epoch)
                    .collect(),
                _ => Vec::new(),
            };
            let other = match deviation {
                Some(Deviation::OtherRoot(_, pick) | Deviation::OtherEpoch(_, pick)) => {
                    other.get(usize::from(pick) % other.len().max(1)).copied()
                }
                _ => None,
            };
            let forged = match deviation {
                Some(Deviation::ForgedState(who, receiver, amount)) if self.user(who) == user => {
                    self.batch(user, &[(receiver, amount)])
                }
                _ => None,
            };
            if let Some(payments) = forged {
                let state = State {
                    epoch,
                    account: self.users[user].account.clone(),
                    payments: payments.root::<Sha256>(),
                    previous: root,
                };
                let forged = Row {
                    account: state.account.clone(),
                    signature: self.key.sign(&self.namespace.state, &state.encode()),
                    payments,
                };
                rows.push((forged, true));
                continue;
            }
            let row = if other.is_some() {
                other
            } else if fresh == Some(user) {
                signed.last()
            } else {
                // Validators accept a state of this epoch on the sender's posted row.
                let valid: Vec<_> = signed
                    .iter()
                    .filter(|signed| signed.state.epoch == epoch && signed.state.previous == root)
                    .collect();
                let (earlier, pick) = (
                    forgery.rows[user].is_multiple_of(EARLIER_ONE_IN),
                    usize::from(forgery.rows[user] / EARLIER_ONE_IN),
                );
                if earlier {
                    valid.get(pick % (valid.len() + 1)).copied()
                } else {
                    valid.last().copied()
                }
            };
            if let Some(signed) = row {
                let row = Row {
                    account: signed.state.account.clone(),
                    payments: signed.payments.clone(),
                    signature: signed.signature.clone(),
                };
                rows.push((row, other.is_some()));
            }
        }

        // The close carries a choice of the soft withdrawals signed for this epoch. A deviation
        // adds one signed for another epoch.
        let mut withdrawals: Vec<_> = self
            .withdrawals
            .iter()
            .filter(|withdrawal| withdrawal.epoch == epoch && withdrawal.amount != 0)
            .enumerate()
            .filter(|(position, _)| forgery.withdrawals >> (position % u8::BITS as usize) & 1 != 0)
            .map(|(_, withdrawal)| withdrawal.clone())
            .collect();
        let stale: Vec<_> = self
            .withdrawals
            .iter()
            .filter(|withdrawal| withdrawal.epoch != epoch)
            .collect();
        let carried = withdrawals.len();
        match deviation {
            Some(Deviation::StaleWithdrawal(pick)) if !stale.is_empty() => {
                withdrawals.push(stale[usize::from(pick) % stale.len()].clone());
            }
            Some(Deviation::RelabeledWithdrawal(pick)) if !stale.is_empty() => {
                let mut withdrawal = stale[usize::from(pick) % stale.len()].clone();
                withdrawal.epoch = epoch;
                withdrawals.push(withdrawal);
            }
            Some(Deviation::ForgedWithdrawal(who, amount)) => {
                let user = &self.users[self.user(who)];
                let amount = amount.resolve(u64::MAX).max(1);
                let message = TestWithdrawal::message(epoch, &user.account, amount, FORGED_TAG);
                withdrawals.push(Withdrawal {
                    epoch,
                    account: user.account.clone(),
                    amount,
                    tag: FORGED_TAG,
                    signature: self.key.sign(&self.namespace.withdrawal, &message),
                });
            }
            _ => {}
        }

        match deviation {
            Some(Deviation::Count(true)) => {
                deposits = queue
                    .required_deposits
                    .checked_sub(1)
                    .unwrap_or(queue.deposits.len() + 1);
            }
            Some(Deviation::Count(false)) => {
                forced = queue
                    .required_forced_withdrawals
                    .checked_sub(1)
                    .unwrap_or(queue.forced_withdrawals.len() + 1);
            }
            _ => {}
        }

        // A close settles only if every sender holds what its row pays before payouts: its
        // balance, the deposits the close processes, and what the other rows pay it. A row that
        // overdraws is left out, unless it is the deviation.
        let mut funds = self.ideal.bal.clone();
        for deposit in queue.deposits.iter().take(deposits) {
            funds[self.index[&deposit.account]] += u128::from(deposit.amount);
        }
        loop {
            let mut held = funds.clone();
            for (row, _) in &rows {
                for (receiver, amount) in self.entries(&row.payments) {
                    held[receiver] += amount;
                }
            }
            let overdrawn = rows.iter().position(|(row, deviates)| {
                let paid: u128 = self
                    .entries(&row.payments)
                    .iter()
                    .map(|(_, amount)| amount)
                    .sum();
                !deviates && paid > held[self.index[&row.account]]
            });
            let Some(overdrawn) = overdrawn else {
                break;
            };
            rows.remove(overdrawn);
        }

        let deviates = rows.iter().any(|(_, deviates)| *deviates)
            || withdrawals.len() > carried
            || matches!(deviation, Some(Deviation::Count(_)));
        let rows = rows.into_iter().map(|(row, _)| row).collect();
        self.sign_close(queue, rows, withdrawals, deposits as u64, forced as u64)
            .map(|close| (close, deviates))
    }

    /// A corrupt operator closes the epoch. Whatever close posts is one the functionality accepts,
    /// and no close that carries a deviation posts. When validators refuse a close they keep what
    /// they hold, and the operator signs the close again without its deviation, and then without
    /// rows and withdrawals.
    async fn close_corrupt(&mut self, deposits: u8, forced: u8, forgery: &Forgery) {
        let queue = self.ledger.queue();
        let mut attempts = vec![(Some(forgery), None), (None, None)];
        if forgery.deviation.is_some() {
            attempts.insert(0, (Some(forgery), forgery.deviation));
        }
        for (forgery, deviation) in attempts {
            let Some((close, deviates)) = self.forge(&queue, deposits, forced, forgery, deviation)
            else {
                continue;
            };
            let before = (self.snapshot(), self.balances().await);
            let Some(posted) = self.post(&close).await else {
                self.unchanged(&before.0, "a close validators refuse");
                assert_eq!(
                    self.balances().await,
                    before.1,
                    "a refused close and the balances"
                );
                continue;
            };
            let chosen = Some((&posted.matrix, posted.balances.as_slice()));
            let paid = self
                .ideal
                .close(posted.deposits, posted.forced, chosen)
                .unwrap_or_else(|bottom| {
                    panic!(
                        "the close of epoch {} posted, and the functionality refuses it: {bottom:?}",
                        posted.epoch
                    )
                });
            assert!(
                !deviates,
                "the close of epoch {} posted with {deviation:?}",
                posted.epoch
            );
            self.settle(&posted, &paid);
            return;
        }
        panic!("a close without rows and withdrawals did not post");
    }

    async fn close(&mut self, deposits: u8, forced: u8, forgery: &Forgery) {
        if self.halted() {
            return;
        }
        if self.ideal.operator {
            self.close_corrupt(deposits, forced, forgery).await;
        } else {
            self.close_honest(deposits, forced).await;
        }
    }

    /// Returns the receipt for `receiver` from `signed` and `acknowledgement`, if `signed` pays it.
    fn issue(
        &self,
        signed: &Signed,
        acknowledgement: &Signature,
        receiver: usize,
    ) -> Option<TestReceipt> {
        TestReceipt::issue::<Sha256>(
            &signed.state,
            &signed.signature,
            acknowledgement,
            &signed.payments,
            [self.users[receiver].account.clone()],
        )?
        .pop()
    }

    /// A corrupt party gives `receiver` a receipt from one of the states `sender` signed, with the
    /// operator's acknowledgement if it holds one or is the operator. Otherwise the sender signs
    /// in the operator's place, the receiver refuses that receipt, and a receipt of a state the
    /// operator did countersign follows.
    fn receipt(&mut self, sender: usize, receiver: usize, pick: u8) {
        let signed = &self.states[sender];
        if self.halted() || signed.is_empty() {
            return;
        }
        let signed = signed[usize::from(pick) % signed.len()].clone();
        let held = self
            .acknowledgements
            .iter()
            .find(|(state, _)| *state == signed.state)
            .map(|(_, acknowledgement)| acknowledgement.clone());
        let countersigned = match held {
            Some(acknowledgement) => Some(acknowledgement),
            None if self.ideal.operator => {
                Some(signed.state.acknowledge(&self.key, &self.namespace))
            }
            None => None,
        };
        if let Some(acknowledgement) = countersigned {
            if let Some(receipt) = self.issue(&signed, &acknowledgement, receiver) {
                self.deliver(receipt, true);
            }
            return;
        }
        let forged = signed
            .state
            .acknowledge(&self.users[sender].key, &self.namespace);
        if let Some(receipt) = self.issue(&signed, &forged, receiver) {
            self.deliver(receipt, false);
        }
        let account = &self.users[sender].account;
        let latest = self
            .acknowledgements
            .iter()
            .rev()
            .find(|(state, _)| state.account == *account)
            .cloned();
        let Some((state, acknowledgement)) = latest else {
            return;
        };
        let signed = self.states[sender]
            .iter()
            .find(|signed| signed.state == state)
            .cloned();
        if let Some(receipt) =
            signed.and_then(|signed| self.issue(&signed, &acknowledgement, receiver))
        {
            self.deliver(receipt, true);
        }
    }

    /// A corrupt party challenges a posted close with a receipt it holds and an opening of
    /// another pair, then with the opening of the receipt's own pair. A challenge the ledger
    /// refuses changes nothing, and only a corrupt operator's close can halt.
    fn challenge(&mut self, pick: u8, other: Option<(u8, u8)>) {
        if self.halted() || self.receipts.is_empty() {
            return;
        }
        let receipt = self.receipts[usize::from(pick) % self.receipts.len()].clone();
        let own = (receipt.state.account.clone(), receipt.receiver.clone());
        let other = other.map(|(sender, receiver)| {
            (
                self.users[self.user(sender)].account.clone(),
                self.users[self.user(receiver)].account.clone(),
            )
        });
        for (sender, receiver) in other
            .into_iter()
            .filter(|pair| *pair != own)
            .chain([own.clone()])
        {
            let Some(opening) = self.validator.open(receipt.state.epoch, &sender, &receiver) else {
                return;
            };
            let challenge = wire(
                Challenge {
                    receipt: receipt.clone(),
                    opening,
                },
                &(),
            );
            let before = self.snapshot();
            if self.ledger.challenge(&challenge).is_err() {
                self.unchanged(&before, "a challenge the ledger refuses");
                continue;
            }
            self.ideal
                .fault(false)
                .expect("a challenge halted the ledger under an honest operator");
            self.stop();
            return;
        }
    }

    /// The account of an owed payout withdraws it with a validator's proof.
    async fn pay(&mut self, position: usize) {
        let (epoch, user, amount) = self.owed.remove(position);
        let account = self.users[user].account.clone();
        let proof = self.validator.prove_payout(epoch, &account).await;
        let proof = proof
            .expect("a validator reads its payout log")
            .expect("a validator proves a payout it applied");
        let proof = wire(proof, &());
        let applied = self.validator.summary().epoch;
        let withdrawn = self.ledger.withdraw_payout(applied, &proof);
        assert_eq!(
            withdrawn.ok(),
            Some((account, amount)),
            "the payout of user {user} in epoch {epoch}"
        );
        let before = self.snapshot();
        assert!(
            self.ledger.withdraw_payout(applied, &proof).is_err(),
            "the payout of user {user} in epoch {epoch} is paid twice"
        );
        self.unchanged(&before, "a payout withdrawn again");
    }

    async fn payout(&mut self, pick: u8) {
        if !self.owed.is_empty() {
            self.pay(usize::from(pick) % self.owed.len()).await;
        }
    }

    /// Every honest receiver learns that the ledger halted.
    fn stop(&mut self) {
        for user in &mut self.users {
            user.receiver.halt();
        }
    }

    /// The deployment's policy halts the ledger, unless it already halted.
    fn halt(&mut self) {
        if self.halted() {
            return;
        }
        self.ledger.halt();
        self.ideal
            .fault(true)
            .expect("the functionality halts with the ledger");
        self.stop();
    }

    /// Checks the invariants of the proof that hold after every event.
    fn check(&self) {
        let users = self.users.len();
        let ideal = &self.ideal;
        let cur = ideal.cur;

        // I1: the epochs and the halt agree.
        assert_eq!(cur, self.ledger.epoch(), "the epoch");
        assert_eq!(ideal.halted, self.halted(), "the halt");

        // The ledger holds the functionality's balances, the deposits no close processed, and the
        // payouts not yet withdrawn. A halt keeps all of them until they are claimed.
        let held: u128 = ideal.refunds().iter().sum::<u128>()
            + self
                .owed
                .iter()
                .map(|(_, _, amount)| u128::from(*amount))
                .sum::<u128>();
        assert_eq!(u128::from(self.ledger.custody()), held, "the funds held");
        if ideal.halted {
            return;
        }

        // I2: the queues and their required counts agree.
        let queue = self.ledger.queue();
        let deposits: Vec<_> = queue
            .deposits
            .iter()
            .map(|deposit| (self.index[&deposit.account], u128::from(deposit.amount)))
            .collect();
        let forced: Vec<_> = queue
            .forced_withdrawals
            .iter()
            .map(|forced| (self.index[&forced.account], u128::from(forced.amount)))
            .collect();
        assert!(ideal.deposits.iter().eq(&deposits), "the deposit queue");
        assert!(
            ideal.forced.iter().eq(&forced),
            "the forced withdrawal queue"
        );
        assert_eq!(ideal.min_deposits, queue.required_deposits);
        assert_eq!(ideal.min_forced, queue.required_forced_withdrawals);

        // I4: every honest receiver holds the functionality's receipts of each open epoch.
        for (receiver, user) in self.users.iter().enumerate() {
            if user.corrupt {
                continue;
            }
            for epoch in cur..=cur + OPEN_EPOCHS {
                for (sender, account) in self.users.iter().map(|user| &user.account).enumerate() {
                    assert_eq!(
                        u128::from(user.receiver.amount(epoch, account)),
                        entry(&ideal.rcpt, epoch, sender, receiver),
                        "what user {receiver} holds from user {sender} in epoch {epoch}"
                    );
                }
            }
        }
        if ideal.operator {
            return;
        }

        // I3: an honest operator holds the functionality's balances, maps and soft withdrawals,
        // and every honest sender holds its own map.
        assert_eq!(self.operator.epoch(), cur, "the operator's epoch");
        let mut asked = vec![0u128; users];
        for withdrawal in self.operator.withdrawals() {
            asked[self.index[&withdrawal.account]] += u128::from(withdrawal.amount);
        }
        for (sender, user) in self.users.iter().enumerate() {
            let account = &user.account;
            let authorized: Vec<_> = (0..users)
                .map(|receiver| entry(&ideal.auth, cur, sender, receiver))
                .collect();
            assert_eq!(
                u128::from(self.operator.balance(account)),
                ideal.bal[sender]
            );
            assert_eq!(u128::from(self.operator.live(account)), ideal.live(sender));
            assert_eq!(self.row(self.operator.payments(account)), authorized);
            assert_eq!(asked[sender], ideal.wdr(cur, sender));
            if !user.corrupt {
                assert_eq!(self.row(user.sender.payments(cur)), authorized);
            }
        }
    }

    /// The deployment's policy halts the ledger if nothing did, every account claims its refund,
    /// and every owed payout is withdrawn. The ledger then holds nothing.
    async fn exit(&mut self) {
        self.halt();
        self.check();
        let refunds = self.ideal.refunds();
        for (user, refund) in refunds.into_iter().enumerate() {
            let account = self.users[user].account.clone();
            let proof = self.validator.prove(&account).await;
            let proof = proof.expect("a validator proves a balance");
            let proof = proof.map(|proof| wire(proof, &()));
            let claimed = self.ledger.claim(&account, proof.as_ref());
            match (claimed, refund) {
                (Err(ledger::Refusal::NothingToClaim), 0) => {}
                (Ok(paid), refund) if u128::from(paid) == refund => {}
                (claimed, refund) => {
                    panic!(
                        "user {user} claims {claimed:?} where the functionality refunds {refund}"
                    )
                }
            }
            let before = self.snapshot();
            assert!(
                self.ledger.claim(&account, proof.as_ref()).is_err(),
                "user {user} claims twice"
            );
            self.unchanged(&before, "a claim made again");
        }
        while !self.owed.is_empty() {
            self.pay(0).await;
        }
        assert_eq!(self.ledger.custody(), 0, "the funds held after every exit");
    }

    async fn run(mut self, ops: Vec<Op>) {
        self.check();
        for op in ops {
            match op {
                Op::Deposit { user, amount } => self.deposit(self.user(user), amount),
                Op::Force { user, amount } => self.force(self.user(user), amount),
                Op::Send {
                    sender,
                    batch,
                    epoch,
                    answer,
                    deliver,
                    twist,
                } => self.send(self.user(sender), &batch, epoch, answer, deliver, twist),
                Op::Withdraw {
                    user,
                    amount,
                    epoch,
                    twist,
                } => self.withdraw(self.user(user), amount, epoch, twist),
                Op::Close {
                    deposits,
                    forced,
                    forgery,
                } => self.close(deposits, forced, &forgery).await,
                Op::Answer {
                    sender,
                    answer,
                    deliver,
                } => self.answer(self.user(sender), answer, deliver),
                Op::Deliver {
                    sender,
                    receiver,
                    pick,
                } => self.receipt(self.user(sender), self.user(receiver), pick),
                Op::Challenge { pick, other } => self.challenge(pick, other),
                Op::Payout { pick } => self.payout(pick).await,
            }
            self.check();
        }
        self.exit().await;
    }
}

fn fuzz(input: FuzzInput) {
    let FuzzInput {
        operator,
        corrupt,
        ops,
        entropy,
    } = input;
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(entropy));
    deterministic::Runner::new(cfg).start(|context| async move {
        World::new(context, operator, &corrupt).await.run(ops).await;
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
