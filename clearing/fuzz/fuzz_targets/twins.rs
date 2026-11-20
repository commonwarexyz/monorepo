#![no_main]

//! Runs Bajillion with a twinned party next to the ideal clearing functionality.
//!
//! A faulty party here is no attack code. It is two copies of the honest reference role with one
//! key, a primary and a secondary half, and neither knows what the other signed, admitted or
//! holds. What the two halves do together is what a faulty party may do: an operator that
//! countersigns a payment and closes the epoch without it, a user that signs two payment maps on
//! the same root.
//!
//! The input says who is twinned for the whole plan: the operator, and any set of users.
//!
//! - A twinned operator is two reference operators. Each serves the users its mask selects, and
//!   the masks may overlap and change during the plan. A request or a soft withdrawal reaches
//!   every half that serves its user. Either half may close the epoch, and both may release a
//!   close of the same epoch, of which validators check both and the ledger posts one. When a
//!   close posts, the other half reads the post: it takes over the posted balances and row roots
//!   and drops what it had countersigned in the closed epoch.
//! - A twinned user is two reference senders and two reference receivers. Each action says which
//!   half signs, and a receipt goes to one half.
//!
//! The oracle is the functionality of Figure 1 of the Bajillion paper (arXiv:2611.21883), written
//! out as [`Functionality`] in this crate's library. A twinned operator is its corrupt operator and
//! a twinned user is a corrupt user, so the honest users must get what the paper promises whatever
//! the halves do: an honest sender is debited at most what it authorized, an honest receiver is
//! credited what it was promised or the ledger halts, an honest account is paid out at most what it
//! asked for, and after a halt every account gets its finalized balance and unprocessed deposits.
//! The functionality is fed as the paper's simulator feeds it:
//!
//! - an input of an honest party goes to the party and to the functionality;
//! - with an honest operator, a state or a soft withdrawal of a twinned user that the operator
//!   admits is sent to the functionality on that user's behalf;
//! - with a twinned operator, a close that posts is sent with its matrix and the balances the
//!   validators computed, and the functionality must accept it;
//! - a receipt an honest receiver relies on is released, and the functionality must allow it;
//! - a challenge of a twinned receiver that halts the ledger is a fault, which the functionality
//!   allows only when the operator is twinned.
//!
//! Every half is honest code, so each one is also held to what an honest role does: it collects
//! a soft withdrawal exactly when it asks for something in its epoch, it stays at the ledger's
//! epoch, and validators accept every close it assembles. Only the pair is faulty.
//!
//! After every action the invariants of the proof are checked: the epoch, the halt, the balances,
//! the queues and their required counts agree, an honest operator holds the functionality's maps,
//! and every honest receiver holds the functionality's receipts. A message that a party refuses
//! leaves every party as it was. Every plan ends with a halt, every claim and every payout
//! withdrawal, and then the ledger holds nothing.
//!
//! The validators are honest and are not twinned: an honest validator may attest every close it
//! checked, and the ledger posts one summary per epoch, so two halves of a validator do nothing
//! an honest one may not. Messages that need a forged signature, a state on a made-up root or a
//! wrong proof do not arise here; the other clearing targets send those.

use arbitrary::{Arbitrary, Unstructured};
use commonware_clearing::bajillion::{Epoch, Limits, Namespace, SettleError};
use commonware_clearing_fuzz::{
    Committee, MAX_USERS, MIN_USERS, OPEN_EPOCHS, Posted, TestAmounts, TestClose, TestLedger,
    TestOperator, TestReceipt, TestReceiver, TestRequest, TestSender, TestSummary, TestValidator,
    TestWithdrawal, UNIT, VALIDATORS, config,
    functionality::{Functionality, entry, zeros},
    roles::{ledger, sender, validator},
    sampling::{Shift, Size, batch, count, stream, weighted},
    scheme, wire,
};
use commonware_cryptography::{
    Digestible as _, Signer as _,
    certificate::Scheme as _,
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_utils::{Entropy, FuzzRng, iter::NonEmpty, sequence::U64};
use libfuzzer_sys::fuzz_target;
use rand_core::Rng as _;
use std::{collections::BTreeMap, fmt::Debug};

/// The deployment namespace every signature is made in.
const NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_FUZZ_TWINS";

/// Actions a plan draws, enough for several epochs with payments in each.
const MAX_OPS: usize = 96;

/// Close limits that no plan reaches: every user may have a row that pays every user, and every
/// action may be a soft withdrawal followed by one more.
const LIMITS: Limits = Limits {
    rows: MAX_USERS,
    receivers: MAX_USERS,
    withdrawals: 2 * MAX_OPS,
};

/// Bytes of the stream a plan is sampled from, more than the largest plan draws (16 bytes for each
/// action).
const STREAM_BYTES: usize = 1 << 12;
/// One user in this many is twinned, and the operator is twinned in one plan of two.
const TWINNED_USER_ONE_IN: u8 = 3;
const TWINNED_OPERATOR_ONE_IN: u8 = 2;

/// The halves of a twinned party. An honest party is its primary alone.
const PRIMARY: usize = 0;
const SECONDARY: usize = 1;
const HALVES: usize = 2;

/// Weights of the actions, in the order of the [`Op`] variants: Deposit, Force, Send, Withdraw,
/// Close, Split, Resend, Payout. Deposits fund everything else, and several payments go into each
/// close.
const OP_WEIGHTS: [u8; 8] = [10, 3, 28, 6, 10, 3, 4, 4];

#[derive(Debug)]
enum Op {
    /// A user deposits through the ledger.
    Deposit { user: u8, amount: u16 },
    /// A user queues a forced withdrawal on the ledger.
    Force { user: u8, amount: Size },
    /// A sender pays a batch of receivers. `second` says which half of a twinned sender signs,
    /// and `receiving` which half of a twinned receiver gets its receipt.
    Send {
        sender: u8,
        second: bool,
        receiving: bool,
        batch: Vec<(u8, Size)>,
        epoch: Shift,
    },
    /// A user asks for a soft withdrawal. `second` says which half of a twinned user signs.
    Withdraw {
        user: u8,
        second: bool,
        amount: Size,
        epoch: Shift,
    },
    /// The operator closes the epoch the ledger expects, validators check and settle the close,
    /// the committee certifies it, the ledger posts it, and every user resolves and audits it.
    /// `second` says which half of a twinned operator closes. With `both`, the other half
    /// releases its own close of the epoch as well, and validators check it before the first posts.
    Close {
        second: bool,
        both: bool,
        deposits: u8,
        forced: u8,
    },
    /// The halves of a twinned operator serve the users these masks select from now on.
    Split { primary: u8, secondary: u8 },
    /// A sender sends its pending request again to the operator that serves it.
    Resend {
        sender: u8,
        second: bool,
        receiving: bool,
    },
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
                second: u.arbitrary()?,
                receiving: u.arbitrary()?,
                batch: batch(u)?,
                epoch: u.arbitrary()?,
            },
            3 => Self::Withdraw {
                user: u.arbitrary()?,
                second: u.arbitrary()?,
                amount: u.arbitrary()?,
                epoch: u.arbitrary()?,
            },
            4 => Self::Close {
                second: u.arbitrary()?,
                both: u.arbitrary()?,
                deposits: u.arbitrary()?,
                forced: u.arbitrary()?,
            },
            5 => Self::Split {
                primary: u.arbitrary()?,
                secondary: u.arbitrary()?,
            },
            6 => Self::Resend {
                sender: u.arbitrary()?,
                second: u.arbitrary()?,
                receiving: u.arbitrary()?,
            },
            _ => Self::Payout {
                pick: u.arbitrary()?,
            },
        })
    }
}

#[derive(Debug)]
struct FuzzInput {
    /// Whether the operator is twinned, and whether each user is.
    operator: bool,
    twinned: Vec<bool>,
    /// The users each half of a twinned operator serves at first.
    split: [u8; HALVES],
    ops: Vec<Op>,
    entropy: Entropy,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let (stream, entropy) = stream(u, STREAM_BYTES)?;
        let u = &mut Unstructured::new(&stream);

        let users = u.int_in_range(MIN_USERS..=MAX_USERS)?;
        Ok(Self {
            operator: u.ratio(1u8, TWINNED_OPERATOR_ONE_IN)?,
            twinned: (0..users)
                .map(|_| u.ratio(1u8, TWINNED_USER_ONE_IN))
                .collect::<arbitrary::Result<_>>()?,
            split: u.arbitrary()?,
            ops: (0..MAX_OPS)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
            entropy: Unstructured::new(&entropy).arbitrary()?,
        })
    }
}

/// One user: its key, and the reference senders and receivers that act for it. An honest user is
/// its primary sender and receiver. A twinned user has two of each with the one key, and neither
/// half knows what the other signed or holds.
struct User {
    key: PrivateKey,
    account: PublicKey,
    twinned: bool,
    senders: [TestSender; HALVES],
    receivers: [TestReceiver; HALVES],
    /// The tag of each half's next soft withdrawal.
    tags: [u64; HALVES],
}

impl User {
    /// Returns how many halves act for the user.
    const fn halves(&self) -> usize {
        if self.twinned { HALVES } else { 1 }
    }
}

/// What every party holds, to show that a refused message changed nothing.
#[derive(PartialEq)]
struct Snapshot {
    ledger: TestLedger,
    operators: [TestOperator; HALVES],
    senders: Vec<[TestSender; HALVES]>,
    receivers: Vec<[TestReceiver; HALVES]>,
    attested: validator::Persisted<Digest>,
    summary: TestSummary,
}

/// The protocol's parties with their halves, and the functionality next to them.
struct World {
    context: deterministic::Context,
    namespace: Namespace,
    users: Vec<User>,
    index: BTreeMap<PublicKey, usize>,
    /// The reference operators with the operator's one key. An honest operator is the primary
    /// alone. The halves of a twinned operator each serve the users their mask in `split` selects.
    operators: [TestOperator; HALVES],
    split: [u8; HALVES],
    validator: TestValidator,
    schemes: Vec<Committee>,
    ledger: TestLedger,
    ideal: Functionality,
    /// Posted payouts not yet withdrawn, as epoch, account and amount.
    owed: Vec<(Epoch, usize, u64)>,
}

impl World {
    async fn new(
        mut context: deterministic::Context,
        operator: bool,
        twinned: &[bool],
        split: [u8; HALVES],
    ) -> Self {
        let namespace = Namespace::new(NAMESPACE);
        let key = PrivateKey::from_seed(context.next_u64());
        let users: Vec<_> = twinned
            .iter()
            .map(|twinned| {
                let user = PrivateKey::from_seed(context.next_u64());
                let account = user.public_key();
                let sender = || TestSender::new(user.clone(), namespace.clone(), key.public_key());
                let receiver =
                    || TestReceiver::new(account.clone(), namespace.clone(), key.public_key(), 1);
                User {
                    senders: [sender(), sender()],
                    receivers: [receiver(), receiver()],
                    key: user.clone(),
                    account: account.clone(),
                    twinned: *twinned,
                    tags: [0; HALVES],
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
        let desk = || TestOperator::new(key.clone(), namespace.clone(), LIMITS);
        Self {
            operators: [desk(), desk()],
            split,
            ideal: Functionality::new(operator, twinned.to_vec()),
            context,
            namespace,
            users,
            index,
            validator,
            schemes: fixture.schemes,
            ledger,
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

    /// Returns the half of `user` that `second` selects: the primary unless the user is twinned.
    fn half(&self, user: usize, second: bool) -> usize {
        if self.users[user].twinned && second {
            SECONDARY
        } else {
            PRIMARY
        }
    }

    /// Returns how many operators act: both halves of a twinned operator, or the primary alone.
    const fn desks(&self) -> usize {
        if self.ideal.operator { HALVES } else { 1 }
    }

    /// Returns whether operator `desk` serves `user`. An honest operator serves every user, and a
    /// half of a twinned operator serves the users its mask selects.
    fn serves(&self, desk: usize, user: usize) -> bool {
        if self.ideal.operator {
            self.split[desk] >> user & 1 != 0
        } else {
            desk == PRIMARY
        }
    }

    /// Returns what every party holds.
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            ledger: self.ledger.clone(),
            operators: self.operators.clone(),
            senders: self.users.iter().map(|user| user.senders.clone()).collect(),
            receivers: self
                .users
                .iter()
                .map(|user| user.receivers.clone())
                .collect(),
            attested: self.validator.persisted().clone(),
            summary: *self.validator.summary(),
        }
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

    /// Gives `receipt`, which an operator countersigned, to its receiver. The half of a twinned
    /// receiver that `receiving` selects takes it, and may refuse it. An honest receiver relies on exactly the receipts
    /// that name an epoch not yet finalized and promise more than it holds from the sender, and
    /// the functionality then releases the amount the receipt promises. Any other receipt
    /// changes nothing.
    fn deliver(&mut self, receipt: TestReceipt, receiving: bool) {
        let (sender, receiver) = (
            self.index[&receipt.state.account],
            self.index[&receipt.receiver],
        );
        let epoch = receipt.state.epoch;
        let promised = u128::from(receipt.amount);
        let receipt = wire(receipt, &());
        if self.users[receiver].twinned {
            let half = self.half(receiver, receiving);
            let _ = self.users[receiver].receivers[half].receive(receipt);
            return;
        }
        let held = entry(&self.ideal.rcpt, epoch, sender, receiver);
        let reliable = !self.halted() && epoch >= self.ideal.cur && promised > held;
        let before = self.snapshot();
        let relied = self.users[receiver].receivers[PRIMARY].receive(receipt);
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

    /// An honest sender asks an honest operator to pay `batch` in `epoch`. The operator admits
    /// exactly the requests the functionality authorizes, and every honest receiver then holds
    /// what the functionality says it received. Returns whether the request was admitted. A
    /// request that was not leaves every party as it was. The half of a twinned receiver that
    /// `receiving` selects takes its receipt.
    fn admit(&mut self, sender: usize, epoch: Epoch, batch: TestAmounts, receiving: bool) -> bool {
        let before = self.snapshot();
        let Ok(request) = self.users[sender].senders[PRIMARY].send(epoch, batch) else {
            self.unchanged(&before, "a request its sender does not sign");
            return false;
        };
        let batch = self.entries(&request.batch);
        let expected = self.ideal.send(sender, &batch, epoch, true);
        let request = wire(request, &LIMITS.receivers);
        match (self.operators[PRIMARY].accept(&request), expected) {
            (Ok(acknowledgement), Some(outputs)) => {
                let receipts = self.users[sender].senders[PRIMARY]
                    .acknowledged(&acknowledgement)
                    .expect("an honest sender records an honest acknowledgement");
                let mut received = Vec::new();
                for receipt in receipts {
                    let receiver = self.index[&receipt.receiver];
                    let half = self.half(receiver, receiving);
                    let relied = self.users[receiver].receivers[half].receive(wire(receipt, &()));
                    if self.users[receiver].twinned {
                        continue;
                    }
                    let amount = relied.expect("an honest receiver relies on an honest receipt");
                    received.push((receiver, u128::from(amount)));
                }
                let outputs: Vec<_> = outputs
                    .into_iter()
                    .filter(|(receiver, _)| !self.users[*receiver].twinned)
                    .collect();
                assert_eq!(received, outputs, "the receipts of user {sender}'s request");
                true
            }
            (Err(_), None) => {
                self.users[sender].senders[PRIMARY]
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

    /// Gives `request`, pending at half `half` of `sender`, to every operator that serves the
    /// sender. The first acknowledgement goes back to that half, and its receipts go to their
    /// receivers. When every operator that got the request refused it, the half drops it. A
    /// request that no operator got stays pending.
    fn submit(&mut self, sender: usize, half: usize, receiving: bool, request: TestRequest) {
        let request = wire(request, &LIMITS.receivers);
        let account = self.users[sender].account.clone();
        let (mut acknowledgement, mut served) = (None, 0);
        for desk in 0..self.desks() {
            if !self.serves(desk, sender) {
                continue;
            }
            served += 1;
            let before = self.snapshot();
            let admitted = self.operators[desk].payments(&account).cloned();
            let answered = self.operators[desk].accept(&request);
            if answered.is_err() {
                self.unchanged(&before, "a request an operator refuses");
            }

            // What an honest operator admits from a twinned sender is a request the functionality
            // authorizes on the sender's behalf.
            if !self.ideal.operator && self.operators[desk].payments(&account) != admitted.as_ref()
            {
                let batch = self.entries(&request.batch);
                let authorized = self.ideal.send(sender, &batch, self.ideal.cur, false);
                assert!(
                    authorized.is_some(),
                    "the operator admitted a batch of user {sender} that the functionality refuses"
                );
            }
            acknowledgement = acknowledgement.or(answered.ok());
        }
        let Some(acknowledgement) = acknowledgement else {
            if served > 0 {
                self.users[sender].senders[half]
                    .refused()
                    .expect("the request is pending");
            }
            return;
        };

        // An honest sender records the acknowledgement of its pending request. A half of a twinned
        // sender may refuse one.
        let acknowledged = self.users[sender].senders[half].acknowledged(&acknowledgement);
        if !self.users[sender].twinned {
            assert!(
                acknowledged.is_ok(),
                "user {sender} refuses an operator's acknowledgement of its request"
            );
        }
        for receipt in acknowledged.unwrap_or_default() {
            self.deliver(receipt, receiving);
        }
    }

    /// A sender pays `batch` in the epoch `shift` names.
    ///
    /// An honest sender with an honest operator: the operator admits the request exactly when the
    /// functionality authorizes it. When it is not admitted, one unit to one of the batch's
    /// receivers follows in the operator's epoch, which the sender can pay unless it can pay
    /// nothing.
    ///
    /// With a twinned sender or a twinned operator: the half `second` selects signs, the
    /// functionality records what an honest sender asked for, and the request goes to every
    /// operator that serves the sender.
    fn send(
        &mut self,
        sender: usize,
        second: bool,
        receiving: bool,
        batch: &[(u8, Size)],
        shift: Shift,
    ) {
        if self.halted() {
            return;
        }
        let epoch = self.epoch(shift);
        let Some(batch) = self.batch(sender, batch) else {
            return;
        };
        let twinned = self.users[sender].twinned;
        if !twinned && !self.ideal.operator {
            let receiver = batch.iter().next().map(|(receiver, _)| receiver.clone());
            if self.admit(sender, epoch, batch, receiving) || self.ideal.live(sender) == 0 {
                return;
            }
            let receiver = receiver.expect("a batch pays a receiver");
            let unit =
                TestAmounts::new([(receiver, u64::from(UNIT))]).expect("a batch of one unit");
            assert!(
                self.admit(sender, self.ledger.epoch(), unit, receiving),
                "an honest operator refuses one unit that user {sender} can pay"
            );
            return;
        }
        let half = self.half(sender, second);
        let before = self.snapshot();
        let Ok(request) = self.users[sender].senders[half].send(epoch, batch) else {
            self.unchanged(&before, "a request its sender does not sign");
            return;
        };
        if !twinned {
            let batch = self.entries(&request.batch);
            self.ideal.send(sender, &batch, epoch, true);
        }
        self.submit(sender, half, receiving, request);
    }

    /// A sender sends the request its half `second` selects still holds as pending again.
    fn resend(&mut self, sender: usize, second: bool, receiving: bool) {
        if self.halted() {
            return;
        }
        let half = self.half(sender, second);
        let pending = self.users[sender].senders[half].pending().cloned();
        if let Some(request) = pending {
            self.submit(sender, half, receiving, request);
        }
    }

    /// A user asks for a soft withdrawal in the epoch `shift` names, signed by the half `second`
    /// selects, and every operator that serves the user gets it.
    ///
    /// Every operator is honest code: it collects the request exactly when it asks for something
    /// in the operator's epoch, and a refusal changes nothing. An honest operator collects exactly
    /// the requests the functionality records, each once. With a twinned operator the
    /// functionality records what an honest user asked for. A request of nothing or of another
    /// epoch is followed by one unit in this epoch.
    fn withdraw(&mut self, user: usize, second: bool, size: Size, shift: Shift) {
        if self.halted() {
            return;
        }
        let expected = self.ledger.epoch();
        let epoch = self.epoch(shift);
        let base = u64::try_from(self.ideal.bal[user]).expect("a balance fits an amount");
        let amount = size.resolve(base);
        let half = self.half(user, second);
        let twinned = self.users[user].twinned;
        let tag = self.users[user].tags[half];
        self.users[user].tags[half] += 1;
        let withdrawal =
            TestWithdrawal::sign(&self.users[user].key, &self.namespace, epoch, amount, tag);
        let withdrawal = wire(withdrawal, &());
        if self.ideal.operator && !twinned {
            self.ideal.soft_withdraw(user, u128::from(amount), epoch);
        }
        let wanted = amount != 0 && epoch == expected;
        for desk in 0..self.desks() {
            if !self.serves(desk, user) {
                continue;
            }
            let before = self.snapshot();
            let held = self.operators[desk].withdrawals().count();
            let collected = self.operators[desk].withdraw(withdrawal.clone());
            let new = self.operators[desk].withdrawals().count() > held;
            assert_eq!(
                collected.is_ok(),
                wanted,
                "user {user}'s soft withdrawal of {amount} in epoch {epoch}: {collected:?}"
            );
            if collected.is_err() {
                self.unchanged(&before, "a soft withdrawal an operator refuses");
            }
            if self.ideal.operator {
                continue;
            }
            if !twinned {
                assert_eq!(collected.is_ok(), new);
            }
            if new {
                assert!(self.ideal.soft_withdraw(user, u128::from(amount), epoch));
            }
        }
        if !wanted {
            self.withdraw(user, second, Size::Few(UNIT), Shift::Current);
        }
    }

    /// Compares what `posted` settled with what the functionality paid and holds, then lets every
    /// user resolve and audit the post, each half of a twinned user on its own.
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

        // Every sender resolves the post and every receiver learns of it. With an honest
        // operator, the post settles exactly what an honest sender recorded.
        let root = *self.ledger.matrix(epoch).expect("the close posted");
        let accounts: Vec<_> = self.users.iter().map(|user| user.account.clone()).collect();
        for user in 0..self.users.len() {
            for half in 0..self.users[user].halves() {
                let account = &accounts[user];
                let opening = self.validator.open(epoch, account, account);
                let opening = wire(opening.expect("a validator opens a close it applied"), &());
                let outcome = self.users[user].senders[half]
                    .posted(epoch, &root, &opening)
                    .expect("a validator's opening verifies");
                if !self.ideal.operator && !self.users[user].twinned {
                    assert_eq!(
                        outcome,
                        sender::Outcome::Match,
                        "user {user} in epoch {epoch}"
                    );
                }
                self.users[user].receivers[half].posted(epoch);
            }
        }

        // Every receiver audits the post and challenges a close that credits it less than a
        // receipt it holds, the honest receivers first. The ledger halts on an honest receiver's
        // challenge. A half of a twinned receiver can halt only a twinned operator's close, and a
        // challenge the ledger refuses changes nothing.
        'audit: for twinned in [false, true] {
            for receiver in 0..self.users.len() {
                if self.users[receiver].twinned != twinned {
                    continue;
                }
                for half in 0..self.users[receiver].halves() {
                    for sender in &accounts {
                        let opening = self.validator.open(epoch, sender, &accounts[receiver]);
                        let opening =
                            wire(opening.expect("a validator opens a close it applied"), &());
                        let challenge = self.users[receiver].receivers[half]
                            .audit(epoch, &root, sender, &opening)
                            .expect("a validator's opening verifies");
                        let Some(challenge) = challenge else {
                            continue;
                        };
                        let challenge = wire(challenge, &());
                        if !twinned {
                            self.ledger
                                .challenge(&challenge)
                                .expect("the ledger halts on an honest receiver's challenge");
                            break 'audit;
                        }
                        let before = self.snapshot();
                        if self.ledger.challenge(&challenge).is_ok() {
                            self.ideal
                                .fault(false)
                                .expect("a challenge halted the ledger under an honest operator");
                            break 'audit;
                        }
                        self.unchanged(&before, "a challenge the ledger refuses");
                    }
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

    /// An operator closes its epoch: the honest operator, or the half of a twinned operator that
    /// `second` selects.
    ///
    /// An honest operator closes exactly when the functionality does. Every operator is honest
    /// code: it refuses a count outside its queue's bounds, no party changes, and the close with
    /// the queue's required counts follows, which validators accept. A twinned operator's close
    /// that posts is one the functionality accepts, and the other half then reads the post: it
    /// takes over the posted state and drops its own records of the closed epoch. With `both`,
    /// that half first releases its own close of the epoch with the same counts, which validators
    /// check and accept as well, and which does not post.
    async fn close(&mut self, second: bool, both: bool, deposits: u8, forced: u8) {
        if self.halted() {
            return;
        }
        let desk = if self.ideal.operator && second {
            SECONDARY
        } else {
            PRIMARY
        };
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
            let ideal = (!self.ideal.operator).then(|| self.ideal.close(deposits, forced, None));
            let real = self.operators[desk].close(&queue, deposits as u64, forced as u64);
            let (close, paid) = match (real, ideal) {
                (Ok((close, _)), Some(Ok(paid))) => (close, Some(paid)),
                (Ok((close, _)), None) => (close, None),
                (Err(_), Some(Err(_)) | None) => {
                    self.unchanged(&before, "a close the operator refuses");
                    continue;
                }
                (real, ideal) => panic!(
                    "the operator closed with {:?}, the functionality with {ideal:?}",
                    real.map(|(close, _)| close.epoch())
                ),
            };
            if self.ideal.operator && both {
                let other = HALVES - 1 - desk;
                let (sibling, _) = self.operators[other]
                    .close(&queue, deposits as u64, forced as u64)
                    .expect("an operator closes with counts its other half closed with");
                self.validator
                    .verify(wire(sibling, &LIMITS), &queue)
                    .await
                    .expect("validators accept a close an operator assembled");
            }
            let posted = self.post(&close).await;
            let posted = posted.expect("validators accept a close an operator assembled");
            let paid = paid.unwrap_or_else(|| {
                let chosen = Some((&posted.matrix, posted.balances.as_slice()));
                self.ideal
                    .close(posted.deposits, posted.forced, chosen)
                    .unwrap_or_else(|bottom| {
                        panic!(
                            "the close of epoch {} posted, and the functionality refuses it: {bottom:?}",
                            posted.epoch
                        )
                    })
            });
            if self.ideal.operator {
                self.operators[HALVES - 1 - desk] = self.operators[desk].clone();
            }
            self.settle(&posted, &paid);
            return;
        }
        panic!("an operator did not close with the required counts");
    }

    /// Every receiver learns that the ledger halted.
    fn stop(&mut self) {
        for receiver in self.users.iter_mut().flat_map(|user| &mut user.receivers) {
            receiver.halt();
        }
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

        // Every operator admits in the epoch the ledger expects, also each half of a twinned one.
        for (desk, operator) in self.operators.iter().take(self.desks()).enumerate() {
            assert_eq!(operator.epoch(), cur, "the epoch of operator {desk}");
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
            if user.twinned {
                continue;
            }
            for epoch in cur..=cur + OPEN_EPOCHS {
                for (sender, account) in self.users.iter().map(|user| &user.account).enumerate() {
                    assert_eq!(
                        u128::from(user.receivers[PRIMARY].amount(epoch, account)),
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
        let operator = &self.operators[PRIMARY];
        let mut asked = vec![0u128; users];
        for withdrawal in operator.withdrawals() {
            asked[self.index[&withdrawal.account]] += u128::from(withdrawal.amount);
        }
        for (sender, user) in self.users.iter().enumerate() {
            let account = &user.account;
            let authorized: Vec<_> = (0..users)
                .map(|receiver| entry(&ideal.auth, cur, sender, receiver))
                .collect();
            assert_eq!(u128::from(operator.balance(account)), ideal.bal[sender]);
            assert_eq!(u128::from(operator.live(account)), ideal.live(sender));
            assert_eq!(self.row(operator.payments(account)), authorized);
            assert_eq!(asked[sender], ideal.wdr(cur, sender));
            if !user.twinned {
                assert_eq!(self.row(user.senders[PRIMARY].payments(cur)), authorized);
            }
        }
    }

    async fn run(mut self, ops: Vec<Op>) {
        self.check();
        for op in ops {
            match op {
                Op::Deposit { user, amount } => self.deposit(self.user(user), amount),
                Op::Force { user, amount } => self.force(self.user(user), amount),
                Op::Send {
                    sender,
                    second,
                    receiving,
                    batch,
                    epoch,
                } => self.send(self.user(sender), second, receiving, &batch, epoch),
                Op::Withdraw {
                    user,
                    second,
                    amount,
                    epoch,
                } => self.withdraw(self.user(user), second, amount, epoch),
                Op::Close {
                    second,
                    both,
                    deposits,
                    forced,
                } => self.close(second, both, deposits, forced).await,
                Op::Split { primary, secondary } => self.split = [primary, secondary],
                Op::Resend {
                    sender,
                    second,
                    receiving,
                } => self.resend(self.user(sender), second, receiving),
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
        twinned,
        split,
        ops,
        entropy,
    } = input;
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(entropy));
    deterministic::Runner::new(cfg).start(|context| async move {
        World::new(context, operator, &twinned, split)
            .await
            .run(ops)
            .await;
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
