//! A Stateright model of the reference roles under every interleaving of a bounded workload.
//!
//! The roles are the reference implementations in this crate, so each step of the model runs the
//! crate's helpers with real signatures, certificates, and proofs. The validators are one
//! reference validator replayed on fresh databases for each history, so the summaries, balances,
//! proofs, and openings it serves are the real ones.
//!
//! The model keeps its own record of what it sent, what was acknowledged, what each receiver
//! kept, what was deposited, and what was claimed. From that record it predicts the outcome of
//! every step before running it, and it computes every balance and payout the posted closes
//! should produce. A step whose outcome differs from the prediction is a violation. To predict a
//! step, the model reads a role only for the epoch it is in and the queues the ledger holds, and
//! its record determines both.
//!
//! The model explores every order of sends, deliveries, replies, lost replies, duplicated
//! requests, closes with every count the queues allow, posts, resolutions, challenges, payout
//! withdrawals, halts, and claims, within the schedule below, and checks the invariants in every
//! reachable state. Witnesses record that the explored paths reach the flows the crate documents.
//!
//! The schedule has four restrictions. A receiver receives the receipts of an acknowledgement
//! when the sender issues them, so receipts arrive in acknowledgement order, and after the post
//! exactly when the acknowledgement does. Receivers see a post as it happens. The committee
//! certifies a close as the operator releases it. The operator forgets an admission only at a
//! cut, and then the whole row.
//!
//! The last epoch a workload allows stays open, so requests admitted in it never settle. The
//! model does not explore crashes, faulty validators, or forged messages. The restart tests in
//! `payments.rs`, `operator.rs`, and `validator.rs` cover crashes at chosen points.
//!
//! ```text
//!   Workload   sends, resends, lost replies, deposits, soft and forced withdrawals, forgotten
//!              admissions, and halts, each spent in every order the budget allows
//!                                              |
//!   +------------------------------------ World -------------------------------------+
//!   |                                                                                |
//!   |  Sender --- Request, copies ---> Operator --- Close(e) ---> candidate          |
//!   |  send, resolve                   accept, withdraw, close     certified         |
//!   |    |  ^                             |                            |             |
//!   |    |  '<-- Reply: ack or refusal ---'                            | Post        |
//!   |    |           may be lost                                       v             |
//!   |    '--- Receipt ---> Receiver --- Challenge, after audit ---> Ledger           |
//!   |                      receive, audit                           post, challenge, |
//!   |                                                               withdraw_payout, |
//!   |                                                               claim            |
//!   +-------------------------------------|------------------------------------------+
//!                                         | posted closes, candidate
//!                                         v
//!   Committee   one validator replayed on fresh databases per history, memoized. It checks,
//!               settles, and certifies the candidate, and serves balances, balance proofs,
//!               payout proofs, and openings under the last post, which Resolve, Post,
//!               WithdrawPayout, and Claim use.
//! ```
//!
//! The invariants are the properties below. Custody backs the balances, the unprocessed deposits,
//! and the unpaid payouts, so a halt leaves nothing in custody once every claim and payout is paid.
//! Every step had the outcome the model predicted. The operator holds the committee's balances
//! after the last close it released. The committee's balances and posted payouts are what the
//! released closes settle. Every receipt of a posted epoch is honored unless its admission was
//! forgotten. A request is admitted in at most one epoch unless its admission was forgotten.
//! Claimed ranges never overlap or touch.
//!
//! The witnesses each workload requires are listed with it. They cover admission and withdrawals
//! while a close awaits its post, a request admitted in the epoch after its own and its copy
//! refused after its own epoch settled it, a retry acknowledged, a post settling an unacknowledged
//! request, a payout capped by the balance, a repeated payout or claim refused, an omitted row
//! challenged, and claims draining the custody.
//!
//! The workloads reach these parts of the users' and the operator's obligations. The model checks
//! every request's roots and map (S1), the sender verifies acknowledgements (S2), the model
//! decides when a refusal is final from the copies it sent (S4), and senders resolve posts in
//! order (S5).
//!
//! The operator admits on both sides of a cut (O2, O4, O6), checks spendable balances (O3), and
//! applies one close per epoch at its cut (O8). Receivers take receipts in acknowledgement order
//! (R1, R2) and audit each post (R3). The omission workloads break O7 once and show its
//! consequence.
//!
//! The replay runs the validator's checks, applications, and services (V1, V3, V5, V6) from the
//! genesis checkpoint (V2), and the records it writes (V4) are replayed from the model's own
//! copies. The ledger starts at genesis (L1), queues requests (L2), posts (L5), pays each payout
//! once (L6), halts on a challenge (L7), drains its queues at a halt (L8), and pays each claim
//! once (L9).
//!
//! Outside the model are O3's floor and O8's reassembly (the reference operator applies each
//! close at its cut and never has a close rejected), the restart branches of V2 and V4, V3's
//! second read of the queue, the read order of O1, the limits of O5 and V7, and the overflow
//! refusal of L3. L4, L10, and L11 depend on the chain's transfers and callers. No workload
//! reaches the third epoch of payments in which a copy admitted twice would debit its sender
//! twice, so the admission invariant catches the second admission itself.

use super::*;
use crate::roles::{
    ledger::{Halt, Refusal as Posting},
    operator::Refusal as Admitting,
    receiver::Refusal as Receiving,
    sender::{Outcome, Refusal as Sending},
};
use bytes::BufMut;
use commonware_clearing::bajillion::{
    BalanceProof, Challenge, ForcedWithdrawal, Opening, PayoutProof, Receipt, Request, RequestError,
};
use commonware_codec::{EncodeSize, Write};
use commonware_cryptography::{Digest as _, ed25519::Signature};
use commonware_macros::test_group;
use commonware_runtime::Runner as _;
use commonware_utils::sync::Mutex;
use stateright::{Checker, HasDiscoveries, Model, Property, report::WriteReporter};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    hash::{Hash, Hasher},
    sync::{Arc, LazyLock},
};

/// Certificates the model's validators produce.
type Certificate = <scheme::Scheme as certificate::Verifier>::Certificate;

/// How much the workload may still do.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Budget {
    /// Payments the users may still attempt.
    sends: usize,
    /// Copies of a pending request a sender may still send again.
    duplicates: usize,
    /// Replies the network may still lose.
    losses: usize,
    /// Deposits the users may still make.
    deposits: usize,
    /// Soft withdrawals the users may still ask the operator for.
    soft: usize,
    /// Forced withdrawals the users may still ask the ledger for.
    forced: usize,
    /// Admissions the operator may still forget at a cut.
    omissions: usize,
    /// Halts the deployment's policy may still order.
    halts: usize,
}

/// A bounded workload over a deployment, and the faults the network and the operator may inject.
#[derive(Clone, Debug)]
struct Workload {
    /// The users' accounts, each a sender and a receiver.
    accounts: Vec<PublicKey>,
    /// Signing schemes of the validators.
    schemes: Vec<scheme::Scheme>,
    /// Verifier of the validators' certificates.
    verifier: scheme::Scheme,
    /// Deposit queued for each user before the first close.
    funding: Vec<u64>,
    /// Amount of every payment.
    payment: u64,
    /// Amount of every deposit made after genesis and of every withdrawal.
    amount: u64,
    /// Closes the ledger may post. The epoch after the last one stays open.
    epochs: Epoch,
    /// What the workload may do.
    budget: Budget,
    /// Flows the explored paths reached.
    witnessed: Arc<Mutex<BTreeSet<&'static str>>>,
}

/// A value hashed through its encoding, for protocol types without `Hash`.
#[derive(Clone, PartialEq, Eq)]
struct Encoded<T>(T);

impl<T: Encode> Hash for Encoded<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.encode().hash(state);
    }
}

/// A request the sender signed.
#[derive(Clone, PartialEq, Eq, Hash)]
struct Sent {
    /// The user that signed it.
    user: usize,
    /// The signed request.
    request: Encoded<Request<PublicKey, Digest, u64>>,
    /// How many copies the sender sent.
    copies: usize,
}

/// The operator's reply to one delivery of a request.
#[derive(Clone, PartialEq, Eq, Hash)]
struct Reply {
    /// Index of the request in the sent requests.
    request: usize,
    /// The epoch the operator admitted in and its acknowledgement, or `None` for a refusal.
    acknowledgement: Option<(Epoch, Signature)>,
}

/// A close with the requests it processes.
#[derive(Clone, PartialEq, Eq)]
struct Processed {
    close: TestClose,
    deposits: Vec<Deposit<PublicKey, u64>>,
    forced: Vec<ForcedWithdrawal<PublicKey, u64>>,
}

impl Processed {
    /// Returns the queue the close processed, with each required count equal to its length.
    fn queue(&self) -> Queue<PublicKey, u64> {
        Queue {
            epoch: self.close.epoch(),
            deposits: self.deposits.clone(),
            required_deposits: self.deposits.len(),
            forced_withdrawals: self.forced.clone(),
            required_forced_withdrawals: self.forced.len(),
        }
    }
}

/// A posted close with its summary.
#[derive(Clone, PartialEq, Eq)]
struct Posted {
    processed: Processed,
    summary: Summary<Sha256>,
}

// The summary's digest chains every earlier summary and commits to the matrix, the balances, the
// payouts, and the running hashes over the processed requests, so it identifies the post.
impl Hash for Posted {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.summary.digest().hash(state);
    }
}

/// A close the operator released and the committee certified, before it posts.
#[derive(Clone, PartialEq, Eq, Hash)]
struct Candidate {
    /// The released close with the requests it processes.
    processed: Encoded<Processed>,
    /// The close's summary.
    summary: Encoded<Summary<Sha256>>,
    /// The committee's certificate over the summary.
    certificate: Certificate,
    /// Every user's balance once the close applies, as the committee settled it.
    balances: BTreeMap<PublicKey, u64>,
    /// Length of the forced withdrawal queue at the cut.
    forced_queued: usize,
}

impl Write for Processed {
    fn write(&self, buf: &mut impl BufMut) {
        self.close.write(buf);
        self.deposits.write(buf);
        self.forced.write(buf);
    }
}

impl EncodeSize for Processed {
    fn encode_size(&self) -> usize {
        self.close.encode_size() + self.deposits.encode_size() + self.forced.encode_size()
    }
}

/// Everything the deployment and the network hold, with the model's record of it.
#[derive(Clone, PartialEq, Eq, Hash)]
struct World {
    /// The ledger the deployment settles on.
    ledger: TestLedger,
    /// The operator admitting every user.
    operator: TestOperator,
    /// One sender per user.
    senders: Vec<TestSender>,
    /// One receiver per user.
    receivers: Vec<TestReceiver>,
    /// The posted closes, in epoch order.
    posted: Vec<Posted>,
    /// The close the operator released and the committee certified, until it posts.
    candidate: Option<Candidate>,
    /// Copies of sent requests in flight to the operator, in request order.
    requests: Vec<usize>,
    /// Replies in flight to senders.
    replies: Vec<Reply>,
    /// Challenges in flight to the ledger.
    challenges: Vec<Encoded<Challenge<PublicKey, PublicKey, Digest, u64>>>,
    /// Every request signed, in order.
    sent: Vec<Sent>,
    /// The request each sender awaits an answer to.
    pending: Vec<Option<usize>>,
    /// Requests the operator admitted as new states, with the epoch admitted in.
    admitted: BTreeSet<(usize, Epoch)>,
    /// Requests whose state the sender holds as countersigned, with the state's epoch.
    countersigned: BTreeSet<(usize, Epoch)>,
    /// The largest amount each receiver kept a receipt for, by receiver, epoch, and sender.
    held: BTreeMap<(usize, Epoch, usize), u64>,
    /// Last epoch whose post each sender resolved.
    resolved: Vec<Epoch>,
    /// Admissions the operator forgot at a cut, as epoch and user.
    omitted: BTreeSet<(Epoch, usize)>,
    /// Every deposit, in queue order.
    deposited: Vec<(usize, u64)>,
    /// Whether the ledger halted.
    halted: bool,
    /// Users that claimed their balance after the halt.
    claimed: BTreeSet<usize>,
    /// Users that claimed their deposits after the halt.
    claimed_deposits: BTreeSet<usize>,
    /// Payouts paid, by epoch and user.
    withdrawn: BTreeSet<(Epoch, usize)>,
    /// Users whose withdrawal request, forced or soft, the halt dropped unprocessed.
    dropped: BTreeSet<usize>,
    /// The first step whose outcome was not the predicted one, if any.
    violation: Option<String>,
    /// What the workload may still do.
    budget: Budget,
}

impl fmt::Debug for World {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let balances: Vec<_> = (0..self.senders.len())
            .map(|index| self.operator.balance(&account(Widen::widen(index))))
            .collect();
        f.debug_struct("World")
            .field("ledger epoch", &self.ledger.epoch())
            .field("operator epoch", &self.operator.epoch())
            .field("operator balances", &balances)
            .field("custody", &self.ledger.custody())
            .field("halted", &self.ledger.halted())
            .field("posted", &self.posted.len())
            .field(
                "candidate",
                &self
                    .candidate
                    .as_ref()
                    .map(|candidate| candidate.processed.0.close.epoch()),
            )
            .field("pending", &self.pending)
            .field("requests in flight", &self.requests)
            .field("replies in flight", &self.replies.len())
            .field("challenges in flight", &self.challenges.len())
            .field("admitted", &self.admitted)
            .field("countersigned", &self.countersigned)
            .field("held", &self.held)
            .field("resolved", &self.resolved)
            .field("omitted", &self.omitted)
            .field("violation", &self.violation)
            .field("budget", &self.budget)
            .finish()
    }
}

/// A step of the workload or of the network.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Action {
    /// A user deposits through the ledger.
    Deposit { user: usize },
    /// A user asks the ledger for a forced withdrawal.
    ForceWithdraw { user: usize },
    /// A user asks the operator for a soft withdrawal in the close of `epoch`.
    SoftWithdraw { user: usize, epoch: Epoch },
    /// A user signs a request paying another in `epoch`.
    Send {
        user: usize,
        receiver: usize,
        epoch: Epoch,
    },
    /// A sender sends another copy of its pending request.
    Resend { user: usize },
    /// The operator receives a copy of a request.
    Deliver { request: usize },
    /// A sender receives the reply at `index`.
    Reply { index: usize },
    /// The network loses the reply at `index`.
    Lose { index: usize },
    /// The operator closes its epoch processing the given counts, after forgetting one user's
    /// admission if `omit` names one, and the committee certifies the close.
    Close {
        deposits: u64,
        forced: u64,
        omit: Option<usize>,
    },
    /// The ledger posts the certified summary, and every receiver audits it.
    Post,
    /// A sender resolves the next post it has not resolved.
    Resolve { user: usize },
    /// The ledger receives the challenge at `index`.
    Challenge { index: usize },
    /// A user withdraws a payout of a posted close.
    WithdrawPayout { epoch: Epoch, user: usize },
    /// The deployment's policy halts the ledger.
    Halt,
    /// A user claims after the halt.
    Claim { user: usize },
}

/// The summary of a close the committee certified, with every user's balance after it.
type Evaluated = (Summary<Sha256>, BTreeMap<PublicKey, u64>);

/// What the committee derives from the posted closes, and from a candidate close on top of them.
struct Replayed {
    /// Balance of every user after the last post.
    balances: BTreeMap<PublicKey, u64>,
    /// Balance proofs under the last posted balances root, for every positive balance.
    proofs: BTreeMap<PublicKey, BalanceProof<Digest, u64>>,
    /// Epoch of the last post. The payout proofs are under its payouts root.
    applied: Epoch,
    /// Every payout the posted closes owe, by epoch and account, with its proof under the last
    /// posted payouts root.
    payouts: BTreeMap<(Epoch, PublicKey), PayoutProof<PublicKey, Digest, u64>>,
    /// What each sender paid each receiver in each posted close, as the validator opens it.
    openings: BTreeMap<(Epoch, PublicKey, PublicKey), Opening<PublicKey, Digest, u64>>,
    /// The candidate's summary and the balances after it, or why the committee refused it.
    candidate: Option<Result<Evaluated, String>>,
}

/// Replays already computed, by the digest of the accounts, the last post, and the candidate.
static REPLAYS: LazyLock<Mutex<HashMap<Digest, Arc<Replayed>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Replays `posted` on fresh databases for `accounts`, and evaluates `candidate`, a close with the
/// requests it processes, on top of them.
fn replay(
    accounts: &[PublicKey],
    posted: &[Posted],
    candidate: Option<&Processed>,
) -> Arc<Replayed> {
    let mut key = accounts.encode().to_vec();
    key.extend(
        posted
            .last()
            .map_or(Digest::EMPTY, |post| post.summary.digest())
            .encode(),
    );
    if let Some(candidate) = candidate {
        key.extend(candidate.encode());
    }
    let digest = Sha256::hash(&[key.as_slice()]);
    if let Some(replayed) = REPLAYS.lock().get(&digest) {
        return replayed.clone();
    }

    let accounts = accounts.to_vec();
    let posted = posted.to_vec();
    let candidate = candidate.cloned();
    let replayed = deterministic::Runner::default().start(|context| async move {
        // The validator applies every posted close from genesis.
        let mut validator = TestValidator::init(
            context.child("committee"),
            config("committee"),
            Persisted::default(),
            None,
        )
        .await
        .unwrap();
        for post in &posted {
            let processed = &post.processed;
            let proposal = validator
                .verify(processed.close.clone(), &processed.queue())
                .await
                .expect("a posted close must check again from the requests it processed");
            assert_eq!(proposal.summary(), &post.summary);
            validator
                .apply(proposal, &post.summary.digest())
                .await
                .unwrap();
        }

        // It then serves balances, proofs, and openings under the last post.
        let applied = validator.summary().epoch;
        let mut balances = BTreeMap::new();
        let mut proofs = BTreeMap::new();
        let mut payouts = BTreeMap::new();
        let mut openings = BTreeMap::new();
        for account in &accounts {
            balances.insert(account.clone(), validator.balance(account).await.unwrap());
            if let Some(proof) = validator.prove(account).await.unwrap() {
                proofs.insert(account.clone(), proof);
            }
            for post in &posted {
                let epoch = post.summary.epoch;
                if let Some(proof) = validator.prove_payout(epoch, account).await.unwrap() {
                    payouts.insert((epoch, account.clone()), proof);
                }
                for receiver in &accounts {
                    let opening = validator
                        .open(epoch, account, receiver)
                        .expect("a validator must open every posted close it applied");
                    openings.insert((epoch, account.clone(), receiver.clone()), opening);
                }
            }
        }

        // The candidate is checked, settled, and applied as the next post would be.
        let mut evaluated = None;
        if let Some(candidate) = candidate {
            let queue = candidate.queue();
            evaluated = Some(match validator.verify(candidate.close, &queue).await {
                Ok(proposal) => {
                    let summary = *proposal.summary();
                    match validator.apply(proposal, &summary.digest()).await {
                        Ok(()) => {
                            let mut after = BTreeMap::new();
                            for account in &accounts {
                                let balance = validator.balance(account).await.unwrap();
                                after.insert(account.clone(), balance);
                            }
                            Ok((summary, after))
                        }
                        Err(error) => Err(error.to_string()),
                    }
                }
                Err(error) => Err(error.to_string()),
            });
        }
        Replayed {
            balances,
            proofs,
            applied,
            payouts,
            openings,
            candidate: evaluated,
        }
    });
    let replayed = Arc::new(replayed);
    REPLAYS.lock().insert(digest, replayed.clone());
    replayed
}

/// Returns `sender`'s row in `close`, if it has one.
fn row_in<'a>(close: &'a TestClose, sender: &PublicKey) -> Option<&'a Row<PublicKey, u64>> {
    close.rows().iter().find(|row| row.account == *sender)
}

/// Returns the root of `sender`'s row in `close`, or the empty map's root if it has none.
fn row_root_in(close: &TestClose, sender: &PublicKey) -> Digest {
    row_in(close, sender).map_or_else(
        || Amounts::<PublicKey, u64>::empty().root::<Sha256>(),
        |row| row.payments.root::<Sha256>(),
    )
}

/// What the model predicts the operator does with a delivered request.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Countersign it as a new state.
    Admit,
    /// Countersign the latest state again.
    Retry,
    /// Refuse it because the request has no state for the operator's epoch.
    WrongEpoch,
    /// Refuse it because its state does not extend the sender's latest countersigned map on top of
    /// its row in the close before.
    Stale,
    /// Refuse it because the batch exceeds what the sender can still spend.
    Insufficient,
}

/// What a sender's pending request becomes at a post, or `None` with no pending request.
type Resolution = Option<Outcome>;

impl Workload {
    /// Records that the explored paths reached `flow`.
    fn witness(&self, flow: &'static str) {
        self.witnessed.lock().insert(flow);
    }

    /// Returns the user index of `account`.
    fn user_of(&self, account: &PublicKey) -> usize {
        self.accounts
            .iter()
            .position(|candidate| candidate == account)
            .expect("every account must belong to a user")
    }

    /// Returns the committee's view of the posted closes.
    fn snapshot(&self, world: &World) -> Arc<Replayed> {
        replay(&self.accounts, &world.posted, None)
    }

    /// Returns the closes the operator released, posted or not, with the requests they process.
    fn released<'a>(&self, world: &'a World) -> impl Iterator<Item = &'a Processed> {
        world.posted.iter().map(|post| &post.processed).chain(
            world
                .candidate
                .iter()
                .map(|candidate| &candidate.processed.0),
        )
    }

    /// Returns the root of `user`'s row in the released close of `epoch`, or the empty map's root
    /// if that close has no row of the user or no close of `epoch` was released.
    fn row_root_of(&self, world: &World, epoch: Epoch, user: usize) -> Digest {
        self.released(world)
            .find(|processed| processed.close.epoch() == epoch)
            .map_or_else(
                || Amounts::<PublicKey, u64>::empty().root::<Sha256>(),
                |processed| row_root_in(&processed.close, &self.accounts[user]),
            )
    }

    /// Returns the payments root and the previous root of the state of `epoch` the request at
    /// `index` claims.
    fn state_of(&self, world: &World, index: usize, epoch: Epoch) -> (Digest, Digest) {
        let request = &world.sent[index].request.0;
        if request.epoch == epoch {
            (request.payments, request.previous)
        } else {
            assert_eq!(
                request.epoch + 1,
                epoch,
                "a state after the request's epoch must be the next one"
            );
            (request.batch.root::<Sha256>(), request.latest)
        }
    }

    /// Returns the map the batches of `user`'s requests in `states` with `epoch` add up to, in
    /// request order.
    fn map_of(
        &self,
        world: &World,
        states: &BTreeSet<(usize, Epoch)>,
        epoch: Epoch,
        user: usize,
    ) -> Amounts<PublicKey, u64> {
        states
            .iter()
            .filter(|(index, state)| *state == epoch && world.sent[*index].user == user)
            .fold(Amounts::empty(), |map, (index, _)| {
                Amounts::combine(&map, &world.sent[*index].request.0.batch).unwrap()
            })
    }

    /// Returns the latest request of `user` the operator admitted in `epoch`.
    fn latest_admitted(&self, world: &World, epoch: Epoch, user: usize) -> Option<usize> {
        world
            .admitted
            .iter()
            .filter(|(index, admitted)| *admitted == epoch && world.sent[*index].user == user)
            .map(|(index, _)| *index)
            .next_back()
    }

    /// Predicts what the operator does with the request at `index` from the closes it released,
    /// the admissions the model recorded, and the balances the closes settle (O2, O3, O4, O6).
    fn verdict(&self, world: &World, index: usize) -> Verdict {
        let sent = &world.sent[index];
        let request = &sent.request.0;
        let epoch = world.operator.epoch();
        let (payments, previous) = if request.epoch == epoch {
            (request.payments, request.previous)
        } else if request.epoch + 1 == epoch {
            (request.batch.root::<Sha256>(), request.latest)
        } else {
            return Verdict::WrongEpoch;
        };

        // The latest admitted state is countersigned again, and any other state must build on the
        // row of the close before and extend the latest map.
        if let Some(latest) = self.latest_admitted(world, epoch, sent.user)
            && self.state_of(world, latest, epoch) == (payments, previous)
        {
            return Verdict::Retry;
        }
        if previous != self.row_root_of(world, epoch - 1, sent.user) {
            return Verdict::Stale;
        }
        let map = self.map_of(world, &world.admitted, epoch, sent.user);
        if Amounts::combine(&map, &request.batch)
            .unwrap()
            .root::<Sha256>()
            != payments
        {
            return Verdict::Stale;
        }
        let balance = self.settled(world, true).0[sent.user];
        if request.batch.total().unwrap() > balance - map.total().unwrap() {
            return Verdict::Insufficient;
        }
        Verdict::Admit
    }

    /// Returns the root a request of `user` for `epoch` must build on (S1). That is the posted row
    /// root of the epoch before once the sender resolved that post. Until then it is the root of
    /// its latest countersigned state of that epoch, or the empty map's root.
    fn expected_previous(&self, world: &World, epoch: Epoch, user: usize) -> Digest {
        if world.resolved[user] + 1 >= epoch {
            return self.row_root_of(world, epoch - 1, user);
        }
        world
            .countersigned
            .iter()
            .filter(|(index, state)| *state + 1 == epoch && world.sent[*index].user == user)
            .map(|(index, _)| self.state_of(world, *index, epoch - 1).0)
            .next_back()
            .unwrap_or_else(|| Amounts::<PublicKey, u64>::empty().root::<Sha256>())
    }

    /// Predicts what the post of `epoch` does with `user`'s pending request (S5).
    fn resolution(&self, world: &World, epoch: Epoch, user: usize) -> Resolution {
        let index = world.pending[user]?;
        let request = &world.sent[index].request.0;
        let epochs = request.epoch..=request.epoch + 1;
        if epochs.contains(&epoch)
            && self.state_of(world, index, epoch).0 == self.row_root_of(world, epoch, user)
        {
            Some(Outcome::Settled)
        } else if *epochs.end() <= epoch {
            Some(Outcome::Dropped)
        } else {
            Some(Outcome::Pending)
        }
    }

    /// Returns every user's balance and every payout the released closes settle, computed from the
    /// deposits and forced withdrawals they process, their rows, and their soft withdrawals. With
    /// `candidate`, the candidate counts as released.
    fn settled(&self, world: &World, candidate: bool) -> (Vec<u64>, BTreeMap<(Epoch, usize), u64>) {
        let mut balances = vec![0; self.accounts.len()];
        let mut payouts = BTreeMap::new();
        let released = world.posted.iter().map(|post| &post.processed).chain(
            world
                .candidate
                .iter()
                .filter(|_| candidate)
                .map(|candidate| &candidate.processed.0),
        );
        for processed in released {
            let epoch = processed.close.epoch();
            for deposit in &processed.deposits {
                balances[self.user_of(&deposit.account)] += deposit.amount;
            }
            for row in processed.close.rows() {
                balances[self.user_of(&row.account)] -= row.payments.total().unwrap();
                for (receiver, amount) in row.payments.iter() {
                    balances[self.user_of(receiver)] += amount;
                }
            }
            let mut requested = vec![0; self.accounts.len()];
            for withdrawal in processed.close.withdrawals() {
                requested[self.user_of(&withdrawal.account)] += withdrawal.amount;
            }
            for forced in &processed.forced {
                requested[self.user_of(&forced.account)] += forced.amount;
            }
            for (user, requested) in requested.into_iter().enumerate() {
                let payout = requested.min(balances[user]);
                balances[user] -= payout;
                if payout > 0 {
                    payouts.insert((epoch, user), payout);
                }
            }
        }
        (balances, payouts)
    }

    /// Returns the deposits no posted close processed, by user.
    fn unprocessed(&self, world: &World) -> Vec<u64> {
        let processed: usize = world
            .posted
            .iter()
            .map(|post| post.processed.deposits.len())
            .sum();
        let mut unprocessed = vec![0; self.accounts.len()];
        for (user, amount) in &world.deposited[processed..] {
            unprocessed[*user] += amount;
        }
        unprocessed
    }

    /// Records the halt and what the ledger and the operator held back at that moment, where
    /// `forced` are the users with a forced withdrawal queued, and tells every receiver.
    fn halt(&self, world: &mut World, forced: Vec<usize>) {
        world.halted = true;
        for receiver in &mut world.receivers {
            receiver.halt();
        }
        if world.candidate.is_some() {
            self.witness("the ledger halts while a close awaits its post");
        }
        if self.unprocessed(world).iter().any(|amount| *amount > 0) {
            self.witness("the ledger halts with deposits queued");
        }
        if !forced.is_empty() {
            self.witness("the ledger halts with a forced withdrawal queued");
        }
        let soft: Vec<_> = world
            .operator
            .withdrawals()
            .map(|withdrawal| self.user_of(&withdrawal.account))
            .collect();
        if !soft.is_empty() {
            self.witness("the ledger halts with a soft withdrawal collected");
        }
        if world.pending.iter().any(Option::is_some) {
            self.witness("the ledger halts with a request pending");
        }
        world.dropped.extend(forced);
        world.dropped.extend(soft);
    }

    /// Returns the users with a forced withdrawal queued at the ledger.
    fn forced_queued(&self, world: &World) -> Vec<usize> {
        world
            .ledger
            .queue()
            .forced_withdrawals
            .iter()
            .map(|forced| self.user_of(&forced.account))
            .collect()
    }

    /// Signs a soft withdrawal of `user` for the close of `epoch` and gives it to the operator,
    /// which collects it exactly if `epoch` is the one it admits in.
    fn soft_withdraw(&self, world: &mut World, user: usize, epoch: Epoch) {
        world.budget.soft -= 1;
        let withdrawal = Withdrawal::sign(
            &super::user(Widen::widen(user)),
            &namespace(),
            epoch,
            self.amount,
            Widen::widen(world.budget.soft),
        );
        let open = epoch == world.operator.epoch();
        match world.operator.withdraw(withdrawal) {
            Ok(()) if open => {
                if world.candidate.is_some() {
                    self.witness("a soft withdrawal is collected while a close awaits its post");
                }
            }
            Err(Admitting::WrongEpoch { .. }) if !open => {
                self.witness("a soft withdrawal for a closed epoch is refused");
            }
            outcome => world.fail(format!("soft withdrawal: {outcome:?}")),
        }
    }

    /// Delivers `receipt` to its receiver and checks the outcome R1 and R2 predict. The receipt is
    /// kept exactly if its epoch is the one whose close the ledger expects or the one after, the
    /// ledger has not halted, and it promises more than the one held.
    fn receive(&self, world: &mut World, receipt: Receipt<PublicKey, PublicKey, Digest, u64>) {
        let receiver = self.user_of(&receipt.receiver);
        let sender = self.user_of(&receipt.state.account);
        let (epoch, amount) = (receipt.state.epoch, receipt.amount);
        let key = (receiver, epoch, sender);
        let held = world.held.get(&key).copied().unwrap_or(0);
        let outcome = world.receivers[receiver].receive(receipt);
        let predicted = if world.halted {
            matches!(outcome, Err(Receiving::Halted))
        } else if epoch <= world.last_posted() {
            matches!(outcome, Err(Receiving::Closed))
        } else if epoch > world.last_posted() + 2 {
            matches!(outcome, Err(Receiving::Unopened))
        } else if amount <= held {
            matches!(outcome, Err(Receiving::NotIncreasing))
        } else {
            matches!(outcome, Ok(kept) if kept == amount)
                && world.receivers[receiver].amount(epoch, &self.accounts[sender]) == amount
        };
        if predicted {
            if outcome.is_ok() {
                world.held.insert(key, amount);
            }
        } else {
            world.fail(format!(
                "receipt of {amount} from user {sender} in epoch {epoch}: {outcome:?}"
            ));
        }
    }

    /// Checks that `user`'s sender awaits exactly the request the model records as pending.
    fn check_pending(&self, world: &mut World, user: usize) {
        let pending = world.pending[user].map(|index| &world.sent[index].request.0);
        if world.senders[user].pending() != pending {
            world.fail(format!(
                "user {user} awaits a request other than the recorded one"
            ));
        }
    }
}

impl World {
    /// Records the first outcome that was not the predicted one.
    fn fail(&mut self, step: String) {
        if self.violation.is_none() {
            self.violation = Some(step);
        }
    }

    /// Returns the epoch of the last post, or zero before the first.
    fn last_posted(&self) -> Epoch {
        Widen::widen(self.posted.len())
    }

    /// Returns the post of the close of `epoch`, if it posted.
    fn post(&self, epoch: Epoch) -> Option<&Posted> {
        let index = usize::try_from(epoch.checked_sub(1)?).ok()?;
        self.posted.get(index)
    }
}

impl Model for Workload {
    type State = World;
    type Action = Action;

    fn init_states(&self) -> Vec<World> {
        // The ledger starts at the genesis summary over the empty balances root and queues the
        // funding deposits.
        let empty = deterministic::Runner::default().start(|context| async move {
            TestValidator::init(
                context.child("genesis"),
                config("genesis"),
                Persisted::default(),
                None,
            )
            .await
            .unwrap()
            .summary()
            .balances
        });
        let mut ledger = Ledger::new(
            namespace(),
            operator_key().public_key(),
            self.verifier.clone(),
            empty,
        );
        let mut deposited = Vec::new();
        for (user, (account, amount)) in self.accounts.iter().zip(&self.funding).enumerate() {
            if *amount > 0 {
                ledger.deposit(account.clone(), *amount).unwrap();
                deposited.push((user, *amount));
            }
        }
        let users = self.accounts.len();
        vec![World {
            ledger,
            operator: operator(),
            senders: (0..users)
                .map(|index| sender(Widen::widen(index)))
                .collect(),
            receivers: (0..users)
                .map(|index| receiver(Widen::widen(index), 1))
                .collect(),
            posted: Vec::new(),
            candidate: None,
            requests: Vec::new(),
            replies: Vec::new(),
            challenges: Vec::new(),
            sent: Vec::new(),
            pending: vec![None; users],
            admitted: BTreeSet::new(),
            countersigned: BTreeSet::new(),
            held: BTreeMap::new(),
            resolved: vec![0; users],
            omitted: BTreeSet::new(),
            deposited,
            halted: false,
            claimed: BTreeSet::new(),
            claimed_deposits: BTreeSet::new(),
            withdrawn: BTreeSet::new(),
            dropped: BTreeSet::new(),
            violation: None,
            budget: self.budget.clone(),
        }]
    }

    fn actions(&self, world: &World, actions: &mut Vec<Action>) {
        // A state whose last step was not the predicted one is outside the oracles' domain.
        if world.violation.is_some() {
            return;
        }
        let users = self.accounts.len();
        let budget = &world.budget;

        // The workload acts until the ledger halts.
        if !world.halted {
            if budget.deposits > 0 {
                actions.extend((0..users).map(|user| Action::Deposit { user }));
            }
            if budget.forced > 0 {
                actions.extend((0..users).map(|user| Action::ForceWithdraw { user }));
            }
            let mut epochs = vec![world.ledger.epoch()];
            if world.operator.epoch() != world.ledger.epoch() {
                epochs.push(world.operator.epoch());
            }
            if budget.soft > 0 {
                for user in 0..users {
                    for epoch in &epochs {
                        actions.push(Action::SoftWithdraw {
                            user,
                            epoch: *epoch,
                        });
                    }
                }
            }
            if budget.sends > 0 {
                for user in 0..users {
                    if world.pending[user].is_some() {
                        continue;
                    }
                    for receiver in (0..users).filter(|receiver| *receiver != user) {
                        for epoch in &epochs {
                            actions.push(Action::Send {
                                user,
                                receiver,
                                epoch: *epoch,
                            });
                        }
                    }
                }
            }
            if budget.duplicates > 0 {
                for user in 0..users {
                    if world.pending[user].is_some() {
                        actions.push(Action::Resend { user });
                    }
                }
            }
            if world.candidate.is_none()
                && world.operator.epoch() == world.ledger.epoch()
                && world.last_posted() < self.epochs
            {
                let queue = world.ledger.queue();
                for deposits in
                    Widen::widen(queue.required_deposits)..=Widen::widen(queue.deposits.len())
                {
                    for forced in Widen::widen(queue.required_forced_withdrawals)
                        ..=Widen::widen(queue.forced_withdrawals.len())
                    {
                        actions.push(Action::Close {
                            deposits,
                            forced,
                            omit: None,
                        });
                        if budget.omissions > 0 {
                            for user in 0..users {
                                if self
                                    .latest_admitted(world, world.operator.epoch(), user)
                                    .is_some()
                                {
                                    actions.push(Action::Close {
                                        deposits,
                                        forced,
                                        omit: Some(user),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            if budget.halts > 0 {
                actions.push(Action::Halt);
            }
            if world.candidate.is_some() {
                actions.push(Action::Post);
            }
        }

        // The network delivers, and the roles act on what the ledger holds.
        for request in world.requests.iter().copied().collect::<BTreeSet<_>>() {
            actions.push(Action::Deliver { request });
        }
        for index in 0..world.replies.len() {
            actions.push(Action::Reply { index });
            if budget.losses > 0 {
                actions.push(Action::Lose { index });
            }
        }
        let last = world.last_posted();
        for user in 0..users {
            if world.resolved[user] < last {
                actions.push(Action::Resolve { user });
            }
        }
        actions.extend((0..world.challenges.len()).map(|index| Action::Challenge { index }));
        for (epoch, user) in self.settled(world, false).1.keys() {
            actions.push(Action::WithdrawPayout {
                epoch: *epoch,
                user: *user,
            });
        }
        if world.halted {
            actions.extend((0..users).map(|user| Action::Claim { user }));
        }
    }

    fn next_state(&self, world: &World, action: Action) -> Option<World> {
        let mut world = world.clone();
        match action {
            Action::Deposit { user } => {
                world.budget.deposits -= 1;
                if let Err(refusal) = world
                    .ledger
                    .deposit(self.accounts[user].clone(), self.amount)
                {
                    world.fail(format!("deposit: {refusal}"));
                }
                world.deposited.push((user, self.amount));
            }
            Action::ForceWithdraw { user } => {
                world.budget.forced -= 1;
                if let Err(refusal) = world
                    .ledger
                    .withdraw(self.accounts[user].clone(), self.amount)
                {
                    world.fail(format!("forced withdrawal: {refusal}"));
                }
                if world.candidate.is_some() {
                    self.witness(
                        "a forced withdrawal is queued while the last close awaits its post",
                    );
                }
            }
            Action::SoftWithdraw { user, epoch } => self.soft_withdraw(&mut world, user, epoch),
            Action::Send {
                user,
                receiver,
                epoch,
            } => {
                world.budget.sends -= 1;
                let batch = amounts(&[(Widen::widen(receiver), self.payment)]);

                // The sender signs unless it holds a countersigned state of a later epoch (S1).
                let later = world
                    .countersigned
                    .iter()
                    .any(|(index, state)| world.sent[*index].user == user && *state > epoch);
                let request = match world.senders[user].send(epoch, batch.clone()) {
                    Err(Sending::LaterEpoch) if later => return None,
                    Ok(request) if !later => request,
                    outcome => {
                        world.fail(format!("send: {outcome:?} with a later state {later}"));
                        return Some(world);
                    }
                };

                // The states extend the latest countersigned map of the epoch on the roots S1
                // names.
                let map = self.map_of(&world, &world.countersigned, epoch, user);
                let own = self.expected_previous(&world, epoch, user);
                if request.epoch != epoch
                    || request.account != self.accounts[user]
                    || request.batch != batch
                    || request.payments != Amounts::combine(&map, &batch).unwrap().root::<Sha256>()
                    || request.previous != own
                    || request.latest != map.root::<Sha256>()
                {
                    world.fail(format!(
                        "send: the request of user {user} is not the one asked for"
                    ));
                }
                world.pending[user] = Some(world.sent.len());
                world.requests.push(world.sent.len());
                world.sent.push(Sent {
                    user,
                    request: Encoded(request),
                    copies: 1,
                });
            }
            Action::Resend { user } => {
                world.budget.duplicates -= 1;
                let index = world.pending[user].expect("a resend must have a pending request");
                world.sent[index].copies += 1;
                world.requests.push(index);
                world.requests.sort_unstable();
            }
            Action::Deliver { request } => {
                let position = world
                    .requests
                    .iter()
                    .position(|copy| *copy == request)
                    .expect("a delivery must take a copy in flight");
                world.requests.remove(position);
                let verdict = self.verdict(&world, request);
                let sent = world.sent[request].clone();
                let account = self.accounts[sent.user].clone();
                let before = world.operator.payments(&account).cloned();
                let epoch = world.operator.epoch();
                let outcome = world.operator.accept(&sent.request.0);
                let actual = match &outcome {
                    Ok(_) if world.operator.payments(&account).cloned() == before => Verdict::Retry,
                    Ok(_) => Verdict::Admit,
                    Err(Admitting::Request(RequestError::WrongEpoch { .. })) => Verdict::WrongEpoch,
                    Err(Admitting::Request(RequestError::InvalidSignature)) => Verdict::Stale,
                    Err(Admitting::InsufficientBalance) => Verdict::Insufficient,
                    Err(refusal) => {
                        world.fail(format!("deliver: {refusal}"));
                        return Some(world);
                    }
                };
                if actual != verdict {
                    world.fail(format!(
                        "deliver: {actual:?} where {verdict:?} was predicted"
                    ));
                }
                match actual {
                    Verdict::Admit => {
                        if epoch == sent.request.0.epoch + 1 {
                            self.witness("a request is admitted in the epoch after its own");
                        }
                        if world.candidate.is_some() {
                            self.witness(
                                "a payment is admitted while the last close awaits its post",
                            );
                            if epoch == sent.request.0.epoch + 1 {
                                self.witness(
                                    "a next state is admitted while the preceding close awaits its post",
                                );
                            }
                            if world.countersigned.iter().any(|(index, earlier)| {
                                world.sent[*index].user == sent.user && *earlier + 1 == epoch
                            }) {
                                self.witness("a state builds on a map whose close awaits its post");
                            }
                        }
                        if world.omitted.contains(&(epoch - 1, sent.user)) {
                            self.witness("a payment builds on a row the close omitted");
                        }
                        world.admitted.insert((request, epoch));
                    }
                    Verdict::Retry => self.witness("a retried request is acknowledged again"),
                    Verdict::Stale
                        if sent.copies > 1
                            && epoch > sent.request.0.epoch
                            && world.admitted.contains(&(request, sent.request.0.epoch)) =>
                    {
                        self.witness("a copy is refused after its own epoch settled it");
                    }
                    _ => {}
                }
                world.replies.push(Reply {
                    request,
                    acknowledgement: outcome.ok().map(|acknowledgement| (epoch, acknowledgement)),
                });
            }
            Action::Reply { index } => {
                let reply = world.replies.remove(index);
                let sent = world.sent[reply.request].clone();
                let user = sent.user;
                let current = world.pending[user] == Some(reply.request);
                match reply.acknowledgement {
                    // An acknowledgement of the pending request countersigns one of its states
                    // and yields a receipt for each receiver of the batch (S2, S3).
                    Some((epoch, acknowledgement)) => {
                        let outcome = world.senders[user].acknowledged(&acknowledgement);
                        match outcome {
                            Ok(receipts) if current => {
                                let map = self.map_of(&world, &world.countersigned, epoch, user);
                                let expected =
                                    Amounts::combine(&map, &sent.request.0.batch).unwrap();
                                let issued: BTreeMap<_, _> = receipts
                                    .iter()
                                    .map(|receipt| (receipt.receiver.clone(), receipt.amount))
                                    .collect();
                                if issued.len() != receipts.len()
                                    || sent.request.0.batch.iter().any(|(receiver, _)| {
                                        issued.get(receiver) != Some(&expected.get(receiver))
                                    })
                                {
                                    world.fail(format!(
                                        "acknowledgement: user {user} issued other receipts"
                                    ));
                                }
                                world.countersigned.insert((reply.request, epoch));
                                world.pending[user] = None;
                                for receipt in receipts {
                                    self.receive(&mut world, receipt);
                                }
                            }
                            Err(Sending::NotPending | Sending::InvalidAcknowledgement)
                                if !current => {}
                            outcome => world.fail(format!(
                                "acknowledgement of a {} request: {outcome:?}",
                                if current { "pending" } else { "resolved" }
                            )),
                        }
                    }

                    // A refusal is final only for a request sent once (S4).
                    None if current && sent.copies == 1 => {
                        if let Err(refusal) = world.senders[user].refused() {
                            world.fail(format!("refusal: {refusal}"));
                        }
                        world.pending[user] = None;
                        self.witness("a refusal of a request sent once is final");
                    }
                    None => {}
                }
                self.check_pending(&mut world, user);
            }
            Action::Lose { index } => {
                world.budget.losses -= 1;
                world.replies.remove(index);
            }
            Action::Close {
                deposits,
                forced,
                omit,
            } => {
                let queue = world.ledger.queue();
                if deposits < Widen::widen(queue.deposits.len())
                    || forced < Widen::widen(queue.forced_withdrawals.len())
                {
                    self.witness("a close defers a queued request");
                }
                if queue.required_forced_withdrawals > 0 {
                    self.witness(
                        "a close must process a forced withdrawal queued before the last post",
                    );
                }
                if let Some(user) = omit {
                    world.budget.omissions -= 1;
                    world.omitted.insert((world.operator.epoch(), user));
                    world.operator.forget(&self.accounts[user]);
                }
                let close = match world.operator.close(&queue, deposits, forced) {
                    Ok((close, _)) => close,
                    Err(error) => {
                        world.fail(format!("close: {error}"));
                        return Some(world);
                    }
                };
                let (processed_deposits, processed_forced) = queue
                    .prefix(deposits, forced)
                    .expect("a close must process counts the queues allow");
                if close.withdrawals().iter().any(|soft| {
                    processed_forced
                        .iter()
                        .any(|forced| forced.account == soft.account)
                }) {
                    self.witness(
                        "a soft and a forced withdrawal of one account settle in one close",
                    );
                }

                // The committee checks the close against the requests it processes. Requests
                // queued after them cannot change the outcome, because the queues grow only at
                // their tails.
                let processed = Processed {
                    close,
                    deposits: processed_deposits.to_vec(),
                    forced: processed_forced.to_vec(),
                };
                match replay(&self.accounts, &world.posted, Some(&processed))
                    .candidate
                    .as_ref()
                    .unwrap()
                {
                    Ok((summary, balances)) => {
                        world.candidate = Some(Candidate {
                            processed: Encoded(processed),
                            summary: Encoded(*summary),
                            certificate: certify(&self.schemes, summary),
                            balances: balances.clone(),
                            forced_queued: queue.forced_withdrawals.len(),
                        });
                    }
                    Err(error) => world.fail(format!("validators: {error}")),
                }
            }
            Action::Post => {
                let candidate = world
                    .candidate
                    .take()
                    .expect("a post must have a candidate");
                let summary = candidate.summary.0;
                let processed = candidate.processed.0;
                if let Err(refusal) =
                    world
                        .ledger
                        .post(&mut test_rng(), &summary, &candidate.certificate)
                {
                    world.fail(format!("post: {refusal}"));
                    return Some(world);
                }

                // The post requires every request still queued of the next close (L5).
                let queue = world.ledger.queue();
                if queue.required_deposits != queue.deposits.len()
                    || queue.required_forced_withdrawals != queue.forced_withdrawals.len()
                {
                    world.fail("post: the next close is not required to process the queues".into());
                }
                if queue.forced_withdrawals.len() + processed.forced.len() > candidate.forced_queued
                {
                    self.witness(
                        "a forced withdrawal queued after the cut is required of the next close",
                    );
                }
                let epoch = summary.epoch;
                let close = processed.close.clone();
                world.posted.push(Posted { processed, summary });
                if world.last_posted() == self.epochs {
                    self.witness("every epoch posts");
                }

                // Every receiver records the post and audits each receipt it kept for the epoch
                // with the opening the committee serves, challenging a post that credits less
                // (R3, V6).
                let snapshot = self.snapshot(&world);
                for receiver in 0..self.accounts.len() {
                    world.receivers[receiver].posted(epoch);
                    for sender in 0..self.accounts.len() {
                        let Some(held) = world.held.get(&(receiver, epoch, sender)).copied() else {
                            continue;
                        };
                        let (sender_account, receiver_account) =
                            (&self.accounts[sender], &self.accounts[receiver]);
                        let credited = row_in(&close, sender_account)
                            .map_or(0, |row| row.payments.get(receiver_account));
                        let opening = &snapshot.openings
                            [&(epoch, sender_account.clone(), receiver_account.clone())];
                        let outcome = world.receivers[receiver].audit(
                            epoch,
                            &summary.matrix,
                            sender_account,
                            opening,
                        );
                        match outcome {
                            Ok(None) if credited >= held => {}
                            Ok(Some(challenge))
                                if credited < held
                                    && challenge.receipt.amount == held
                                    && challenge.receipt.receiver == *receiver_account
                                    && challenge.receipt.state.account == *sender_account
                                    && challenge.receipt.state.epoch == epoch =>
                            {
                                world.challenges.push(Encoded(challenge));
                            }
                            outcome => world.fail(format!(
                                "audit of user {receiver} against user {sender} in epoch {epoch}: \
                                 {outcome:?}"
                            )),
                        }
                    }
                }
            }
            Action::Resolve { user } => {
                let epoch = world.resolved[user] + 1;
                let account = self.accounts[user].clone();
                let snapshot = self.snapshot(&world);
                let opening = &snapshot.openings[&(epoch, account.clone(), account)];
                let root = world
                    .post(epoch)
                    .expect("the epoch a sender resolves must have posted")
                    .summary
                    .matrix;
                let resolution = self.resolution(&world, epoch, user);
                match world.senders[user].posted(epoch, &root, opening) {
                    Ok(outcome) if outcome == resolution => match outcome {
                        Some(Outcome::Settled) => {
                            let index = world.pending[user].take().unwrap();
                            world.countersigned.insert((index, epoch));
                            self.witness(
                                "a post settles a request before its acknowledgement arrives",
                            );
                        }
                        Some(Outcome::Dropped) => {
                            world.pending[user] = None;
                            self.witness("a post drops a request");
                        }
                        Some(Outcome::Pending) => {
                            self.witness("a post keeps a request pending");
                        }
                        None => {}
                    },
                    outcome => world.fail(format!(
                        "resolve: {outcome:?} where {resolution:?} was predicted"
                    )),
                }
                world.resolved[user] = epoch;
                self.check_pending(&mut world, user);
            }
            Action::Challenge { index } => {
                let challenge = world.challenges.remove(index);
                let forced = self.forced_queued(&world);
                match world.ledger.challenge(&challenge.0) {
                    Ok(()) if !world.halted => {
                        if !matches!(world.ledger.halted(), Some(Halt::Challenge { .. })) {
                            world.fail("challenge: the ledger did not record the halt".into());
                        }
                        self.witness("an omitted payment halts the ledger");
                        self.halt(&mut world, forced);
                    }
                    Err(Posting::Halted) if world.halted => {}
                    outcome => world.fail(format!("challenge: {outcome:?}")),
                }
            }
            Action::WithdrawPayout { epoch, user } => {
                let snapshot = self.snapshot(&world);
                let account = &self.accounts[user];
                let proof = &snapshot.payouts[&(epoch, account.clone())];
                let paid = world.withdrawn.contains(&(epoch, user));
                match world.ledger.withdraw_payout(snapshot.applied, proof) {
                    Ok((to, amount))
                        if !paid && to == *account && amount == proof.payout.amount =>
                    {
                        world.withdrawn.insert((epoch, user));
                        if amount < self.amount {
                            self.witness("a payout is capped by the balance");
                        }
                    }
                    Err(Posting::Withdrawn) if paid => {
                        self.witness("a payout proven again is refused");
                    }
                    outcome => world.fail(format!("payout withdrawal: {outcome:?}")),
                }
            }
            Action::Halt => {
                world.budget.halts -= 1;
                let forced = self.forced_queued(&world);
                world.ledger.halt();
                self.halt(&mut world, forced);
            }
            Action::Claim { user } => {
                // A claim pays the balance of the last post once and the unprocessed deposits
                // once (L9).
                let snapshot = self.snapshot(&world);
                let account = &self.accounts[user];
                let balance = if world.claimed.contains(&user) {
                    0
                } else {
                    self.settled(&world, false).0[user]
                };
                let deposits = if world.claimed_deposits.contains(&user) {
                    0
                } else {
                    self.unprocessed(&world)[user]
                };
                let expected = balance + deposits;
                match world.ledger.claim(account, snapshot.proofs.get(account)) {
                    Ok(paid) if expected > 0 && paid == expected => {
                        if balance > 0 {
                            world.claimed.insert(user);
                            if world.dropped.contains(&user) {
                                self.witness("a withdrawal the halt dropped is claimed as balance");
                            }
                            if world.withdrawn.iter().any(|(_, paid)| *paid == user) {
                                self.witness(
                                    "a user claims its balance after withdrawing a payout",
                                );
                            }
                        }
                        world.claimed_deposits.insert(user);
                        if world.ledger.custody() == 0 {
                            self.witness("claims and withdrawals drain the custody after a halt");
                        }
                    }
                    Err(Posting::NothingToClaim) if expected == 0 => {
                        self.witness("a claim with nothing left to claim is refused");
                    }
                    outcome => {
                        world.fail(format!("claim: {outcome:?} where {expected} was expected"))
                    }
                }
            }
        }
        Some(world)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always(
                "custody backs the balances, the unprocessed deposits, and the unpaid payouts",
                |model: &Self, world: &World| {
                    let (balances, payouts) = model.settled(world, false);
                    let balances: u64 = balances
                        .iter()
                        .enumerate()
                        .filter(|(user, _)| !world.claimed.contains(user))
                        .map(|(_, balance)| balance)
                        .sum();
                    let deposits: u64 = model
                        .unprocessed(world)
                        .iter()
                        .enumerate()
                        .filter(|(user, _)| !world.claimed_deposits.contains(user))
                        .map(|(_, amount)| amount)
                        .sum();
                    let unpaid: u64 = payouts
                        .iter()
                        .filter(|(payout, _)| !world.withdrawn.contains(payout))
                        .map(|(_, amount)| amount)
                        .sum();
                    world.ledger.custody() == balances + deposits + unpaid
                },
            ),
            Property::always(
                "every step had the outcome the model predicted",
                |_: &Self, world: &World| world.violation.is_none(),
            ),
            Property::always(
                "the operator holds the committee's balances after the last close it released",
                |model: &Self, world: &World| {
                    let snapshot = model.snapshot(world);
                    world
                        .candidate
                        .as_ref()
                        .map_or(&snapshot.balances, |candidate| &candidate.balances)
                        .iter()
                        .all(|(account, balance)| world.operator.balance(account) == *balance)
                },
            ),
            Property::always(
                "the committee's balances and posted payouts are what the released closes settle",
                |model: &Self, world: &World| {
                    let snapshot = model.snapshot(world);
                    let (balances, payouts) = model.settled(world, false);
                    let posted = balances.iter().enumerate().all(|(user, balance)| {
                        snapshot.balances[&model.accounts[user]] == *balance
                    }) && payouts.len() == snapshot.payouts.len()
                        && payouts.iter().all(|((epoch, user), amount)| {
                            snapshot
                                .payouts
                                .get(&(*epoch, model.accounts[*user].clone()))
                                .is_some_and(|proof| proof.payout.amount == *amount)
                        });
                    let candidate = world.candidate.as_ref().is_none_or(|candidate| {
                        let (balances, _) = model.settled(world, true);
                        balances.iter().enumerate().all(|(user, balance)| {
                            candidate.balances[&model.accounts[user]] == *balance
                        })
                    });
                    posted && candidate
                },
            ),
            Property::always(
                "every receipt of a posted epoch is honored unless its admission was forgotten",
                |model: &Self, world: &World| {
                    world.held.iter().all(|((receiver, epoch, sender), held)| {
                        let Some(post) = world.post(*epoch) else {
                            return true;
                        };
                        row_in(&post.processed.close, &model.accounts[*sender]).is_some_and(|row| {
                            row.payments.get(&model.accounts[*receiver]) >= *held
                        }) || world.omitted.contains(&(*epoch, *sender))
                    })
                },
            ),
            Property::always(
                "a request is admitted in at most one epoch unless its admission was forgotten",
                |_: &Self, world: &World| {
                    (0..world.sent.len()).all(|request| {
                        let user = world.sent[request].user;
                        let epochs: Vec<_> = world
                            .admitted
                            .iter()
                            .filter(|(admitted, _)| *admitted == request)
                            .map(|(_, epoch)| *epoch)
                            .collect();
                        epochs.len() <= 1
                            || epochs[..epochs.len() - 1]
                                .iter()
                                .all(|epoch| world.omitted.contains(&(*epoch, user)))
                    })
                },
            ),
            Property::always(
                "claimed ranges never overlap or touch",
                |_: &Self, world: &World| {
                    world
                        .ledger
                        .ranges()
                        .windows(2)
                        .all(|pair| pair[0].end < pair[1].start)
                },
            ),
        ]
    }
}

/// Checks every interleaving of `workload`, and that its paths reach each flow in `flows`. The
/// search is depth first because every property is an invariant, and the breadth-first checker
/// would keep the whole frontier of states in memory.
fn check(workload: Workload, flows: &[&'static str]) {
    let witnessed = workload.witnessed.clone();
    let threads = std::thread::available_parallelism().map_or(1, |threads| threads.get());
    let checker = workload
        .checker()
        .threads(threads)
        .finish_when(HasDiscoveries::Any)
        .spawn_dfs()
        .join_and_report(&mut WriteReporter::new(&mut std::io::stdout()));
    checker.assert_properties();
    let witnessed = witnessed.lock();
    for flow in flows {
        assert!(
            witnessed.contains(flow),
            "some path must reach: {flow}, reached {witnessed:?}"
        );
    }
}

/// Returns a workload of two users funded with 3 and 2, paying 1 at a time, depositing and
/// withdrawing 2 at a time, over `epochs` epochs, with `budget`.
fn workload(epochs: Epoch, budget: Budget) -> Workload {
    let (schemes, verifier) = committee(4);
    Workload {
        accounts: (0..2).map(account).collect(),
        schemes,
        verifier,
        funding: vec![3, 2],
        payment: 1,
        amount: 2,
        epochs,
        budget,
        witnessed: Arc::default(),
    }
}

/// A budget that allows nothing.
const NOTHING: Budget = Budget {
    sends: 0,
    duplicates: 0,
    losses: 0,
    deposits: 0,
    soft: 0,
    forced: 0,
    omissions: 0,
    halts: 0,
};

/// One payment attempt around the funding cut is refused, or is admitted and stays pending, and
/// the funding posts. A request the cut overtakes is admitted in the epoch after its own.
#[test]
fn test_model_admits_one_payment() {
    check(
        workload(
            1,
            Budget {
                sends: 1,
                ..NOTHING
            },
        ),
        &[
            "every epoch posts",
            "a request is admitted in the epoch after its own",
            "a next state is admitted while the preceding close awaits its post",
            "a post keeps a request pending",
            "a refusal of a request sent once is final",
        ],
    );
}

/// Two payment attempts over two epochs, a request sent again, and a reply lost settle each
/// payment at most once in every order of sends, deliveries, cuts, posts, and resolutions.
#[test_group("slow")]
#[test]
fn test_model_retries_payments() {
    check(
        workload(
            2,
            Budget {
                sends: 2,
                duplicates: 1,
                losses: 1,
                ..NOTHING
            },
        ),
        &[
            "every epoch posts",
            "a payment is admitted while the last close awaits its post",
            "a request is admitted in the epoch after its own",
            "a copy is refused after its own epoch settled it",
            "a state builds on a map whose close awaits its post",
            "a post keeps a request pending",
            "a post settles a request before its acknowledgement arrives",
            "a post drops a request",
            "a retried request is acknowledged again",
            "a refusal of a request sent once is final",
            "a close defers a queued request",
        ],
    );
}

/// A payment attempt, a deposit, a soft withdrawal, and a forced withdrawal racing a cut over
/// two epochs settle as the queues and the balances dictate.
#[test_group("slow")]
#[test]
fn test_model_races_withdrawals_around_a_cut() {
    check(
        workload(
            2,
            Budget {
                sends: 1,
                deposits: 1,
                soft: 1,
                forced: 1,
                ..NOTHING
            },
        ),
        &[
            "every epoch posts",
            "a payment is admitted while the last close awaits its post",
            "a soft withdrawal is collected while a close awaits its post",
            "a soft withdrawal for a closed epoch is refused",
            "a forced withdrawal is queued while the last close awaits its post",
            "a forced withdrawal queued after the cut is required of the next close",
            "a close defers a queued request",
            "a close must process a forced withdrawal queued before the last post",
            "a soft and a forced withdrawal of one account settle in one close",
            "a payout is capped by the balance",
            "a payout proven again is refused",
        ],
    );
}

/// A payment attempt and a forced withdrawal over two epochs, while the operator may forget an
/// admission and the deployment may halt, end in challenges, claims, and payouts that drain the
/// custody.
#[test_group("slow")]
#[test]
fn test_model_halts_and_claims() {
    check(
        workload(
            2,
            Budget {
                sends: 1,
                forced: 1,
                omissions: 1,
                halts: 1,
                ..NOTHING
            },
        ),
        &[
            "every epoch posts",
            "an omitted payment halts the ledger",
            "the ledger halts with a request pending",
            "the ledger halts with a forced withdrawal queued",
            "claims and withdrawals drain the custody after a halt",
            "a claim with nothing left to claim is refused",
            "a payout proven again is refused",
        ],
    );
}

/// Two payment attempts over three epochs, while the operator may forget an admission, build the
/// second on the posted row even when that row lacks the state the operator countersigned.
#[test_group("slow")]
#[test]
fn test_model_rebuilds_on_the_posted_row() {
    check(
        workload(
            3,
            Budget {
                sends: 2,
                omissions: 1,
                ..NOTHING
            },
        ),
        &[
            "every epoch posts",
            "an omitted payment halts the ledger",
            "a payment builds on a row the close omitted",
            "a state builds on a map whose close awaits its post",
        ],
    );
}

/// A payment attempt, a deposit, a soft withdrawal, and a forced withdrawal over two epochs while
/// the deployment may halt at any point. Whatever the queues and the operator hold at the halt,
/// claims and payout withdrawals recover every unit the ledger holds.
#[test_group("slow")]
#[test]
fn test_model_recovers_funds_after_a_halt() {
    check(
        workload(
            2,
            Budget {
                sends: 1,
                deposits: 1,
                soft: 1,
                forced: 1,
                halts: 1,
                ..NOTHING
            },
        ),
        &[
            "the ledger halts while a close awaits its post",
            "the ledger halts with deposits queued",
            "the ledger halts with a forced withdrawal queued",
            "the ledger halts with a soft withdrawal collected",
            "the ledger halts with a request pending",
            "a withdrawal the halt dropped is claimed as balance",
            "a user claims its balance after withdrawing a payout",
            "claims and withdrawals drain the custody after a halt",
            "a claim with nothing left to claim is refused",
            "a payout proven again is refused",
        ],
    );
}
