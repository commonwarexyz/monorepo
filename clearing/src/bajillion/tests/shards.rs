//! Operators split into shards that cut epochs, assemble closes, and settle them.

use super::*;
use crate::bajillion::{Balances, Cut, Error, Flow, ForcedWithdrawal};
use commonware_codec::{Decode as _, Encode as _, RangeCfg};
use commonware_macros::select;
use commonware_runtime::{Clock as _, Runner as _};
use commonware_utils::{sync::Mutex, test_rng};
use rand_core::Rng as _;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    future::{Future, pending, ready},
    sync::Arc,
    time::Duration,
};

type TestCut = Cut<PublicKey, Digest, u64>;
type TestQueue = Queue<PublicKey, u64>;
type Flows = Vec<(PublicKey, Flow<Digest, u64>)>;
type Shard = Operator<PublicKey, PublicKey, PrivateKey, Sha256, u64, Backend>;

/// What a [Backend]'s writes do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Writes {
    /// Writes apply.
    #[default]
    Apply,
    /// Writes fail without applying.
    Fail,
    /// Writes never complete.
    Hang,
}

#[derive(Clone, Debug, Default)]
struct Contents {
    epoch: Epoch,
    balances: HashMap<PublicKey, u64>,
    writes: Writes,
}

/// A database of balances whose contents outlive the operators on top of it.
#[derive(Clone, Debug, Default)]
struct Backend(Arc<Mutex<Contents>>);

/// Why a [Backend]'s put failed.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum WriteError {
    /// The write failed without applying.
    #[error("write failed")]
    Failed,
    /// The database holds another epoch than the put expected, so the write did not apply.
    #[error("database at another epoch")]
    Conflict,
}

impl Backend {
    /// Returns a database holding the close of `epoch` with `balances`.
    fn new(epoch: Epoch, balances: &[(PublicKey, u64)]) -> Self {
        Self(Arc::new(Mutex::new(Contents {
            epoch,
            balances: balances.iter().cloned().collect(),
            writes: Writes::Apply,
        })))
    }

    /// Returns the epoch the database holds.
    fn epoch(&self) -> Epoch {
        self.0.lock().epoch
    }

    /// Returns `account`'s balance in the database.
    fn balance(&self, account: &PublicKey) -> u64 {
        self.0.lock().balances.get(account).copied().unwrap_or(0)
    }

    /// Returns a database holding a copy of these contents.
    fn fork(&self) -> Self {
        Self(Arc::new(Mutex::new(self.0.lock().clone())))
    }

    /// Makes later writes do `writes`.
    fn set_writes(&self, writes: Writes) {
        self.0.lock().writes = writes;
    }

    /// Copies `account`'s balance from `from`, as a deployment moving the account would.
    fn copy(&self, from: &Self, account: &PublicKey) {
        let balance = from.0.lock().balances.get(account).copied();
        let mut contents = self.0.lock();
        match balance {
            Some(balance) => contents.balances.insert(account.clone(), balance),
            None => contents.balances.remove(account),
        };
    }
}

impl Balances<PublicKey, u64> for Backend {
    type Error = WriteError;

    fn get(
        &self,
        accounts: &[PublicKey],
    ) -> impl Future<Output = Result<(Epoch, Vec<u64>), Self::Error>> + Send {
        let contents = self.0.lock();
        let balances = accounts
            .iter()
            .map(|account| contents.balances.get(account).copied().unwrap_or(0))
            .collect();
        ready(Ok((contents.epoch, balances)))
    }

    async fn put(
        self,
        previous: Epoch,
        epoch: Epoch,
        balances: &[(PublicKey, u64)],
    ) -> Result<Self, Self::Error> {
        let writes = self.0.lock().writes;
        match writes {
            Writes::Apply => {}
            Writes::Fail => return Err(WriteError::Failed),
            Writes::Hang => pending::<()>().await,
        }
        {
            let mut contents = self.0.lock();
            if contents.epoch != previous {
                return Err(WriteError::Conflict);
            }
            for (account, balance) in balances {
                if *balance == 0 {
                    contents.balances.remove(account);
                } else {
                    contents.balances.insert(account.clone(), *balance);
                }
            }
            contents.epoch = epoch;
        }
        Ok(self)
    }
}

/// Returns whether `result` failed because the database moved to another epoch.
fn conflicted(result: &Result<(), Error>) -> bool {
    matches!(
        result,
        Err(Error::Store(error)) if error.downcast_ref() == Some(&WriteError::Conflict)
    )
}

/// Returns which of `shards` shards the router assigns `account` unless it moved, partitioning
/// accounts by key as a deployment would.
fn assigned(account: &PublicKey, shards: usize) -> usize {
    usize::from(account.as_ref()[0]) % shards
}

/// Returns the first `count` users the router assigns shard `shard` of `shards`.
fn served(shard: usize, shards: usize, count: usize) -> Vec<u64> {
    (0..)
        .filter(|index| assigned(&account(*index), shards) == shard)
        .take(count)
        .collect()
}

/// Starts a shard on top of `backend`.
async fn start(backend: Backend, cut: Option<&TestCut>) -> Result<Shard, Error> {
    Shard::init(operator_key(), namespace(), LIMITS, backend, [], cut).await
}

/// Returns a queue for the close of `epoch` holding a forced withdrawal for each
/// `(index, amount)`, none of which the close must process.
fn forced(epoch: Epoch, entries: &[(u64, u64)]) -> TestQueue {
    Queue {
        forced_withdrawals: entries
            .iter()
            .map(|(index, amount)| ForcedWithdrawal {
                account: account(*index),
                amount: *amount,
            })
            .collect(),
        ..deposits(epoch, &[])
    }
}

/// Assembles the close of `cuts` as the operator's builder would, processing every request queued
/// in `queue`.
fn assemble(queue: &TestQueue, cuts: Vec<TestCut>) -> Result<(TestClose, Flows), Error> {
    TestClose::assemble::<Sha256, _>(
        &operator_key(),
        &namespace(),
        queue,
        queue.deposits.len() as u64,
        queue.forced_withdrawals.len() as u64,
        cuts,
    )
}

/// An operator split into shards that keep their balances in separate backends, with what the
/// deployment persists to restart them.
struct Shards {
    /// The shards, by index.
    shards: Vec<Shard>,
    /// The backend each shard restarts from.
    backends: Vec<Backend>,
    /// The last cut each shard took.
    cuts: Vec<Option<TestCut>>,
    /// Accounts routed away from the shard [assigned] gives them.
    moved: HashMap<PublicKey, usize>,
    /// Accounts that move at the next cut.
    moving: HashMap<PublicKey, usize>,
}

impl Shards {
    async fn new(count: usize) -> Self {
        let backends: Vec<_> = (0..count).map(|_| Backend::default()).collect();
        let mut shards = Vec::with_capacity(count);
        for backend in &backends {
            shards.push(start(backend.clone(), None).await.unwrap());
        }
        Self {
            shards,
            backends,
            cuts: vec![None; count],
            moved: HashMap::new(),
            moving: HashMap::new(),
        }
    }

    /// Returns the index of the shard serving `account` in the current epoch.
    fn serving(&self, account: &PublicKey) -> usize {
        self.moved
            .get(account)
            .copied()
            .unwrap_or_else(|| assigned(account, self.shards.len()))
    }

    /// Returns the shard serving `account`.
    fn of(&mut self, account: &PublicKey) -> &mut Shard {
        let serving = self.serving(account);
        &mut self.shards[serving]
    }

    async fn balance(&self, account: &PublicKey) -> u64 {
        self.shards[self.serving(account)]
            .balance(account)
            .await
            .unwrap()
    }

    async fn live(&self, account: &PublicKey) -> Result<u64, Error> {
        self.shards[self.serving(account)].live(account).await
    }

    /// Cuts every shard's epoch, processing every request queued in `queue`, and persists the
    /// cuts. Each shard is given the processed forced withdrawals of the accounts it serves, and
    /// the accounts in `moving` move at the cut.
    fn cut(&mut self, queue: &TestQueue) -> Vec<TestCut> {
        let processed: Vec<Vec<_>> = (0..self.shards.len())
            .map(|index| {
                queue
                    .forced_withdrawals
                    .iter()
                    .filter(|withdrawal| self.serving(&withdrawal.account) == index)
                    .cloned()
                    .collect()
            })
            .collect();
        let mut cuts = Vec::new();
        for ((shard, persisted), processed) in
            self.shards.iter_mut().zip(&mut self.cuts).zip(processed)
        {
            let cut = shard
                .cut(
                    queue.epoch,
                    queue.deposits.len() as u64,
                    queue.forced_withdrawals.len() as u64,
                    &processed,
                )
                .unwrap();
            *persisted = Some(cut.clone());
            cuts.push(cut);
        }
        self.moved.extend(self.moving.drain());
        cuts
    }

    /// Assembles the close of `cuts` as the operator's builder would.
    fn assemble(&self, queue: &TestQueue, cuts: Vec<TestCut>) -> (TestClose, Flows) {
        assemble(queue, cuts).unwrap()
    }

    /// Splits `flows` by the shard serving each account in the current epoch.
    fn route(&self, flows: Flows) -> Vec<Flows> {
        let mut routed = vec![Vec::new(); self.shards.len()];
        for (account, flow) in flows {
            routed[self.serving(&account)].push((account, flow));
        }
        routed
    }

    /// Settles `epoch` at every shard, routing each flow to the shard serving its account.
    async fn settle(&mut self, epoch: Epoch, flows: Flows) {
        for (index, flows) in self.route(flows).into_iter().enumerate() {
            self.try_settle(index, epoch, flows).await.unwrap();
        }
    }

    /// Settles `epoch` at shard `index` with `flows`.
    async fn try_settle(&mut self, index: usize, epoch: Epoch, flows: Flows) -> Result<(), Error> {
        self.shards[index].settle(epoch, flows).await
    }

    /// Starts shard `index` again from `backend` and the state the deployment persisted.
    async fn start(&self, index: usize, backend: Backend) -> Shard {
        start(backend, self.cuts[index].as_ref()).await.unwrap()
    }

    /// Restarts shard `index` from its backend.
    async fn restart(&mut self, index: usize) {
        self.shards[index] = self.start(index, self.backends[index].clone()).await;
    }
}

/// Returns a sender for each of `users`.
fn senders(users: &[u64]) -> HashMap<u64, TestSender> {
    users.iter().map(|index| (*index, sender(*index))).collect()
}

/// Has user `from` pay user `to` `amount` in `epoch` through the shard serving it.
async fn pay(
    shards: &mut Shards,
    senders: &mut HashMap<u64, TestSender>,
    epoch: Epoch,
    from: u64,
    to: u64,
    amount: u64,
) -> Result<(), Error> {
    let sender = senders.get_mut(&from).unwrap();
    let request = sender.send(epoch, amounts(&[(to, amount)]), false).unwrap();
    match shards.of(&account(from)).accept(&request).await {
        Ok(acknowledgement) => {
            sender.acknowledged(&acknowledgement).unwrap();
            Ok(())
        }
        Err(error) => {
            sender.refused().unwrap();
            Err(error)
        }
    }
}

/// Cuts every shard, assembles the close, and has every validator check it and the ledger post
/// it. Returns the epoch closed and the flows the shards settle.
async fn close(
    deployment: &mut Deployment,
    context: &mut deterministic::Context,
    shards: &mut Shards,
) -> (Epoch, Flows) {
    let queue = deployment.ledger.queue();
    let cuts = shards.cut(&queue);
    let (close, flows) = shards.assemble(&queue, cuts);
    let proposals = deployment.verify(&close).await;
    deployment.post(context, proposals).await;
    (close.epoch(), flows)
}

/// Closes and settles one epoch at every shard.
async fn close_and_settle(
    deployment: &mut Deployment,
    context: &mut deterministic::Context,
    shards: &mut Shards,
) {
    let (epoch, flows) = close(deployment, context, shards).await;
    shards.settle(epoch, flows).await;
}

/// Closes and settles one epoch at every shard, processing every request queued in `queue`,
/// without validators.
async fn close_queue(shards: &mut Shards, queue: &TestQueue) -> Flows {
    let cuts = shards.cut(queue);
    let (_, flows) = shards.assemble(queue, cuts);
    shards.settle(queue.epoch, flows.clone()).await;
    flows
}

/// Checks that the shard serving each of `users` holds the balance every validator holds, and that
/// the ledger holds exactly those balances and the deposits no close processed.
async fn check_balances(deployment: &Deployment, shards: &Shards, users: &[u64]) {
    let mut total = 0;
    for index in users {
        let expected = shards.balance(&account(*index)).await;
        for validator in &deployment.validators {
            assert_eq!(validator.balance(&account(*index)).await.unwrap(), expected);
        }
        total += expected;
    }
    let unprocessed: u64 = deployment
        .ledger
        .queue()
        .deposits
        .iter()
        .map(|deposit| deposit.amount)
        .sum();
    assert_eq!(deployment.ledger.custody(), total + unprocessed);
}

/// Shards admit payments within and across shards, the builder assembles their cuts into closes
/// validators certify, and each shard settles to exactly the balances validators post.
#[test]
fn test_shards_settle_the_balances_validators_post() {
    deterministic::Runner::default().start(|mut context| async move {
        const SHARDS: usize = 3;
        let mut deployment = Deployment::new(&context, "shards", 4).await;
        let mut shards = Shards::new(SHARDS).await;
        let users: Vec<_> = (0..SHARDS)
            .flat_map(|shard| served(shard, SHARDS, 3))
            .collect();
        let mut senders = senders(&users);

        // Every user deposits, and every shard settles the first close.
        for index in &users {
            deployment.ledger.deposit(account(*index), 1_000).unwrap();
        }
        close_and_settle(&mut deployment, &mut context, &mut shards).await;
        check_balances(&deployment, &shards, &users).await;

        let mut across = 0;
        for epoch in 2..=4 {
            // Every user pays the next two users, in its own shard or in another.
            for (position, from) in users.iter().enumerate() {
                for offset in [1, 2] {
                    let to = users[(position + offset) % users.len()];
                    let amount = epoch * 10 + offset as u64;
                    pay(&mut shards, &mut senders, epoch, *from, to, amount)
                        .await
                        .unwrap();
                    if shards.serving(&account(*from)) != shards.serving(&account(to)) {
                        across += 1;
                    }
                }
            }

            // One user withdraws through its shard, another through the ledger, and a third
            // deposits.
            let pick = |offset: u64| users[((epoch + offset) % users.len() as u64) as usize];
            let withdrawal = Withdrawal::sign(&user(pick(0)), &namespace(), epoch, 25, 0);
            shards.of(&account(pick(0))).withdraw(withdrawal).unwrap();
            deployment.ledger.withdraw(account(pick(3)), 15).unwrap();
            deployment.ledger.deposit(account(pick(1)), 40).unwrap();

            // Each shard settles the flows of its own accounts from the posted close.
            let (closed, flows) = close(&mut deployment, &mut context, &mut shards).await;
            assert_eq!(closed, epoch);
            shards.settle(closed, flows).await;
            check_balances(&deployment, &shards, &users).await;
        }
        assert!(across > 0 && across < 3 * 2 * users.len());

        // The next epoch continues on every shard.
        for from in &users {
            pay(&mut shards, &mut senders, 5, *from, users[0], 1)
                .await
                .unwrap();
        }
        for (shard, backend) in shards.shards.iter().zip(&shards.backends) {
            assert_eq!(shard.epoch(), 5);
            assert_eq!(backend.epoch(), 4);
        }
    });
}

/// A shard admits payments of the next epoch while the close builds, against a floor that
/// subtracts what the cut epoch may still take from each balance. Incoming payments become
/// spendable once the shard settles their epoch.
#[test]
fn test_shard_admits_against_the_floor_until_settle() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "floor", 1).await;
        let mut shards = Shards::new(2).await;
        let (alice, bob) = (served(0, 2, 1)[0], served(1, 2, 1)[0]);
        let mut senders = senders(&[alice, bob]);
        deployment.ledger.deposit(account(alice), 100).unwrap();
        close_and_settle(&mut deployment, &mut context, &mut shards).await;

        // Alice pays bob in epoch 2, and the shards cut it.
        pay(&mut shards, &mut senders, 2, alice, bob, 30)
            .await
            .unwrap();
        let queue = deployment.ledger.queue();
        let cuts = shards.cut(&queue);

        // While the close builds, alice can spend what epoch 2 left her, and bob cannot spend
        // what he received in it.
        assert_eq!(shards.live(&account(alice)).await.unwrap(), 70);
        assert_eq!(shards.live(&account(bob)).await.unwrap(), 0);
        assert!(matches!(
            pay(&mut shards, &mut senders, 3, alice, bob, 71).await,
            Err(Error::InsufficientBalance)
        ));
        pay(&mut shards, &mut senders, 3, alice, bob, 70)
            .await
            .unwrap();
        assert!(matches!(
            pay(&mut shards, &mut senders, 3, bob, alice, 1).await,
            Err(Error::InsufficientBalance)
        ));

        // Once the shards settle epoch 2, bob can spend what he received in it.
        let (close_2, flows) = shards.assemble(&queue, cuts);
        let proposals = deployment.verify(&close_2).await;
        deployment.post(&mut context, proposals).await;
        shards.settle(2, flows).await;
        assert_eq!(shards.balance(&account(bob)).await, 30);
        assert_eq!(shards.live(&account(bob)).await.unwrap(), 30);
        assert_eq!(shards.live(&account(alice)).await.unwrap(), 0);
        pay(&mut shards, &mut senders, 3, bob, alice, 30)
            .await
            .unwrap();

        // The close of epoch 3 verifies, and every balance matches the validators'.
        close_and_settle(&mut deployment, &mut context, &mut shards).await;
        assert_eq!(shards.balance(&account(alice)).await, 30);
        assert_eq!(shards.balance(&account(bob)).await, 70);
        check_balances(&deployment, &shards, &[alice, bob]).await;
    });
}

/// Soft withdrawals a cut holds and forced withdrawals its close processes lower the floor, so a
/// balance withdrawn in full cannot be spent before its epoch settles.
#[test]
fn test_withdrawals_lower_the_floor() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "withdrawn", 1).await;
        let mut shards = Shards::new(2).await;
        let first = served(0, 2, 2);
        let (alice, carol, bob) = (first[0], first[1], served(1, 2, 1)[0]);
        let mut senders = senders(&[alice, bob, carol]);
        for (index, amount) in [(alice, 100), (bob, 50), (carol, 100)] {
            deployment.ledger.deposit(account(index), amount).unwrap();
        }
        close_and_settle(&mut deployment, &mut context, &mut shards).await;

        // Alice withdraws everything through her shard, carol part of her balance, and bob
        // everything through the ledger.
        for (index, amount) in [(alice, 100), (carol, 40)] {
            let withdrawal = Withdrawal::sign(&user(index), &namespace(), 2, amount, 0);
            shards.of(&account(index)).withdraw(withdrawal).unwrap();
        }
        deployment.ledger.withdraw(account(bob), 50).unwrap();
        let queue = deployment.ledger.queue();
        let cuts = shards.cut(&queue);

        // Until epoch 2 settles, only carol has anything left to spend.
        assert_eq!(shards.live(&account(alice)).await.unwrap(), 0);
        assert_eq!(shards.live(&account(bob)).await.unwrap(), 0);
        assert_eq!(shards.live(&account(carol)).await.unwrap(), 60);
        for (from, to) in [(alice, carol), (bob, alice)] {
            assert!(matches!(
                pay(&mut shards, &mut senders, 3, from, to, 1).await,
                Err(Error::InsufficientBalance)
            ));
        }
        pay(&mut shards, &mut senders, 3, carol, alice, 60)
            .await
            .unwrap();

        // The close pays every withdrawal in full, so the floors were exact.
        let (close_2, flows) = shards.assemble(&queue, cuts);
        let proposals = deployment.verify(&close_2).await;
        assert_eq!(
            proposals[0].payouts(),
            &Amounts::new([
                (account(alice), 100),
                (account(bob), 50),
                (account(carol), 40)
            ])
            .unwrap()
        );
        deployment.post(&mut context, proposals).await;
        shards.settle(2, flows).await;
        assert_eq!(shards.live(&account(alice)).await.unwrap(), 0);
        assert_eq!(shards.live(&account(carol)).await.unwrap(), 0);

        close_and_settle(&mut deployment, &mut context, &mut shards).await;
        assert_eq!(shards.balance(&account(alice)).await, 60);
        check_balances(&deployment, &shards, &[alice, bob, carol]).await;
    });
}

/// A shard holds one cut at a time. It cuts the next epoch only once it settles the last, and a
/// refused cut leaves the epoch open.
#[test]
fn test_one_pending_cut() {
    deterministic::Runner::default().start(|_| async move {
        let mut shards = Shards::new(1).await;
        close_queue(&mut shards, &deposits(1, &[(0, 100)])).await;
        let mut senders = senders(&[0]);
        pay(&mut shards, &mut senders, 2, 0, 1, 30).await.unwrap();
        let queue = deposits(2, &[]);
        let cuts = shards.cut(&queue);
        let (_, flows) = shards.assemble(&queue, cuts);

        // A single operator does not close past the unsettled cut, and stays where it was.
        let result = shards.shards[0].close(&deposits(3, &[]), 0, 0).await;
        assert!(matches!(result, Err(Error::Unsettled)));
        assert_eq!(shards.shards[0].epoch(), 3);

        // Nor does a shard cut past it, and the epoch stays open.
        pay(&mut shards, &mut senders, 3, 0, 1, 20).await.unwrap();
        let shard = &mut shards.shards[0];
        assert!(matches!(shard.cut(3, 0, 0, &[]), Err(Error::Unsettled)));
        assert_eq!(shard.epoch(), 3);
        assert_eq!(shard.payments(&account(0)), Some(&amounts(&[(1, 20)])));

        // Once epoch 2 settles, epoch 3 is cut.
        shards.settle(2, flows).await;
        close_queue(&mut shards, &deposits(3, &[])).await;
        assert_eq!(shards.shards[0].epoch(), 4);
        assert_eq!(shards.balance(&account(0)).await, 50);
    });
}

/// How an account's whole balance leaves in an epoch.
#[derive(Clone, Copy)]
enum Spend {
    Payment,
    Soft,
    Forced,
}

/// Settling refuses flows that leave out an account the cut deducted from, whether the account
/// paid, withdrew through its shard, or withdrew through the ledger. The shard restarts with the
/// deduction in force. Were the deduction lifted without the flow, the account could spend what
/// the close took and the next close would overdraw.
#[test]
fn test_settle_requires_flows_of_deducted_accounts() {
    for spend in [Spend::Payment, Spend::Soft, Spend::Forced] {
        deterministic::Runner::default().start(|mut context| async move {
            let mut deployment = Deployment::new(&context, "missing", 1).await;
            let mut shards = Shards::new(1).await;
            let mut senders = senders(&[0]);
            deployment.ledger.deposit(account(0), 100).unwrap();
            close_and_settle(&mut deployment, &mut context, &mut shards).await;

            // Alice's whole balance leaves in epoch 2.
            match spend {
                Spend::Payment => pay(&mut shards, &mut senders, 2, 0, 1, 100).await.unwrap(),
                Spend::Soft => {
                    let withdrawal = Withdrawal::sign(&user(0), &namespace(), 2, 100, 0);
                    shards.of(&account(0)).withdraw(withdrawal).unwrap();
                }
                Spend::Forced => deployment.ledger.withdraw(account(0), 100).unwrap(),
            }
            let (epoch, flows) = close(&mut deployment, &mut context, &mut shards).await;

            // The shard refuses to settle without alice's flow, still holds her deduction, and
            // settles once given every flow.
            let withheld = flows
                .iter()
                .filter(|(account, _)| *account != super::account(0))
                .cloned()
                .collect();
            let refused = shards.try_settle(0, epoch, withheld).await;
            let held = shards.live(&account(0)).await.unwrap();
            if refused.is_err() {
                shards.settle(epoch, flows).await;
            }

            // Alice spends whatever her shard lets her, and the next close still verifies.
            let live = shards.live(&account(0)).await.unwrap();
            if live > 0 {
                pay(&mut shards, &mut senders, 3, 0, 1, live).await.unwrap();
            }
            close_and_settle(&mut deployment, &mut context, &mut shards).await;
            assert!(matches!(refused, Err(Error::MissingFlow)));
            assert_eq!((held, live), (0, 0));
            check_balances(&deployment, &shards, &[0, 1]).await;
        });
    }
}

/// A flow that only credits its account carries no deduction, so settling without it succeeds and
/// leaves the account's stored balance below the validators'. That only holds the account back.
#[test]
fn test_missing_credit_only_flow_is_conservative() {
    deterministic::Runner::default().start(|_| async move {
        let mut shards = Shards::new(1).await;
        close_queue(&mut shards, &deposits(1, &[(0, 100)])).await;
        let mut senders = senders(&[0]);
        pay(&mut shards, &mut senders, 2, 0, 1, 30).await.unwrap();
        let queue = deposits(2, &[]);
        let cuts = shards.cut(&queue);
        let (_, flows) = shards.assemble(&queue, cuts);
        let withheld = flows
            .into_iter()
            .filter(|(account, _)| *account != super::account(1))
            .collect();
        shards.settle(2, withheld).await;
        assert_eq!(shards.balance(&account(0)).await, 70);
        assert_eq!(shards.balance(&account(1)).await, 0);
        assert_eq!(shards.live(&account(1)).await.unwrap(), 0);
    });
}

/// Settling refuses flows of another epoch, an epoch other than the pending cut's, an account with
/// two flows, and a balance the flows would push beyond the largest amount. The store is
/// untouched, and the shard still holds the cut's deductions.
#[test]
fn test_settle_rejects_flows_that_do_not_fit() {
    deterministic::Runner::default().start(|_| async move {
        let mut shards = Shards::new(1).await;
        let funding = close_queue(&mut shards, &deposits(1, &[(0, 100)])).await;
        let mut senders = senders(&[0]);
        pay(&mut shards, &mut senders, 2, 0, 1, 30).await.unwrap();

        // The close of epoch 2 also processes a deposit that bob's balance cannot hold.
        let queue = deposits(2, &[(1, u64::MAX)]);
        let cuts = shards.cut(&queue);
        let (_, flows) = shards.assemble(&queue, cuts);
        let mut duplicated = flows.clone();
        duplicated.push(flows[0].clone());

        let result = shards.try_settle(0, 2, funding).await;
        assert!(matches!(
            result,
            Err(Error::WrongEpoch {
                expected: 2,
                found: 1
            })
        ));
        let result = shards.try_settle(0, 3, flows.clone()).await;
        assert!(matches!(
            result,
            Err(Error::WrongEpoch {
                expected: 3,
                found: 2
            })
        ));
        let result = shards.try_settle(0, 3, Vec::new()).await;
        assert!(matches!(
            result,
            Err(Error::WrongEpoch {
                expected: 2,
                found: 3
            })
        ));
        let result = shards.try_settle(0, 2, duplicated).await;
        assert!(matches!(result, Err(Error::DuplicateAccount)));
        let result = shards.try_settle(0, 2, flows).await;
        assert!(matches!(result, Err(Error::Overflow)));
        assert_eq!(shards.backends[0].epoch(), 1);
        assert_eq!(shards.live(&account(0)).await.unwrap(), 70);
    });
}

/// Shards whose limits on senders and soft withdrawals add up to the validators' admit up to their
/// own, and the close they assemble at those limits decodes with the validators' limits.
#[test]
fn test_shard_limits_add_up_to_the_close_limits() {
    deterministic::Runner::default().start(|_| async move {
        let limits = Limits {
            rows: 4,
            receivers: 2,
            withdrawals: 2,
        };
        let half = Limits {
            rows: 2,
            withdrawals: 1,
            ..limits
        };
        let users: Vec<_> = (0..2).map(|shard| served(shard, 2, 3)).collect();
        let balances: Vec<_> = users
            .iter()
            .flatten()
            .map(|index| (account(*index), 100))
            .collect();
        let funded = Backend::new(1, &balances);
        let mut cuts = Vec::new();
        for users in &users {
            let mut shard = Shard::init(operator_key(), namespace(), half, funded.fork(), [], None)
                .await
                .unwrap();

            // Two of the shard's users pay and withdraw, and a third sender or soft withdrawal
            // would not fit.
            for (position, index) in users.iter().enumerate() {
                let request = sender(*index)
                    .send(2, amounts(&[(100, 1), (101, 1)]), false)
                    .unwrap();
                let withdrawal = Withdrawal::sign(&user(*index), &namespace(), 2, 1, 0);
                if position < 2 {
                    shard.accept(&request).await.unwrap();
                } else {
                    assert!(matches!(shard.accept(&request).await, Err(Error::Full)));
                }
                if position < 1 {
                    shard.withdraw(withdrawal).unwrap();
                } else {
                    assert!(matches!(shard.withdraw(withdrawal), Err(Error::Full)));
                }
            }
            cuts.push(shard.cut(2, 0, 0, &[]).unwrap());
        }
        let (close, _) = assemble(&deposits(2, &[]), cuts).unwrap();
        assert_eq!(close.rows().len(), 4);
        assert_eq!(close.withdrawals().len(), 2);
        assert_eq!(
            TestClose::decode_cfg(close.encode(), &limits).unwrap(),
            close
        );
    });
}

/// An operator refuses to cut or close an epoch other than its current one, and stays as it was.
#[test]
fn test_stale_cut_and_close_are_refused() {
    deterministic::Runner::default().start(|_| async move {
        let mut operator = operator().await;
        close_epoch(&mut operator, &deposits(1, &[(0, 100)]), 1, 0).await;
        assert!(matches!(
            operator.cut(1, 0, 0, &[]),
            Err(Error::WrongEpoch {
                expected: 2,
                found: 1
            })
        ));
        assert!(matches!(
            operator.close(&deposits(1, &[]), 0, 0).await,
            Err(Error::WrongEpoch {
                expected: 2,
                found: 1
            })
        ));
        assert_eq!(operator.epoch(), 2);
        close_epoch(&mut operator, &deposits(2, &[]), 0, 0).await;
    });
}

/// Assembly rejects cuts that disagree on the epoch or on the queued requests their close
/// processes, and an account that pays or withdraws in two cuts, as misrouted requests produce.
#[test]
fn test_assembly_rejects_misrouted_and_mismatched_cuts() {
    deterministic::Runner::default().start(|_| async move {
        // Shards whose stores hold alice's balance after the close of epoch 1, or nothing.
        let funded = Backend::new(1, &[(account(0), 100)]);
        let empty = Backend::new(1, &[]);
        async fn on(backend: &Backend) -> Shard {
            start(backend.fork(), None).await.unwrap()
        }
        let queue = Queue {
            forced_withdrawals: forced(2, &[(0, 3)]).forced_withdrawals,
            ..deposits(2, &[(1, 5)])
        };
        let cut = |shard: &mut Shard, deposits: u64, forced: u64| {
            shard
                .cut(2, deposits, forced, &queue.forced_withdrawals)
                .unwrap()
        };
        let assemble = |cuts: Vec<TestCut>| assemble(&queue, cuts);

        // Two shards that both hold alice's balance accept the same request.
        let request = sender(0).send(2, amounts(&[(1, 10)]), false).unwrap();
        let (mut first, mut second) = (on(&funded).await, on(&funded).await);
        first.accept(&request).await.unwrap();
        second.accept(&request).await.unwrap();
        assert!(matches!(
            assemble(vec![cut(&mut first, 1, 1), cut(&mut second, 1, 1)]),
            Err(Error::DuplicateAccount)
        ));

        // Alice's soft withdrawal reaches another shard than her payment.
        let (mut first, mut second) = (on(&funded).await, on(&empty).await);
        first.accept(&request).await.unwrap();
        second
            .withdraw(Withdrawal::sign(&user(0), &namespace(), 2, 5, 0))
            .unwrap();
        assert!(matches!(
            assemble(vec![cut(&mut first, 1, 1), cut(&mut second, 1, 1)]),
            Err(Error::DuplicateAccount)
        ));

        // Every cut must record the counts the close processes, and the counts must fit the queue.
        for (deposits, forced) in [(0, 1), (1, 0)] {
            let (mut first, mut second) = (on(&funded).await, on(&empty).await);
            assert!(matches!(
                assemble(vec![
                    cut(&mut first, 1, 1),
                    cut(&mut second, deposits, forced)
                ]),
                Err(Error::InvalidCut)
            ));
        }
        assert!(matches!(
            TestClose::assemble::<Sha256, _>(
                &operator_key(),
                &namespace(),
                &queue,
                2,
                1,
                Vec::new()
            ),
            Err(Error::InvalidCount)
        ));

        // Cuts and their soft withdrawals must be of the epoch the ledger expects.
        let ahead = Backend::new(2, &[]);
        let stale = on(&ahead).await.cut(3, 1, 1, &[]).unwrap();
        assert!(matches!(
            assemble(vec![cut(&mut on(&funded).await, 1, 1), stale]),
            Err(Error::WrongEpoch {
                expected: 2,
                found: 3
            })
        ));
        let mut collected = on(&empty).await;
        collected
            .withdraw(Withdrawal::sign(&user(2), &namespace(), 2, 5, 0))
            .unwrap();
        let mut misdated = cut(&mut collected, 1, 1);
        misdated.withdrawals[0].epoch = 4;
        assert!(matches!(
            assemble(vec![misdated]),
            Err(Error::WrongEpoch {
                expected: 2,
                found: 4
            })
        ));

        // Cuts of disjoint accounts assemble, and so does an epoch without cuts.
        let (mut first, mut second) = (on(&funded).await, on(&empty).await);
        first.accept(&request).await.unwrap();
        let (close, flows) = assemble(vec![cut(&mut first, 1, 1), cut(&mut second, 1, 1)]).unwrap();
        assert_eq!(close.rows().len(), 1);
        assert_eq!(flows.len(), 2);
        let (close, flows) = assemble(Vec::new()).unwrap();
        assert!(close.rows().is_empty());
        assert_eq!(flows.len(), 2);
    });
}

/// The same activity closed by one operator and assembled from three shards yields the same
/// close, byte for byte, and the same flows.
#[test]
fn test_assembly_matches_monolithic_close() {
    deterministic::Runner::default().start(|_| async move {
        let users: Vec<u64> = (0..6).collect();
        let mut shards = Shards::new(3).await;
        let mut single = operator().await;
        let mut replica = operator().await;
        let funding: Vec<_> = users.iter().map(|index| (*index, 100)).collect();
        let funding = deposits(1, &funding);
        close_queue(&mut shards, &funding).await;
        for operator in [&mut single, &mut replica] {
            close_epoch(operator, &funding, 6, 0).await;
        }

        // The same requests and soft withdrawals reach the single operators and the owning
        // shards.
        let mut senders = senders(&users);
        for from in &users {
            for offset in [1, 3] {
                let to = (from + offset) % 6;
                let sender = senders.get_mut(from).unwrap();
                let request = sender.send(2, amounts(&[(to, 10 + from)]), false).unwrap();
                let acknowledgement = shards.of(&account(*from)).accept(&request).await.unwrap();
                single.accept(&request).await.unwrap();
                replica.accept(&request).await.unwrap();
                sender.acknowledged(&acknowledgement).unwrap();
            }
        }
        let withdrawal = Withdrawal::sign(&user(2), &namespace(), 2, 15, 0);
        shards.of(&account(2)).withdraw(withdrawal.clone()).unwrap();
        single.withdraw(withdrawal.clone()).unwrap();
        replica.withdraw(withdrawal).unwrap();

        // All three close epoch 2 identically.
        let queue = Queue {
            forced_withdrawals: forced(2, &[(4, 5)]).forced_withdrawals,
            ..deposits(2, &[(5, 7)])
        };
        let monolithic = close_epoch(&mut single, &queue, 1, 1).await;
        let cut = replica.cut(2, 1, 1, &queue.forced_withdrawals).unwrap();
        let (assembled, flows) = assemble(&queue, vec![cut]).unwrap();
        let cuts = shards.cut(&queue);
        let (sharded, sharded_flows) = shards.assemble(&queue, cuts);
        assert_eq!(monolithic.encode(), sharded.encode());
        assert_eq!(assembled.encode(), sharded.encode());
        assert_eq!(flows, sharded_flows);
    });
}

/// A pipelined request that reaches its shard after the cut of its epoch is acknowledged in the
/// next epoch, against the floor, and the next close settles it.
#[test]
fn test_pipelined_request_acknowledged_after_cut() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "pipelined", 1).await;
        let mut shards = Shards::new(2).await;
        let (alice, bob) = (served(0, 2, 1)[0], served(1, 2, 1)[0]);
        deployment.ledger.deposit(account(alice), 100).unwrap();
        close_and_settle(&mut deployment, &mut context, &mut shards).await;

        // Alice's request for epoch 2 reaches her shard after it cut epoch 2.
        let mut sender = sender(alice);
        let request = sender.send(2, amounts(&[(bob, 30)]), true).unwrap();
        let queue = deployment.ledger.queue();
        let cuts = shards.cut(&queue);
        let acknowledgement = shards.of(&account(alice)).accept(&request).await.unwrap();
        assert_eq!(acknowledgement.epoch, 3);
        sender.acknowledged(&acknowledgement).unwrap();

        // The close of epoch 2 posts without it, and the close of epoch 3 settles it.
        let (close_2, flows) = shards.assemble(&queue, cuts);
        assert!(close_2.rows().is_empty());
        let proposals = deployment.verify(&close_2).await;
        deployment.post(&mut context, proposals).await;
        shards.settle(2, flows).await;
        close_and_settle(&mut deployment, &mut context, &mut shards).await;
        assert_eq!(shards.balance(&account(bob)).await, 30);
        check_balances(&deployment, &shards, &[alice, bob]).await;
    });
}

/// Withdrawal requests adding up to more than the largest amount travel to their shard as exact
/// totals, and settle to the balance validators post.
#[test]
fn test_flows_ship_exact_totals() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "totals", 1).await;
        let mut shards = Shards::new(2).await;
        deployment.ledger.deposit(account(0), 100).unwrap();
        close_and_settle(&mut deployment, &mut context, &mut shards).await;

        // Alice asks to withdraw the largest amount twice through her shard and once through the
        // ledger.
        for tag in [0, 1] {
            let withdrawal = Withdrawal::sign(&user(0), &namespace(), 2, u64::MAX, tag);
            shards.of(&account(0)).withdraw(withdrawal).unwrap();
        }
        deployment.ledger.withdraw(account(0), u64::MAX).unwrap();
        let (epoch, flows) = close(&mut deployment, &mut context, &mut shards).await;
        assert_eq!(shards.live(&account(0)).await.unwrap(), 0);

        // The flows cross the wire before the shards settle them.
        let decoded = Flows::decode_cfg(flows.encode(), &(RangeCfg::new(..), ((), ()))).unwrap();
        assert_eq!(decoded, flows);
        shards.settle(epoch, decoded).await;
        assert_eq!(shards.balance(&account(0)).await, 0);
        check_balances(&deployment, &shards, &[0]).await;
        assert_eq!(deployment.ledger.custody(), 0);
    });
}

/// A shard that restarts with a pending cut starts from its store, the matrix of the last close
/// the store includes, and that cut, then acts exactly like a shard that never restarted.
#[test]
fn test_shard_restarts_with_a_pending_cut() {
    deterministic::Runner::default().start(|_| async move {
        let mut shards = Shards::new(1).await;
        close_queue(&mut shards, &deposits(1, &[(0, 100), (1, 50)])).await;
        let mut alice = sender(0);
        let mut bob = sender(1);

        // Epoch 2 is cut and not settled.
        let request = alice.send(2, amounts(&[(1, 20)]), false).unwrap();
        alice
            .acknowledged(&shards.shards[0].accept(&request).await.unwrap())
            .unwrap();
        shards.shards[0]
            .withdraw(Withdrawal::sign(&user(1), &namespace(), 2, 10, 0))
            .unwrap();
        let queue = deposits(2, &[(2, 5)]);
        let cuts = shards.cut(&queue);
        let (_, flows) = shards.assemble(&queue, cuts);

        // During epoch 3, a copy of the shard restarts from its store and replays the requests and
        // soft withdrawals of epoch 3.
        let replayed = [
            alice.send(3, amounts(&[(1, 5)]), false).unwrap(),
            bob.send(3, amounts(&[(0, 15)]), false).unwrap(),
        ];
        let withdrawal = Withdrawal::sign(&user(0), &namespace(), 3, 3, 0);
        let mut restarted = shards.start(0, shards.backends[0].fork()).await;
        for shard in [&mut shards.shards[0], &mut restarted] {
            for request in &replayed {
                shard.accept(request).await.unwrap();
            }
            shard.withdraw(withdrawal.clone()).unwrap();
        }
        let mut original = shards.shards.remove(0);

        // Both settle, and close epoch 3, identically.
        async fn check(original: &Shard, restarted: &Shard) {
            assert_eq!(restarted.epoch(), original.epoch());
            for index in [0, 1, 2] {
                assert_eq!(
                    restarted.live(&account(index)).await.unwrap(),
                    original.live(&account(index)).await.unwrap()
                );
                assert_eq!(
                    restarted.balance(&account(index)).await.unwrap(),
                    original.balance(&account(index)).await.unwrap()
                );
            }
        }
        check(&original, &restarted).await;
        assert_eq!(original.live(&account(0)).await.unwrap(), 100 - 20 - 5);
        original.settle(2, flows.clone()).await.unwrap();
        restarted.settle(2, flows).await.unwrap();
        check(&original, &restarted).await;
        let queue = deposits(3, &[]);
        let mut closes = Vec::new();
        for shard in [&mut original, &mut restarted] {
            let cut = shard.cut(3, 0, 0, &[]).unwrap();
            closes.push(assemble(&queue, vec![cut]).unwrap());
        }
        assert_eq!(closes[0], closes[1]);

        // A cut the store includes is settled and ignored, and a cut of any later epoch is pending,
        // since a shard skips the epochs it has nothing to do in.
        let pending = shards.cuts[0].clone().unwrap();
        let settled = Backend::new(2, &[]);
        let mut resumed = start(settled, Some(&pending)).await.unwrap();
        assert_eq!(resumed.epoch(), 3);
        resumed.cut(3, 0, 0, &[]).unwrap();
        let behind = Backend::new(0, &[]);
        let mut resumed = start(behind, Some(&pending)).await.unwrap();
        assert_eq!(resumed.epoch(), 3);
        assert!(matches!(resumed.cut(3, 0, 0, &[]), Err(Error::Unsettled)));
    });
}

/// A shard that restarts with a later cut pending still knows it settled the cut before, so a
/// repeated settle of that epoch returns without effect, even with flows that take.
#[test]
fn test_repeated_settle_after_restart_with_a_later_cut() {
    deterministic::Runner::default().start(|_| async move {
        let mut shards = Shards::new(1).await;
        close_queue(&mut shards, &deposits(1, &[(0, 100)])).await;
        let mut senders = senders(&[0, 1]);

        // Alice pays in epoch 2, and the shard cuts and settles it, then cuts epoch 3.
        pay(&mut shards, &mut senders, 2, 0, 1, 30).await.unwrap();
        let flows = close_queue(&mut shards, &deposits(2, &[])).await;
        shards.cut(&deposits(3, &[]));

        // Restarted from its store and the cut of epoch 3, it repeats the settle of epoch 2.
        shards.restart(0).await;
        shards.try_settle(0, 2, flows).await.unwrap();
        assert_eq!(shards.balance(&account(0)).await, 70);
        assert_eq!(shards.backends[0].epoch(), 2);
        assert_eq!(shards.shards[0].epoch(), 4);
    });
}

/// A shard that caught up past an epoch and then cut the next one did not cut the skipped epoch,
/// so after a restart it still refuses a late flow of that epoch that takes.
#[test]
fn test_late_taking_flow_after_restart_needs_a_cut() {
    deterministic::Runner::default().start(|_| async move {
        let backend = Backend::default();
        let mut shard = start(backend.clone(), None).await.unwrap();
        let (_, flows) = assemble(&deposits(1, &[(0, 100)]), Vec::new()).unwrap();
        shard.settle(1, flows).await.unwrap();

        // The close of epoch 2 processes alice's forced withdrawal without a cut of the shard,
        // which catches up past epoch 2 and cuts epoch 3 before her flow arrives.
        let (_, late) = assemble(&forced(2, &[(0, 100)]), Vec::new()).unwrap();
        shard.settle(2, Vec::new()).await.unwrap();
        let cut = shard.cut(3, 0, 0, &[]).unwrap();

        // Restarted from its store and that cut, it refuses the late flow.
        let mut restarted = start(backend, Some(&cut)).await.unwrap();
        assert!(matches!(
            restarted.settle(2, late).await,
            Err(Error::MissingCut)
        ));
    });
}

/// A shard restarted from its store and the cut it settled, given no previous roots, admits the
/// next state of an account that paid in the cut's epoch, because the cut holds the account's map.
#[test]
fn test_restart_takes_previous_maps_from_the_settled_cut() {
    deterministic::Runner::default().start(|_| async move {
        let mut shards = Shards::new(1).await;
        close_queue(&mut shards, &deposits(1, &[(0, 100)])).await;
        let mut senders = senders(&[0, 1]);
        pay(&mut shards, &mut senders, 2, 0, 1, 30).await.unwrap();
        close_queue(&mut shards, &deposits(2, &[])).await;

        // Alice's next state commits to her map of epoch 2.
        shards.restart(0).await;
        pay(&mut shards, &mut senders, 3, 0, 1, 10).await.unwrap();
        close_queue(&mut shards, &deposits(3, &[])).await;
        assert_eq!(shards.balance(&account(0)).await, 60);
    });
}

/// A store write that fails or never completes leaves the shard failed before its floor deductions
/// drop. Every later call fails, and the shard restarts from its store and its cut with the floor
/// still in force.
#[test]
fn test_failed_store_write_keeps_the_floor() {
    for writes in [Writes::Fail, Writes::Hang] {
        deterministic::Runner::default().start(|context| async move {
            let mut shards = Shards::new(1).await;
            close_queue(&mut shards, &deposits(1, &[(0, 100)])).await;

            // Alice spends 60 in epoch 2, and the shard cuts it.
            let mut senders = senders(&[0]);
            pay(&mut shards, &mut senders, 2, 0, 1, 60).await.unwrap();
            let queue = deposits(2, &[]);
            let cuts = shards.cut(&queue);
            let (_, flows) = shards.assemble(&queue, cuts);

            // The store's write of epoch 2 fails or hangs and is abandoned.
            shards.backends[0].set_writes(writes);
            select! {
                result = shards.shards[0].settle(2, flows.clone()) => {
                    assert!(matches!(result, Err(Error::Store(_))));
                },
                _ = context.sleep(Duration::from_secs(1)) => assert_eq!(writes, Writes::Hang),
            }

            // Every later call fails.
            let shard = &mut shards.shards[0];
            let request = sender(0).send(3, amounts(&[(1, 1)]), false).unwrap();
            let withdrawal = Withdrawal::sign(&user(0), &namespace(), 3, 1, 0);
            let next = deposits(3, &[]);
            let processed: &[ForcedWithdrawal<PublicKey, u64>] = &[];
            assert!(matches!(shard.accept(&request).await, Err(Error::Failed)));
            assert!(matches!(shard.withdraw(withdrawal), Err(Error::Failed)));
            assert!(matches!(
                shard.load(&[account(0)]).await,
                Err(Error::Failed)
            ));
            assert!(matches!(shard.live(&account(0)).await, Err(Error::Failed)));
            assert!(matches!(
                shard.balance(&account(0)).await,
                Err(Error::Failed)
            ));
            assert!(matches!(
                shard.settle(2, flows.clone()).await,
                Err(Error::Failed)
            ));
            assert!(matches!(shard.cut(3, 0, 0, processed), Err(Error::Failed)));
            assert!(matches!(shard.close(&next, 0, 0).await, Err(Error::Failed)));

            // The restarted shard still holds the deductions of epoch 2.
            shards.backends[0].set_writes(Writes::Apply);
            shards.restart(0).await;
            assert_eq!(shards.backends[0].epoch(), 1);
            assert_eq!(shards.live(&account(0)).await.unwrap(), 40);
            shards.settle(2, flows).await;
            assert_eq!(shards.balance(&account(0)).await, 40);
            assert_eq!(shards.live(&account(0)).await.unwrap(), 40);
        });
    }
}

/// The operator caches only the balances of accounts the current epoch or its pending cut
/// involves, however many balances its store holds.
#[test]
fn test_cache_holds_only_active_accounts() {
    deterministic::Runner::default().start(|_| async move {
        const ACCOUNTS: u64 = 2_000;
        let balances: Vec<_> = (0..ACCOUNTS).map(|index| (account(index), 100)).collect();
        let backend = Backend::new(1, &balances);
        let mut shards = Shards::new(1).await;
        shards.backends[0] = backend.clone();
        shards.restart(0).await;
        let mut senders = senders(&[0, 1, 2]);

        // Three accounts pay three others in epoch 2.
        for (from, to) in [(0, 10), (1, 11), (2, 12)] {
            pay(&mut shards, &mut senders, 2, from, to, 5)
                .await
                .unwrap();
        }
        assert_eq!(shards.shards[0].cached(), 3);
        let queue = deposits(2, &[]);
        let cuts = shards.cut(&queue);
        let (_, flows) = shards.assemble(&queue, cuts);

        // One of them pays again in epoch 3 and a stranger is refused. After the settle of epoch
        // 2, only the account paying in epoch 3 stays cached.
        pay(&mut shards, &mut senders, 3, 0, 10, 5).await.unwrap();
        let mut stranger = sender(ACCOUNTS + 1);
        let request = stranger.send(3, amounts(&[(0, 1)]), false).unwrap();
        assert!(matches!(
            shards.shards[0].accept(&request).await,
            Err(Error::InsufficientBalance)
        ));
        shards.settle(2, flows).await;
        assert_eq!(shards.shards[0].cached(), 1);
        assert_eq!(shards.balance(&account(10)).await, 105);

        // Once epoch 3 settles too, nothing stays cached.
        close_queue(&mut shards, &deposits(3, &[])).await;
        assert_eq!(shards.shards[0].cached(), 0);
        assert_eq!(backend.epoch(), 3);
    });
}

/// An account idle in an epoch moves to another shard at that epoch's cut. Its new shard admits it
/// at once against its stored balance, before settling the credit the epoch brings it, and its
/// states commit to the empty map of its idle epoch. Every balance matches the validators'.
#[test]
fn test_idle_account_moves_at_once() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "idle", 1).await;
        let mut shards = Shards::new(2).await;
        let (xavier, bob) = (served(0, 2, 1)[0], served(1, 2, 1)[0]);
        let mut senders = senders(&[xavier, bob]);
        deployment.ledger.deposit(account(xavier), 100).unwrap();
        deployment.ledger.deposit(account(bob), 100).unwrap();
        close_and_settle(&mut deployment, &mut context, &mut shards).await;

        // Xavier pays in epoch 2 on shard 0, and is idle in epoch 3 but for a payment from bob.
        pay(&mut shards, &mut senders, 2, xavier, bob, 30)
            .await
            .unwrap();
        close_and_settle(&mut deployment, &mut context, &mut shards).await;
        pay(&mut shards, &mut senders, 3, bob, xavier, 10)
            .await
            .unwrap();

        // The deployment moves him to shard 1 at the cut of epoch 3, and copies his balance there.
        shards.moving.insert(account(xavier), 1);
        let (epoch, flows) = close(&mut deployment, &mut context, &mut shards).await;
        shards.backends[1].copy(&shards.backends[0], &account(xavier));

        // Shard 1 admits him at once against the balance epoch 2 left him. His sender accepts the
        // acknowledgement only if the state commits to his empty map of epoch 3.
        assert_eq!(shards.live(&account(xavier)).await.unwrap(), 70);
        pay(&mut shards, &mut senders, 4, xavier, bob, 70)
            .await
            .unwrap();

        // Settling epoch 3 adds bob's payment, and the next close verifies.
        shards.settle(epoch, flows).await;
        assert_eq!(shards.live(&account(xavier)).await.unwrap(), 10);
        close_and_settle(&mut deployment, &mut context, &mut shards).await;
        check_balances(&deployment, &shards, &[xavier, bob]).await;
    });
}

/// To move an active account, the deployment holds its requests for one epoch. The old shard
/// settles the epoch the account was active in, and the new shard admits the account against the
/// balance that epoch left. Every balance matches the validators'.
#[test]
fn test_active_account_moves_after_a_held_epoch() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "held", 1).await;
        let mut shards = Shards::new(2).await;
        let (xavier, bob) = (served(0, 2, 1)[0], served(1, 2, 1)[0]);
        let mut senders = senders(&[xavier, bob]);
        deployment.ledger.deposit(account(xavier), 100).unwrap();
        close_and_settle(&mut deployment, &mut context, &mut shards).await;

        // Xavier pays bob 30 and withdraws 40 on shard 0 in epoch 2.
        pay(&mut shards, &mut senders, 2, xavier, bob, 30)
            .await
            .unwrap();
        let withdrawal = Withdrawal::sign(&user(xavier), &namespace(), 2, 40, 0);
        shards.of(&account(xavier)).withdraw(withdrawal).unwrap();
        let (epoch, flows) = close(&mut deployment, &mut context, &mut shards).await;

        // The deployment holds his requests in epoch 3, while shard 0 settles epoch 2. It moves him
        // at the cut of epoch 3 and copies his balance to shard 1.
        shards.settle(epoch, flows).await;
        shards.moving.insert(account(xavier), 1);
        let (epoch, flows) = close(&mut deployment, &mut context, &mut shards).await;
        shards.backends[1].copy(&shards.backends[0], &account(xavier));

        // Shard 1 admits him at once against the 30 epoch 2 left him, and no more.
        assert!(matches!(
            pay(&mut shards, &mut senders, 4, xavier, bob, 31).await,
            Err(Error::InsufficientBalance)
        ));
        pay(&mut shards, &mut senders, 4, xavier, bob, 30)
            .await
            .unwrap();
        shards.settle(epoch, flows).await;
        close_and_settle(&mut deployment, &mut context, &mut shards).await;
        assert_eq!(shards.balance(&account(xavier)).await, 0);
        check_balances(&deployment, &shards, &[xavier, bob]).await;
    });
}

/// An account moved at the cut of an epoch it was active in comes to light at its old shard. That
/// shard's cut deducted from the account, and the account's flow goes to the new shard, so the old
/// shard refuses to settle without it and changes nothing.
#[test]
fn test_active_account_moved_early_is_missing_its_flow() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "early", 1).await;
        let mut shards = Shards::new(2).await;
        let (xavier, bob) = (served(0, 2, 1)[0], served(1, 2, 1)[0]);
        let mut senders = senders(&[xavier, bob]);
        deployment.ledger.deposit(account(xavier), 100).unwrap();
        close_and_settle(&mut deployment, &mut context, &mut shards).await;

        // Xavier pays in epoch 2 on shard 0, and the deployment moves him at its cut anyway.
        pay(&mut shards, &mut senders, 2, xavier, bob, 30)
            .await
            .unwrap();
        shards.moving.insert(account(xavier), 1);
        let (epoch, flows) = close(&mut deployment, &mut context, &mut shards).await;
        let routed = shards.route(flows);
        assert!(
            routed[1]
                .iter()
                .any(|(account, _)| *account == super::account(xavier))
        );

        // Shard 0 still holds his deduction, so it refuses to settle without his flow.
        let result = shards.try_settle(0, epoch, routed[0].clone()).await;
        assert!(matches!(result, Err(Error::MissingFlow)));
        assert_eq!(shards.backends[0].epoch(), 1);
    });
}

/// Each put applies only if the database still records the epoch the shard's handle holds. So when
/// another writer advances the database before the shard settles, the shard's put fails, writes
/// nothing, and leaves the shard failed.
#[test]
fn test_settle_fails_once_another_writer_advanced_the_store() {
    deterministic::Runner::default().start(|_| async move {
        let mut shards = Shards::new(1).await;
        close_queue(&mut shards, &deposits(1, &[(0, 100)])).await;
        let mut senders = senders(&[0]);
        pay(&mut shards, &mut senders, 2, 0, 1, 60).await.unwrap();
        let queue = deposits(2, &[]);
        let cuts = shards.cut(&queue);
        let (_, flows) = shards.assemble(&queue, cuts);

        // Another writer records epoch 3 and a balance for bob before the shard settles epoch 2.
        let database = shards.backends[0].clone();
        database
            .clone()
            .put(1, 3, &[(account(1), 7)])
            .await
            .unwrap();

        // The shard's put fails, and the database keeps the other writer's epoch and balances.
        let result = shards.try_settle(0, 2, flows).await;
        assert!(conflicted(&result));
        assert_eq!(database.epoch(), 3);
        assert_eq!(database.balance(&account(0)), 100);
        assert_eq!(database.balance(&account(1)), 7);
        assert!(matches!(shards.live(&account(0)).await, Err(Error::Failed)));
    });
}

/// Two processes opened on the same database, such as a shard and a stale copy of it, settle the
/// same epoch. The first put applies and the second fails without writing, so a stale process can
/// neither apply an epoch twice nor move the database back.
#[test]
fn test_stale_process_cannot_overwrite_the_store() {
    deterministic::Runner::default().start(|_| async move {
        let mut shards = Shards::new(1).await;
        close_queue(&mut shards, &deposits(1, &[(0, 100)])).await;
        let mut senders = senders(&[0]);
        pay(&mut shards, &mut senders, 2, 0, 1, 30).await.unwrap();
        let queue = deposits(2, &[]);
        let cuts = shards.cut(&queue);
        let (_, flows) = shards.assemble(&queue, cuts);

        // Two stale processes open the shard's database with its cut.
        let database = shards.backends[0].clone();
        let mut stale = [
            shards.start(0, database.clone()).await,
            shards.start(0, database.clone()).await,
        ];

        // The shard's put of epoch 2 applies. A stale process's put of the same epoch, computed
        // from the balances the shard wrote, fails and leaves them unchanged.
        shards.settle(2, flows.clone()).await;
        assert!(conflicted(&stale[0].settle(2, flows.clone()).await));
        assert_eq!(database.epoch(), 2);
        assert_eq!(database.balance(&account(0)), 70);
        assert_eq!(database.balance(&account(1)), 30);

        // Once the shard settles epoch 3, the other stale process cannot move the database back.
        pay(&mut shards, &mut senders, 3, 0, 1, 10).await.unwrap();
        close_queue(&mut shards, &deposits(3, &[])).await;
        assert!(conflicted(&stale[1].settle(2, flows).await));
        assert_eq!(database.epoch(), 3);
        assert_eq!(database.balance(&account(0)), 60);
        assert!(matches!(
            stale[1].live(&account(0)).await,
            Err(Error::Failed)
        ));
    });
}

/// One shard per account, the finest split a deployment can run. A shard exists only once a flow or
/// request reaches its account, and takes part only in the epochs it has something to do in.
#[derive(Default)]
struct Objects(HashMap<PublicKey, Shard>);

impl Objects {
    /// Returns the shard of `account`, starting it on an empty store the first time.
    async fn of(&mut self, account: &PublicKey) -> &mut Shard {
        if !self.0.contains_key(account) {
            let shard = start(Backend::default(), None).await.unwrap();
            self.0.insert(account.clone(), shard);
        }
        self.0.get_mut(account).expect("the shard must exist")
    }

    /// Returns the shard of `account`, caught up to `epoch` over every epoch it skipped.
    async fn at(&mut self, account: &PublicKey, epoch: Epoch) -> &mut Shard {
        let shard = self.of(account).await;
        if shard.epoch() < epoch {
            shard.settle(epoch - 1, Vec::new()).await.unwrap();
        }
        shard
    }

    async fn balance(&self, account: &PublicKey) -> u64 {
        match self.0.get(account) {
            Some(shard) => shard.balance(account).await.unwrap(),
            None => 0,
        }
    }
}

/// With one shard per account, only the shards of accounts that pay, withdraw, or have a forced
/// withdrawal processed cut an epoch, and only the shards of accounts a flow reaches settle it. An
/// idle shard catches up over the epochs it skipped when it next takes part. The closes match the
/// ones a single operator builds from the same activity, byte for byte, and every balance matches
/// the validators'.
#[test]
fn test_one_account_shards_close_like_one_operator() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "objects", 1).await;
        let mut objects = Objects::default();
        let users: Vec<u64> = (0..7).collect();
        let mut senders = senders(&users);
        let payments: [&[(u64, u64, u64)]; 5] =
            [&[], &[(0, 1, 30)], &[(1, 4, 10)], &[], &[(0, 3, 5)]];
        for epoch in 1..=5 {
            // The deployment routes each request to its sender's shard, catching it up first, and
            // the single operator sees the same requests.
            let mut active = BTreeSet::new();
            for (from, to, amount) in payments[(epoch - 1) as usize] {
                let sender = senders.get_mut(from).unwrap();
                let request = sender
                    .send(epoch, amounts(&[(*to, *amount)]), false)
                    .unwrap();
                let shard = objects.at(&account(*from), epoch).await;
                let acknowledgement = shard.accept(&request).await.unwrap();
                deployment.operator.accept(&request).await.unwrap();
                sender.acknowledged(&acknowledgement).unwrap();
                active.insert(account(*from));
            }
            match epoch {
                1 => {
                    for index in 0..5 {
                        deployment.ledger.deposit(account(index), 100).unwrap();
                    }
                }
                2 => {
                    let withdrawal = Withdrawal::sign(&user(2), &namespace(), 2, 20, 0);
                    let shard = objects.at(&account(2), 2).await;
                    shard.withdraw(withdrawal.clone()).unwrap();
                    deployment.operator.withdraw(withdrawal).unwrap();
                    active.insert(account(2));
                }
                3 => {
                    deployment.ledger.withdraw(account(3), 50).unwrap();
                    deployment.ledger.deposit(account(5), 40).unwrap();
                }
                _ => {}
            }

            // Only the shards of accounts that paid, withdrew, or have a forced withdrawal
            // processed cut, each given its own account's forced withdrawals. There may be none.
            let queue = deployment.ledger.queue();
            let (deposits, forced) = (
                queue.deposits.len() as u64,
                queue.forced_withdrawals.len() as u64,
            );
            let processed = &queue.forced_withdrawals;
            active.extend(
                processed
                    .iter()
                    .map(|withdrawal| withdrawal.account.clone()),
            );
            let mut cuts = Vec::new();
            for account in &active {
                let shard = objects.at(account, epoch).await;
                let own: Vec<_> = processed
                    .iter()
                    .filter(|withdrawal| withdrawal.account == *account)
                    .cloned()
                    .collect();
                cuts.push(shard.cut(epoch, deposits, forced, &own).unwrap());
            }
            let (close, flows) = TestClose::assemble::<Sha256, _>(
                &operator_key(),
                &namespace(),
                &queue,
                deposits,
                forced,
                cuts,
            )
            .unwrap();
            let single = close_epoch(&mut deployment.operator, &queue, deposits, forced).await;
            assert_eq!(close.encode(), single.encode());
            let proposals = deployment.verify(&close).await;
            deployment.post(&mut context, proposals).await;

            // Each flow reaches its account's shard right after assembly. A shard that did not cut
            // settles only credits.
            for (account, flow) in flows {
                objects
                    .of(&account)
                    .await
                    .settle(epoch, vec![(account, flow)])
                    .await
                    .unwrap();
            }
            for index in &users {
                let expected = deployment.validators[0]
                    .balance(&account(*index))
                    .await
                    .unwrap();
                assert_eq!(objects.balance(&account(*index)).await, expected);
            }
        }

        // The account no flow or request ever reached has no shard.
        assert_eq!(objects.0.len(), 6);
        assert!(!objects.0.contains_key(&account(6)));
    });
}

/// An idle shard catches up over several skipped epochs with one settle and no flows, though its
/// store lags several epochs behind. It then admits its accounts against their stored balances,
/// and their states commit to an empty previous map.
#[test]
fn test_idle_shard_catches_up_over_skipped_epochs() {
    deterministic::Runner::default().start(|_| async move {
        let mut shard = start(Backend::default(), None).await.unwrap();

        // Epoch 1 funds alice, and the shard settles the credit without a cut.
        let (_, flows) = assemble(&deposits(1, &[(0, 100)]), Vec::new()).unwrap();
        shard.settle(1, flows).await.unwrap();

        // Alice pays bob in epoch 2.
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 30)]), false).unwrap();
        alice
            .acknowledged(&shard.accept(&request).await.unwrap())
            .unwrap();
        let cut = shard.cut(2, 0, 0, &[]).unwrap();
        let (_, flows) = assemble(&deposits(2, &[]), vec![cut]).unwrap();
        shard.settle(2, flows).await.unwrap();

        // The shard skips epochs 3 to 5, and catches up with one settle.
        shard.settle(5, Vec::new()).await.unwrap();
        assert_eq!(shard.epoch(), 6);

        // Alice pays in epoch 6 against her stored balance, on top of an empty previous map.
        assert_eq!(shard.live(&account(0)).await.unwrap(), 70);
        let request = alice.send(6, amounts(&[(1, 70)]), false).unwrap();
        alice
            .acknowledged(&shard.accept(&request).await.unwrap())
            .unwrap();
        let cut = shard.cut(6, 0, 0, &[]).unwrap();
        let (_, flows) = assemble(&deposits(6, &[]), vec![cut]).unwrap();
        shard.settle(6, flows).await.unwrap();
        assert_eq!(shard.balance(&account(0)).await.unwrap(), 0);
        assert_eq!(shard.balance(&account(1)).await.unwrap(), 100);
    });
}

/// A shard with activity it has not cut cannot settle without a cut, so it never moves past
/// payments it admitted.
#[test]
fn test_idle_settle_refuses_uncut_activity() {
    deterministic::Runner::default().start(|_| async move {
        let mut shard = start(Backend::default(), None).await.unwrap();
        let (_, flows) = assemble(&deposits(1, &[(0, 100)]), Vec::new()).unwrap();
        shard.settle(1, flows).await.unwrap();

        // Alice pays in epoch 2, and the shard does not cut it.
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 30)]), false).unwrap();
        alice
            .acknowledged(&shard.accept(&request).await.unwrap())
            .unwrap();
        for epoch in [2, 4] {
            assert!(matches!(
                shard.settle(epoch, Vec::new()).await,
                Err(Error::Active)
            ));
        }
        assert_eq!(shard.epoch(), 2);
        assert_eq!(shard.payments(&account(0)), Some(&amounts(&[(1, 30)])));

        // Once cut, the epoch settles.
        let cut = shard.cut(2, 0, 0, &[]).unwrap();
        let (_, flows) = assemble(&deposits(2, &[]), vec![cut]).unwrap();
        shard.settle(2, flows).await.unwrap();
        assert_eq!(shard.balance(&account(0)).await.unwrap(), 70);
    });
}

/// A shard that caught up past an epoch has settled it, so the epoch's flows arriving late change
/// nothing. The account's stored balance then stays below the validators'. That holds it back but
/// never lets it overspend.
#[test]
fn test_late_flow_after_catch_up_is_ignored() {
    deterministic::Runner::default().start(|_| async move {
        let mut objects = Objects::default();
        let (_, flows) = assemble(&deposits(1, &[(0, 100)]), Vec::new()).unwrap();
        for (account, flow) in flows {
            objects
                .of(&account)
                .await
                .settle(1, vec![(account, flow)])
                .await
                .unwrap();
        }

        // Alice pays bob in epoch 2, and her shard cuts it.
        let mut alice = sender(0);
        let request = alice.send(2, amounts(&[(1, 30)]), false).unwrap();
        let shard = objects.at(&account(0), 2).await;
        alice
            .acknowledged(&shard.accept(&request).await.unwrap())
            .unwrap();
        let cut = shard.cut(2, 0, 0, &[]).unwrap();
        let (_, flows) = assemble(&deposits(2, &[]), vec![cut]).unwrap();

        // Bob's shard catches up past epoch 2 before his credit reaches it, and then ignores it.
        let bob = objects.at(&account(1), 3).await;
        assert_eq!(bob.epoch(), 3);
        let credit: Vec<_> = flows
            .into_iter()
            .filter(|(account, _)| *account == super::account(1))
            .collect();
        bob.settle(2, credit).await.unwrap();
        assert_eq!(bob.epoch(), 3);
        assert_eq!(bob.balance(&account(1)).await.unwrap(), 0);
        assert_eq!(bob.live(&account(1)).await.unwrap(), 0);
    });
}

/// Settling is idempotent. A repeated settle of the latest epoch the shard settled, whether after
/// success, after a restart that found the epoch in the store, or after the next cut, returns
/// without effect. So does a repeated catch-up. A settle of an older epoch is late.
#[test]
fn test_settle_is_idempotent() {
    deterministic::Runner::default().start(|_| async move {
        let mut shards = Shards::new(1).await;
        close_queue(&mut shards, &deposits(1, &[(0, 100)])).await;
        let mut senders = senders(&[0]);
        pay(&mut shards, &mut senders, 2, 0, 1, 30).await.unwrap();
        let queue = deposits(2, &[]);
        let cuts = shards.cut(&queue);
        let (_, flows) = shards.assemble(&queue, cuts);
        shards.settle(2, flows.clone()).await;

        // A duplicate delivery after success, and a retry after a restart, change nothing.
        async fn state(shards: &Shards) -> (Epoch, usize, Epoch, u64, u64) {
            let shard = &shards.shards[0];
            (
                shard.epoch(),
                shard.cached(),
                shards.backends[0].epoch(),
                shards.balance(&account(0)).await,
                shards.balance(&account(1)).await,
            )
        }
        for restart in [false, true] {
            if restart {
                shards.restart(0).await;
            }
            let before = state(&shards).await;
            shards.try_settle(0, 2, flows.clone()).await.unwrap();
            assert_eq!(state(&shards).await, before);
            assert_eq!(before.2, 2);
            assert_eq!((before.3, before.4), (70, 30));
        }

        // A retry after the next cut changes nothing, and the new cut stays pending.
        pay(&mut shards, &mut senders, 3, 0, 1, 20).await.unwrap();
        let next = deposits(3, &[]);
        let cuts = shards.cut(&next);
        let (_, later) = shards.assemble(&next, cuts);
        shards.try_settle(0, 2, flows.clone()).await.unwrap();
        assert_eq!(shards.live(&account(0)).await.unwrap(), 50);
        assert_eq!(shards.backends[0].epoch(), 2);
        shards.settle(3, later).await;
        assert_eq!(shards.balance(&account(0)).await, 50);

        // An older epoch is late, and changes nothing either.
        let result = shards.try_settle(0, 2, flows).await;
        assert!(matches!(result, Err(Error::Late { epoch: 2, found: 3 })));
        assert_eq!(shards.shards[0].epoch(), 4);
        assert_eq!(shards.backends[0].epoch(), 3);

        // A repeated catch-up changes nothing either.
        for _ in 0..2 {
            shards.try_settle(0, 5, Vec::new()).await.unwrap();
            assert_eq!(shards.shards[0].epoch(), 6);
            assert_eq!(shards.backends[0].epoch(), 5);
        }
    });
}

/// A flow that takes from its account needs the cut of its epoch, so a shard that lost its cut
/// refuses the flows of the epoch and changes nothing.
#[test]
fn test_taking_flow_needs_a_cut() {
    deterministic::Runner::default().start(|_| async move {
        let mut shards = Shards::new(1).await;
        close_queue(&mut shards, &deposits(1, &[(0, 100)])).await;

        // Alice withdraws everything in epoch 2, and the shard cuts it, then restarts without its
        // cut.
        let withdrawal = Withdrawal::sign(&user(0), &namespace(), 2, 100, 0);
        shards.shards[0].withdraw(withdrawal).unwrap();
        let queue = deposits(2, &[]);
        let cuts = shards.cut(&queue);
        let (_, flows) = shards.assemble(&queue, cuts);
        shards.cuts[0] = None;
        shards.restart(0).await;

        // Her flow asks to withdraw, so the shard refuses to settle it without the cut.
        let result = shards.try_settle(0, 2, flows).await;
        assert!(matches!(result, Err(Error::MissingCut)));
        assert_eq!(shards.shards[0].epoch(), 2);
        assert_eq!(shards.backends[0].epoch(), 1);
    });
}

/// A shard that caught up past an epoch did not cut it, so it refuses a late flow of that epoch
/// that takes from its account. Ignoring it would leave the account's balance from before the
/// epoch in the store, and the account could spend what the close took.
#[test]
fn test_taking_flow_after_catch_up_needs_a_cut() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut deployment = Deployment::new(&context, "caught", 1).await;
        let mut objects = Objects::default();
        let alice = account(0);
        deployment.ledger.deposit(alice.clone(), 100).unwrap();

        // Epochs 1 and 2 close without cuts. The close of epoch 2 processes a forced withdrawal of
        // alice's whole balance, but her shard is not woken and catches up past epoch 2 before her
        // flow of it arrives.
        let mut closes = Vec::new();
        for epoch in [1, 2] {
            if epoch == 2 {
                deployment.ledger.withdraw(alice.clone(), 100).unwrap();
            }
            let queue = deployment.ledger.queue();
            let (deposits, forced) = (
                queue.deposits.len() as u64,
                queue.forced_withdrawals.len() as u64,
            );
            let (close, flows) = TestClose::assemble::<Sha256, _>(
                &operator_key(),
                &namespace(),
                &queue,
                deposits,
                forced,
                Vec::new(),
            )
            .unwrap();
            let proposals = deployment.verify(&close).await;
            deployment.post(&mut context, proposals).await;
            closes.push(flows);
        }
        let shard = objects.of(&alice).await;
        shard.settle(1, closes[0].clone()).await.unwrap();
        shard.settle(2, Vec::new()).await.unwrap();
        let late = shard.settle(2, closes[1].clone()).await;

        // Had the shard ignored the flow, alice would spend her whole balance again.
        if late.is_ok() {
            let mut sender = sender(0);
            let request = sender.send(3, amounts(&[(1, 100)]), false).unwrap();
            shard.accept(&request).await.unwrap();
            let cut = shard.cut(3, 0, 0, &[]).unwrap();
            let queue = deployment.ledger.queue();
            let (close, _) = TestClose::assemble::<Sha256, _>(
                &operator_key(),
                &namespace(),
                &queue,
                0,
                0,
                vec![cut],
            )
            .unwrap();
            deployment.verify(&close).await;
        }
        assert!(matches!(late, Err(Error::MissingCut)));
        assert_eq!(shard.epoch(), 3);
    });
}

/// The operator's futures are [Send] when its store's are, so a deployment can run them on any
/// thread.
#[test]
fn test_operator_futures_are_send() {
    fn send<T: Send>(_: T) {}
    deterministic::Runner::default().start(|_| async move {
        send(Shard::init(
            operator_key(),
            namespace(),
            LIMITS,
            Backend::default(),
            [],
            None,
        ));
        let mut shard = start(Backend::default(), None).await.unwrap();
        let request = sender(0).send(1, amounts(&[(1, 1)]), false).unwrap();
        send(shard.accept(&request));
        send(shard.load(&[]));
        send(shard.live(&account(0)));
        send(shard.balance(&account(0)));
        send(shard.settle(1, Vec::new()));
        send(shard.close(&deposits(1, &[]), 0, 0));
    });
}

/// Random activity across shards never makes an honest close fail to verify, and every shard
/// holds the validators' balances once it settles. A shard given every flow but one refuses to
/// settle exactly when it deducted from the account left out.
#[test]
fn test_random_activity_matches_validators() {
    deterministic::Runner::default().start(|mut context| async move {
        const SHARDS: usize = 3;
        const USERS: u64 = 12;
        let mut rng = test_rng();
        let mut deployment = Deployment::new(&context, "random", 1).await;
        let mut shards = Shards::new(SHARDS).await;
        let users: Vec<_> = (0..USERS).collect();
        let mut senders = senders(&users);
        for index in &users {
            deployment.ledger.deposit(account(*index), 100).unwrap();
        }
        close_and_settle(&mut deployment, &mut context, &mut shards).await;

        let (mut missing, mut conservative) = (0, 0);
        for epoch in 2..=16 {
            // Users pay random users, sometimes beyond their floor.
            let mut deducted = HashSet::new();
            for _ in 0..rng.next_u64() % 12 {
                let from = rng.next_u64() % USERS;
                let to = rng.next_u64() % USERS;
                let live = shards.live(&account(from)).await.unwrap();
                let amount = 1 + rng.next_u64() % (live + 5);
                let result = pay(&mut shards, &mut senders, epoch, from, to, amount).await;
                if amount <= live {
                    result.unwrap();
                    deducted.insert(account(from));
                } else {
                    assert!(matches!(result, Err(Error::InsufficientBalance)));
                }
            }

            // Users withdraw through their shard or the ledger, and deposit.
            for tag in 0..rng.next_u64() % 3 {
                let index = rng.next_u64() % USERS;
                let amount = 1 + rng.next_u64() % 60;
                let withdrawal = Withdrawal::sign(&user(index), &namespace(), epoch, amount, tag);
                shards.of(&account(index)).withdraw(withdrawal).unwrap();
                deducted.insert(account(index));
            }
            for _ in 0..rng.next_u64() % 3 {
                let index = rng.next_u64() % USERS;
                let amount = 1 + rng.next_u64() % 60;
                deployment.ledger.withdraw(account(index), amount).unwrap();
                deducted.insert(account(index));
                let index = rng.next_u64() % USERS;
                let amount = 1 + rng.next_u64() % 60;
                deployment.ledger.deposit(account(index), amount).unwrap();
            }
            let (epoch, flows) = close(&mut deployment, &mut context, &mut shards).await;

            // A copy of a shard given every flow but one refuses to settle exactly when it deducted
            // from the account left out.
            for (index, flows) in shards.route(flows.clone()).into_iter().enumerate() {
                if flows.is_empty() || rng.next_u64().is_multiple_of(2) {
                    continue;
                }
                let skipped = (rng.next_u64() % flows.len() as u64) as usize;
                let account = flows[skipped].0.clone();
                let withheld = flows
                    .into_iter()
                    .enumerate()
                    .filter(|(position, _)| *position != skipped)
                    .map(|(_, flow)| flow)
                    .collect::<Vec<_>>();
                let mut copy = shards.start(index, shards.backends[index].fork()).await;
                let result = copy.settle(epoch, withheld).await;
                if deducted.contains(&account) {
                    assert!(matches!(result, Err(Error::MissingFlow)));
                    missing += 1;
                } else {
                    assert!(result.is_ok());
                    conservative += 1;
                }
            }
            shards.settle(epoch, flows).await;
            check_balances(&deployment, &shards, &users).await;
        }
        assert!(missing > 0 && conservative > 0);
    });
}
