//! Application orchestration across wallets, SQLite, and the clearing protocol.

#[cfg(test)]
use super::store::{AccountView, Endpoint, StoreSnapshot};
use super::{
    qmdb,
    rpc::{AcceptSendRequest, AcceptSendsRequest},
    store::{
        AcceptedBatch, CloseRejected, EpochData, IncomingPayment, MutationFailed, Report,
        SendsVerdict, StagedDeposit, StagedWithdrawal, Store, StoreStatus, StoredCloseOutcome,
        Take, TakeKind, withdrawal_amount,
    },
    verify::{VerifiedSends, verify_sends},
};
#[cfg(test)]
use crate::protocol::{
    DepositEvent, MAX_DESTINATION_BYTES, PreparedEpoch, Wallet, accounts, eve_identity, wallets,
};
use crate::{
    chain::{
        node::Pipeline,
        state::{AdmittedRootsResponse, Intake, RegistrationRecord, StatusRecord},
        tx::{AdmitRequest, RegisterEpochRequest},
    },
    protocol::{
        Account, AccountIdentity, Ack, Deployment, Entry, EpochRegistration, Key,
        MAX_ACCEPTED_PAYMENTS, MAX_DEPOSIT_EVENTS, Protocol, SettlementResult, Timing,
        deposit_batch, ensure_amount_withdrawal_horizon, ensure_balance_intake_horizon,
        ensure_close_horizon, identities, openable_epoch_after, short_digest,
    },
    store::CommitUnknown,
};
use anyhow::{Context, Result, ensure};
#[cfg(test)]
use bytes::Bytes;
#[cfg(test)]
use commonware_clearing::bajillion::payment::VectorSendBody;
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::HigherEntryLookup,
    commitment::{self, VectorKind, VectorRoot},
    logs::LogHead,
    payment::{PaymentContext, SendAuthorization},
    qmdb::{StateOpening, StateRoot},
    settlement::Genesis,
    transition::{BatchId, EpochContext, RootBundle, Terminal, WithdrawalClaim},
    vector::{OutEntry, OutVector},
};
#[cfg(test)]
use commonware_codec::EncodeSize as _;
use commonware_codec::{DecodeExt as _, Encode as _};
#[cfg(test)]
use commonware_cryptography::Hasher;
use commonware_cryptography::{Sha256, Signer as _, sha256::Digest};
#[cfg(test)]
use std::num::NonZeroU64;
#[cfg(test)]
use std::sync::mpsc::SyncSender;
#[cfg(test)]
use std::time::Duration;
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    num::NonZeroUsize,
    path::Path,
    sync::{
        Arc,
        mpsc::{self, Receiver, TryRecvError},
    },
    thread::{self, JoinHandle},
};

pub(crate) const DEFAULT_AMOUNT: u64 = 5;
type WithdrawalBoundary = (PaymentContext<Key, Digest>, WithdrawalBatch<Key, Digest>);
#[cfg(test)]
const DEPOSIT_ID_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_DEPOSIT";

pub(crate) struct CloseStarted {
    pub(crate) epoch: u64,
    pub(crate) queued: bool,
}

pub(crate) struct PaymentHead {
    pub(crate) context: EpochContext<Key, Digest>,
    pub(crate) balance: u64,
    /// First epoch whose payments the floor root omits.
    pub(crate) floor_epoch: u64,
    pub(crate) root: StateRoot<Digest>,
    pub(crate) opening: StateOpening<Key, Digest>,
}

/// A payment head captured under the operator lock. Resolving it queries the
/// proof replica, so callers resolve it after releasing the lock.
pub(crate) struct HeadSnapshot {
    context: EpochContext<Key, Digest>,
    balance: u64,
    floor_epoch: u64,
    account: Key,
    balances: qmdb::Handle,
}

impl HeadSnapshot {
    /// Opens the payer at the floor checkpoint. The replica replays only
    /// certified results the operator already retained, so this never waits
    /// for an unfinished close.
    pub(crate) fn resolve(self) -> Result<PaymentHead> {
        Ok(PaymentHead {
            root: self.balances.root(self.floor_epoch)?,
            opening: self.balances.opening(self.floor_epoch, &self.account)?,
            context: self.context,
            balance: self.balance,
            floor_epoch: self.floor_epoch,
        })
    }
}

pub(crate) struct WithdrawalOpening {
    pub(crate) root: StateRoot<Digest>,
    pub(crate) opening: StateOpening<Key, Digest>,
}

/// A withdrawal opening captured under the operator lock and resolved after
/// releasing it.
pub(crate) struct OpeningSnapshot {
    checkpoint: u64,
    root: StateRoot<Digest>,
    account: Key,
    balances: qmdb::Handle,
}

impl OpeningSnapshot {
    /// Opens the account at the finalized checkpoint.
    pub(crate) fn resolve(self) -> Result<WithdrawalOpening> {
        ensure!(
            self.balances.root(self.checkpoint)? == self.root,
            "proof replica differs from finalized root"
        );
        Ok(WithdrawalOpening {
            opening: self
                .balances
                .opening(self.checkpoint, &self.account)
                .context("open withdrawing account")?,
            root: self.root,
        })
    }
}

/// The operator's verdict on one submitted send.
pub(crate) enum SendOutcome {
    /// The send, or its exact replay, is committed with its acceptance.
    Accepted(AcceptedBatch),
    /// An unauthenticated report: the live context, the payer's endpoint in the rejected
    /// send's epoch, and the predecessor the live epoch requires.
    Stale {
        context: PaymentContext<Key, Digest>,
        report: Report,
    },
}

/// The verdict for a complete ordered payer submission.
#[allow(clippy::large_enum_variant)]
pub(crate) enum SendsOutcome {
    Accepted(Vec<AcceptedBatch>),
    Stale {
        context: PaymentContext<Key, Digest>,
        report: Report,
    },
}

#[cfg(test)]
impl SendOutcome {
    /// Unwraps the accepted batch, panicking on a corrective rejection.
    pub(crate) fn into_accepted(self) -> AcceptedBatch {
        match self {
            Self::Accepted(accepted) => accepted,
            Self::Stale { .. } => panic!("the send was rejected with a corrective context"),
        }
    }
}

pub(crate) struct CloseFinished {
    pub(crate) epoch: u64,
    pub(crate) header_digest: String,
    pub(crate) rows: usize,
    pub(crate) dealing_bytes: usize,
    pub(crate) withdrawal_total: u64,
    pub(crate) header_bytes: usize,
    pub(crate) certificate_bytes: usize,
    pub(crate) prepare_micros: u128,
    pub(crate) deal_micros: u128,
    pub(crate) seal_micros: u128,
}

pub(crate) enum CloseEvent {
    Finished(CloseFinished),
    Failed { epoch: u64, error: String },
}

struct AdmittedClose {
    epoch: u64,
    batch_id: BatchId<Digest>,
    roots: RootBundle<Digest>,
}

struct ActiveClose {
    epoch: u64,
    receiver: Receiver<Result<SettlementResult>>,
    thread: JoinHandle<()>,
}

/// Where a test holds the next close worker.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stage {
    /// Before the worker prepares the close.
    Prepare,
    /// After preparation, before certification.
    Certify,
    /// After the certified result is retained, before admission.
    Admit,
}

#[cfg(test)]
struct CloseGate {
    stage: Stage,
    started: SyncSender<()>,
    release: Receiver<()>,
}

#[cfg(test)]
impl CloseGate {
    /// Signals arrival and blocks until released. Returns whether the release
    /// side is still connected.
    fn hold(self) -> bool {
        let _ = self.started.send(());
        self.release.recv().is_ok()
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum ResultFailure {
    Read,
    Commit,
}

/// Complete local operator. Only public state and signed artifacts enter SQLite.
pub(crate) struct Operator {
    store: Store,
    balances: Option<qmdb::Handle>,
    protocol: Arc<Protocol>,
    identities: Vec<AccountIdentity>,
    #[cfg(test)]
    wallets: Vec<Wallet>,
    /// Close pipeline over the operator node's DA channel and local chain
    /// backend. `None` runs the in-process harness certification instead.
    pipeline: Option<Pipeline>,
    epoch_fee: u64,
    genesis: commonware_clearing::bajillion::settlement::Genesis<Digest>,
    registration: EpochRegistration,
    // Every read revalidates the cached successor plan against durable state before extending
    // it over rows observed since.
    projection: RefCell<Option<Box<Projection>>>,
    #[cfg(test)]
    initial_accounts: Vec<Account>,
    active_close: Option<ActiveClose>,
    // The FIFO retains admission identities; close jobs own the complete durable results.
    admitted: VecDeque<AdmittedClose>,
    recovering: bool,
    store_fault: Option<String>,
    close_fault: Option<String>,
    #[cfg(test)]
    close_gate: Option<CloseGate>,
    #[cfg(test)]
    fail_close_spawn: bool,
    #[cfg(test)]
    panic_close_worker: bool,
    #[cfg(test)]
    result_failure: Option<ResultFailure>,
    #[cfg(test)]
    registration_probe_failure: std::cell::Cell<Option<usize>>,
}

/// A boundary with the takes planned into it, in index order.
struct Plan {
    registration: EpochRegistration,
    takes: Vec<Take>,
    deposit_events: usize,
}

/// A successor plan and the withdrawals of the base it extends.
struct Projection {
    base: WithdrawalBatch<Key, Digest>,
    plan: Plan,
}

/// How a boundary takes one chain-queued withdrawal row.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// The request is already staged, so the take only links it to its row.
    Link,
    /// A registration carries another request for the account.
    Superseded,
    /// The take stages the request.
    Fresh,
}

impl Operator {
    #[cfg(test)]
    pub(crate) fn open(path: &Path, workers: NonZeroUsize) -> Result<Self> {
        let identities = identities();
        let store = Store::open(path, &identities)?;
        Self::from_store(
            store,
            identities,
            Protocol::new(workers)?,
            None,
            &accounts(),
            None,
            4 * 1024,
            true,
        )
    }

    /// Opens the operator from the identity and initial balances of its certified deployment.
    pub(crate) fn open_remote(
        path: &Path,
        workers: NonZeroUsize,
        pipeline: Pipeline,
        config: &Deployment,
        clearing: commonware_cryptography_curve25519::signing::SigningKey,
        epoch_fee: u64,
        proof_replica: bool,
    ) -> Result<Self> {
        let protocol = Protocol::with_signer(workers, *config.digest(), clearing)?;
        ensure!(
            protocol.operator().public_key() == config.operator,
            "operator signing key differs from the certified deployment"
        );
        let known = identities();
        let identities = config
            .accounts
            .iter()
            .map(|account| AccountIdentity {
                name: known
                    .iter()
                    .find(|identity| identity.key == account.key)
                    .map_or("Account", |identity| identity.name),
                key: account.key.clone(),
            })
            .collect::<Vec<_>>();
        let store = Store::open_configured(path, &identities, &config.accounts)?;
        Self::from_store(
            store,
            identities,
            protocol,
            Some(pipeline),
            &config.accounts,
            Some(*config.genesis()),
            epoch_fee,
            proof_replica,
        )
    }

    #[cfg(test)]
    fn in_memory(workers: NonZeroUsize) -> Result<Self> {
        let identities = identities();
        let store = Store::in_memory(&identities)?;
        Self::from_store(
            store,
            identities,
            Protocol::new(workers)?,
            None,
            &accounts(),
            None,
            4 * 1024,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_store(
        mut store: Store,
        identities: Vec<AccountIdentity>,
        protocol: Protocol,
        pipeline: Option<Pipeline>,
        initial_accounts: &[Account],
        configured: Option<Genesis<Digest>>,
        epoch_fee: u64,
        proof_replica: bool,
    ) -> Result<Self> {
        let protocol = Arc::new(protocol);
        #[cfg(test)]
        let configured = match configured {
            Some(configured) => Some(configured),
            None => Some(protocol.fixture_genesis(initial_accounts)?),
        };
        let configured = configured.context("operator requires a configured genesis")?;
        ensure!(
            initial_accounts
                .iter()
                .try_fold(0u64, |total, account| total.checked_add(account.balance))
                .context("genesis liability overflow")?
                == configured.liability(),
            "configured genesis liability mismatch"
        );
        let configured_genesis_root = configured.root();
        store.bind_genesis(configured_genesis_root)?;
        let balances = if proof_replica {
            qmdb::Handle::open(
                &store.database_path(),
                initial_accounts,
                Arc::clone(&protocol),
                store.epoch_reader(),
                Some(configured),
            )
            .map_err(|error| {
                tracing::warn!(?error, "optional operator proof replica is unavailable");
                error
            })
            .ok()
        } else {
            None
        };
        let current = store.load_current()?;
        let mut registration = registration_for(&protocol, &current)?;
        registration.intake = store.live_intake()?;
        store.ensure_current_context(registration.context.payment())?;
        validate_epoch_data(&current, &registration, &store.predecessors(current.epoch)?)
            .context("validate current SQLite epoch")?;
        ensure!(
            projected_liability(&current)? == store.current_liability()?,
            "stored live liability differs from the projected account state"
        );
        ensure!(
            current.deposits.len() == store.current_deposit_events()?,
            "stored deposit event count differs from the current epoch log"
        );
        let close_fault = store.failed_close()?;
        let pending_close = store.closing_epoch_from(0)?.is_some();

        // A restarted operator releases intake only after authenticating its
        // live registration against the chain.
        let recovering = close_fault.is_none() && (pending_close || registration.floors.is_some());
        if close_fault.is_none() && !pending_close {
            let expected_epoch = store.latest_finalized_root()?.map_or(Ok(0), |(epoch, _)| {
                epoch.checked_add(1).context("settlement epoch overflow")
            })?;
            ensure!(
                current.epoch == expected_epoch,
                "current epoch does not extend the finalized settlement tip"
            );
        }

        let mut operator = Self {
            store,
            balances,
            protocol,
            identities,
            #[cfg(test)]
            wallets: wallets(),
            pipeline,
            genesis: configured,
            registration,
            projection: RefCell::new(None),
            #[cfg(test)]
            initial_accounts: initial_accounts.to_vec(),
            active_close: None,
            admitted: VecDeque::new(),
            epoch_fee,
            recovering,
            store_fault: None,
            close_fault,
            #[cfg(test)]
            close_gate: None,
            #[cfg(test)]
            fail_close_spawn: false,
            #[cfg(test)]
            panic_close_worker: false,
            #[cfg(test)]
            result_failure: None,
            #[cfg(test)]
            registration_probe_failure: std::cell::Cell::new(None),
        };
        operator.start_next_persisted_close()?;
        Ok(operator)
    }

    #[cfg(test)]
    pub(crate) const fn wallet_count(&self) -> usize {
        self.wallets.len()
    }

    #[cfg(test)]
    pub(crate) const fn receiver_count(&self) -> usize {
        self.wallets.len() + 1
    }

    #[cfg(test)]
    pub(crate) fn pay(
        &mut self,
        payer: usize,
        receiver: usize,
        amount: u64,
    ) -> Result<AcceptedBatch> {
        self.ensure_operating()?;
        ensure!(amount > 0, "payment amount must be positive");
        let payer = payer % self.wallets.len();
        let receiver_index = receiver % self.receiver_count();
        let receiver = if receiver_index == self.wallets.len() {
            eve_identity().key
        } else {
            self.wallets[receiver_index].public_key()
        };
        let balance = self
            .store
            .current_account(&self.wallets[payer].public_key())?
            .context("selected payer is not registered")?
            .current;
        ensure!(balance > 0, "selected payer has no balance");
        let (authorization, entries) = self.sign_send(payer, &[(receiver, amount)])?;
        match self.accept_send(authorization, entries)? {
            SendOutcome::Accepted(accepted) => Ok(accepted),

            // Mutations are serialized on `&mut self`, so the endpoint cannot move
            // between the signing above and this acceptance.
            SendOutcome::Stale { .. } => unreachable!("the live endpoint moved under one borrow"),
        }
    }

    /// Signs `deltas` from wallet `payer` at its live accepted endpoint.
    #[cfg(test)]
    pub(crate) fn sign_send(
        &self,
        payer: usize,
        deltas: &[(Key, u64)],
    ) -> Result<(SendAuthorization<Key, Digest>, Vec<Entry>)> {
        let wallet = &self.wallets[payer % self.wallets.len()];
        let endpoint = self.store.payer_endpoint(&wallet.public_key())?;
        sign_send_at(
            self.registration.context.payment(),
            self.store.predecessor(&wallet.public_key())?,
            wallet,
            &endpoint,
            deltas,
        )
    }

    // SQL cutover projects successor balances before certification and admission complete.
    // A key created only by those credits waits for admission before originating payments or withdrawals.
    fn ensure_payer_eligible(&self, account: &Key) -> Result<()> {
        let first_unadmitted = self.certified_tip()?.map_or(Ok(0), |(epoch, _)| {
            epoch.checked_add(1).context("admitted epoch overflow")
        })?;
        self.store.ensure_payer_eligible(account, first_unadmitted)
    }

    #[cfg(test)]
    pub(crate) fn payment_head(&self, account: &Key) -> Result<PaymentHead> {
        self.head_snapshot(account)?.resolve()
    }

    /// Captures the live context and balance with the floor at the locally
    /// admitted tip, or else the finalized tip. The floor never depends on the
    /// live epoch's own predecessor close, which may still be unfinished.
    pub(crate) fn head_snapshot(&self, account: &Key) -> Result<HeadSnapshot> {
        self.ensure_operating()?;
        self.ensure_balance_intake_horizon()?;
        self.ensure_payer_eligible(account)?;
        let state = self
            .store
            .current_account(account)?
            .context("payer is not in the current live state")?;
        ensure!(state.current > 0, "payer is not in the current live state");
        let floor_epoch = self.certified_tip()?.map_or(Ok(0), |(epoch, _)| {
            epoch.checked_add(1).context("admitted epoch overflow")
        })?;
        Ok(HeadSnapshot {
            context: self.registration.context.clone(),
            balance: state.current,
            floor_epoch,
            account: account.clone(),
            balances: self
                .balances
                .clone()
                .context("optional proof replica is unavailable")?,
        })
    }

    /// Reads the committed batch for one authorization, a plain durable lookup by its
    /// signed endpoint.
    ///
    /// This is an optional receipts fetch for a wallet that already decided commitment from
    /// a finalized settlement root. It carries no verdict, so it stays readable across the
    /// operating fence (a failed predecessor close leaves committed rows intact) but still
    /// refuses to read past a storage fault, which is fatal until the operator restarts.
    pub(crate) fn accepted_batch(
        &self,
        authorization: &SendAuthorization<Key, Digest>,
        entries: &[Entry],
    ) -> Result<Option<AcceptedBatch>> {
        self.ensure_store_usable()?;
        self.store.accepted_batch(authorization, entries)
    }

    /// Serves accepted entry receipts crediting `receiver` after the caller's durable cursor.
    ///
    /// This is a plain durable read of committed serving-log rows, so it stays readable across
    /// the operating fence and refuses only past a storage fault.
    pub(crate) fn incoming_payments(
        &self,
        receiver: &Key,
        after: u64,
        limit: usize,
    ) -> Result<Vec<IncomingPayment>> {
        self.ensure_store_usable()?;
        self.store.incoming_payments(receiver, after, limit)
    }

    /// Opens a locally certified payer-recipient edge from the optional native replica.
    pub(crate) fn committed_entry(
        &self,
        payer: &Key,
        recipient: &Key,
        epoch: u64,
    ) -> Result<HigherEntryLookup<Key, Digest>> {
        self.ensure_store_usable()?;
        self.balances
            .as_ref()
            .context("operator proof replica unavailable")?
            .committed_entry(epoch, payer, recipient)
    }

    pub(crate) fn payment_strategy(&self) -> commonware_parallel::Rayon {
        self.protocol.strategy().clone()
    }

    pub(crate) fn accept_send(
        &mut self,
        authorization: SendAuthorization<Key, Digest>,
        entries: Vec<Entry>,
    ) -> Result<SendOutcome> {
        Ok(
            match self.accept_sends(AcceptSendsRequest {
                sends: vec![AcceptSendRequest {
                    authorization,
                    entries,
                }],
            })? {
                SendsOutcome::Accepted(mut accepted) => {
                    SendOutcome::Accepted(accepted.pop().expect("one submitted send"))
                }
                SendsOutcome::Stale { context, report } => SendOutcome::Stale { context, report },
            },
        )
    }

    pub(crate) fn accept_sends(&mut self, request: AcceptSendsRequest) -> Result<SendsOutcome> {
        #[cfg(test)]
        let mut rng = commonware_utils::test_rng();
        #[cfg(not(test))]
        let mut rng = rand::rng();
        let verified = verify_sends(vec![request], &mut rng, self.protocol.strategy())
            .pop()
            .expect("one submitted batch")?;
        self.accept_verified_sends(vec![verified])?
            .pop()
            .expect("one submitted batch")
    }

    pub(crate) fn accept_verified_sends(
        &mut self,
        requests: Vec<VerifiedSends>,
    ) -> Result<Vec<Result<SendsOutcome>>> {
        self.ensure_operating()?;
        let context = self.registration.context.payment().clone();
        let requests = requests
            .into_iter()
            .map(|request| {
                let admission = self.ensure_balance_intake_horizon().and_then(|()| {
                    self.ensure_payer_eligible(
                        request.request().sends[0].authorization.body().payer(),
                    )
                });
                (request, admission)
            })
            .collect();
        let result = self
            .store
            .accept_verified_sends(&context, &self.protocol, requests);
        let committed = self.guard_store(result)?;
        if committed.requests > 0 {
            println!(
                "payment group committed: epoch={} requests={} entries={}",
                committed.epoch, committed.requests, committed.entries,
            );
        }
        Ok(committed
            .verdicts
            .into_iter()
            .map(|verdict| {
                Ok(match verdict? {
                    SendsVerdict::Accepted(accepted) => SendsOutcome::Accepted(accepted),
                    SendsVerdict::Stale(report) => SendsOutcome::Stale {
                        context: context.clone(),
                        report,
                    },
                })
            })
            .collect())
    }

    pub(crate) fn send_requires_epoch_registration_verified(
        &self,
        request: &VerifiedSends,
    ) -> Result<bool> {
        #[cfg(test)]
        if let Some(remaining) = self.registration_probe_failure.get() {
            if remaining == 0 {
                self.registration_probe_failure.set(None);
                return Err(rusqlite::Error::InvalidQuery.into());
            }
            self.registration_probe_failure.set(Some(remaining - 1));
        }
        self.ensure_operating()?;
        let context = self.registration.context.payment();
        if self.registration.floors.is_some() {
            return Ok(false);
        }
        let required =
            self.store
                .sends_require_epoch_registration(context, &self.protocol, request)?;
        if required {
            self.ensure_balance_intake_horizon()?;
            self.ensure_payer_eligible(request.request().sends[0].authorization.body().payer())?;
        }
        Ok(required)
    }

    pub(crate) fn send_requires_epoch_registration(
        &self,
        authorization: &SendAuthorization<Key, Digest>,
        entries: &[Entry],
    ) -> Result<bool> {
        #[cfg(test)]
        let mut rng = commonware_utils::test_rng();
        #[cfg(not(test))]
        let mut rng = rand::rng();
        let verified = verify_sends(
            vec![AcceptSendsRequest {
                sends: vec![AcceptSendRequest {
                    authorization: authorization.clone(),
                    entries: entries.to_vec(),
                }],
            }],
            &mut rng,
            self.protocol.strategy(),
        )
        .pop()
        .expect("one submitted batch")?;
        self.send_requires_epoch_registration_verified(&verified)
    }

    #[cfg(test)]
    pub(crate) fn fail_registration_probe_after(&self, successful_probes: usize) {
        self.registration_probe_failure.set(Some(successful_probes));
    }

    #[cfg(test)]
    pub(crate) const fn fail_next_payment_commit(&mut self) {
        self.store.fail_next_payment_commit();
    }

    #[cfg(test)]
    pub(crate) fn gate_next_payment_commit(
        &mut self,
        entered: commonware_utils::channel::oneshot::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        self.store.gate_next_payment_commit(entered, release);
    }

    #[cfg(test)]
    pub(crate) fn deposit(&mut self, wallet: usize, amount: u64) -> Result<StagedDeposit> {
        self.ensure_operating()?;
        let key = self.wallets[wallet % self.wallets.len()].public_key();
        let index = self.store.observed()?;
        let event = DepositEvent {
            id: Sha256::hash(&[
                DEPOSIT_ID_NAMESPACE,
                &index.to_be_bytes(),
                key.as_ref(),
                &amount.to_be_bytes(),
            ]),
            account: key,
            amount,
        };
        let mut staged = self.observe(index, &[Intake::Deposit(event)])?;
        staged
            .pop()
            .context("the live boundary did not take the deposit")
    }

    /// Whether settlement superseded the chain-queued `request` recorded at inbox `index`. It
    /// decides only for registrations this operator adopted.
    pub(crate) fn superseded(
        &self,
        request: &SignedWithdrawal<Key, Digest>,
        index: u64,
    ) -> Result<bool> {
        self.ensure_store_usable()?;
        self.store.superseded(request, index)
    }

    /// Returns the next inbox index to observe.
    pub(crate) fn observed(&self) -> Result<u64> {
        self.ensure_store_usable()?;
        self.store.observed()
    }

    /// Records certified inbox entries from index `start`, the operator's only intake, and lets
    /// the live boundary take the untaken inbox while it is unpublished. Returns the newly
    /// credited deposits. A fenced operator takes nothing, because its live epoch never
    /// registers and settlement refunds what it would credit.
    ///
    /// Observation follows the chain's inbox in index order. Indices below the observed cursor
    /// are skipped, so a crash between the certified reads and this commit observes the same
    /// entries again. The live boundary takes rows in index order, so it always holds a prefix
    /// of the untaken inbox. Rows it cannot take wait for a later epoch: every row once its
    /// boundary is published, because a stale signed registration stays valid, and every row
    /// from the first one the close limits do not admit.
    pub(crate) fn observe(&mut self, start: u64, records: &[Intake]) -> Result<Vec<StagedDeposit>> {
        self.ensure_store_usable()?;
        let observed = self.store.observed()?;
        ensure!(
            start <= observed,
            "inbox observation from index {start} skips unobserved index {observed}"
        );
        let skip = usize::try_from(observed - start).unwrap_or(usize::MAX);
        let fresh = records.get(skip..).unwrap_or_default();
        let mut plan = Plan {
            registration: self.registration.clone(),
            takes: Vec::new(),
            deposit_events: self.store.current_deposit_events()?,
        };
        if self.close_fault.is_none() && !self.store.published()? {
            let rows = self
                .store
                .untaken()?
                .into_iter()
                .chain((observed..).zip(fresh.iter().cloned()));
            plan = self.plan_takes(plan, rows)?;
        }
        let Plan {
            registration,
            takes,
            ..
        } = plan;
        if fresh.is_empty() && takes.is_empty() {
            return Ok(Vec::new());
        }
        let result =
            self.store
                .observe(observed, fresh, &takes, self.registration.context.payment());
        let staged = self.guard_store(result)?;
        self.registration = registration;
        Ok(staged)
    }

    // Extends `plan` with the takes of `rows` in index order. Planning stops at the first row the
    // close limits or the intake horizon do not admit, which waits for a later epoch.
    fn plan_takes(
        &self,
        mut plan: Plan,
        rows: impl IntoIterator<Item = (u64, Intake)>,
    ) -> Result<Plan> {
        let epoch = plan.registration.context.payment().epoch();
        for (index, record) in rows {
            let registration = &plan.registration;
            ensure!(
                index == registration.intake.end,
                "the untaken inbox is not contiguous with the boundary"
            );
            let (kind, mut replacement) = match record {
                Intake::Deposit(event) => {
                    if plan.deposit_events >= MAX_DEPOSIT_EVENTS
                        || ensure_balance_intake_horizon(epoch).is_err()
                    {
                        break;
                    }
                    let Ok(replacement) = registration_with_deposit(
                        &self.protocol,
                        registration,
                        event.account.clone(),
                        event.amount,
                    ) else {
                        break;
                    };
                    plan.deposit_events += 1;
                    let identity = self.identity(&event.account);
                    (TakeKind::Deposit { identity, event }, replacement)
                }
                Intake::Withdrawal(request) => match self.classify(epoch, index, &request)? {
                    Class::Link => (TakeKind::Link { request }, registration.clone()),
                    Class::Superseded => (TakeKind::Superseded { request }, registration.clone()),
                    Class::Fresh => {
                        let horizon = match request.body().action() {
                            WithdrawalAction::Amount(_) => ensure_amount_withdrawal_horizon(epoch),
                            WithdrawalAction::Close => ensure_close_horizon(epoch),
                        };
                        if horizon.is_err() {
                            break;
                        }
                        let replaced = registration
                            .withdrawals
                            .request_for(request.account())
                            .cloned();
                        let Ok(replacement) = registration_replacing_withdrawal(
                            &self.protocol,
                            registration,
                            replaced.as_ref(),
                            request.clone(),
                        ) else {
                            break;
                        };
                        let kind = TakeKind::Withdrawal {
                            request,
                            replaced: replaced.map(Box::new),
                        };
                        (kind, replacement)
                    }
                },
            };
            replacement.intake.end = index.checked_add(1).context("inbox index overflow")?;
            plan.takes.push(Take {
                index,
                kind,
                replacement: replacement.context.payment().clone(),
            });
            plan.registration = replacement;
        }
        Ok(plan)
    }

    // How the boundary of `epoch` takes the chain-queued `request` recorded at inbox `index`.
    fn classify(
        &self,
        epoch: u64,
        index: u64,
        request: &SignedWithdrawal<Key, Digest>,
    ) -> Result<Class> {
        if let Some(staged) = self.store.staged_withdrawal_request(request)? {
            // The request is already staged in this epoch, or an earlier registration carried it
            // early. Either way it is carried once.
            ensure!(
                staged.epoch <= epoch,
                "a chain-queued withdrawal is staged in a later epoch"
            );
            Ok(Class::Link)
        } else if self.store.superseded(request, index)? {
            Ok(Class::Superseded)
        } else {
            Ok(Class::Fresh)
        }
    }

    // The display identity of `key`, or a generic one for an account outside the demo set.
    fn identity(&self, key: &Key) -> AccountIdentity {
        self.identities
            .iter()
            .find(|identity| identity.key == *key)
            .cloned()
            .unwrap_or(AccountIdentity {
                name: "Account",
                key: key.clone(),
            })
    }

    #[cfg(test)]
    pub(crate) fn withdraw(
        &mut self,
        wallet: usize,
        action: WithdrawalAction,
    ) -> Result<StagedWithdrawal> {
        self.ensure_operating()?;
        let wallet = &self.wallets[wallet % self.wallets.len()];
        let deadline = crate::protocol::epoch_start(self.registration.context.payment().epoch())?
            .checked_add(50)
            .context("withdrawal deadline overflow")?;
        let destination = Bytes::copy_from_slice(wallet.public_key().as_ref());
        ensure!(
            destination.len() <= MAX_DESTINATION_BYTES,
            "operator destination exceeds its bound"
        );
        let request = SignedWithdrawal::sign(
            self.protocol.deployment(),
            destination,
            action,
            deadline,
            wallet.signer(),
        );
        self.apply_withdrawal(request, false)
    }

    #[cfg(test)]
    pub(crate) fn withdrawal_opening(&self, account: &Key) -> Result<WithdrawalOpening> {
        self.opening_snapshot(account)?.resolve()
    }

    /// Captures a finalized balance opening for withdrawal recovery and escalation.
    pub(crate) fn opening_snapshot(&self, account: &Key) -> Result<OpeningSnapshot> {
        self.ensure_operating()?;
        ensure_close_horizon(self.registration.context.payment().epoch())?;
        self.ensure_payer_eligible(account)?;
        let (checkpoint, root) = match self.store.latest_finalized_root()? {
            Some((epoch, root)) => (
                epoch
                    .checked_add(1)
                    .context("finalized checkpoint overflow")?,
                root,
            ),
            None => (0, self.genesis.root()),
        };
        Ok(OpeningSnapshot {
            checkpoint,
            root,
            account: account.clone(),
            balances: self
                .balances
                .clone()
                .context("optional proof replica is unavailable")?,
        })
    }

    // Intake stages into the successor only once the live epoch adopted its certified
    // registration. An unadopted live boundary can still be unpublished, which would leave
    // successor rows ahead of the intake it takes again.
    fn withdrawal_registration(&self) -> Result<EpochRegistration> {
        if self.registration.floors.is_some() && self.store.published()? {
            self.successor().map(|(registration, _)| registration)
        } else {
            Ok(self.registration.clone())
        }
    }

    /// Whether publication has fixed the boundary available to withdrawal intake.
    pub(crate) fn withdrawals_frozen(&self) -> Result<bool> {
        self.ensure_operating()?;
        self.store
            .withdrawals_frozen(self.withdrawal_registration()?.context.payment().epoch())
    }

    /// Stages an authorization after the service authenticates fresh intake or its exact queue record.
    pub(crate) fn apply_withdrawal(
        &mut self,
        request: SignedWithdrawal<Key, Digest>,
        queued: bool,
    ) -> Result<StagedWithdrawal> {
        Key::decode(request.body().destination().clone())
            .context("withdrawal destination is not a canonical native account")?;
        if let Some(staged) = self.staged_withdrawal(&request)? {
            return Ok(staged);
        }
        self.ensure_operating()?;

        // An observed chain-queued withdrawal takes precedence over a different request for its
        // account.
        if let Some(queued) = self.store.queued_intake(request.account())? {
            ensure!(
                queued == request,
                "the account has another chain-queued withdrawal"
            );
        }
        let registration = self.withdrawal_registration()?;
        let epoch = registration.context.payment().epoch();
        match request.body().action() {
            WithdrawalAction::Amount(_) => ensure_amount_withdrawal_horizon(epoch)?,
            WithdrawalAction::Close => ensure_close_horizon(epoch)?,
        }
        ensure!(
            !self.store.withdrawals_frozen(epoch)?,
            "withdrawal boundary is published"
        );
        if !queued {
            ensure!(
                registration.intake.end == self.store.observed()?,
                "the withdrawal boundary leaves inbox rows untaken"
            );
            self.ensure_payer_eligible(request.account())?;
        }
        request
            .verify_deployment(&self.protocol.deployment())
            .context("verify withdrawal authorization")?;
        let replacement =
            registration_with_withdrawal(&self.protocol, &registration, request.clone())
                .context("prospective withdrawal does not fit the epoch anchor")?;
        let result = self.store.stage_withdrawal(
            &request,
            registration.context.payment(),
            replacement.context.payment(),
            queued,
        );
        let staged = self.guard_store(result)?;
        if epoch == self.registration.context.payment().epoch() {
            self.registration = replacement;
        }
        Ok(staged)
    }

    /// Unregistered authorizations and the exact boundary that owns them.
    pub(crate) fn unregistered_withdrawals(&self) -> Result<Option<WithdrawalBoundary>> {
        self.ensure_store_usable()?;
        if self.ensure_operating().is_err() {
            return Ok(None);
        }
        let registration = self.withdrawal_registration()?;
        if registration.withdrawals.requests().is_empty() || registration.floors.is_some() {
            return Ok(None);
        }
        Ok(Some((
            registration.context.payment().clone(),
            registration.withdrawals,
        )))
    }

    /// Restores reservations proven unable to enter settlement under this boundary.
    pub(crate) fn discard_unregistered_withdrawals(
        &mut self,
        expected: &PaymentContext<Key, Digest>,
        discarded: &WithdrawalBatch<Key, Digest>,
    ) -> Result<()> {
        self.ensure_operating()?;
        let registration = if expected.epoch() == self.registration.context.payment().epoch() {
            self.registration.clone()
        } else {
            self.withdrawal_registration()?
        };
        if registration.context.payment() != expected || discarded.requests().is_empty() {
            return Ok(());
        }
        for request in discarded.requests() {
            ensure!(
                registration.withdrawals.request_for(request.account()) == Some(request),
                "discarded withdrawal differs from the live boundary"
            );
        }
        let remaining = registration
            .withdrawals
            .requests()
            .iter()
            .filter(|request| discarded.request_for(request.account()).is_none())
            .cloned()
            .collect();
        let mut replacement = self.protocol.registration(
            expected.epoch(),
            registration.deposits,
            WithdrawalBatch::new(remaining)?,
            registration.liability,
        )?;
        replacement.intake = registration.intake;
        let result = self.store.discard_unregistered_withdrawals(
            expected,
            replacement.context.payment(),
            discarded.requests(),
        );
        self.guard_store(result)?;
        if expected.epoch() == self.registration.context.payment().epoch() {
            self.registration = replacement;
        }
        Ok(())
    }

    pub(crate) fn staged_withdrawal(
        &self,
        request: &SignedWithdrawal<Key, Digest>,
    ) -> Result<Option<StagedWithdrawal>> {
        self.ensure_store_usable()?;
        if let Some(staged) = self.store.staged_withdrawal_request(request)? {
            return Ok(Some(staged));
        }
        let Some((stored, staged)) = self.store.staged_withdrawal(request.account())? else {
            return Ok(None);
        };

        // The observed inbox selects which request the successor carries for this account.
        if stored != *request
            && staged.epoch == self.next_openable_epoch()?
            && self
                .successor()?
                .0
                .withdrawals
                .request_for(request.account())
                == Some(request)
        {
            return Ok(None);
        }
        ensure!(
            stored == *request,
            "account already staged another withdrawal"
        );
        Ok(Some(staged))
    }

    /// Freezes the predecessor and installs its exactly certified successor before scheduling
    /// close construction. Payer vectors and deferred withdrawals resolve at this handoff.
    pub(crate) fn start_close(
        &mut self,
        expected_epoch: u64,
        record: &RegistrationRecord,
    ) -> Result<CloseStarted> {
        if self.close_already_started(expected_epoch)? {
            return Ok(CloseStarted {
                epoch: expected_epoch,
                queued: true,
            });
        }
        self.validate_close_start(expected_epoch)?;
        ensure!(
            self.registration.floors.is_some(),
            "the live epoch has no adopted registration to close"
        );
        let epoch = expected_epoch;
        let payment_context = self.registration.context.payment().clone();
        ensure!(
            self.store.successor_end()?.is_some(),
            "successor publication has not begun"
        );
        let (successor, takes) = self.certified_successor(record)?;
        let next_epoch = successor.context.payment().epoch();
        let cutover = self.store.rotate_epoch(
            epoch,
            self.registration.context.payment(),
            &successor.context,
            &takes,
            self.registration.intake.end,
            record,
        );
        if let Err(error) = self.guard_store(cutover) {
            if self.store_fault.is_some() {
                return Err(error);
            }
            let message = format!("epoch {epoch} cutover failed: {error:#}");
            self.close_fault = Some(message.clone());
            return Err(error.context(format!("operator fenced: {message}")));
        }
        println!("epoch {epoch} cut; successor={next_epoch}");

        // SQLite commits successor adoption with the cut, so every new receipt belongs to the
        // certified boundary and binds its payer's final predecessor vector.
        let scheduling: Result<bool> = (|| {
            self.registration = successor;
            self.validate_current_epoch()?;
            let queued = self.active_close.is_some();
            if !queued {
                self.spawn_close(payment_context)?;
            }
            Ok(queued)
        })();
        let queued = match scheduling {
            Ok(queued) => queued,
            Err(error) => {
                let message = format!("epoch {epoch} could not be scheduled: {error:#}");
                self.close_fault = Some(message.clone());
                let persisted = self.store.fail_close(epoch, &message);
                if let Err(persist_error) = self.guard_store(persisted) {
                    return Err(anyhow::anyhow!(
                        "operator fenced after {message}; persisting the fence also failed: {persist_error:#}"
                    ));
                }
                return Err(error.context(format!("operator fenced: {message}")));
            }
        };
        Ok(CloseStarted { epoch, queued })
    }

    // The planned successor bound to its certified registration `record`.
    fn certified_successor(
        &self,
        record: &RegistrationRecord,
    ) -> Result<(EpochRegistration, Vec<Take>)> {
        let (mut successor, takes) = self.successor()?;
        validate_registration(&successor, record)?;
        ensure!(
            record.admitted.is_none(),
            "the successor has already closed"
        );
        successor.floors = Some(record.floors);
        successor.deadlines = record.deadlines;
        Ok((successor, takes))
    }

    // Publication fixes only the boundary. Liability and withdrawal reservations are projected
    // from the latest predecessor tail when the cut installs this successor.
    fn successor(&self) -> Result<(EpochRegistration, Vec<Take>)> {
        let epoch = self.next_openable_epoch()?;
        let start = self.registration.intake.end;
        let withdrawals = self.store.successor_withdrawals()?;
        let published = self.store.successor_end()?;
        let rows = self
            .store
            .untaken()?
            .into_iter()
            .take_while(|(index, _)| published.is_none_or(|end| *index < end))
            .collect::<Vec<_>>();
        // Inbox rows never change once observed, and a withdrawal row's class depends only on the
        // successor's withdrawals and the boundary it extends, which key the cached plan.
        let mut projection = self.projection.borrow_mut();
        let cached = match projection.take().map(|boxed| *boxed) {
            Some(Projection { base, plan })
                if base == withdrawals
                    && plan.registration.context.payment().epoch() == epoch
                    && plan.registration.intake.start == start =>
            {
                Some(plan)
            }
            _ => None,
        };
        let plan = match cached {
            Some(plan) => plan,
            None => {
                let mut registration = self.protocol.registration(
                    epoch,
                    DepositBatch::empty(),
                    withdrawals.clone(),
                    0,
                )?;
                registration.intake = start..start;
                Plan {
                    registration,
                    takes: Vec::new(),
                    deposit_events: 0,
                }
            }
        };
        let taken = plan.takes.len();
        let plan = self.plan_takes(plan, rows.into_iter().skip(taken))?;
        ensure!(
            published.is_none_or(|end| plan.registration.intake.end == end),
            "published successor boundary cannot be reconstructed"
        );
        let mut successor = plan.registration.clone();
        successor.liability = self.store.successor_liability()?;
        let takes = plan.takes.clone();
        *projection = Some(Box::new(Projection {
            base: withdrawals,
            plan,
        }));
        Ok((successor, takes))
    }

    pub(crate) fn close_already_started(&self, epoch: u64) -> Result<bool> {
        self.ensure_store_usable()?;
        self.store.has_close_job(epoch)
    }

    pub(crate) fn validate_close_start(&self, expected_epoch: u64) -> Result<()> {
        self.ensure_operating()?;
        ensure!(
            self.registration.context.payment().epoch() == expected_epoch,
            "close request does not match the active epoch"
        );
        self.next_openable_epoch()?;
        ensure!(self.store.has_current_work()?, "there is nothing to close");
        Ok(())
    }

    pub(crate) fn poll_close(&mut self, epoch: u64) -> Result<Option<CloseEvent>> {
        self.ensure_store_usable()?;
        self.advance_close()?;
        match self.store.close_outcome(epoch)? {
            StoredCloseOutcome::Pending => Ok(None),
            StoredCloseOutcome::Finished(close) => Ok(Some(CloseEvent::Finished(CloseFinished {
                epoch,
                header_digest: short_digest(close.header.digest()),
                rows: close.rows,
                dealing_bytes: close.dealing_bytes,
                withdrawal_total: close.withdrawal_total,
                header_bytes: close.header_bytes,
                certificate_bytes: close.certificate_bytes,
                prepare_micros: close.prepare_micros,
                deal_micros: close.deal_micros,
                seal_micros: close.seal_micros,
            }))),
            StoredCloseOutcome::Failed(error) => Ok(Some(CloseEvent::Failed { epoch, error })),
        }
    }

    pub(crate) fn advance_close(&mut self) -> Result<()> {
        self.ensure_store_usable()?;
        let Some(active) = self.active_close.as_ref() else {
            return Ok(());
        };
        let result = match active.receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return Ok(()),
            Err(TryRecvError::Disconnected) => Err(anyhow::anyhow!(
                "close worker disconnected without a result"
            )),
        };
        let active = self
            .active_close
            .take()
            .expect("active close was checked above");
        let epoch = active.epoch;
        if active.thread.join().is_err() {
            self.record_failed_close(epoch, "close worker panicked".to_string())?;
            return Ok(());
        }

        match result {
            Ok(result) => {
                if let StoredCloseOutcome::Failed(error) = self.store.close_outcome(epoch)? {
                    self.close_fault = Some(error.clone());
                    anyhow::bail!("epoch {epoch} close is durably fenced: {error}");
                }
                let persisted = if self.pipeline.is_some() {
                    self.record_admission(&result)
                } else {
                    self.store.finish_close(&result, self.genesis.root())
                };
                if let Err(error) = persisted {
                    let message = format!("epoch {epoch} close completion failed: {error:#}");
                    if error.downcast_ref::<CloseRejected>().is_some() {
                        self.record_failed_close(epoch, message.clone())?;
                    } else {
                        self.store_fault =
                            Some(format!("{message}; restart the operator before continuing"));
                    }
                    return Err(error.context(format!("operator fenced: {message}")));
                }
                if self.pipeline.is_none()
                    && let Some(balances) = &self.balances
                {
                    balances.notify();
                }
                if let Err(error) = self.start_next_persisted_close() {
                    let message = format!("next close could not be scheduled: {error:#}");
                    self.close_fault = Some(message.clone());
                    if let Ok(Some(pending_epoch)) = self.next_construction_epoch() {
                        let persisted = self.store.fail_close(pending_epoch, &message);
                        if let Err(persist_error) = self.guard_store(persisted) {
                            return Err(anyhow::anyhow!(
                                "operator fenced after {message}; persisting the fence also failed: {persist_error:#}"
                            ));
                        }
                    }
                    return Err(error.context(format!("operator fenced: {message}")));
                }
            }
            Err(error) => {
                if error
                    .downcast_ref::<crate::chain::client::AdmissionPending>()
                    .is_some()
                {
                    self.ensure_store_usable()?;
                    self.start_next_persisted_close()?;
                    return Ok(());
                }
                if error
                    .downcast_ref::<crate::chain::node::PipelineStopped>()
                    .is_some()
                {
                    self.close_fault = Some(format!("{error:#}"));
                    return Err(error);
                }
                if error.downcast_ref::<CommitUnknown>().is_some()
                    || error.downcast_ref::<MutationFailed>().is_some()
                    || error
                        .chain()
                        .any(|cause| cause.downcast_ref::<rusqlite::Error>().is_some())
                {
                    self.store_fault = Some(format!("{error:#}"));
                    return Err(error);
                }
                self.record_failed_close(epoch, format!("{error:#}"))?;
            }
        }
        Ok(())
    }

    pub(crate) fn close_in_progress(&self) -> bool {
        self.active_close.is_some() || !self.admitted.is_empty()
    }

    pub(crate) fn fault(&self) -> Option<&str> {
        self.store_fault
            .as_deref()
            .or(self.store.storage_fault())
            .or(self.close_fault.as_deref())
            .or(self
                .recovering
                .then_some("authenticating the recovered live registration"))
    }

    /// Returns the operational epoch from the durable ledger.
    pub(crate) fn epoch(&self) -> Result<u64> {
        self.ensure_store_usable()?;
        self.store.epoch()
    }

    pub(crate) fn status(&self) -> Result<StoreStatus> {
        self.ensure_store_usable()?;
        self.store.status()
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Result<StoreSnapshot> {
        self.ensure_store_usable()?;
        let mut snapshot = self.store.snapshot()?;
        for identity in &self.identities {
            if !snapshot
                .accounts
                .iter()
                .any(|account| account.name == identity.name)
            {
                snapshot.accounts.push(AccountView {
                    name: identity.name.to_string(),
                    balance: 0,
                    present: false,
                });
            }
        }
        snapshot
            .accounts
            .sort_unstable_by(|left, right| left.name.cmp(&right.name));
        Ok(snapshot)
    }

    /// Snapshot of the boundary whose exact withdrawals need certified queue classification.
    pub(crate) fn registration_boundary(&self) -> Result<WithdrawalBoundary> {
        self.ensure_operating()?;
        let registration = self.withdrawal_registration()?;
        Ok((
            registration.context.payment().clone(),
            registration.withdrawals,
        ))
    }

    #[cfg(test)]
    pub(crate) fn live_registration_boundary(&self) -> Result<WithdrawalBoundary> {
        self.ensure_store_usable()?;
        Ok((
            self.registration.context.payment().clone(),
            self.registration.withdrawals.clone(),
        ))
    }

    #[cfg(test)]
    pub(crate) fn live_withdrawals_frozen(&self) -> Result<bool> {
        self.ensure_store_usable()?;
        self.store
            .withdrawals_frozen(self.registration.context.payment().epoch())
    }

    /// Returns whether the live epoch's certified registration is adopted.
    #[cfg(test)]
    pub(crate) const fn adopted(&self) -> bool {
        self.registration.floors.is_some()
    }

    /// Freezes the live boundary before publishing its signed registration.
    pub(crate) fn signed_registration(&mut self) -> Result<RegisterEpochRequest> {
        self.ensure_operating()?;
        self.next_openable_epoch()?;
        let prepared = self.store.begin_registration(
            self.registration.context.payment(),
            self.registration.intake.end,
        );
        self.guard_store(prepared)?;
        self.sign_registration(&self.registration)
    }

    /// Retains the successor boundary while the current epoch continues accepting payments.
    pub(crate) fn signed_successor(&mut self, expected_epoch: u64) -> Result<RegisterEpochRequest> {
        self.validate_close_start(expected_epoch)?;
        ensure!(
            self.registration.floors.is_some(),
            "the live registration is not adopted"
        );
        let (successor, _) = self.successor()?;
        let prepared = self
            .store
            .begin_successor(self.registration.context.payment(), successor.intake.end);
        self.guard_store(prepared)?;
        self.sign_registration(&successor)
    }

    pub(crate) fn successor_pending(&self) -> Result<bool> {
        self.ensure_store_usable()?;
        Ok(self.store.successor_end()?.is_some())
    }

    fn sign_registration(&self, registration: &EpochRegistration) -> Result<RegisterEpochRequest> {
        let epoch = registration.context.payment().epoch();
        let end = registration.intake.end;
        let withdrawals = registration.withdrawals.clone();
        let deposits_root = registration.deposits.root::<Sha256>()?;
        let signature = self.protocol.sign_chain_registration(
            epoch,
            end,
            &deposits_root,
            &withdrawals,
            self.epoch_fee,
        );
        Ok(RegisterEpochRequest {
            deployment: self.protocol.deployment(),
            epoch,
            end,
            deposits_root,
            withdrawals,
            fee: self.epoch_fee,
            signature,
        })
    }

    /// Adopts the live epoch's certified registration record: the floors it
    /// captured, and its deadlines once settlement assigned them.
    ///
    /// The payment context commits neither, so the anchor the chain derived
    /// from the registered boundary must already be the live one. Adoption is
    /// idempotent, and deadlines assigned after an earlier adoption are
    /// adopted when the record carries them, so a restart between the
    /// registration's submission and this read-back recovers by re-reading
    /// the same certified record.
    pub(crate) fn adopt_registration(&mut self, record: &RegistrationRecord) -> Result<()> {
        self.ensure_operating()?;
        let epoch = self.registration.context.payment().epoch();
        validate_registration(&self.registration, record)?;
        let adopted = self.registration.floors.is_some();
        if let Some(floors) = self.registration.floors {
            ensure!(
                floors == record.floors,
                "the adopted native boundary diverged from the certified registration"
            );
            ensure!(
                self.registration
                    .deadlines
                    .is_none_or(|adopted| record.deadlines == Some(adopted)),
                "the adopted deadlines diverged from the certified registration"
            );
            if self.registration.deadlines == record.deadlines {
                return Ok(());
            }
        }
        let stored = self
            .store
            .adopt_registration(self.registration.context.payment(), record);
        self.guard_store(stored)?;
        self.registration.floors = Some(record.floors);
        self.registration.deadlines = record.deadlines;
        match (record.deadlines, adopted) {
            (Some((admission, challenge)), false) => println!(
                "epoch {epoch} registered: admission deadline block {admission}; challenge deadline block {challenge}"
            ),
            (Some((admission, challenge)), true) => println!(
                "epoch {epoch} became the admission frontier: admission deadline block {admission}; challenge deadline block {challenge}"
            ),
            (None, _) => println!("epoch {epoch} registered behind an unadmitted predecessor"),
        }
        Ok(())
    }

    /// Adopts the record a chain would certify for the live epoch at
    /// `height`, for tests that cut epochs without a chain. The genesis floors
    /// stay valid for in-process closes.
    #[cfg(test)]
    pub(crate) fn adopt_at(
        &mut self,
        height: u64,
        deadlines: Option<(u64, u64)>,
    ) -> Result<RegistrationRecord> {
        let record = registration_record(&self.registration, height, deadlines)?;
        self.adopt_registration(&record)?;
        Ok(record)
    }

    #[cfg(test)]
    pub(crate) const fn fail_next_cutover_commit(&mut self) {
        self.store.fail_next_cutover_commit();
    }

    #[cfg(test)]
    pub(crate) fn start_close_at(&mut self, epoch: u64) -> Result<CloseStarted> {
        if self.close_already_started(epoch)? {
            return Ok(CloseStarted {
                epoch,
                queued: true,
            });
        }
        self.signed_successor(epoch)?;
        let (successor, _) = self.successor()?;
        let record = registration_record(&successor, 0, None)?;
        self.start_close(epoch, &record)
    }

    /// Audits the operational successor after its durable epoch transition.
    fn validate_current_epoch(&mut self) -> Result<()> {
        let current = self.store.load_current()?;
        validate_epoch_data(
            &current,
            &self.registration,
            &self.store.predecessors(current.epoch)?,
        )
        .context("validate rotated SQLite epoch")?;
        Ok(())
    }

    fn next_openable_epoch(&self) -> Result<u64> {
        openable_epoch_after(self.registration.context.payment().epoch())
    }

    fn ensure_balance_intake_horizon(&self) -> Result<()> {
        ensure_balance_intake_horizon(self.registration.context.payment().epoch())
    }

    pub(crate) fn payout_proof(
        &self,
        head: LogHead<Digest>,
        index: u64,
    ) -> Result<WithdrawalClaim<Digest>> {
        self.balances
            .as_ref()
            .context("operator proof replica unavailable")?
            .payout_proof(head, index)
    }

    #[cfg(test)]
    pub(crate) fn wait_for_closes(&mut self) -> Result<Vec<CloseEvent>> {
        let mut events = Vec::new();
        loop {
            let epoch = self
                .active_close
                .as_ref()
                .map(|active| active.epoch)
                .or(self.next_construction_epoch()?);
            let Some(epoch) = epoch else {
                break;
            };
            if let Some(event) = self.poll_close(epoch)? {
                events.push(event);
                continue;
            }
            if self.active_close.is_none() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(events)
    }

    fn spawn_close(&mut self, payment_context: PaymentContext<Key, Digest>) -> Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_close_spawn) {
            anyhow::bail!("injected close worker start failure");
        }

        let epoch = payment_context.epoch();
        let protocol = Arc::clone(&self.protocol);
        let reader = self.store.epoch_reader();
        let genesis_root = self.genesis.root();
        #[cfg(test)]
        let initial_accounts = self.initial_accounts.clone();
        let pipeline = self.pipeline.clone();
        let balances = self.balances.clone();
        #[cfg(test)]
        let close_gate = self.close_gate.take();
        #[cfg(test)]
        let panic_close_worker = std::mem::take(&mut self.panic_close_worker);
        #[cfg(test)]
        let result_failure = self.result_failure.take();
        let (sender, receiver) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name(format!("terminal-close-{epoch}"))
            .spawn(move || {
                #[cfg(test)]
                let mut close_gate = close_gate;
                #[cfg(test)]
                if let Some(gate) = close_gate.take_if(|gate| gate.stage == Stage::Prepare)
                    && !gate.hold()
                {
                    return;
                }

                #[cfg(test)]
                assert!(!panic_close_worker, "injected close worker panic");

                let result = (|| {
                    #[cfg(test)]
                    if matches!(result_failure, Some(ResultFailure::Read)) {
                        return Err(rusqlite::Error::SqliteFailure(
                            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
                            Some("injected certified result read failure".into()),
                        )
                        .into());
                    }
                    let result = if let Some(result) = reader.stored_result(epoch)? {
                        ensure!(
                            result.context.payment() == &payment_context,
                            "retained close has the wrong context"
                        );
                        result
                    } else {
                        let data = reader.load(epoch)?;
                        let registration = registration_for(&protocol, &data)?;
                        ensure!(
                            payment_context == *registration.context.payment(),
                            "frozen epoch context differs from its durable close job"
                        );
                        let assembled =
                            assemble_epoch(&data, &registration, &reader.predecessors(epoch)?)?;
                        let prepared = protocol.prepare(registration, assembled.terminals)?;
                        #[cfg(test)]
                        if let Some(gate) = close_gate.take_if(|gate| gate.stage == Stage::Certify)
                        {
                            ensure!(gate.hold(), "the held close was abandoned");
                        }
                        let result = match &pipeline {
                            Some(pipeline) => pipeline.certify(&prepared)?,
                            #[cfg(test)]
                            None => {
                                let history = (0..epoch)
                                    .map(|epoch| {
                                        reader
                                            .stored_result(epoch)?
                                            .context("test validator predecessor missing")
                                    })
                                    .collect::<Result<Vec<_>>>()?;
                                protocol.fixture_complete(
                                    &initial_accounts,
                                    &history,
                                    prepared,
                                    epoch,
                                )?
                            }
                            #[cfg(not(test))]
                            None => anyhow::bail!("operator has no validator pipeline"),
                        };
                        reader.record_result(&result, genesis_root)?;
                        #[cfg(test)]
                        if matches!(result_failure, Some(ResultFailure::Commit)) {
                            return Err(CommitUnknown::new(
                                "injected certified close retention",
                                rusqlite::Error::ExecuteReturnedResults,
                            )
                            .into());
                        }
                        result
                    };
                    if let Some(balances) = &balances {
                        balances.notify();
                    }
                    #[cfg(test)]
                    if let Some(gate) = close_gate.take_if(|gate| gate.stage == Stage::Admit) {
                        ensure!(gate.hold(), "the held close was abandoned");
                    }
                    if let Some(pipeline) = &pipeline {
                        pipeline.admit(result.context.clone(), AdmitRequest::from(&result))?;
                    }
                    Ok(result)
                })();
                let _ = sender.send(result);
            })
            .context("spawn asynchronous close worker")?;
        self.active_close = Some(ActiveClose {
            epoch,
            receiver,
            thread,
        });
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn pause_next_close(&mut self) -> (Receiver<()>, SyncSender<()>) {
        self.pause_close_at(Stage::Prepare)
    }

    /// Holds the next close worker at `stage` until the returned sender
    /// releases it. The receiver signals when the worker arrives.
    #[cfg(test)]
    pub(crate) fn pause_close_at(&mut self, stage: Stage) -> (Receiver<()>, SyncSender<()>) {
        let (started_sender, started_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        self.close_gate = Some(CloseGate {
            stage,
            started: started_sender,
            release: release_receiver,
        });
        (started_receiver, release_sender)
    }

    /// Returns the certified close retained for `epoch`.
    #[cfg(test)]
    pub(crate) fn retained_result(&self, epoch: u64) -> Result<Option<SettlementResult>> {
        self.store.stored_result(epoch)
    }

    #[cfg(test)]
    const fn fail_next_close_spawn(&mut self) {
        self.fail_close_spawn = true;
    }

    #[cfg(test)]
    const fn panic_next_close_worker(&mut self) {
        self.panic_close_worker = true;
    }

    #[cfg(test)]
    const fn fail_next_result_commit(&mut self) {
        self.result_failure = Some(ResultFailure::Commit);
    }

    #[cfg(test)]
    const fn fail_next_result_read(&mut self) {
        self.result_failure = Some(ResultFailure::Read);
    }

    fn start_next_persisted_close(&mut self) -> Result<()> {
        if self.active_close.is_some() {
            return Ok(());
        }

        // A failed close invalidates its suffix but must not strand older custody-bearing closes.
        let failed_epoch = self.store.first_failed_epoch()?;
        let payment_context = if let Some(epoch) = self.next_construction_epoch()? {
            if failed_epoch.is_some_and(|failed| epoch >= failed) {
                return Ok(());
            }
            Some(self.store.closing_context(epoch)?)
        } else {
            None
        };
        if let Some(payment_context) = payment_context {
            self.spawn_close(payment_context)?;
        }
        Ok(())
    }

    fn certified_tip(&self) -> Result<Option<(u64, StateRoot<Digest>)>> {
        self.admitted.back().map_or_else(
            || self.store.latest_finalized_root(),
            |admitted| Ok(Some((admitted.epoch, admitted.roots.successor))),
        )
    }

    fn next_construction_epoch(&self) -> Result<Option<u64>> {
        let first = self.admitted.back().map_or(Ok(0), |admitted| {
            admitted
                .epoch
                .checked_add(1)
                .context("admitted epoch overflow")
        })?;
        self.store.closing_epoch_from(first)
    }

    fn record_admission(&mut self, result: &SettlementResult) -> Result<()> {
        let predecessor = self
            .certified_tip()?
            .map_or(self.genesis.root(), |(_, root)| root);
        ensure!(
            self.next_construction_epoch()? == Some(result.context.payment().epoch())
                && *result.context.predecessor_root() == predecessor,
            "admitted close does not extend the authenticated local tip"
        );
        println!(
            "epoch {} close admitted: challenge deadline block {}",
            result.context.payment().epoch(),
            result.context.challenge_deadline(),
        );
        self.admitted.push_back(AdmittedClose {
            epoch: result.context.payment().epoch(),
            batch_id: result.header.batch_id::<Sha256>(),
            roots: result.roots,
        });
        Ok(())
    }

    pub(crate) fn pending_epochs(&self) -> Result<Vec<u64>> {
        self.ensure_store_usable()?;
        self.store.pending_epochs()
    }

    /// Releases custody locally only after its exact certified close finalizes.
    pub(crate) fn observe_admitted(
        &mut self,
        epoch: u64,
        record: &AdmittedRootsResponse,
    ) -> Result<()> {
        self.ensure_store_usable()?;
        let Some(admitted) = self.admitted.front() else {
            return Ok(());
        };
        if admitted.epoch != epoch {
            return Ok(());
        }
        ensure!(
            record.batch_id == admitted.batch_id && record.roots == admitted.roots,
            "certified admission differs from the durable operator close"
        );
        if record.finalized {
            self.observe_finalized(epoch)?;
        }
        Ok(())
    }

    /// Finishes owned certified closes through the authenticated FIFO finalization boundary.
    pub(crate) fn observe_finalized(&mut self, finalized: u64) -> Result<()> {
        self.ensure_store_usable()?;
        while let Some(admitted) = self.admitted.front() {
            let epoch = admitted.epoch;
            if epoch > finalized {
                break;
            }
            let result = self
                .store
                .stored_result(epoch)?
                .context("admitted close has no retained result")?;
            ensure!(
                result.context.deployment() == &self.protocol.deployment()
                    && result.context.payment().epoch() == epoch
                    && result.header.batch_id::<Sha256>() == admitted.batch_id
                    && result.roots == admitted.roots
                    && result.header.verify::<Sha256, _>(
                        &result.context,
                        &result.roots,
                        result.withdrawal_total
                    ),
                "retained close differs from its admitted identity"
            );
            let finished = self.store.finish_close(&result, self.genesis.root());
            self.guard_store(finished)?;
            self.admitted.pop_front();
            if let Some(balances) = &self.balances {
                balances.notify();
            }
            println!("epoch {epoch} close finalized");
        }
        Ok(())
    }

    /// Fences invalid descendants while retaining older admitted custody.
    pub(crate) fn fence_suffix(&mut self, first: u64, message: String) -> Result<()> {
        self.ensure_store_usable()?;
        self.close_fault = Some(message.clone());
        if self.store.closing_epoch_from(first)?.is_some() {
            let failed = self.store.fail_close(first, &message);
            self.guard_store(failed)?;
        }
        if let Some(pipeline) = &self.pipeline {
            pipeline.fence(first);
        }
        self.admitted.retain(|admitted| admitted.epoch < first);
        Ok(())
    }

    pub(crate) fn automatic_epoch(&self) -> Result<Option<u64>> {
        self.ensure_store_usable()?;
        if self.ensure_operating().is_err() || !self.store.has_current_work()? {
            return Ok(None);
        }
        Ok(Some(self.registration.context.payment().epoch()))
    }

    /// Whether dwell time or capacity calls for publishing the successor registration.
    ///
    /// The dwell leaves time in the live epoch's admission window for publication and close
    /// construction. The handoff follows certified successor registration. Every registered
    /// epoch receives its admission window when its predecessor is admitted. Registration
    /// pulls the successor's deposits, protecting them from expiry while earlier closes finish.
    /// Withdrawal deadlines are absolute heights, so a backlog of closes that
    /// outlasts one faults the deployment.
    pub(crate) fn close_due(
        &self,
        record: &RegistrationRecord,
        height: u64,
        timing: Timing,
    ) -> Result<bool> {
        if self.automatic_epoch()? != Some(record.epoch)
            || self.registration.floors.is_none()
            || self.registration.context.payment().anchor() != &record.anchor
        {
            return Ok(false);
        }
        let runway = timing.admission_offset.min(4);
        let due = record
            .height
            .saturating_add((timing.admission_offset - runway).min(4));
        let full = self.store.current_entry_count()? >= MAX_ACCEPTED_PAYMENTS
            || self.store.current_deposit_events()? >= MAX_DEPOSIT_EVENTS;
        if height < due && !full {
            return Ok(false);
        }
        Ok(true)
    }

    fn ensure_operating(&self) -> Result<()> {
        self.ensure_store_usable()?;
        ensure!(
            self.close_fault.is_none(),
            "the operator is fenced after a failed predecessor close"
        );
        ensure!(
            !self.recovering,
            "the operator is authenticating the recovered live registration"
        );
        Ok(())
    }

    pub(crate) fn ensure_store_usable(&self) -> Result<()> {
        if let Some(fault) = self.store_fault.as_deref().or(self.store.storage_fault()) {
            anyhow::bail!("the SQLite connection is unusable: {fault}");
        }
        Ok(())
    }

    fn guard_store<T>(&mut self, result: Result<T>) -> Result<T> {
        match result {
            Err(error)
                if error.downcast_ref::<CommitUnknown>().is_some()
                    || error.downcast_ref::<MutationFailed>().is_some() =>
            {
                self.store.epoch_reader().fence_storage_failure(&error);
                let message = format!("{error:#}; restart the operator before continuing");
                self.store_fault = Some(message.clone());
                Err(error.context(format!("operator fenced: {message}")))
            }
            result => result,
        }
    }

    fn record_failed_close(&mut self, epoch: u64, message: String) -> Result<()> {
        if let Err(error) = self.fence_suffix(epoch, message) {
            let fault = format!(
                "persisting the epoch {epoch} close fence failed: {error:#}; restart the operator"
            );
            self.store_fault = Some(fault.clone());
            return Err(error.context(fault));
        }
        Ok(())
    }

    /// The live epoch a restarted operator must authenticate before intake
    /// resumes.
    pub(crate) fn recovering_epoch(&self) -> Option<u64> {
        (self.recovering && self.close_fault.is_none())
            .then(|| self.registration.context.payment().epoch())
    }

    /// Releases intake after restart once the live epoch is authenticated
    /// against the chain, without waiting for earlier closes.
    ///
    /// `record` is the live epoch's registration, and `status` is read at the
    /// same height or later. A faulted chain is left to the fault path. A
    /// healthy chain may include the live epoch and its durably staged successor beyond
    /// the cut epochs. An adopted live registration must match its certified record.
    pub(crate) fn release_recovery(
        &mut self,
        record: Option<&RegistrationRecord>,
        status: &StatusRecord,
    ) -> Result<()> {
        self.ensure_store_usable()?;
        if self.recovering_epoch().is_none() || status.hard_faulted {
            return Ok(());
        }
        let epoch = self.registration.context.payment().epoch();
        let registered = status.next_registration == epoch
            || Some(status.next_registration) == epoch.checked_add(1)
            || (self.store.successor_end()?.is_some()
                && Some(status.next_registration) == epoch.checked_add(2));
        let adopted = self.registration.floors.is_none_or(|floors| {
            record.is_some_and(|record| {
                record.epoch == epoch
                    && &record.anchor == self.registration.context.payment().anchor()
                    && record.pulled == self.registration.intake
                    && record.floors == floors
                    && self
                        .registration
                        .deadlines
                        .is_none_or(|deadlines| record.deadlines == Some(deadlines))
            })
        });
        if !registered || !adopted {
            let message = "recovered live epoch differs from its certified registration";
            self.close_fault = Some(message.to_string());
            anyhow::bail!(message);
        }
        self.validate_current_epoch()?;
        self.recovering = false;
        Ok(())
    }

    #[cfg(test)]
    fn validator_history(&self, epoch: u64) -> Result<Vec<SettlementResult>> {
        (0..epoch)
            .map(|epoch| {
                self.store
                    .stored_result(epoch)?
                    .context("validator predecessor unavailable")
            })
            .collect()
    }

    #[cfg(test)]
    fn prepare_epoch(
        &self,
        data: EpochData,
        registration: EpochRegistration,
    ) -> Result<PreparedEpoch> {
        let assembled =
            assemble_epoch(&data, &registration, &self.store.predecessors(data.epoch)?)?;
        self.protocol.prepare(registration, assembled.terminals)
    }

    #[cfg(test)]
    fn complete_prepared(&self, prepared: PreparedEpoch, seed: u64) -> Result<SettlementResult> {
        let history = self.validator_history(prepared.epoch())?;
        let result =
            self.protocol
                .fixture_complete(&self.initial_accounts, &history, prepared, seed)?;
        self.store
            .epoch_reader()
            .record_result(&result, self.genesis.root())?;
        Ok(result)
    }

    /// Test-only synchronous close pipeline: prepares the live epoch's close,
    /// rotates to the successor, completes and records the close, and returns
    /// the result for chain admission by the caller.
    #[cfg(test)]
    pub(crate) fn complete_close(&mut self, seed: u64) -> Result<SettlementResult> {
        let (successor, _) = self.successor()?;
        let record = registration_record(&successor, 0, None)?;
        self.complete_close_with_successor(seed, &record)
    }

    /// Runs the synchronous fixture pipeline with the actual certified successor boundary.
    #[cfg(test)]
    pub(crate) fn complete_close_with_successor(
        &mut self,
        seed: u64,
        record: &RegistrationRecord,
    ) -> Result<SettlementResult> {
        let epoch = self.registration.context.payment().epoch();
        let data = self.store.load_current()?;
        let prepared = self.prepare_epoch(data, self.registration.clone())?;
        let (successor, takes) = self.certified_successor(record)?;
        self.store
            .begin_successor(self.registration.context.payment(), successor.intake.end)?;
        self.store.rotate_epoch(
            epoch,
            self.registration.context.payment(),
            &successor.context,
            &takes,
            self.registration.intake.end,
            record,
        )?;
        self.registration = successor;
        self.validate_current_epoch()?;
        let result = self.complete_prepared(prepared, seed)?;
        self.store.finish_close(&result, self.genesis.root())?;
        if let Some(balances) = &self.balances {
            let _ = balances.catch_up();
        }
        Ok(result)
    }

    #[cfg(test)]
    fn finish_prepared<R: rand_core::CryptoRng>(
        &mut self,
        prepared: PreparedEpoch,
        rng: &mut R,
    ) -> Result<CloseFinished> {
        let result = self.complete_prepared(prepared, rng.next_u64())?;
        self.store.finish_close(&result, self.genesis.root())?;
        if let Some(balances) = &self.balances {
            let _ = balances.catch_up();
        }
        Ok(CloseFinished {
            epoch: result.context.payment().epoch(),
            header_digest: short_digest(result.header.digest()),
            rows: result
                .roots
                .row_count
                .try_into()
                .context("row count overflow")?,
            dealing_bytes: result.dealing_bytes,
            withdrawal_total: result.withdrawal_total,
            header_bytes: result.header.encode_size(),
            certificate_bytes: result.certificate.encode_size(),
            prepare_micros: result.prepare_micros,
            deal_micros: result.deal_micros,
            seal_micros: result.seal_micros,
        })
    }
}

fn validate_registration(
    registration: &EpochRegistration,
    record: &RegistrationRecord,
) -> Result<()> {
    ensure!(
        record.epoch == registration.context.payment().epoch()
            && &record.anchor == registration.context.payment().anchor()
            && &record.deposits_root == registration.context.deposit_root()
            && &record.withdrawals_root == registration.context.withdrawal_root()
            && record.pulled == registration.intake
            && record.intake >= record.pulled.end,
        "the certified registration does not match the planned boundary"
    );
    ensure!(
        record
            .deadlines
            .is_none_or(|(admission, challenge)| admission < challenge),
        "the certified registration has invalid deadlines"
    );
    Ok(())
}

#[cfg(test)]
fn registration_record(
    registration: &EpochRegistration,
    height: u64,
    deadlines: Option<(u64, u64)>,
) -> Result<RegistrationRecord> {
    Ok(RegistrationRecord {
        epoch: registration.context.payment().epoch(),
        anchor: *registration.context.payment().anchor(),
        height,
        deadlines,
        deposits_root: registration.deposits.root::<Sha256>()?,
        withdrawals_root: registration.withdrawals.root::<Sha256>()?,
        pulled: registration.intake.clone(),
        intake: registration.intake.end,
        floors: commonware_clearing::bajillion::logs::Floors {
            activity: 0,
            payouts: 0,
        },
        admitted: None,
    })
}

pub(super) fn registration_for(protocol: &Protocol, data: &EpochData) -> Result<EpochRegistration> {
    let deposits = deposit_batch(&data.deposits)?;
    let withdrawals = WithdrawalBatch::new(
        data.withdrawals
            .iter()
            .map(|stored| stored.request.clone())
            .collect(),
    )?;

    // The context commits only the boundary, so an adopted epoch rebuilds the
    // same anchor it registered. The adopted floors and deadlines ride along.
    let mut registration = protocol.registration(
        data.epoch,
        deposits,
        withdrawals,
        predecessor_liability(data)?,
    )?;
    registration.floors = data.floors;
    registration.deadlines = data.deadlines;
    Ok(registration)
}

fn registration_with_deposit(
    protocol: &Protocol,
    current: &EpochRegistration,
    account: Key,
    amount: u64,
) -> Result<EpochRegistration> {
    ensure!(amount > 0, "deposit amount must be positive");
    let mut aggregates = current
        .deposits
        .records()
        .iter()
        .map(|record| (record.account().clone(), record.amount()))
        .collect::<BTreeMap<_, _>>();
    let total = aggregates.entry(account).or_default();
    *total = total
        .checked_add(amount)
        .context("deposit total overflow")?;
    let deposits = DepositBatch::new(
        aggregates
            .into_iter()
            .map(|(account, amount)| DepositRecord::new(account, amount))
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let mut replacement = protocol.registration(
        current.context.payment().epoch(),
        deposits,
        current.withdrawals.clone(),
        current.liability,
    )?;
    replacement.intake = current.intake.clone();
    Ok(replacement)
}

fn registration_with_withdrawal(
    protocol: &Protocol,
    current: &EpochRegistration,
    request: SignedWithdrawal<Key, Digest>,
) -> Result<EpochRegistration> {
    // Observed requests can belong to the successor projection before intake persists them.
    if current.withdrawals.request_for(request.account()) == Some(&request) {
        return Ok(current.clone());
    }
    registration_replacing_withdrawal(protocol, current, None, request)
}

// The registration with `request` added after removing `replaced`, if any.
fn registration_replacing_withdrawal(
    protocol: &Protocol,
    current: &EpochRegistration,
    replaced: Option<&SignedWithdrawal<Key, Digest>>,
    request: SignedWithdrawal<Key, Digest>,
) -> Result<EpochRegistration> {
    let mut requests = current
        .withdrawals
        .requests()
        .iter()
        .filter(|staged| Some(*staged) != replaced)
        .cloned()
        .collect::<Vec<_>>();
    requests.push(request);
    let withdrawals = WithdrawalBatch::new(requests)?;
    let mut replacement = protocol.registration(
        current.context.payment().epoch(),
        current.deposits.clone(),
        withdrawals,
        current.liability,
    )?;
    replacement.intake = current.intake.clone();
    Ok(replacement)
}

fn predecessor_liability(data: &EpochData) -> Result<u64> {
    data.accounts
        .iter()
        .filter(|account| account.predecessor > 0)
        .try_fold(0_u64, |total, account| {
            total
                .checked_add(account.predecessor)
                .context("predecessor liability overflow")
        })
}

fn projected_liability(data: &EpochData) -> Result<u64> {
    data.accounts.iter().try_fold(0_u64, |total, account| {
        total
            .checked_add(account.current)
            .context("projected liability overflow")
    })
}

#[derive(Clone, Default)]
struct AccountActivity {
    debit: u64,
    credit: u64,
}

pub(super) struct EpochAssembly {
    pub(super) terminals: Vec<Terminal<Key, Digest>>,
}

/// Signs `deltas` from `wallet` against `endpoint`, merging them into its cumulative
/// out vector under `context` and binding `predecessor`.
#[cfg(test)]
pub(crate) fn sign_send_at(
    context: &PaymentContext<Key, Digest>,
    predecessor: VectorRoot<Digest>,
    wallet: &Wallet,
    endpoint: &Endpoint,
    deltas: &[(Key, u64)],
) -> Result<(SendAuthorization<Key, Digest>, Vec<Entry>)> {
    let mut merged = endpoint.entries.clone();
    let mut entries = Vec::with_capacity(deltas.len());
    let mut total = 0_u64;
    for (recipient, amount) in deltas.iter().cloned() {
        total = total.checked_add(amount).context("delta total overflow")?;
        match merged.binary_search_by(|edge| edge.recipient.cmp(&recipient)) {
            Ok(position) => {
                merged[position].cumulative = merged[position]
                    .cumulative
                    .checked_add(amount)
                    .context("edge cumulative overflow")?;
                merged[position].count = merged[position]
                    .count
                    .checked_add(1)
                    .context("edge count overflow")?;
            }
            Err(position) => merged.insert(
                position,
                OutEntry {
                    recipient: recipient.clone(),
                    cumulative: amount,
                    count: 1,
                },
            ),
        }
        entries.push(Entry { recipient, amount });
    }
    entries.sort_unstable_by(|left, right| left.recipient.cmp(&right.recipient));
    let vector = OutVector::new(context.epoch(), wallet.public_key(), merged)
        .context("assemble signed out vector")?;
    let body = VectorSendBody::new(
        context,
        wallet.public_key(),
        endpoint.seq.checked_add(1).context("sequence overflow")?,
        endpoint
            .cumulative_debit
            .checked_add(total)
            .context("endpoint overflow")?,
        vector
            .root::<Sha256, Digest>()
            .context("commit signed out vector")?,
    );
    Ok((
        SendAuthorization::sign(body, predecessor, wallet.signer()),
        entries,
    ))
}

fn close_tail(predecessor: u64, deposit: u64, credit: u64, debit: u64) -> Result<u64> {
    let available = u128::from(predecessor) + u128::from(deposit) + u128::from(credit);
    let tail = available
        .checked_sub(u128::from(debit))
        .context("Close debit exceeds available balance")?;
    u64::try_from(tail).context("Close tail exceeds u64")
}

fn validate_epoch_data(
    data: &EpochData,
    registration: &EpochRegistration,
    predecessors: &BTreeMap<Key, VectorRoot<Digest>>,
) -> Result<()> {
    assemble_epoch(data, registration, predecessors)?;
    Ok(())
}

/// Replays one epoch's acknowledgment log into the terminals its close carries.
///
/// `predecessors` holds each payer's terminal root in the preceding epoch.
pub(super) fn assemble_epoch(
    data: &EpochData,
    registration: &EpochRegistration,
    predecessors: &BTreeMap<Key, VectorRoot<Digest>>,
) -> Result<EpochAssembly> {
    ensure!(
        data.epoch == registration.context.payment().epoch(),
        "registration does not match SQLite epoch"
    );
    let context = registration.context.payment();
    let accounts = data
        .accounts
        .iter()
        .map(|account| (account.key.clone(), account))
        .collect::<BTreeMap<_, _>>();
    let stored_withdrawals = data
        .withdrawals
        .iter()
        .map(|stored| (stored.request.account().clone(), stored))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        stored_withdrawals.len() == data.withdrawals.len(),
        "SQLite contains duplicate account withdrawals"
    );

    // Replay the acknowledgment chain in canonical database order: contiguous epoch-local
    // sequences per payer, a strictly advancing epoch debit endpoint, valid payer and operator
    // signatures on every accepted message, and the payer's frozen root in the preceding epoch
    // as every predecessor. These checks bind every mutable cache field back to the immutable
    // acknowledgment log before any recovered operator action is allowed. The preceding
    // epoch's close is built from the same frozen acknowledgments, so they also keep a close
    // from proposing a terminal that close contradicts.
    let empty = commitment::empty_root::<Sha256>(VectorKind::OutEntry);
    let mut terminals = BTreeMap::<Key, Ack>::new();
    let mut endpoints = BTreeMap::<Key, (u64, u64)>::new();
    let mut batches = BTreeMap::<(Key, u64), (VectorRoot<Digest>, u64)>::new();
    for stored in &data.acks {
        let body = stored.body();
        let payer = body.payer().clone();
        ensure!(
            accounts.contains_key(&payer),
            "stored acknowledgment payer is not registered"
        );
        stored
            .verify(context)
            .context("verify stored acknowledgment")?;
        ensure!(
            stored.predecessor() == predecessors.get(&payer).copied().unwrap_or(empty),
            "stored acknowledgment binds another predecessor than its payer's preceding terminal"
        );
        let (prior_seq, prior_debit) = endpoints.get(&payer).copied().unwrap_or((0, 0));
        let expected_seq = prior_seq
            .checked_add(1)
            .context("batch sequence overflow")?;
        ensure!(
            body.seq() == expected_seq,
            "stored acknowledgment sequence is not consecutive"
        );
        let delta = body
            .cumulative_debit()
            .checked_sub(prior_debit)
            .filter(|delta| *delta > 0)
            .context("stored acknowledgment endpoint did not advance")?;
        batches.insert((payer.clone(), body.seq()), (body.send_root(), delta));
        endpoints.insert(payer.clone(), (body.seq(), body.cumulative_debit()));
        terminals.insert(payer, stored.clone());
    }

    // Replay the serving log against the acknowledged batches: every entry advances its
    // edge by exactly its delta, opens under its batch's acknowledged root, and each
    // batch's deltas sum to its endpoint advance.
    let mut edges = BTreeMap::<(Key, Key), (u64, u64)>::new();
    let mut credited = BTreeMap::<(Key, u64), u64>::new();
    let mut cursor = 0_u64;
    for stored in &data.entries {
        ensure!(
            stored.sequence > cursor,
            "stored entry cursor is not increasing"
        );
        cursor = stored.sequence;
        let key = (stored.payer.clone(), stored.seq);
        let (send_root, _) = batches
            .get(&key)
            .context("stored entry has no acknowledged batch")?;
        ensure!(
            stored.recipient != stored.payer,
            "stored entry credits its own payer"
        );
        ensure!(
            accounts.contains_key(&stored.recipient),
            "stored receiver has no virtual balance row"
        );
        let edge = edges
            .entry((stored.payer.clone(), stored.recipient.clone()))
            .or_insert((0, 0));
        ensure!(
            stored.amount > 0
                && Some(stored.cumulative) == edge.0.checked_add(stored.amount)
                && Some(stored.count) == edge.1.checked_add(1),
            "stored entry endpoint is not consecutive"
        );
        let entry = OutEntry {
            recipient: stored.recipient.clone(),
            cumulative: stored.cumulative,
            count: stored.count,
        };
        stored
            .opening
            .verify::<Sha256>(VectorKind::OutEntry, send_root, entry.encode().as_ref())
            .map_err(|_| anyhow::anyhow!("stored entry opening does not authenticate"))?;
        *edge = (stored.cumulative, stored.count);
        let sum = credited.entry(key).or_insert(0);
        *sum = sum
            .checked_add(stored.amount)
            .context("batch credit overflow")?;
    }
    for (key, (_, delta)) in &batches {
        ensure!(
            credited.get(key) == Some(delta),
            "stored batch entries do not sum to its endpoint advance"
        );
    }

    // The edge table is a cache used on the online payment path. Exact comparison keeps a
    // corrupt cache from acknowledging a vector the immutable serving log cannot justify.
    ensure!(
        data.edges.len() == edges.len(),
        "stored edge count is inconsistent"
    );
    for (stored, ((payer, recipient), (cumulative, count))) in data.edges.iter().zip(&edges) {
        ensure!(
            &stored.payer == payer
                && &stored.entry.recipient == recipient
                && stored.entry.cumulative == *cumulative
                && stored.entry.count == *count,
            "stored edge endpoint is inconsistent"
        );
    }

    // Derive balance deltas and canonical payer vectors from authenticated edges.
    let mut activity = BTreeMap::<Key, AccountActivity>::new();
    let mut outgoing = BTreeMap::<Key, Vec<OutEntry<Key>>>::new();
    for ((payer, recipient), (cumulative, count)) in &edges {
        let payer_activity = activity.entry(payer.clone()).or_default();
        payer_activity.debit = payer_activity
            .debit
            .checked_add(*cumulative)
            .context("payer debit overflow")?;
        let receiver_activity = activity.entry(recipient.clone()).or_default();
        receiver_activity.credit = receiver_activity
            .credit
            .checked_add(*cumulative)
            .context("receiver credit overflow")?;
        outgoing.entry(payer.clone()).or_default().push(OutEntry {
            recipient: recipient.clone(),
            cumulative: *cumulative,
            count: *count,
        });
    }

    // Every terminal endpoint must equal its replayed edge total, and every debiting
    // account must hold a terminal acknowledgment.
    for (payer, (_, debit)) in &endpoints {
        let advance = activity.get(payer).map_or(0, |totals| totals.debit);
        ensure!(
            *debit == advance,
            "stored acknowledgment endpoint differs from its edges"
        );
    }
    for (account, totals) in &activity {
        if totals.debit > 0 {
            ensure!(
                endpoints.contains_key(account),
                "stored edges have no acknowledged sender"
            );
        }
    }

    // Reconcile the materialized account table with the replayed payments and staged deposits.
    for account in accounts.values() {
        let totals = activity.get(&account.key).cloned().unwrap_or_default();
        let deposit = registration.deposits.amount_for(&account.key);
        let withdrawal = registration.withdrawals.request_for(&account.key);
        let stored_withdrawal = stored_withdrawals.get(&account.key).copied();
        ensure!(
            account.predecessor > 0 || deposit > 0 || totals.debit == 0,
            "absent boundary account originated activity"
        );
        ensure!(
            withdrawal == stored_withdrawal.map(|stored| &stored.request),
            "registration withdrawal differs from SQLite"
        );
        let tail = close_tail(account.predecessor, deposit, totals.credit, totals.debit)?;
        let expected_balance = match stored_withdrawal.and_then(|stored| stored.applied_amount) {
            Some(applied) => {
                let expected = withdrawal_amount(
                    withdrawal
                        .expect("stored withdrawal matches the registration")
                        .body()
                        .action(),
                    tail,
                );
                ensure!(
                    applied == expected,
                    "stored withdrawal tail is inconsistent"
                );
                tail.checked_sub(applied)
                    .context("withdrawal exceeds the epoch tail")?
            }
            None => tail,
        };
        ensure!(account.current == expected_balance, "SQLite balance drift");
    }

    Ok(EpochAssembly {
        terminals: terminal_vectors(data.epoch, terminals, outgoing)?,
    })
}

/// Reconstructs accepted endpoints for the proof replica from the operator's retained log.
pub(super) fn replica_terminals(data: &EpochData) -> Result<Vec<Terminal<Key, Digest>>> {
    let mut terminals = BTreeMap::new();
    for ack in &data.acks {
        terminals.insert(ack.body().payer().clone(), ack.clone());
    }
    let mut outgoing = BTreeMap::<Key, Vec<OutEntry<Key>>>::new();
    for edge in &data.edges {
        outgoing
            .entry(edge.payer.clone())
            .or_default()
            .push(edge.entry.clone());
    }
    terminal_vectors(data.epoch, terminals, outgoing)
}

fn terminal_vectors(
    epoch: u64,
    terminals: BTreeMap<Key, Ack>,
    mut outgoing: BTreeMap<Key, Vec<OutEntry<Key>>>,
) -> Result<Vec<Terminal<Key, Digest>>> {
    terminals
        .into_iter()
        .map(|(account, ack)| {
            let vector = OutVector::new(
                epoch,
                account,
                outgoing.remove(ack.body().payer()).unwrap_or_default(),
            )
            .context("assemble stored out vector")?;
            ensure!(
                vector.root::<Sha256, Digest>()? == ack.body().send_root(),
                "stored out vector does not match its acknowledged root"
            );
            let authorization = SendAuthorization::from_raw_unchecked(
                ack.body().clone(),
                ack.predecessor(),
                ack.payer_signature().clone(),
            );
            Ok(Terminal {
                authorization,
                vector,
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
