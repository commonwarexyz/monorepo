//! Application orchestration across wallets, SQLite, and the clearing protocol.

#[cfg(test)]
use super::store::{AccountView, Endpoint, StoreSnapshot};
use super::{
    qmdb,
    store::{
        AcceptedBatch, CloseRejected, EpochData, IncomingPayment, MutationFailed, SendVerdict,
        StagedDeposit, StagedWithdrawal, Staging, Store, StoreStatus, StoredCloseOutcome,
        withdrawal_amount,
    },
};
#[cfg(test)]
use crate::protocol::{
    MAX_DESTINATION_BYTES, PreparedEpoch, Wallet, accounts, eve_identity, wallets,
};
use crate::{
    chain::{
        node::Pipeline,
        state::{AdmittedRootsResponse, RegistrationRecord},
        tx::{AdmitRequest, RegisterEpochRequest},
    },
    protocol::{
        Account, AccountIdentity, Ack, Deployment, DepositEvent, Entry, EpochRegistration, Key,
        MAX_ACCEPTED_PAYMENTS, MAX_DEPOSIT_EVENTS, Protocol, SettlementResult, Timing,
        ensure_amount_withdrawal_horizon, ensure_balance_intake_horizon, ensure_close_horizon,
        identities, openable_epoch_after, short_digest,
    },
    store::CommitUnknown,
};
use anyhow::{Context, Result, ensure};
#[cfg(test)]
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::HigherEntryLookup,
    commitment::{VectorKind, VectorRoot},
    logs::LogHead,
    payment::{PaymentContext, SendAuthorization, VectorSendBody},
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
    pub(crate) root: StateRoot<Digest>,
    pub(crate) opening: StateOpening<Key, Digest>,
}

pub(crate) struct WithdrawalOpening {
    pub(crate) root: StateRoot<Digest>,
    pub(crate) opening: StateOpening<Key, Digest>,
}

/// The operator's verdict on one submitted send.
pub(crate) enum SendOutcome {
    /// The send, or its exact replay, is committed with its acceptance.
    Accepted(AcceptedBatch),
    /// An unauthenticated hint about the operator's current epoch endpoint.
    Stale {
        context: PaymentContext<Key, Digest>,
        cumulative_debit: u64,
        seq: u64,
        entries: Vec<OutEntry<Key>>,
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

#[cfg(test)]
struct CloseGate {
    started: SyncSender<()>,
    release: Receiver<()>,
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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_remote(
        path: &Path,
        workers: NonZeroUsize,
        pipeline: Pipeline,
        config: &Deployment,
        clearing: commonware_cryptography_curve25519::signing::SigningKey,
        ack: commonware_cryptography::bls12381::primitives::group::Private,
        epoch_fee: u64,
        proof_replica: bool,
    ) -> Result<Self> {
        let protocol = Protocol::with_signer(workers, *config.digest(), clearing, ack)?;
        ensure!(
            protocol.operator().public_key() == config.operator
                && protocol.operator_ack_key() == &config.operator_ack,
            "operator signing keys differ from the certified deployment"
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
        let registration = registration_for(&protocol, &current)?;
        store.ensure_current_context(registration.context.payment())?;
        validate_epoch_data(&protocol, &current, &registration)
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
        let recovering = close_fault.is_none() && pending_close;
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

    pub(crate) fn payment_head(&self, account: &Key) -> Result<PaymentHead> {
        self.ensure_operating()?;
        self.ensure_balance_intake_horizon()?;
        self.ensure_payer_eligible(account)?;
        let state = self
            .store
            .current_account(account)?
            .context("payer is not in the current live state")?;
        ensure!(state.current > 0, "payer is not in the current live state");
        Ok(PaymentHead {
            context: self.registration.context.clone(),
            balance: state.current,
            root: self
                .balances
                .as_ref()
                .context("optional proof replica is unavailable")?
                .root(self.registration.context.payment().epoch())?,
            opening: self
                .balances
                .as_ref()
                .context("optional proof replica is unavailable")?
                .opening(self.registration.context.payment().epoch(), account)?,
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

    pub(crate) fn accept_send(
        &mut self,
        authorization: SendAuthorization<Key, Digest>,
        entries: Vec<Entry>,
    ) -> Result<SendOutcome> {
        self.ensure_operating()?;

        // Exact replays remain readable after an account drains or its epoch closes.
        // The store transaction validates new authorizations before any mutation.
        if let Some(accepted) = self.store.accepted_batch(&authorization, &entries)? {
            return Ok(SendOutcome::Accepted(accepted));
        }

        // The corrective response reports the live context. The wallet must resolve
        // its saved authorization before using that context for another send.
        let context = self.registration.context.payment().clone();
        let body = authorization.body();
        let account_name = |identities: &[AccountIdentity], key: &Key| {
            identities
                .iter()
                .find(|identity| identity.key == *key && identity.name != "Account")
                .map_or_else(|| key.to_string(), |identity| identity.name.to_string())
        };
        let payer = account_name(&self.identities, body.payer());
        let seq = body.seq();
        let cumulative_debit = body.cumulative_debit();
        let rebound = VectorSendBody::new(
            &context,
            body.payer().clone(),
            body.seq(),
            body.cumulative_debit(),
            body.send_root(),
        );
        if rebound != *body {
            let endpoint = self.store.payer_endpoint(body.payer())?;
            println!(
                "payment rejected stale context: payer={payer} sent_epoch={} sent_anchor={} seq={seq} live_epoch={} live_anchor={}",
                body.epoch(),
                short_digest(body.anchor()),
                context.epoch(),
                short_digest(context.anchor()),
            );
            return Ok(SendOutcome::Stale {
                context,
                cumulative_debit: endpoint.cumulative_debit,
                seq: endpoint.seq,
                entries: endpoint.entries,
            });
        }
        self.ensure_balance_intake_horizon()?;
        self.ensure_payer_eligible(body.payer())?;
        let result = self.store.accept_send(
            self.registration.context.payment(),
            &self.protocol,
            authorization,
            &entries,
        );
        match self.guard_store(result)? {
            SendVerdict::Accepted(accepted) => {
                let recipients = entries
                    .iter()
                    .map(|entry| {
                        let recipient = account_name(&self.identities, &entry.recipient);
                        format!("{recipient}:{}", entry.amount)
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "payment accepted: epoch={} seq={} payer={payer} recipients=[{recipients}] total={}",
                    accepted.epoch, accepted.sequence, accepted.total,
                );
                Ok(SendOutcome::Accepted(*accepted))
            }
            SendVerdict::Stale(endpoint) => {
                println!(
                    "payment rejected stale endpoint: epoch={} payer={payer} sent_seq={seq} sent_debit={cumulative_debit} accepted_seq={} accepted_debit={}",
                    context.epoch(),
                    endpoint.seq,
                    endpoint.cumulative_debit,
                );
                Ok(SendOutcome::Stale {
                    context,
                    cumulative_debit: endpoint.cumulative_debit,
                    seq: endpoint.seq,
                    entries: endpoint.entries,
                })
            }
        }
    }

    /// Reports whether accepting this send must first register the epoch with settlement.
    ///
    /// This probe keeps the full validation of a new live-context send: registering an
    /// epoch starts settlement's liveness clock, so only a payer-authorized send may
    /// trigger it. A stale send short-circuits to `false` instead, because acceptance
    /// answers it with the corrective rejection and admits nothing.
    pub(crate) fn send_requires_epoch_registration(
        &self,
        authorization: &SendAuthorization<Key, Digest>,
        entries: &[Entry],
    ) -> Result<bool> {
        self.ensure_operating()?;
        let context = self.registration.context.payment();
        let body = authorization.body();
        let rebound = VectorSendBody::new(
            context,
            body.payer().clone(),
            body.seq(),
            body.cumulative_debit(),
            body.send_root(),
        );
        if rebound != *body {
            return Ok(false);
        }
        if self.store.accepted_batch(authorization, entries)?.is_some() {
            return Ok(false);
        }
        self.ensure_payer_eligible(body.payer())?;
        let required = self.store.chain_deadlines(context.epoch())?.is_none()
            && self
                .store
                .payment_requires_epoch_registration(context, authorization, entries)?;
        if required {
            self.ensure_balance_intake_horizon()?;
        }
        Ok(required)
    }

    #[cfg(test)]
    pub(crate) fn deposit(&mut self, wallet: usize, amount: u64) -> Result<StagedDeposit> {
        self.ensure_operating()?;
        let wallet = &self.wallets[wallet % self.wallets.len()];
        let identity = AccountIdentity {
            name: wallet.name,
            key: wallet.public_key(),
        };

        let sequence = self
            .store
            .current_deposit_events()?
            .checked_add(1)
            .context("deposit sequence overflow")?;
        let event = DepositEvent {
            id: Sha256::hash(&[
                DEPOSIT_ID_NAMESPACE,
                &self.registration.context.payment().epoch().to_be_bytes(),
                &sequence.to_be_bytes(),
                identity.key.as_ref(),
                &amount.to_be_bytes(),
            ]),
            account: identity.key.clone(),
            amount,
        };
        let mut staged = self.observe(std::slice::from_ref(&event))?;
        Ok(staged.pop().expect("one observed event stages one credit"))
    }

    /// Stages chain-confirmed deposit events observed from one finalized
    /// block, the operator's only deposit intake.
    ///
    /// The staged row keyed by deposit id is the idempotence key, so the
    /// at-least-once observation stream (marshal re-delivers any block whose
    /// acknowledgement was not durable) never double-credits: an event whose
    /// id is already staged is verified against its row and skipped. Every
    /// new event of the block commits in one transaction together with the
    /// boundary context the events chain to, so a crash stages either the
    /// whole block or none of it. Returns the newly staged credits in event order.
    pub(crate) fn observe(&mut self, events: &[DepositEvent]) -> Result<Vec<StagedDeposit>> {
        // Confirmed custody stages before the follower acknowledges its block. Its
        // deposits leave the retained predecessor unchanged during close recovery.
        self.ensure_store_usable()?;
        let mut registration = self.registration.clone();
        let mut batch = Vec::new();
        let mut seen = BTreeMap::new();
        for event in events {
            // Distinct transaction envelopes can contain the same custody event.
            if let Some(previous) = seen.insert(event.id, event) {
                ensure!(previous == event, "deposit id is bound to another event");
                continue;
            }
            if let Some(staged) = self.store.staged_deposit(&event.id)? {
                ensure!(
                    staged.account == event.account && staged.amount == event.amount,
                    "deposit id is bound to another event"
                );
                continue;
            }
            let identity = self
                .identities
                .iter()
                .find(|identity| identity.key == event.account)
                .cloned()
                .unwrap_or(AccountIdentity {
                    name: "Account",
                    key: event.account.clone(),
                });
            let replacement = registration_with_deposit(
                &self.protocol,
                &registration,
                identity.key.clone(),
                event.amount,
            )
            .context("prospective deposit does not fit the epoch anchor")?;
            batch.push(Staging {
                identity,
                event: event.clone(),
                replacement: replacement.context.payment().clone(),
            });
            registration = replacement;
        }
        if batch.is_empty() {
            return Ok(Vec::new());
        }
        self.ensure_balance_intake_horizon()?;
        let result = self
            .store
            .stage_deposits(self.registration.context.payment(), &batch);
        let staged = self.guard_store(result)?;
        self.registration = registration;
        Ok(staged)
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
            self.store
                .latest_finalized_root()?
                .map_or(self.genesis.root(), |(_, root)| root)
                .digest,
            destination,
            action,
            deadline,
            wallet.signer(),
        );
        self.apply_withdrawal(request, false)
    }

    pub(crate) const fn genesis(
        &self,
    ) -> commonware_clearing::bajillion::settlement::Genesis<Digest> {
        self.genesis
    }

    pub(crate) fn withdrawal_opening(&self, account: &Key) -> Result<WithdrawalOpening> {
        self.ensure_operating()?;
        ensure_close_horizon(self.registration.context.payment().epoch())?;
        self.ensure_payer_eligible(account)?;
        let (epoch, root) = match self.store.latest_finalized_root()? {
            Some((epoch, root)) => (
                epoch
                    .checked_add(1)
                    .context("finalized checkpoint overflow")?,
                root,
            ),
            None => (0, self.genesis.root()),
        };
        ensure!(
            self.balances
                .as_ref()
                .context("optional proof replica is unavailable")?
                .root(epoch)?
                == root,
            "proof replica differs from finalized root"
        );
        Ok(WithdrawalOpening {
            root,
            opening: self
                .balances
                .as_ref()
                .context("optional proof replica is unavailable")?
                .opening(epoch, account)
                .context("open withdrawing account")?,
        })
    }

    /// Whether registration has fixed the live epoch's withdrawal boundary.
    pub(crate) fn withdrawals_frozen(&self) -> Result<bool> {
        self.ensure_operating()?;
        self.store.withdrawals_frozen()
    }

    /// Stages an authorization after the service authenticates fresh intake or its exact queue record.
    pub(crate) fn apply_withdrawal(
        &mut self,
        request: SignedWithdrawal<Key, Digest>,
        queued: bool,
    ) -> Result<StagedWithdrawal> {
        self.ensure_operating()?;
        Key::decode(request.body().destination().clone())
            .context("withdrawal destination is not a canonical native account")?;
        if let Some(staged) = self.staged_withdrawal(&request)? {
            return Ok(staged);
        }
        self.ensure_withdrawal_intake_horizon(request.body().action())?;
        if !queued {
            self.ensure_payer_eligible(request.account())?;
        }
        request
            .verify_deployment(&self.protocol.deployment())
            .context("verify withdrawal authorization")?;

        let replacement =
            registration_with_withdrawal(&self.protocol, &self.registration, request.clone())
                .context("prospective withdrawal does not fit the epoch anchor")?;
        let result = self.store.stage_withdrawal(
            &request,
            self.registration.context.payment(),
            replacement.context.payment(),
            queued,
        );
        let staged = self.guard_store(result)?;
        self.registration = replacement;
        Ok(staged)
    }

    /// Unregistered withdrawal reservations and the exact boundary that owns them.
    pub(crate) fn unregistered_withdrawals(&self) -> Result<Option<WithdrawalBoundary>> {
        self.ensure_store_usable()?;
        if self.ensure_operating().is_err()
            || self.registration.withdrawals.requests().is_empty()
            || self
                .store
                .chain_deadlines(self.registration.context.payment().epoch())?
                .is_some()
        {
            return Ok(None);
        }
        Ok(Some((
            self.registration.context.payment().clone(),
            self.registration.withdrawals.clone(),
        )))
    }

    /// Restores reservations proven unable to enter settlement under this boundary.
    pub(crate) fn discard_unregistered_withdrawals(
        &mut self,
        expected: &PaymentContext<Key, Digest>,
        discarded: &WithdrawalBatch<Key, Digest>,
    ) -> Result<()> {
        self.ensure_operating()?;
        if self.registration.context.payment() != expected || discarded.requests().is_empty() {
            return Ok(());
        }
        for request in discarded.requests() {
            ensure!(
                self.registration.withdrawals.request_for(request.account()) == Some(request),
                "discarded withdrawal differs from the live boundary"
            );
        }
        let remaining = self
            .registration
            .withdrawals
            .requests()
            .iter()
            .filter(|request| discarded.request_for(request.account()).is_none())
            .cloned()
            .collect();
        let replacement = self.protocol.registration_at(
            expected.epoch(),
            self.registration.deposits.clone(),
            WithdrawalBatch::new(remaining)?,
            self.registration.context.predecessor_liability(),
            self.registration.context.admission_deadline(),
            self.registration.context.challenge_deadline(),
        )?;
        let result = self.store.discard_unregistered_withdrawals(
            expected,
            replacement.context.payment(),
            discarded.requests(),
        );
        self.guard_store(result)?;
        self.registration = replacement;
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
        ensure!(
            stored == *request,
            "account already staged another withdrawal"
        );
        Ok(Some(staged))
    }

    /// Cuts the registered epoch, opens its successor, and schedules close construction.
    pub(crate) fn start_close(&mut self, expected_epoch: u64) -> Result<CloseStarted> {
        if self.close_already_started(expected_epoch)? {
            return Ok(CloseStarted {
                epoch: expected_epoch,
                queued: true,
            });
        }
        self.validate_close_start(expected_epoch)?;
        let epoch = expected_epoch;
        let payment_context = self.registration.context.payment().clone();
        let next_epoch = self.next_openable_epoch()?;

        let successor = self.protocol.registration(
            next_epoch,
            DepositBatch::empty(),
            WithdrawalBatch::empty(),
            self.store.successor_liability()?,
        )?;
        let cutover = self.store.rotate_epoch(
            epoch,
            self.registration.context.payment(),
            &successor.context,
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

        // SQLite owns the cut and the root-independent successor context. The RPC service registers
        // that exact context with settlement before it releases the successor's first receipt.
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
                self.verify_recovered_predecessor()?;
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
                .then_some("authenticating recovered settlement ancestry"))
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
        Ok((
            self.registration.context.payment().clone(),
            self.registration.withdrawals.clone(),
        ))
    }

    /// Freezes withdrawal intake before publishing the live epoch's signed boundary.
    /// Confirmed deposits can invalidate an unadopted request; retries rebuild from
    /// the durable boundary and the immutable deployment fee.
    #[cfg(test)]
    pub(crate) fn signed_registration(
        &mut self,
        queued: &WithdrawalBatch<Key, Digest>,
    ) -> Result<RegisterEpochRequest> {
        let epoch = self.registration.context.payment().epoch();
        let openings = self
            .registration
            .withdrawals
            .requests()
            .iter()
            .filter(|request| queued.request_for(request.account()).is_none())
            .map(|request| {
                self.balances
                    .as_ref()
                    .context("optional proof replica is unavailable")?
                    .opening(epoch, request.account())
            })
            .collect::<Result<Vec<_>>>()?;
        self.signed_registration_with_openings(queued, openings)
    }

    pub(crate) fn signed_registration_with_openings(
        &mut self,
        queued: &WithdrawalBatch<Key, Digest>,
        openings: Vec<StateOpening<Key, Digest>>,
    ) -> Result<RegisterEpochRequest> {
        self.ensure_operating()?;
        self.next_openable_epoch()?;

        let epoch = self.registration.context.payment().epoch();
        let predecessor_liability = self.registration.context.predecessor_liability();
        let withdrawals = self.registration.withdrawals.clone();
        for request in queued.requests() {
            ensure!(
                withdrawals.request_for(request.account()) == Some(request),
                "queued withdrawal differs from the live boundary"
            );
        }
        let deposits_root = self
            .registration
            .deposits
            .root::<Sha256>()
            .context("commit registration deposit boundary")?;
        let signature = self.protocol.sign_chain_registration(
            epoch,
            predecessor_liability,
            &deposits_root,
            &withdrawals,
            self.epoch_fee,
        );
        let request = RegisterEpochRequest {
            deployment: self.protocol.deployment(),
            epoch,
            predecessor_liability,
            deposits_root,

            openings,
            withdrawals,
            fee: self.epoch_fee,
            signature,
        };
        let prepared = self
            .store
            .begin_registration(self.registration.context.payment());
        self.guard_store(prepared)?;
        Ok(request)
    }

    /// Adopts the chain-assigned registration for the live epoch from its
    /// certified record: rebuilds the epoch context at the assigned deadlines
    /// (moving the payment anchor with it), persists them with the context
    /// transition, and swaps the live registration. Payers signed under the
    /// placeholder context learn the move from the corrective rejection.
    ///
    /// Idempotent for a record already adopted, so a restart between the
    /// registration's submission and this read-back recovers by re-reading
    /// the same certified record.
    pub(crate) fn adopt_registration(&mut self, record: &RegistrationRecord) -> Result<()> {
        self.ensure_operating()?;
        let epoch = self.registration.context.payment().epoch();
        ensure!(
            record.epoch == epoch,
            "the certified registration record is not the live epoch"
        );
        if let Some(adopted) = self.store.chain_deadlines(epoch)? {
            ensure!(
                adopted == (record.admission_deadline, record.challenge_deadline),
                "the adopted deadlines diverged from the certified registration"
            );
            ensure!(
                self.registration.context.payment().anchor() == &record.anchor,
                "the adopted context diverged from the certified registration"
            );
            ensure!(
                self.registration.floors == Some(record.floors),
                "the adopted native boundary diverged from the certified registration"
            );
            return Ok(());
        }
        let mut replacement = self.protocol.registration_at(
            epoch,
            self.registration.deposits.clone(),
            self.registration.withdrawals.clone(),
            self.registration.context.predecessor_liability(),
            record.admission_deadline,
            record.challenge_deadline,
        )?;
        ensure!(
            replacement.context.payment().anchor() == &record.anchor,
            "the rebuilt context does not match the certified registration"
        );
        replacement.floors = Some(record.floors);
        let adopted = self.store.adopt_deadlines(
            epoch,
            self.registration.context.payment(),
            replacement.context.payment(),
            record.admission_deadline,
            record.challenge_deadline,
            record.floors,
        );
        self.guard_store(adopted)?;
        self.registration = replacement;
        println!(
            "epoch {epoch} registered: admission deadline block {}; challenge deadline block {}",
            record.admission_deadline, record.challenge_deadline,
        );
        Ok(())
    }

    /// Audits the operational successor after its durable epoch transition.
    fn validate_current_epoch(&mut self) -> Result<()> {
        let current = self.store.load_current()?;
        validate_epoch_data(&self.protocol, &current, &self.registration)
            .context("validate rotated SQLite epoch")?;
        Ok(())
    }

    fn next_openable_epoch(&self) -> Result<u64> {
        openable_epoch_after(self.registration.context.payment().epoch())
    }

    fn ensure_balance_intake_horizon(&self) -> Result<()> {
        ensure_balance_intake_horizon(self.registration.context.payment().epoch())
    }

    fn ensure_withdrawal_intake_horizon(&self, action: &WithdrawalAction) -> Result<()> {
        match action {
            WithdrawalAction::Amount(_) => {
                ensure_amount_withdrawal_horizon(self.registration.context.payment().epoch())
            }
            WithdrawalAction::Close => {
                ensure_close_horizon(self.registration.context.payment().epoch())
            }
        }
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
                if let Some(gate) = close_gate {
                    let _ = gate.started.send(());
                    if gate.release.recv().is_err() {
                        return;
                    }
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
                        let assembled = assemble_epoch(&protocol, &data, &registration)?;
                        let prepared = protocol.prepare(registration, assembled.terminals)?;
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
    fn pause_next_close(&mut self) -> (Receiver<()>, SyncSender<()>) {
        let (started_sender, started_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        self.close_gate = Some(CloseGate {
            started: started_sender,
            release: release_receiver,
        });
        (started_receiver, release_sender)
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
            self.verify_recovered_predecessor()?;
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

    /// Cuts work using certified height and the adopted admission deadline.
    pub(crate) fn close_if_due(
        &mut self,
        epoch: u64,
        height: u64,
        timing: Timing,
    ) -> Result<Option<CloseStarted>> {
        if self.automatic_epoch()? != Some(epoch) {
            return Ok(None);
        }
        let Some((deadline, _)) = self.store.chain_deadlines(epoch)? else {
            return Ok(None);
        };
        let registered = deadline
            .checked_sub(timing.admission_offset)
            .context("invalid admission deadline")?;
        let runway = timing.admission_offset.min(4);
        let due = registered.saturating_add(4).min(deadline - runway);
        let full = self.store.current_entry_count()? >= MAX_ACCEPTED_PAYMENTS
            || self.store.current_deposit_events()? >= MAX_DEPOSIT_EVENTS;
        if height < due && !full {
            return Ok(None);
        }
        self.start_close(epoch).map(Some)
    }

    fn ensure_operating(&self) -> Result<()> {
        self.ensure_store_usable()?;
        ensure!(
            self.close_fault.is_none(),
            "the operator is fenced after a failed predecessor close"
        );
        ensure!(
            !self.recovering,
            "the operator is authenticating recovered settlement ancestry"
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

    fn verify_recovered_predecessor(&mut self) -> Result<()> {
        if !self.recovering {
            return Ok(());
        }
        if self.close_fault.is_some()
            || self.active_close.is_some()
            || self.next_construction_epoch()?.is_some()
        {
            return Ok(());
        }
        let (epoch, _) = self
            .certified_tip()?
            .context("recovered close chain has no authenticated state root")?;
        let current_epoch = self.registration.context.payment().epoch();
        let expected_epoch = epoch.checked_add(1).context("settlement epoch overflow")?;
        if current_epoch != expected_epoch {
            let message =
                "recovered current epoch does not extend the authenticated settlement tip";
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
        let assembled = assemble_epoch(&self.protocol, &data, &registration)?;
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
        let epoch = self.registration.context.payment().epoch();
        let data = self.store.load_current()?;
        let prepared = self.prepare_epoch(data, self.registration.clone())?;
        let next_epoch = self.next_openable_epoch()?;
        let successor = self.protocol.registration(
            next_epoch,
            DepositBatch::empty(),
            WithdrawalBatch::empty(),
            self.store.successor_liability()?,
        )?;
        self.store.rotate_epoch(
            epoch,
            self.registration.context.payment(),
            &successor.context,
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

/// Folds deposit events into their canonical per-account aggregate batch.
fn deposit_batch<'a>(
    events: impl IntoIterator<Item = &'a DepositEvent>,
) -> Result<DepositBatch<Key>> {
    let mut aggregates = BTreeMap::<Key, u64>::new();
    for event in events {
        let amount = aggregates.entry(event.account.clone()).or_default();
        *amount = amount
            .checked_add(event.amount)
            .context("deposit total overflow")?;
    }
    Ok(DepositBatch::new(
        aggregates
            .into_iter()
            .map(|(account, amount)| DepositRecord::new(account, amount))
            .collect::<Result<Vec<_>, _>>()?,
    )?)
}

pub(super) fn registration_for(protocol: &Protocol, data: &EpochData) -> Result<EpochRegistration> {
    let staged = deposit_batch(&data.deposits)?;
    let withdrawals = WithdrawalBatch::new(
        data.withdrawals
            .iter()
            .map(|stored| stored.request.clone())
            .collect(),
    )?;

    // An epoch that registered on the chain rebuilds under the chain-assigned
    // absolute deadlines it adopted from the certified registration record.
    // An epoch that never registered rebuilds under the deterministic
    // placeholder deadlines its contexts were staged with.
    let liability = predecessor_liability(data)?;
    let mut registration = match data.deadlines {
        Some((admission_deadline, challenge_deadline)) => protocol.registration_at(
            data.epoch,
            staged,
            withdrawals,
            liability,
            admission_deadline,
            challenge_deadline,
        ),
        None => protocol.registration(data.epoch, staged, withdrawals, liability),
    }?;
    registration.floors = data.floors;
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
    let staged = DepositBatch::new(
        aggregates
            .into_iter()
            .map(|(account, amount)| DepositRecord::new(account, amount))
            .collect::<Result<Vec<_>, _>>()?,
    )?;

    // Boundary moves preserve the context's deadlines: only the chain
    // assigns them, at the registration's inclusion height.
    protocol.registration_at(
        current.context.payment().epoch(),
        staged,
        current.withdrawals.clone(),
        current.context.predecessor_liability(),
        current.context.admission_deadline(),
        current.context.challenge_deadline(),
    )
}

fn registration_with_withdrawal(
    protocol: &Protocol,
    current: &EpochRegistration,
    request: SignedWithdrawal<Key, Digest>,
) -> Result<EpochRegistration> {
    let mut requests = current.withdrawals.requests().to_vec();
    requests.push(request);
    let withdrawals = WithdrawalBatch::new(requests)?;

    // Boundary moves preserve the context's deadlines: only the chain
    // assigns them, at the registration's inclusion height.
    protocol.registration_at(
        current.context.payment().epoch(),
        current.deposits.clone(),
        withdrawals,
        current.context.predecessor_liability(),
        current.context.admission_deadline(),
        current.context.challenge_deadline(),
    )
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
/// out vector under `context`.
#[cfg(test)]
pub(crate) fn sign_send_at(
    context: &PaymentContext<Key, Digest>,
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
    Ok((SendAuthorization::sign(body, wallet.signer()), entries))
}

fn close_tail(predecessor: u64, deposit: u64, credit: u64, debit: u64) -> Result<u64> {
    let available = u128::from(predecessor) + u128::from(deposit) + u128::from(credit);
    let tail = available
        .checked_sub(u128::from(debit))
        .context("Close debit exceeds available balance")?;
    u64::try_from(tail).context("Close tail exceeds u64")
}

fn validate_epoch_data(
    protocol: &Protocol,
    data: &EpochData,
    registration: &EpochRegistration,
) -> Result<()> {
    assemble_epoch(protocol, data, registration)?;
    Ok(())
}

pub(super) fn assemble_epoch(
    protocol: &Protocol,
    data: &EpochData,
    registration: &EpochRegistration,
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
    // sequences per payer, a strictly advancing epoch debit endpoint, and valid
    // payer and operator signatures on every accepted body. These checks bind every mutable cache
    // field back to the immutable acknowledgment log before any recovered operator action
    // is allowed.
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
        terminals: terminal_vectors(protocol, data.epoch, terminals, outgoing)?,
    })
}

/// Reconstructs accepted endpoints for the proof replica from the operator's retained log.
pub(super) fn replica_terminals(
    protocol: &Protocol,
    data: &EpochData,
) -> Result<Vec<Terminal<Key, Digest>>> {
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
    terminal_vectors(protocol, data.epoch, terminals, outgoing)
}

fn terminal_vectors(
    protocol: &Protocol,
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
            Ok(Terminal {
                authorization: SendAuthorization::from_raw_unchecked(
                    ack.body().clone(),
                    ack.payer_signature().clone(),
                ),
                vector,
                operator_signature: protocol.sign_ack_aggregate(ack.body()),
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
