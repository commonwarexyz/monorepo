//! Interactive wallet and scripted payment walkthrough.

mod dashboard;
mod walkthrough;

use crate::{
    agent::{Agent, PaymentOutcome, WithdrawalOutcome},
    chain::{
        client::{Chain, Client, EFFECT_ATTEMPTS, Env, POLL},
        harness,
        state::{FaultRecord, HardFaultReasonResponse, Record, StatusRecord, status_key},
        tx::{AdmitRequest, ChallengeRequest, DepositRequest, RegisterEpochRequest, SettlementTx},
    },
    operator::{
        DEFAULT_AMOUNT,
        rpc::{
            self as operator_rpc, AcceptedBatchResponse, PollCloseResponse,
            StatusResponse as OperatorStatus,
        },
    },
    protocol::{Protocol, deployment, omitting_boundary, omitting_close},
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    boundary::{WithdrawalAction, WithdrawalBatch},
    challenge::{AckWitness, Challenge, ChallengeKind, EntryWitness},
};
use commonware_codec::Encode as _;
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_macros::select;
use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
use crossterm::{
    cursor::Show,
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use dashboard::render;
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{
    collections::VecDeque,
    io::Stdout,
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};

const MAX_ACTIVITY: usize = 100;
/// Poll budget covering finalization across the challenge window.
const FINALIZE_ATTEMPTS: usize = 3_000;

/// Budget for one background refresh pass.
///
/// Refresh dials run inline in the event loop, and connect timeouts alone can hold one
/// pass for many seconds. The budget keeps quit keys responsive when a role is
/// unreachable.
const REFRESH_BUDGET: Duration = Duration::from_millis(100);

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    _mode: TerminalMode,
}

struct TerminalMode {
    alternate_screen: bool,
}

impl TerminalMode {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("enable terminal raw mode")?;
        let mut mode = Self {
            alternate_screen: false,
        };
        execute!(std::io::stdout(), EnterAlternateScreen).context("enter alternate screen")?;
        mode.alternate_screen = true;
        Ok(mode)
    }
}

impl Drop for TerminalMode {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        if self.alternate_screen {
            let _ = execute!(std::io::stdout(), LeaveAlternateScreen, Show);
        }
    }
}

impl TerminalSession {
    fn enter() -> Result<Self> {
        // Arm restoration before the final fallible constructor so setup errors also restore the
        // terminal.
        let mode = TerminalMode::enter()?;
        let backend = CrosstermBackend::new(std::io::stdout());
        let terminal = Terminal::new(backend).context("initialize terminal")?;
        Ok(Self {
            terminal,
            _mode: mode,
        })
    }
}

pub(crate) struct UiState {
    receiver: usize,
    amount: u64,
    staged: Vec<(usize, u64)>,
    balance: Option<u64>,
    native_balance: Option<u64>,
    operator: Option<OperatorStatus>,
    settlement: Option<StatusRecord>,
    pending_closes: VecDeque<u64>,
    activity: VecDeque<String>,
}

impl UiState {
    fn new() -> Self {
        let mut activity = VecDeque::new();
        activity
            .push_back("Pay to get a receipt. Close the epoch to settle the payments.".to_string());
        Self {
            receiver: 1,
            amount: DEFAULT_AMOUNT,
            staged: Vec::new(),
            balance: None,
            native_balance: None,
            operator: None,
            settlement: None,
            pending_closes: VecDeque::new(),
            activity,
        }
    }

    fn log(&mut self, message: impl Into<String>) {
        self.activity.push_back(message.into());
        while self.activity.len() > MAX_ACTIVITY {
            self.activity.pop_front();
        }
    }
}

pub(crate) async fn run<E: Env>(
    network: &E,
    operator: SocketAddr,
    mut chain: Client,
    mut agent: Agent,
) -> Result<()> {
    let mut terminal = TerminalSession::enter()?;
    run_with_io(
        network,
        operator,
        &mut chain,
        &mut agent,
        |agent, state| {
            terminal
                .terminal
                .draw(|frame| render(frame, agent, state))
                .map(|_| ())
                .context("draw clearing agent")
        },
        || {
            if !event::poll(Duration::ZERO).context("poll terminal input")? {
                return Ok(None);
            }
            let Event::Key(key) = event::read().context("read terminal input")? else {
                return Ok(None);
            };
            Ok(Some(key))
        },
    )
    .await
}

pub(crate) async fn run_with_io<E: Env>(
    network: &E,
    operator: SocketAddr,
    chain: &mut Client,
    agent: &mut Agent,
    mut draw: impl FnMut(&Agent, &UiState) -> Result<()>,
    mut input: impl FnMut() -> Result<Option<KeyEvent>>,
) -> Result<()> {
    let mut state = UiState::new();
    state.receiver = agent.default_receiver();
    if agent.has_pending_payment() {
        state.log("A payment is awaiting confirmation. Press R to retry the saved request.");
    }
    draw(agent, &state)?;
    loop {
        // Receipt verification survives input ticks under the same wallet owner. Keep
        // the first command pressed while busy; quit always takes precedence.
        let mut key = None;
        let mut poll_input = || -> Result<bool> {
            if let Some(next) = input()?
                && next.kind == KeyEventKind::Press
            {
                if matches!(next.code, KeyCode::Char('q') | KeyCode::Esc) {
                    return Ok(true);
                }
                key.get_or_insert(next);
            }
            Ok(false)
        };
        let summary = {
            let assurance = async {
                let _ = agent.intake_incoming(network, chain, operator).await;
                agent.ensure_store_usable()?;
                agent.reconcile(network, chain, operator).await
            };
            let mut assurance = std::pin::pin!(assurance);
            loop {
                select! {
                    result = &mut assurance => break result,
                    _ = network.sleep(REFRESH_BUDGET) => {
                        if poll_input()? { return Ok(()); }
                    },
                }
            }
        };
        agent.ensure_store_usable()?;
        if let Ok(summary) = summary {
            for epoch in summary.convicted {
                state.log(format!(
                    "epoch {epoch} omission convicted via HigherAckEntry; the close is invalidated"
                ));
            }
            for epoch in summary.protected {
                state.log(format!(
                    "epoch {epoch} protected: its admitted close was invalidated before finalization"
                ));
            }
            for epoch in summary.reconciled {
                state.log(format!(
                    "epoch {epoch} reconciled: every held credit is evidence-backed"
                ));
            }
            for epoch in summary.unenforceable {
                state.log(format!(
                    "epoch {epoch} ALARM: a held credit can no longer be enforced (finalized understatement or a faulted unadmitted close)"
                ));
            }
            for epoch in summary.withheld {
                state.log(format!(
                    "epoch {epoch} ALARM: finalized while the operator withholds the committed evidence for held credits (unverifiable, window closed)"
                ));
            }
        }

        refresh_bounded(network, operator, chain, agent, &mut state).await?;
        draw(agent, &state)?;
        network.sleep(REFRESH_BUDGET).await;
        if poll_input()? {
            return Ok(());
        }
        let Some(key) = key else {
            continue;
        };
        match key.code {
            KeyCode::Left => state.receiver = state.receiver.saturating_sub(1),
            KeyCode::Right => {
                state.receiver = (state.receiver + 1) % agent.receiver_count();
            }
            KeyCode::Char('-') => state.amount = state.amount.saturating_sub(1).max(1),
            KeyCode::Char('+') | KeyCode::Char('=') => {
                state.amount = state.amount.saturating_add(1);
            }
            KeyCode::PageDown => state.amount = state.amount.saturating_sub(10).max(1),
            KeyCode::PageUp => state.amount = state.amount.saturating_add(10),
            KeyCode::Char('p' | 'b') if agent.has_pending_payment() => {
                state.log("A saved payment is awaiting confirmation; press R to retry it.");
            }
            KeyCode::Char('p') => {
                let receiver = agent.receiver_name(state.receiver);
                match agent
                    .pay(
                        network,
                        chain,
                        operator,
                        &[(state.receiver, state.amount)],
                    )
                    .await
                {
                    Ok(PaymentOutcome::Accepted(payment)) => state.log(format!(
                        "Paid {} to {receiver}; receipt saved (epoch {})",
                        payment.total, payment.epoch
                    )),
                    Ok(PaymentOutcome::CommittedUnheld { epoch, total }) => state.log(format!(
                        "epoch {epoch} payment for {total} committed in a finalized close; receipts unheld"
                    )),
                    Err(error) => {
                        let action = if agent.has_pending_payment() {
                            "saved payment unconfirmed; press R to retry it"
                        } else {
                            "payment not sent"
                        };
                        state.log(format!("{action}: {error:#}"));
                    }
                }
            }
            KeyCode::Char('R') => {
                let outcome = agent.resume_pending_payment(network, chain, operator).await;
                match outcome {
                    Ok(Some(PaymentOutcome::Accepted(payment))) => state.log(format!(
                        "epoch {} payment #{} confirmed for {}", payment.epoch, payment.sequence, payment.total
                    )),
                    Ok(Some(PaymentOutcome::CommittedUnheld { epoch, total })) => state.log(format!(
                        "epoch {epoch} payment for {total} committed in a finalized close; receipts unheld"
                    )),
                    Ok(None) => state.log("No payment is awaiting confirmation."),
                    Err(error) => state.log(format!("Payment still unresolved; press R to retry: {error:#}")),
                }
            }
            KeyCode::Char('a') => {
                if state
                    .staged
                    .iter()
                    .any(|(receiver, _)| *receiver == state.receiver)
                {
                    state.log(format!(
                        "{} is already staged; batch entries name unique receivers",
                        agent.receiver_name(state.receiver)
                    ));
                } else {
                    state.staged.push((state.receiver, state.amount));
                    state.log(format!(
                        "staged {} to {}; press b to send the batch",
                        state.amount,
                        agent.receiver_name(state.receiver)
                    ));
                }
            }
            KeyCode::Char('b') => {
                if state.staged.is_empty() {
                    state.log("no staged entries; press a to stage the selected payment");
                } else {
                    match agent
                        .pay(network, chain, operator, &state.staged)
                        .await
                    {
                        Ok(PaymentOutcome::Accepted(payment)) => {
                            state.log(format!(
                                "epoch {} batch #{} paid {} across {} receivers",
                                payment.epoch,
                                payment.sequence,
                                payment.total,
                                payment.acceptance.entries.len()
                            ));
                            state.staged.clear();
                        }
                        Ok(PaymentOutcome::CommittedUnheld { epoch, total }) => {
                            state.log(format!(
                                "epoch {epoch} batch for {total} committed in a finalized close; receipts unheld"
                            ));
                            state.staged.clear();
                        }
                        Err(error) => {
                            let pending = agent.has_pending_payment();
                            let action = if pending {
                                "saved payment unconfirmed; press R to retry it"
                            } else {
                                "batch not sent"
                            };
                            if pending {
                                state.staged.clear();
                            }
                            state.log(format!("{action}: {error:#}"));
                        }
                    }
                }
            }
            KeyCode::Char('h') => {
                handle_hard_fault_recovery(network, chain, agent, &mut state).await;
            }
            KeyCode::Char('r') => {
                handle_pending_deposit_recovery(network, chain, agent, &mut state).await;
            }
            KeyCode::Char('t') => {
                let recipient = agent.operator();
                match agent.transfer_native(network, chain, recipient, state.amount).await {
                    Ok(receipt) => state.log(format!("operator native funding certified: {}", receipt.amount)),
                    Err(error) => state.log(format!("native transfer pending: {error:#}")),
                }
            }
            KeyCode::Char('d') => match agent.deposit(network, chain, state.amount).await {
                Ok(event) => {
                    state.log(format!(
                        "deposit custody certified for {}; the operator credits it from its own observation of the finalized record",
                        event.amount
                    ));
                }
                Err(error) => state.log(format!(
                    "deposit not confirmed; a staged deposit retries the same id: {error:#}"
                )),
            },
            KeyCode::Char('w') | KeyCode::Char('f') => {
                let action = if key.code == KeyCode::Char('f') {
                    WithdrawalAction::Close
                } else {
                    WithdrawalAction::Amount(
                        NonZeroU64::new(state.amount).expect("UI amount is positive"),
                    )
                };
                match agent.withdraw(network, chain, operator, action).await {
                    Ok(WithdrawalOutcome::Applied { epoch, request }) => match request.body().action() {
                        WithdrawalAction::Amount(amount) => state.log(format!(
                            "epoch {epoch} withdrawal carried by operator: {amount}"
                        )),
                        WithdrawalAction::Close => state.log(format!(
                            "epoch {epoch} Close carried by operator; press c to claim after finalization"
                        )),
                    },
                    Ok(WithdrawalOutcome::Signed {
                        request,
                        error,
                    }) => {
                        let deadline = request.body().deadline();
                        state.log(format!(
                            "withdrawal signed through deadline {deadline}; operator carriage unknown; press x to escalate to settlement, or retry with the same signed request: {error:#}"
                        ));
                    }
                    Err(error) => state.log(format!("withdrawal not confirmed: {error:#}")),
                }
            }
            KeyCode::Char('x') => match agent.escalate_withdrawal(network, chain).await {
                Ok(request) => state.log(format!(
                    "withdrawal escalated to settlement through deadline {}; the next registered close must carry it verbatim; if the operator stalls, expiry becomes hard-fault recovery via h",
                    request.body().deadline()
                )),
                Err(error) => state.log(format!("withdrawal escalation rejected: {error:#}")),
            },
            KeyCode::Char('c') => match agent
                .claim_withdrawal(network, chain, operator)
                .await
            {
                Ok(release) => state.log(format!(
                    "withdrawal claimed: {} to {}",
                    release.amount,
                    commonware_formatting::hex(&release.destination)
                )),
                Err(error) => state.log(format!("claim rejected: {error:#}")),
            },
            KeyCode::Char('s') => match agent.start_close(network, operator).await {
                Ok(close) => {
                    if !state.pending_closes.contains(&close.epoch) {
                        state.pending_closes.push_back(close.epoch);
                    }
                    state.log(format!(
                        "Closing epoch {}{}; waiting for certification and finality",
                        close.epoch,
                        if close.queued { " and queued" } else { "" }
                    ));
                }
                Err(error) => state.log(format!("close rejected: {error:#}")),
            },
            _ => {}
        }
    }
}

async fn handle_hard_fault_recovery<E: Env>(
    ctx: &E,
    chain: &mut Client,
    agent: &mut Agent,
    state: &mut UiState,
) {
    match agent.recover_hard_fault(ctx, chain).await {
        Ok(None) => state.log("No balance remains at the frozen root; finalized withdrawal claims and deposit refunds remain available".to_string()),
        Ok(Some(release)) => state.log(format!(
            "hard-fault recovery released {} (residual {})",
            release.released_custody, release.residual
        )),
        Err(error) => state.log(format!("hard-fault recovery rejected: {error:#}")),
    }
}

async fn handle_pending_deposit_recovery<E: Env>(
    ctx: &E,
    chain: &mut Client,
    agent: &Agent,
    state: &mut UiState,
) {
    match agent.recover_pending_deposit(ctx, chain).await {
        Ok(refund) => state.log(format!(
            "pending deposit refunded for {}: {}",
            agent.name(),
            refund.amount
        )),
        Err(error) => state.log(format!("deposit refund rejected: {error:#}")),
    }
}

/// Refreshes displayed state under [REFRESH_BUDGET] so a hung dial never wedges input.
///
/// Native funds are polled first, so a hung operator cannot hide a completed native
/// read. The remaining displays become unavailable on timeout.
async fn refresh_bounded<E: Env>(
    network: &E,
    operator: SocketAddr,
    chain: &mut Client,
    agent: &mut Agent,
    state: &mut UiState,
) -> Result<()> {
    state.native_balance = None;
    let refreshed = select! {
        result = refresh(network, operator, chain, agent, state) => Some(result),
        _ = network.sleep(REFRESH_BUDGET) => None,
    };
    agent.ensure_store_usable()?;
    match refreshed {
        Some(result) => result,
        None => {
            state.operator = None;
            state.settlement = None;
            state.balance = None;
            Ok(())
        }
    }
}

async fn refresh<E: Env>(
    network: &E,
    operator: SocketAddr,
    chain: &mut Client,
    agent: &mut Agent,
    state: &mut UiState,
) -> Result<()> {
    state.native_balance = chain
        .native_balance(network, chain.genesis().native.chain_id(), agent.account())
        .await
        .ok();
    if let Some(epoch) = state.pending_closes.front().copied() {
        match agent.poll_close(network, operator, epoch).await {
            Ok(PollCloseResponse::NoEvent) | Err(_) => {}
            Ok(PollCloseResponse::Finished(close)) => {
                state.pending_closes.pop_front();
                state.log(format!(
                    "Finalized epoch {} / account records: {} / {:.1} KB per validator",
                    close.epoch,
                    close.rows,
                    close.dealing_bytes as f64 / 1_000.0
                ));
            }
            Ok(PollCloseResponse::Failed { epoch, error }) => {
                state.pending_closes.pop_front();
                state.log(format!(
                    "epoch {epoch} close failed: {}",
                    String::from_utf8_lossy(&error)
                ));
            }
        }
    }
    state.operator = agent.operator_status(network, operator).await.ok();
    state.settlement = chain.status(network).await.ok();

    // The verified balance poll also refreshes the wallet's frozen-root recovery opening.
    state.balance = agent.balance(network, chain, operator).await.ok();

    Ok(())
}

/// Unwraps a receipts-held acceptance, which every scripted payment expects.
fn accepted(outcome: PaymentOutcome) -> Result<AcceptedBatchResponse> {
    match outcome {
        PaymentOutcome::Accepted(payment) => Ok(*payment),
        PaymentOutcome::CommittedUnheld { epoch, .. } => {
            anyhow::bail!("epoch {epoch} payment committed without receipts")
        }
    }
}

/// Retries one payment intent while a cut's successor becomes certifiable.
/// The wallet owns exact pending-byte replay and adjudication of moved contexts.
async fn scripted_payment<E: Env>(
    network: &E,
    operator: SocketAddr,
    chain: &mut Client,
    agent: &mut Agent,
    entries: &[(usize, u64)],
) -> Result<AcceptedBatchResponse> {
    for attempt in 0..FINALIZE_ATTEMPTS {
        match agent.pay(network, chain, operator, entries).await {
            Ok(outcome) => return accepted(outcome),
            Err(error) => {
                agent.ensure_store_usable()?;
                if attempt + 1 == FINALIZE_ATTEMPTS {
                    return Err(error.context("complete scripted payment"));
                }
            }
        }
        network.sleep(POLL).await;
    }
    unreachable!("payment attempt budget is nonzero")
}

/// Starts one asynchronous close and drives it to the operator's certified
/// finalization, returning the closed epoch.
async fn close_epoch<E: Env>(
    network: &E,
    operator: SocketAddr,
    agent: &mut Agent,
    epoch: u64,
) -> Result<u64> {
    let close = operator_rpc::start_close(network, operator, epoch).await?;
    ensure!(close.epoch == epoch, "operator started another close epoch");
    walkthrough::event(
        "Closing",
        format_args!("epoch {epoch}; waiting for certification and finality..."),
    );
    loop {
        match agent.poll_close(network, operator, close.epoch).await? {
            PollCloseResponse::NoEvent => network.sleep(Duration::from_millis(10)).await,
            PollCloseResponse::Finished(finished) => {
                ensure!(
                    finished.epoch == epoch,
                    "operator finished another close epoch"
                );
                walkthrough::event(
                    "Finalized",
                    format_args!(
                        "epoch {epoch} / account records: {} / {:.1} KB per validator",
                        finished.rows,
                        finished.dealing_bytes as f64 / 1_000.0
                    ),
                );
                return Ok(close.epoch);
            }
            PollCloseResponse::Failed { epoch, error } => {
                anyhow::bail!(
                    "epoch {epoch} close failed: {}",
                    String::from_utf8_lossy(&error)
                );
            }
        }
    }
}

/// Waits for the script's sole deposit to reach the certified finalized head.
async fn finalized_deposit<E: Env>(
    network: &E,
    operator: SocketAddr,
    chain: &mut Client,
    agent: &mut Agent,
    expected: u64,
) -> Result<u64> {
    for _ in 0..FINALIZE_ATTEMPTS {
        if let Ok((status, opening)) = agent.finalized_head(network, chain, operator).await {
            ensure!(!status.hard_faulted, "the deposit deployment hard-faulted");
            if opening.balance.get() == expected
                && let Some(epoch) = status.last_finalized
            {
                return Ok(epoch);
            }
        }
        agent.ensure_store_usable()?;
        network.sleep(POLL).await;
    }
    anyhow::bail!("the deposit never reached the certified finalized balance {expected}")
}

/// Completes a saved withdrawal intent before the walkthrough creates more work.
async fn complete_pending_withdrawal<E: Env>(
    network: &E,
    operator: SocketAddr,
    chain: &mut Client,
    agent: &mut Agent,
) -> Result<()> {
    if !agent.has_pending_withdrawal_claim() {
        return Ok(());
    }
    let mut released = None;
    let mut last = None;
    for _ in 0..FINALIZE_ATTEMPTS {
        match agent.claim_withdrawal(network, chain, operator).await {
            Ok(release) => {
                released = Some(release);
                break;
            }
            Err(error) => {
                last = Some(error);
                if let Some(action) = agent.pending_withdrawal_action() {
                    let _ = agent.withdraw(network, chain, operator, action).await;
                    agent.ensure_store_usable()?;
                }
            }
        }
        network.sleep(POLL).await;
    }
    let Some(release) = released else {
        return Err(last
            .expect("a failed claim retry leaves its error")
            .context("complete the interrupted withdrawal claim"));
    };
    walkthrough::event(
        "Resumed",
        format_args!("claimed a saved withdrawal of {}", release.amount),
    );
    Ok(())
}

/// Runs one wallet's funded payment and claim arc with an automatic operator.
pub(crate) async fn scripted<E: Env>(
    network: &E,
    operator: SocketAddr,
    mut chain: Client,
    mut agent: Agent,
    mut eve: Agent,
) -> Result<()> {
    walkthrough::banner();
    walkthrough::event("Wallet", agent.name());
    walkthrough::event("Operator", operator);
    walkthrough::step(
        1,
        "FUND THE WALLET",
        "Fund your operator balance from the settlement chain.",
    );

    // A saved claim can precede delivery of its authorization. Resolve that intent
    // before starting another withdrawal in this walkthrough.
    complete_pending_withdrawal(network, operator, &mut chain, &mut agent).await?;

    let mut start = None;
    for _ in 0..EFFECT_ATTEMPTS {
        if let Ok(balance) = agent.balance(network, &mut chain, operator).await {
            start = Some(balance);
            break;
        }
        network.sleep(POLL).await;
    }
    let start = start.context("read the verified starting balance")?;
    let native_start = chain
        .native_balance(network, chain.genesis().native.chain_id(), agent.account())
        .await?;
    walkthrough::event(
        "Before",
        format_args!("{native_start} onchain / {start} with the operator"),
    );
    let deposit = agent.deposit(network, &mut chain, 20).await?;
    walkthrough::event(
        "Deposit",
        format_args!("{} moved into chain custody", deposit.amount),
    );

    // The withdrawal signs the finalized root containing this deposit. Wait for
    // the operator to observe that finality before sending the fresh request.
    let deposit_epoch = finalized_deposit(
        network,
        operator,
        &mut chain,
        &mut agent,
        start + deposit.amount,
    )
    .await?;
    close_epoch(network, operator, &mut agent, deposit_epoch).await?;
    walkthrough::event(
        "Balance",
        format_args!("{} available with the operator", start + deposit.amount),
    );
    let mut withdrawal = None;
    for _ in 0..EFFECT_ATTEMPTS {
        match agent
            .withdraw(
                network,
                &mut chain,
                operator,
                WithdrawalAction::Amount(NonZeroU64::new(3).unwrap()),
            )
            .await?
        {
            WithdrawalOutcome::Applied { epoch, .. } => {
                withdrawal = Some(epoch);
                break;
            }
            WithdrawalOutcome::Signed { .. } => network.sleep(POLL).await,
        }
    }
    let withdrawal = withdrawal
        .context("the signed withdrawal remains unresolved; retry keeps the saved request")?;
    walkthrough::event(
        "Withdrawal",
        format_args!("3 queued for epoch {withdrawal}; claim after finality"),
    );

    walkthrough::step(
        2,
        "PAY SEVERAL RECIPIENTS",
        "The operator returns receipts before settlement.",
    );

    // An interrupted run can also lose a staged payment's response. Resubmit
    // the exact staged bytes here, after this run's deposit and withdrawal:
    // the resumed send registers the epoch and becomes its first payment,
    // which freezes the boundary that intake had to enter first.
    if let Some(outcome) = agent
        .resume_pending_payment(network, &mut chain, operator)
        .await
        .context("resume the interrupted payment")?
    {
        match outcome {
            PaymentOutcome::Accepted(payment) => walkthrough::event(
                "Resumed",
                format_args!("saved payment #{} accepted", payment.sequence),
            ),
            PaymentOutcome::CommittedUnheld { epoch, total } => walkthrough::event(
                "Resumed",
                format_args!("saved payment of {total} already committed in epoch {epoch}"),
            ),
        }
    }
    let payment = scripted_payment(network, operator, &mut chain, &mut agent, &[(1, 5)]).await?;
    walkthrough::event(
        agent.name(),
        format_args!("-> Bob     5 / receipt saved / epoch {}", payment.epoch),
    );

    // The payer-signed acknowledgment body digest is the receipt_id reference a receiver
    // answers its service-accounting query against below.
    let receipt_id = Sha256::hash(&[payment.acceptance.ack.body().encode().as_ref()]);
    let payer_account = agent.account();
    let batch =
        scripted_payment(network, operator, &mut chain, &mut agent, &[(2, 2), (3, 1)]).await?;
    walkthrough::event(
        agent.name(),
        format_args!(
            "-> Carol   2 + Dave 1 / one signed batch / epoch {}",
            batch.epoch
        ),
    );
    let eve_receiver = agent.receiver_count() - 1;
    complete_pending_withdrawal(network, operator, &mut chain, &mut eve).await?;
    let mut eve_start = None;
    for _ in 0..EFFECT_ATTEMPTS {
        if let Ok(balance) = eve.balance(network, &mut chain, operator).await {
            eve_start = Some(balance);
            break;
        }
        network.sleep(POLL).await;
    }
    let eve_start = eve_start.context("read Eve's verified starting balance")?;
    let eve_expected = eve_start.checked_add(2).context("Eve balance overflow")?;
    let eve_payment = scripted_payment(
        network,
        operator,
        &mut chain,
        &mut agent,
        &[(eve_receiver, 2)],
    )
    .await?;
    walkthrough::event(
        agent.name(),
        format_args!("-> Eve     2 / receipt saved / epoch {}", eve_payment.epoch),
    );
    let eve_receipt_id = Sha256::hash(&[eve_payment.acceptance.ack.body().encode().as_ref()]);

    // Service relies on durably held, settlement-anchored receipts even when the
    // automatic driver has already cut their epoch.
    let receiver_database = std::env::temp_dir().join(format!(
        "commonware-terminal-receiver-{}.sqlite",
        std::process::id()
    ));
    let mut receiver =
        Agent::open_for(&receiver_database, 1, chain.deployment(), agent.operator())?;
    receiver
        .intake_incoming(network, &mut chain, operator)
        .await?;
    ensure!(
        receiver.has_receipt(&payer_account, &receipt_id)?,
        "receiver holds no evidence for the accepted batch"
    );
    walkthrough::event("Bob", "verified and saved the payment receipt");

    eve.intake_incoming(network, &mut chain, operator).await?;
    ensure!(
        eve.has_receipt(&payer_account, &eve_receipt_id)?,
        "Eve holds no evidence for the accepted payment"
    );
    walkthrough::event("Eve", "verified and saved the payment receipt");

    walkthrough::step(
        3,
        "SETTLE THE PAYMENTS",
        "Validators check the close; the chain waits out its challenge window.",
    );

    let work_epoch = withdrawal
        .max(payment.epoch)
        .max(batch.epoch)
        .max(eve_payment.epoch);
    let closed = close_epoch(network, operator, &mut agent, work_epoch).await?;
    let release = agent
        .claim_withdrawal(network, &mut chain, operator)
        .await?;
    walkthrough::event(
        "Claimed",
        format_args!("{} returned to {} onchain", release.amount, agent.name()),
    );

    // Reconcile the held receipts against finalized activity while the epoch's
    // evidence remains retained.
    let summary = receiver.reconcile(network, &mut chain, operator).await?;
    ensure!(
        summary.reconciled.contains(&payment.epoch)
            || receiver.last_reconciled_epoch() == Some(payment.epoch),
        "the receiver receipt_id epoch has not reconciled"
    );
    walkthrough::event("Bob", "receipt matches the finalized close");
    let _ = std::fs::remove_file(&receiver_database);
    for suffix in ["-wal", "-shm"] {
        let mut path = receiver_database.clone().into_os_string();
        path.push(suffix);
        let _ = std::fs::remove_file(path);
    }

    let eve_summary = eve.reconcile(network, &mut chain, operator).await?;
    ensure!(
        eve_summary.reconciled.contains(&eve_payment.epoch)
            || eve.last_reconciled_epoch() == Some(eve_payment.epoch),
        "Eve's fresh receipt has not reconciled against the finalized close"
    );
    let mut eve_balance = None;
    for _ in 0..EFFECT_ATTEMPTS {
        if let Ok(balance) = eve.balance(network, &mut chain, operator).await
            && balance == eve_expected
        {
            eve_balance = Some(balance);
            break;
        }
        network.sleep(POLL).await;
    }
    ensure!(
        eve_balance == Some(eve_expected),
        "Eve's fresh receipt did not become a virtual successor balance"
    );
    walkthrough::event(
        "Eve",
        format_args!("receipt matches the close / operator balance {eve_expected}"),
    );

    walkthrough::step(
        4,
        "WITHDRAW THE NEW BALANCE",
        "Eve chooses when to move her received funds onchain.",
    );

    let mut eve_withdrawal = None;
    for _ in 0..EFFECT_ATTEMPTS {
        match eve
            .withdraw(
                network,
                &mut chain,
                operator,
                WithdrawalAction::Amount(NonZeroU64::new(2).unwrap()),
            )
            .await?
        {
            WithdrawalOutcome::Applied { epoch, .. } => {
                eve_withdrawal = Some(epoch);
                break;
            }
            WithdrawalOutcome::Signed { .. } => network.sleep(POLL).await,
        }
    }
    let eve_withdrawal = eve_withdrawal
        .context("Eve's explicit withdrawal remains unresolved; retry keeps the saved request")?;
    walkthrough::event(
        "Eve",
        format_args!("withdrawal of 2 queued for epoch {eve_withdrawal}"),
    );

    let successor = scripted_payment(network, operator, &mut chain, &mut agent, &[(1, 1)]).await?;
    walkthrough::event(
        agent.name(),
        format_args!(
            "-> Bob     1 / epoch {} follows finalized epoch {closed}",
            successor.epoch
        ),
    );
    // The successor payment registered the next epoch's payment context, so
    // close that epoch too, inside its admission runway: an activated context
    // left registered would expire its admission deadline and permanently
    // hard-fault the deployment.
    close_epoch(
        network,
        operator,
        &mut agent,
        successor.epoch.max(eve_withdrawal),
    )
    .await?;
    let eve_release = eve.claim_withdrawal(network, &mut chain, operator).await?;
    ensure!(
        eve_release.amount == 2,
        "Eve's certified withdrawal release has the wrong amount"
    );
    walkthrough::event(
        "Claimed",
        format_args!("{} returned to Eve onchain", eve_release.amount),
    );

    // Every close completes only on its certified finalization, which
    // retires the registration slot, and nothing after the last close
    // registers, so only validator serving lag separates this read from the
    // proven absence.
    let mut retired = false;
    for _ in 0..100 {
        if chain.registration(network).await?.is_none() {
            retired = true;
            break;
        }
        network.sleep(Duration::from_millis(100)).await;
    }
    ensure!(retired, "a live registration outlived the walkthrough");
    walkthrough::event(
        "Complete",
        "all live closes finalized; no pending epoch deadlines",
    );

    Ok(())
}

/// Demonstrates the enforcement thesis live: an operator that omits a receiver's credit is
/// convicted by the receiver's held receipt, and the close is invalidated.
///
/// The honest operator binary can never produce an inconsistent close, so the fraud is
/// assembled with the shared omitting-close machinery and adjudicated by a throwaway
/// in-process single-validator chain: the fraudulent close is registered and admitted as
/// real transactions, the receiver files one real `HigherAckEntry` challenge transaction,
/// and the proven verdict, the fault record, and the hard-faulted status are all read back
/// certified through the light client. This mirrors what a receiver's reconciliation does
/// on the wire against the live deployment.
pub(crate) fn fraud_arc() -> Result<()> {
    walkthrough::step(
        5,
        "PROVE AN OMITTED PAYMENT",
        "Isolated simulation / one validator / simulated close certification.",
    );
    walkthrough::event(
        "Scope",
        "This example leaves your live operator and balances untouched.",
    );

    deterministic::Runner::default().start(|context| async move {
        let address = SocketAddr::from(([127, 0, 0, 1], 9_900));
        let control = harness::start(&context, address, "fraud").await;
        let mut chain = Client::new(
            control.identity(),
            deployment(),
            vec![address],
            context.child("fraud_client"),
        )?;

        // Stand the fraudulent deployment up with real transactions: the
        // bystander deposit, then the boundary-only registration whose
        // deadlines and anchor the chain assigns at inclusion. Every
        // submission completes on a certified read of its effect record.
        let (deposit, deposits) = omitting_boundary()?;
        let deposit_id = deposit.id;
        chain
            .deliver(
                &context,
                &SettlementTx::Deposit(DepositRequest::sign(
                    chain.genesis().native.chain_id(), deployment(), deposit.clone(),
                    crate::protocol::wallets().iter().find(|wallet| wallet.public_key() == deposit.account).context("deposit signer")?.signer(),
                )),
            )
            .await?;
        let mut recorded = false;
        for _ in 0..EFFECT_ATTEMPTS {
            if let Ok(Some(_)) = chain.deposit(&context, deposit_id).await {
                recorded = true;
                break;
            }
            context.sleep(POLL).await;
        }
        ensure!(recorded, "the fraud deposit earned no custody record");
        let protocol = Protocol::new(NonZeroUsize::MIN)?;
        let deposits_root = deposits.root::<Sha256>()?;
        let withdrawals = WithdrawalBatch::empty();
        let fee = chain.genesis().native.epoch_fee.checked_mul(
            u64::from(chain.registered(&context).await?.max_dealing_bytes).div_ceil(1024),
        ).context("epoch fee overflow")?;
        let signature = protocol.sign_chain_registration(
            0,
            400,
            &deposits_root,
            &withdrawals,
            fee,
        );
        let register = SettlementTx::RegisterEpoch(RegisterEpochRequest {
            fee,
            deployment: deployment(),
            epoch: 0,
            predecessor_liability: 400,
            deposits_root,

            withdrawals,
            openings: Vec::new(),
            signature,
        });
        chain.deliver(&context, &register).await?;

        // The registration's effect is its certified record, and the chain
        // assigned the deadlines at inclusion, so the fraudulent close is
        // built only after that read-back reveals them: the same completion
        // the honest operator performs.
        let mut registered = None;
        for _ in 0..EFFECT_ATTEMPTS {
            if let Ok(Some(record)) = chain.registration(&context).await {
                registered = Some(record);
                break;
            }
            context.sleep(POLL).await;
        }
        let record = registered.context("the registered epoch left no certified record")?;
        ensure!(record.epoch == 0, "the certified record is not epoch 0");
        let state = crate::protocol::init_replica(
            context.child("fraud_replica"), "fraud-replica",
            commonware_parallel::Rayon::new(NonZeroUsize::MIN)?,
            crate::protocol::genesis_balances(&crate::protocol::deployments()[0])?,
        ).await?;
        let mut fraud_rng = context.child("fraud_rng");
        let fraud = Box::pin(omitting_close(
            state,
            &mut fraud_rng,
            record.admission_deadline,
            record.challenge_deadline,
        ))
        .await?;
        ensure!(
            *fraud.result.context.payment().anchor() == record.anchor,
            "the fraudulent close does not bind the assigned anchor"
        );
        let (committed, _) = fraud
            .held_lookup
            .resolve::<Sha256>(
                &fraud.result.roots.activity_range(&fraud.result.context)?,
                fraud.held_receipt.ack.body().payer(),
                &fraud.receiver,
            )
            .context("resolve the omitted committed entry")?;
        walkthrough::event("Mismatch", format_args!("receipt promises {} / close records {committed}", fraud.held_credit));
        let batch_id = fraud.result.header.batch_id::<Sha256>();
        let admit = SettlementTx::Admit(AdmitRequest::from(&fraud.result));
        chain.deliver(&context, &admit).await?;
        let mut admitted = false;
        for _ in 0..EFFECT_ATTEMPTS {
            if let Ok(Some(record)) = chain.admitted(&context, 0).await
                && record.batch_id == batch_id
            {
                admitted = true;
                break;
            }
            context.sleep(POLL).await;
        }
        ensure!(admitted, "the fraud admission earned no admitted record");

        // The receiver files exactly the challenge its reconciliation would: its held
        // receipt against the committed lookup that omits it.
        let held = &fraud.held_receipt;
        let challenge = Challenge::HigherAckEntry {
            entry: Box::new(EntryWitness {
                ack: AckWitness::from_ack(&held.ack),
                recipient: held.recipient.clone(),
                cumulative: held.cumulative,
                count: held.count,
                opening: held.opening.clone(),
            }),
            sender: Box::new(fraud.held_lookup),
        };
        let tx = SettlementTx::Challenge(ChallengeRequest {
            deployment: deployment(),
            batch_id,
            evidence: challenge.encode(),
        });
        chain.deliver(&context, &tx).await?;

        // The proven verdict is read back certified: the challenge's effect
        // is the fault record naming the exact batch and challenge kind, and
        // the status shows the fence.
        let mut faulted = None;
        for _ in 0..EFFECT_ATTEMPTS {
            if let Ok(Some(fault)) = chain.fault(&context).await {
                faulted = Some(fault);
                break;
            }
            context.sleep(POLL).await;
        }
        let fault = faulted.context("the proven challenge left no certified fault record")?;
        let reason = match fault {
            FaultRecord::Faulted(reason) => reason,
            FaultRecord::Settling(settlement) => settlement.reason,
        };
        ensure!(
            matches!(
                reason,
                HardFaultReasonResponse::ProvenChallenge { batch_id: proven, kind }
                    if proven == batch_id && kind == ChallengeKind::HigherAckEntry
            ),
            "the certified fault record does not name the proven challenge"
        );
        walkthrough::event("Challenge", "receipt proves the omission in one chain transaction");
        let status = chain.status(&context).await?;
        ensure!(
            status.hard_faulted,
            "the proven challenge did not fault the deployment"
        );

        // The harness state agrees with what the light client verified.
        ensure!(
            matches!(
                control.record(status_key(&deployment())).await,
                Some(Record::Status(status)) if status.hard_faulted
            ),
            "the harness status diverged from the certified read"
        );
        walkthrough::event("Verified", "close invalidated; the simulated operator cannot continue");
        println!("\n  Walkthrough complete. Payments, settlement, withdrawals, and receipt enforcement verified.\n");
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::{
        REFRESH_BUDGET, UiState, fraud_arc, handle_hard_fault_recovery,
        handle_pending_deposit_recovery, refresh, refresh_bounded, render,
    };
    use crate::{
        agent::Agent,
        chain::{
            client::{Chain as _, Client},
            harness,
            tx::SettlementTx,
        },
        operator::{Operator, rpc as operator_rpc},
        protocol::{INITIAL_BALANCE, deployment},
        rpc,
    };
    use commonware_clearing::bajillion::boundary::WithdrawalBatch;
    use commonware_cryptography::{Hasher as _, Sha256};
    use commonware_runtime::{
        Clock as _, Listener as _, Network as _, Runner as _, Spawner as _, Supervisor as _,
        deterministic,
    };
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};
    use std::{
        cell::{Cell, RefCell},
        net::SocketAddr,
        num::NonZeroUsize,
        path::Path,
    };

    /// The scripted walkthrough's fraud arc convicts through real chain
    /// transactions and certified reads on the throwaway deployment.
    #[test]
    fn fraud_arc_convicts_on_a_certified_chain() {
        fraud_arc().unwrap();
    }

    #[test]
    fn controls_offer_only_explicit_withdrawal_claims() {
        let backend = TestBackend::new(180, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let agent = Agent::new(0).unwrap();
        let state = UiState::new();

        terminal
            .draw(|frame| render(frame, &agent, &state))
            .unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();

        assert!(rendered.contains("c claim withdrawal"), "{rendered}");
        assert!(!rendered.contains("e payout"), "{rendered}");
    }

    #[derive(Clone, Copy)]
    enum RetryDraftCase {
        BatchThenUnrelated,
        DirectThenSame,
        SameThenDirect,
    }

    #[test]
    fn retry_retires_only_the_paid_draft_entries() {
        retry_draft_case(RetryDraftCase::BatchThenUnrelated);
    }

    #[test]
    fn retry_preserves_same_tuple_staged_after_direct_payment() {
        retry_draft_case(RetryDraftCase::DirectThenSame);
    }

    #[test]
    fn retry_preserves_same_tuple_staged_before_direct_payment() {
        retry_draft_case(RetryDraftCase::SameThenDirect);
    }

    fn retry_draft_case(case: RetryDraftCase) {
        deterministic::Runner::default().start(move |context| async move {
            let chain_address = SocketAddr::from(([127, 0, 0, 1], 2));
            let control = harness::start(&context, chain_address, "retry-ui").await;
            let mut chain = Client::new(
                control.identity(),
                deployment(),
                vec![chain_address],
                context.child("client_rng"),
            )
            .unwrap();
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            control
                .submit(SettlementTx::RegisterEpoch(
                    operator
                        .signed_registration(&WithdrawalBatch::empty())
                        .unwrap(),
                ))
                .await;
            operator
                .adopt_registration(&chain.registration(&context).await.unwrap().unwrap())
                .unwrap();
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let server = context.child("operator").spawn(move |_| async move {
                let mut first = None;
                loop {
                    let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    let request = operator_rpc::decode_request(request).unwrap();
                    let mut drop_reply = false;
                    if let operator_rpc::OperatorRequest::AcceptSend(send) = &request {
                        if let Some(original) = &first {
                            assert_eq!(&send.authorization, original);
                        } else {
                            first = Some(send.authorization.clone());
                            drop_reply = true;
                        }
                    }
                    let response = operator_rpc::handle_decoded(&mut operator, request);
                    if !drop_reply {
                        let _ = rpc::send_response(&mut sink, &response).await;
                    }
                }
            });
            let mut agent = Agent::new(0).unwrap();
            let phase = Cell::new(0);
            let displayed = RefCell::new((1, Vec::new(), false, String::new()));
            let started = context.current();
            super::run_with_io(
                &context,
                address,
                &mut chain,
                &mut agent,
                |agent, state| {
                    *displayed.borrow_mut() = (
                        state.receiver,
                        state.staged.clone(),
                        agent.has_pending_payment(),
                        state.activity.back().cloned().unwrap_or_default(),
                    );
                    Ok(())
                },
                || {
                    assert!(
                        context.current().duration_since(started).unwrap()
                            < std::time::Duration::from_secs(30)
                    );
                    let shown = displayed.borrow();
                    let key = match (case, phase.get()) {
                        (RetryDraftCase::BatchThenUnrelated, 0) => Some(KeyCode::Char('a')),
                        (RetryDraftCase::BatchThenUnrelated, 1) if shown.1.len() == 1 => {
                            Some(KeyCode::Char('b'))
                        }
                        (RetryDraftCase::BatchThenUnrelated, 2) if shown.2 => Some(KeyCode::Right),
                        (RetryDraftCase::BatchThenUnrelated, 3) if shown.0 == 2 => {
                            Some(KeyCode::Char('a'))
                        }
                        (RetryDraftCase::BatchThenUnrelated, 4)
                            if shown.1.iter().any(|(receiver, _)| *receiver == 2) =>
                        {
                            Some(KeyCode::Char('b'))
                        }
                        (RetryDraftCase::BatchThenUnrelated, 5) => {
                            assert!(shown.2);
                            assert!(shown.3.contains("press R"), "{}", shown.3);
                            Some(KeyCode::Char('R'))
                        }
                        (RetryDraftCase::BatchThenUnrelated, 6) if !shown.2 => {
                            Some(KeyCode::Char('q'))
                        }
                        (RetryDraftCase::DirectThenSame, 0) => Some(KeyCode::Char('p')),
                        (RetryDraftCase::DirectThenSame, 1) if shown.2 => Some(KeyCode::Char('a')),
                        (RetryDraftCase::DirectThenSame, 2) if shown.1.len() == 1 => {
                            Some(KeyCode::Char('R'))
                        }
                        (RetryDraftCase::SameThenDirect, 0) => Some(KeyCode::Char('a')),
                        (RetryDraftCase::SameThenDirect, 1) if shown.1.len() == 1 => {
                            Some(KeyCode::Char('p'))
                        }
                        (RetryDraftCase::SameThenDirect, 2) if shown.2 => Some(KeyCode::Char('R')),
                        (_, 3) if !shown.2 => Some(KeyCode::Char('q')),
                        _ => None,
                    };
                    if key.is_some() {
                        phase.set(phase.get() + 1);
                    }
                    Ok(key.map(|key| KeyEvent::new(key, KeyModifiers::NONE)))
                },
            )
            .await
            .unwrap();
            server.abort();
            assert!(!agent.has_pending_payment());
            assert_eq!(agent.receipt_count(), 1);
            let expected = match case {
                RetryDraftCase::BatchThenUnrelated => 2,
                RetryDraftCase::DirectThenSame | RetryDraftCase::SameThenDirect => 1,
            };
            assert_eq!(
                displayed.borrow().1,
                vec![(expected, super::DEFAULT_AMOUNT)]
            );
        });
    }

    #[test]
    fn hung_operator_refresh_degrades_within_its_budget() {
        deterministic::Runner::default().start(|context| async move {
            // Bound but never accepted: dials succeed and the RPC then hangs forever, the
            // same stall shape as a SYN-dropping operator behind a connect timeout. The
            // chain's one query address hangs the same way.
            let operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let chain_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let mut identity_rng = context.child("identity_rng");
            let mut chain = Client::new(
                &harness::identity(&mut identity_rng),
                crate::protocol::deployment(),
                vec![chain_listener.local_addr().unwrap()],
                context.child("client_rng"),
            )
            .unwrap();

            let mut agent = Agent::new(0).unwrap();
            let mut state = UiState::new();
            state.operator = Some(operator_rpc::StatusResponse {
                epoch: 0,
                accounts: 4,
                present_accounts: 4,
                recent_payments: 0,
                close_in_progress: false,
                faulted: false,
            });
            state.settlement = Some(crate::chain::state::StatusRecord {
                height: 1,
                timestamp: 1,
                deployment: deployment(),
                state_root: commonware_clearing::bajillion::qmdb::StateRoot {
                    digest: Sha256::hash(&[b"stale-display-root"]),
                },
                last_finalized: None,
                custody: 400,
                claimable: 0,
                hard_faulted: false,
            });
            state.balance = Some(7);

            let started = context.current();
            refresh_bounded(
                &context,
                operator_address,
                &mut chain,
                &mut agent,
                &mut state,
            )
            .await
            .unwrap();
            let elapsed = context.current().duration_since(started).unwrap();
            assert!(elapsed >= REFRESH_BUDGET, "{elapsed:?}");
            assert!(elapsed < 2 * REFRESH_BUDGET, "{elapsed:?}");
            assert!(state.operator.is_none());
            assert!(state.settlement.is_none());
            assert!(state.balance.is_none());
            drop(operator_listener);
            drop(chain_listener);
        });
    }

    #[test]
    fn hung_operator_cannot_hide_certified_native_funds() {
        deterministic::Runner::default().start(|context| async move {
            let address = SocketAddr::from(([127, 0, 0, 1], 2));
            let control = harness::start(&context, address, "native-ui").await;
            let mut chain = Client::new(
                control.identity(),
                deployment(),
                vec![address],
                context.child("client_rng"),
            )
            .unwrap();
            let operator = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let mut agent = Agent::new(0).unwrap();
            let expected = control
                .identity()
                .native
                .balances
                .iter()
                .find(|entry| entry.key == agent.account())
                .unwrap()
                .balance;
            let mut state = UiState::new();
            refresh_bounded(
                &context,
                operator.local_addr().unwrap(),
                &mut chain,
                &mut agent,
                &mut state,
            )
            .await
            .unwrap();
            assert_eq!(state.native_balance, Some(expected));
            assert!(state.operator.is_none());
        });
    }

    #[test]
    fn unavailable_operator_keeps_settlement_visible_and_recovery_reachable() {
        deterministic::Runner::default().start(|context| async move {
            let control =
                harness::start(&context, SocketAddr::from(([127, 0, 0, 1], 2)), "ui").await;
            let mut chain = Client::new(
                control.identity(),
                crate::protocol::deployment(),
                vec![SocketAddr::from(([127, 0, 0, 1], 2))],
                context.child("client_rng"),
            )
            .unwrap();

            let operator_address = SocketAddr::from(([127, 0, 0, 1], 1));
            let mut agent = Agent::new(0).unwrap();
            let mut state = UiState::new();
            state.pending_closes.push_back(7);

            refresh(
                &context,
                operator_address,
                &mut chain,
                &mut agent,
                &mut state,
            )
            .await
            .unwrap();

            assert!(state.operator.is_none());

            // The validators serve the certified head, so the balance stays
            // visible with the operator dead.
            assert_eq!(state.balance, Some(INITIAL_BALANCE));
            assert_eq!(
                state.pending_closes.iter().copied().collect::<Vec<_>>(),
                [7]
            );

            // Recovery remains available, but an unfaulted deployment cannot
            // release custody through either recovery path.
            let settlement = state.settlement.clone().unwrap();
            assert_eq!(settlement.deployment, deployment());
            assert!(!settlement.hard_faulted);
            assert_eq!(settlement.custody, 400);

            handle_hard_fault_recovery(&context, &mut chain, &mut agent, &mut state).await;
            let logged = state.activity.back().unwrap().clone();
            assert!(
                logged.contains("terminal settlement never certifiably began"),
                "{logged}"
            );
            handle_pending_deposit_recovery(&context, &mut chain, &agent, &mut state).await;
            let logged = state.activity.back().unwrap().clone();
            assert!(
                logged.contains("deposit recovery requires a certified deployment fault"),
                "{logged}"
            );
        });
    }
}
