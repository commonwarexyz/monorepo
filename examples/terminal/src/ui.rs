//! Ratatui presentation for one independently owned agent wallet.

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
        rpc::{AcceptedBatchResponse, PollCloseResponse, StatusResponse as OperatorStatus},
    },
    protocol::{Protocol, deployment, omitting_boundary, omitting_close},
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    boundary::{WithdrawalAction, WithdrawalBatch},
    challenge::ChallengeKind,
};
use commonware_cryptography::Sha256;
use commonware_macros::select;
use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
use crossterm::{
    cursor::Show,
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::{
    collections::VecDeque,
    io::Stdout,
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    thread,
    time::Duration,
};

const MAX_ACTIVITY: usize = 100;

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

struct UiState {
    receiver: usize,
    amount: u64,
    staged: Vec<(usize, u64)>,
    balance: Option<u64>,
    operator: Option<OperatorStatus>,
    settlement: Option<StatusRecord>,
    pending_closes: VecDeque<u64>,
    activity: VecDeque<String>,
}

impl UiState {
    fn new() -> Self {
        let mut activity = VecDeque::new();
        activity.push_back(
            "Ready: deposit or withdraw before paying; a close finalizes after its challenge window."
                .to_string(),
        );
        Self {
            receiver: 1,
            amount: DEFAULT_AMOUNT,
            staged: Vec::new(),
            balance: None,
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
    let mut state = UiState::new();
    state.receiver = agent.default_receiver();
    loop {
        refresh_bounded(network, operator, &mut chain, &mut agent, &mut state).await?;
        terminal
            .terminal
            .draw(|frame| render(frame, &agent, &state))
            .context("draw clearing agent")?;
        if !event::poll(Duration::from_millis(100)).context("poll terminal input")? {
            continue;
        }
        let Event::Key(key) = event::read().context("read terminal input")? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => break,
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
            KeyCode::Char('p') => {
                let receiver = agent.receiver_name(state.receiver);
                match agent
                    .pay(
                        network,
                        &mut chain,
                        operator,
                        &[(state.receiver, state.amount)],
                    )
                    .await
                {
                    Ok(PaymentOutcome::Accepted(payment)) => state.log(format!(
                        "epoch {} payment #{} to {receiver}: {}",
                        payment.epoch, payment.sequence, payment.total
                    )),
                    Ok(PaymentOutcome::CommittedUnheld { epoch, total }) => state.log(format!(
                        "epoch {epoch} payment for {total} committed in a finalized close; receipts unheld"
                    )),
                    Err(error) => state.log(format!("payment rejected: {error:#}")),
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
                        .pay(network, &mut chain, operator, &state.staged)
                        .await
                    {
                        Ok(PaymentOutcome::Accepted(payment)) => {
                            state.log(format!(
                                "epoch {} batch #{} paid {} across {} receivers",
                                payment.epoch,
                                payment.sequence,
                                payment.total,
                                payment.acceptance.receipts.len()
                            ));
                            state.staged.clear();
                        }
                        Ok(PaymentOutcome::CommittedUnheld { epoch, total }) => {
                            state.log(format!(
                                "epoch {epoch} batch for {total} committed in a finalized close; receipts unheld"
                            ));
                            state.staged.clear();
                        }
                        Err(error) => state.log(format!(
                            "batch rejected; press b to retry the same batch: {error:#}"
                        )),
                    }
                }
            }
            KeyCode::Char('h') => {
                handle_hard_fault_recovery(network, &mut chain, &agent, &mut state).await;
            }
            KeyCode::Char('r') => {
                handle_pending_deposit_recovery(network, &mut chain, &agent, &mut state).await;
            }
            KeyCode::Char('d') => match agent.deposit(network, &mut chain, state.amount).await {
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
                match agent.withdraw(network, &mut chain, operator, action).await {
                    Ok(WithdrawalOutcome::Applied { epoch, request }) => match request.body().action() {
                        WithdrawalAction::Amount(amount) => state.log(format!(
                            "epoch {epoch} withdrawal carried by operator: {amount}"
                        )),
                        WithdrawalAction::Close => state.log(format!(
                            "epoch {epoch} Close carried by operator; payout is finalized at epoch close"
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
            KeyCode::Char('x') => match agent.escalate_withdrawal(network, &mut chain).await {
                Ok(request) => state.log(format!(
                    "withdrawal escalated to settlement through deadline {}; the next registered close must carry it verbatim; if the operator stalls, expiry becomes hard-fault recovery via h",
                    request.body().deadline()
                )),
                Err(error) => state.log(format!("withdrawal escalation rejected: {error:#}")),
            },
            KeyCode::Char('c') => match agent
                .claim_withdrawal(network, &mut chain, operator)
                .await
            {
                Ok(release) => state.log(format!(
                    "withdrawal claimed: {} to {}",
                    release.amount,
                    String::from_utf8_lossy(&release.destination)
                )),
                Err(error) => state.log(format!("claim rejected: {error:#}")),
            },
            KeyCode::Char('e') => {
                match agent
                    .claim_external_payout(network, &mut chain, operator)
                    .await
                {
                    Ok(payout) => state.log(format!(
                        "external payout claimed for {}: {}",
                        agent.name(),
                        payout.amount
                    )),
                    Err(error) => state.log(format!("external claim rejected: {error:#}")),
                }
            }
            KeyCode::Char('s') => match agent.start_close(network, operator).await {
                Ok(close) => {
                    if !state.pending_closes.contains(&close.epoch) {
                        state.pending_closes.push_back(close.epoch);
                    }
                    state.log(format!(
                        "epoch {} cut{}; successor payments resume after settlement finalization",
                        close.epoch,
                        if close.queued { " and queued" } else { "" }
                    ));
                }
                Err(error) => state.log(format!("close rejected: {error:#}")),
            },
            _ => {}
        }
    }
    Ok(())
}

async fn handle_hard_fault_recovery<E: Env>(
    ctx: &E,
    chain: &mut Client,
    agent: &Agent,
    state: &mut UiState,
) {
    match agent.recover_hard_fault(ctx, chain).await {
        Ok(release) => state.log(format!(
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
/// On timeout the refresh future is dropped and every polled status degrades to its
/// unavailable display. At most one refresh is ever in flight.
async fn refresh_bounded<E: Env>(
    network: &E,
    operator: SocketAddr,
    chain: &mut Client,
    agent: &mut Agent,
    state: &mut UiState,
) -> Result<()> {
    let refreshed = select! {
        result = refresh(network, operator, chain, agent, state) => Some(result),
        _ = network.sleep(REFRESH_BUDGET) => None,
    };
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
    if let Some(epoch) = state.pending_closes.front().copied() {
        match agent.poll_close(network, operator, epoch).await {
            Ok(PollCloseResponse::NoEvent) | Err(_) => {}
            Ok(PollCloseResponse::Finished(close)) => {
                state.pending_closes.pop_front();
                state.log(format!(
                    "epoch {} finalized {}: {} rows, {} slices, prepare {}us, deal {}us, seal {}us",
                    close.epoch,
                    String::from_utf8_lossy(&close.header),
                    close.rows,
                    close.slices,
                    close.prepare_micros,
                    close.deal_micros,
                    close.seal_micros
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

    // Receiver intake and its background assurance loop degrade silently like the rest of the
    // heartbeat: a held pair is reliance-grade only once durably persisted and settlement-anchored
    // here. Enforcement events are surfaced into the activity feed so the conviction arc is
    // visible in the running wallet.
    let _ = agent.intake_incoming(network, chain, operator).await;
    if let Ok(summary) = agent.reconcile(network, chain, operator).await {
        for epoch in summary.convicted {
            state.log(format!(
                "epoch {epoch} omission convicted via HigherShardTip; the close is invalidated"
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
    Ok(())
}

fn render(frame: &mut Frame<'_>, agent: &Agent, state: &UiState) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(7),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let incoming = agent.incoming();
    let reconciled = agent
        .last_reconciled_epoch()
        .map_or_else(|| "none".to_string(), |epoch| format!("epoch {epoch}"));
    let title = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                " Bajillion Agent ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "{}  balance {}  {} retained receipt(s)",
                agent.name(),
                state
                    .balance
                    .map_or_else(|| "?".to_string(), |value| value.to_string()),
                agent.receipt_count()
            )),
        ]),
        Line::raw(format!(
            "Receiver ledger: verified incoming {} across {} pair(s) | last reconciled {reconciled}",
            incoming.total, incoming.count
        )),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, sections[0]);

    let operator = state.operator.map_or_else(
        || "operator unavailable".to_string(),
        |status| {
            format!(
                "Operator epoch {} | {}/{} live accounts | {} recent payments | close {} | reserved payouts {}{}",
                status.epoch,
                status.present_accounts,
                status.accounts,
                status.recent_payments,
                if status.close_in_progress { "active" } else { "idle" },
                status.reserved_payout_value,
                if status.faulted { " | FENCED" } else { "" }
            )
        },
    );
    let settlement = state.settlement.as_ref().map_or_else(
        || "settlement unavailable".to_string(),
        |status| {
            format!(
                "Settlement custody {} | claimable {} | height {} | state {}...{}",
                status.custody,
                status.claimable,
                status.height,
                status
                    .state_root
                    .digest
                    .as_ref()
                    .iter()
                    .take(4)
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                if status.hard_faulted {
                    " | HARD FAULT"
                } else {
                    ""
                }
            )
        },
    );
    let staged = if state.staged.is_empty() {
        "Batch: empty".to_string()
    } else {
        let entries = state
            .staged
            .iter()
            .map(|(receiver, amount)| format!("{} {amount}", agent.receiver_name(*receiver)))
            .collect::<Vec<_>>()
            .join(", ");
        format!("Batch: {entries}")
    };
    let controls = Paragraph::new(vec![
        Line::raw(operator),
        Line::raw(settlement),
        Line::raw(format!(
            "Receiver: {} | amount {}",
            agent.receiver_name(state.receiver),
            state.amount
        )),
        Line::raw(staged),
        Line::raw(
            "p pay  a stage  b pay batch  d deposit  r refund deposit  w withdraw  f Close  x escalate  c claim  e payout  h recover state  s cut epoch",
        ),
        Line::raw("Left/Right receiver  +/- amount  PgUp/PgDn +/-10"),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Roles and actions"),
    );
    frame.render_widget(controls, sections[1]);

    let activity = Paragraph::new(
        state
            .activity
            .iter()
            .rev()
            .map(|message| Line::raw(message.clone()))
            .collect::<Vec<_>>(),
    )
    .wrap(Wrap { trim: true })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Activity (newest first)"),
    );
    frame.render_widget(activity, sections[2]);

    let footer = Paragraph::new(
        "The agent signs locally; the SQLite operator issues receipts; the settlement chain owns custody and claims. q or Esc quits.",
    )
    .style(Style::default().fg(Color::DarkGray))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, sections[3]);
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

/// Starts one asynchronous close and drives it to the operator's certified
/// finalization, returning the closed epoch.
async fn close_epoch<E: Env>(network: &E, operator: SocketAddr, agent: &mut Agent) -> Result<u64> {
    let close = agent.start_close(network, operator).await?;
    println!("epoch {} cut and closing asynchronously", close.epoch);
    loop {
        match agent.poll_close(network, operator, close.epoch).await? {
            PollCloseResponse::NoEvent => thread::sleep(Duration::from_millis(10)),
            PollCloseResponse::Finished(finished) => {
                println!(
                    "epoch {} finalized {} rows: dealings sealed and voted by the validator committee over the DA channel (prepare={}us deal={}us seal={}us)",
                    finished.epoch,
                    finished.rows,
                    finished.prepare_micros,
                    finished.deal_micros,
                    finished.seal_micros
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

/// Polls the verified balance until it reaches `expected`, the wallet's view
/// of the operator observing and crediting a finalized deposit.
async fn observed_balance<E: Env>(
    network: &E,
    operator: SocketAddr,
    chain: &mut Client,
    agent: &mut Agent,
    expected: u64,
) -> Result<u64> {
    for _ in 0..EFFECT_ATTEMPTS {
        if let Ok(balance) = agent.balance(network, chain, operator).await
            && balance == expected
        {
            return Ok(balance);
        }
        network.sleep(POLL).await;
    }
    anyhow::bail!("the operator never credited the observed deposit")
}

pub(crate) async fn scripted<E: Env>(
    network: &E,
    operator: SocketAddr,
    mut chain: Client,
    mut agent: Agent,
) -> Result<()> {
    let mut start = None;
    for _ in 0..EFFECT_ATTEMPTS {
        if let Ok(balance) = agent.balance(network, &mut chain, operator).await {
            start = Some(balance);
            break;
        }
        network.sleep(POLL).await;
    }
    let start = start.context("read the verified starting balance")?;
    let deposit = agent.deposit(network, &mut chain, 10).await?;
    println!(
        "deposited {}: chain custody proven by a certified read; no operator report",
        deposit.amount
    );

    // The operator's follower observes the finalized custody record and
    // stages the credit on its own, which the verified balance poll shows.
    let credited = observed_balance(
        network,
        operator,
        &mut chain,
        &mut agent,
        start + deposit.amount,
    )
    .await?;
    println!("operator observed the deposit: verified balance {credited}");
    let withdrawal = match agent
        .withdraw(
            network,
            &mut chain,
            operator,
            WithdrawalAction::Amount(NonZeroU64::new(3).unwrap()),
        )
        .await?
    {
        WithdrawalOutcome::Applied { epoch, .. } => epoch,
        WithdrawalOutcome::Signed { request, error } => anyhow::bail!(
            "withdrawal signed through deadline {}; operator carriage unknown; retry uses the same signed request: {error:#}",
            request.body().deadline()
        ),
    };
    println!("epoch {} carried withdrawal 3", withdrawal);
    let payment = accepted(agent.pay(network, &mut chain, operator, &[(1, 5)]).await?)?;
    println!(
        "epoch {} accepted payment #{}: the context matches a certified anchor read",
        payment.epoch, payment.sequence
    );

    // The payer chooses the transaction id by signing its send, so it is the invoice reference a
    // receiver answers its service-accounting query against below.
    let invoice = payment.acceptance.send.tx_id::<Sha256>().into_digest();
    let payer_account = agent.account();
    let batch = accepted(
        agent
            .pay(network, &mut chain, operator, &[(2, 2), (3, 1)])
            .await?,
    )?;
    println!(
        "epoch {} accepted batch #{} paying {} across {} receivers",
        batch.epoch,
        batch.sequence,
        batch.total,
        batch.acceptance.receipts.len()
    );
    let external_payment = accepted(
        agent
            .pay(
                network,
                &mut chain,
                operator,
                &[(agent.receiver_count() - 1, 2)],
            )
            .await?,
    )?;
    println!(
        "epoch {} accepted external payment #{}",
        external_payment.epoch, external_payment.sequence
    );

    // Receiver gate-before-service: the receiver durably intakes and settlement-anchors its
    // incoming pairs BEFORE the epoch is cut, and only then relies on the payment. A balance
    // read from the operator's head is not reliance-grade, but the held, anchored receipt is.
    let receiver_database = std::env::temp_dir().join(format!(
        "commonware-terminal-receiver-{}.sqlite",
        std::process::id()
    ));
    let mut receiver = Agent::open_for(&receiver_database, 1, agent.operator())?;
    receiver
        .intake_incoming(network, &mut chain, operator)
        .await?;
    let ledger = receiver.incoming();
    println!(
        "receiver {} durably holds verified incoming {} across {} pair(s), anchored to the chain-registered context by a certified read, before the close is cut",
        receiver.name(),
        ledger.total,
        ledger.count
    );
    match receiver.paid(&payer_account, &invoice)? {
        Some(credit) => println!(
            "receiver gate: releasing service, payer paid {} under the invoice in epoch {}",
            credit.amount, credit.epoch
        ),
        None => println!("receiver gate: no held evidence for the invoice, withholding service"),
    }

    let closed = close_epoch(network, operator, &mut agent).await?;
    let release = agent
        .claim_withdrawal(network, &mut chain, operator)
        .await?;
    println!(
        "claimed withdrawal {} against the certified release record",
        release.amount
    );

    // Receiver reconciliation after finalization: every finalized credit is proven backed by the
    // committed close, so the earlier service release was evidence-backed. It runs before the
    // successor epoch closes: the operator's shard-tip reconstruction retains a finalized
    // epoch's account-state versions only until a later finalization prunes them.
    let summary = receiver.reconcile(network, &mut chain, operator).await?;
    for epoch in &summary.reconciled {
        println!(
            "receiver reconciled epoch {epoch} against the certified admitted roots: every held credit is evidence-backed"
        );
    }
    let _ = std::fs::remove_file(&receiver_database);
    for suffix in ["-wal", "-shm"] {
        let mut path = receiver_database.clone().into_os_string();
        path.push(suffix);
        let _ = std::fs::remove_file(path);
    }

    let mut external = Agent::new_for(4, agent.operator())?;
    let payout = external
        .claim_external_payout(network, &mut chain, operator)
        .await?;
    println!(
        "claimed external payout {} against the certified release record",
        payout.amount
    );

    let successor = accepted(agent.pay(network, &mut chain, operator, &[(1, 1)]).await?)?;
    println!(
        "epoch {} accepted successor payment #{} after epoch {} finalized",
        successor.epoch, successor.sequence, closed
    );

    // The successor payment registered the next epoch's payment context, so
    // close that epoch too, inside its admission runway: an activated context
    // left registered would expire its admission deadline and permanently
    // hard-fault the deployment.
    close_epoch(network, operator, &mut agent).await?;

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
        thread::sleep(Duration::from_millis(100));
    }
    ensure!(retired, "a live registration outlived the walkthrough");
    println!("certified read proves no live registration remains: the deployment idles safely");

    fraud_arc()?;
    Ok(())
}

/// Demonstrates the enforcement thesis live: an operator that omits a receiver's credit is
/// convicted by the receiver's held receipt, and the close is invalidated.
///
/// The honest operator binary can never produce an inconsistent close, so the fraud is
/// assembled with the shared omitting-close machinery and adjudicated by a throwaway
/// in-process single-validator chain: the fraudulent close is registered and admitted as
/// real transactions, the receiver files one real `HigherShardTip` challenge transaction,
/// and the proven verdict, the fault record, and the hard-faulted status are all read back
/// certified through the light client. This mirrors what a receiver's reconciliation does
/// on the wire against the live deployment.
fn fraud_arc() -> Result<()> {
    println!(
        "fraud: this arc alone is a throwaway in-process single-validator chain with locally simulated close certification, while its deposit, registration, admission, challenge, and readbacks are real transactions and certified reads"
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
                &SettlementTx::Deposit(DepositRequest {
                    deployment: deployment(),
                    event: deposit,
                }),
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
        let signature = protocol.sign_chain_registration(
            0,
            400,
            &deposits_root,
            &deposits_root,
            &withdrawals,
        );
        let register = SettlementTx::RegisterEpoch(RegisterEpochRequest {
            deployment: deployment(),
            epoch: 0,
            predecessor_liability: 400,
            deposits_root,
            staged_root: deposits_root,
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
        let fraud = omitting_close(
            &mut rand::rng(),
            record.admission_deadline,
            record.challenge_deadline,
        )?;
        ensure!(
            *fraud.result.payment_context.anchor() == record.anchor,
            "the fraudulent close does not bind the assigned anchor"
        );
        let committed = fraud
            .held_lookup
            .resolve::<Sha256>(&fraud.result.roots.change, &fraud.receiver, 0)
            .context("resolve the omitted committed tip")?
            .map_or(0, |tip| tip.cumulative_credit);
        println!(
            "fraud: the operator's admitted close commits cumulative credit {committed} for the omitted receiver, which holds an operator-signed receipt for {}",
            fraud.held_credit
        );
        let batch_id = fraud.result.finalized.batch_id;
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

        // The receiver files exactly the challenge its reconciliation would: its held pair
        // against the committed lookup that omits it.
        let challenge = commonware_clearing::bajillion::challenge::Challenge::HigherShardTip {
            payment: Box::new(
                commonware_clearing::bajillion::payment::PaymentWitness::from_payment(
                    &fraud.held_pair,
                ),
            ),
            recipient: Box::new(fraud.held_lookup),
        };
        let tx = SettlementTx::Challenge(ChallengeRequest {
            batch_id,
            evidence: commonware_codec::Encode::encode(&challenge),
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
                    if proven == batch_id && kind == ChallengeKind::HigherShardTip
            ),
            "the certified fault record does not name the proven challenge"
        );
        println!("fraud: HigherShardTip proven; the omitting close is invalidated");
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
        println!("fraud: settlement is hard-faulted, so the fraudulent operator is fenced");
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::{
        REFRESH_BUDGET, UiState, fraud_arc, handle_hard_fault_recovery,
        handle_pending_deposit_recovery, refresh, refresh_bounded,
    };
    use crate::{
        agent::Agent,
        chain::{client::Client, harness},
        operator::rpc as operator_rpc,
        protocol::deployment,
    };
    use commonware_clearing::bajillion::commitment::VectorRoot;
    use commonware_cryptography::{Hasher as _, Sha256};
    use commonware_runtime::{
        Clock as _, Listener as _, Network as _, Runner as _, Supervisor as _, deterministic,
    };
    use std::net::SocketAddr;

    /// The scripted walkthrough's fraud arc convicts through real chain
    /// transactions and certified reads on the throwaway deployment.
    #[test]
    fn fraud_arc_convicts_on_a_certified_chain() {
        fraud_arc().unwrap();
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
            let mut chain = Client::new(
                &harness::identity(&mut context.child("identity_rng")),
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
                reserved_payout_value: 0,
                close_in_progress: false,
                faulted: false,
            });
            state.settlement = Some(crate::chain::state::StatusRecord {
                height: 1,
                timestamp: 1,
                deployment: deployment(),
                state_root: VectorRoot {
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
            assert!(state.balance.is_none());
            assert_eq!(
                state.pending_closes.iter().copied().collect::<Vec<_>>(),
                [7]
            );

            // The certified settlement status stays visible with the operator
            // dead, and the recovery keys still reach the chain: an unfaulted
            // deployment rejects both with no effect, so the flows time out
            // on the missing effect record and surface the advisory dry-run
            // diagnosis.
            let settlement = state.settlement.clone().unwrap();
            assert_eq!(settlement.deployment, deployment());
            assert!(!settlement.hard_faulted);
            assert_eq!(settlement.custody, 400);

            handle_hard_fault_recovery(&context, &mut chain, &agent, &mut state).await;
            let logged = state.activity.back().unwrap().clone();
            assert!(
                logged.contains("terminal settlement never certifiably began")
                    && logged.contains("Doomed(FaultUnavailable)"),
                "{logged}"
            );
            handle_pending_deposit_recovery(&context, &mut chain, &agent, &mut state).await;
            let logged = state.activity.back().unwrap().clone();
            assert!(
                logged.contains("the refund claim earned no certified release")
                    && logged.contains("Doomed(FaultUnavailable)"),
                "{logged}"
            );
        });
    }
}
