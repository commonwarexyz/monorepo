//! Ratatui presentation for one independently owned agent wallet.

use crate::{
    agent::{Agent, DepositOutcome, PaymentOutcome, WithdrawalOutcome},
    operator::{
        DEFAULT_AMOUNT,
        rpc::{AcceptedBatchResponse, PollCloseResponse, StatusResponse as OperatorStatus},
    },
    protocol::omitting_close,
    rpc,
    settlement::{
        Settlement, SettlementSubmission, rpc as settlement_rpc,
        rpc::StatusResponse as SettlementStatus,
    },
};
use anyhow::{Context, Result};
use commonware_clearing::bajillion::{
    boundary::{WithdrawalAction, WithdrawalBatch},
    challenge::{Challenge, ChallengeKind},
    payment::PaymentWitness,
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::Sha256;
use commonware_macros::select;
use commonware_runtime::{Clock, Network};
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
    collections::VecDeque, io::Stdout, net::SocketAddr, num::NonZeroU64, thread, time::Duration,
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
    settlement: Option<SettlementStatus>,
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

pub(crate) async fn run<E: Clock + Network>(
    network: &E,
    operator: SocketAddr,
    settlement: SocketAddr,
    mut agent: Agent,
) -> Result<()> {
    let mut terminal = TerminalSession::enter()?;
    let mut state = UiState::new();
    state.receiver = agent.default_receiver();
    loop {
        refresh_bounded(network, operator, settlement, &mut agent, &mut state).await?;
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
                        settlement,
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
                        .pay(network, settlement, operator, &state.staged)
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
                handle_hard_fault_recovery(network, settlement, &agent, &mut state).await;
            }
            KeyCode::Char('r') => {
                handle_pending_deposit_recovery(network, settlement, &agent, &mut state).await;
            }
            KeyCode::Char('d') => match agent
                .deposit(network, settlement, operator, state.amount)
                .await
            {
                Ok(DepositOutcome::Applied { epoch, event }) => {
                    let amount = event.amount;
                    state.log(format!("epoch {epoch} deposit credited: {amount}"));
                }
                Ok(DepositOutcome::Recorded { event, error }) => {
                    let amount = event.amount;
                    state.log(format!(
                        "settlement custody recorded for {amount}; operator credit unknown; retry uses the same deposit: {error:#}"
                    ));
                }
                Err(error) => state.log(format!("deposit not confirmed: {error:#}")),
            },
            KeyCode::Char('w') | KeyCode::Char('f') => {
                let action = if key.code == KeyCode::Char('f') {
                    WithdrawalAction::Close
                } else {
                    WithdrawalAction::Amount(
                        NonZeroU64::new(state.amount).expect("UI amount is positive"),
                    )
                };
                match agent.withdraw(network, settlement, operator, action).await {
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
            KeyCode::Char('x') => match agent.escalate_withdrawal(network, settlement).await {
                Ok(request) => state.log(format!(
                    "withdrawal escalated to settlement through deadline {}; the next registered close must carry it verbatim; if the operator stalls, expiry becomes hard-fault recovery via h",
                    request.body().deadline()
                )),
                Err(error) => state.log(format!("withdrawal escalation rejected: {error:#}")),
            },
            KeyCode::Char('c') => match agent.claim_withdrawal(network, settlement, operator).await
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
                    .claim_external_payout(network, settlement, operator)
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

async fn handle_hard_fault_recovery<E: Network>(
    network: &E,
    settlement: SocketAddr,
    agent: &Agent,
    state: &mut UiState,
) {
    match agent.recover_hard_fault(network, settlement).await {
        Ok(release) => state.log(format!(
            "hard-fault recovery released {} (residual {})",
            release.released_custody, release.residual
        )),
        Err(error) => state.log(format!("hard-fault recovery rejected: {error:#}")),
    }
}

async fn handle_pending_deposit_recovery<E: Network>(
    network: &E,
    settlement: SocketAddr,
    agent: &Agent,
    state: &mut UiState,
) {
    match agent.recover_pending_deposit(network, settlement).await {
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
async fn refresh_bounded<E: Clock + Network>(
    network: &E,
    operator: SocketAddr,
    settlement: SocketAddr,
    agent: &mut Agent,
    state: &mut UiState,
) -> Result<()> {
    let refreshed = select! {
        result = refresh(network, operator, settlement, agent, state) => Some(result),
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

async fn refresh<E: Network>(
    network: &E,
    operator: SocketAddr,
    settlement: SocketAddr,
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
    state.settlement = agent.settlement_status(network, settlement).await.ok();

    // The verified balance poll also refreshes the wallet's frozen-root recovery opening.
    state.balance = agent.balance(network, settlement, operator).await.ok();

    // Receiver intake and its background assurance loop degrade silently like the rest of the
    // heartbeat: a held pair is reliance-grade only once durably persisted and settlement-anchored
    // here. Enforcement events are surfaced into the activity feed so the conviction arc is
    // visible in the running wallet.
    let _ = agent.intake_incoming(network, settlement, operator).await;
    if let Ok(summary) = agent.reconcile(network, settlement, operator).await {
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
    let settlement = state.settlement.map_or_else(
        || "settlement unavailable".to_string(),
        |status| {
            format!(
                "Settlement custody {} | claimable {} | time {} | state {}...{}",
                status.custody_balance,
                status.claimable_balance,
                status.now,
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
        "The agent signs locally; the SQLite operator issues receipts; settlement owns custody and claims. q or Esc quits.",
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

pub(crate) async fn scripted<E: Network>(
    network: &E,
    operator: SocketAddr,
    settlement: SocketAddr,
    mut agent: Agent,
) -> Result<()> {
    let (deposit_epoch, deposit) = match agent.deposit(network, settlement, operator, 10).await? {
        DepositOutcome::Applied { epoch, event } => (epoch, event),
        DepositOutcome::Recorded { event, error } => anyhow::bail!(
            "settlement custody recorded for {}; operator credit unknown; retry uses the same deposit: {error:#}",
            event.amount
        ),
    };
    println!("epoch {} deposited {}", deposit_epoch, deposit.amount);
    let withdrawal = match agent
        .withdraw(
            network,
            settlement,
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
    let payment = accepted(agent.pay(network, settlement, operator, &[(1, 5)]).await?)?;
    println!(
        "epoch {} accepted payment #{}",
        payment.epoch, payment.sequence
    );

    // The payer chooses the transaction id by signing its send, so it is the invoice reference a
    // receiver answers its service-accounting query against below.
    let invoice = payment.acceptance.send.tx_id::<Sha256>().into_digest();
    let payer_account = agent.account();
    let batch = accepted(
        agent
            .pay(network, settlement, operator, &[(2, 2), (3, 1)])
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
                settlement,
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
    let mut receiver = Agent::open(&receiver_database, 1)?;
    receiver
        .intake_incoming(network, settlement, operator)
        .await?;
    let ledger = receiver.incoming();
    println!(
        "receiver {} durably holds verified incoming {} across {} pair(s) before the close is cut",
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

    let close = agent.start_close(network, operator).await?;
    println!("epoch {} cut and closing asynchronously", close.epoch);
    loop {
        match agent.poll_close(network, operator, close.epoch).await? {
            PollCloseResponse::NoEvent => thread::sleep(Duration::from_millis(10)),
            PollCloseResponse::Finished(finished) => {
                println!(
                    "epoch {} finalized {} rows in prepare={}us deal={}us seal={}us",
                    finished.epoch,
                    finished.rows,
                    finished.prepare_micros,
                    finished.deal_micros,
                    finished.seal_micros
                );
                break;
            }
            PollCloseResponse::Failed { epoch, error } => {
                anyhow::bail!(
                    "epoch {epoch} close failed: {}",
                    String::from_utf8_lossy(&error)
                );
            }
        }
    }
    let successor = accepted(agent.pay(network, settlement, operator, &[(1, 1)]).await?)?;
    println!(
        "epoch {} accepted successor payment #{} after epoch {} finalized",
        successor.epoch, successor.sequence, close.epoch
    );
    let release = agent
        .claim_withdrawal(network, settlement, operator)
        .await?;
    println!("claimed withdrawal {}", release.amount);

    // Receiver reconciliation after finalization: every finalized credit is proven backed by the
    // committed close, so the earlier service release was evidence-backed.
    let summary = receiver.reconcile(network, settlement, operator).await?;
    for epoch in &summary.reconciled {
        println!("receiver reconciled epoch {epoch}: every held credit is evidence-backed");
    }
    let _ = std::fs::remove_file(&receiver_database);
    for suffix in ["-wal", "-shm"] {
        let mut path = receiver_database.clone().into_os_string();
        path.push(suffix);
        let _ = std::fs::remove_file(path);
    }

    let mut external = Agent::new(4)?;
    let payout = external
        .claim_external_payout(network, settlement, operator)
        .await?;
    println!("claimed external payout {}", payout.amount);

    fraud_arc()?;
    Ok(())
}

/// Demonstrates the enforcement thesis live: an operator that omits a receiver's credit is
/// convicted by the receiver's held receipt, and the close is invalidated.
///
/// The honest operator binary can never produce an inconsistent close, so the fraud is assembled
/// here with the shared omitting-close machinery and adjudicated by a self-contained settlement
/// through the real challenge dispatch. This mirrors what a receiver's reconciliation does on
/// the wire: it holds an operator-signed receipt, resolves the committed tip that omits it, and
/// files one `HigherShardTip` challenge that settlement proves.
fn fraud_arc() -> Result<()> {
    let fraud = omitting_close(&mut rand::rng())?;
    let committed = fraud
        .held_lookup
        .resolve::<Sha256>(&fraud.result.roots.change, &fraud.receiver, 0)
        .context("resolve the omitted committed tip")?
        .map_or(0, |tip| tip.cumulative_credit);
    println!(
        "fraud: the operator's admitted close commits cumulative credit {committed} for the omitted receiver, which holds an operator-signed receipt for {}",
        fraud.held_credit
    );

    let mut settlement = Settlement::new()?;
    settlement.deposit(fraud.deposit.clone())?;
    let deposits_root = fraud.deposits.root::<Sha256>()?;
    settlement.register_epoch(
        0,
        400,
        deposits_root,
        deposits_root,
        WithdrawalBatch::empty(),
        &[],
    )?;
    settlement.admit_submission(SettlementSubmission::from(&fraud.result))?;

    // The receiver files exactly the challenge its reconciliation would: its held pair against
    // the committed lookup that omits it.
    let challenge = Challenge::HigherShardTip {
        payment: Box::new(PaymentWitness::from_payment(&fraud.held_pair)),
        recipient: Box::new(fraud.held_lookup),
    };
    let batch_id = fraud.result.finalized.batch_id;
    let now = settlement.observe_now();
    let response = settlement_rpc::dispatch(
        &mut settlement,
        now,
        rpc::Request {
            method: settlement_rpc::METHOD_CHALLENGE,
            body: settlement_rpc::ChallengeRequest {
                batch_id,
                evidence: challenge.encode(),
            }
            .encode(),
        },
    )
    .context("adjudicate the fraud challenge")?;
    let verdict =
        settlement_rpc::ChallengeVerdict::decode(response).context("decode the fraud verdict")?;
    anyhow::ensure!(
        verdict == settlement_rpc::ChallengeVerdict::Proven(ChallengeKind::HigherShardTip),
        "the fraud challenge did not prove"
    );
    println!("fraud: HigherShardTip proven; the omitting close is invalidated");
    anyhow::ensure!(
        settlement.status()?.hard_faulted,
        "the proven challenge did not fault the deployment"
    );
    println!("fraud: settlement is hard-faulted, so the fraudulent operator is fenced");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        REFRESH_BUDGET, UiState, handle_hard_fault_recovery, handle_pending_deposit_recovery,
        refresh, refresh_bounded,
    };
    use crate::{
        agent::Agent,
        operator::rpc as operator_rpc,
        rpc,
        settlement::{Settlement, rpc as settlement_rpc},
    };
    use bytes::Bytes;
    use commonware_codec::Encode as _;
    use commonware_runtime::{
        Clock as _, Listener as _, Network as _, Runner as _, Spawner as _, Supervisor as _,
        deterministic,
    };
    use std::net::SocketAddr;

    #[test]
    fn hung_operator_refresh_degrades_within_its_budget() {
        deterministic::Runner::default().start(|context| async move {
            // Bound but never accepted: dials succeed and the RPC then hangs forever, the
            // same stall shape as a SYN-dropping operator behind a connect timeout.
            let operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let settlement_address = SocketAddr::from(([127, 0, 0, 1], 2));

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
            state.settlement = Some(settlement_rpc::StatusResponse::from(
                Settlement::new().unwrap().status().unwrap(),
            ));
            state.balance = Some(7);

            let started = context.current();
            refresh_bounded(
                &context,
                operator_address,
                settlement_address,
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
        });
    }

    #[test]
    fn unavailable_operator_keeps_settlement_visible_and_recovery_reachable() {
        deterministic::Runner::default().start(|context| async move {
            let mut settlement = Settlement::new().unwrap();
            let expected = settlement_rpc::StatusResponse::from(settlement.status().unwrap());
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let settlement_address = listener.local_addr().unwrap();
            let server = context.child("settlement").spawn(move |_| async move {
                for expected_method in [
                    settlement_rpc::METHOD_STATUS,
                    settlement_rpc::METHOD_BEGIN_HARD_FAULT_SETTLEMENT,
                    settlement_rpc::METHOD_CLAIM_PENDING_DEPOSIT,
                ] {
                    let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert_eq!(request.method, expected_method);
                    let response = match expected_method {
                        settlement_rpc::METHOD_STATUS => rpc::Response::Success {
                            body: expected.encode(),
                        },
                        settlement_rpc::METHOD_BEGIN_HARD_FAULT_SETTLEMENT => {
                            rpc::Response::Error {
                                error: Bytes::from_static(b"recovery key reached settlement"),
                            }
                        }
                        settlement_rpc::METHOD_CLAIM_PENDING_DEPOSIT => rpc::Response::Error {
                            error: Bytes::from_static(b"refund key reached settlement"),
                        },
                        _ => unreachable!(),
                    };
                    rpc::send_response(&mut sink, &response).await.unwrap();
                }
            });

            let operator_address = SocketAddr::from(([127, 0, 0, 1], 1));
            let mut agent = Agent::new(0).unwrap();
            let mut state = UiState::new();
            state.pending_closes.push_back(7);

            refresh(
                &context,
                operator_address,
                settlement_address,
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
            assert_eq!(state.settlement.unwrap(), expected);

            handle_hard_fault_recovery(&context, settlement_address, &agent, &mut state).await;
            assert!(
                state
                    .activity
                    .back()
                    .unwrap()
                    .contains("recovery key reached settlement")
            );
            handle_pending_deposit_recovery(&context, settlement_address, &agent, &mut state).await;
            assert!(
                state
                    .activity
                    .back()
                    .unwrap()
                    .contains("refund key reached settlement")
            );
            server.await.unwrap();
        });
    }
}
