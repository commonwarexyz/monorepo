//! Ratatui presentation for one independently owned agent wallet.

use crate::{
    agent::{Agent, DepositOutcome, WithdrawalOutcome},
    operator::DEFAULT_AMOUNT,
    operator_rpc::{PollCloseResponse, StatusResponse as OperatorStatus},
    settlement_rpc::StatusResponse as SettlementStatus,
};
use anyhow::{Context, Result};
use commonware_clearing::bajillion::boundary::WithdrawalAction;
use commonware_runtime::Network;
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
    recipient: usize,
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
            recipient: 1,
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

pub(crate) async fn run<E: Network>(
    network: &E,
    operator: SocketAddr,
    settlement: SocketAddr,
    mut agent: Agent,
) -> Result<()> {
    let mut terminal = TerminalSession::enter()?;
    let mut state = UiState::new();
    state.recipient = agent.default_recipient();
    loop {
        refresh(network, operator, settlement, &agent, &mut state).await?;
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
            KeyCode::Left => state.recipient = state.recipient.saturating_sub(1),
            KeyCode::Right => {
                state.recipient = (state.recipient + 1) % agent.recipient_count();
            }
            KeyCode::Char('-') => state.amount = state.amount.saturating_sub(1).max(1),
            KeyCode::Char('+') | KeyCode::Char('=') => {
                state.amount = state.amount.saturating_add(1);
            }
            KeyCode::PageDown => state.amount = state.amount.saturating_sub(10).max(1),
            KeyCode::PageUp => state.amount = state.amount.saturating_add(10),
            KeyCode::Char('p') => {
                let recipient = agent.recipient_name(state.recipient);
                match agent
                    .pay(network, settlement, operator, &[(state.recipient, state.amount)])
                    .await
                {
                    Ok(payment) => state.log(format!(
                        "epoch {} payment #{} to {recipient}: {}",
                        payment.epoch, payment.sequence, payment.total
                    )),
                    Err(error) => state.log(format!("payment rejected: {error:#}")),
                }
            }
            KeyCode::Char('a') => {
                if state
                    .staged
                    .iter()
                    .any(|(recipient, _)| *recipient == state.recipient)
                {
                    state.log(format!(
                        "{} is already staged; batch entries name unique recipients",
                        agent.recipient_name(state.recipient)
                    ));
                } else {
                    state.staged.push((state.recipient, state.amount));
                    state.log(format!(
                        "staged {} to {}; press b to send the batch",
                        state.amount,
                        agent.recipient_name(state.recipient)
                    ));
                }
            }
            KeyCode::Char('b') => {
                if state.staged.is_empty() {
                    state.log("no staged entries; press a to stage the selected payment");
                } else {
                    match agent.pay(network, settlement, operator, &state.staged).await {
                        Ok(payment) => {
                            state.log(format!(
                                "epoch {} batch #{} paid {} across {} recipients",
                                payment.epoch,
                                payment.sequence,
                                payment.total,
                                payment.acceptance.receipts.len()
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
                Ok(DepositOutcome::Applied { epoch, event }) => state.log(format!(
                    "epoch {} deposit credited: {}",
                    epoch, event.amount
                )),
                Ok(DepositOutcome::Recorded {
                    event,
                    error,
                }) => state.log(format!(
                    "settlement custody recorded for {}; operator credit unknown; retry uses the same deposit: {error:#}",
                    event.amount
                )),
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
                            "epoch {} withdrawal carried by operator: {}",
                            epoch, amount
                        )),
                        WithdrawalAction::Close => state.log(format!(
                            "epoch {} Close carried by operator; payout is finalized at epoch close",
                            epoch
                        )),
                    },
                    Ok(WithdrawalOutcome::Signed {
                        request,
                        error,
                    }) => state.log(format!(
                        "withdrawal signed through deadline {}; operator carriage unknown; retry uses the same signed request: {error:#}",
                        request.body().deadline()
                    )),
                    Err(error) => state.log(format!("withdrawal not confirmed: {error:#}")),
                }
            }
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

async fn refresh<E: Network>(
    network: &E,
    operator: SocketAddr,
    settlement: SocketAddr,
    agent: &Agent,
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
    state.balance = agent.balance(network, operator).await.ok();
    Ok(())
}

fn render(frame: &mut Frame<'_>, agent: &Agent, state: &UiState) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(7),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let title = Paragraph::new(Line::from(vec![
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
    ]))
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
            .map(|(recipient, amount)| format!("{} {amount}", agent.recipient_name(*recipient)))
            .collect::<Vec<_>>()
            .join(", ");
        format!("Batch: {entries}")
    };
    let controls = Paragraph::new(vec![
        Line::raw(operator),
        Line::raw(settlement),
        Line::raw(format!(
            "Recipient: {} | amount {}",
            agent.recipient_name(state.recipient),
            state.amount
        )),
        Line::raw(staged),
        Line::raw(
            "p pay  a stage  b pay batch  d deposit  r refund deposit  w withdraw  f Close  c claim  e payout  h recover state  s cut epoch",
        ),
        Line::raw("Left/Right recipient  +/- amount  PgUp/PgDn +/-10"),
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
    let payment = agent.pay(network, settlement, operator, &[(1, 5)]).await?;
    println!(
        "epoch {} accepted payment #{}",
        payment.epoch, payment.sequence
    );
    let batch = agent
        .pay(network, settlement, operator, &[(2, 2), (3, 1)])
        .await?;
    println!(
        "epoch {} accepted batch #{} paying {} across {} recipients",
        batch.epoch,
        batch.sequence,
        batch.total,
        batch.acceptance.receipts.len()
    );
    let external = agent
        .pay(
            network,
            settlement,
            operator,
            &[(agent.recipient_count() - 1, 2)],
        )
        .await?;
    println!(
        "epoch {} accepted external payment #{}",
        external.epoch, external.sequence
    );
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
    let successor = agent.pay(network, settlement, operator, &[(1, 1)]).await?;
    println!(
        "epoch {} accepted successor payment #{} after epoch {} finalized",
        successor.epoch, successor.sequence, close.epoch
    );
    let release = agent
        .claim_withdrawal(network, settlement, operator)
        .await?;
    println!("claimed withdrawal {}", release.amount);
    let mut external = Agent::new(4)?;
    let payout = external
        .claim_external_payout(network, settlement, operator)
        .await?;
    println!("claimed external payout {}", payout.amount);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{UiState, handle_hard_fault_recovery, handle_pending_deposit_recovery, refresh};
    use crate::{agent::Agent, rpc, settlement::Settlement, settlement_rpc};
    use bytes::Bytes;
    use commonware_codec::Encode as _;
    use commonware_runtime::{
        Listener as _, Network as _, Runner as _, Spawner as _, Supervisor as _, deterministic,
    };
    use std::net::SocketAddr;

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
            let agent = Agent::new(0).unwrap();
            let mut state = UiState::new();
            state.pending_closes.push_back(7);

            refresh(
                &context,
                operator_address,
                settlement_address,
                &agent,
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
