//! Wallet dashboard with persistent controls and space for recent activity.

use super::{OperatorState, UiState};
use crate::agent::Agent;
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Padding, Paragraph, Wrap},
};

const ACCENT: Color = Color::Cyan;
const DRAFT_ACCENT: Color = Color::Green;

pub(super) fn render(frame: &mut Frame<'_>, agent: &Agent, state: &UiState) {
    let area = frame.area();
    let operator_status = match state.operator {
        OperatorState::Checking => "CHECKING",
        OperatorState::Available(status) if status.faulted => "FENCED",
        OperatorState::Available(_) => "ONLINE",
        OperatorState::Unavailable => "UNAVAILABLE",
    };
    let settlement_status = state.settlement.as_ref().map_or("UNAVAILABLE", |status| {
        if status.hard_faulted {
            "HARD FAULT"
        } else {
            "ONLINE"
        }
    });
    let balances = format!(
        "With operator {}  |  Onchain {}",
        amount(state.balance),
        amount(state.native_balance)
    );

    if area.width < 80 || area.height < 24 {
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled("Resize to 80 x 24", emphasis(ACCENT)),
                Line::raw("q / Esc quit"),
                Line::styled(
                    format!("Operator: {operator_status}"),
                    status_style(operator_status),
                ),
                Line::styled(
                    format!("Settlement: {settlement_status}"),
                    status_style(settlement_status),
                ),
                Line::raw(format!("{} wallet", agent.name())),
                Line::raw(balances),
            ])
            .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let sections = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(5),
        Constraint::Min(3),
        Constraint::Length(7),
        Constraint::Length(3),
    ])
    .split(area);

    let incoming = agent.incoming();
    let reconciled = agent
        .last_reconciled_epoch()
        .map_or_else(|| "none".to_string(), |epoch| epoch.to_string());
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(balances, emphasis(Color::White)),
            Line::raw(format!(
                "Sent receipts {}  |  Verified incoming {}  |  Checked epoch {reconciled}",
                agent.receipt_count(),
                incoming.total
            )),
        ])
        .block(panel(format!(
            " BAJILLION / {} wallet - payer signs locally ",
            agent.name()
        ))),
        sections[0],
    );

    let roles = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(sections[1]);
    let operator = match state.operator {
        OperatorState::Checking => {
            vec![
                Line::raw("Waiting for operator status"),
                Line::raw("Issues payment receipts"),
            ]
        }
        OperatorState::Unavailable => {
            vec![
                Line::raw("Operator status unavailable"),
                Line::raw("Issues payment receipts"),
            ]
        }
        OperatorState::Available(status) => {
            vec![
                Line::raw(format!(
                    "Epoch {} | {} recent payments",
                    status.epoch, status.recent_payments
                )),
                Line::raw(format!(
                    "Live accounts {}/{}",
                    status.present_accounts, status.accounts
                )),
                Line::raw(format!(
                    "Close {} | {} pending",
                    if status.close_in_progress {
                        "active"
                    } else {
                        "idle"
                    },
                    state.pending_closes.len()
                )),
            ]
        }
    };
    frame.render_widget(
        Paragraph::new(operator).block(
            panel(format!(" Operator / receipts - {operator_status} "))
                .border_style(status_style(operator_status)),
        ),
        roles[0],
    );

    let settlement = state.settlement.as_ref().map_or_else(
        || {
            vec![
                Line::raw("Waiting for certified chain status"),
                Line::raw("Owns custody and withdrawal claims"),
            ]
        },
        |status| {
            vec![
                Line::raw(format!("Custody {}", status.custody)),
                Line::raw(format!("Claimable {}", status.claimable)),
                Line::raw(format!(
                    "Height {} | finalized {}",
                    status.height,
                    status
                        .last_finalized
                        .map_or_else(|| "none".to_string(), |epoch| epoch.to_string())
                )),
            ]
        },
    );
    frame.render_widget(
        Paragraph::new(settlement).block(
            panel(format!(" Settlement / custody - {settlement_status} "))
                .border_style(status_style(settlement_status)),
        ),
        roles[1],
    );

    frame.render_widget(
        Paragraph::new(
            state
                .activity
                .iter()
                .rev()
                .map(|message| {
                    let alert = message.contains("ALARM")
                        || message.contains("HARD FAULT")
                        || message.contains("rejected")
                        || message.contains("failed")
                        || message.contains("unconfirmed")
                        || message.contains("not sent");
                    Line::styled(
                        format!("> {message}"),
                        Style::default().fg(if alert { Color::Yellow } else { Color::White }),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .wrap(Wrap { trim: true })
        .block(panel(" Activity / newest first ")),
        sections[2],
    );

    let staged = if state.staged.is_empty() {
        "Batch empty - add payments with a".to_string()
    } else {
        format!(
            "Batch: {}",
            state
                .staged
                .iter()
                .map(|(receiver, amount)| format!("{} {amount}", agent.receiver_name(*receiver)))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let total: u128 = state
        .staged
        .iter()
        .map(|(_, amount)| u128::from(*amount))
        .sum();
    let mut draft = panel(" Payment draft ")
        .border_type(BorderType::Rounded)
        .border_style(emphasis(DRAFT_ACCENT))
        .padding(Padding::horizontal(1))
        .style(Style::default().fg(Color::White).bg(Color::Rgb(17, 35, 30)));
    if agent.has_pending_payment() {
        draft = draft.title_bottom(Line::styled(
            " Saved payment awaiting confirmation - R retries that request ",
            emphasis(Color::Yellow),
        ));
    }
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                format!(
                    "{} -> {}  |  Amount {}",
                    agent.name(),
                    agent.receiver_name(state.receiver),
                    state.amount
                ),
                emphasis(Color::White),
            ),
            Line::styled(
                "Left/Right recipient  +/- or = amount  PgUp/PgDn +/-10",
                Style::default().fg(Color::Gray),
            ),
            Line::from(vec![
                Span::styled("p", emphasis(DRAFT_ACCENT)),
                Span::raw(" send this payment    "),
                Span::styled("a", emphasis(DRAFT_ACCENT)),
                Span::raw(" add to batch"),
            ]),
            Line::raw(staged),
            Line::from(vec![
                Span::styled("b", emphasis(DRAFT_ACCENT)),
                Span::raw(format!(" send batch ({total} total)    ")),
                Span::styled("R", emphasis(DRAFT_ACCENT)),
                Span::raw(" retry saved payment"),
            ]),
        ])
        .block(draft),
        sections[3],
    );

    frame.render_widget(
        Paragraph::new(vec![
            help("Funds   ", "d deposit  t fund operator  r refund deposit"),
            help(
                "Withdraw",
                "w withdraw  f Close account  x escalate  c claim withdrawal",
            ),
            help("Network ", "s cut epoch  h recover state  q / Esc quit"),
        ]),
        sections[4],
    );
}

fn amount(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown".to_string(), |value| value.to_string())
}

fn emphasis(color: Color) -> Style {
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

fn status_style(status: &str) -> Style {
    emphasis(match status {
        "FENCED" | "HARD FAULT" => Color::Red,
        "CHECKING" | "UNAVAILABLE" => Color::Yellow,
        _ => ACCENT,
    })
}

fn panel<'a>(title: impl Into<Line<'a>>) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(title)
}

fn help(group: &'static str, keys: &'static str) -> Line<'static> {
    Line::from(vec![
        Span::styled(group, emphasis(ACCENT)),
        Span::raw("  "),
        Span::raw(keys),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chain::state::StatusRecord, operator::rpc::StatusResponse, protocol::deployment};
    use commonware_clearing::bajillion::qmdb::StateRoot;
    use commonware_cryptography::{Hasher as _, Sha256};
    use ratatui::{Terminal, backend::TestBackend};

    fn draw(width: u16, height: u16, state: &UiState) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let agent = Agent::new(0).unwrap();
        terminal.draw(|frame| render(frame, &agent, state)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(usize::from(width).max(1))
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn compact_and_large_dashboards_keep_actions_and_wallet_values_visible() {
        let mut state = UiState::new();
        state.balance = Some(321);
        state.native_balance = Some(654);
        state.amount = 17;
        state.staged.push((1, 17));
        state.staged.push((2, 3));
        state.log("Payment confirmed: 17 to Bob");
        for (width, height) in [(80, 24), (120, 35)] {
            let output = draw(width, height, &state);
            for expected in [
                "Alice wallet",
                "With operator 321",
                "Onchain 654",
                "Verified incoming 0",
                "Alice -> Bob",
                "Amount 17",
                "Batch: Bob 17, Carol 3",
                "Payment confirmed: 17 to Bob",
                "p send this payment",
                "R retry saved payment",
                "a add to batch",
                "b send batch (20 total)",
                "d deposit",
                "t fund operator",
                "r refund deposit",
                "w withdraw",
                "f Close account",
                "x escalate",
                "c claim withdrawal",
                "s cut epoch",
                "h recover state",
                "q / Esc quit",
                "Left/Right recipient",
                "+/- or = amount",
                "PgUp/PgDn +/-10",
            ] {
                assert!(
                    output.contains(expected),
                    "missing {expected:?} at {width}x{height}:\n{output}"
                );
            }
            assert!(output.find("Activity /").unwrap() < output.find("Payment draft").unwrap());
        }
    }

    #[test]
    fn checking_unavailable_and_faulted_roles_are_distinct() {
        let mut state = UiState::new();
        for (width, height) in [(80, 24), (120, 35)] {
            let output = draw(width, height, &state);
            assert!(output.contains("With operator unknown"), "{output}");
            assert!(output.contains("Onchain unknown"), "{output}");
            assert!(
                output.contains("Operator / receipts - CHECKING"),
                "{output}"
            );
            assert!(
                output.contains("Settlement / custody - UNAVAILABLE"),
                "{output}"
            );
        }
        state.operator = OperatorState::Unavailable;
        let unavailable = draw(80, 24, &state);
        assert!(
            unavailable.contains("Operator / receipts - UNAVAILABLE"),
            "{unavailable}"
        );
        assert!(
            unavailable.contains("Operator status unavailable"),
            "{unavailable}"
        );
        state.balance = Some(0);
        state.native_balance = Some(u64::MAX);
        state.operator = OperatorState::Available(StatusResponse {
            epoch: 7,
            accounts: 4,
            present_accounts: 3,
            recent_payments: 12,
            close_in_progress: true,
            faulted: true,
        });
        state.settlement = Some(StatusRecord {
            height: 42,
            timestamp: 1,
            deployment: deployment(),
            state_root: StateRoot {
                digest: Sha256::hash(&[b"dashboard"]),
            },
            last_finalized: Some(6),
            custody: u64::MAX,
            claimable: 0,
            hard_faulted: true,
        });
        state.log("ALARM: retained credit cannot be enforced");
        let compact = draw(79, 24, &state);
        assert!(compact.contains("Operator: FENCED"), "{compact}");
        assert!(compact.contains("Settlement: HARD FAULT"), "{compact}");
        for (width, height) in [(80, 24), (120, 35)] {
            let output = draw(width, height, &state);
            for expected in [
                "With operator 0",
                "Onchain 18446744073709551615",
                "FENCED",
                "HARD FAULT",
                "Epoch 7",
                "12 recent payments",
                "Live accounts 3/4",
                "Close active",
                "Custody 18446744073709551615",
                "Claimable 0",
                "Height 42 | finalized 6",
                "ALARM: retained credit cannot be enforced",
            ] {
                assert!(output.contains(expected), "missing {expected:?}:\n{output}");
            }
        }
    }

    #[test]
    fn activity_wraps_and_keeps_the_newest_message_first() {
        let mut state = UiState::new();
        state.activity.clear();
        state.log("Older event");
        state.log("A payment remains awaiting confirmation while the operator is unavailable; press R to retry the saved request.");
        let output = draw(80, 24, &state);
        assert!(
            output.contains("press R to retry the saved request."),
            "{output}"
        );
        assert!(output.find("A payment remains").unwrap() < output.find("Older event").unwrap());
    }

    #[test]
    fn tiny_terminals_offer_resize_guidance_without_panicking() {
        let state = UiState::new();
        for (width, height) in [(0, 0), (1, 1), (20, 4), (79, 24), (80, 23)] {
            let output = draw(width, height, &state);
            if width >= 20 && height >= 4 {
                assert!(output.contains("Resize to 80 x 24"), "{output}");
                assert!(output.contains("q / Esc quit"), "{output}");
            }
        }
    }
}
