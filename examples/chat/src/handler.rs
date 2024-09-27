use commonware_cryptography::utils::hex;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{select, Spawner};
use crossterm::{
    event::{self, Event as CEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::{channel::mpsc, SinkExt, StreamExt};
use prometheus_client::{encoding::text::encode, registry::Registry};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Text},
    widgets::{Block, Borders, Paragraph},
    Terminal,
};
use std::{
    io::stdout,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::{debug, warn};

pub const CHANNEL: u32 = 0;

enum Event<I> {
    Input(I),
    Tick,
}

pub async fn run(
    runtime: impl Spawner,
    me: String,
    runtime_registry: Arc<Mutex<Registry>>,
    p2p_registry: Arc<Mutex<Registry>>,
    logs: Arc<Mutex<Vec<String>>>,
    mut sender: impl Sender,
    mut receiver: impl Receiver,
) {
    // Setup terminal
    enable_raw_mode().unwrap();
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();

    // Listen for input
    let (mut tx, mut rx) = mpsc::channel(100);
    runtime.spawn("inputter", async move {
        loop {
            match event::poll(Duration::from_millis(500)) {
                Ok(true) => {}
                Ok(false) => {
                    if tx.send(Event::Tick).await.is_err() {
                        break;
                    }
                    continue;
                }
                Err(_) => break,
            };
            let e = match event::read() {
                Ok(e) => e,
                Err(_) => break,
            };
            if let CEvent::Key(key) = e {
                if tx.send(Event::Input(key)).await.is_err() {
                    break;
                }
            }
        }
    });

    // Application state
    let mut messages = Vec::new();
    let mut input = String::new();
    let mut cursor_visible = true;

    // Print messages received from peers
    loop {
        // Draw UI
        terminal
            .draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Percentage(70), Constraint::Percentage(30)].as_ref())
                    .split(f.size());
                let horizontal_chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                    .split(chunks[0]);
                let messages_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Percentage(80), Constraint::Percentage(20)].as_ref())
                    .split(horizontal_chunks[0]);

                // Display messages
                let messages_text = Text::from(messages.clone());
                let messages_block = Paragraph::new(messages_text)
                    .style(Style::default().fg(Color::Cyan))
                    .block(Block::default().borders(Borders::ALL).title("Messages"));
                f.render_widget(messages_block, messages_chunks[0]);

                // Display metrics
                let mut buffer = String::new();
                {
                    let registry = runtime_registry.lock().unwrap();
                    encode(&mut buffer, &registry).unwrap();
                }
                {
                    let registry = p2p_registry.lock().unwrap();
                    encode(&mut buffer, &registry).unwrap();
                }
                let metrics_text = Text::from(buffer);
                let metrics_block = Paragraph::new(metrics_text)
                    .block(Block::default().borders(Borders::ALL).title("Metrics"));
                f.render_widget(metrics_block, horizontal_chunks[1]);

                // Display input
                //
                // Show or hide the cursor in the input block
                let input_with_cursor = if cursor_visible {
                    format!("> {}_", input)
                } else {
                    format!("> {}", input.clone())
                };
                let input_block = Paragraph::new(input_with_cursor)
                    .style(Style::default().fg(Color::Yellow))
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("Input (ESC to quit | ENTER to send)"),
                    );
                f.render_widget(input_block, messages_chunks[1]);

                // Display logs
                let logs = logs.lock().unwrap();
                let logs_text = Text::from(
                    logs.iter()
                        .map(|log| Line::raw(log.clone()))
                        .collect::<Vec<Line>>(),
                );
                let logs_block = Paragraph::new(logs_text)
                    .block(Block::default().borders(Borders::ALL).title("Logs"));
                f.render_widget(logs_block, chunks[1]);
            })
            .unwrap();

        // Handle input
        let formatted_me = format!("{}**{}", &me[..4], &me[me.len() - 4..]);
        select! {
            event = rx.next() => {
                let event = match event {
                    Some(event) => event,
                    None => break,
                };
                match event {
                    Event::Input(event) => match event.code {
                        KeyCode::Char(c) => {
                            input.push(c);
                        }
                        KeyCode::Backspace => {
                            input.pop();
                        }
                        KeyCode::Enter => {
                            if input.is_empty() {
                                continue;
                            }
                            let mut successful = sender
                                .send(Recipients::All, input.clone().into_bytes().into(), false)
                                .await
                                .expect("failed to send message");
                            if !successful.is_empty() {
                                successful.sort();
                                let mut friends = String::from_str("[").unwrap();
                                for friend in successful {
                                    friends.push_str(&format!("{},", hex(&friend)));
                                }
                                friends.pop();
                                friends.push(']');
                                debug!(friends, input, "sent message");
                            } else {
                                warn!(input, "dropped message");
                            }
                            let msg = Line::styled(format!(
                                "[{}] {}: {}",
                                chrono::Local::now().format("%m/%d %H:%M:%S"),
                                formatted_me,
                                input,
                            ), Style::default().fg(Color::Yellow));
                            messages.insert(0, msg);
                            input = String::new();
                        }
                        KeyCode::Esc => {
                            disable_raw_mode().unwrap();
                            execute!(terminal.backend_mut(), LeaveAlternateScreen).unwrap();
                            terminal.show_cursor().unwrap();
                            break;
                        }
                        _ => {}
                    },
                    Event::Tick => {
                        cursor_visible = !cursor_visible;
                    }
                }
            },
            result = receiver.recv() => {
                match result {
                    Ok((peer, msg)) => {
                        let peer = hex(&peer);
                        messages.insert(0, format!(
                            "[{}] {}**{}: {}",
                            chrono::Local::now().format("%m/%d %H:%M:%S"),
                            &peer[..4],
                            &peer[peer.len() - 4..],
                            String::from_utf8_lossy(&msg)
                        ).into());
                    }
                    Err(err) => {
                        debug!(?err, "failed to receive message");
                        continue;
                    }
                }
            }
        };
    }
}
