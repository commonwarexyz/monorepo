use commonware_runtime::Spawner;
use crossterm::{
    event::{self, Event as CEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::{channel::mpsc, SinkExt, StreamExt};
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
use tracing_subscriber::fmt::MakeWriter;

const HEIGHT_OFFSET: u16 = 2;

#[derive(PartialEq, Eq)]
enum Focus {
    Progress,
    Logs,
}

enum Event<I> {
    Input(I),
    Tick,
}

/// Appends logs to a provided vector.
pub struct Writer {
    progress: Arc<Mutex<Vec<String>>>,
    logs: Arc<Mutex<Vec<String>>>,
}

impl Writer {
    /// Creates a new `Writer` instance.
    pub fn new(progress: Arc<Mutex<Vec<String>>>, logs: Arc<Mutex<Vec<String>>>) -> Self {
        Self { progress, logs }
    }

    /// Adds fields that weren't previously handled to the log message.
    fn add_to_log_message(key: &str, value: &serde_json::Value, log_message: &mut String) {
        if let serde_json::Value::Object(map) = value {
            for (key, value) in map {
                Self::add_to_log_message(key, value, log_message);
            }
        } else if !key.is_empty()
            && key != "level"
            && key != "timestamp"
            && key != "target"
            && key != "message"
        {
            log_message.push_str(&format!("{}={} ", key, value));
        }
    }
}

impl std::io::Write for Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Process JSON
        let json_str = String::from_utf8_lossy(buf);
        let json: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Create log message
        let level = json["level"].as_str().unwrap();
        let timestamp = json["timestamp"].as_str().unwrap();
        let target = json["target"].as_str().unwrap();
        let msg = json["fields"]["message"].as_str().unwrap();
        let mut log_message = format!(
            "[{}|{}] {} => {} (",
            chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.6fZ")
                .unwrap()
                .format("%m/%d %H:%M:%S"),
            level,
            target,
            msg,
        );

        // Add remaining fields
        Self::add_to_log_message("", &json, &mut log_message);
        let log_message = format!("{})", log_message.trim_end());

        // Cleanup empty logs
        let log_message = log_message.replace("()", "");

        // Append log message
        let mut logs = self.logs.lock().unwrap();
        logs.push(log_message.trim_end().to_string());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Writer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        Writer {
            progress: Arc::clone(&self.progress),
            logs: Arc::clone(&self.logs),
        }
    }
}

pub struct GUI {
    progress: Arc<Mutex<Vec<String>>>,
    logs: Arc<Mutex<Vec<String>>>,
}

impl GUI {
    pub fn new() -> Self {
        // Create writer
        let progress = Arc::new(Mutex::new(Vec::new()));
        let logs = Arc::new(Mutex::new(Vec::new()));
        let writer = Writer::new(progress.clone(), logs.clone());

        // Register writer
        tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(writer)
            .init();
        Self { progress, logs }
    }

    pub async fn run<R: Spawner>(
        runtime: R,
        progress: Arc<Mutex<Vec<String>>>,
        logs: Arc<Mutex<Vec<String>>>,
    ) {
        // Setup terminal
        enable_raw_mode().unwrap();
        let mut stdout = stdout();
        execute!(stdout, EnterAlternateScreen).unwrap();
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend).unwrap();

        // Listen for input
        let (mut tx, mut rx) = mpsc::channel(100);
        runtime.spawn("keyboard", async move {
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
        let mut cursor_visible = true;
        let mut progress_scroll_vertical: u16 = 0;
        let mut progress_scroll_horizontal: u16 = 0;
        let mut logs_scroll_vertical: u16 = 0;
        let mut logs_scroll_horizontal: u16 = 0;
        let mut focused_window = Focus::Progress;

        // Print progress
        loop {
            // Draw UI
            terminal
                .draw(|f| {
                    let chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints(
                            [Constraint::Percentage(70), Constraint::Percentage(30)].as_ref(),
                        )
                        .split(f.size());
                    let horizontal_chunks = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints(
                            [Constraint::Percentage(50), Constraint::Percentage(50)].as_ref(),
                        )
                        .split(chunks[0]);
                    let messages_chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints(
                            [Constraint::Percentage(80), Constraint::Percentage(20)].as_ref(),
                        )
                        .split(horizontal_chunks[0]);

                    // Display messages
                    let messages_height = messages_chunks[0].height - HEIGHT_OFFSET;
                    let messages_len = messages.len() as u16;
                    let messages_max_scroll = messages_len.saturating_sub(messages_height);
                    if focused_window != Focus::Messages {
                        messages_scroll_vertical = messages_max_scroll;
                    }
                    let messages_text = Text::from(messages.clone());
                    let messages_block = Paragraph::new(messages_text)
                        .style(Style::default().fg(Color::Cyan))
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Messages")
                                .border_style(match focused_window {
                                    Focus::Messages => Style::default().fg(Color::Red),
                                    _ => Style::default(),
                                }),
                        )
                        .scroll((messages_scroll_vertical, messages_scroll_horizontal));
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
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Metrics")
                                .border_style(match focused_window {
                                    Focus::Metrics => Style::default().fg(Color::Red),
                                    _ => Style::default(),
                                }),
                        )
                        .scroll((metrics_scroll_vertical, metrics_scroll_horizontal));

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
                                .title("Input (TAB to switch panes | ESC to quit | ENTER to send)")
                                .border_style(match focused_window {
                                    Focus::Input => Style::default().fg(Color::Red),
                                    _ => Style::default(),
                                }),
                        );
                    f.render_widget(input_block, messages_chunks[1]);

                    // Display logs
                    let logs_height = chunks[1].height - HEIGHT_OFFSET;
                    let logs = logs.lock().unwrap();
                    let logs_len = logs.len() as u16;
                    let logs_max_scroll = logs_len.saturating_sub(logs_height);
                    if focused_window != Focus::Logs {
                        logs_scroll_vertical = logs_max_scroll;
                    }
                    let logs_text = Text::from(
                        logs.iter()
                            .map(|log| Line::raw(log.clone()))
                            .collect::<Vec<Line>>(),
                    );
                    let logs_block = Paragraph::new(logs_text)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Logs")
                                .border_style(match focused_window {
                                    Focus::Logs => Style::default().fg(Color::Red),
                                    _ => Style::default(),
                                }),
                        )
                        .scroll((logs_scroll_vertical, logs_scroll_horizontal));
                    f.render_widget(logs_block, chunks[1]);
                })
                .unwrap();

            // Handle input
            let event = rx.next().await;
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
                    KeyCode::Tab => {
                        focused_window = match focused_window {
                            Focus::Input => Focus::Logs,
                            Focus::Logs => Focus::Metrics,
                            Focus::Metrics => Focus::Messages,
                            Focus::Messages => Focus::Input,
                        };
                    }
                    KeyCode::Up => match focused_window {
                        Focus::Logs => {
                            logs_scroll_vertical = logs_scroll_vertical.saturating_sub(1)
                        }
                        Focus::Metrics => {
                            metrics_scroll_vertical = metrics_scroll_vertical.saturating_sub(1)
                        }
                        Focus::Messages => {
                            messages_scroll_vertical = messages_scroll_vertical.saturating_sub(1)
                        }
                        _ => {}
                    },
                    KeyCode::Down => match focused_window {
                        Focus::Logs => {
                            logs_scroll_vertical = logs_scroll_vertical.saturating_add(1)
                        }
                        Focus::Metrics => {
                            metrics_scroll_vertical = metrics_scroll_vertical.saturating_add(1)
                        }
                        Focus::Messages => {
                            messages_scroll_vertical = messages_scroll_vertical.saturating_add(1)
                        }
                        _ => {}
                    },
                    KeyCode::Left => match focused_window {
                        Focus::Logs => {
                            logs_scroll_horizontal = logs_scroll_horizontal.saturating_sub(1)
                        }
                        Focus::Metrics => {
                            metrics_scroll_horizontal = metrics_scroll_horizontal.saturating_sub(1)
                        }
                        Focus::Messages => {
                            messages_scroll_horizontal =
                                messages_scroll_horizontal.saturating_sub(1)
                        }
                        _ => {}
                    },
                    KeyCode::Right => match focused_window {
                        Focus::Logs => {
                            logs_scroll_horizontal = logs_scroll_horizontal.saturating_add(1)
                        }
                        Focus::Metrics => {
                            metrics_scroll_horizontal = metrics_scroll_horizontal.saturating_add(1)
                        }
                        Focus::Messages => {
                            messages_scroll_horizontal =
                                messages_scroll_horizontal.saturating_add(1)
                        }
                        _ => {}
                    },
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
                        let msg = Line::styled(
                            format!(
                                "[{}] {}: {}",
                                chrono::Local::now().format("%m/%d %H:%M:%S"),
                                formatted_me,
                                input,
                            ),
                            Style::default().fg(Color::Yellow),
                        );
                        messages.push(msg);
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
        }
    }
}
