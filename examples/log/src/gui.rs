//! Logic that drives the terminal UI.
//!
//! This code has nothing to do with the application or consensus and was
//! implemented to make consensus logging easier to follow.

use commonware_runtime::{Metrics, Spawner};
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

/// Appends logs to provided vectors.
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

        // Create message
        let timestamp = json["timestamp"].as_str().unwrap();
        let target = json["target"].as_str().unwrap();
        let msg = json["fields"]["message"].as_str().unwrap();
        let (progress, mut formatted_msg) = if target.contains("commonware_log::application") {
            (
                true,
                format!(
                    "[{}] => {} (",
                    chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.6fZ")
                        .unwrap()
                        .format("%m/%d %H:%M:%S"),
                    msg,
                ),
            )
        } else {
            let level = json["level"].as_str().unwrap();
            (
                false,
                format!(
                    "[{}|{}] {} => {} (",
                    chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.6fZ")
                        .unwrap()
                        .format("%m/%d %H:%M:%S"),
                    level,
                    target,
                    msg,
                ),
            )
        };

        // Add remaining fields
        Self::add_to_log_message("", &json, &mut formatted_msg);
        let formatted_msg = format!("{})", formatted_msg.trim_end());

        // Cleanup empty logs
        let formatted_msg = formatted_msg.replace("()", "");

        // Append progress message
        if progress {
            let mut progress = self.progress.lock().unwrap();
            progress.push(formatted_msg);
        } else {
            let mut logs = self.logs.lock().unwrap();
            logs.push(formatted_msg);
        }
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

pub struct Gui<E: Spawner + Metrics> {
    context: E,
    progress: Arc<Mutex<Vec<String>>>,
    logs: Arc<Mutex<Vec<String>>>,
}

impl<E: Spawner + Metrics> Gui<E> {
    pub fn new(context: E) -> Self {
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
        Self {
            context,
            progress,
            logs,
        }
    }

    pub async fn run(self) {
        // Setup terminal
        enable_raw_mode().unwrap();
        let mut stdout = stdout();
        execute!(stdout, EnterAlternateScreen).unwrap();
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend).unwrap();

        // Listen for input
        let (mut tx, mut rx) = mpsc::channel(100);
        self.context.with_label("keyboard").spawn(|_| async move {
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
                            [Constraint::Percentage(60), Constraint::Percentage(40)].as_ref(),
                        )
                        .split(f.size());

                    // Display progress
                    let progress_height = chunks[0].height - HEIGHT_OFFSET;
                    let progress = self.progress.lock().unwrap();
                    let progress_len = progress.len() as u16;
                    let progress_max_scroll = progress_len.saturating_sub(progress_height);
                    if focused_window != Focus::Logs {
                        progress_scroll_vertical = progress_max_scroll;
                    }
                    let progress_text = Text::from(
                        progress
                            .iter()
                            .map(|p| {
                                if p.contains("proposed") {
                                    Line::styled(p.clone(), Style::default().fg(Color::Blue))
                                } else if p.contains("prepared") {
                                    Line::styled(p.clone(), Style::default().fg(Color::Yellow))
                                } else if p.contains("finalized") {
                                    Line::styled(p.clone(), Style::default().fg(Color::Green))
                                } else {
                                    Line::raw(p.clone())
                                }
                            })
                            .collect::<Vec<Line>>(),
                    );
                    let progress_block = Paragraph::new(progress_text)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Activity")
                                .border_style(match focused_window {
                                    Focus::Progress => Style::default().fg(Color::Red),
                                    _ => Style::default(),
                                }),
                        )
                        .scroll((progress_scroll_vertical, progress_scroll_horizontal));
                    f.render_widget(progress_block, chunks[0]);

                    // Display logs
                    let logs_height = chunks[1].height - HEIGHT_OFFSET;
                    let logs = self.logs.lock().unwrap();
                    let logs_len = logs.len() as u16;
                    let logs_max_scroll = logs_len.saturating_sub(logs_height);
                    if focused_window != Focus::Logs {
                        logs_scroll_vertical = logs_max_scroll;
                    }
                    let logs_text = Text::from(
                        logs.iter()
                            .map(|l| Line::raw(l.clone()))
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
                None => panic!("Failed to receive event"),
            };
            match event {
                Event::Input(event) => match event.code {
                    KeyCode::Tab => {
                        focused_window = match focused_window {
                            Focus::Progress => Focus::Logs,
                            Focus::Logs => Focus::Progress,
                        };
                    }
                    KeyCode::Up => match focused_window {
                        Focus::Progress => {
                            progress_scroll_vertical = progress_scroll_vertical.saturating_sub(1)
                        }
                        Focus::Logs => {
                            logs_scroll_vertical = logs_scroll_vertical.saturating_sub(1)
                        }
                    },
                    KeyCode::Down => match focused_window {
                        Focus::Progress => {
                            progress_scroll_vertical = progress_scroll_vertical.saturating_add(1)
                        }
                        Focus::Logs => {
                            logs_scroll_vertical = logs_scroll_vertical.saturating_add(1)
                        }
                    },
                    KeyCode::Left => match focused_window {
                        Focus::Progress => {
                            progress_scroll_horizontal =
                                progress_scroll_horizontal.saturating_sub(1)
                        }
                        Focus::Logs => {
                            logs_scroll_horizontal = logs_scroll_horizontal.saturating_sub(1)
                        }
                    },
                    KeyCode::Right => match focused_window {
                        Focus::Progress => {
                            progress_scroll_horizontal =
                                progress_scroll_horizontal.saturating_add(1)
                        }
                        Focus::Logs => {
                            logs_scroll_horizontal = logs_scroll_horizontal.saturating_add(1)
                        }
                    },
                    KeyCode::Esc => {
                        disable_raw_mode().unwrap();
                        execute!(terminal.backend_mut(), LeaveAlternateScreen).unwrap();
                        terminal.show_cursor().unwrap();
                        break;
                    }
                    _ => {}
                },
                Event::Tick => {
                    // Refresh screen
                }
            }
        }
    }
}
