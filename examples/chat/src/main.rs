//! Send encrypted messages to a group of friends using [commonware-p2p](https://crates.io/crates/commonware-p2p).

mod logger;

use clap::{value_parser, Arg, Command};
use commonware_p2p::{
    crypto::{self, Crypto},
    Config, Network, Receiver, Sender,
};
use crossterm::{
    event::{self, Event as CEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use governor::Quota;
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use ratatui::text::Text;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph},
    Terminal,
};
use std::num::NonZeroU32;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::{
    io::{self, Write},
    net::SocketAddr,
};
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use tracing::info;
use tracing_subscriber::fmt::MakeWriter;

const CHAT_CHANNEL: u32 = 0;
enum Event<I> {
    Input(I),
    Tick,
}

async fn run_chat_handler(
    me: String,
    registry: Arc<Mutex<Registry>>,
    logs: Arc<Mutex<Vec<String>>>,
    peers: Vec<crypto::PublicKey>,
    sender: Sender,
    mut receiver: Receiver,
) {
    // Setup terminal
    enable_raw_mode().unwrap();
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();

    // Listen for input
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    tokio::spawn(async move {
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
                    .block(Block::default().borders(Borders::ALL).title("Messages"))
                    .scroll(((messages.len() as u16).saturating_sub(chunks[0].height), 0));
                f.render_widget(messages_block, messages_chunks[0]);

                // Display metrics
                let mut buffer = String::new();
                {
                    let registry = registry.lock().unwrap();
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
                    .block(Block::default().borders(Borders::ALL).title("Logs"))
                    .scroll(((logs.len() as u16).saturating_sub(chunks[1].height), 0));
                f.render_widget(logs_block, chunks[1]);
            })
            .unwrap();

        // Handle input
        tokio::select! {
            Some(event) = rx.recv() => {
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
                            sender
                                .send(peers.clone(), input.clone().into_bytes().into(), false)
                                .await;
                            let msg = Line::styled(format!(
                                "[{}] {}: {}",
                                chrono::Local::now().format("%m/%d %H:%M:%S"),
                                me,
                                input,
                            ), Style::default().fg(Color::Yellow));
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
            },
            Some((peer, msg)) = receiver.recv() => {
                messages.push(format!(
                    "[{}] {}: {}",
                    chrono::Local::now().format("%m/%d %H:%M:%S"),
                    hex::encode(peer),
                    String::from_utf8_lossy(&msg)
                ).into());
            }
        };
    }
}

#[tokio::main]
async fn main() {
    // Parse arguments
    let matches = Command::new("chat")
        .version("0.1")
        .author("Patrick O'Grady <patrick@commonware.xyz>")
        .about("encrypted chat between authorized peers")
        .arg(Arg::new("me").long("me").required(true))
        .arg(
            Arg::new("allowed_keys")
                .long("allowed_keys")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(u16)),
        )
        .arg(
            Arg::new("bootstrappers")
                .long("bootstrappers")
                .required(false)
                .value_delimiter(',')
                .value_parser(value_parser!(String)),
        )
        .get_matches();

    // Create logger
    let logs = Arc::new(Mutex::new(Vec::new()));
    let vec_writer = logger::VecWriter {
        logs: Arc::clone(&logs),
    };
    tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(vec_writer)
        .init();

    // Configure my identity
    let me = matches
        .get_one::<String>("me")
        .expect("Please provide identity");
    let parts = me.split('@').collect::<Vec<&str>>();
    let key = parts[0].parse::<u16>().expect("Key not well-formed");
    let signer = crypto::ed25519::insecure_signer(key);
    info!(key = hex::encode(signer.me()), "loaded signer");

    // Configure my port
    let port = parts[1].parse::<u16>().expect("Port not well-formed");
    info!(port, "loaded port");

    // Configure allowed peers
    let mut recipients = Vec::new();
    let allowed_keys = matches
        .get_many::<u16>("allowed_keys")
        .expect("Please provide allowed keys")
        .copied();
    if allowed_keys.len() == 0 {
        panic!("Please provide at least one allowed key");
    }
    for peer in allowed_keys {
        let verifier = crypto::ed25519::insecure_signer(peer).me();
        info!(key = hex::encode(&verifier), "registered authorized key",);
        recipients.push(verifier);
    }

    // Configure bootstrappers (if provided)
    let bootstrappers = matches.get_many::<String>("bootstrappers");
    let mut bootstrapper_identities = Vec::new();
    if let Some(bootstrappers) = bootstrappers {
        for bootstrapper in bootstrappers {
            let parts = bootstrapper.split('@').collect::<Vec<&str>>();
            let bootstrapper_key = parts[0]
                .parse::<u16>()
                .expect("Bootstrapper key not well-formed");
            let verifier = crypto::ed25519::insecure_signer(bootstrapper_key).me();
            let bootstrapper_address =
                SocketAddr::from_str(parts[1]).expect("Bootstrapper address not well-formed");
            bootstrapper_identities.push((verifier, bootstrapper_address));
        }
    }

    // Configure network
    let registry = Arc::new(Mutex::new(Registry::with_prefix("p2p")));
    let config = Config::default(
        signer.clone(),
        registry.clone(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        bootstrapper_identities.clone(),
        true,
    );
    let (mut network, oracle) = Network::new(config);

    // Provide authorized peers
    //
    // In a real-world scenario, this would be updated as new peer sets are created (like when
    // the composition of a validator set changes).
    oracle.register(0, recipients.clone()).await;

    // Initialize chat
    let (chat_sender, chat_receiver) = network.register(
        CHAT_CHANNEL,
        Quota::per_second(NonZeroU32::new(1).unwrap()),
        1024, // 1 KB max message size
        128,
    );

    // Start network
    let network_handler = tokio::spawn(network.run());

    // Start chat
    run_chat_handler(
        hex::encode(signer.me()),
        registry,
        logs,
        recipients,
        chat_sender,
        chat_receiver,
    )
    .await;

    // Abort network
    network_handler.abort();
}
