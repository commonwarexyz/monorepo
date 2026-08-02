//! Terminal UI for observing Multimmit consensus and producer-chain progress.

mod components;

use commonware_consensus::multimmit::Inspection;
use commonware_cryptography::Digest;
use commonware_runtime::{Metrics, Spawner};
use commonware_utils::{channel::mpsc, sync::Mutex};
use components::{App, Effect};
use crossterm::{
    event::{self, Event as CrosstermEvent, KeyEvent},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{
    collections::VecDeque,
    env::var,
    fs::File,
    io::{Error as IoError, Result as IoResult, Write, stdout},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tracing_subscriber::fmt::{MakeWriter, writer::MakeWriterExt as _};

const LOG_CAPACITY: usize = 10_000;
const TRACE_FILE_QUEUE_CAPACITY: usize = 256;
const TRACE_EVENT_MAX_BYTES: usize = 64 * 1024;
const TRACE_FILE_CLOSED: usize = 1 << (usize::BITS - 1);
const STATUS_STALE_AFTER: Duration = Duration::from_secs(2);

enum Event {
    Input(KeyEvent),
    Tick,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum EngineHealth {
    Starting,
    Responsive,
    Unresponsive,
    Stopped,
}

#[derive(Clone, Debug)]
struct EngineInspection {
    view: u64,
    finality_floor: u64,
    live: bool,
    cached_artifacts: usize,
    outbox_effects: usize,
    verification_jobs: usize,
    resolution_jobs: usize,
    producer: Option<EngineProducerProgress>,
    chains: Vec<EngineChainProgress>,
}

#[derive(Copy, Clone, Debug)]
struct EngineProducerProgress {
    chain: u32,
    produced: u64,
    certified: u64,
    vote_shares: usize,
    da_quorum: usize,
    pipeline_blocked: bool,
    recovery_ready: bool,
    recovery_pending: bool,
    recovery_active: bool,
    production_credit: bool,
}

#[derive(Copy, Clone, Debug)]
struct EngineChainProgress {
    chain: u32,
    finalized: u64,
    certified: u64,
    known: u64,
}

#[derive(Default)]
struct EngineStatusState {
    stopped: bool,
    last_response: Option<Instant>,
    inspection: Option<EngineInspection>,
}

#[derive(Clone)]
struct EngineSnapshot {
    health: EngineHealth,
    age: Option<Duration>,
    inspection: Option<EngineInspection>,
}

/// Shared status reported by the engine inspection loop.
#[derive(Clone, Default)]
pub struct EngineStatus {
    state: Arc<Mutex<EngineStatusState>>,
}

impl EngineStatus {
    /// Records one successful engine inspection.
    pub fn observed<D: Digest>(&self, inspection: &Inspection<D>) {
        self.record(
            EngineInspection {
                view: inspection.view().get(),
                finality_floor: inspection.finality_floor().get(),
                live: inspection.is_live(),
                cached_artifacts: inspection.cached_artifacts(),
                outbox_effects: inspection.outbox().len(),
                verification_jobs: inspection.verification_jobs().len(),
                resolution_jobs: inspection.resolution_jobs(),
                producer: inspection
                    .producer()
                    .map(|producer| EngineProducerProgress {
                        chain: producer.chain().get(),
                        produced: producer.produced().get(),
                        certified: producer.certified().get(),
                        vote_shares: producer.vote_shares(),
                        da_quorum: producer.da_quorum(),
                        pipeline_blocked: producer.pipeline_blocked(),
                        recovery_ready: producer.ready_recovery(),
                        recovery_pending: producer.pending_recovery(),
                        recovery_active: producer.active_recovery(),
                        production_credit: producer.production_credit(),
                    }),
                chains: inspection
                    .chain_progress()
                    .iter()
                    .map(|progress| EngineChainProgress {
                        chain: progress.chain().get(),
                        finalized: progress.finalized().get(),
                        certified: progress.certified().get(),
                        known: progress.known().get(),
                    })
                    .collect(),
            },
            Instant::now(),
        );
    }

    /// Marks the engine stopped while retaining its last inspection.
    pub fn stopped(&self) {
        self.state.lock().stopped = true;
    }

    fn record(&self, inspection: EngineInspection, now: Instant) {
        let mut state = self.state.lock();
        state.stopped = false;
        state.last_response = Some(now);
        state.inspection = Some(inspection);
    }

    fn health_from(state: &EngineStatusState, now: Instant) -> EngineHealth {
        if state.stopped {
            return EngineHealth::Stopped;
        }
        let Some(last_response) = state.last_response else {
            return EngineHealth::Starting;
        };
        if now.saturating_duration_since(last_response) >= STATUS_STALE_AFTER {
            return EngineHealth::Unresponsive;
        }
        EngineHealth::Responsive
    }

    fn snapshot(&self, now: Instant) -> EngineSnapshot {
        let state = self.state.lock();
        EngineSnapshot {
            health: Self::health_from(&state, now),
            age: state
                .last_response
                .map(|last_response| now.saturating_duration_since(last_response)),
            inspection: state.inspection.clone(),
        }
    }

    #[cfg(test)]
    fn health(&self, now: Instant) -> EngineHealth {
        Self::health_from(&self.state.lock(), now)
    }
}

struct UiSnapshot {
    me: u32,
    producer_chain: Option<u32>,
    engine: EngineSnapshot,
    logs: Vec<String>,
}

fn format_age(age: Option<Duration>) -> String {
    let Some(age) = age else {
        return String::from("never");
    };
    if age < Duration::from_secs(1) {
        return format!("{}ms ago", age.as_millis());
    }
    format!("{:.1}s ago", age.as_secs_f64())
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<VecDeque<String>>>);

impl LogBuffer {
    fn push(&self, line: String) {
        let mut logs = self.0.lock();
        if logs.len() == LOG_CAPACITY {
            logs.pop_front();
        }
        logs.push_back(line);
    }

    fn snapshot(&self) -> Vec<String> {
        self.0.lock().iter().cloned().collect()
    }
}

/// Captures formatted tracing events for the terminal log pane.
#[derive(Clone)]
pub struct Writer {
    logs: LogBuffer,
}

impl Writer {
    const fn new(logs: LogBuffer) -> Self {
        Self { logs }
    }

    fn add_fields(key: &str, value: &serde_json::Value, message: &mut String) {
        if let serde_json::Value::Object(map) = value {
            for (key, value) in map {
                Self::add_fields(key, value, message);
            }
            return;
        }
        if !key.is_empty()
            && key != "level"
            && key != "timestamp"
            && key != "target"
            && key != "message"
        {
            message.push_str(&format!("{key}={value} "));
        }
    }
}

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        let json: serde_json::Value = serde_json::from_slice(buf).map_err(IoError::other)?;
        let timestamp = json["timestamp"].as_str().unwrap_or("unknown");
        let target = json["target"].as_str().unwrap_or("unknown");
        let message = json["fields"]["message"].as_str().unwrap_or("event");
        let timestamp = timestamp
            .parse::<chrono::DateTime<chrono::Utc>>()
            .map(|timestamp| {
                timestamp
                    .with_timezone(&chrono::Local)
                    .format("%Y-%m-%dT%H:%M:%S")
                    .to_string()
            })
            .unwrap_or_else(|_| timestamp.to_owned());
        let application = target.contains("commonware_log_multimmit::application");
        let mut line = if application {
            format!("[{timestamp}] => {message} (")
        } else {
            let level = json["level"].as_str().unwrap_or("UNKNOWN");
            format!("[{timestamp}|{level}] {target} => {message} (")
        };
        Self::add_fields("", &json, &mut line);
        let line = format!("{})", line.trim_end()).replace("()", "");
        self.logs.push(line);
        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Writer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

enum TraceFileMessage {
    Event(Vec<u8>),
    Shutdown,
}

struct TraceFileState {
    queue: SyncSender<TraceFileMessage>,
    admission: AtomicUsize,
    dropped_full: AtomicUsize,
    dropped_oversized: AtomicUsize,
    dropped_closed: AtomicUsize,
}

impl TraceFileState {
    const fn new(queue: SyncSender<TraceFileMessage>) -> Self {
        Self {
            queue,
            admission: AtomicUsize::new(0),
            dropped_full: AtomicUsize::new(0),
            dropped_oversized: AtomicUsize::new(0),
            dropped_closed: AtomicUsize::new(0),
        }
    }

    fn submit(&self, bytes: Vec<u8>) {
        let mut admission = self.admission.load(Ordering::Acquire);
        loop {
            if admission & TRACE_FILE_CLOSED != 0 {
                self.dropped_closed.fetch_add(1, Ordering::Relaxed);
                return;
            }
            match self.admission.compare_exchange_weak(
                admission,
                admission + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => admission = current,
            }
        }
        match self.queue.try_send(TraceFileMessage::Event(bytes)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped_full.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.dropped_closed.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.admission.fetch_sub(1, Ordering::Release);
    }
}

struct FileWriter {
    state: Arc<TraceFileState>,
}

impl FileWriter {
    fn new(path: impl AsRef<std::path::Path>) -> IoResult<(Self, FileWriterGuard)> {
        let file = File::create(path)?;
        let (queue, receiver) = sync_channel(TRACE_FILE_QUEUE_CAPACITY);
        let state = Arc::new(TraceFileState::new(queue));
        let worker = thread::Builder::new()
            .name("log-multimmit-trace".to_owned())
            .spawn(move || write_trace_file(file, receiver))?;
        Ok((
            Self {
                state: Arc::clone(&state),
            },
            FileWriterGuard {
                state,
                worker: Some(worker),
            },
        ))
    }
}

struct TraceEventWriter {
    state: Arc<TraceFileState>,
    bytes: Vec<u8>,
    oversized: bool,
}

impl Write for TraceEventWriter {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        if !self.oversized && buf.len() <= TRACE_EVENT_MAX_BYTES.saturating_sub(self.bytes.len()) {
            self.bytes.extend_from_slice(buf);
        } else if !buf.is_empty() {
            self.bytes.clear();
            self.oversized = true;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl Drop for TraceEventWriter {
    fn drop(&mut self) {
        if self.oversized {
            self.state.dropped_oversized.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if !self.bytes.is_empty() {
            self.state.submit(std::mem::take(&mut self.bytes));
        }
    }
}

impl<'a> MakeWriter<'a> for FileWriter {
    type Writer = TraceEventWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TraceEventWriter {
            state: Arc::clone(&self.state),
            bytes: Vec::new(),
            oversized: false,
        }
    }
}

fn write_trace_file(mut file: File, receiver: Receiver<TraceFileMessage>) -> IoResult<()> {
    while let Ok(message) = receiver.recv() {
        match message {
            TraceFileMessage::Event(bytes) => file.write_all(&bytes)?,
            TraceFileMessage::Shutdown => return file.flush(),
        }
    }
    file.flush()
}

struct FileWriterGuard {
    state: Arc<TraceFileState>,
    worker: Option<JoinHandle<IoResult<()>>>,
}

impl Drop for FileWriterGuard {
    fn drop(&mut self) {
        self.state
            .admission
            .fetch_or(TRACE_FILE_CLOSED, Ordering::AcqRel);
        while self.state.admission.load(Ordering::Acquire) != TRACE_FILE_CLOSED {
            thread::yield_now();
        }
        let _ = self.state.queue.send(TraceFileMessage::Shutdown);
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => eprintln!("trace file writer failed: {error}"),
                Err(_) => eprintln!("trace file writer panicked"),
            }
        }
        let full = self.state.dropped_full.load(Ordering::Relaxed);
        let oversized = self.state.dropped_oversized.load(Ordering::Relaxed);
        let closed = self.state.dropped_closed.load(Ordering::Relaxed);
        if full != 0 || oversized != 0 || closed != 0 {
            eprintln!(
                "trace file writer dropped events: queue_full={full} oversized={oversized} closed={closed}"
            );
        }
    }
}

pub struct Gui<E: Spawner + Metrics> {
    context: E,
    status: EngineStatus,
    me: u32,
    producer_chain: Option<u32>,
    logs: LogBuffer,
    _trace_file: Option<FileWriterGuard>,
}

impl<E: Spawner + Metrics> Gui<E> {
    /// Creates the UI and installs its tracing writer.
    pub fn new(context: E, status: EngineStatus, me: u32, producer_chain: Option<u32>) -> Self {
        let logs = LogBuffer::default();
        let ui_writer = Writer::new(logs.clone());
        let trace_file = if let Ok(path) = var("LOG_MULTIMMIT_TRACE") {
            let (file_writer, guard) = FileWriter::new(path).expect("trace file opens");
            tracing_subscriber::fmt()
                .json()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(ui_writer.and(file_writer))
                .init();
            Some(guard)
        } else {
            tracing_subscriber::fmt()
                .json()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(ui_writer)
                .init();
            None
        };
        Self {
            context,
            status,
            me,
            producer_chain,
            logs,
            _trace_file: trace_file,
        }
    }

    fn snapshot(&self, now: Instant) -> UiSnapshot {
        UiSnapshot {
            me: self.me,
            producer_chain: self.producer_chain,
            engine: self.status.snapshot(now),
            logs: self.logs.snapshot(),
        }
    }

    pub async fn run(self) {
        enable_raw_mode().unwrap();
        let mut stdout = stdout();
        execute!(stdout, EnterAlternateScreen).unwrap();
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend).unwrap();

        let (tx, mut rx) = mpsc::channel(100);
        self.context
            .child("keyboard")
            .dedicated()
            .spawn(|_| async move {
                loop {
                    match event::poll(Duration::from_millis(250)) {
                        Ok(true) => {}
                        Ok(false) => {
                            if tx.send(Event::Tick).await.is_err() {
                                break;
                            }
                            continue;
                        }
                        Err(_) => break,
                    }
                    let Ok(CrosstermEvent::Key(key)) = event::read() else {
                        continue;
                    };
                    if tx.send(Event::Input(key)).await.is_err() {
                        break;
                    }
                }
            });

        let mut app = App::default();
        let mut render = true;
        loop {
            if render {
                let snapshot = self.snapshot(Instant::now());
                terminal
                    .draw(|frame| app.render(frame, frame.area(), &snapshot))
                    .unwrap();
            }

            let Some(event) = rx.recv().await else {
                break;
            };
            let update = match event {
                Event::Input(key) => app.update(key),
                Event::Tick => components::Update {
                    effect: None,
                    render: true,
                },
            };
            if matches!(update.effect, Some(Effect::Quit)) {
                break;
            }
            render = update.render;
        }

        disable_raw_mode().unwrap();
        execute!(terminal.backend_mut(), LeaveAlternateScreen).unwrap();
        terminal.show_cursor().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspection() -> EngineInspection {
        EngineInspection {
            view: 11,
            finality_floor: 7,
            live: true,
            cached_artifacts: 8,
            outbox_effects: 7,
            verification_jobs: 5,
            resolution_jobs: 3,
            producer: None,
            chains: vec![EngineChainProgress {
                chain: 0,
                finalized: 22,
                certified: 33,
                known: 34,
            }],
        }
    }

    #[test]
    fn engine_health_distinguishes_stalls_from_stops() {
        let status = EngineStatus::default();
        let now = Instant::now();
        assert_eq!(status.health(now), EngineHealth::Starting);
        status.record(inspection(), now);
        assert_eq!(status.health(now), EngineHealth::Responsive);
        assert_eq!(
            status.health(now + STATUS_STALE_AFTER),
            EngineHealth::Unresponsive
        );
        status.stopped();
        assert_eq!(
            status.health(now + STATUS_STALE_AFTER),
            EngineHealth::Stopped
        );
    }

    #[test]
    fn inspection_age_is_compact() {
        assert_eq!(format_age(None), "never");
        assert_eq!(format_age(Some(Duration::from_millis(27))), "27ms ago");
        assert_eq!(format_age(Some(Duration::from_millis(2_340))), "2.3s ago");
    }

    #[test]
    fn log_buffer_is_bounded() {
        let logs = LogBuffer::default();
        for index in 0..=LOG_CAPACITY {
            logs.push(index.to_string());
        }
        let snapshot = logs.snapshot();
        assert_eq!(snapshot.len(), LOG_CAPACITY);
        assert_eq!(snapshot.first().unwrap(), "1");
    }

    #[test]
    fn trace_file_emission_does_not_wait_for_file_io() {
        let (queue, receiver) = sync_channel(1);
        let state = Arc::new(TraceFileState::new(queue));
        state
            .queue
            .try_send(TraceFileMessage::Event(Vec::new()))
            .unwrap();
        let writer = FileWriter {
            state: Arc::clone(&state),
        };
        let mut output = writer.make_writer();
        output.write_all(b"{\"message\":\"bounded\"}\n").unwrap();
        drop(output);

        assert_eq!(state.dropped_full.load(Ordering::Relaxed), 1);
        drop(receiver);
    }

    #[test]
    fn trace_file_shutdown_drains_accepted_events() {
        let path = std::env::temp_dir().join(format!(
            "commonware-log-multimmit-trace-{}.json",
            uuid::Uuid::new_v4()
        ));
        let (writer, guard) = FileWriter::new(&path).unwrap();
        let mut output = writer.make_writer();
        output.write_all(b"{\"message\":\"drained\"}\n").unwrap();
        drop(output);
        drop(guard);

        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"{\"message\":\"drained\"}\n"
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn oversized_trace_events_are_dropped_before_enqueue() {
        let (queue, receiver) = sync_channel(1);
        let state = Arc::new(TraceFileState::new(queue));
        let writer = FileWriter {
            state: Arc::clone(&state),
        };
        let mut output = writer.make_writer();
        output
            .write_all(&vec![0; TRACE_EVENT_MAX_BYTES + 1])
            .unwrap();
        drop(output);

        assert_eq!(state.dropped_oversized.load(Ordering::Relaxed), 1);
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
    }
}
