//! Bounded, time-limited diagnostic capture for one example node.

use commonware_consensus::multimmit::diagnostics::{self as consensus_diagnostics, Sink};
use std::{
    fmt::{self, Debug, Write as _},
    fs::File,
    io::{self, BufWriter, Write},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const QUEUE_CAPACITY: usize = 8192;
const QUEUE_MAX_BYTES: usize = 64 * 1024 * 1024;
const EVENT_MAX_BYTES: usize = 256 * 1024;
const WRITER_BUFFER_BYTES: usize = 1024 * 1024;
const ANCHOR_INTERVAL: Duration = Duration::from_secs(1);
const CLOSED: usize = 1 << (usize::BITS - 1);

struct Counters {
    attempts: AtomicU64,
    accepted: AtomicU64,
    written: AtomicU64,
    dropped_full: AtomicU64,
    dropped_oversized: AtomicU64,
    dropped_closed: AtomicU64,
    dropped_io: AtomicU64,
    artifact_omitted: AtomicU64,
}

impl Counters {
    const fn new() -> Self {
        Self {
            attempts: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            written: AtomicU64::new(0),
            dropped_full: AtomicU64::new(0),
            dropped_oversized: AtomicU64::new(0),
            dropped_closed: AtomicU64::new(0),
            dropped_io: AtomicU64::new(0),
            artifact_omitted: AtomicU64::new(0),
        }
    }
}

struct State {
    queue: SyncSender<Message>,
    start: Instant,
    warmup: Duration,
    cohort_end: Duration,
    end: Duration,
    admission: AtomicUsize,
    sequence: AtomicU64,
    queued_bytes: AtomicUsize,
    counters: Counters,
}

enum Message {
    Event(String),
    Shutdown,
}

impl State {
    fn phase(&self, elapsed: Duration) -> Option<&'static str> {
        if elapsed < self.warmup {
            Some("warmup")
        } else if elapsed < self.cohort_end {
            Some("cohort")
        } else if elapsed < self.end {
            Some("drain")
        } else {
            None
        }
    }

    fn new(
        queue: SyncSender<Message>,
        start: Instant,
        warmup: Duration,
        cohort: Duration,
        drain: Duration,
    ) -> io::Result<Self> {
        let cohort_end = warmup.checked_add(cohort).ok_or_else(invalid_duration)?;
        let end = cohort_end.checked_add(drain).ok_or_else(invalid_duration)?;
        // Instant arithmetic on some platforms has a smaller range than Duration.
        start.checked_add(end).ok_or_else(invalid_duration)?;
        Ok(Self {
            queue,
            start,
            warmup,
            cohort_end,
            end,
            admission: AtomicUsize::new(0),
            sequence: AtomicU64::new(0),
            queued_bytes: AtomicUsize::new(0),
            counters: Counters::new(),
        })
    }

    fn close(&self) {
        self.admission.fetch_or(CLOSED, Ordering::AcqRel);
        while self.admission.load(Ordering::Acquire) != CLOSED {
            thread::yield_now();
        }
    }

    fn admit(&self) -> bool {
        let mut current = self.admission.load(Ordering::Acquire);
        loop {
            if current & CLOSED != 0 {
                return false;
            }
            match self.admission.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(next) => current = next,
            }
        }
    }

    fn emit(&self, kind: &'static str, fields: &[(&'static str, &dyn Debug)]) {
        let elapsed = self.start.elapsed();
        if !self.admit() {
            return;
        }
        self.counters.attempts.fetch_add(1, Ordering::Relaxed);
        if kind == "artifact_omitted" {
            self.counters
                .artifact_omitted
                .fetch_add(1, Ordering::Relaxed);
        }
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let Some(phase) = self.phase(elapsed) else {
            self.counters.dropped_closed.fetch_add(1, Ordering::Relaxed);
            self.admission.fetch_sub(1, Ordering::Release);
            return;
        };
        let event = format_event(sequence, elapsed, phase, kind, fields);
        match event {
            Some(line) => {
                let bytes = line.len();
                if self
                    .queued_bytes
                    .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |queued| {
                        queued
                            .checked_add(bytes)
                            .filter(|next| *next <= QUEUE_MAX_BYTES)
                    })
                    .is_err()
                {
                    self.counters.dropped_full.fetch_add(1, Ordering::Relaxed);
                } else {
                    match self.queue.try_send(Message::Event(line)) {
                        Ok(()) => {
                            self.counters.accepted.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(error) => {
                            self.queued_bytes.fetch_sub(bytes, Ordering::Release);
                            match error {
                                TrySendError::Full(_) => {
                                    self.counters.dropped_full.fetch_add(1, Ordering::Relaxed);
                                }
                                TrySendError::Disconnected(_) => {
                                    self.counters.dropped_closed.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
            }
            None => {
                self.counters
                    .dropped_oversized
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        self.admission.fetch_sub(1, Ordering::Release);
    }
}

struct CaptureSink(Arc<State>);

impl Sink for CaptureSink {
    fn enabled(&self) -> bool {
        self.0.admission.load(Ordering::Relaxed) & CLOSED == 0
            && self.0.start.elapsed() < self.0.end
    }

    fn elapsed_ns(&self) -> Option<u128> {
        self.enabled().then(|| self.0.start.elapsed().as_nanos())
    }

    fn record(&self, kind: &'static str, fields: &[(&'static str, &dyn Debug)]) {
        self.0.emit(kind, fields);
    }
}

struct BoundedJson {
    line: String,
}

impl BoundedJson {
    const fn new() -> Self {
        Self {
            line: String::new(),
        }
    }

    fn quoted(&mut self, value: &str) -> fmt::Result {
        self.raw("\"")?;
        self.escaped(value)?;
        self.raw("\"")
    }

    fn escaped(&mut self, value: &str) -> fmt::Result {
        for ch in value.chars() {
            match ch {
                '"' => self.raw("\\\"")?,
                '\\' => self.raw("\\\\")?,
                '\n' => self.raw("\\n")?,
                '\r' => self.raw("\\r")?,
                '\t' => self.raw("\\t")?,
                c if c <= '\u{1f}' => self.raw(&format!("\\u{:04x}", c as u32))?,
                c => self.push(c)?,
            }
        }
        Ok(())
    }

    fn raw(&mut self, value: &str) -> fmt::Result {
        if value.len() > EVENT_MAX_BYTES.saturating_sub(self.line.len()) {
            return Err(fmt::Error);
        }
        self.line.push_str(value);
        Ok(())
    }

    fn push(&mut self, ch: char) -> fmt::Result {
        if ch.len_utf8() > EVENT_MAX_BYTES.saturating_sub(self.line.len()) {
            return Err(fmt::Error);
        }
        self.line.push(ch);
        Ok(())
    }
}

impl fmt::Write for BoundedJson {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.escaped(s)
    }
}

fn format_event(
    sequence: u64,
    elapsed: Duration,
    phase: &str,
    kind: &str,
    fields: &[(&'static str, &dyn Debug)],
) -> Option<String> {
    let mut out = BoundedJson::new();
    (|| -> fmt::Result {
        out.raw("{\"type\":\"event\",\"seq\":")?;
        out.raw(&sequence.to_string())?;
        out.raw(",\"elapsed_ns\":")?;
        out.raw(&elapsed.as_nanos().to_string())?;
        out.raw(",\"phase\":")?;
        out.quoted(phase)?;
        out.raw(",\"kind\":")?;
        out.quoted(kind)?;
        out.raw(",\"fields\":{")?;
        for (index, (name, value)) in fields.iter().enumerate() {
            if index > 0 {
                out.raw(",")?;
            }
            out.quoted(name)?;
            out.raw(":\"")?;
            write!(&mut out, "{value:?}")?;
            out.raw("\"")?;
        }
        out.raw("}}\n")
    })()
    .ok()?;
    Some(out.line)
}

fn invalid_duration() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "capture duration exceeds Instant range",
    )
}

/// Installs a process-wide capture sink and runs the timed capture in a writer thread.
///
/// The header's wall clock anchors one node's monotonic elapsed timestamps. Clock skew and
/// transport latency prevent precise ordering of events from different nodes.
pub fn install(
    path: &Path,
    node: u64,
    warmup: Duration,
    cohort: Duration,
    drain: Duration,
) -> io::Result<Guard> {
    let file = File::create(path)?;
    let start = Instant::now();
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    let (queue, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
    let state = Arc::new(State::new(queue, start, warmup, cohort, drain)?);
    let writer_state = Arc::clone(&state);
    let worker = thread::Builder::new()
        .name("log-multimmit-diagnostics".into())
        .spawn(move || write_events(file, receiver, writer_state, node, wall, cohort, drain))?;
    if consensus_diagnostics::install(Arc::new(CaptureSink(Arc::clone(&state)))).is_err() {
        state.close();
        let _ = state.queue.send(Message::Shutdown);
        let _ = worker.join();
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "diagnostic sink already installed",
        ));
    }
    Ok(Guard {
        state,
        worker: Some(worker),
    })
}

fn write_events(
    file: File,
    receiver: Receiver<Message>,
    state: Arc<State>,
    node: u64,
    wall: Duration,
    cohort: Duration,
    drain: Duration,
) -> io::Result<()> {
    let mut file = BufWriter::with_capacity(WRITER_BUFFER_BYTES, file);
    let header = format!(
        "{{\"type\":\"header\",\"schema\":1,\"capture_id\":\"{}\",\"node\":{node},\"wall_unix_ns\":{},\"warmup_ns\":{},\"cohort_ns\":{},\"drain_ns\":{},\"clock\":\"elapsed_ns is local monotonic time; cross-node timestamps are not precisely comparable\"}}\n",
        uuid::Uuid::new_v4(),
        wall.as_nanos(),
        state.warmup.as_nanos(),
        cohort.as_nanos(),
        drain.as_nanos()
    );
    let mut failure = file.write_all(header.as_bytes()).err();
    let mut next_anchor = ANCHOR_INTERVAL;
    let completed_window = loop {
        let elapsed = state.start.elapsed();
        if elapsed >= state.end {
            break true;
        }
        if state.admission.load(Ordering::Acquire) & CLOSED != 0 {
            break false;
        }
        if elapsed >= next_anchor {
            write_anchor(&mut file, &state, &mut failure);
            next_anchor = elapsed.saturating_add(ANCHOR_INTERVAL);
            continue;
        }
        let remaining = state
            .end
            .saturating_sub(elapsed)
            .min(next_anchor.saturating_sub(elapsed));
        match receiver.recv_timeout(remaining) {
            Ok(Message::Event(line)) => {
                state.queued_bytes.fetch_sub(line.len(), Ordering::Release);
                write_event(&mut file, &state.counters, &mut failure, &line)
            }
            Ok(Message::Shutdown) | Err(mpsc::RecvTimeoutError::Disconnected) => break false,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    state.close();
    loop {
        match receiver.try_recv() {
            Ok(Message::Event(line)) => {
                state.queued_bytes.fetch_sub(line.len(), Ordering::Release);
                write_event(&mut file, &state.counters, &mut failure, &line)
            }
            Ok(Message::Shutdown) => {}
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
        }
    }
    write_anchor(&mut file, &state, &mut failure);
    if let Some(error) = failure {
        return Err(error);
    }
    let count = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    let complete = completed_window
        && count(&state.counters.dropped_full) == 0
        && count(&state.counters.dropped_oversized) == 0
        && count(&state.counters.dropped_closed) == 0
        && count(&state.counters.dropped_io) == 0
        && count(&state.counters.artifact_omitted) == 0;
    let reason = if completed_window {
        "timed"
    } else {
        "early_stop"
    };
    let footer = format!(
        "{{\"type\":\"footer\",\"complete\":{complete},\"reason\":\"{reason}\",\"attempts\":{},\"accepted\":{},\"written\":{},\"dropped_full\":{},\"dropped_oversized\":{},\"dropped_closed\":{},\"dropped_io\":{},\"artifact_omitted\":{}}}\n",
        count(&state.counters.attempts),
        count(&state.counters.accepted),
        count(&state.counters.written),
        count(&state.counters.dropped_full),
        count(&state.counters.dropped_oversized),
        count(&state.counters.dropped_closed),
        count(&state.counters.dropped_io),
        count(&state.counters.artifact_omitted),
    );
    file.write_all(footer.as_bytes())?;
    file.flush()
}

fn write_anchor(file: &mut BufWriter<File>, state: &State, failure: &mut Option<io::Error>) {
    if failure.is_some() {
        return;
    }
    let elapsed = state.start.elapsed();
    let wall = SystemTime::now().duration_since(UNIX_EPOCH);
    let result = wall.map_err(io::Error::other).and_then(|wall| {
        writeln!(
            file,
            "{{\"type\":\"wall_anchor\",\"elapsed_ns\":{},\"wall_unix_ns\":{}}}",
            elapsed.as_nanos(),
            wall.as_nanos()
        )
    });
    if let Err(error) = result {
        *failure = Some(error);
    }
}

fn write_event(
    file: &mut BufWriter<File>,
    counters: &Counters,
    failure: &mut Option<io::Error>,
    line: &str,
) {
    if failure.is_some() {
        counters.dropped_io.fetch_add(1, Ordering::Relaxed);
    } else if let Err(error) = file.write_all(line.as_bytes()) {
        *failure = Some(error);
        counters.dropped_io.fetch_add(1, Ordering::Relaxed);
    } else {
        counters.written.fetch_add(1, Ordering::Relaxed);
    }
}

/// Owns the writer thread. Dropping it closes admission, drains accepted events, and joins it.
pub struct Guard {
    state: Arc<State>,
    worker: Option<JoinHandle<io::Result<()>>>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.state.close();
        // The worker also shuts itself down at the deadline. Its receiver can already be gone.
        let _ = self.state.queue.try_send(Message::Shutdown);
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => eprintln!("diagnostic capture writer failed: {error}"),
                Err(_) => eprintln!("diagnostic capture writer panicked"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(
        capacity: usize,
        warmup: Duration,
        cohort: Duration,
        drain: Duration,
    ) -> (Arc<State>, Receiver<Message>) {
        let (queue, receiver) = mpsc::sync_channel(capacity);
        (
            Arc::new(State::new(queue, Instant::now(), warmup, cohort, drain).unwrap()),
            receiver,
        )
    }

    #[test]
    fn bounded_queue_and_oversized_record() {
        let (state, receiver) = state(
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        state.emit("one", &[]);
        state.emit("two", &[]);
        let large = "x".repeat(EVENT_MAX_BYTES);
        state.emit("large", &[("value", &large)]);
        assert_eq!(state.counters.attempts.load(Ordering::Relaxed), 3);
        assert_eq!(state.counters.accepted.load(Ordering::Relaxed), 1);
        assert_eq!(state.counters.dropped_full.load(Ordering::Relaxed), 1);
        assert_eq!(state.counters.dropped_oversized.load(Ordering::Relaxed), 1);
        assert!(matches!(receiver.try_recv(), Ok(Message::Event(_))));
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn phase_boundaries_are_contiguous() {
        let (state, _receiver) = state(
            8,
            Duration::from_secs(5),
            Duration::from_secs(15),
            Duration::from_secs(5),
        );
        assert_eq!(
            state.phase(Duration::from_secs(5) - Duration::from_nanos(1)),
            Some("warmup")
        );
        assert_eq!(state.phase(Duration::from_secs(5)), Some("cohort"));
        assert_eq!(
            state.phase(Duration::from_secs(20) - Duration::from_nanos(1)),
            Some("cohort")
        );
        assert_eq!(state.phase(Duration::from_secs(20)), Some("drain"));
        assert_eq!(state.phase(Duration::from_secs(25)), None);
    }

    #[test]
    fn escaped_debug_fields_are_valid_json_strings() {
        let line = format_event(
            7,
            Duration::from_nanos(3),
            "cohort",
            "quoted",
            &[("text", &"a\"\\\n")],
        )
        .unwrap();
        assert!(line.contains(r#""text":"\"a\\\"\\\\\\n\"""#), "{line}");
        assert!(line.len() <= EVENT_MAX_BYTES);
    }

    #[test]
    fn deadline_finishes_capture_without_dropping_guard() {
        let path = std::env::temp_dir().join(format!(
            "commonware-diagnostics-deadline-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let file = File::create(&path).unwrap();
        let (state, receiver) = state(8, Duration::ZERO, Duration::from_millis(30), Duration::ZERO);
        let worker_state = Arc::clone(&state);
        let worker = thread::spawn(move || {
            write_events(
                file,
                receiver,
                worker_state,
                3,
                Duration::ZERO,
                Duration::from_millis(30),
                Duration::ZERO,
            )
        });
        state.emit("cohort_event", &[]);
        worker.join().unwrap().unwrap();
        assert!(!CaptureSink(Arc::clone(&state)).enabled());
        let data = std::fs::read_to_string(&path).unwrap();
        assert!(data.contains("\"phase\":\"cohort\""));
        assert!(data.contains("\"type\":\"footer\",\"complete\":true"));
        assert!(data.contains("\"type\":\"wall_anchor\""));
        assert!(data.contains("\"capture_id\":\""));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn omitted_artifact_makes_finished_capture_incomplete() {
        let path = std::env::temp_dir().join(format!(
            "commonware-diagnostics-omitted-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let file = File::create(&path).unwrap();
        let (state, receiver) = state(8, Duration::ZERO, Duration::from_millis(30), Duration::ZERO);
        let worker_state = Arc::clone(&state);
        let worker = thread::spawn(move || {
            write_events(
                file,
                receiver,
                worker_state,
                3,
                Duration::ZERO,
                Duration::from_millis(30),
                Duration::ZERO,
            )
        });
        state.emit("artifact_omitted", &[]);
        worker.join().unwrap().unwrap();
        let data = std::fs::read_to_string(&path).unwrap();
        assert!(data.contains("\"complete\":false,\"reason\":\"timed\""));
        assert!(data.contains("\"artifact_omitted\":1}"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn writer_samples_wall_clock_during_capture() {
        let path = std::env::temp_dir().join(format!(
            "commonware-diagnostics-anchors-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let file = File::create(&path).unwrap();
        let duration = ANCHOR_INTERVAL + Duration::from_millis(100);
        let (state, receiver) = state(8, Duration::ZERO, duration, Duration::ZERO);
        let worker = thread::spawn(move || {
            write_events(
                file,
                receiver,
                state,
                3,
                Duration::ZERO,
                duration,
                Duration::ZERO,
            )
        });
        worker.join().unwrap().unwrap();
        let data = std::fs::read_to_string(&path).unwrap();
        assert_eq!(data.matches("\"type\":\"wall_anchor\"").count(), 2);
        assert!(data.contains("\"complete\":true,\"reason\":\"timed\""));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn shutdown_drains_and_writes_complete_footer() {
        let path = std::env::temp_dir().join(format!(
            "commonware-diagnostics-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let file = File::create(&path).unwrap();
        let (state, receiver) = state(
            8,
            Duration::from_secs(5),
            Duration::from_secs(15),
            Duration::from_secs(5),
        );
        let worker_state = Arc::clone(&state);
        let worker = thread::spawn(move || {
            write_events(
                file,
                receiver,
                worker_state,
                3,
                Duration::from_secs(1),
                Duration::from_secs(15),
                Duration::from_secs(5),
            )
        });
        state.emit("proposal", &[("round", &17u64)]);
        let guard = Guard {
            state: Arc::clone(&state),
            worker: Some(worker),
        };
        drop(guard);
        assert_eq!(CaptureSink(Arc::clone(&state)).elapsed_ns(), None);
        state.emit("late", &[]);
        let data = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = data.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].contains("\"type\":\"header\""));
        assert!(lines[1].contains("\"phase\":\"warmup\""));
        assert!(lines[1].contains("\"round\":\"17\""));
        assert!(lines[2].contains("\"type\":\"wall_anchor\""));
        assert!(lines[3].contains(
            "\"type\":\"footer\",\"complete\":false,\"reason\":\"early_stop\",\"attempts\":1,\"accepted\":1,\"written\":1"
        ));
        assert_eq!(state.counters.dropped_closed.load(Ordering::Relaxed), 0);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn concurrent_close_freezes_footer_counters() {
        use std::sync::Barrier;

        let path = std::env::temp_dir().join(format!(
            "commonware-diagnostics-close-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let file = File::create(&path).unwrap();
        let (state, receiver) = state(
            8,
            Duration::from_secs(5),
            Duration::from_secs(15),
            Duration::from_secs(5),
        );
        let worker_state = Arc::clone(&state);
        let worker = thread::spawn(move || {
            write_events(
                file,
                receiver,
                worker_state,
                3,
                Duration::ZERO,
                Duration::from_secs(15),
                Duration::from_secs(5),
            )
        });
        state.emit("pre_close", &[]);
        let barrier = Arc::new(Barrier::new(5));
        let emitters: Vec<_> = (0..4)
            .map(|_| {
                let state = Arc::clone(&state);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..500 {
                        state.emit("racing", &[]);
                    }
                })
            })
            .collect();
        barrier.wait();
        drop(Guard {
            state: Arc::clone(&state),
            worker: Some(worker),
        });
        let footer = std::fs::read_to_string(&path).unwrap();
        let footer = footer.lines().last().unwrap().to_owned();
        for emitter in emitters {
            emitter.join().unwrap();
        }
        let count = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let attempts = count(&state.counters.attempts);
        let accepted = count(&state.counters.accepted);
        let written = count(&state.counters.written);
        let full = count(&state.counters.dropped_full);
        let oversized = count(&state.counters.dropped_oversized);
        let closed = count(&state.counters.dropped_closed);
        let io = count(&state.counters.dropped_io);
        assert_eq!(attempts, accepted + full + oversized + closed);
        assert_eq!(accepted, written + io);
        for (name, value) in [
            ("attempts", attempts),
            ("accepted", accepted),
            ("written", written),
            ("dropped_full", full),
            ("dropped_oversized", oversized),
            ("dropped_closed", closed),
            ("dropped_io", io),
        ] {
            assert!(footer.contains(&format!("\"{name}\":{value}")), "{footer}");
        }
        std::fs::remove_file(path).unwrap();
    }
}
