//! Non-blocking JSON tracing output to a file for the terminal UI.
//!
//! The terminal owns stdout, so the UI writes debug tracing events to a file instead. Emitting
//! an event never waits for file I/O: a background thread drains a bounded queue, and events
//! that do not fit are counted and reported on shutdown.

use std::{
    fs::File,
    io::{Result as IoResult, Write},
    mem,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
};
use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

/// Events buffered between emitters and the writer thread.
const QUEUE_CAPACITY: usize = 256;

/// Largest encoded event written; larger events are dropped.
const EVENT_MAX_BYTES: usize = 64 * 1024;

/// Admission flag set once shutdown begins; the low bits count in-flight submissions.
const CLOSED: usize = 1 << (usize::BITS - 1);

/// Installs a global JSON subscriber that writes debug events to `path`.
///
/// Dropping the returned guard flushes accepted events and stops the writer thread.
pub fn install(path: &Path) -> IoResult<Guard> {
    let (writer, guard) = FileWriter::new(path)?;
    tracing_subscriber::fmt()
        .json()
        .with_max_level(Level::DEBUG)
        .with_writer(writer)
        .init();
    Ok(guard)
}

enum Message {
    Event(Vec<u8>),
    Shutdown,
}

struct State {
    queue: SyncSender<Message>,
    admission: AtomicUsize,
    dropped_full: AtomicUsize,
    dropped_oversized: AtomicUsize,
    dropped_closed: AtomicUsize,
}

impl State {
    const fn new(queue: SyncSender<Message>) -> Self {
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
            if admission & CLOSED != 0 {
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
        match self.queue.try_send(Message::Event(bytes)) {
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

/// Tracing writer that enqueues each event for the writer thread.
struct FileWriter {
    state: Arc<State>,
}

impl FileWriter {
    fn new(path: &Path) -> IoResult<(Self, Guard)> {
        let file = File::create(path)?;
        let (queue, receiver) = sync_channel(QUEUE_CAPACITY);
        let state = Arc::new(State::new(queue));
        let worker = thread::Builder::new()
            .name("log-multimmit-trace".to_owned())
            .spawn(move || write_events(file, receiver))?;
        Ok((
            Self {
                state: Arc::clone(&state),
            },
            Guard {
                state,
                worker: Some(worker),
            },
        ))
    }
}

/// Buffers one event and submits it when dropped.
struct EventWriter {
    state: Arc<State>,
    bytes: Vec<u8>,
    oversized: bool,
}

impl Write for EventWriter {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        if !self.oversized && buf.len() <= EVENT_MAX_BYTES.saturating_sub(self.bytes.len()) {
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

impl Drop for EventWriter {
    fn drop(&mut self) {
        if self.oversized {
            self.state.dropped_oversized.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if !self.bytes.is_empty() {
            self.state.submit(mem::take(&mut self.bytes));
        }
    }
}

impl<'a> MakeWriter<'a> for FileWriter {
    type Writer = EventWriter;

    fn make_writer(&'a self) -> Self::Writer {
        EventWriter {
            state: Arc::clone(&self.state),
            bytes: Vec::new(),
            oversized: false,
        }
    }
}

fn write_events(mut file: File, receiver: Receiver<Message>) -> IoResult<()> {
    while let Ok(message) = receiver.recv() {
        match message {
            Message::Event(bytes) => file.write_all(&bytes)?,
            Message::Shutdown => return file.flush(),
        }
    }
    file.flush()
}

/// Keeps the writer thread running; dropping it drains accepted events and joins the thread.
pub struct Guard {
    state: Arc<State>,
    worker: Option<JoinHandle<IoResult<()>>>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.state.admission.fetch_or(CLOSED, Ordering::AcqRel);
        while self.state.admission.load(Ordering::Acquire) != CLOSED {
            thread::yield_now();
        }
        let _ = self.state.queue.send(Message::Shutdown);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_file_emission_does_not_wait_for_file_io() {
        let (queue, receiver) = sync_channel(1);
        let state = Arc::new(State::new(queue));
        state.queue.try_send(Message::Event(Vec::new())).unwrap();
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
        let state = Arc::new(State::new(queue));
        let writer = FileWriter {
            state: Arc::clone(&state),
        };
        let mut output = writer.make_writer();
        output.write_all(&vec![0; EVENT_MAX_BYTES + 1]).unwrap();
        drop(output);

        assert_eq!(state.dropped_oversized.load(Ordering::Relaxed), 1);
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
    }
}
