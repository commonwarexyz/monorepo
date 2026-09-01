//! Terminal UI for observing Multimmit consensus and producer-chain progress.

mod components;
mod ordering;
mod status;

use crate::progress::Summary;
use commonware_consensus::multimmit::Inspector;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::{channel::mpsc, futures::OptionFuture};
use components::{App, Update};
use crossterm::{
    event::{self, Event as CrosstermEvent, KeyEvent},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ordering::OrderedBlock;
pub use ordering::OrderedReporter;
use ratatui::{Terminal, backend::CrosstermBackend};
use status::{EngineSnapshot, EngineStatus};
use std::{
    future::Future,
    io::stdout,
    pin::Pin,
    time::{Duration, Instant},
};

/// How often the UI requests a fresh engine inspection.
const INSPECTION_INTERVAL: Duration = Duration::from_millis(250);

/// How long the keyboard thread waits for input before requesting a redraw.
const INPUT_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Keyboard events buffered for the UI loop.
const INPUT_QUEUE: usize = 100;

/// Something the UI loop reacts to.
enum Event<C> {
    /// Marshal delivered a block in the total order.
    Delivery,
    /// The user pressed a key.
    Input(KeyEvent),
    /// No input arrived within [`INPUT_POLL_INTERVAL`].
    Tick,
    /// An engine inspection completed.
    Inspection(Inspected<C>),
}

/// One completed engine inspection.
struct Inspected<C> {
    /// Clock the next inspection waits on.
    clock: C,
    /// The inspection, or `None` once the engine stopped.
    summary: Option<Summary>,
}

/// An engine inspection in flight.
type PendingInspection<C> = Pin<Box<dyn Future<Output = Inspected<C>> + Send>>;

/// Everything one frame renders.
struct UiSnapshot {
    me: u32,
    producer_chain: Option<u32>,
    engine: EngineSnapshot,
    ordering: Vec<OrderedBlock>,
}

/// Terminal UI showing engine health, producer-chain progress, and the total order.
pub struct Gui<E: Clock + Spawner + Metrics> {
    context: E,
    status: EngineStatus,
    me: u32,
    producer_chain: Option<u32>,
    ordering: OrderedReporter,
    redraws: mpsc::Receiver<()>,
}

impl<E: Clock + Spawner + Metrics> Gui<E> {
    /// Creates the UI for participant `me`, which produces `producer_chain` if set.
    pub fn new(context: E, me: u32, producer_chain: Option<u32>) -> Self {
        let (ordering, redraws) = OrderedReporter::channel();
        Self {
            context,
            status: EngineStatus::default(),
            me,
            producer_chain,
            ordering,
            redraws,
        }
    }

    /// Returns the marshal reporter that feeds the total-order pane.
    pub fn reporter(&self) -> OrderedReporter {
        self.ordering.clone()
    }

    fn snapshot(&self, now: Instant) -> UiSnapshot {
        UiSnapshot {
            me: self.me,
            producer_chain: self.producer_chain,
            engine: self.status.snapshot(now),
            ordering: self.ordering.snapshot(),
        }
    }

    /// Inspects the engine after `delay`, returning `clock` for the next inspection.
    fn inspect(
        clock: E,
        inspector: &Inspector<Sha256Digest>,
        delay: Duration,
    ) -> PendingInspection<E> {
        let inspector = inspector.clone();
        Box::pin(async move {
            clock.sleep(delay).await;
            let summary = inspector
                .inspect()
                .await
                .map(|inspection| Summary::new(&inspection));
            Inspected { clock, summary }
        })
    }

    /// Runs the UI until the user quits, inspecting the engine from the same loop.
    ///
    /// Inspections never block rendering, so a stuck engine leaves its last inspection visible
    /// and the UI derives unresponsiveness from the inspection's age.
    pub async fn run(mut self, inspector: Inspector<Sha256Digest>) {
        enable_raw_mode().unwrap();
        let mut stdout = stdout();
        execute!(stdout, EnterAlternateScreen).unwrap();
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend).unwrap();

        let (tx, mut rx) = mpsc::channel(INPUT_QUEUE);
        self.context
            .child("keyboard")
            .dedicated()
            .spawn(|_| async move {
                loop {
                    match event::poll(INPUT_POLL_INTERVAL) {
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
        let mut inspection = OptionFuture::from(Some(Self::inspect(
            self.context.child("inspection"),
            &inspector,
            Duration::ZERO,
        )));
        loop {
            if render {
                let snapshot = self.snapshot(Instant::now());
                terminal
                    .draw(|frame| app.render(frame, frame.area(), &snapshot))
                    .unwrap();
            }

            let event = select! {
                event = rx.recv() => event,
                redraw = self.redraws.recv() => redraw.map(|()| Event::Delivery),
                inspected = &mut inspection => Some(Event::Inspection(inspected)),
            };
            let Some(event) = event else {
                break;
            };
            let update = match event {
                Event::Input(key) => app.update(key),
                Event::Delivery | Event::Tick => Update::Render,
                Event::Inspection(Inspected {
                    clock,
                    summary: Some(summary),
                }) => {
                    self.status.observed(summary, Instant::now());
                    inspection = Some(Self::inspect(clock, &inspector, INSPECTION_INTERVAL)).into();
                    Update::Render
                }
                Event::Inspection(Inspected { summary: None, .. }) => {
                    self.status.stopped();
                    inspection = OptionFuture::default();
                    Update::Render
                }
            };
            match update {
                Update::Ignore => render = false,
                Update::Render => render = true,
                Update::Quit => break,
            }
        }

        disable_raw_mode().unwrap();
        execute!(terminal.backend_mut(), LeaveAlternateScreen).unwrap();
        terminal.show_cursor().unwrap();
    }
}
