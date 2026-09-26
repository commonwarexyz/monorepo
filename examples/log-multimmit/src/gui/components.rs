//! Screen layout and rendering for the terminal UI.

use super::{
    UiSnapshot,
    status::{EngineHealth, EngineSnapshot},
};
use crate::progress::Chain;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Paragraph},
};
use std::{ops::Range, time::Duration};

/// Smallest pending depth the lane bars are scaled to.
const MIN_PENDING_DEPTH: u64 = 16;

const CHAIN_COLORS: [Color; 8] = [
    Color::Cyan,
    Color::Magenta,
    Color::Green,
    Color::Yellow,
    Color::Blue,
    Color::LightRed,
    Color::LightGreen,
    Color::LightMagenta,
];

/// What the UI loop does after an event.
pub(super) enum Update {
    /// Keep the current frame.
    Ignore,
    /// Draw a new frame.
    Render,
    /// Exit the UI.
    Quit,
}

#[derive(Default)]
pub(super) struct App {
    ordering: Ordering,
}

impl App {
    pub(super) fn update(&mut self, key: KeyEvent) -> Update {
        if key.kind == KeyEventKind::Release {
            return Update::Ignore;
        }

        match key.code {
            KeyCode::Esc => Update::Quit,
            KeyCode::Up => {
                self.ordering.history_offset = self.ordering.history_offset.saturating_sub(1);
                Update::Render
            }
            KeyCode::Down => {
                self.ordering.history_offset = self.ordering.history_offset.saturating_add(1);
                Update::Render
            }
            _ => Update::Ignore,
        }
    }

    pub(super) fn render(&mut self, frame: &mut Frame<'_>, area: Rect, state: &UiSnapshot) {
        if area.is_empty() {
            return;
        }

        let chain_count = state
            .engine
            .summary
            .as_ref()
            .map_or(0, |summary| summary.chains.len());
        let [lanes, ordering] = screen_panes(area, chain_count);
        render_lanes(frame, lanes, state);
        self.ordering.render(frame, ordering, state);
    }
}

fn screen_panes(area: Rect, chain_count: usize) -> [Rect; 2] {
    let desired = u16::try_from(chain_count.max(1))
        .unwrap_or(u16::MAX)
        .saturating_add(2);
    let top_height = desired.min(area.height.saturating_sub(3));
    let bottom_height = area.height.saturating_sub(top_height);
    [
        Rect::new(area.x, area.y, area.width, top_height),
        Rect::new(
            area.x,
            area.y.saturating_add(top_height),
            area.width,
            bottom_height,
        ),
    ]
}

fn render_lanes(frame: &mut Frame<'_>, area: Rect, state: &UiSnapshot) {
    let engine = &state.engine;
    let chains = engine
        .summary
        .as_ref()
        .map_or(&[][..], |summary| summary.chains.as_slice());
    let scale = chains
        .iter()
        .map(pending)
        .max()
        .unwrap_or(0)
        .max(MIN_PENDING_DEPTH);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(health_color(engine.health)))
        .title(header(state.me, engine))
        .title_bottom(footer(engine, scale));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.is_empty() {
        return;
    }
    if chains.is_empty() {
        frame.render_widget(
            Paragraph::new("waiting for the first machine inspection")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    let format = LaneFormat::measure(chains, inner.width, state.producer_chain, scale);
    let window = visible_window(chains, state.producer_chain, usize::from(inner.height));
    let lines = chains[window]
        .iter()
        .map(|progress| lane_line(progress, format))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(Text::from(lines)), inner);
}

const fn health_label(health: EngineHealth) -> &'static str {
    match health {
        EngineHealth::Starting => "starting",
        EngineHealth::Responsive => "responsive",
        EngineHealth::Unresponsive => "unresponsive",
        EngineHealth::Stopped => "stopped",
    }
}

const fn health_color(health: EngineHealth) -> Color {
    match health {
        EngineHealth::Starting => Color::Yellow,
        EngineHealth::Responsive => Color::Green,
        EngineHealth::Unresponsive | EngineHealth::Stopped => Color::Red,
    }
}

/// Blocks known locally but not yet finalized.
const fn pending(progress: &Chain) -> u64 {
    progress.known.saturating_sub(progress.finalized)
}

/// Node identity, health, view, and finality floor.
fn header(me: u32, engine: &EngineSnapshot) -> Line<'static> {
    let summary = engine.summary.as_ref();
    let view = summary.map_or(0, |summary| summary.view);
    let floor = summary.map_or(0, |summary| summary.finality_floor);
    let live = summary.is_some_and(|summary| summary.live);
    Line::from(vec![
        Span::styled(
            format!(" Node {me} "),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{} ", health_label(engine.health)),
            Style::default().fg(health_color(engine.health)),
        ),
        Span::styled(
            format!(
                "· view {view} · finality floor {floor} · {} ",
                if live { "live" } else { "idle" }
            ),
            Style::default().fg(Color::DarkGray),
        ),
    ])
}

/// Outstanding engine work, the local producer's state, the bar scale, and inspection age.
fn footer(engine: &EngineSnapshot, scale: u64) -> Line<'static> {
    let work = engine.summary.as_ref().map_or_else(
        || String::from("waiting for inspection"),
        |summary| {
            let producer = summary.producer.map_or_else(String::new, |producer| {
                format!(
                    " · C{} DA {}/{} quorum {}{}{}",
                    producer.chain,
                    producer.produced,
                    producer.certified,
                    producer.da_quorum,
                    if producer.pipeline_blocked {
                        " BLOCKED"
                    } else {
                        ""
                    },
                    if producer.production_credit {
                        ""
                    } else {
                        " no-credit"
                    },
                )
            });
            format!(
                "cache {} · outbox {} · verify {} · resolve {}{}",
                summary.cached_artifacts,
                summary.outbox_effects,
                summary.verification_jobs,
                summary.resolution_jobs,
                producer,
            )
        },
    );
    Line::styled(
        format!(
            " {work} · pending 0..={scale} · inspected {} ",
            format_age(engine.age),
        ),
        Style::default().fg(Color::DarkGray),
    )
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

/// Rows of chains to show: the local chain centered when all rows do not fit.
fn visible_window(chains: &[Chain], mine: Option<u32>, capacity: usize) -> Range<usize> {
    let visible = chains.len().min(capacity);
    let mine = chains
        .iter()
        .position(|progress| Some(progress.chain) == mine)
        .unwrap_or(0);
    let start = mine
        .saturating_sub(visible / 2)
        .min(chains.len().saturating_sub(visible));
    start..start + visible
}

#[derive(Clone, Copy)]
struct LaneFormat {
    mine: Option<u32>,
    scale: u64,
    width: u16,
    chain_width: usize,
    height_width: usize,
    pending_width: usize,
}

impl LaneFormat {
    /// Sizes every column to the widest value across `chains`.
    fn measure(chains: &[Chain], width: u16, mine: Option<u32>, scale: u64) -> Self {
        let digits = |value: u64| value.to_string().len();
        Self {
            mine,
            scale,
            width,
            chain_width: chains
                .iter()
                .map(|progress| digits(u64::from(progress.chain)))
                .max()
                .unwrap_or(1),
            height_width: chains
                .iter()
                .flat_map(|progress| [progress.finalized, progress.certified, progress.known])
                .map(digits)
                .max()
                .unwrap_or(1),
            pending_width: chains
                .iter()
                .map(|progress| digits(pending(progress)))
                .max()
                .unwrap_or(1),
        }
    }
}

fn lane_line(progress: &Chain, format: LaneFormat) -> Line<'static> {
    let chain = progress.chain;
    let mine = Some(chain) == format.mine;
    let style = Style::default().fg(chain_color(chain));
    let label_style = if mine {
        style.add_modifier(Modifier::BOLD)
    } else {
        style
    };
    let gap = pending(progress);
    let label_width = format.chain_width + 2;
    let label = Span::styled(
        format!(" C{chain:>width$}", width = format.chain_width),
        label_style,
    );
    let left = format!(
        "  finalized {:>width$} │",
        progress.finalized,
        width = format.height_width,
    );
    let base_right = format!(
        "│ known {:>height_width$} · pending {gap:>pending_width$}",
        progress.known,
        height_width = format.height_width,
        pending_width = format.pending_width,
    );
    let details = format!(
        " · DA-certified {:>height_width$} ",
        progress.certified,
        height_width = format.height_width,
    );
    let right = if usize::from(format.width)
        >= label_width + left.len() + base_right.len() + details.len() + 8
    {
        base_right + &details
    } else {
        base_right + " "
    };
    let track_width =
        usize::from(format.width).saturating_sub(label_width + left.len() + right.len());
    let (pending, empty) = pending_bar_segments(gap, format.scale, track_width);
    let mut spans = vec![
        label,
        Span::styled(left, Style::default().fg(Color::DarkGray)),
    ];
    if gap == 0 {
        spans.push(Span::styled(
            "·".repeat(track_width),
            Style::default().fg(Color::DarkGray),
        ));
    } else {
        spans.extend([
            Span::styled("━".repeat(pending), style),
            Span::styled("◆", style.add_modifier(Modifier::BOLD)),
            Span::styled("·".repeat(empty), Style::default().fg(Color::DarkGray)),
        ]);
    }
    spans.push(Span::styled(right, Style::default().fg(Color::DarkGray)));
    Line::from(spans)
}

#[derive(Default)]
struct Ordering {
    history_offset: u16,
}

impl Ordering {
    fn render(&self, frame: &mut Frame<'_>, area: Rect, state: &UiSnapshot) {
        let height = usize::from(area.height.saturating_sub(2));
        let max_scroll = state.ordering.len().saturating_sub(height);
        let history_offset = usize::from(self.history_offset).min(max_scroll);
        let index_width = state
            .ordering
            .last()
            .map_or(1, |block| block.index.to_string().len());
        let lines = state
            .ordering
            .iter()
            .rev()
            .skip(history_offset)
            .take(height)
            .map(|block| {
                Line::from(vec![
                    Span::styled(
                        format!(" #{:>index_width$} ", block.index),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("C{} H{}", block.chain, block.height),
                        Style::default()
                            .fg(chain_color(block.chain))
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!(" · {}", block.digest),
                        Style::default().fg(Color::DarkGray),
                    ),
                ])
            })
            .collect::<Vec<_>>();
        let title = state.ordering.last().map_or_else(
            || String::from(" Total order · waiting for marshal "),
            |latest| {
                format!(
                    " Total order · latest #{} · {} blocks ",
                    latest.index,
                    state.ordering.len()
                )
            },
        );
        frame.render_widget(
            Paragraph::new(Text::from(lines)).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(title)
                    .title_bottom(Line::styled(
                        " ↓ older · ↑ newer · Esc quit ",
                        Style::default().fg(Color::DarkGray),
                    )),
            ),
            area,
        );
    }
}

const fn chain_color(chain: u32) -> Color {
    CHAIN_COLORS[(chain as usize) % CHAIN_COLORS.len()]
}

fn pending_bar_segments(gap: u64, scale: u64, width: usize) -> (usize, usize) {
    if gap == 0 || width == 0 {
        return (0, width);
    }
    let tip = (u128::from(gap) * width as u128)
        .div_ceil(u128::from(scale))
        .try_into()
        .unwrap_or(width)
        .clamp(1, width);
    (tip - 1, width - tip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gui::OrderedBlock,
        progress::{Producer, Summary},
    };
    use commonware_cryptography::Hasher as _;
    use crossterm::event::{KeyEvent, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};

    fn snapshot() -> UiSnapshot {
        UiSnapshot {
            me: 0,
            producer_chain: Some(0),
            engine: EngineSnapshot {
                health: EngineHealth::Responsive,
                age: Some(Duration::from_millis(20)),
                summary: Some(Summary {
                    view: 8,
                    finality_floor: 7,
                    retired: 6,
                    live: true,
                    cached_artifacts: 4,
                    outbox_effects: 2,
                    verification_jobs: 1,
                    resolution_jobs: 0,
                    producer: None,
                    chains: vec![Chain {
                        chain: 0,
                        finalized: 9,
                        certified: 11,
                        known: 12,
                    }],
                }),
            },
            ordering: vec![
                OrderedBlock {
                    index: 4,
                    chain: 0,
                    height: 9,
                    digest: commonware_cryptography::Sha256::hash(&[b"OLDER_SENTINEL"]),
                },
                OrderedBlock {
                    index: 5,
                    chain: 0,
                    height: 10,
                    digest: commonware_cryptography::Sha256::hash(&[b"NEWER_SENTINEL"]),
                },
            ],
        }
    }

    fn render(app: &mut App, snapshot: &UiSnapshot) -> String {
        let backend = TestBackend::new(90, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| app.render(frame, frame.area(), snapshot))
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn keyboard_scrolls_ordering_and_release_is_ignored() {
        let mut app = App::default();
        let update = app.update(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert!(matches!(update, Update::Render));
        assert_eq!(app.ordering.history_offset, 1);

        assert!(matches!(
            app.update(KeyEvent::new_with_kind(
                KeyCode::Up,
                KeyModifiers::NONE,
                KeyEventKind::Release,
            )),
            Update::Ignore
        ));
        assert_eq!(app.ordering.history_offset, 1);

        app.update(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.ordering.history_offset, 0);
        assert!(matches!(
            app.update(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE)),
            Update::Ignore
        ));
        assert!(matches!(
            app.update(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            Update::Quit
        ));
    }

    #[test]
    fn screen_split_fills_the_area() {
        let area = Rect::new(3, 4, 80, 19);
        let [top, bottom] = screen_panes(area, 6);
        assert_eq!(top.height, 8);
        assert_eq!(bottom.height, 11);
        assert_eq!(top.bottom(), bottom.y);
        assert_eq!(bottom.bottom(), area.bottom());
    }

    #[test]
    fn producer_pane_tracks_the_number_of_chains() {
        let area = Rect::new(0, 2, 80, 30);
        assert_eq!(screen_panes(area, 1)[0].height, 3);
        assert_eq!(screen_panes(area, 6)[0].height, 8);
        assert_eq!(screen_panes(area, 100)[0].height, 27);
    }

    #[test]
    fn one_screen_renders_lanes_and_total_order() {
        let snapshot = snapshot();
        let mut app = App::default();

        let screen = render(&mut app, &snapshot);
        assert!(screen.contains("C0"));
        assert!(screen.contains("finality floor 7"));
        assert!(screen.contains("Total order"));
        assert!(screen.contains("C0 H10"));
        assert!(screen.contains("#4"));
        assert!(screen.find("#5").unwrap() < screen.find("#4").unwrap());
        assert_eq!(screen.matches('◆').count(), 1);
    }

    #[test]
    fn inspection_age_is_compact() {
        assert_eq!(format_age(None), "never");
        assert_eq!(format_age(Some(Duration::from_millis(27))), "27ms ago");
        assert_eq!(format_age(Some(Duration::from_millis(2_340))), "2.3s ago");
    }

    #[test]
    fn footer_reports_the_local_producer() {
        let mut engine = snapshot().engine;
        let text = |engine: &EngineSnapshot| {
            footer(engine, 16)
                .spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
        };
        assert!(text(&engine).contains("pending 0..=16 · inspected 20ms ago"));
        assert!(!text(&engine).contains("DA"));
        engine.summary.as_mut().unwrap().producer = Some(Producer {
            chain: 3,
            produced: 12,
            certified: 10,
            da_quorum: 4,
            pipeline_blocked: true,
            production_credit: false,
        });
        assert!(text(&engine).contains("C3 DA 12/10 quorum 4 BLOCKED no-credit"));
        engine.summary = None;
        assert!(text(&engine).contains("waiting for inspection"));
    }

    #[test]
    fn pending_bars_share_the_depth_scale() {
        let mut snapshot = snapshot();
        let screen = render(&mut App::default(), &snapshot);
        assert!(screen.contains("pending 0..=16"));
        let chain = &mut snapshot.engine.summary.as_mut().unwrap().chains[0];
        chain.known = chain.finalized + 17;
        let screen = render(&mut App::default(), &snapshot);
        assert!(screen.contains("pending 0..=17"));
        assert_eq!(pending_bar_segments(0, 16, 16), (0, 16));
        assert_eq!(pending_bar_segments(8, 16, 16), (7, 8));
        assert_eq!(pending_bar_segments(16, 32, 16), (7, 8));
    }

    #[test]
    fn visible_window_centers_the_local_chain() {
        let chains = (0..10)
            .map(|chain| Chain {
                chain,
                finalized: 0,
                certified: 0,
                known: 0,
            })
            .collect::<Vec<_>>();
        assert_eq!(visible_window(&chains, Some(7), 4), 5..9);
        assert_eq!(visible_window(&chains, Some(9), 4), 6..10);
        assert_eq!(visible_window(&chains, None, 4), 0..4);
        assert_eq!(visible_window(&chains, Some(7), 20), 0..10);
    }

    #[test]
    fn lane_format_measures_the_widest_values() {
        let chains = [
            Chain {
                chain: 3,
                finalized: 9,
                certified: 10,
                known: 1_000,
            },
            Chain {
                chain: 12,
                finalized: 0,
                certified: 0,
                known: 0,
            },
        ];
        let format = LaneFormat::measure(&chains, 80, Some(3), 16);
        assert_eq!(format.chain_width, 2);
        assert_eq!(format.height_width, 4);
        assert_eq!(format.pending_width, 3);
        assert_eq!(format.mine, Some(3));
        assert_eq!(format.scale, 16);
        assert_eq!(format.width, 80);
    }

    #[test]
    fn lane_labels_align_and_only_the_local_label_is_bold() {
        let progress = Chain {
            chain: 7,
            finalized: 9,
            certified: 10,
            known: 11,
        };
        let format = LaneFormat {
            mine: Some(7),
            scale: 16,
            width: 100,
            chain_width: 2,
            height_width: 2,
            pending_width: 1,
        };
        let local = lane_line(&progress, format);
        let remote = lane_line(
            &Chain {
                chain: 12,
                ..progress
            },
            format,
        );

        assert_eq!(local.spans[0].content.chars().count(), 4);
        assert_eq!(remote.spans[0].content.chars().count(), 4);
        assert!(local.spans[0].style.add_modifier.contains(Modifier::BOLD));
        assert!(!remote.spans[0].style.add_modifier.contains(Modifier::BOLD));
        assert!(!local.spans[1].style.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn histogram_boundaries_align_across_height_widths() {
        let format = LaneFormat {
            mine: Some(0),
            scale: 16,
            width: 100,
            chain_width: 1,
            height_width: 2,
            pending_width: 1,
        };
        let mut short = snapshot().engine.summary.unwrap().chains[0];
        short.finalized = 1;
        let mut tall = short;
        tall.chain = 1;
        tall.finalized = 10;
        tall.known = 12;

        let short = lane_line(&short, format)
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        let tall = lane_line(&tall, format)
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert_eq!(short.find('│'), tall.find('│'));
    }
}
