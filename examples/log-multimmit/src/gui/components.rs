use super::{EngineChainProgress, EngineHealth, UiSnapshot, format_age};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Paragraph},
};

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

pub(super) enum Effect {
    Quit,
}

pub(super) struct Update {
    pub(super) effect: Option<Effect>,
    pub(super) render: bool,
}

impl Update {
    const fn none() -> Self {
        Self {
            effect: None,
            render: false,
        }
    }

    const fn render() -> Self {
        Self {
            effect: None,
            render: true,
        }
    }

    const fn effect(effect: Effect) -> Self {
        Self {
            effect: Some(effect),
            render: false,
        }
    }
}

#[derive(Default)]
pub(super) struct App {
    ordering: Ordering,
}

impl App {
    pub(super) fn update(&mut self, key: KeyEvent) -> Update {
        if key.kind == KeyEventKind::Release {
            return Update::none();
        }

        match key.code {
            KeyCode::Esc => Update::effect(Effect::Quit),
            KeyCode::Up => {
                self.ordering.history_offset = self.ordering.history_offset.saturating_sub(1);
                Update::render()
            }
            KeyCode::Down => {
                self.ordering.history_offset = self.ordering.history_offset.saturating_add(1);
                Update::render()
            }
            _ => Update::none(),
        }
    }

    pub(super) fn render(&mut self, frame: &mut Frame<'_>, area: Rect, state: &UiSnapshot) {
        if area.is_empty() {
            return;
        }

        let chain_count = state
            .engine
            .inspection
            .as_ref()
            .map_or(0, |inspection| inspection.chains.len());
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
    let status = &state.engine;
    let (health, health_color) = match status.health {
        EngineHealth::Starting => ("starting", Color::Yellow),
        EngineHealth::Responsive => ("responsive", Color::Green),
        EngineHealth::Unresponsive => ("unresponsive", Color::Red),
        EngineHealth::Stopped => ("stopped", Color::Red),
    };
    let machine = status.inspection.as_ref();
    let view = machine.map_or(0, |inspection| inspection.view);
    let floor = machine.map_or(0, |inspection| inspection.finality_floor);
    let live = machine.is_some_and(|inspection| inspection.live);
    let work = machine.map_or_else(
        || String::from("waiting for inspection"),
        |inspection| {
            let producer = inspection.producer.map_or_else(String::new, |producer| {
                let recovery = if producer.recovery_active {
                    "active"
                } else if producer.recovery_pending {
                    "pending"
                } else if producer.recovery_ready {
                    "ready"
                } else {
                    "shares"
                };
                format!(
                    " · C{} DA {}/{} shares {}/{} recovery {}{}{}",
                    producer.chain,
                    producer.produced,
                    producer.certified,
                    producer.vote_shares,
                    producer.da_quorum,
                    recovery,
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
                inspection.cached_artifacts,
                inspection.outbox_effects,
                inspection.verification_jobs,
                inspection.resolution_jobs,
                producer,
            )
        },
    );
    let chains = machine.map_or(&[][..], |inspection| inspection.chains.as_slice());
    let max_gap = chains
        .iter()
        .map(|progress| progress.known.saturating_sub(progress.finalized))
        .max()
        .unwrap_or(0);
    let scale = pending_depth_scale(max_gap);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(health_color))
        .title(Line::from(vec![
            Span::styled(
                format!(" Node {} ", state.me),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{health} "), Style::default().fg(health_color)),
            Span::styled(
                format!(
                    "· view {view} · finality floor {floor} · {} ",
                    if live { "live" } else { "idle" }
                ),
                Style::default().fg(Color::DarkGray),
            ),
        ]))
        .title_bottom(Line::styled(
            format!(
                " {work} · pending 0..={scale} · inspected {} ",
                format_age(status.age),
            ),
            Style::default().fg(Color::DarkGray),
        ));
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

    let capacity = usize::from(inner.height);
    let visible = chains.len().min(capacity);
    let chain_width = chains
        .iter()
        .map(|progress| progress.chain.to_string().len())
        .max()
        .unwrap_or(1);
    let height_width = chains
        .iter()
        .flat_map(|progress| [progress.finalized, progress.certified, progress.known])
        .map(|height| height.to_string().len())
        .max()
        .unwrap_or(1);
    let pending_width = chains
        .iter()
        .map(|progress| {
            progress
                .known
                .saturating_sub(progress.finalized)
                .to_string()
                .len()
        })
        .max()
        .unwrap_or(1);
    let format = LaneFormat {
        mine: state.producer_chain,
        scale,
        width: inner.width,
        chain_width,
        height_width,
        pending_width,
    };
    let me_index = chains
        .iter()
        .position(|progress| Some(progress.chain) == state.producer_chain)
        .unwrap_or(0);
    let start = me_index
        .saturating_sub(visible / 2)
        .min(chains.len().saturating_sub(visible));
    let lines = chains
        .iter()
        .skip(start)
        .take(visible)
        .map(|progress| lane_line(progress.chain, progress, format))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(Text::from(lines)), inner);
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

fn lane_line(chain: u32, progress: &EngineChainProgress, format: LaneFormat) -> Line<'static> {
    let mine = Some(chain) == format.mine;
    let style = Style::default().fg(chain_color(chain));
    let label_style = if mine {
        style.add_modifier(Modifier::BOLD)
    } else {
        style
    };
    let gap = progress.known.saturating_sub(progress.finalized);
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

const fn pending_depth_scale(max_gap: u64) -> u64 {
    if max_gap < MIN_PENDING_DEPTH {
        return MIN_PENDING_DEPTH;
    }
    max_gap
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
    use crate::gui::{EngineInspection, EngineSnapshot, OrderedBlock, UiSnapshot};
    use commonware_cryptography::Hasher as _;
    use crossterm::event::{KeyEvent, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};

    fn snapshot() -> UiSnapshot {
        UiSnapshot {
            me: 0,
            producer_chain: Some(0),
            engine: EngineSnapshot {
                health: EngineHealth::Responsive,
                age: Some(std::time::Duration::from_millis(20)),
                inspection: Some(EngineInspection {
                    view: 8,
                    finality_floor: 7,
                    live: true,
                    cached_artifacts: 4,
                    outbox_effects: 2,
                    verification_jobs: 1,
                    resolution_jobs: 0,
                    producer: None,
                    chains: vec![EngineChainProgress {
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
        assert!(update.render);
        assert_eq!(app.ordering.history_offset, 1);

        app.update(KeyEvent::new_with_kind(
            KeyCode::Up,
            KeyModifiers::NONE,
            KeyEventKind::Release,
        ));
        assert_eq!(app.ordering.history_offset, 1);

        app.update(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.ordering.history_offset, 0);
        assert!(matches!(
            app.update(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
                .effect,
            Some(Effect::Quit)
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
    fn pending_bars_share_the_depth_scale() {
        assert_eq!(pending_depth_scale(8), 16);
        assert_eq!(pending_depth_scale(17), 17);
        assert_eq!(pending_bar_segments(0, 16, 16), (0, 16));
        assert_eq!(pending_bar_segments(8, 16, 16), (7, 8));
        assert_eq!(pending_bar_segments(16, 32, 16), (7, 8));
    }

    #[test]
    fn lane_labels_align_and_only_the_local_label_is_bold() {
        let progress = EngineChainProgress {
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
        let local = lane_line(7, &progress, format);
        let remote = lane_line(12, &progress, format);

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
        let mut short = snapshot().engine.inspection.unwrap().chains[0];
        short.finalized = 1;
        let mut tall = short;
        tall.chain = 1;
        tall.finalized = 10;
        tall.known = 12;

        let short = lane_line(0, &short, format)
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        let tall = lane_line(1, &tall, format)
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert_eq!(short.find('│'), tall.find('│'));
    }
}
