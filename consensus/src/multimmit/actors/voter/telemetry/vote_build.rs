//! The span of this node's vote-body pass, from its start to its body or abandonment.
//!
//! A span's timestamps are taken when it opens and closes, so a span opened after the poll that
//! began and finished a pass would cover none of its work. The voter therefore opens the span
//! immediately before the poll the machine reports will begin the pass, and closes it after the
//! poll that reports the body.

use crate::{multimmit::machine::VoteBuild, types::Round};
use commonware_runtime::telemetry::traces::TracedExt as _;
use tracing::{Span, info_span};

/// Records one `multimmit.vote.build` span per vote-body pass the core reports.
#[derive(Default)]
pub(crate) struct VoteBuildTrace {
    /// The span of the pass in flight, if any.
    span: Option<Span>,
    /// The span opened for a pass the next poll begins, until that poll reports the start.
    opened: Option<OpenedSpan>,
}

/// A span opened before the poll that begins its pass.
struct OpenedSpan {
    round: Round,
    span: Span,
}

/// Opens one pass's span under the current span.
fn vote_build_span(round: Round, extension_bound: usize) -> Span {
    info_span!(
        "multimmit.vote.build",
        epoch = round.epoch().get().traced(),
        view = round.view().get().traced(),
        extension_bound = extension_bound.traced(),
        complete = false,
        eligible_extensions = tracing::field::Empty,
        short_chains = tracing::field::Empty,
        extension_cap_chains = tracing::field::Empty,
        late_da_chains = tracing::field::Empty,
    )
}

impl VoteBuildTrace {
    /// Opens the span of the pass for `round` that the next poll begins.
    ///
    /// The voter calls this immediately before that poll, so the span covers it.
    pub(crate) fn open(&mut self, round: Round, extension_bound: usize) {
        self.opened = Some(OpenedSpan {
            round,
            span: vote_build_span(round, extension_bound),
        });
    }

    /// Applies the vote-pass lifecycle events of one core poll.
    ///
    /// A started pass takes the span opened before the poll, or opens one under the current span
    /// when none was, a completed pass records its statistics and closes the span, and an abandoned
    /// pass closes it with `complete = false`. A span opened before the poll always sees its pass
    /// start in that poll.
    pub(crate) fn observe(&mut self, builds: impl IntoIterator<Item = VoteBuild>) {
        for build in builds {
            match build {
                VoteBuild::Started {
                    round,
                    extension_bound,
                } => {
                    let opened = self.opened.take();
                    debug_assert!(
                        opened.as_ref().is_none_or(|opened| opened.round == round),
                        "a span opened before a poll belongs to the pass it begins"
                    );
                    self.span = Some(opened.map_or_else(
                        || vote_build_span(round, extension_bound),
                        |opened| opened.span,
                    ));
                }
                VoteBuild::Completed(stats) => {
                    let Some(span) = self.span.take() else {
                        continue;
                    };
                    span.record("eligible_extensions", stats.eligible_extensions.traced());
                    span.record("short_chains", stats.short_chains.traced());
                    span.record("extension_cap_chains", stats.extension_cap_chains.traced());
                    span.record("late_da_chains", stats.late_da_chains.traced());
                    span.record("complete", true);
                }
                VoteBuild::Abandoned => self.span = None,
            }
        }
        debug_assert!(
            self.opened.is_none(),
            "a span opened before a poll sees its pass start in that poll"
        );
        self.opened = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{machine::VoteBuildStats, testing::SpanRecorder},
        types::{Epoch, Round, View},
    };

    const STARTED: VoteBuild = VoteBuild::Started {
        round: Round::new(Epoch::new(7), View::new(3)),
        extension_bound: 2,
    };

    const STATS: VoteBuildStats = VoteBuildStats {
        eligible_extensions: 1,
        short_chains: 2,
        extension_cap_chains: 3,
        late_da_chains: 4,
    };

    #[test]
    fn completed_pass_records_its_statistics_under_the_current_span() {
        let recorder = SpanRecorder::default();
        recorder.capture(|| {
            let round = info_span!("test.round");
            let mut trace = VoteBuildTrace::default();
            round.in_scope(|| trace.observe(vec![STARTED]));
            trace.observe(vec![VoteBuild::Completed(STATS)]);
        });

        let spans = recorder.spans();
        let [round, build] = &spans[..] else {
            panic!("one round span and one vote-build span");
        };
        assert_eq!(build.name, "multimmit.vote.build");
        assert_eq!(build.parent, Some(round.id));
        assert!(build.closed());
        for (field, value) in [
            ("epoch", "7"),
            ("view", "3"),
            ("extension_bound", "2"),
            ("complete", "true"),
            ("eligible_extensions", "1"),
            ("short_chains", "2"),
            ("extension_cap_chains", "3"),
            ("late_da_chains", "4"),
        ] {
            build.fields.expect_field_exact(field, value).unwrap();
        }
    }

    #[test]
    fn pass_span_stays_open_until_its_body_completes() {
        let recorder = SpanRecorder::default();
        recorder.capture(|| {
            let mut trace = VoteBuildTrace::default();
            trace.observe(vec![STARTED]);
            trace.observe(Vec::new());
            assert!(!recorder.spans()[0].closed());
            trace.observe(vec![VoteBuild::Completed(STATS)]);
        });

        let spans = recorder.spans();
        assert!(spans[0].closed());
        spans[0]
            .fields
            .expect_field_exact("complete", "true")
            .unwrap();
    }

    #[test]
    fn abandoned_pass_closes_incomplete() {
        let recorder = SpanRecorder::default();
        recorder.capture(|| {
            let mut trace = VoteBuildTrace::default();
            trace.observe(vec![STARTED, VoteBuild::Abandoned, STARTED]);
            trace.observe(vec![VoteBuild::Completed(STATS)]);
        });

        let spans = recorder.spans();
        let [abandoned, completed] = &spans[..] else {
            panic!("two vote-build spans");
        };
        assert!(abandoned.closed() && completed.closed());
        abandoned
            .fields
            .expect_field_exact("complete", "false")
            .unwrap();
        assert!(
            abandoned
                .fields
                .expect_field_exact("late_da_chains", "4")
                .is_err()
        );
        completed
            .fields
            .expect_field_exact("complete", "true")
            .unwrap();
    }

    #[test]
    fn span_opened_before_a_poll_covers_the_pass_it_begins() {
        let recorder = SpanRecorder::default();
        recorder.capture(|| {
            let round = info_span!("test.round");
            let mut trace = VoteBuildTrace::default();
            // The voter opens the span before the poll, the poll begins and completes the pass,
            // and the voter observes both events after it.
            round.in_scope(|| trace.open(Round::new(Epoch::new(7), View::new(3)), 2));
            tracing::info!("poll");
            trace.observe(vec![STARTED, VoteBuild::Completed(STATS)]);
        });

        let events = recorder.events();
        let spans = recorder.spans();
        let ([poll], [round, build]) = (&events[..], &spans[..]) else {
            panic!("one poll event, one round span, and one vote-build span");
        };
        assert!(
            build.opened_at < poll.at && build.closed_at.is_some_and(|closed| poll.at < closed)
        );
        assert_eq!(build.parent, Some(round.id));
        for (field, value) in [
            ("epoch", "7"),
            ("view", "3"),
            ("extension_bound", "2"),
            ("complete", "true"),
        ] {
            build.fields.expect_field_exact(field, value).unwrap();
        }
    }
}
