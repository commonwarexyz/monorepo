use commonware_runtime::telemetry::traces::collector::EventMetadata;
use commonware_utils::sync::Mutex;
use std::{collections::BTreeMap, sync::Arc};
use tracing::{Subscriber, span};
use tracing_subscriber::{Layer, layer::Context, prelude::*};

struct RecordedSpan {
    name: &'static str,
    fields: EventMetadata,
    closed: bool,
}

#[derive(Clone, Default)]
struct Spans(Arc<Mutex<BTreeMap<u64, RecordedSpan>>>);

impl<S: Subscriber> Layer<S> for Spans {
    fn on_new_span(&self, attributes: &span::Attributes<'_>, id: &span::Id, _: Context<'_, S>) {
        let mut fields = EventMetadata::default();
        attributes.record(&mut fields);
        self.0.lock().insert(
            id.into_u64(),
            RecordedSpan {
                name: attributes.metadata().name(),
                fields,
                closed: false,
            },
        );
    }

    fn on_record(&self, id: &span::Id, values: &span::Record<'_>, _: Context<'_, S>) {
        values.record(&mut self.0.lock().get_mut(&id.into_u64()).unwrap().fields);
    }

    fn on_close(&self, id: span::Id, _: Context<'_, S>) {
        self.0.lock().get_mut(&id.into_u64()).unwrap().closed = true;
    }
}

#[test]
fn vote_snapshot_trace_distinguishes_later_da_choices() {
    let spans = Spans::default();
    let subscriber = tracing_subscriber::registry().with(spans.clone());
    tracing::subscriber::with_default(subscriber, || {
        super::vote_body_pass_ignores_later_da_choices();
    });

    let spans = spans.0.lock();
    assert_eq!(
        spans.len(),
        1,
        "one aggregate span covers the entire vote build"
    );
    let (_, build) = spans
        .iter()
        .find(|(_, span)| span.name == "multimmit.vote.build")
        .unwrap();
    assert!(build.closed);
    build.fields.expect_field_exact("complete", "true").unwrap();
    build.fields.expect_field_exact("view", "1").unwrap();
    for (field, value) in [
        ("extension_bound", "1"),
        ("eligible_extensions", "1"),
        ("short_chains", "0"),
        ("extension_cap_chains", "1"),
        ("late_da_chains", "1"),
    ] {
        build.fields.expect_field_exact(field, value).unwrap();
    }
}
