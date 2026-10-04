// Fixtures for the `owned_span_parent` lint, compiled against the real
// `tracing` crate so the lint sees its actual types, re-exports, and macro
// expansions.

use tracing::{Span, info, info_span};

mod unrelated {
    pub struct Span;

    impl Span {
        pub fn child_of(parent: tracing::Span) -> tracing::Span {
            parent
        }
    }
}

mod lookalike {
    pub mod tracing {
        pub struct Span;
    }
}

impl From<lookalike::tracing::Span> for Option<tracing::span::Id> {
    fn from(_: lookalike::tracing::Span) -> Self {
        None
    }
}

#[tracing::instrument(skip_all, follows_from = causes)]
fn process(causes: Vec<Span>) {}

fn main() {
    let span = Span::none();
    let cause = Span::none();
    let metadata = info_span!("component.template").metadata().unwrap();
    let values = metadata.fields().value_set(&[]);
    let dispatch = tracing::Dispatch::none();

    // Every tracing function that converts an owned span into an ID, including
    // one called through a stored function item.
    info!(parent: span.clone(), "component.processed");
    span.follows_from(cause.clone());
    Span::follows_from(&span, cause.clone());
    let _child = Span::child_of_with(span.clone(), metadata, &values, &dispatch);
    let _event = tracing::Event::new_child_of(span.clone(), metadata, &values);
    let child_of = Span::child_of;
    let _child = child_of(span.clone(), metadata, &values);
    process(vec![Span::none()]);

    // Unrelated owners, lookalike types, references, and IDs are not flagged.
    let _held = unrelated::Span::child_of(span.clone());
    span.follows_from(lookalike::tracing::Span);
    let _process = info_span!(parent: &span, "component.process");
    let _process = info_span!(parent: span.id(), "component.process");

    // Consuming the only handle is the case that panics with the registry.
    let _process = info_span!(parent: span, "component.process");
}
