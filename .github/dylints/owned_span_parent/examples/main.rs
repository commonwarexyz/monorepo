// These fixtures compile against the real `tracing` crate so the lint sees its
// actual types, re-exports, and macro expansions.

use tracing::{Span, info_span, span::Id};

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

impl From<lookalike::tracing::Span> for Option<Id> {
    fn from(_: lookalike::tracing::Span) -> Self {
        None
    }
}

fn keep(parent: impl Into<Option<Id>>, kept: Span) -> (Span, Span) {
    (info_span!(parent: parent, "component.keep"), kept)
}

#[tracing::instrument(skip_all, follows_from = causes)]
fn process(causes: Vec<Span>) {}

fn main() {
    let span = Span::none();
    let cause = Span::none();

    // Owned spans converted into IDs by tracing methods, explicit conversions, and
    // helpers. Only the converted argument of `keep` is flagged.
    span.follows_from(cause.clone());
    Span::follows_from(&span, cause.clone());
    let follows_from = Span::follows_from;
    follows_from(&span, cause.clone());
    let _id: Option<Id> = cause.clone().into();
    let _id = Option::<Id>::from(cause.clone());
    let _kept = keep(cause.clone(), cause.clone());
    process(vec![Span::none()]);

    // Borrowed spans, IDs, unrelated owners, and lookalike types are not flagged.
    let _process = info_span!(parent: &span, "component.process");
    let _process = info_span!(parent: span.id(), "component.process");
    let _held = unrelated::Span::child_of(span.clone());
    span.follows_from(lookalike::tracing::Span);

    // Consuming the only handle is the case that panics with the registry.
    let _process = info_span!(parent: span, "component.process");
}
