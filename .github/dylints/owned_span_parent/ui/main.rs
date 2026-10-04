// run-rustfix
// Self-contained fixtures for the `owned_span_parent` lint. The stubs mirror the
// tracing functions that take a span parent or `follows_from` source as
// `impl Into<Option<Id>>`, and the macros expand to them like tracing's do, so
// the test needs no external dependencies.

mod tracing {
    pub mod span {
        pub struct Id;

        #[derive(Clone)]
        pub struct Span;

        impl Span {
            pub fn child_of(parent: impl Into<Option<Id>>) -> Span {
                let _ = parent.into();
                Span
            }

            pub fn follows_from(&self, from: impl Into<Option<Id>>) -> &Self {
                let _ = from.into();
                self
            }

            pub fn id(&self) -> Option<Id> {
                None
            }
        }

        impl From<&Span> for Option<Id> {
            fn from(_: &Span) -> Self {
                None
            }
        }

        impl From<Span> for Option<Id> {
            fn from(_: Span) -> Self {
                None
            }
        }
    }

    pub mod event {
        use std::marker::PhantomData;

        pub struct Event<'a>(PhantomData<&'a ()>);

        impl Event<'_> {
            pub fn child_of(parent: impl Into<Option<super::span::Id>>) {
                let _ = parent.into();
            }
        }
    }

    pub use self::{event::Event, span::Span};
}

macro_rules! info_span {
    (parent: $parent:expr, $name:literal) => {{
        let _ = $name;
        tracing::Span::child_of($parent)
    }};
}

macro_rules! info {
    (parent: $parent:expr, $message:literal) => {{
        let _ = $message;
        tracing::Event::child_of($parent)
    }};
}

fn view_span() -> tracing::Span {
    tracing::Span
}

fn main() {
    let span = tracing::Span;
    let cause = tracing::Span;

    // Owned spans are dropped before tracing uses their IDs.
    let _process = info_span!(parent: span.clone(), "component.process");
    let _process = info_span!(parent: view_span(), "component.process");
    info!(parent: span.clone(), "component.processed");
    span.follows_from(cause.clone());
    tracing::Span::follows_from(&span, cause.clone());
    let process_span = |parent: tracing::Span| info_span!(parent: parent, "component.process");
    let _process = process_span(span.clone());

    // Borrowed spans, and IDs of spans that stay alive, are allowed.
    let _process = info_span!(parent: &span, "component.process");
    let _process = info_span!(parent: span.id(), "component.process");
    let _process = info_span!(parent: None, "component.process");
    info!(parent: &span, "component.processed");
    span.follows_from(&cause);
    span.follows_from(cause.id());

    // Consuming the only handle is the case that panics with a real subscriber.
    let _process = info_span!(parent: span, "component.process");
}
