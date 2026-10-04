// An owned span produced inside a macro, like the loop variable that
// `#[instrument(follows_from = ...)]` iterates with, has no caller-written source
// to borrow, so the lint reports the macro call without a suggestion.

mod tracing {
    pub struct Id;

    pub struct Span;

    impl Span {
        pub fn follows_from(&self, from: impl Into<Option<Id>>) -> &Self {
            let _ = from.into();
            self
        }
    }

    impl From<Span> for Option<Id> {
        fn from(_: Span) -> Self {
            None
        }
    }
}

macro_rules! follows_from_all {
    ($span:expr, $causes:expr) => {
        for cause in $causes {
            $span.follows_from(cause);
        }
    };
}

fn main() {
    let span = tracing::Span;
    follows_from_all!(span, vec![tracing::Span, tracing::Span]);
}
