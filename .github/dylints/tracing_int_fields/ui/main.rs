// Self-contained fixtures for the `tracing_int_fields` lint. The stubs mimic the
// `tracing::field::display`/`debug` calls that `%x`/`?x` expand to inside tracing
// macros, plus integer newtypes and a composite type, so the test needs no
// external dependencies.

macro_rules! info_span {
    ($name:literal, $field:ident = %$value:expr) => {{
        let _ = $name;
        let _ = tracing::field::display(&$value);
    }};
    ($name:literal, $field:ident = ?$value:expr) => {{
        let _ = $name;
        let _ = tracing::field::debug(&$value);
    }};
}

macro_rules! debug {
    ($field:ident = %$value:expr, $message:literal) => {{
        let _ = $message;
        let _ = tracing::field::display(&$value);
    }};
}

mod tracing {
    pub mod field {
        pub struct DisplayValue<T>(pub T);
        pub fn display<T>(value: T) -> DisplayValue<T> {
            DisplayValue(value)
        }
        pub fn debug<T>(value: T) -> DisplayValue<T> {
            DisplayValue(value)
        }
    }
}

mod types {
    use std::marker::PhantomData;

    #[derive(Clone, Copy)]
    pub struct View(pub u64);
    #[derive(Clone, Copy)]
    pub struct Epoch(pub u64);
    #[derive(Clone, Copy)]
    pub struct Height(pub u64);

    impl View {
        pub const fn get(self) -> u64 {
            self.0
        }
    }

    // A single-integer newtype that carries a zero-sized marker, e.g.
    // Delta<T>(u64, PhantomData<T>). The PhantomData must be ignored so this is
    // still linted.
    #[derive(Clone, Copy)]
    pub struct Delta<T>(pub u64, pub PhantomData<T>);
    #[derive(Clone, Copy)]
    pub struct ViewTag;
    pub type ViewDelta = Delta<ViewTag>;

    // A composite (multiple fields), e.g. a Round = (epoch, view). Recorded as a
    // string is fine, so it must NOT be linted.
    pub struct Round {
        pub epoch: u64,
        pub view: u64,
    }
}

fn main() {
    let view = types::View(7);
    let epoch = types::Epoch(0);
    let height = types::Height(3);
    let view_delta: types::ViewDelta = types::Delta(5, std::marker::PhantomData);
    let round = types::Round { epoch: 0, view: 7 };
    let count: u64 = 42;

    // Bad: integer primitive or single-integer-field newtype via Display/Debug
    // inside a span.
    info_span!("simplex.voter.view", view = %view);
    info_span!("simplex.voter.view", view = ?view);
    info_span!("simplex.voter.view", epoch = %epoch);
    info_span!("simplex.voter.view", height = %height);
    info_span!("simplex.voter.view", view_delta = %view_delta);
    info_span!("simplex.voter.view", count = %count);

    // Good: numeric, not routed through Display/Debug.
    let _ = view.get() as i64;
    let _ = count as i64;

    // Good: events are logs, not span attributes.
    debug!(view = %view, "view advanced");

    // Unrelated: not integer-like, so no lint.
    info_span!("simplex.voter.view", round = %round);
    info_span!("simplex.voter.view", done = %true);
    info_span!("simplex.voter.view", name = %"a string");
}
