// aux-build:tokio.rs
// aux-build:commonware_macros_impl.rs
// aux-build:commonware_macros.rs
// aux-build:external.rs
// edition:2021

// The auxiliary crates stand in for the real ones under the same crate names, so
// the fixtures exercise the macro definitions the lint matches.

extern crate commonware_macros;
extern crate external;
extern crate tokio;

use core::future::ready;

// Re-exports tokio's `select!` under another path.
mod reexport {
    pub use tokio::select;
}

// Expands to tokio's `select!` in this crate.
macro_rules! local_select {
    ($future:expr) => {
        tokio::select! {
            _ = $future => (),
        }
    };
}

// Expands to the guarded `select!` in this crate.
macro_rules! local_guarded {
    ($future:expr) => {
        commonware_macros::select! {
            _ = $future => (),
        }
    };
}

// Shares the name `select` but not tokio's definition.
macro_rules! select {
    ($($tokens:tt)*) => {
        ()
    };
}

fn main() {
    // Bad: a direct invocation, reported once despite the recursion.
    tokio::select! {
        biased;
        _ = ready(1) => (),
        _ = ready(2) => (),
    }

    // Bad: re-exported, imported, and renamed paths.
    commonware_macros::__reexport::tokio::select! {
        _ = ready(1) => (),
    }
    reexport::select! {
        _ = ready(1) => (),
    }
    {
        use tokio::select as race;
        race! {
            _ = ready(1) => (),
        }
    }

    // Bad: a local macro, reported once per invocation.
    local_select!(ready(1));
    local_select!(ready(2));

    // Bad: a macro of another crate, reported at its invocation.
    external::race!(ready(1));

    // Bad: a direct invocation in a branch of the guarded `select!`.
    commonware_macros::select! {
        _ = ready(1) => tokio::select! {
            _ = ready(2) => (),
        },
    }

    // Good: the guarded macros, directly and through a local macro.
    commonware_macros::select! {
        _ = ready(1) => (),
        _ = ready(2) => (),
    }
    commonware_macros::select_loop! {
        _ = ready(1) => (),
    }
    local_guarded!(ready(1));

    // Good: a lookalike defined elsewhere.
    select! {
        _ = ready(1) => (),
    }
}
