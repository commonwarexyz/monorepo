//! Strategy adapters shared by the verification modules.

use commonware_parallel::Strategy;

/// One of two independent tasks or its output.
enum Either<A, B> {
    A(A),
    B(B),
}

/// Runs two independent fallible tasks under one adaptive execution decision.
///
/// Each task is written exactly once. The strategy chooses serial or parallel execution the
/// same way it does for any other two-item workload. Both tasks always run, and the first
/// task's error takes precedence, so every strategy reports the same result.
pub(crate) fn try_join<A, B, E>(
    strategy: &impl Strategy,
    a: impl FnOnce() -> Result<A, E> + Send,
    b: impl FnOnce() -> Result<B, E> + Send,
) -> Result<(A, B), E>
where
    A: Send,
    B: Send,
    E: Send,
{
    let mut outputs = strategy
        .map_collect_vec([Either::A(a), Either::B(b)], |task| match task {
            Either::A(a) => a().map(Either::A),
            Either::B(b) => b().map(Either::B),
        })
        .into_iter();
    match (outputs.next(), outputs.next(), outputs.next()) {
        (Some(a), Some(b), None) => match (a?, b?) {
            (Either::A(a), Either::B(b)) => Ok((a, b)),

            // The adaptive map returns exactly one output per input in input order.
            _ => unreachable!("two mapped tasks must produce outputs in task order"),
        },

        // The adaptive map returns exactly one output per input.
        _ => unreachable!("two mapped tasks must produce two outputs"),
    }
}
