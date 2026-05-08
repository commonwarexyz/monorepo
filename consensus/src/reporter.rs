//! Reporter implementations for various standard types.

use crate::Reporter;
use commonware_utils::channel::Submission;
use std::marker::PhantomData;

/// An implementation of [Reporter] for an optional [Reporter].
///
/// This is useful for reporting activity to a [Reporter] that may not be present.
/// Reporting is a no-op if the [Reporter] is `None`.
impl<A: Send, R: Reporter<Activity = A>> Reporter for Option<R> {
    type Activity = A;

    fn report(&mut self, activity: Self::Activity) -> Submission {
        let Some(reporter) = self else {
            return Submission::Dropped;
        };
        reporter.report(activity)
    }
}

/// A struct used to report activity to multiple [Reporter]s (which may or may not be present).
#[derive(Clone)]
pub struct Reporters<A, R1, R2> {
    r1: Option<R1>,
    r2: Option<R2>,

    _phantom: PhantomData<A>,
}

impl<A, R1, R2> Reporter for Reporters<A, R1, R2>
where
    A: Clone + Send + 'static,
    R1: Reporter<Activity = A>,
    R2: Reporter<Activity = A>,
{
    type Activity = A;

    fn report(&mut self, activity: Self::Activity) -> Submission {
        match (&mut self.r1, &mut self.r2) {
            (Some(r1), Some(r2)) => combine(r1.report(activity.clone()), r2.report(activity)),
            (Some(r1), None) => r1.report(activity),
            (None, Some(r2)) => r2.report(activity),
            (None, None) => Submission::Dropped,
        }
    }
}

fn combine(left: Submission, right: Submission) -> Submission {
    match (left, right) {
        (Submission::Closed, _) | (_, Submission::Closed) => Submission::Closed,
        (Submission::Dropped, _) | (_, Submission::Dropped) => Submission::Dropped,
        (Submission::Backlogged, _) | (_, Submission::Backlogged) => Submission::Backlogged,
        (Submission::Accepted, Submission::Accepted) => Submission::Accepted,
    }
}

impl<A, R1, R2> From<(Option<R1>, Option<R2>)> for Reporters<A, R1, R2> {
    fn from((r1, r2): (Option<R1>, Option<R2>)) -> Self {
        Self {
            r1,
            r2,
            _phantom: PhantomData,
        }
    }
}

impl<A, R1, R2> From<(Option<R1>, R2)> for Reporters<A, R1, R2> {
    fn from((r1, r2): (Option<R1>, R2)) -> Self {
        Self {
            r1,
            r2: Some(r2),
            _phantom: PhantomData,
        }
    }
}

impl<A, R1, R2> From<(R1, Option<R2>)> for Reporters<A, R1, R2> {
    fn from((r1, r2): (R1, Option<R2>)) -> Self {
        Self {
            r1: Some(r1),
            r2,
            _phantom: PhantomData,
        }
    }
}

impl<A, R1, R2> From<(R1, R2)> for Reporters<A, R1, R2> {
    fn from((r1, r2): (R1, R2)) -> Self {
        Self {
            r1: Some(r1),
            r2: Some(r2),
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_async;
    use commonware_utils::acknowledgement::{Acknowledgement, Exact};
    use futures::FutureExt;

    #[derive(Clone, Debug)]
    struct SimpleAcknowledger;

    impl crate::Reporter for SimpleAcknowledger {
        type Activity = Exact;

        fn report(&mut self, activity: Self::Activity) -> Submission {
            activity.acknowledge();
            Submission::Accepted
        }
    }

    #[test_async]
    async fn optional_branch_acknowledges() {
        let mut reporters = Reporters::<Exact, SimpleAcknowledger, SimpleAcknowledger>::from((
            Some(SimpleAcknowledger),
            None,
        ));

        let (ack, waiter) = Exact::handle();
        assert_eq!(reporters.report(ack), Submission::Accepted);

        assert!(
            waiter.now_or_never().unwrap().is_ok(),
            "Waiter did not resolve successfully"
        );
    }
}
