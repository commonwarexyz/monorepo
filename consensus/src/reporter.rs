//! Reporter implementations for various standard types.

use crate::Reporter;
use commonware_utils::acknowledgement::Splittable;
use futures::join;
use std::marker::PhantomData;

/// An implementation of [Reporter] for an optional [Reporter].
///
/// This is useful for reporting activity to a [Reporter] that may not be present.
/// Reporting is a no-op if the [Reporter] is `None`.
impl<A: Send, R: Reporter<Activity = A>> Reporter for Option<R> {
    type Activity = A;

    async fn report(&mut self, activity: Self::Activity) {
        let Some(reporter) = self else {
            return;
        };
        reporter.report(activity).await;
    }
}

/// A struct used to report activity to multiple [Reporter]s (which may or may not be present).
pub struct Reporters<A, R1, R2> {
    r1: Option<R1>,
    r2: Option<R2>,

    _phantom: PhantomData<A>,
}

impl<A, R1, R2> Clone for Reporters<A, R1, R2>
where
    R1: Clone,
    R2: Clone,
{
    fn clone(&self) -> Self {
        Self {
            r1: self.r1.clone(),
            r2: self.r2.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<A, R1, R2> Reporter for Reporters<A, R1, R2>
where
    A: Splittable + Send + 'static,
    R1: Reporter<Activity = A>,
    R2: Reporter<Activity = A>,
{
    type Activity = A;

    async fn report(&mut self, activity: Self::Activity) {
        // This approach avoids cloning activity, if possible.
        match (&mut self.r1, &mut self.r2) {
            (Some(r1), Some(r2)) => {
                let (a1, a2) = activity.split();
                join!(r1.report(a1), r2.report(a2))
            }
            (Some(r1), None) => (r1.report(activity).await, ()),
            (None, Some(r2)) => ((), r2.report(activity).await),
            (None, None) => ((), ()),
        };
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
    use super::Reporters;
    use crate::Reporter as _;
    use commonware_macros::test_async;
    use commonware_utils::{acknowledgement::Exact, Acknowledgement};
    use futures::FutureExt as _;

    /// Integration test of Reporters with `utils::Acknowledge`
    #[test_async]
    async fn optional_branch_acknowledges() {
        #[derive(Clone)]
        struct Reporter;
        impl crate::Reporter for Reporter {
            // Problem 1: need to know the number of acknowledgments of the combined
            // type in the leafs
            type Activity = Exact;

            async fn report(&mut self, activity: Self::Activity) {
                activity.acknowledge();
            }
        }

        let mut split =
            Reporters::<Exact, Reporter, Reporter>::from((Some(Reporter), None::<Reporter>));

        let (ack, waiter) = Exact::handle();
        split.report(ack).await;
        assert!(waiter.now_or_never().unwrap().is_ok());
    }
}
