//! Reporter implementations for various standard types.

use crate::Reporter;
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

    async fn report(&mut self, activity: Self::Activity) {
        // This approach avoids cloning activity, if possible.
        match (&mut self.r1, &mut self.r2) {
            (Some(r1), Some(r2)) => join!(r1.report(activity.clone()), r2.report(activity)),
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
