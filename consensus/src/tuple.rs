//! Trait implementations for tuples.

use crate::Reporter;
use futures::join;

/// An implementation of `Reporter` for a tuple of two reporters.
///
/// This is useful for sending the same activity to multiple consumers.
impl<A, R1, R2> Reporter for (R1, R2)
where
    A: Clone + Send,
    R1: Reporter<Activity = A>,
    R2: Reporter<Activity = A>,
{
    type Activity = A;

    async fn report(&mut self, activity: Self::Activity) {
        join!(self.0.report(activity.clone()), self.1.report(activity));
    }
}
