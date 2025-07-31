//! Reporter implementations for various standard types.

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

/// An implementation of `Reporter` for an optional reporter.
///
/// This is useful for reporting activity to a reporter that may not be present.
/// Reporting is a no-op if the reporter is `None`.
impl<A: Send, R: Reporter<Activity = A>> Reporter for Option<R> {
    type Activity = A;

    async fn report(&mut self, activity: Self::Activity) {
        let Some(reporter) = self else {
            return;
        };
        reporter.report(activity).await;
    }
}
