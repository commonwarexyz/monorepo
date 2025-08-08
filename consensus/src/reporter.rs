//! Reporter implementations for various standard types.

use crate::{Artifactable, Reporter};
use futures::join;

/// An implementation of [Reporter] for an optional [Reporter].
///
/// This is useful for reporting activity to a [Reporter] that may not be present.
/// Reporting is a no-op if the [Reporter] is `None`.
impl<R: Reporter> Reporter for Option<R>
where
    R::Activity: Artifactable,
{
    type Activity = R::Activity;

    async fn report(&mut self, activity: Self::Activity) {
        let Some(reporter) = self else {
            return;
        };
        reporter.report(activity).await;
    }
}

/// A struct used to report activity to multiple [Reporter]s (which may or may not be present).
#[derive(Clone)]
pub struct Reporters<R1, R2> {
    r1: Option<R1>,
    r2: Option<R2>,
}

impl<R1, R2> Reporter for Reporters<R1, R2>
where
    R1: Reporter,
    R2: Reporter<Activity = R1::Activity>,
    R1::Activity: Artifactable,
{
    type Activity = R1::Activity;

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

impl<R1, R2> From<(Option<R1>, Option<R2>)> for Reporters<R1, R2> {
    fn from((r1, r2): (Option<R1>, Option<R2>)) -> Self {
        Self { r1, r2 }
    }
}

impl<R1, R2> From<(Option<R1>, R2)> for Reporters<R1, R2> {
    fn from((r1, r2): (Option<R1>, R2)) -> Self {
        Self { r1, r2: Some(r2) }
    }
}

impl<R1, R2> From<(R1, Option<R2>)> for Reporters<R1, R2> {
    fn from((r1, r2): (R1, Option<R2>)) -> Self {
        Self { r1: Some(r1), r2 }
    }
}

impl<R1, R2> From<(R1, R2)> for Reporters<R1, R2> {
    fn from((r1, r2): (R1, R2)) -> Self {
        Self {
            r1: Some(r1),
            r2: Some(r2),
        }
    }
}
