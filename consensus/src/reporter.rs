//! Reporter implementations for various standard types.

use crate::Reporter;
use futures::future::try_join;

/// An implementation of [Reporter] for an optional [Reporter].
///
/// This is useful for reporting activity to a [Reporter] that may not be present.
/// Reporting is a no-op if the [Reporter] is `None`.
impl<R> Reporter for Option<R>
where
    R: Reporter,
    R::Activity: Send,
{
    type Activity = R::Activity;
    type Error = R::Error;

    async fn report(&mut self, activity: Self::Activity) -> Result<(), Self::Error> {
        let Some(reporter) = self else {
            return Ok(());
        };
        reporter.report(activity).await
    }
}

/// A struct used to report activity to multiple [Reporter]s (which may or may not be present).
#[derive(Clone)]
pub struct Reporters<R1, R2> {
    r1: R1,
    r2: R2,
}

impl<R1, R2> Reporter for Reporters<R1, R2>
where
    R1: Reporter,
    R2: Reporter<Activity = R1::Activity, Error = R1::Error>,
    R1::Activity: Clone + Send,
{
    type Activity = R1::Activity;
    type Error = R1::Error;

    async fn report(&mut self, activity: Self::Activity) -> Result<(), Self::Error> {
        try_join(self.r1.report(activity.clone()), self.r2.report(activity)).await?;
        Ok(())
        // // This approach avoids cloning activity, if possible.
        // match (&mut self.r1, &mut self.r2) {
        //     (Some(r1), Some(r2)) => join!(r1.report(activity.clone()), r2.report(activity)),
        //     (Some(r1), None) => (r1.report(activity).await, ()),
        //     (None, Some(r2)) => ((), r2.report(activity).await),
        //     (None, None) => ((), ()),
        // };
    }
}

// impl<A, R1, R2> From<(Option<R1>, Option<R2>)> for Reporters<A, R1, R2> {
//     fn from((r1, r2): (Option<R1>, Option<R2>)) -> Self {
//         Self {
//             r1,
//             r2,
//             _phantom: PhantomData,
//         }
//     }
// }

// impl<A, R1, R2> From<(Option<R1>, R2)> for Reporters<A, R1, R2> {
//     fn from((r1, r2): (Option<R1>, R2)) -> Self {
//         Self {
//             r1,
//             r2: Some(r2),
//             _phantom: PhantomData,
//         }
//     }
// }

// impl<A, R1, R2> From<(R1, Option<R2>)> for Reporters<A, R1, R2> {
//     fn from((r1, r2): (R1, Option<R2>)) -> Self {
//         Self {
//             r1: Some(r1),
//             r2,
//             _phantom: PhantomData,
//         }
//     }
// }

impl<R1, R2> From<(R1, R2)> for Reporters<R1, R2> {
    fn from((r1, r2): (R1, R2)) -> Self {
        Self { r1, r2 }
    }
}
