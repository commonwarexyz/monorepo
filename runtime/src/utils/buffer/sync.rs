use crate::{Error, Handle};
use futures::{
    future::{BoxFuture, Shared as FuturesShared},
    FutureExt as _,
};
use std::future::Future;

pub(crate) type Shared = FuturesShared<BoxFuture<'static, ()>>;

pub(crate) fn share(
    fut: impl Future<Output = Result<(), Error>> + Send + 'static,
    message: &'static str,
) -> Shared {
    async move { fut.await.expect(message) }.boxed().shared()
}

pub(crate) fn observe(sync: Shared) -> Handle<()> {
    Handle::from_future(async move {
        sync.await;
        Ok(())
    })
}
