use crate::{Blob, Error, Handle};
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

#[derive(Clone)]
pub(crate) enum State {
    Clean,
    Dirty,
    InFlight(Shared),
}

impl State {
    pub(crate) const fn dirty() -> Self {
        Self::Dirty
    }

    pub(crate) const fn is_dirty(&self) -> bool {
        matches!(self, Self::Dirty)
    }

    pub(crate) fn mark_dirty(&mut self) {
        *self = Self::Dirty;
    }

    pub(crate) const fn prepare_range_sync(&mut self) -> Self {
        std::mem::replace(self, Self::Dirty)
    }

    pub(crate) fn restore(&mut self, previous: Self) {
        *self = previous;
    }

    pub(crate) async fn sync<B: Blob>(&mut self, blob: &B) -> Result<bool, Error> {
        match self {
            Self::Clean => Ok(false),
            Self::Dirty => {
                blob.sync().await?;
                *self = Self::Clean;
                Ok(true)
            }
            Self::InFlight(syncing) => {
                syncing.clone().await;
                *self = Self::Clean;
                Ok(true)
            }
        }
    }

    pub(crate) async fn observe_in_flight(&mut self) {
        let Self::InFlight(syncing) = self else {
            return;
        };
        syncing.clone().await;
        *self = Self::Clean;
    }

    pub(crate) async fn start<B: Blob>(
        &mut self,
        blob: &B,
        message: &'static str,
    ) -> Option<Shared> {
        match self {
            Self::Clean => None,
            Self::Dirty => {
                let syncing = share(blob.start_sync().await, message);
                *self = Self::InFlight(syncing.clone());
                Some(syncing)
            }
            Self::InFlight(syncing) => Some(syncing.clone()),
        }
    }
}
