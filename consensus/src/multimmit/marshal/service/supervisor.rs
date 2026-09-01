//! Supervision of marshal's actor tasks.

use crate::multimmit::marshal::{
    actors::{
        backfill::{self, serve},
        catalog, delivery, promoter, synchronizer,
    },
    types::{Cause, Component, Error},
};
use commonware_macros::select;
use commonware_runtime::Handle;
use std::future::pending;

/// Folds a finished actor task into the service result.
///
/// An actor that stops cleanly ends the service without error; an actor failure or a failed task
/// ends it with that failure as the cause.
fn child_result<T: Into<Cause>>(
    component: Component,
    result: Result<Result<(), T>, commonware_runtime::Error>,
) -> Result<(), Error> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(Error::failed(error)),
        Err(error) => Err(Error::failed(Cause::Task { component, error })),
    }
}

/// Resolves when the promoter task finishes, and never without a promoter.
async fn promoter_result(
    handle: &mut Option<Handle<Result<(), promoter::Error>>>,
) -> Result<Result<(), promoter::Error>, commonware_runtime::Error> {
    match handle {
        Some(handle) => handle.await,
        None => pending().await,
    }
}

/// The task of every marshal actor, aborted together when dropped.
pub(super) struct Children {
    pub(super) catalog: Handle<Result<(), catalog::Fatal>>,
    pub(super) promoter: Option<Handle<Result<(), promoter::Error>>>,
    pub(super) backfill: Handle<Result<(), backfill::Error>>,
    pub(super) serve: Handle<Result<(), serve::Error>>,
    pub(super) synchronizer: Handle<Result<(), synchronizer::Error>>,
    pub(super) delivery: Handle<Result<(), delivery::Error>>,
    pub(super) router: Handle<Result<(), Error>>,
}

impl Children {
    fn abort(&self) {
        self.catalog.abort();
        if let Some(promoter) = &self.promoter {
            promoter.abort();
        }
        self.backfill.abort();
        self.serve.abort();
        self.synchronizer.abort();
        self.delivery.abort();
        self.router.abort();
    }

    /// Waits for the first actor to finish, then aborts the rest and returns its result.
    pub(super) async fn supervise(mut self) -> Result<(), Error> {
        let result = select! {
            result = &mut self.catalog => child_result(Component::Catalog, result),
            result = promoter_result(&mut self.promoter) => child_result(Component::Promoter, result),
            result = &mut self.backfill => child_result(Component::Backfill, result),
            result = &mut self.serve => child_result(Component::Serve, result),
            result = &mut self.synchronizer => child_result(Component::Synchronizer, result),
            result = &mut self.delivery => child_result(Component::Delivery, result),
            result = &mut self.router => child_result(Component::Router, result),
        };
        self.abort();
        result
    }
}

impl Drop for Children {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Lifecycle owner for a running marshal service.
pub struct ServiceHandle {
    pub(super) task: Handle<Result<(), Error>>,
    pub(super) shutdown_requested: bool,
}

impl ServiceHandle {
    /// Requests shutdown of the service and every child actor.
    pub fn abort(&mut self) {
        self.shutdown_requested = true;
        self.task.abort();
    }

    /// Waits for the service to stop and returns its first component failure.
    pub async fn join(self) -> Result<(), Error> {
        match self.task.await {
            Ok(result) => result,
            Err(commonware_runtime::Error::Closed | commonware_runtime::Error::Aborted)
                if self.shutdown_requested =>
            {
                Ok(())
            }
            Err(error) => Err(Error::failed(Cause::Task {
                component: Component::Supervisor,
                error,
            })),
        }
    }
}
