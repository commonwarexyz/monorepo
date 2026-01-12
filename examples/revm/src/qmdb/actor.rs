//! QMDB actor that isolates non-Send futures from cross-crate trait boundaries.
//!
//! The QMDB storage crate's async methods use RPITIT patterns that capture `&self` references,
//! causing cross-crate Send bound issues (rust-lang/rust#100013). This actor runs QMDB
//! operations on a dedicated thread with its own single-threaded tokio runtime, communicating
//! via channels to avoid Send requirements entirely.
//!
//! # Architecture
//!
//! The actor pattern follows Tokio's recommended approach for !Send futures: run them on a
//! dedicated thread with a single-threaded runtime, and communicate via Send channels.
//!
//! Two channel types are used:
//! - **Async callers** (e.g., `preview_root`, `commit_changes`): Use `futures::channel` for
//!   both send and receive, enabling normal async/await patterns.
//! - **Sync callers** (e.g., `QmdbRefDb::basic_ref`): Use `try_send` for commands and
//!   `std::sync::mpsc` for responses. These callers must run on a blocking executor.
//!
//! # Backpressure
//!
//! The command channel is bounded (32 slots). Async callers will await backpressure naturally.
//! Sync callers use `try_send` which fails immediately if the channel is full - this indicates
//! the actor is overloaded and callers should handle the error appropriately.

use super::{model::AccountRecord, Error, QmdbChanges, QmdbConfig, QmdbState};
use crate::types::StateRoot;
use alloy_evm::revm::primitives::{Address, B256, U256};
use commonware_runtime::{tokio, Runner};
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use std::sync::mpsc as std_mpsc;
use std::thread;

/// Async response channel (for async callers).
type AsyncReply<T> = oneshot::Sender<Result<T, Error>>;

/// Sync response channel (for sync callers like DatabaseRef).
type SyncReply<T> = std_mpsc::Sender<Result<T, Error>>;

/// Commands sent to the QMDB actor.
enum Command {
    // Async commands (use futures::channel::oneshot for response)
    PreviewRoot {
        changes: QmdbChanges,
        reply: AsyncReply<StateRoot>,
    },
    CommitChanges {
        changes: QmdbChanges,
        reply: AsyncReply<StateRoot>,
    },
    GetRoot {
        reply: AsyncReply<StateRoot>,
    },

    // Sync database read commands (use std::sync::mpsc for response)
    // These are used by QmdbRefDb which implements the sync DatabaseRef trait
    GetAccountSync {
        address: Address,
        reply: SyncReply<Option<AccountRecord>>,
    },
    GetCodeSync {
        code_hash: B256,
        reply: SyncReply<Option<Vec<u8>>>,
    },
    GetStorageSync {
        address: Address,
        index: U256,
        reply: SyncReply<U256>,
    },
}

/// Handle to communicate with the QMDB actor.
#[derive(Clone)]
pub(crate) struct QmdbHandle {
    sender: mpsc::Sender<Command>,
}

impl QmdbHandle {
    /// Spawns a new QMDB actor on a dedicated thread and returns a handle to communicate with it.
    ///
    /// The actor runs on its own thread with a single-threaded tokio runtime, which allows
    /// non-Send futures to execute without crossing thread boundaries.
    pub(crate) async fn spawn(
        context: tokio::Context,
        config: QmdbConfig,
        genesis_alloc: Vec<(Address, U256)>,
    ) -> Result<Self, Error> {
        let (sender, receiver) = mpsc::channel(32);
        let (init_tx, init_rx) = oneshot::channel();

        // Spawn the actor on a dedicated thread with its own runtime
        thread::spawn(move || {
            let cfg = tokio::Config::new().with_worker_threads(1);
            let runner = tokio::Runner::new(cfg);

            runner.start(|_| async move {
                // Initialize QMDB on the actor thread
                let qmdb = match QmdbState::init(context, config, genesis_alloc).await {
                    Ok(q) => {
                        let _ = init_tx.send(Ok(()));
                        q
                    }
                    Err(e) => {
                        let _ = init_tx.send(Err(e));
                        return;
                    }
                };

                // Run the actor loop
                run_actor(qmdb, receiver).await;
            });
        });

        // Wait for initialization to complete
        init_rx
            .await
            .map_err(|_| Error::StoreUnavailable("actor init channel closed"))??;

        Ok(Self { sender })
    }

    /// Computes the state commitment that would result from applying the changes.
    pub(crate) async fn preview_root(&self, changes: QmdbChanges) -> Result<StateRoot, Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.sender
            .clone()
            .send(Command::PreviewRoot {
                changes,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Error::StoreUnavailable("actor channel closed"))?;
        reply_rx
            .await
            .map_err(|_| Error::StoreUnavailable("actor reply channel closed"))?
    }

    /// Applies state changes to QMDB and commits them to durable storage.
    pub(crate) async fn commit_changes(&self, changes: QmdbChanges) -> Result<StateRoot, Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.sender
            .clone()
            .send(Command::CommitChanges {
                changes,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Error::StoreUnavailable("actor channel closed"))?;
        reply_rx
            .await
            .map_err(|_| Error::StoreUnavailable("actor reply channel closed"))?
    }

    /// Returns the current authenticated state commitment.
    pub(crate) async fn root(&self) -> Result<StateRoot, Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.sender
            .clone()
            .send(Command::GetRoot { reply: reply_tx })
            .await
            .map_err(|_| Error::StoreUnavailable("actor channel closed"))?;
        reply_rx
            .await
            .map_err(|_| Error::StoreUnavailable("actor reply channel closed"))?
    }

    /// Gets account record by address (sync version for DatabaseRef).
    ///
    /// Callers must ensure they are running on a blocking executor.
    pub(crate) fn get_account_sync(
        &self,
        address: Address,
    ) -> Result<Option<AccountRecord>, Error> {
        let (reply_tx, reply_rx) = std_mpsc::channel();
        self.sender
            .clone()
            .try_send(Command::GetAccountSync {
                address,
                reply: reply_tx,
            })
            .map_err(|_| Error::StoreUnavailable("actor channel full or closed"))?;
        reply_rx
            .recv()
            .map_err(|_| Error::StoreUnavailable("actor reply channel closed"))?
    }

    /// Gets contract code by hash (sync version for DatabaseRef).
    ///
    /// Callers must ensure they are running on a blocking executor.
    pub(crate) fn get_code_sync(&self, code_hash: B256) -> Result<Option<Vec<u8>>, Error> {
        let (reply_tx, reply_rx) = std_mpsc::channel();
        self.sender
            .clone()
            .try_send(Command::GetCodeSync {
                code_hash,
                reply: reply_tx,
            })
            .map_err(|_| Error::StoreUnavailable("actor channel full or closed"))?;
        reply_rx
            .recv()
            .map_err(|_| Error::StoreUnavailable("actor reply channel closed"))?
    }

    /// Gets storage value for an account (sync version for DatabaseRef).
    ///
    /// Callers must ensure they are running on a blocking executor.
    pub(crate) fn get_storage_sync(&self, address: Address, index: U256) -> Result<U256, Error> {
        let (reply_tx, reply_rx) = std_mpsc::channel();
        self.sender
            .clone()
            .try_send(Command::GetStorageSync {
                address,
                index,
                reply: reply_tx,
            })
            .map_err(|_| Error::StoreUnavailable("actor channel full or closed"))?;
        reply_rx
            .recv()
            .map_err(|_| Error::StoreUnavailable("actor reply channel closed"))?
    }
}

/// Runs the QMDB actor loop, processing commands sequentially.
async fn run_actor(mut qmdb: QmdbState, mut receiver: mpsc::Receiver<Command>) {
    while let Some(cmd) = receiver.next().await {
        match cmd {
            Command::PreviewRoot { changes, reply } => {
                let result = qmdb.preview_root(changes).await;
                let _ = reply.send(result);
            }
            Command::CommitChanges { changes, reply } => {
                let result = qmdb.commit_changes(changes).await;
                let _ = reply.send(result);
            }
            Command::GetRoot { reply } => {
                let result = qmdb.root();
                let _ = reply.send(result);
            }
            // Sync database read commands (responses go via std::sync::mpsc)
            Command::GetAccountSync { address, reply } => {
                let result = qmdb.get_account(address).await;
                // std::sync::mpsc::Sender::send is non-blocking
                let _ = reply.send(result);
            }
            Command::GetCodeSync { code_hash, reply } => {
                let result = qmdb.get_code(code_hash).await;
                let _ = reply.send(result);
            }
            Command::GetStorageSync {
                address,
                index,
                reply,
            } => {
                let result = qmdb.get_storage(address, index).await;
                let _ = reply.send(result);
            }
        }
    }
}
