//! This client binary creates or opens a [commonware_storage::qmdb] database and
//! synchronizes it to a remote server's state. It uses the [Resolver] to fetch operations and
//! sync target updates from the server, and continuously syncs to demonstrate that sync works
//! with both empty and already-initialized databases.

use clap::{Arg, Command};
use commonware_codec::{EncodeShared, Read};
use commonware_runtime::{
    tokio as tokio_runtime, BufferPooler, Clock, Metrics, Network, Runner, Spawner, Storage,
    Supervisor as _,
};
use commonware_storage::{
    mmr,
    qmdb::sync::{self, compact},
};
use commonware_sync::{
    any, crate_version, current,
    databases::{DatabaseType, SyncMode},
    immutable, immutable_compact, keyless, keyless_compact,
    net::{ErrorCode, Resolver},
    Error, Key,
};
use commonware_utils::{
    channel::mpsc::{self, error::TrySendError},
    DurationExt,
};
use rand::Rng;
use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroU64,
    time::Duration,
};
use tracing::{debug, error, info, warn};

/// Default server address.
const DEFAULT_SERVER: &str = "127.0.0.1:8080";

/// Default client storage directory prefix.
const DEFAULT_CLIENT_DIR_PREFIX: &str = "/tmp/commonware-sync/client";

/// Size of the channel for target updates.
const UPDATE_CHANNEL_SIZE: usize = 16;

/// Client configuration.
#[derive(Debug, Clone)]
struct Config {
    /// Sync mode to use.
    sync_mode: SyncMode,
    /// Database family to use.
    family: DatabaseType,
    /// Server address to connect to.
    server: SocketAddr,
    /// Batch size for fetching operations.
    batch_size: NonZeroU64,
    /// Storage directory.
    storage_dir: String,
    /// Port on which metrics are exposed.
    metrics_port: u16,
    /// Interval for requesting target updates.
    target_update_interval: Duration,
    /// Interval between sync operations.
    sync_interval: Duration,
    /// Maximum number of outstanding requests.
    max_outstanding_requests: usize,
}

/// Every `interval_duration`, request an updated full-sync target from `resolver` and send any
/// changes on `update_tx`.
async fn target_update_task<E, Op, D>(
    context: E,
    resolver: Resolver<Op, D>,
    update_tx: mpsc::Sender<sync::Target<mmr::Family, D>>,
    interval_duration: Duration,
    initial_target: sync::Target<mmr::Family, D>,
) -> Result<(), Error>
where
    E: Clock,
    Op: Read + EncodeShared,
    Op::Cfg: commonware_codec::IsUnit,
    D: commonware_cryptography::Digest,
{
    let mut current_target = initial_target;

    loop {
        context.sleep(interval_duration).await;

        match resolver.get_sync_target().await {
            Ok(new_target) => {
                // Check if target has changed
                if current_target != new_target {
                    // Send new target to the sync client
                    match update_tx.clone().try_send(new_target.clone()) {
                        Ok(()) => {
                            info!(old_target = ?current_target, new_target = ?new_target, "target updated");
                            current_target = new_target;
                        }
                        Err(TrySendError::Closed(_)) => {
                            debug!("sync client disconnected, terminating target update task");
                            return Ok(());
                        }
                        Err(err) => {
                            warn!(?err, "failed to send target update to sync client");
                            return Err(Error::TargetUpdateChannel {
                                reason: err.to_string(),
                            });
                        }
                    }
                } else {
                    debug!(current_target = ?current_target, "target unchanged");
                }
            }
            Err(err) => {
                warn!(?err, "failed to get sync target from server");
            }
        }
    }
}

/// Repeatedly sync a full database to the server's state.
async fn run_full_sync<DB, Op, E, SyncOnce, SyncFut>(
    context: E,
    config: Config,
    sync_once: SyncOnce,
    label: &'static str,
) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner,
    Op: Clone + Read + EncodeShared + 'static,
    Op::Cfg: commonware_codec::IsUnit,
    SyncOnce: Fn(
        E,
        Config,
        Resolver<Op, Key>,
        sync::Target<mmr::Family, Key>,
        mpsc::Receiver<sync::Target<mmr::Family, Key>>,
        u32,
    ) -> SyncFut,
    SyncFut: Future<Output = Result<DB, Box<dyn std::error::Error>>>,
{
    info!("starting {label} sync process");
    let mut iteration = 0u32;
    loop {
        let resolver =
            Resolver::<Op, Key>::connect(context.child("resolver"), config.server).await?;

        let initial_target = resolver.get_sync_target().await?;
        let (update_sender, update_receiver) = mpsc::channel(UPDATE_CHANNEL_SIZE);

        let target_update_handle = {
            let resolver = resolver.clone();
            let initial_target_clone = initial_target.clone();
            let target_update_interval = config.target_update_interval;
            context.child("target_update").spawn(move |context| {
                target_update_task(
                    context,
                    resolver,
                    update_sender,
                    target_update_interval,
                    initial_target_clone,
                )
            })
        };

        sync_once(
            context.child("sync"),
            config.clone(),
            resolver,
            initial_target,
            update_receiver,
            iteration,
        )
        .await?;
        target_update_handle.abort();
        context.sleep(config.sync_interval).await;
        iteration += 1;
    }
}

/// Repeatedly sync an Any database to the server's state.
async fn run_any<E>(context: E, config: Config) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner,
{
    run_full_sync::<any::Database<_>, any::Operation, _, _, _>(
        context,
        config,
        |context, config, resolver, initial_target, update_receiver, iteration| async move {
            let db_config = any::create_config(&context);
            let sync_config =
                sync::engine::Config::<any::Database<_>, Resolver<any::Operation, Key>> {
                    context,
                    db_config,
                    fetch_batch_size: config.batch_size,
                    target: initial_target,
                    resolver,
                    apply_batch_size: 1024,
                    max_outstanding_requests: config.max_outstanding_requests,
                    update_rx: Some(update_receiver),
                    finish_rx: None,
                    reached_target_tx: None,
                    max_retained_roots: 8,
                };
            let database: any::Database<_> = sync::sync(sync_config).await?;
            info!(
                sync_iteration = iteration,
                root = %database.root(),
                sync_interval = ?config.sync_interval,
                "Any sync completed successfully"
            );
            Ok(database)
        },
        "Any database",
    )
    .await
}

/// Repeatedly sync a Current database to the server's state.
///
/// Uses the `current::sync::sync` wrapper. The wrapper verifies each target's `OpsRootWitness`
/// before forwarding its ops root to the shared sync engine, then checks the canonical root for the
/// target the engine finishes on.
async fn run_current<E>(context: E, config: Config) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner,
{
    use commonware_storage::qmdb::current as current_qmdb;

    info!("starting Current database sync process");
    let mut iteration = 0u32;
    loop {
        let resolver =
            Resolver::<current::Operation, Key>::connect(context.child("resolver"), config.server)
                .await?;

        let initial_target = resolver.get_current_sync_target().await?;
        info!(
            canonical_root = %initial_target.canonical_root,
            ops_root = %initial_target.ops_root,
            range = ?initial_target.range,
            "received current sync target"
        );

        let (update_sender, update_receiver) = mpsc::channel(UPDATE_CHANNEL_SIZE);

        let target_update_handle = {
            let resolver = resolver.clone();
            let mut current_target_root = initial_target.canonical_root;
            let target_update_interval = config.target_update_interval;
            context
                .child("target_update")
                .spawn(move |context| async move {
                    loop {
                        context.sleep(target_update_interval).await;
                        match resolver.get_current_sync_target().await {
                            Ok(new_target) => {
                                if current_target_root != new_target.canonical_root {
                                    let new_root = new_target.canonical_root;
                                    match update_sender.clone().try_send(new_target) {
                                        Ok(()) => {
                                            info!("target updated");
                                            current_target_root = new_root;
                                        }
                                        Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                                        Err(err) => {
                                            warn!(?err, "failed to send target update");
                                            return Err(Error::TargetUpdateChannel {
                                                reason: err.to_string(),
                                            });
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                warn!(?err, "failed to get sync target from server");
                            }
                        }
                    }
                })
        };

        let db_config = current::create_config(&context);
        let database: current::Database<_> = current_qmdb::sync::sync(current_qmdb::sync::Config {
            context: context.child("sync"),
            resolver,
            target: initial_target,
            max_outstanding_requests: config.max_outstanding_requests,
            fetch_batch_size: config.batch_size,
            apply_batch_size: 1024,
            db_config,
            update_rx: Some(update_receiver),
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        })
        .await?;

        target_update_handle.abort();
        info!(
            sync_iteration = iteration,
            canonical_root = %database.root(),
            ops_root = %database.ops_root(),
            sync_interval = ?config.sync_interval,
            "Current sync completed successfully"
        );
        database.destroy().await?;
        context.sleep(config.sync_interval).await;
        iteration += 1;
    }
}

/// Repeatedly sync an Immutable database to the server's state.
async fn run_immutable<E>(context: E, config: Config) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner,
{
    run_full_sync::<immutable::Database<_>, immutable::Operation, _, _, _>(
        context,
        config,
        |context, config, resolver, initial_target, update_receiver, iteration| async move {
            let db_config = immutable::create_config(&context);
            let sync_config = sync::engine::Config::<
                immutable::Database<_>,
                Resolver<immutable::Operation, Key>,
            > {
                context,
                db_config,
                fetch_batch_size: config.batch_size,
                target: initial_target,
                resolver,
                apply_batch_size: 1024,
                max_outstanding_requests: config.max_outstanding_requests,
                update_rx: Some(update_receiver),
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            };
            let database: immutable::Database<_> = sync::sync(sync_config).await?;
            info!(
                sync_iteration = iteration,
                root = %database.root(),
                sync_interval = ?config.sync_interval,
                "Immutable sync completed successfully"
            );
            Ok(database)
        },
        "Immutable database",
    )
    .await
}

/// Repeatedly sync a Keyless database to the server's state.
async fn run_keyless<E>(context: E, config: Config) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner,
{
    run_full_sync::<keyless::Database<_>, keyless::Operation, _, _, _>(
        context,
        config,
        |context, config, resolver, initial_target, update_receiver, iteration| async move {
            let db_config = keyless::create_config(&context);
            let sync_config =
                sync::engine::Config::<keyless::Database<_>, Resolver<keyless::Operation, Key>> {
                    context,
                    db_config,
                    fetch_batch_size: config.batch_size,
                    target: initial_target,
                    resolver,
                    apply_batch_size: 1024,
                    max_outstanding_requests: config.max_outstanding_requests,
                    update_rx: Some(update_receiver),
                    finish_rx: None,
                    reached_target_tx: None,
                    max_retained_roots: 8,
                };
            let database: keyless::Database<_> = sync::sync(sync_config).await?;
            info!(
                sync_iteration = iteration,
                root = %database.root(),
                sync_interval = ?config.sync_interval,
                "Keyless sync completed successfully"
            );
            Ok(database)
        },
        "Keyless database",
    )
    .await
}

/// Repeatedly sync a compact-storage database via compact state transfer.
async fn run_compact_sync<DB, Op, E, MakeConfig>(
    context: E,
    config: Config,
    make_db_config: MakeConfig,
    label: &'static str,
) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner,
    DB: compact::Database<Family = mmr::Family, Context = E, Digest = Key, Op = Op>,
    Op: Clone + Read + EncodeShared + 'static,
    Op::Cfg: commonware_codec::IsUnit,
    MakeConfig: Fn(&E) -> DB::Config,
{
    info!("starting {label} compact sync process");
    let mut iteration = 0u32;
    loop {
        let resolver =
            Resolver::<Op, Key>::connect(context.child("resolver"), config.server).await?;
        let target = resolver.get_compact_target().await?;
        let sync_config = compact::Config::<DB, Resolver<Op, Key>> {
            context: context.child("sync"),
            resolver,
            target,
            db_config: make_db_config(&context),
        };
        let database: DB = match compact::sync(sync_config).await {
            Ok(database) => database,
            Err(sync::Error::Resolver(Error::Server {
                code: ErrorCode::StaleTarget,
                message,
            })) => {
                warn!(
                    sync_iteration = iteration,
                    "{label} target went stale before state fetch: {message}; retrying"
                );
                continue;
            }
            Err(err) => return Err(err.into()),
        };
        info!(
            sync_iteration = iteration,
            root = %database.root(),
            sync_interval = ?config.sync_interval,
            "{label} sync completed successfully"
        );
        context.sleep(config.sync_interval).await;
        iteration += 1;
    }
}

async fn run_immutable_compact<E>(
    context: E,
    config: Config,
) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner,
{
    run_compact_sync::<immutable_compact::Database<_>, immutable_compact::Operation, _, _>(
        context,
        config,
        |ctx| immutable_compact::create_config(ctx),
        "Immutable compact",
    )
    .await
}

async fn run_keyless_compact<E>(
    context: E,
    config: Config,
) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner,
{
    run_compact_sync::<keyless_compact::Database<_>, keyless_compact::Operation, _, _>(
        context,
        config,
        |ctx| keyless_compact::create_config(ctx),
        "Keyless compact",
    )
    .await
}

fn parse_config() -> Result<Config, Box<dyn std::error::Error>> {
    // Parse command line arguments
    let matches = Command::new("Sync Client")
        .version(crate_version())
        .about("Continuously syncs a database to a server's database state")
        .arg(
            Arg::new("mode")
                .long("mode")
                .value_name("full|compact")
                .help("Sync mode to demonstrate. Use `full` for operation replay or `compact` for compact state transfer.")
                .default_value("full"),
        )
        .arg(
            Arg::new("family")
                .long("family")
                .value_name("any|current|immutable|keyless")
                .help("Database family to use for the selected mode.")
                .default_value("any"),
        )
        .arg(
            Arg::new("server")
                .short('s')
                .long("server")
                .value_name("ADDRESS")
                .help("Server address to connect to")
                .default_value(DEFAULT_SERVER),
        )
        .arg(
            Arg::new("batch-size")
                .short('b')
                .long("batch-size")
                .value_name("SIZE")
                .help("Batch size for fetching operations in full mode")
                .default_value("50"),
        )
        .arg(
            Arg::new("storage-dir")
                .short('d')
                .long("storage-dir")
                .value_name("PATH")
                .help("Storage directory for local database")
                .default_value(DEFAULT_CLIENT_DIR_PREFIX),
        )
        .arg(
            Arg::new("metrics-port")
                .short('m')
                .long("metrics-port")
                .value_name("PORT")
                .help("Port on which metrics are exposed")
                .default_value("9091"),
        )
        .arg(
            Arg::new("target-update-interval")
                .short('t')
                .long("target-update-interval")
                .value_name("DURATION")
                .help("Interval for requesting target updates in full mode ('ms', 's', 'm', 'h')")
                .default_value("1s"),
        )
        .arg(
            Arg::new("sync-interval")
                .short('i')
                .long("sync-interval")
                .value_name("DURATION")
                .help("Interval between sync operations ('ms', 's', 'm', 'h')")
                .default_value("10s"),
        )
        .arg(
            Arg::new("max-outstanding-requests")
                .short('r')
                .long("max-outstanding-requests")
                .value_name("COUNT")
                .help("Maximum number of outstanding sync requests in full mode")
                .default_value("1"),
        )
        .get_matches();

    let sync_mode = matches
        .get_one::<String>("mode")
        .unwrap()
        .parse::<SyncMode>()
        .map_err(|e| format!("Invalid sync mode: {e}"))?;
    let family = matches
        .get_one::<String>("family")
        .unwrap()
        .parse::<DatabaseType>()
        .map_err(|e| format!("Invalid database family: {e}"))?;
    if !family.supports_client_mode(sync_mode) {
        return Err(format!(
            "Database family '{}' is not supported in '{}' mode",
            family.as_str(),
            sync_mode.as_str()
        )
        .into());
    }

    let server = matches
        .get_one::<String>("server")
        .unwrap()
        .parse()
        .map_err(|e| format!("Invalid server address: {e}"))?;

    let batch_size = matches
        .get_one::<String>("batch-size")
        .unwrap()
        .parse()
        .map_err(|e| format!("Invalid batch size: {e}"))?;

    let storage_dir = {
        let storage_dir = matches
            .get_one::<String>("storage-dir")
            .unwrap()
            .to_string();
        // Only add suffix if using the default value
        if storage_dir == DEFAULT_CLIENT_DIR_PREFIX {
            let suffix: u64 = rand::thread_rng().gen();
            format!("{storage_dir}-{suffix}")
        } else {
            storage_dir
        }
    };

    let metrics_port = matches
        .get_one::<String>("metrics-port")
        .unwrap()
        .parse()
        .map_err(|e| format!("Invalid metrics port: {e}"))?;

    let target_update_interval =
        Duration::parse(matches.get_one::<String>("target-update-interval").unwrap())
            .map_err(|e| format!("Invalid target update interval: {e}"))?;

    let sync_interval = Duration::parse(matches.get_one::<String>("sync-interval").unwrap())
        .map_err(|e| format!("Invalid sync interval: {e}"))?;

    let max_outstanding_requests = matches
        .get_one::<String>("max-outstanding-requests")
        .unwrap()
        .parse()
        .map_err(|e| format!("Invalid max outstanding requests: {e}"))?;

    Ok(Config {
        sync_mode,
        family,
        server,
        batch_size,
        storage_dir,
        metrics_port,
        target_update_interval,
        sync_interval,
        max_outstanding_requests,
    })
}

fn main() {
    let config = parse_config().unwrap_or_else(|e| {
        eprintln!("Configuration error: {e}");
        std::process::exit(1);
    });
    let materialized_storage = match config.sync_mode {
        SyncMode::Full => "full",
        SyncMode::Compact => "compact",
    };

    let executor_config =
        tokio_runtime::Config::default().with_storage_directory(config.storage_dir.clone());
    let executor = tokio_runtime::Runner::new(executor_config);
    executor.start(|context| async move {
        tokio_runtime::telemetry::init(
            context.child("telemetry"),
            tokio_runtime::telemetry::Logging {
                level: tracing::Level::INFO,
                json: false,
            },
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, config.metrics_port))),
            None,
        );
        info!(
            sync_mode = %config.sync_mode.as_str(),
            family = %config.family.as_str(),
            materialized_storage,
            server = %config.server,
            batch_size = config.batch_size,
            storage_dir = %config.storage_dir,
            metrics_port = config.metrics_port,
            target_update_interval = ?config.target_update_interval,
            sync_interval = ?config.sync_interval,
            max_outstanding_requests = config.max_outstanding_requests,
            "client starting with configuration"
        );

        // Dispatch based on sync mode and database family.
        let result = match (config.sync_mode, config.family) {
            (SyncMode::Full, DatabaseType::Any) => run_any(context.child("sync"), config).await,
            (SyncMode::Full, DatabaseType::Current) => {
                run_current(context.child("sync"), config).await
            }
            (SyncMode::Full, DatabaseType::Immutable) => {
                run_immutable(context.child("sync"), config).await
            }
            (SyncMode::Full, DatabaseType::Keyless) => {
                run_keyless(context.child("sync"), config).await
            }
            (SyncMode::Compact, DatabaseType::Immutable) => {
                run_immutable_compact(context.child("sync"), config).await
            }
            (SyncMode::Compact, DatabaseType::Keyless) => {
                run_keyless_compact(context.child("sync"), config).await
            }
            _ => Err(Box::<dyn std::error::Error>::from(format!(
                "unsupported combination: mode={} family={}",
                config.sync_mode.as_str(),
                config.family.as_str()
            ))),
        };

        if let Err(err) = result {
            error!(?err, "continuous sync failed");
            std::process::exit(1);
        }
    });
}
