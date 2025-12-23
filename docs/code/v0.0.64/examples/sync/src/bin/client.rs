//! This client binary creates or opens an [commonware_storage::qmdb::any] database and
//! synchronizes it to a remote server's state. It uses the [Resolver] to fetch operations and
//! sync target updates from the server, and continuously syncs to demonstrate that sync works
//! with both empty and already-initialized databases.

use clap::{Arg, Command};
use commonware_codec::{Encode, Read};
use commonware_runtime::{
    tokio as tokio_runtime, Clock, Metrics, Network, Runner, Spawner, Storage,
};
use commonware_storage::qmdb::sync;
use commonware_sync::{
    any, crate_version,
    databases::{DatabaseType, Syncable},
    immutable,
    net::Resolver,
    Digest, Error, Key,
};
use commonware_utils::DurationExt;
use futures::channel::mpsc;
use rand::Rng;
use std::{
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
#[derive(Debug)]
struct Config {
    /// Database type to use.
    database_type: DatabaseType,
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

/// Every `interval_duration`, use `resolver` to request an updated sync target and send it on
/// `update_tx`.
async fn target_update_task<E, Op, D>(
    context: E,
    resolver: Resolver<Op, D>,
    update_tx: mpsc::Sender<sync::Target<D>>,
    interval_duration: Duration,
    initial_target: sync::Target<D>,
) -> Result<(), Error>
where
    E: Clock,
    Op: Read<Cfg = ()> + Encode + Send + Sync,
    D: commonware_cryptography::Digest,
{
    let mut current_target = initial_target;

    loop {
        context.sleep(interval_duration).await;

        match resolver.get_sync_target().await {
            Ok(new_target) => {
                // Check if target has changed
                if new_target.root != current_target.root {
                    // Send new target to the sync client
                    match update_tx.clone().try_send(new_target.clone()) {
                        Ok(()) => {
                            info!(old_target = ?current_target, new_target = ?new_target, "target updated");
                            current_target = new_target;
                        }
                        Err(e) if e.is_disconnected() => {
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

/// Repeatedly sync an Any database to the server's state.
async fn run_any<E>(context: E, config: Config) -> Result<(), Box<dyn std::error::Error>>
where
    E: Storage + Clock + Metrics + Network + Spawner,
{
    info!("starting Any database sync process");
    let mut iteration = 0u32;
    loop {
        let resolver = Resolver::<any::Operation, Digest>::connect(
            context.with_label("resolver"),
            config.server,
        )
        .await?;

        let initial_target = resolver.get_sync_target().await?;

        let db_config = any::create_config();
        let (update_sender, update_receiver) = mpsc::channel(UPDATE_CHANNEL_SIZE);

        let target_update_handle = {
            let resolver = resolver.clone();
            let initial_target_clone = initial_target.clone();
            let target_update_interval = config.target_update_interval;
            context.with_label("target_update").spawn(move |context| {
                target_update_task(
                    context,
                    resolver,
                    update_sender,
                    target_update_interval,
                    initial_target_clone,
                )
            })
        };

        let sync_config =
            sync::engine::Config::<any::Database<_>, Resolver<any::Operation, Digest>> {
                context: context.with_label("sync"),
                db_config,
                fetch_batch_size: config.batch_size,
                target: initial_target,
                resolver,
                apply_batch_size: 1024,
                max_outstanding_requests: config.max_outstanding_requests,
                update_rx: Some(update_receiver),
            };

        let database: any::Database<_> = sync::sync(sync_config).await?;
        let got_root = database.root();
        info!(
            sync_iteration = iteration,
            root = %got_root,
            sync_interval = ?config.sync_interval,
            "✅ Any sync completed successfully"
        );
        database.close().await?;
        target_update_handle.abort();
        context.sleep(config.sync_interval).await;
        iteration += 1;
    }
}

/// Repeatedly sync an Immutable database to the server's state.
async fn run_immutable<E>(context: E, config: Config) -> Result<(), Box<dyn std::error::Error>>
where
    E: Storage + Clock + Metrics + Network + Spawner,
{
    info!("starting Immutable database sync process");
    let mut iteration = 0u32;
    loop {
        let resolver = Resolver::<immutable::Operation, Key>::connect(
            context.with_label("resolver"),
            config.server,
        )
        .await?;

        let initial_target = resolver.get_sync_target().await?;

        let db_config = immutable::create_config();
        let (update_sender, update_receiver) = mpsc::channel(UPDATE_CHANNEL_SIZE);

        let target_update_handle = {
            let resolver = resolver.clone();
            let initial_target_clone = initial_target.clone();
            let target_update_interval = config.target_update_interval;
            context.with_label("target_update").spawn(move |context| {
                target_update_task(
                    context,
                    resolver,
                    update_sender,
                    target_update_interval,
                    initial_target_clone,
                )
            })
        };

        let sync_config =
            sync::engine::Config::<immutable::Database<_>, Resolver<immutable::Operation, Key>> {
                context: context.with_label("sync"),
                db_config,
                fetch_batch_size: config.batch_size,
                target: initial_target,
                resolver,
                apply_batch_size: 1024,
                max_outstanding_requests: config.max_outstanding_requests,
                update_rx: Some(update_receiver),
            };

        let database: immutable::Database<_> = sync::sync(sync_config).await?;
        let got_root = database.root();
        info!(
            sync_iteration = iteration,
            root = %got_root,
            sync_interval = ?config.sync_interval,
            "✅ Immutable sync completed successfully"
        );
        database.close().await?;
        target_update_handle.abort();
        context.sleep(config.sync_interval).await;
        iteration += 1;
    }
}

fn parse_config() -> Result<Config, Box<dyn std::error::Error>> {
    // Parse command line arguments
    let matches = Command::new("Sync Client")
        .version(crate_version())
        .about("Continuously syncs a database to a server's database state")
        .arg(
            Arg::new("db")
                .long("db")
                .value_name("any|immutable")
                .help("Database type to use. Must be `any` or `immutable`.")
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
                .help("Batch size for fetching operations")
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
                .help("Interval for requesting target updates ('ms', 's', 'm', 'h')")
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
                .help("Maximum number of outstanding sync requests")
                .default_value("1"),
        )
        .get_matches();

    let database_type = matches
        .get_one::<String>("db")
        .unwrap()
        .parse::<DatabaseType>()
        .map_err(|e| format!("Invalid database type: {e}"))?;

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
        database_type,
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
        eprintln!("❌ Configuration error: {e}");
        std::process::exit(1);
    });

    let executor_config =
        tokio_runtime::Config::default().with_storage_directory(config.storage_dir.clone());
    let executor = tokio_runtime::Runner::new(executor_config);
    executor.start(|context| async move {
        tokio_runtime::telemetry::init(
            context.with_label("telemetry"),
            tokio_runtime::telemetry::Logging {
                level: tracing::Level::INFO,
                json: false,
            },
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, config.metrics_port))),
            None,
        );
        info!(
            database_type = %config.database_type.as_str(),
            server = %config.server,
            batch_size = config.batch_size,
            storage_dir = %config.storage_dir,
            metrics_port = config.metrics_port,
            target_update_interval = ?config.target_update_interval,
            sync_interval = ?config.sync_interval,
            max_outstanding_requests = config.max_outstanding_requests,
            "client starting with configuration"
        );

        // Dispatch based on database type
        let result = match config.database_type {
            DatabaseType::Any => run_any(context.with_label("sync"), config).await,
            DatabaseType::Immutable => run_immutable(context.with_label("sync"), config).await,
        };

        if let Err(err) = result {
            error!(?err, "❌ continuous sync failed");
            std::process::exit(1);
        }
    });
}
