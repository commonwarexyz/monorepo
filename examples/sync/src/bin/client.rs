//! This client demonstrates how to use the [commonware_storage::adb::any::sync] functionality
//! to synchronize to the server's state. It uses the [Resolver] to fetch operations and sync
//! target updates from the server, and continuously syncs to demonstrate that sync works
//! with both empty and already-initialized databases.

use clap::{Arg, Command};
use commonware_runtime::{tokio as tokio_runtime, Metrics as _, Runner};
use commonware_storage::adb::sync::Target;
use commonware_sync::any::{create_config, Database as AnyDb, Operation as AnyOp};
use commonware_sync::immutable::Operation as ImmOp;
use commonware_sync::immutable::{create_config as create_imm_config, Database as ImmDb};
use commonware_sync::net::Resolver;
use commonware_sync::Digest;
use commonware_sync::{crate_version, Error, Key};
use commonware_utils::parse_duration;
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
    /// Server address to connect to.
    server: SocketAddr,
    /// Batch size for fetching operations.
    batch_size: u64,
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

/// Periodically request target updates from server and send them to sync client on `update_sender`.
async fn target_update_task<E, Op, D>(
    context: E,
    resolver: Resolver<E, Op, D>,
    update_sender: mpsc::Sender<Target<D>>,
    interval_duration: Duration,
    initial_target: Target<D>,
) -> Result<(), Error>
where
    E: commonware_runtime::Network + commonware_runtime::Clock + commonware_runtime::Spawner,
    Op: commonware_codec::Read<Cfg = ()>
        + commonware_codec::Write
        + commonware_codec::EncodeSize
        + Clone
        + Send
        + Sync
        + 'static,
    D: commonware_cryptography::Digest,
{
    let mut current_target = initial_target;

    loop {
        context.sleep(interval_duration).await;

        match resolver.get_sync_target().await {
            Ok(new_target) => {
                if new_target.root != current_target.root {
                    match update_sender.clone().try_send(new_target.clone()) {
                        Ok(()) => {
                            info!(old_target = ?current_target, new_target = ?new_target, "target updated");
                            current_target = new_target;
                        }
                        Err(e) if e.is_disconnected() => {
                            debug!("sync client disconnected, terminating target update task");
                            return Ok(());
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to send target update to sync client");
                            return Err(Error::TargetUpdateChannel {
                                reason: e.to_string(),
                            });
                        }
                    }
                } else {
                    debug!(current_target = ?current_target, "target unchanged");
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to get sync target from server");
            }
        }
    }
}

/// Run sync for Any database.
async fn run_any<E>(context: E, config: Config) -> Result<(), String>
where
    E: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
        + commonware_runtime::Network
        + commonware_runtime::Spawner
        + Clone,
{
    use commonware_storage::adb::sync::{self, engine::EngineConfig};

    info!("starting Any database sync process");
    let mut iteration = 1u32;
    loop {
        let resolver = Resolver::<_, AnyOp, Digest>::new(context.clone(), config.server);

        let initial_target = resolver
            .get_sync_target()
            .await
            .map_err(|e| e.to_string())?;

        let db_config = create_config();
        let (update_sender, update_receiver) = mpsc::channel(UPDATE_CHANNEL_SIZE);

        let target_update_handle = {
            let resolver = resolver.clone();
            let initial_target_clone = initial_target.clone();
            let target_update_interval = config.target_update_interval;
            context.with_label("target-update").spawn(move |context| {
                target_update_task(
                    context,
                    resolver,
                    update_sender,
                    target_update_interval,
                    initial_target_clone,
                )
            })
        };

        let sync_config = EngineConfig::<AnyDb<_>, Resolver<_, AnyOp, Digest>> {
            context: context.clone(),
            db_config,
            fetch_batch_size: NonZeroU64::new(config.batch_size).unwrap(),
            target: initial_target,
            resolver,
            apply_batch_size: 1024,
            max_outstanding_requests: config.max_outstanding_requests,
            update_receiver: Some(update_receiver),
        };

        let database: AnyDb<_> = sync::sync(sync_config).await.map_err(|e| format!("{e}"))?;
        let got_root = {
            let mut hasher = commonware_storage::mmr::hasher::Standard::new();
            database.root(&mut hasher)
        };
        info!(
            sync_iteration = iteration,
            root = %got_root,
            sync_interval = ?config.sync_interval,
            "✅ Any sync completed successfully"
        );
        database.close().await.map_err(|e| format!("{e}"))?;
        target_update_handle.abort();
        context.sleep(config.sync_interval).await;
        iteration += 1;
    }
}

/// Run sync for Immutable database.
async fn run_immutable<E>(context: E, config: Config) -> Result<(), String>
where
    E: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
        + commonware_runtime::Network
        + commonware_runtime::Spawner
        + Clone,
{
    use commonware_storage::adb::sync::{self, engine::EngineConfig};

    info!("starting Immutable database sync process");
    let mut iteration = 1u32;
    loop {
        let resolver = Resolver::<_, ImmOp, Key>::new(context.clone(), config.server);

        let initial_target = resolver
            .get_sync_target()
            .await
            .map_err(|e| e.to_string())?;

        let db_config = create_imm_config();
        let (update_sender, update_receiver) = mpsc::channel(UPDATE_CHANNEL_SIZE);

        let target_update_handle = {
            let resolver = resolver.clone();
            let initial_target_clone = initial_target.clone();
            let target_update_interval = config.target_update_interval;
            context.with_label("target-update").spawn(move |context| {
                target_update_task(
                    context,
                    resolver,
                    update_sender,
                    target_update_interval,
                    initial_target_clone,
                )
            })
        };

        let sync_config = EngineConfig::<ImmDb<_>, Resolver<_, ImmOp, Key>> {
            context: context.clone(),
            db_config,
            fetch_batch_size: NonZeroU64::new(config.batch_size).unwrap(),
            target: initial_target,
            resolver,
            apply_batch_size: 1024,
            max_outstanding_requests: config.max_outstanding_requests,
            update_receiver: Some(update_receiver),
        };

        let database: ImmDb<_> = sync::sync(sync_config).await.map_err(|e| format!("{e}"))?;
        let got_root = {
            let mut hasher = commonware_storage::mmr::hasher::Standard::new();
            database.root(&mut hasher)
        };
        info!(
            sync_iteration = iteration,
            root = %got_root,
            sync_interval = ?config.sync_interval,
            "✅ Immutable sync completed successfully"
        );
        database.close().await.map_err(|e| format!("{e}"))?;
        target_update_handle.abort();
        context.sleep(config.sync_interval).await;
        iteration += 1;
    }
}

fn main() {
    // Parse command line arguments
    let matches = Command::new("Sync Client")
        .version(crate_version())
        .about("Continuously syncs a database to a server's database state")
        .arg(
            Arg::new("db")
                .long("db")
                .value_name("any|immutable")
                .help("Database type to use")
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

    let config = Config {
        server: matches
            .get_one::<String>("server")
            .unwrap()
            .parse()
            .unwrap_or_else(|e| {
                eprintln!("❌ Invalid server address: {e}");
                std::process::exit(1);
            }),
        batch_size: matches
            .get_one::<String>("batch-size")
            .unwrap()
            .parse()
            .unwrap_or_else(|e| {
                eprintln!("❌ Invalid batch size: {e}");
                std::process::exit(1);
            }),
        storage_dir: {
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
        },
        metrics_port: matches
            .get_one::<String>("metrics-port")
            .unwrap()
            .parse()
            .unwrap_or_else(|e| {
                eprintln!("❌ Invalid metrics port: {e}");
                std::process::exit(1);
            }),
        target_update_interval: parse_duration(
            matches.get_one::<String>("target-update-interval").unwrap(),
        )
        .unwrap_or_else(|e| {
            eprintln!("❌ Invalid target update interval: {e}");
            std::process::exit(1);
        }),
        sync_interval: parse_duration(matches.get_one::<String>("sync-interval").unwrap())
            .unwrap_or_else(|e| {
                eprintln!("❌ Invalid sync interval: {e}");
                std::process::exit(1);
            }),
        max_outstanding_requests: matches
            .get_one::<String>("max-outstanding-requests")
            .unwrap()
            .parse()
            .unwrap_or_else(|e| {
                eprintln!("❌ Invalid max outstanding requests: {e}");
                std::process::exit(1);
            }),
    };
    info!(
        server = %config.server,
        batch_size = config.batch_size,
        storage_dir = %config.storage_dir,
        metrics_port = config.metrics_port,
        target_update_interval = ?config.target_update_interval,
        sync_interval = ?config.sync_interval,
        max_outstanding_requests = config.max_outstanding_requests,
        "client starting with configuration"
    );

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

        // Dispatch based on db flag
        let db_choice = matches.get_one::<String>("db").unwrap().as_str();
        let result = match db_choice {
            "any" => run_any(context.with_label("sync"), config).await,
            "immutable" => run_immutable(context.with_label("sync"), config).await,
            other => Err(format!("unsupported --db value: {other}")),
        };

        if let Err(e) = result {
            error!(error = %e, "❌ continuous sync failed");
            std::process::exit(1);
        }
    });
}
