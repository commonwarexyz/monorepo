//! This client demonstrates how to use the [commonware_storage::adb::any::sync] functionality
//! to synchronize to the server's state. It fetches server metadata to determine sync parameters
//! and then performs the actual sync operation. It uses the [Resolver] trait to fetch operations
//! from the server and periodically requests target updates for dynamic sync.

use clap::{Arg, Command};
use commonware_cryptography::sha256::Digest;
use commonware_runtime::{tokio as tokio_runtime, Metrics as _, Runner};
use commonware_storage::{
    adb::any::sync::{self, client::Config as SyncConfig, SyncTarget},
    mmr::hasher::Standard,
};
use commonware_sync::{crate_version, create_adb_config, parse_duration, Database, Resolver};
use futures::channel::mpsc;
use rand::Rng;
use std::{
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroU64,
    time::Duration,
};
use tracing::{error, info, warn};

/// Default server address.
const DEFAULT_SERVER: &str = "127.0.0.1:8080";

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
}

#[derive(Debug)]
struct ServerMetadata {
    target_hash: Digest,
    oldest_retained_loc: u64,
    latest_op_loc: u64,
}

/// Get server metadata to determine sync parameters.
async fn get_server_metadata<E>(
    resolver: &Resolver<E>,
) -> Result<ServerMetadata, Box<dyn std::error::Error>>
where
    E: commonware_runtime::Network + Clone,
{
    info!("Requesting server metadata...");

    let metadata = resolver.get_server_metadata().await?;
    let metadata = ServerMetadata {
        target_hash: metadata.target_hash,
        oldest_retained_loc: metadata.oldest_retained_loc,
        latest_op_loc: metadata.latest_op_loc,
    };
    info!(?metadata, "Received server metadata");
    Ok(metadata)
}

/// Periodically request target updates from server and send them to sync client
/// on `update_sender`.
async fn target_update_task<E>(
    context: E,
    resolver: Resolver<E>,
    update_sender: mpsc::Sender<SyncTarget<Digest>>,
    interval_duration: Duration,
    initial_target: SyncTarget<Digest>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    E: commonware_runtime::Network + commonware_runtime::Clock + Clone,
{
    let mut current_target = initial_target;

    // Initial sleep before first update check
    context.sleep(interval_duration).await;

    loop {
        context.sleep(interval_duration).await;

        // Request target update from server
        match resolver.get_target_update().await {
            Ok(new_target) => {
                // Check if target has changed
                if new_target.hash != current_target.hash {
                    info!(
                        old_target = ?current_target,
                        new_target = ?new_target,
                        "Target updated from server"
                    );

                    // Send new target to sync client
                    if let Err(e) = update_sender.clone().try_send(new_target.clone()) {
                        warn!(error = %e, "Failed to send target update to sync client");
                    } else {
                        current_target = new_target;
                    }
                } else {
                    info!("Target unchanged from server");
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to get target update from server");
                // Continue trying on next interval
            }
        }
    }
}

/// Create a new database synced to the server's state.
async fn sync<E>(
    context: E,
    resolver: Resolver<E>,
    config: Config,
) -> Result<Database<E>, Box<dyn std::error::Error>>
where
    E: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
        + commonware_runtime::Network
        + commonware_runtime::Spawner
        + Clone,
{
    info!(server = %config.server, "Starting sync to server's database state");

    // Get server metadata to determine sync parameters
    let ServerMetadata {
        target_hash,
        oldest_retained_loc,
        latest_op_loc,
    } = get_server_metadata(&resolver).await?;

    info!(
        lower_bound = oldest_retained_loc,
        upper_bound = latest_op_loc,
        "Sync parameters"
    );

    // Create database configuration
    let db_config = create_adb_config();
    info!("Created local database");

    // Create channel for target updates
    let (update_sender, update_receiver) = mpsc::channel(16);

    // Create initial sync target
    let initial_target = SyncTarget {
        hash: target_hash,
        lower_bound_ops: oldest_retained_loc,
        upper_bound_ops: latest_op_loc,
    };

    // Start target update task
    let target_resolver = Resolver::new(context.clone(), config.server);
    let target_update_interval = config.target_update_interval;
    let initial_target_clone = initial_target.clone();
    let target_context = context.clone();
    let _target_update_handle = context.with_label("target-update").spawn(move |_| {
        target_update_task(
            target_context,
            target_resolver,
            update_sender,
            target_update_interval,
            initial_target_clone,
        )
    });

    // Create sync configuration with target update receiver
    let sync_config = SyncConfig::<
        E,
        commonware_sync::Key,
        commonware_sync::Value,
        commonware_sync::Hasher,
        commonware_sync::Translator,
        Resolver<E>,
    > {
        context: context.clone(),
        db_config,
        fetch_batch_size: NonZeroU64::new(config.batch_size).unwrap(),
        target: initial_target,
        resolver,
        hasher: Standard::new(),
        apply_batch_size: 1024,
        update_receiver: Some(update_receiver),
    };

    info!(
        batch_size = config.batch_size,
        lower_bound = sync_config.target.lower_bound_ops,
        upper_bound = sync_config.target.upper_bound_ops,
        target_update_interval = ?config.target_update_interval,
        "Sync configuration",
    );

    // Do the sync with target updates
    info!("Beginning sync operation...");
    let database = sync::sync(sync_config).await?;

    // Get the root hash of the synced database
    let mut hasher = Standard::new();
    let root_hash = database.root(&mut hasher);

    let root_hash_hex = root_hash
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    info!(
        database_ops = database.op_count(),
        root_hash = %root_hash_hex,
        "✅ Sync completed successfully"
    );

    Ok(database)
}

fn main() {
    // Parse command line arguments
    let matches = Command::new("Sync Client")
        .version(crate_version())
        .about("Syncs a database to a server's database state")
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
                .default_value("/tmp/commonware-sync/client"),
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
                .help("Interval for requesting target updates in 's' or 'ms'")
                .default_value("1s"),
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
            let base_dir = matches
                .get_one::<String>("storage-dir")
                .unwrap()
                .to_string();
            let suffix: u64 = rand::thread_rng().gen();
            format!("{base_dir}-{suffix}")
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
    };

    info!("Sync Client starting");
    info!(
        server = %config.server,
        batch_size = config.batch_size,
        storage_dir = %config.storage_dir,
        metrics_port = config.metrics_port,
        target_update_interval = ?config.target_update_interval,
        "Configuration"
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

        // Create the network resolver with the runtime context
        let resolver = Resolver::new(context.with_label("resolver"), config.server);

        // Perform the sync operation
        match sync(context.with_label("sync"), resolver, config).await {
            Ok(_database) => {
                // _database is now synced to the server's state.
                // We don't use it in this example, but at this point it's ready to be used.
            }
            Err(e) => {
                error!(error = %e, "❌ Sync failed");
                std::process::exit(1);
            }
        }
    });
}
