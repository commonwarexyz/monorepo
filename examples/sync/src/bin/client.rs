//! This client demonstrates how to use the [commonware_storage::adb::any::sync] functionality
//! to synchronize to the server's state. It fetches server metadata to determine sync parameters
//! and then performs the actual sync operation. It uses the [Resolver] trait to fetch operations
//! from the server.

use clap::{Arg, Command};
use commonware_cryptography::sha256::Digest;
use commonware_runtime::{tokio as tokio_runtime, Metrics as _, Runner};
use commonware_storage::{
    adb::any::sync::{self, client::Config as SyncConfig, SyncTarget},
    mmr::hasher::Standard,
};
use commonware_sync::{crate_version, create_adb_config, Database, Resolver};
use std::{
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroU64,
};
use tracing::{error, info};

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
}

#[derive(Debug)]
struct ServerMetadata {
    root: Digest,
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
        root: metadata.root,
        oldest_retained_loc: metadata.oldest_retained_loc,
        latest_op_loc: metadata.latest_op_loc,
    };
    info!(?metadata, "Received server metadata");
    Ok(metadata)
}

/// Create a new database synced to the server's state.
async fn sync<E>(
    context: E,
    resolver: Resolver<E>,
    config: &Config,
) -> Result<Database<E>, Box<dyn std::error::Error>>
where
    E: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
        + commonware_runtime::Network,
{
    info!(server = %config.server, "Starting sync to server's database state");

    // Get server metadata to determine sync parameters
    let ServerMetadata {
        root,
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

    // Create sync configuration
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
        target: SyncTarget {
            root,
            lower_bound_ops: oldest_retained_loc,
            upper_bound_ops: latest_op_loc,
        },
        resolver,
        hasher: Standard::new(),
        apply_batch_size: 1024,
        update_receiver: None,
    };

    info!(
        batch_size = config.batch_size,
        lower_bound = sync_config.target.lower_bound_ops,
        upper_bound = sync_config.target.upper_bound_ops,
        "Sync configuration"
    );

    // Do the sync.
    info!("Beginning sync operation...");
    let database = sync::sync(sync_config).await?;

    // Get the root digest of the synced database
    let mut hasher = Standard::new();
    let got_root = database.root(&mut hasher);

    // Verify the digest matches the  target digest.
    if got_root != root {
        return Err(format!(
            "Synced database root digest does not match target root digest: {got_root:?} != {root:?}"
        )
        .into());
    }

    let root_hex = got_root
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    info!(
        database_ops = database.op_count(),
        root = %root_hex,
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
        storage_dir: matches
            .get_one::<String>("storage-dir")
            .unwrap()
            .to_string(),
        metrics_port: matches
            .get_one::<String>("metrics-port")
            .unwrap()
            .parse()
            .unwrap_or_else(|e| {
                eprintln!("❌ Invalid metrics port: {e}");
                std::process::exit(1);
            }),
    };

    info!("Sync Client starting");
    info!(
        server = %config.server,
        batch_size = config.batch_size,
        storage_dir = %config.storage_dir,
        metrics_port = config.metrics_port,
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
        match sync(context.with_label("sync"), resolver, &config).await {
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
