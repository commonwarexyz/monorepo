//! Server that serves operations and proofs to clients attempting to sync a
//! [commonware_storage::adb::any::Any] database.

use clap::{Arg, Command};
use commonware_codec::{DecodeExt, Encode};
use commonware_runtime::{
    tokio as tokio_runtime, Listener, Metrics as _, Network, Runner, RwLock, Spawner as _,
};
use commonware_storage::mmr::hasher::Standard;
use commonware_stream::utils::codec::{recv_frame, send_frame};
use commonware_sync::{
    crate_version, create_adb_config, create_test_operations, Database, ErrorResponse,
    GetOperationsRequest, GetOperationsResponse, GetServerMetadataResponse, Message, Operation,
    ProtocolError, MAX_MESSAGE_SIZE,
};
use prometheus_client::metrics::counter::Counter;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tracing::{error, info, warn};

const MAX_BATCH_SIZE: u64 = 100;

/// Server configuration.
#[derive(Debug)]
struct Config {
    /// Port to listen on.
    port: u16,
    /// Number of initial operations to create.
    initial_ops: usize,
    /// Storage directory.
    storage_dir: String,
    /// Seed for generating test operations.
    seed: u64,
    /// Port on which metrics are exposed.
    metrics_port: u16,
}

/// Server state containing the database and metrics.
struct State<E>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
{
    /// The database wrapped in async mutex.
    database: Arc<RwLock<Database<E>>>,
    /// Request counter for metrics.
    request_counter: Counter,
    /// Error counter for metrics.
    error_counter: Counter,
}

impl<E> State<E>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
{
    fn new(context: E, database: Database<E>) -> Self {
        let state = Self {
            database: Arc::new(RwLock::new(database)),
            request_counter: Counter::default(),
            error_counter: Counter::default(),
        };
        context.register(
            "request",
            "Number of requests",
            state.request_counter.clone(),
        );
        context.register("error", "Number of errors", state.error_counter.clone());
        state
    }
}

/// Add operations to the database.
async fn add_operations<E>(
    database: &mut Database<E>,
    operations: Vec<Operation>,
) -> Result<(), commonware_storage::adb::Error>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
{
    for operation in operations {
        match operation {
            Operation::Update(key, value) => {
                database.update(key, value).await?;
            }
            Operation::Deleted(key) => {
                database.delete(key).await?;
            }
            Operation::Commit(_) => {
                database.commit().await?;
            }
        }
    }
    Ok(())
}

/// Handle a request for server state information.
async fn handle_get_server_metadata_request<E>(
    state: &State<E>,
) -> Result<GetServerMetadataResponse, ProtocolError>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
{
    state.request_counter.inc();

    let database = state.database.read().await;

    // Get the current database state
    let oldest_retained_loc = database.oldest_retained_loc().unwrap_or(0);
    let latest_op_loc = database.op_count().saturating_sub(1);

    let root = {
        let mut hasher = Standard::new();
        database.root(&mut hasher)
    };

    drop(database);

    let response = GetServerMetadataResponse {
        root,
        oldest_retained_loc,
        latest_op_loc,
    };
    info!(?response, "Serving metadata");
    Ok(response)
}

/// Handle a GetOperationsRequest and return operations with proof.
async fn handle_get_operations_request<E>(
    state: &State<E>,
    request: GetOperationsRequest,
) -> Result<GetOperationsResponse, ProtocolError>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
{
    request.validate()?;
    state.request_counter.inc();

    let database = state.database.read().await;

    // Check if we have enough operations
    let db_size = database.op_count();
    if request.start_loc >= db_size {
        return Err(ProtocolError::InvalidRequest {
            message: format!(
                "start_loc >= database size ({}) >= ({})",
                request.start_loc, db_size
            ),
        });
    }

    // Calculate how many operations to return
    let max_ops = std::cmp::min(request.max_ops.get(), db_size - request.start_loc);
    let max_ops = std::cmp::min(max_ops, MAX_BATCH_SIZE);

    info!(
        max_ops,
        start_loc = request.start_loc,
        db_size,
        "Operations request"
    );

    // Get the historical proof and operations
    let result = database
        .historical_proof(request.size, request.start_loc, max_ops)
        .await;

    drop(database);

    let (proof, operations) = result.map_err(|e| {
        warn!(error = %e, "❌ Failed to generate historical proof");
        ProtocolError::DatabaseError(e)
    })?;

    info!(
        operations_len = operations.len(),
        proof_len = proof.digests.len(),
        "Sending operations and proof"
    );

    Ok(GetOperationsResponse { proof, operations })
}

/// Handle a client connection using [commonware_runtime::Network].
async fn handle_client<E>(
    state: Arc<State<E>>,
    mut sink: commonware_runtime::SinkOf<E>,
    mut stream: commonware_runtime::StreamOf<E>,
    client_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>>
where
    E: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
        + commonware_runtime::Network,
{
    info!(client_addr = %client_addr, "Client connected");

    loop {
        // Read length-prefixed message
        let message_data = match recv_frame(&mut stream, MAX_MESSAGE_SIZE).await {
            Ok(data) => data,
            Err(e) => {
                info!(client_addr = %client_addr, error = %e, "Recv failed (likely because client disconnected)");
                state.error_counter.inc();
                break;
            }
        };

        // Parse the message
        let message: Message = match Message::decode(&message_data[..]) {
            Ok(msg) => msg,
            Err(e) => {
                error!(client_addr = %client_addr, error = %e, "❌ Failed to parse message");
                state.error_counter.inc();
                continue;
            }
        };

        // Handle the message
        let response = match message {
            Message::GetOperationsRequest(request) => {
                match handle_get_operations_request(&state, request).await {
                    Ok(response) => Message::GetOperationsResponse(response),
                    Err(e) => {
                        warn!(client_addr = %client_addr, error = %e, "❌ GetOperations failed");
                        state.error_counter.inc();
                        Message::Error(e.into())
                    }
                }
            }
            Message::GetServerMetadataRequest => {
                match handle_get_server_metadata_request(&state).await {
                    Ok(response) => Message::GetServerMetadataResponse(response),
                    Err(e) => {
                        warn!(client_addr = %client_addr, error = %e, "❌ GetServerMetadata failed");
                        state.error_counter.inc();
                        Message::Error(e.into())
                    }
                }
            }
            _ => {
                warn!(client_addr = %client_addr, "❌ Unexpected message type");
                state.error_counter.inc();
                Message::Error(ErrorResponse {
                    error_code: commonware_sync::ErrorCode::InvalidRequest,
                    message: "Unexpected message type".to_string(),
                })
            }
        };

        // Send the response with length prefix
        let response_data = response.encode().to_vec();
        if let Err(e) = send_frame(&mut sink, &response_data, MAX_MESSAGE_SIZE).await {
            info!(client_addr = %client_addr, error = %e, "Send failed (likely because client disconnected)");
            state.error_counter.inc();
            break;
        }
    }

    Ok(())
}

fn main() {
    // Parse command line arguments
    let matches = Command::new("Sync Server")
        .version(crate_version())
        .about("Serves database operations and proofs to sync clients")
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .help("Port to listen on")
                .default_value("8080"),
        )
        .arg(
            Arg::new("initial-ops")
                .short('i')
                .long("initial-ops")
                .value_name("COUNT")
                .help("Number of initial operations to create")
                .default_value("100"),
        )
        .arg(
            Arg::new("storage-dir")
                .short('d')
                .long("storage-dir")
                .value_name("PATH")
                .help("Storage directory for database")
                .default_value("/tmp/commonware-sync/server"),
        )
        .arg(
            Arg::new("seed")
                .short('s')
                .long("seed")
                .value_name("SEED")
                .help("Seed for generating test operations")
                .default_value("1337"),
        )
        .arg(
            Arg::new("metrics-port")
                .short('m')
                .long("metrics-port")
                .value_name("PORT")
                .help("Port on which metrics are exposed")
                .default_value("9090"),
        )
        .get_matches();

    let config = Config {
        port: matches
            .get_one::<String>("port")
            .unwrap()
            .parse()
            .unwrap_or_else(|e| {
                eprintln!("❌ Invalid port: {e}");
                std::process::exit(1);
            }),
        initial_ops: matches
            .get_one::<String>("initial-ops")
            .unwrap()
            .parse()
            .unwrap_or_else(|e| {
                eprintln!("❌ Invalid initial operations count: {e}");
                std::process::exit(1);
            }),
        storage_dir: matches
            .get_one::<String>("storage-dir")
            .unwrap()
            .to_string(),
        seed: matches
            .get_one::<String>("seed")
            .unwrap()
            .parse()
            .unwrap_or_else(|e| {
                eprintln!("❌ Invalid seed: {e}");
                std::process::exit(1);
            }),
        metrics_port: matches
            .get_one::<String>("metrics-port")
            .unwrap()
            .parse()
            .unwrap_or_else(|e| {
                eprintln!("❌ Invalid metrics port: {e}");
                std::process::exit(1);
            }),
    };

    info!(
        port = config.port,
        initial_ops = config.initial_ops,
        storage_dir = %config.storage_dir,
        seed = %config.seed,
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

        // Create and initialize database
        let db_config = create_adb_config();
        info!("Initializing database");

        let mut database = match Database::init(context.with_label("database"), db_config).await {
            Ok(db) => db,
            Err(e) => {
                error!(error = %e, "❌ Failed to initialize database");
                return;
            }
        };

        // Create and add initial operations
        let initial_ops = create_test_operations(config.initial_ops, config.seed);
        info!(operations_len = initial_ops.len(), "Creating initial operations");

        if let Err(e) = add_operations(&mut database, initial_ops).await {
            error!(error = %e, "❌ Failed to add initial operations");
            return;
        }

        // Commit the database to ensure operations are persisted
        if let Err(e) = database.commit().await {
            error!(error = %e, "❌ Failed to commit database");
            return;
        }

        // Display database state
        let mut hasher = Standard::new();
        let root = database.root(&mut hasher);
        let root_hex = root
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        info!(
            op_count = database.op_count(),
            root = %root_hex,
            "Database ready"
        );

        // Create listener to accept connections
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, config.port));
        let mut listener = match context.with_label("listener").bind(addr).await {
            Ok(listener) => listener,
            Err(e) => {
                error!(addr = %addr, error = %e, "❌ Failed to bind");
                return;
            }
        };

        info!(addr = %addr, "Server listening");

        // Handle each client connection in a separate task.
        let state = Arc::new(State::new(context.with_label("server"), database));
        loop {
            match listener.accept().await {
                Ok((client_addr, sink, stream)) => {
                    let state = state.clone();
                    context.with_label("client").spawn(move|_|async move {
                        if let Err(e) =
                            handle_client(state.clone(), sink, stream, client_addr).await
                        {
                            error!(client_addr = %client_addr, error = %e, "❌ Error handling client");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "❌ Failed to accept connection");
                    break;
                }
            }
        }
    });
}
