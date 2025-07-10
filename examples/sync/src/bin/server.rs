//! ADB sync server that serves operations and proofs to clients.

use clap::{Arg, Command};
use commonware_codec::{DecodeExt, Encode};
use commonware_runtime::{tokio as tokio_runtime, Listener, Network, Runner, Spawner as _};
use commonware_storage::mmr::hasher::Standard;
use commonware_sync::{
    crate_version, create_adb_config, create_test_operations, generate_db_id, read_message,
    send_message, Database, ErrorResponse, GetOperationsRequest, GetOperationsResponse,
    GetServerMetadataRequest, GetServerMetadataResponse, Message, NetworkError, Operation,
    ProtocolError,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

const MAX_BATCH_SIZE: u64 = 100;

/// Server configuration.
#[derive(Debug)]
struct ServerConfig {
    /// Port to listen on.
    port: u16,
    /// Number of initial operations to create.
    initial_ops: usize,
    /// Storage directory.
    storage_dir: String,
    /// Seed for generating test operations.
    seed: u64,
}

/// Server state containing the database and metrics.
struct ServerState<E>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
{
    /// The database wrapped in async mutex.
    database: Arc<Mutex<Database<E>>>,
    /// Request counter for metrics.
    request_counter: AtomicU64,
    /// Error counter for metrics.
    error_counter: AtomicU64,
}

impl<E> ServerState<E>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
{
    fn new(database: Database<E>) -> Self {
        Self {
            database: Arc::new(Mutex::new(database)),
            request_counter: AtomicU64::new(0),
            error_counter: AtomicU64::new(0),
        }
    }

    fn inc_requests(&self) {
        self.request_counter.fetch_add(1, Ordering::SeqCst);
    }

    fn inc_errors(&self) {
        self.error_counter.fetch_add(1, Ordering::SeqCst);
    }

    fn get_stats(&self) -> (u64, u64) {
        (
            self.request_counter.load(Ordering::SeqCst),
            self.error_counter.load(Ordering::SeqCst),
        )
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

/// Handle a [GetServerMetadataRequest] and return server state information.
async fn handle_get_server_metadata_request<E>(
    state: &ServerState<E>,
    request: GetServerMetadataRequest,
) -> Result<GetServerMetadataResponse, ProtocolError>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
{
    request.validate()?;
    state.inc_requests();

    let database = state.database.lock().await;

    // Get the current database state
    let oldest_retained_loc = database.oldest_retained_loc().unwrap_or(0);
    let latest_op_loc = database.op_count().saturating_sub(1);

    let target_hash = {
        let mut hasher = Standard::new();
        database.root(&mut hasher)
    };

    drop(database);

    let response = GetServerMetadataResponse::new(
        request.request_id,
        target_hash,
        oldest_retained_loc,
        latest_op_loc,
    );
    info!(?response, "Serving metadata");
    Ok(response)
}

/// Handle a GetOperationsRequest and return operations with proof.
async fn handle_get_operations_request<E>(
    state: &ServerState<E>,
    request: GetOperationsRequest,
) -> Result<GetOperationsResponse, ProtocolError>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
{
    request.validate()?;
    state.inc_requests();

    let database = state.database.lock().await;

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

    // Serialize the proof and operations
    let proof_bytes = proof.encode().to_vec();
    let operations_bytes = operations.encode().to_vec();

    info!(
        operations_len = operations.len(),
        proof_bytes_len = proof_bytes.len(),
        "Sending operations with proof"
    );

    Ok(GetOperationsResponse::new(
        request.request_id,
        proof_bytes,
        operations_bytes,
    ))
}

/// Handle a client connection using commonware-runtime networking with message framing.
async fn handle_client<E>(
    state: Arc<ServerState<E>>,
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
        let message_data = match read_message(&mut stream).await {
            Ok(data) => data,
            Err(NetworkError::ReadFailed(_)) => {
                info!(client_addr = %client_addr, "Client disconnected");
                break;
            }
            Err(e) => {
                error!(client_addr = %client_addr, error = %e, "❌ Connection error");
                state.inc_errors();
                break;
            }
        };

        // Parse the message
        let message: Message = match Message::decode(&message_data[..]) {
            Ok(msg) => msg,
            Err(e) => {
                error!(client_addr = %client_addr, error = %e, "❌ Failed to parse message");
                state.inc_errors();
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
                        state.inc_errors();
                        Message::Error(e.into())
                    }
                }
            }
            Message::GetServerMetadataRequest(request) => {
                match handle_get_server_metadata_request(&state, request).await {
                    Ok(response) => Message::GetServerMetadataResponse(response),
                    Err(e) => {
                        warn!(client_addr = %client_addr, error = %e, "❌ GetServerMetadata failed");
                        state.inc_errors();
                        Message::Error(e.into())
                    }
                }
            }
            _ => {
                warn!(client_addr = %client_addr, "❌ Unexpected message type");
                state.inc_errors();
                Message::Error(ErrorResponse::new(
                    None,
                    commonware_sync::ErrorCode::InvalidRequest,
                    "Unexpected message type".to_string(),
                ))
            }
        };

        // Send the response with length prefix
        let response_data = response.encode().to_vec();
        if let Err(e) = send_message(&mut sink, &response_data).await {
            error!(client_addr = %client_addr, error = %e, "❌ Failed to send response");
            state.inc_errors();
            break;
        }
    }

    Ok(())
}

fn main() {
    // Initialize tracing with a clean format
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    // Parse command line arguments
    let matches = Command::new("ADB Sync Server")
        .version(crate_version())
        .about("Serves ADB operations and proofs to sync clients")
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
                .default_value("/tmp/adb_sync_server"),
        )
        .arg(
            Arg::new("seed")
                .short('s')
                .long("seed")
                .value_name("SEED")
                .help("Seed for generating test operations")
                .default_value("1337"),
        )
        .get_matches();

    let config = ServerConfig {
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
    };

    info!("ADB Sync Server starting");
    info!(
        port = config.port,
        initial_ops = config.initial_ops,
        storage_dir = %config.storage_dir,
        "Configuration"
    );

    let executor = tokio_runtime::Runner::default();
    executor.start(|context| async move {
        // Create and initialize database
        let db_id = generate_db_id(&context);
        let db_config = create_adb_config(&db_id);

        info!(db_id = %db_id, "Initializing database");

        let mut database = match Database::init(context.clone(), db_config).await {
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
        let root_hash = database.root(&mut hasher);
        let root_hash_hex = root_hash
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        info!(
            op_count = database.op_count(),
            root_hash = %root_hash_hex,
            "Database ready"
        );

        // Create listener to accept connections
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, config.port));
        let mut listener = match context.bind(addr).await {
            Ok(listener) => listener,
            Err(e) => {
                error!(addr = %addr, error = %e, "❌ Failed to bind");
                return;
            }
        };

        info!(addr = %addr, "Server listening");

        // Handle each client connection in a separate task.
        let state = Arc::new(ServerState::new(database));
        loop {
            match listener.accept().await {
                Ok((client_addr, sink, stream)) => {
                    let state = state.clone();
                    context.clone().spawn(move|_|async move {
                        if let Err(e) =
                            handle_client(state.clone(), sink, stream, client_addr).await
                        {
                            error!(client_addr = %client_addr, error = %e, "❌ Error handling client");
                        }

                        // Log server stats periodically
                        let (requests, errors) = state.get_stats();
                        if requests > 0 && requests % 10 == 0 {
                            info!(requests, errors, "Server stats");
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
