//! Server that serves operations and proofs to clients attempting to sync a
//! [commonware_storage::adb::any::Any] database.

use clap::{Arg, Command};
use commonware_codec::{DecodeExt, Encode};
use commonware_macros::select;
use commonware_runtime::{
    tokio as tokio_runtime, Clock, Listener, Metrics as _, Network, Runner, RwLock, Spawner as _,
};
use commonware_storage::{adb::any::sync::SyncTarget, mmr::hasher::Standard};
use commonware_stream::utils::codec::{recv_frame, send_frame};
use commonware_sync::{
    crate_version, create_adb_config, create_test_operations, Database, Error, ErrorCode,
    ErrorResponse, GetOperationsRequest, GetOperationsResponse, GetSyncTargetRequest,
    GetSyncTargetResponse, Message, Operation, MAX_MESSAGE_SIZE,
};
use commonware_utils::parse_duration;
use futures::{channel::mpsc, SinkExt, StreamExt};
use prometheus_client::metrics::counter::Counter;
use rand::{Rng, RngCore};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{debug, error, info, warn};

/// Maximum batch size for operations.
const MAX_BATCH_SIZE: u64 = 100;

/// Size of the channel for responses.
const RESPONSE_BUFFER_SIZE: usize = 64;

/// Server configuration.
#[derive(Debug, Clone)]
struct Config {
    /// Port to listen on.
    port: u16,
    /// Number of initial operations to create.
    initial_ops: usize,
    /// Storage directory.
    storage_dir: String,
    /// Port on which metrics are exposed.
    metrics_port: u16,
    /// Interval for adding new operations.
    op_interval: Duration,
    /// Number of operations to add each interval.
    ops_per_interval: usize,
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
    /// Counter for operations added.
    ops_counter: Counter,
    /// Last time we added operations.
    last_operation_time: Arc<RwLock<SystemTime>>,
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
            ops_counter: Counter::default(),
            last_operation_time: Arc::new(RwLock::new(SystemTime::now())),
        };
        context.register(
            "requests",
            "Number of requests received",
            state.request_counter.clone(),
        );
        context.register("error", "Number of errors", state.error_counter.clone());
        context.register(
            "ops_added",
            "Number of operations added since server start, not including the initial operations",
            state.ops_counter.clone(),
        );
        state
    }

    /// Add operations to the database if the configured interval has passed.
    async fn maybe_add_operations(
        &self,
        context: &mut E,
        config: &Config,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        E: commonware_runtime::Clock + RngCore,
    {
        let mut last_time = self.last_operation_time.write().await;
        let now = context.current();

        if now.duration_since(*last_time).unwrap_or(Duration::ZERO) >= config.op_interval {
            *last_time = now;

            // Generate new operations
            let new_operations =
                create_test_operations(config.ops_per_interval, context.next_u64());

            // Add operations to database and get the new root
            let root = {
                let mut database = self.database.write().await;
                for operation in new_operations.iter() {
                    let result = match operation {
                        Operation::Update(key, value) => {
                            database.update(*key, *value).await.map(|_| ())
                        }
                        Operation::Deleted(key) => database.delete(*key).await.map(|_| ()),
                        Operation::Commit(_) => database.commit().await.map(|_| ()),
                    };

                    if let Err(e) = result {
                        error!(error = %e, "failed to add operations to database");
                    }
                }
                database.root(&mut Standard::new())
            };

            self.ops_counter.inc_by(new_operations.len() as u64);
            info!(
                operations_added = new_operations.len(),
                root = %root,
                "added operations"
            );
        }

        Ok(())
    }
}

/// Add the given `operations` to the `database`.
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

/// Handle a request for sync target.
async fn handle_get_sync_target<E>(
    state: &State<E>,
    request: GetSyncTargetRequest,
) -> Result<GetSyncTargetResponse, Error>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
{
    state.request_counter.inc();

    // Get the current database state
    let (root, lower_bound_ops, upper_bound_ops) = {
        let mut hasher = Standard::new();
        let database = state.database.read().await;
        (
            database.root(&mut hasher),
            database.inactivity_floor_loc(),
            database.op_count().saturating_sub(1),
        )
    };
    let response = GetSyncTargetResponse {
        request_id: request.request_id,
        target: SyncTarget {
            root,
            lower_bound_ops,
            upper_bound_ops,
        },
    };

    debug!(?response, "serving target update");
    Ok(response)
}

/// Handle a GetOperationsRequest and return operations with proof.
async fn handle_get_operations<E>(
    state: &State<E>,
    request: GetOperationsRequest,
) -> Result<GetOperationsResponse, Error>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
{
    state.request_counter.inc();
    request.validate()?;

    let database = state.database.read().await;

    // Check if we have enough operations
    let db_size = database.op_count();
    if request.start_loc >= db_size {
        return Err(Error::InvalidRequest(format!(
            "start_loc >= database size ({}) >= ({})",
            request.start_loc, db_size
        )));
    }

    // Calculate how many operations to return
    let max_ops = std::cmp::min(request.max_ops.get(), db_size - request.start_loc);
    let max_ops = std::cmp::min(max_ops, MAX_BATCH_SIZE);

    debug!(
        request_id = request.request_id.value(),
        max_ops,
        start_loc = request.start_loc,
        db_size,
        "operations request"
    );

    // Get the historical proof and operations
    let result = database
        .historical_proof(request.size, request.start_loc, max_ops)
        .await;

    drop(database);

    let (proof, operations) = result.map_err(|e| {
        warn!(error = %e, "failed to generate historical proof");
        Error::Database(e)
    })?;

    debug!(
        request_id = request.request_id.value(),
        operations_len = operations.len(),
        proof_len = proof.digests.len(),
        "sending operations and proof"
    );

    Ok(GetOperationsResponse {
        request_id: request.request_id,
        proof,
        operations,
    })
}

/// Handle a message from a client and return the appropriate response.
async fn handle_message<E>(state: Arc<State<E>>, message: Message) -> Message
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
{
    let request_id = message.request_id();
    match message {
        Message::GetOperationsRequest(request) => {
            match handle_get_operations(&state, request).await {
                Ok(response) => Message::GetOperationsResponse(response),
                Err(e) => {
                    state.error_counter.inc();
                    Message::Error(ErrorResponse {
                        request_id,
                        error_code: e.to_error_code(),
                        message: e.to_string(),
                    })
                }
            }
        }

        Message::GetSyncTargetRequest(request) => {
            match handle_get_sync_target(&state, request).await {
                Ok(response) => Message::GetSyncTargetResponse(response),
                Err(e) => {
                    state.error_counter.inc();
                    Message::Error(ErrorResponse {
                        request_id,
                        error_code: e.to_error_code(),
                        message: e.to_string(),
                    })
                }
            }
        }

        _ => {
            state.error_counter.inc();
            Message::Error(ErrorResponse {
                request_id,
                error_code: ErrorCode::InvalidRequest,
                message: "unexpected message type".to_string(),
            })
        }
    }
}

/// Handle a client connection with concurrent request processing.
async fn handle_client<E>(
    context: E,
    state: Arc<State<E>>,
    mut sink: commonware_runtime::SinkOf<E>,
    mut stream: commonware_runtime::StreamOf<E>,
    client_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>>
where
    E: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
        + commonware_runtime::Network
        + commonware_runtime::Spawner
        + Clone,
{
    info!(client_addr = %client_addr, "client connected");

    // Wait until we receive a message from the client or we have a response to send.
    let (response_sender, mut response_receiver) = mpsc::channel::<Message>(RESPONSE_BUFFER_SIZE);
    loop {
        select! {
            incoming = recv_frame(&mut stream, MAX_MESSAGE_SIZE) => {
                match incoming {
                    Ok(message_data) => {
                        // Parse the message.
                        let message: Message = match Message::decode(&message_data[..]) {
                            Ok(msg) => msg,
                            Err(e) => {
                                warn!(client_addr = %client_addr, error = %e, "failed to parse message");
                                state.error_counter.inc();
                                continue;
                            }
                        };

                        // Start a new task to handle the message.
                        // The response will be sent on `response_sender`.
                        context.with_label("request-handler").spawn({
                            let state = state.clone();
                            let mut response_sender = response_sender.clone();
                            move |_| async move {
                                let response = handle_message(state, message).await;
                                if let Err(e) = response_sender.send(response).await {
                                    warn!(client_addr = %client_addr, error = %e, "failed to send response to main loop");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        info!(client_addr = %client_addr, error = %e, "recv failed (client likely disconnected)");
                        state.error_counter.inc();
                        break Ok(());
                    }
                }
            },

            outgoing = response_receiver.next() => {
                if let Some(response) = outgoing {
                    // We have a response to send to the client.
                    let response_data = response.encode().to_vec();
                    if let Err(e) = send_frame(&mut sink, &response_data, MAX_MESSAGE_SIZE).await {
                        info!(client_addr = %client_addr, error = %e, "send failed (client likely disconnected)");
                        state.error_counter.inc();
                        break Ok(());
                    }
                } else {
                    // Channel closed
                    break Ok(());
                }
            }
        }
    }
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
            Arg::new("metrics-port")
                .short('m')
                .long("metrics-port")
                .value_name("PORT")
                .help("Port on which metrics are exposed")
                .default_value("9090"),
        )
        .arg(
            Arg::new("op-interval")
                .short('t')
                .long("op-interval")
                .value_name("DURATION")
                .help("Interval for adding new operations ('ms', 's', 'm', 'h')")
                .default_value("100ms"),
        )
        .arg(
            Arg::new("ops-per-interval")
                .short('o')
                .long("ops-per-interval")
                .value_name("COUNT")
                .help("Number of operations to add each interval")
                .default_value("5"),
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
        storage_dir: {
            let storage_dir = matches
                .get_one::<String>("storage-dir")
                .unwrap()
                .to_string();
            // Only add suffix if using the default value
            if storage_dir == "/tmp/commonware-sync/server" {
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
        op_interval: parse_duration(matches.get_one::<String>("op-interval").unwrap())
            .unwrap_or_else(|e| {
                eprintln!("❌ Invalid operation interval: {e}");
                std::process::exit(1);
            }),
        ops_per_interval: matches
            .get_one::<String>("ops-per-interval")
            .unwrap()
            .parse()
            .unwrap_or_else(|e| {
                eprintln!("❌ Invalid ops per interval: {e}");
                std::process::exit(1);
            }),
    };
    info!(
        port = config.port,
        initial_ops = config.initial_ops,
        storage_dir = %config.storage_dir,
        metrics_port = config.metrics_port,
        op_interval = ?config.op_interval,
        ops_per_interval = config.ops_per_interval,
        "configuration"
    );

    let executor_config =
        tokio_runtime::Config::default().with_storage_directory(config.storage_dir.clone());
    let executor = tokio_runtime::Runner::new(executor_config);
    executor.start(|mut context| async move {
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
        info!("initializing database");
        let db_config = create_adb_config();
        let mut database = match Database::init(context.with_label("database"), db_config).await {
            Ok(db) => db,
            Err(e) => {
                error!(error = %e, "❌ failed to initialize database");
                return;
            }
        };

        // Create and add initial operations
        let initial_ops = create_test_operations(config.initial_ops, context.next_u64());
        info!(operations_len = initial_ops.len(), "creating initial operations");
        if let Err(e) = add_operations(&mut database, initial_ops).await {
            error!(error = %e, "❌ failed to add initial operations");
            return;
        }

        // Commit the database to ensure operations are persisted
        if let Err(e) = database.commit().await {
            error!(error = %e, "❌ failed to commit database");
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
            "database ready"
        );

        // Create listener to accept connections
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, config.port));
        let mut listener = match context.with_label("listener").bind(addr).await {
            Ok(listener) => listener,
            Err(e) => {
                error!(addr = %addr, error = %e, "❌ failed to bind");
                return;
            }
        };
        info!(
            addr = %addr,
            op_interval = ?config.op_interval,
            ops_per_interval = config.ops_per_interval,
            "server listening and continuously adding operations"
        );

        let state = Arc::new(State::new(context.with_label("server"), database));
        let mut next_op_time = context.current() + config.op_interval;
        loop {
            select! {
                _ = context.sleep_until(next_op_time) => {
                    // Add operations to the database
                    if let Err(e) = state.maybe_add_operations(&mut context, &config).await {
                        warn!(error = %e, "failed to add additional operations");
                    }
                    next_op_time = context.current() + config.op_interval;
                },
                client_result = listener.accept() => {
                    match client_result {
                        Ok((client_addr, sink, stream)) => {
                            let state = state.clone();
                            let context = context.clone();
                            context.with_label("client").spawn(move|context|async move {
                                if let Err(e) =
                                    handle_client(context,state.clone(), sink, stream, client_addr).await
                                {
                                    error!(client_addr = %client_addr, error = %e, "❌ error handling client");
                                }
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "❌ failed to accept client");
                        }
                    }
                }
            }
        }
    });
}
