//! Server that serves operations and proofs to clients attempting to sync a
//! [commonware_storage::qmdb::any::unordered::fixed::Db] database.

use clap::{Arg, Command};
use commonware_codec::{DecodeExt, Encode, Read};
use commonware_macros::select_loop;
use commonware_runtime::{
    tokio as tokio_runtime, Clock, Listener, Metrics, Network, Runner, RwLock, SinkOf, Spawner,
    Storage, StreamOf,
};
use commonware_storage::qmdb::sync::Target;
use commonware_stream::utils::codec::{recv_frame, send_frame};
use commonware_sync::{
    any::{self},
    crate_version,
    databases::{DatabaseType, Syncable},
    immutable::{self},
    net::{wire, ErrorCode, ErrorResponse, MAX_MESSAGE_SIZE},
    Error, Key,
};
use commonware_utils::DurationExt;
use futures::{channel::mpsc, SinkExt, StreamExt};
use prometheus_client::metrics::counter::Counter;
use rand::{Rng, RngCore};
use std::{
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroU64,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{debug, error, info, warn};

/// Maximum batch size for operations.
const MAX_BATCH_SIZE: u64 = 100;

/// Size of the channel for responses.
const RESPONSE_BUFFER_SIZE: usize = 64;

/// Server configuration.
#[derive(Debug)]
struct Config {
    /// Database type to use.
    database_type: DatabaseType,
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
struct State<DB> {
    /// The database wrapped in async mutex.
    database: RwLock<DB>,
    /// Request counter for metrics.
    request_counter: Counter,
    /// Error counter for metrics.
    error_counter: Counter,
    /// Counter for operations added.
    ops_counter: Counter,
    /// Last time we added operations.
    last_operation_time: RwLock<SystemTime>,
}

impl<DB> State<DB> {
    fn new<E>(context: E, database: DB) -> Self
    where
        E: Metrics,
    {
        let state = Self {
            database: RwLock::new(database),
            request_counter: Counter::default(),
            error_counter: Counter::default(),
            ops_counter: Counter::default(),
            last_operation_time: RwLock::new(SystemTime::now()),
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
}

/// Add operations to the database if the configured interval has passed.
async fn maybe_add_operations<DB, E>(
    state: &State<DB>,
    context: &mut E,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>>
where
    DB: Syncable,
    E: Storage + Clock + Metrics + RngCore,
{
    let mut last_time = state.last_operation_time.write().await;
    let now = context.current();
    if now.duration_since(*last_time).unwrap_or(Duration::ZERO) >= config.op_interval {
        *last_time = now;
        // Generate new operations
        let new_operations =
            DB::create_test_operations(config.ops_per_interval, context.next_u64());
        let new_operations_len = new_operations.len();
        // Add operations to database and get the new root
        let root = {
            let mut database = state.database.write().await;
            if let Err(err) = DB::add_operations(&mut *database, new_operations).await {
                error!(?err, "failed to add operations to database");
            }
            DB::root(&*database)
        };
        state.ops_counter.inc_by(new_operations_len as u64);
        let root_hex = root
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        info!(
            new_operations_len,
            root = %root_hex,
            "added operations"
        );
    }

    Ok(())
}

/// Handle a request for sync target.
async fn handle_get_sync_target<DB>(
    state: &State<DB>,
    request: wire::GetSyncTargetRequest,
) -> Result<wire::GetSyncTargetResponse<Key>, Error>
where
    DB: Syncable,
{
    state.request_counter.inc();

    // Get the current database state
    let (root, lower_bound, upper_bound) = {
        let database = state.database.read().await;
        (database.root(), database.lower_bound(), database.op_count())
    };
    let response = wire::GetSyncTargetResponse::<Key> {
        request_id: request.request_id,
        target: Target {
            root,
            range: lower_bound..upper_bound,
        },
    };

    debug!(?response, "serving target update");
    Ok(response)
}

/// Handle a GetOperationsRequest and return operations with proof.
async fn handle_get_operations<DB>(
    state: &State<DB>,
    request: wire::GetOperationsRequest,
) -> Result<wire::GetOperationsResponse<DB::Operation, Key>, Error>
where
    DB: Syncable,
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
    let max_ops = std::cmp::min(request.max_ops.get(), *db_size - *request.start_loc);
    let max_ops = std::cmp::min(max_ops, MAX_BATCH_SIZE);
    let max_ops =
        NonZeroU64::new(max_ops).expect("max_ops cannot be zero since start_loc < db_size");

    debug!(
        request_id = request.request_id,
        max_ops,
        start_loc = ?request.start_loc,
        ?db_size,
        "operations request"
    );

    // Get the historical proof and operations
    let result = database
        .historical_proof(request.op_count, request.start_loc, max_ops)
        .await;

    drop(database);

    let (proof, operations) = result.map_err(|err| {
        warn!(?err, "failed to generate historical proof");
        Error::Database(err)
    })?;

    debug!(
        request_id = request.request_id,
        operations_len = operations.len(),
        proof_len = proof.digests.len(),
        "sending operations and proof"
    );

    Ok(wire::GetOperationsResponse::<DB::Operation, Key> {
        request_id: request.request_id,
        proof,
        operations,
    })
}

/// Handle a message from a client and return the appropriate response.
async fn handle_message<DB>(
    state: &State<DB>,
    message: wire::Message<DB::Operation, Key>,
) -> wire::Message<DB::Operation, Key>
where
    DB: Syncable,
{
    let request_id = message.request_id();
    match message {
        wire::Message::GetOperationsRequest(request) => {
            match handle_get_operations::<DB>(state, request).await {
                Ok(response) => wire::Message::GetOperationsResponse(response),
                Err(e) => {
                    state.error_counter.inc();
                    wire::Message::Error(ErrorResponse {
                        request_id,
                        error_code: e.to_error_code(),
                        message: e.to_string(),
                    })
                }
            }
        }

        wire::Message::GetSyncTargetRequest(request) => {
            match handle_get_sync_target::<DB>(state, request).await {
                Ok(response) => wire::Message::GetSyncTargetResponse(response),
                Err(e) => {
                    state.error_counter.inc();
                    wire::Message::Error(ErrorResponse {
                        request_id,
                        error_code: e.to_error_code(),
                        message: e.to_string(),
                    })
                }
            }
        }

        _ => {
            state.error_counter.inc();
            wire::Message::Error(ErrorResponse {
                request_id,
                error_code: ErrorCode::InvalidRequest,
                message: "unexpected message type".to_string(),
            })
        }
    }
}

/// Handle a client connection with concurrent request processing.
async fn handle_client<DB, E>(
    context: E,
    state: Arc<State<DB>>,
    mut sink: SinkOf<E>,
    mut stream: StreamOf<E>,
    client_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>>
where
    DB: Syncable + Send + Sync + 'static,
    DB::Operation: Read<Cfg = ()> + Send,
    E: Storage + Clock + Metrics + Network + Spawner,
{
    info!(client_addr = %client_addr, "client connected");

    // Wait until we receive a message from the client or we have a response to send.
    let (response_sender, mut response_receiver) =
        mpsc::channel::<wire::Message<DB::Operation, Key>>(RESPONSE_BUFFER_SIZE);
    select_loop! {
        context,
        on_stopped => {
            debug!("context shutdown, closing client connection");
        },
        incoming = recv_frame(&mut stream, MAX_MESSAGE_SIZE) => {
            match incoming {
                Ok(message_data) => {
                    // Parse the message.
                    let message = match wire::Message::decode(&message_data[..]) {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(client_addr = %client_addr, ?err, "failed to parse message");
                            state.error_counter.inc();
                            continue;
                        }
                    };

                    // Start a new task to handle the message.
                    // The response will be sent on `response_sender`.
                    context.with_label("request_handler").spawn({
                        let state = state.clone();
                        let mut response_sender = response_sender.clone();
                        move |_| async move {
                            let response = handle_message::<DB>(&state, message).await;
                            if let Err(err) = response_sender.send(response).await {
                                warn!(client_addr = %client_addr, ?err, "failed to send response to main loop");
                            }
                        }
                    });
                }
                Err(err) => {
                    info!(client_addr = %client_addr, ?err, "recv failed (client likely disconnected)");
                    state.error_counter.inc();
                    return Ok(());
                }
            }
        },

        outgoing = response_receiver.next() => {
            if let Some(response) = outgoing {
                // We have a response to send to the client.
                let response_data = response.encode().to_vec();
                if let Err(err) = send_frame(&mut sink, &response_data, MAX_MESSAGE_SIZE).await {
                    info!(client_addr = %client_addr, ?err, "send failed (client likely disconnected)");
                    state.error_counter.inc();
                    return Ok(());
                }
            } else {
                // Channel closed
                return Ok(());
            }
        }
    }

    Ok(())
}

/// Initialize and display database state with initial operations.
async fn initialize_database<DB, E>(
    database: &mut DB,
    config: &Config,
    context: &mut E,
) -> Result<(), Box<dyn std::error::Error>>
where
    DB: Syncable,
    E: RngCore,
{
    info!("starting {} database", DB::name());

    // Create and initialize database
    let initial_ops = DB::create_test_operations(config.initial_ops, context.next_u64());
    info!(
        operations_len = initial_ops.len(),
        "creating initial operations"
    );
    DB::add_operations(database, initial_ops).await?;

    // Commit the database to ensure operations are persisted
    database.commit().await?;

    // Display database state
    let root = database.root();
    let root_hex = root
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    info!(
        op_count = ?database.op_count(),
        root = %root_hex,
        "{} database ready",
        DB::name()
    );

    Ok(())
}

/// Run a generic server with the given database.
async fn run_helper<DB, E>(
    mut context: E,
    config: Config,
    mut database: DB,
) -> Result<(), Box<dyn std::error::Error>>
where
    DB: Syncable + Send + Sync + 'static,
    DB::Operation: Read<Cfg = ()> + Send,
    E: Storage + Clock + Metrics + Network + Spawner + RngCore + Clone,
{
    info!("starting {} database server", DB::name());

    initialize_database(&mut database, &config, &mut context).await?;

    // Create listener to accept connections
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, config.port));
    let mut listener = context.with_label("listener").bind(addr).await?;
    info!(
        addr = %addr,
        op_interval = ?config.op_interval,
        ops_per_interval = config.ops_per_interval,
        "{} server listening and continuously adding operations",
        DB::name()
    );

    let state = Arc::new(State::new(context.with_label("server"), database));
    let mut next_op_time = context.current() + config.op_interval;
    select_loop! {
        context,
        on_stopped => {
            debug!("context shutdown, stopping server");
        },
        _ = context.sleep_until(next_op_time) => {
            // Add operations to the database
            if let Err(err) = maybe_add_operations(&state, &mut context, &config).await {
                warn!(?err, "failed to add additional operations");
            }
            next_op_time = context.current() + config.op_interval;
        },
        client_result = listener.accept() => {
            match client_result {
                Ok((client_addr, sink, stream)) => {
                    let state = state.clone();
                    context.with_label("client").spawn(move|context|async move {
                        if let Err(err) =
                            handle_client::<DB, _>(context, state, sink, stream, client_addr).await
                        {
                            error!(client_addr = %client_addr, ?err, "❌ error handling client");
                        }
                    });
                }
                Err(err) => {
                    error!(?err, "❌ failed to accept client");
                }
            }
        }
    }

    Ok(())
}

/// Run the Any database server.
async fn run_any<E>(context: E, config: Config) -> Result<(), Box<dyn std::error::Error>>
where
    E: Storage + Clock + Metrics + Network + Spawner + RngCore + Clone,
{
    // Create and initialize database
    let db_config = any::create_config();
    let database = any::Database::init(context.with_label("database"), db_config).await?;

    run_helper(context, config, database).await
}

/// Run the Immutable database server.
async fn run_immutable<E>(context: E, config: Config) -> Result<(), Box<dyn std::error::Error>>
where
    E: Storage + Clock + Metrics + Network + Spawner + RngCore + Clone,
{
    // Create and initialize database
    let db_config = immutable::create_config();
    let database = immutable::Database::init(context.with_label("database"), db_config).await?;

    run_helper(context, config, database).await
}

/// Parse command line arguments and return configuration.
fn parse_config() -> Result<Config, Box<dyn std::error::Error>> {
    // Parse command line arguments
    let matches = Command::new("Sync Server")
        .version(crate_version())
        .about("Serves database operations and proofs to sync clients")
        .arg(
            Arg::new("db")
                .long("db")
                .value_name("any|immutable")
                .help("Database type to use. Must be `any` or `immutable`.")
                .default_value("any"),
        )
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

    let database_type = matches
        .get_one::<String>("db")
        .unwrap()
        .parse::<DatabaseType>()?;

    Ok(Config {
        database_type,
        port: matches
            .get_one::<String>("port")
            .unwrap()
            .parse()
            .map_err(|e| format!("Invalid port: {e}"))?,
        initial_ops: matches
            .get_one::<String>("initial-ops")
            .unwrap()
            .parse()
            .map_err(|e| format!("Invalid initial operations count: {e}"))?,
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
            .map_err(|e| format!("Invalid metrics port: {e}"))?,
        op_interval: Duration::parse(matches.get_one::<String>("op-interval").unwrap())
            .map_err(|e| format!("Invalid operation interval: {e}"))?,
        ops_per_interval: matches
            .get_one::<String>("ops-per-interval")
            .unwrap()
            .parse()
            .map_err(|e| format!("Invalid ops per interval: {e}"))?,
    })
}

fn main() {
    let config = parse_config().unwrap_or_else(|e| {
        eprintln!("❌ {e}");
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
            port = config.port,
            initial_ops = config.initial_ops,
            storage_dir = %config.storage_dir,
            metrics_port = config.metrics_port,
            op_interval = ?config.op_interval,
            ops_per_interval = config.ops_per_interval,
            "configuration"
        );

        // Run the appropriate server based on database type
        let result = match config.database_type {
            DatabaseType::Any => run_any(context, config).await,
            DatabaseType::Immutable => run_immutable(context, config).await,
        };

        if let Err(err) = result {
            error!(?err, "❌ server failed");
        }
    });
}
