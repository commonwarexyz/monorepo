//! Server that serves either full replay data or compact authenticated state to sync clients.
//!
//! In `full` mode this serves authenticated operations and proofs for `any`, `current`,
//! `immutable`, or `keyless` databases. In `compact` mode it serves compact authenticated state
//! for `immutable` / `keyless` families, backed by either full or compact-storage sources.

use clap::{Arg, Command};
use commonware_codec::{DecodeExt, Encode, Read};
use commonware_macros::select_loop;
use commonware_runtime::{
    tokio as tokio_runtime, BufferPooler, Clock, Listener, Metrics, Network, Runner, SinkOf,
    Spawner, Storage, StreamOf,
};
use commonware_storage::{
    mmr,
    qmdb::sync::{compact, Target},
};
use commonware_stream::utils::codec::{recv_frame, send_frame};
use commonware_sync::{
    any, crate_version, current,
    databases::{CompactSyncable, DatabaseType, ExampleDatabase, StorageKind, SyncMode, Syncable},
    immutable, immutable_compact, keyless, keyless_compact,
    net::{wire, ErrorCode, ErrorResponse, MAX_MESSAGE_SIZE},
    Error, Key,
};
use commonware_utils::{
    channel::mpsc,
    non_empty_range,
    sync::{AsyncRwLock, Mutex},
    DurationExt,
};
use prometheus_client::metrics::counter::Counter;
use rand::{Rng, RngCore};
use std::{
    future::Future,
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
    /// Sync mode to use.
    sync_mode: SyncMode,
    /// Database family to use.
    family: DatabaseType,
    /// Backing storage kind used by compact-mode servers.
    storage: Option<StorageKind>,
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
    /// The database wrapped in async rwlock.
    database: Arc<AsyncRwLock<DB>>,
    /// Request counter for metrics.
    request_counter: Counter,
    /// Error counter for metrics.
    error_counter: Counter,
    /// Counter for operations added.
    ops_counter: Counter,
    /// Last time we added operations.
    last_operation_time: Mutex<SystemTime>,
}

impl<DB> State<DB> {
    fn new<E>(context: E, database: DB) -> Self
    where
        E: Metrics,
    {
        let state = Self {
            database: Arc::new(AsyncRwLock::new(database)),
            request_counter: Counter::default(),
            error_counter: Counter::default(),
            ops_counter: Counter::default(),
            last_operation_time: Mutex::new(SystemTime::now()),
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

type BoxError = Box<dyn std::error::Error>;

fn format_root(root: &Key) -> String {
    root.as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

fn error_message<DB>(
    state: &State<DB>,
    request_id: u64,
    error: Error,
) -> wire::Message<DB::Operation, Key>
where
    DB: ExampleDatabase,
{
    state.error_counter.inc();
    wire::Message::Error(ErrorResponse {
        request_id,
        error_code: error.to_error_code(),
        message: error.to_string(),
    })
}

fn unexpected_message<DB>(state: &State<DB>, request_id: u64) -> wire::Message<DB::Operation, Key>
where
    DB: ExampleDatabase,
{
    state.error_counter.inc();
    wire::Message::Error(ErrorResponse {
        request_id,
        error_code: ErrorCode::InvalidRequest,
        message: "unexpected message type".to_string(),
    })
}

macro_rules! dispatch_message {
    ($state:expr, $request_id:expr, $response_variant:path, $future:expr) => {
        match $future.await {
            Ok(response) => $response_variant(response),
            Err(error) => error_message($state, $request_id, error),
        }
    };
}

trait ServeMode<DB>
where
    DB: ExampleDatabase<Family = mmr::Family> + Send + Sync + 'static,
    DB::Operation: Read + Encode + Send,
    <DB::Operation as Read>::Cfg: commonware_codec::IsUnit,
{
    const LISTENING_MESSAGE: &'static str;
    const SHUTDOWN_MESSAGE: &'static str;

    fn handle_message(
        state: &State<DB>,
        message: wire::Message<DB::Operation, Key>,
    ) -> impl Future<Output = wire::Message<DB::Operation, Key>> + Send;
}

struct FullMode;
struct CompactMode;

/// Add operations to the database if the configured interval has passed.
async fn maybe_add_operations<DB, E>(
    state: &State<DB>,
    context: &mut E,
    config: &Config,
) -> Result<(), BoxError>
where
    DB: ExampleDatabase<Family = mmr::Family>,
    E: Storage + Clock + Metrics + RngCore,
{
    let now = context.current();
    let should_add = {
        let mut last_time = state.last_operation_time.lock();
        if now.duration_since(*last_time).unwrap_or(Duration::ZERO) >= config.op_interval {
            *last_time = now;
            true
        } else {
            false
        }
    };
    if should_add {
        let new_operations =
            DB::create_test_operations(config.ops_per_interval, context.next_u64());
        let new_operations_len = new_operations.len();
        let root = {
            let mut database = state.database.write().await;
            if let Err(err) = database.add_operations(new_operations).await {
                error!(?err, "failed to add operations to database");
                return Err(err.into());
            }
            database.root()
        };
        state.ops_counter.inc_by(new_operations_len as u64);
        info!(
            new_operations_len,
            root = %format_root(&root),
            "added operations"
        );
    }

    Ok(())
}

/// Handle a request for full-sync target.
async fn handle_get_sync_target<DB>(
    state: &State<DB>,
    request: wire::GetSyncTargetRequest,
) -> Result<wire::GetSyncTargetResponse<Key>, Error>
where
    DB: Syncable<Family = mmr::Family>,
{
    state.request_counter.inc();

    // Get the current database state
    let (root, sync_boundary, size) = {
        let database = state.database.read().await;
        (
            database.root(),
            database.sync_boundary().await,
            database.size().await,
        )
    };
    let response = wire::GetSyncTargetResponse::<Key> {
        request_id: request.request_id,
        target: Target {
            root,
            range: non_empty_range!(sync_boundary, size),
        },
    };

    debug!(?response, "serving target update");
    Ok(response)
}

/// Handle a request for compact-sync target.
async fn handle_get_compact_sync_target<DB>(
    state: &State<DB>,
    request: wire::GetCompactTargetRequest,
) -> Result<wire::GetCompactTargetResponse<Key>, Error>
where
    DB: CompactSyncable<Family = mmr::Family>,
{
    state.request_counter.inc();

    let target = {
        let database = state.database.read().await;
        database.current_target().await
    };
    let response = wire::GetCompactTargetResponse::<Key> {
        request_id: request.request_id,
        target,
    };

    debug!(?response, "serving compact target update");
    Ok(response)
}

/// Handle a GetOperationsRequest and return operations with proof.
async fn handle_get_operations<DB>(
    state: &State<DB>,
    request: wire::GetOperationsRequest,
) -> Result<wire::GetOperationsResponse<DB::Operation, Key>, Error>
where
    DB: Syncable<Family = mmr::Family>,
{
    state.request_counter.inc();
    request.validate()?;

    let database = state.database.read().await;

    // Check if we have enough operations
    let db_size = database.size().await;
    if request.start_loc >= db_size {
        return Err(Error::InvalidRequest(format!(
            "start_loc ({}) >= database size ({})",
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

    let (proof, operations) = result.map_err(|err| {
        warn!(?err, "failed to generate historical proof");
        Error::Database(err)
    })?;

    // Optionally fetch pinned nodes
    let pinned_nodes = if request.include_pinned_nodes {
        let nodes = database
            .pinned_nodes_at(request.start_loc)
            .await
            .map_err(|err| {
                warn!(?err, "failed to get pinned nodes");
                Error::Database(err)
            })?;
        Some(nodes)
    } else {
        None
    };

    drop(database);

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
        pinned_nodes,
    })
}

/// Handle a GetCompactStateRequest and return compact authenticated state.
async fn handle_get_compact_state<DB>(
    state: &State<DB>,
    request: wire::GetCompactStateRequest<Key>,
) -> Result<wire::GetCompactStateResponse<DB::Operation, Key>, Error>
where
    DB: CompactSyncable<Family = mmr::Family>,
    Arc<AsyncRwLock<DB>>: compact::Resolver<
        Family = mmr::Family,
        Op = DB::Operation,
        Digest = Key,
        Error = compact::ServeError<mmr::Family, Key>,
    >,
{
    state.request_counter.inc();

    let compact_state = compact::Resolver::get_compact_state(&state.database, request.target)
        .await
        .map_err(|err| {
            warn!(?err, "failed to serve compact state");
            match err {
                compact::ServeError::Database(err) => Error::Database(err),
                compact::ServeError::StaleTarget { .. } => Error::StaleTarget(err.to_string()),
                compact::ServeError::InvalidTarget(_) | compact::ServeError::MissingSource => {
                    Error::InvalidRequest(err.to_string())
                }
            }
        })?;

    Ok(wire::GetCompactStateResponse {
        request_id: request.request_id,
        state: compact_state,
    })
}

impl<DB> ServeMode<DB> for FullMode
where
    DB: Syncable<Family = mmr::Family> + Send + Sync + 'static,
    DB::Operation: Read + Encode + Send,
    <DB::Operation as Read>::Cfg: commonware_codec::IsUnit,
{
    const LISTENING_MESSAGE: &'static str = "server listening and continuously adding operations";
    const SHUTDOWN_MESSAGE: &'static str = "context shutdown, stopping server";

    async fn handle_message(
        state: &State<DB>,
        message: wire::Message<DB::Operation, Key>,
    ) -> wire::Message<DB::Operation, Key> {
        let request_id = message.request_id();
        match message {
            wire::Message::GetOperationsRequest(request) => dispatch_message!(
                state,
                request_id,
                wire::Message::GetOperationsResponse,
                handle_get_operations::<DB>(state, request)
            ),
            wire::Message::GetSyncTargetRequest(request) => dispatch_message!(
                state,
                request_id,
                wire::Message::GetSyncTargetResponse,
                handle_get_sync_target::<DB>(state, request)
            ),
            _ => unexpected_message(state, request_id),
        }
    }
}

impl<DB> ServeMode<DB> for CompactMode
where
    DB: CompactSyncable<Family = mmr::Family> + Send + Sync + 'static,
    DB::Operation: Read + Encode + Send,
    <DB::Operation as Read>::Cfg: commonware_codec::IsUnit,
    Arc<AsyncRwLock<DB>>: compact::Resolver<
        Family = mmr::Family,
        Op = DB::Operation,
        Digest = Key,
        Error = compact::ServeError<mmr::Family, Key>,
    >,
{
    const LISTENING_MESSAGE: &'static str =
        "compact server listening and continuously adding operations";
    const SHUTDOWN_MESSAGE: &'static str = "context shutdown, stopping compact server";

    async fn handle_message(
        state: &State<DB>,
        message: wire::Message<DB::Operation, Key>,
    ) -> wire::Message<DB::Operation, Key> {
        let request_id = message.request_id();
        match message {
            wire::Message::GetCompactStateRequest(request) => dispatch_message!(
                state,
                request_id,
                wire::Message::GetCompactStateResponse,
                handle_get_compact_state::<DB>(state, request)
            ),
            wire::Message::GetCompactTargetRequest(request) => dispatch_message!(
                state,
                request_id,
                wire::Message::GetCompactTargetResponse,
                handle_get_compact_sync_target::<DB>(state, request)
            ),
            _ => unexpected_message(state, request_id),
        }
    }
}

/// Receive loop for client requests.
///
/// This stays isolated from response sending so a cancellation while serving one request cannot
/// interrupt `recv_frame` mid-read and leave the stream framing state ambiguous for the next loop.
async fn recv_loop<DB, E, Mode>(
    context: E,
    state: Arc<State<DB>>,
    mut stream: StreamOf<E>,
    response_sender: mpsc::Sender<wire::Message<DB::Operation, Key>>,
    client_addr: SocketAddr,
) where
    DB: ExampleDatabase<Family = mmr::Family> + Send + Sync + 'static,
    DB::Operation: Read + Encode + Send,
    <DB::Operation as Read>::Cfg: commonware_codec::IsUnit,
    E: Metrics + Network + Spawner,
    Mode: ServeMode<DB> + 'static,
{
    loop {
        let message_data = match recv_frame(&mut stream, MAX_MESSAGE_SIZE).await {
            Ok(data) => data,
            Err(err) => {
                debug!(?err, client_addr = %client_addr, "client disconnected");
                return;
            }
        };

        let message = match wire::Message::decode(message_data.coalesce()) {
            Ok(msg) => msg,
            Err(err) => {
                warn!(client_addr = %client_addr, ?err, "failed to parse message");
                state.error_counter.inc();
                continue;
            }
        };

        context.with_label("request_handler").spawn({
            let state = state.clone();
            let response_sender = response_sender.clone();
            move |_| async move {
                let response = Mode::handle_message(state.as_ref(), message).await;
                if let Err(err) = response_sender.send(response).await {
                    warn!(client_addr = %client_addr, ?err, "failed to send response to main loop");
                }
            }
        });
    }
}

/// Handle a client connection with concurrent request processing.
///
/// The outer loop owns the sink and writes responses in order. Request handling runs in separate
/// tasks that feed a channel back to this loop so send-side backpressure or disconnects do not
/// cancel in-flight framed reads.
async fn handle_client<DB, E, Mode>(
    context: E,
    state: Arc<State<DB>>,
    mut sink: SinkOf<E>,
    stream: StreamOf<E>,
    client_addr: SocketAddr,
) -> Result<(), BoxError>
where
    DB: ExampleDatabase<Family = mmr::Family> + Send + Sync + 'static,
    DB::Operation: Read + Encode + Send,
    <DB::Operation as Read>::Cfg: commonware_codec::IsUnit,
    E: Storage + Clock + Metrics + Network + Spawner,
    Mode: ServeMode<DB> + 'static,
{
    info!(client_addr = %client_addr, "client connected");

    let (response_sender, mut response_receiver) =
        mpsc::channel::<wire::Message<DB::Operation, Key>>(RESPONSE_BUFFER_SIZE);

    let recv_handle = context.with_label("recv").spawn({
        let state = state.clone();
        let response_sender = response_sender.clone();
        move |context| {
            recv_loop::<DB, E, Mode>(context, state, stream, response_sender, client_addr)
        }
    });

    drop(response_sender);

    while let Some(response) = response_receiver.recv().await {
        let response_data = response.encode();
        if let Err(err) = send_frame(&mut sink, response_data, MAX_MESSAGE_SIZE).await {
            info!(client_addr = %client_addr, ?err, "send failed (client likely disconnected)");
            state.error_counter.inc();
            break;
        }
    }

    recv_handle.abort();
    Ok(())
}

/// Initialize and display database state with initial operations.
async fn initialize_database<DB, E>(
    mut database: DB,
    config: &Config,
    context: &mut E,
) -> Result<DB, BoxError>
where
    DB: Syncable<Family = mmr::Family>,
    E: RngCore,
{
    info!("starting {} database", DB::name());

    // Create and initialize database
    let initial_ops = DB::create_test_operations(config.initial_ops, context.next_u64());
    info!(
        operations_len = initial_ops.len(),
        "creating initial operations"
    );
    database.add_operations(initial_ops).await?;

    // Display database state
    let size = database.size().await;
    let sync_boundary = database.sync_boundary().await;
    let root = database.root();
    info!(size = ?size, sync_boundary = ?sync_boundary, root = %format_root(&root), "{} database ready", DB::name());

    Ok(database)
}

/// Initialize and display compact-source database state with initial operations.
async fn initialize_compact_database<DB, E>(
    mut database: DB,
    config: &Config,
    context: &mut E,
) -> Result<DB, BoxError>
where
    DB: CompactSyncable<Family = mmr::Family>,
    E: RngCore,
{
    info!("starting {} database", DB::name());

    let initial_ops = DB::create_test_operations(config.initial_ops, context.next_u64());
    info!(
        operations_len = initial_ops.len(),
        "creating initial operations"
    );
    database.add_operations(initial_ops).await?;

    let target = database.current_target().await;
    let root = target.root;
    info!(
        leaf_count = ?target.leaf_count,
        root = %format_root(&root),
        "{} compact source ready",
        DB::name()
    );

    Ok(database)
}

/// Run a generic serving loop with the given initialized database.
async fn run_server<DB, E, Mode>(
    mut context: E,
    config: Config,
    database: DB,
) -> Result<(), BoxError>
where
    DB: ExampleDatabase<Family = mmr::Family> + Send + Sync + 'static,
    DB::Operation: Read + Encode + Send,
    <DB::Operation as Read>::Cfg: commonware_codec::IsUnit,
    E: Storage + Clock + Metrics + Network + Spawner + RngCore + Clone + Send,
    Mode: ServeMode<DB> + 'static,
{
    // Create listener to accept connections
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, config.port));
    let mut listener = context.with_label("listener").bind(addr).await?;
    info!(
        addr = %addr,
        op_interval = ?config.op_interval,
        ops_per_interval = config.ops_per_interval,
        "{}",
        Mode::LISTENING_MESSAGE
    );

    let state = Arc::new(State::new(context.with_label("server"), database));
    let mut next_op_time = context.current() + config.op_interval;
    select_loop! {
        context,
        on_stopped => {
            debug!("{}", Mode::SHUTDOWN_MESSAGE);
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
                    context.with_label("client").spawn(move |context| async move {
                        if let Err(err) = handle_client::<DB, _, Mode>(
                            context,
                            state,
                            sink,
                            stream,
                            client_addr,
                        )
                        .await
                        {
                            error!(client_addr = %client_addr, ?err, "error handling client");
                        }
                    });
                }
                Err(err) => {
                    error!(?err, "failed to accept client");
                }
            }
        },
    }

    Ok(())
}

/// Run a full-sync server with the given database.
async fn run_helper<DB, E>(mut context: E, config: Config, database: DB) -> Result<(), BoxError>
where
    DB: Syncable<Family = mmr::Family> + Send + Sync + 'static,
    DB::Operation: Read + Encode + Send,
    <DB::Operation as Read>::Cfg: commonware_codec::IsUnit,
    E: Storage + Clock + Metrics + Network + Spawner + RngCore + Clone + Send,
{
    let database = initialize_database(database, &config, &mut context).await?;
    run_server::<DB, E, FullMode>(context, config, database).await
}

/// Run a compact-sync server with the given database.
async fn run_compact_helper<DB, E>(
    mut context: E,
    config: Config,
    database: DB,
) -> Result<(), BoxError>
where
    DB: CompactSyncable<Family = mmr::Family> + Send + Sync + 'static,
    DB::Operation: Read + Encode + Send,
    <DB::Operation as Read>::Cfg: commonware_codec::IsUnit,
    E: Storage + Clock + Metrics + Network + Spawner + RngCore + Clone + Send,
    Arc<AsyncRwLock<DB>>: compact::Resolver<
        Family = mmr::Family,
        Op = DB::Operation,
        Digest = Key,
        Error = compact::ServeError<mmr::Family, Key>,
    >,
{
    let database = initialize_compact_database(database, &config, &mut context).await?;
    run_server::<DB, E, CompactMode>(context, config, database).await
}

/// Run the Any database server.
async fn run_any<E>(context: E, config: Config) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner + RngCore + Clone + Send,
{
    let db_config = any::create_config(&context);
    let database = any::Database::init(context.with_label("database"), db_config).await?;

    run_helper(context, config, database).await
}

/// Run the Current database server.
async fn run_current<E>(context: E, config: Config) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner + RngCore + Clone + Send,
{
    let db_config = current::create_config(&context);
    let database = current::Database::init(context.with_label("database"), db_config).await?;

    run_helper(context, config, database).await
}

/// Run the Immutable database server.
async fn run_immutable<E>(context: E, config: Config) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner + RngCore + Clone + Send,
{
    let db_config = immutable::create_config(&context);
    let database = immutable::Database::init(context.with_label("database"), db_config).await?;

    run_helper(context, config, database).await
}

/// Run the full immutable database as a compact-sync source.
async fn run_immutable_full_source<E>(
    context: E,
    config: Config,
) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner + RngCore + Clone + Send,
{
    let db_config = immutable::create_config(&context);
    let database = immutable::Database::init(context.with_label("database"), db_config).await?;

    run_compact_helper(context, config, database).await
}

/// Run the Keyless database server.
async fn run_keyless<E>(context: E, config: Config) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner + RngCore + Clone + Send,
{
    let db_config = keyless::create_config(&context);
    let database = keyless::Database::init(context.with_label("database"), db_config).await?;

    run_helper(context, config, database).await
}

/// Run the full keyless database as a compact-sync source.
async fn run_keyless_full_source<E>(
    context: E,
    config: Config,
) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner + RngCore + Clone + Send,
{
    let db_config = keyless::create_config(&context);
    let database = keyless::Database::init(context.with_label("database"), db_config).await?;

    run_compact_helper(context, config, database).await
}

/// Run the compact immutable database server.
async fn run_immutable_compact<E>(
    context: E,
    config: Config,
) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner + RngCore + Clone + Send,
{
    let db_config = immutable_compact::create_config(&context);
    let database =
        immutable_compact::Database::init(context.with_label("database"), db_config).await?;

    run_compact_helper(context, config, database).await
}

/// Run the compact keyless database server.
async fn run_keyless_compact<E>(
    context: E,
    config: Config,
) -> Result<(), Box<dyn std::error::Error>>
where
    E: BufferPooler + Storage + Clock + Metrics + Network + Spawner + RngCore + Clone + Send,
{
    let db_config = keyless_compact::create_config(&context);
    let database =
        keyless_compact::Database::init(context.with_label("database"), db_config).await?;

    run_compact_helper(context, config, database).await
}

/// Parse command line arguments and return configuration.
fn parse_config() -> Result<Config, Box<dyn std::error::Error>> {
    // Parse command line arguments
    let matches = Command::new("Sync Server")
        .version(crate_version())
        .about("Serves database sync state to clients")
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
            Arg::new("storage")
                .long("storage")
                .value_name("full|compact")
                .help(
                    "Backing storage used by compact-mode servers. Only valid with `--mode compact`; when omitted there, `full` is used.",
                )
                .required(false),
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

    let sync_mode = matches
        .get_one::<String>("mode")
        .unwrap()
        .parse::<SyncMode>()?;
    let family = matches
        .get_one::<String>("family")
        .unwrap()
        .parse::<DatabaseType>()?;
    let storage = matches
        .get_one::<String>("storage")
        .map(|value| value.parse::<StorageKind>())
        .transpose()?;
    match sync_mode {
        SyncMode::Full => {
            if storage.is_some() {
                return Err("--storage is only valid with --mode compact".into());
            }
        }
        SyncMode::Compact => {
            if !family.supports_compact_storage() {
                return Err(format!(
                    "Database family '{}' is not supported in 'compact' mode",
                    family.as_str()
                )
                .into());
            }
        }
    }

    Ok(Config {
        sync_mode,
        family,
        storage,
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
        eprintln!("{e}");
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
            sync_mode = %config.sync_mode.as_str(),
            family = %config.family.as_str(),
            storage = %config.storage.map(|kind| kind.as_str()).unwrap_or("n/a"),
            port = config.port,
            initial_ops = config.initial_ops,
            storage_dir = %config.storage_dir,
            metrics_port = config.metrics_port,
            op_interval = ?config.op_interval,
            ops_per_interval = config.ops_per_interval,
            "configuration"
        );

        // Run the appropriate server based on sync mode, family, and compact backing storage.
        let compact_storage = config.storage.unwrap_or(StorageKind::Full);
        let result = match (config.sync_mode, config.family, compact_storage) {
            (SyncMode::Full, DatabaseType::Any, _) => run_any(context, config).await,
            (SyncMode::Full, DatabaseType::Current, _) => run_current(context, config).await,
            (SyncMode::Full, DatabaseType::Immutable, _) => run_immutable(context, config).await,
            (SyncMode::Full, DatabaseType::Keyless, _) => run_keyless(context, config).await,
            (SyncMode::Compact, DatabaseType::Immutable, StorageKind::Full) => {
                run_immutable_full_source(context, config).await
            }
            (SyncMode::Compact, DatabaseType::Keyless, StorageKind::Full) => {
                run_keyless_full_source(context, config).await
            }
            (SyncMode::Compact, DatabaseType::Immutable, StorageKind::Compact) => {
                run_immutable_compact(context, config).await
            }
            (SyncMode::Compact, DatabaseType::Keyless, StorageKind::Compact) => {
                run_keyless_compact(context, config).await
            }
            _ => Err(Box::<dyn std::error::Error>::from(format!(
                "unsupported combination: mode={} family={} storage={}",
                config.sync_mode.as_str(),
                config.family.as_str(),
                compact_storage.as_str()
            ))),
        };

        if let Err(err) = result {
            error!(?err, "server failed");
        }
    });
}
