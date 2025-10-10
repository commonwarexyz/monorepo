use axum::{
    body::Bytes as AxumBytes,
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use clap::{Arg, Command};
use commonware_codec::{extensions::DecodeExt, Encode};
use commonware_consensus::{threshold_simplex::types::Finalization, Block as _};
use commonware_cryptography::{
    bls12381::{
        dkg::ops,
        primitives::{poly, variant::MinSig},
    },
    ed25519,
    sha256::Digest as Sha256Digest,
    Committable, PrivateKeyExt as _,
};
use commonware_epocher::{
    types::{block::Block, epoch},
    NAMESPACE, THRESHOLD, TOTAL_VALIDATORS,
};
use commonware_runtime::{
    buffer::PoolRef,
    tokio::{Config as TokioConfig, Context as TokioContext, Runner as TokioRunner},
    Metrics, Runner,
};
use commonware_storage::cache;
use commonware_utils::{NZUsize, NZU64};
use rand::SeedableRng;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{net::TcpListener, sync::RwLock};
use tracing::{error, warn};

#[derive(Clone)]
struct AppState {
    cursor: u64,
    identity: <MinSig as commonware_cryptography::bls12381::primitives::variant::Variant>::Public,
    cache: Arc<RwLock<cache::Cache<TokioContext, Finalization<MinSig, Sha256Digest>>>>,
}

fn main() {
    let matches = Command::new("epocher-indexer")
        .about("indexer for epoch finalizations")
        .arg(Arg::new("me").long("me").required(true))
        .arg(Arg::new("storage-dir").long("storage-dir").required(true))
        .get_matches();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Identity/port
    let me = matches.get_one::<String>("me").expect("provide --me");
    let parts = me.split('@').collect::<Vec<&str>>();
    let key = parts[0].parse::<u64>().expect("key not well-formed");
    let _signer = ed25519::PrivateKey::from_seed(key);
    let port = parts[1].parse::<u16>().expect("port not well-formed");

    // Configure storage directory
    let storage_directory = matches
        .get_one::<String>("storage-dir")
        .expect("Please provide storage directory");

    // Start runtime
    let runtime_cfg = TokioConfig::new().with_storage_directory(storage_directory);
    let executor = TokioRunner::new(runtime_cfg);
    executor.start(|context| async move {
        // Compute network identity used to verify threshold signatures
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let (polynomial, _shares) =
            ops::generate_shares::<_, MinSig>(&mut rng, None, TOTAL_VALIDATORS, THRESHOLD);
        let identity = *poly::public::<MinSig>(&polynomial);

        // Initialize immutable archive for finalizations
        let prefix = {
            // Use a unique partition prefix based on the provided identity/port
            let me = matches
                .get_one::<String>("me")
                .expect("provide --me")
                .clone();
            format!("epocher-indexer-{}", me.replace('@', "-"))
        };
        let cache_cfg = cache::Config {
            partition: format!("{}-finalizations-cache", prefix),
            compression: None,
            codec_config: (),
            items_per_blob: NZU64!(8),
            write_buffer: NZUsize!(1_024 * 1_024),
            replay_buffer: NZUsize!(1_024 * 1_024),
            buffer_pool: PoolRef::new(NZUsize!(16_384), NZUsize!(1_000)),
        };
        let cache = cache::Cache::init(context.with_label("cache"), cache_cfg)
            .await
            .expect("failed to initialize cache");

        // Build HTTP server with axum
        let state = AppState {
            cursor: 0,
            identity,
            cache: Arc::new(RwLock::new(cache)),
        };
        let app = Router::new()
            .route("/upload", post(upload))
            .route("/latest", get(latest))
            .with_state(state);

        // Bind and serve
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let listener = TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
}

async fn upload(State(state): State<AppState>, body: AxumBytes) -> StatusCode {
    // Decode finalization from binary body
    let Ok((finalization, block)) =
        <(Finalization<MinSig, Sha256Digest>, Block)>::decode(body.as_ref())
    else {
        error!("indexer: failed to decode finalization");
        return StatusCode::BAD_REQUEST;
    };

    // Verify the block is at the end of the epoch
    let epoch = finalization.proposal.round.epoch();
    if block.height() != epoch::get_boundary_height(epoch) {
        error!(
            "indexer: block height mismatch: height: {}, epoch: {}",
            block.height(),
            epoch
        );
        return StatusCode::BAD_REQUEST;
    }

    // Verify the block commitment matches the finalization
    if block.commitment() != finalization.proposal.payload {
        error!("indexer: block commitment mismatch");
        return StatusCode::BAD_REQUEST;
    }

    // Verify threshold signatures against network identity
    if !finalization.verify(NAMESPACE, &state.identity) {
        error!("indexer: finalization failed verification");
        return StatusCode::BAD_REQUEST;
    }

    // Early return if key already exists
    let finals = state.cache.read().await;
    if finals.has(epoch) {
        error!("indexer: finalization already exists: {}", epoch);
        return StatusCode::ALREADY_REPORTED;
    }
    drop(finals);

    // Persist finalization
    let mut finals = state.cache.write().await;
    if finals.put(epoch, finalization.clone()).await.is_err() {
        error!("indexer: failed to put finalization: {}", epoch);
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    finals.sync().await.expect("failed to sync cache");
    drop(finals);

    warn!("indexer: persisted finalization: {}", epoch);
    StatusCode::OK
}

async fn latest(State(mut state): State<AppState>) -> impl IntoResponse {
    // Find the latest finalized epoch present by scanning gaps from 0 upward
    // We probe with increasing cursors to find the last continuous segment.
    // For simplicity, probe in steps until no next range is found.
    let mut tip = None;
    {
        let finals = state.cache.read().await;
        loop {
            let (end, next) = finals.next_gap(state.cursor);
            if let Some(end) = end {
                tip = Some(end);
            }
            if let Some(next) = next {
                state.cursor = next;
            } else {
                break;
            }
        }
    }

    // Collect up to two most recent finalizations by epoch
    let mut finals_vec = Vec::new();
    if let Some(end) = tip {
        // Read end
        let finals = state.cache.read().await;
        if let Ok(Some(f)) = finals.get(end).await {
            finals_vec.push(f);
        }
        // Read end-1 if present
        if end > 0 {
            if let Ok(Some(f)) = finals.get(end - 1).await {
                finals_vec.push(f);
                finals_vec.sort_by_key(|f| f.proposal.round.epoch());
            } else {
                error!("indexer: failed to read end-1: {}", end - 1);
                finals_vec.clear();
            }
        }
    }

    // Encode and return the latest finalizations
    let bytes = finals_vec.encode().freeze();
    ([(header::CONTENT_TYPE, "application/octet-stream")], bytes)
}
