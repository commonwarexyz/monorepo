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
use commonware_runtime::Runner;
use rand::SeedableRng;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;

#[derive(Clone)]
struct AppState {
    identity: <MinSig as commonware_cryptography::bls12381::primitives::variant::Variant>::Public,
    store: Arc<Mutex<BTreeMap<u64, Finalization<MinSig, Sha256Digest>>>>,
}

fn main() {
    let matches = Command::new("epocher-indexer")
        .about("indexer for epoch finalizations")
        .arg(Arg::new("me").long("me").required(true))
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

    // Start runtime
    let executor = commonware_runtime::tokio::Runner::default();
    executor.start(|_context| async move {
        // Compute network identity used to verify threshold signatures
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let (polynomial, _shares) =
            ops::generate_shares::<_, MinSig>(&mut rng, None, TOTAL_VALIDATORS, THRESHOLD);
        let identity = *poly::public::<MinSig>(&polynomial);

        // Shared storage: map epoch -> best known finalization (highest view)
        let store: Arc<Mutex<BTreeMap<u64, Finalization<MinSig, Sha256Digest>>>> =
            Arc::new(Mutex::new(BTreeMap::new()));

        // Build HTTP server with axum
        let state = AppState {
            identity,
            store: store.clone(),
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
        return StatusCode::BAD_REQUEST;
    };

    // Verify the block is at the end of the epoch
    let (epoch, view) = finalization.proposal.round.into();
    if block.height() != epoch::get_last_height(epoch) {
        return StatusCode::BAD_REQUEST;
    }

    // Verify the block commitment matches the finalization
    if block.commitment() != finalization.proposal.payload {
        return StatusCode::BAD_REQUEST;
    }

    // Verify threshold signatures against network identity
    if !finalization.verify(NAMESPACE, &state.identity) {
        return StatusCode::BAD_REQUEST;
    }

    // Upsert if earlier view in same epoch
    let mut guard = state.store.lock().unwrap();
    if guard
        .get(&epoch)
        .is_some_and(|existing| view >= existing.proposal.round.view())
    {
        return StatusCode::OK;
    };

    // Upsert since this is an earlier view
    guard.insert(epoch, finalization);
    StatusCode::OK
}

async fn latest(State(state): State<AppState>) -> impl IntoResponse {
    // Collect up-to the two most-recent finalizations by epoch
    let finals = {
        let guard = state.store.lock().unwrap();
        guard
            .iter()
            .rev()
            .take(2)
            .map(|(_, f)| f.clone())
            .collect::<Vec<_>>()
    };

    let bytes = finals.encode().freeze();
    ([(header::CONTENT_TYPE, "application/octet-stream")], bytes)
}
