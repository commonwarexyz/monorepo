use axum::{
    extract::{Path, State},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use commonware_codec::Encode;
use commonware_cryptography::{ed25519, Hasher, Sha256, Signer as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const VRF_NAMESPACE: &[u8] = b"COMMONWARE_VRF_DICE_v1";
const PLAYER_NAMESPACE: &[u8] = b"COMMONWARE_PLAYER_SIG_v1";
const SERVER_SEED: u64 = 42;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Escapes `\` and `|` in user-controlled VRF message fields so the pipe-delimited
/// format is unambiguous and no two distinct inputs produce the same message.
fn escape_vrf_field(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

#[derive(Clone)]
struct AppState {
    inner: Arc<Mutex<InnerState>>,
}

struct InnerState {
    signer: ed25519::PrivateKey,
    round: u64,
    next_player_seed: u64,
    players: HashMap<String, (String, ed25519::PrivateKey)>,
    history: Vec<RollRecord>,
}

#[derive(Serialize, Clone)]
struct PlayerIdentity {
    public_key: String,
    short_id: String,
    player_name: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    player_name: Option<String>,
}

#[derive(Serialize, Clone)]
struct RollRecord {
    round: u64,
    game_mode: String,
    player_name: String,
    player_public_key: String,
    player_short_id: String,
    client_seed: String,
    dice_result: u8,
    proof: String,
    vrf_hash: String,
    player_signature: String,
    message_hex: String,
    message_raw: String,
    public_key: String,
    timestamp: String,
}

#[derive(Deserialize)]
struct RollRequest {
    player_name: Option<String>,
    client_seed: Option<String>,
    player_public_key: Option<String>,
    game_mode: Option<String>,
}

#[derive(Deserialize)]
struct VerifyRequest {
    round: u64,
    player_name: String,
    client_seed: String,
    claimed_proof: String,
    claimed_result: u8,
    game_mode: Option<String>,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    proof_matches: bool,
    result_matches: bool,
    computed_result: u8,
    computed_proof: String,
    computed_vrf_hash: String,
}

#[derive(Serialize)]
struct InfoResponse {
    public_key: String,
    algorithm: String,
    vrf_namespace: String,
    total_rolls: u64,
    active_players: usize,
}

/// VRF construction using Commonware Ed25519 + SHA-256.
///
/// Ed25519 signatures are deterministic: same key + same message = same signature.
/// The SHA-256 hash of the signature serves as verifiable random output.
fn compute_vrf(signer: &ed25519::PrivateKey, message: &[u8], game_mode: &str) -> (Vec<u8>, Vec<u8>, u8) {
    let signature = signer.sign(VRF_NAMESPACE, message);
    let sig_bytes = signature.encode().to_vec();

    let mut hasher = Sha256::new();
    hasher.update(&sig_bytes);
    let vrf_digest = hasher.finalize();
    let vrf_bytes = vrf_digest.encode().to_vec();

    let sum: u32 = vrf_bytes.iter().map(|&b| b as u32).sum();
    let result = match game_mode {
        "coin" => (sum % 2) as u8,
        "lottery" => ((sum % 100) + 1) as u8,
        _ => ((sum % 6) + 1) as u8,
    };

    (sig_bytes, vrf_bytes, result)
}

async fn register_player(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    let mut inner = state.inner.lock().unwrap();
    const PLAYERS_CAP: usize = 1000;
    if inner.players.len() >= PLAYERS_CAP {
        return Json(serde_json::json!({
            "error": "player_capacity_reached",
            "message": "Player registry is full; please try again later."
        }));
    }
    inner.next_player_seed += 1;
    let player_signer = ed25519::PrivateKey::from_seed(inner.next_player_seed);
    let pk_hex = hex_encode(&player_signer.public_key().encode().to_vec());
    let short_id = pk_hex[..8].to_string();
    let name = req
        .player_name
        .unwrap_or_else(|| "Anonymous".to_string());
    inner.players.insert(pk_hex.clone(), (name.clone(), player_signer));

    Json(PlayerIdentity {
        public_key: pk_hex,
        short_id,
        player_name: name,
    })
}

async fn roll_dice(
    State(state): State<AppState>,
    Json(req): Json<RollRequest>,
) -> impl IntoResponse {
    let mut inner = state.inner.lock().unwrap();
    inner.round += 1;
    let round = inner.round;

    let player_name = req.player_name.unwrap_or_else(|| "Anonymous".to_string());
    let client_seed = req
        .client_seed
        .unwrap_or_else(|| "default".to_string());
    let player_pk = req.player_public_key.unwrap_or_default();
    let game_mode = req.game_mode.unwrap_or_else(|| "dice".to_string());

    let (player_public_key, player_short_id, player_signature) =
        if let Some((_, player_signer)) = inner.players.get(&player_pk) {
            let msg = format!("roll:{}|round:{}", player_pk, round);
            let sig = player_signer.sign(PLAYER_NAMESPACE, msg.as_bytes());
            (
                player_pk.clone(),
                player_pk[..8].to_string(),
                hex_encode(&sig.encode().to_vec()),
            )
        } else {
            (String::new(), String::new(), String::new())
        };

    let message_raw = format!(
        "round:{}|player:{}|seed:{}|mode:{}",
        round,
        escape_vrf_field(&player_name),
        escape_vrf_field(&client_seed),
        escape_vrf_field(&game_mode),
    );
    let (sig_bytes, vrf_bytes, dice_result) =
        compute_vrf(&inner.signer, message_raw.as_bytes(), &game_mode);

    let record = RollRecord {
        round,
        game_mode,
        player_name,
        player_public_key,
        player_short_id,
        client_seed,
        dice_result,
        proof: hex_encode(&sig_bytes),
        vrf_hash: hex_encode(&vrf_bytes),
        player_signature: player_signature.clone(),
        message_hex: hex_encode(message_raw.as_bytes()),
        message_raw,
        public_key: hex_encode(&inner.signer.public_key().encode().to_vec()),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    inner.history.push(record.clone());
    const HISTORY_CAP: usize = 100;
    if inner.history.len() > HISTORY_CAP {
        inner.history.remove(0);
    }

    Json(record)
}

async fn verify_proof(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> impl IntoResponse {
    let inner = state.inner.lock().unwrap();
    let game_mode = req.game_mode.unwrap_or_else(|| "dice".to_string());

    let message_raw = format!(
        "round:{}|player:{}|seed:{}|mode:{}",
        req.round,
        escape_vrf_field(&req.player_name),
        escape_vrf_field(&req.client_seed),
        escape_vrf_field(&game_mode),
    );
    let (sig_bytes, vrf_bytes, dice_result) =
        compute_vrf(&inner.signer, message_raw.as_bytes(), &game_mode);

    let computed_proof = hex_encode(&sig_bytes);
    let proof_matches = computed_proof == req.claimed_proof;
    let result_matches = dice_result == req.claimed_result;

    Json(VerifyResponse {
        valid: proof_matches && result_matches,
        proof_matches,
        result_matches,
        computed_result: dice_result,
        computed_proof,
        computed_vrf_hash: hex_encode(&vrf_bytes),
    })
}

async fn get_history(State(state): State<AppState>) -> impl IntoResponse {
    let inner = state.inner.lock().unwrap();
    let len = inner.history.len();
    let start = len.saturating_sub(100);
    Json(inner.history[start..].to_vec())
}

async fn get_info(State(state): State<AppState>) -> impl IntoResponse {
    let inner = state.inner.lock().unwrap();
    Json(InfoResponse {
        public_key: hex_encode(&inner.signer.public_key().encode().to_vec()),
        algorithm: "Ed25519 (Commonware Cryptography)".to_string(),
        vrf_namespace: String::from_utf8_lossy(VRF_NAMESPACE).to_string(),
        total_rolls: inner.round,
        active_players: inner.players.len(),
    })
}

async fn get_leaderboard(State(state): State<AppState>) -> impl IntoResponse {
    let inner = state.inner.lock().unwrap();
    let mut stats: HashMap<String, (String, String, u32, u32, u32, u8)> = HashMap::new();

    for r in &inner.history {
        let e = stats
            .entry(r.player_public_key.clone())
            .or_insert((r.player_name.clone(), r.player_short_id.clone(), 0, 0, 0, 0));
        e.2 += 1;
        if r.game_mode == "dice" && r.dice_result == 6 {
            e.3 += 1;
        }
        if r.game_mode == "coin" && r.dice_result == 1 {
            e.4 += 1;
        }
        if r.game_mode == "lottery" && r.dice_result > e.5 {
            e.5 = r.dice_result;
        }
    }

    let mut board: Vec<_> = stats
        .into_iter()
        .filter(|(pk, _)| !pk.is_empty())
        .map(|(_, (name, sid, rolls, sixes, heads, best))| {
            serde_json::json!({
                "player_name": name,
                "short_id": sid,
                "total_rolls": rolls,
                "dice_sixes": sixes,
                "coin_heads": heads,
                "lottery_best": best,
            })
        })
        .collect();

    board.sort_by(|a, b| {
        b["total_rolls"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["total_rolls"].as_u64().unwrap_or(0))
    });

    Json(board)
}

async fn get_proof(State(state): State<AppState>, Path(round): Path<u64>) -> impl IntoResponse {
    let inner = state.inner.lock().unwrap();
    if let Some(record) = inner.history.iter().find(|r| r.round == round) {
        Json(serde_json::json!({"found": true, "record": record}))
    } else {
        Json(serde_json::json!({"found": false}))
    }
}

async fn ping() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok", "timestamp": chrono::Utc::now().to_rfc3339()}))
}

async fn fallback() -> impl IntoResponse {
    Json(serde_json::json!({
        "error": "Not found",
        "hint": "API endpoints: /api/register, /api/roll, /api/verify, /api/history, /api/info, /api/leaderboard, /api/proof/{round}, /api/ping"
    }))
}

#[tokio::main]
async fn main() {
    let signer = ed25519::PrivateKey::from_seed(SERVER_SEED);
    println!("========================================");
    println!("  CommonVRF Dice - Provably Fair Game");
    println!("  Powered by Commonware Cryptography");
    println!("========================================");
    println!("Public Key: {}", hex_encode(&signer.public_key().encode().to_vec()));
    println!("Algorithm:  Ed25519 + SHA-256 VRF");
    println!("Namespace:  {}", String::from_utf8_lossy(VRF_NAMESPACE));
    println!("========================================");

    let state = AppState {
        inner: Arc::new(Mutex::new(InnerState {
            signer,
            round: 0,
            next_player_seed: 1000,
            players: HashMap::new(),
            history: Vec::new(),
        })),
    };

    let app = Router::new()
        .route("/api/register", post(register_player))
        .route("/api/roll", post(roll_dice))
        .route("/api/verify", post(verify_proof))
        .route("/api/history", get(get_history))
        .route("/api/info", get(get_info))
        .route("/api/leaderboard", get(get_leaderboard))
        .route("/api/proof/{round}", get(get_proof))
        .route("/api/ping", get(ping))
        .fallback(fallback)
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("Server running at http://localhost:{}", port);
    axum::serve(listener, app).await.unwrap();
}
