use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub private_key: String,
    pub port: u16,
    pub allowed_peers: Vec<String>,
    pub bootstrappers: Vec<String>,
    pub message_size: usize,
}
