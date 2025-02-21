use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Peer {
    pub name: String,
    pub region: String,
    pub ip: String,
}

#[derive(Deserialize, Serialize)]
pub struct Peers {
    pub peers: Vec<Peer>,
}

#[derive(Deserialize, Clone)]
pub struct PortConfig {
    pub protocol: String,
    pub port: u16,
    pub cidr: String,
}

#[derive(Deserialize, Clone)]
pub struct InstanceConfig {
    pub name: String,
    pub region: String,
    pub instance_type: String,
    pub binary: String,
    pub config: String,
}

#[derive(Deserialize, Clone)]
pub struct MonitoringConfig {
    pub instance_type: String,
    pub dashboard: String,
}

#[derive(Deserialize, Clone)]
pub struct KeyConfig {
    pub name: String,
    pub file: String,
}

#[derive(Deserialize, Clone)]
pub struct Config {
    pub instances: Vec<InstanceConfig>,
    pub key: KeyConfig,
    pub monitoring: MonitoringConfig,
    pub ports: Vec<PortConfig>,
}
