use serde::{Deserialize, Serialize};

mod aws;
mod create;
mod services;
pub use create::create;
mod destroy;
pub use destroy::destroy;
mod update;
pub use update::update;
mod utils;

/// Name of the monitoring instance
const MONITORING_NAME: &str = "monitoring";

/// AWS region where monitoring instances are deployed
const MONITORING_REGION: &str = "us-east-1";

pub const CMD: &str = "ec2";
pub const CREATE_CMD: &str = "create";
pub const UPDATE_CMD: &str = "update";
pub const DESTROY_CMD: &str = "destroy";

#[derive(Serialize, Deserialize, Clone)]
pub struct Peer {
    pub name: String,
    pub region: String,
    pub ip: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Peers {
    pub peers: Vec<Peer>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PortConfig {
    pub protocol: String,
    pub port: u16,
    pub cidr: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InstanceConfig {
    pub name: String,
    pub region: String,
    pub instance_type: String,
    pub storage_size: i32,
    pub storage_class: String,
    pub binary: String,
    pub config: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MonitoringConfig {
    pub instance_type: String,
    pub storage_size: i32,
    pub storage_class: String,
    pub dashboard: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub tag: String,
    pub instances: Vec<InstanceConfig>,
    pub monitoring: MonitoringConfig,
    pub ports: Vec<PortConfig>,
}
