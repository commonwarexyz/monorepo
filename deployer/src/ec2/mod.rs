use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

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

/// Subcommand name
pub const CMD: &str = "ec2";

/// Create subcommand name
pub const CREATE_CMD: &str = "create";

/// Update subcommand name
pub const UPDATE_CMD: &str = "update";

/// Destroy subcommand name
pub const DESTROY_CMD: &str = "destroy";

/// File name that indicates the deployment completed
const CREATED_FILE_NAME: &str = "created";

/// File name that indicates the deployment was destroyed
const DESTROYED_FILE_NAME: &str = "destroyed";

/// Directory where deployer files are stored
fn deployer_directory(tag: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/deployer-{}", tag))
}

/// Errors that can occur when deploying infrastructure on AWS.
#[derive(Error, Debug)]
pub enum Error {
    #[error("AWS error: {0}")]
    Aws(#[from] aws_sdk_ec2::Error),
    #[error("AWS operations error: {0}")]
    AwsOperations(#[from] aws_sdk_ec2::operation::authorize_security_group_ingress::AuthorizeSecurityGroupIngressError),
    #[error("AWS describe error: {0}")]
    AwsDescribe(#[from] aws_sdk_ec2::operation::describe_instances::DescribeInstancesError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("creation already attempted")]
    CreationAttempted,
    #[error("invalid instance name: {0}")]
    InvalidInstanceName(String),
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("SCP failed")]
    ScpFailed,
    #[error("SSH failed")]
    SshFailed,
    #[error("keygen failed")]
    KeygenFailed,
    #[error("service timeout({0}): {1}")]
    ServiceTimeout(String, String),
    #[error("deployment does not exist: {0}")]
    DeploymentDoesNotExist(String),
    #[error("deployment is not complete: {0}")]
    DeploymentNotComplete(String),
    #[error("deployment already destroyed: {0}")]
    DeploymentAlreadyDestroyed(String),
    #[error("private key not found")]
    PrivateKeyNotFound,
}

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
