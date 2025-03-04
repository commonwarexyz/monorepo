//! AWS EC2 deployer
//!
//! Deploy a custom binary (and configuration) to any number of EC2 instances across multiple regions. Collect metrics and logs
//! from all instances via a private network.
//!
//! # Features
//!
//! - **Automated Deployment**: Creates VPCs, subnets, security groups, and EC2 instances.
//! - **Monitoring Setup**: Deploys Prometheus, Grafana, Loki, and Promtail for monitoring and logging.
//! - **Multi-Region Support**: Deploys instances across multiple AWS regions with VPC peering.
//! - **SSH Key Management**: Generates and imports SSH key pairs for secure instance access.
//! - **Service Management**: Configures systemd services for the deployed binary and monitoring tools.
//! - **Update and Destroy**: Provides commands to update binaries/configurations or destroy deployments.
//!
//! # Architecture
//!
//!
//!
//! # Example Configuration
//!
//! ```yaml
//! tag: ffa638a0-991c-442c-8ec4-aa4e418213a5
//! monitoring:
//!   instance_type: t4g.small
//!   storage_size: 10
//!   storage_class: gp2
//!   dashboard: /path/to/dashboard.json
//! instances:
//!   - name: node1
//!     region: us-east-1
//!     instance_type: t4g.small
//!     storage_size: 10
//!     storage_class: gp2
//!     binary: /path/to/binary
//!     config: /path/to/config.conf
//!   - name: node2
//!     region: us-west-2
//!     instance_type: t4g.small
//!     storage_size: 10
//!     storage_class: gp2
//!     binary: /path/to/binary2
//!     config: /path/to/config2.conf
//! ports:
//!   - protocol: tcp
//!     port: 4545
//!     cidr: 0.0.0.0/0
//! ```

use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::PathBuf};
use thiserror::Error;

pub mod aws;
mod create;
pub mod services;
pub use create::create;
mod destroy;
pub use destroy::destroy;
mod update;
pub use update::update;
pub mod utils;

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

/// Errors that can occur when deploying infrastructure on AWS
#[derive(Error, Debug)]
pub enum Error {
    #[error("AWS EC2 error: {0}")]
    AwsEc2(#[from] aws_sdk_ec2::Error),
    #[error("AWS security group ingress error: {0}")]
    AwsSecurityGroupIngress(#[from] aws_sdk_ec2::operation::authorize_security_group_ingress::AuthorizeSecurityGroupIngressError),
    #[error("AWS describe instances error: {0}")]
    AwsDescribeInstances(#[from] aws_sdk_ec2::operation::describe_instances::DescribeInstancesError),
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

/// Peer deployment information
#[derive(Serialize, Deserialize, Clone)]
pub struct Peer {
    /// Name of the peer
    pub name: String,

    /// Region where the peer is deployed
    pub region: String,

    /// Public IP address of the peer
    pub ip: IpAddr,
}

/// List of peers
#[derive(Serialize, Deserialize, Clone)]
pub struct Peers {
    /// Peers deployed across all regions
    pub peers: Vec<Peer>,
}

/// Port configuration
#[derive(Serialize, Deserialize, Clone)]
pub struct PortConfig {
    /// Protocol (e.g., "tcp")
    pub protocol: String,

    /// Port number
    pub port: u16,

    /// CIDR block
    pub cidr: String,
}

/// Instance configuration
#[derive(Serialize, Deserialize, Clone)]
pub struct InstanceConfig {
    /// Name of the instance
    pub name: String,

    /// AWS region where the instance is deployed
    pub region: String,

    /// Instance type (only ARM-based instances are supported)
    pub instance_type: String,

    /// Storage size in GB
    pub storage_size: i32,

    /// Storage class (e.g., "gp2")
    pub storage_class: String,

    /// Path to the binary to deploy
    pub binary: String,

    /// Path to the binary configuration file
    pub config: String,
}

/// Monitoring configuration
#[derive(Serialize, Deserialize, Clone)]
pub struct MonitoringConfig {
    /// Instance type (only ARM-based instances are supported)
    pub instance_type: String,

    /// Storage size in GB
    pub storage_size: i32,

    /// Storage class (e.g., "gp2")
    pub storage_class: String,

    /// Path to a custom dashboard file that is automatically
    /// uploaded to grafana
    pub dashboard: String,
}

/// Deployer configuration
#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    /// Unique tag for the deployment
    pub tag: String,

    /// Monitoring instance configuration
    pub monitoring: MonitoringConfig,

    /// Instance configurations
    pub instances: Vec<InstanceConfig>,

    /// Ports open on all instances
    pub ports: Vec<PortConfig>,
}
