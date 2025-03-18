//! AWS EC2 deployer
//!
//! Deploy a custom binary (and configuration) to any number of EC2 instances across multiple regions. View metrics and logs
//! from all instances with Grafana.
//!
//! # Features
//!
//! * Automated creation, update, and destruction of EC2 instances across multiple regions
//! * Provide a unique name, instance type, region, binary, and configuration for each deployed instance
//! * Collect metrics, profiles, and logs from all deployed instances on a long-lived monitoring instance (accessible only to the deployer's IP)
//!
//! # Architecture
//!
//! ```txt
//!                    Deployer's Machine (Public IP)
//!                                  |
//!                                  |
//!                                  v
//!               +-----------------------------------+
//!               | Monitoring VPC (us-east-1)        |
//!               |  - Monitoring Instance            |
//!               |    - Prometheus                   |
//!               |    - Loki                         |
//!               |    - Pyroscope                    |
//!               |    - Grafana                      |
//!               |  - Security Group                 |
//!               |    - All: Deployer IP             |
//!               |    - 3100: Binary VPCs            |
//!               +-----------------------------------+
//!                     ^                       ^
//!           (Metrics & Logs)              (Metrics & Logs)
//!                     |                       |
//!                     |                       |
//! +------------------------------+  +------------------------------+
//! | Binary VPC 1                 |  | Binary VPC 2                 |
//! |  - Binary Instance           |  |  - Binary Instance           |
//! |    - Binary A                |  |    - Binary B                |
//! |    - Promtail                |  |    - Promtail                |
//! |  - Security Group            |  |  - Security Group            |
//! |    - All: Deployer IP        |  |    - All: Deployer IP        |
//! |    - 9090: Monitoring IP     |  |    - 9090: Monitoring IP     |
//! |    - 9091: Monitoring IP     |  |    - 9091: Monitoring IP     |
//! |    - 8012: 0.0.0.0/0         |  |    - 8765: 12.3.7.9/32       |
//! +------------------------------+  +------------------------------+
//! ```
//!
//! ## Instances
//!
//! ### Monitoring
//!
//! * Deployed in `us-east-1` with a configurable ARM64 instance type (e.g., `t4g.small`) and storage (e.g., 10GB gp2).
//! * Runs:
//!     * **Prometheus**: Scrapes metrics from all instances at `:9090`, configured via `/opt/prometheus/prometheus.yml`.
//!     * **Loki**: Listens at `:3100`, storing logs in `/loki/chunks` with a TSDB index at `/loki/index`.
//!     * **Pyroscope**: Scrapes metrics from all instances at `:9091`, configured via `/opt/pyroscope/config.yml`.
//!     * **Grafana**: Hosted at `:3000`, provisioned with Prometheus and Loki datasources and a custom dashboard.
//! * Security:
//!     * Allows deployer IP access (TCP 0-65535).
//!     * Binary instance traffic to Loki (TCP 3100).
//!
//! ### Binary
//!
//! * Deployed in user-specified regions with configurable ARM64 instance types and storage.
//! * Run:
//!     * **Custom Binary**: Executes with `--peers=/home/ubuntu/peers.yaml --config=/home/ubuntu/config.conf`, exposing metrics at `:9090` and profiles at `:9091`.
//!     * **Promtail**: Forwards `/var/log/binary.log` to Loki on the monitoring instance.
//! * Security:
//!     * Deployer IP access (TCP 0-65535).
//!     * Monitoring IP access to `:9090` for Prometheus and `:9091` for Pyroscope scraping.
//!     * User-defined ports from the configuration.
//!
//! ## Networking
//!
//! ### VPCs
//!
//! One per region with CIDR `10.<region-index>.0.0/16` (e.g., `10.0.0.0/16` for `us-east-1`).
//!
//! ### Subnets
//!
//! Single subnet per VPC (e.g., `10.<region-index>.1.0/24`), linked to a route table with an internet gateway.
//!
//! ### VPC Peering
//!
//! Connects the monitoring VPC to each binary VPC, with routes added to route tables for private communication.
//!
//! ### Security Groups
//!
//! Separate for monitoring (tag) and binary instances (`{tag}-binary`), dynamically configured for deployer and inter-instance traffic.
//!
//! # Workflow
//!
//! ## `ec2 create`
//!
//! 1. Validates configuration and generates an SSH key pair, stored in `/tmp/deployer-{tag}/id_rsa_{tag}`.
//! 2. Creates VPCs, subnets, internet gateways, route tables, and security groups per region.
//! 3. Establishes VPC peering between the monitoring region and binary regions.
//! 4. Launches the monitoring instance, uploads service files, and installs Prometheus, Grafana, Loki, and Pyroscope.
//! 5. Launches binary instances, uploads binaries, configurations, and peers.yaml, and installs Promtail and the binary.
//! 6. Configures BBR on all instances and updates the monitoring security group for Loki traffic.
//! 7. Marks completion with `/tmp/deployer-{tag}/created`.
//!
//! ## `ec2 update`
//!
//! 1. Stops the `binary` service on each binary instance.
//! 2. Uploads the latest binary and configuration from the YAML config.
//! 3. Restarts the `binary` service, ensuring minimal downtime.
//!
//! ## `ec2 refresh`
//!
//! 1. Obtains the deployer's current public IP address.
//! 2. For each security group in the deployment, adds an ingress rule for the deployer's IP (if it doesn't already exist).
//!
//! ## `ec2 destroy`
//!
//! 1. Terminates all instances across regions.
//! 2. Deletes security groups, subnets, route tables, VPC peering connections, internet gateways, key pairs, and VPCs in dependency order.
//! 3. Marks destruction with `/tmp/deployer-{tag}/destroyed`, retaining the directory to prevent tag reuse.
//!
//! # Persistence
//!
//! * A temporary directory `/tmp/deployer-{tag}` stores the SSH private key, service files, and status files (`created`, `destroyed`).
//! * The deployment state is tracked via these files, ensuring operations respect prior create/destroy actions.
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
mod update;
pub use update::update;
mod refresh;
pub use refresh::refresh;
mod destroy;
pub use destroy::destroy;
pub mod utils;

/// Port on binary where metrics are exposed
pub const METRICS_PORT: u16 = 9090;

/// Port on binary where profiles are exposed
pub const PROFILES_PORT: u16 = 4040;

pub const LOGGING_PORT: u16 = 3100;

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

/// Refresh subcommand name
pub const REFRESH_CMD: &str = "refresh";

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
    /// Monitoring instance
    pub monitoring_private_ip: IpAddr,
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
