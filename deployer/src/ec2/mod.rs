//! AWS EC2 deployer
//!
//! Deploy a custom binary (and configuration) to any number of EC2 instances across multiple regions. View metrics and logs
//! from all instances with Grafana.
//!
//! # Features
//!
//! * Automated creation, update, and destruction of EC2 instances across multiple regions
//! * Provide a unique name, instance type, region, binary, and configuration for each deployed instance
//! * Collect metrics, profiles (when enabled), and logs from all deployed instances on a long-lived monitoring instance
//!   (accessible only to the deployer's IP)
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
//!               |    - Tempo                        |
//!               |    - Grafana                      |
//!               |  - Security Group                 |
//!               |    - All: Deployer IP             |
//!               |    - 3100: Binary VPCs            |
//!               |    - 4040: Binary VPCs            |
//!               |    - 4318: Binary VPCs            |
//!               +-----------------------------------+
//!                     ^                       ^
//!                (Telemetry)             (Telemetry)
//!                     |                       |
//!                     |                       |
//! +------------------------------+  +------------------------------+
//! | Binary VPC 1                 |  | Binary VPC 2                 |
//! |  - Binary Instance           |  |  - Binary Instance           |
//! |    - Binary A                |  |    - Binary B                |
//! |    - Promtail                |  |    - Promtail                |
//! |    - Node Exporter           |  |    - Node Exporter           |
//! |    - Pyroscope Agent         |  |    - Pyroscope Agent         |
//! |  - Security Group            |  |  - Security Group            |
//! |    - All: Deployer IP        |  |    - All: Deployer IP        |
//! |    - 9090: Monitoring IP     |  |    - 9090: Monitoring IP     |
//! |    - 9100: Monitoring IP     |  |    - 9100: Monitoring IP     |
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
//!     * **Prometheus**: Scrapes binary metrics from all instances at `:9090` and system metrics from all instances at `:9100`.
//!     * **Loki**: Listens at `:3100`, storing logs in `/loki/chunks` with a TSDB index at `/loki/index`.
//!     * **Pyroscope**: Listens at `:4040`, storing profiles in `/var/lib/pyroscope`.
//!     * **Tempo**: Listens at `:4318`, storing traces in `/var/lib/tempo`.
//!     * **Grafana**: Hosted at `:3000`, provisioned with Prometheus, Loki, and Tempo datasources and a custom dashboard.
//! * Ingress:
//!     * Allows deployer IP access (TCP 0-65535).
//!     * Binary instance traffic to Loki (TCP 3100) and Tempo (TCP 4318).
//!
//! ### Binary
//!
//! * Deployed in user-specified regions with configurable ARM64 instance types and storage.
//! * Run:
//!     * **Custom Binary**: Executes with `--hosts=/home/ubuntu/hosts.yaml --config=/home/ubuntu/config.conf`, exposing metrics at `:9090`.
//!     * **Promtail**: Forwards `/var/log/binary.log` to Loki on the monitoring instance.
//!     * **Node Exporter**: Exposes system metrics at `:9100`.
//!     * **Pyroscope Agent**: Forwards `perf` profiles to Pyroscope on the monitoring instance.
//! * Ingress:
//!     * Deployer IP access (TCP 0-65535).
//!     * Monitoring IP access to `:9090` and `:9100` for Prometheus.
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
//! 1. Validates configuration and generates an SSH key pair, stored in `$HOME/.commonware_deployer/{tag}/id_rsa_{tag}`.
//! 2. Ensures the shared S3 bucket exists and caches observability tools (Prometheus, Grafana, Loki, etc.) if not already present.
//! 3. Uploads deployment-specific files (binaries, configs) to S3.
//! 4. Creates VPCs, subnets, internet gateways, route tables, and security groups per region (concurrently).
//! 5. Establishes VPC peering between the monitoring region and binary regions.
//! 6. Launches the monitoring instance.
//! 7. Launches binary instances.
//! 8. Caches all static config files and uploads per-instance configs (hosts.yaml, promtail, pyroscope) to S3.
//! 9. Configures monitoring and binary instances in parallel via SSH (BBR, service installation, service startup).
//! 10. Updates the monitoring security group to allow telemetry traffic from binary instances.
//! 11. Marks completion with `$HOME/.commonware_deployer/{tag}/created`.
//!
//! ## `ec2 update`
//!
//! 1. Uploads the latest binary and configuration to S3.
//! 2. Stops the `binary` service on each binary instance.
//! 3. Instances download the updated files from S3 via pre-signed URLs.
//! 4. Restarts the `binary` service, ensuring minimal downtime.
//!
//! ## `ec2 authorize`
//!
//! 1. Obtains the deployer's current public IP address (or parses the one provided).
//! 2. For each security group in the deployment, adds an ingress rule for the IP (if it doesn't already exist).
//!
//! ## `ec2 destroy`
//!
//! 1. Terminates all instances across regions.
//! 2. Deletes security groups, subnets, route tables, VPC peering connections, internet gateways, key pairs, and VPCs in dependency order.
//! 3. Deletes deployment-specific data from S3 (cached tools remain for future deployments).
//! 4. Marks destruction with `$HOME/.commonware_deployer/{tag}/destroyed`, retaining the directory to prevent tag reuse.
//!
//! ## `ec2 clean`
//!
//! 1. Deletes the shared S3 bucket and all its contents (cached tools and any remaining deployment data).
//! 2. Use this to fully clean up when you no longer need the deployer cache.
//!
//! # Persistence
//!
//! * A directory `$HOME/.commonware_deployer/{tag}` stores the SSH private key and status files (`created`, `destroyed`).
//! * The deployment state is tracked via these files, ensuring operations respect prior create/destroy actions.
//!
//! ## S3 Caching
//!
//! A shared S3 bucket (`commonware-deployer-cache`) is used to cache deployment artifacts. The bucket
//! uses a fixed name intentionally so that all users within the same AWS account share the cache. This
//! design provides two benefits:
//!
//! 1. **Faster deployments**: Observability tools (Prometheus, Grafana, Loki, etc.) are downloaded from
//!    upstream sources once and cached in S3. Subsequent deployments by any user skip the download and
//!    use pre-signed URLs to fetch directly from S3.
//!
//! 2. **Reduced bandwidth**: Instead of requiring the deployer to push binaries to each instance,
//!    unique binaries are uploaded once to S3 and then pulled from there.
//!
//! Per-deployment data (binaries, configs, hosts files) is isolated under `deployments/{tag}/` to prevent
//! conflicts between concurrent deployments.
//!
//! The bucket stores:
//!   * `tools/binaries/{tool}/{version}/{platform}/{filename}` - Tool binaries (e.g., prometheus, grafana)
//!   * `tools/configs/{deployer-version}/{component}/{file}` - Static configs and service files
//!   * `deployments/{tag}/` - Deployment-specific files:
//!     * `monitoring/` - Prometheus config, dashboard
//!     * `instances/{name}/` - Binary, config, hosts.yaml, promtail config, pyroscope script
//!
//! Tool binaries are namespaced by tool version and platform. Static configs are namespaced by deployer
//! version to ensure cache invalidation when the deployer is updated.
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
//!     profiling: true
//!   - name: node2
//!     region: us-west-2
//!     instance_type: t4g.small
//!     storage_size: 10
//!     storage_class: gp2
//!     binary: /path/to/binary2
//!     config: /path/to/config2.conf
//!     profiling: false
//! ports:
//!   - protocol: tcp
//!     port: 4545
//!     cidr: 0.0.0.0/0
//! ```

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

cfg_if::cfg_if! {
    if #[cfg(feature="aws")] {
        use thiserror::Error;
        use std::path::PathBuf;

        /// CPU architecture for EC2 instances
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Architecture {
            Arm64,
            X86_64,
        }

        impl Architecture {
            /// Returns the architecture string for AMI name matching
            pub fn ami_arch(&self) -> &'static str {
                match self {
                    Architecture::Arm64 => "arm64",
                    Architecture::X86_64 => "amd64",
                }
            }

            /// Returns the architecture string for download URLs
            pub fn download_arch(&self) -> &'static str {
                match self {
                    Architecture::Arm64 => "arm64",
                    Architecture::X86_64 => "amd64",
                }
            }

            /// Returns the Linux library architecture path for jemalloc
            pub fn linux_lib_arch(&self) -> &'static str {
                match self {
                    Architecture::Arm64 => "aarch64-linux-gnu",
                    Architecture::X86_64 => "x86_64-linux-gnu",
                }
            }
        }

        impl std::fmt::Display for Architecture {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Architecture::Arm64 => write!(f, "arm64"),
                    Architecture::X86_64 => write!(f, "x86_64"),
                }
            }
        }

        pub mod aws;
        mod create;
        pub mod services;
        pub use create::create;
        mod update;
        pub use update::update;
        mod authorize;
        pub use authorize::authorize;
        mod destroy;
        pub use destroy::destroy;
        mod clean;
        pub use clean::clean;
        pub mod utils;
        pub mod s3;

        /// Name of the monitoring instance
        const MONITORING_NAME: &str = "monitoring";

        /// AWS region where monitoring instances are deployed
        const MONITORING_REGION: &str = "us-east-1";

        /// File name that indicates the deployment completed
        const CREATED_FILE_NAME: &str = "created";

        /// File name that indicates the deployment was destroyed
        const DESTROYED_FILE_NAME: &str = "destroyed";

        /// Port on instance where system metrics are exposed
        const SYSTEM_PORT: u16 = 9100;

        /// Port on monitoring where logs are pushed
        const LOGS_PORT: u16 = 3100;

        /// Port on monitoring where profiles are pushed
        const PROFILES_PORT: u16 = 4040;

        /// Port on monitoring where traces are pushed
        const TRACES_PORT: u16 = 4318;

        /// Subcommand name
        pub const CMD: &str = "ec2";

        /// Create subcommand name
        pub const CREATE_CMD: &str = "create";

        /// Update subcommand name
        pub const UPDATE_CMD: &str = "update";

        /// Authorize subcommand name
        pub const AUTHORIZE_CMD: &str = "authorize";

        /// Destroy subcommand name
        pub const DESTROY_CMD: &str = "destroy";

        /// Clean subcommand name
        pub const CLEAN_CMD: &str = "clean";

        /// Directory where deployer files are stored
        fn deployer_directory(tag: &str) -> PathBuf {
            let base_dir = std::env::var("HOME").expect("$HOME is not configured");
            PathBuf::from(format!("{base_dir}/.commonware_deployer/{tag}"))
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
            #[error("AWS S3 error: {0}")]
            AwsS3(Box<aws_sdk_s3::Error>),
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
            #[error("invalid IP address: {0}")]
            IpAddrParse(#[from] std::net::AddrParseError),
            #[error("IP address is not IPv4: {0}")]
            IpAddrNotV4(std::net::IpAddr),
            #[error("download failed: {0}")]
            DownloadFailed(String),
            #[error("S3 presigning config error: {0}")]
            S3PresigningConfig(#[from] aws_sdk_s3::presigning::PresigningConfigError),
            #[error("S3 presigning failed: {0}")]
            S3PresigningFailed(Box<aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::get_object::GetObjectError>>),
            #[error("S3 builder error: {0}")]
            S3Builder(#[from] aws_sdk_s3::error::BuildError),
            #[error("duplicate instance name: {0}")]
            DuplicateInstanceName(String),
        }

        impl From<aws_sdk_s3::Error> for Error {
            fn from(err: aws_sdk_s3::Error) -> Self {
                Self::AwsS3(Box::new(err))
            }
        }

        impl From<aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::get_object::GetObjectError>> for Error {
            fn from(err: aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::get_object::GetObjectError>) -> Self {
                Self::S3PresigningFailed(Box::new(err))
            }
        }
    }
}

/// Port on binary where metrics are exposed
pub const METRICS_PORT: u16 = 9090;

/// Host deployment information
#[derive(Serialize, Deserialize, Clone)]
pub struct Host {
    /// Name of the host
    pub name: String,

    /// Region where the host is deployed
    pub region: String,

    /// Public IP address of the host
    pub ip: IpAddr,
}

/// List of hosts
#[derive(Serialize, Deserialize, Clone)]
pub struct Hosts {
    /// Private IP address of the monitoring instance
    pub monitoring: IpAddr,

    /// Hosts deployed across all regions
    pub hosts: Vec<Host>,
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

    /// Whether to enable profiling
    pub profiling: bool,
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
