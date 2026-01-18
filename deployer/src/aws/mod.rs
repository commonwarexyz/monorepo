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
//! * Deployed in `us-east-1` with a configurable instance type (e.g., `t4g.small` for ARM64, `t3.small` for x86_64) and storage (e.g., 10GB gp2). Architecture is auto-detected from the instance type.
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
//! * Deployed in user-specified regions with configurable ARM64 or AMD64 instance types and storage.
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
//! One subnet per availability zone that supports any required instance type in the region
//! (e.g., `10.<region-index>.<az-index>.0/24`), linked to a shared route table with an internet gateway.
//! Each instance is placed in an AZ that supports its instance type, distributed round-robin across
//! eligible AZs, with automatic fallback to other AZs on capacity errors.
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
//! ## `aws create`
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
//! ## `aws update`
//!
//! Performs rolling updates across all binary instances:
//!
//! 1. Uploads the latest binary and configuration to S3.
//! 2. For each instance (up to `--concurrency` at a time, default 128):
//!    a. Stops the `binary` service.
//!    b. Downloads the updated files from S3 via pre-signed URLs.
//!    c. Restarts the `binary` service.
//!    d. Waits for the service to become active before proceeding.
//!
//! _Use `--concurrency 1` for fully sequential updates that wait for each instance to be healthy
//! before updating the next._
//!
//! ## `aws authorize`
//!
//! 1. Obtains the deployer's current public IP address (or parses the one provided).
//! 2. For each security group in the deployment, adds an ingress rule for the IP (if it doesn't already exist).
//!
//! ## `aws destroy`
//!
//! 1. Terminates all instances across regions.
//! 2. Deletes security groups, subnets, route tables, VPC peering connections, internet gateways, key pairs, and VPCs in dependency order.
//! 3. Deletes deployment-specific data from S3 (cached tools remain for future deployments).
//! 4. Marks destruction with `$HOME/.commonware_deployer/{tag}/destroyed`, retaining the directory to prevent tag reuse.
//!
//! ## `aws clean`
//!
//! 1. Deletes the shared S3 bucket and all its contents (cached tools and any remaining deployment data).
//! 2. Use this to fully clean up when you no longer need the deployer cache.
//!
//! ## `aws profile`
//!
//! 1. Loads the deployment configuration and locates the specified instance.
//! 2. Caches the samply binary in S3 if not already present.
//! 3. SSHes to the instance, downloads samply, and records a CPU profile of the running binary for the specified duration.
//! 4. Downloads the profile locally via SCP.
//! 5. Opens Firefox Profiler with symbols resolved from your local debug binary.
//!
//! # Profiling
//!
//! The deployer supports two profiling modes:
//!
//! ## Continuous Profiling (Pyroscope)
//!
//! Enable continuous CPU profiling by setting `profiling: true` in your instance config. This runs
//! Pyroscope in the background, continuously collecting profiles that are viewable in the Grafana
//! dashboard on the monitoring instance.
//!
//! For best results, build and deploy your binary with debug symbols and frame pointers:
//!
//! ```bash
//! CARGO_PROFILE_RELEASE_DEBUG=true RUSTFLAGS="-C force-frame-pointers=yes" cargo build --release
//! ```
//!
//! ## On-Demand Profiling (samply)
//!
//! To generate an on-demand CPU profile (viewable in the Firefox Profiler UI), run the
//! following:
//!
//! ```bash
//! deployer aws profile --config config.yaml --instance <name> --binary <path-to-binary-with-debug>
//! ```
//!
//! This captures a 30-second profile (configurable with `--duration`) using samply on the remote
//! instance, downloads it, and opens it in Firefox Profiler. Unlike Continuous Profiling, this mode
//! does not require deploying a binary with debug symbols (reducing deployment time).
//!
//! Like above, build your binary with debug symbols (but not frame pointers):
//!
//! ```bash
//! CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release
//! ```
//!
//! Now, strip symbols and deploy via `aws create` (preserve the original binary for profile symbolication
//! when you run the `aws profile` command shown above):
//!
//! ```bash
//! cp target/release/my-binary target/release/my-binary-debug
//! strip target/release/my-binary
//! ```
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
//!   instance_type: t4g.small  # ARM64 (Graviton)
//!   storage_size: 10
//!   storage_class: gp2
//!   dashboard: /path/to/dashboard.json
//! instances:
//!   - name: node1
//!     region: us-east-1
//!     instance_type: t4g.small  # ARM64 (Graviton)
//!     storage_size: 10
//!     storage_class: gp2
//!     binary: /path/to/binary-arm64
//!     config: /path/to/config.conf
//!     profiling: true
//!   - name: node2
//!     region: us-west-2
//!     instance_type: t3.small  # x86_64 (Intel/AMD)
//!     storage_size: 10
//!     storage_class: gp2
//!     binary: /path/to/binary-x86
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
            /// Returns the architecture string used in AMI names, download URLs, and labels
            pub const fn as_str(&self) -> &'static str {
                match self {
                    Self::Arm64 => "arm64",
                    Self::X86_64 => "amd64",
                }
            }

            /// Returns the Linux library path component for jemalloc
            pub const fn linux_lib(&self) -> &'static str {
                match self {
                    Self::Arm64 => "aarch64-linux-gnu",
                    Self::X86_64 => "x86_64-linux-gnu",
                }
            }
        }

        impl std::fmt::Display for Architecture {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        pub mod ec2;
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
        mod profile;
        pub use profile::profile;
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

        /// Maximum instances to manipulate at one time
        pub const DEFAULT_CONCURRENCY: &str = "128";

        /// Subcommand name
        pub const CMD: &str = "aws";

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

        /// Profile subcommand name
        pub const PROFILE_CMD: &str = "profile";

        /// Directory where deployer files are stored
        fn deployer_directory(tag: &str) -> PathBuf {
            let base_dir = std::env::var("HOME").expect("$HOME is not configured");
            PathBuf::from(format!("{base_dir}/.commonware_deployer/{tag}"))
        }

        /// S3 operations that can fail
        #[derive(Debug, Clone, Copy)]
        pub enum S3Operation {
            CreateBucket,
            DeleteBucket,
            HeadObject,
            ListObjects,
            DeleteObjects,
        }

        /// Reasons why accessing a bucket may be forbidden
        #[derive(Debug, Clone, Copy)]
        pub enum BucketForbiddenReason {
            /// Access denied (missing s3:ListBucket permission or bucket owned by another account)
            AccessDenied,
        }

        impl std::fmt::Display for BucketForbiddenReason {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::AccessDenied => write!(f, "access denied (check IAM permissions or bucket ownership)"),
                }
            }
        }

        impl std::fmt::Display for S3Operation {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::CreateBucket => write!(f, "CreateBucket"),
                    Self::DeleteBucket => write!(f, "DeleteBucket"),
                    Self::HeadObject => write!(f, "HeadObject"),
                    Self::ListObjects => write!(f, "ListObjects"),
                    Self::DeleteObjects => write!(f, "DeleteObjects"),
                }
            }
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
            #[error("S3 operation failed: {operation} on bucket '{bucket}'")]
            AwsS3 {
                bucket: String,
                operation: S3Operation,
                #[source]
                source: Box<aws_sdk_s3::Error>,
            },
            #[error("S3 bucket '{bucket}' forbidden: {reason}")]
            S3BucketForbidden {
                bucket: String,
                reason: BucketForbiddenReason,
            },
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
            #[error("instance not found: {0}")]
            InstanceNotFound(String),
            #[error("symbolication failed: {0}")]
            Symbolication(String),
            #[error("no subnet supports instance type: {0}")]
            UnsupportedInstanceType(String),
            #[error("no subnets available")]
            NoSubnetsAvailable,
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

    /// Instance type (e.g., `t4g.small` for ARM64, `t3.small` for x86_64)
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
    /// Instance type (e.g., `t4g.small` for ARM64, `t3.small` for x86_64)
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
