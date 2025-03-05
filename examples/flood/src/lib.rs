//! Flood peers deployed to AWS EC2 with random messages.
//!
//! # Setup
//!
//! _To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install) and [Docker](https://www.docker.com/get-started/)._
//!
//! ## Install `commonware-deployer`
//!
//! ```bash
//! cargo install commonware-deployer
//! ```
//!
//! ## Create Deployer Artifacts
//!
//! ```bash
//! cargo run --bin setup -- --peers 3 --bootstrappers 1 --regions us-west-2,us-east-1,eu-west-1 --instance-type c7g.medium --storage-size 10 --storage-class gp3 --message-size 1024 --message-backlog 1024 --mailbox-size 16384 --dashboard dashboard.json --output assets
//! ```
//!
//! ## Build Flood Binary
//!
//! ### Build Cross-Platform Compiler
//!
//! ```bash
//! docker build -t flood-builder .
//! ```
//!
//! ### Compile Binary for ARM64
//!
//! ```bash
//! docker run -it -v ${PWD}/../..:/monorepo flood-builder
//! ```
//!
//! _Emitted binary `flood` is placed in `assets`._
//!
//! ## Deploy Flood Binary
//!
//! ```bash
//! cd assets
//! deployer ec2 create --config config.yaml
//! ```
//!
//! # Monitor Performance on Grafana
//!
//! Visit `http://<monitoring-ip>:3000/d/flood`
//!
//! _This dashboard is only accessible from the IP used to deploy the infrastructure._
//!
//! ## [Optional] Update Flood Binary
//!
//! ## Re-Compile Binary for ARM64
//!
//! ```bash
//! docker run -it -v ${PWD}/../..:/monorepo flood-builder
//! ```
//!
//! ## Restart Flood Binary on EC2 Instances
//!
//! ```bash
//! deployer ec2 update --config config.yaml
//! ```
//!
//! # Destroy Infrastructure
//!
//! ```bash
//! deployer ec2 destroy --config config.yaml
//! ```
//!
//! # Debugging
//!
//! ## Missing AWS Credentials
//!
//! If `commonware-deployer` can't detect your AWS credentials, you'll see a "Request has expired." error:
//!
//! ```
//! 2025-03-05T01:36:47.550105Z  INFO deployer::ec2::create: created EC2 client region="eu-west-1"
//! 2025-03-05T01:36:48.268330Z ERROR deployer: failed to create EC2 deployment error=AwsEc2(Unhandled(Unhandled { source: ErrorMetadata { code: Some("RequestExpired"), message: Some("Request has expired."), extras: Some({"aws_request_id": "006f6b92-4965-470d-8eac-7c9644744bdf"}) }, meta: ErrorMetadata { code: Some("RequestExpired"), message: Some("Request has expired."), extras: Some({"aws_request_id": "006f6b92-4965-470d-8eac-7c9644744bdf"}) } }))
//! ```
//!
//! ## EC2 Throttling
//!
//! EC2 instances may throttle network traffic if a workload exceeds the allocation for a particular instance type. To check
//! if an instance is throttled, SSH into the instance and run:
//!
//! ```bash
//! ethtool -S ens5 | grep "allowance"
//! ```
//!
//! If throttled, you'll see a non-zero value for some "allowance" item:
//!
//! ```txt
//! bw_in_allowance_exceeded: 0
//! bw_out_allowance_exceeded: 14368
//! pps_allowance_exceeded: 0
//! conntrack_allowance_exceeded: 0
//! linklocal_allowance_exceeded: 0
//! ```

use serde::{Deserialize, Serialize};

/// Configuration for flood.
#[derive(Deserialize, Serialize)]
pub struct Config {
    pub private_key: String,
    pub port: u16,
    pub allowed_peers: Vec<String>,
    pub bootstrappers: Vec<String>,
    pub message_size: usize,
    pub message_backlog: usize,
    pub mailbox_size: usize,
}
