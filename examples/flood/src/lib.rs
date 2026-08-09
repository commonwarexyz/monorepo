//! Spam peers deployed to AWS EC2 with random messages.
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
//! cargo run --bin setup -- --peers 3 --bootstrappers 1 --regions us-west-2,us-east-1,eu-west-1 --instance-type c7g.xlarge --storage-size 10 --storage-class gp3 --worker-threads 4 --message-size 1024 --message-rate 16384 --mailbox-size 16384 --dashboard dashboard.json --output assets
//! ```
//!
//! _We use 3 peers (instead of the 2 required to test connection performance) to demonstrate that peer discovery works._
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
//! deployer aws create --config config.yaml
//! ```
//!
//! # Monitor Performance on Grafana
//!
//! Visit `http://<monitoring-ip>:3000/d/flood`
//!
//! _This dashboard is only accessible from the IP used to deploy the infrastructure._
//!
//! ## (Optional) Update Flood Binary
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
//! deployer aws update --config config.yaml
//! ```
//!
//! # Destroy Infrastructure
//!
//! ```bash
//! deployer aws destroy --config config.yaml
//! ```
//!
//! # Debugging
//!
//! ## Missing AWS Credentials
//!
//! If `commonware-deployer` can't detect your AWS credentials, you'll see a "Request has expired." error:
//!
//! ```txt
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

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use commonware_utils::Bounded;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::num::{NonZeroU32, NonZeroUsize};

const MIN_MESSAGE_SIZE: u32 = size_of::<u64>() as _;

fn deserialize_message_size<'de, D>(
    deserializer: D,
) -> Result<Bounded<u32, MIN_MESSAGE_SIZE, { commonware_p2p::authenticated::MAX_SIZE }>, D::Error>
where
    D: Deserializer<'de>,
{
    let message_size = u32::deserialize(deserializer)?;
    message_size.try_into().map_err(|message_size| {
        D::Error::custom(format_args!(
            "message_size must be between {MIN_MESSAGE_SIZE} and {} bytes (received {message_size})",
            commonware_p2p::authenticated::MAX_SIZE,
        ))
    })
}

fn serialize_message_size<S>(
    message_size: &Bounded<u32, MIN_MESSAGE_SIZE, { commonware_p2p::authenticated::MAX_SIZE }>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    message_size.get().serialize(serializer)
}

/// Configuration for flood.
#[derive(Deserialize, Serialize)]
pub struct Config {
    pub private_key: String,
    pub port: u16,
    pub allowed_peers: Vec<String>,
    pub bootstrappers: Vec<String>,
    pub worker_threads: usize,
    #[serde(
        deserialize_with = "deserialize_message_size",
        serialize_with = "serialize_message_size"
    )]
    pub message_size: Bounded<u32, MIN_MESSAGE_SIZE, { commonware_p2p::authenticated::MAX_SIZE }>,
    pub message_rate: NonZeroU32,
    pub mailbox_size: NonZeroUsize,
    pub instrument: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_message_size(message_size: u32) -> String {
        format!(
            r#"private_key: key
port: 1
allowed_peers: []
bootstrappers: []
worker_threads: 1
message_size: {message_size}
message_rate: 1
mailbox_size: 1
instrument: false
"#
        )
    }

    #[test]
    fn rejects_invalid_message_sizes_during_deserialization() {
        for message_size in [0, MIN_MESSAGE_SIZE - 1] {
            let error = serde_yaml::from_str::<Config>(&config_with_message_size(message_size))
                .err()
                .expect("undersized message should be rejected");
            assert!(error.to_string().contains("message_size"));
        }

        let oversized = commonware_p2p::authenticated::MAX_SIZE + 1;
        let oversized_error = serde_yaml::from_str::<Config>(&config_with_message_size(oversized))
            .err()
            .expect("oversized message size should be rejected");
        assert!(oversized_error.to_string().contains("message_size"));
        assert!(
            oversized_error
                .to_string()
                .contains(&commonware_p2p::authenticated::MAX_SIZE.to_string())
        );

        let minimum = serde_yaml::from_str::<Config>(&config_with_message_size(MIN_MESSAGE_SIZE))
            .expect("minimum message size should be accepted");
        assert_eq!(minimum.message_size.get(), MIN_MESSAGE_SIZE);

        let maximum = serde_yaml::from_str::<Config>(&config_with_message_size(
            commonware_p2p::authenticated::MAX_SIZE,
        ))
        .expect("maximum message size should be accepted");
        assert_eq!(
            maximum.message_size.get(),
            commonware_p2p::authenticated::MAX_SIZE
        );

        let serialized = serde_yaml::to_string(&maximum).expect("config should serialize");
        let round_trip: Config =
            serde_yaml::from_str(&serialized).expect("serialized config should deserialize");
        assert_eq!(round_trip.message_size, maximum.message_size);
    }
}
