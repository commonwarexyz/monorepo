//! Remote deployment bundle generation.

use crate::BULK_PORT_OFFSET;
use clap::{Args, ValueEnum};
use commonware_consensus::multimmit::ProposalPolicy;
use commonware_deployer::aws;
use core::fmt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};
use tracing::info;
use uuid::Uuid;

const BINARY_FILE: &str = "commonware-log-multimmit";
const CONFIG_FILE: &str = "config.yaml";
const DASHBOARD_FILE: &str = "dashboard.json";
const DEFAULT_REGIONS: &str = "us-east-1,us-west-2,eu-west-1";
const DEFAULT_STORAGE_CLASS: &str = "gp3";
const DEFAULT_STORAGE_IOPS: i32 = 16_000;
const DEFAULT_STORAGE_THROUGHPUT: i32 = 1_250;
pub(super) const DEFAULT_MARSHAL_LIVE_CACHE_BYTES: usize = 512 * 1024 * 1024;
pub(super) const DEFAULT_MARSHAL_MATERIALIZED_CACHE_BYTES: usize = 512 * 1024 * 1024;

/// Generate a remote AWS deployment bundle.
#[derive(Debug, Args)]
pub struct Deploy {
    /// Directory to create with node and deployer configuration.
    #[arg(long, default_value = "deploy")]
    output_dir: PathBuf,

    /// Number of validator nodes.
    #[arg(long, default_value_t = 6)]
    nodes: usize,

    /// Producer keys in chain order. Defaults to every validator.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    producers: Vec<u64>,

    /// Number of validators all nodes dial during startup.
    #[arg(long, default_value_t = 2)]
    bootstrappers: usize,

    /// AWS regions across which validators are spread.
    #[arg(long, value_delimiter = ',', default_value = DEFAULT_REGIONS)]
    regions: Vec<String>,

    /// EC2 instance type for validators.
    #[arg(long, default_value = "c8g.large")]
    instance_type: String,

    /// EC2 instance type for monitoring.
    #[arg(long, default_value = "t4g.small")]
    monitoring_instance_type: String,

    /// Validator volume size in GiB.
    #[arg(long, default_value_t = 50)]
    storage_size: i32,

    /// EBS volume class for validators.
    #[arg(long, default_value = DEFAULT_STORAGE_CLASS)]
    storage_class: String,

    /// Monitoring volume size in GiB.
    #[arg(long, default_value_t = 50)]
    monitoring_storage_size: i32,

    /// Provisioned IOPS for validator volumes.
    #[arg(long)]
    storage_iops: Option<i32>,

    /// Provisioned throughput in MiB/s for validator gp3 volumes.
    #[arg(long)]
    storage_throughput: Option<i32>,

    /// Provisioned IOPS for the monitoring gp3 volume.
    #[arg(long)]
    monitoring_storage_iops: Option<i32>,

    /// Provisioned throughput in MiB/s for the monitoring gp3 volume.
    #[arg(long)]
    monitoring_storage_throughput: Option<i32>,

    /// Tokio worker threads per validator.
    #[arg(long, default_value_t = 4)]
    worker_threads: usize,

    /// Parallel verification threads per validator.
    #[arg(long, default_value_t = 2)]
    compute_threads: usize,

    /// View-critical cryptography threads per validator.
    ///
    /// Defaults to the committee-derived width, which scales with the validator count.
    #[arg(long)]
    critical_threads: Option<usize>,

    /// Bytes of junk data placed in every producer block body.
    #[arg(long, default_value_t = 1_024)]
    body_size: usize,

    /// Maximum blocks appended by one producer-chain proposal.
    ///
    /// A time window in blocks: it must cover the DA-certificate lag at the configured block
    /// rate, so smaller bodies at the same byte throughput need proportionally larger values.
    #[arg(long, default_value_t = default_pipeline_depth())]
    pipeline_depth: u32,

    /// Maximum blocks carried by one vote extension per chain.
    ///
    /// A time window in blocks, like the pipeline depth: it must cover the proposal-tip-to-
    /// frontier gap at the configured block rate.
    #[arg(long, default_value_t = default_extension_bound())]
    extension_bound: u32,

    /// How far above its anchor a leader's proposal reaches on each producer chain.
    #[arg(long, value_enum, default_value_t)]
    proposal_policy: ProposalPolicyArg,

    /// Minimum milliseconds between two blocks built by one producer (the paper's theta).
    ///
    /// Zero builds as fast as block custody admits.
    #[arg(long, default_value_t = 0)]
    production_interval_ms: u64,

    /// Bytes reserved for live producer blocks awaiting ordered delivery.
    #[arg(long, default_value_t = DEFAULT_MARSHAL_LIVE_CACHE_BYTES)]
    marshal_live_cache_bytes: usize,

    /// Bytes reserved for reused historical producer-block reads.
    #[arg(long, default_value_t = DEFAULT_MARSHAL_MATERIALIZED_CACHE_BYTES)]
    marshal_materialized_cache_bytes: usize,

    /// Validator consensus-plane port.
    #[arg(long, default_value_t = 3000)]
    port: u16,

    /// Validator bulk-plane port. Defaults to the consensus-plane port plus one.
    #[arg(long)]
    bulk_port: Option<u16>,

    /// Enable CPU profiling on validators.
    #[arg(long, default_value_t = false)]
    profiling: bool,

    /// Fraction of traces sent to the monitoring instance.
    ///
    /// Sampling keys on the deterministic per-view trace identifier, so every validator keeps
    /// or drops the same views and each kept view arrives as one deployment-wide trace.
    #[arg(long, default_value_t = 0.25, value_parser = parse_sampling_rate)]
    trace_sampling: f64,

    /// Dashboard to provision instead of the bundled dashboard.
    #[arg(long)]
    dashboard: Option<PathBuf>,

    /// Deployable binary filename expected in the output directory.
    #[arg(long, default_value = BINARY_FILE)]
    binary: String,
}

/// Per-node configuration consumed by the deployed binary.
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub key: u64,
    pub port: u16,
    pub bulk_port: u16,
    pub participants: Vec<u64>,
    pub producers: Vec<u64>,
    pub bootstrappers: Vec<u64>,
    pub worker_threads: usize,
    pub compute_threads: usize,
    #[serde(default)]
    pub critical_threads: Option<usize>,
    pub body_size: usize,
    #[serde(default = "default_pipeline_depth")]
    pub pipeline_depth: u32,
    #[serde(default = "default_extension_bound")]
    pub extension_bound: u32,
    #[serde(default)]
    pub proposal_policy: ProposalPolicyArg,
    #[serde(default)]
    pub production_interval_ms: u64,
    pub marshal_live_cache_bytes: usize,
    pub marshal_materialized_cache_bytes: usize,
    pub storage_dir: PathBuf,
    pub trace_sampling: f64,
}

/// Default maximum blocks appended by one producer-chain proposal.
const fn default_pipeline_depth() -> u32 {
    32
}

/// Default maximum blocks carried by one vote extension per chain.
const fn default_extension_bound() -> u32 {
    16
}

/// The command-line and node-config spelling of [`ProposalPolicy`].
///
/// The consensus crate carries no serialization or argument-parsing dependencies, so the
/// deployable spelling of its local tuning lives here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ProposalPolicyArg {
    /// Propose only blocks whose data-availability certificate the leader holds.
    #[default]
    Certified,
    /// Propose the prefix the leader has DA-voted itself.
    Endorsed,
}

impl fmt::Display for ProposalPolicyArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_possible_value()
            .expect("every policy has one stable name")
            .get_name()
            .fmt(f)
    }
}

impl From<ProposalPolicyArg> for ProposalPolicy {
    fn from(value: ProposalPolicyArg) -> Self {
        match value {
            ProposalPolicyArg::Certified => Self::Certified,
            ProposalPolicyArg::Endorsed => Self::Endorsed,
        }
    }
}

impl Deploy {
    /// Generate configuration files without creating cloud resources.
    pub fn run(self) {
        self.validate();
        assert!(
            !self.output_dir.exists(),
            "output directory already exists: {}",
            self.output_dir.display()
        );

        fs::create_dir_all(&self.output_dir).expect("failed to create output directory");
        self.write_node_configs();
        self.write_dashboard();

        let config = self.deployer_config();
        write_yaml(&self.output_dir.join(CONFIG_FILE), &config);
        info!(
            output_dir = %self.output_dir.display(),
            nodes = self.nodes,
            "generated remote deployment bundle"
        );
        info!(
            binary = %self.output_dir.join(&self.binary).display(),
            "build or copy the deployable binary before creating the deployment"
        );
        info!(
            command = %format!("cd {} && deployer aws create --config {CONFIG_FILE}", self.output_dir.display()),
            "create the deployment"
        );
    }

    fn validate(&self) {
        assert!(self.nodes >= 6, "Multimmit requires at least six nodes");
        assert!(
            self.pipeline_depth >= 1,
            "a pipeline must admit at least one block"
        );
        let producers = self.producers();
        assert_eq!(
            producers.iter().collect::<BTreeSet<_>>().len(),
            producers.len(),
            "producers must be unique"
        );
        assert!(
            producers
                .iter()
                .all(|producer| *producer < self.nodes as u64),
            "every producer must be a validator"
        );
        assert!(self.port != 0, "port must be non-zero");
        assert!(
            self.bulk_port() > self.port,
            "bulk port must be above the consensus-plane port"
        );
        assert!(self.bootstrappers > 0, "need at least one bootstrapper");
        assert!(
            self.bootstrappers <= self.nodes,
            "bootstrappers cannot exceed nodes"
        );
        assert!(!self.regions.is_empty(), "need at least one region");
        assert!(
            self.regions.len() <= self.nodes,
            "need at least one node per region"
        );
        assert!(self.worker_threads > 0, "worker threads must be non-zero");
        assert!(self.compute_threads > 0, "compute threads must be non-zero");
        assert!(
            self.critical_threads.is_none_or(|threads| threads > 0),
            "critical threads must be non-zero"
        );
        assert!(
            self.marshal_live_cache_bytes > 0,
            "marshal live cache must be non-zero"
        );
        assert!(
            self.marshal_materialized_cache_bytes > 0,
            "marshal materialized cache must be non-zero"
        );
        assert!(
            u32::try_from(self.body_size).is_ok(),
            "body size must fit in the canonical bytes codec"
        );
        assert!(self.storage_size > 0, "storage size must be positive");
        assert!(
            self.storage_iops.is_none_or(|iops| iops > 0),
            "storage IOPS must be positive"
        );
        assert!(
            self.storage_throughput
                .is_none_or(|throughput| throughput > 0),
            "storage throughput must be positive"
        );
        assert!(
            !self.storage_class.is_empty(),
            "storage class must be non-empty"
        );
        assert!(
            self.monitoring_storage_size > 0,
            "monitoring storage size must be positive"
        );
    }

    fn write_node_configs(&self) {
        let participants = (0..self.nodes as u64).collect::<Vec<_>>();
        let producers = self.producers();
        let bootstrappers = participants[..self.bootstrappers].to_vec();
        for key in &participants {
            let config = NodeConfig {
                key: *key,
                port: self.port,
                bulk_port: self.bulk_port(),
                participants: participants.clone(),
                producers: producers.clone(),
                bootstrappers: bootstrappers.clone(),
                worker_threads: self.worker_threads,
                compute_threads: self.compute_threads,
                critical_threads: self.critical_threads,
                body_size: self.body_size,
                pipeline_depth: self.pipeline_depth,
                extension_bound: self.extension_bound,
                proposal_policy: self.proposal_policy,
                production_interval_ms: self.production_interval_ms,
                marshal_live_cache_bytes: self.marshal_live_cache_bytes,
                marshal_materialized_cache_bytes: self.marshal_materialized_cache_bytes,
                storage_dir: PathBuf::from("/home/ubuntu/data"),
                trace_sampling: self.trace_sampling,
            };
            write_yaml(&self.output_dir.join(format!("node-{key}.yaml")), &config);
        }
    }

    /// Port every validator binds for the bulk block plane.
    ///
    /// The deployed binary derives every peer's bulk address by shifting that peer's
    /// consensus address by the local offset, so all validators must share this offset.
    fn bulk_port(&self) -> u16 {
        self.bulk_port.unwrap_or_else(|| {
            self.port
                .checked_add(BULK_PORT_OFFSET)
                .expect("bulk port must be representable")
        })
    }

    fn producers(&self) -> Vec<u64> {
        if self.producers.is_empty() {
            (0..self.nodes as u64).collect()
        } else {
            self.producers.clone()
        }
    }

    fn write_dashboard(&self) {
        let destination = self.output_dir.join(DASHBOARD_FILE);
        if let Some(source) = &self.dashboard {
            fs::copy(source, destination).expect("failed to copy dashboard");
            return;
        }
        fs::write(destination, include_bytes!("../assets/dashboard.json"))
            .expect("failed to write bundled dashboard");
    }

    fn deployer_config(&self) -> aws::Config {
        let gp3 = self.storage_class == DEFAULT_STORAGE_CLASS;
        let storage_iops = self.storage_iops.or(gp3.then_some(DEFAULT_STORAGE_IOPS));
        let storage_throughput = self
            .storage_throughput
            .or(gp3.then_some(DEFAULT_STORAGE_THROUGHPUT));
        let instances = (0..self.nodes)
            .map(|index| aws::InstanceConfig {
                name: index.to_string(),
                region: self.regions[index % self.regions.len()].clone(),
                availability_zone_group: None,
                instance_type: self.instance_type.clone(),
                storage_size: self.storage_size,
                storage_class: self.storage_class.clone(),
                storage_iops,
                storage_throughput,
                binary: self.binary.clone(),
                config: format!("node-{index}.yaml"),
                profiling: self.profiling,
            })
            .collect();

        aws::Config {
            tag: format!("log-multimmit-{}", Uuid::new_v4()),
            monitoring: aws::MonitoringConfig {
                instance_type: self.monitoring_instance_type.clone(),
                storage_size: self.monitoring_storage_size,
                storage_class: DEFAULT_STORAGE_CLASS.to_string(),
                storage_iops: self.monitoring_storage_iops,
                storage_throughput: self.monitoring_storage_throughput,
                dashboard: DASHBOARD_FILE.to_string(),
            },
            instances,
            ports: vec![
                aws::PortConfig {
                    protocol: "tcp".to_string(),
                    port: self.port,
                    cidr: "0.0.0.0/0".to_string(),
                },
                aws::PortConfig {
                    protocol: "tcp".to_string(),
                    port: self.bulk_port(),
                    cidr: "0.0.0.0/0".to_string(),
                },
            ],
        }
    }
}

fn parse_sampling_rate(value: &str) -> Result<f64, String> {
    let rate = value
        .parse::<f64>()
        .map_err(|error| format!("invalid sampling rate: {error}"))?;
    if !(0.0..=1.0).contains(&rate) {
        return Err("sampling rate must be between 0 and 1".to_string());
    }
    Ok(rate)
}

fn write_yaml(path: &Path, value: &impl Serialize) {
    let file = fs::File::create(path).expect("failed to create configuration file");
    serde_yaml::to_writer(file, value).expect("failed to serialize configuration");
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Command, FromArgMatches as _};

    fn parse(args: &[&str]) -> Deploy {
        let matches = <Deploy as Args>::augment_args(Command::new("deploy"))
            .try_get_matches_from(args)
            .unwrap();
        Deploy::from_arg_matches(&matches).unwrap()
    }

    #[test]
    fn both_planes_are_opened_by_the_security_group() {
        let default = parse(&["deploy"]);
        assert_eq!(default.bulk_port(), 3_001);
        let config = default.deployer_config();
        let ports = config
            .ports
            .iter()
            .map(|port| port.port)
            .collect::<Vec<_>>();
        assert_eq!(ports, [3_000, 3_001]);

        let explicit = parse(&["deploy", "--port", "4000", "--bulk-port", "4100"]);
        assert_eq!(explicit.bulk_port(), 4_100);
        let ports = explicit
            .deployer_config()
            .ports
            .iter()
            .map(|port| port.port)
            .collect::<Vec<_>>();
        assert_eq!(ports, [4_000, 4_100]);
    }

    #[test]
    #[should_panic(expected = "bulk port must be above the consensus-plane port")]
    fn bulk_port_must_not_collide_with_the_consensus_plane() {
        parse(&["deploy", "--port", "3000", "--bulk-port", "3000"]).validate();
    }

    #[test]
    fn the_proposal_policy_is_certified_unless_named() {
        assert_eq!(
            parse(&["deploy"]).proposal_policy,
            ProposalPolicyArg::Certified
        );
        assert_eq!(
            parse(&["deploy", "--proposal-policy", "endorsed"]).proposal_policy,
            ProposalPolicyArg::Endorsed
        );
        assert_eq!(
            serde_yaml::from_str::<ProposalPolicyArg>("endorsed").unwrap(),
            ProposalPolicyArg::Endorsed,
            "node configs must accept the same spelling the flag takes",
        );
    }

    #[test]
    fn node_configs_carry_both_ports() {
        let deploy = parse(&["deploy"]);
        assert_eq!(deploy.port, 3_000);
        assert_eq!(deploy.bulk_port(), 3_001);
    }

    #[test]
    fn validator_storage_tuning_matches_the_volume_class() {
        let gp3 = parse(&["deploy"]);
        let config = gp3.deployer_config();
        assert_eq!(config.instances[0].storage_iops, Some(DEFAULT_STORAGE_IOPS));
        assert_eq!(
            config.instances[0].storage_throughput,
            Some(DEFAULT_STORAGE_THROUGHPUT)
        );

        let io2 = parse(&[
            "deploy",
            "--storage-class",
            "io2",
            "--storage-iops",
            "16000",
        ]);
        let config = io2.deployer_config();
        assert_eq!(config.instances[0].storage_iops, Some(16_000));
        assert_eq!(config.instances[0].storage_throughput, None);

        let gp2 = parse(&["deploy", "--storage-class", "gp2"]);
        let config = gp2.deployer_config();
        assert_eq!(config.instances[0].storage_iops, None);
        assert_eq!(config.instances[0].storage_throughput, None);
    }
}
