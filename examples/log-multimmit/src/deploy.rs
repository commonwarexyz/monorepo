//! Remote deployment bundle generation.

use crate::{
    bench,
    config::{NodeTuning, validate_committee},
};
use clap::Args;
use commonware_deployer::aws;
use commonware_utils::NZUsize;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    num::NonZeroUsize,
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
/// Default Tokio worker threads per validator.
const DEFAULT_WORKER_THREADS: NonZeroUsize = NZUsize!(4);
/// Directory on each validator that holds persisted consensus state.
const DATA_DIR: &str = "/home/ubuntu/data";

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
    #[arg(long, default_value_t = DEFAULT_WORKER_THREADS)]
    worker_threads: NonZeroUsize,

    #[command(flatten)]
    tuning: NodeTuning,

    /// Validator P2P port.
    #[arg(long, default_value_t = 3000)]
    port: u16,

    /// Enable CPU profiling on validators.
    #[arg(long, default_value_t = false)]
    profiling: bool,

    /// Fraction of traces sent to the monitoring instance.
    ///
    /// Sampling applies to trace identifiers. Independent validator round roots are sampled
    /// separately, not as one deployment-wide trace.
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
    /// Benchmark repetition added by a benchmark driver; see [`bench::Config`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benchmark: Option<bench::Config>,
    /// This node's participant key.
    pub key: u64,
    /// P2P port every validator listens on.
    pub port: u16,
    /// Participant keys in committee order.
    pub participants: Vec<u64>,
    /// Producer keys in chain order.
    pub producers: Vec<u64>,
    /// Participant keys every node dials on startup.
    pub bootstrappers: Vec<u64>,
    /// Tokio worker threads.
    pub worker_threads: NonZeroUsize,
    /// Consensus, marshal, and production settings.
    #[serde(flatten)]
    pub tuning: NodeTuning,
    /// Directory for all persisted consensus state.
    pub storage_dir: PathBuf,
    /// Fraction of traces sent to the monitoring instance.
    pub trace_sampling: f64,
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
        if let Err(error) = self
            .tuning
            .validate()
            .and_then(|()| validate_committee(&self.participants(), &self.producers()))
        {
            panic!("invalid deployment: {error}");
        }
        assert!(self.port != 0, "port must be non-zero");
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
        let participants = self.participants();
        let producers = self.producers();
        let bootstrappers = participants[..self.bootstrappers].to_vec();
        for key in &participants {
            let config = NodeConfig {
                benchmark: None,
                key: *key,
                port: self.port,
                participants: participants.clone(),
                producers: producers.clone(),
                bootstrappers: bootstrappers.clone(),
                worker_threads: self.worker_threads,
                tuning: self.tuning.clone(),
                storage_dir: PathBuf::from(DATA_DIR),
                trace_sampling: self.trace_sampling,
            };
            write_yaml(&self.output_dir.join(format!("node-{key}.yaml")), &config);
        }
    }

    fn participants(&self) -> Vec<u64> {
        (0..self.nodes as u64).collect()
    }

    fn producers(&self) -> Vec<u64> {
        if self.producers.is_empty() {
            self.participants()
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
            ports: vec![aws::PortConfig {
                protocol: "tcp".to_string(),
                port: self.port,
                cidr: "0.0.0.0/0".to_string(),
            }],
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
    use crate::config::{EXTENSION_BOUND, Output, PIPELINE_DEPTH, RunConfig};
    use clap::{Command, FromArgMatches as _};
    use commonware_deployer::aws::{Host, Hosts, Ips, METRICS_PORT, TRACES_PORT};
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        num::NonZeroU64,
    };

    fn parse(args: &[&str]) -> Deploy {
        let matches = <Deploy as Args>::augment_args(Command::new("deploy"))
            .try_get_matches_from(args)
            .unwrap();
        Deploy::from_arg_matches(&matches).unwrap()
    }

    fn write_bundle(deploy: &mut Deploy) -> PathBuf {
        deploy.output_dir =
            std::env::temp_dir().join(format!("commonware-trace-run-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&deploy.output_dir).unwrap();
        deploy.write_node_configs();
        let monitoring_ip = "127.0.0.1".parse().unwrap();
        let hosts = Hosts {
            monitoring: Ips {
                public: monitoring_ip,
                private: monitoring_ip,
            },
            hosts: (0..deploy.nodes)
                .map(|key| Host {
                    name: key.to_string(),
                    region: "test".to_owned(),
                    ip: monitoring_ip,
                })
                .collect(),
        };
        let hosts_path = deploy.output_dir.join("hosts.yaml");
        write_yaml(&hosts_path, &hosts);
        hosts_path
    }

    #[test]
    fn deployment_configures_trace_endpoint() {
        let mut deploy = parse(&["deploy", "--pipeline-depth", "48"]);
        let hosts_path = write_bundle(&mut deploy);
        for key in 0..deploy.nodes {
            let path = deploy.output_dir.join(format!("node-{key}.yaml"));
            let raw = std::fs::read_to_string(&path).unwrap();
            let node: NodeConfig = serde_yaml::from_str(&raw).unwrap();
            assert_eq!(node.port, deploy.port);
            assert_eq!(node.tuning.pipeline_depth, 48);
            let config = RunConfig::load_remote(&path, &hosts_path);
            config.validate().unwrap();
            assert_eq!(config.identity.key, key as u64);
            assert_eq!(config.identity.storage_dir, Path::new(DATA_DIR));
            assert_eq!(config.tuning.pipeline_depth, 48);
            let Output::Headless(telemetry) = &config.output else {
                panic!("deployed nodes run headless");
            };
            assert_eq!(
                telemetry.metrics,
                Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    METRICS_PORT
                ))
            );
            let traces = telemetry.traces.as_ref().unwrap();
            assert_eq!(
                traces.endpoint,
                format!("http://127.0.0.1:{TRACES_PORT}/v1/traces")
            );
            assert_eq!(traces.rate.as_f64(), deploy.trace_sampling);
        }
        std::fs::remove_dir_all(&deploy.output_dir).unwrap();
    }

    #[test]
    fn zero_trace_sampling_disables_trace_export() {
        let mut deploy = parse(&["deploy", "--trace-sampling", "0"]);
        let hosts_path = write_bundle(&mut deploy);
        let config = RunConfig::load_remote(&deploy.output_dir.join("node-0.yaml"), &hosts_path);
        let Output::Headless(telemetry) = &config.output else {
            panic!("deployed nodes run headless");
        };
        assert!(telemetry.traces.is_none());
        std::fs::remove_dir_all(&deploy.output_dir).unwrap();
    }

    #[test]
    fn node_config_keeps_its_flat_yaml_layout() {
        let deploy = parse(&["deploy"]);
        let config = NodeConfig {
            benchmark: None,
            key: 0,
            port: deploy.port,
            participants: vec![0, 1],
            producers: vec![0],
            bootstrappers: vec![0],
            worker_threads: deploy.worker_threads,
            tuning: deploy.tuning.clone(),
            storage_dir: PathBuf::from(DATA_DIR),
            trace_sampling: deploy.trace_sampling,
        };
        let raw = serde_yaml::to_string(&config).unwrap();
        for line in [
            "key: 0",
            "worker_threads: 4",
            "compute_threads: 2",
            "critical_threads: null",
            "body_size: 1024",
            "pipeline_depth: 32",
            "extension_bound: 16",
            "production_interval_ms: 0",
            "marshal_live_cache_bytes: 536870912",
            "marshal_materialized_cache_bytes: 536870912",
            "storage_dir: /home/ubuntu/data",
            "trace_sampling: 0.25",
        ] {
            assert!(
                raw.lines().any(|raw| raw == line),
                "missing `{line}` in:\n{raw}"
            );
        }
        assert!(!raw.contains("benchmark"));
        assert!(!raw.contains("offered_bytes_per_second"));
        assert!(!raw.contains("marshal_delivery_bytes"));

        // Optional tuning keys fall back to the command-line defaults.
        let minimal = "key: 1\nport: 3000\nparticipants: [0, 1]\nproducers: [0]\n\
            bootstrappers: [0]\nworker_threads: 4\ncompute_threads: 2\nbody_size: 1024\n\
            marshal_live_cache_bytes: 1\nmarshal_materialized_cache_bytes: 1\n\
            storage_dir: /tmp\ntrace_sampling: 0.5\n";
        let minimal: NodeConfig = serde_yaml::from_str(minimal).unwrap();
        assert_eq!(minimal.tuning.pipeline_depth, PIPELINE_DEPTH);
        assert_eq!(minimal.tuning.extension_bound, EXTENSION_BOUND);
        assert_eq!(minimal.tuning.production_interval_ms, 0);
        assert_eq!(minimal.tuning.critical_threads, None);
        assert_eq!(minimal.tuning.offered_bytes_per_second, None);
        assert!(serde_yaml::from_str::<NodeConfig>("key: 1\nport: 3000\n").is_err());
    }

    #[test]
    fn security_group_opens_the_p2p_port() {
        for port in [3_000, 4_000, u16::MAX] {
            let port_arg = port.to_string();
            let deploy = parse(&["deploy", "--port", &port_arg]);
            deploy.validate();
            let config = deploy.deployer_config();
            assert_eq!(config.ports.len(), 1);
            assert_eq!(config.ports[0].port, port);
            assert_eq!(config.ports[0].protocol, "tcp");
        }
    }

    #[test]
    #[should_panic(expected = "producer 1 is listed more than once")]
    fn duplicate_producers_are_rejected() {
        parse(&["deploy", "--producers", "1,1"]).validate();
    }

    #[test]
    #[should_panic(expected = "producer 6 is not a participant")]
    fn producers_must_be_validators() {
        parse(&["deploy", "--producers", "6"]).validate();
    }

    #[test]
    fn delivery_budget_is_optional_and_nonzero() {
        assert_eq!(parse(&["deploy"]).tuning.marshal_delivery_bytes, None);
        assert_eq!(
            parse(&["deploy", "--marshal-delivery-bytes", "134217728"])
                .tuning
                .marshal_delivery_bytes,
            NonZeroUsize::new(128 * 1024 * 1024),
        );
        assert!(
            <Deploy as Args>::augment_args(Command::new("deploy"))
                .try_get_matches_from(["deploy", "--marshal-delivery-bytes", "0"])
                .is_err()
        );
    }

    #[test]
    fn offered_load_is_optional_and_nonzero() {
        assert_eq!(parse(&["deploy"]).tuning.offered_bytes_per_second, None);
        assert_eq!(
            parse(&["deploy", "--offered-bytes-per-second", "5120000"])
                .tuning
                .offered_bytes_per_second,
            NonZeroU64::new(5_120_000),
        );
        assert!(
            <Deploy as Args>::augment_args(Command::new("deploy"))
                .try_get_matches_from(["deploy", "--offered-bytes-per-second", "0"])
                .is_err()
        );
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
