//! Remote deployment bundle generation.

use clap::Args;
use commonware_deployer::aws;
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
const STORAGE_CLASS: &str = "gp3";

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

    /// Monitoring volume size in GiB.
    #[arg(long, default_value_t = 50)]
    monitoring_storage_size: i32,

    /// Provisioned IOPS for validator gp3 volumes.
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

    /// Validator P2P port.
    #[arg(long, default_value_t = 3000)]
    port: u16,

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
    pub participants: Vec<u64>,
    pub producers: Vec<u64>,
    pub bootstrappers: Vec<u64>,
    pub worker_threads: usize,
    pub compute_threads: usize,
    pub storage_dir: PathBuf,
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
        assert!(self.storage_size > 0, "storage size must be positive");
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
                participants: participants.clone(),
                producers: producers.clone(),
                bootstrappers: bootstrappers.clone(),
                worker_threads: self.worker_threads,
                compute_threads: self.compute_threads,
                storage_dir: PathBuf::from("/home/ubuntu/data"),
                trace_sampling: self.trace_sampling,
            };
            write_yaml(&self.output_dir.join(format!("node-{key}.yaml")), &config);
        }
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
        let instances = (0..self.nodes)
            .map(|index| aws::InstanceConfig {
                name: index.to_string(),
                region: self.regions[index % self.regions.len()].clone(),
                availability_zone_group: None,
                instance_type: self.instance_type.clone(),
                storage_size: self.storage_size,
                storage_class: STORAGE_CLASS.to_string(),
                storage_iops: self.storage_iops,
                storage_throughput: self.storage_throughput,
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
                storage_class: STORAGE_CLASS.to_string(),
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
