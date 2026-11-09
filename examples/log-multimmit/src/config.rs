//! Node configuration for local runs, deployment bundles, and deployed nodes.

use crate::{
    bench::{self, EmptyBody, ScheduleError},
    deploy::NodeConfig,
};
use clap::Args;
use commonware_consensus::multimmit::{
    self,
    config::Victims,
    types::{ChainId, CodecConfigError, PathLimits},
};
use commonware_deployer::aws::{Hosts, METRICS_PORT, TRACES_PORT};
use commonware_utils::{NZUsize, Probability, probability};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    net::{AddrParseError, IpAddr, Ipv4Addr, SocketAddr},
    num::{NonZeroU32, NonZeroU64, NonZeroUsize, ParseIntError},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
use thiserror::Error;
use tracing::Level;

/// Blocks a leader includes above its certified proposal anchor.
#[derive(Clone, Copy, Debug, Default, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalPolicy {
    /// Include the contiguous DA-voted frontier, bounded by the pipeline depth.
    #[default]
    Endorsed,
    /// Include only the certified anchor.
    Certified,
}

impl From<ProposalPolicy> for commonware_consensus::multimmit::config::ProposalPolicy {
    fn from(policy: ProposalPolicy) -> Self {
        match policy {
            ProposalPolicy::Endorsed => Self::Endorsed,
            ProposalPolicy::Certified => Self::Certified,
        }
    }
}

/// Default maximum blocks a producer builds above its latest DA certificate.
pub const PIPELINE_DEPTH: u32 = 32;

/// Default maximum blocks one vote extension carries per chain.
pub const EXTENSION_BOUND: u32 = 16;

/// Default bytes of junk data in every producer block body.
const BODY_SIZE: usize = 1_024;

/// Default parallel verification threads.
const COMPUTE_THREADS: NonZeroUsize = NZUsize!(2);

/// Default Tokio worker threads for local runs.
const LOCAL_WORKER_THREADS: NonZeroUsize = NZUsize!(2);

/// Default memory marshal sizes its budgets within.
const MARSHAL_MEMORY_BYTES: NonZeroUsize = NZUsize!(1024 * 1024 * 1024);

/// Fraction of traces a local run with `--trace-endpoint` exports.
const LOCAL_TRACE_SAMPLING: Probability = probability!(1, 1);

const fn default_pipeline_depth() -> u32 {
    PIPELINE_DEPTH
}

const fn default_extension_bound() -> u32 {
    EXTENSION_BOUND
}

/// A configuration that cannot run.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// No participant was listed.
    #[error("at least one participant is required")]
    NoParticipants,
    /// A participant key appears more than once.
    #[error("participant {0} is listed more than once")]
    DuplicateParticipant(u64),
    /// A producer key appears more than once.
    #[error("producer {0} is listed more than once")]
    DuplicateProducer(u64),
    /// A producer key is not a participant.
    #[error("producer {0} is not a participant")]
    UnknownProducer(u64),
    /// This node's key is not a participant.
    #[error("this node's key {0} is not a participant")]
    UnknownIdentity(u64),
    /// A bootstrapper key is not a participant.
    #[error("bootstrapper {0} is not a participant")]
    UnknownBootstrapper(u64),
    /// The pipeline window is narrower than the pipeline depth.
    #[error("invalid pipeline window: {0}")]
    PipelineWindow(CodecConfigError),
    /// The body size does not fit the canonical bytes codec.
    #[error("body size {0} does not fit the canonical bytes codec")]
    BodyTooLarge(usize),
    /// Offered load or a benchmark schedule was configured with empty bodies.
    #[error(transparent)]
    EmptyBody(#[from] EmptyBody),
    /// A benchmark was configured with the terminal UI.
    #[error("benchmarks require headless operation")]
    BenchmarkRequiresHeadless,
    /// A benchmark schedule was combined with a constant input rate.
    #[error("a benchmark schedule cannot be combined with a constant input rate")]
    ScheduleWithOfferedRate,
    /// The benchmark schedule cannot be replayed.
    #[error("invalid benchmark schedule: {0}")]
    Schedule(#[from] ScheduleError),
    /// The benchmark loss rate is not a probability.
    #[error("loss rate {0} is not a probability")]
    Loss(f64),
    /// Censors were configured without victims, or victims without censors.
    #[error("censorship requires both censors and victims")]
    IncompleteCensorship,
    /// A censor is not a participant.
    #[error("censor {0} is not a participant")]
    UnknownCensor(u64),
    /// A victim is not a producer.
    #[error("victim {0} is not a producer")]
    UnknownVictim(u64),
    /// A victim produces a chain the censoring policy cannot name.
    #[error("victim {0} produces chain {1}, but only chains below 128 can be censored")]
    VictimChain(u64, usize),
    /// A censor runs a proposal policy other than the endorsed one, which censorship extends.
    #[error("censors must run the endorsed proposal policy")]
    CensorPolicy,
}

/// A malformed `key@port` or `key@host:port` argument.
#[derive(Debug, Error)]
pub enum AddressError {
    /// The argument has no `@` separator.
    #[error("expected `<key>@<address>`")]
    Format,
    /// The key is not an integer.
    #[error("invalid key: {0}")]
    Key(#[source] ParseIntError),
    /// The port is not a `u16`.
    #[error("invalid port: {0}")]
    Port(#[source] ParseIntError),
    /// The address is not `host:port`.
    #[error("invalid socket address: {0}")]
    Address(#[from] AddrParseError),
}

/// A participant key and the unparsed address that follows its `@`.
struct Keyed<'a> {
    key: u64,
    address: &'a str,
}

impl<'a> Keyed<'a> {
    fn parse(value: &'a str) -> Result<Self, AddressError> {
        let (key, address) = value.split_once('@').ok_or(AddressError::Format)?;
        Ok(Self {
            key: key.parse().map_err(AddressError::Key)?,
            address,
        })
    }
}

/// This node's key and listening port, parsed from `key@port`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Me {
    /// Participant key.
    pub key: u64,
    /// Port to listen on.
    pub port: u16,
}

impl FromStr for Me {
    type Err = AddressError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Keyed { key, address } = Keyed::parse(value)?;
        Ok(Self {
            key,
            port: address.parse().map_err(AddressError::Port)?,
        })
    }
}

/// A peer dialed on startup, parsed from `key@host:port`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bootstrapper {
    /// Participant key.
    pub key: u64,
    /// Address the peer listens on.
    pub address: SocketAddr,
}

impl FromStr for Bootstrapper {
    type Err = AddressError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Keyed { key, address } = Keyed::parse(value)?;
        Ok(Self {
            key,
            address: address.parse()?,
        })
    }
}

/// Consensus, marshal, and production settings shared by local runs, deployment bundles, and
/// deployed nodes.
#[derive(Args, Clone, Debug, Serialize, Deserialize)]
pub struct NodeTuning {
    /// Blocks to include above the certified proposal anchor.
    #[arg(long, value_enum, default_value = "endorsed")]
    #[serde(default)]
    pub proposal_policy: ProposalPolicy,

    /// Parallel verification threads.
    #[arg(long, default_value_t = COMPUTE_THREADS)]
    pub compute_threads: NonZeroUsize,

    /// View-critical cryptography threads.
    ///
    /// Defaults to the committee-derived width, which scales with the validator count.
    #[arg(long)]
    #[serde(default)]
    pub critical_threads: Option<NonZeroUsize>,

    /// Bytes of junk data placed in every producer block body.
    #[arg(long, default_value_t = BODY_SIZE)]
    pub body_size: usize,

    /// Pipeline depth: maximum blocks a producer chain holds above its DA-certified anchor.
    ///
    /// It also caps the blocks one proposal appends per chain (see
    /// `commonware_consensus::multimmit::types::PathLimits`). This is a time window in blocks: it
    /// must cover the DA-certificate lag at the configured block rate, so smaller bodies at the same
    /// byte throughput need proportionally larger values.
    #[arg(long, default_value_t = PIPELINE_DEPTH)]
    #[serde(default = "default_pipeline_depth")]
    pub pipeline_depth: u32,

    /// Maximum blocks carried by one vote extension per chain; zero disables extensions.
    ///
    /// Like the pipeline depth, this must cover the DA-certificate lag at the configured block
    /// rate.
    #[arg(long, default_value_t = EXTENSION_BOUND)]
    #[serde(default = "default_extension_bound")]
    pub extension_bound: u32,

    /// Blocks a producer builds, and a validator DA-votes, above the certified anchor.
    ///
    /// Defaults to the pipeline depth, or one with zero depth, and may only widen it. With zero
    /// depth it must cover the DA-certificate lag at the configured block rate.
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipeline_window: Option<NonZeroU32>,

    /// Minimum milliseconds between two blocks built by one producer.
    ///
    /// Zero builds as fast as block custody admits.
    #[arg(long, default_value_t = 0)]
    #[serde(default)]
    pub production_interval_ms: u64,

    /// Independent payload arrival rate per producer; omitted means saturated input.
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered_bytes_per_second: Option<NonZeroU64>,

    /// Memory marshal sizes its budgets within: bodies held ahead of delivery, fetches in
    /// flight, staged blocks and the record backlog share what delivery, serving and journal
    /// buffers leave.
    #[arg(long, default_value_t = MARSHAL_MEMORY_BYTES)]
    pub marshal_memory_bytes: NonZeroUsize,
}

impl NodeTuning {
    /// Returns the configured pipeline limits.
    ///
    /// # Errors
    ///
    /// Returns an error when the pipeline window is narrower than the depth allows.
    pub const fn limits(&self) -> Result<PathLimits, CodecConfigError> {
        let limits = PathLimits::new(self.pipeline_depth, self.extension_bound);
        match self.pipeline_window {
            Some(window) => limits.with_pipeline_window(window.get()),
            None => Ok(limits),
        }
    }

    /// Returns the minimum time between two blocks built by one producer.
    pub const fn production_interval(&self) -> Duration {
        Duration::from_millis(self.production_interval_ms)
    }

    /// Checks settings that the command line cannot express.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if u32::try_from(self.body_size).is_err() {
            return Err(ConfigError::BodyTooLarge(self.body_size));
        }
        self.limits().map_err(ConfigError::PipelineWindow)?;
        if self.offered_bytes_per_second.is_some() {
            self.require_body()?;
        }
        Ok(())
    }

    /// Checks that blocks carry payload, which input pacing needs to count bytes.
    const fn require_body(&self) -> Result<(), EmptyBody> {
        if self.body_size == 0 {
            return Err(EmptyBody);
        }
        Ok(())
    }
}

/// Checks that participants are unique and that producers are unique participants.
pub fn validate_committee(participants: &[u64], producers: &[u64]) -> Result<(), ConfigError> {
    if participants.is_empty() {
        return Err(ConfigError::NoParticipants);
    }
    let mut members = BTreeSet::new();
    for participant in participants {
        if !members.insert(participant) {
            return Err(ConfigError::DuplicateParticipant(*participant));
        }
    }
    let mut seen = BTreeSet::new();
    for producer in producers {
        if !members.contains(producer) {
            return Err(ConfigError::UnknownProducer(*producer));
        }
        if !seen.insert(producer) {
            return Err(ConfigError::DuplicateProducer(*producer));
        }
    }
    Ok(())
}

/// Returns `producers`, or every participant when none are listed.
fn producers_or_all(participants: &[u64], producers: Vec<u64>) -> Vec<u64> {
    if producers.is_empty() {
        participants.to_vec()
    } else {
        producers
    }
}

/// Command-line arguments for running a node.
#[derive(Args)]
pub struct RunArgs {
    /// Peers to dial on startup, as `key@host:port`.
    #[arg(long, value_delimiter = ',')]
    bootstrappers: Vec<Bootstrapper>,

    /// This node's key and port, as `key@port`.
    #[arg(long, required_unless_present = "config")]
    me: Option<Me>,

    /// Participant keys in committee order.
    ///
    /// Keys are labels: every node derives committee material from each key's position in
    /// this list, so the values only need to be unique.
    #[arg(
        long,
        value_delimiter = ',',
        num_args = 1..,
        required_unless_present = "config"
    )]
    participants: Vec<u64>,

    /// Producer keys in chain order. Defaults to every participant.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    producers: Vec<u64>,

    /// Directory for all persisted consensus state.
    #[arg(long, required_unless_present = "config")]
    storage_dir: Option<PathBuf>,

    /// Deployer-generated host inventory.
    #[arg(long, requires = "config")]
    hosts: Option<PathBuf>,

    /// Deployer-generated node configuration.
    #[arg(long, requires = "hosts")]
    config: Option<PathBuf>,

    /// Tokio worker threads.
    #[arg(long, default_value_t = LOCAL_WORKER_THREADS)]
    worker_threads: NonZeroUsize,

    #[command(flatten)]
    tuning: NodeTuning,

    /// Run without the terminal UI and emit structured logs.
    #[arg(long)]
    headless: bool,

    /// OTLP HTTP endpoint that receives every trace. Does not enable metrics.
    #[arg(long, requires = "headless", conflicts_with = "config")]
    trace_endpoint: Option<String>,

    /// File that receives the terminal UI's debug tracing events as JSON lines.
    #[arg(long, conflicts_with_all = ["headless", "config"])]
    trace_file: Option<PathBuf>,

    /// Include debug diagnostics in headless logs.
    #[arg(long, requires = "headless")]
    debug: bool,
}

/// This node's key, port, and storage.
pub struct Identity {
    /// Participant key.
    pub key: u64,
    /// Port to listen on.
    pub port: u16,
    /// Directory for all persisted consensus state.
    pub storage_dir: PathBuf,
}

/// Committee membership and peer addresses.
pub struct Network {
    /// Participant keys in committee order.
    pub participants: Vec<u64>,
    /// Producer keys in chain order.
    pub producers: Vec<u64>,
    /// Peers to dial on startup.
    pub bootstrappers: Vec<Bootstrapper>,
    /// Address to listen on.
    pub listen_ip: IpAddr,
    /// Address peers dial.
    pub public_ip: IpAddr,
}

/// Where traces are exported.
pub struct TraceConfig {
    /// OTLP HTTP endpoint.
    pub endpoint: String,
    /// Fraction of traces exported.
    pub rate: Probability,
}

/// Headless logging, metrics, and trace export.
pub struct Telemetry {
    /// Minimum level of emitted log events.
    pub log_level: Level,
    /// Address that serves metrics, if any.
    pub metrics: Option<SocketAddr>,
    /// Trace export, if any.
    pub traces: Option<TraceConfig>,
}

/// How a node reports its progress.
pub enum Output {
    /// Structured JSON logs with optional metrics and trace export.
    Headless(Telemetry),
    /// The terminal UI; debug tracing events go to `trace_file` when set.
    Terminal { trace_file: Option<PathBuf> },
}

/// Everything a node needs to run.
pub struct RunConfig {
    /// This node's key, port, and storage.
    pub identity: Identity,
    /// Committee membership and peer addresses.
    pub network: Network,
    /// Tokio worker threads.
    pub worker_threads: NonZeroUsize,
    /// Consensus, marshal, and production settings.
    pub tuning: NodeTuning,
    /// Benchmark repetition, when a driver configured one.
    pub benchmark: Option<bench::Config>,
    /// How the node reports progress.
    pub output: Output,
}

impl RunConfig {
    /// Loads a deployed node's configuration when `--config` is set, or the command line
    /// otherwise.
    pub fn load(args: RunArgs) -> Self {
        match (&args.config, &args.hosts) {
            (Some(config), Some(hosts)) => Self::load_remote(config, hosts),
            _ => Self::load_local(args),
        }
    }

    fn load_local(args: RunArgs) -> Self {
        let me = args.me.expect("clap requires --me without --config");
        let telemetry = Telemetry {
            log_level: if args.debug {
                Level::DEBUG
            } else {
                Level::INFO
            },
            metrics: None,
            traces: args.trace_endpoint.map(|endpoint| TraceConfig {
                endpoint,
                rate: LOCAL_TRACE_SAMPLING,
            }),
        };
        Self {
            identity: Identity {
                key: me.key,
                port: me.port,
                storage_dir: args
                    .storage_dir
                    .expect("clap requires --storage-dir without --config"),
            },
            network: Network {
                producers: producers_or_all(&args.participants, args.producers),
                participants: args.participants,
                bootstrappers: args.bootstrappers,
                listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                public_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            },
            worker_threads: args.worker_threads,
            tuning: args.tuning,
            benchmark: None,
            output: if args.headless {
                Output::Headless(telemetry)
            } else {
                Output::Terminal {
                    trace_file: args.trace_file,
                }
            },
        }
    }

    /// Loads a deployed node's configuration and resolves peers through the host inventory.
    pub fn load_remote(config: &Path, hosts: &Path) -> Self {
        let raw = fs::read_to_string(config).expect("failed to read node config");
        let config: NodeConfig = serde_yaml::from_str(&raw).expect("invalid node config");
        let raw = fs::read_to_string(hosts).expect("failed to read hosts config");
        let hosts: Hosts = serde_yaml::from_str(&raw).expect("invalid hosts config");
        let host_ip = |key: u64| {
            hosts
                .hosts
                .iter()
                .find(|host| host.name == key.to_string())
                .map(|host| host.ip)
        };
        let public_ip = host_ip(config.key).expect("node missing from hosts config");
        let bootstrappers = config
            .bootstrappers
            .iter()
            .filter(|key| **key != config.key)
            .map(|key| Bootstrapper {
                key: *key,
                address: SocketAddr::new(
                    host_ip(*key).expect("bootstrapper missing from hosts config"),
                    config.port,
                ),
            })
            .collect();
        let rate =
            Probability::try_from(config.trace_sampling).expect("trace sampling is a probability");
        let traces = (!rate.is_zero()).then(|| TraceConfig {
            endpoint: format!(
                "http://{}:{TRACES_PORT}/v1/traces",
                hosts.monitoring.private
            ),
            rate,
        });
        Self {
            identity: Identity {
                key: config.key,
                port: config.port,
                storage_dir: config.storage_dir,
            },
            network: Network {
                producers: producers_or_all(&config.participants, config.producers),
                participants: config.participants,
                bootstrappers,
                listen_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                public_ip,
            },
            worker_threads: config.worker_threads,
            tuning: config.tuning,
            benchmark: config.benchmark,
            output: Output::Headless(Telemetry {
                log_level: Level::INFO,
                metrics: Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    METRICS_PORT,
                )),
                traces,
            }),
        }
    }

    /// Checks the whole configuration before any service starts.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.tuning.validate()?;
        let participants = &self.network.participants;
        validate_committee(participants, &self.network.producers)?;
        if !participants.contains(&self.identity.key) {
            return Err(ConfigError::UnknownIdentity(self.identity.key));
        }
        if let Some(bootstrapper) = self
            .network
            .bootstrappers
            .iter()
            .find(|bootstrapper| !participants.contains(&bootstrapper.key))
        {
            return Err(ConfigError::UnknownBootstrapper(bootstrapper.key));
        }
        if let Some(benchmark) = &self.benchmark {
            if !matches!(self.output, Output::Headless(_)) {
                return Err(ConfigError::BenchmarkRequiresHeadless);
            }
            if self.tuning.offered_bytes_per_second.is_some() {
                return Err(ConfigError::ScheduleWithOfferedRate);
            }
            self.tuning.require_body()?;
            benchmark.schedule.validate()?;
            self.validate_faults(&benchmark.faults)?;
        }
        Ok(())
    }

    /// Checks the faults a benchmark injects against the committee.
    fn validate_faults(&self, faults: &bench::Faults) -> Result<(), ConfigError> {
        if Probability::from_f64(faults.loss).is_none() {
            return Err(ConfigError::Loss(faults.loss));
        }
        if faults.censors.is_empty() != faults.victims.is_empty() {
            return Err(ConfigError::IncompleteCensorship);
        }
        if let Some(censor) = faults
            .censors
            .iter()
            .find(|censor| !self.network.participants.contains(censor))
        {
            return Err(ConfigError::UnknownCensor(*censor));
        }
        for victim in &faults.victims {
            let chain = self
                .network
                .producers
                .iter()
                .position(|producer| producer == victim)
                .ok_or(ConfigError::UnknownVictim(*victim))?;
            if chain >= Victims::CAPACITY {
                return Err(ConfigError::VictimChain(*victim, chain));
            }
        }
        if faults.censors.contains(&self.identity.key)
            && !matches!(self.tuning.proposal_policy, ProposalPolicy::Endorsed)
        {
            return Err(ConfigError::CensorPolicy);
        }
        Ok(())
    }

    /// Returns the probability that this node drops each message it receives.
    ///
    /// # Panics
    ///
    /// Panics unless [`Self::validate`] succeeded.
    pub fn loss(&self) -> Probability {
        self.benchmark
            .as_ref()
            .map_or(probability!(0, 1), |benchmark| {
                Probability::from_f64(benchmark.faults.loss).expect("validated loss rate")
            })
    }

    /// Returns the proposal policy this node runs: the configured one, or censorship of the
    /// benchmark's victims when this node is one of its censors.
    ///
    /// # Panics
    ///
    /// Panics unless [`Self::validate`] succeeded.
    pub fn proposal_policy(&self) -> multimmit::config::ProposalPolicy {
        let Some(faults) = self
            .benchmark
            .as_ref()
            .map(|benchmark| &benchmark.faults)
            .filter(|faults| faults.censors.contains(&self.identity.key))
        else {
            return self.tuning.proposal_policy.into();
        };
        let chains = faults.victims.iter().map(|victim| {
            let chain = self
                .network
                .producers
                .iter()
                .position(|producer| producer == victim)
                .expect("validated victim is a producer");
            ChainId::new(u32::try_from(chain).expect("validated victim chain fits u32"))
        });
        multimmit::config::ProposalPolicy::Censor(
            Victims::new(chains).expect("validated victim chains are below the capacity"),
        )
    }

    /// Returns this node's position in the committee.
    ///
    /// # Panics
    ///
    /// Panics unless [`Self::validate`] succeeded.
    pub fn index(&self) -> usize {
        self.network
            .participants
            .iter()
            .position(|participant| *participant == self.identity.key)
            .expect("validated identity is a participant")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        run: RunArgs,
    }

    const LOCAL: [&str; 7] = [
        "log-multimmit",
        "--me",
        "0@3000",
        "--participants",
        "0,1,2",
        "--storage-dir",
        "unused",
    ];

    fn parse<'a>(extra: impl IntoIterator<Item = &'a str>) -> Result<RunConfig, clap::Error> {
        Cli::try_parse_from(LOCAL.into_iter().chain(extra)).map(|cli| RunConfig::load(cli.run))
    }

    fn telemetry(config: &RunConfig) -> &Telemetry {
        match &config.output {
            Output::Headless(telemetry) => telemetry,
            Output::Terminal { .. } => panic!("expected headless output"),
        }
    }

    #[test]
    fn local_trace_endpoint_is_opt_in() {
        let default = parse(["--headless"]).unwrap();
        assert!(telemetry(&default).traces.is_none());
        assert!(telemetry(&default).metrics.is_none());
        let explicit = parse([
            "--headless",
            "--trace-endpoint",
            "http://localhost:4318/v1/traces",
        ])
        .unwrap();
        let traces = telemetry(&explicit).traces.as_ref().unwrap();
        assert_eq!(traces.endpoint, "http://localhost:4318/v1/traces");
        assert!(traces.rate.is_one());
        assert!(telemetry(&explicit).metrics.is_none());
        assert!(parse(["--trace-endpoint", "http://localhost:4318/v1/traces"]).is_err());
        assert!(
            Cli::try_parse_from([
                "log-multimmit",
                "--config",
                "node.yaml",
                "--hosts",
                "hosts.yaml",
                "--headless",
                "--trace-endpoint",
                "value",
            ])
            .is_err()
        );
    }

    #[test]
    fn trace_file_is_terminal_only() {
        let config = parse(["--trace-file", "trace.json"]).unwrap();
        assert!(matches!(
            config.output,
            Output::Terminal { trace_file: Some(ref path) } if path == Path::new("trace.json")
        ));
        assert!(matches!(
            parse([]).unwrap().output,
            Output::Terminal { trace_file: None }
        ));
        assert!(parse(["--headless", "--trace-file", "trace.json"]).is_err());
    }

    #[test]
    fn local_offered_load_is_optional_and_nonzero() {
        let default = parse([]).unwrap();
        assert_eq!(default.tuning.offered_bytes_per_second, None);
        let explicit = parse(["--offered-bytes-per-second", "5120000"]).unwrap();
        assert_eq!(
            explicit.tuning.offered_bytes_per_second,
            NonZeroU64::new(5_120_000)
        );
        assert_eq!(explicit.tuning.production_interval(), Duration::ZERO);
        assert!(parse(["--offered-bytes-per-second", "0"]).is_err());
    }

    #[test]
    fn local_runs_require_identity_participants_and_storage() {
        for missing in ["--me", "--participants", "--storage-dir"] {
            let position = LOCAL.iter().position(|arg| *arg == missing).unwrap();
            let args = LOCAL
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != position && *index != position + 1)
                .map(|(_, arg)| *arg);
            assert!(Cli::try_parse_from(args).is_err(), "{missing} is required");
        }
        assert!(
            Cli::try_parse_from([
                "log-multimmit",
                "--config",
                "node.yaml",
                "--hosts",
                "hosts.yaml",
            ])
            .is_ok()
        );
    }

    #[test]
    fn addresses_parse_into_typed_values() {
        assert_eq!("7@3000".parse::<Me>().unwrap(), Me { key: 7, port: 3000 });
        assert_eq!(
            "7@127.0.0.1:3000".parse::<Bootstrapper>().unwrap(),
            Bootstrapper {
                key: 7,
                address: "127.0.0.1:3000".parse().unwrap(),
            }
        );
        assert!(matches!("3000".parse::<Me>(), Err(AddressError::Format)));
        assert!(matches!("x@3000".parse::<Me>(), Err(AddressError::Key(_))));
        assert!(matches!(
            "7@70000".parse::<Me>(),
            Err(AddressError::Port(_))
        ));
        assert!(matches!(
            "7@localhost".parse::<Bootstrapper>(),
            Err(AddressError::Address(_))
        ));
        assert!(parse(["--bootstrappers", "1@127.0.0.1"]).is_err());
    }

    #[test]
    fn producers_default_to_every_participant() {
        assert_eq!(parse([]).unwrap().network.producers, [0, 1, 2]);
        assert_eq!(
            parse(["--producers", "2,0"]).unwrap().network.producers,
            [2, 0]
        );
    }

    #[test]
    fn validation_rejects_inconsistent_committees() {
        assert!(parse([]).unwrap().validate().is_ok());
        let error = |extra: &[&str]| {
            parse(extra.iter().copied())
                .unwrap()
                .validate()
                .unwrap_err()
        };
        assert!(matches!(
            error(&["--producers", "1,1"]),
            ConfigError::DuplicateProducer(1)
        ));
        assert!(matches!(
            error(&["--producers", "3"]),
            ConfigError::UnknownProducer(3)
        ));
        assert!(matches!(
            error(&["--bootstrappers", "9@127.0.0.1:3001"]),
            ConfigError::UnknownBootstrapper(9)
        ));
        let mut config = parse([]).unwrap();
        config.identity.key = 5;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnknownIdentity(5))
        ));
        config.identity.key = 0;
        config.network.participants = vec![0, 1, 1];
        assert!(matches!(
            config.validate(),
            Err(ConfigError::DuplicateParticipant(1))
        ));
        config.network.participants.clear();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::NoParticipants)
        ));
    }

    #[test]
    fn validation_checks_benchmarks() {
        let benchmark = |phases: &str| bench::Config {
            committee_seed: 1,
            schedule: serde_yaml::from_str(&format!("start_unix_ms: 0\nphases: {phases}")).unwrap(),
            faults: bench::Faults::default(),
        };
        let phase = "[{duration_ms: 1000, bytes_per_second: 1000}]";
        let mut config = parse(["--headless"]).unwrap();
        config.benchmark = Some(benchmark(phase));
        assert!(config.validate().is_ok());
        config.benchmark = Some(benchmark("[]"));
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Schedule(ScheduleError::NoPhases))
        ));

        let mut config = parse(["--headless", "--offered-bytes-per-second", "1"]).unwrap();
        config.benchmark = Some(benchmark(phase));
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ScheduleWithOfferedRate)
        ));

        let mut config = parse([]).unwrap();
        config.benchmark = Some(benchmark(phase));
        assert!(matches!(
            config.validate(),
            Err(ConfigError::BenchmarkRequiresHeadless)
        ));
    }

    #[test]
    fn faults_default_to_none_and_parse_from_the_benchmark() {
        let schedule = "start_unix_ms: 0\nphases: [{duration_ms: 1000, bytes_per_second: 1000}]";
        let benchmark: bench::Config = serde_yaml::from_str(&format!(
            "committee_seed: 1\nschedule:\n  {}",
            schedule.replace('\n', "\n  ")
        ))
        .unwrap();
        assert_eq!(benchmark.faults, bench::Faults::default());
        let benchmark: bench::Config = serde_yaml::from_str(&format!(
            "committee_seed: 1\nschedule:\n  {}\nfaults: {{loss: 0.001, censors: [0], victims: [1, 2]}}",
            schedule.replace('\n', "\n  ")
        ))
        .unwrap();
        assert_eq!(
            benchmark.faults,
            bench::Faults {
                loss: 0.001,
                censors: vec![0],
                victims: vec![1, 2],
            }
        );
        // Misspelled faults must not silently disable injection.
        assert!(serde_yaml::from_str::<bench::Faults>("{lose: 0.001}").is_err());
        assert!(
            serde_yaml::from_str::<bench::Config>(&format!(
                "committee_seed: 1\nschedule:\n  {}\nfault: {{loss: 0.001}}",
                schedule.replace('\n', "\n  ")
            ))
            .is_err()
        );
    }

    #[test]
    fn validation_checks_faults() {
        let configure = |extra: &[&str], faults: bench::Faults| {
            let mut config = parse(["--headless"].iter().chain(extra).copied()).unwrap();
            config.benchmark = Some(bench::Config {
                committee_seed: 1,
                schedule: serde_yaml::from_str(
                    "start_unix_ms: 0\nphases: [{duration_ms: 1000, bytes_per_second: 1000}]",
                )
                .unwrap(),
                faults,
            });
            config
        };

        // Without faults, nothing is lost and the configured policy runs.
        let config = configure(&[], bench::Faults::default());
        assert!(config.validate().is_ok());
        assert!(config.loss().is_zero());
        assert_eq!(
            config.proposal_policy(),
            multimmit::config::ProposalPolicy::Endorsed
        );

        let lossy = configure(
            &[],
            bench::Faults {
                loss: 0.001,
                ..Default::default()
            },
        );
        assert!(lossy.validate().is_ok());
        assert_eq!(lossy.loss().as_f64(), 0.001);
        for loss in [-0.1, 1.5, f64::NAN] {
            let config = configure(
                &[],
                bench::Faults {
                    loss,
                    ..Default::default()
                },
            );
            assert!(matches!(config.validate(), Err(ConfigError::Loss(_))));
        }

        // A censor censors its victims' chains, which are their positions among the producers.
        let censorship = |censors: Vec<u64>, victims: Vec<u64>| bench::Faults {
            censors,
            victims,
            ..Default::default()
        };
        let censor = configure(&["--producers", "2,1"], censorship(vec![0, 1], vec![1]));
        assert!(censor.validate().is_ok());
        assert_eq!(
            censor.proposal_policy(),
            multimmit::config::ProposalPolicy::Censor(Victims::new([ChainId::new(1)]).unwrap())
        );
        // A node that is not a censor runs the configured policy.
        let bystander = configure(&["--producers", "2,1"], censorship(vec![1], vec![1]));
        assert!(bystander.validate().is_ok());
        assert_eq!(
            bystander.proposal_policy(),
            multimmit::config::ProposalPolicy::Endorsed
        );

        for (extra, faults, expected) in [
            (&[][..], censorship(vec![0], vec![]), "incomplete"),
            (&[][..], censorship(vec![], vec![1]), "incomplete"),
            (&[][..], censorship(vec![3], vec![1]), "censor"),
            (
                &["--producers", "1"][..],
                censorship(vec![0], vec![2]),
                "victim",
            ),
            (
                &["--proposal-policy", "certified"][..],
                censorship(vec![0], vec![1]),
                "policy",
            ),
        ] {
            let result = configure(extra, faults).validate();
            assert!(
                matches!(
                    (&result, expected),
                    (Err(ConfigError::IncompleteCensorship), "incomplete")
                        | (Err(ConfigError::UnknownCensor(3)), "censor")
                        | (Err(ConfigError::UnknownVictim(2)), "victim")
                        | (Err(ConfigError::CensorPolicy), "policy")
                ),
                "{expected}: {result:?}"
            );
        }
    }

    #[test]
    fn validation_requires_bodies_for_input_pacing() {
        assert!(parse(["--body-size", "0"]).unwrap().validate().is_ok());
        assert!(matches!(
            parse(["--body-size", "0", "--offered-bytes-per-second", "1"])
                .unwrap()
                .validate(),
            Err(ConfigError::EmptyBody(EmptyBody))
        ));
        let mut config = parse(["--headless", "--body-size", "0"]).unwrap();
        config.benchmark = Some(bench::Config {
            committee_seed: 1,
            schedule: serde_yaml::from_str(
                "start_unix_ms: 0\nphases: [{duration_ms: 1000, bytes_per_second: 1000}]",
            )
            .unwrap(),
            faults: bench::Faults::default(),
        });
        assert!(matches!(
            config.validate(),
            Err(ConfigError::EmptyBody(EmptyBody))
        ));
    }

    #[test]
    fn validation_bounds_the_body_size() {
        let size = (u64::from(u32::MAX) + 1).to_string();
        assert!(matches!(
            parse(["--body-size", &size]).unwrap().validate(),
            Err(ConfigError::BodyTooLarge(_))
        ));
    }
}
