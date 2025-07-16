use std::collections::HashMap;

use clap::{value_parser, Arg, Command};
use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
use commonware_p2p::simulated::{Config, Network};
use commonware_runtime::{deterministic, Metrics, Runner};
use reqwest::blocking::Client;
use tracing::info;

const DEFAULT_CHANNEL: u32 = 0;

/// Returns the version of the crate.
fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

type Region = String;
type LatJitPair = (f64, f64); // (avg_latency_ms, jitter_ms)
type LatencyMap = HashMap<Region, HashMap<Region, LatJitPair>>;

#[derive(serde::Deserialize)]
struct ApiResp {
    data: HashMap<Region, HashMap<Region, f64>>,
}

const BASE: &str = "https://www.cloudping.co/api/latencies";

fn download_latency_data() -> LatencyMap {
    let cli = Client::builder().build().unwrap();

    // Pull P50 and P90 matrices (time-frame: last 1 year)
    let p50: ApiResp = cli
        .get(format!("{BASE}?percentile=p_50&timeframe=1Y"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let p90: ApiResp = cli
        .get(format!("{BASE}?percentile=p_90&timeframe=1Y"))
        .send()
        .unwrap()
        .json()
        .unwrap();

    // Merge into LatencyMap with jitter = P90 − P50
    let mut map: LatencyMap = HashMap::new();
    for (from, inner_p50) in p50.data {
        let inner_p90 = &p90.data[&from];
        let mut dest_map = HashMap::new();
        for (to, lat50) in inner_p50 {
            if let Some(lat90) = inner_p90.get(&to) {
                dest_map.insert(to.clone(), (lat50, lat90 - lat50));
            }
        }
        map.insert(from, dest_map);
    }

    map
}

fn main() {
    // Create logger
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Parse arguments
    let matches = Command::new("commonware-simulator")
        .about("TBA")
        .version(crate_version())
        .arg(
            Arg::new("peers")
                .long("peers")
                .required(true)
                .value_parser(value_parser!(usize))
                .help("Number of peers to simulate"),
        )
        .arg(
            Arg::new("regions")
                .long("regions")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(String))
                .help("Regions to simulate"),
        )
        .arg(
            Arg::new("message-processing-time")
                .long("message-processing-time")
                .required(true)
                .value_parser(value_parser!(u64))
                .help("Message processing time in milliseconds"),
        )
        .get_matches();
    let peers = *matches.get_one::<usize>("peers").unwrap();
    let regions = matches
        .get_one::<String>("regions")
        .unwrap()
        .split(',')
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    assert!(
        peers >= regions.len(),
        "must have at least as many peers as regions"
    );
    let message_processing_time = *matches.get_one::<u64>("message-processing-time").unwrap();
    info!(
        peers,
        ?regions,
        message_processing_time,
        "Initializing simulator"
    );

    // Download latency data
    let latency_map = download_latency_data();
    info!(?latency_map, "downloaded latency data");

    // Configure deterministic runtime
    let runtime_cfg = deterministic::Config::new();
    let executor = deterministic::Runner::new(runtime_cfg);

    // Start context
    executor.start(async |context| {
        // Initialize simulated p2p network
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            Config {
                max_size: usize::MAX,
            },
        );

        // Start network
        let network_handler = network.start();

        // Generate peers
        let mut identities = Vec::with_capacity(peers);
        for i in 0..peers {
            let identity = ed25519::PrivateKey::from_seed(i as u64).public_key();
            let (sender, receiver) = oracle
                .register(identity.clone(), DEFAULT_CHANNEL)
                .await
                .unwrap();
            let region = regions[i % regions.len()].clone();
            info!(?identity, region, "registered peer");
            identities.push((identity, region, sender, receiver));
        }

        // Create connections between all peers
    });
}
