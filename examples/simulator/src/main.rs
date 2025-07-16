use std::collections::HashMap;

use bytes::Bytes;
use clap::{value_parser, Arg, Command};
use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
use commonware_p2p::{
    simulated::{Config, Link, Network},
    Receiver, Sender,
};
use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
use futures::future::try_join_all;
use reqwest::blocking::Client;
use serde_json;
use tracing::info;

const DEFAULT_CHANNEL: u32 = 0;
const DEFAULT_SUCCESS_RATE: f64 = 1.0;

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

    populate_latency_map(p50, p90)
}

fn load_latency_data() -> LatencyMap {
    let p50 = include_str!("p50.json");
    let p90 = include_str!("p90.json");
    let p50: ApiResp = serde_json::from_str(p50).unwrap();
    let p90: ApiResp = serde_json::from_str(p90).unwrap();

    populate_latency_map(p50, p90)
}

fn populate_latency_map(p50: ApiResp, p90: ApiResp) -> LatencyMap {
    let mut map = HashMap::new();
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
        .arg(
            Arg::new("reload-latency-data")
                .long("reload-latency-data")
                .required(false)
                .num_args(0)
                .help("Reload latency data from cloudping.co"),
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
    let latency_map = if matches.get_flag("reload-latency-data") {
        info!("downloading latency data");
        download_latency_data()
    } else {
        info!("loading latency data");
        load_latency_data()
    };

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
        for (i, (identity, region, _, _)) in identities.iter().enumerate() {
            for (j, (other_identity, other_region, _, _)) in identities.iter().enumerate() {
                // Skip self
                if i == j {
                    continue;
                }

                // Add link
                let latency = latency_map[region][other_region];
                let link = Link {
                    latency: latency.0,
                    jitter: latency.1,
                    success_rate: DEFAULT_SUCCESS_RATE,
                };
                oracle
                    .add_link(identity.clone(), other_identity.clone(), link)
                    .await
                    .unwrap();
            }
        }

        // For each peer, see how long it takes to send a message (and hear back from all other peers)
        let mut jobs = Vec::new();
        for (i, (identity, region, sender, receiver)) in identities.iter().enumerate() {
            let mut job = context.with_label("job");
            jobs.push(job.spawn(move |ctx| async move {
                let start = ctx.current();

                for (j, (other_identity, other_region, other_sender, other_receiver)) in
                    identities.iter().enumerate()
                {
                    if i == j {
                        continue;
                    }

                    // Send message
                    sender
                        .send(
                            commonware_p2p::Recipients::One(other_identity.clone()),
                            Bytes::from("Hello, world!"),
                            true,
                        )
                        .await
                        .unwrap();
                }

                // Loop until all messages are received
                while let Ok((other_identity, message)) = receiver.recv().await {
                    info!(?other_identity, "message received");
                }
            }));
        }

        // Wait for all jobs to complete
        try_join_all(jobs).await.unwrap();
    });
}
