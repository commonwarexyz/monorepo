use clap::{value_parser, Arg, Command};
use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
use commonware_p2p::simulated::{Config, Network};
use commonware_runtime::{deterministic, Metrics, Runner};

const DEFAULT_CHANNEL: u32 = 0;

/// Returns the version of the crate.
pub fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn main() {
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
            identities.push((identity, region, sender, receiver));
        }
    });
}
