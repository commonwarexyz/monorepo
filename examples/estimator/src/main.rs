use clap::{value_parser, Arg, Command};
use colored::Colorize;
use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
use commonware_macros::select;
use commonware_p2p::{
    simulated::{Config, Link, Network, Receiver, Sender},
    utils::codec::{wrap, WrappedReceiver, WrappedSender},
};
use commonware_runtime::{deterministic, Clock, Metrics, Network as RNetwork, Runner, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    future::try_join_all,
    SinkExt, StreamExt,
};
use rand::RngCore;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime},
};
use tracing::debug;

// Import from our library
use estimator::{
    crate_version, download_latency_data, load_latency_data, mean, median, parse_task, std_dev,
    LatencyMap, SimCommand, Threshold,
};

const DEFAULT_CHANNEL: u32 = 0;
const DEFAULT_SUCCESS_RATE: f64 = 1.0;

// Type aliases for better readability
type RegionCounts = Vec<(String, usize)>;
type WaitLatencies = BTreeMap<usize, BTreeMap<String, Vec<f64>>>;
type LeaderLatencies = BTreeMap<usize, f64>;
type PeerIdentity = (
    ed25519::PublicKey,
    String,
    WrappedSender<Sender<ed25519::PublicKey>, u32>,
    WrappedReceiver<Receiver<ed25519::PublicKey>, u32>,
);
type PeerJobHandle = commonware_runtime::Handle<(
    String,
    Vec<(usize, Duration)>,
    Option<Vec<(usize, Duration)>>,
)>;

/// Context data for a peer in the simulation
struct PeerContext {
    peer_idx: usize,
    leader_idx: usize,
    peers: usize,
    identity: ed25519::PublicKey,
    region: String,
    dsl: Vec<(usize, SimCommand)>,
}

/// Results from a single simulation run
#[derive(Clone)]
struct SimulationResult {
    leader_idx: usize,
    leader_region: String,
    wait_latencies: WaitLatencies,
    leader_latencies: LeaderLatencies,
}

/// Command line arguments parsed from user input
struct Arguments {
    region_counts: RegionCounts,
    task_content: String,
    reload_latency_data: bool,
}

fn main() {
    setup_logging();

    let args = parse_arguments();
    let peers = calculate_total_peers(&args.region_counts);
    let dsl = parse_task(&args.task_content);

    debug!(peers, ?args.region_counts, "Initializing simulator");

    let latency_map = get_latency_data(args.reload_latency_data);
    let simulation_results = run_all_simulations(
        peers,
        &args.region_counts,
        &dsl,
        &latency_map,
        &args.task_content,
    );

    print_aggregated_results(&simulation_results, &args.task_content);
}

/// Initialize logging with debug level
fn setup_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
}

/// Parse command line arguments and return structured data
fn parse_arguments() -> Arguments {
    let matches = Command::new("commonware-simulator")
        .about("TBA")
        .version(crate_version())
        .arg(
            Arg::new("regions")
                .long("regions")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(String))
                .help("Regions to simulate in the form <region>:<count>, e.g. us-east-1:3,eu-west-1:2"),
        )
        .arg(
            Arg::new("reload-latency-data")
                .long("reload-latency-data")
                .required(false)
                .num_args(0)
                .help("Reload latency data from cloudping.co"),
        )
        .arg(
            Arg::new("task")
                .long("task")
                .required(true)
                .value_parser(value_parser!(String))
                .help("Path to DSL file defining the simulation behavior"),
        )
        .get_matches();

    let region_counts = matches
        .get_many::<String>("regions")
        .unwrap()
        .map(|s| {
            let mut parts = s.split(':');
            let region = parts.next().expect("missing region").to_string();
            let count = parts
                .next()
                .expect("missing count")
                .parse::<usize>()
                .expect("invalid count");
            (region, count)
        })
        .collect::<Vec<_>>();

    let task_path = matches
        .get_one::<String>("task")
        .expect("task file required")
        .clone();

    let task_content = std::fs::read_to_string(&task_path).expect("Failed to read task file");
    let reload_latency_data = matches.get_flag("reload-latency-data");

    Arguments {
        region_counts,
        task_content,
        reload_latency_data,
    }
}

/// Calculate total number of peers across all regions
fn calculate_total_peers(region_counts: &RegionCounts) -> usize {
    let peers: usize = region_counts.iter().map(|(_, count)| *count).sum();
    assert!(peers > 1, "must have at least 2 peers");
    peers
}

/// Get latency data either by downloading or loading from cache
fn get_latency_data(reload: bool) -> LatencyMap {
    if reload {
        debug!("downloading latency data");
        download_latency_data()
    } else {
        debug!("loading latency data");
        load_latency_data()
    }
}

/// Run simulations for all possible leaders and return results
fn run_all_simulations(
    peers: usize,
    region_counts: &RegionCounts,
    dsl: &[(usize, SimCommand)],
    latency_map: &LatencyMap,
    task_content: &str,
) -> Vec<SimulationResult> {
    let leaders: Vec<usize> = (0..peers).collect();
    let mut results = Vec::new();

    for leader_idx in leaders {
        let result = run_single_simulation(leader_idx, region_counts, dsl, latency_map);
        print_simulation_results(&result, task_content);
        results.push(result);
    }

    results
}

/// Run a single simulation with the specified leader
fn run_single_simulation(
    leader_idx: usize,
    region_counts: &RegionCounts,
    dsl: &[(usize, SimCommand)],
    latency_map: &LatencyMap,
) -> SimulationResult {
    let peers = calculate_total_peers(region_counts);
    let runtime_cfg = deterministic::Config::default().with_seed(leader_idx as u64);
    let executor = deterministic::Runner::new(runtime_cfg);

    let (wait_latencies, leader_latencies) = executor.start({
        let dsl_clone = dsl.to_vec();
        let latency_map_clone = latency_map.clone();
        let region_counts_clone = region_counts.to_vec();

        async move |context| {
            run_simulation_logic(
                context,
                leader_idx,
                peers,
                &region_counts_clone,
                &dsl_clone,
                &latency_map_clone,
            )
            .await
        }
    });

    let leader_region = calculate_leader_region(leader_idx, region_counts);

    SimulationResult {
        leader_idx,
        leader_region,
        wait_latencies,
        leader_latencies,
    }
}

/// Calculate which region a leader belongs to based on their index
fn calculate_leader_region(leader_idx: usize, region_counts: &RegionCounts) -> String {
    let mut current = 0;
    for (region, count) in region_counts {
        let start = current;
        current += *count;
        if leader_idx >= start && leader_idx < current {
            return region.clone();
        }
    }
    panic!("Leader index {leader_idx} out of bounds");
}

/// Core simulation logic that runs the network simulation
async fn run_simulation_logic<C: Spawner + Clock + Clone + Metrics + RNetwork + RngCore>(
    context: C,
    leader_idx: usize,
    peers: usize,
    region_counts: &RegionCounts,
    dsl: &[(usize, SimCommand)],
    latency_map: &LatencyMap,
) -> (WaitLatencies, LeaderLatencies) {
    let (network, mut oracle) = Network::new(
        context.with_label("network"),
        Config {
            max_size: usize::MAX,
        },
    );
    network.start();

    let identities = setup_network_identities(&mut oracle, region_counts).await;
    setup_network_links(&mut oracle, &identities, latency_map).await;

    let (tx, mut rx) = mpsc::channel(peers);
    let jobs = spawn_peer_jobs(&context, leader_idx, peers, identities, dsl, tx);

    // Wait for all jobs to indicate they're done
    let responders = collect_job_responses(&mut rx, peers).await;

    // Ensure any messages in the simulator are queued (this is virtual time)
    context.sleep(Duration::from_millis(10_000)).await;

    // Send the shutdown signal to all jobs
    shutdown_jobs(responders);

    let results = try_join_all(jobs).await.unwrap();
    process_simulation_results(results)
}

/// Set up network identities for all peers across regions
async fn setup_network_identities(
    oracle: &mut commonware_p2p::simulated::Oracle<ed25519::PublicKey>,
    region_counts: &RegionCounts,
) -> Vec<PeerIdentity> {
    let peers = calculate_total_peers(region_counts);
    let mut identities = Vec::with_capacity(peers);
    let mut peer_idx = 0;

    for (region, count) in region_counts {
        for _ in 0..*count {
            let identity = ed25519::PrivateKey::from_seed(peer_idx as u64).public_key();
            let (sender, receiver) = oracle
                .register(identity.clone(), DEFAULT_CHANNEL)
                .await
                .unwrap();
            let (sender, receiver) = wrap::<_, _, u32>((), sender, receiver);
            identities.push((identity, region.clone(), sender, receiver));
            peer_idx += 1;
        }
    }

    identities
}

/// Set up network links between all peers with appropriate latencies
async fn setup_network_links(
    oracle: &mut commonware_p2p::simulated::Oracle<ed25519::PublicKey>,
    identities: &[PeerIdentity],
    latency_map: &LatencyMap,
) {
    for (i, (identity, region, _, _)) in identities.iter().enumerate() {
        for (j, (other_identity, other_region, _, _)) in identities.iter().enumerate() {
            if i == j {
                continue;
            }
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
}

/// Spawn jobs for all peers in the simulation
fn spawn_peer_jobs<C: Spawner + Metrics + Clock>(
    context: &C,
    leader_idx: usize,
    peers: usize,
    identities: Vec<PeerIdentity>,
    dsl: &[(usize, SimCommand)],
    tx: mpsc::Sender<oneshot::Sender<()>>,
) -> Vec<PeerJobHandle> {
    let mut jobs = Vec::new();

    for (i, (identity, region, sender, receiver)) in identities.into_iter().enumerate() {
        let tx = tx.clone();
        let job = context.with_label("job");
        let dsl = dsl.to_vec();

        jobs.push(job.spawn(move |ctx| async move {
            let peer_context = PeerContext {
                peer_idx: i,
                leader_idx,
                peers,
                identity,
                region,
                dsl,
            };
            run_peer_logic(ctx, peer_context, sender, receiver, tx).await
        }));
    }

    jobs
}

/// Core logic for a single peer in the simulation
async fn run_peer_logic(
    ctx: impl Spawner + Clock,
    peer_context: PeerContext,
    mut sender: WrappedSender<Sender<ed25519::PublicKey>, u32>,
    mut receiver: WrappedReceiver<Receiver<ed25519::PublicKey>, u32>,
    mut tx: mpsc::Sender<oneshot::Sender<()>>,
) -> (
    String,
    Vec<(usize, Duration)>,
    Option<Vec<(usize, Duration)>>,
) {
    let PeerContext {
        peer_idx,
        leader_idx,
        peers,
        identity,
        region,
        dsl,
    } = peer_context;
    let is_leader = peer_idx == leader_idx;
    let start = ctx.current();
    let mut completions: Vec<(usize, Duration)> = Vec::new();
    let mut current_index = 0;
    let mut received: BTreeMap<u32, BTreeSet<ed25519::PublicKey>> = BTreeMap::new();

    // Main simulation loop
    loop {
        if current_index >= dsl.len() {
            break;
        }

        // Process commands that can be executed immediately
        let mut advanced = true;
        while advanced {
            if current_index >= dsl.len() {
                break;
            }

            advanced = process_command(
                &dsl[current_index],
                &mut current_index,
                is_leader,
                leader_idx,
                peers,
                &identity,
                &mut sender,
                &mut received,
                &ctx,
                start,
                &mut completions,
            )
            .await;
        }

        if current_index >= dsl.len() {
            break;
        }

        // Wait for incoming message
        let (other_identity, message) = receiver.recv().await.unwrap();
        let msg_id = message.unwrap();
        received.entry(msg_id).or_default().insert(other_identity);
    }

    let maybe_leader = if is_leader {
        Some(completions.clone())
    } else {
        None
    };

    // Signal completion and wait for shutdown
    let (shutter, mut listener) = oneshot::channel::<()>();
    tx.send(shutter).await.unwrap();

    // Process remaining messages until shutdown
    loop {
        select! {
            _ = receiver.recv() => {
                // Discard message
            },
            _ = &mut listener => {
                break;
            }
        }
    }

    (region, completions, maybe_leader)
}

/// Process a single command in the DSL
async fn process_command<C: Spawner + Clock>(
    command: &(usize, SimCommand),
    current_index: &mut usize,
    is_leader: bool,
    leader_idx: usize,
    peers: usize,
    identity: &ed25519::PublicKey,
    sender: &mut WrappedSender<Sender<ed25519::PublicKey>, u32>,
    received: &mut BTreeMap<u32, BTreeSet<ed25519::PublicKey>>,
    ctx: &C,
    start: SystemTime,
    completions: &mut Vec<(usize, Duration)>,
) -> bool {
    match &command.1 {
        SimCommand::Propose(id) => {
            if is_leader {
                sender
                    .send(commonware_p2p::Recipients::All, *id, true)
                    .await
                    .unwrap();
                received.entry(*id).or_default().insert(identity.clone());
            }
            *current_index += 1;
            true
        }
        SimCommand::Broadcast(id) => {
            sender
                .send(commonware_p2p::Recipients::All, *id, true)
                .await
                .unwrap();
            received.entry(*id).or_default().insert(identity.clone());
            *current_index += 1;
            true
        }
        SimCommand::Reply(id) => {
            let leader_identity = ed25519::PrivateKey::from_seed(leader_idx as u64).public_key();
            if is_leader {
                received.entry(*id).or_default().insert(identity.clone());
            } else {
                sender
                    .send(commonware_p2p::Recipients::One(leader_identity), *id, true)
                    .await
                    .unwrap();
            }
            *current_index += 1;
            true
        }
        SimCommand::Collect(id, thresh, delay) => {
            if is_leader {
                let count = received.get(id).map_or(0, |s| s.len());
                let required = calculate_threshold(thresh, peers);
                if let Some((message, _)) = delay {
                    ctx.sleep(*message).await;
                }
                if count >= required {
                    let duration = ctx.current().duration_since(start).unwrap();
                    completions.push((command.0, duration));
                    if let Some((_, completion)) = delay {
                        ctx.sleep(*completion).await;
                    }
                    *current_index += 1;
                    true
                } else {
                    false
                }
            } else {
                *current_index += 1;
                true
            }
        }
        SimCommand::Wait(id, thresh, delay) => {
            let count = received.get(id).map_or(0, |s| s.len());
            let required = calculate_threshold(thresh, peers);
            if let Some((message, _)) = delay {
                ctx.sleep(*message).await;
            }
            if count >= required {
                let duration = ctx.current().duration_since(start).unwrap();
                completions.push((command.0, duration));
                if let Some((_, completion)) = delay {
                    ctx.sleep(*completion).await;
                }
                *current_index += 1;
                true
            } else {
                false
            }
        }
    }
}

/// Calculate required count based on threshold
fn calculate_threshold(thresh: &Threshold, peers: usize) -> usize {
    match thresh {
        Threshold::Percent(p) => ((peers as f64) * *p).ceil() as usize,
        Threshold::Count(c) => *c,
    }
}

/// Collect responses from all peer jobs
async fn collect_job_responses(
    rx: &mut mpsc::Receiver<oneshot::Sender<()>>,
    peers: usize,
) -> Vec<oneshot::Sender<()>> {
    let mut responders = Vec::with_capacity(peers);
    for _ in 0..peers {
        responders.push(rx.next().await.unwrap());
    }
    responders
}

/// Send shutdown signal to all jobs
fn shutdown_jobs(responders: Vec<oneshot::Sender<()>>) {
    for responder in responders {
        responder.send(()).unwrap();
    }
}

type SimResult = (
    String,
    Vec<(usize, Duration)>,
    Option<Vec<(usize, Duration)>>,
);

/// Process simulation results and extract wait/leader latencies
fn process_simulation_results(results: Vec<SimResult>) -> (WaitLatencies, LeaderLatencies) {
    let mut leader_latencies: Option<LeaderLatencies> = None;
    let mut wait_latencies: WaitLatencies = BTreeMap::new();

    for (region, completions, maybe_leader) in results {
        for (line, duration) in completions {
            wait_latencies
                .entry(line)
                .or_default()
                .entry(region.clone())
                .or_default()
                .push(duration.as_millis() as f64);
        }
        if let Some(completions) = maybe_leader {
            leader_latencies = Some(
                completions
                    .into_iter()
                    .map(|(line, dur)| (line, dur.as_millis() as f64))
                    .collect(),
            );
        }
    }

    (wait_latencies, leader_latencies.unwrap())
}

/// Print results for a single simulation
fn print_simulation_results(result: &SimulationResult, task_content: &str) {
    println!(
        "{}",
        format!(
            "\nSimulation results for proposer {} ({}):\n",
            result.leader_idx, result.leader_region
        )
        .bold()
        .cyan()
    );

    let dsl_lines: Vec<String> = task_content.lines().map(|s| s.to_string()).collect();
    let mut wait_lines: Vec<usize> = result.wait_latencies.keys().cloned().collect();
    wait_lines.sort();
    let mut wait_idx = 0;

    for (i, line) in dsl_lines.iter().enumerate() {
        println!("{}", line.yellow());
        let line_num = i + 1;
        let is_collect = line.starts_with("collect");

        if wait_idx < wait_lines.len() && wait_lines[wait_idx] == line_num {
            // Print proposer latency if available
            if let Some(proposer_latency) = result.leader_latencies.get(&line_num) {
                let stat_line = format!("    [proposer] Latency: {proposer_latency:.2}ms");
                println!("{}", stat_line.magenta());
            }

            // Print regional statistics for non-collect commands
            if !is_collect {
                print_regional_statistics(&result.wait_latencies, line_num);
            }
            wait_idx += 1;
        }
    }
}

/// Print regional statistics for a specific line
fn print_regional_statistics(wait_latencies: &WaitLatencies, line_num: usize) {
    if let Some(regional) = wait_latencies.get(&line_num) {
        let mut stats: Vec<(String, f64, f64, f64)> = Vec::new();
        for (region, latencies) in regional.iter() {
            let mut lats = latencies.clone();
            let mean_ms = mean(&lats);
            let median_ms = median(&mut lats);
            let std_dev_ms = std_dev(&lats).unwrap_or(0.0);
            stats.push((region.clone(), mean_ms, median_ms, std_dev_ms));
        }
        stats.sort_by(|a, b| a.0.cmp(&b.0));
        for (region, mean_ms, median_ms, std_dev_ms) in stats {
            let stat_line = format!(
                "    [{region}] Mean: {mean_ms:.2}ms (Std Dev: {std_dev_ms:.2}ms) | Median: {median_ms:.2}ms",
            );
            println!("{}", stat_line.cyan());
        }
    }
}

/// Print aggregated results across all simulations
fn print_aggregated_results(results: &[SimulationResult], task_content: &str) {
    let (all_wait_latencies, all_leader_latencies) = aggregate_simulation_results(results);

    println!("\n{}", "-".repeat(80).yellow());
    println!("{}", "\nAveraged simulation results:\n".bold().blue());

    let dsl_lines: Vec<String> = task_content.lines().map(|s| s.to_string()).collect();
    let mut wait_lines: Vec<usize> = all_wait_latencies.keys().cloned().collect();
    wait_lines.sort();
    let mut wait_idx = 0;

    for (i, line) in dsl_lines.iter().enumerate() {
        println!("{}", line.green());
        let line_num = i + 1;
        let is_collect = line.starts_with("collect");

        if wait_idx < wait_lines.len() && wait_lines[wait_idx] == line_num {
            // Print aggregated proposer statistics
            print_aggregated_proposer_statistics(&all_leader_latencies, line_num);

            // Print aggregated regional and overall statistics for non-collect commands
            if !is_collect {
                print_aggregated_regional_statistics(&all_wait_latencies, line_num);
            }
            wait_idx += 1;
        }
    }
}

/// Aggregate results from all simulations
fn aggregate_simulation_results(
    results: &[SimulationResult],
) -> (WaitLatencies, BTreeMap<usize, Vec<f64>>) {
    let mut all_leader_latencies: BTreeMap<usize, Vec<f64>> = BTreeMap::new();
    let mut all_wait_latencies: WaitLatencies = BTreeMap::new();

    // Aggregate leader latencies
    for result in results {
        for (&line, &lat) in result.leader_latencies.iter() {
            all_leader_latencies.entry(line).or_default().push(lat);
        }
    }

    // Aggregate wait latencies
    for result in results {
        for (line, regional) in result.wait_latencies.iter() {
            let all_regional = all_wait_latencies.entry(*line).or_default();
            for (region, lats) in regional.iter() {
                all_regional
                    .entry(region.clone())
                    .or_default()
                    .extend(lats.clone());
            }
        }
    }

    (all_wait_latencies, all_leader_latencies)
}

/// Print aggregated proposer statistics
fn print_aggregated_proposer_statistics(
    all_leader_latencies: &BTreeMap<usize, Vec<f64>>,
    line_num: usize,
) {
    if let Some(lats) = all_leader_latencies.get(&line_num) {
        if !lats.is_empty() {
            let mut lats_sorted = lats.clone();
            let mean_ms = mean(lats);
            let median_ms = median(&mut lats_sorted);
            let std_dev_ms = std_dev(lats).unwrap_or(0.0);
            let stat_line = format!(
                "    [proposer] Mean: {mean_ms:.2}ms (Std Dev: {std_dev_ms:.2}ms) | Median: {median_ms:.2}ms"
            );
            println!("{}", stat_line.magenta());
        }
    }
}

/// Print aggregated regional and overall statistics
fn print_aggregated_regional_statistics(all_wait_latencies: &WaitLatencies, line_num: usize) {
    if let Some(regional) = all_wait_latencies.get(&line_num) {
        let mut stats = Vec::new();
        let mut all_lats: Vec<f64> = Vec::new();

        // Calculate regional statistics
        for (region, latencies) in regional.iter() {
            let mut lats = latencies.clone();
            let mean_ms = mean(&lats);
            let median_ms = median(&mut lats);
            let std_dev_ms = std_dev(&lats).unwrap_or(0.0);
            stats.push((region.clone(), mean_ms, median_ms, std_dev_ms));
            all_lats.extend_from_slice(latencies);
        }

        // Print regional statistics
        stats.sort_by(|a, b| a.0.cmp(&b.0));
        for (region, mean_ms, median_ms, std_dev_ms) in stats {
            let stat_line = format!(
                "    [{region}] Mean: {mean_ms:.2}ms (Std Dev: {std_dev_ms:.2}ms) | Median: {median_ms:.2}ms",
            );
            println!("{}", stat_line.blue());
        }

        // Print overall statistics
        if !all_lats.is_empty() {
            let mut all_lats_sorted = all_lats.clone();
            let overall_mean = mean(&all_lats);
            let overall_median = median(&mut all_lats_sorted);
            let overall_std = std_dev(&all_lats).unwrap_or(0.0);
            let stat_line = format!(
                "    [all] Mean: {overall_mean:.2}ms (Std Dev: {overall_std:.2}ms) | Median: {overall_median:.2}ms"
            );
            println!("{}", stat_line.white());
        }
    }
}
