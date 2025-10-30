//! Simulate mechanism performance under realistic network conditions.

use clap::{value_parser, Arg, Command as ClapCommand};
use colored::Colorize;
use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
use commonware_macros::select;
use commonware_p2p::{
    simulated::{Config, Link, Network, Receiver, Sender},
    utils::codec::{wrap, WrappedReceiver, WrappedSender},
};
use commonware_runtime::{
    deterministic, Clock, Handle, Metrics, Network as RNetwork, Runner, Spawner,
};
use estimator::{
    calculate_proposer_region, calculate_threshold, count_peers, crate_version, get_latency_data,
    mean, median, parse_task, std_dev, Command, Distribution, Latencies, RegionConfig,
};
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

/// The channel to use for all messages
const DEFAULT_CHANNEL: u64 = 0;

/// The success rate over all links (1.0 = 100%)
const DEFAULT_SUCCESS_RATE: f64 = 1.0;

/// The message type
type Message = Vec<u8>;

/// Create a message containing the ID encoded as a big-endian u32,
/// padded to the given size.
fn create_message(id: u32, target_size: Option<usize>) -> Message {
    match target_size {
        Some(size) => {
            let mut message = Vec::with_capacity(size);
            message.extend_from_slice(&id.to_be_bytes());
            if size > 4 {
                message.resize(size, 0);
            }
            message
        }
        None => id.to_be_bytes().to_vec(),
    }
}

/// Extract the ID from a message.
fn extract_id_from_message(message: &Message) -> u32 {
    // Messages are always at least 4 bytes by construction
    u32::from_be_bytes([message[0], message[1], message[2], message[3]])
}

/// All state for a given peer
type PeerIdentity = (
    ed25519::PublicKey,
    String,
    WrappedSender<Sender<ed25519::PublicKey>, Message>,
    WrappedReceiver<Receiver<ed25519::PublicKey>, Message>,
);

/// The result of a peer job execution
type PeerResult = (
    String,
    Vec<(usize, Duration)>,
    Option<Vec<(usize, Duration)>>,
);

/// Context data for command processing
struct CommandContext {
    identity: ed25519::PublicKey,
    proposer_identity: ed25519::PublicKey,
    peers: usize,
    start: SystemTime,
}

/// A map of line numbers to the latencies of all regions for that line
type Observations = BTreeMap<usize, BTreeMap<String, Vec<f64>>>;

/// A map of line numbers to the latencies of all regions for that line
#[derive(Clone)]
struct Steps {
    all: Observations,
    proposer: BTreeMap<usize, f64>,
}

/// Results from a single simulation run
#[derive(Clone)]
struct Simulation {
    proposer_idx: usize,
    proposer_region: String,
    steps: Steps,
}

/// Command line arguments parsed from user input
struct Arguments {
    distribution: Distribution,
    task_content: String,
    reload_latency_data: bool,
}

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Parse command line arguments
    let args = parse_arguments();
    let peers = count_peers(&args.distribution);
    let commands = parse_task(&args.task_content);
    debug!(peers, ?args.distribution, "Initializing simulator");

    // Get latency data
    let latency_map = get_latency_data(args.reload_latency_data);

    // Run simulations
    let simulation_results = run_all_simulations(
        peers,
        &args.distribution,
        &commands,
        &latency_map,
        &args.task_content,
    );
    print_aggregated_results(&simulation_results, &args.task_content);
}

/// Parse command line arguments and return structured data
fn parse_arguments() -> Arguments {
    let matches = ClapCommand::new("commonware-simulator")
        .about("Simulate mechanism performance under realistic network conditions")
        .version(crate_version())
        .arg(
            Arg::new("task")
                .value_parser(value_parser!(String))
                .required(true)
                .help("Path to .lazy file defining the simulation behavior"),
        )
        .arg(
            Arg::new("distribution")
                .long("distribution")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(String))
                .help(
                    "Distribution of peers across regions:\n\
                       <region>:<count> (unlimited bandwidth)\n\
                       <region>:<count>:<egress>/<ingress> (asymmetric)\n\
                       <region>:<count>:<bandwidth> (symmetric)\n\
                     \n\
                     Bandwidth is in bytes per second.\n\
                     \n\
                     Examples:\n\
                       us-east-1:3 (3 peers, unlimited bandwidth)\n\
                       us-east-1:3:1000/500 (1000 B/s egress, 500 B/s ingress)\n\
                       eu-west-1:2:2000 (2000 B/s both ways)",
                ),
        )
        .arg(
            Arg::new("reload")
                .long("reload")
                .required(false)
                .num_args(0)
                .help("Reload latency data from cloudping.co"),
        )
        .get_matches();

    let distribution = matches
        .get_many::<String>("distribution")
        .unwrap()
        .map(|s| {
            let mut parts = s.split(':');
            let region = parts.next().expect("missing region").to_string();
            let count = parts
                .next()
                .expect("missing count")
                .parse::<usize>()
                .expect("invalid count");

            let (egress_cap, ingress_cap) = match parts.next() {
                Some(bandwidth) => {
                    if bandwidth.contains('/') {
                        let mut bw = bandwidth.split('/');
                        let egress = bw.next().unwrap().parse::<usize>().expect("invalid egress");
                        let ingress = bw
                            .next()
                            .unwrap()
                            .parse::<usize>()
                            .expect("invalid ingress");
                        (Some(egress), Some(ingress))
                    } else {
                        let bw = bandwidth.parse::<usize>().expect("invalid bandwidth");
                        (Some(bw), Some(bw))
                    }
                }
                None => (None, None),
            };

            (
                region,
                RegionConfig {
                    count,
                    egress_cap,
                    ingress_cap,
                },
            )
        })
        .collect();

    let task_path = matches
        .get_one::<String>("task")
        .expect("task file required")
        .clone();

    let task_content = std::fs::read_to_string(&task_path).expect("Failed to read task file");
    let reload_latency_data = matches.get_flag("reload");

    Arguments {
        distribution,
        task_content,
        reload_latency_data,
    }
}

/// Run simulations for all possible proposers and return results
fn run_all_simulations(
    peers: usize,
    distribution: &Distribution,
    dsl: &[(usize, Command)],
    latency_map: &Latencies,
    task_content: &str,
) -> Vec<Simulation> {
    let proposers: Vec<usize> = (0..peers).collect();
    let mut results = Vec::new();

    for proposer_idx in proposers {
        let result = run_single_simulation(proposer_idx, distribution, dsl, latency_map);
        print_simulation_results(&result, task_content);
        results.push(result);
    }

    results
}

/// Run a single simulation with the specified proposer
fn run_single_simulation(
    proposer_idx: usize,
    distribution: &Distribution,
    commands: &[(usize, Command)],
    latencies: &Latencies,
) -> Simulation {
    let proposer_region = calculate_proposer_region(proposer_idx, distribution);
    let peers = count_peers(distribution);
    let runtime_cfg = deterministic::Config::default()
        .with_seed(proposer_idx as u64)
        .with_cycle(Duration::from_micros(1));
    let executor = deterministic::Runner::new(runtime_cfg);

    // Run the simulation
    let steps = executor.start(async move |context| {
        run_simulation_logic(
            context,
            proposer_idx,
            peers,
            distribution,
            commands,
            latencies,
        )
        .await
    });

    Simulation {
        proposer_idx,
        proposer_region,
        steps,
    }
}

/// Core simulation logic that runs the network simulation
async fn run_simulation_logic<C: Spawner + Clock + Clone + Metrics + RNetwork + RngCore>(
    context: C,
    proposer_idx: usize,
    peers: usize,
    distribution: &Distribution,
    commands: &[(usize, Command)],
    latencies: &Latencies,
) -> Steps {
    let (network, mut oracle) = Network::new(
        context.with_label("network"),
        Config {
            max_size: usize::MAX,
            disconnect_on_block: true,
            tracked_peer_sets: None,
        },
    );
    network.start();

    let identities = setup_network_identities(&mut oracle, distribution).await;
    setup_network_links(&mut oracle, &identities, latencies).await;

    let (tx, mut rx) = mpsc::channel(peers);
    let jobs = spawn_peer_jobs(&context, proposer_idx, peers, identities, commands, tx);

    // Wait for all jobs to indicate they're done
    let mut responders = Vec::with_capacity(peers);
    for _ in 0..peers {
        responders.push(rx.next().await.unwrap());
    }

    // Ensure any messages in the simulator are queued (this is virtual time)
    context.sleep(Duration::from_secs(10)).await;

    // Send the shutdown signal to all jobs
    for responder in responders {
        responder.send(()).unwrap();
    }

    let results = try_join_all(jobs).await.unwrap();
    process_simulation_results(results)
}

/// Set up network identities for all peers across regions
async fn setup_network_identities(
    oracle: &mut commonware_p2p::simulated::Oracle<ed25519::PublicKey>,
    distribution: &Distribution,
) -> Vec<PeerIdentity> {
    let peers = count_peers(distribution);
    let mut identities = Vec::with_capacity(peers);
    let mut peer_idx = 0;

    // Register all peers
    for (region, config) in distribution {
        for _ in 0..config.count {
            let identity = ed25519::PrivateKey::from_seed(peer_idx as u64).public_key();
            let (sender, receiver) = oracle
                .control(identity.clone())
                .register(DEFAULT_CHANNEL)
                .await
                .unwrap();
            let codec_config = (commonware_codec::RangeCfg::from(..), ());
            let (sender, receiver) = wrap::<_, _, Message>(codec_config, sender, receiver);
            identities.push((identity, region.clone(), sender, receiver));
            peer_idx += 1;
        }
    }

    // Set bandwidth limits for each peer based on their region config
    for (identity, region, _, _) in &identities {
        let config = &distribution[region];
        oracle
            .limit_bandwidth(identity.clone(), config.egress_cap, config.ingress_cap)
            .await
            .unwrap();
    }

    identities
}

/// Set up network links between all peers with appropriate latencies
async fn setup_network_links(
    oracle: &mut commonware_p2p::simulated::Oracle<ed25519::PublicKey>,
    identities: &[PeerIdentity],
    latencies: &Latencies,
) {
    for (i, (identity, region, _, _)) in identities.iter().enumerate() {
        for (j, (other_identity, other_region, _, _)) in identities.iter().enumerate() {
            if i == j {
                continue;
            }
            let latency = latencies[region][other_region];
            let link = Link {
                latency: Duration::from_micros((latency.0 * 1000.0) as u64),
                jitter: Duration::from_micros((latency.1 * 1000.0) as u64),
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
    proposer_idx: usize,
    peers: usize,
    identities: Vec<PeerIdentity>,
    commands: &[(usize, Command)],
    tx: mpsc::Sender<oneshot::Sender<()>>,
) -> Vec<Handle<PeerResult>> {
    let proposer_identity = identities[proposer_idx].0.clone();
    let mut jobs = Vec::new();
    for (i, (identity, region, mut sender, mut receiver)) in identities.into_iter().enumerate() {
        let proposer_identity = proposer_identity.clone();
        let mut tx = tx.clone();
        let job = context.with_label("job");
        let commands = commands.to_vec();
        jobs.push(job.spawn(move |ctx| async move {
            let start = ctx.current();
            let mut completions: Vec<(usize, Duration)> = Vec::new();
            let mut current_index = 0;
            let mut received: BTreeMap<u32, BTreeSet<ed25519::PublicKey>> = BTreeMap::new();

            loop {
                if current_index >= commands.len() {
                    break;
                }

                // Process commands that can be executed immediately
                let mut advanced = true;
                while advanced {
                    if current_index >= commands.len() {
                        break;
                    }

                    let mut command_ctx = CommandContext {
                        proposer_identity: proposer_identity.clone(),
                        peers,
                        identity: identity.clone(),
                        start,
                    };
                    let command = &commands[current_index];
                    advanced = process_command(
                        &ctx,
                        &mut command_ctx,
                        &mut current_index,
                        command,
                        &mut sender,
                        &mut received,
                        &mut completions,
                    )
                    .await;
                }

                if current_index >= commands.len() {
                    break;
                }

                // Wait for incoming message
                let (other_identity, message) = receiver.recv().await.unwrap();
                let msg = message.unwrap();
                let msg_id = extract_id_from_message(&msg);
                received.entry(msg_id).or_default().insert(other_identity);
            }

            let maybe_proposer = if i == proposer_idx {
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

            (region, completions, maybe_proposer)
        }));
    }

    jobs
}

/// Check if a single command would succeed without executing side effects
async fn process_single_command_check<C: Spawner + Clock>(
    ctx: &C,
    command_ctx: &CommandContext,
    command: &(usize, Command),
    received: &BTreeMap<u32, BTreeSet<ed25519::PublicKey>>,
) -> bool {
    let is_proposer = command_ctx.identity == command_ctx.proposer_identity;

    // Handle delays for time-sensitive commands before checking conditions
    match &command.1 {
        Command::Collect(_, _, delay) | Command::Wait(_, _, delay) => {
            if let Some((message, _)) = delay {
                ctx.sleep(*message).await;
            }
        }
        _ => {} // No delays for other commands
    }

    // For compound commands, we need to handle recursion with delays
    match &command.1 {
        Command::Or(cmd1, cmd2) => {
            let cmd1_test = (command.0, cmd1.as_ref().clone());
            let cmd2_test = (command.0, cmd2.as_ref().clone());
            let result1 = Box::pin(process_single_command_check(
                ctx,
                command_ctx,
                &cmd1_test,
                received,
            ))
            .await;
            let result2 = Box::pin(process_single_command_check(
                ctx,
                command_ctx,
                &cmd2_test,
                received,
            ))
            .await;
            result1 || result2
        }
        Command::And(cmd1, cmd2) => {
            let cmd1_test = (command.0, cmd1.as_ref().clone());
            let cmd2_test = (command.0, cmd2.as_ref().clone());
            let result1 = Box::pin(process_single_command_check(
                ctx,
                command_ctx,
                &cmd1_test,
                received,
            ))
            .await;
            let result2 = Box::pin(process_single_command_check(
                ctx,
                command_ctx,
                &cmd2_test,
                received,
            ))
            .await;
            result1 && result2
        }
        _ => {
            // Use shared logic for basic command evaluation
            estimator::can_command_advance(&command.1, is_proposer, command_ctx.peers, received)
        }
    }
}

/// Process a single command in the DSL
async fn process_command<C: Spawner + Clock>(
    ctx: &C,
    command_ctx: &mut CommandContext,
    current_index: &mut usize,
    command: &(usize, Command),
    sender: &mut WrappedSender<Sender<ed25519::PublicKey>, Message>,
    received: &mut BTreeMap<u32, BTreeSet<ed25519::PublicKey>>,
    completions: &mut Vec<(usize, Duration)>,
) -> bool {
    let is_proposer = command_ctx.identity == command_ctx.proposer_identity;
    match &command.1 {
        Command::Propose(id, size) => {
            if is_proposer {
                let message = create_message(*id, *size);
                sender
                    .send(commonware_p2p::Recipients::All, message, true)
                    .await
                    .unwrap();
                received
                    .entry(*id)
                    .or_default()
                    .insert(command_ctx.identity.clone());
            }
            *current_index += 1;
            true
        }
        Command::Broadcast(id, size) => {
            let message = create_message(*id, *size);
            sender
                .send(commonware_p2p::Recipients::All, message, true)
                .await
                .unwrap();
            received
                .entry(*id)
                .or_default()
                .insert(command_ctx.identity.clone());
            *current_index += 1;
            true
        }
        Command::Reply(id, size) => {
            if is_proposer {
                received
                    .entry(*id)
                    .or_default()
                    .insert(command_ctx.identity.clone());
            } else {
                let message = create_message(*id, *size);
                sender
                    .send(
                        commonware_p2p::Recipients::One(command_ctx.proposer_identity.clone()),
                        message,
                        true,
                    )
                    .await
                    .unwrap();
            }
            *current_index += 1;
            true
        }
        Command::Collect(id, thresh, delay) => {
            if is_proposer {
                let count = received.get(id).map_or(0, |s| s.len());
                let required = calculate_threshold(thresh, command_ctx.peers);
                if let Some((message, _)) = delay {
                    ctx.sleep(*message).await;
                }
                if count >= required {
                    let duration = ctx.current().duration_since(command_ctx.start).unwrap();
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
        Command::Wait(id, thresh, delay) => {
            let count = received.get(id).map_or(0, |s| s.len());
            let required = calculate_threshold(thresh, command_ctx.peers);
            if let Some((message, _)) = delay {
                ctx.sleep(*message).await;
            }
            if count >= required {
                let duration = ctx.current().duration_since(command_ctx.start).unwrap();
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
        Command::Or(cmd1, cmd2) => {
            // For OR: succeed if either command would succeed
            // Create temporary command structs for testing
            let cmd1_test = (command.0, cmd1.as_ref().clone());
            let cmd2_test = (command.0, cmd2.as_ref().clone());

            // Test first command
            let result1 =
                process_single_command_check(ctx, command_ctx, &cmd1_test, received).await;
            let result2 =
                process_single_command_check(ctx, command_ctx, &cmd2_test, received).await;

            if result1 || result2 {
                let duration = ctx.current().duration_since(command_ctx.start).unwrap();
                completions.push((command.0, duration));
                *current_index += 1;
                true
            } else {
                false
            }
        }
        Command::And(cmd1, cmd2) => {
            // For AND: succeed only if both commands would succeed
            // Create temporary command structs for testing
            let cmd1_test = (command.0, cmd1.as_ref().clone());
            let cmd2_test = (command.0, cmd2.as_ref().clone());

            // Test both commands
            let result1 =
                process_single_command_check(ctx, command_ctx, &cmd1_test, received).await;
            let result2 =
                process_single_command_check(ctx, command_ctx, &cmd2_test, received).await;

            if result1 && result2 {
                let duration = ctx.current().duration_since(command_ctx.start).unwrap();
                completions.push((command.0, duration));
                *current_index += 1;
                true
            } else {
                false
            }
        }
    }
}

/// Process simulation results and extract wait/proposer latencies
fn process_simulation_results(results: Vec<PeerResult>) -> Steps {
    let mut steps = Steps {
        all: BTreeMap::new(),
        proposer: BTreeMap::new(),
    };

    for (region, completions, maybe_proposer) in results {
        for (line, duration) in completions {
            steps
                .all
                .entry(line)
                .or_default()
                .entry(region.clone())
                .or_default()
                .push(duration.as_millis() as f64);
        }
        if let Some(completions) = maybe_proposer {
            steps.proposer = completions
                .into_iter()
                .map(|(line, dur)| (line, dur.as_millis() as f64))
                .collect();
        }
    }

    steps
}

/// Print results for a single simulation
fn print_simulation_results(result: &Simulation, task_content: &str) {
    println!(
        "{}",
        format!(
            "\nresults for proposer {} ({}):\n",
            result.proposer_idx, result.proposer_region
        )
        .bold()
        .cyan()
    );

    // Emit results
    let dsl_lines: Vec<String> = task_content.lines().map(|s| s.to_string()).collect();
    let mut wait_lines: Vec<usize> = result.steps.all.keys().cloned().collect();
    wait_lines.sort();
    let mut wait_idx = 0;
    for (i, line) in dsl_lines.iter().enumerate() {
        println!("{}", line.yellow());
        let line_num = i + 1;
        let is_collect = line.starts_with("collect");

        if wait_idx < wait_lines.len() && wait_lines[wait_idx] == line_num {
            // Print proposer latency if available
            if let Some(proposer_latency) = result.steps.proposer.get(&line_num) {
                let stat_line = format!("    [proposer] latency: {proposer_latency:.2}ms");
                println!("{}", stat_line.magenta());
            }

            // Print regional statistics for non-collect commands
            if !is_collect {
                print_regional_statistics(&result.steps, line_num);
            }
            wait_idx += 1;
        }
    }
}

/// Print regional statistics for a specific line
fn print_regional_statistics(steps: &Steps, line: usize) {
    let Some(regional) = steps.all.get(&line) else {
        return;
    };

    // Calculate statistics
    let mut stats: Vec<(String, f64, f64, f64)> = Vec::new();
    for (region, latencies) in regional.iter() {
        let mut lats = latencies.clone();
        let mean = mean(&lats);
        let median = median(&mut lats);
        let stdv = std_dev(&lats).unwrap_or(0.0);
        stats.push((region.clone(), mean, median, stdv));
    }
    stats.sort_by(|a, b| a.0.cmp(&b.0));
    for (region, mean, median, stdv) in stats {
        let stat_line = format!(
            "    [{region}] mean: {mean:.2}ms (stdv: {stdv:.2}ms) | median: {median:.2}ms",
        );
        println!("{}", stat_line.cyan());
    }
}

/// Print aggregated results across all simulations
fn print_aggregated_results(results: &[Simulation], task_content: &str) {
    println!("\n{}", "-".repeat(80).yellow());
    println!("{}", "\nresults:\n".bold().blue());

    // Emit results
    let (observations, proposer_observations) = aggregate_simulation_results(results);
    let dsl_lines: Vec<String> = task_content.lines().map(|s| s.to_string()).collect();
    let mut wait_lines: Vec<usize> = observations.keys().cloned().collect();
    wait_lines.sort();
    let mut wait_idx = 0;
    for (i, line) in dsl_lines.iter().enumerate() {
        println!("{}", line.green());
        let line_num = i + 1;
        let is_collect = line.starts_with("collect");

        if wait_idx < wait_lines.len() && wait_lines[wait_idx] == line_num {
            // Print aggregated proposer statistics
            print_aggregated_proposer_statistics(&proposer_observations, line_num);

            // Print aggregated regional and overall statistics for non-collect commands
            if !is_collect {
                print_aggregated_regional_statistics(&observations, line_num);
            }
            wait_idx += 1;
        }
    }
}

/// Aggregate results from all simulations
fn aggregate_simulation_results(
    results: &[Simulation],
) -> (Observations, BTreeMap<usize, Vec<f64>>) {
    let mut proposer_observations: BTreeMap<usize, Vec<f64>> = BTreeMap::new();
    let mut observations: Observations = BTreeMap::new();

    // Aggregate proposer latencies
    for result in results {
        for (&line, &lat) in result.steps.proposer.iter() {
            proposer_observations.entry(line).or_default().push(lat);
        }
    }

    // Aggregate wait latencies
    for result in results {
        for (line, regional) in result.steps.all.iter() {
            let all_regional = observations.entry(*line).or_default();
            for (region, lats) in regional.iter() {
                all_regional
                    .entry(region.clone())
                    .or_default()
                    .extend(lats.clone());
            }
        }
    }

    (observations, proposer_observations)
}

/// Print aggregated proposer statistics
fn print_aggregated_proposer_statistics(
    proposer_observations: &BTreeMap<usize, Vec<f64>>,
    line_num: usize,
) {
    // Determine if there are any observations for this line
    let Some(lats) = proposer_observations.get(&line_num) else {
        return;
    };
    if lats.is_empty() {
        return;
    }

    // Calculate statistics
    let mut lats_sorted = lats.clone();
    let mean = mean(lats);
    let median = median(&mut lats_sorted);
    let stdv = std_dev(lats).unwrap_or(0.0);
    let stat_line =
        format!("    [proposer] mean: {mean:.2}ms (stdv: {stdv:.2}ms) | median: {median:.2}ms");
    println!("{}", stat_line.magenta());
}

/// Print aggregated regional and overall statistics
fn print_aggregated_regional_statistics(observations: &Observations, line_num: usize) {
    // Determine if there are any observations for this line
    let Some(regional) = observations.get(&line_num) else {
        return;
    };
    let mut stats = Vec::new();
    let mut all_lats: Vec<f64> = Vec::new();

    // Calculate regional statistics
    for (region, latencies) in regional.iter() {
        let mut lats = latencies.clone();
        let mean = mean(&lats);
        let median = median(&mut lats);
        let stdv = std_dev(&lats).unwrap_or(0.0);
        stats.push((region.clone(), mean, median, stdv));
        all_lats.extend_from_slice(latencies);
    }

    // Print regional statistics
    stats.sort_by(|a, b| a.0.cmp(&b.0));
    for (region, mean, median, stdv) in stats {
        let stat_line = format!(
            "    [{region}] mean: {mean:.2}ms (stdv: {stdv:.2}ms) | median: {median:.2}ms",
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
                "    [all] mean: {overall_mean:.2}ms (stdv: {overall_std:.2}ms) | median: {overall_median:.2}ms"
            );
        println!("{}", stat_line.white());
    }
}
