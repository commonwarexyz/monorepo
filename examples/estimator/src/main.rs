use clap::{value_parser, Arg, Command};
use colored::Colorize;
use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
use commonware_macros::select;
use commonware_p2p::{
    simulated::{Config, Link, Network},
    utils::codec::wrap,
};
use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    future::try_join_all,
    SinkExt, StreamExt,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use tracing::debug;

// Import from our library
use estimator::{
    crate_version, download_latency_data, load_latency_data, mean, median, parse_task, std_dev,
    Region, SimCommand, Threshold,
};

const DEFAULT_CHANNEL: u32 = 0;
const DEFAULT_SUCCESS_RATE: f64 = 1.0;

type SimResult = (
    usize,
    String,
    BTreeMap<usize, BTreeMap<String, Vec<f64>>>,
    BTreeMap<usize, f64>,
);

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
    let peers: usize = region_counts.iter().map(|(_, count)| *count).sum();
    assert!(peers > 1, "must have at least 2 peers");
    let task_path = matches
        .get_one::<String>("task")
        .expect("task file required")
        .clone();
    let task_content = std::fs::read_to_string(&task_path).expect("Failed to read task file");
    let dsl = parse_task(&task_content);
    debug!(peers, ?region_counts, "Initializing simulator");

    // Download latency data
    let latency_map = if matches.get_flag("reload-latency-data") {
        debug!("downloading latency data");
        download_latency_data()
    } else {
        debug!("loading latency data");
        load_latency_data()
    };
    let leaders: Vec<usize> = (0..peers).collect();
    let mut results: Vec<SimResult> = Vec::new();
    let mut all_wait_latencies: BTreeMap<usize, BTreeMap<String, Vec<f64>>> = BTreeMap::new();
    for leader_idx in leaders {
        let runtime_cfg = deterministic::Config::default().with_seed(leader_idx as u64);
        let executor = deterministic::Runner::new(runtime_cfg);
        let (wait_latencies, leader_latencies) = executor.start({
            let dsl_clone = dsl.clone();
            let latency_map_clone = latency_map.clone();
            let region_counts_clone = region_counts.clone();
            async move |context| {
                let (network, mut oracle) = Network::new(
                    context.with_label("network"),
                    Config {
                        max_size: usize::MAX,
                    },
                );
                network.start();
                let mut identities = Vec::with_capacity(peers);
                let mut peer_idx = 0;
                for (region, count) in &region_counts_clone {
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
                for (i, (identity, region, _, _)) in identities.iter().enumerate() {
                    for (j, (other_identity, other_region, _, _)) in identities.iter().enumerate() {
                        if i == j {
                            continue;
                        }
                        let latency = latency_map_clone[region][other_region];
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
                let (tx, mut rx) = mpsc::channel(peers);
                let mut jobs = Vec::new();
                for (i, (identity, region, mut sender, mut receiver)) in
                    identities.into_iter().enumerate()
                {
                    let mut tx = tx.clone();
                    let job = context.with_label("job");
                    let dsl = dsl_clone.clone();
                    jobs.push(job.spawn(move |ctx| async move {
                        let is_leader = i == leader_idx;
                        let start = ctx.current();
                        let mut completions: Vec<(usize, Duration)> = Vec::new();
                        let mut current_index = 0;
                        let mut received: BTreeMap<u32, BTreeSet<ed25519::PublicKey>> =
                            BTreeMap::new();
                        loop {
                            if current_index >= dsl.len() {
                                break;
                            }
                            let mut advanced = true;
                            while advanced {
                                advanced = false;
                                if current_index >= dsl.len() {
                                    break;
                                }
                                match &dsl[current_index].1 {
                                    SimCommand::Propose(id) => {
                                        if is_leader {
                                            sender
                                                .send(commonware_p2p::Recipients::All, *id, true)
                                                .await
                                                .unwrap();
                                            received
                                                .entry(*id)
                                                .or_default()
                                                .insert(identity.clone());
                                        }
                                        current_index += 1;
                                        advanced = true;
                                    }
                                    SimCommand::Broadcast(id) => {
                                        sender
                                            .send(commonware_p2p::Recipients::All, *id, true)
                                            .await
                                            .unwrap();
                                        received.entry(*id).or_default().insert(identity.clone());
                                        current_index += 1;
                                        advanced = true;
                                    }
                                    SimCommand::Reply(id) => {
                                        let leader_identity =
                                            ed25519::PrivateKey::from_seed(leader_idx as u64)
                                                .public_key();
                                        if is_leader {
                                            received
                                                .entry(*id)
                                                .or_default()
                                                .insert(identity.clone());
                                        } else {
                                            sender
                                                .send(
                                                    commonware_p2p::Recipients::One(
                                                        leader_identity,
                                                    ),
                                                    *id,
                                                    true,
                                                )
                                                .await
                                                .unwrap();
                                        }
                                        current_index += 1;
                                        advanced = true;
                                    }
                                    SimCommand::Collect(id, thresh, delay) => {
                                        if is_leader {
                                            let count = received.get(id).map_or(0, |s| s.len());
                                            let required = match thresh {
                                                Threshold::Percent(p) => {
                                                    ((peers as f64) * *p).ceil() as usize
                                                }
                                                Threshold::Count(c) => *c,
                                            };
                                            if let Some((message, _)) = delay {
                                                ctx.sleep(*message).await;
                                            }
                                            if count >= required {
                                                let duration =
                                                    ctx.current().duration_since(start).unwrap();
                                                completions.push((dsl[current_index].0, duration));
                                                if let Some((_, completion)) = delay {
                                                    ctx.sleep(*completion).await;
                                                }
                                                current_index += 1;
                                                advanced = true;
                                            }
                                        } else {
                                            current_index += 1;
                                            advanced = true;
                                        }
                                    }
                                    SimCommand::Wait(id, thresh, delay) => {
                                        let count = received.get(id).map_or(0, |s| s.len());
                                        let required = match thresh {
                                            Threshold::Percent(p) => {
                                                ((peers as f64) * *p).ceil() as usize
                                            }
                                            Threshold::Count(c) => *c,
                                        };
                                        if let Some((message, _)) = delay {
                                            ctx.sleep(*message).await;
                                        }
                                        if count >= required {
                                            let duration =
                                                ctx.current().duration_since(start).unwrap();
                                            completions.push((dsl[current_index].0, duration));
                                            if let Some((_, completion)) = delay {
                                                ctx.sleep(*completion).await;
                                            }
                                            current_index += 1;
                                            advanced = true;
                                        }
                                    }
                                }
                            }
                            if current_index >= dsl.len() {
                                break;
                            }
                            let (other_identity, message) = receiver.recv().await.unwrap();
                            let msg_id = message.unwrap();
                            received.entry(msg_id).or_default().insert(other_identity);
                        }
                        let maybe_leader = if is_leader {
                            Some(completions.clone())
                        } else {
                            None
                        };

                        // Notify that we're done
                        let (shutter, mut listener) = oneshot::channel::<()>();
                        tx.send(shutter).await.unwrap();

                        // Process messages until we're done
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
                    }));
                }

                // Wait for all jobs to indicate they're done
                let mut responders = Vec::with_capacity(peers);
                for _ in 0..peers {
                    responders.push(rx.next().await.unwrap());
                }

                // Ensure any messages in the simulator are queued (this is virtual time)
                context.sleep(Duration::from_millis(10_000)).await;

                // Send the shutdown signal to all jobs
                for responder in responders {
                    responder.send(()).unwrap();
                }
                let results = try_join_all(jobs).await.unwrap();

                // Process the results
                let mut leader_latencies: Option<BTreeMap<usize, f64>> = None;
                let mut wait_latencies: BTreeMap<usize, BTreeMap<Region, Vec<f64>>> =
                    BTreeMap::new();
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
        });

        // Emit intermediate results
        let mut current = 0;
        let leader_region = region_counts
            .iter()
            .find_map(|(reg, cnt)| {
                let start = current;
                current += *cnt;
                if leader_idx >= start && leader_idx < current {
                    Some(reg.clone())
                } else {
                    None
                }
            })
            .unwrap();

        println!(
            "{}",
            format!("\nSimulation results for proposer {leader_idx} ({leader_region}):\n")
                .bold()
                .cyan()
        );
        let dsl_lines: Vec<String> = task_content.lines().map(|s| s.to_string()).collect();
        let mut wait_lines: Vec<usize> = wait_latencies.keys().cloned().collect();
        wait_lines.sort();
        let mut wait_idx = 0;
        for (i, line) in dsl_lines.iter().enumerate() {
            println!("{}", line.yellow());
            let line_num = i + 1;
            let is_collect = line.starts_with("collect");
            if wait_idx < wait_lines.len() && wait_lines[wait_idx] == line_num {
                if let Some(proposer_latency) = leader_latencies.get(&line_num) {
                    let stat_line = format!("    [proposer] Latency: {proposer_latency:.2}ms");
                    println!("{}", stat_line.magenta());
                }
                if !is_collect {
                    let regional = wait_latencies.get(&line_num).unwrap();
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
                wait_idx += 1;
            }
        }

        results.push((leader_idx, leader_region, wait_latencies, leader_latencies));
    }
    let mut all_leader_latencies: BTreeMap<usize, Vec<f64>> = BTreeMap::new();
    for tuple in &results {
        let (_, _, _, leader_latencies) = tuple;
        for (&line, &lat) in leader_latencies.iter() {
            all_leader_latencies.entry(line).or_default().push(lat);
        }
    }
    for tuple in &results {
        let (_, _, wait_latencies, _) = tuple;
        for (line, regional) in wait_latencies.iter() {
            let all_regional = all_wait_latencies.entry(*line).or_default();
            for (region, lats) in regional.iter() {
                all_regional
                    .entry(region.clone())
                    .or_default()
                    .extend(lats.clone());
            }
        }
    }
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
            if let Some(lats) = all_leader_latencies.get(&line_num) {
                if !lats.is_empty() {
                    let mut lats_sorted = lats.clone();
                    let mean_ms = mean(lats);
                    let median_ms = median(&mut lats_sorted);
                    let std_dev_ms = std_dev(lats).unwrap_or(0.0);
                    let stat_line = format!("    [proposer] Mean: {mean_ms:.2}ms (Std Dev: {std_dev_ms:.2}ms) | Median: {median_ms:.2}ms");
                    println!("{}", stat_line.magenta());
                }
            }
            if !is_collect {
                let regional = all_wait_latencies.get(&line_num).unwrap();
                let mut stats = Vec::new();
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
                    println!("{}", stat_line.blue());
                }
                let mut all_lats: Vec<f64> = Vec::new();
                for latencies in regional.values() {
                    all_lats.extend_from_slice(latencies);
                }
                if !all_lats.is_empty() {
                    let mut all_lats_sorted = all_lats.clone();
                    let overall_mean = mean(&all_lats);
                    let overall_median = median(&mut all_lats_sorted);
                    let overall_std = std_dev(&all_lats).unwrap_or(0.0);
                    let stat_line = format!("    [all] Mean: {overall_mean:.2}ms (Std Dev: {overall_std:.2}ms) | Median: {overall_median:.2}ms");
                    println!("{}", stat_line.white());
                }
            }
            wait_idx += 1;
        }
    }
}
