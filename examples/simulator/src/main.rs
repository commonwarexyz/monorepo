use clap::{value_parser, Arg, Command};
use colored::Colorize;
use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
use commonware_macros::select;
use commonware_p2p::{
    simulated::{Config, Link, Network},
    utils::codec::wrap,
};
use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
use futures::future::try_join_all;
use reqwest::blocking::Client;
use std::sync::mpsc::channel;
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
use tracing::debug;

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

fn mean(data: &[f64]) -> f64 {
    let sum = data.iter().sum::<f64>();
    sum / data.len() as f64
}

fn median(data: &mut [f64]) -> f64 {
    data.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = data.len() / 2;
    if data.len() % 2 == 0 {
        (data[mid - 1] + data[mid]) / 2.0
    } else {
        data[mid]
    }
}

fn std_dev(data: &[f64]) -> Option<f64> {
    if data.is_empty() {
        return None;
    }
    let mean = mean(data);
    let variance = data
        .iter()
        .map(|value| {
            let diff = mean - *value;
            diff * diff
        })
        .sum::<f64>()
        / data.len() as f64;
    Some(variance.sqrt())
}

#[derive(Clone)]
enum SimCommand {
    Propose(u32),
    Broadcast(u32),
    Reply(u32),
    Collect(u32, Threshold),
    Wait(u32, Threshold),
}

#[derive(Clone)]
enum Threshold {
    Count(usize),
    Percent(f64),
}

fn parse_task(content: &str) -> Vec<(usize, SimCommand)> {
    let mut cmds = Vec::new();
    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts[0] {
            "propose" => {
                let id = parts[1].parse::<u32>().expect("Invalid propose id");
                cmds.push((line_num + 1, SimCommand::Propose(id)));
            }
            "broadcast" => {
                let id = parts[1].parse::<u32>().expect("Invalid broadcast id");
                cmds.push((line_num + 1, SimCommand::Broadcast(id)));
            }
            "reply" => {
                let id = parts[1].parse::<u32>().expect("Invalid reply id");
                cmds.push((line_num + 1, SimCommand::Reply(id)));
            }
            "collect" => {
                let id = parts[1].parse::<u32>().expect("Invalid collect id");
                let thresh_str = parts[2];
                let thresh = if thresh_str.ends_with('%') {
                    let p = thresh_str
                        .trim_end_matches('%')
                        .parse::<f64>()
                        .expect("Invalid percent")
                        / 100.0;
                    Threshold::Percent(p)
                } else {
                    let c = thresh_str.parse::<usize>().expect("Invalid count");
                    Threshold::Count(c)
                };
                cmds.push((line_num + 1, SimCommand::Collect(id, thresh)));
            }
            "wait" => {
                let id = parts[1].parse::<u32>().expect("Invalid wait id");
                let thresh_str = parts[2];
                let thresh = if thresh_str.ends_with('%') {
                    let p = thresh_str
                        .trim_end_matches('%')
                        .parse::<f64>()
                        .expect("Invalid percent")
                        / 100.0;
                    Threshold::Percent(p)
                } else {
                    let c = thresh_str.parse::<usize>().expect("Invalid count");
                    Threshold::Count(c)
                };
                cmds.push((line_num + 1, SimCommand::Wait(id, thresh)));
            }
            _ => panic!("Unknown command: {}", parts[0]),
        }
    }
    cmds
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
    let mut all_wait_latencies: HashMap<usize, HashMap<String, Vec<f64>>> = HashMap::new();

    // Run simulation for each proposer
    for leader_idx in 0..peers {
        let task_content_inner = task_content.clone();
        let (tx, rx) = channel();
        let dsl_outer = dsl.clone();
        let region_counts_outer = region_counts.clone();
        let latency_map_outer = latency_map.clone();
        let runtime_cfg = deterministic::Config::new();
        let executor = deterministic::Runner::new(runtime_cfg);
        executor.start(async move |context| {
            // Initialize simulated p2p network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: usize::MAX,
                },
            );

            // Start network
            network.start();

            // Generate peers
            let mut identities = Vec::with_capacity(peers);
            let mut peer_idx = 0;
            for (region, count) in &region_counts_outer {
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

            // Create connections between all peers
            for (i, (identity, region, _, _)) in identities.iter().enumerate() {
                for (j, (other_identity, other_region, _, _)) in identities.iter().enumerate() {
                    // Skip self
                    if i == j {
                        continue;
                    }

                    // Add link
                    let latency = latency_map_outer[region][other_region];
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

            // For each peer, see how long it takes to complete the DSL script
            let mut jobs = Vec::new();
            for (i, (identity, region, mut sender, mut receiver)) in
                identities.into_iter().enumerate()
            {
                let job = context.with_label("job");
                let dsl = dsl_outer.clone();
                jobs.push(job.spawn(move |ctx| async move {
                    let is_leader = i == leader_idx;
                    let start = ctx.current();
                    let mut completions: Vec<(usize, Duration)> = Vec::new();
                    let mut current_index = 0;
                    let mut received: HashMap<u32, HashSet<ed25519::PublicKey>> = HashMap::new();
                    loop {
                        // Attempt to advance state machine
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
                                        received.entry(*id).or_default().insert(identity.clone());
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
                                    let leader_identity = ed25519::PrivateKey::from_seed(leader_idx as u64).public_key();
                                    if is_leader {
                                        received.entry(*id).or_default().insert(identity.clone());
                                    } else {
                                        sender.send(commonware_p2p::Recipients::One(leader_identity), *id, true).await.unwrap();
                                    }
                                    current_index += 1;
                                    advanced = true;
                                }
                                SimCommand::Collect(id, thresh) => {
                                    if is_leader {
                                        let count = received.get(id).map_or(0, |s| s.len());
                                        let required = match thresh {
                                            Threshold::Percent(p) => ((peers as f64) * p).ceil() as usize,
                                            Threshold::Count(c) => *c,
                                        };
                                        if count >= required {
                                            let duration = ctx.current().duration_since(start).unwrap();
                                            completions.push((dsl[current_index].0, duration));
                                            current_index += 1;
                                            advanced = true;
                                        }
                                    } else {
                                        current_index += 1;
                                        advanced = true;
                                    }
                                }
                                SimCommand::Wait(id, thresh) => {
                                    let count = received.get(id).map_or(0, |s| s.len());
                                    let required = match thresh {
                                        Threshold::Percent(p) => {
                                            ((peers as f64) * p).ceil() as usize
                                        }
                                        Threshold::Count(c) => *c,
                                    };
                                    if count >= required {
                                        let duration = ctx.current().duration_since(start).unwrap();
                                        completions.push((dsl[current_index].0, duration));
                                        current_index += 1;
                                        advanced = true;
                                    }
                                }
                            }
                        }

                        // If we've completed the DSL, break
                        if current_index >= dsl.len() {
                            break;
                        }

                        // Process messages from other peers
                        let (other_identity, message) = receiver.recv().await.unwrap();
                        let msg_id = message.unwrap();
                        received.entry(msg_id).or_default().insert(other_identity);
                    }

                    (region, completions, receiver)
                }));
            }

            // Wait for all jobs to complete
            let results_with_receivers = try_join_all(jobs).await.unwrap();
            let mut drain_jobs = Vec::new();
            let mut processed_results = Vec::new();
            for (region, completions, mut receiver) in results_with_receivers.into_iter() {
                drain_jobs.push(context.with_label("drain").spawn(move |ctx| async move {
                    let drain_until = ctx.current() + Duration::from_millis(1000);
                    loop {
                        select! {
                            _ = ctx.sleep_until(drain_until) => {
                                break;
                            },
                            msg = receiver.recv() => {
                                match msg {
                                    Ok(_) => {
                                        // Discard message
                                    }
                                    Err(_) => {
                                        break;
                                    }
                                }
                            },
                        }
                    }
                }));
                processed_results.push((region, completions));
            }
            try_join_all(drain_jobs).await.unwrap();

            // Group results by wait line and region
            let mut wait_latencies: HashMap<usize, HashMap<Region, Vec<f64>>> = HashMap::new();
            for (region, completions) in processed_results {
                for (line, duration) in completions {
                    wait_latencies
                        .entry(line)
                        .or_default()
                        .entry(region.clone())
                        .or_default()
                        .push(duration.as_millis() as f64);
                }
            }

            // Print proposer results
            let mut current = 0;
            let leader_region = region_counts_outer
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
                format!(
                    "\nSimulation results for proposer {leader_idx} ({leader_region}):\n"
                )
                .bold()
                .cyan()
            );
            let dsl_lines: Vec<String> =
                task_content_inner.lines().map(|s| s.to_string()).collect();
            let mut wait_lines: Vec<usize> = wait_latencies.keys().cloned().collect();
            wait_lines.sort();
            let mut wait_idx = 0;
            for (i, line) in dsl_lines.iter().enumerate() {
                println!("{}", line.yellow());
                let line_num = i + 1;
                if wait_idx < wait_lines.len() && wait_lines[wait_idx] == line_num {
                    let regional = wait_latencies.get(&line_num).unwrap();
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
                        println!("{}", stat_line.cyan());
                    }
                    wait_idx += 1;
                }
            }

            tx.send(wait_latencies).unwrap();
        });

        let run_wait_latencies: HashMap<usize, HashMap<String, Vec<f64>>> = rx.recv().unwrap();

        for (line, regional) in run_wait_latencies {
            let all_regional = all_wait_latencies.entry(line).or_default();
            for (region, lats) in regional {
                all_regional.entry(region).or_default().extend(lats);
            }
        }
    }
    println!("\n{}", "-".repeat(80).yellow());

    // Calculate and print averaged stats
    println!("{}", "\nAveraged simulation results:\n".bold().magenta());
    let dsl_lines: Vec<String> = task_content.lines().map(|s| s.to_string()).collect();
    let mut wait_lines: Vec<usize> = all_wait_latencies.keys().cloned().collect();
    wait_lines.sort();
    let mut wait_idx = 0;
    for (i, line) in dsl_lines.iter().enumerate() {
        println!("{}", line.green());
        let line_num = i + 1;
        if wait_idx < wait_lines.len() && wait_lines[wait_idx] == line_num {
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
            wait_idx += 1;
        }
    }
}
