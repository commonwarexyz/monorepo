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
    collections::{BTreeMap, BTreeSet, HashMap},
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
type LatencyMap = BTreeMap<Region, BTreeMap<Region, LatJitPair>>;

#[derive(serde::Deserialize)]
struct ApiResp {
    data: BTreeMap<Region, BTreeMap<Region, f64>>,
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
    let mut map = BTreeMap::new();
    for (from, inner_p50) in p50.data {
        let inner_p90 = &p90.data[&from];
        let mut dest_map = BTreeMap::new();
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
    Collect(u32, Threshold, Option<(Duration, Duration)>),
    Wait(u32, Threshold, Option<(Duration, Duration)>),
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
        let command = parts[0];
        let mut args: HashMap<&str, &str> = HashMap::new();
        for &arg in &parts[1..] {
            let kv: Vec<&str> = arg.splitn(2, '=').collect();
            if kv.len() != 2 {
                panic!("Invalid argument format: {arg}");
            }
            args.insert(kv[0], kv[1]);
        }
        match command {
            "propose" => {
                let id_str = args.get("id").expect("Missing id for propose");
                let id = id_str.parse::<u32>().expect("Invalid id");
                cmds.push((line_num + 1, SimCommand::Propose(id)));
            }
            "broadcast" => {
                let id_str = args.get("id").expect("Missing id for broadcast");
                let id = id_str.parse::<u32>().expect("Invalid id");
                cmds.push((line_num + 1, SimCommand::Broadcast(id)));
            }
            "reply" => {
                let id_str = args.get("id").expect("Missing id for reply");
                let id = id_str.parse::<u32>().expect("Invalid id");
                cmds.push((line_num + 1, SimCommand::Reply(id)));
            }
            "collect" | "wait" => {
                let id_str = args.get("id").expect("Missing id");
                let id = id_str.parse::<u32>().expect("Invalid id");
                let thresh_str = args.get("threshold").expect("Missing threshold");
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
                let delay = args.get("delay").map(|delay_str| {
                    let delay_str = delay_str.trim_matches('(').trim_matches(')');
                    let parts: Vec<&str> = delay_str.split(',').collect();
                    let message =
                        Duration::from_secs_f64(parts[0].parse::<f64>().expect("Invalid delay"));
                    let completion =
                        Duration::from_secs_f64(parts[1].parse::<f64>().expect("Invalid delay"));
                    (message, completion)
                });
                if command == "collect" {
                    cmds.push((line_num + 1, SimCommand::Collect(id, thresh, delay)));
                } else {
                    cmds.push((line_num + 1, SimCommand::Wait(id, thresh, delay)));
                }
            }
            _ => panic!("Unknown command: {command}"),
        }
    }
    cmds
}

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
        .arg(
            Arg::new("concurrency")
                .long("concurrency")
                .required(false)
                .value_parser(value_parser!(usize))
                .default_value("4")
                .help("Number of concurrent simulations to run"),
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
    let concurrency = *matches.get_one::<usize>("concurrency").unwrap_or(&4);
    let leaders: Vec<usize> = (0..peers).collect();
    let mut results: Vec<SimResult> = Vec::new();
    let mut all_wait_latencies: BTreeMap<usize, BTreeMap<String, Vec<f64>>> = BTreeMap::new();
    for chunk in leaders.chunks(concurrency) {
        let mut chunk_handles: Vec<std::thread::JoinHandle<SimResult>> = Vec::new();
        for &leader_idx in chunk {
            let dsl_clone = dsl.clone();
            let latency_map_clone = latency_map.clone();
            let region_counts_clone = region_counts.clone();
            let peers_clone = peers;
            let handle = std::thread::spawn(move || {
                let leader_idx_clone = leader_idx;
                let (tx, rx) = channel();
                let runtime_cfg = deterministic::Config::default().with_seed(leader_idx as u64);
                let executor = deterministic::Runner::new(runtime_cfg);
                executor.start({
                    let region_counts_clone = region_counts_clone.clone();
                    async move |context| {
                        let (network, mut oracle) = Network::new(
                            context.with_label("network"),
                            Config {
                                max_size: usize::MAX,
                            },
                        );
                        network.start();
                        let mut identities = Vec::with_capacity(peers_clone);
                        let mut peer_idx = 0;
                        for (region, count) in &region_counts_clone {
                            for _ in 0..*count {
                                let identity =
                                    ed25519::PrivateKey::from_seed(peer_idx as u64).public_key();
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
                            for (j, (other_identity, other_region, _, _)) in
                                identities.iter().enumerate()
                            {
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
                        let mut jobs = Vec::new();
                        for (i, (identity, region, mut sender, mut receiver)) in
                            identities.into_iter().enumerate()
                        {
                            let job = context.with_label("job");
                            let dsl = dsl_clone.clone();
                            jobs.push(job.spawn(move |ctx| async move {
                                let is_leader = i == leader_idx_clone;
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
                                                        .send(
                                                            commonware_p2p::Recipients::All,
                                                            *id,
                                                            true,
                                                        )
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
                                                    .send(
                                                        commonware_p2p::Recipients::All,
                                                        *id,
                                                        true,
                                                    )
                                                    .await
                                                    .unwrap();
                                                received
                                                    .entry(*id)
                                                    .or_default()
                                                    .insert(identity.clone());
                                                current_index += 1;
                                                advanced = true;
                                            }
                                            SimCommand::Reply(id) => {
                                                let leader_identity =
                                                    ed25519::PrivateKey::from_seed(
                                                        leader_idx_clone as u64,
                                                    )
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
                                                    let count =
                                                        received.get(id).map_or(0, |s| s.len());
                                                    let required = match thresh {
                                                        Threshold::Percent(p) => {
                                                            ((peers_clone as f64) * *p).ceil()
                                                                as usize
                                                        }
                                                        Threshold::Count(c) => *c,
                                                    };
                                                    if let Some((message, _)) = delay {
                                                        ctx.sleep(*message).await;
                                                    }
                                                    if count >= required {
                                                        let duration = ctx
                                                            .current()
                                                            .duration_since(start)
                                                            .unwrap();
                                                        completions
                                                            .push((dsl[current_index].0, duration));
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
                                                        ((peers_clone as f64) * *p).ceil() as usize
                                                    }
                                                    Threshold::Count(c) => *c,
                                                };
                                                if let Some((message, _)) = delay {
                                                    ctx.sleep(*message).await;
                                                }
                                                if count >= required {
                                                    let duration = ctx
                                                        .current()
                                                        .duration_since(start)
                                                        .unwrap();
                                                    completions
                                                        .push((dsl[current_index].0, duration));
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
                                (region, completions, maybe_leader, receiver)
                            }));
                        }
                        let results_with_receivers = try_join_all(jobs).await.unwrap();
                        let mut drain_jobs = Vec::new();
                        let mut processed_results = Vec::new();
                        let mut leader_completions: Option<Vec<(usize, Duration)>> = None;
                        for (region, completions, maybe_leader, mut receiver) in
                            results_with_receivers.into_iter()
                        {
                            drain_jobs.push(context.with_label("drain").spawn(
                                move |ctx| async move {
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
                                },
                            ));
                            if let Some(comps) = maybe_leader {
                                leader_completions = Some(comps);
                            }
                            processed_results.push((region, completions));
                        }
                        try_join_all(drain_jobs).await.unwrap();
                        let mut wait_latencies: BTreeMap<usize, BTreeMap<Region, Vec<f64>>> =
                            BTreeMap::new();
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
                        let leader_latencies: BTreeMap<usize, f64> = leader_completions
                            .unwrap()
                            .into_iter()
                            .map(|(line, dur)| (line, dur.as_millis() as f64))
                            .collect();
                        tx.send((wait_latencies, leader_latencies)).unwrap();
                    }
                });
                let (wait_latencies, leader_latencies) = rx.recv().unwrap();
                let mut current = 0;
                let leader_region = region_counts_clone
                    .iter()
                    .find_map(|(reg, cnt)| {
                        let start = current;
                        current += *cnt;
                        if leader_idx_clone >= start && leader_idx_clone < current {
                            Some(reg.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap();
                (
                    leader_idx_clone,
                    leader_region,
                    wait_latencies,
                    leader_latencies,
                )
            });
            chunk_handles.push(handle);
        }
        for handle in chunk_handles {
            let res = handle.join().unwrap();
            results.push(res);
        }
    }
    results.sort_by_key(|(idx, _, _, _)| *idx);
    for tuple in &results {
        let (leader_idx, leader_region, wait_latencies, leader_latencies) = tuple;
        println!(
            "{}",
            format!(
                "\nSimulation results for proposer {} ({}):\n",
                *leader_idx, leader_region
            )
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
                    let stat_line = format!("    [proposer] Latency: {:.2}ms", proposer_latency);
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
    println!("{}", "\nAveraged simulation results:\n".bold().white());
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
                    let mean_ms = mean(&lats);
                    let median_ms = median(&mut lats_sorted);
                    let std_dev_ms = std_dev(&lats).unwrap_or(0.0);
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
            }
            wait_idx += 1;
        }
    }
}
