use reqwest::blocking::Client;
use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};
use tracing::debug;

pub type Region = String;
pub type Distribution = BTreeMap<Region, usize>;
pub type Behavior = (f64, f64); // (avg_latency_ms, jitter_ms)
pub type Latencies = BTreeMap<Region, BTreeMap<Region, Behavior>>;

#[derive(serde::Deserialize)]
struct CloudPing {
    pub data: BTreeMap<Region, BTreeMap<Region, f64>>,
}

#[derive(Clone)]
pub enum Command {
    Propose(u32),
    Broadcast(u32),
    Reply(u32),
    Collect(u32, Threshold, Option<(Duration, Duration)>),
    Wait(u32, Threshold, Option<(Duration, Duration)>),
}

#[derive(Clone)]
pub enum Threshold {
    Count(usize),
    Percent(f64),
}

const BASE: &str = "https://www.cloudping.co/api/latencies";

/// Returns the version of the crate.
pub fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Downloads latency data from cloudping.co API
fn download_latency_data() -> Latencies {
    let cli = Client::builder().build().unwrap();

    // Pull P50 and P90 matrices (time-frame: last 1 year)
    let p50: CloudPing = cli
        .get(format!("{BASE}?percentile=p_50&timeframe=1Y"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let p90: CloudPing = cli
        .get(format!("{BASE}?percentile=p_90&timeframe=1Y"))
        .send()
        .unwrap()
        .json()
        .unwrap();

    populate_latency_map(p50, p90)
}

/// Loads latency data from local JSON files
fn load_latency_data() -> Latencies {
    let p50 = include_str!("p50.json");
    let p90 = include_str!("p90.json");
    let p50: CloudPing = serde_json::from_str(p50).unwrap();
    let p90: CloudPing = serde_json::from_str(p90).unwrap();

    populate_latency_map(p50, p90)
}

/// Populates a latency map from P50 and P90 data
fn populate_latency_map(p50: CloudPing, p90: CloudPing) -> Latencies {
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

/// Get latency data either by downloading or loading from cache
pub fn get_latency_data(reload: bool) -> Latencies {
    if reload {
        debug!("downloading latency data");
        download_latency_data()
    } else {
        debug!("loading latency data");
        load_latency_data()
    }
}

/// Calculate total number of peers across all regions
pub fn count_peers(distribution: &Distribution) -> usize {
    let peers = distribution.values().sum();
    assert!(peers > 1, "must have at least 2 peers");
    peers
}

/// Calculate which region a leader belongs to based on their index
pub fn calculate_leader_region(leader_idx: usize, distribution: &Distribution) -> String {
    let mut current = 0;
    for (region, count) in distribution {
        let start = current;
        current += *count;
        if leader_idx >= start && leader_idx < current {
            return region.clone();
        }
    }
    panic!("Leader index {leader_idx} out of bounds");
}

/// Calculates the mean of a slice of f64 values
pub fn mean(data: &[f64]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let sum = data.iter().sum::<f64>();
    sum / data.len() as f64
}

/// Calculates the median of a slice of f64 values
/// Note: This function modifies the input slice by sorting it
pub fn median(data: &mut [f64]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    data.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = data.len() / 2;
    if data.len() % 2 == 0 {
        (data[mid - 1] + data[mid]) / 2.0
    } else {
        data[mid]
    }
}

/// Calculates the standard deviation of a slice of f64 values
pub fn std_dev(data: &[f64]) -> Option<f64> {
    if data.is_empty() {
        return None;
    }
    let mean_val = mean(data);
    let variance = data
        .iter()
        .map(|value| {
            let diff = mean_val - *value;
            diff * diff
        })
        .sum::<f64>()
        / data.len() as f64;
    Some(variance.sqrt())
}

/// Calculate required count based on threshold
pub fn calculate_threshold(thresh: &Threshold, peers: usize) -> usize {
    match thresh {
        Threshold::Percent(p) => ((peers as f64) * *p).ceil() as usize,
        Threshold::Count(c) => *c,
    }
}

/// Parses a DSL task file into a vector of simulation commands
pub fn parse_task(content: &str) -> Vec<(usize, Command)> {
    let mut cmds = Vec::new();
    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("#") {
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
                cmds.push((line_num + 1, Command::Propose(id)));
            }
            "broadcast" => {
                let id_str = args.get("id").expect("Missing id for broadcast");
                let id = id_str.parse::<u32>().expect("Invalid id");
                cmds.push((line_num + 1, Command::Broadcast(id)));
            }
            "reply" => {
                let id_str = args.get("id").expect("Missing id for reply");
                let id = id_str.parse::<u32>().expect("Invalid id");
                cmds.push((line_num + 1, Command::Reply(id)));
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
                    cmds.push((line_num + 1, Command::Collect(id, thresh, delay)));
                } else {
                    cmds.push((line_num + 1, Command::Wait(id, thresh, delay)));
                }
            }
            _ => panic!("Unknown command: {command}"),
        }
    }
    cmds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_version() {
        let version = crate_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_mean() {
        assert_eq!(mean(&[]), 0.0);
        assert_eq!(mean(&[1.0]), 1.0);
        assert_eq!(mean(&[1.0, 2.0, 3.0]), 2.0);
        assert_eq!(mean(&[10.0, 20.0, 30.0]), 20.0);
    }

    #[test]
    fn test_median() {
        assert_eq!(median(&mut []), 0.0);
        assert_eq!(median(&mut [5.0]), 5.0);
        assert_eq!(median(&mut [1.0, 3.0, 2.0]), 2.0);
        assert_eq!(median(&mut [1.0, 2.0, 3.0, 4.0]), 2.5);
        assert_eq!(median(&mut [4.0, 1.0, 3.0, 2.0, 5.0]), 3.0);
    }

    #[test]
    fn test_std_dev() {
        assert_eq!(std_dev(&[]), None);
        assert_eq!(std_dev(&[1.0]), Some(0.0));

        let result = std_dev(&[1.0, 2.0, 3.0, 4.0, 5.0]);
        assert!(result.is_some());
        let std = result.unwrap();
        assert!((std - std::f64::consts::SQRT_2).abs() < 1e-10);
    }

    #[test]
    fn test_calculate_threshold() {
        assert_eq!(calculate_threshold(&Threshold::Count(5), 10), 5);
        assert_eq!(calculate_threshold(&Threshold::Percent(0.5), 10), 5);
    }

    #[test]
    fn test_populate_latency_map() {
        let p50_data = BTreeMap::from([(
            "us-east-1".to_string(),
            BTreeMap::from([
                ("us-west-1".to_string(), 50.0),
                ("eu-west-1".to_string(), 100.0),
            ]),
        )]);
        let p50 = CloudPing { data: p50_data };
        let p90_data = BTreeMap::from([(
            "us-east-1".to_string(),
            BTreeMap::from([
                ("us-west-1".to_string(), 80.0),
                ("eu-west-1".to_string(), 150.0),
            ]),
        )]);
        let p90 = CloudPing { data: p90_data };

        let result = populate_latency_map(p50, p90);
        assert_eq!(result.len(), 1);
        let us_east = &result["us-east-1"];
        assert_eq!(us_east["us-west-1"], (50.0, 30.0)); // P50=50, jitter=P90-P50=30
        assert_eq!(us_east["eu-west-1"], (100.0, 50.0)); // P50=100, jitter=P90-P50=50
    }

    #[test]
    fn test_parse_task_simple_commands() {
        let content = r#"
# This is a comment
propose id=1
broadcast id=2
reply id=3
"#;

        let commands = parse_task(content);
        assert_eq!(commands.len(), 3);

        match &commands[0].1 {
            Command::Propose(id) => assert_eq!(*id, 1),
            _ => panic!("Expected Propose command"),
        }

        match &commands[1].1 {
            Command::Broadcast(id) => assert_eq!(*id, 2),
            _ => panic!("Expected Broadcast command"),
        }

        match &commands[2].1 {
            Command::Reply(id) => assert_eq!(*id, 3),
            _ => panic!("Expected Reply command"),
        }
    }

    #[test]
    fn test_parse_task_collect_command() {
        let content = "collect id=1 threshold=75%";
        let commands = parse_task(content);
        assert_eq!(commands.len(), 1);

        match &commands[0].1 {
            Command::Collect(id, threshold, delay) => {
                assert_eq!(*id, 1);
                match threshold {
                    Threshold::Percent(p) => assert_eq!(*p, 0.75),
                    _ => panic!("Expected Percent threshold"),
                }
                assert!(delay.is_none());
            }
            _ => panic!("Expected Collect command"),
        }
    }

    #[test]
    fn test_parse_task_wait_with_delay() {
        let content = "wait id=2 threshold=5 delay=(0.5,1.0)";
        let commands = parse_task(content);
        assert_eq!(commands.len(), 1);

        match &commands[0].1 {
            Command::Wait(id, threshold, delay) => {
                assert_eq!(*id, 2);
                match threshold {
                    Threshold::Count(c) => assert_eq!(*c, 5),
                    _ => panic!("Expected Count threshold"),
                }
                assert!(delay.is_some());
                let (msg, comp) = delay.unwrap();
                assert_eq!(msg, Duration::from_secs_f64(0.5));
                assert_eq!(comp, Duration::from_secs_f64(1.0));
            }
            _ => panic!("Expected Wait command"),
        }
    }

    #[test]
    fn test_parse_task_empty_and_comments() {
        let content = r#"
# Comment line

# Another comment
propose id=1

# Final comment
"#;

        let commands = parse_task(content);
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].0, 5); // Line number should be 5
    }

    #[test]
    #[should_panic(expected = "Invalid argument format")]
    fn test_parse_task_invalid_format() {
        let content = "propose invalid_arg_format";
        parse_task(content);
    }

    #[test]
    #[should_panic(expected = "Missing id for propose")]
    fn test_parse_task_missing_id() {
        let content = "propose threshold=50%";
        parse_task(content);
    }

    #[test]
    #[should_panic(expected = "Unknown command")]
    fn test_parse_task_unknown_command() {
        let content = "unknown_command id=1";
        parse_task(content);
    }
}
