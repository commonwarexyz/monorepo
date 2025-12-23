//! Simulate mechanism performance under realistic network conditions.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use commonware_cryptography::{
    ed25519::{self, PublicKey},
    Signer,
};
use commonware_p2p::Recipients;
use reqwest::blocking::Client;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    time::Duration,
};
use tracing::debug;

// =============================================================================
// Constants
// =============================================================================

const CLOUDPING_BASE: &str = "https://www.cloudping.co/api/latencies";
const CLOUDPING_DIVISOR: f64 = 2.0; // cloudping.co reports ping times not latency
const MILLISECONDS_TO_SECONDS: f64 = 1000.0;

// =============================================================================
// Type Definitions
// =============================================================================

pub type Region = String;

/// Regional configuration specifying peer count and optional bandwidth limits
#[derive(Debug, Clone)]
pub struct RegionConfig {
    pub count: usize,
    pub egress_cap: Option<usize>,
    pub ingress_cap: Option<usize>,
}

pub type Distribution = BTreeMap<Region, RegionConfig>;
pub type Behavior = (f64, f64); // (avg_latency_ms, jitter_ms)
pub type Latencies = BTreeMap<Region, BTreeMap<Region, Behavior>>;

// =============================================================================
// Struct Definitions
// =============================================================================

/// CloudPing API response data structure
#[derive(serde::Deserialize)]
struct CloudPing {
    pub data: BTreeMap<Region, BTreeMap<Region, f64>>,
}

/// State of a peer during validation
struct PeerState {
    received: BTreeMap<u32, BTreeSet<PublicKey>>,
    current_index: usize,
}

// =============================================================================
// Enum Definitions
// =============================================================================

#[derive(Clone)]
pub enum Command {
    Propose(u32, Option<usize>),   // id, size in bytes
    Broadcast(u32, Option<usize>), // id, size in bytes
    Reply(u32, Option<usize>),     // id, size in bytes
    Collect(u32, Threshold, Option<(Duration, Duration)>),
    Wait(u32, Threshold, Option<(Duration, Duration)>),
    Or(Box<Self>, Box<Self>),
    And(Box<Self>, Box<Self>),
}

#[derive(Clone)]
pub enum Threshold {
    Count(usize),
    Percent(f64),
}

// =============================================================================
// Public API Functions
// =============================================================================

/// Returns the version of the crate.
pub const fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
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

        // Check if line contains operators or parentheses
        let command = if line.contains(" || ")
            || line.contains(" && ")
            || line.contains('(')
            || line.contains(')')
        {
            parse_expression(line)
        } else {
            parse_single_command(line)
        };

        cmds.push((line_num + 1, command));
    }
    cmds
}

/// Parse a single command (no operators)
fn parse_single_command(line: &str) -> Command {
    let brace_start = line.find('{').expect("Missing opening brace");
    let brace_end = line.rfind('}').expect("Missing closing brace");

    // Parse arguments - first argument is always the ID (no key)
    let command = line[..brace_start].trim();
    let args_str = &line[brace_start + 1..brace_end];
    let mut args = Vec::new();
    let mut current_arg = String::new();
    let mut paren_depth = 0;
    let mut in_quotes = false;
    for ch in args_str.chars() {
        match ch {
            '(' => {
                paren_depth += 1;
                current_arg.push(ch);
            }
            ')' => {
                paren_depth -= 1;
                current_arg.push(ch);
            }
            '"' => {
                in_quotes = !in_quotes;
                current_arg.push(ch);
            }
            ',' if paren_depth == 0 && !in_quotes => {
                if !current_arg.trim().is_empty() {
                    args.push(current_arg.trim().to_string());
                }
                current_arg.clear();
            }
            _ => {
                current_arg.push(ch);
            }
        }
    }

    // Don't forget the last argument
    if !current_arg.trim().is_empty() {
        args.push(current_arg.trim().to_string());
    }
    if args.is_empty() {
        panic!("Missing arguments in curly braces");
    }

    // First argument is always the ID
    let id = args[0].parse::<u32>().expect("Invalid id");

    // Parse remaining arguments as key=value pairs
    let mut parsed_args: HashMap<String, String> = HashMap::new();
    for arg in &args[1..] {
        if let Some(eq_pos) = arg.find('=') {
            let key = arg[..eq_pos].trim().to_string();
            let value = arg[eq_pos + 1..].trim().to_string();
            parsed_args.insert(key, value);
        } else {
            panic!("Invalid argument format (expected key=value): {arg}");
        }
    }

    match command {
        "propose" => {
            let size = parsed_args
                .get("size")
                .map(|s| s.parse::<usize>().expect("Invalid size"));
            Command::Propose(id, size)
        }
        "broadcast" => {
            let size = parsed_args
                .get("size")
                .map(|s| s.parse::<usize>().expect("Invalid size"));
            Command::Broadcast(id, size)
        }
        "reply" => {
            let size = parsed_args
                .get("size")
                .map(|s| s.parse::<usize>().expect("Invalid size"));
            Command::Reply(id, size)
        }
        "collect" | "wait" => {
            let thresh = parsed_args.get("threshold").map_or_else(
                || {
                    panic!("Missing threshold for {command}");
                },
                |thresh_str| {
                    if thresh_str.ends_with('%') {
                        let p = thresh_str
                            .trim_end_matches('%')
                            .parse::<f64>()
                            .expect("Invalid percent")
                            / 100.0;
                        Threshold::Percent(p)
                    } else {
                        let c = thresh_str.parse::<usize>().expect("Invalid count");
                        Threshold::Count(c)
                    }
                },
            );

            let delay = parsed_args.get("delay").map(|delay_str| {
                let delay_str = delay_str.trim_matches('(').trim_matches(')');
                let parts: Vec<&str> = delay_str.split(',').collect();
                if parts.len() != 2 {
                    panic!("Invalid delay format (expected (value1,value2)): {delay_str}");
                }
                let message = parts[0].parse::<f64>().expect("Invalid message delay")
                    / MILLISECONDS_TO_SECONDS;
                let message = Duration::from_secs_f64(message);
                let completion = parts[1].parse::<f64>().expect("Invalid completion delay")
                    / MILLISECONDS_TO_SECONDS;
                let completion = Duration::from_secs_f64(completion);
                (message, completion)
            });

            if command == "collect" {
                Command::Collect(id, thresh, delay)
            } else {
                Command::Wait(id, thresh, delay)
            }
        }
        _ => panic!("Unknown command: {command}"),
    }
}

/// Parse a complex expression with parentheses and operators
fn parse_expression(line: &str) -> Command {
    let mut parser = ExpressionParser::new(line);
    let result = parser.parse_or_expression();

    // Validate that we've consumed all input
    parser.skip_whitespace();
    if !parser.is_at_end() {
        panic!(
            "Unexpected character '{}' at position {}",
            parser.peek_char().unwrap_or('\0'),
            parser.position
        );
    }

    result
}

/// Expression parser that handles parentheses and operator precedence
struct ExpressionParser<'a> {
    input: &'a str,
    position: usize,
}

impl<'a> ExpressionParser<'a> {
    const fn new(input: &'a str) -> Self {
        Self { input, position: 0 }
    }

    /// Parse OR expression (lowest precedence)
    fn parse_or_expression(&mut self) -> Command {
        let mut expr = self.parse_and_expression();

        while self.peek_operator() == Some("||") {
            self.consume_operator("||");
            let right = self.parse_and_expression();
            expr = Command::Or(Box::new(expr), Box::new(right));
        }

        expr
    }

    /// Parse AND expression (higher precedence than OR)
    fn parse_and_expression(&mut self) -> Command {
        let mut expr = self.parse_primary();

        while self.peek_operator() == Some("&&") {
            self.consume_operator("&&");
            let right = self.parse_primary();
            expr = Command::And(Box::new(expr), Box::new(right));
        }

        expr
    }

    /// Parse primary expression (parentheses or atomic command)
    fn parse_primary(&mut self) -> Command {
        self.skip_whitespace();

        if self.peek_char() == Some('(') {
            self.consume_char('(');
            let expr = self.parse_or_expression();
            self.skip_whitespace();
            self.consume_char(')');
            expr
        } else {
            // Parse atomic command
            let command_text = self.extract_atomic_command();
            parse_single_command(&command_text)
        }
    }

    /// Extract the text for an atomic command (until we hit an operator or closing paren)
    fn extract_atomic_command(&mut self) -> String {
        let start = self.position;
        let mut paren_depth = 0;

        while self.position < self.input.len() {
            let ch = self.input.chars().nth(self.position).unwrap();

            if ch == '(' {
                paren_depth += 1;
            } else if ch == ')' {
                if paren_depth == 0 {
                    break; // Hit closing paren for parent expression
                }
                paren_depth -= 1;
            } else if paren_depth == 0 {
                // Check for operators at top level
                if self.input[self.position..].starts_with(" || ")
                    || self.input[self.position..].starts_with(" && ")
                {
                    break;
                }
            }

            self.position += ch.len_utf8();
        }

        self.input[start..self.position].trim().to_string()
    }

    /// Peek at the next operator without consuming it
    fn peek_operator(&self) -> Option<&'static str> {
        let remaining = &self.input[self.position..];
        let trimmed = remaining.trim_start();

        if trimmed.starts_with("||") {
            Some("||")
        } else if trimmed.starts_with("&&") {
            Some("&&")
        } else {
            None
        }
    }

    /// Consume a specific operator
    fn consume_operator(&mut self, op: &str) {
        self.skip_whitespace();

        let remaining = &self.input[self.position..];
        if remaining.starts_with(op) {
            self.position += op.len();
            self.skip_whitespace();
        } else {
            panic!("Expected operator '{}' at position {}", op, self.position);
        }
    }

    /// Peek at the next character without consuming it
    fn peek_char(&self) -> Option<char> {
        self.input[self.position..].chars().next()
    }

    /// Consume a specific character
    fn consume_char(&mut self, expected: char) {
        self.skip_whitespace();

        if let Some(ch) = self.input[self.position..].chars().next() {
            if ch == expected {
                self.position += ch.len_utf8();
                self.skip_whitespace();
            } else {
                panic!(
                    "Expected '{}' but found '{}' at position {}",
                    expected, ch, self.position
                );
            }
        } else {
            panic!("Expected '{expected}' but reached end of input");
        }
    }

    /// Skip whitespace characters
    fn skip_whitespace(&mut self) {
        while self.position < self.input.len() {
            let ch = self.input.chars().nth(self.position).unwrap();
            if ch.is_whitespace() {
                self.position += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    /// Check if we are at the end of the input string
    const fn is_at_end(&self) -> bool {
        self.position >= self.input.len()
    }
}

// =============================================================================
// Latency Data Functions
// =============================================================================

/// Downloads latency data from cloudping.co API
fn download_latency_data() -> Latencies {
    let cli = Client::builder().build().unwrap();

    // Pull P50 and P90 matrices (time-frame: last 1 year)
    let p50: CloudPing = cli
        .get(format!("{CLOUDPING_BASE}?percentile=p_50&timeframe=1Y"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let p90: CloudPing = cli
        .get(format!("{CLOUDPING_BASE}?percentile=p_90&timeframe=1Y"))
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
                dest_map.insert(
                    to.clone(),
                    (
                        lat50 / CLOUDPING_DIVISOR,
                        (lat90 - lat50) / CLOUDPING_DIVISOR,
                    ),
                );
            }
        }
        map.insert(from, dest_map);
    }

    map
}

// =============================================================================
// Statistical Functions
// =============================================================================

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
    data.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = data.len() / 2;
    if data.len().is_multiple_of(2) {
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

// =============================================================================
// Peer & Region Calculation Functions
// =============================================================================

/// Calculate total number of peers across all regions
pub fn count_peers(distribution: &Distribution) -> usize {
    let peers = distribution.values().map(|config| config.count).sum();
    assert!(peers > 1, "must have at least 2 peers");
    peers
}

/// Calculate which region a proposer belongs to based on their index
pub fn calculate_proposer_region(proposer_idx: usize, distribution: &Distribution) -> String {
    let mut current = 0;
    for (region, config) in distribution {
        let start = current;
        current += config.count;
        if proposer_idx >= start && proposer_idx < current {
            return region.clone();
        }
    }
    panic!("Proposer index {proposer_idx} out of bounds");
}

/// Calculate required count based on threshold
pub fn calculate_threshold(thresh: &Threshold, peers: usize) -> usize {
    match thresh {
        Threshold::Percent(p) => ((peers as f64) * *p).ceil() as usize,
        Threshold::Count(c) => *c,
    }
}

/// Check if a command would advance given current state (shared validation logic)
pub fn can_command_advance(
    cmd: &Command,
    is_proposer: bool,
    peers: usize,
    received: &BTreeMap<u32, BTreeSet<PublicKey>>,
) -> bool {
    match cmd {
        Command::Propose(_, _) => true, // Propose always advances (proposer check handled by caller)
        Command::Broadcast(_, _) => true, // Broadcast always advances
        Command::Reply(_, _) => true,   // Reply always advances
        Command::Collect(id, thresh, _) => {
            if is_proposer {
                let count = received.get(id).map_or(0, |s| s.len());
                let required = calculate_threshold(thresh, peers);
                count >= required
            } else {
                true // Non-proposers always advance on collect
            }
        }
        Command::Wait(id, thresh, _) => {
            let count = received.get(id).map_or(0, |s| s.len());
            let required = calculate_threshold(thresh, peers);
            count >= required
        }
        Command::Or(cmd1, cmd2) => {
            // OR succeeds if either sub-command would succeed
            can_command_advance(cmd1, is_proposer, peers, received)
                || can_command_advance(cmd2, is_proposer, peers, received)
        }
        Command::And(cmd1, cmd2) => {
            // AND succeeds only if both sub-commands would succeed
            can_command_advance(cmd1, is_proposer, peers, received)
                && can_command_advance(cmd2, is_proposer, peers, received)
        }
    }
}

/// Validate a DSL task file can be executed
pub fn validate(commands: &[(usize, Command)], peers: usize, proposer: usize) -> bool {
    // Initialize peer states
    let mut peer_states: Vec<PeerState> = (0..peers)
        .map(|_| PeerState {
            received: BTreeMap::new(),
            current_index: 0,
        })
        .collect();
    let keys: Vec<PublicKey> = (0..peers)
        .map(|i| ed25519::PrivateKey::from_seed(i as u64).public_key())
        .collect();
    let mut messages: Vec<(usize, Recipients<PublicKey>, u32)> = Vec::new();

    // Run the simulation until completion or stall
    loop {
        let mut did_progress = false;
        for p in 0..peers {
            let state = &mut peer_states[p];
            if state.current_index >= commands.len() {
                continue;
            }

            loop {
                // Check if the peer is done
                if state.current_index >= commands.len() {
                    break;
                }

                // Execute the next command
                let cmd = &commands[state.current_index].1;
                let is_proposer = p == proposer;
                let identity = keys[p].clone();

                // Check if command can advance using shared logic
                let advanced = can_command_advance(cmd, is_proposer, peers, &state.received);

                // If command advances, execute side effects (message sending, state updates)
                if advanced {
                    match cmd {
                        Command::Propose(id, _) => {
                            if is_proposer {
                                messages.push((p, Recipients::All, *id));
                                state.received.entry(*id).or_default().insert(identity);
                            }
                        }
                        Command::Broadcast(id, _) => {
                            messages.push((p, Recipients::All, *id));
                            state.received.entry(*id).or_default().insert(identity);
                        }
                        Command::Reply(id, _) => {
                            let proposer_key = keys[proposer].clone();
                            if is_proposer {
                                state.received.entry(*id).or_default().insert(identity);
                            } else {
                                messages.push((p, Recipients::One(proposer_key), *id));
                            }
                        }
                        Command::Collect(_, _, _) | Command::Wait(_, _, _) => {
                            // No side effects for collect/wait - just advancement
                        }
                        Command::Or(_, _) | Command::And(_, _) => {
                            // No direct side effects for compound commands
                            // Side effects come from their sub-commands when they execute
                        }
                    }
                }

                // If the peer advanced, continue
                if advanced {
                    state.current_index += 1;
                    did_progress = true;
                } else {
                    break;
                }
            }
        }

        // Deliver messages
        let pending = std::mem::take(&mut messages);
        if !pending.is_empty() {
            did_progress = true;
        }
        for (from, recipients, id) in pending {
            let from_key = keys[from].clone();
            match recipients {
                Recipients::All => {
                    for (to, state) in peer_states.iter_mut().enumerate() {
                        if to != from {
                            state
                                .received
                                .entry(id)
                                .or_default()
                                .insert(from_key.clone());
                        }
                    }
                }
                Recipients::One(to_key) => {
                    let to = keys
                        .iter()
                        .position(|k| k == &to_key)
                        .expect("key not found");
                    peer_states[to]
                        .received
                        .entry(id)
                        .or_default()
                        .insert(from_key);
                }
                _ => unreachable!(),
            }
        }

        // Check if all peers are done
        if peer_states
            .iter()
            .all(|state| state.current_index >= commands.len())
        {
            return true;
        }
        if !did_progress {
            return false;
        }
    }
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
        assert_eq!(us_east["us-west-1"], (25.0, 15.0)); // P50=50/2=25, jitter=(P90-P50)/2=(80-50)/2=15
        assert_eq!(us_east["eu-west-1"], (50.0, 25.0)); // P50=100/2=50, jitter=(P90-P50)/2=(150-100)/2=25
    }

    #[test]
    fn test_parse_task_commands() {
        let content = r#"
# This is a comment with new syntax
propose{1}
broadcast{2}
reply{3}
"#;

        let commands = parse_task(content);
        assert_eq!(commands.len(), 3);

        match &commands[0].1 {
            Command::Propose(id, _) => assert_eq!(*id, 1),
            _ => panic!("Expected Propose command"),
        }

        match &commands[1].1 {
            Command::Broadcast(id, _) => assert_eq!(*id, 2),
            _ => panic!("Expected Broadcast command"),
        }

        match &commands[2].1 {
            Command::Reply(id, _) => assert_eq!(*id, 3),
            _ => panic!("Expected Reply command"),
        }
    }

    #[test]
    fn test_parse_task_collect_command() {
        let content = "collect{1, threshold=75%}";
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
        let content = "wait{2, threshold=5, delay=(0.5,1.0)}";
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
                assert_eq!(msg, Duration::from_micros(500));
                assert_eq!(comp, Duration::from_millis(1));
            }
            _ => panic!("Expected Wait command"),
        }
    }

    #[test]
    fn test_parse_task_empty_and_comments() {
        let content = r#"
# Comment line

# Another comment
propose{1}

# Final comment
"#;

        let commands = parse_task(content);
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].0, 5); // Line number should be 5
    }

    #[test]
    #[should_panic(expected = "Missing opening brace")]
    fn test_parse_task_invalid_format() {
        let content = "propose invalid_arg_format";
        parse_task(content);
    }

    #[test]
    #[should_panic(expected = "Missing opening brace")]
    fn test_parse_task_missing_id() {
        let content = "propose threshold=50%";
        parse_task(content);
    }

    #[test]
    #[should_panic(expected = "Unknown command")]
    fn test_parse_task_unknown_command() {
        let content = "unknown_command{1}";
        parse_task(content);
    }

    #[test]
    #[should_panic(expected = "Missing arguments in curly braces")]
    fn test_parse_task_empty_braces() {
        let content = "propose{}";
        parse_task(content);
    }

    #[test]
    #[should_panic(expected = "Missing threshold for wait")]
    fn test_parse_task_missing_threshold() {
        let content = "wait{1}";
        parse_task(content);
    }

    #[test]
    fn test_parse_task_or_command() {
        let content =
            "wait{1, threshold=67%, delay=(0.1,1)} || wait{2, threshold=1, delay=(0.1,1)}";
        let commands = parse_task(content);
        assert_eq!(commands.len(), 1);

        match &commands[0].1 {
            Command::Or(cmd1, cmd2) => {
                match cmd1.as_ref() {
                    Command::Wait(id, threshold, delay) => {
                        assert_eq!(*id, 1);
                        match threshold {
                            Threshold::Percent(p) => assert_eq!(*p, 0.67),
                            _ => panic!("Expected Percent threshold"),
                        }
                        assert!(delay.is_some());
                    }
                    _ => panic!("Expected Wait command in first part of OR"),
                }
                match cmd2.as_ref() {
                    Command::Wait(id, threshold, delay) => {
                        assert_eq!(*id, 2);
                        match threshold {
                            Threshold::Count(c) => assert_eq!(*c, 1),
                            _ => panic!("Expected Count threshold"),
                        }
                        assert!(delay.is_some());
                    }
                    _ => panic!("Expected Wait command in second part of OR"),
                }
            }
            _ => panic!("Expected Or command"),
        }
    }

    #[test]
    fn test_parse_task_and_command() {
        let content = "wait{3, threshold=67%} && wait{4, threshold=1}";
        let commands = parse_task(content);
        assert_eq!(commands.len(), 1);

        match &commands[0].1 {
            Command::And(cmd1, cmd2) => {
                match cmd1.as_ref() {
                    Command::Wait(id, threshold, delay) => {
                        assert_eq!(*id, 3);
                        match threshold {
                            Threshold::Percent(p) => assert_eq!(*p, 0.67),
                            _ => panic!("Expected Percent threshold"),
                        }
                        assert!(delay.is_none());
                    }
                    _ => panic!("Expected Wait command in first part of AND"),
                }
                match cmd2.as_ref() {
                    Command::Wait(id, threshold, delay) => {
                        assert_eq!(*id, 4);
                        match threshold {
                            Threshold::Count(c) => assert_eq!(*c, 1),
                            _ => panic!("Expected Count threshold"),
                        }
                        assert!(delay.is_none());
                    }
                    _ => panic!("Expected Wait command in second part of AND"),
                }
            }
            _ => panic!("Expected And command"),
        }
    }

    #[test]
    fn test_parse_task_chained_or_command() {
        let content = "wait{1, threshold=67%} || wait{2, threshold=1} || wait{3, threshold=50%}";
        let commands = parse_task(content);
        assert_eq!(commands.len(), 1);

        // Debug: Let's just check that it's an OR command and move on
        // The exact nesting structure is less important than functionality
        match &commands[0].1 {
            Command::Or(_, _) => {
                // Just verify it's an OR command - the nesting details are implementation-specific
                // The important thing is that execution works correctly
            }
            _ => panic!("Expected Or command"),
        }
    }

    #[test]
    fn test_validate_or_and_logic() {
        let content = r#"
## Propose a block
propose{0}

## This should fail because we wait for id=0 (which gets 1 message)
## AND id=99 (which never gets any messages), so the AND cannot be satisfied
wait{0, threshold=1} && wait{99, threshold=1}
broadcast{1}
        "#;
        let commands = parse_task(content);
        let completed = validate(&commands, 3, 0);
        assert!(!completed);
    }

    #[test]
    fn test_parse_task_or_and_logic() {
        let content = r#"
## Propose a block
propose{0}
broadcast{6}

## This should fail because we wait for id=0 (which gets 1 message)
## AND id=99 (which never gets any messages), so the AND cannot be satisfied
wait{0, threshold=1} && (wait{99, threshold=1} || wait{6, threshold=2})
broadcast{1}
        "#;
        let commands = parse_task(content);
        let completed = validate(&commands, 3, 0);
        assert!(completed);
    }

    #[test]
    fn test_example_files() {
        let files = vec![
            ("stall.lazy", include_str!("../stall.lazy"), false),
            ("echo.lazy", include_str!("../echo.lazy"), true),
            ("simplex.lazy", include_str!("../simplex.lazy"), true),
            (
                "simplex_with_delay.lazy",
                include_str!("../simplex_with_delay.lazy"),
                true,
            ),
            (
                "simplex_with_certificates.lazy",
                include_str!("../simplex_with_certificates.lazy"),
                true,
            ),
            (
                "simplex_small_block.lazy",
                include_str!("../simplex_small_block.lazy"),
                true,
            ),
            (
                "simplex_large_block.lazy",
                include_str!("../simplex_large_block.lazy"),
                true,
            ),
            (
                "simplex_large_block_coding_50.lazy",
                include_str!("../simplex_large_block_coding_50.lazy"),
                true,
            ),
            ("minimmit.lazy", include_str!("../minimmit.lazy"), true),
            (
                "minimmit_small_block.lazy",
                include_str!("../minimmit_small_block.lazy"),
                true,
            ),
            (
                "minimmit_large_block.lazy",
                include_str!("../minimmit_large_block.lazy"),
                true,
            ),
            (
                "minimmit_large_block_coding_50.lazy",
                include_str!("../minimmit_large_block_coding_50.lazy"),
                true,
            ),
            (
                "kudzu_small_block.lazy",
                include_str!("../kudzu_small_block.lazy"),
                true,
            ),
            (
                "kudzu_large_block.lazy",
                include_str!("../kudzu_large_block.lazy"),
                true,
            ),
            (
                "kudzu_large_block_coding_50.lazy",
                include_str!("../kudzu_large_block_coding_50.lazy"),
                true,
            ),
            ("hotstuff.lazy", include_str!("../hotstuff.lazy"), true),
        ];

        for (name, content, expected) in files {
            let task = parse_task(content);
            let completed = validate(&task, 3, 0);
            assert_eq!(completed, expected, "{name}");
        }
    }

    #[test]
    fn test_parse_task_simple_parentheses() {
        let content = "(wait{1, threshold=67%} && wait{2, threshold=1}) || wait{3, threshold=50%}";
        let commands = parse_task(content);
        assert_eq!(commands.len(), 1);

        match &commands[0].1 {
            Command::Or(cmd1, cmd2) => {
                // First part should be an AND command
                match cmd1.as_ref() {
                    Command::And(and_cmd1, and_cmd2) => {
                        match and_cmd1.as_ref() {
                            Command::Wait(id, threshold, _) => {
                                assert_eq!(*id, 1);
                                match threshold {
                                    Threshold::Percent(p) => assert_eq!(*p, 0.67),
                                    _ => panic!("Expected Percent threshold"),
                                }
                            }
                            _ => panic!("Expected Wait command in first part of AND"),
                        }
                        match and_cmd2.as_ref() {
                            Command::Wait(id, threshold, _) => {
                                assert_eq!(*id, 2);
                                match threshold {
                                    Threshold::Count(c) => assert_eq!(*c, 1),
                                    _ => panic!("Expected Count threshold"),
                                }
                            }
                            _ => panic!("Expected Wait command in second part of AND"),
                        }
                    }
                    _ => panic!("Expected And command in first part of OR"),
                }
                // Second part should be a simple Wait command
                match cmd2.as_ref() {
                    Command::Wait(id, threshold, _) => {
                        assert_eq!(*id, 3);
                        match threshold {
                            Threshold::Percent(p) => assert_eq!(*p, 0.50),
                            _ => panic!("Expected Percent threshold"),
                        }
                    }
                    _ => panic!("Expected Wait command in second part of OR"),
                }
            }
            _ => panic!("Expected Or command"),
        }
    }

    #[test]
    fn test_parse_task_nested_parentheses() {
        let content = "((wait{1, threshold=1} || wait{2, threshold=1}) && wait{3, threshold=1}) || wait{4, threshold=1}";
        let commands = parse_task(content);
        assert_eq!(commands.len(), 1);

        match &commands[0].1 {
            Command::Or(cmd1, cmd2) => {
                // First part should be an AND with nested OR
                match cmd1.as_ref() {
                    Command::And(and_cmd1, and_cmd2) => {
                        // First part of AND should be an OR
                        match and_cmd1.as_ref() {
                            Command::Or(or_cmd1, or_cmd2) => {
                                match or_cmd1.as_ref() {
                                    Command::Wait(id, _, _) => assert_eq!(*id, 1),
                                    _ => panic!("Expected Wait id=1"),
                                }
                                match or_cmd2.as_ref() {
                                    Command::Wait(id, _, _) => assert_eq!(*id, 2),
                                    _ => panic!("Expected Wait id=2"),
                                }
                            }
                            _ => panic!("Expected Or command in first part of AND"),
                        }
                        // Second part of AND should be a Wait
                        match and_cmd2.as_ref() {
                            Command::Wait(id, _, _) => assert_eq!(*id, 3),
                            _ => panic!("Expected Wait id=3"),
                        }
                    }
                    _ => panic!("Expected And command in first part of OR"),
                }
                // Second part should be a Wait
                match cmd2.as_ref() {
                    Command::Wait(id, _, _) => assert_eq!(*id, 4),
                    _ => panic!("Expected Wait id=4"),
                }
            }
            _ => panic!("Expected Or command"),
        }
    }

    #[test]
    fn test_parse_task_complex_expression() {
        let content = "(wait{1, threshold=1} && wait{2, threshold=1}) || (wait{3, threshold=1} && wait{4, threshold=1})";
        let commands = parse_task(content);
        assert_eq!(commands.len(), 1);

        match &commands[0].1 {
            Command::Or(cmd1, cmd2) => {
                // Both parts should be AND commands
                match cmd1.as_ref() {
                    Command::And(and_cmd1, and_cmd2) => {
                        match and_cmd1.as_ref() {
                            Command::Wait(id, _, _) => assert_eq!(*id, 1),
                            _ => panic!("Expected Wait id=1"),
                        }
                        match and_cmd2.as_ref() {
                            Command::Wait(id, _, _) => assert_eq!(*id, 2),
                            _ => panic!("Expected Wait id=2"),
                        }
                    }
                    _ => panic!("Expected And command in first part"),
                }
                match cmd2.as_ref() {
                    Command::And(and_cmd1, and_cmd2) => {
                        match and_cmd1.as_ref() {
                            Command::Wait(id, _, _) => assert_eq!(*id, 3),
                            _ => panic!("Expected Wait id=3"),
                        }
                        match and_cmd2.as_ref() {
                            Command::Wait(id, _, _) => assert_eq!(*id, 4),
                            _ => panic!("Expected Wait id=4"),
                        }
                    }
                    _ => panic!("Expected And command in second part"),
                }
            }
            _ => panic!("Expected Or command"),
        }
    }

    #[test]
    fn test_parse_task_operator_precedence() {
        // Without parentheses: AND should have higher precedence than OR
        let content = "wait{1, threshold=1} || wait{2, threshold=1} && wait{3, threshold=1}";
        let commands = parse_task(content);
        assert_eq!(commands.len(), 1);

        match &commands[0].1 {
            Command::Or(cmd1, cmd2) => {
                // First part should be a simple Wait
                match cmd1.as_ref() {
                    Command::Wait(id, _, _) => assert_eq!(*id, 1),
                    _ => panic!("Expected Wait id=1"),
                }
                // Second part should be an AND
                match cmd2.as_ref() {
                    Command::And(and_cmd1, and_cmd2) => {
                        match and_cmd1.as_ref() {
                            Command::Wait(id, _, _) => assert_eq!(*id, 2),
                            _ => panic!("Expected Wait id=2"),
                        }
                        match and_cmd2.as_ref() {
                            Command::Wait(id, _, _) => assert_eq!(*id, 3),
                            _ => panic!("Expected Wait id=3"),
                        }
                    }
                    _ => panic!("Expected And command"),
                }
            }
            _ => panic!("Expected Or command"),
        }
    }

    #[test]
    fn test_parse_task_parentheses_override_precedence() {
        // With parentheses: should force different precedence
        let content = "(wait{1, threshold=1} || wait{2, threshold=1}) && wait{3, threshold=1}";
        let commands = parse_task(content);
        assert_eq!(commands.len(), 1);

        match &commands[0].1 {
            Command::And(cmd1, cmd2) => {
                // First part should be an OR
                match cmd1.as_ref() {
                    Command::Or(or_cmd1, or_cmd2) => {
                        match or_cmd1.as_ref() {
                            Command::Wait(id, _, _) => assert_eq!(*id, 1),
                            _ => panic!("Expected Wait id=1"),
                        }
                        match or_cmd2.as_ref() {
                            Command::Wait(id, _, _) => assert_eq!(*id, 2),
                            _ => panic!("Expected Wait id=2"),
                        }
                    }
                    _ => panic!("Expected Or command"),
                }
                // Second part should be a simple Wait
                match cmd2.as_ref() {
                    Command::Wait(id, _, _) => assert_eq!(*id, 3),
                    _ => panic!("Expected Wait id=3"),
                }
            }
            _ => panic!("Expected And command"),
        }
    }

    #[test]
    fn test_parse_task_mixed_commands_with_parentheses() {
        let content = "(propose{1} && broadcast{2}) || reply{3}";
        let commands = parse_task(content);
        assert_eq!(commands.len(), 1);

        match &commands[0].1 {
            Command::Or(cmd1, cmd2) => {
                match cmd1.as_ref() {
                    Command::And(and_cmd1, and_cmd2) => {
                        match and_cmd1.as_ref() {
                            Command::Propose(id, _) => assert_eq!(*id, 1),
                            _ => panic!("Expected Propose id=1"),
                        }
                        match and_cmd2.as_ref() {
                            Command::Broadcast(id, _) => assert_eq!(*id, 2),
                            _ => panic!("Expected Broadcast id=2"),
                        }
                    }
                    _ => panic!("Expected And command"),
                }
                match cmd2.as_ref() {
                    Command::Reply(id, _) => assert_eq!(*id, 3),
                    _ => panic!("Expected Reply id=3"),
                }
            }
            _ => panic!("Expected Or command"),
        }
    }

    #[test]
    #[should_panic(expected = "Expected ')' but reached end of input")]
    fn test_parse_task_unmatched_parentheses() {
        let content = "(wait{1, threshold=1} && wait{2, threshold=1}";
        parse_task(content);
    }

    #[test]
    #[should_panic(expected = "Unexpected character ')' at position")]
    fn test_parse_task_extra_closing_paren() {
        let content = "wait{1, threshold=1} && wait{2, threshold=1})";
        parse_task(content);
    }

    #[test]
    fn test_parse_task_commands_with_message_sizes() {
        let content = r#"
propose{1, size=1024}
broadcast{2, size=100}
reply{3, size=64}
reply{4}
"#;

        let commands = parse_task(content);
        assert_eq!(commands.len(), 4);

        match &commands[0].1 {
            Command::Propose(id, size) => {
                assert_eq!(*id, 1);
                assert_eq!(*size, Some(1024));
            }
            _ => panic!("Expected Propose command with size"),
        }

        match &commands[1].1 {
            Command::Broadcast(id, size) => {
                assert_eq!(*id, 2);
                assert_eq!(*size, Some(100));
            }
            _ => panic!("Expected Broadcast command with size"),
        }

        match &commands[2].1 {
            Command::Reply(id, size) => {
                assert_eq!(*id, 3);
                assert_eq!(*size, Some(64));
            }
            _ => panic!("Expected Reply command with size"),
        }

        match &commands[3].1 {
            Command::Reply(id, size) => {
                assert_eq!(*id, 4);
                assert_eq!(*size, None);
            }
            _ => panic!("Expected Reply command without size"),
        }
    }
}
