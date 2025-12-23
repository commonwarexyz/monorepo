# commonware-estimator

[![Crates.io](https://img.shields.io/crates/v/commonware-estimator.svg)](https://crates.io/crates/commonware-estimator)

Simulate mechanism performance under realistic network conditions.

## Overview

`commonware-estimator` shortens the time from idea to data when experimenting with new mechanisms. With a basic DSL, you can simulate the performance of arbitrary mechanisms under realistic network conditions (AWS region-to-region latencies from cloudping.co).

Key features:
- Simulates peers distributed across specified AWS regions with real-world latency/jitter in virtual time.
- Supports defining simulation tasks via a simple DSL with logical operators (AND/OR) and parentheses for complex conditional logic.
- Outputs latency statistics (mean, median, std dev) at intermediate points in the simulation, both per-proposer and averaged across all runs.
- Deterministic runtime for reproducible results.

With built-in handling for message passing (proposes, broadcasts, replies), waiting/collecting thresholds, and compound conditional expressions, it's suitable for testing new consensus algorithms or other broadcast-based protocols.

## Usage

Build and run the simulator using Cargo:

```
cargo run -- [OPTIONS]
```

### Command-Line Options

- `<TASK>` (required): Path to the .lazy file defining the simulation behavior (e.g., `minimmit.lazy`).
- `--distribution <DISTRIBUTION>` (required): Specify the distribution of peers across regions with optional bandwidth limits:
  - `<region>:<count>` (unlimited bandwidth)
  - `<region>:<count>:<egress>/<ingress>` (asymmetric bandwidth)
  - `<region>:<count>:<bandwidth>` (symmetric bandwidth)

  Bandwidth is in bytes per second. Examples:
  - `us-east-1:10,eu-west-1:5` (no bandwidth limits)
  - `us-east-1:3:1000/500,eu-west-1:2:2000` (with bandwidth limits)

  Regions must match AWS regions from the latency data (e.g., us-east-1, eu-west-1).
- `--reload` (optional flag): Download fresh latency data from cloudping.co instead of using embedded data.

### Examples

```
# Basic usage without bandwidth limits
cargo run -- hotstuff.lazy --distribution us-east-1:3,eu-west-1:2

# With bandwidth limits (asymmetric: 1000 B/s egress, 500 B/s ingress for us-east-1; symmetric: 2000 B/s for eu-west-1)
cargo run -- hotstuff.lazy --distribution us-east-1:3:1000/500,eu-west-1:2:2000

# With message sizes for more realistic bandwidth simulation
cargo run -- simplex_with_sizes.lazy --distribution us-east-1:3:1000,eu-west-1:2:2000
```

The first example runs simulations with 5 peers (3 in us-east-1, 2 in eu-west-1) without bandwidth constraints. The second adds bandwidth limits, and the third uses message sizes for more realistic simulations.

### Output

For each possible proposer (peer index), the simulator prints:
- The DSL lines with interleaved latency statistics for `wait` and `collect` commands.
- Proposer latency (for `collect`).
- Regional latencies (for `wait`).

Finally, it prints averaged results across all simulations.

```
# HotStuff

## Send PREPARE
propose{0}

## Reply to proposer PREPARE with VOTE(PREPARE)
wait{0, threshold=1, delay=(0.1,1)}
    [proposer] mean: 0.00ms (stdv: 0.00ms) | median: 0.00ms
    [eu-west-1] mean: 20.90ms (stdv: 16.69ms) | median: 33.00ms
    [us-east-1] mean: 15.27ms (stdv: 15.56ms) | median: 5.00ms
    [all] mean: 17.52ms (stdv: 16.26ms) | median: 5.00ms
reply{1}

## Collect VOTE(PREPARE) from 67% of the network and then broadcast (PRECOMMIT, QC_PREPARE)
collect{1, threshold=67%, delay=(0.1,1)}
    [proposer] mean: 69.80ms (stdv: 1.83ms) | median: 69.00ms
propose{1}

## Reply to proposer (PRECOMMIT, QC_PREPARE) with VOTE(PRECOMMIT)
wait{1, threshold=1, delay=(0.1,1)}
    [proposer] mean: 70.80ms (stdv: 1.83ms) | median: 70.00ms
    [eu-west-1] mean: 91.80ms (stdv: 16.23ms) | median: 101.00ms
    [us-east-1] mean: 85.40ms (stdv: 16.30ms) | median: 76.00ms
    [all] mean: 87.96ms (stdv: 16.57ms) | median: 77.00ms
reply{2}

## Collect VOTE(PRECOMMIT) from 67% of the network and then broadcast (COMMIT, QC_PRECOMMIT)
collect{2, threshold=67%, delay=(0.1,1)}
    [proposer] mean: 139.60ms (stdv: 2.87ms) | median: 140.00ms
propose{3}

## Wait for proposer (COMMIT, QC_PRECOMMIT)
wait{3, threshold=1, delay=(0.1,1)}
    [proposer] mean: 140.60ms (stdv: 2.87ms) | median: 141.00ms
    [eu-west-1] mean: 161.20ms (stdv: 16.59ms) | median: 170.00ms
    [us-east-1] mean: 155.67ms (stdv: 16.09ms) | median: 146.00ms
    [all] mean: 157.88ms (stdv: 16.52ms) | median: 150.00ms
```

## DSL Style Guide

The DSL is a plain text file where each non-empty line represents a command or compound expression. Commands are executed sequentially by each simulated peer, but blocking commands (`wait` and `collect`) pause until their conditions are met. Compound expressions using logical operators are evaluated based on the current state of each peer. Empty lines are ignored.

### General Rules

- Commands are case-sensitive.
- Parameters are specified as `key=value` pairs, separated by commas.
- Lines must not end with semicolons or other terminators.
- Thresholds can be absolute counts (e.g., `5`) or percentages (e.g., `80%`). Percentages are relative to the total number of peers.
- Delays are optional and specified as `delay=(<message_delay>,<completion_delay>)`, where delays are floats in milliseconds (e.g., `(0.1,1)`). The message delay is incurred for each processed message and completion delay is incurred once after the threshold is met.
- Each command must have a unique `id` (u32) for tracking messages.
- Execution is per-peer: Proposers (current proposer) may behave differently (e.g., in `propose` or `collect`).
- Peers process commands in lockstep but use async selects for receiving messages when blocked on `wait`/`collect`.
- AND (`&&`) has higher precedence than OR (`||`). Use parentheses to override.
- If a `wait` or `collect` has a per-message delay and it is used in an AND or OR expression, the delay (in milliseconds) is applied for each check on an incoming message (i.e. the delay is additive).

### Message Sizes and Bandwidth

All message commands (`propose`, `broadcast`, `reply`) support an optional `size` parameter to specify message size in bytes. This allows for more realistic simulations when combined with bandwidth limits:

- **Default behavior**: Without the `size` parameter, messages are 4 bytes (just the message ID)
- **With size parameter**: Messages are padded to the specified size with the ID in the first 4 bytes
- **Bandwidth impact**: Larger messages take longer to transmit over limited bandwidth connections
- **Realistic simulation**: Use message sizes that match your actual protocol (e.g., 1KB block proposals, 64-byte votes)

Example with different message sizes:
```
# 1KB block proposal
propose{0, size=1024}

# Small 64-byte votes
reply{1, size=64}

# Medium 200-byte certificates
broadcast{2, size=200}
```

### Supported Commands

1. **propose{<id>[, size=<size>]}**
   - Description: If the peer is the current proposer, sends a proposal message with the given ID to all peers (including self). Non-proposers skip this but advance.
   - Parameters:
     - `id`: Unique message identifier (u32).
     - `size` (optional): Message size in bytes. If not specified, defaults to 4 bytes (just the ID).
   - Examples:
     - `propose{0}` (4-byte message)
     - `propose{0, size=1024}` (1KB message)
   - Use case: Initiate a proposal in proposer-based protocols.

2. **broadcast{<id>[, size=<size>]}**
   - Description: Broadcasts a message with the given ID to all peers (including self).
   - Parameters:
     - `id`: Unique message identifier (u32).
     - `size` (optional): Message size in bytes. If not specified, defaults to 4 bytes (just the ID).
   - Examples:
     - `broadcast{1}` (4-byte message)
     - `broadcast{1, size=100}` (100-byte message)
   - Use case: Disseminate information to the entire network.

3. **reply{<id>[, size=<size>]}**
   - Description: If not the proposer, sends a reply message with the given ID directly to the proposer. If the proposer, just records its own receipt.
   - Parameters:
     - `id`: Unique message identifier (u32).
     - `size` (optional): Message size in bytes. If not specified, defaults to 4 bytes (just the ID).
   - Examples:
     - `reply{2}` (4-byte message)
     - `reply{2, size=64}` (64-byte message)
   - Use case: Respond to a proposer's proposal or broadcast.

4. **collect{<id>, threshold=<threshold> [, delay=(<msg_delay>,<comp_delay>)]}**
   - Description: (Proposer-only) Blocks until the threshold number of messages with the given ID are received. Records the latency from simulation start, then advances. Non-proposers skip immediately.
   - Parameters:
     - `id`: Message ID to collect.
     - `threshold`: Count (e.g., `5`) or percentage (e.g., `80%`).
     - `delay` (optional): Sleeps `msg_delay` milliseconds before checking, and `comp_delay` milliseconds after threshold met.
   - Example: `collect{1, threshold=80%, delay=(0.1,1)}`
   - Use case: Proposer waits for quorum of votes/acks.

5. **wait{<id>, threshold=<threshold> [, delay=(<msg_delay>,<comp_delay>)]}**
   - Description: (All peers) Blocks until the threshold number of messages with the given ID are received. Records the latency from simulation start, then advances.
   - Parameters: Same as `collect`.
   - Example: `wait{0, threshold=40%}`
   - Use case: Peers wait for a certain fraction of the network to acknowledge or respond.

### Compound Commands with Logical Operators

The DSL supports complex conditional logic using AND (`&&`) and OR (`||`) operators, along with parentheses for grouping.

#### AND Operator (`&&`)
- Syntax: `command1 && command2`
- Behavior: Advances only when BOTH sub-commands would advance given the current state
- Example: `wait{1, threshold=1} && wait{2, threshold=1}`
- Use case: Wait for multiple conditions to be satisfied simultaneously

#### OR Operator (`||`)
- Syntax: `command1 || command2`
- Behavior: Advances when EITHER sub-command would advance given the current state
- Example: `wait{1, threshold=67%} || wait{2, threshold=1}`
- Use case: Wait for any one of multiple conditions to be satisfied

#### Parentheses and Precedence
- Precedence: AND (`&&`) has higher precedence than OR (`||`)
- Grouping: Use parentheses to override precedence and create complex expressions
- Examples:
  - `wait{1, threshold=1} || wait{2, threshold=1} && wait{3, threshold=1}`
    - Equivalent to: `wait{1, threshold=1} || (wait{2, threshold=1} && wait{3, threshold=1})`
  - `(wait{1, threshold=1} || wait{2, threshold=1}) && wait{3, threshold=1}`
    - Forces OR to be evaluated first

## Simulating an Alto-Like Network

To simulate the performance of HotStuff, Simplex, and Minimmit on an [Alto-like Network](https://alto.commonware.xyz), run the following commands:

```
# Basic simulation without bandwidth constraints
cargo run -- --distribution us-west-1:5,us-east-1:5,eu-west-1:5,ap-northeast-1:5,eu-north-1:5,ap-south-1:5,sa-east-1:5,eu-central-1:5,ap-northeast-2:5,ap-southeast-2:5 hotstuff.lazy

# With realistic bandwidth limits (1 Gbps symmetric)
cargo run -- --distribution us-west-1:5:125000000,us-east-1:5:125000000,eu-west-1:5:125000000,ap-northeast-1:5:125000000,eu-north-1:5:125000000,ap-south-1:5:125000000,sa-east-1:5:125000000,eu-central-1:5:125000000,ap-northeast-2:5:125000000,ap-southeast-2:5:125000000 simplex.lazy

# With asymmetric bandwidth (varying by region to simulate different network conditions)
cargo run -- --distribution us-west-1:5:200000000/100000000,us-east-1:5:200000000/100000000,eu-west-1:5:150000000/75000000,ap-northeast-1:5:100000000/50000000 minimmit.lazy
```
