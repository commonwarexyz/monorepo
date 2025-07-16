# commonware-estimator

[![Crates.io](https://img.shields.io/crates/v/commonware-estimator.svg)](https://crates.io/crates/commonware-estimator)

## Overview

The Commonware Estimator is a tool for estimating the latency of distributed systems protocols under realistic network conditions. It uses a simulated peer-to-peer network with latency and jitter data derived from AWS regions (sourced from cloudping.co). The estimator allows you to define simulation behaviors using a simple Domain-Specific Language (DSL) and runs multiple simulations in parallel, varying the proposer/proposer across peers.

Key features:
- Simulates peers distributed across specified AWS regions with real-world latency/jitter.
- Supports defining simulation tasks via a DSL file.
- Outputs latency statistics (mean, median, std dev) for key points in the simulation, both per-proposer and averaged across all runs.
- Deterministic runtime for reproducible results.

The simulator models message passing (proposes, broadcasts, replies) and waiting/collecting thresholds, making it suitable for testing consensus algorithms like HotStuff or other broadcast-based protocols.

## Usage

Build and run the simulator using Cargo:

```
cargo run -- [OPTIONS]
```

### Command-Line Options

- `--distribution <DISTRIBUTION>` (required): Specify the distribution of peers across regions in the format `<region>:<count>`, comma-separated. Example: `us-east-1:10,eu-west-1:5`. Regions must match AWS regions from the latency data (e.g., us-east-1, eu-west-1).
- `--task <PATH>` (required): Path to the DSL file defining the simulation behavior (e.g., `minimmit.lazy`).
- `--reload-latency-data` (optional flag): Download fresh latency data from cloudping.co instead of using embedded data.

### Example

```
cargo run -- --distribution us-east-1:3,eu-west-1:2 --task examples/estimator/hotstuff.lazy
```

This runs simulations with 5 peers (3 in us-east-1, 2 in eu-west-1), using the DSL from `minimmit.lazy`.

### Output

For each possible proposer (peer index), the simulator prints:
- The DSL lines with interleaved latency statistics for `wait` and `collect` commands.
- Proposer latencies (for `collect`).
- Regional latencies (mean, median, std dev in ms) for `wait`.

Finally, it prints averaged results across all proposer simulations.

## DSL Style Guide

The DSL is a plain text file where each non-empty line represents a command. Commands are executed sequentially by each simulated peer, but blocking commands (`wait` and `collect`) pause until their conditions are met. Empty lines are ignored.

### General Rules
- Commands are case-sensitive.
- Parameters are specified as `key=value` pairs, separated by spaces.
- No quotes are needed for values unless they contain spaces (but currently, values shouldn't contain spaces).
- Lines must not end with semicolons or other terminators.
- Comments are not supported; keep the file clean.
- Thresholds can be absolute counts (e.g., `5`) or percentages (e.g., `80%`). Percentages are relative to the total number of peers.
- Delays are optional and specified as `delay=(<message_delay>,<completion_delay>)`, where delays are floats in seconds (e.g., `(0.1,0.2)`). The message delay is slept before checking the threshold, and completion delay after the threshold is met.
- Each command must have a unique `id` (u32) for tracking messages.
- Execution is per-peer: Leaders (current proposer) may behave differently (e.g., in `propose` or `collect`).
- Peers process commands in lockstep but use async selects for receiving messages when blocked on `wait`/`collect`.

### Supported Commands

1. **propose id=<number>**
   - Description: If the peer is the current proposer, sends a proposal message with the given ID to all peers (including self). Non-proposers skip this but advance.
   - Parameters:
     - `id`: Unique message identifier (u32).
   - Example: `propose id=0`
   - Use case: Initiate a proposal in proposer-based protocols.

2. **broadcast id=<number>**
   - Description: Broadcasts a message with the given ID to all peers (including self).
   - Parameters:
     - `id`: Unique message identifier (u32).
   - Example: `broadcast id=1`
   - Use case: Disseminate information to the entire network.

3. **reply id=<number>**
   - Description: If not the proposer, sends a reply message with the given ID directly to the proposer. If the proposer, just records its own receipt.
   - Parameters:
     - `id`: Unique message identifier (u32).
   - Example: `reply id=2`
   - Use case: Respond to a proposer's proposal or broadcast.

4. **collect id=<number> threshold=<threshold> [delay=(<msg_delay>,<comp_delay>)]**
   - Description: (Leader-only) Blocks until the threshold number of messages with the given ID are received. Records the latency from simulation start, then advances. Non-proposers skip immediately.
   - Parameters:
     - `id`: Message ID to collect.
     - `threshold`: Count (e.g., `5`) or percentage (e.g., `80%`).
     - `delay` (optional): Sleeps `msg_delay` before checking, and `comp_delay` after threshold met.
   - Example: `collect id=1 threshold=80% delay=(0.0001,0.001)`
   - Use case: Leader waits for quorum of votes/acks.

5. **wait id=<number> threshold=<threshold> [delay=(<msg_delay>,<comp_delay>)]**
   - Description: (All peers) Blocks until the threshold number of messages with the given ID are received. Records the latency from simulation start, then advances.
   - Parameters: Same as `collect`.
   - Example: `wait id=0 threshold=40%`
   - Use case: Peers wait for a certain fraction of the network to acknowledge or respond.

### Best Practices
- Use unique IDs across the DSL to avoid message confusion.
- Start with simple thresholds (e.g., absolute counts) for small networks.
- Include delays to simulate processing time; keep them small for fast simulations.
- Test with small peer counts first to validate DSL logic.
- For percentages, note that they are ceiled (e.g., 80% of 5 peers = ceil(4) = 4).
- Avoid infinite loops; ensure waits/collects can eventually complete based on prior sends.
- Example file (`hotstuff.lazy`):
  ```
  propose id=0
  wait id=0 threshold=1 delay=(0.0001,0.001)
  broadcast id=1
  wait id=1 threshold=40% delay=(0.0001,0.001)
  wait id=1 threshold=80% delay=(0.0001,0.001)
  ```

This DSL allows modeling protocols like echo broadcasts, quorums, or multi-phase consensus with realistic network delays.

## Comparison on Alto-Like Network

```
cargo run -- --distribution us-west-1:5,us-east-1:5,eu-west-1:5,ap-northeast-1:5,eu-north-1:5,ap-south-1:5,sa-east-1:5,eu-central-1:5,ap-northeast-2:5,ap-southeast-2:5 --task hotstuff.lazy
```