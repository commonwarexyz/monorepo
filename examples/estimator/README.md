# commonware-estimator

[![Crates.io](https://img.shields.io/crates/v/commonware-estimator.svg)](https://crates.io/crates/commonware-estimator)

Simulate mechanism performance under realistic network conditions.

## Overview

`commonware-estimator` shortens the time from idea to data when experimenting with new mechanisms. With a basic DSL, you can simulate the performance of arbitrary mechanisms under realistic network conditions (AWS region-to-region latencies from cloudping.co).

Key features:
- Simulates peers distributed across specified AWS regions with real-world latency/jitter.
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
- Proposer latency (for `collect`).
- Regional latencies (for `wait`).

Finally, it prints averaged results across all proposer simulations.

```
# HotStuff

## Send PREPARE
propose id=0

## Reply to proposer PREPARE with VOTE(PREPARE)
wait id=0 threshold=1 delay=(0.0001,0.001)
    [proposer] mean: 5.80ms (dev: 0.40ms) | median: 6.00ms
    [eu-west-1] mean: 50.80ms (dev: 33.35ms) | median: 73.50ms
    [us-east-1] mean: 37.20ms (dev: 32.05ms) | median: 17.00ms
    [all] mean: 42.64ms (dev: 33.25ms) | median: 18.00ms
reply id=1

## Collect VOTE(PREPARE) from 67% of the network and then broadcast (PRECOMMIT, QC_PREPARE)
collect id=1 threshold=67% delay=(0.0001,0.001)
    [proposer] mean: 151.60ms (dev: 4.41ms) | median: 153.00ms
propose id=1

## Reply to proposer (PRECOMMIT, QC_PREPARE) with VOTE(PRECOMMIT)
wait id=1 threshold=1 delay=(0.0001,0.001)
    [proposer] mean: 158.60ms (dev: 4.41ms) | median: 160.00ms
    [eu-west-1] mean: 200.70ms (dev: 34.08ms) | median: 226.50ms
    [us-east-1] mean: 190.07ms (dev: 32.98ms) | median: 168.00ms
    [all] mean: 194.32ms (dev: 33.83ms) | median: 169.00ms
reply id=2

## Collect VOTE(PRECOMMIT) from 67% of the network and then broadcast (COMMIT, QC_PRECOMMIT)
collect id=2 threshold=67% delay=(0.0001,0.001)
    [proposer] mean: 304.60ms (dev: 2.42ms) | median: 304.00ms
propose id=3

## Wait for proposer (COMMIT, QC_PRECOMMIT)
wait id=3 threshold=1 delay=(0.0001,0.001)
    [proposer] mean: 311.60ms (dev: 2.42ms) | median: 311.00ms
    [eu-west-1] mean: 354.70ms (dev: 31.66ms) | median: 376.00ms
    [us-east-1] mean: 343.27ms (dev: 35.18ms) | median: 320.00ms
    [all] mean: 347.84ms (dev: 34.27ms) | median: 324.00ms
```

## DSL Style Guide

The DSL is a plain text file where each non-empty line represents a command or compound expression. Commands are executed sequentially by each simulated peer, but blocking commands (`wait` and `collect`) pause until their conditions are met. Compound expressions using logical operators are evaluated based on the current state of each peer. Empty lines are ignored.

### General Rules

- Commands are case-sensitive.
- Parameters are specified as `key=value` pairs, separated by spaces.
- No quotes are needed for values unless they contain spaces (but currently, values shouldn't contain spaces).
- Lines must not end with semicolons or other terminators.
- Thresholds can be absolute counts (e.g., `5`) or percentages (e.g., `80%`). Percentages are relative to the total number of peers.
- Delays are optional and specified as `delay=(<message_delay>,<completion_delay>)`, where delays are floats in seconds (e.g., `(0.1,0.2)`). The message delay is incurred for each processed message and completion delay is incurred once after the threshold is met.
- Each command must have a unique `id` (u32) for tracking messages.
- Execution is per-peer: Proposers (current proposer) may behave differently (e.g., in `propose` or `collect`).
- Peers process commands in lockstep but use async selects for receiving messages when blocked on `wait`/`collect`.
- AND (`&&`) has higher precedence than OR (`||`). Use parentheses to override.

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
   - Description: (Proposer-only) Blocks until the threshold number of messages with the given ID are received. Records the latency from simulation start, then advances. Non-proposers skip immediately.
   - Parameters:
     - `id`: Message ID to collect.
     - `threshold`: Count (e.g., `5`) or percentage (e.g., `80%`).
     - `delay` (optional): Sleeps `msg_delay` before checking, and `comp_delay` after threshold met.
   - Example: `collect id=1 threshold=80% delay=(0.0001,0.001)`
   - Use case: Proposer waits for quorum of votes/acks.

5. **wait id=<number> threshold=<threshold> [delay=(<msg_delay>,<comp_delay>)]**
   - Description: (All peers) Blocks until the threshold number of messages with the given ID are received. Records the latency from simulation start, then advances.
   - Parameters: Same as `collect`.
   - Example: `wait id=0 threshold=40%`
   - Use case: Peers wait for a certain fraction of the network to acknowledge or respond.

### Compound Commands with Logical Operators

The DSL supports complex conditional logic using AND (`&&`) and OR (`||`) operators, along with parentheses for grouping.

#### AND Operator (`&&`)
- **Syntax**: `command1 && command2`
- **Behavior**: Advances only when BOTH sub-commands would advance given the current state
- **Example**: `wait id=1 threshold=1 && wait id=2 threshold=1`
- **Use case**: Wait for multiple conditions to be satisfied simultaneously

#### OR Operator (`||`)
- **Syntax**: `command1 || command2`
- **Behavior**: Advances when EITHER sub-command would advance given the current state
- **Example**: `wait id=1 threshold=67% || wait id=2 threshold=1`
- **Use case**: Wait for any one of multiple conditions to be satisfied

#### Parentheses and Precedence
- **Precedence**: AND (`&&`) has higher precedence than OR (`||`)
- **Grouping**: Use parentheses to override precedence and create complex expressions
- **Examples**:
  - `wait id=1 threshold=1 || wait id=2 threshold=1 && wait id=3 threshold=1`
    - Equivalent to: `wait id=1 threshold=1 || (wait id=2 threshold=1 && wait id=3 threshold=1)`
  - `(wait id=1 threshold=1 || wait id=2 threshold=1) && wait id=3 threshold=1`
    - Forces OR to be evaluated first

### Example DSL (hotstuff.lazy)

```
# HotStuff

## Send PREPARE
propose id=0

## Reply to proposer PREPARE with VOTE(PREPARE)
wait id=0 threshold=1 delay=(0.0001,0.001)
reply id=1

## Collect VOTE(PREPARE) from 67% of the network and then broadcast (PRECOMMIT, QC_PREPARE)
collect id=1 threshold=67% delay=(0.0001,0.001)
propose id=1

## Reply to proposer (PRECOMMIT, QC_PREPARE) with VOTE(PRECOMMIT)
wait id=1 threshold=1 delay=(0.0001,0.001)
reply id=2

## Collect VOTE(PRECOMMIT) from 67% of the network and then broadcast (COMMIT, QC_PRECOMMIT)
collect id=2 threshold=67% delay=(0.0001,0.001)
propose id=3

## Wait for proposer (COMMIT, QC_PRECOMMIT)
wait id=3 threshold=1 delay=(0.0001,0.001)
```

## Comparison on Alto-Like Network

To simulate the performance of HotStuff, Simplicity, and Minimmit on an [Alto-like network](https://alto.commonware.xyz), run:

```
cargo run -- --distribution us-west-1:5,us-east-1:5,eu-west-1:5,ap-northeast-1:5,eu-north-1:5,ap-south-1:5,sa-east-1:5,eu-central-1:5,ap-northeast-2:5,ap-southeast-2:5 --task hotstuff.lazy
cargo run -- --distribution us-west-1:5,us-east-1:5,eu-west-1:5,ap-northeast-1:5,eu-north-1:5,ap-south-1:5,sa-east-1:5,eu-central-1:5,ap-northeast-2:5,ap-southeast-2:5 --task simplex.lazy
cargo run -- --distribution us-west-1:5,us-east-1:5,eu-west-1:5,ap-northeast-1:5,eu-north-1:5,ap-south-1:5,sa-east-1:5,eu-central-1:5,ap-northeast-2:5,ap-southeast-2:5 --task minimmit.lazy
```