# commonware-collector-demo

[![Crates.io](https://img.shields.io/crates/v/commonware-collector-demo.svg)](https://crates.io/crates/commonware-collector-demo)

Demonstrate collecting responses from multiple nodes using [commonware-collector](https://crates.io/crates/commonware-collector) and [commonware-p2p](https://crates.io/crates/commonware-p2p).

## Overview

This example demonstrates how to use `commonware-collector` to send queries to multiple nodes and collect their responses. One node acts as an **originator** that sends queries, while other nodes act as **handlers** that process queries and send responses back. The originator uses a **monitor** to track all collected responses.

## Usage (3 Nodes)

_To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install)._

**Important**: Each instance must use a unique port. The format is `--me=<node_id>@<port>` where each node uses a different port number.

### Node 1 (Originator - Bootstrapper)

```sh
cargo run --release -- --me=1@3001 --participants=1,2,3 --role=originator
```

### Node 2 (Handler)

```sh
cargo run --release -- --me=2@3002 --participants=1,2,3 --role=handler --bootstrappers=1@127.0.0.1:3001
```

### Node 3 (Handler)

```sh
cargo run --release -- --me=3@3003 --participants=1,2,3 --role=handler --bootstrappers=1@127.0.0.1:3001
```

**Note**: If you get a "failed to bind listener" error, it means the port is already in use. Make sure:
- Each instance uses a different port number
- No other processes are using the ports (3001, 3002, 3003)
- Previous instances have been properly terminated

## How It Works

1. **Originator**: Sends queries to all handler nodes asking them to compute a value (e.g., multiply a number by 2).
2. **Handlers**: Receive queries, process them, and send responses back.
3. **Monitor**: Collects all responses and displays them as they arrive.

The example demonstrates:
- How to implement a `Handler` trait to process requests
- How to implement a `Monitor` trait to track collected responses
- How to use `collector::p2p::Engine` to coordinate request/response flow
- How responses are collected from multiple nodes concurrently
