# commonware-broadcast-example

[![Crates.io](https://img.shields.io/crates/v/commonware-broadcast-example.svg)](https://crates.io/crates/commonware-broadcast-example) <!-- TODO: Update badge if this example gets published -->

This example demonstrates a simple broadcast scenario using `commonware-broadcast`. One node acts as a designated broadcaster, sending a message to all other participating nodes, which act as receivers.

# Usage

_To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install)._

The application uses several command-line arguments:
- `--me <ID@HOST:PORT>`: Sets the identity and listening address of the current node (e.g., `0@127.0.0.1:3000`). The ID is a u64.
- `--participants <ID1,ID2,...>`: A comma-separated list of all participant IDs (u64) in the network, including the broadcaster. All nodes must be aware of all other participating nodes for the P2P layer.
- `--broadcaster <ID>`: The u64 ID of the node that will act as the message broadcaster.
- `--bootstrappers <ID1@HOST1:PORT1,ID2@HOST2:PORT2,...>`: (Optional) Comma-separated list of peer addresses to connect to for network discovery. Typically, one node starts without bootstrappers, and others use its address.
- `--storage-dir <PATH>`: Specifies a directory for storing runtime data (e.g., P2P network information).

## Example Setup (Node 0 as Broadcaster)

Let's assume we have three participants: 0, 1, and 2. Node 0 will be the broadcaster.

### Node 0 (Broadcaster)

This node starts first and does not need bootstrappers initially (it becomes a bootstrapper for others).

```bash
cargo run --release --bin commonware-broadcast-example -- \
  --me 0@127.0.0.1:3000 \
  --participants 0,1,2 \
  --broadcaster 0 \
  --storage-dir /tmp/commonware-broadcast/0
```

**Explanation:**
- `--me 0@127.0.0.1:3000`: Node 0 listens on port 3000.
- `--participants 0,1,2`: Nodes 0, 1, and 2 are part of this network.
- `--broadcaster 0`: This node (ID 0) is the broadcaster.
- `--storage-dir /tmp/commonware-broadcast/0`: Storage for node 0.

### Node 1 (Receiver)

This node connects to Node 0 (the bootstrapper) to join the network.

```bash
cargo run --release --bin commonware-broadcast-example -- \
  --bootstrappers 0@127.0.0.1:3000 \
  --me 1@127.0.0.1:3001 \
  --participants 0,1,2 \
  --broadcaster 0 \
  --storage-dir /tmp/commonware-broadcast/1
```

**Explanation:**
- `--bootstrappers 0@127.0.0.1:3000`: Uses Node 0 as a bootstrapper.
- `--me 1@127.0.0.1:3001`: Node 1 listens on port 3001.
- `--participants 0,1,2`: Same participant list.
- `--broadcaster 0`: Node 0 is still the designated broadcaster.
- `--storage-dir /tmp/commonware-broadcast/1`: Storage for node 1.

### Node 2 (Receiver)

Similar to Node 1, this node also connects to Node 0.

```bash
cargo run --release --bin commonware-broadcast-example -- \
  --bootstrappers 0@127.0.0.1:3000 \
  --me 2@127.0.0.1:3002 \
  --participants 0,1,2 \
  --broadcaster 0 \
  --storage-dir /tmp/commonware-broadcast/2
```

**Explanation:**
- `--bootstrappers 0@127.0.0.1:3000`: Uses Node 0 as a bootstrapper.
- `--me 2@127.0.0.1:3002`: Node 2 listens on port 3002.
- `--participants 0,1,2`: Same participant list.
- `--broadcaster 0`: Node 0 is the designated broadcaster.
- `--storage-dir /tmp/commonware-broadcast/2`: Storage for node 2.

After starting all nodes, Node 0 should broadcast a message which Nodes 1 and 2 will receive and log to their console output. The application runs until you stop it with Ctrl-C.
