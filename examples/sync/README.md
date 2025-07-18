# commonware-sync

 [![Crates.io](https://img.shields.io/crates/v/commonware-sync.svg)](https://crates.io/crates/commonware-sync)

Synchronize state between a server and client with [adb::any::Any](https://docs.rs/commonware-storage/latest/commonware_storage/adb/any/struct.Any.html).

## Components

- [Server](src/bin/server.rs): Serves historical operations and proofs to clients.
- [Client](src/bin/client.rs): Starting from an empty database, syncs to the server's database state.
- [Resolver](src/resolver.rs): Used by client to communicate with server.
- [Protocol](src/protocol.rs): Defines network messages.

## Usage

### Build

```bash
cargo build
```

### Run Tests

```bash
cargo test
```

### Running the Server

```bash
# Start server with default settings (port 8080, 100 initial operations)
cargo run --bin server

# Start server with custom settings
cargo run --bin server -- --port 8080 --initial-ops 50 --storage-dir /tmp/my_server --seed 1337 --metrics-port 9090 --operation-interval 5 --ops-per-interval 10
```

Server options:
- `-p, --port <PORT>`: Port to listen on (default: 8080)
- `-i, --initial-ops <COUNT>`: Number of initial operations to create (default: 100)
- `-d, --storage-dir <PATH>`: Storage directory (default: /tmp/commonware-sync/server)
- `-s, --seed <SEED>`: Seed for generating test operations (default: 1337)
- `-m, --metrics-port <PORT>`: Port on which metrics are exposed (default: 9090)
- `-t, --operation-interval <SECONDS>`: Interval for adding new operations (default: 5)
- `-o, --ops-per-interval <COUNT>`: Number of operations to add each interval (default: 10)

### Running the Client

```bash
# Connect to server with default settings
cargo run --bin client

# Connect with custom settings
cargo run --bin client -- --server 127.0.0.1:8080 --batch-size 25 --storage-dir /tmp/my_client --metrics-port 9091 --target-update-interval 3
```

Client options:
- `-s, --server <ADDRESS>`: Server address to connect to (default: 127.0.0.1:8080)
- `-b, --batch-size <SIZE>`: Batch size for fetching operations (default: 50)
- `-d, --storage-dir <PATH>`: Storage directory (default: /tmp/commonware-sync/client)
- `-m, --metrics-port <PORT>`: Port on which metrics are exposed (default: 9091)
- `-t, --target-update-interval <SECONDS>`: Interval for requesting target updates (default: 3)

## Example Session

1. **Start the server:**
   ```bash
   cargo run --bin server -- --initial-ops 50
   ```

   You should see output like:
   ```
   INFO  Sync Server starting
   INFO  Configuration port=8080 initial_ops=50 storage_dir=/tmp/commonware-sync/server seed=1337 metrics_port=9090 operation_interval=5 ops_per_interval=10
   INFO  Initializing database
   INFO  Database ready op_count=51 root_hash=abc123...
   INFO  Server listening - will continuously add operations addr=127.0.0.1:8080 operation_interval=5 ops_per_interval=10
   ```

2. **In another terminal, run the client:**
   ```bash
   cargo run --bin client -- --batch-size 25 --target-update-interval 3
   ```

   You should see output like:
   ```
   INFO Sync Client starting
   INFO Configuration server=127.0.0.1:8080 batch_size=25 storage_dir=/tmp/commonware-sync/client metrics_port=9091 target_update_interval=3
   INFO Starting sync to server's database state server=127.0.0.1:8080
   INFO Establishing connection server_addr=127.0.0.1:8080
   INFO Connected server_addr=127.0.0.1:8080
   INFO Received server metadata
   INFO Sync configuration - will check for target updates every 3 seconds batch_size=25 lower_bound=0 upper_bound=50 target_update_interval=3
   INFO Beginning sync operation...
   INFO Target unchanged from server
   INFO ✅ Sync completed successfully database_ops=51 root_hash=abc123...
   ```

## Metrics

Both the server and client expose Prometheus metrics:
- Server metrics: `http://localhost:9090/metrics` (configurable with `--metrics-port`)
- Client metrics: `http://localhost:9091/metrics` (configurable with `--metrics-port`)

To fetch server metrics (using default port):
```bash
curl http://localhost:9090/metrics
```

## Sync Process

1. **Server Setup**: Server starts, populates database, and listens for connections
2. **Client Connection**: Client establishes connection to server
3. **Initial Sync Target**: Client requests server metadata to determine initial sync target
4. **Dynamic Target Updates**: Client periodically requests target updates during sync
5. **Completion**: Client continues until all operations applied, state matches server's latest target
6. **Cleanup**: Client disconnects and stops; Server keeps running

## Adapting to Production

To keep this example simple and sweet, we've taken some shortcuts that would be inadvisable in production.

### Authenticated Connections

In `sync`, the client simply dials the server and connects. It does not perform any authentication
of the server's identity. In a real application, this may be necessary.

Refer to [chat](../chat/README.md) for an example of using [commonware_p2p::authenticated](https://docs.rs/commonware-p2p/latest/commonware_p2p/authenticated/index.html)
to implement authenticated networking.

### Sourcing a Sync Target

When instantiating the client, it asks the server for a target root hash (to sync to) and periodically
requests updates.

In a real application, the client should source this information from a trusted source (like a [commonware_consensus::threshold_simplex](https://docs.rs/commonware-consensus/latest/commonware_consensus/threshold_simplex/index.html)
consensus certificate) and only use the server for data that can be cryptographically verified against
this target root hash.

### Rate Limiting

The current implementation doesn't implement rate limiting for target update requests. In production,
you should implement appropriate rate limiting to prevent excessive server load.
