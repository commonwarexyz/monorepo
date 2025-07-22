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
cargo run --bin server -- --port 8080 --initial-ops 50 --storage-dir /tmp/my_server --metrics-port 9090 --op-interval 2s --ops-per-interval 10
```

Server options:
- `-p, --port <PORT>`: Port to listen on (default: 8080)
- `-i, --initial-ops <COUNT>`: Number of initial operations to create (default: 100)
- `-d, --storage-dir <PATH>`: Storage directory for database (default: /tmp/commonware-sync/server-{RANDOM_SUFFIX})
- `-m, --metrics-port <PORT>`: Port on which metrics are exposed (default: 9090)
- `-t, --op-interval <DURATION>`: Interval for adding new operations in 's' or 'ms' (default: 100ms)
- `-o, --ops-per-interval <COUNT>`: Number of operations to add each interval (default: 5)

### Running the Client

```bash
# Connect to server with default settings
cargo run --bin client

# Connect with custom settings
cargo run --bin client -- --server 127.0.0.1:8080 --batch-size 25 --storage-dir /tmp/my_client --metrics-port 9091 --target-update-interval 3s
```

Client options:
- `-s, --server <ADDRESS>`: Server address to connect to (default: 127.0.0.1:8080)
- `-b, --batch-size <SIZE>`: Batch size for fetching operations (default: 50)
- `-d, --storage-dir <PATH>`: Storage directory for local database (default: /tmp/commonware-sync/client-{RANDOM_SUFFIX})
- `-m, --metrics-port <PORT>`: Port on which metrics are exposed (default: 9091)
- `-t, --target-update-interval <DURATION>`: Interval for requesting target updates in 's' or 'ms' (default: 1s)

## Example Session

1. **Start the server:**
   ```bash
   cargo run --bin server -- --initial-ops 50 --op-interval 2s --ops-per-interval 3
   ```

   You should see output like:
   ```
   INFO initializing database
   INFO creating initial operations operations_len=56
   INFO database ready op_count=112 root=8837dd38704093f65b8c9ca4041daa57b3df20fac95474a86580f57bd6ee6bd9
   INFO server listening and continuously adding operations addr=127.0.0.1:8080 op_interval=2s ops_per_interval=3
   INFO added operations operations_added=4 root=c63b04a06ea36be9e7b82a2f70b28578fd940e8b8f5b8d616bfafa7471508514
   ```

2. **In another terminal, run the client:**
   ```bash
   cargo run --bin client -- --batch-size 25 --target-update-interval 3s
   ```

   You should see output like:
   ```
   INFO starting sync to server server=127.0.0.1:8080
   INFO establishing connection server_addr=127.0.0.1:8080
   INFO connected server_addr=127.0.0.1:8080
   INFO initial sync target target=SyncTarget { root: 234bc873fac6d19f96b172fb910ca51b0acbb94858420ae0c6e5e4fc4cc6e4f3, lower_bound_ops: 74, upper_bound_ops: 144 }
   INFO sync configuration batch_size=25 lower_bound=74 upper_bound=144 target_update_interval=3s
   INFO starting sync
   INFO sync completed successfully target_root=234bc873fac6d19f96b172fb910ca51b0acbb94858420ae0c6e5e4fc4cc6e4f3 lower_bound_ops=74 upper_bound_ops=144 log_size=145 valid_batches_received=3 invalid_batches_received=0
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

1. **Server Setup**: Server starts, populates database with initial operations, and listens for connections
2. **Continuous Operation Generation**: Server continuously adds new operations at the specified interval
3. **Client Connection**: Client establishes connection to server
4. **Initial Sync Target**: Client requests server metadata to determine initial sync target (inactivity floor, size, and digest of the server's database)
5. **Dynamic Target Updates**: Client periodically requests target updates during sync to handle new operations added by the server
6. **Completion**: Client continues until all operations are applied and state matches server's target
7. **Cleanup**: Client disconnects and stops; Server keeps running and adding operations

## Adapting to Production

To keep this example simple and sweet, we've taken some shortcuts that would be inadvisable in production.

### Authenticated Connections

In `sync`, the client simply dials the server and connects. It does not perform any authentication
of the server's identity. In a real application, this may be necessary.

Refer to [chat](../chat/README.md) for an example of using [commonware_p2p::authenticated](https://docs.rs/commonware-p2p/latest/commonware_p2p/authenticated/index.html)
to implement authenticated networking.

### Sourcing a Sync Target

When instantiating the client, it asks the server for a target root digest to sync to. During the sync, the client periodically
requests sync target updates from the server.

In a real application, the client should source this information from a trusted source (like a [commonware_consensus::threshold_simplex](https://docs.rs/commonware-consensus/latest/commonware_consensus/threshold_simplex/index.html)
consensus certificate) and only use the server for data that can be cryptographically verified against
this target root digest.

### Rate Limiting

The current implementation doesn't implement rate limiting for target update requests. In production,
you should implement appropriate rate limiting to prevent excessive server load.
