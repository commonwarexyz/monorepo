# commonware-sync

 [![Crates.io](https://img.shields.io/crates/v/commonware-sync.svg)](https://crates.io/crates/commonware-sync)

Continuously synchronize state between a server and client with [qmdb::any::Any](https://docs.rs/commonware-storage/latest/commonware_storage/qmdb/any/struct.Any.html) and [qmdb::immutable::Immutable](https://docs.rs/commonware-storage/latest/commonware_storage/qmdb/immutable/struct.Immutable.html)

## Components

- [Server](src/bin/server.rs): Serves historical operations and proofs to clients.
- [Client](src/bin/client.rs): Continuously syncs to the server's database state.
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
- `--db <any|immutable>`: Database type to use. Must be 'any' or 'immutable' (default: any)
- `-p, --port <PORT>`: Port to listen on (default: 8080)
- `-i, --initial-ops <COUNT>`: Number of initial operations to create (default: 100)
- `-d, --storage-dir <PATH>`: Storage directory for database (default: /tmp/commonware-sync/server-{RANDOM_SUFFIX})
- `-m, --metrics-port <PORT>`: Port on which metrics are exposed (default: 9090)
- `-t, --op-interval <DURATION>`: Interval for adding new operations ('ms', 's', 'm', 'h') (default: 100ms)
- `-o, --ops-per-interval <COUNT>`: Number of operations to add each interval (default: 5)

### Running the Client

```bash
# Connect to server with default settings
cargo run --bin client

# Connect with custom settings
cargo run --bin client -- --server 127.0.0.1:8080 --batch-size 25 --storage-dir /tmp/my_client --metrics-port 9091 --target-update-interval 3s --sync-interval 5s
```

Client options:
- `--db <any|immutable>`: Database type to use. Must be 'any' or 'immutable' (default: any)
- `-s, --server <ADDRESS>`: Server address to connect to (default: 127.0.0.1:8080)
- `-b, --batch-size <SIZE>`: Batch size for fetching operations (default: 50)
- `-d, --storage-dir <PATH>`: Storage directory for local database (default: /tmp/commonware-sync/client-{RANDOM_SUFFIX})
- `-m, --metrics-port <PORT>`: Port on which metrics are exposed (default: 9091)
- `-t, --target-update-interval <DURATION>`: Interval for requesting target updates ('ms', 's', 'm', 'h') (default: 1s)
- `-i, --sync-interval <DURATION>`: Interval between sync operations ('ms', 's', 'm', 'h') (default: 10s)

_The client must use the same `--db` as the server it syncs from._

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
   cargo run --bin client -- --batch-size 25 --target-update-interval 3s --sync-interval 5s
   ```

   You should see output like:
   ```
   INFO starting continuous sync process
   INFO starting sync sync_iteration=1 target=SyncTarget { root: 234bc873fac6d19f96b172fb910ca51b0acbb94858420ae0c6e5e4fc4cc6e4f3, lower_bound_ops: 74, upper_bound_ops: 144 } server=127.0.0.1:8080 batch_size=25 target_update_interval=3s
   INFO ✅ sync completed successfully sync_iteration=1 database_ops=145 root=234bc873fac6d19f96b172fb910ca51b0acbb94858420ae0c6e5e4fc4cc6e4f3 sync_interval=5s
   INFO starting sync sync_iteration=2 target=SyncTarget { root: a47d3c2e8b1f9c045e6d2b8a7c9f1e4d3a6b5c8e2f4a7d1e9c2b5a8f3e6d9c2b, lower_bound_ops: 74, upper_bound_ops: 162 } server=127.0.0.1:8080 batch_size=25 target_update_interval=3s
   INFO ✅ sync completed successfully sync_iteration=2 database_ops=163 root=a47d3c2e8b1f9c045e6d2b8a7c9f1e4d3a6b5c8e2f4a7d1e9c2b5a8f3e6d9c2b sync_interval=5s
   ...
   ```

   The client will continue syncing indefinitely, with each iteration showing a new sync_iteration value.

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
3. **Client Startup**: Client starts continuous sync process
4. **Sync Iteration Loop**: For each sync iteration:
   - **Database Initialization**: Client opens a new database (or reopens existing one)
   - **Connection**: Client establishes connection to server
   - **Initial Sync Target**: Client requests server metadata to determine sync target (inactivity floor, size, and root digest)
   - **Dynamic Target Updates**: Client periodically requests target updates during sync to handle new operations added by the server
   - **Sync Completion**: Client continues until all operations are applied and state matches server's target
   - **Database Closure**: Client closes the database to prepare for next iteration
   - **Wait Period**: Client waits for the configured sync interval before starting next iteration
5. **Continuous Operation**: This process continues indefinitely, allowing the client to stay synchronized with the ever-changing server state

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

In a real application, the client should source this information from a trusted source (like a [commonware_consensus::simplex](https://docs.rs/commonware-consensus/latest/commonware_consensus/simplex/index.html)
consensus certificate) and only use the server for data that can be cryptographically verified against
this target root digest.

### Rate Limiting

The current implementation doesn't implement rate limiting for target update requests. In production,
you should implement appropriate rate limiting to prevent excessive server load.
