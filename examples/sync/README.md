# commonware-sync

 [![Crates.io](https://img.shields.io/crates/v/commonware-sync.svg)](https://crates.io/crates/commonware-sync) 
 [![Docs.rs](https://docs.rs/commonware-sync/badge.svg)](https://docs.rs/commonware-sync) 

In this example, a client synchronizes a new [adb::any::Any](https://docs.rs/commonware-storage/latest/commonware_storage/adb/any/struct.Any.html) database to the server's database state.

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
cargo run --bin server -- --port 8080 --initial-ops 50 --storage-dir /tmp/my_server --seed 1337 --metrics-port 9090
```

Server options:
- `-p, --port <PORT>`: Port to listen on (default: 8080)
- `-i, --initial-ops <COUNT>`: Number of initial operations to create (default: 100)
- `-d, --storage-dir <PATH>`: Storage directory (default: /tmp/commonware-sync/server)
- `-s, --seed <SEED>`: Seed for generating test operations (default: 1337)
- `-m, --metrics-port <PORT>`: Port on which metrics are exposed (default: 9090)

### Running the Client

```bash
# Connect to server with default settings
cargo run --bin client

# Connect with custom settings
cargo run --bin client -- --server 127.0.0.1:8080 --batch-size 25 --storage-dir /tmp/my_client --metrics-port 9091
```

Client options:
- `-s, --server <ADDRESS>`: Server address to connect to (default: 127.0.0.1:8080)
- `-b, --batch-size <SIZE>`: Batch size for fetching operations (default: 50)
- `-d, --storage-dir <PATH>`: Storage directory (default:/tmp/commonware-sync/client)
- `-m, --metrics-port <PORT>`: Port on which metrics are exposed (default: 9091)

## Example Session

1. **Start the server:**
   ```bash
   cargo run --bin server -- --initial-ops 50
   ```
   
   You should see output like:
   ```
   INFO  Sync Server starting
   INFO  Configuration port=8080 initial_ops=50 storage_dir=/tmp/adb_sync_server seed=1337 metrics_port=9091
   INFO  Initializing database
   INFO  Database ready op_count=51 root_hash=abc123...
   INFO  Server listening addr=127.0.0.1:8080
   ```

2. **In another terminal, run the client:**
   ```bash
   cargo run --bin client -- --batch-size 25
   ```
   
   You should see output like:
   ```
   INFO Sync Client starting
   INFO Configuration server=127.0.0.1:8080 batch_size=25 storage_dir=/tmp/adb_sync_client metrics_port=9090
   INFO Starting sync to server's database state server=127.0.0.1:8080
   INFO Establishing connection server_addr=127.0.0.1:8080
   INFO Connected server_addr=127.0.0.1:8080
   INFO Received server metadata
   INFO Beginning sync operation...
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

1. Server starts, populates database, listening for connections
2. Client establishes connection to server
3. Client requests server metadata to determine sync target
4. Client repeatedly fetches, applies operations served by Server
5. Client continues until all operations applied, state matches Server
6. Client disconnects and stops; Server keeps running

## Notes About Production Usage

For the sake of making this example short, straightforward, and to the point, we've taken some 
expedients that would be inadvisable in a production system.

### Authenticated Connections

In this example, the client simply dials the server and connects. It does not do any authentication
of the server's identity. In a real application, this may be necessary.

Look at the [chat](../chat/README.md) example to see how to use Commonware networking primitives
like [commonware_p2p::authenticated](https://docs.rs/commonware-p2p/latest/commonware_p2p/authenticated/index.html) 
to do authenticated networking.

### Trusting the Server

In typical usage, the server is untrusted, which is the reason the client uses cryptographic proofs
to verify the data it receives from the server. 
In this example, however, the client trusts the server to provide it the correct target root hash.
In a real application, the client should get the target information from a trusted source such as,
for example, a chain state.