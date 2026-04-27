# commonware-sync

 [![Crates.io](https://img.shields.io/crates/v/commonware-sync.svg)](https://crates.io/crates/commonware-sync)

Continuously synchronize state between a server and client using either:

- `full` sync: replay authenticated operations into `qmdb::any`, `qmdb::current`, `qmdb::immutable`, or `qmdb::keyless`
- `compact` sync: serve compact authenticated state from full or compact `qmdb::immutable` / `qmdb::keyless` sources into compact targets

## Components

- [Server](src/bin/server.rs): Serves either full replay data or compact authenticated state.
- [Client](src/bin/client.rs): Continuously syncs to the server's database state.
- [Network layer](src/net): Shared request/response protocol and resolver implementation.

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
# Start a full-sync server with default settings
cargo run --bin server

# Start a compact-sync server backed by a full immutable database
cargo run --bin server -- --mode compact --family immutable --storage full

# Start a compact-sync server backed by a compact-storage immutable database
cargo run --bin server -- --mode compact --family immutable --storage compact
```

Server options:
- `--mode <full|compact>`: Sync mode to demonstrate (default: `full`)
- `--family <any|current|immutable|keyless>`: Database family to use for the selected mode (default: `any`)
- `--storage <full|compact>`: Backing storage used by compact-mode servers. Only valid with `--mode compact`; when omitted there, `full` is used
- `-p, --port <PORT>`: Port to listen on (default: 8080)
- `-i, --initial-ops <COUNT>`: Number of initial operations to create (default: 100)
- `-d, --storage-dir <PATH>`: Storage directory for database (default: /tmp/commonware-sync/server-{RANDOM_SUFFIX})
- `-m, --metrics-port <PORT>`: Port on which metrics are exposed (default: 9090)
- `-t, --op-interval <DURATION>`: Interval for adding new operations ('ms', 's', 'm', 'h') (default: 100ms)
- `-o, --ops-per-interval <COUNT>`: Number of operations to add each interval (default: 5)

### Running the Client

```bash
# Connect to a full-sync server with default settings
cargo run --bin client

# Connect to a compact-sync server for immutable state
cargo run --bin client -- --mode compact --family immutable
```

Client options:
- `--mode <full|compact>`: Sync mode to demonstrate (default: `full`)
- `--family <any|current|immutable|keyless>`: Database family to use for the selected mode (default: `any`)
- `-s, --server <ADDRESS>`: Server address to connect to (default: 127.0.0.1:8080)
- `-b, --batch-size <SIZE>`: Batch size for fetching operations in `full` mode (default: 50)
- `-d, --storage-dir <PATH>`: Storage directory for local database (default: /tmp/commonware-sync/client-{RANDOM_SUFFIX})
- `-m, --metrics-port <PORT>`: Port on which metrics are exposed (default: 9091)
- `-t, --target-update-interval <DURATION>`: Interval for requesting target updates in `full` mode ('ms', 's', 'm', 'h') (default: 1s)
- `-i, --sync-interval <DURATION>`: Interval between sync operations ('ms', 's', 'm', 'h') (default: 10s)
- `-r, --max-outstanding-requests <COUNT>`: Maximum in-flight replay requests in `full` mode (default: 1)

### Supported mode/database combinations

- Client:
  - `--mode full --family any`
  - `--mode full --family current`
  - `--mode full --family immutable`
  - `--mode full --family keyless`
  - `--mode compact --family immutable`
  - `--mode compact --family keyless`
- Server:
  - `--mode full --family any`
  - `--mode full --family current`
  - `--mode full --family immutable`
  - `--mode full --family keyless`
  - `--mode compact --family immutable --storage full`
  - `--mode compact --family immutable --storage compact`
  - `--mode compact --family keyless --storage full`
  - `--mode compact --family keyless --storage compact`

The important distinction is between:

- the sync **mode** (`full` vs `compact`)
- the database **family** (`any`, `current`, `immutable`, `keyless`)
- the compact-server backing **storage** (`full` vs `compact`)

- In `full` mode, the client downloads and replays authenticated operations into a full database.
- In `compact` mode, the client does **not** store historical operations. Instead it downloads the
  latest authenticated compact state and materializes a compact-storage target.

That means:

- a compact-sync **server** may be backed by either a full or compact `immutable` / `keyless`
  database, selected via `--storage`
- a compact-sync **client** always materializes into compact storage:
  - `--mode compact --family immutable` creates a compact immutable target
  - `--mode compact --family keyless` creates a compact keyless target

Compact sync can therefore flow:

- from full `immutable` / `keyless` into compact `immutable` / `keyless`
- from compact `immutable` / `keyless` into compact `immutable` / `keyless`

But it cannot flow from compact storage back into a full database, because compact storage keeps
only the current authenticated frontier and witness, not the historical operations required for
full replay sync.

## Example Session

### Full sync

Full sync is the "download history and replay it" path. The server keeps a full database with
authenticated operations, and the client incrementally fetches those operations plus proofs until
it has reconstructed the same full database state locally.

1. **Start the server:**
   ```bash
   cargo run --bin server -- --mode full --family any --initial-ops 50 --op-interval 2s --ops-per-interval 3
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
   cargo run --bin client -- --mode full --family any --batch-size 25 --target-update-interval 3s --sync-interval 5s
   ```

   In full mode, the client must use the same database family as the server because it is replaying
   the server's operation stream into the matching local implementation.

   You should see output like:
   ```
   INFO starting continuous sync process
   INFO starting sync sync_iteration=1 target=SyncTarget { root: 234bc873fac6d19f96b172fb910ca51b0acbb94858420ae0c6e5e4fc4cc6e4f3, lower_bound_ops: 74, upper_bound_ops: 144 } server=127.0.0.1:8080 batch_size=25 target_update_interval=3s
   INFO ✅ sync completed successfully sync_iteration=1 database_ops=145 root=234bc873fac6d19f96b172fb910ca51b0acbb94858420ae0c6e5e4fc4cc6e4f3 sync_interval=5s
   INFO starting sync sync_iteration=2 target=SyncTarget { root: a47d3c2e8b1f9c045e6d2b8a7c9f1e4d3a6b5c8e2f4a7d1e9c2b5a8f3e6d9c2b, lower_bound_ops: 74, upper_bound_ops: 162 } server=127.0.0.1:8080 batch_size=25 target_update_interval=3s
   INFO ✅ sync completed successfully sync_iteration=2 database_ops=163 root=a47d3c2e8b1f9c045e6d2b8a7c9f1e4d3a6b5c8e2f4a7d1e9c2b5a8f3e6d9c2b sync_interval=5s
   ...
   ```

### Compact sync

Compact sync is the "jump directly to the latest authenticated state" path. Instead of replaying
historical operations, the client fetches only the current compact authenticated state and
materializes a compact-storage database locally.

1. **Start the compact server:**
   ```bash
   cargo run --bin server -- --mode compact --family immutable --storage full --initial-ops 50 --op-interval 2s --ops-per-interval 3
   ```

   Here the server is using a full immutable database as the source for compact sync. A compact
   sync source may use either `--storage full` or `--storage compact`, as long as it can serve the
   latest compact authenticated state.

2. **Run the compact client:**
   ```bash
   cargo run --bin client -- --mode compact --family immutable --sync-interval 5s
   ```

   The compact client fetches the latest compact target, downloads the authenticated frontier and
   last-commit witness, verifies the result, persists it into a compact-storage local database, then
   repeats after `--sync-interval`.

   Unlike full sync, the compact client is not reconstructing local history. After sync completes,
   the local database stores the current compact authenticated state, but not the full sequence of
   historical operations that produced it.

## Metrics

Both the server and client expose Prometheus metrics:
- Server metrics: `http://localhost:9090/metrics` (configurable with `--metrics-port`)
- Client metrics: `http://localhost:9091/metrics` (configurable with `--metrics-port`)

To fetch server metrics (using default port):
```bash
curl http://localhost:9090/metrics
```

## Sync Process

### Full mode

1. Server initializes a full database and keeps appending authenticated operations.
2. Client requests an initial sync target.
3. Client replays authenticated batches while periodically polling for newer targets.
4. Client persists the replayed database and repeats after `--sync-interval`.

### Compact mode

1. Server initializes either a full or compact-storage `immutable` / `keyless` database.
2. Client requests the latest compact target.
3. Client fetches compact authenticated state: frontier, pinned nodes, last commit operation, and proof.
4. Client reconstructs a compact-storage database that stores no historical operations, verifies the
   resulting root, persists it, and repeats after `--sync-interval`.

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

The current implementation does not implement rate limiting. In production, you should add
appropriate request limits and backpressure to avoid excessive server load.
