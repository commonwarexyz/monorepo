# ADB Sync Example

This example demonstrates how to synchronize ADB (Authenticated Database) operations between a server and client using the commonware framework.

## Overview

The ADB sync example consists of:

- **Server** (`src/bin/server.rs`): Serves ADB operations and proofs to clients
- **Client** (`src/bin/client.rs`): Syncs operations from a server
- **NetworkResolver** (`src/resolver.rs`): Network-based resolver for sync operations
- **Protocol** (`src/protocol.rs`): Network protocol definitions for ADB sync

## Components

### Server

The server creates an ADB database, populates it with initial operations, and serves requests from clients. It listens for TCP connections and responds to `GetOperationsRequest` messages with proofs and operations.

Key features:
- Configurable port and initial operations count
- Handles multiple client connections
- Provides cryptographic proofs for operations

### Client

The client connects to a server and synchronizes operations to build a local replica of the database.

Key features:
- Configurable server address and batch size
- Optional repeated syncing
- Network timeout configuration

### NetworkResolver

Implements the resolver trait for network-based sync operations. It connects to the server, sends requests, and processes responses.

### Protocol

Defines the network protocol for ADB sync communication, including message types, request/response structures, and error handling.

## Building

```bash
cargo build
```

## Running Tests

```bash
cargo test
```

## Usage

### Starting the Server

```bash
# Start server with default settings (port 8080, 100 initial operations)
cargo run --bin server

# Start server with custom settings
cargo run --bin server -- --port 8080 --initial-ops 50 --storage-dir /tmp/my_server
```

Server options:
- `-p, --port <PORT>`: Port to listen on (default: 8080)
- `-i, --initial-ops <COUNT>`: Number of initial operations to create (default: 100)
- `-d, --storage-dir <PATH>`: Storage directory (default: /tmp/adb_sync_server)

### Running the Client

```bash
# Connect to server with default settings
cargo run --bin client

# Connect with custom settings
cargo run --bin client -- --server-address 127.0.0.1:8080 --batch-size 25

# Run with repeated syncing
cargo run --bin client -- --repeat --repeat-interval 5
```

Client options:
- `-s, --server-address <ADDRESS>`: Server address to connect to (default: 127.0.0.1:8080)
- `-b, --batch-size <SIZE>`: Batch size for operations (default: 50)
- `-r, --repeat`: Repeat syncing
- `--repeat-interval <SECONDS>`: Repeat interval in seconds (default: 10)
- `-d, --storage-dir <PATH>`: Storage directory (default: /tmp/adb_sync_client)
- `-t, --network-timeout <SECONDS>`: Network timeout in seconds (default: 30)

## Example Session

1. **Start the server:**
   ```bash
   cargo run --bin server -- --initial-ops 20
   ```

2. **In another terminal, run the client:**
   ```bash
   cargo run --bin client -- --batch-size 10
   ```

3. **For continuous syncing:**
   ```bash
   cargo run --bin client -- --repeat --repeat-interval 30
   ```

## Implementation Details

### Current Status

- ✅ Server: Creates database, inserts data, serves operations to clients so they can sync.
- ✅ Client: Connects to server and syncs to server state
- ✅ NetworkResolver: Network communication infrastructure
- ✅ Protocol: Message definitions and serialization
- ✅ Tests: Unit tests for core functionality

### Network Protocol

The protocol uses JSON over TCP for communication. Messages include:

- `GetOperationsRequest`: Request operations from server
- `GetOperationsResponse`: Response with operations and proofs
- `Error`: Error responses

### Sync Process

1. Client connects to server via TCP
2. Client requests operations starting from its current position
3. Server responds with operations and cryptographic proofs
4. Client verifies proofs and applies operations to local database
5. Process repeats until all operations are synchronized

## Architecture

```
┌─────────────────┐    Network     ┌─────────────────┐
│     Client      │ ◄──────────► │     Server      │
│                 │   Protocol    │                 │
│ - Database      │               │ - Database      │
│ - NetworkResolver│               │ - TCP Listener  │
│ - Sync Logic    │               │ - Request Handler│
└─────────────────┘               └─────────────────┘
```

## Future Enhancements

- [ ] Implement actual sync logic using commonware-storage sync API
- [ ] Add proper proof verification
- [ ] Implement operation deserialization from bytes
- [ ] Add comprehensive error handling
- [ ] Support for different network transports
- [ ] Metrics and monitoring
- [ ] Configuration file support
- [ ] TLS encryption for network communication

## Dependencies

- `commonware-storage`: ADB storage and sync functionality
- `commonware-runtime`: Runtime and context management
- `commonware-codec`: Serialization support
- `commonware-cryptography`: Cryptographic operations
- `tokio`: Async runtime
- `clap`: Command-line argument parsing
- `serde`: Serialization framework
- `tracing`: Logging and diagnostics
