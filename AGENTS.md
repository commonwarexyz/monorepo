# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Repository Overview

Commonware is a Rust library providing high-performance, production-ready distributed systems primitives for adversarial environments. It's organized as a Cargo workspace with many primitives that build on each other (sharing testing infrastructure, types, traits, etc.).

## Essential Commands

### Quick Reference
```bash
# Build entire workspace
cargo build --workspace --all-targets

# Test specific crate
cargo test -p commonware-cryptography

# Test single function
cargo test -p commonware-consensus test_name

# Run benchmarks
cargo bench -p commonware-cryptography

# Update all crate versions
./scripts/bump_versions.sh <new_version>
```

_For linting, formatting, fuzzing, and other CI-related commands, see the [CI/CD Pipeline](#cicd-pipeline) section below._

## Architecture

### Core Primitives
- **broadcast**: Disseminate data over a wide-area network.
- **codec**: Serialize structured data.
- **coding**: Encode data to enable recovery from a subset of fragments.
- **collector**: Collect responses to committable requests.
- **consensus**: Order opaque messages in a Byzantine environment.
- **cryptography**: Generate keys, sign arbitrary messages, and deterministically verify signatures.
- **deployer**: Deploy infrastructure across cloud providers.
- **p2p**: Communicate with authenticated peers over encrypted connections.
- **resolver**: Resolve data identified by a fixed-length key.
- **runtime**: Execute asynchronous tasks with a configurable scheduler.
- **storage**: Persist and retrieve data from an abstract store.
- **stream**: Exchange messages over arbitrary transport.

_More primitives can be found in the [Cargo.toml](Cargo.toml) file (anything with a `commonware-` prefix)._

### Examples
- **alto** (https://github.com/commonwarexyz/alto): A minimal (and wicked fast) blockchain built with the Commonware Library.
- **bridge** (`examples/bridge`): Send succinct consensus certificates between two networks.
- **chat** (`examples/chat`): Send encrypted messages to a group of friends.
- **estimator** (`examples/estimator`): Simulate mechanism performance under realistic network conditions.
- **flood** (`examples/flood`): Spam peers deployed to AWS EC2 with random messages.
- **log** (`examples/log`): Commit to a secret log and agree to its hash.
- **sync** (`examples/sync`): Synchronize state between a server and client.
- **vrf** (`examples/vrf`): Generate bias-resistant randomness with untrusted contributors.

### Key Design Principles
1. **The Simpler The Better**: Code should look obviously correct and contain the minimum features necessary to achieve a goal.
2. **Test Everything**: All code should be designed for deterministic and comprehensive testing. We employ an abstract runtime (`runtime/src/deterministic.rs`) commonly in the repository to drive tests.
3. **Performance Sensitive**: All primitives are optimized for high throughput/low latency.
4. **Adversarial Safety**: All primitives are designed to operate robustly in adversarial environments.
5. **Abstract Runtime**: All code outside the `runtime` primitive must be runtime-agnostic (never import `tokio` directly outside of `runtime/`). When requiring some `runtime`, use the provided traits in `runtime/src/lib.rs`.
6. **Always Commit Complete Code**: When implementing code and writing tests, always implement complete functionality. If there is a large task, implement the simplest possible solution that works and then incrementally improve it.
7. **Own Core Mechanisms**: If a primitive relies heavily on some core mechanism/algorithm, we should implement it rather than relying on external crates.

## Technical Documentation

Extensive technical writing in `docs/blogs/` provides deep insights into design decisions and implementation details:

### Core Concepts
- **introducing-commonware.html**: Overview of the library's philosophy and goals
- **commonware-the-anti-framework.html**: Why Commonware avoids framework patterns

### Primitive Deep Dives
- **commonware-runtime.html**: Abstract runtime design and implementation
- **commonware-cryptography.html**: Cryptographic primitives and safety guarantees
- **commonware-broadcast.html**: Reliable broadcast protocol implementation
- **commonware-deployer.html**: Infrastructure deployment automation

### Algorithms & Data Structures
- **adb-current.html** / **adb-any.html**: Authenticated data broadcast protocols
- **mmr.html**: Merkle Mountain Range implementation
- **minimmit.html**: Minimal commit protocol
- **buffered-signatures.html**: Efficient signature aggregation
- **threshold-simplex.html**: Threshold consensus mechanism

## CI/CD Pipeline

The repository uses GitHub Actions with three main workflows: **Fast** (every push/PR), **Slow** (main/PR, cancellable), and **Coverage** (main/PR).

### Pre-Push Checklist

Run these commands locally before pushing to avoid CI failures:

```bash
# 1. Format and lint (REQUIRED)
cargo +nightly fmt --all
cargo clippy --all-targets --all-features -- -D warnings

# 2. Run tests (REQUIRED)
cargo test --workspace --verbose

# 3. Platform-specific (Linux only, if touching runtime)
cargo test --features commonware-runtime/iouring-storage
cargo test --features commonware-runtime/iouring-network

# 4. Check dependencies (if modified)
cargo +nightly udeps --all-targets

# 5. WASM build (if touching cryptography/utils/storage)
cargo build --target wasm32-unknown-unknown --release -p commonware-cryptography

# 6. Unsafe code (if adding unsafe blocks)
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test --lib <module>::
```

### Extended Checks (before PR)

```bash
# Long-running tests
cargo test --workspace -- --ignored

# Fuzz testing (60 seconds per target)
cd <primitive>/fuzz
cargo +nightly fuzz run <target> -- -max_total_time=60

# Coverage report
cargo llvm-cov --workspace --lcov --output-path lcov.info
```

### CI Matrix
- **OS**: Ubuntu, Windows, macOS
- **Features**: Standard, io_uring storage, io_uring network (Linux only)
- **Toolchain**: Stable (default), Nightly (formatting/fuzzing)

## Testing Strategy
- Unit tests: Core logic validation
- Integration tests: Cross-primitive interaction
- Fuzz tests: Input validation and edge cases
- MIRI tests: Memory safety verification for unsafe code
- Benchmarks: Performance regression detection
- Coverage: Track test coverage with llvm-cov (see CI section)

## Development Workflow
1. Make changes in relevant primitive directory
2. Run `cargo test -p <crate-name>` for quick iteration
3. Run CI fast checks before committing (see CI section above)
4. Use `cargo +nightly fmt` for formatting
5. Run full CI checks locally before creating PR

## Deterministic Async Testing
Exclusively use the deterministic runtime (`runtime/src/deterministic.rs`) for reproducible async tests:
```rust
#[test]
fn test_async_behavior() {
    let executor = deterministic::Runner::seeded(42); // Use seed for reproducibility
    executor.start(|context| async move {
        // Spawn actors with labels for debugging
        let handle = context.with_label("worker").spawn(|context| async move {
            // Actor logic here
            context.sleep(Duration::from_secs(1)).await;
        });

        // Control time explicitly
        context.sleep(Duration::from_millis(100)).await;

        // Use select! for timeouts
        select! {
            result = handle => { /* handle result */ },
            _ = context.sleep(Duration::from_secs(5)) => panic!("timeout"),
        }
    });
}
```

### Advanced Testing Patterns

#### Test Configuration
```rust
// Use deterministic::Config for precise control
let cfg = deterministic::Config::new()
    .with_seed(seed)
    .with_timeout(Some(Duration::from_secs(30)));
let executor = deterministic::Runner::new(cfg);

// Or use timed runner for simpler tests
let executor = deterministic::Runner::timed(Duration::from_secs(30));
```

#### Stateful Recovery Testing
```rust
// Test unclean shutdowns and recovery
let mut prev_ctx = None;
loop {
    let (complete, context) = if let Some(prev_ctx) = prev_ctx {
        deterministic::Runner::from(prev_ctx) // Resume from previous state
    } else {
        deterministic::Runner::timed(Duration::from_secs(30))
    }.start(f);
    
    if complete { break; }
    prev_ctx = Some(context.recover()); // Save state for next iteration
}
```

### Simulated Network Testing
To simulate network operations, use the simulated network (`p2p/src/simulated`):
```rust
let (network, mut oracle) = Network::new(
    context.with_label("network"),
    Config { max_size: 1024 * 1024 }
);
network.start();

// Register multiple channels per peer for different message types
let (pending_sender, pending_receiver) = oracle.register(pk, 0).await.unwrap();
let (recovered_sender, recovered_receiver) = oracle.register(pk, 1).await.unwrap();
let (resolver_sender, resolver_receiver) = oracle.register(pk, 2).await.unwrap();

// Configure network links with realistic conditions
oracle.add_link(pk1, pk2, Link {
    latency: 10.0,      // ms
    jitter: 2.5,        // ms
    success_rate: 0.95, // 95% success
}).await.unwrap();
```

#### Dynamic Network Conditions
```rust
// Test network partitions
fn separated(n: usize, a: usize, b: usize) -> bool {
    let m = n / 2;
    (a < m && b >= m) || (a >= m && b < m)
}
link_validators(&mut oracle, &validators, Action::Unlink, Some(separated)).await;

// Update links dynamically
let degraded_link = Link {
    latency: 3_000.0,  // Simulate slow network
    jitter: 0.0,
    success_rate: 1.0,
};
oracle.update_link(pk1, pk2, degraded_link).await.unwrap();

// Test with lossy networks
let lossy_link = Link {
    latency: 200.0,
    jitter: 150.0,
    success_rate: 0.5,  // 50% packet loss
};
```

### Byzantine Testing Patterns
```rust
// Test Byzantine actors by replacing normal participants
if idx_scheme == 0 {
    // Create Byzantine actor instead of normal engine
    let cfg = mocks::conflicter::Config { /* ... */ };
    let engine = mocks::conflicter::Conflicter::new(context, cfg);
    engine.start(pending);
} else {
    // Normal honest participant
    let engine = Engine::new(context, cfg);
    engine.start(pending, recovered, resolver);
}

// Verify Byzantine behavior is detected
let blocked = oracle.blocked().await.unwrap();
assert!(!blocked.is_empty()); // Byzantine nodes should be blocked
```

### Verification Patterns
```rust
// Use supervisors to monitor and verify distributed behavior
let supervisor = mocks::supervisor::Supervisor::new(config);
let (mut latest, mut monitor) = supervisor.subscribe().await;

// Wait for progress with explicit monitoring
while latest < required_containers {
    latest = monitor.next().await.expect("event missing");
}

// Verify no Byzantine faults occurred
let faults = supervisor.faults.lock().unwrap();
assert!(faults.is_empty());

// Verify determinism across runs
let state1 = slow_and_lossy_links::<MinPk>(seed);
let state2 = slow_and_lossy_links::<MinPk>(seed);
assert_eq!(state1, state2); // Must be deterministic with same seed
```

### Key Testing Patterns
- **Determinism First**: Always verify tests are deterministic with `context.auditor().state()`
- **Label Everything**: Use `context.with_label()` for all actors and spawned tasks
- **Multi-Channel Testing**: Register multiple channels per peer for different message types
- **Progressive Degradation**: Start with ideal conditions, then introduce failures
- **Byzantine Simulation**: Replace honest nodes with Byzantine actors to test fault tolerance
- **State Recovery**: Test crash recovery by saving and restoring context state
- **Network Partitions**: Simulate split-brain scenarios with selective link removal
- **Metric Verification**: Use supervisors or monitors to verify distributed properties

## Storage Testing via Runtime

The deterministic runtime provides a simulated storage backend for testing storage operations without real I/O:

### Basic Storage Operations
```rust
#[test]
fn test_storage_operations() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        // Open a blob in a partition
        let (blob, size) = context
            .open("partition_name", &0u64.to_be_bytes())
            .await
            .expect("Failed to open blob");
        
        // Write data at offset
        blob.write_at(vec![1, 2, 3, 4], 0)
            .await
            .expect("Failed to write");
        
        // Read data from offset
        let data = blob.read_at(vec![0u8; 4], 0)
            .await
            .expect("Failed to read");
        
        // Sync to ensure durability
        blob.sync().await.expect("Failed to sync");
    });
}
```

### Testing Crash Recovery
```rust
#[test]
fn test_crash_recovery() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        // Initialize journal/storage
        let mut journal = Journal::init(context.clone(), cfg)
            .await
            .expect("Failed to init");
        
        // Append data
        journal.append(1, data).await.expect("Failed to append");
        
        // Close to simulate clean shutdown
        journal.close().await.expect("Failed to close");
        
        // Re-initialize to simulate restart
        let journal = Journal::init(context.clone(), cfg)
            .await
            .expect("Failed to re-init");
        
        // Verify data persisted correctly
        let item = journal.get(1, 0).await.expect("Failed to get");
        assert_eq!(item, data);
    });
}
```

### Testing Corruption Handling
```rust
#[test]
fn test_corruption_recovery() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        // Write valid data
        let mut journal = Journal::init(context.clone(), cfg).await.unwrap();
        journal.append(1, valid_data).await.unwrap();
        journal.close().await.unwrap();
        
        // Manually corrupt data
        let (blob, size) = context
            .open(&cfg.partition, &1u64.to_be_bytes())
            .await
            .unwrap();
        
        // Corrupt checksum or truncate data
        blob.write_at(vec![0xFF; 4], size - 4).await.unwrap();
        blob.sync().await.unwrap();
        
        // Re-initialize and verify recovery
        let journal = Journal::init(context.clone(), cfg).await.unwrap();
        
        // Replay should handle corruption gracefully
        let stream = journal.replay(buffer_size).await.unwrap();
        // Verify corrupted items are skipped/truncated
    });
}
```

### Storage Testing Patterns

#### Simulating Partial Writes
```rust
// Test recovery from incomplete writes
let (blob, size) = context.open(&partition, &name).await.unwrap();
blob.resize(size - 1).await.unwrap(); // Simulate partial write
blob.sync().await.unwrap();

// Verify recovery truncates to last valid item
let journal = Journal::init(context, cfg).await.unwrap();
assert_eq!(journal.size().await.unwrap(), expected_size);
```

#### Testing Blob Management
```rust
// Test multiple blob handling
for section in 0..10 {
    journal.append(section, data).await.unwrap();
    journal.sync(section).await.unwrap();
}

// Test pruning old blobs
journal.prune(5).await.unwrap();

// Verify metrics
let buffer = context.encode();
assert!(buffer.contains("tracked 5"));
assert!(buffer.contains("pruned_total 5"));
```

#### Conformance Testing
```rust
// Protect against accidental format changes
#[test]
fn test_storage_conformance() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        // Write known data
        let mut journal = Journal::init(context.clone(), cfg).await.unwrap();
        for i in 0..100 {
            journal.append(1, i).await.unwrap();
        }
        journal.close().await.unwrap();
        
        // Hash blob contents to verify format
        let (blob, size) = context.open(&partition, &name).await.unwrap();
        let buf = blob.read_at(vec![0u8; size as usize], 0).await.unwrap();
        let digest = hash(buf.as_ref());
        
        // Compare against known hash
        assert_eq!(hex(&digest), "expected_hash_value");
    });
}
```

### Key Storage Testing Principles
- **Test Recovery Paths**: Always test crash recovery and restart scenarios
- **Corrupt Data Intentionally**: Test handling of truncated, corrupted, or missing data
- **Verify Metrics**: Check storage metrics (tracked, synced, pruned) after operations
- **Test Edge Cases**: Empty journals, single items, maximum sizes, offset overflows
- **Conformance Testing**: Hash storage format to detect unintended changes
- **Cleanup After Tests**: Use `destroy()` to remove test data
- **Test Pruning**: Verify old data can be safely removed
- **Test Concurrent Access**: Multiple readers/writers on same storage

## Code Style Guide

### Runtime Isolation Rule
**CRITICAL**: All code outside the `runtime` primitive must be runtime-agnostic:
- Never import or use `tokio` directly outside of `runtime/`
- Always use `futures` for async operations
- Use capabilities exported by `runtime` traits for I/O operations
- This ensures all primitives remain portable across different runtime implementations

### Error Handling
Use `thiserror` for all error types:
```rust
#[derive(Error, Debug)]
pub enum Error {
    #[error("descriptive message: {0}")]
    VariantWithContext(String),

    #[error("validation failed: Context({0}), Message({1})")]
    ValidationError(&'static str, &'static str),

    #[error("wrapped: {0}")]
    Wrapped(#[from] OtherError),
}
```

### Documentation
- Use `//!` for module-level docs with Status and Examples sections
- Use `///` for public items with clear descriptions
- Include `# Examples` sections for public APIs
- Document `# Safety` for any unsafe code usage

### Naming Conventions
- **Types**: `PascalCase` (e.g., `PublicKey`, `SignatureSet`)
- **Functions/methods**: `snake_case` (e.g., `verify_signature`, `from_bytes`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `MAX_MESSAGE_SIZE`)
- **Traits**: Action-oriented names (`Signer`, `Verifier`) or `-able` suffix (`Viewable`)

_Generally, we try to minimize the length of functions and variables._

### Trait Patterns
```rust
// Comprehensive trait bounds
pub trait PublicKey: Verifier + Sized + ReadExt + Encode + PartialEq + Array {}

// Extension traits for additional functionality
pub trait PrivateKeyExt: PrivateKey {
    fn from_rng<R: Rng + CryptoRng>(rng: &mut R) -> Self;
}
```

### Async Code
- Use `impl Future<Output = Result<T, Error>> + Send` for async trait methods
- Utilize `commonware_macros::select!` for concurrent operations
- Always add `Send + 'static` bounds for async traits

### Test Organization
```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Helper functions first
    fn setup_test_environment() -> TestEnv { }

    // Tests with descriptive names
    #[test]
    fn test_specific_behavior() { }

    #[test]
    #[should_panic(expected = "error message")]
    fn test_panic_condition() { }
}
```

### Module Structure
- Keep `mod.rs` minimal with re-exports
- Use `cfg_if!` for platform-specific code

### Performance Patterns
- Prefer `Bytes` over `Vec<u8>` for zero-copy operations
- Use `Arc` for shared ownership without cloning data
- Implement `Clone` as cheaply as possible (often just `Arc` clones)
- Avoid allocations in hot paths
- Prefer static dispatch with generics over trait objects where possible
- Use `spawn_blocking` for CPU-intensive work in async contexts
- When in doubt, write a benchmark and profile the code (don't trust your intuition)

### Debugging Patterns
- Use `tracing` for structured, leveled logging throughout the codebase
- Implement metrics (via prometheus) for performance-critical operations
- Add comprehensive context to errors for better debugging

### Safety Guidelines
- Minimize unsafe blocks with clear `// SAFETY:` comments
- Prefer safe abstractions over raw unsafe code
- Enable overflow checks in all profiles (already configured)