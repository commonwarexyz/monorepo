# AGENTS.md

Agent guidance for this repository.

> **Communication Style**: Be brief, concise. Maximize information density, minimize tokens. Incomplete sentences acceptable when clear. Remove filler words. Prioritize clarity over grammar.

## Repository Overview

Rust library: high-performance distributed systems primitives for adversarial environments. Cargo workspace with interdependent primitives sharing testing infrastructure, types, traits.

## Essential Commands

### Quick Reference
```bash
# Build entire workspace
cargo build --workspace --all-targets

# Test specific crate
just test -p commonware-cryptography

# Test single function
just test -p commonware-consensus test_name

# Run benchmarks
cargo bench -p commonware-cryptography

# Update all crate versions
./scripts/bump_versions.sh <new_version>
```

_CI-related commands: see [CI/CD Pipeline](#cicd-pipeline)_

## Architecture

### Core Primitives
- **broadcast**: Disseminate data over wide-area networks
- **codec**: Serialize structured data
- **coding**: Encode data for recovery from fragment subsets
- **collector**: Collect responses to committable requests
- **consensus**: Order opaque messages (Byzantine environment)
- **cryptography**: Generate keys, sign messages, verify signatures
- **deployer**: Deploy infrastructure across cloud providers
- **p2p**: Communicate with authenticated peers (encrypted connections)
- **resolver**: Resolve data by fixed-length key
- **runtime**: Execute async tasks (configurable scheduler)
- **storage**: Persist/retrieve data from abstract store
- **stream**: Exchange messages over arbitrary transport

_More primitives: [Cargo.toml](Cargo.toml) (`commonware-` prefix)_

### Examples
- **alto** (https://github.com/commonwarexyz/alto): Minimal, fast blockchain
- **bridge** (`examples/bridge`): Send consensus certificates between networks
- **chat** (`examples/chat`): Encrypted group messaging
- **estimator** (`examples/estimator`): Simulate mechanism performance under realistic network conditions
- **flood** (`examples/flood`): Spam AWS EC2 peers with random messages
- **log** (`examples/log`): Commit to secret log, agree on hash
- **sync** (`examples/sync`): Synchronize state between server/client
- **vrf** (`examples/vrf`): Generate bias-resistant randomness with untrusted contributors

### Key Design Principles
1. **Simplicity**: Code must look obviously correct with minimum necessary features
2. **Test Everything**: Design for deterministic, comprehensive testing using abstract runtime (`runtime/src/deterministic.rs`)
3. **Performance**: Optimize for high throughput/low latency
4. **Adversarial Safety**: Robust operation in adversarial environments
5. **Abstract Runtime**: Runtime-agnostic outside `runtime/` (never import `tokio` directly; use traits from `runtime/src/lib.rs`)
6. **Complete Code**: Always implement complete functionality; for large tasks, start with simplest working solution, iterate
7. **Own Core Mechanisms**: Implement heavily-used core mechanisms/algorithms vs external crates

## Technical Documentation

Technical docs in `docs/blogs/`:

### Core Concepts
- **introducing-commonware.html**: Library philosophy and goals
- **commonware-the-anti-framework.html**: Framework avoidance rationale

### Primitive Deep Dives
- **commonware-runtime.html**: Abstract runtime design/implementation
- **commonware-cryptography.html**: Cryptographic primitives and safety guarantees
- **commonware-broadcast.html**: Reliable broadcast protocol
- **commonware-deployer.html**: Infrastructure deployment automation

### Algorithms & Data Structures
- **adb-current.html** / **adb-any.html**: Authenticated data broadcast protocols
- **mmr.html**: Merkle Mountain Range
- **minimmit.html**: Minimal commit protocol
- **buffered-signatures.html**: Efficient signature aggregation
- **threshold-simplex.html**: Threshold consensus mechanism

## CI/CD Pipeline

GitHub Actions workflows: **Fast** (every push/PR), **Slow** (main/PR, cancellable), **Coverage** (main/PR)

### Pre-Push Checklist

Run locally before pushing (avoid CI failures):

```bash
# 1. Format and lint (REQUIRED)
just lint

# 2. Run tests (REQUIRED)
just test --workspace

# 3. Platform-specific (Linux only, runtime changes)
just test --features commonware-runtime/iouring-storage
just test --features commonware-runtime/iouring-network

# 4. Check dependencies (if modified)
just udeps

# 5. WASM build (cryptography/utils/storage changes)
cargo build --target wasm32-unknown-unknown --release -p commonware-cryptography

# 6. Unsafe code (new unsafe blocks)
just miri <module>::
```

### Extended Checks (before PR)

```bash
# Long-running tests
just test --workspace -- --ignored

# Fuzz testing (60 seconds per target)
just fuzz <primitive>/fuzz

# Coverage report
cargo llvm-cov --workspace --lcov --output-path lcov.info
```

## Testing Strategy
- Unit tests: Core logic validation
- Integration tests: Cross-primitive interaction
- Fuzz tests: Input validation and edge cases
- MIRI tests: Memory safety verification (unsafe code)
- Benchmarks: Performance regression detection
- Coverage: Track with llvm-cov (see CI section)

## Development Workflow
1. Make changes in relevant primitive directory
2. Quick iteration: `just test -p <crate-name>`
3. Before commit: Run CI fast checks (see CI section)
4. Format: `just fix-fmt`
5. Before PR: Run full CI checks locally

## Reviewing PRs
Focus PR reviews on correctness and performance (not style). Pay special attention to malicious input bugs. Repository is for adversarial environments - ensure code robustness.

## Deterministic Async Testing
Use deterministic runtime (`runtime/src/deterministic.rs`) for reproducible async tests:
```rust
#[test]
fn test_async_behavior() {
    let executor = deterministic::Runner::seeded(42); // Reproducible via seed
    executor.start(|context| async move {
        // Spawn actors with labels
        let handle = context.with_label("worker").spawn(|context| async move {
            // Actor logic
            context.sleep(Duration::from_secs(1)).await;
        });

        // Control time explicitly
        context.sleep(Duration::from_millis(100)).await;

        // select! for timeouts
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
// deterministic::Config for precise control
let cfg = deterministic::Config::new()
    .with_seed(seed)
    .with_timeout(Some(Duration::from_secs(30)));
let executor = deterministic::Runner::new(cfg);

// Timed runner for simpler tests
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
    prev_ctx = Some(context.recover()); // Save for next iteration
}
```

### Simulated Network Testing
Use simulated network (`p2p/src/simulated`):
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
    latency: Duration::from_millis(10),
    jitter: Duration::from_millis(3),
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
    latency: Duration::from_secs(3), // Slow network
    jitter: Duration::from_millis(0),
    success_rate: 1.0,
};
oracle.update_link(pk1, pk2, degraded_link).await.unwrap();

// Lossy networks
let lossy_link = Link {
    latency: Duration::from_millis(200),
    jitter: Duration::from_millis(150),
    success_rate: 0.5, // 50% packet loss
};
```

### Byzantine Testing Patterns
```rust
// Test Byzantine actors by replacing normal participants
if idx_scheme == 0 {
    // Byzantine actor instead of normal engine
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

Deterministic runtime provides simulated storage backend (no real I/O):

### Basic Storage Operations
```rust
#[test]
fn test_storage_operations() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        // Open blob in partition
        let (blob, size) = context
            .open("partition_name", &0u64.to_be_bytes())
            .await
            .expect("Failed to open blob");

        // Write at offset
        blob.write_at(vec![1, 2, 3, 4], 0)
            .await
            .expect("Failed to write");

        // Read from offset
        let data = blob.read_at(vec![0u8; 4], 0)
            .await
            .expect("Failed to read");

        // Sync for durability
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
        let mut journal = Journal::init(context.with_label("journal"), cfg)
            .await
            .expect("Failed to init");

        // Append data
        journal.append(1, data).await.expect("Failed to append");

        // Close (clean shutdown)
        journal.close().await.expect("Failed to close");

        // Re-initialize (restart)
        let journal = Journal::init(context.with_label("journal"), cfg)
            .await
            .expect("Failed to re-init");

        // Verify data persisted
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
        let mut journal = Journal::init(context.with_label("journal"), cfg).await.unwrap();
        journal.append(1, valid_data).await.unwrap();
        journal.close().await.unwrap();

        // Manually corrupt data
        let (blob, size) = context
            .open(&cfg.partition, &1u64.to_be_bytes())
            .await
            .unwrap();

        // Corrupt checksum or truncate
        blob.write_at(vec![0xFF; 4], size - 4).await.unwrap();
        blob.sync().await.unwrap();

        // Re-initialize and verify recovery
        let journal = Journal::init(context.with_label("journal"), cfg).await.unwrap();

        // Replay handles corruption gracefully
        let stream = journal.replay(buffer_size).await.unwrap();
        // Verify corrupted items skipped/truncated
    });
}
```

### Storage Testing Patterns

#### Simulating Partial Writes
```rust
// Test recovery from incomplete writes
let (blob, size) = context.open(&partition, &name).await.unwrap();
blob.resize(size - 1).await.unwrap(); // Partial write
blob.sync().await.unwrap();

// Verify recovery truncates to last valid item
let journal = Journal::init(context, cfg).await.unwrap();
assert_eq!(journal.size().await.unwrap(), expected_size);
```

#### Testing Blob Management
```rust
// Multiple blob handling
for section in 0..10 {
    journal.append(section, data).await.unwrap();
    journal.sync(section).await.unwrap();
}

// Pruning old blobs
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
        let mut journal = Journal::init(context.with_label("journal"), cfg).await.unwrap();
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
**CRITICAL**: Code outside `runtime` must be runtime-agnostic:
- Never import `tokio` directly outside `runtime/`
- Use `futures` for async operations
- Use `runtime` trait capabilities for I/O
- Ensures primitive portability across runtime implementations

### Error Handling
Use `thiserror`:
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
- `//!`: Module-level docs (Status/Examples sections)
- `///`: Public items (clear descriptions)
- `# Examples`: Public APIs
- `# Safety`: Unsafe code
- Use easily-typed characters (no em dashes, arrows)

### Naming Conventions
- **Types**: `PascalCase` (`PublicKey`, `SignatureSet`)
- **Functions/methods**: `snake_case` (`verify_signature`, `from_bytes`)
- **Constants**: `SCREAMING_SNAKE_CASE` (`MAX_MESSAGE_SIZE`)
- **Traits**: Action names (`Signer`, `Verifier`) or `-able` suffix (`Viewable`)

_Minimize function/variable length_

### Trait Patterns
```rust
// Comprehensive trait bounds
pub trait PublicKey: Verifier + Sized + ReadExt + Encode + PartialEq + Array {}

// Extension traits for additional functionality
pub trait PrivateKeyExt: PrivateKey {
    fn from_rng<R: CryptoRngCore>(rng: &mut R) -> Self;
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
- Prefer `Bytes` over `Vec<u8>` (zero-copy)
- Use `Arc` for shared ownership (no cloning)
- Implement cheap `Clone` (often `Arc` clones)
- Avoid hot path allocations
- Prefer static dispatch (generics) over trait objects
- CPU-intensive async work: `context.shared(true).spawn()`
- Benchmark and profile (don't trust intuition)

### Debugging Patterns
- `tracing`: Structured, leveled logging
- Metrics (prometheus): Performance-critical operations
- Add comprehensive error context
- Write failing test before claiming bug

### Safety Guidelines
- Minimize unsafe blocks (`// SAFETY:` comments required)
- Prefer safe abstractions over raw unsafe
- Overflow checks enabled (all profiles)
