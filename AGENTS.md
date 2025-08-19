# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Repository Overview

Commonware is a Rust library providing high-performance, production-ready distributed systems primitives for adversarial environments. It's organized as a Cargo workspace with many primitives that build on each other (sharing testing infrastructure, types, traits, etc.).

## Essential Commands

### Build & Test
```bash
# Build entire workspace
cargo build --workspace --all-targets

# Run all tests
cargo test --workspace --verbose

# Run tests for specific crate
cargo test -p commonware-cryptography

# Run single test
cargo test -p commonware-consensus test_name

# Run clippy (linting)
cargo clippy --all-targets --all-features -- -D warnings

# Format code
cargo +nightly fmt --all

# Check for unsafe code issues
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test --lib commonware-storage::index::
```

### Fuzzing
```bash
# Run fuzzer for specific primitive (requires nightly)
cd cryptography
cargo +nightly fuzz run ed25519_decode -- -max_total_time=60
```

### Benchmarking
```bash
# Run benchmarks for specific crate
cargo bench -p commonware-cryptography
```

### Version Management
```bash
# Update all crate versions
./scripts/bump_versions.sh <new_version>
```

## Architecture

### Core Primitives (`primitives/`)
- **broadcast**: Message broadcasting with Byzantine fault tolerance
- **codec**: Wire format serialization/deserialization
- **coding**: Erasure coding and fountain codes
- **collector**: Distributed data aggregation
- **consensus**: BFT consensus implementations
- **cryptography**: Ed25519, BLS12-381, cryptographic primitives
- **deployer**: Environment-specific platform configuration
- **p2p**: Peer-to-peer networking layer
- **resolver**: Service discovery and load balancing
- **runtime**: Async runtime abstraction
- **storage**: Persistent key-value storage
- **stream**: Multiplexed streaming channels

### Key Design Principles
1. **Performance First**: All primitives optimized for high throughput/low latency
2. **Adversarial Safety**: Designed for Byzantine environments with malicious actors
3. **Zero-Copy Operations**: Extensive use of `Bytes` for efficient data handling
4. **Platform Abstraction**: Clean separation between platform-specific code (deployer) and portable logic

### Critical Implementation Notes
- Overflow checks enabled in all profiles (including release) for safety
- All cryptographic operations use constant-time implementations where applicable
- P2P layer provides abstract `Sender`/`Receiver`/`Blocker` traits, transport-agnostic
- Storage provides abstract data structures (ADB, MMR, journals) over runtime storage backends
- All code outside `runtime` is runtime-agnostic (never import tokio, use `futures` or runtime capabilities)

## Testing Strategy
- Unit tests: Core logic validation
- Integration tests: Cross-primitive interaction
- Fuzz tests: Input validation and edge cases
- MIRI tests: Memory safety verification for unsafe code
- Benchmarks: Performance regression detection

## Development Workflow
1. Make changes in relevant primitive directory
2. Run `cargo test -p <crate-name>` for quick iteration
3. Run `cargo clippy` before committing
4. Use `cargo +nightly fmt` for formatting
5. For cryptography changes, also run `cargo +nightly fmt -p commonware-cryptography`

## Deterministic Async Testing

Use the deterministic runtime for reproducible async tests:

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

### Simulated Network Testing
```rust
let (network, mut oracle) = Network::new(
    context.with_label("network"),
    Config { max_size: 1024 * 1024 }
);
network.start();

// Register peers and configure network links
let (sender, receiver) = oracle.register(public_key, 0).await.unwrap();
oracle.add_link(pk1, pk2, Link {
    latency: 10.0,      // ms
    jitter: 2.5,        // ms
    success_rate: 0.95, // 95% success
}).await.unwrap();
```

### Key Patterns
- Always use seeds for reproducible tests
- Label contexts for clear debugging
- Use `context.auditor().state()` to verify determinism
- Test with network partitions, delays, and failures
- Set timeouts with `Runner::timed(Duration::from_secs(30))`

## Code Style Guide

### Runtime Isolation Rule
**CRITICAL**: All code outside the `runtime` primitive must be runtime-agnostic:
- Never import or use `tokio` directly outside of `runtime/`
- Always use `futures` for async operations
- Use capabilities exported by `runtime` traits for I/O operations
- This ensures all primitives remain portable across different runtime implementations

### Import Organization
Always organize imports in this order:
```rust
// 1. Standard library
use std::{collections::HashMap, sync::Arc};

// 2. External crates (alphabetically)
use bytes::Bytes;
use futures::StreamExt;
use thiserror::Error;

// 3. Internal commonware crates
use commonware_codec::Encode;
use commonware_utils::Array;

// 4. Local module imports
use super::config::Config;
use crate::Error;
```

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
- Hide internal implementation with `#[doc(hidden)]` or private modules
- Feature flags: `#[cfg(feature = "feature-name")]`

### Performance Patterns
- Prefer `Bytes` over `Vec<u8>` for zero-copy operations
- Use `Arc` for shared ownership without cloning data
- Implement `Clone` as cheaply as possible (often just `Arc` clones)
- Avoid allocations in hot paths

### Safety Guidelines
- Minimize unsafe blocks with clear `// SAFETY:` comments
- Prefer safe abstractions over raw unsafe code
- Enable overflow checks in all profiles (already configured)
- Use `#[must_use]` for critical return values