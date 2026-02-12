# DKG Formal Specification

This directory contains the formal specification for the Joint-Feldman Distributed Key Generation (DKG) protocol in [Quint](https://github.com/informalsystems/quint).

## Setup

Install `quint` via npm:

```bash
npm i @informalsystems/quint -g
```

For bounded model checking with Apalache, install the Java Development Kit (JDK) 17 or higher. Both [Eclipse Temurin](https://adoptium.net/) and [Zulu](https://www.azul.com/downloads/?version=java-17-lts&package=jdk#download-openjdk) work.

## Protocol Overview

The DKG protocol allows multiple dealers to jointly generate a shared secret. Each dealer:
1. Generates a random polynomial and distributes shares to players
2. Collects ACKs from players who received valid shares
3. Finalizes with a log containing ACKs or revealed shares

Players verify shares against commitments and finalize by combining contributions from selected dealers.

## Protocol Configurations

| File | N | F | Byzantine Dealers | Byzantine Players |
|------|---|---|-------------------|-------------------|
| `main_n4f1b0.qnt` | 4 | 1 | 0 | 0 |
| `main_n4f1b1.qnt` | 4 | 1 | 1 (p3) | 0 |
| `main_n7f2b0.qnt` | 7 | 2 | 0 | 0 |
| `main_n7f2b2.qnt` | 7 | 2 | 2 (p5, p6) | 0 |

## Safety Invariants

| Invariant | Description |
|-----------|-------------|
| `assumptions_valid` | Configuration constraints hold (correct/Byzantine partition, fault bounds) |
| `output_agreement` | All finalized correct players compute the same public polynomial |
| `dealer_logs_valid` | Correct dealer logs have valid structure |
| `bounded_reveals` | Each correct dealer reveals at most F shares |
| `share_secrecy` | Each correct player is revealed by at most F selected dealers (may be violated under asynchrony) |
| `safe` | Conjunction of core safety properties (excludes `share_secrecy`) |

## Running the Specification

### Typecheck

```bash
make typecheck
```

### Run Scenario Tests

Explicit `.then()` chained tests that deterministically verify specific execution paths:

```bash
make test
```

Tests include:
- `happyPathTest` - Synchronous execution, all players finalize
- `asyncSlowPlayerTest` - Async execution, share_secrecy violated
- `boundedRevealsTest` - One slow player, share_secrecy holds
- `tooManyRevealsTest` - Dealer finalizes with TooManyReveals
- `byzantineLogRejectedTest` - Byzantine dealer's fake log rejected
- `outputAgreementTest` - All players compute same public polynomial

### Randomized Simulation

```bash
# n=4 configurations
make run

# n=7 configurations
make run-n7
```

Or manually:

```bash
quint run --max-steps=40 --max-samples=1000 --invariant=safe main_n4f1b0.qnt
```

### Bounded Model Checking

Verify invariants exhaustively within a depth bound using Apalache:

```bash
quint verify --invariant=safe --max-steps=5 main_n4f1b0.qnt
```

Note: Model checking is slow due to state space size. Use `--max-steps=3` for quick checks.

### Adversarial Test

Demonstrate that `share_secrecy` can be violated under adversarial scheduling:

```bash
make run-adversarial
```

## File Structure

```
.
├── types.qnt              # Type definitions
├── defs.qnt               # Pure functions (polynomial ops, quorum calculations)
├── dkg.qnt                # Main protocol specification
├── main_n4f1b0.qnt        # Configuration: n=4, f=1, 0 Byzantine
├── main_n4f1b1.qnt        # Configuration: n=4, f=1, 1 Byzantine dealer
├── main_n7f2b0.qnt        # Configuration: n=7, f=2, 0 Byzantine
├── main_n7f2b2.qnt        # Configuration: n=7, f=2, 2 Byzantine dealers
├── makefile               # Build/test commands
└── tests/
    ├── scenarios.qnt      # Scenario tests for n=4
    ├── scenarios_n7.qnt   # Scenario tests for n=7
    └── test_adversarial.qnt # Adversarial scheduling test
```

## Partial Synchrony Model

The spec models partial synchrony following the minimmit pattern:
- `timer_expired: bool` tracks whether a dealer's timer has fired
- `dealer_timer_expired` action fires nondeterministically to finalize a dealer
- `dealer_receive_ack` can happen while `timer_expired` is false

The nondeterministic scheduler explores all interleavings:
- **Synchrony**: ACKs arrive before timer expires → `share_secrecy` holds
- **Asynchrony**: Timer fires before ACKs arrive → `share_secrecy` may be violated

Random simulation rarely finds synchronous executions; use explicit scenario tests to verify these paths.
