# Minimmit Formal Specification

This repository contains the formal specification for the [Minimmit](../minimmit.md) Byzantine Fault-Tolerant consensus protocol (in [Quint](https://github.com/informalsystems/quint)).

## Setup

Once you've installed `node/npm`, run the following to install `quint`:

```
npm i @informalsystems/quint -g
```

_To run the model checker, you must install the Java Development Kit (JDK) 17 or higher. Both [Eclipse Temurin](https://adoptium.net/) and [Zulu](https://www.azul.com/downloads/?version=java-17-lts&package=jdk#download-openjdk) work great!_

## Protocol Configurations

The specification supports various configurations for testing:

- **N=6, F=0**: 6 replicas, no Byzantine replicas
- **N=6, F=1**: 6 replicas, 1 Byzantine replica
- **N=6, F=2**: 6 replicas, 2 Byzantine replicas (safety violations expected)
- **N=7, F=1**: 7 replicas, no Byzantine replicas

## Safety Invariants

The specification validates the following safety properties:

| # | Invariant Name | Description |
|---|----------------|-------------|
| 1 | `agreement` | No two correct replicas disagree on the committed blocks - ensures all correct replicas have consistent blockchain prefixes |
| 2 | `no_vote_equivocation_inv` | A correct replica should not send two votes in the same view - honest replicas may not broadcast a `notarize(c, v)` after first broadcasting a `nullify(v)` |
| 3 | `no_nullification_and_finalization_in_the_same_view` | It is impossible to produce both a nullification and finalization certificate for the same slot `v` |
| 4 | `no_proposal_equivocation` | No correct proposer sends two different proposals in the same view |
| 5 | `valid_last_finalized` | The last finalized view must not exceed the last seen notarization view |
| 6 | `certificates_are_valid_inv` | All certificates stored by correct replicas are well-formed with valid signatures and proper thresholds |
| 7 | `notarized_consistence` | Consistency between notarized blocks in replica state and sent votes |
| 8 | `validity` | If a block `B` for some slot `v` is finalized, then no other block `B'` for slot `v` can be finalized |
| 9 | `no_nullification_in_finalized_view` | If there is a finalized block in a view `v`, there is no nullification in this view |
| 10 | `no_notarization_in_finalized_view` | If there is a finalized block in a view `v`, there is no notarization for another block in this view |

## Running the Specification

You can choose any specification instance stored in the `main_` files:

```bash
quint run --invariant=block_example ./main_n6f0.qnt
quint run --invariant=two_chained_blocks_example ./main_n6f0.qnt
```

## Checking State Invariants

### Randomized Simulator

The simulator converts non-deterministic constructs in the specification like `any` and `oneOf` into random selections:

```bash
quint verify --invariant=safe --max-steps=20 --random-transitions ./main_n6f0.qnt
```

### Randomized Symbolic Execution

Symbolic execution uses the symbolic model checker to find executions, with actions chosen randomly at each step:

```bash
quint verify --invariant=safe --max-steps=20 --random-transitions=true ./main_n6f1.qnt
```

### Bounded Model Checking

The bounded model checker verifies an invariant across all possible executions within a specified depth limit:

```bash
quint verify --invariant=safe --max-steps=20 ./main_n6f1.qnt
```