# Minimmit Formal Specification

This repository contains the formal specification for the [Minimmit](../minimmit.md) Byzantine Fault-Tolerant consensus protocol (in [Quint](https://github.com/informalsystems/quint)).

## Setup

Once you've installed `node/npm`, run the following to install `quint`:

```
npm i @informalsystems/quint -g
```

_To run the model checker, you must install the Java Development Kit (JDK) 17 or higher. Both [Eclipse Temurin](https://adoptium.net/) and [Zulu](https://www.azul.com/downloads/?version=java-17-lts&package=jdk#download-openjdk) work great!_

## Protocol Configurations

The specification supports these top-level configurations:

- `main_n6f1b0.qnt`: 6 replicas, no Byzantine replicas
- `main_n6f1b1.qnt`: 6 replicas, 1 Byzantine replica
- `main_n6f1b2.qnt`: 6 replicas, 2 Byzantine replicas with `F = 1` (safety violations expected)
- `main_twins_n6f1b1.qnt`: 6 logical replicas with one faulty logical key modeled by two twin actors

The test suite also includes `tests_n7f1b1.qnt`, with 7 replicas and 1 Byzantine replica.

## Safety Invariants

The specification validates the following safety properties:

| # | Invariant Name | Description |
|---|----------------|-------------|
| 1 | `no_proposal_equivocation` | No honest proposer sends two different proposals in the same view |
| 2 | `agreement` | No two honest replicas disagree on committed proposal-chain prefixes |
| 3 | `no_vote_equivocation_inv` | An honest replica does not send an invalid sequence of votes in one view |
| 4 | `no_nullification_and_finalization_in_the_same_view` | One honest replica does not observe both nullification and finalization evidence for the same view |
| 5 | `validity` | At most one proposal can be finalized in a view |
| 6 | `valid_last_finalized` | The last finalized view must not exceed the last seen notarization view |
| 7 | `certificates_are_valid_inv` | Stored certificates are well-formed and meet their thresholds |
| 8 | `certificates_are_backed` | Certificate signatures from non-faulty keys are backed by matching votes |
| 9 | `notarized_consistency` | Local notarization state matches notarize votes sent by the same honest key |
| 10 | `safe_finalization` | A finalized view has neither nullification nor conflicting notarization evidence |
| 11 | `committed_blocks_are_finalized` | Every committed proposal has a local finalization certificate |
| 12 | `committed_chain_is_connected` | Every committed proposal links to the preceding committed proposal |
| 13 | `no_nullification_and_finalization_globally` | No view has both nullification and finalization certificates across honest stores |

## Running the Specification

You can choose any specification instance stored in the `main_` files:

```bash
quint run --invariant=block_example ./main_n6f1b0.qnt
quint run --invariant=two_chained_blocks_example ./main_n6f1b0.qnt
```

## Checking State Invariants

### Randomized Simulator

The simulator converts non-deterministic constructs in the specification like `any` and `oneOf` into random selections:

```bash
quint verify --invariant=safe --max-steps=20 --random-transitions ./main_n6f1b0.qnt
```

### Randomized Symbolic Execution

Symbolic execution uses the symbolic model checker to find executions, with actions chosen randomly at each step:

```bash
quint verify --invariant=safe --max-steps=20 --random-transitions=true ./main_n6f1b1.qnt
```

### Bounded Model Checking

The bounded model checker verifies an invariant across all possible executions within a specified depth limit:

```bash
quint verify --invariant=safe --max-steps=20 ./main_n6f1b1.qnt
```
