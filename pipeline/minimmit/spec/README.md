# Minimmit Formal Specification

This repository contains the Quint formal specification for the [Minimmit](https://github.com/commonwarexyz/monorepo/blob/main/pipeline/minimmit.md) Byzantine Fault Tolerant consensus protocol.

## Getting Started

It is supposed that you have `node/npm` installed. Then to install `quint` run the following:

```
npm i @informalsystems/quint -g
```


## Protocol Configurations

The specification supports various configurations for testing:

- **N=6, F=1, B=0**: 6 replicas, fault tolerance of 1, no Byzantine replicas
- **N=7, F=1, B=0**: 7 replicas, fault tolerance of 1, no Byzantine replicas
- **N=6, F=1, B=1**: 6 replicas, fault tolerance of 1, 1 Byzantine replica
- **N=6, F=1, B=2**: 6 replicas, fault tolerance of 1, 2 Byzantine replicas (safety violations expected)

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

You can choose any canfiguration stored in the `main_` files.

### Running execution examples:**

```bash
quint run --invariant=block_example ./main_n6f1b0.qnt
quint run --invariant=two_chained_blocks_example ./main_n6f1b0.qnt

## Checking State Invariants

### Randomized Simulator

The simulator converts non-deterministic constructs in the specification like `any` and `oneOf` into random selections:

```bash
quint verify --invariant=safe --max-steps=20 --random-transitions ./main_n6f1b1.qnt
```

### Randomized Symbolic Execution

Symbolic execution uses the symbolic model checker to find executions, with actions chosen randomly at each step:

```bash
quint verify --invariant=safe --max-steps=20 --random-transitions=true ./main_n6f1b1.qnt
```

### Bounded Model Cheking

The bounded model checker verifies an invariant across all possible executions within a specified depth limit:

```bash
quint verify --invariant=safe --max-steps=20 ./main_n6f1b1.qnt
```



