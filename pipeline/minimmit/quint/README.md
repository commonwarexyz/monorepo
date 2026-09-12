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
- `main_n7f1b1.qnt`: 7 replicas, 1 Byzantine replica
- `main_twins_n6f1b1.qnt`: 6 logical replicas with one faulty logical key modeled by two twin actors

The test suite also includes `tests_n7f1b1.qnt`, with 7 replicas and 1 Byzantine replica.

## Safety Invariants

The specification validates the following safety properties. They are conjoined by
`all_invariants` (aliased as `safe`) in `replica.qnt`; `scripts/invariant.sh` lists the same names,
in the same order, so that each one can be checked as a separate job.

| # | Invariant Name | Description |
|---|----------------|-------------|
| 1 | `no_proposal_equivocation` | No honest proposer sends two different proposals in the same view |
| 2 | `agreement` | No two honest replicas commit different blocks at the same height |
| 3 | `no_vote_equivocation_inv` | In one view an honest replica sends at most one vote, or a notarize followed by a nullify, and never a notarize after a nullify |
| 4 | `no_nullification_and_finalization_in_the_same_view` | One honest replica does not observe both nullification and finalization evidence for the same view |
| 5 | `validity` | No two honest replicas store finalization certificates for different blocks in the same view |
| 6 | `valid_last_finalized` | The last finalized view must not exceed the last seen notarization view |
| 7 | `certificates_are_valid_inv` | Stored certificates are well-formed and meet the threshold for their kind (`M` for notarization and nullification, `L` for finalization) |
| 8 | `notarized_consistency` | An honest replica's local notarization state for a view is set exactly when it has sent a notarize vote in that view |
| 9 | `safe_finalization` | A finalized view has neither an `M`-quorum of nullify votes (`no_nullification_in_finalized_view`) nor an `M`-quorum of notarize votes for a different proposal (`no_notarization_in_finalized_view`) |

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

## Modeling Notes

The model is faithful to [minimmit.md](../minimmit.md) except for the following deliberate choices, which materially affect the modeled behavior:

- **`Block` is a hash-protected container that commits to its parent.** The `ghost_block_parent`
  map gives every block a single parent, so the same block cannot be built on two different parents.
  This is the "block digests" extension (minimmit.md §10). It is enforced by construction: the
  honest proposer may only extend the parent already recorded for its block, and both the honest and
  the Byzantine proposal paths are guarded by `is_proposal_with_valid_parent_block`. It is what makes
  ancestor finalization (see below) unambiguous and safe.

- **Ancestor finalization.** `_process_certificate` realizes minimmit.md §8.4 "finalize `c` and all
  of its ancestors": on a new finalization certificate that advances `last_finalized`, the replica
  commits the finalized block together with every ancestor reachable through `ghost_block_parent`
  (`block_and_ancestors`), excluding genesis.

- **Notarize votes may also be certificate-driven (minimmit.md §8.4/§8.5).** Besides voting on the
  leader's proposal (`on_proposal`), a replica casts a `notarize(c, v)` vote from
  `_process_certificate` when a new notarization or finalization certificate arrives for its current
  view and it has neither notarized nor nullified that view yet.
