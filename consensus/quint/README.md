# Simplex Formal Specification

This repository contains the formal specification for the Simplex Byzantine Fault-Tolerant consensus protocol (in [Quint](https://github.com/informalsystems/quint)).

## Setup

Once you've installed `node/npm`, run the following to install `quint`:

```
npm i @informalsystems/quint -g
```

_To run the model checker, you must install the Java Development Kit (JDK) 17 or higher. Both [Eclipse Temurin](https://adoptium.net/) and [Zulu](https://www.azul.com/downloads/?version=java-17-lts&package=jdk#download-openjdk) work great!_

## Protocol Configurations

The specification supports various configurations for testing:

- **N=4, F=0**: 4 replicas, no Byzantine replicas
- **N=4, F=1**: 4 replicas, 1 Byzantine replica
- **N=5, F=1**: 5 replicas, 1 Byzantine replica


## Running the Specification

You can choose any specification instance stored in the `main_` files:

```bash
quint run --invariant=block_example ./main_n4f1b0.qnt
quint run --invariant=two_chained_blocks_example ./main_n4f1b0.qnt
```

## Checking State Invariants

### Randomized Simulator

The simulator converts non-deterministic constructs in the specification like `any` and `oneOf` into random selections:

```bash
quint run --max-steps=1000 --random-transitions ./main_n4f1b0.qnt
```

### Randomized Symbolic Execution

Symbolic execution uses the symbolic model checker to find executions, with actions chosen randomly at each step:

```bash
quint verify --invariant=safe_invariants --max-steps=20 --random-transitions=true ./main_n4f1b0.qnt
```

### Bounded Model Checking

The bounded model checker verifies an invariant across all possible executions within a specified depth limit:

```bash
quint verify --invariant=safe_invariants --max-steps=20 ./main_n4f1b0.qnt
```