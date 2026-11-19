# Inherited Threats

Part of the [Security Policy](../SECURITY.md). Here "this file" means the whole policy.

Commonware is a constructor of blockchains: a library of primitives that an
integrator composes into a network. It therefore inherits every general threat
and attack vector of the systems those primitives build. The per-crate lists
under ["Threats"](threats.md) and ["Attack Vectors"](attack-vectors.md) do not
repeat them. A reviewer must assume all of them apply wherever the
named crates are used, and must check the well-known attacks of a class before
looking for new ones.

- **Blockchains** (the composed system; `glue`, `consensus`, `storage`,
  `clearing`, `examples`, `sol`): double spend and reversal of finality, forks
  and long-range history rewrites, leader front-running and censorship,
  transaction replay across chains or forks, state growth and spam, validator
  set and key rotation attacks, non-deterministic execution, upgrade
  divergence, and forged proofs to light clients and bridges.
- **Authenticated databases** (`storage/src/qmdb`, `merkle`, `bmt`, `bitmap`,
  `journal`, and the hashes in `cryptography`; the Solidity verifiers in
  `sol`): forged inclusion, exclusion, and range proofs, leaf and inner node
  confusion, proof malleability, proofs replayed against a stale root, equal
  size with different history, rollback after a crash, torn writes, unsound
  pruning, poisoned state sync, oversized proofs, and key grinding against
  indexes.
- **Consensus protocols** (`consensus/src/simplex`, `marshal`, `aggregation`;
  `broadcast`, `coding`, `resolver`, `collector`: equivocation, 
  quorum-intersection errors, amnesia
  after a crash, replay across views and epochs, view-change and timeout
  attacks on liveness, leader withholding and data unavailability, violated
  synchrony assumptions, reconfiguration attacks, biased or predictable
  randomness, and forged or missing accountability evidence.
- **P2P networks** (`p2p`, `resolver`, `broadcast`, `collector`): Sybil and
  eclipse attacks, discovery poisoning, partitioning, connection and handshake
  exhaustion, amplification, message floods and replay, abuse of peer scoring
  and blocking against honest peers, address spoofing, and exposure of
  validator addresses.
- **Secure transport protocols** (`stream/src/sake`, `stream/src/cups`,
  `cryptography/src/handshake`, `cryptography/src/chacha20_poly1305`):
  man-in-the-middle, identity misbinding and unknown key share, key-compromise
  impersonation, reflection, replay, downgrade, nonce reuse, record reordering
  and truncation, missing forward secrecy, length leakage, timing side
  channels, and work done before authentication.
- **DKG and threshold protocols** (`cryptography/src/bls12381/dkg`,
  `glue/src/dkg`, `examples/dkg`): rogue keys, biased output keys, dealer
  equivocation, invalid or withheld shares, false complaints, share leakage
  past the threshold, a mobile adversary across epochs, replay of dealings
  across rounds, wrong threshold parameters, and ceremonies that never
  terminate.
- **Payment channels** (`clearing/src/bajillion` on `main`, with
  `utils/src/amount.rs` and `codec/src/uint.rs`): publication of a stale state,
  double spend of an off-chain balance, operator censorship and withholding,
  griefing and forced exits, missed challenge windows, replay of a signed
  state in another epoch, mass exit, arithmetic that mints or destroys value,
  and a ledger reorganized after the off-chain parties read it.
- **Runtimes** (`runtime`, `actor`, `allocator`, `parallel`, `utils`,
  `macros`): scheduler starvation, blocking inside async tasks, cancellation
  that leaves partial effects, unbounded tasks and queues, clock steps and
  timer errors, descriptor and memory exhaustion, `fsync` semantics weaker
  than assumed, lost or swallowed panics, non-determinism, and memory unsafety
  in buffers and I/O.

The general threats of serialization formats (`codec`), of cryptographic
primitives (`cryptography`, `math`, `simd`), and of the software supply chain
(dependencies, build scripts, CI) apply in the same way.
