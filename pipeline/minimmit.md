# Specification

## 1. Introduction

Minimmit is a responsive, leader-based consensus protocol designed for simplicity and speed, tolerant of a Byzantine adversary that controls fewer than `20%` of replicas. Minimmit advances to the next view when a `40%` quorum is reached and finalizes blocks when an `80%` quorum is reached (after only a single round of voting). Minimmit can be instantiated with a number of practical optimizations to improve performance when deployed in production.

## 2. Model & Parameters

- Byzantine replicas: `≤ f`
- Total replicas: `n ≥ 5f + 1`
- Partial synchrony: every message arrives within `Δ` after an unknown global stabilization time (GST).

## 3. Quorums

- `L = n - 3f` (`2f + 1`)
- `Q = n - f` (`4f + 1`)

_There exists `≥ 1` honest replica in any `Q`-set and `L`-set intersection._

## 4. Message Types

| Message | Purpose |
|---------|---------|
| `genesis` | The genesis block. |
| `propose(c, v, (c', v'))` | Leader's proposal `c` for view `v` with parent `c'` in view `v'`. |
| `notarize(c, v)` | Vote to finalize block `c` in view `v`. |
| `nullify(v)` | Vote to advance to view `v + 1`. |
| `notarization(c, v)` | Certificate of ≥ `L` `notarize(c, v)` messages for `(c, v)`. |
| `nullification(v)` | Certificate of ≥ `L` `nullify(v)` messages for view `v`. |
| `proof(v)` | Either a `notarization(*, v)` or a `nullification(v)` certificate. |

## 5. Initial Replica State

```text
view         = 0
notarized    = ⊥         # the proposal this replica has notarized
nullified    = false     # whether this replica has nullified this view
timer        = None      # time until nullify if not yet nullified or notarized
messages     = []        # list of messages this replica has seen
proofs       = []        # list of proofs this replica has collected
```

## 6. External Functions

```text
// Select the leader for view `v`
fn leader(v) -> L;

// Build a block on top of `c'`. This should pass `verify(c, c')`.
fn build(c') -> c;

// Verify whether `c` is valid given the parent `c'`. Anything produced by
// `build(c')` should pass `verify(c, c')`.
fn verify(c, c') -> bool;
```

## 7. Helpers

```text
// Find a valid parent to build on
fn select_parent(v) -> (c', v') {
    let i = v - 1;
    while i >= 0 {
        if ∃c': notarization(c', i) ∈ proofs[i] {
            // If there are multiple, pick any.
            return (c', i);
        }
        if nullification(i) ∈ proofs[i] {
            i -= 1;
            continue;
        }
        return ⊥;
    }
    return genesis;
}

// Ensure there are proofs for all views between `v` and `v'`
fn valid_parent(v, (c', v')) -> bool {
    let i = v - 1;
    while i > v' {
        if nullification(i) ∈ proofs[i] {
            i -= 1;
            continue;
        }
        return false;
    }
    return notarization(c', v') ∈ proofs[v']
}

// Enter view `next`
fn enter_view(next) {
    if view >= next {
        return;
    }
    view = next;
    notarized = ⊥;
    nullified = false;
    timer = 2Δ;
}

// Record a message from a `replica`
fn record_message(replica, message) -> bool {
    if message.view ∉ messages {
        messages[message.view] = {};
    }
    if replica ∉ messages[message.view] {
        messages[message.view][replica] = [];
    }
    if message ∉ messages[message.view][replica] {
        messages[message.view][replica].add(message);
        return true;
    }
    return false;
}

// Prune data less than `view`
fn prune(view) {
    messages.remove(m => m.view < view);
    proofs.remove(p => p.view < view);
}
```

## 8. Protocol for View `v`

### 8.1. Propose

_If the leader, propose._

1. Upon entering view `v`, if identity is equal to `leader(v)`:
   1. `(c', v') = select_parent(v)` (if `⊥`, return).
   1. `c = build(c')`.
   1. `notarized = c`.
   1. Broadcast `propose(c, v, (c', v'))`.

_Treat `propose(c, v, (c', v'))` as `leader(v)`'s `notarize(c, v)`._

### 8.2. Notarize

_Upon receipt of a first valid block proposal from leader, broadcast `notarize(c, v)`._

1. On receiving first `propose(c, v, (c', v'))` from `leader(v)`:
   1. If `notarized != ⊥` or `nullified`, return.
   1. If `!valid_parent(v, (c', v'))`, return.
   1. If `!verify(c, c')`, return.
   1. `notarized = c`.
   1. Broadcast `notarize(c, v)`.

### 8.3. Nullify by Timeout

_If `timer` expires, broadcast `nullify(v)` if not yet broadcasted `notarize(c, v)`._

1. On `timer` expiry:
   1. If `notarized != ⊥` or `nullified`, return.
   1. `nullified = true`.
   1. Broadcast `nullify(v)`.

### 8.4. Notarization & Finalization

_After `L` messages, create and broadcast a `notarization(c, v)` certificate. After `Q` messages, finalize._

1. On receiving `notarize(c, v)` from replica `r`:
   1. If `!record_message(r, notarize(c, v))`, return.
1. On observing `≥ L` `notarize(c, v)` messages:
   1. Assemble `notarization(c, v)`.
   1. Add `notarization(c, v)` to `proofs`.
   1. Broadcast `notarization(c, v)`.
   1. `enter_view(v + 1)`.
1. On observing `≥ Q` `notarize(c, v)` messages:
   1. Finalize `c` and all of its ancestors.
   1. `prune(v)`.

### 8.5. Nullification

_After `L` messages, create and broadcast a `nullification(v)` certificate._

1. On receiving `nullify(v)` from replica `r`:
   1. If `!record_message(r, nullify(v))`, return.
1. On observing `≥ L` `nullify(v)` messages (or a single `nullification(v)` message):
   1. Assemble `nullification(v)`.
   1. Add `nullification(v)` to `proofs`.
   1. Broadcast `nullification(v)`.
   1. `enter_view(v + 1)`.

### 8.6 Nullify by Contradiction

_If you have already broadcast `notarize(c, v)` for a `c` that cannot be finalized directly, broadcast `nullify(v)` to ensure some `proof(v)` will exist in view `v`._

1. On observing messages from `≥ L` replicas of either `nullify(v)` or `notarize(*, v)` (where `notarized != ⊥` and `notarized != *`):
   1. `nullified = true`.
   1. Broadcast `nullify(v)`.

## 9. Intuition

### 9.1 General

- A leader selected in `v + 1` may propose any block `c` that extends some known `notarization(c', v')` as long as there exist `nullification(j)` proofs for all views in `(v', v]`. Notably, this means that leaders are never required to re-propose a block from an earlier view and can only skip some block proposed in an earlier view `v` if there exists some `nullification(v)`.

### 9.2 Safety

- Honest replicas may not broadcast a `notarize(c, v)` after first broadcasting a `nullify(v)`.
- Honest replicas may broadcast a `nullify(v)` after first broadcasting a `notarize(c, v)`.
   - To broadcast both a `notarize(c, v)` and a `nullify(v)` message, a replica must first see that it is impossible for the proposal that it notarized to reach a quorum of `Q` `notarize(c, v)` messages. Otherwise, the replica is forbidden from broadcasting `nullify(v)`, no matter how much time has passed.
   - A replica knows it is impossible for its notarized proposal `c` to reach the finalization quorum `Q` once it has observed `L` other replicas that conflict. A conflicting replica has broadcast either a `nullify(v)` message or a `notarize(*, v)` message for a different proposal `*`.
   - If a replica has seen `L` conflicting votes, at least `L - f` (i.e. `f + 1`) are from honest replicas. Therefore, the maximum number of `notarize(c, v)` it can receive is `n - (f + 1)`, or `4f` (strictly less than `Q`).
- Suppose a correct leader broadcasts a block `c` and, after honest replicas broadcast `notarize(c, v)`, message delivery is disrupted, preventing any replica from receiving `L` such messages. In this state, replicas have locked on `c` for view `v` and cannot broadcast some `nullify(v)`. Progress is stalled until network conditions improve, allowing a `notarization(c, v)` to be assembled, which in turn allows replicas to enter view `v + 1`.
- In any given view `v`, there may be multiple `notarization(*, v)` messages and one `nullification(v)`. If there are multiple `notarization(*, v)`s, no block `*` referenced by a `notarization(*, v)` can be finalized in `v`. If there exists some `nullification(v)`, no block can be finalized in `v`.

### 9.3 Liveness

- There exists at least one `proof(v)` for every view `v`.
- After GST, all views with honest leaders will emit a `notarization` message before the timer of any honest replica expires. To see this is true, consider the following:
    - The first honest replica broadcasts some `proof(v - 1)` message to all replicas and enters view `v` at time `t_0`.
    - The leader of view `v` will receive said `proof(v - 1)` message by `t_0 + Δ` and broadcast some `propose(c, v, (c', v'))` message to all replicas.
    - All honest replicas will receive said `propose(c, v, (c', v'))` message by `t_0 + 2Δ` and broadcast some `notarize(c, v)` message.
- Replicas enter `v + 1` as soon as they see some `proof(v)` (as fast as `L` messages). If the network is partitioned in two, replicas in each half of the partition may continue to enter successive views (on different `proof(v)`s) but will never finalize conflicting blocks. To bound the depth of forks in a partition, replicas can wait to enter some view `v + k` until they have seen `Q` messages in view `v`.
- A Byzantine leader could equivocate, sending a distinct proposal to each replica and causing them to broadcast a `notarize(*, v)` for different blocks. After a replica observes `≥ L` `notarize(*, v)` messages for some `* != c`, it will then choose to broadcast a `nullify(v)` message. Eventually, `L` `nullify(v)` messages will be received and honest replicas will enter `v + 1` (within `Δ` of the first honest replica).
- Since at most `f` nodes are Byzantine or faulty, once an honest leader is assigned, it is possible for at least `Q` correct replicas to finalize a block (including all of its ancestors).

## 10. Extensions

Minimmit can be instantiated in several different ways to tune performance when deployed to production. Some examples are below:

- Use block digests (i.e. `c = hash(block)`) in `propose(c, v, (c', v'))`, `notarize(c, v)`, and `notarization(c, v)` messages.
- Employ BLS multi-signatures or BLS threshold signatures, like [Threshold Simplex](#threshold), to cap `notarization(c, v)` and `nullification(v)` messages at a constant size regardless of the number of replicas.
- Attach some recent set of `proof(v)` messages to each `propose(c, v, (c', v'))` message (to ensure honest replicas that are not yet aware of recent proofs can still broadcast a `notarize(c, v)` message for valid blocks).
- If `≥ f + 1` `notarize(c, v)` messages are observed for some `proposal(c, v, (c', v'))` considered invalid, request the missing `notarization(c, v')` or `nullification(v')` not found in our `proofs` (that prohibited us from broadcasting a `notarize(c, v)`) from the peers that consider it valid.
- If stuck in the same view `v` for time `t_s`, re-broadcast some `proof(v - 1)` (to ensure all correct replicas enter `v`) and re-broadcast `notarized` (if not `⊥`) and `nullified` (if not `false`).
- Assemble and broadcast a `finalization(c, v)` message after finalizing some `c` (i.e. `≥ Q` `notarize(c, v)` messages). This can both help lagging replicas catch up to the finalized tip and make it easier for downstream services to integrate.
- Disseminate blocks using `(k,d)`-erasure codes, like [DispersedSimplex](#sing-a-song), [Kudzu](#kudzu), and [Alpenglow](#alpenglow), to avoid a leader broadcast bottleneck. Each `notarize` message would be augmented with the relevant fragment. `k` would be set to the number of replicas, and `d` can be set as `f+1` so that the replicas only have a bandwidth requirement of about ~5 times the size of the full block. If a `notarization` exists, then at least `f+1` honest nodes have been distributed a fragment. This prevents `Byzantine` nodes from constructing a `notarization` without honest nodes being able to reconstruct the block among themselves. `d` can be set at higher values like `2f+1` to halve the required bandwidth, but replicas would have to ignore any gossiped `notarization` messages, instead making sure to gather the `2f+1` `notarize` messages themselves.
- To punish equivocating leaders, treat `propose` messages for different blocks in the same view as a slashable offense. To incentivize performant leaders, issue a reward for any block `c` included in the canonical chain.

## 11. Related Works

- <a id="fbc"></a>[Fast Byzantine Consensus](https://ieeexplore.ieee.org/document/1467815)
- <a id="simplex"></a>[Simplex Consensus: A Simple and Fast Consensus Protocol](https://eprint.iacr.org/2023/463)
- <a id="alpenglow"></a>[Solana Alpenglow Consensus: Increased Bandwidth, Reduced Latency](https://drive.google.com/file/d/1y_7ddr8oNOknTQYHzXeeMD2ProQ0WjMs/view)
- <a id="sing-a-song"></a>[Sing a song of Simplex (DispersedSimplex)](https://eprint.iacr.org/2023/1916)
- <a id="kudzu"></a>[Kudzu: Fast and Simple High-Throughput BFT](https://arxiv.org/abs/2505.08771)
- <a id="hydrangea"></a>[Hydrangea: Optimistic Two-Round Partial Synchrony with One-Third Fault Resilience](https://eprint.iacr.org/2025/1112)
- <a id="autobahn"></a>[Autobahn: Seamless high speed BFT](https://arxiv.org/abs/2401.10369)
- <a id="chonky"></a>[ChonkyBFT: Consensus Protocol of ZKsync](https://arxiv.org/abs/2503.15380)
- <a id="threshold"></a>[Threshold Simplex](https://docs.rs/commonware-consensus/latest/commonware_consensus/threshold_simplex/index.html)