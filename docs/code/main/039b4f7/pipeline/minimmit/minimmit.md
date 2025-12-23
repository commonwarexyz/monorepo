# Specification

_For a formal analysis of Minimmit, please refer to [arXiv](https://arxiv.org/abs/2508.10862)._

## 1. Introduction

Minimmit is a responsive, leader-based consensus protocol designed for simplicity and speed, tolerant of a Byzantine adversary that controls fewer than `20%` of replicas. Minimmit advances to the next view when a `40%` quorum is reached and finalizes blocks when an `80%` quorum is reached (after only a single round of voting). Minimmit can be instantiated with a number of practical optimizations to improve performance when deployed in production.

_Minimmit is so-named for the `2f + 1` proofs that provide its "faster block times". We call each proof a "mini" + "commit"._

## 2. Model & Parameters

- There is a set of `n` total replicas.
- At-most `f` are Byzantine or faulty, such that `n ≥ 5f + 1`.
- Partial synchrony: every message arrives within `Δ` after an unknown Global Stabilization Time (GST).

## 3. Quorums

- `M = 2f + 1`
- `L = n - f`

_There exists `≥ 1` honest replica in any `M`-set and `L`-set intersection._

## 4. Message Types

| Message | Purpose |
|---------|---------|
| `genesis` | The genesis block. Considered finalized at view `⊥ < 0`. |
| `propose(r, c, v, (c', v'))` | Leader `r`'s proposal `c` for view `v` with parent `c'` in view `v'`. |
| `notarize(c, v)` | Vote to finalize block `c` in view `v`. |
| `nullify(v)` | Vote to advance to view `v + 1`. |
| `notarization(c, v)` | Certificate of ≥ `M` `notarize(c, v)` messages for `(c, v)`. |
| `nullification(v)` | Certificate of ≥ `M` `nullify(v)` messages for view `v`. |
| `proof(v)` | Either a `notarization(c, v)` certificate for some block `c` or a `nullification(v)` certificate. |

## 5. Initial Replica State

A replica's (`r`'s) state contains the following fields:

- `view` is the replica's view, initially `0`
- `notarized` is the proposal this replica has notarized, initially `⊥`
- `nullified` is whether this replica has nullified this view, initially `false`
- `timer` is the time until nullifying (if `notarized == ⊥` and `!nullified` ), initially `2Δ`
- `proofs` is a map `View → Set<Certificate>` the set of certificates this replica has collected for each view, initially `{}`.
- `messages` is a map `View → (Replica → Set<Message>)` storing every message the replica has received, grouped first by view and then by sender, initially `{}`.

_We denote replica `r`'s state fields using dot notation (e.g., `r.view`, `r.timer`, etc.)._

## 6. External Functions

```text
// Select the leader replica for view `v`
fn leader(v) -> r;

// Build a block on top of `c'`. This should pass `verify(c, c')`.
fn build(c') -> c;

// Verify whether `c` is valid given the parent `c'`. Anything produced by
// `build(c')` should pass `verify(c, c')`.
fn verify(c, c') -> bool;
```

## 7. Helpers

_In every helper function, the first parameter `r` is the replica whose local state the helper inspects or updates._

```text
// Replica `r` selects a valid parent to build on
fn select_parent(r, v) -> (c', v') {
    let i = v - 1;
    while i >= 0 {
        if notarization(c', i) ∈ r.proofs[i] {
            return (c', i); // If there are multiple, pick any
        }
        if nullification(i) ∈ r.proofs[i] {
            i -= 1;
            continue;
        }
        return (⊥, ⊥); // No proofs for view i, cannot proceed
    }
    return (genesis, ⊥);
}

// Replica `r` ensures there are nullifications for all views `[v', v)` and that there is a `notarization(c', v')`
fn valid_parent(r, v, (c', v')) -> bool {
    let i = v - 1;
    while i > v' {
        if nullification(i) ∉ r.proofs[i] {
            return false;
        }
        i -= 1;
    }
    return notarization(c', v') ∈ r.proofs[v']
}

// Replica `r` enters view `next` if greater than the current view
fn enter_view(r, next) {
    if r.view >= next {
        return;
    }
    r.view = next;
    r.notarized = ⊥;
    r.nullified = false;
    r.timer = 2Δ;
}

// Replica `r` records a message, `m`, received from a replica `r'`
fn record_message(r, r', m) -> bool {
    if m.v ∉ r.messages {
        r.messages[m.v] = {};
    }
    if r' ∉ r.messages[m.v] {
        r.messages[m.v][r'] = {};
    }
    if m ∉ r.messages[m.v][r'] {
        r.messages[m.v][r'].add(m);
        return true;
    }
    return false;
}

// Replica `r` prunes data less than `view`
fn prune(r, view) {
    r.messages.remove(v => v < view);
    r.proofs.remove(v => v < view);
}
```

## 8. Protocol for Replica `r` in View `v`

### 8.1. Propose

_If replica `r` is the leader, propose._

1. On entering view `v`, if `leader(v) == r`:
   1. Let `(c', v') = select_parent(r, v)`.
   1. If `c' == ⊥`, return.
   1. Let `c = build(c')`.
   1. Set `r.notarized = c`.
   1. Broadcast `propose(r, c, v, (c', v'))`.

_Treat `propose(r, c, v, (c', v'))` as `r`'s `notarize(c, v)`._

### 8.2. Notarize

_Upon receipt of a first valid block proposal from leader, broadcast `notarize(c, v)`._

1. On receiving first `propose(r', c, v, (c', v'))` from `r' = leader(v)`:
   1. If `r.notarized != ⊥` or `r.nullified`, return.
   1. If `!valid_parent(r, v, (c', v'))`, return.
   1. If `!verify(c, c')`, return.
   1. Set `r.notarized = c`.
   1. Broadcast `notarize(c, v)`.

### 8.3. Nullify by Timeout

_If `timer` expires, broadcast `nullify(v)` if not yet broadcasted `notarize(c, v)`._

1. On `timer` expiry:
   1. If `r.notarized != ⊥` or `r.nullified`, return.
   1. Set `r.nullified = true`.
   1. Broadcast `nullify(v)`.

### 8.4. Notarization & Finalization

_After `M` messages, create and broadcast a `notarization(c, v)` certificate. After `L` messages, finalize._

1. On receiving `notarize(c, v)` from replica `r'`:
   1. If `!record_message(r, r', notarize(c, v))`, return.
1. On observing `≥ M` `notarize(c, v)` messages:
   1. Assemble `notarization(c, v)`.
   1. Add `notarization(c, v)` to `r.proofs[v]`.
   1. Broadcast `notarization(c, v)`.
   1. Call `enter_view(r, v + 1)`.
1. On observing `≥ L` `notarize(c, v)` messages:
   1. Finalize `c` and all of its ancestors.
   1. Call `prune(r, v)`.

### 8.5. Nullification

_After `M` messages, create and broadcast a `nullification(v)` certificate._

1. On receiving `nullify(v)` from replica `r'`:
   1. If `!record_message(r, r', nullify(v))`, return.
1. On observing `≥ M` `nullify(v)` messages (or a single `nullification(v)` message):
   1. Assemble `nullification(v)`.
   1. Add `nullification(v)` to `r.proofs[v]`.
   1. Broadcast `nullification(v)`.
   1. Call `enter_view(r, v + 1)`.

### 8.6 Nullify by Contradiction

_If you are in view `v` and have already broadcast `notarize(c, v)` for a `c` that cannot be finalized directly, broadcast `nullify(v)` to ensure some `proof(v)` will exist in view `v`._

1. A replica `r` with `r.view = v` and `r.notarized = b`, where `b != ⊥`, on observing messages from `≥ M` distinct replicas where each observed message is either `nullify(v)` or `notarize(b', v)` where `b' != b`:
   1. Set `r.nullified = true`.
   1. Broadcast `nullify(v)`.

## 9. Intuition

### 9.1 General

- A leader selected in `v + 1` may propose any block `c` that extends some known `notarization(c', v')` as long as there exist `nullification(j)` proofs for all views in `(v', v]`. Notably, this means that leaders are never required to re-propose a block from an earlier view and can only skip some block proposed in an earlier view `v` if there exists some `nullification(v)`.

### 9.2 Safety

- Honest replicas may not broadcast a `notarize(c, v)` after first broadcasting a `nullify(v)`.
- Honest replicas may broadcast a `nullify(v)` after first broadcasting a `notarize(c, v)`.
   - To broadcast both a `notarize(c, v)` and a `nullify(v)` message, a replica must first see that it is impossible for the proposal that it notarized to reach a quorum of `L` `notarize(c, v)` messages. Otherwise, the replica is forbidden from broadcasting `nullify(v)`, no matter how much time has passed.
   - A replica knows it is impossible for its notarized proposal `c` to reach the finalization quorum `L` once it has observed `M` other replicas that conflict. A conflicting replica has broadcast either a `nullify(v)` message or a `notarize(*, v)` message for a different proposal `*`.
   - If a replica has seen `M` conflicting votes, at least `M - f = f + 1` are from honest replicas. Therefore, the maximum number of `notarize(c, v)` it can observe is `n - (f + 1)`, or `4f` (strictly less than `L`).
- Suppose a correct leader broadcasts a block `c` and, after honest replicas broadcast `notarize(c, v)`, message delivery is disrupted, preventing any replica from observing `M` such messages. In this state, replicas have locked on `c` for view `v` and cannot broadcast some `nullify(v)`. Progress is stalled until network conditions improve, allowing a `notarization(c, v)` to be assembled, which in turn allows replicas to enter view `v + 1`.
- In any given view `v`, there may be multiple `notarization(*, v)` messages and one `nullification(v)`. If there are multiple `notarization(*, v)`s, no block `*` referenced by a `notarization(*, v)` can be finalized in `v`. If there exists some `nullification(v)`, no block can be finalized in `v`.

### 9.3 Liveness
- After GST, all views with honest leaders will:
   - Emit a `notarization` message before the timer of any honest replica expires. To see this is true:
      - The first honest replica broadcasts some `proof(v - 1)` message to all replicas and enters view `v` at time `t`.
      - The leader of view `v` will receive said `proof(v - 1)` message by `t + Δ` and broadcast some `propose(c, v, (c', v'))` message to all replicas.
      - All honest replicas will receive said `propose(c, v, (c', v'))` message by `t + 2Δ` and broadcast some `notarize(c, v)` message.
      - Since, by definition, the first honest replica entered the view at `t`, then none of the honest replica timers fired before broadcasting `notarize(c, v)`.
   - Finalize a block. To see this is true:
      - As above, each honest replica will broadcast `notarize(c, v)` before their timers expire.
      - As there are at least `L` honest nodes, each honest node will eventually see at least `L` `notarize(c, v)` messages.
- Faulty leaders can delay the network, however it still makes progress under good network conditions.
    - A crash-faulty leader can delay the network by at most `3Δ`. Let's assume that all honest replicas enter view `v` by time `t'` and set a `2Δ` timer. If the leader is faulty and sends no proposal, all timers will expire by `t' + 2Δ`, causing honest replicas to broadcast `nullify(v)`. These messages will be seen by all other honest replicas by `t' + 3Δ`, allowing them to form a `nullification(v)` and enter view `v+1`.
    - A Byzantine leader can delay the network by at most `4Δ`. This can happen if the leader equivocates by sending different proposals to different replicas, causing them to broadcast `notarize(*, v)` for different blocks. To see why, again assume all honest replicas enter view `v` by time `t'`. The first round of `notarize` messages are sent and received by `t' + 3Δ`. At this point, all honest replicas observe the conflicting votes and broadcast `nullify(v)`. This "second-round" vote is received by `t' + 4Δ`, allowing a `nullification(v)` to be created, allowing them to enter `v+1`.
    - These latency bounds are competitive despite the possibility of two rounds of voting. This is due to the timer being set to `2Δ`. For comparison, a protocol like Simplex with a `3Δ` timer would see replicas advance to the next view by `t' + 4Δ` regardless of whether the leader is crash-faulty or Byzantine.
- Every view `v` eventually produces at least one certificate `proof(v)`. As soon as a replica sees any `proof(v)` (as fast as `M` messages), it moves to view `v + 1`. If the network is partitioned in two, replicas in each half of the partition may continue to enter successive views (on different `proof(v)`s) but will never be able to finalize such blocks. To bound the depth of forks in a partition, replicas can wait to enter some view `v + k` until they have seen `L` messages in view `v`.

## 10. Extensions

Minimmit can be instantiated in several different ways to tune performance when deployed to production. Some examples are below:

- Use block digests (i.e. `c = hash(block)`) in `propose(c, v, (c', v'))`, `notarize(c, v)`, and `notarization(c, v)` messages.
- Employ BLS multi-signatures or BLS threshold signatures, like [Threshold Simplex](#threshold), to cap `notarization(c, v)` and `nullification(v)` messages at a constant size regardless of the number of replicas.
- Broadcast `nullify(v)` when entering the view of a leader that has been offline for some number of recent views, like [Threshold Simplex](#threshold). This reduces the effect of faulty or crashed nodes on a network's block production rate. Once the faulty replicas begin participating in consensus again, honest replicas can stop "fast-skipping" their views.
- Attach some recent set of `proof(v)` messages to each `propose(c, v, (c', v'))` message (to ensure honest replicas that are not yet aware of recent proofs can still broadcast a `notarize(c, v)` message for valid blocks).
- If `≥ f + 1` `notarize(c, v)` messages are observed for some `proposal(c, v, (c', v'))` considered invalid, request the missing `notarization(c, v')` or `nullification(v')` not found in our `proofs` (that prohibited us from broadcasting a `notarize(c, v)`) from the peers that consider it valid.
- If stuck in the same view `v` for time `t_s`, re-broadcast some `proof(v - 1)` (to ensure all correct replicas enter `v`) and re-broadcast `r.notarized` (if not `⊥`) and `r.nullified` (if not `false`).
- Assemble and broadcast a `finalization(c, v)` message after finalizing some `c` (i.e. `≥ L` `notarize(c, v)` messages). This can both help lagging replicas catch up to the finalized tip and make it easier for downstream services to integrate.
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
- <a id="threshold"></a>[Threshold Simplex](https://docs.rs/commonware-consensus/latest/commonware_consensus/simplex/index.html)
