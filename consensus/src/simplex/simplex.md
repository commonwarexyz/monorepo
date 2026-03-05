# Specification


## 1. Introduction

This is a specification of modification of the [Simplex Consensus](https://eprint.iacr.org/2023/463). It targets:

- Network-speed view latency (about `2` network hops to notarization).
- Optimal finalization latency (about `3` network hops).
- Partial synchrony.

Simplex externalizes proof artifacts (`notarization`, `nullification`, `finalization`) so downstream systems can consume standalone certificates of progress.

## 2. Model & Parameters

- Replicas proceed in views `v = 1, 2, ...`.
- Genesis is view `0` and is implicitly finalized.
- Partial synchrony: after GST, messages arrive within `Δ`.
- Byzantine threshold is parameterized by `f`, with quorum threshold `Q` according to `utils/src/faults.rs`.
- `lookback` is the leader-activity window (for fast skip of inactive leaders).
- `T` is the retry period used by the retry timer.

## 3. Quorums and Certificates

- `Q` votes from unique replicas are required to assemble a certificate.
- Vote/certificate pairs:
  - `notarize(c, v)` -> `notarization(c, v)`
  - `nullify(v)` -> `nullification(v)`
  - `finalize(c, v)` -> `finalization(c, v)`

When `Q` votes of a given type are collected from distinct participants, the corresponding certificate can be assembled and disseminated as proof of progress.

## 4. Message Types

| Message | Purpose                                                                  |
|---------|--------------------------------------------------------------------------|
| `genesis` | Initial finalized state at view `0` (implicit finalization certificate). |
| `notarize(c, v)` | Leader proposal and replica vote for container `c` in view `v`.          |
| `notarization(c, v)` | Certificate of `≥ Q` `notarize(c, v)` votes.                             |
| `nullify(v)` | Vote to abandon progress in view `v` and advance.                        |
| `nullification(v)` | Certificate of `≥ Q` `nullify(v)` votes.                              |
| `finalize(c, v)` | Vote to finalize container `c` in view `v` after certification.          |
| `finalization(c, v)` | Certificate of `≥ Q` `finalize(c, v)` votes.                          |
| `request(v_m)` | Catch-up request for missing proof material from prior view `v_m`.       |

## 5. Replica State and Timers

Replica `r` tracks, per view `v`:

- `view` is the replica view, initially `1`.
- `nullified` is whether `nullify(v)` has already been broadcast.
- `proofs` is a map `View -> Set<Certificate>` where `Certificate` is only one of:
  - `finalization(c, v)`
  - `notarization(c, v)`
  - `nullification(v)`
- `messages` is a map `View -> (Replica -> Set<Message>)` storing received vote messages
  (`notarize`, `nullify`, `finalize`) grouped by view then sender.
- Timer `t_l` (leader proposal timeout).
- Timer `t_a` (advance/certification timeout).
- Timer `t_r` (retry timeout).

Timer semantics:

- `t_x = Some(d)` means timer `t_x` is armed with deadline `d`.
- `t_x = None` means timer `t_x` is canceled.
- `t_x = 0` is shorthand for immediate expiry (`Some(now)`).
- Timer `t_x` fires iff `t_x = Some(d)` and `now >= d`.

## 6. External Functions / Predicates

```text
// Deterministic leader selection.
fn leader(v) -> r;

// Build or fetch a container to propose in view v on top of parent `(c_parent, v_parent)`.
fn propose(v, (c_parent, v_parent)) -> Option<c>;

// Verify container c against protocol/application validity rules.
fn verify(c) -> bool;

// Application-level certification gate for notarized containers.
fn certify(c) -> bool;

// Request missing view proof material.
fn request(v_m);
```

### 6.1 Helpers

```text
// Selects the best parent proof for a leader proposal in view `v`.
// Returns either a parent `(c_parent, v_parent)` or a missing view `v_m` that must be requested.
fn select_parent(r, v) -> Result<(c_parent, v_parent), v_m> {
    let i = v - 1;
    while i > 0 {
        if finalization(c_parent, i) ∈ r.proofs[i] {
            return Ok((c_parent, i));
        }
        // TODO: Align with implementation in `actors/voter/state.rs` (`is_certified`):
        // select the first certified ancestor, instead of modeling this as
        // `notarization(c_parent, i) ∈ r.proofs[i] and certify(c_parent)`.
        if notarization(c_parent, i) ∈ r.proofs[i] and certify(c_parent) {
            return Ok((c_parent, i));
        }
        if nullification(i) ∈ r.proofs[i] {
            i -= 1;
            continue;
        }
        return Err(i); // Missing proof for view i.
    }
    return Ok((genesis, 0));
}

// Validates a claimed parent `(c_parent, v_parent)` for a proposal in view `v`.
// Returns `Ok(true)` if valid, `Ok(false)` if invalid, and `Err(v_m)` if missing proof for view `v_m`.
fn valid_parent(r, v, (c_parent, v_parent)) -> Result<bool, v_m> {
    if v_parent == 0 {
        return Ok(c_parent == genesis);
    }

    if finalization(c_parent, v_parent) ∉ r.proofs[v_parent] {
        if notarization(c_parent, v_parent) ∉ r.proofs[v_parent] {
            return Err(v_parent); // Missing parent proof.
        }
        if !certify(c_parent) {
            return Ok(false);
        }
    }

    let i = v - 1;
    while i > v_parent {
        if nullification(i) ∉ r.proofs[i] {
            return Err(i); // Missing bridge proof.
        }
        i -= 1;
    }
    return Ok(true);
}

// Records message `m` from replica `r'`. Returns true only on first observation.
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

// Replica `r` enters `next` iff `next` is ahead of the current view.
fn enter_view(r, next) {
    if r.view >= next {
        return;
    }
    r.view = next;
    r.leader = leader(next);
    r.nullified = false;
    r.t_l = now + 2Δ;
    r.t_r = None;
    r.t_a = now + 3Δ;
    if r.leader has not been active in the last lookback views {
        r.t_l = 0;
        r.t_a = 0;
    }
}

// Returns the strongest certificate known for view `v`.
// Mirrors `get_best_certificate` behavior in voter state.
// Priority: finalization > nullification > notarization.
fn get_best_vertificate(r, v) -> Option<certificate> {
    if finalization(c, v) ∈ r.proofs[v] {
        return finalization(c, v);
    }
    if nullification(v) ∈ r.proofs[v] {
        return nullification(v);
    }
    if notarization(c, v) ∈ r.proofs[v] {
        return notarization(c, v);
    }
    return None;
}
```

## 7. Protocol for Replica `r` in View `v`

### 7.1. View Entry

1. On entering view `v`:
   1. Determine leader `l = leader(v)`.
   1. Set `t_l = now + 2Δ`, `t_r = None`, and `t_a = now + 3Δ`.
   1. If `l` has not been active in the last `lookback` views, set `t_l = 0` and `t_a = 0`.
   1. If `r == l`, attempt to propose:
      1. Let `parent = select_parent(r, v)`.
      1. If `parent = Err(v_m)`, send `request(v_m)`, set `t_l = 0`, and return.
      1. Let `c = propose(v, parent)`.
      1. If `c = None`, set `t_l = 0`, and return.
      1. Broadcast `notarize(c, v)`.

### 7.2. First Leader Notarize

1. On receiving the first `notarize(c, v)` from leader `l`:
   1. If `!record_message(r, l, notarize(c, v))`, return.
   1. Set `t_l = None`.
   1. Let `(c_parent, v_parent)` be `c`'s declared parent.
   1. Let `parent_ok = valid_parent(r, v, (c_parent, v_parent))`.
   1. If `parent_ok = Err(v_m)`, send `request(v_m)` and return.
   1. If `parent_ok = Ok(false)`, return.
   1. Verify `c`.
   1. If verification succeeds, broadcast `notarize(c, v)`.
   1. If verification fails, set `t_l = 0`.

### 7.3. First Leader Nullify

1. On receiving first `nullify(v)` from leader `l`:
   1. If `!record_message(r, l, nullify(v))`, return.
   1. Set `t_l = 0`.

### 7.4. Notarization Path

1. On receiving `notarize(c, v)` from replica `r'`:
   1. If `!record_message(r, r', notarize(c, v))`, return.
1. On observing `≥ Q` `notarize(c, v)` votes:
   1. Mark `c` as notarized.
   1. Assemble `notarization(c, v)` (even if `c` itself is not yet verified locally).
   2. Add `notarization(c, v)` to `r.proofs[v]`.
1. On constructing or receiving first `notarization(c, v)`:
   1. Broadcast `notarization(c, v)`.
   1. Attempt `certify(c)`:
      1. On success:
         1. Set `t_a = None`.
         1. If `!r.nullified`, broadcast `finalize(c, v)`.
         1. Call `enter_view(r, v + 1)`.
      1. On failure:
         1. Set `t_l = 0`.

### 7.5. Nullification Path

1. On receiving `nullify(v)` from replica `r'`:
   1. If `!record_message(r, r', nullify(v))`, return.
1. On observing `≥ Q` `nullify(v)` votes:
   1. Assemble `nullification(v)`.
   2. Add `nullification(v)` to `r.proofs[v]`.
1. On constructing or receiving the first `nullification(v)`:
   1. Set `t_l = None` and `t_a = None`.
   1. If `!r.nullified`, set `r.nullified = true` and broadcast `nullify(v)`.
   1. Broadcast `nullification(v)`.
   1. Call `enter_view(r, v + 1)`.

### 7.6. Finalization Path

1. On receiving `finalize(c, v)` from replica `r'`:
   1. If `!record_message(r, r', finalize(c, v))`, return.
1. On observing `≥ Q` `finalize(c, v)` votes:
   1. Assemble `finalization(c, v)`.
   2. Add `finalization(c, v)` to `r.proofs[v]`.
1. On constructing or receiving the first `finalization(c, v)`:
   1. Set `t_l = None` and `t_a = None`.
   1. Mark `c` finalized and recursively finalize ancestors.
   1. Broadcast `finalization(c, v)` (even if `c` itself is not yet verified locally).
   1. Call `enter_view(r, v + 1)`.

### 7.7. Timeout Behavior

1. On `t_l` or `t_a` firing:
   1. If `!r.nullified`:
      1. Set `r.nullified = true`.
      1. Broadcast `nullify(v)`.
      1. Set `t_r = now + T`.
1. On `t_r` firing:
   1. Broadcast `nullify(v)`.
   1. Let `cert = get_best_vertificate(r, v - 1)`.
   1. If `cert != None`, broadcast `cert`.
   1. Set `t_r = now + T`.
