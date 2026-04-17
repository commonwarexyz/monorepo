# The canonical `Trace` format and how it becomes Quint

## 1. On-disk shape

A `Trace` is a JSON document with three top-level fields:

```jsonc
{
  "topology": { "n": 4, "faults": 0, "epoch": 0,
                "namespace": "636f6e73656e7375735f66757a7a",
                "timing": { "leader_timeout_ms": 1000, /* ... */ } },
  "events":   [ /* ... ordered event stream ... */ ],
  "expected": { "nodes": [ /* per-correct-replica observable state */ ] }
}
```

- **`topology`** pins down the world: how many replicas (`n`), how many
  are Byzantine (`faults` — indices `0..faults`), the signing namespace,
  the epoch, and the timeout knobs. This is everything `replay(&Trace)`
  and `rehydrate_keys(&Topology)` need to reconstruct an
  identical-signing replica set.
- **`events`** is the entire causal history — not just network traffic,
  but also locally-authored actions and timeouts. Four variants, in this
  order of abstraction (low → high):
  - `Deliver { to, from, msg: Wire }` — a message arrived at `to`. `msg`
    is either `Wire::Vote(signed vote)` or `Wire::Cert(signed
    certificate)`, both with real cryptographic payloads as hex.
  - `Construct { node, vote }` — `node` locally produced a signed vote
    (notarize/nullify/finalize). This is fundamentally different from
    `Deliver`: it says "this replica authored this vote", not "this
    replica received a vote".
  - `Propose { leader, proposal }` — the leader of a view produced a
    fresh proposal. The `Construct(Notarize)` that immediately follows
    carries the leader's own notarize for that proposal.
  - `Timeout { node, view, reason }` — a replica's leader-timeout or
    certification-timeout fired.
- **`expected`** is a `Snapshot`: per-correct-replica observable state
  (`notarizations`, `nullifications`, `finalizations`, `certified`,
  per-view signer sets for each vote kind, and `last_finalized`).
  Byzantine indices contribute no `NodeSnapshot`. The snapshot lets
  `replay_trace` check replay-equivalence without re-running Quint.

## 2. How events are produced

- `fuzz/src/tracing/record.rs` wraps a live 4-node run:
  - A `Recorder::new(participants)` is shared across all engines.
  - Each replica's vote receiver/sender is wrapped by
    `RecordingReceiver` / `RecordingSender`; its application is wrapped
    by `RecordingApp`.
  - `RecordingSender::send` pushes an `Event::Construct` before
    forwarding (this replica authored this vote).
  - `RecordingReceiver::recv` pushes an `Event::Deliver` after decoding
    (this replica received this message from that peer).
  - `RecordingApp::on_propose` pushes an `Event::Propose` when the app
    emits a proposal.
  - The keyset must match what `rehydrate_keys` computes — we
    pre-derive via a nested `Runner::seeded(0)` so the fuzz runtime's
    FuzzRng doesn't bias key derivation.
- `recorder.freeze(topology, snapshot)` bakes the collected events +
  provided snapshot into a `Trace`.
- `static_honest.rs` synthesizes the same event shape analytically
  without running the engine (for fast fuzz-seed generation).

## 3. Quint encoding is a three-stage pipeline

All three stages live in `fuzz/src/tracing/encoder.rs`.

### Stage A: `build_block_map_from_events(&events)`

Scans every `Event::Propose` and
`Event::Deliver { msg: Vote(Notarize|Finalize) | Cert(Notarization|Finalization) }`,
collects each distinct proposal-payload hex (`Sha256Digest` → 64-char
hex), and assigns each one the name `val_b0`, `val_b1`, … in first-seen
order. Returns `Vec<(hex, name)>`.

Quint can't work with 64-char hex digests — it has a small finite
`VALID_PAYLOADS` set. This map is the bijection.

### Stage B: `lower_events_to_actions(&events, &block_map, faults) -> Vec<ActionItem>`

A 1:1 lowering — no causal reconstruction, just direct per-event
translation with two mandatory filters for `faults > 0`:

| Event | ActionItem | Notes |
|---|---|---|
| `Propose { leader, proposal }` | `Propose { leader, view, parent_view, payload }` | **Dropped** if `leader < faults` (Quint doesn't model Byzantine replicas; the proposal gets introduced by the following `Construct`). |
| `Construct { node, Vote::Notarize(n) }` | `SendNotarizeVote { view, parent_view, payload, sig }` | Signer is the signed vote's `signer()`, not `node`. Byzantine signers still emit this — it's a pure network barrier. |
| `Construct { node, Vote::Nullify(n) }` | `SendNullifyVote` | |
| `Construct { node, Vote::Finalize(f) }` | `SendFinalizeVote` | |
| `Deliver { to, from, Wire::Vote(Notarize) }` | `OnNotarize { receiver, view, parent_view, payload, sig }` | **Dropped** if `to < faults` (Byzantine receivers have no modeled state; `replica_state.get("n0")` would panic). |
| `Deliver { to, from, Wire::Vote(Nullify) }` | `OnNullify` | Same filter. |
| `Deliver { to, from, Wire::Vote(Finalize) }` | `OnFinalize` | Same filter. |
| `Deliver { to, from, Wire::Cert(c) }` | `SendCertificate` (on first sighting of this `(ghost_sender, cert)`) + `OnCertificate { receiver, cert }` | `SendCertificate` is a network-availability barrier and fires even for Byzantine receivers; only `OnCertificate` is gated. |
| `Timeout { ... }` | — | Quint models timeouts indirectly via the nullify votes that follow; no direct `on_timeout` is emitted. |

### Stage C: `render_quint_from_actions(&cfg, &events, &block_map, &proposals, &actions, &reporter_states) -> String`

Builds the `.qnt` test module. Rough skeleton:

```quint
module tests {
    import types.*  from "../types"
    import defs.*   from "../defs"
    import option.* from "../option"
    import automaton(CERTIFY_DOMAIN = Set("val_b0", ...)) as app from "../automaton"
    import replica(
        N = 4, F = 1, Q = 3,
        CORRECT     = Set("n1","n2","n3"),
        BYZANTINE   = Set("n0"),
        REPLICA_KEYS = Map("n0"->"n0", "n1"->"n1", ...),
        VIEWS       = 1.to(19),
        VALID_PAYLOADS = Set("val_b0","val_b1",...),
        INVALID_PAYLOADS = Set(),
        ACTIVITY_TIMEOUT = 10
    ).* from "../replica"

    // One named value per (view, parent, block_name) seen in events:
    pure val proposal_v1_p0_val_b0 = { payload: "val_b0", view: 1, parent: 0 }
    pure val proposal_v2_p1_val_b1 = { payload: "val_b1", view: 2, parent: 1 }
    // ...

    // Per-replica certify-policy map:
    pure val CERTIFY_POLICY = Set(GENESIS_PAYLOAD, "val_b0", /* ... */)
    pure val CERTIFY_CUSTOM = Replicas.mapBy(_ => CERTIFY_POLICY)

    // Helper actions (see below for send_*_vote semantics).
    action send_notarize_vote(vote: NotarizeVote) = all { /* ... */ }
    action send_nullify_vote(vote: NullifyVote)   = all { /* ... */ }
    action send_finalize_vote(vote: FinalizeVote) = all { /* ... */ }
    action send_certificate(cert: Certificate)    = all { /* ... */ }

    // Action chain, chunked into trace_part_NN for readability:
    action trace_part_00 =
        initWithLeaderAndCertify(
            Map(0->"n1", 1->"n3", 2->"n3", 3->"n0", 4->"n1", 5->"n2"),
            CERTIFY_CUSTOM
        )
        .then(propose("n3", "val_b0", 0))
        .then(send_notarize_vote({ proposal: proposal_v1_p0_val_b0, sig: "n3" }))
        .then(on_notarize("n1", { proposal: proposal_v1_p0_val_b0, sig: "n3" }))
        .then(on_notarize("n2", { proposal: proposal_v1_p0_val_b0, sig: "n3" }))
        // ...
        .expect(safe_invariants)

    run traceTest =
        trace_part_02
            .expect(safe_invariants)
            .expect(replica_state.get("n1").last_finalized >= 1)
            .expect(replica_state.get("n2").last_finalized >= 1)
            .expect(replica_state.get("n3").last_finalized >= 1)
}
```

Three non-obvious details in this stage:

1. **Leader map is read from the trace, not computed.**
   `build_leader_map_to(cfg, max_view, events)` walks every
   `Event::Propose` and records `view -> leader.get()`; it only falls
   back to `(epoch + view) % n` for views that have no recorded
   `Propose`. This matters because twins scenarios / Random / VRF
   electors don't follow round-robin.

2. **`send_*_vote` helpers are not pure network barriers** — they also
   mirror the vote into the signer's local vote store when the signer
   is correct:
   ```quint
   store_notarize_votes' = if (CORRECT.contains(vote.sig))
       store_notarize_votes.set(vote.sig,
           store_notarize_votes.get(vote.sig).union(Set(vote)))
       else store_notarize_votes
   ```
   This matches the Rust model: `Event::Construct` for a correct node
   is "this replica locally authored a vote", which updates its state,
   not just the network. Without this, `n1`'s self-nullify would be
   invisible to `n1`'s own quorum check.

3. **`send_certificate` is emitted once per
   `(ghost_sender, dedup_key)`**, not once per delivery. A cert may be
   `Deliver`ed to all four replicas; we want one `send_certificate`
   into the network and one `on_certificate` per correct receiver.

## 4. Example: one view of an honest 4-node trace

Recorded events, in order, for view 1 with leader n2:

```
Propose    { leader: 2, proposal { view: 1, parent: 0, payload: sha(val_b0) } }
Construct  { node: 2, vote: Notarize(n2, ...) }
Deliver    { to: 0, from: 2, Vote(Notarize n2) }
Deliver    { to: 1, from: 2, Vote(Notarize n2) }
Deliver    { to: 3, from: 2, Vote(Notarize n2) }
Construct  { node: 0, vote: Notarize(n0, ...) }   // n0 echoes after seeing leader vote
Construct  { node: 1, vote: Notarize(n1, ...) }
Construct  { node: 3, vote: Notarize(n3, ...) }
Deliver    { to: 0, from: 1, Vote(Notarize n1) }
// ...all the peer deliveries...
Deliver    { to: 0, from: 0, Cert(Notarization) }   // cert broadcast
Deliver    { to: 1, from: 0, Cert(Notarization) }
// ...finalize votes + cert...
```

Lowers to:

```
Propose           leader="n2"  view=1  parent=0  payload="val_b0"
SendNotarizeVote  view=1  parent=0  payload="val_b0"  sig="n2"
OnNotarize        receiver="n0"  view=1  parent=0  payload="val_b0"  sig="n2"
OnNotarize        receiver="n1"  ...
OnNotarize        receiver="n3"  ...
SendNotarizeVote  sig="n0"   # from Construct
SendNotarizeVote  sig="n1"
SendNotarizeVote  sig="n3"
OnNotarize        receiver="n0"  sig="n1"
// ...
SendCertificate   cert=Notarization(v=1, signers=[n0,n1,n2,n3], ghost="n0")
OnCertificate     receiver="n0"  ...
OnCertificate     receiver="n1"  ...
// ...
SendFinalizeVote  ...
OnFinalize        ...
SendCertificate   cert=Finalization(...)
OnCertificate     ...
```

Which renders into the Quint chain:

```quint
.then(propose("n2", "val_b0", 0))
.then(send_notarize_vote({ proposal: proposal_v1_p0_val_b0, sig: "n2" }))
.then(on_notarize("n0", { proposal: proposal_v1_p0_val_b0, sig: "n2" }))
.then(on_notarize("n1", /* ... */))
.then(on_notarize("n3", /* ... */))
.then(send_notarize_vote({ proposal: proposal_v1_p0_val_b0, sig: "n0" }))
.then(send_notarize_vote({ proposal: proposal_v1_p0_val_b0, sig: "n1" }))
.then(send_notarize_vote({ proposal: proposal_v1_p0_val_b0, sig: "n3" }))
.then(on_notarize("n0", { proposal: proposal_v1_p0_val_b0, sig: "n1" }))
// ...
.then(send_certificate(notarization(proposal_v1_p0_val_b0,
                                    Set("n0","n1","n2","n3"), "n0")))
.then(on_certificate("n0", notarization(/* ... */)))
// ...
```

The same `Vec<ActionItem>` is what `tlc_encoder::encode_from_trace`
renders into the JSON action sequence posted to tlc-controlled —
identical semantic walk, different target syntax. The JSON variant must
also terminate the action sequence with `{"reset": true}` so the TLC
server's `simulate(..., is_reset=true)` loop exits cleanly; see
`tlc::terminate_actions`.

## 5. Quint's side of the contract

The emitted `.qnt` imports `replica.qnt`, which maintains per-replica
state machines. Our generated file adds a `traceTest` run that:

1. Seeds the initial state with
   `initWithLeaderAndCertify(LEADER_MAP, CERTIFY_CUSTOM)`.
2. Fires each `ActionItem` via `.then(...)`.
3. Asserts `safe_invariants` holds throughout, and per-replica
   `last_finalized >= required_containers` at the end.

Once Quint accepts the trace, `quint_model::validate_and_extract_expected`
reads the final ITF state (via `--out-itf`) and reconstructs the
expected `Snapshot` by walking `replica_state`, the split
`store_{notarize,nullify,finalize}_votes` maps, and `store_certificates`.
That snapshot is what then gets embedded back into `Trace.expected` for
downstream `replay_trace` equivalence checking.
