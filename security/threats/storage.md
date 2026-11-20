# Storage

Part of the [Security Policy](../../SECURITY.md), under ["Threats"](../threats.md). Here "this file" means the whole policy.

## qmdb

1. Two honest nodes that applied the same finalized blocks hold databases with
   different roots, because the node that diverged votes against every valid
   block and never gets its own proposals accepted, and once more than `f` nodes
   diverge no block can be finalized.
2. A proof that a key holds a value the database never recorded as its current
   value verifies against a finalized root, because light clients, bridges, and
   rollup verifiers that accept the proof release funds or honor state the chain
   never agreed to, and the committed root gives them no way to detect the
   forgery.
3. An exclusion proof verifies for a key that is active in the database, because
   a verifier that trusts it treats an existing account, nullifier, or
   registration as absent, so an attacker can double spend a note, re-register
   an identity, or claim a balance that already belongs to someone else.
4. An honest node cannot produce a verifiable proof for a key that is active
   under a published root, because users whose withdrawals, bridge transfers, or
   settlements depend on presenting that proof are stuck, and the relaying
   service has no other source for it until the node is repaired or the state is
   re-committed.
5. State whose commit was reported durable is missing after a restart, because
   the node has already acknowledged the matching finalized blocks to marshal,
   marshal has pruned them and will not redeliver them, so the node must resync
   from peers, and if enough nodes lose the same state the finalized history
   survives only while some peer still holds it.
6. After a crash the database reopens at a state that was never committed,
   because the node builds on history the network never finalized, serves that
   history to syncing peers and proof requesters as if it were canonical, and
   the fault surfaces only when its root later disagrees with a finalized block.
7. A node fails to reopen its database after a crash or restart, because the
   validator stays out of the committee until an operator wipes the database and
   resyncs from peers, counts toward `f` while down, and a failure that
   reproduces on every node at the same point halts the network.
8. Pruning removes operations or Merkle nodes that the retained root, the
   inactivity floor, or a later restart still needs, because the node can no
   longer serve state sync or proofs for live keys, syncing peers and light
   clients that depend on it receive errors instead of data, and when the node
   restarts at a checkpoint whose history is gone it has to be rebuilt from
   peers.
9. Two replicas at the same root return different values for the same read,
   because an application that reads such a key while executing a block
   produces different state on different nodes, and the divergence appears as a
   root mismatch several blocks later with no record of which read caused it.
10. An honest validator crashes or exhausts memory while answering a peer's
    state sync request or decoding a peer's response, because the same cheap
    messages can be sent to every honest validator, so more than `f` validators
    are down at once and the network stops finalizing blocks.

## qmdb/store

1. Writes whose commit returned successfully are missing after a restart,
   because the application has already told its users and downstream systems
   the data is saved, so it loses or repeats work it believed complete and has
   no record of what was lost.
2. The store reopens with writes that were never committed, because the
   application resumes from a state it never acknowledged, and any external
   effect it tied to the commit boundary, such as a sent message or a released
   lock, is now inconsistent with what the store reports.

## qmdb/sync

Sync sources are untrusted and their responses are verified against the
requested target. The target is a trusted input chosen by the caller: sync
does not select or authenticate it (`storage/src/qmdb/sync/mod.rs`, "Trust
Model"). A threat that needs an attacker-chosen target belongs to the caller
that picks the target, such as `glue/src/stateful`.

1. A state sync completes and persists a database whose history is not the one
   the target root commits to, because the node joins the committee holding
   state the network never agreed on, executes and votes on blocks from it,
   serves it to the next syncing node and to proof requesters, and the error is
   noticed only when its root first disagrees with a finalized block.
2. A node that is syncing from peers never reaches its target although honest
   peers hold the data, because the node cannot join or rejoin the committee,
   counts toward `f` for as long as it is stuck, and several nodes recovering at
   once can leave the network below quorum while the attacker pays only for a
   few bad responses.
3. A failed or interrupted sync leaves the node with durable state it can
   neither resume from nor reopen as its previous database, because the node
   loses its last good local checkpoint, must be wiped and resynced from
   scratch, and its downtime grows from a restart to a full state transfer
   during which it counts toward `f`.
4. A syncing node runs out of memory while one slow or withholding peer leaves a
   request unanswered, because the node is killed before it ever joins the
   committee, and an attacker who controls one of the peers it fetches from can
   repeat this at no cost beyond keeping a connection open.

## merkle

1. A proof verifies for an element at a location the structure never held,
   because a light client or bridge releases funds or accepts a cross-chain
   message for an operation no validator ever committed, and the certified root
   lends that fabrication the authority of the whole committee.
2. Two honest nodes compute different roots from the same sequence of appended
   elements, because the validators disagree on the state root of every block
   from then on, the side with fewer nodes is outvoted and treated as faulty,
   and nobody can tell which history is wrong without manual inspection.
3. A node panics while computing its root or pinning nodes after it has pruned
   old history, because the database stops accepting blocks until an operator
   rebuilds it from an unpruned peer, and the node is out of the committee for
   the whole rebuild.
4. A persisted structure reopens after a crash with a root different from the
   one it had committed and reports no error, because the node resumes voting
   on state roots no other validator can reproduce, is outvoted on every block,
   and the only remedy is for an operator to notice, wipe its storage, and
   resync.
5. A persisted structure refuses to reopen after a crash or an interrupted
   state sync, because the node stays out of the committee until an operator
   deletes its state and completes a full resync, and it counts toward `f` the
   whole time.
6. A syncing node accepts operations or pinned nodes from a peer that do not
   belong to the database with the target root, because it finishes the
   download only to fail the final root check, discards everything, and starts
   over, so one malicious source can keep a new validator from ever joining
   while it counts toward `f`.
7. A proof generated by an honest node fails to verify at another honest node,
   because light clients and bridges reject genuine state, state sync stalls
   while the honest source is marked invalid, and new validators cannot join.
8. A node's memory or CPU is exhausted while decoding or verifying a
   peer-supplied proof, because the same proof can be sent to every validator
   that serves or runs state sync, so more than `f` validators are killed by
   the OS or fall behind the chain at once while the attacker spends only
   bandwidth.

## bmt

On `main` the same tree also commits Bajillion payment maps and matrices
(`clearing/src/bajillion`), so the threats below apply to those commitments
as well as to shards.

1. A shard proof verifies against a commitment for shard data the encoder never
   placed at that index, because honest nodes decoding the same certified
   commitment reconstruct different block bodies or fail to decode, so a block
   the committee finalized has no single agreed content and execution forks or
   stops.
2. Two different sets of leaves produce the same root, because an encoder can
   hand different validators different shards under one commitment, the
   committee certifies a commitment that identifies no single block, and the
   chain's content at that height depends on which shards each node received.
3. A shard proof produced by an honest encoder fails to verify at an honest
   receiver, because the receiver blocks the peer that relayed it as a sender of
   invalid shards and drops a shard it needed, and when enough receivers do this
   the block cannot be reconstructed and the honest leader's slot is lost.
4. A node panics or exhausts memory while verifying a peer-supplied shard
   proof, because every shard delivery is a chance to trigger it and the same
   proof can be sent to every honest validator, so more than `f` validators are
   down at once and consensus halts until they are restarted.

## bitmap

1. A proof verifies a bit with the opposite value from the one the bitmap
   holds, because a verifier that uses the bit to tell live state from history
   accepts a superseded balance or an already consumed withdrawal as current, or
   rejects a live one, and a bridge paying out on that answer loses the funds.
2. Two honest nodes compute different roots for the same sequence of bits,
   because the combined operations and activity root a current database commits
   per block differs across validators, they disagree on the state root of every
   later block, and the minority side is outvoted and treated as faulty.
3. A bitmap restored from its persisted pruned state plus a replay of retained
   elements has a different root than it had before the restart, because the
   node's current-state root diverges from the network after every restart and
   stays wrong until an operator wipes and resyncs it.
4. A node panics when asked for a bit or a proof at an already pruned location,
   because a caller that exposes location-addressed queries to peers or clients
   goes down on one request and goes down again on every retry until an
   operator restarts it.

## journal

1. An item that `sync` reported durable is missing from replay after a restart,
   because the simplex voter relies on replay to remember the votes it already
   broadcast, signs a conflicting vote or nullify for the same view, and the
   equivocation evidence it produces gets an honest validator slashed and
   removed from the committee.
2. The item returned for a position or offset is not the item that was appended
   there, because callers address Merkle leaves, operations, and votes by
   position, rebuild authenticated state or vote history from the wrong
   records, and end up with a state root or vote set that no other honest node
   shares.
3. A journal that opened cleanly before fails to open or replay after a restart,
   because the voter, the aggregation engine, and the DKG reshare store all
   panic at startup, the validator stays out of the committee until an operator
   deletes the journal by hand, and deleting it also throws away the vote record
   that stops the node from equivocating.

## archive

1. A read of a block or certificate that was committed long ago fails with a
   corruption error, because marshal panics on any archive read error, a peer
   can trigger that read by requesting the block, and the node crashes every
   time it is asked until an operator repairs the files by hand.
2. An index below the prune floor is stored and served again after a restart,
   because the archive's range reports count it as present, marshal's gap repair
   requests every height between it and the live floor from peers, and the node
   spends bandwidth and disk on history it had already discarded.
3. An archive that reported a successful sync comes back empty, or rewound to an
   earlier commit, after a restart, because the finalized blocks and
   certificates marshal already acknowledged to the application are gone,
   marshal's recorded processed position has no stored block behind it, and the
   node panics on startup until an operator wipes its state and resyncs from
   peers.
4. The archive reports a height as present that it cannot serve, because marshal
   panics during gap repair, the application stops receiving finalized blocks
   at that height, and the node falls permanently behind the chain.
5. Archive initialization fails on a damaged or mismatched record, because
   marshal and the DKG bootstrap panic before they can deliver or serve
   anything, and the validator stays out of the committee until an operator
   intervenes.

## freezer

1. Lookups for keys that share a table slot with attacker-chosen keys take one
   disk read per colliding key, because the slot is the CRC32 of the key
   masked to the table size, a Byzantine proposer can grind a block digest
   into the slot of an honest block in about as many hash tries as the table
   has entries, and every honest validator's lookups for blocks in that slot
   stay slow for as long as the archive is retained.

## metadata

1. The store comes back holding the previous version's values after a restart
   that followed a successful sync, because the archives and marshal caches that
   use it as their commit record rewind to an older checkpoint and delete data
   written since, and a stale DKG state-sync plan that was already removed is
   present again at the next startup and is used again if the recovered epoch
   does not exceed the plan's floor epoch.
2. Metadata initialization fails with a corruption error, because every store
   built on it panics at startup, the node stays down, and the only operator
   remedy is to delete the metadata, which then wipes the archives that depend
   on it.

## ordinal

1. A record the caller marked as committed is reported present but fails to
   read, because consumers treat presence as truth, marshal's gap repair panics
   when the read fails, and the node cannot finish startup.

## index

1. Lookups and inserts for attacker-chosen keys take time linear in the number
   of colliding keys, because a QMDB-backed application pushes every operation
   of every block through the index, block execution slows on each honest node
   that uses the same translator, and validators miss view deadlines while the
   attacker pays only the cost of grinding short key prefixes.
2. A lookup yields values that were stored under other keys, because a caller
   that treats the first value as the answer reads or overwrites a different
   record, and in a key-value database that means one account's slot is read or
   updated in place of another's.

## queue

1. An item is delivered to the reader a second time after a restart, because a
   consumer that performs a side effect per item, such as sending a message or a
   payment, repeats it.
2. An item the writer accepted is gone after a restart, because the writer's
   caller already treated the work as handed off, nothing re-enqueues it, and
   the task is silently never performed.

## translator

1. Keys chosen by an attacker collide in the translated key space, because every
   structure keyed through the translator degrades to a linear scan over the
   colliding records, and with the marshal cache keyed by the first two bytes of
   block digests, without the seeded collision-resistant wrapper that
   `storage/src/translator.rs` provides, a Byzantine proposer can grind
   digests cheaply to slow the lookups every honest validator performs on each
   view.
