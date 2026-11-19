# Runtime

Part of the [Security Policy](../../SECURITY.md), under ["Threats"](../threats.md). Here "this file" means the whole policy.

## storage

1. A vote the node already broadcast is missing from its journal when the node
   restarts after a crash, because the restarted node treats that view as
   unvoted, signs a conflicting vote, and the resulting equivocation is
   slashable and shrinks the honest majority the protocol depends on.
2. A write sequence that survives power loss on a developer's macOS machine
   loses its earlier unsynced bytes on a Linux validator, because the recovery
   path that handles the resulting gap is never exercised before deployment,
   and the first time it runs is on a live validator's vote journal.
3. Two processes write the same storage directory at the same time, each
   believing it is the only instance of that validator, because both sign and
   broadcast votes under the same key, their interleaved writes corrupt each
   other's recovery state, and the validator is slashed for equivocating against
   itself.
4. A restarted node blocks before user code runs, waiting for the storage
   directory hold while the previous process's storage threads are still alive,
   because the validator is absent from the committee and counted toward `f`
   for as long as nobody notices, and the only signal is one warning log line.
5. After a power loss a blob holds a record that is partly new bytes and partly
   old bytes, because a reader that trusts the blob length or a record's own
   length prefix decodes garbage as a vote or a block, and either refuses to
   start or acts on data nobody wrote.
6. A blob whose creation was interrupted by a crash fails every later open with
   a corruption, layout, or version error, because the node cannot start until
   an operator identifies and deletes the half-created file, and it stays out
   of the committee the whole time.
7. A write or resize whose future the caller dropped completes on disk after the
   caller has moved on, because the caller's later writes land at offsets
   computed from a stale size, overwrite live records or leave holes that
   recovery trims, and committed entries disappear.

## network and I/O

1. The runtime allocates a receive buffer of the full requested length before a
   single byte arrives, because one unauthenticated host can make every
   validator it connects to allocate gigabytes, so more than `f` validators are
   killed by the OS at once while the attacker sends only a few bytes.
2. Every I/O request on an io_uring worker stalls behind receives that occupy
   all of the ring's in-flight slots, because journal syncs and sends to honest
   peers on that worker wait up to the receive timeout, the node misses its view
   deadlines, and the attacker needs only idle connections.
3. The listener reports a terminal-looking error for a transient accept failure
   such as descriptor exhaustion, because the consumer either stops accepting
   inbound connections for the life of the process or retries in a hot loop
   that starves the other tasks on that worker, and honest peers cannot dial in
   while the attacker pays only for half-open connections.
4. A connection to an honest peer is closed after one receive or send on it was
   cancelled or exceeded its timeout, because every in-flight consensus message
   on that link is lost, both sides must re-handshake, and a consumer that races
   a receive against a timer tears down healthy links repeatedly, which looks
   to the rest of the committee like a flapping validator.

## scheduling, supervision, and time

1. A timer armed for a future deadline fires immediately when the host clock
   steps forward, and a timer armed before a backward step fires late by the
   size of the step, because view timeouts built on those timers nullify a live
   leader's view early or let a stalled leader hold a view far past its
   deadline, and rate limiters keyed on the same clock either admit a burst or
   refuse honest peers until the clock catches up.
2. A long-lived actor stops running while every other task in the node
   continues, because the node keeps serving metrics, holding connections, and
   answering peers, so nothing restarts it, it stops voting or relaying for as
   long as nobody reads a single error log line, and it counts toward `f` the
   whole time.
3. A task spawned from a future that was later dropped keeps running until the
   task that spawned it exits, because it continues to send requests, write
   storage, and hold resources for an operation the caller already abandoned,
   duplicating or contradicting the caller's replacement work.
4. Shutdown never completes because a dedicated or blocking task that never
   yields cannot observe its abort, because the process stays alive holding its
   ports and the storage directory hold, the replacement process blocks on that
   hold, and the operator must kill both by hand while the validator is absent
   from the committee.
5. On the io_uring runtime, timers and I/O completions registered on one worker
   are delayed for as long as any task on that worker runs a long synchronous
   poll, because view timeouts and journal syncs owned by tasks that have since
   moved to other workers fire late, and a burst of expensive verification work
   triggered by one peer slows the node's consensus progress.
6. Two runs of the deterministic runtime with the same seed take different
   paths, because a failure found by a fuzzer or CI cannot be reproduced from
   its seed, is dismissed as flaky, and ships to validators where it recurs
   under real scheduling.
7. A recovery path passes every simulated crash but fails on a real disk,
   because a journal that mishandles a half-written record survives the test
   suite and corrupts a validator's state after its first power loss.
