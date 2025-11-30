# Simplex Actors Refactor Plan

## Overview

Refactor the voter/batcher/resolver actors to clarify responsibilities and remove
vote tracking duplication from voter. The key changes:

1. Batcher becomes the single entry point for all network messages (votes AND certificates)
2. Voter no longer tracks individual votes or constructs certificates
3. Voter remains responsible for all persistence (safety-critical)
4. Resolver maintains its own certificate store and handles fetching missing certificates

## Current Architecture

```
Network --votes--> Batcher --verified votes--> Voter (tracks votes, constructs certs)
Network --certs--> Voter (verifies directly)
Resolver --certs--> Voter
```

## Target Architecture

```
Network --votes--> Batcher --Proposal/Certificate--> Voter
Network --certs--> Batcher --Certificate--> Voter
Resolver --certs--> Voter

Voter --certificate persisted--> Resolver (updates store)
```

## Actor Responsibilities

### Batcher

**Receives**:
- Votes from network (notarize, nullify, finalize)
- Certificates from network (notarization, nullification, finalization)
- Constructed votes from voter (our own votes, needed for quorum)
- View updates from voter (current view, leader, finalized)

**Does**:
- Batch-verifies vote signatures
- Tracks votes per round using VoteTracker
- Constructs certificates when quorum reached
- Verifies incoming certificates (can skip if already have certificate for view)
- Stores certificates locally
- Tracks leader activity for skip timeout

**Sends to Voter**:
- `Proposal { view, proposal }` - First valid leader notarize arrived, start verification
- `Certificate { notarization | nullification | finalization }` - From construction or network

**Does NOT**:
- Persist anything (voter handles persistence)
- Make consensus decisions

### Voter

**Receives**:
- Proposals and certificates from batcher
- Certificates from resolver
- Proposal results from automaton (propose/verify)

**Does**:
- Manages view transitions and timeouts
- Coordinates proposal/verification with automaton
- Constructs and broadcasts our own votes (notarize, nullify, finalize)
- **Handles all journal persistence** (sync before broadcasting)
- Broadcasts certificates to network
- Detects leader equivocation (certificate proposal != our voted proposal)
- Blocks equivocating leaders

**Tracks per round**:
- Proposal slot (what we're verifying / voted on)
- Certificates (notarization, nullification, finalization)
- Broadcast flags
- Timeouts

**Does NOT**:
- Track votes from other validators
- Construct certificates from votes
- Verify incoming votes (batcher does this)

### Resolver

**Receives**:
- Certificate notifications from voter (after persistence)
- Fetch requests/responses from p2p layer

**Does**:
- Maintains its own certificate store (floor + nullifications)
- Fetches missing certificates from peers
- Produces certificates for peer requests
- Validates fetched certificates

**Sends to Voter**:
- Recovered certificates (fetched from peers)

## Detailed Changes

### Phase 1: Update Batcher to Handle Certificates

1. Add certificate receiver channel to batcher (currently goes to voter's `recovered_receiver`)
2. Add certificate storage to batcher's Round struct
3. When certificate arrives from network:
   - Check if already have certificate for this view -> skip verification
   - Otherwise verify and store
   - Forward to voter
4. When constructing certificate from votes:
   - Store locally
   - Forward to voter
5. Stop accumulating votes for a view once certificate exists

Files modified:
- `batcher/actor.rs` - Add certificate handling
- `batcher/ingress.rs` - Add certificate message type to mailbox

### Phase 2: Simplify Voter Round State

1. Remove VoteTracker from voter/round.rs
2. Remove certificate construction logic (notarizable, nullifiable, finalizable)
3. Keep proposal slot for verification flow
4. Keep certificate storage (received from batcher/resolver)
5. Update broadcast flags to only track what we've broadcast

Files modified:
- `voter/round.rs` - Remove vote tracking, simplify state
- `voter/state.rs` - Remove quorum_payload vote counting fallback

### Phase 3: Update Voter Message Handling

1. Remove handling of individual verified votes from mailbox
2. Add handling of Proposal message (triggers verification)
3. Update certificate handling (now comes from batcher, not direct network)
4. Keep resolver certificate handling as-is

Files modified:
- `voter/actor.rs` - Update message handling in run loop
- `voter/ingress.rs` - Update mailbox message types

### Phase 4: Update Equivocation Handling

1. When notarization certificate arrives, compare against our voted proposal
2. If different, block leader but still proceed with certificate's proposal
3. Vote finalize on certificate's proposal (not our original vote)
4. Remove "equivocation blocks finalize" logic

Files modified:
- `voter/round.rs` - Update equivocation detection
- `voter/actor.rs` - Update finalize vote construction

### Phase 5: Update Channel Wiring

1. Route `recovered_receiver` (network certificates) to batcher instead of voter
2. Add channel from batcher to voter for Proposal/Certificate messages
3. Keep voter->resolver notification path (after persistence)

Files modified:
- `voter/actor.rs` - Update channel setup in start/run
- `batcher/actor.rs` - Add certificate receiver
- Parent module wiring (wherever actors are instantiated)

### Phase 6: Cleanup

1. Remove unused imports and dead code
2. Update tests to reflect new architecture
3. Update documentation/comments

## Message Types

### Batcher -> Voter

```rust
pub enum BatcherMessage<S: Scheme, D: Digest> {
    /// First valid leader notarize arrived for this view.
    /// Voter should start verification if not already done.
    Proposal {
        view: View,
        proposal: Proposal<D>,
    },

    /// Certificate constructed or received from network.
    Notarization(Notarization<S, D>),
    Nullification(Nullification<S>),
    Finalization(Finalization<S, D>),
}
```

### Voter -> Batcher (unchanged)

```rust
pub enum Message<S: Scheme, D: Digest> {
    /// View update with leader info.
    /// Voter remains the source of truth for view advancement.
    /// Batcher uses this to filter messages and track leader activity.
    Update { current: View, leader: u32, finalized: View, active: oneshot::Sender<bool> },

    /// Our constructed vote (needed for quorum)
    Constructed(Voter<S, D>),
}
```

## Safety Invariants Preserved

1. **Persist before broadcast**: Voter syncs journal before broadcasting any vote or certificate
2. **Equivocation detection**: Voter detects when certificate differs from our vote, blocks leader
3. **View advancement**: Only advance view on valid certificate (notarization, nullification, finalization)

## Testing Strategy

### Existing Test Migration

The tests in `voter/mod.rs` will be updated to send messages that simulate batcher output
rather than sending raw votes. Voter mailbox will accept `Proposal` and `Certificate`
messages from batcher.

**Tests to migrate**:

| Test | Current | After |
|------|---------|-------|
| `finalization_without_notarization_certificate` | `mailbox.verified(Voter::Finalize(...))` | `mailbox.certificate(Finalization(...))` |
| `replay_duplicate_votes` | `mailbox.verified(Voter::Notarize/Finalize(...))` | `mailbox.certificate(...)` |
| `certificate_overrides_existing_proposal` | `mailbox.verified(Voter::Notarize(...))` + network cert | `mailbox.proposal(...)` + `mailbox.certificate(...)` |
| `drop_our_proposal_on_conflict` | `mailbox.verified(Voter::Notarize(...))` + network cert | `mailbox.proposal(...)` + `mailbox.certificate(...)` |
| `stale_backfill` | Network finalization + `mailbox.verified(Voter::Notarization(...))` | `mailbox.certificate(...)` for both |
| `append_old_interesting_view` | Network finalization/notarization | `mailbox.certificate(...)` |
| `finalization_from_resolver` | `mailbox.verified(Voter::Finalization(...))` | Unchanged (already simulates resolver) |

**Tests to remove** (no longer relevant since voter doesn't track votes):
- `finalization_without_notarization_certificate` - Tests constructing finalization from votes
- `replay_duplicate_votes` - Tests duplicate vote handling

**Tests to simplify**:
- Remove network setup where it was only used to send certificates to voter
- Send certificates directly via mailbox instead

### New Tests to Add

**Batcher tests**:
1. Certificate deduplication - skip verification if certificate exists for view
2. Certificate forwarding - forward certificates to voter
3. Stop accumulating votes after certificate
4. Construct certificate when quorum reached

**Voter tests**:
1. Equivocation detection - certificate proposal differs from verified proposal
2. Finalize on certificate proposal - use certificate's proposal, not original
3. Block leader on equivocation

## Code Quality Requirements

1. **Preserve and enhance comments**: Retain existing comments throughout the refactor.
   Add additional comments where new logic is introduced, especially for:
   - Certificate deduplication logic in batcher
   - Equivocation detection in voter
   - Message flow between actors

2. **Batcher test coverage**: Add comprehensive tests to `batcher/mod.rs` similar to
   the test coverage in `voter/mod.rs`. Tests should cover:
   - Vote accumulation and certificate construction
   - Certificate deduplication (skip verification if already have certificate)
   - Certificate forwarding to voter
   - Handling certificates from network
   - Stop accumulating votes after certificate exists
   - Leader activity tracking
   - View update handling
   - Edge cases (stale views, future views, invalid signatures)

## Migration Notes

- This is a breaking change to internal actor APIs
- External API (Engine) should remain unchanged
- Journal format unchanged (voter still persists same data)
