# StateLens-Style Analysis of Commonware Simplex Voter State

## Purpose

This document gives a concrete, step-by-step example of how a StateLens-style agent could analyze:

`consensus/src/simplex/actors/voter/state.rs`

with special focus on:

- `add_nullification`
- `add_finalization`
- `optimistic_parent_ready`
- `construct_notarize`

The goal is not to claim that these functions are buggy. The goal is to show how a StateLens-like system can turn developer-authored semantic clues into:

1. semantic beacons,
2. targeted Knowledge Base queries,
3. source-validated causal hypotheses,
4. explicit invariants,
5. candidate runtime state expressions,
6. probe locations, and
7. state-coverage dimensions for fuzzing.

The example assumes a **mock Knowledge Base (KB)** containing protocol documentation, design notes, issue reports, comments extracted from the repository, and historical debugging notes. Section 0 says how that maps onto the real knowledge base this repository uses.

---

<!-- statelens-lint: not-code: related_findings, remediation_status,
     proposal_parent_resolution, proposal_parent_resolvable,
     parent_ancestry_payload_available, add_nullification_inner -->

# 0. How this maps onto StateLens in this repository

`just check-examples` verifies that every code name this document cites still exists. The
names declared above are exempt: two are knowledge-base claim fields, and the rest are names
this document mentions only to say they are not functions in this codebase.

This document is written in the vocabulary of the StateLens paper. The workflow in this
repository divides the same work differently, so read the mapping below before following the
example literally.

**Two agents, not one.** The example shows a single agent deriving invariants *and* choosing
probes. Here those are separate jobs:

| The example's step | Who does it here | Reads |
|---|---|---|
| Seed discovery from comments, deriving invariants (sections 3 to 25) | the invariant analyst, `just extract comment <path>` | `prompts/analyst.md` + `prompts/analyst-comment.md` |
| Choosing states and transitions, probe synthesis (sections 26 to 28) | the instrumenter's beacon step, inside `just campaign` | `prompts/instrument.md` + `prompts/instrument-beacons.md` |
| Binding an invariant to assertion sites | the instrumenter's invariant step, inside `just campaign` | `prompts/instrument.md` + `prompts/instrument-invariants.md` |

The division matters because **an assertion can panic**. Invariants therefore live in a
committed registry that a human reviews before any campaign binds them, and the beacon step
adds `sl_probe!` only: it never writes an assertion, and it never invents an invariant. When
the beacon step finds what looks like a property rather than a state, it says so in its reply
and leaves it for Phase 1.

**Names.** The paper's pipeline artifacts do not exist here:

| Paper term used below | Here |
|---|---|
| Beacon Summary, State Report | no artifact: the instrumenter holds this in its own context and records the result as a row of the plan's beacon table |
| Iterative State Discovery | not adopted. There is no call-graph, data-flow or AST tool; tracing is search and reading, and a finding's own citations name the files and symbols (`R-AG-2`) |
| Probe Synthesis, Probe Validation | step 3 of a campaign, then `cargo check`, the sanitizer build with up to three agent repairs, and the test gate |
| `INV-A1`, `INV-B2`, and the other family labels | local labels for this document only. A registry invariant has a global `INV-NNNN` id that `just extract` assigns |
| `STATE_PROBE!` with a struct of fields | `sl_probe!(me, "label", a, b)`, which records exactly one pair; section 27 shows how several values become a pair |

**The knowledge base is real.** `STATELENS_KB` names one or more corpus roots outside this
repository. A corpus holds findings under `findings/<state>/`, each opening with a fenced
` ```claim ` block (`module`, `severity`, `remediation_status`, `summary`, `related_findings`)
followed by fixed prose sections, of which `Context`, `Root Cause`, `Lifecycle Events` and
`Exploitation Or Trigger Conditions` are the ones a query can read. Curated documents live
under `kb/`, `config/` and `context/`. The agent never reads a corpus directly; it runs:

```text
kb modules                    what this subsystem's findings cover
kb find TERM...               findings whose summary or tags match, with the code they cite
kb cites PATH                 findings that cite a file under PATH  <- start here
kb grep TEXT                  snippets of the state-bearing sections
kb show IDENTIFIER [SECTION]  one claim block, or one state-bearing section
```

The fictional KB entries below stand in for real findings. A real one carries the same kind
of content, and `kb cites consensus/src/simplex/actors/voter` is how you would find the ones
about this file.

---

# 1. High-Level System

A useful approximation of the complete system is:

The paper's shape, for reference:

```text
Repository + Developer Artifacts -> LLM agent -> Beacon Summary
  -> Iterative State Discovery -> State Report -> State/Transition Selection
  -> Probe Synthesis -> Probe Validation -> instrumented target
  -> edge coverage + state coverage -> fuzzer
```

The same work in this repository:

```text
PHASE 1  just extract <kind> <source>
           source artifact -> invariant analyst -> invariants/<subsystem>/INV-NNNN.md
                                                  (committed, human-reviewed)

PHASE 2  just campaign
           registry invariants -> instrumenter -> sl_assert! / sl_implies! + ghost state
           component code      -> instrumenter -> sl_probe!
             ^                        |
             |                        +---- read and search the code        (leads)
             |                        +---- kb cites / find / grep / show   (on demand)
             |                        v
             +------------------ campaign/plan.md, then cargo check,
                                 the sanitizer build, and the test gate

PHASE 3  just run <target>
           edge coverage + state coverage -> libFuzzer
```

The central point is that **KB retrieval is an agent action, not a mandatory preprocessing step for every source location**. That is exactly how the beacon step works here: reading the code leads, and a query happens when a candidate needs developer context the source does not carry.

The agent queries the KB when source inspection reveals a semantic question that cannot be answered reliably from local code alone.

---

# 2. Source Region That Triggers the Analysis

The analysis begins around the following comments and functions.

## 2.1 `add_nullification`

The code says, in effect:

```rust
/// Unlike finalization, nullification does not cancel pending certification work for the
/// same view. The next proposer may build on a certified notarization we haven't finished
/// processing yet and stopping here could halt the network.
pub fn add_nullification(&mut self, nullification: Nullification<S>) -> bool {
    let view = nullification.view();

    let next_view = view.next_term_start(self.term_length());
    self.enter_view(next_view);
    self.set_leader(next_view, Some(&nullification.certificate));

    let round = self.create_round(view);
    let added = round.add_nullification(nullification);
    ...
    added
}
```

This comment is a very strong semantic beacon because it does not merely document behavior. It states a **liveness-relevant cross-state relationship**:

> Receiving a nullification must not destroy certification work for the same view.

It also explains the consequence of violating that relationship:

> The next proposer may need a certified notarization that is still being processed; cancelling the work can halt the network.

---

## 2.2 `add_finalization`

The finalization path explicitly does the opposite:

```rust
if view > self.last_finalized {
    self.last_finalized = view;

    // Finalization overrides local certification rejections at or below its view.
    self.failed_certifications = self.failed_certifications.split_off(&view.next());

    // Finalization is definitive, so these certifications are no longer relevant.
    self.certification_candidates.retain(|v| *v > view);

    let keep = self.outstanding_certifications.split_off(&view.next());
    for v in replace(&mut self.outstanding_certifications, keep) {
        if let Some(round) = self.views.get_mut(&v) {
            round.abort_certify();
        }
    }
}
```

This is another semantic beacon:

> Finalization is definitive and therefore *does* invalidate certification work at or below its view.

The contrast between nullification and finalization is much more interesting than either function in isolation.

---

## 2.3 `optimistic_parent_ready`

The comments contain an unusually strong cross-component contract:

```rust
/// This must use the same ancestry rule as proposal construction.
/// A stricter rule can permanently lose a one-shot vote, while a looser rule can sign
/// ancestry the local automaton rejected.
```

This is almost an invariant written in natural language:

```text
optimistic notarize ancestry rule == proposal construction ancestry rule
```

The consequences are asymmetric:

```text
stricter rule  -> liveness loss / permanently lost one-shot vote
looser rule    -> safety-relevant signing over ancestry rejected locally
```

---

## 2.4 `construct_notarize`

The signing path is a sequence of semantic gates:

```rust
if !self.admits_outbound(view) {
    return None;
}

if !self.views.get(&view)?.can_construct_notarize() {
    return None;
}

if self.in_issuance_window(view) && !self.optimistic_parent_ready(view) {
    return None;
}

if !self.verification_matches(view) {
    return None;
}

let candidate = ...construct_notarize()...?;
self.prepare_optimistic_successor(view);
Notarize::sign(&self.scheme, candidate)
```

The semantic question is not simply "was this function executed?"

The interesting state is the combination of gates under which a vote is or is not produced.

---

# 3. Step 0 -- Candidate Seed Discovery

The system first performs a relatively cheap repository scan for developer-authored artifacts that are likely to encode important state relationships. Here that scan is the first thing both Phase 2 prompts ask for, over the non-test code of one component and the types it owns.

Examples include:

- comments containing words such as `must`, `cannot`, `only`, `unless`, `otherwise`, `halt`, `safety`, `liveness`, `definitive`, `rejected`;
- assertions;
- enums representing protocol modes;
- helper predicates used as gates;
- comments describing differences between two certificate types;
- comments that explicitly relate two functions.

The scanner does **not** yet decide that a comment is an invariant or generate a probe.

For our source region it could produce these candidate seeds:

```text
Seed A:
  Location: add_nullification documentation
  Text clue: "nullification does not cancel pending certification work"

Seed B:
  Location: add_finalization
  Text clue: "Finalization is definitive"

Seed C:
  Location: optimistic_parent_ready
  Text clue: "must use the same ancestry rule as proposal construction"

Seed D:
  Location: construct_notarize
  Text clue: optimistic views wait for local evidence of their parent
```

These are not yet confirmed semantic beacons. They are analysis starting points.

---

# 4. Step 1 -- Agent Examines Seed A: Nullification vs Certification

## 4.1 Local source observation

The agent reads `add_nullification` and observes:

```text
Input event:
    Nullification(view = v)

State transition:
    current view -> next term start after v

Important negative effect:
    outstanding certification work is NOT cancelled
```

The critical clue is the negative requirement:

```text
Nullification(v)
    must NOT imply
AbortCertification(v)
```

## 4.2 What is still unknown?

The agent can read the local code, but it still does not know:

1. What exactly is "pending certification work" in this automaton?
2. Which collections encode it?
3. Why can a certified notarization still become useful after a nullification?
4. Which later path consumes that certification?
5. Is the non-cancellation property same-view only, same-term, or more general?

These are **semantic questions**, not merely structural ones.

This is the first point at which the agent chooses `QUERY_KB`.

---

# 5. Knowledge Base Query 1

## Agent query

In this repository the agent runs, from the repository root:

```text
kb cites consensus/src/simplex/actors/voter
kb find nullification certification
kb grep "pending certification"
```

`kb cites` comes first because it turns the path in front of the agent into the findings
about that code, each with the files and symbols it names. `kb find` and `kb grep` are for
following a concept that the path alone does not surface. Every query is already restricted
to the findings whose `module` names Simplex.

## Knowledge Base results

Three hits, in the shape a real finding has: an identifier, a state, a summary, and the
state-bearing sections `kb show` can return.

### KB-1 -- a `triaged` finding whose Root Cause explains that certification survives nullification

```text
A nullification proves that the protocol abandons progress through the
nullified portion of the current term, but it does not retroactively make
an already-notarized block invalid. Certification of that notarization may
still establish ancestry used by a proposer in a later view.
```

### KB-2 -- a `valid`, `remediation_status: fixed` finding: cancelling certification on nullification

```text
A previous implementation cleared outstanding certification when receiving
a nullification. Under delayed certification responses, nodes entered the
next term with different beliefs about whether a notarized block could be
a valid parent. Progress stopped because neither ancestry was accepted by
all correct nodes.
```

### KB-3 -- a hit whose words match but whose subject does not: metric attribution

```text
Nullification metrics are attributed to the leader responsible for a view.
```

## Self-reflection filtering

The agent keeps KB-1 and KB-2 and rejects KB-3. A rejection costs one line of reasoning and
nothing else; the plan records only what a probe ends up watching.

Reason:

```text
KB-1: directly explains the semantic role of surviving certification.
KB-2: directly explains the liveness failure caused by cancelling it.
KB-3: discusses metrics, not protocol state transitions.
```

---

# 6. Step 2 -- Agent Forms the First Beacon Summary

The agent can now construct:

```text
Beacon Summary A

State descriptions:
    - nullification received for view v
    - certification candidate exists for v
    - certification outstanding for v
    - certification result may still arrive after nullification

Transition hint:
    certification_pending(v)
        + receive_nullification(v)
        -> certification_pending(v) must remain true

Potential bad transition:
    certification_pending(v)
        + receive_nullification(v)
        -> certification_aborted(v)

Why interesting:
    certified notarization may remain usable ancestry;
    losing certification can cause divergent parent validity and halt progress.

Seed symbols:
    add_nullification
    certification_candidates
    outstanding_certifications
    abort_certify
    add_finalization
```

This is a strong StateLens-style beacon because it describes a **cross-event state transition**, not merely a line of code.

---

# 7. Step 3 -- Structural Traversal from the Beacon

The agent now switches primarily to source tools.

It asks structural questions:

```text
Where is outstanding_certifications inserted?
Where is it removed?
Who calls abort_certify()?
What event reports certification success/failure?
Who consumes certification after nullification?
```

Assume source traversal discovers:

```text
notarization accepted
      |
      v
certification candidate / outstanding certification
      |
      +-------------------------+
      |                         |
      |                         v
nullification(v)          finalization(v or higher)
      |                         |
      |                         v
      |                   abort/prune obsolete
      |                   certification work
      |
      v
must preserve same-view certification work
```

At this point, the contrast with `add_finalization` becomes central.

---

# 8. Step 4 -- Agent Examines `add_finalization`

The agent observes explicit state mutation:

```text
Finalization(v) received
    -> last_finalized := max(last_finalized, v)
    -> remove failed certifications <= v
    -> remove certification candidates <= v
    -> abort outstanding certifications <= v
```

This provides a paired semantic relationship:

```text
Nullification(v): certification at v may still matter.
Finalization(v):   certification at <= v no longer matters.
```

This distinction is exactly the kind of state dimension structural coverage will not capture well.

Two test executions may enter both certificate handlers, but the critical question is whether the correct certification state survives or is destroyed.

---

# 9. Derived Invariant Family A -- Certificate/Cancellation Semantics

The labels `INV-A1`, `INV-A2` and so on are local to this document. A real invariant goes into
`invariants/simplex/` with a global `INV-NNNN` id that `just extract` assigns, an EARS
statement that names no Rust identifier, and its source recorded. Deriving these is Phase 1
work; the Phase 2 beacon step never writes one.

The agent now writes candidate invariants in natural language first.

## INV-A1 -- Nullification must preserve same-view pending certification

```text
If certification work for view v is pending immediately before
add_nullification(Nullification(v)), processing that nullification must not
cancel or remove that same-view certification solely because of the
nullification.
```

Possible executable approximation:

```rust
let pending_before = certification_pending(v);
add_nullification(n);
let pending_after = certification_pending(v);

invariant!(
    !pending_before || pending_after || certification_completed(v)
);
```

The `certification_completed(v)` exception matters because asynchronous work could complete during a larger event-processing sequence. The exact implementation should model the actual event boundaries rather than blindly require the same container membership.

### Why the agent adds it

Because the source comment explicitly says nullification must not cancel the work, and the Knowledge Base explains the liveness consequence.

### Strong beacon

```text
"Unlike finalization, nullification does not cancel pending certification work
for the same view."
```

---

## INV-A2 -- Finalization makes certification work at or below the finalized view obsolete

```text
After last_finalized advances to v:

    no certification candidate <= v remains actionable;
    no outstanding certification <= v remains active;
    local certification rejection <= v cannot continue blocking state.
```

Executable approximations:

```rust
for c in certification_candidates {
    invariant!(c > last_finalized);
}

for c in outstanding_certifications {
    invariant!(c > last_finalized);
}

for f in failed_certifications {
    invariant!(f > last_finalized);
}
```

The actual semantics of historical/replay state may require a weaker invariant depending on whether the sets are intended to retain archival entries. The source shown here strongly suggests they are active-state structures and are pruned.

### Why the agent adds it

Because finalization is explicitly described as definitive and the code performs coordinated cleanup across three state structures.

### Strong beacons

```text
"Finalization overrides local certification rejections at or below its view."

"Finalization is definitive, so these certifications are no longer relevant."
```

---

## INV-A3 -- Certificate-type asymmetry must be preserved

This is a relational invariant across handlers:

```text
For same view v:

receive Nullification(v)
    MUST NOT perform the certification invalidation performed by
receive Finalization(v).
```

This is useful because a regression may arise from code refactoring:

```text
common "advance certificate" helper
    -> accidentally clears outstanding certification for both certificate types
```

Even if each individual function still passes ordinary unit tests, the cross-handler semantic distinction can be lost.

---

# 10. Candidate Probes for Invariant Family A

StateLens would normally prefer lightweight state coverage to hard assertions in the fuzzing target.

Candidate probe state:

```text
certificate_event_type:
    NULLIFICATION | FINALIZATION

same_view_cert_candidate_before:
    0 | 1

same_view_outstanding_before:
    0 | 1

same_view_cert_candidate_after:
    0 | 1

same_view_outstanding_after:
    0 | 1

last_finalized_relation:
    event_view < last_finalized
    event_view == last_finalized
    event_view > last_finalized
```

A compressed semantic state could be:

```text
(event_type,
 pending_before,
 pending_after,
 event_view_relation_to_last_finalized)
```

Interesting transitions include:

```text
NULLIFICATION, pending -> pending
NULLIFICATION, pending -> gone        <-- suspicious/high-value
FINALIZATION, pending -> gone         <-- expected
FINALIZATION, pending -> pending      <-- suspicious depending on view relation
```

This is much richer than edge coverage because both handlers can be fully covered while these state combinations remain unexplored.

---

# 11. Step 5 -- Agent Examines the Nullification View Advance

The agent notices another comment:

```text
A nullification below last_finalized in an earlier term targets a view at or
below it, and one in the same term cannot exist due to Same-Term Vote Safety.
```

This comment encodes several semantic facts:

1. `enter_view` is monotonic.
2. A stale nullification may be processed without moving the node backwards.
3. Same-term coexistence with a conflicting finalized state is prohibited by protocol safety.

The agent does not yet know the exact same-term safety rule, so it queries the KB.

---

# 12. Knowledge Base Query 2

## Query

```text
Simplex same-term vote safety nullification finalization
nullification below last_finalized term
```

## Knowledge Base query result

```text
A correct voter must not produce combinations of votes that can support both
nullification and conflicting finalization within the prohibited same-term
region. Observed finalization can override local uncertainty because it proves
a quorum progressed consistently.
```

The agent then inspects `construct_finalize`, where the source itself says that a prior same-term nullify vote blocks finalize unless an observed finalization covers it.

This confirms that the comment in `add_nullification` is connected to a broader vote-safety rule rather than being only a local implementation detail.

---

# 13. Derived Invariant Family B -- Monotonic View/Finalization State

## INV-B1 -- `enter_view` must not move the voter backwards

```text
For every event:
    state.view_after >= state.view_before
```

This is not derived only from `add_nullification`; the local comment explicitly relies on it:

```text
"enter_view only advances"
```

This makes it an excellent semantic beacon.

Candidate probe:

```text
(event_kind, old_view_relation_to_target, new_view_relation_to_old)
```

A transition `new_view < old_view` should be impossible.

---

## INV-B2 -- `last_finalized` is monotonic

```text
last_finalized_after >= last_finalized_before
```

`add_finalization` explicitly updates it only when:

```rust
view > self.last_finalized
```

A StateLens agent would likely classify this as a high-confidence state invariant.

---

## INV-B3 -- A stale nullification must not undo finalized progress

```text
If nullification.view <= last_finalized,
processing it must not reduce last_finalized and must not move current view
backward.
```

This is more semantically meaningful than checking only monotonic fields because it binds a specific event type to a protected state transition.

---

# 14. Step 6 -- Agent Moves to `optimistic_parent_ready`

The next beacon is especially strong:

```text
"This must use the same ancestry rule as proposal construction."
```

This is almost a specification-level statement.

The agent extracts:

```text
State description:
    whether an optimistic child view has locally usable parent ancestry

Cross-component relationship:
    vote-construction ancestry predicate
        ==
    proposal-construction ancestry predicate

Failure modes:
    stricter voting predicate -> permanently lost one-shot vote
    looser voting predicate   -> sign ancestry local automaton rejected
```

The agent now needs to identify what "same ancestry rule" actually means.

This is a semantic unknown, so it queries the KB.

---

# 15. Knowledge Base Query 3

## Query

```text
Simplex optimistic proposal construction ancestry rule
optimistic_parent_ready one-shot notarize vote parent payload
```

## Knowledge Base query results

### KB-4 -- Optimistic issuance design note

```text
Within the optimistic issuance window a voter may prepare a child before
ordinary certified ancestry is complete, but it may sign only when the same
parent payload that proposal construction would use is locally resolvable.
```

### KB-5 -- One-shot voting note

```text
A notarize vote is one-shot. If the local automaton declines to sign because
parent ancestry is temporarily unavailable, a later unrelated event does not
necessarily cause the same child vote to be reconstructed.
```

### KB-6 -- Generic leader-election description

Rejected as irrelevant.

The agent keeps KB-4 and KB-5.

---

# 16. Step 7 -- Source Traversal for Ancestry Consumers

The agent now uses source tools, not the KB, to answer structural questions:

```text
Where is optimistic_ancestry_payload used?
What ancestry helper does proposal construction use?
What does previous_in_term return?
What exactly defines in_issuance_window?
What event calls construct_notarize?
Can finalization change ancestry availability?
```

It discovers the following conceptual flow:

```text
                   parent state
                       |
              +--------+--------+
              |                 |
              v                 v
     proposal construction   construct_notarize
              |                 |
       ancestry resolver   optimistic_parent_ready
              |                 |
              +--------+--------+
                       |
                 must agree
```

The important state is not merely the Boolean returned by `optimistic_parent_ready`. It is the **relationship between two independently implemented consumers of ancestry state**.

---

# 17. Derived Invariant Family C -- Ancestry Rule Consistency

## INV-C1 -- Optimistic voting and proposal construction must agree on parent usability

For an optimistic in-term view `v`:

```text
parent_usable_for_notarize(v)
    ==
parent_usable_for_proposal_construction(v)
```

This may need normalization because proposal construction could return a concrete payload while `optimistic_parent_ready` returns only a Boolean.

The executable semantic relation is:

```text
optimistic_parent_ready(v)
    ==
optimistic_ancestry_payload(previous_in_term(v)).is_some()
```

for states where both paths are intended to use the same ancestry regime. Those are the two
real functions: `optimistic_parent_ready` delegates to `optimistic_ancestry_payload`, and the
proposal path resolves the same ancestry through its own context. This document earlier called
the second one `proposal_parent_resolution`, which is not a function in this codebase.

### Why add it?

Because the source explicitly says the two rules **must** match and documents both sides of failure:

```text
too strict -> liveness degradation

too loose  -> safety-relevant invalid ancestry signing
```

This is one of the strongest candidate invariants in the entire region.

---

## INV-C2 -- No-parent in-term boundary is immediately ready

From:

```rust
let Some(parent) = self.previous_in_term(view) else {
    return true;
};
```

we get:

```text
If there is no previous view in the current term,
optimistic_parent_ready(view) == true.
```

This is likely a lower-value invariant than INV-C1, but useful as a boundary-state coverage dimension.

---

## INV-C3 -- Parent readiness must correspond to resolvable ancestry

For a view with an in-term parent:

```text
optimistic_parent_ready(view)
    <=>
optimistic_ancestry_payload(parent).is_some()
```

This is almost tautological for the current implementation, so StateLens may decide **not** to instrument it independently.

The more valuable target is the cross-component equality in INV-C1.

---

# 18. Step 8 -- Agent Analyzes the "One Abstention Is Tolerated" Comment

This part is subtle:

```text
A parent whose certification failed rejects the child's one-shot vote.
A later parent finalization restores the ancestry but does not retry the vote.
```

The agent extracts a temporal state machine:

```text
parent certification pending
        |
        v
parent certification failed
        |
        v
child one-shot notarize declined
        |
        v
later parent finalization
        |
        v
ancestry becomes valid again
        |
        X
child vote is NOT automatically retried
```

This is a perfect example of why state coverage can expose behavior that edge coverage misses.

A test that only covers `construct_notarize -> return None` tells us little.

State coverage can distinguish:

```text
NONE because outbound inadmissible
NONE because local round not eligible
NONE because optimistic parent unavailable
NONE because verification mismatch
```

and, even more importantly:

```text
parent unavailable because certification failed
parent later finalized
child still not retried
```

---

# 19. Derived Invariant Family D -- One-Shot Vote Semantics

This area requires care. The comment explicitly says that missing a vote in one special sequence is tolerated. Therefore the agent must **not** generate the naive liveness invariant:

```text
WRONG:
If parent ancestry eventually becomes valid, child must eventually vote.
```

That would contradict the documented protocol semantics.

Instead it derives:

## INV-D1 -- A one-shot vote must not be emitted while optimistic parent ancestry is unavailable

```text
If:
    in_issuance_window(v)
and previous_in_term(v) exists
and optimistic_parent_ready(v) == false

then:
    construct_notarize(v) == None
```

This is directly reflected in the source.

---

## INV-D2 -- Later restoration of ancestry does not imply automatic retry

This is better represented as a **state-coverage target** than as a hard invariant:

```text
(certification_failed(parent),
 child_vote_withheld,
 finalization(parent)_later,
 child_vote_not_retried)
```

The agent wants the fuzzer to reach this unusual temporal state because the developers explicitly documented it as expected but subtle.

---

# 20. Step 9 -- Agent Analyzes `construct_notarize` as a Gate Vector

The function has four main pre-signing gates:

```text
G1 = admits_outbound(view)
G2 = round.can_construct_notarize()
G3 = !in_issuance_window(view) || optimistic_parent_ready(view)
G4 = verification_matches(view)
```

Signing occurs only if all gates hold and the round supplies a candidate.

So conceptually:

```text
sign(v) requires G1 & G2 & G3 & G4 & candidate_exists
```

A classic edge-coverage fuzzer can cover every `return None` branch fairly quickly.

But StateLens cares about the semantic combinations leading to those branches.

For example:

```text
G1=1 G2=1 G3=0 G4=?
```

is the optimistic-parent block.

Whereas:

```text
G1=1 G2=1 G3=1 G4=0
```

represents verification mismatch.

These are semantically distinct execution states even if later fuzzing mutations traverse mostly the same surrounding control flow.

---

# 21. Derived Invariant Family E -- Signing Preconditions

## INV-E1 -- No notarize signature outside outbound admissibility

```text
Notarize::sign succeeds for view v
    -> admits_outbound(v)
```

---

## INV-E2 -- No notarize signature without local round eligibility

```text
Notarize::sign succeeds for view v
    -> can_construct_notarize(v)
```

---

## INV-E3 -- Optimistic notarize requires locally usable parent ancestry

```text
Notarize::sign succeeds for v
AND in_issuance_window(v)
AND previous_in_term(v).is_some()
    -> optimistic_parent_ready(v)
```

This is a higher-value invariant because the source explicitly connects ancestry mistakes to lost votes or invalid ancestry signing.

---

## INV-E4 -- Signature requires verification state to match

```text
Notarize::sign succeeds for v
    -> verification_matches(v)
```

---

## INV-E5 -- The signing gate vector should be observable as a semantic state

This is not a correctness assertion but a state-coverage specification:

```text
State = (
    outbound_admitted,
    local_round_eligible,
    in_issuance_window,
    parent_ready,
    verification_matches,
    candidate_exists,
    signed
)
```

The fuzzer should receive novelty credit for previously unseen meaningful combinations.

---

# 22. Step 10 -- Why the Agent Queries the KB Again

Suppose source traversal reaches:

```rust
self.prepare_optimistic_successor(view);
```

The agent now asks:

```text
Does preparing the successor before Notarize::sign have semantic consequences
if signing fails?
```

The nearby comment says:

```text
Signing can only fail if we are a verifier, so we don't need to worry about
unwinding our broadcast toggle.
```

This creates a new semantic question:

- What state is changed by `prepare_optimistic_successor`?
- What is the "broadcast toggle"?
- Why is failure restricted to verifier mode?
- Can a failed signing attempt leave an externally observable state mutation?

This is another **on-demand KB trigger** because local code gives the rule but not necessarily its design rationale.

Knowledge Base query:

```text
Simplex prepare_optimistic_successor notarize signing verifier failure
broadcast toggle unwind
```

If the KB supplies a design note confirming that only verifier-mode signing failure is possible and no unsafe successor state escapes, the agent may derive another invariant or decide that the state is low priority.

This illustrates an important property of the agent:

```text
KB query is not tied to a fixed phase.
It is invoked whenever a newly discovered semantic dependency needs context.
```

---

# 23. Full Example of the Agent's Internal Timeline

The following is a more literal step-by-step execution trace.

## Step 1 -- Seed artifact

Agent sees:

```text
"Unlike finalization, nullification does not cancel pending certification work"
```

Agent hypothesis:

```text
There is a state distinction between nullification and finalization concerning
certification lifetime.
```

Next action:

```text
INSPECT_SOURCE(add_nullification)
```

---

## Step 2 -- Local source inspection

Observed:

```text
add_nullification advances view and records nullification,
but does not visibly touch certification collections.
```

Missing semantic information:

```text
Why must certification survive?
```

Next action:

```text
QUERY_KB("nullification pending certification same view valid parent liveness")
```

---

## Step 3 -- KB retrieval and filtering

Retained evidence:

```text
Certified notarization can remain valid ancestry after nullification.
Cancelling certification can cause nodes to disagree about valid ancestry.
```

Hypothesis strengthened.

Next action:

```text
SEARCH_CODE(outstanding_certifications, certification_candidates, abort_certify)
```

---

## Step 4 -- Source search discovers finalization cleanup

Observed:

```text
add_finalization prunes/aborts certification <= finalized view.
```

New semantic relationship:

```text
nullification != finalization
with respect to certification invalidation
```

Next action:

```text
INSPECT_SOURCE(add_finalization)
```

---

## Step 5 -- State relationship becomes concrete

Agent writes tentative invariant:

```text
Nullification(v) must preserve still-relevant certification work at v;
Finalization(v) must invalidate certification work at <= v.
```

Next action:

```text
TRACE_CONSUMERS(certified notarization / parent ancestry)
```

---

## Step 6 -- Traversal reaches optimistic ancestry logic

Agent encounters:

```text
"must use the same ancestry rule as proposal construction"
```

This is a new semantic beacon discovered **during traversal**, not only at the initial scan.

Agent opens a second hypothesis branch:

```text
Voting ancestry decision must agree with proposal ancestry decision.
```

Missing information:

```text
What is the intended proposal ancestry rule?
Why is the vote one-shot?
```

Next action:

```text
QUERY_KB("optimistic proposal ancestry one-shot notarize")
```

---

## Step 7 -- KB explains one-shot semantics

Agent learns:

```text
Temporary ancestry unavailability can cause a child vote to be skipped once;
later parent finalization does not necessarily revisit that child.
```

Next action:

```text
INSPECT_SOURCE(construct_notarize)
```

---

## Step 8 -- Signing gate vector discovered

Agent extracts:

```text
admissible
AND round eligible
AND parent ready when optimistic
AND verification matches
AND candidate exists
-> sign
```

This gives concrete runtime expressions suitable for instrumentation.

---

## Step 9 -- Source validation

Before emitting invariants, the agent verifies:

```text
- these predicates are actually evaluated on the signing path;
- optimistic_parent_ready delegates to optimistic_ancestry_payload;
- finalization really removes/aborts certification structures;
- nullification really does not do so locally;
- enter_view semantics are monotonic.
```

Any relation that cannot be validated is marked as a hypothesis rather than an invariant.

---

## Step 10 -- State Report emitted

The final report might be:

```text
WHAT
----
1. Whether same-view certification survives nullification but is invalidated
   by finalization.
2. Whether optimistic notarize parent readiness agrees with proposal ancestry
   resolution.
3. Which semantic gate prevents or permits notarize signing.
4. Whether view/finalization progress remains monotonic across stale or
   out-of-order certificate arrival.

WHY
---
1. Cancelling valid certification after nullification can halt progress by
   creating incompatible ancestry beliefs.
2. An ancestry rule stricter than proposal construction can permanently lose
   a one-shot vote; a looser rule can sign ancestry rejected locally.
3. The same structural signing path represents several semantically distinct
   states that ordinary edge coverage does not distinguish.

HOW
---
Notarization/certification work
        |
        +--> Nullification(v) -------- preserves same-view certification
        |
        +--> Finalization(v) --------- invalidates certification <= v

Parent state
        |
        +--> Proposal construction ancestry resolver
        |
        +--> optimistic_parent_ready
                     |
                     v
              construct_notarize
                     |
          admissibility + readiness
          + verification gates
                     |
                     v
                   sign

CANDIDATE PROBE SITES
---------------------
- immediately before/after add_nullification state mutation
- immediately before/after finalization cleanup
- optimistic_parent_ready result
- proposal ancestry-resolution result
- construct_notarize immediately before each semantic gate
- immediately before Notarize::sign
```

---

# 24. Recommended Invariants Ranked by Semantic Value

These are not "all possible assertions." They are the ones a StateLens-style agent would likely consider most semantically valuable from the supplied region.

## High-value invariant 1

### Nullification preserves same-view certification work

```text
pending_certification(v)
AND receive_nullification(v)
-> certification is not cancelled merely because of the nullification
```

**Why:** explicit liveness rationale in source.

**Beacon strength:** very high.

---

## High-value invariant 2

### Finalization invalidates obsolete certification work

```text
last_finalized advances to v
-> no active certification work <= v remains
```

**Why:** finalization is described as definitive; multiple coordinated data structures are pruned.

**Beacon strength:** high.

---

## High-value invariant 3

### Proposal ancestry and optimistic voting ancestry agree

```text
optimistic_parent_ready(v)
==
proposal_parent_is_usable(v)
```

within the domain where both are intended to implement the same rule.

**Why:** source explicitly states `must use the same ancestry rule` and explains both stricter and looser failure modes.

**Beacon strength:** extremely high.

---

## High-value invariant 4

### Optimistic signing never occurs without required parent ancestry

```text
signed_notarize(v)
AND in_issuance_window(v)
AND previous_in_term(v).is_some()
-> optimistic_parent_ready(v)
```

**Why:** directly guards a safety-relevant signing decision.

**Beacon strength:** high.

---

## High-value invariant 5

### Signing requires all local semantic gates

```text
signed(v)
-> admits_outbound(v)
   AND round_can_construct(v)
   AND ancestry_gate(v)
   AND verification_matches(v)
```

**Why:** converts scattered early-return conditions into a single semantic contract.

**Beacon strength:** medium/high.

---

## High-value invariant 6

### View progress is monotonic

```text
view_after >= view_before
```

**Why:** the nullification comment explicitly relies on `enter_view` only advancing.

**Beacon strength:** medium/high.

---

## High-value invariant 7

### `last_finalized` is monotonic

```text
last_finalized_after >= last_finalized_before
```

**Why:** fundamental protocol state and directly encoded by the update guard.

**Beacon strength:** medium.

---

# 25. Invariants the Agent Should NOT Add

A strong agent must also reject tempting but incorrect invariants.

## Incorrect invariant 1

```text
Nullification(v) implies all work for v is obsolete.
```

Wrong because the source explicitly says same-view certification may remain necessary.

---

## Incorrect invariant 2

```text
If parent ancestry eventually becomes valid, every skipped child notarize vote
must be retried.
```

Wrong because the comment explicitly documents a tolerated one-shot abstention.

---

## Incorrect invariant 3

```text
Finalization and nullification should perform symmetric cleanup because both
advance the view.
```

Wrong. The asymmetry is one of the central semantic properties documented by the code.

---

## Incorrect invariant 4

```text
optimistic_parent_ready(view) must always be true before construct_notarize is called.
```

Wrong. The function is deliberately called as a gate and can return false.

The correct rule concerns **signing**, not function invocation.

---

# 26. State Coverage Instead of Assertions

StateLens is fundamentally about providing the fuzzer with semantic feedback, so some discoveries are more useful as coverage states than as assertions. Here that choice is also a choice of phase: a property that must hold is an invariant, written in Phase 1 and reviewed; a state worth telling apart is a beacon probe, added by the campaign. Each dimension below is written as a tuple for readability, but a probe records one pair, so section 27 shows how a tuple is packed.

## Coverage dimension 1 -- Certificate event vs certification lifetime

```text
(
  event = nullification | finalization,
  relation(event_view, last_finalized),
  certification_pending_before,
  certification_pending_after
)
```

Interesting states:

```text
nullification, pending -> pending
nullification, pending -> absent
finalization,   pending -> absent
finalization,   pending -> pending
```

---

## Coverage dimension 2 -- Optimistic ancestry state

```text
(
  in_issuance_window,
  has_previous_in_term,
  parent_ancestry_payload_available,
  optimistic_parent_ready
)
```

`parent_ancestry_payload_available` is `optimistic_ancestry_payload(parent).is_some()`; the
example's `proposal_parent_resolvable` is not a function in this codebase.

The mismatch states are especially valuable:

```text
parent_ancestry_payload_available = true
optimistic_parent_ready          = false
```

Potential consequence: unnecessarily lost one-shot vote.

```text
parent_ancestry_payload_available = false
optimistic_parent_ready          = true
```

Potential consequence: voting with ancestry the proposal logic rejects.

---

## Coverage dimension 3 -- Notarize gate vector

```text
(
  admits_outbound,
  round_can_construct,
  in_issuance_window,
  parent_ready,
  verification_matches,
  candidate_exists,
  signed
)
```

The fuzzer can retain an input because it discovers a new gate combination even when edge coverage is unchanged.

---

## Coverage dimension 4 -- Temporal ancestry restoration

```text
(
  parent_certification_failed,
  child_vote_withheld,
  parent_later_finalized,
  child_vote_retried
)
```

Expected unusual state:

```text
1, 1, 1, 0
```

The comment makes this a valuable target because it is counterintuitive but intentionally tolerated.

---

# 27. Example Probe Sketches

`sl_probe!` records **one pair** per site, and both halves must convert into `u32`, so a raw
view, digest or count cannot go in directly. The discretization helpers in
`crate::simplex::statelens` turn protocol values into small codes:

```text
flag(b)            0 or 1
bucket(n)          0, 1, 2, 3-4, 5-8, 9+  ->  0..=5
delta(a, b)        bucket(a - b), or 5 + bucket(b - a) when b > a
pack(high, low)    (high << 16) | (low & 0xffff)
disc(&value)       a stable code for an enum variant, payload ignored
```

A coverage dimension of four booleans therefore becomes one packed side, not four fields. The
sketches below are legal under the instrumentation rules of `prompts/instrument.md`: they add
statements and read-only helpers, and they never split or re-order existing code.

## Probe A -- Around nullification

The example's earlier sketch called an `add_nullification_inner`. Splitting the function would
change existing logic, which rule 1 forbids. Capture the before-state in a local at the top of
the existing function instead, and probe at the end:

```rust
pub fn add_nullification(&mut self, nullification: Nullification<S>) -> bool {
    let view = nullification.view();
    // [statelens] beacon:voter.nullification.certification
    let statelens_pending = self.outstanding_certifications.contains(&view);
    // [statelens] beacon:voter.nullification.certification
    let statelens_view = self.view;

    // ... the existing body, unchanged ...

    // [statelens] beacon:voter.nullification.certification
    crate::simplex::statelens::sl_probe!(
        self.scheme.me(),
        "voter.nullification.certification",
        crate::simplex::statelens::pack(
            crate::simplex::statelens::flag(statelens_pending),
            crate::simplex::statelens::flag(self.outstanding_certifications.contains(&view)),
        ),
        crate::simplex::statelens::delta(self.view.get(), statelens_view.get())
    );
    added
}
```

The pair is (what happened to the certification, how far the view moved). The interesting cell
is `pending -> absent` for a nullification, which is what the comment says must not happen.

## Probe B -- Around finalization

The same shape, with the opposite expectation: here `pending -> absent` is correct, and
`pending -> pending` for a view at or below `last_finalized` is the surprising cell.

```rust
// [statelens] beacon:voter.finalization.certification
crate::simplex::statelens::sl_probe!(
    self.scheme.me(),
    "voter.finalization.certification",
    crate::simplex::statelens::pack(
        crate::simplex::statelens::flag(statelens_pending),
        crate::simplex::statelens::flag(self.outstanding_certifications.contains(&view)),
    ),
    crate::simplex::statelens::delta(view.get(), statelens_finalized.get())
);
```

## Probe C -- Cross-rule ancestry agreement

The example named a `proposal_parent_resolution`, which does not exist. The real pair is
`optimistic_parent_ready(view)` and the ancestry lookup it delegates to,
`optimistic_ancestry_payload(parent)`. Both take `&self` and have no side effects, so both are
safe to read at one site:

```rust
// [statelens] beacon:voter.ancestry.agreement
crate::simplex::statelens::sl_probe!(
    self.scheme.me(),
    "voter.ancestry.agreement",
    crate::simplex::statelens::pack(
        crate::simplex::statelens::flag(self.optimistic_parent_ready(view)),
        crate::simplex::statelens::flag(
            self.previous_in_term(view)
                .is_none_or(|parent| self.optimistic_ancestry_payload(parent).is_some())
        ),
    ),
    crate::simplex::statelens::flag(self.in_issuance_window(view))
);
```

When the two rules can only be read at different call sites, probe each at its own site with a
shared label prefix and let the view relate them, rather than calling one from the other's
site.

## Probe D -- `construct_notarize` gate state

Five gates do not fit in a pair as five fields, so build a mask, as the real instrumentation
does for timeout reasons:

```rust
// [statelens] beacon:voter.construct_notarize.gates
let statelens_gates = crate::simplex::statelens::flag(self.admits_outbound(view))
    | crate::simplex::statelens::flag(round_eligible) << 1
    | crate::simplex::statelens::flag(self.in_issuance_window(view)) << 2
    | crate::simplex::statelens::flag(parent_ready) << 3;
// [statelens] beacon:voter.construct_notarize.gates
crate::simplex::statelens::sl_probe!(
    self.scheme.me(),
    "voter.construct_notarize.gates",
    statelens_gates,
    crate::simplex::statelens::flag(signed)
);
```

The mask is the state, the outcome is whether a signature was produced, and a new mask-outcome
combination is a new coverage cell even when every branch was already exercised.

Read each gate only where the original code already evaluated it, or where reading it is free
of side effects and of short-circuit meaning. Section 28 is about exactly that.

# 28. Important Instrumentation Constraint

A naive implementation could rewrite:

```rust
if self.in_issuance_window(view) && !self.optimistic_parent_ready(view) {
    return None;
}
```

as:

```rust
let in_window = self.in_issuance_window(view);
let ready = self.optimistic_parent_ready(view);
probe(in_window, ready);

if in_window && !ready {
    return None;
}
```

But this is only semantics-preserving if `optimistic_parent_ready` is safe to evaluate when `in_window == false`.

The original code short-circuits.

Therefore instrumentation must preserve evaluation semantics:

```rust
let in_window = self.in_issuance_window(view);
let ready = if in_window {
    Some(self.optimistic_parent_ready(view))
} else {
    None
};

probe(in_window, ready);

if in_window && ready == Some(false) {
    return None;
}
```

This is exactly the type of subtlety an instrumentation-validation phase must catch. In this
repository the rule it belongs to is non-interference, rule 4 of `prompts/instrument.md`:
instrumentation observes program state without changing the semantics or control logic, so it
must not change which branch the original code takes, and must not add a `return`, `break`,
`continue` or `?` that can leave or skip it. Forcing a short-circuited call to be evaluated
changes what runs, so the guarded form above is the only correct one. `cargo check` and the
test gate catch some of these; the rest is why a human reads `instrumentation.diff`.

---

# 29. What the Knowledge Base Contributes

The KB should not be treated as proof.

Its purpose in this example is:

```text
Source code says WHAT the implementation currently does.
KB explains WHY the behavior matters and WHAT larger protocol rule it belongs to.
```

Examples:

| Source observation | KB contribution | Agent result |
|---|---|---|
| nullification does not abort certification | explains valid-parent/liveness rationale | preserve same-view certification invariant |
| finalization aborts certification | explains definitive nature of finalization | cleanup invariant |
| ancestry rules must match | explains optimistic issuance / one-shot voting | cross-component ancestry invariant |
| parent finalization may restore ancestry without retry | explains tolerated abstention | temporal coverage target, not naive liveness assertion |

The agent must validate all executable relationships against source code before generating probes.

---

# 30. Final StateLens-Style Output

The paper's agent emits a State Report. Here the same content is split across three places,
so the block below is a summary of the analysis rather than a file any tool writes:

- the **invariants** become `invariants/simplex/INV-NNNN.md`, one file each, from Phase 1;
- the **coverage dimensions and probe sites** become `sl_probe!` call sites plus one row each
  in the `## Beacon probes` table of `campaign/plan.md`;
- the **beacons, what and why** are the agent's reasoning: they survive in its reply and in the
  plan's `Beacon` column, which says what a probe watches and where the agent found it.

A realistic summary of this analysis:

```yaml
analysis:
  title: "Certification lifetime and optimistic ancestry consistency"

  semantic_beacons:
    - "Nullification does not cancel pending certification work for the same view"
    - "Finalization is definitive, so these certifications are no longer relevant"
    - "optimistic_parent_ready must use the same ancestry rule as proposal construction"
    - "A stricter rule can permanently lose a one-shot vote; a looser rule can sign rejected ancestry"
    - "enter_view only advances"

  what:
    - "Certification lifetime across nullification vs finalization"
    - "Agreement between proposal-parent and optimistic-vote ancestry rules"
    - "Semantic gate vector controlling notarize signing"
    - "Monotonic view and finalization progress"

  why:
    - "Incorrectly cancelling certification after nullification can halt progress"
    - "Ancestry-rule mismatch can either lose votes or permit locally rejected ancestry"
    - "Ordinary edge coverage does not distinguish the relevant internal protocol states"

  invariants:
    - id: INV-A1
      text: "Nullification must not cancel still-relevant same-view certification solely because of the nullification"
    - id: INV-A2
      text: "After finalization advances to v, active certification state at or below v is obsolete"
    - id: INV-C1
      text: "Optimistic voting and proposal construction use equivalent ancestry usability rules"
    - id: INV-E3
      text: "Optimistic notarize signing requires locally usable parent ancestry"
    - id: INV-B1
      text: "Current view never moves backward"
    - id: INV-B2
      text: "last_finalized never decreases"

  coverage_dimensions:
    - "certificate event x certification lifetime transition"
    - "proposal ancestry decision x voting ancestry decision"
    - "notarize signing gate vector"
    - "failed certification -> withheld child vote -> later parent finalization"

  candidate_probe_sites:            # each becomes an sl_probe! site and a plan row
    - "before/after add_nullification protocol-state changes"
    - "before/after add_finalization cleanup"
    - "optimistic_parent_ready decision"
    - "optimistic_ancestry_payload lookup for the parent"
    - "construct_notarize gates and pre-sign point"
```

---

# 31. The Most Important Takeaway

The useful StateLens target in this source is **not** simply:

```text
Did add_nullification execute?
Did add_finalization execute?
Did construct_notarize execute?
```

Edge coverage already answers those questions.

The interesting semantic questions are:

```text
What certification state existed when nullification arrived?
Did it survive?

What certification state existed when finalization arrived?
Was it correctly invalidated?

Did proposal construction and optimistic voting agree on the same parent?

Which combination of admissibility, ancestry, verification, and round state
caused a notarize vote to be signed or withheld?

Did an unusual event ordering create a state that ordinary structural coverage
would consider equivalent to a routine execution?
```

That is the actual value of applying the StateLens idea to a consensus implementation: the fuzzer receives feedback about **protocol state relationships**, not merely about which Rust branches executed.

---

# 32. Source

Primary code examined:

- Commonware monorepo: `consensus/src/simplex/actors/voter/state.rs`
- https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/simplex/actors/voter/state.rs

The Knowledge Base entries in this document are intentionally fictionalized examples used to demonstrate the agent workflow. They should not be treated as actual Commonware documentation or historical issues.

The real knowledge base a campaign queries is whatever `STATELENS_KB` names, and its findings
carry the same kind of content in a fixed shape: a ` ```claim ` block, then `Context`,
`Root Cause`, `Lifecycle Events` and `Exploitation Or Trigger Conditions` among other sections,
of which those four are the ones a query may read. To see the real findings about the file this
document analyses, run `kb cites consensus/src/simplex/actors/voter`.
