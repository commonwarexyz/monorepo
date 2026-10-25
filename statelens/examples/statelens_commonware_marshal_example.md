# StateLens-Style Analysis of Commonware Marshal Deferred

Source:

```text
consensus/src/marshal/standard/deferred.rs
commit: 1a59fcd16273591ee500d2ef95e2c8a6902ebf68
```

## Objective

This example demonstrates how a StateLens-style agent should analyze the Marshal deferred-verification path.

The purpose is not to inspect one function in isolation. The agent should reconstruct the state machine that spans:

```text
propose
verify
deferred_verify
certify
certify_from_existing_task
certify_from_embedded_context
broadcast
report
Marshal storage
certification gates
crash/restart recovery
```

The example is written as a few-shot reasoning pattern for another agent. Section 0 says how
its vocabulary maps onto the StateLens workflow in this repository; read that first.

The agent should learn to:

1. identify semantic beacons,
2. formulate hypotheses,
3. distinguish structural unknowns from semantic unknowns,
4. query the Knowledge Base only when developer/protocol context is missing,
5. validate every important relationship against source,
6. derive candidate invariants,
7. select meaningful state dimensions,
8. propose probes only after the causal chain is understood.

---

<!-- statelens-lint: not-code: related_findings, remediation_status -->

# 0. How this maps onto StateLens in this repository

`just check-examples` verifies that every code name this document cites still exists. The two
names declared above are knowledge-base claim fields, not code.

This document uses the vocabulary of the StateLens paper. The workflow here divides the work
differently, so read the mapping before following the example literally. The companion
document `statelens_commonware_voter_example.md` does the same for the Simplex voter.

**Which agent does what.** The example shows one agent deriving invariants *and* choosing
probes. Here those are separate jobs:

| The example's step | Who does it here | Reads |
|---|---|---|
| The semantic scan and the candidate invariants M1 to M9 (sections 1 to 31) | the invariant analyst, `just extract-invariants --registry marshal comment consensus/src/marshal/standard/deferred.rs` | `prompts/analyst.md` + `prompts/analyst-comment.md` |
| State dimensions and probe sites (sections 32 to 34) | the instrumenter's beacon step for `marshal.standard`, inside `just campaign --profile marshal` | `prompts/instrument.md` + `prompts/instrument-beacons.md` |
| Binding an invariant to assertion sites | the instrumenter's invariant step | `prompts/instrument.md` + `prompts/instrument-invariants.md` |

An assertion can panic, so invariants live in a committed registry that a human reviews before
a campaign binds them, and the beacon step adds `sl_probe!` only: it never writes an assertion
and never invents an invariant.

**Where this code sits in a campaign.** `consensus/src/marshal/standard/deferred.rs` belongs to
the `marshal.standard` component, one of the six the `marshal` profile instruments (the three
Simplex actors, plus `marshal.core`, `marshal.standard` and `marshal.coding`). A marshal
invariant goes to `invariants/marshal/`, and a knowledge-base query made while instrumenting
this component sees only the findings whose `module` names marshal.

**Names.** The paper's pipeline artifacts do not exist here:

| Paper term used below | Here |
|---|---|
| Beacon Summary (section 10), reconstructed state machine (section 30) | no artifact: the agent holds this in its own context and records the result as rows of the plan's beacon table |
| `M1` to `M9` | local labels for this document. A registry invariant has a global `INV-NNNN` id that `just extract-invariants` assigns, and an EARS statement that names no Rust identifier |
| `QUERY_KB: "free text"` | `kb search` with a question in plain words, one of the six commands shown below |
| the uppercase state values in sections 33 and 34, such as `MATCH`, `READY_VALID`, `GATE_LOST` | this document's own vocabulary for coverage cells, not code identifiers. A probe records small integers, so section 33 shows how such a cell is encoded |
| a tuple of three to six fields | `sl_probe!(me, "label", a, b)` records exactly **one pair**; section 33 shows the packing |

**The knowledge base is real.** `STATELENS_KB` names corpus roots outside this repository,
holding findings under `findings/<state>/` -- each a fenced ` ```claim ` block (`module`,
`severity`, `remediation_status`, `summary`, `related_findings`) followed by fixed prose
sections, of which `Context`, `Root Cause`, `Lifecycle Events` and
`Exploitation Or Trigger Conditions` are the ones a query may read -- plus curated documents
under `kb/`, `config/` and `context/`. The agent never reads a corpus directly:

```text
kb modules                    what this subsystem's findings cover
kb find TERM...               findings whose summary or tags match, with the code they cite
kb cites PATH                 findings that cite a file under PATH  <- start here
kb grep TEXT                  snippets of the state-bearing sections
kb show IDENTIFIER [SECTION]  one claim block, or one state-bearing section
kb search QUESTION            snippets ranked by meaning: findings, documents, comments, docs
```

The mock KB results below stand in for real findings. `consensus/src/marshal/standard` is
unusually well covered: `kb cites consensus/src/marshal/standard` returns real findings about
this exact path, several of them about the availability and gate-ordering states this document
reconstructs.

---

# 1. Initial Semantic Scan

The agent starts with developer-authored comments and regression tests rather than blindly instrumenting variables.

Several comments immediately expose important Marshal semantics.

---

## Beacon 1 -- Notarization Does Not Guarantee Block Availability

The module documentation explains that a notarization certificate may exist even when the block is unavailable to honest parties.

Conceptually:

```text
notarization_exists = true
block_available_locally = false
```

is a legal state.

This is important because a naive state model might assume:

```text
notarized
    =>
block_available
```

but Marshal explicitly supports recovery when this implication does not hold.

### Initial hypothesis

```text
H1:
Notarization, block availability, verification, and certifiability are
distinct semantic states.
```

### Why this beacon matters

It suggests state dimensions such as:

```text
notarized
block_available
verification_state
certification_state
```

rather than one coarse boolean like:

```text
known_block
```

---

# 2. Beacon 2 -- Deferred Verification Splits Notarization from Finalization

The module documentation states that before casting a notarize vote, the wrapper waits for block availability and validates the block context, but does not wait for the application to finish verification.

Application verification continues concurrently with quorum formation.

Certification waits for that result before allowing finalization.

The agent extracts:

```text
H2:

notarize eligibility
    !=
finalize eligibility
```

More precisely:

```text
optimistic verification may succeed while:
    application_verification = PENDING
```

but:

```text
successful certification requires:
    application_verification = VALID
```

This is a very strong semantic beacon because it describes a deliberate intermediate state.

---

# 3. Beacon 3 -- Storing Before Validation Is Intentional

Inside `deferred_verify`, the comment explains that storage starts immediately:

```text
store(block)
```

before parent/application verification completes.

The comment also explicitly says:

```text
these caches provide candidate availability/recovery,
not a validity decision
```

The agent records:

```text
H3:

stored(block)
    !=
valid(block)
```

This is a critical Marshal distinction.

A block can be:

```text
present in Marshal
but not yet application-valid
```

or even:

```text
present in Marshal
and application-invalid
```

The storage layer serves availability and recovery, while validity is carried by the verification gate.

---

# 4. Beacon 4 -- Gate Success Requires Both Verification and Durability

The same `deferred_verify` path performs:

```text
verify
and
store
```

concurrently and later combines them.

Conceptually:

```text
(verdict, durable) = join(verify, store)

gate = resolve(verdict, durable)
```

The agent extracts:

```text
H4:

successful certification readiness requires both:

    application_validity
    storage_durability
```

Candidate state dimensions:

```text
application_verdict:
    PENDING
    VALID
    INVALID

durability:
    PENDING
    DURABLE
    FAILED
```

---

# 5. Beacon 5 -- Embedded Context Is Security-Critical

Inside `verify`, the code checks:

```rust
if block.context() != context {
    ...
    return;
}
```

The surrounding comment explains that this comparison is necessary before an honest validator emits a notarize vote.

Why?

Because validators that did not vote may later rely on the block's embedded context during certification recovery.

The agent extracts:

```text
H5:

A normal proposal may receive optimistic notarize approval only if:

    block.embedded_context == consensus_context
```

This is more than a local equality check.

It creates a cross-phase trust relationship:

```text
verify-time context equality
        ->
later certify-time trust in embedded context
```

---

# 6. Beacon 6 -- Nullification Does Not Destroy Deferred Work

The `verify` path explicitly states:

```text
Nullification keeps that gate alive,
while finalization drops it.
```

The agent should flag this immediately.

It describes lifecycle semantics that cannot be inferred from the current view number alone.

The important distinction is:

```text
nullified != finalized
```

A node may leave the view operationally while still needing certification work associated with that view.

Initial hypothesis:

```text
H6:

Gate lifetime is controlled by semantic settlement,
not merely by view advancement.
```

---

# 7. Beacon 7 -- Missing Gate Means Recovery, Not Failure

`certify()` performs conceptually:

```rust
if let Some(task) = gates.take(round, digest) {
    certify_from_existing_task(...)
} else {
    certify_from_embedded_context(...)
}
```

The comments explain why a gate can legitimately be missing:

```text
- proposal was never verified locally
- unclean restart lost in-memory state
```

Therefore:

```text
gate_absent
    !=
cannot_certify
```

Instead:

```text
gate_absent
    ->
reconstruct the verification path
```

The agent records:

```text
H7:

Certification must tolerate loss or absence of volatile gate state.
```

---

# 8. Beacon 8 -- Context-Mismatch Rejection Must Not Poison Later Certification

A regression test describes a particularly important case.

A leader can present the same block digest under different proposal contexts.

A local validator may reject one proposal because:

```text
proposal context != block embedded context
```

Later, a valid notarization for that digest may arrive.

Certification must then use the notarized block's embedded context rather than permanently reusing the earlier contextual rejection.

The agent extracts:

```text
H8:

CONTEXT_MISMATCH rejection
    !=
APPLICATION_INVALID verdict
```

This is a high-value state distinction.

Two executions may both contain:

```text
verify -> false
```

but the reasons have completely different semantics.

---

# 9. Beacon 9 -- Real Application Rejection Must Survive Notarization

Another regression test provides the complementary rule.

If the block is verified under the correct context and:

```text
application.verify(block) == false
```

then certification must reject it even if a notarization exists.

The agent extracts:

```text
H9:

APPLICATION_INVALID
    must remain authoritative during certify.
```

Together, Beacons 8 and 9 suggest a typed verdict model.

---

# 10. Initial Beacon Summary

The agent now emits a Phase-1-style summary:

```text
STATE DESCRIPTIONS

    block availability
    block durability
    optimistic verification status
    application verification status
    context relationship
    gate presence/lifetime
    recovery path
    finalization status
    rejection provenance

TRANSITION HINTS

    unavailable -> available
    non-durable -> durable
    app verification pending -> valid / invalid
    no gate -> gate registered
    gate registered -> consumed
    gate absent -> recovery path
    active -> nullified with gate preserved
    active -> finalized with gate retired
    context mismatch rejection -> later embedded-context recovery
    application rejection -> certification rejection

SEED SYMBOLS

    Deferred::verify
    Deferred::deferred_verify
    Deferred::certify
    Deferred::certify_from_existing_task
    Deferred::certify_from_embedded_context
    Relay::broadcast
    Reporter::report
    Gates
    Mailbox
```

At this point the agent still should not generate probes.

---

# 11. Decide What to Inspect in Source First

The agent distinguishes two classes of unknowns.

## Structural unknowns

```text
Where is a gate inserted?
Where is it removed?
Who consumes it?
Where does storage become durable?
Which function returns the optimistic result?
Which path recovers a missing gate?
```

These should be answered using source tools:

```text
inspect_source
search_code
call_graph
data_flow
```

## Semantic unknowns

```text
Why may notarization precede application verification?
Why may embedded context be trusted after notarization?
Why must nullification preserve gate work?
Why is context mismatch weaker than application rejection?
```

These are appropriate KB questions.

This is the first explicit decision rule for the agent:

```text
Use source for "where/how".

Use KB for "what does this mean / why is it correct".
```

---

# 12. Source Traversal -- `verify`

The agent follows `verify()`.

Conceptually:

```text
verify(context, digest)
    |
    |-- subscribe_by_digest(digest, Wait)
    |
    |-- create task channel
    |
    |-- gates.insert(round, digest, task_rx)
    |
    `-- spawn optimistic verification task
```

The task then:

```text
start parent fetch when needed
    ->
wait for candidate block
    ->
run epoch/reproposal precheck
    ->
for normal proposal:
    require block.context == consensus context
    ->
start deferred_verify
    ->
return optimistic true
    ->
deferred work continues through the gate
```

The agent records a state transition:

```text
GATE_ABSENT
    ->
GATE_REGISTERED
```

before the asynchronous work completes.

This ordering is interesting because it protects against races where certification arrives while verification is still in progress.

---

# 13. Source Traversal -- `deferred_verify`

The agent inspects the function.

It sees two concurrent branches:

```text
             deferred_verify
             /             \
            /               \
     store candidate      verify candidate
            \               /
             \             /
              join results
                   |
                   v
          gates::resolve(...)
```

The storage path begins before validation.

The verification path performs:

```text
parent acquisition
parent validation
application verification
```

The resulting gate state therefore summarizes a relation across multiple subsystems.

---

# 14. First KB Query -- Why Is This Split Safe?

At this point the source tells the agent what happens, but the agent still needs protocol meaning.

It issues, from the repository root:

```text
kb cites consensus/src/marshal/standard/deferred.rs
kb find deferred verification certification gate
```

`kb cites` first, because the path is what the agent is holding; `kb find` for the concept the
path alone does not explain. Both are already restricted to findings whose `module` names
marshal.

Mock KB result, in the shape a finding's `Root Cause` section returns:

```text
Deferred verification overlaps application validation with quorum formation.

A validator may vote to notarize after validating availability,
parent/context constraints, and proposal identity.

The application verdict is deferred until certification.

A finalize vote must not be emitted until the deferred application
verdict is successful.
```

### Self-reflection

```text
KEEP
```

Reason:

```text
Directly explains why the intermediate PENDING state is legal.
```

The agent updates:

```text
optimistic_verify_success
    means
eligible_to_notarize

not
eligible_to_finalize
```

---

# 15. Candidate Invariant M1 -- Certification Cannot Bypass Application Validity

`M1` to `M9` are labels local to this document. A real invariant goes into
`invariants/marshal/` with a global `INV-NNNN` id that `just extract-invariants` assigns and a
statement that names no Rust identifier; deriving them is Phase 1 work, and the beacon step
never writes one.

The agent derives:

```text
M1:

certify(round, digest) == true
    =>
authoritative application verification == VALID
```

This is supported by:

```text
deferred_verify
certification gate
application-rejection regression tests
```

### Why this invariant is useful

A structural fuzzer may cover:

```text
verify -> certify
```

for both valid and invalid application payloads.

State-aware coverage should distinguish:

```text
app_valid -> certify_true
app_invalid -> certify_false
```

---

# 16. Candidate Invariant M2 -- Successful Certification Requires Required Durability

The agent observes that the gate is resolved from both:

```text
verification verdict
storage durability
```

It derives:

```text
M2:

successful deferred certification
    =>
required candidate storage completed successfully
```

The agent should mark this invariant as tied specifically to the normal deferred path and verify reproposal/recovery exceptions separately.

---

# 17. Candidate Invariant M3 -- Storage Does Not Imply Validity

The source strongly supports:

```text
M3:

marshal_contains(block)
    does not imply
application_valid(block)
```

This may not be an invariant in the "assert always true" sense.

It is better represented as a semantic non-implication that the agent must preserve when designing state coverage.

The fuzzer should intentionally exercise:

```text
stored + app_pending
stored + app_valid
stored + app_invalid
```

because all can be meaningful runtime states.

---

# 18. Source Traversal -- `certify`

The agent follows:

```text
certify(round, digest)
    |
    |-- flush_unrelayed(...)
    |
    |-- gates.take(round, digest)
    |
    +-- Some(task)
    |      |
    |      `-> certify_from_existing_task
    |
    `-- None
           |
           `-> certify_from_embedded_context
```

This exposes another state dimension:

```text
certification_source:
    EXISTING_GATE
    EMBEDDED_CONTEXT_RECOVERY
```

A normal coverage metric sees two branches.

State coverage asks why the branch was taken:

```text
never verified locally?
gate lost after crash?
task already consumed?
```

Those are semantically different histories.

---

# 19. Second KB Query -- Why Is Embedded Context Trustworthy?

The agent cannot prove the trust argument solely from this function.

It asks:

```text
kb find embedded context notarization recovery
kb grep "embedded context"
```

Mock result:

```text
A notarization quorum contains at least f+1 honest validators.

Honest validators verify that the block's embedded context matches the
consensus context before voting.

Therefore, once the digest is notarized, the embedded context can serve
as a recovery anchor for validators that lost or never had the original
in-memory verification task.
```

### Self-reflection

```text
KEEP
```

This changes the agent's state model.

The bytes of `block.context()` do not change, but their semantic evidence state does:

```text
before quorum evidence:
    embedded_context = untrusted claim

after notarization:
    embedded_context = quorum-backed recovery context
```

This is exactly the kind of semantic state ordinary code coverage cannot encode.

---

# 20. Candidate Invariant M4 -- Context Must Match Before Normal Optimistic Approval

The agent derives:

```text
M4:

For a non-reproposal:

optimistic_verify == true
    =>
block.context() == consensus_context
```

The agent explicitly excludes the source-defined reproposal path, which follows different rules.

### Candidate coverage dimensions

```text
proposal_kind:
    NORMAL
    REPROPOSAL

context_relation:
    MATCH
    MISMATCH

optimistic_result:
    TRUE
    FALSE
```

Interesting bucket:

```text
NORMAL + MISMATCH + TRUE
```

should be unreachable.

---

# 21. Source Traversal -- Gate Lifetime and `report`

The agent searches all gate-retention/removal sites.

It finds finalization cleanup in:

```rust
if let Update::Tip(round, _, _) = &update {
    self.gates.retain_after(round);
}
```

The source says this removes certification gate tasks at or below the finalized round.

The agent now asks:

```text
Does mere view advancement also permit this cleanup?
```

The source comments suggest no.

Nullification intentionally leaves deferred work alive.

This creates the next candidate invariant.

---

# 22. Third KB Query -- Why Does Nullification Preserve Certification Work?

The agent asks:

```text
kb find nullification certification gate
kb grep "gate lifetime"
```

Mock result:

```text
Nullification moves consensus past a view without proving all information
from that view is irrelevant.

A notarized/certified result for the view can still become useful as ancestry.

Finalization is stronger: once a view is finalized, certification work at
or below the finalized tip is no longer required for future progress.
```

### Self-reflection

```text
KEEP
```

The agent updates its model:

```text
cleanup eligibility depends on settlement state,
not simply current_view > old_view.
```

---

# 23. Candidate Invariant M5 -- Nullification Must Not Imply Gate Destruction

The agent derives:

```text
M5:

nullification(view)
    must not, by itself, destroy pending certification work
    still needed for that view.
```

And the complementary lifecycle rule:

```text
M6:

finalization through view v
    may retire certification work at/below v.
```

This suggests the state dimension:

```text
settlement:
    ACTIVE
    NULLIFIED
    FINALIZED
```

combined with:

```text
gate:
    ABSENT
    PENDING
    READY_VALID
    READY_INVALID
```

Interesting transitions:

```text
ACTIVE/PENDING
    --nullification-->
NULLIFIED/PENDING
```

and:

```text
ACTIVE/PENDING
    --finalization-->
FINALIZED/REMOVED
```

---

# 24. Source Traversal -- `certify_from_embedded_context`

The agent now inspects recovery.

The path is conceptually:

```text
subscribe/fetch block
    ->
if reproposal:
    route through certified storage
    ->
otherwise:
    read embedded context
    ->
derive parent round/commitment
    ->
fetch parent
    ->
deferred_verify(..., Stage::Certified)
```

This is important.

The recovery path does not simply say:

```text
notarized => valid
```

Instead, it reconstructs enough context to run the required verification.

The agent derives:

```text
H10:

Recovery substitutes evidence provenance,
not validity semantics.
```

---

# 25. Candidate Invariant M7 -- Losing a Gate Must Not Weaken Validation

The agent formulates:

```text
M7:

absence/loss of an in-memory certification gate
    must not weaken the application validity rule.
```

In other words, conceptually:

```text
certify_with_existing_gate(block)
```

and:

```text
certify_after_gate_loss(block)
```

should enforce the same application-validity requirement.

They may obtain context differently, but they must not silently turn:

```text
UNKNOWN
```

into:

```text
VALID
```

---

# 26. Regression-Test Beacon -- Context Equivocation

Now the agent inspects the regression test involving proposal-layer equivocation.

The test describes:

```text
same block digest
same round

but different proposal contexts / parents
```

One context may be rejected locally.

Later the block becomes notarized under its embedded context.

The comment says certification must not adopt the earlier verdict computed under the equivocating proposal context.

The agent recognizes this as a cross-component stale-verdict problem:

```text
verdict created under Context A
        |
        X  must not be reused blindly
        |
certification under Context B
```

This is one of the strongest semantic beacons in the file.

---

# 27. Fourth KB Query -- Verdict Scope

The agent asks:

```text
kb find equivocation context digest
kb show <the identifier a previous hit named in related_findings>
```

Mock result:

```text
A proposal-layer equivocation can associate the same payload digest with
different proposal headers.

A context-mismatch rejection proves that the local proposal presentation
was unacceptable.

It does not prove that the underlying block is application-invalid under
the context supported by a later notarization.
```

### Self-reflection

```text
KEEP
```

Now the agent has enough information to split verification failures into semantic classes.

---

# 28. Candidate Invariant M8 -- Contextual Rejection Is Not Application Invalidity

The agent derives:

```text
M8:

CONTEXT_MISMATCH
    must not be persisted or propagated as
APPLICATION_INVALID(block).
```

This is a classic StateLens target because both may manifest structurally as:

```text
verification returns false
```

but have very different downstream semantics.

---

# 29. Candidate Invariant M9 -- Genuine Application Rejection Remains Authoritative

The complementary regression test says:

```text
application.verify(block) == false
```

under the correct context must cause certification failure.

Thus:

```text
M9:

APPLICATION_INVALID
    =>
certify == false
```

even if a notarization exists.

Together:

```text
CONTEXT_MISMATCH
    may later recover and certify

APPLICATION_INVALID
    must not certify
```

This is an excellent state-coverage distinction.

---

# 30. Reconstructed Causal State Machine

The agent can now produce a causal model.

## Normal path

```text
proposal received
    ->
block locally available
    ->
normal/reproposal precheck
    ->
context validated
    ->
gate registered
    ->
optimistic verify succeeds
    ->
notarize vote may be emitted
    ->
application verification continues
    ->
storage becomes durable
    ->
gate resolves
    ->
certify consumes result
    ->
finalize vote allowed only when authoritative result is true
```

## Nullification path

```text
optimistic verify succeeded
    ->
deferred work pending
    ->
view nullified
    ->
gate remains alive
    ->
late useful certification can still complete
```

## Restart / missing-gate path

```text
notarization exists
    ->
in-memory gate absent
    ->
certify selects embedded-context recovery
    ->
block fetched
    ->
quorum-backed embedded context used
    ->
required verification reconstructed
    ->
authoritative application verdict propagated
```

## Context-equivocation path

```text
proposal presented under mismatched context
    ->
local verify rejects CONTEXT_MISMATCH
    ->
honest notarization later exists
    ->
certify must not reuse contextual rejection
    ->
embedded-context recovery
    ->
block may certify successfully
```

## Genuine application-rejection path

```text
context valid
    ->
optimistic vote may occur
    ->
application verify eventually rejects
    ->
notarization may still exist
    ->
certify must return false
```

---

# 31. Final Candidate Invariant Set

The agent should label these as candidate semantic invariants until validated against the protocol specification.

```text
M1 -- Certification validity

certify == true
    =>
authoritative application verification == VALID
```

```text
M2 -- Deferred certification durability

successful normal deferred certification
    =>
required storage is durable
```

```text
M3 -- Storage is not validity

marshal_contains(block)
    does not imply
application_valid(block)
```

```text
M4 -- Normal optimistic context agreement

normal_proposal && optimistic_verify == true
    =>
block.context == consensus_context
```

```text
M5 -- Nullification preserves relevant pending certification work

nullification(view)
    does not by itself imply
gate(view) may be discarded
```

```text
M6 -- Finalization allows cleanup

finalized_tip >= view
    =>
certification gate work for view may be retired
```

```text
M7 -- Recovery preserves validity semantics

gate_absent
    must not weaken
application verification requirements
```

```text
M8 -- Context mismatch is scoped

CONTEXT_MISMATCH
    !=
APPLICATION_INVALID
```

```text
M9 -- Application rejection is authoritative

APPLICATION_INVALID
    =>
certify == false
```

---

# 32. State Dimensions Worth Instrumenting

The agent should avoid instrumenting every local variable.

The following dimensions are semantically meaningful:

```text
block_availability:
    ABSENT
    LOCAL_BUFFER
    FETCHED
    STORED

storage_durability:
    PENDING
    DURABLE
    FAILED

verification_stage:
    NOT_STARTED
    OPTIMISTIC_ACCEPTED
    DEFERRED_PENDING
    VALID
    INVALID

context_relation:
    MATCH
    MISMATCH
    REPROPOSAL_SPECIAL_CASE

gate_state:
    ABSENT
    REGISTERED
    PENDING
    READY_VALID
    READY_INVALID
    CONSUMED
    RETIRED

certification_path:
    EXISTING_TASK
    EMBEDDED_CONTEXT_RECOVERY

settlement:
    ACTIVE
    NULLIFIED
    FINALIZED

failure_provenance:
    NONE
    UNSUPPORTED_EPOCH
    CONTEXT_MISMATCH
    PARENT_INVALID
    APPLICATION_INVALID
    DATA_UNAVAILABLE
    RECOVERY_REQUIRED
```

---

# 33. Candidate Probe Sites

`sl_probe!(me, "label", a, b)` records **one pair**, and both halves must convert into `u32`,
so the tuples below are analysis notation, not a probe signature. The discretization helpers in
`crate::simplex::statelens` encode them:

```text
flag(b)            0 or 1
bucket(n)          0, 1, 2, 3-4, 5-8, 9+  ->  0..=5
delta(a, b)        bucket(a - b), or 5 + bucket(b - a) when b > a
pack(high, low)    (high << 16) | (low & 0xffff)
disc(&value)       a stable code for an enum variant, payload ignored
```

Probe P2's `(application_verdict, durability, gate_outcome)` therefore becomes one pair, with
the two inputs on one side and the outcome on the other:

```rust
// [statelens] beacon:marshal.standard.deferred_verify.outcome
crate::simplex::statelens::sl_probe!(
    me,
    "marshal.standard.deferred_verify.outcome",
    crate::simplex::statelens::pack(
        crate::simplex::statelens::flag(application_valid),
        crate::simplex::statelens::flag(durable),
    ),
    crate::simplex::statelens::disc(&outcome)
);
```

`me` is marshal's replica index, obtained as the marshal subsystem rules say, not
`self.scheme.me()`. Where a dimension has more than three components, prefer two probes at the
sites where the values are naturally available over one probe that has to reach for them: a
probe must not call anything with side effects, and must not force a value the original code
only computes conditionally.

## Probe P1 -- `verify`

Observe:

```text
proposal kind
block availability
context relation
optimistic result
gate registered
```

Useful tuple:

```text
(
    proposal_kind,
    context_relation,
    optimistic_result
)
```

---

## Probe P2 -- `deferred_verify`

Observe:

```text
parent result
application verdict
store/durability result
gate outcome
```

Useful tuple:

```text
(
    application_verdict,
    durability,
    gate_outcome
)
```

---

## Probe P3 -- `certify`

Observe:

```text
gate present?
selected path?
```

Tuple:

```text
(
    gate_presence,
    certification_path
)
```

---

## Probe P4 -- `certify_from_embedded_context`

Observe:

```text
block recovered?
reproposal?
embedded context used?
parent recovered?
application verdict?
certification result?
```

---

## Probe P5 -- `report`

Observe transition:

```text
gate state before finalized-tip update
    ->
gate state after cleanup
```

especially for rounds:

```text
<= finalized_tip
> finalized_tip
```

---

## Probe P6 -- Rejection provenance

Instead of only recording:

```text
verify = false
```

record:

```text
failure_reason
```

This is particularly important for:

```text
CONTEXT_MISMATCH
vs
APPLICATION_INVALID
```

because their later certification behavior intentionally differs.

---

# 34. Example State-Coverage Tuples

The fuzzer could encode:

```text
(
    context_relation,
    verification_stage,
    gate_state,
    certification_path,
    settlement,
    certification_result
)
```

Examples:

```text
E1:
MATCH,
VALID,
READY_VALID,
EXISTING_TASK,
ACTIVE,
TRUE
```

```text
E2:
MATCH,
INVALID,
READY_INVALID,
EXISTING_TASK,
ACTIVE,
FALSE
```

```text
E3:
MISMATCH,
OPTIMISTIC_REJECTED,
ABSENT_OR_RECOVERY,
EMBEDDED_CONTEXT_RECOVERY,
NOTARIZED,
TRUE
```

```text
E4:
MATCH,
VALID,
GATE_LOST,
EMBEDDED_CONTEXT_RECOVERY,
NOTARIZED,
TRUE
```

```text
E5:
MATCH,
INVALID,
NO_PRIOR_LOCAL_VERIFY,
EMBEDDED_CONTEXT_RECOVERY,
NOTARIZED,
FALSE
```

These executions can share substantial structural coverage while having very different protocol
meaning, which is exactly what a beacon probe exists to separate.

Six components do not fit in one pair, and three probes at three sites would not record them
either: a probe keeps only the presence of its own pair, nothing joins sites, and the round is
not recorded, so the verification outcome seen in `deferred_verify`, the path choice in
`certify` and the settlement in `report` would survive only as marginals, no longer telling E3
from an execution that mixed its parts with E4's. Carry the earlier parts to the last site in
bounded ghost state -- the outcome and the path, keyed by the round the adapter already
tracks -- and emit them packed on one side of a `marshal.standard.settlement` probe, against
the settlement on the other. A part that cannot be carried without reaching for a value is
probed alone, and the plan says that its relationship to the rest is unobserved. The uppercase
names above are this
document's vocabulary; in a probe each becomes a small integer, usually `disc` of the
corresponding enum where one exists and a packed set of flags where it does not.

---

# 35. Example Agent Trace

The following is a reusable few-shot template for another analysis agent.

It intentionally records observable analysis decisions rather than hidden internal reasoning.

```text
STEP 1

OBSERVE:
    Documentation says notarization may exist without block availability.

HYPOTHESIS:
    notarization and availability are separate states.

ACTION:
    inspect verify(), certify(), and Marshal subscription/fetch behavior.

RESULT:
    verify may wait locally, while certification recovery can actively fetch.

STATE DIMENSIONS:
    notarized
    available
    recovery_mode
```

```text
STEP 2

OBSERVE:
    deferred_verify stores the candidate before validation.

QUESTION:
    Is storage itself a validity decision?

ACTION:
    read surrounding source comments.

RESULT:
    no; storage is for recovery/availability.

HYPOTHESIS:
    storage_state and validity_state must be tracked independently.
```

```text
STEP 3

OBSERVE:
    optimistic verify can return true before app verification completes.

QUESTION:
    Why is this protocol-safe?

ACTION:
    kb find deferred verification application verdict

RESULT:
    application verification latency is hidden behind quorum formation;
    certification gates finalization.

INVARIANT:
    certify TRUE => authoritative app verdict VALID.
```

```text
STEP 4

OBSERVE:
    certify falls back to embedded-context recovery when no gate exists.

QUESTION:
    Why can embedded context be trusted?

ACTION:
    kb find embedded context recovery

RESULT:
    honest notarizers checked context equality before voting.

HYPOTHESIS:
    notarization changes the evidence status of embedded context.
```

```text
STEP 5

OBSERVE:
    nullification keeps a gate alive; finalization removes old gates.

QUESTION:
    Is cleanup driven by current view or settlement semantics?

ACTION:
    search all gate lifecycle sites.
    query KB only for protocol rationale.

RESULT:
    cleanup is tied to finalization, not simple view advancement.

INVARIANT:
    nullification alone must not discard still-relevant certification work.
```

```text
STEP 6

OBSERVE:
    regression test rejects a mismatched proposal context but later certification succeeds.

QUESTION:
    Why can a previous false verdict be ignored?

ACTION:
    inspect test and recovery path.
    kb find equivocation context mismatch

RESULT:
    contextual rejection is not application invalidity.

INVARIANT:
    CONTEXT_MISMATCH != APPLICATION_INVALID.
```

```text
STEP 7

OBSERVE:
    application rejection under correct context remains fatal to certification.

ACTION:
    inspect application-rejection regression tests.

INVARIANT:
    APPLICATION_INVALID -> certify FALSE.
```

```text
STEP 8

ACTION:
    produce State Report.

WHAT:
    Marshal availability / verification / durability / gate / recovery state machine.

WHY:
    these dimensions determine whether a notarized candidate can safely
    progress to certification/finalization.

HOW:
    verify
      -> deferred_verify
      -> gate
      -> certify(existing | recovery)
      -> report(finalization cleanup)

PROBES:
    verify classification
    deferred resolution
    gate lifecycle
    certification path
    recovery result
    failure provenance
```

---

# 36. Few-Shot Instruction Extracted from This Example

```text
When analyzing Marshal-like code:

1. Do not assume a certificate implies local data availability.
2. Do not assume stored data is valid data.
3. Distinguish optimistic acceptance from authoritative application validity.
4. Track asynchronous work as explicit state.
5. Track evidence provenance:
       local verification
       quorum-backed embedded context
       recovered state
6. Treat failure reasons as semantic states, not only booleans.
7. Inspect lifecycle events such as:
       nullification
       finalization
       restart
       task loss
8. Query the KB only when the source tells you what happens but not why
   the protocol allows or requires it.
9. Validate KB claims against actual call/data flow.
10. Only after reconstructing the state machine should you derive probes.
```

