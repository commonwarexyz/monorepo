# TSS reach check: explanation and worked example

Step 3 of Target-State Synthesis (TSS) checks whether a generated scaffold reaches
the state described by its target-state card. It executes a fixed input, collects
evidence, checks that evidence against the card, and runs a control with one event
withheld. This happens before ordinary fuzzing.

## Start here: all three nodes have the leader's view-1 nullify vote

Your requested state is:

> All three nodes have the nullify vote from the leader of view 1.

Use three nodes named A, B and C. A is the leader of view 1. All messages in
this example belong to the same epoch, which we call epoch 0.

Here, "have" means that a node's current view-1 vote collection records A's
nullify vote. A records its own vote locally; B and C accept A's vote from the
network. A vote waiting in the network queue does not count.

This is one leader-signed vote present at three nodes. It is not three votes
signed by different nodes, and it is not a quorum nullification certificate.

This section describes a proposed scaffold for your example. It does not claim
that this card or a suitable state accessor has already been implemented or run.

### Step 1: write down exactly what success means

Call A's signed vote N. Its identity is:

```text
kind:   nullify
epoch:  0
view:   1
signer: A, the leader of view 1
```

The goal is one simultaneous condition at handoff:

```text
A has N  AND  B has N  AND  C has N
```

The final check must inspect all three nodes. Observing only A broadcasting N
cannot establish this condition.

### Step 2: start the cluster in the right setup

The scaffold starts from the harness's normal fresh setup, with genesis as the
initial finalized state. It arranges leader election so that A leads view 1,
then lets the nodes enter view 1.

For this example, it delays A's proposal response so that A takes the normal
proposal-timeout path. It controls message delivery so that later votes or
certificates do not move the nodes beyond the state being inspected before
handoff. Those delays are part of the scripted setup.

TSS is driving existing application, timer and network operations. It does not
set an internal "has nullify" flag on any node.

#### How A's timeout actually fires

The mock [application](../consensus/src/simplex/mocks/application.rs) already has
`Application::set_stall_proposals(true)`. Configured before starting A's application,
this keeps proposal reply senders alive in `pending_proposes` without answering
them. A's voter receives a pending proposal receiver and can keep running its
event loop while the application has not supplied a proposal.

The native timer path is:

```text
State::enter_view(1)
    sets leader deadline = current simulated time + leader_timeout

A requests a proposal; its application keeps the response pending

State::next_timeout / Round::next_timeout
    select the leader deadline while there is no proposal

The voter awaits context.sleep_until(deadline)

The deterministic runtime advances its simulated clock and wakes that wait

The voter's timer branch invokes its native timeout handler
```

The scaffold lets the runtime run until it observes A's resulting nullify vote,
with a stage deadline of its own. It must also keep A in view 1 and prevent other
progress from satisfying or superseding the selected timeout. Sleeping for a
fixed duration alone would not establish that this happened.

For example, if the configured leader timeout were one simulated second, A's
proposal remains unanswered through that deadline. The runtime wakes A's timer,
and A takes its normal nullify transition and journal path. This does not require
waiting one second on the machine's real clock or manually calling the timeout
handler.

There is a setup integration detail: `build_validator_with_reporter` in the shared
fuzz core currently constructs the application and starts it immediately. A
scaffold would need a permitted setup adaptation in its own package to apply
the existing setter to A before starting that actor. This example is not claiming
that the adaptation has already been written or that the base input has a flag
which automatically enables it.

### Step 3: let A produce its vote

The scaffold advances the deterministic execution until A's normal timeout
handling produces N. A's protocol code signs its own vote, durably records it
before publication, passes it to the local batcher and broadcasts it to peers.

The scaffold waits until A's current vote collection records N. It also captures
the outgoing vote so that the network schedule can deliver it to B and C.

At this point, the intended observations are:

| Node | Has A's view-1 nullify vote? |
|---|---|
| A | yes |
| B | no |
| C | no |

The target is not reached yet.

### Step 4: deliver A's vote to B

The scaffold releases N on A's normal outgoing connection to B. It then lets B
run until B's vote handling has accepted and recorded that vote.

The witness must identify the observer B, signer A, epoch 0 and view 1. A
network send record alone is insufficient: B could still have the message
queued, ignore it or reject it.

The intended observations now are:

| Node | Has A's view-1 nullify vote? |
|---|---|
| A | yes |
| B | yes |
| C | no |

The target is still not reached.

### Step 5: deliver A's vote to C

The scaffold releases the same vote on A's normal outgoing connection to C.
It lets C run until C has accepted and recorded it.

The intended observations now are:

| Node | Has A's view-1 nullify vote? |
|---|---|
| A | yes |
| B | yes |
| C | yes |

This looks like the desired state, but the final check must still establish
that all three conditions hold together at handoff.

### Step 6: inspect all three nodes at handoff

Immediately before the continuation starts, the scaffold supplies the helper
with a read of the three current vote collections. Conceptually, it asks:

```text
Does A currently record a nullify from A for epoch 0, view 1?
Does B currently record a nullify from A for epoch 0, view 1?
Does C currently record a nullify from A for epoch 0, view 1?
```

All three answers must be yes. The final witness contains all three observations,
with their identities. The helper then marks the handoff without yielding
execution between that read and the mark.

This matters because A could have recorded N earlier and later removed its
view-1 state. An old "A received N" log entry would not prove A still has it.

There is a real implementation requirement here: the scaffold needs an exact,
side-effect-free observation of current presence that is usable synchronously
at handoff. The existing reporter's nullify history can show that a valid vote
was observed, but does not by itself prove that the protocol still retains it.
The batcher's `Round::has_nullify` expresses the relevant membership condition,
but it is not already a synchronous accessor available to the external scaffold.
If the chosen harness cannot expose suitable evidence through permitted changes,
TSS must report the stage as unverifiable or the capability as missing.

If you meant "each node has accepted this vote at some time" instead, the goal
would be a historical condition and the reporter history could be suitable.
That is a different condition from current possession at handoff.

### Step 7: check the evidence against the card

One possible division into card stages is:

| Stage | What it establishes |
|---|---|
| E1 | The fresh setup has A as the view-1 leader |
| E2 | A produced N and its local collection records it |
| E3 | After delivery to B, B's collection records N |
| E4 | After delivery to C, C's collection records N |
| E5 | At handoff, A, B and C all currently record N |

The Python validator checks the submitted records: the signer must remain A,
the epoch and view must remain 0 and 1, and the required stage order must hold.
It also checks the final witness's handoff timing.

For example, these observations would not satisfy the goal:

- B has B's own nullify vote, rather than A's.
- C has A's vote for view 2, rather than view 1.
- N was sent to C, but C has not accepted it.
- A had N earlier, but no longer records it at handoff.

### Step 8: repeat with the delivery to C withheld

The control run repeats the same setup, A's vote production and the delivery
to B. It withholds E4's delivery to C, including any retry copies of that vote
that would reach C before handoff. The final check still executes.

The intended control result is:

| Node | Has A's view-1 nullify vote? |
|---|---|
| A | yes |
| B | yes |
| C | no |

E5 therefore misses. C might produce its own nullify vote during the control;
that does not satisfy the check for A's vote. If another path or retry delivers
A's vote to C anyway, the control has failed to distinguish the executions and
must be reconsidered.

A complete control showing this miss, together with accepted witnesses for all
five canonical stages and completed correctness checks, supports `REACHED 5/5`.
A control that crashes or stops before its final check is not this result.

### Step 9: fuzz from this setup

After the reach check, the generated target can be fuzzed repeatedly. Each input
starts fresh, repeats this prefix with allowed variations, and continues running
the protocol. It does not reuse the memory of the previous input.

For this card, the leader, epoch and view stay fixed. Possible knobs include the
delivery order of B and C, pauses between deliveries, and continuation scheduling.
If both recipient orders are allowed, the card must explicitly free that pair's
order rather than require the canonical B-then-C order for every input.

The existing invariants and harness checks look for bugs during these executions.
The reach witnesses separately show whether an input actually reached the
all-three-have-N condition.

If your three nodes are three followers in addition to a separate leader L,
the same walkthrough applies with deliveries from L to A, B and C. The target
then checks those three receivers; it does not need a self-delivery case.

## How the three-node example maps to code

The target-specific actions and state predicate are Rust code written by the
synthesizer agent. The Python script does not inspect the nodes or translate the
card into an executable predicate by itself. The helper provides recording and
handoff operations; the generated module decides what to do and what to observe.

There is no generated scaffold for this exact three-node example in the inspected
checkout. The code paths below are the existing machinery that would generate,
build and evaluate one. Names containing `NNNN` are placeholders, not existing
files or an allocated card ID.

### 1. Python gives the agent a concrete coding task

In [statelens.py](scripts/statelens.py), `Synthesis.prompt` reads the selected
card and renders [prompts/synthesize.md](prompts/synthesize.md). The rendered
prompt includes the full card, number of stages, selected base target, base input
type and entry call, installed probe labels, edit restrictions and prior feedback.

`Synthesis.run_agent` sends that prompt to the configured agent process. The agent
must write the scenario-specific Rust module and a thin fuzz target. For this
example on `simplex_cert_mock`, their proposed names would be:

```text
consensus/fuzz/simplex/src/target_states/tsNNNN_simplex_cert_mock.rs
consensus/fuzz/simplex/fuzz_targets/simplex_cert_mock_tsNNNN_statelens.rs
```

For an online prefix, the generated module must contain the actual calls that
start the base harness, arrange A as leader, delay the proposal, control delivery
to B and C, wait for observations, and continue into the base's correctness checks.
Those operations are not predefined by the names E1 through E5.

### 2. The script installs the generic helper and executable entry

`Synthesis.write_mod` copies [runtime/target_states.rs](runtime/target_states.rs)
into the fuzz package's `src/target_states/mod.rs`, then declares the generated
module. The script also manages the package declaration and scaffold binary entry.

The thin target wraps the generated module's `fuzz` call between the runtime's
`reset` and `clear_compromised` calls. Its input type remains the base's input type.
The generated module opens `Stages` and checks its knob/time budget before starting
engines. It then runs the scenario-specific prefix on the deterministic harness.

### 3. Generated Rust performs actions and records observations

The helper APIs used here are real:

- `Stages::new` opens the card's stages and starts observation.
- `Witness::act` or `Witness::act_async` performs and positions a harness action.
- `stamp` positions an observable entry when a recording wrapper records it.
- `Witness::exact` packages the values read from observables into evidence.
- `Stages::held`, `missed` and `unverifiable` record intermediate outcomes.
- `Stages::handoff` reads the final witness and marks the boundary.
- `Stages::done` marks completion after the required correctness checks.

For example, a generated network schedule releases N to B. A separate observation
must establish that B records the vote. A construction witness for the release
cannot replace that observation.

The existing differential-test [Recorder](differential/src/record.rs) illustrates
the recording pattern: `Recorder::record` calls the helper's `stamp`, then stores
the observable name, key, value and returned `Stamp`. `Entry::read` supplies the
tuple that `Witness::exact` accepts. This recorder is part of the handwritten
differential fixtures; it is not a universal current-vote observer for Simplex.

### 4. The final predicate is written inside the scaffold

The following is pseudocode for the missing scenario-specific observation layer.
The names `read_current_vote` and `observation` are illustrative APIs that would
need to be implemented. They are not callable functions in the current tree.

```text
stages.handoff(function:
    a = read_current_vote(observer=A, signer=A, epoch=0, view=1)
    b = read_current_vote(observer=B, signer=A, epoch=0, view=1)
    c = read_current_vote(observer=C, signer=A, epoch=0, view=1)

    if a is absent OR b is absent OR c is absent:
        return no witness

    return Witness::exact(
        bindings for A, B, C, epoch and view,
        observations of a, b and c with their actual evidence
    )
)
```

The generated code performs the three reads and the AND condition. The helper
does not know what a nullify vote means. In `Stages::handoff`, `None` becomes a
missed final condition; a supplied witness is recorded and its timing checked.

For the literal current-possession target, the hard part is implementing these
reads correctly. The batcher's round owns its vote collection inside an actor.
Its `Round::has_nullify` can test membership, but simply widening that method's
visibility does not give the scaffold access to the running actor's state.
An async mailbox query also cannot be awaited inside the synchronous handoff
closure. The chosen harness therefore needs a suitable read-side design; if
none can be supplied within the edit contract, the scaffold must say so.

The mock reporter already exposes a `nullifies` map keyed by view, containing
signer public keys. That supports an "observed a valid vote" condition. It does
not track later removal from the live actor's collection, so it cannot silently
stand in for the stronger current-possession predicate.

### 5. The helper produces records, not a semantic proof

When `Stages::held` or the handoff records a witness, the helper emits a structured
`[statelens-reach]` line. `stamp` emits matching entry lines. `settle` records the
stage's outcome; for a held stage, it also adds the stage feature through the
StateLens runtime's `record` API.

The evidence includes entity bindings, observable values, positions and the
witness read position. These make mechanical consistency checks possible. They
do not establish that a supplied string such as `present` came from the correct
protocol state. The observation code and its connection to that state need review.

### 6. Python runs the binary and checks those records

`Synthesis.attempt` checks and builds the candidate, then calls `Synthesis.replay`
for the canonical input and the control. `Synthesis.replay` executes the built
binary on the empty file, captures its output and exit status, and selects one
input execution's report through `first_run`.

`reach_verdict` calls `reach_replay` to parse and check the stage records.
`witness_rule` checks the witness's bindings and evidence; `reach_replay` checks
required positions, order, restart relationships and handoff timing.
`control_status` checks the withheld event and whether the control distinguishes
the final state. Failures and incomplete reporting produce their own outcomes.

For this example, generated Rust must branch on `control()` to withhold the
delivery to C. Python sets the environment switch and checks the resulting
records. It does not itself select and drop a particular network packet.

Finally, `Synthesis.finish` selects the version to keep, rebuilds it, performs
the final replay and writes the report. The agent can receive feedback for
further attempts when an earlier candidate did not establish the target.

The existing [TS-9005 prefix](differential/src/cards/ts9005.rs) shows this pattern
on a different state: it performs real harness operations, tests the receiver
with `try_recv`, constructs exact witnesses, and supplies its final condition
to `Stages::handoff`. Your nullify example would need its own corresponding
action and observation code.

## General explanation of the reach check

There are three participants:

- The scaffold performs the setup and protocol actions.
- The Rust helper records stage outcomes, evidence and event positions.
- The Python validator checks the records and assigns a verdict.

The validator checks the consistency of supplied evidence. Code review must also
establish that the evidence measures the protocol facts claimed by the card.

## 1. Check and build the scaffold

The synthesis script checks the generated edits against the campaign's immutable
baseline. The restrictions protect installed instrumentation and existing
correctness checks, and constrain where the synthesizer may edit code.

Then it compiles the dedicated fuzz target. Compilation establishes that the
scaffold can execute, not that its actions match the card. The agent writes and
builds a candidate; the script executes the reach checks and returns feedback.

## 2. Execute the canonical input

Normal synthesis runs the fuzz binary on an empty input file with
`STATELENS_REACH=1`. The scaffold decodes this into its canonical case: its knobs
take source values intended to reproduce the history behind the card.

This invocation replays one specified file. It does not mutate inputs, search a
corpus or establish anything about all possible inputs.

The scaffold performs the history's events and observes their results. Online
stages use deadlines in simulated time, so an expected response that never
arrives becomes a miss. The script also imposes a separate wall-clock timeout
on the replay process.

## 3. Collect evidence for each stage

Each card has a History, E1 through En. The earlier events have a `Check`; En has
a `Holds` condition defining the target state. The scaffold must supply a witness
for the whole condition of each stage it reports as held.

| Witness | What it can establish | Important restriction |
|---|---|---|
| `construction` | An action performed by the harness | It cannot establish En or a replica's resulting state |
| `exact` | A fact read from an observable, recorder or side-effect-free query | The observation must measure the claimed fact without creating it |
| `intrinsic` | A relationship observed by one installed probe | It cannot identify a view or block that the observation does not identify |

For example, calling a delivery operation establishes a harness action. It does
not establish that the replica processed the delivery. Likewise, initiating a
request does not establish that the request remains outstanding later.

The helper records `held`, `missed` or `unverifiable`. In a control run, it can
also record `withheld`. A helper's `held` is provisional: the validator can reject
its witness.

## 4. Validate identities, ordering and usable evidence

The validator parses the recorded stages and checks them against the card.

- Names must refer to the right concrete entities. If a later stage refers to
  the replica and block from E1, its witness must bind those same values.
- Evidence must support its bindings. A record keyed by another block cannot
  establish a condition about the selected block.
- Required event order needs positions. Reading two records after execution
  proves their presence, not which event happened first.
- A stamped observable must have a matching entry record. Harness actions and
  observations receive positions from the helper's shared event sequence.
- Recorded restarts and incarnation references must be consistent with the
  relations the stages claim.
- A truncated observation trace cannot justify affected later stages from
  incomplete history.

Missing bindings, rejected evidence or absent required positions make stages
unverifiable. Wrong card IDs, wrong stage counts and incomplete required reporting
can make the report unusable.

These checks do not interpret arbitrary Rust code or prove that a recorder is
installed on the actual execution path. That remains a review responsibility.

## 5. Check the target state at handoff

For an explicitly driven prefix, handoff is the boundary between the scripted
history and the continuation. En must hold at that boundary. A temporary state
that held earlier but disappeared before handoff is insufficient.

The scaffold supplies a synchronous witness-reading closure to
`Stages::handoff`. The helper calls it, takes a handoff mark immediately afterward,
and records En and the handoff outcome. The validator requires:

```text
handoff mark = final witness read position + 1
```

This rejects a witness built earlier and saved while the system continued to run.
The closure cannot await. A pending-state condition needs an observation that
the work is still pending, not merely that it was requested.

There is a semantic limit: a closure could construct a new witness using values
cached before handoff. The position checks date witness construction; review must
establish that its underlying observation is current.

The description above is Shape B. Shape A instead pins the existing driver's
input and evaluates the recorded history after that driver runs. Its target-state
evidence also needs a position and a later honest observation in the same run to
establish continuation. It does not introduce a new online handoff into the driver.

## 6. Run a control with one event withheld

The script replays the same canonical input with
`STATELENS_REACH_CONTROL=1`. The scaffold omits the harness event named by its
`Control: withholds Ek` header. Ek must precede En.

Earlier stages must still correspond to the canonical setup. Later events and
checks must be attempted, and the final condition and completion must be reported.
A miss does not close the scripted history in control mode.

| Control outcome | Interpretation |
|---|---|
| Target state absent after a complete, acceptable control | The withheld event distinguishes these executions |
| Target state still holds for the same bound entities | The control is weak |
| Run stops early, omits another event or lacks required reporting | The control is vacuous |

A weak, vacuous or missing control prevents an ordinary `REACHED` verdict. A
narrow `Control: n/a` exception exists for cards with no harness event before En
and only the accepted witness kinds.

This is evidence of dependence in the tested executions. It does not establish
that every alternative history is unable to reach the state.

## 7. Assign the verdict and replay the kept version

| Verdict | Meaning |
|---|---|
| `REACHED n/n` | All stages have accepted witnesses, handoff holds, reporting completes and the control is acceptable |
| `UNVERIFIED k/n` | Evidence or control is insufficient, without an explicit stage miss |
| `PARTIAL k/n` | A stage after E1 missed, including loss of En at handoff |
| `UNREACHED 0/n` | E1 missed |
| `NO REPORT` | Required reporting is absent or unusable |
| `CRASH (finding candidate)` | Execution failed and requires triage |
| `SCAFFOLD ERROR` | A helper preflight check rejected the scaffold |

The scaffold must emit `done` after its existing correctness checks. Missing
completion prevents a successful reach verdict. Review must establish that the
checks really precede that marker.

Synthesis rebuilds the kept version and repeats the canonical replay. Differences
in the stage records add a `nondeterministic` annotation; this does not automatically
replace the main verdict. Reports preserve stage details, reasons, diffs and replay
commands under `statelens/campaign/reach/`.

## 8. Feed unsuccessful results back into synthesis

The first attempt can be followed by up to three further attempts. Feedback
distinguishes setup misses, later event misses, lost handoffs, rejected witnesses
and inadequate controls.

A crash stops automatic refinement for the pair and is preserved as a finding
candidate. Human triage decides whether it is a protocol defect or a scaffold
defect. Built scaffolds can be fuzzed even with weaker reach verdicts; `REACHED`
is not the sole admission criterion for fuzzing.

## Worked example: TS-9005

This example follows the existing [TS-9005 card](differential/cards/TS-9005.md)
and its [handwritten prefix](differential/src/cards/ts9005.rs). It uses the actual
helper and validator, but it is a differential-test fixture, not evidence of an
agent generating a scaffold. The fixture has no knobs and uses 64 zero bytes for
its canonical deterministic setup. Normal synthesis uses the empty file described
above.

The outcomes below are expected behavior derived from the code. No protocol test
was executed to produce this explanation, and the tables are not captured logs.

The goal is to exercise this relationship: verification of a missing candidate
waits locally without fetching; a subsequent certification request triggers one
round-bound fetch, whose delivery allows both operations to complete.

### A. Establish the concrete entities

The prefix starts from genesis and constructs a height-1 candidate at view 1,
led by Node B. No node initially holds that candidate.

For the history, B is bound to node index 1, v to view 1, and d to the candidate's
actual digest. The same bindings must carry through all five stages.

### B. E1: request verification

The harness calls B's verification operation for d at v and receives a reply
receiver. `Witness::act_async` positions that harness action.

E1 is held with a construction witness. This establishes that verification was
requested. It does not establish that verification completed or stayed pending.

### C. E2: observe the local wait and pending verification

The prefix waits, within a simulated-time deadline, until its recorder shows:

- A local block-wait registration for d on B.
- An empty fetch history on B.

It then polls the verification receiver with `try_recv`. Only an `Empty` result
supports the pending condition. A returned verdict or a closed channel makes E2
miss. The pending observation is stamped only after the empty receiver is observed.

E2 is held with an exact witness containing all three facts: local wait, no fetch
and verification still pending. This is the distinction between requesting an
operation and observing its state.

### D. E3: arm the resolver delivery

The harness prepares a notarization for d at v and configures B's resolver to
supply that notarization and block when the next fetch occurs.

E3 is held with a construction witness. Arming the delivery does not itself
establish that a fetch happened or that B received the block.

### E. E4: request certification

The harness calls B's certification operation for the same view and digest.
`Witness::act_async` positions this action. E4 is held with a construction witness.

### F. E5: observe the final condition at handoff

The prefix waits, with deadlines, for the verification and certification replies.
It records each received result, then invokes `Stages::handoff` with a closure
that reads the recorder and requires all of these facts:

- Verification returned true.
- Certification returned true.
- The resolver's fetch history contains exactly one fetch.
- That fetch is the round-bound notarized fetch for v and is still active in the
  resolver's bookkeeping.
- No targeted fetch was issued.

If any item is absent, the closure supplies no final witness and En misses.
Otherwise it builds an exact witness, and the helper takes the handoff mark.
The validator then checks bindings, evidence, required order and handoff timing.

The target condition's values are read from the recorder. Their meaning depends
on the recording wrappers forwarding real operations and accurately recording
their results. Block presence is checked separately after the mark by the
reference handoff checks and digest; it is not an additional synchronous E5 item.

The expected canonical stage results are:

| Stage | Outcome | Evidence |
|---|---|---|
| E1 | held | Construction: verification requested |
| E2 | held | Exact: local wait, no fetch, receiver empty |
| E3 | held | Construction: resolver delivery armed |
| E4 | held | Construction: certification requested |
| E5 | held | Exact: both replies true and the required fetch state |

After the test completes its required checks and reporting, this execution can
contribute to `REACHED 5/5`. The control must also be acceptable.

### G. Repeat with E3 withheld

The module's header names `Control: withholds E3`. The control therefore performs
the same setup, requests verification, observes E2, and skips only the arming of
the resolver delivery.

It still requests certification at E4 and attempts E5. Certification can initiate
a fetch, but this prefix has supplied no delivery to resolve it. Waiting for the
replies eventually reaches the simulated-time deadlines, and the final condition
cannot be witnessed.

| Stage | Expected control outcome |
|---|---|
| E1 | held, with the same entities |
| E2 | held, with the same entities |
| E3 | withheld |
| E4 | held: certification was still requested |
| E5 | missed: the final condition is not held |

The control must complete reporting. Its miss is expected; a crashed or incomplete
control is not a substitute for this observation. With an acceptable control and
the successful canonical execution, the pair's reach verdict is `REACHED 5/5`.

### H. What changing the prefix would reveal

If E3's arming is performed before E1, while the stage lines are still printed in
card order, the action positions expose the reversal. The validator can reject
the order even if the final state is otherwise the same.

If the pending condition at E2 were merely asserted without polling the receiver,
the validator could accept internally consistent records that do not establish
the actual fact. That illustrates why witness code needs review.

The differential suite adds a separate comparison: it executes the original
scenario driver and this handwritten prefix on identical setup and bytes, then
compares their observed states after settling. That comparison is additional
evidence; it is not part of the normal synthesis reach check and does not establish
state equality at the handoff instant.

## Implementation references

References use symbols and document sections, without unpinned source line numbers.

- [Synthesis and validator](scripts/statelens.py): `Synthesis.attempt`,
  `Synthesis.replay`, `Synthesis.finish`, `reach_replay`, `witness_rule`,
  `control_status` and `reach_verdict`.
- [Rust helper](runtime/target_states.rs): `Witness`, `Stages` and
  `Stages::handoff`.
- [Specification](docs/SPEC.md): sections 18.7, 18.8 and 18.11.
- [Example recorder](differential/src/record.rs) and
  [differential test driver](differential/src/tests.rs).
