## Task: beacon probes for the {{ACTOR}} component (`{{ACTOR_DIR}}`)

Add state probes that let the fuzzer tell apart executions that run the same code in
different internal states. Do not add assertions in this task.

This is a loop, not a checklist. At each step you choose one action, look at what it
returned, and choose again. Your actions are: read and search the code of this component;
query the knowledge base with one of the commands below; add a probe.

Reading the code leads, because that is where a candidate announces itself. Query the
knowledge base when your hypothesis needs developer context the source does not carry.
Source shows you that an assumption exists. It rarely tells you what the assumption means,
why it matters, whether it has failed before, or which code manages the transition. The
moment you find yourself asking one of those, query. For example, reading

    let task = self.gates.take(round, digest);

tells you that certification consumes a gate, but not why a gate might be absent, nor what
happens to certification when it is: that is a query, not a guess.

### The knowledge base

{{QUERY}}

The knowledge base holds findings reported against this workspace, each with a summary, the
state it concerns, and the files and symbols it cites. `kb cites {{ACTOR_DIR}}` is the
fastest way to see which of them are about the code in front of you, and what they name.
When nothing is listed above, there is no knowledge base configured: work from the code
alone.

A finding tells you which states have gone wrong before, so a state it describes is worth
probing even when the code looks unremarkable. It never tells you to add an assertion: a
finding is evidence, not a property, and this task adds probes only.

### Beacons in the code

1. Inventory the semantic beacons in the non-test code of `{{ACTOR_DIR}}` and the types
   it owns: enums that describe states, modes, reasons or outcomes; boolean and
   `Option` fields of per-view or per-round state; the conditions of `debug_assert!`,
   `assert!`, `expect("...")` and `unreachable!`; comments about orderings, races,
   recovery, or cases that "cannot happen".
2. For each beacon, find the transition sites (where the state is set or changed) and
   the decision sites (where it is read to choose what to do).
3. Choose probes in this order of priority:
   - transitions caused by side effects or asynchrony, such as those the subsystem rules
     list;
   - conditions set in one actor or component and used in another through mailbox
     messages;
   - state combinations that comments or assertions call out as fragile.
4. Probe shape: `sl_probe!(me, "{{ACTOR}}.<beacon>.<event>", a, b)`, with `(a, b)` the
   state before and after a transition, or the state and its context at a decision
   point. Use `disc` for enums, `flag` for booleans and options, `delta` and `bucket`
   for views and counts, and `pack` to put two small values on one side.
5. Budget: 20 to 60 probes for this component. Avoid per-message hot loops unless the state
   there is interesting.
6. Add one row per probe to the "Beacon probes" table of the plan.

### A worked example

Two documents in `consensus/fuzz/statelens/examples/` work this task through end to end:
`statelens_commonware_voter_example.md` on the Simplex voter, and
`statelens_commonware_marshal_example.md` on marshal's deferred verification path. Read the one
whose subsystem matches this component. The parts that match what you are doing:

- section 0, how the example's vocabulary maps onto this workflow;
- sections 3 to 8, reading a comment, noticing what the source cannot answer, and querying the
  knowledge base at exactly that point rather than up front;
- section 26 of the voter example, or 32 of the marshal one, turning a finding into a coverage
  dimension and choosing which cells of it are worth telling apart;
- section 27, or 33 of the marshal one, the probe shapes: how several booleans become one packed
  side of the pair, how to observe two rules that live at different call sites, and when to
  split a wide dimension into several probes that a round relates;
- section 28 of the voter example, why reading a short-circuited condition eagerly changes what
  the program does;
- section 35 of the marshal example, a trace of observe, hypothesise, act, which is the shape
  your own reasoning should take.

Two things in them are not your job. They derive invariants, which belongs to Phase 1: you add
probes only. And they name artifacts from the StateLens paper, a Beacon Summary and a State
Report, which do not exist here -- your output is the probes and the plan rows. Section 0 of
each gives the rest of the mapping.
