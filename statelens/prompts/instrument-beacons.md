## Task: beacon probes for the {{ACTOR}} component (`{{ACTOR_DIR}}`)

Add state probes that let the fuzzer tell apart executions that run the same code in
different internal states. Do not add assertions in this task.

This is a loop, not a checklist. At each step you choose one action, look at what it
returned, and choose again. Your actions are: read and search the code of this component;
identify an entity with the code index; query the knowledge base with one of the commands
below; add a probe.

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
state it concerns, and the files and symbols it cites, and the design documents beside them.
`kb cites {{ACTOR_DIR}}` is the fastest way to see which findings are about the code in front
of you, and what they name. `kb search` takes a question in plain words and ranks by meaning
as well as by the words you chose, across the findings, the design documents, and the
comments, doc comments and Markdown of the whole repository. Ask it what the source raises
and does not answer -- why an assumption holds, what happens when it fails -- and read the
code a hit points at before you rely on it. When nothing is listed above, there is neither a
knowledge base nor a search index: work from the code alone.

A finding tells you which states have gone wrong before, so a state it describes is worth
probing even when the code looks unremarkable. It never tells you to add an assertion: a
finding is evidence, not a property, and this task adds probes only.

### The code index

You run from the root of the repository, so bind the script once:

    SL=statelens/scripts/statelens.py

    python3 $SL code defs|refs|callers|callees <NAME> [--tests]

Names collide: in consensus, `proposal` is five different methods, and `broadcast_notarize` is
both a field and a method of the same type. So when a name turns up in more places than you
expect, it is probably several entities, and `refs` separates them. Before you probe a field,
ask `refs` for every place that touches it, because the site you would miss by reading one
function is the one worth probing. To learn which actor sends a mailbox message, ask for the
`callers` of the mailbox method. Most of each crate is test code, and the index hides it unless
you pass `--tests`.

If the index is missing the campaign said so, and search and reading are the fallback.

### The syntax tree

    python3 $SL ast sites <NAME>    # written here, read there
    python3 $SL ast notes [PATH]    # comments about races and recovery

The index says a line mentions a field; it does not say whether the line changes it. Before
you probe a transition, ask `ast sites` for the write sites and the `maybe` sites. A write is
an assignment. A `maybe` is the field handed out, as the receiver of a method call or by a
`&mut` borrow, printed with what was done (`.push(..)`, `&mut`): the tree carries no types,
so it cannot tell `push` from `len`, and `push`, `insert`, `clear` and `take` are transitions
as much as an assignment is. Read each `maybe` site before you call the transition inventory
complete; the reads are the decisions. A site it marks `macro` sits inside a macro body,
which the tree does not structure, so read that one yourself; much of the consensus code's
concurrency is inside `select!`. `ast notes` is the fastest way to do step 1 below:
it finds the comments about orderings, races, recovery and cases that cannot happen, and
names the item each one documents.

When a candidate needs state followed across functions, actors or a restart, work through
`statelens/prompts/discover-flow.md`. There is no data-flow tool here, so you are the one simulating
the flow, and that method says how to propose a step and then make the tools confirm or
reject it.

### Beacons in the code

1. Inventory the semantic beacons in the non-test code of `{{ACTOR_DIR}}` and the types
   it owns: enums that describe states, modes, reasons or outcomes; boolean and
   `Option` fields of per-view, per-round or per-batch state; the conditions of `debug_assert!`,
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
   for views, locations and counts, and `pack` to put two small values on one side.
5. Budget: 20 to 60 probes for this component, and at most about 64 `(a, b)` pairs each.
   Count the pairs with the arithmetic of the discretization rules above before you write
   the probe: three bucketed counts on one side is already 216, and two unrestricted
   `delta`s are 121. Over budget, drop a dimension or coarsen one, rather than expecting
   the reachable combinations to be fewer. Avoid per-message hot loops unless the state
   there is interesting.
6. Add one row per probe to the "Beacon probes" table of the plan.

### What makes a probe worth adding

- A state is worth probing when its outcomes **run the same code**. If two outcomes take
  different branches, edge coverage already separates them and the probe adds nothing.
- Probe what the code decided and what it held, not what a peer or an input claimed.
- A finding tells you a state has gone wrong before, so it is worth probing even where the code
  looks unremarkable. It does not tell you to assert anything.
- Prefer a state established in one place and read in another, across a mailbox, a component
  boundary or a restart. Those are the states a single-function reading misses.

### Fitting a wide dimension into a pair

A dimension often has more parts than a pair holds. In order of preference:

1. Put the inputs on one side and the outcome on the other:
   `pack(flag(valid), flag(durable))` against `disc(&outcome)`.
2. Build a mask when several flags belong together:
   `flag(a) | flag(b) << 1 | flag(c) << 2`, against the outcome.
3. Keep related values at one site. A probe records only the presence of its own `(a, b)`
   pair: nothing joins sites, a shared label prefix means nothing to the fuzzer, and the
   view or round is not recorded, so two probes at two sites keep the marginal values and
   lose which value of one went with which of the other. To cover a relationship, emit the
   related, discretized values together at one site, carrying an earlier value there in
   bounded ghost state when it is read elsewhere (a field holding the last value; the round
   may key it, but never enters a probe). Never call something with side effects, and never
   force a value the original code computes only conditionally, to bring a value to a site:
   then probe the parts separately and say in the plan that the relationship is unobserved.

Full worked analyses of Simplex and marshal are in `statelens/examples/`. They are
reference material, not a pattern to copy: they also derive invariants, which is Phase 1 work,
and they use the vocabulary of the StateLens paper, which section 0 of each maps onto this
workflow. Do not let their shape decide what this component's states are -- the code does.
