## Method: semantic flow discovery

This is the method to follow when a beacon or an invariant needs state traced across
functions. It is not a task on its own: the beacon step adds probes, and Phase 1 writes
invariants. What this method produces is the evidence either of those needs.

StateLens has no data-flow tool. That is measured, not an oversight: the code index records
that a line mentions an entity, not what it does to it; syntax trees give that, but carry no
types; and the tools that do real information flow either cannot follow a value across a call
at all, or answer a different question (does a marked source reach a marked sink) from one
chosen entry point. Nothing crosses an actor mailbox.

So you are the flow simulator. **You propose; the tools confirm or reject.** A flow you
reasoned your way to and did not check is a guess, and must be labelled one.

### Your tools

You run from the root of the repository, so bind the script once:

    SL=consensus/fuzz/statelens/scripts/statelens.py

    python3 $SL code refs <NAME>      # every occurrence, by symbol
    python3 $SL code callers <NAME>   # call sites, with the enclosing function
    python3 $SL code callees <NAME>   # what a definition calls
    python3 $SL code defs <NAME>      # definitions and their extents

    python3 $SL ast sites <NAME>      # write / init / read, per site
    python3 $SL ast notes [PATH]      # comments on races and recovery

    python3 $SL kb find|cites|grep|show

plus reading files and `rg`. All of `code` and `ast` hide test code unless given `--tests`,
because nearly three quarters of this crate is test code sharing files with the code it exercises.

The index knows identity, the tree knows shape, and they answer different halves of one
question. `code refs broadcast_notarize` gives six sites and will not confuse the field with
the method of that name; `ast sites broadcast_notarize` says which two of the six are writes.
Neither knows types and shape at once, so use both.

### Structural or semantic

Classify the question before choosing a tool.

Structural -- who calls this, where is this written, what does this read -- is what `code`
and `ast` answer. Do not ask the knowledge base first; it does not know this implementation,
it knows what has gone wrong in it.

Semantic -- why does nullification preserve this where finalization clears it, why must these
two rules agree, what property does this state implement -- is what `kb` is for. Reach for it
when you can say exactly what you know and exactly what you cannot explain. The source
establishes what the code does; a finding explains why it matters, and may be older than the
code.

### The loop

1. **Name the beacon.** Its exact text, the symbol enclosing it, the concepts it mentions,
   and one sentence of hypothesis. `ast notes` is the fastest way to find beacons, and it
   names the item each comment documents. Do not turn a beacon into an invariant here.

2. **Find the state in code.** List three to five candidate fields, predicates or helpers the
   beacon might mean, most likely first. Check each with `code defs` and `code refs`. Drop
   the ones with no support. A name is a hint, not a definition: read the body.

3. **Establish, mutate, invalidate, consume.** For the confirmed state, use `ast sites` for
   the writes and the reads, and `code callers` on each writer to learn who drives it. The
   write you would miss by reading one function is the one worth having: `broadcast_notarize`
   is written at `round.rs:697` when a vote is constructed and at `round.rs:746` when the
   journal is replayed. Both are reached from `Actor::run`, but by different paths, and a
   reading that found only the first would describe the latch as set once per view.

4. **Simulate, then check.** When no tool answers the next step, reason it out: given this
   write, which decisions plausibly depend on it; given this decision, which state plausibly
   determines it. Produce a ranked short list, three to five, then validate each with `code`
   or `ast`. Keep what survives. Report the rest as hypotheses or not at all.

5. **Cross the mailbox by name.** No tool connects a send to a receive, because they are in
   different spawned tasks. The message variant is in both, so: `code callers` on the mailbox
   method names the sending function, and the variant name finds the handler arm. The voter's
   `Mailbox::resolved` is called from `Actor::handle_resolver` at `resolver/actor.rs:595`, and
   the `Message::Verified` it sends is handled at `voter/actor.rs:790`. Note that `recovered`
   and `resolved` both send `Message::Verified`, differing only in a `from_resolver` flag --
   the handler cannot tell them apart from the variant, which is exactly the kind of state
   worth separating.

6. **Follow a request to where it lands.** A decision and the act it leads to are often in
   different functions, separated by an await on a reply. `Actor::try_propose`
   (`voter/actor.rs:369`) asks `State::try_propose` for a context, sends it to the automaton
   and keeps the receiver in `pending_propose`; the reply is awaited in the main `select!`,
   and `Actor::process_proposed` (`voter/actor.rs:683`) records the proposal and hands it to
   the broadcaster. In between, the replica handles everything else, including the results
   that decide whether the act is still legal. So find the far end before calling a state
   "decided here": `code callees` on the deciding function names the request method, `code
   refs` on the field holding the receiver names where it is awaited, and `code callers` on
   the recording method names the handler. Report the pair -- where it is decided, where it
   is committed -- and name what the replica can learn between them.

7. **Stop.** A thread is done when you can say what state matters, where it lives, where it
   is established, changed and read, why that matters, which locations support each claim,
   and what remains unproven. Abandon a thread earlier when the symbol only logs, when the
   relation is syntactic, when no behavior consumes the state, or when the evidence is
   already sufficient.

Expand three to five candidates at a step, not every neighbor. A symbol two calls away can
matter more than twenty direct callers.

### Evidence status

Label every relation you report:

    HYPOTHESIS               your reasoning, no tool run
    SOURCE_SUPPORTED         the source text or a comment says so
    STRUCTURALLY_VALIDATED   `code` or `ast` confirms the symbol, call, write or read
    RUNTIME_VALIDATED        a test reaches it, or a probe separated the states in a run

Never present a hypothesis as a property. The last status is reachable here, unlike in most
analysis: this subproject runs a fuzzer, so a state you cannot separate statically can be
separated by a probe and observed.

### What the findings become

Two different things, and the difference is not negotiable.

A **probe** is feedback. It cannot fail, so it needs only a state worth telling apart --
including a state that is legal but rare. Prefer a dimension whose outcomes run the same
code, because edge coverage already separates the ones that branch. Place it where the
implementation already computes the value: adding an evaluation that did not happen before
changes evaluation order, short-circuiting or side effects, and that is forbidden.

An **invariant** is an oracle. It can panic, so it is written down, reviewed by a person, and
only then bound to code. Propose one only after the relationship is understood, with its
text, the source evidence, the rationale, the evidence status, and its known exceptions. Do
not strengthen it past what the code claims: where the code documents an odd but tolerated
state, that exception belongs in the invariant.

When you are unsure which one a discovery deserves, it is a probe.

### Report

Give, in this order: the beacon and where it is; the state you found and its representation
in code; the steps you took, each as question, tool, result, interpretation, status; any
knowledge base query with why it was needed and what you rejected; the causal chain from
establishment through change and propagation to consumption and consequence; candidate probe
dimensions with the sites where the value is already computed; candidate invariants with
evidence and exceptions; and last, the questions you could not answer with the tools
available.

Do not invent a field, a function or a tool that does not exist. Keep separate what the
source proves, what the tools prove, what a finding explains, and what you are guessing.
