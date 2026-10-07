## Task: bind invariants {{INVARIANT_IDS}} of the {{REGISTRY}} registry

Bind each invariant only in the code that the subsystem rules allow. For each invariant
below:

1. Read the Statement (EARS). Identify the trigger or state (`pre`) and the required
   response (`post`), or the single condition of a ubiquitous statement. Treat
   "Preconditions / assumptions" as part of `pre`. Treat "Observation hints" as leads,
   not as facts. "Source excerpts" show the code the invariant was written against, at the
   commit each names; the code may have moved or changed since, so find today's sites with
   the tools below rather than by those lines.
2. Find where the implementation establishes and uses the concepts. Trace with search,
   references and call hierarchy across the components the subsystem rules name,
   including the mailbox messages between them and the recovery path on restart.
   From the root of the repository, with
   `SL=statelens/scripts/statelens.py`, the command
   `python3 $SL code refs|callers|callees <NAME>` gives references and call hierarchy
   by symbol, which matters because names here collide: `proposal` is five different
   methods. `python3 $SL ast sites <NAME>` says which of those sites assign the state,
   which hand it out to a method or a `&mut` borrow (`maybe`, with the method name: the
   tree cannot tell `push` from `len`, so read those), and which only read it. Both hide
   test sites unless you pass `--tests`, and the
   `callers` of a mailbox method name the actor that sends the message. The guide
   `statelens/prompts/discover-flow.md` is the method for the cases
   where this is not enough.
3. Name the actions the Statement constrains, and find the commit site of each one: the
   point past which the action is visible outside the component that takes it, and the
   first point at which a violation is observable. A signature exists, a message is
   handed to a mailbox or to the broadcaster, a record is appended to the journal, a
   certificate is accepted, the view counter moves; a batch is applied, a commit becomes
   durable, a root, a value or a proof is returned. List every site that reaches it, on
   every path: the live one, the retry or rebroadcast, and replay or recovery after a
   restart.
4. Assert at the commit sites, not where the action was decided. The replica usually
   decides in one function and commits in another: it picks a parent and asks the
   application to build on it, and the proposal reaches the network in the handler of the
   reply, with every message the replica handled in between already applied. The state
   your `pre` reads at the decision is not the state the replica acted on, so a check
   there proves nothing about the action. Read the history inside the assertion, at the
   commit; the act's own parameters come from the decision, as they must, but the state
   you test against them is read here. Put the check after the last guard that can still
   abandon the act and before the call that performs it: a response the handler drops for
   a view the replica has left never reached the network, and asserting on it is a false
   alarm. Keep a second check at the decision
   site when it helps -- it names the cause, and its probe feeds the fuzzer -- but it
   never stands in for the commit site. That a later site "only records what the
   application returned" is not a reason to skip it: what the replica hands to the
   network is the action.
5. Map the EARS pattern to a macro. Ubiquitous: `sl_assert!`. State-driven,
   event-driven, unwanted behavior and complex: `sl_implies!(pre, post)`. For
   properties about history ("after", "once", "never again"), record the history in
   ghost state (`with_ghost` for one replica, `with_global` for scope `protocol` or for a
   subsystem without replicas, or a `// [statelens] ghost:` field when the history
   belongs to one object) and assert at the later action.
6. Add the probe the assertion cannot give. `sl_implies!` records `(pre, pre && post)`,
   which is what rewards the fuzzer for reaching a precondition -- unless that pair cannot
   vary on an execution that passes. It cannot when `post` is `false` (the only passing
   pair is `(false, false)`, since a true `pre` panics), and it cannot when the assertion
   sits on the branch the replica takes only once it is about to do the forbidden thing.
   Then the site teaches the fuzzer nothing: add a `sl_probe!` where the state is
   classified, recording the classification, so that reaching the protected state is
   rewarded even when the replica handles it correctly. A constant `true` `post` is not
   this case: the pair follows `pre` and already carries the feedback. For a numeric
   invariant, add a margin probe as well:
   `sl_probe!(me, "INV-NNNN/margin", {{RUNTIME_MODULE}}::bucket(distance), 0u8)`,
   where `distance` is how far the state is from a violation.
7. Be faithful: the code must check exactly the Statement. Never check something
   stronger, because that creates false alarms. If you can check only part of it, bind
   that part and set Status to `partial` with the reason. If you cannot bind it, add
   nothing for it and set Status to `unbound` with the reason. The status is a claim
   about coverage, and a campaign that never panics is read as evidence for whatever it
   claims. `bound` means every commit site of every action the Statement names carries
   the check, and the condition checked is the Statement itself. `partial` means
   anything less: a weaker condition, a site left out, a path left out. `unbound` means
   nothing was added. A binding that watches the decision and not the commit is
   `partial`, however exact its condition.
8. Add the invariant's section to the plan, with the `Sites` ledger: one line per commit
   site of step 3, naming the action in plain words, then the file and the function in
   backticks (everything backticked after the file is read as a function)
   (`` `actors/voter/actor.rs` `Actor::process_proposed` ``), then `checked` or
   `not checked` in those words, and for `not checked` the reason and the delivery order
   that escapes it. `lint-plan` reads this ledger: it finds the entry by the file, and a
   site you call `checked` has to carry an assertion naming this invariant in the function
   you name.

### Readings that look right and are too strong

Rule 7 is where bindings go wrong, and always in the same direction: a Statement is checked
more strictly than it is written, and the assertion fires on correct behavior. The patterns to
watch for:

- **A negative read as its converse.** "Nullification must not cancel certification work" does
  not say the work survives; something else may legitimately end it in the same moment. Assert
  that this event did not cause it, not that it is still there.
- **A permission read as an obligation.** "The replica may retry" does not mean it must. An
  invariant about what is allowed is not an invariant about what happens.
- **A local rule read as a global one.** Same-view often does not mean same-term, and same-term
  does not mean always. Bind the scope the Statement gives, not the widest one that parses.
- **A property read as a synchronous one.** Two components reach a state through mailboxes, so
  "after X, Y holds" is not checkable at X. Record the history in ghost state and assert at Y.
- **An accident of today's code read as the rule.** If the Statement is silent about ordering
  and the code happens to be ordered, do not assert the order.

When you find only a weaker form is checkable, that is a `partial`, not a licence to round up.

### Readings that look right and are too weak

The section above guards one direction: a check stronger than the Statement, which fires on
correct behavior and wastes a person's time. This is the other direction, and it is quieter.
The condition is faithful, but it is evaluated where the forbidden state cannot appear, so the
campaign stays silent and the silence is read as evidence. The patterns to watch for:

- **The decision mistaken for the action.** The check sits where the work starts -- a request
  issued, a candidate chosen, a handle stored -- rather than where it is performed. Everything
  the replica learns while the work is outstanding is invisible to it. This is rule 4.
- **One path of several.** The same vote is signed on the live path and restored by journal
  replay; a certificate arrives from the batcher and from the resolver; a message is sent once
  and rebroadcast on a timer. A check on one path is a check on one path.
- **A value captured too early.** A local read before an `await`, before the implementation's
  own update, or before a guard that can change the answer, is the old value. Read the state in
  the assertion itself, in the same statement sequence as the action.
- **A precondition the site cannot reach.** If a guard just above returns for exactly the state
  the Statement forbids, your `pre` is false there forever: the assertion runs on every pass,
  its probe records one pair, and nothing is ever checked. Find the site where the forbidden
  state survives, or record the gap and set `partial`.
- **Absence of evidence read as evidence.** A check that passes when the ghost record it
  needs is missing -- `is_none_or(..)`, `map_or(true, ..)` or `unwrap_or(true)` on the lookup
  -- accepts every case it never observed: a block the replica restored, a write nobody
  recorded and a different block at the same height all look alike. A missing record is
  unknown, not satisfied. Require positive evidence keyed by the exact identity (height and
  digest, view and signer), from what the replica holds or restored; where none can be had
  without changing behaviour, make the evidence part of `pre`, so the case is not evaluated
  rather than passed, say in the Notes which cases are unknown, and set `partial`.
- **Validity read from who sent it.** A vote, signature or certificate is valid because it
  verifies, not because an engine produced, signed or published it. The guard skips only the
  replicas a fuzz target marks compromised, and the tests the campaign gates on also run
  Byzantine participants it is never told about: the real engine with a scheme that corrupts
  what it signs, whose published votes every other replica rejects. A ghost record of what a
  signer published says that it was sent, not that it is valid. When `pre` needs a message to
  be valid, take that from a verification the observing replica completed, or from its own
  construction, keyed by the exact message. The subsystem rules name the tests that do this.
- **A binding the campaign never evaluates.** A `pre` that cannot hold in the fuzz targets
  leaves the check silent there however many unit tests exercise it. Read what the targets
  of this campaign do from their harness in `{{FUZZ_PACKAGE}}` rather than assuming it; the
  subsystem rules say what it is known to provide. When no target of the profile reaches
  `pre`, write `Status: partial (inactive in the fuzz targets)` (or `bound (inactive ...)`
  when the sites and condition are complete) and the reason in the Notes, so the campaign
  reports it apart from the bindings its silence speaks for; when some targets reach it and
  others do not, name them in the Notes.

A check you cannot imagine failing is either a theorem about the line above it or a check in
the wrong place. Say which, in the Notes.

Full worked analyses of Simplex and marshal are in `statelens/examples/`. They are reference
material: they *derive* invariants, which is Phase 1 work, while your job is to bind the ones
below, and their local labels (`INV-A1`, `M1` and so on) are not registry ids.

Invariants:

{{INVARIANTS}}
