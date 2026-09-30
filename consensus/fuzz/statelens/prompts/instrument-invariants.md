## Task: bind invariants {{INVARIANT_IDS}} of the {{REGISTRY}} registry

Bind each invariant only in the code that the subsystem rules allow. For each invariant
below:

1. Read the Statement (EARS). Identify the trigger or state (`pre`) and the required
   response (`post`), or the single condition of a ubiquitous statement. Treat
   "Preconditions / assumptions" as part of `pre`. Treat "Observation hints" as leads,
   not as facts.
2. Find where the implementation establishes and uses the concepts. Trace with search,
   references and call hierarchy across the components the subsystem rules name,
   including the mailbox messages between them and the recovery path on restart.
   `python3 scripts/statelens.py code refs|callers|callees <NAME>` gives references and
   call hierarchy by symbol, which matters because names here collide: `proposal` is
   five different methods. `ast sites <NAME>` says which of those sites write the state
   and which only read it. Both hide test sites unless you pass `--tests`, and the
   `callers` of a mailbox method name the actor that sends the message.
   `prompts/discover-flow.md` is the method for the cases where this is not enough.
3. Choose assertion sites where a violation first becomes observable: just before the
   replica acts (signs, broadcasts, persists, accepts a certificate, enters a view) or
   just after it changes the relevant state. Cover every code path that performs the
   action.
4. Map the EARS pattern to a macro. Ubiquitous: `sl_assert!`. State-driven,
   event-driven, unwanted behavior and complex: `sl_implies!(pre, post)`. For
   properties about history ("after", "once", "never again"), record the history in
   ghost state (`with_ghost` for one replica, `with_global` for scope `protocol`, or a
   `// [statelens] ghost:` field when the history belongs to one object) and assert at
   the later action.
5. For a numeric invariant, also add a margin probe:
   `sl_probe!(me, "INV-NNNN/margin", crate::simplex::statelens::bucket(distance), 0u8)`,
   where `distance` is how far the state is from a violation.
6. Be faithful: the code must check exactly the Statement. Never check something
   stronger, because that creates false alarms. If you can check only part of it, bind
   that part and set Status to `partial` with the reason. If you cannot bind it, add
   nothing for it and set Status to `unbound` with the reason.
7. Add the invariant's section to the plan.

### Readings that look right and are too strong

Rule 6 is where bindings go wrong, and always in the same direction: a Statement is checked
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

Full worked analyses, one per subsystem, are in `consensus/fuzz/statelens/examples/`. They are
reference material: they *derive* invariants, which is Phase 1 work, while your job is to bind
the ones below, and their local labels (`INV-A1`, `M1` and so on) are not registry ids.

Invariants:

{{INVARIANTS}}
