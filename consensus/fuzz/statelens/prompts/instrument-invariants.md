## Task: bind invariants {{INVARIANT_IDS}}

For each invariant below:

1. Read the Statement (EARS). Identify the trigger or state (`pre`) and the required
   response (`post`), or the single condition of a ubiquitous statement. Treat
   "Preconditions / assumptions" as part of `pre`. Treat "Observation hints" as leads,
   not as facts.
2. Find where the implementation establishes and uses the concepts. Trace with search,
   references and call hierarchy across the voter, batcher and resolver, including the
   mailbox messages between them and the journal replay path on restart.
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

Invariants:

{{INVARIANTS}}
