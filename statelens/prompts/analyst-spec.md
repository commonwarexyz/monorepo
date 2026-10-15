## How to read a formal specification

- The sources are Quint, TLA+ or Lean files, optionally with `:line`. Read the named
  invariants and temporal properties, the assertions, and the guards and effects of
  the actions that model the system in Context.
- Translate each invariant, and each action guard that encodes a safety rule (for
  example "vote to finalize only if the view was not nullified"), into an EARS
  statement about the system Context names. Keep the exact meaning.
- Record modeling assumptions the implementation may not share (a fixed number of
  replicas, bounded views, a static leader, no crashes) under "Preconditions /
  assumptions".
- source_ref is `path:line@{{COMMIT}}` of the property or action, with the path from the
  repository root, or a URL that names a commit for a specification outside it.
