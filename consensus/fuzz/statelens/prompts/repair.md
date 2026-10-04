## Task: repair the instrumentation (attempt {{ATTEMPT}} of 3)

The instrumented tree does not build. Fix the instrumentation only: code marked
`// [statelens]`, and `consensus/src/simplex/statelens.rs`. Do not change existing code.
Do not weaken an assertion to make it compile: if an assertion cannot be written
faithfully, remove it, set its invariant to `unbound` in the plan with the reason, and mark
the sites it checked `not checked` in the `Sites` ledger. The plan lint runs again after
the repair, against the tree as you leave it.
Never fix a type error at a macro's `me` with `.flatten()`, `.unwrap_or(None)` or
`.and_then(|me| me)`: each turns an unknown index into "not a participant", which turns the
Byzantine guard off. The error means a guard is missing: `if let Some(me) = ...` around the
site, or `me.and_then(|me| ...)` where the site yields a value. Never make a missing `me`
available by looking a scheme provider up, directly or through a method that does: obtain it
as the subsystem rules say.
Run the failing command and the check command until both pass.

Failing command:

    {{COMMAND}}

Last lines of its output:

{{ERRORS}}
