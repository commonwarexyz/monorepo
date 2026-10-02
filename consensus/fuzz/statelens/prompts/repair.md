## Task: repair the instrumentation (attempt {{ATTEMPT}} of 3)

The instrumented tree does not build. Fix the instrumentation only: code marked
`// [statelens]`, and `consensus/src/simplex/statelens.rs`. Do not change existing code.
Do not weaken an assertion to make it compile: if an assertion cannot be written
faithfully, remove it and set its invariant to `unbound` in the plan with the reason.
Never fix a type error at a macro's `me` with `.flatten()`, `.unwrap_or(None)` or
`.and_then(|me| me)`: each turns an unknown index into "not a participant", which turns the
Byzantine guard off. The error means a guard such as `if let Some(me) = ...` is missing.
Run the failing command and the check command until both pass.

Failing command:

    {{COMMAND}}

Last lines of its output:

{{ERRORS}}
