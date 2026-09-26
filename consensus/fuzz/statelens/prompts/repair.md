## Task: repair the instrumentation (attempt {{ATTEMPT}} of 3)

The instrumented tree does not build. Fix the instrumentation only: code marked
`// [statelens]`, and `consensus/src/simplex/statelens.rs`. Do not change existing code.
Do not weaken an assertion to make it compile: if an assertion cannot be written
faithfully, remove it and set its invariant to `unbound` in the plan with the reason.
Run the failing command and the check command until both pass.

Failing command:

    {{COMMAND}}

Last lines of its output:

{{ERRORS}}
