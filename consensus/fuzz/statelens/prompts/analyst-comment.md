## How to read code comments

- The sources are files or directories under `consensus/src/simplex`, optionally with
  `:line` or `:start-end`. Read the doc comments, the inline comments, and the
  conditions of `assert!`, `debug_assert!`, `unreachable!`, `expect("...")` and
  `panic!` in non-test code. Ignore test modules and `mocks/`.
- Look for conditions the author relies on: "must", "never", "always", "only", "cannot
  happen because", "invariant", "at most", "before", "after". Each one is a candidate.
- Restate each candidate in protocol terms. Keep Rust identifiers out of the Statement
  and put the code location and identifiers in "Observation hints".
- source_ref is `path:line` of the comment or assertion.
- Skip comments that describe mechanics without stating a condition.
