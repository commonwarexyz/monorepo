# Differential test: TSS prefixes against the marshal scenario prefixes

A test-only crate. For the six source tests the marshal scenario prefixes replay
(`consensus/fuzz/marshal/src/scenarios/scenarios.rs`), each test here runs two
prefixes on an identical cluster setup and identical input bytes:

- side A: the existing scenario's `drive(kind, &mut harness)`, unmodified;
- side B: a hand-written Target-State Synthesis prefix built from the StateLens
  helper primitives (`Stages`, `Witness::exact`, `Witness::act`,
  `Witness::act_async`, `stamp`, `Stages::handoff`, `Stages::done`) and the same
  harness verbs, as `statelens/prompts/synthesize.md` and SPEC 18.7 prescribe
  for a scaffold: one stage per History event, a witness per stage from exact
  observables or constructions, `En` read freshly inside `Stages::handoff`, no
  fabrication beyond the scenario's own.

Both sides take a canonical state digest after `finish` (`src/digest.rs`: the
recorded resolver fetches, active and targeted fetches, the resolver's armed
delivery and unconsumed verdicts, buffer subscriptions and sends, held blocks by
digest, verified blocks by view, finalizations and info by height, the
application tip, deliveries and pending acknowledgements, every node's durable
storage partition by partition (the certificate and block caches, the finalized
archives, the application metadata) with one audit of the whole runtime's
storage, the handoff description, the ledger and the canonical chain, all
read-only and sorted). The test asserts the digests are equal and that the TSS
prefix reached its handoff; the script then runs the real reach-check validator
(`statelens.py reach-verdict`, over `card_history`, `module_header`, `first_run`
and `reach_verdict`) on side B's captured `[statelens-reach]` lines and requires
`REACHED n/n` with no rejected witness.

Negative controls (`neg_*` tests) run a deliberately wrong TSS prefix: an event
dropped (TS-9001), the view-1 notarization also reported to another node
(TS-9001), `En`'s witness built before the handoff call (TS-9002), a garbage
delivery left armed on the victim (TS-9002), two order-relevant events swapped
with the stages recorded in card order (TS-9005), and a finalization delivered
to another node (TS-9007). Each must yield unequal digests or a verdict other
than REACHED (annotated or not: an annotation is informational, never a
rejected witness), from a replay that ran to its digest line (exit 0) and a
verdict the validator computed (`REACHED`, `UNVERIFIED`, `PARTIAL` or
`UNREACHED` `k/n`); a crash, a missing digest line or an unparsed verdict (a
traceback, `CRASH`, `NO REPORT`) is an error of the run, marked `(ERROR)`, not
a caught control. The script runs the control replay for the negatives too, so
a verdict of REACHED is possible there and the check is live.

What this establishes: for a hand-written TSS prefix of each source test, the
same settled state after `finish` as the scenario prefix, and a REACHED verdict
from the real validator. What it does not: equality of the two states at the
handoff mark (the digest is taken after `finish` and after a settle), and
anything about a scaffold an agent writes, which AC-24 and AC-25 with a real
agent judge.

Nothing here instruments the system under test or starts an engine; this is
testing of the TSS method, not a campaign.

## Layout

```
Cargo.toml            package statelens-differential; an empty [workspace] table
cards/TS-9001.md ..   one target-state card per History (SPEC 18.3 grammar, citations
                      pinned to HEAD, generated Source excerpts: after editing a citation
                      run `just excerpts differential/cards/TS-NNNN.md`); outside the
                      card trees, so `lint` sees them only when named and then reports
                      their location (rule 1) and nothing else
shim/                 statelens-differential-shim: compiles the two committed templates
                      statelens/runtime/{target_states,statelens}.rs by #[path], byte-
                      identical, as `commonware_consensus::simplex::statelens` and
                      `target_states`, with `extern crate self as ...` and a local
                      `deterministic::STATELENS_FRESH_RUN`
src/setup.rs          verbatim copy of the SETUP block of scenarios::runner::run, with the
                      stamping wrappers inserted at start_with_buffer
src/record.rs         Recorder and the StampingResolver/StampingBuffer/StampingReporter
src/digest.rs         the state digest
src/cards/tsNNNN.rs   one module per card, opened by the //! header of SPEC 18.7
src/tests.rs          one #[test] per (card, variant, mode), and the negative controls;
                      the script's EXPECTED_TESTS names these 30 tests, so a test added
                      here is added there
```

The crate is built by nothing in the root workspace: the empty `[workspace]`
table in its manifest stops cargo's upward search, and the shim, a path
dependency under the crate's directory, is a member of that workspace
automatically. This is an explicit exception to PRD R-LAYOUT-2 (no `Cargo.toml`
under `statelens/`), confined to this test crate; its lockfile is generated in
the scratch worktree and not committed.

## How to run

```
statelens/scripts/differential.sh
```

The script never builds in the checkout it runs from. It makes a directory of
its own for the run, `$DIFFERENTIAL_SCRATCH/run.XXXXXX` (default
`$TMPDIR/statelens-differential`), so concurrent runs share nothing and the
cleanup removes only what the run created, adds a detached git worktree of
`HEAD` there, copies `statelens/` and `consensus/fuzz/marshal/` into it (so the
uncommitted visibility change of the fuzz package and this crate are present),
sets `CARGO_TARGET_DIR` inside the worktree, checks the fuzz package there
(`cargo +stable clippy -p commonware-consensus-fuzz-marshal --all-targets -- -D
warnings`, rustfmt of the touched files, `cargo +stable nextest run -p
commonware-consensus-fuzz-marshal`; `SKIP_FUZZ_CHECKS=1` skips them), checks
this crate with rustfmt, builds the tests, checks that `-- --list` names exactly
the 30 tests of `EXPECTED_TESTS` (a missing, extra or duplicate name is exit 2
before any replay), runs every test in its own process with `STATELENS_REACH=1`
and a second time with `STATELENS_REACH_CONTROL=1` (the control run the
validator requires), capturing stdout and stderr per run, runs the validator,
prints a `| test | digest equal | verdict |` table, and removes the worktree
with its target directory. Exit 0 when it passed; 1 when a row carries
`(FAILED)`, `(NOT CAUGHT)` or `(ERROR)`; 2 when it could not start (disk, the
test listing); a failing build or check exits with that command's code. Logs
stay in `$DIFFERENTIAL_SCRATCH/run.XXXXXX/logs/` (the path is printed at the
end; old `run.*` directories are the operator's to remove), with both digests
of every test (`<test>.{a,b}.digest`) for a diff. It needs about 25 GB of free
disk and the `nightly-2026-06-21` rustfmt.

## What the visibility change is

`consensus/fuzz/marshal/src` makes the scenario primitives this crate imports
`pub` instead of `pub(crate)`: the modules `environment`, `harness`, `input`,
`recording_resolver` and `scenarios`, the `Scenario` trait and `drive`,
`FuzzScenarioStandardHarness` and its verbs and `finish`, `ScenarioHandoff` and
its types, the recorders (with `RecordingResolver`'s two injection fields,
`auto_delivery` and `delivery_responses`, which the digest reads), the runner's
setup pieces under `marshal::end_to_end::{app, twins}`. Two `#[allow]`s
accompany it (`async_fn_in_trait` on the now-pub trait,
`clippy::new_without_default` on `ProgressHandle::new`); nothing under
`consensus/src` changes.

## Limitations

- Block presence and the trailing `get_block` queries are async mailbox reads,
  so they are not `En` items; `finish` and the digest check them right after
  the mark.
- No probe exists in this crate, so no `intrinsic` witness is used and the run
  counter is what the fresh-run hook makes it (1).
- The digest settles the cluster first (no pending application acknowledgement,
  processed positions stable), because the two sides never share a schedule:
  the deterministic executor's ready queue depends on the timers each side
  registers. So it compares settled states after `finish`, not the states at
  the handoff mark: a prefix that skips a barrier the scenario takes, so that an
  event is still in flight at its handoff, settles to the same state and is not
  told apart; the digest panics when the cluster does not settle in 64 rounds.
  A stage's claim about the handoff instant (a reply still pending, a count
  unchanged) is carried by its witness, observed at the stage (TS-9005 and
  TS-9006 read the verify receiver with `try_recv` at E2 and stamp
  `verify=pending` only then; TS-9006's E4 requires the count E2 observed), not
  by the digest.
- Both sides run the same system under test, so equal digests cannot show a
  regression of that system; only side A's reference assertions (`finish` and
  the scenario's own) can. The prefixes are hand-written: nothing here judges a
  scaffold an agent wrote.
- The marshal mailbox has no query for cached certificates, so the digest reads
  them from the runtime's durable storage (`Context::scan`, `logical_blob` and
  `storage_audit`, all without opening a blob) under the partition names
  `setup_validator` and the marshal actor use; a renamed partition drops out of
  the per-node listing silently, while the `storage_audit` line still covers it.
