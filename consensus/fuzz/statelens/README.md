# StateLens for Simplex

StateLens turns English invariants about the Simplex consensus implementation into
runtime assertions and state probes, then fuzzes the instrumented code with the
`TwinsMutator` harness until an invariant breaks. An LLM agent (Claude Code or Codex)
writes the invariants from issues, documents, code comments, specifications and papers
(Phase 1), and binds them to the current code in a campaign (Phase 2). See
[PRD.md](PRD.md) for the goals and [SPEC.md](SPEC.md) for the details.

## Run campaigns safely

A campaign gives the agent full control of the machine and instruments the checkout in
place. Clone the repository fresh on a dedicated machine or container, run the campaign
in that clone, and discard the clone afterwards. Never commit an instrumented checkout.

## Prerequisites

- `git`, `python3` (3.9 or later), `just`, `cargo-nextest` and `cargo-fuzz`.
- The `stable` toolchain and the nightly pinned in `.github/workflows/slow.yml`.
- The `claude` or `codex` CLI, logged in.
- For issues: `gh` (logged in) or network access for `curl`. For PDF papers: `pdftotext`
  or the Python `pypdf` module.

Defaults live in [config.env](config.env): the agent (`claude`), the models, and the
toolchains. An environment variable with the same name overrides a value there.

All commands below run in `consensus/fuzz/statelens/`. Local source paths are relative
to the repository root.

## Phase 1: build invariants

```
just extract issue https://github.com/commonwarexyz/monorepo/issues/2070
just extract design docs/simplex-design.md#voting
just extract comment consensus/src/simplex/actors/voter/round.rs
just extract spec consensus/quint/replica.qnt:34
just extract paper papers/simplex.pdf#page=7
STATELENS_AGENT=codex just extract issue https://github.com/commonwarexyz/monorepo/issues/2070
```

The agent writes new files to `invariants/` in the format of
[templates/invariant.md](templates/invariant.md). **Every file in `invariants/` is used
by the next campaign**, so review the new files first: edit them, delete the ones you do
not want, and run `just check-invariants`. Logs and rendered prompts go to `extract/`.

## Phase 2: run a campaign

```
git clone <repository> && cd <repository>/consensus/fuzz/statelens
just campaign                                        # agent from config.env
STATELENS_AGENT=codex just campaign                  # another agent
python3 scripts/statelens.py campaign -- -fork=8     # extra libFuzzer arguments
python3 scripts/statelens.py campaign --stop-after build
```

A campaign copies the runtime module and the fuzz target into the tree, lets the agent
bind every invariant and add beacon probes, builds, runs the engine-level Simplex tests,
and then fuzzes `simplex_statelens` until a panic or Ctrl-C. The target runs at about 13
inputs per second per process, so use `-fork=<N>` on a many-core machine.

The campaign refuses to start when tracked files outside `consensus/fuzz/statelens/`
have uncommitted changes, or when an earlier campaign already instrumented the checkout.

## Results

The campaign ends with lines like these, also saved to `campaign/summary.txt`:

```
statelens: result     PANIC (fuzz)
statelens: panic      [statelens][INV-0001] replica=1 ...
statelens: artifact   consensus/fuzz/simplex/artifacts/simplex_statelens/crash-...
statelens: replay     cd <repo>/consensus/fuzz && CONSENSUS_FUZZ_LOG=1 just run ...
```

| Exit code | Result |
|---|---|
| 0 | `NO PANIC` (the fuzzer stopped), or a `--stop-after` step finished |
| 1 | usage or configuration error |
| 2 | `SETUP FAILED`: checkout not fresh, agent failure, moved anchor, scope violation |
| 3 | `BUILD FAILED` after 3 repair attempts |
| 4 | `PANIC (tests)`: the test gate failed |
| 5 | `PANIC (fuzz)`: the fuzzer found a crash |

`campaign/` holds the instrumentation plan (`plan.md`), every change the campaign made
(`instrumentation.diff`), the logs and the rendered prompts.

## Investigating a panic

1. Read the panic message: `[statelens][<ID>]` names the violated invariant; any other
   panic comes from the existing harness oracles or the code itself.
2. Find how the invariant was bound: its section in `campaign/plan.md`, and its sites
   with `rg '\[statelens\] <ID>' consensus/src`.
3. Replay the crash with the `replay` line; `CONSENSUS_FUZZ_LOG=1` prints the decoded
   input.
4. Decide whether it is an implementation bug, a wrong invariant or a wrong binding. Fix
   wrong invariants in `invariants/` in your development checkout.

## Testing the workflow itself

| Variable | Use |
|---|---|
| `STATELENS_FALSE_INVARIANTS=1` | Also binds the deliberately false invariants in `false-invariants/`; the campaign must panic with `[statelens][FALSE-0001]`. |
| `STATELENS_BYZANTINE=panic` | Panics when a compromised replica reaches an instrumented site, which shows the Byzantine guard is needed and wired (`skip` is the default, `check` checks compromised replicas too). |
| `STATELENS_FEEDBACK=0` | Leaves the StateLens counters unregistered, to compare libFuzzer's `ft:` with and without state feedback. |
