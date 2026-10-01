# StateLens for Simplex

StateLens turns invariants written in English into runtime assertions and state probes in
the Simplex implementation, so that fuzzing the instrumented code with libFuzzer panics
when an invariant breaks. It covers two subsystems, each with its own invariant registry
and campaign profile: Simplex consensus (`consensus/src/simplex`: the voter, batcher and
resolver actors) and marshal (`consensus/src/marshal`: the core, standard and coding
components). It works in three phases: an LLM agent (Claude Code or Codex) discovers
invariants in issues, design documents, code comments, formal specifications and papers
(Phase 1); a campaign lets the agent instrument the code and generates the StateLens fuzz
targets (Phase 2); and you run those targets (Phase 3). See [PRD.md](docs/PRD.md) for the
goals and [SPEC.md](docs/SPEC.md) for the details.

## Run campaigns safely

A campaign gives the agent full control of the machine and instruments the checkout in
place. Clone the repository fresh on a dedicated machine or container, run the campaign
and the fuzz targets in that clone, and discard the clone afterwards. Never commit an
instrumented checkout, and never reuse it for another campaign.

Phase 1 agents run restricted in your working tree: Claude may only read, edit and write
files, fetch web pages and run `gh` and `curl`; Codex runs in its workspace-write sandbox
with network access.

## Prerequisites

- `git`, `python3` (3.9 or later) and `just`.
- `cargo` with the `stable` toolchain and the nightly pinned in
  `.github/workflows/slow.yml`, `cargo-nextest` and `cargo-fuzz`.
- The `claude` or `codex` CLI, logged in.
- For issues: `gh` (logged in) or network access for `curl`. For PDF papers: `pdftotext`
  or the Python `pypdf` module; without either, the agent gets the PDF as is.

Defaults live in [config.env](config.env): the agent (`claude`), the model of each agent
CLI (empty means the CLI default), the test toolchain (`stable`) and the fuzz toolchain
(empty means the pinned nightly). An environment variable with the same name overrides a
value there, and `--agent` overrides `STATELENS_AGENT`. `CARGO_TARGET_DIR` is passed
through; by default builds use the checkout's `target/`.

Commands run in `consensus/fuzz/statelens/`, except the fuzz targets, which run in
`consensus/fuzz/`. Local source paths are relative to the repository root. Generated
outputs go to `campaign/` and `extract/`, which git ignores.

## Phase 1: discover invariants

```
just extract issue https://github.com/commonwarexyz/monorepo/issues/2070
just extract design docs/blogs/pipelining-simplex.md#how-optimism-stays-safe
just extract comment consensus/src/simplex/actors/voter/round.rs
just extract spec <spec>.qnt:34
just extract paper https://eprint.iacr.org/2023/463.pdf#page=7
just extract --registry marshal comment consensus/src/marshal/mod.rs
just extract --registry marshal issue commonwarexyz/monorepo#<N>
just extract --agent codex issue https://github.com/commonwarexyz/monorepo/issues/2070
```

| Kind | Source |
|---|---|
| `issue` | GitHub URL of an issue or pull request, or `owner/repo#N` |
| `design` | Local path or URL, optionally `#section` |
| `comment` | File or directory under `consensus/src/<registry>`, optionally `:line` or `:start-end` |
| `spec` | Quint, TLA+ or Lean file, optionally `:line` |
| `paper` | Local PDF or text file, or URL, optionally `#page=N` |

`--registry` is `simplex` (the default) or `marshal`. Several sources of one kind may be
passed at once. The agent writes new files to `invariants/<registry>/` in the format of
[templates/invariant.md](templates/invariant.md), numbered from the next free ID; IDs are
unique across registries. The script lints the new files, and reports an existing
invariant that the agent changed and a new file outside `invariants/<registry>/`. Because
Phase 1 runs in your own working tree, it also compares the whole worktree before and after
the run and reports anything the agent changed elsewhere; any of these makes it exit 3. Logs,
rendered prompts and paper text go to `extract/`.

**Every file in a registry is used by the next campaign that binds it** (the `simplex`
profile binds the simplex registry, the `marshal` profile both), so review the new files
first: edit them, delete the ones you do not want, and run `just check-invariants`.

## The knowledge base

A campaign's beacon step can consult a knowledge base of developer artifacts while it
instruments: the findings reported against this workspace, plus the curated documents beside
them. Point `STATELENS_KB` at one or more corpus roots, separated by `:`.

```
export STATELENS_KB=/path/to/commonware-findings
```

The instrumenter reads a component's code, and when a candidate state needs context the
source does not carry -- what an assumption means, whether it has failed before, which code
manages a transition -- it queries. You can run the same queries by hand:

```
python3 scripts/statelens.py kb modules --registry marshal
python3 scripts/statelens.py kb find --registry marshal certification
python3 scripts/statelens.py kb cites --registry marshal consensus/src/marshal/core
python3 scripts/statelens.py kb grep --registry marshal "availability waiters"
python3 scripts/statelens.py kb show <identifier> "Root Cause"
```

`kb cites` is the one to start from: it turns a path in this repository into the findings
about that code, with the files and symbols each one names. Queries see only the findings
whose `module` belongs to the subsystem being instrumented, and only the state-bearing
sections of each; the impact, exploitation, reachability and fix sections are not reachable
through the interface.

A finding is evidence, never a property: it can aim a probe, and never becomes an assertion.
Without `STATELENS_KB` a campaign still runs, with beacons mined from the code alone.

The knowledge base is private. Its index and the campaign logs quote what was retrieved, and
both live in the git-ignored `extract/` and `campaign/` directories; nothing derived from a
finding is committed to this repository.

## Phase 2: instrument the code and generate fuzz targets

```
git clone <repository> && cd <repository>/consensus/fuzz/statelens
export STATELENS_KB=<the findings repository>   # optional; see The knowledge base
just campaign                          # simplex profile, agent from config.env
just campaign --profile marshal        # marshal profile
just campaign --agent codex            # another agent (or STATELENS_AGENT=codex just campaign)
just campaign --stop-after build       # stop after materialize, instrument or build
```

**`just campaign` starts an agent with full access to this machine.** Run it in a fresh
clone on a dedicated machine or container, and throw the clone away afterwards.

Two conveniences: `just fuzz <target>` runs a campaign and then fuzzes one of its targets,
inferring the profile from the target name; and `just clean` undoes what a campaign wrote,
so a checkout can be reused. Note that in `consensus/fuzz/` and at the repository root,
`just fuzz` is a different, pre-existing recipe that runs a package's fuzz targets.

A campaign adds the runtime module, the fuzz targets and the harness and runtime hooks to
the tree, lets the agent bind every invariant of the profile's registries, audits those
bindings and adds beacon probes, checks that only the profile's subsystems were edited,
builds (with up to 3 agent repair attempts), and runs the test gate. The audit pass re-reads
each invariant against the sites that commit the actions it names, adds the checks that are
missing, and corrects a plan section whose `Status` claims more coverage than it has;
`STATELENS_AUDIT=0` skips it. It then ends with the result `READY` and prints
the command that runs each target. **The campaign builds the fuzz targets and runs no
fuzzer**, and passes no arguments to libFuzzer: that is Phase 3. `--stop-after` is for
development and ends the campaign with `STOPPED after <step>`.

| | `simplex` (default) | `marshal` |
|---|---|---|
| Registries | `simplex` | `simplex`, then `marshal` |
| Beacon probes | voter, batcher, resolver | the same, and marshal core, standard, coding |
| Fuzz targets | `<target>_statelens` for `simplex_cert_mock`, `simplex_cert_mock_twins_campaign` and `simplex_cert_mock_twins_mutator` | `<target>_statelens` for each of the 12 marshal targets |
| Test gate | `simplex::tests` without Twins, `simplex::statelens` | the same, and `marshal::` |

The simplex test gate is about 240 tests and 2 minutes on 16 cores; marshal adds 421
tests and about 70 seconds.

The campaign refuses to start when a required tool is missing, when tracked files outside
`consensus/fuzz/statelens/` have uncommitted changes, or when an earlier campaign already
instrumented the checkout. Uncommitted registry edits are used.

## Phase 3: run fuzz targets

In the instrumented checkout, run the `run` commands of a `READY` summary for the targets
you choose, adding libFuzzer arguments as needed, such as `-fork=<N>` to use N cores or
`-max_total_time=<s>` to bound the run. From this directory `just run <target>` does the
same, and `just fuzz <target>` runs the campaign first.

`just fuzz <profile>` runs every target the profile builds. It campaigns once, then runs
them one after another; `--parallel` runs them together and writes each one's output to
`campaign/logs/<target>.run.log`; `--tmux` runs them together in one tmux window each, so
their output stays live and separate. Nothing bounds a run unless you pass
`-max_total_time`, so a target runs until it stops. The sequential form warns about that,
because there the first target would be the only one to run. With several targets at once,
divide `-fork` between them rather than giving each the whole machine:

```
just fuzz simplex --tmux -- -fork=5
just fuzz simplex --parallel -- -max_total_time=600 -fork=5
STATELENS_JOBS=4 just fuzz marshal --parallel -- -max_total_time=600

just run simplex_cert_mock_twins_mutator_statelens -- -rss_limit_mb=4000 -print_final_stats=1 -fork=8

cd <repo>/consensus/fuzz
NIGHTLY_VERSION=<fuzz toolchain> just run simplex_cert_mock_twins_mutator_statelens -- \
  -rss_limit_mb=4000 -print_final_stats=1 -fork=8
NIGHTLY_VERSION=<fuzz toolchain> just run \
  marshal_e2e_standard_app_cert_mock_twins_statelens -- \
  -rss_limit_mb=4000 -print_final_stats=1 -fork=8
```

A run ends when the target panics or you stop it; libFuzzer, fork mode included, stops at
the first crash. A variant runs at about 13 inputs per second per process, so
use `-fork` on a many-core machine. For marshal only the stock standard Twins target was
measured, at about 15 inputs per second and 0.6 GB per process; size the other runs
yourself.

Do not pass `-artifact_prefix` or `-exact_artifact_path`, which move the crash file
elsewhere, or any `-handle_*` switch, which can stop libFuzzer from reporting a crash and
saving its input. Crashes land in `consensus/fuzz/simplex/artifacts/simplex_cert_mock_twins_mutator_statelens/`,
or in `consensus/fuzz/marshal/artifacts/<variant>/` for a marshal variant.

A `marshal` campaign builds 12 variants, one per target in
`consensus/fuzz/marshal/fuzz_targets/`, each named `<target>_statelens`. Only five have an
adversary that runs Simplex or marshal code, and only they exercise the Byzantine guard:

- the four Twins variants: `marshal_e2e_standard_app_cert_mock_twins_statelens`,
  `marshal_e2e_coding_app_cert_mock_twins_statelens`,
  `marshal_e2e_standard_deferred_cert_mock_twins_split_header_statelens` and
  `marshal_e2e_standard_inline_cert_mock_twins_split_header_statelens`;
- the wedge-scenario variant:
  `marshal_e2e_standard_deferred_cert_mock_scenarios_statelens`.

In the other seven (Disrupter, poisoned backfill, block dissemination, scenario prefix
and store), no adversary runs Simplex or marshal code, so every engine is checked.

## Coverage

When a run is over, `just coverage` says what its corpus actually reaches. It takes a
profile, single targets, or neither (every target of the default profile), and a name
beginning `simplex_` or `marshal_` picks its own profile, as `just fuzz` does:

```
just coverage simplex
just coverage marshal
just coverage simplex_cert_mock_twins_mutator_statelens
```

For each target that has a corpus it replays that corpus under coverage instrumentation
(`cargo fuzz coverage`), then writes, under the fuzz package's `coverage/html/`:

- `<target>/index.html`, one per target, and `unified/index.html` merged over all of them;
- `<target>.<subsystem>.txt`, the summary of the code the campaign instruments, which
  leaves out `mocks/` and `scheme/`;
- `<target>.workspace.txt`, the same without dependencies or the standard library.

A target with no corpus is skipped, so run this after the targets you care about, in the
same instrumented checkout that produced them. Replaying a corpus costs about as much as
the run did, so a profile with many targets takes a while; name a single target to keep it
short. `llvm-cov` comes from the fuzz toolchain, so that toolchain needs
`llvm-tools-preview` (`rustup component add llvm-tools-preview --toolchain <nightly>`).

## Results

The campaign ends with these lines, leaving out those that do not apply:

```
statelens: checkout   <repo>
statelens: base       <base commit>
statelens: agent      <agent>
statelens: profile    simplex | marshal
statelens: invariants <n> (bound <b>, partial <p>, unbound <u>)
statelens: audit      <ID> <before> -> <after>, ... | no status change
statelens: plan       <n> commit site(s) listed, <u> not checked, <p> lint problem(s)
statelens: sites      <k> assertion sites, <m> probe sites, <d> deleted lines
statelens: result     READY | STOPPED after <step> | PANIC (tests) | BUILD FAILED | SETUP FAILED
statelens: reason     <why the campaign stopped, for PANIC (tests), BUILD FAILED or SETUP FAILED>
statelens: panic      <first [statelens][...] line, or the first panic message>
statelens: run        cd <repo>/consensus/fuzz && NIGHTLY_VERSION=<fuzz toolchain> just run simplex_cert_mock_twins_mutator_statelens -- -rss_limit_mb=4000 -print_final_stats=1
statelens: replay     cd <repo>/consensus/fuzz && CONSENSUS_FUZZ_LOG=1 NIGHTLY_VERSION=<fuzz toolchain> just run simplex_cert_mock_twins_mutator_statelens simplex/artifacts/simplex_cert_mock_twins_mutator_statelens/<crash file>
```

The `run` and `replay` lines appear only with `READY`, one pair per target; the `marshal`
profile prints a pair for each variant. The `replay` line is a template: put in the crash
file that libFuzzer wrote, and set the `STATELENS_BYZANTINE` value of the run that found
it. A campaign that passed its preconditions also saves the lines
to `campaign/summary.txt`. A run refused by the preconditions prints them only, so the
summary of the campaign that instrumented the checkout is kept.

| Exit code | Result |
|---|---|
| 0 | `READY`: the targets are built and the test gate passed; or `STOPPED after <step>` |
| 1 | usage error |
| 2 | `SETUP FAILED`: missing tool, checkout not fresh or already instrumented, agent failure, moved anchor, a target without the `cert_mock` scheme, scope violation |
| 3 | `BUILD FAILED` after 3 repair attempts |
| 4 | `PANIC (tests)`: the test gate failed |

`campaign/` holds the instrumentation plan (`plan.md`), every change the campaign made
(`instrumentation.diff`), the agent and test logs (`logs/`), the rendered prompts
(`prompts/`), `meta.json` and `summary.txt`. A campaign that passes its preconditions
recreates it.

A plan section's `Status` is a claim about coverage: `bound` means every site that commits
an action the invariant names carries the check, `partial` means a weaker condition or a
site left out, and the `Sites` ledger says which is which, one entry per site. `just
check-plan` re-checks those claims against the section and against the code, including that
a site the ledger calls `checked` really carries an assertion naming the invariant; the
campaign runs it too and reports the problems as warnings. It cannot see a commit site the
ledger never names, so read the `Assertion sites by file` line of the plan summary as well:
an instrumented layer with no assertions at all is the shape that gap takes.

## Investigating a panic

1. Read the panic message: `[statelens][<ID>] replica=<index|none>` names the violated
   invariant. `[statelens][BYZANTINE]` appears only with `STATELENS_BYZANTINE=panic`, and
   `[statelens] participant index mismatch` comes from a runner hook. Any other panic
   comes from the existing harness oracles or the code itself.
2. For `PANIC (tests)`, the console shows the `FAIL` lines and every `[statelens][` line;
   the full output is in `campaign/logs/test.log`.
3. Find how the invariant was bound: its section in `campaign/plan.md`, its sites with
   `rg '\[statelens\] <ID>' consensus/src`, and every change in
   `campaign/instrumentation.diff` (or `git diff`). The agents' logs and prompts are in
   `campaign/logs/` and `campaign/prompts/`.
4. Replay a fuzz crash in the same checkout with the `replay` line; it reproduces the
   panic. Keep the `STATELENS_BYZANTINE` value of the run that found it: a guard-test
   crash exists only with `STATELENS_BYZANTINE=panic`, so replay it as
   `STATELENS_BYZANTINE=panic` followed by the `replay` line; without it, the input runs
   cleanly. For the Simplex target, `CONSENSUS_FUZZ_LOG=1` also prints the decoded input;
   the marshal harnesses do not read it.
5. Decide whether it is an implementation bug, a wrong invariant or a wrong binding. Fix
   wrong invariants in the registry in your development checkout, and discard the
   instrumented one: the next campaign starts from a fresh clone.

## Testing the workflow itself

| Variable | Use |
|---|---|
| `STATELENS_FALSE_INVARIANTS=1` | Set on `just campaign`. Also binds the deliberately false invariants in `false-invariants/<subsystem>/`: FALSE-0001 with the `simplex` profile, FALSE-0001 and FALSE-0002 with the `marshal` profile. A `simplex` campaign must end with `PANIC (tests)` and `[statelens][FALSE-0001]`, or, if it reports `READY`, a short run of its `run` command must panic with it. A `marshal` campaign must end with `PANIC (tests)`, and `campaign/logs/test.log` must contain both `[statelens][FALSE-0001]` and `[statelens][FALSE-0002]`. |
| `STATELENS_BYZANTINE=panic` | Set on a `run` command. Panics when a compromised replica reaches an instrumented site, which shows the Byzantine guard is needed and wired: `simplex_cert_mock_twins_campaign_statelens`, `simplex_cert_mock_twins_mutator_statelens`, the four marshal Twins variants and the wedge-scenario variant must panic with `[statelens][BYZANTINE]`, and no other variant may; `[statelens] participant index mismatch` must never appear. `skip` is the default, `check` checks compromised replicas too. |
| `STATELENS_CLAUDE_EFFORT`, `STATELENS_CODEX_EFFORT` | Set in `config.env` or the environment. The reasoning effort the agent CLI runs with: `low`, `medium`, `high`, `xhigh` or `max` for claude, codex's own `model_reasoning_effort` levels for codex. Empty means the CLI's default, which is what a campaign uses unless you pin it. `STATELENS_CLAUDE_MODEL` and `STATELENS_CODEX_MODEL` work the same way for the model. Both land in `campaign/meta.json`, so pin them when you want two campaigns to be comparable. |
| `STATELENS_AUDIT=0` | Set on `just campaign`. Skips the audit pass over the bindings, which costs one agent run per batch of 8 invariants. The campaign then prints no `audit` line, and a plan section keeps whatever `Status` the first pass gave it. |
| `STATELENS_FEEDBACK=0` | Set on a `run` command. Leaves the StateLens counters unregistered. Run a target for the same time on two empty corpora, with and without it: `ft:` on the `DONE` line should be higher with feedback. Compare `ft:`, not `cov:`, which libFuzzer stops printing once the counters are registered. |

Each false-invariant campaign in a fresh clone of its own:

```
STATELENS_FALSE_INVARIANTS=1 just campaign
STATELENS_FALSE_INVARIANTS=1 just campaign --profile marshal
```

In the checkout of a `READY` simplex campaign (for a `READY` marshal campaign, use a Twins
variant such as `marshal_e2e_standard_app_cert_mock_twins_statelens`):

```
cd <repo>/consensus/fuzz
STATELENS_BYZANTINE=panic NIGHTLY_VERSION=<fuzz toolchain> just run simplex_cert_mock_twins_mutator_statelens -- \
  -max_total_time=120
STATELENS_FEEDBACK=0 NIGHTLY_VERSION=<fuzz toolchain> just run simplex_cert_mock_twins_mutator_statelens \
  <empty dir> -- -max_total_time=600
```
