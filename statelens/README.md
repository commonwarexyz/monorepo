# StateLens

StateLens turns invariants written in English into runtime assertions and state probes in
this repository's code, so that fuzzing the instrumented code with libFuzzer panics when an
invariant breaks. It covers three subsystems, each with its own invariant registry and
campaign profile: Simplex consensus (`consensus/src/simplex`: the voter, batcher and
resolver actors), marshal (`consensus/src/marshal`: the core, standard and coding
components) and qmdb (`storage/src/qmdb`: the log-based databases and their sync
engine). It works in three phases: an LLM agent (Claude Code or Codex) discovers
invariants in issues, design documents, code comments, formal specifications, papers and
knowledge-base findings (Phase 1); a campaign lets the agent instrument the code and
generates the StateLens fuzz targets (Phase 2); and you run those targets (Phase 3). For
simplex and marshal, Target-State Synthesis also writes, per reviewed target state and base
target, a fuzz target that drives that base into the state. See [PRD.md](docs/PRD.md) for the goals and
[SPEC.md](docs/SPEC.md) for the details.

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
- `rust-analyzer` (`rustup component add rust-analyzer`) for the code index a campaign
  builds before instrumenting. It takes several minutes and writes its output to
  `extract/code-index.log` rather than the console, because it logs `ERROR` lines it
  recovers from, such as `Encountered enclosing definition with no name` for modules a
  macro declares; they are expected, and the build carries on. Without rust-analyzer the
  campaign warns and continues without an index.
- For issues: `gh` (logged in) or network access for `curl`. For PDF papers: `pdftotext`
  or the Python `pypdf` module; without either, the agent gets the PDF as is.
- For `kb search`, the Python packages numpy and sentence-transformers. No GPU is needed;
  `just search-index` downloads the embedding model the first time.
- For the `qmdb` profile, an open-file limit well above 256, the macOS default. One test of
  its gate opens more files than that and fails with `Too many open files`, with or without
  instrumentation. Raise the limit in the shell that runs `just campaign`, `just fuzz` or
  `just test`, for example with `ulimit -n 65536`.

Defaults live in [config.env](config.env), which git tracks; a `config.local.env` beside it,
which git ignores, overrides them and is where a knowledge-base root or any other
machine-specific or private value goes. In `config.env` live the agent (`claude`), the model and the
reasoning effort of each agent CLI (empty means the CLI default), the test toolchain (`stable`) and the fuzz toolchain
(empty means the pinned nightly). An environment variable with the same name overrides a
value there, and `--agent` overrides `STATELENS_AGENT`. `CARGO_TARGET_DIR` is passed
through; by default builds use the checkout's `target/`.

Commands run in `statelens/`, the fuzz targets included: `just run` finds the package that
defines a target, under `consensus/fuzz/` or `storage/fuzz/`. Local source paths are
relative to the repository root. Generated outputs go to `campaign/` and `extract/`, which
git ignores.

## Phase 1: discover invariants

```
just extract-invariants issue https://github.com/commonwarexyz/monorepo/issues/2070
just extract-invariants design docs/blogs/pipelining-simplex.md#how-optimism-stays-safe
just extract-invariants comment consensus/src/simplex/actors/voter/round.rs
just extract-invariants spec <spec>.qnt:34
just extract-invariants paper https://eprint.iacr.org/2023/463.pdf#page=7
just extract-invariants --registry marshal comment consensus/src/marshal/mod.rs
just extract-invariants --registry marshal issue commonwarexyz/monorepo#<N>
just extract-invariants --registry qmdb comment storage/src/qmdb/mod.rs storage/src/qmdb/current/mod.rs
just extract-invariants --registry qmdb --number 10 comment storage/src/qmdb/mod.rs
just extract-invariants --registry qmdb --number 10 kb /path/to/commonware-findings
just extract-invariants --registry qmdb kb                # the corpus STATELENS_KB names
just extract-invariants --agent codex issue https://github.com/commonwarexyz/monorepo/issues/2070
```

| Kind | Source |
|---|---|
| `issue` | GitHub URL of an issue or pull request, or `owner/repo#N` |
| `design` | Local path or URL, optionally `#section` |
| `comment` | File or directory under the registry's source (`consensus/src/simplex`, `consensus/src/marshal` or `storage/src/qmdb`), optionally `:line` or `:start-end` |
| `spec` | Quint, TLA+ or Lean file, optionally `:line` |
| `paper` | Local PDF or text file, or URL, optionally `#page=N` |
| `kb` | Knowledge-base corpus roots, or none for `STATELENS_KB`; the findings whose `module` belongs to the registry are the sources |

`--registry` is `simplex` (the default), `marshal` or `qmdb`. Several sources of one kind
may be passed at once. `--number N` asks for the N invariants the sources justify best: the
agent may write fewer when they justify fewer, never more, and more is reported as a
problem. A `comment` source must be the registry's own code; anything else is refused. The
agent writes new files to `invariants/<registry>/` in the format of
[templates/invariant.md](templates/invariant.md), numbered from the next free ID; IDs are
unique across registries. The script lints the new files, and reports an existing invariant
that the agent changed and a new file outside `invariants/<registry>/`. Because Phase 1 runs
in your own working tree, it also compares the whole worktree before and after the run and
reports anything the agent changed elsewhere; any of these makes it exit 3. Logs, rendered
prompts and paper text go to `extract/`.

**Every file in a registry is used by the next campaign that binds it** (the `simplex`
profile binds the simplex registry, the `marshal` profile both consensus registries, and the
`qmdb` profile the qmdb registry), so review the new files first: edit them, delete the ones
you do not want, and run `just check-invariants`. The qmdb registry starts empty; a `qmdb`
campaign run before Phase 1 has filled it adds beacon probes only.

`kb` turns knowledge-base findings into invariants: the agent reads the findings in the
registry's scope through the same `kb` commands a campaign uses, and writes the invariants
each reported bug violated. A finding is private, so these invariants go to
`invariants.local/<registry>/`, which git ignores, rather than to `invariants/`. Campaigns in
this checkout bind them like any other; a fresh clone does not have them unless you copy
the directory. To share one, rewrite it without the finding's detail and move it into
`invariants/<registry>/` yourself. IDs count across both, so a local ID can clash with a
tracked one someone else adds later; `just check-invariants` reports the clash.

A line number means something only at one commit, so an invariant cites lines as
`path:line@commit`, with the path from the repository root; the agent pins them to the
commit you run it on, and hints name functions and types instead of lines. Each file ends
with a `## Source excerpts` section holding the cited lines as they read at that commit, so
you can review an invariant without fetching anything. The script writes it after the agent
finishes; when you change a citation by hand, run `just excerpts <file>` to rewrite it.
`just check-invariants` reports a citation without a commit, one that does not resolve, and
an excerpt section that no longer matches its citations.

## The knowledge base

A campaign's beacon step can consult a knowledge base of developer artifacts while it
instruments: the findings reported against this workspace, plus the curated documents beside
them. `just extract-invariants kb` also turns its findings into local invariants (Phase 1).
Point `STATELENS_KB` at one or more corpus roots, separated by `:`, in `config.local.env` or
in the environment, never in the tracked `config.env`.

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
python3 scripts/statelens.py kb search --registry marshal "why can the floor move while backfill is in flight"
```

`kb cites` is the one to start from: it turns a path in this repository into the findings
about that code, with the files and symbols each one names. Queries see only the findings
whose `module` belongs to the subsystem being instrumented, and only the state-bearing
sections of each; the impact, exploitation, reachability and fix sections are not reachable
through the interface.

`kb search` answers a question in plain words. It ranks snippets by meaning as well as by
the words you chose, from four sources: the findings in scope, the design documents in the
knowledge base's `kb/` and `context/`, and the comments, doc comments and Markdown of this
repository. A code hit names `path:line@commit` and the item the comment documents or sits
in; test code is left out unless you pass `--tests`, and `--path` narrows the code and
documentation to a directory. It answers from an index you build or update with

```
just search-index              # update: embeds only what changed since the last build
just search-index --rebuild    # embed everything again
just search "add_nullification"                    # ask it, as the agent does
just search --registry qmdb --path storage/src/qmdb "stale batch"
```

The index lives in the git-ignored `extract/search/`. It reads this repository at HEAD, so
a hit's line holds at that commit even in an instrumented checkout. It embeds on the CPU with
the model `STATELENS_SEARCH_MODEL` names, which it downloads the first time; a query never
uses the network. A first build takes about a minute, an update about ten seconds, and a
campaign updates the index before it instruments. Without a knowledge base the index holds
the repository alone, and without the model `kb search` ranks by words only.

A finding is evidence, never a property: it can aim a probe, and never becomes an assertion.
Without `STATELENS_KB` a campaign still runs, with beacons mined from the code alone.

The knowledge base is private. Its index and the campaign logs quote what was retrieved, and
both live in the git-ignored `extract/` and `campaign/` directories; nothing derived from a
finding is committed to this repository.

## Phase 2: instrument the code and generate fuzz targets

```
git clone <repository> && cd <repository>/statelens
export STATELENS_KB=<the findings repository>   # optional; see The knowledge base
just campaign                          # simplex profile, agent from config.env
just campaign --profile marshal        # marshal profile
just campaign --profile qmdb           # qmdb profile
just campaign --agent codex            # another agent (or STATELENS_AGENT=codex just campaign)
just campaign --stop-after build       # stop after materialize, instrument or build
just campaign --invariants INV-0001,INV-0002                              # bind only these
just campaign --profile marshal --invariants simplex/INV-0001,marshal/INV-0024
```

**`just campaign` starts an agent with full access to this machine.** Run it in a fresh
clone on a dedicated machine or container, and throw the clone away afterwards.

Two conveniences: `just fuzz <target>` runs a campaign and then fuzzes one of its targets,
inferring the profile from the target name; and `just clean` undoes what a campaign or a
synthesis wrote, so a checkout can be reused. After fixing an instrumented checkout by hand, `just test`
runs only the campaign's test gate on it, for the profile in `campaign/meta.json`, then
the component tests the gate leaves out (reported, not gated), before
you fuzz it with `just fuzz <profile> --skip-campaign`. Note that in `consensus/fuzz/` and at the
repository root, `just fuzz` is a different, pre-existing recipe that runs a package's fuzz
targets.

A campaign adds the runtime module, the fuzz targets and the harness and runtime hooks to
the tree, lets the agent bind every invariant of the profile's registries, adds beacon probes, then
audits the bindings against the tree as it stands, checks that only the profile's
subsystems were edited,
builds (with up to 3 agent repair attempts), and runs the test gate. The audit pass re-reads
each invariant against the sites that commit the actions it names, adds the checks that are
missing, and corrects a plan section whose `Status` claims more coverage than it has;
`STATELENS_AUDIT=0` skips it. It then ends with the result `READY` and prints
the command that runs each target. **The campaign builds the fuzz targets and runs no
fuzzer**, and passes no arguments to libFuzzer: that is Phase 3. `--stop-after` is for
development and ends the campaign with `STOPPED after <step>`.

| | `simplex` (default) | `marshal` | `qmdb` |
|---|---|---|---|
| Registries | `simplex` | `simplex`, then `marshal` | `qmdb` |
| Instrumented code | `consensus/src/simplex` | the same, and `consensus/src/marshal` | `storage/src/qmdb` |
| Beacon probes | voter, batcher, resolver | the same, and marshal core, standard, coding | `any`, `current`, `immutable`, `keyless`, `store`, `sync` |
| Fuzz targets | `<target>_statelens` for each of the 21 `simplex_*` targets of `consensus/fuzz/simplex` | `<target>_statelens` for each of the 12 marshal targets | `<target>_statelens` for each of the 17 `qmdb_*` targets of `storage/fuzz` |
| Test gate | `simplex::tests` without Twins, `simplex::statelens` | the same, and `marshal::` | every `qmdb::` test of `commonware-storage` |

The simplex test gate is about 240 tests and 2 minutes on 16 cores; marshal adds 421 tests
and about 70 seconds; the qmdb gate is 2,289 tests and about 100 seconds. For simplex and
marshal, after the gate passes, the campaign also runs every other simplex test the gate
leaves out (the actor, type and scheme tests and the rest, about 516 tests and a few
seconds) and names any that fail on the `components` line of the summary. They drive one
actor with states built by hand, so a failure there is for you to judge, and it never
changes the result. A `coverage UNVALIDATED` line means the plan lint found problems after
the audit or a repair, a repair changed instrumented files after the audit, no audit ran
(`STATELENS_AUDIT=0`), or a later audit batch changed existing lines after an earlier
batch's verdict: the targets are built and the gate passed, but the plan's coverage claims
are not supported by the code, or the audit describes a tree the repair replaced. Run a
campaign with a new audit before relying on the counts. The `invariants` line also names
the bindings whose `Status` says `(inactive in the fuzz targets)`: bound or partial as
written, but never evaluated by the targets, so a silent campaign says nothing about them.

The campaign refuses to start when a required tool is missing, when tracked files outside
`statelens/` have uncommitted changes, or when an earlier campaign already
instrumented the checkout. Uncommitted registry edits are used.

`--invariants LIST` binds only the invariants a comma-separated list names, each written
`<registry>/INV-NNNN`, or as a bare `INV-NNNN` when the profile binds one registry (the
`marshal` profile binds two, so there every id names its registry); the flag may be
repeated. The list is applied after the registries are collected, so a local invariant and,
under `STATELENS_FALSE_INVARIANTS=1`, a false one (`simplex/FALSE-0001`) can be selected
too, and the bound set keeps the registries' order. An id of a registry the profile does
not bind, or that no file provides, stops the campaign (exit 2) with the ids available, as
does a list that selects nothing. `campaign/meta.json` records the selected ids under
`invariants` and the number available under `invariants_available`, the plan lists the
selected ones only, and `just check-plan` expects sections for those. The beacon probes are
added as always: they are feedback, not oracles.

## Phase 3: run fuzz targets

In the instrumented checkout, run the `run` commands of a `READY` summary for the targets
you choose, adding libFuzzer arguments as needed, such as `-fork=<N>` to use N cores or
`-max_total_time=<s>` to bound the run. From this directory `just run <target>` does the
same, and `just fuzz <target>` runs the campaign first.

`just fuzz <profile>` runs every target the profile builds. It campaigns once, then runs
them one after another; `--parallel` runs them together and writes each one's output to
`campaign/logs/<target>.run.log`; `--tmux` runs them together in one tmux window each, so
their output stays live and separate. Nothing bounds a run unless you pass
`-max_total_time` or `-runs`, so a target runs until it stops. The sequential form warns about
that, because there the first target would be the only one to run. With several targets at once,
divide `-fork` between them rather than giving each the whole machine. `--skip-campaign`
fuzzes the targets a campaign already built in this checkout, whatever its result -- the way
to keep going after a campaign that built its targets and then stopped, since a new campaign
refuses an instrumented checkout. Each target starts from whatever corpus its directory
holds, as without the flag. `--fuzz-targets GLOB`, which you may repeat, keeps only the targets
a shell pattern names, by the variant's name or the original target's; a pattern that names
none stops before the campaign, listing what the profile builds. `--state-reaching` runs the
profile's scaffolds instead, one per selected card and base, and `--state-targets` selects its
cards (see Target-State Synthesis). `--invariants LIST`, which you may repeat, goes to the campaign, which then binds
only the invariants it names (see Phase 2); it is refused with `--skip-campaign`, which runs
no campaign, and with a single target. A double-dash flag `just fuzz` does not know is refused
rather than passed to libFuzzer, whose own flags take one dash:

```
just fuzz simplex --tmux -- -fork=5
just fuzz simplex --tmux --fuzz-targets "simplex_cert_*" -- -fork=4
just fuzz simplex --invariants INV-0001,INV-0002 -- -max_total_time=3600
just fuzz marshal --skip-campaign --parallel --tmux
just fuzz simplex --parallel -- -max_total_time=600 -fork=5
STATELENS_JOBS=4 just fuzz marshal --parallel -- -max_total_time=600

just run simplex_cert_mock_twins_mutator_statelens -- -rss_limit_mb=4000 -print_final_stats=1 -fork=8

just fuzz qmdb --parallel -- -max_total_time=600
just run qmdb_current_recovery_statelens -- -rss_limit_mb=4000 -fork=4

cd <repo>/statelens
NIGHTLY_VERSION=<fuzz toolchain> just run simplex_cert_mock_twins_mutator_statelens -- \
  -rss_limit_mb=4000 -print_final_stats=1 -fork=8
NIGHTLY_VERSION=<fuzz toolchain> just run \
  marshal_e2e_standard_app_cert_mock_twins_statelens -- \
  -rss_limit_mb=4000 -print_final_stats=1 -fork=8
```

`just run` hands a consensus target to `consensus/fuzz`'s own `run` recipe and runs a
`qmdb_*` target from `storage/fuzz`; both pick the toolchain the same way, `NIGHTLY_VERSION`
first and then the pin in `.github/workflows/slow.yml`. Give a crash file as an absolute
path, as the `replay` line does.

A run ends when the target panics or you stop it; libFuzzer, fork mode included, stops at
the first crash. A variant runs at about 13 inputs per second per process, so
use `-fork` on a many-core machine. For marshal only the stock standard Twins target was
measured, at about 15 inputs per second and 0.6 GB per process, and for qmdb only
`qmdb_current_mmb_prune_grow_statelens` before instrumentation, at about 13 inputs per
second and 0.5 GB; size the other runs yourself.

Do not pass `-artifact_prefix` or `-exact_artifact_path`, which move the crash file
elsewhere, or any `-handle_*` switch, which can stop libFuzzer from reporting a crash and
saving its input. Crashes land in `consensus/fuzz/simplex/artifacts/<variant>/` for a
simplex variant, in `consensus/fuzz/marshal/artifacts/<variant>/` for a marshal one, or in
`storage/fuzz/artifacts/<variant>/` for a qmdb one.

A `simplex` campaign builds 21 variants, one per target in
`consensus/fuzz/simplex/fuzz_targets/`, each named `<target>_statelens`. Only those whose
adversary runs a real Simplex engine exercise the Byzantine guard:

- the nine Twins variants: those of `simplex_cert_mock_twins_campaign` and
  `simplex_cert_mock_twins_mutator` with their `_audit`, `_hb` and `_state_cov` forms,
  and that of `simplex_cert_mock_shuffled_twins_mutator`;
- `simplex_cert_mock_chaos_twins_statelens` and `simplex_cert_mock_byzzfuzz_statelens`;
- `simplex_cert_mock_audit_statelens`, for an input that draws the RejectView
  certification choice;
- `simplex_cert_mock_mallory_statelens`, after an amnesia restart, which brings a node back
  on empty storage.

In the other eight (Standard, FaultyNet, the notarize-omission audit and Chaos), no
adversary runs a Simplex engine, so every engine is checked.

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

A `qmdb` campaign builds 17 variants, one per `qmdb_*` target in
`storage/fuzz/fuzz_targets/`. qmdb has no replicas, so nothing is compromised, every site is
checked, and `STATELENS_BYZANTINE` has no effect.

## Target-State Synthesis

Some states need a specific history that random inputs rarely produce: a replica that
nullified a view and then certifies a notarization of it, or one that restarted from its
journal after every online replica crashed. For `simplex` and `marshal`, Target-State
Synthesis turns a description of such a state into a reviewed card, and after a campaign has
an agent write one scaffold per card and base: a fuzz target built on an existing target, its
base, that scripts the card's history, leaves the values the history does not fix to libFuzzer
as knobs, and reports which events of the history it reached. qmdb is refused. SPEC.md chapter
18 has the details.

### Cards

```
just extract-states --registry simplex test consensus/src/simplex/mod.rs:3260
just extract-states --registry marshal test consensus/src/marshal/standard/mod.rs:7027
just extract-states --registry marshal issue https://github.com/commonwarexyz/monorepo/pull/4317
just extract-states text "A replica signs a nullify vote for view v, then ..."
just extract-states --registry simplex text /path/to/notes.txt
just extract-states --registry marshal --local issue <owner>/<private repository>#<N>
just extract-states --registry marshal kb <finding id>
```

The kinds are those of Phase 1 and two more. `test` takes `path:line` or `path:start-end` of a
test under the registry's source or its profile's fuzz package; the history follows the calls
that build the state, and the test's assertions are dropped. `text` takes a file or a literal,
and the agent confirms every event against the code. `--registry` is `simplex` (the default) or
`marshal`, and `--number` works as in Phase 1. The agent writes
`target-states/<registry>/TS-NNNN.md` in the format of
[templates/target-state.md](templates/target-state.md): a Statement about honest replicas, the
Evidence, a History of events `E1` to `En`, each with its actor and what is observable once it
happened, and the Knobs. A card is a goal to reach, never an oracle. As for an invariant, its
citations are pinned to a commit, and the script writes its Source excerpts.

**Every card is used by the next synthesis of its profile**, so review the new cards first:
edit them, delete the ones you do not want, and run `just check-invariants`, which lints the
cards with the invariants.

A card goes to `target-states.local/<registry>/`, which git ignores, when its source is not
public: a `kb` or `text` source, a path outside the repository, or any run with `--local`, for
a private advisory or repository. To share one, rewrite it without the private detail and move
it into `target-states/<registry>/` yourself. A campaign and a synthesis run in a fresh clone,
which has no ignored files, so copy the local trees you have into it before the campaign:

```
git clone <repository> <clone>
cd <development checkout>/statelens
cp -R invariants.local target-states.local <clone>/statelens/
```

`just synthesize` prints how many cards are tracked and how many local, so a missing copy shows.

### Synthesis

In the checkout a campaign instrumented, once it ended `READY` or `PANIC (tests)`:

```
just synthesize                                         # every card of the campaign's profile, on every base
just synthesize --match TS-0003 --match TS-0004         # these cards, on every base
just synthesize --match "simplex_cert_mock_chaos*"      # every card, on these bases only
just synthesize --match simplex_cert_mock_chaos_ts0003  # TS-0003 on one base
just synthesize --match TS-0003 --redo                  # undo TS-0003's scaffolds and write them again
just synthesize --agent codex
```

**`just synthesize` starts an agent with full access to this machine**, as a campaign does, in
the same disposable clone.

The unit of synthesis is a pair of a card and a base, one of the profile's targets: for
simplex all but `simplex_cert_mock_mallory`, whose custom mutator a scaffold cannot reuse (20
bases), and for marshal every target (13). A card is synthesized on every base unless `--match`
names some: a `TS-NNNN` pattern names cards, any other pattern names bases, by any name a
variant or scaffold of theirs has, so `simplex_cert_mock_chaos_ts0003` pins TS-0003 to one
base and `"simplex_cert_mock_twins_*"` gives each card eight pairs. Pairs run one at a time, and
the agent chooses no base. For each pair, the agent writes a module,
`<package>/src/target_states/tsNNNN_<base>.rs`, and a thin target, `<base>_tsNNNN_statelens`,
whose name carries the base. The script writes `target_states/mod.rs`, the helper through which
a scaffold reports its stages, its declaration and the `[[bin]]` block, and builds. The
scaffold keeps its base's input type, `run` recipe and libFuzzer flags, and has no seed corpus:
the empty input decodes to the card's source history, and the script replays it with
`STATELENS_REACH=1`, then once more without one harness event of the history, the control run,
which shows that the state depends on that history. The verdict and its stage lines drive up to
three further attempts. The agent never runs its scaffold; only these replays judge it.

Each pair costs up to four runs of the agent with their builds and replays, a test gate when
the kept version edited the profile's code, and, because the modules are public siblings in
one crate, a build and three replays of every other scaffold that stands, the card's other
pairs included. A card on all 20 simplex bases is 20 such syntheses, each revalidating every
scaffold that stands. Bound it with base patterns: `<base>_tsNNNN` pins a card to one base,
and `--fuzz-targets` does the same for `just fuzz --state-reaching`.

Synthesis never instruments: it adds no probe, assertion or ghost state. The agent may edit the
profile's code (`consensus/src/simplex/`, and `consensus/src/marshal/` for `marshal`) and its
fuzz package to expose or observe what exists, never to change what the protocol does, and
marks each such edit with `// [statelens] tss:TS-NNNN`; an edit without the mark is annotated
`unmarked edit`, and one next to a probe, an assertion or another line the campaign added is
annotated `edit beside instrumentation`, since an `if false` around an assertion leaves the
assertion itself unchanged. The script vetoes a version that changes the campaign's
instrumentation, the runtime module or a manifest, or adds a print, a panic hook, an included
file or a Rust file git ignores, with feedback to the next attempt. An edit anywhere else stops
synthesis with exit code 2 and the advice to use a fresh clone, and every later synthesis
refuses the checkout while the edit remains. The first synthesis after a campaign records the
tree in `campaign/reach/baseline/`, and every later one is checked against it. After every run
of the agent, and when the synthesis ends, the script writes back, with a warning, what changed
in that record, in its test inventory or in `campaign/instrumentation.diff`. Ctrl-C kills the
agent and what it started before the pair's edits are restored; a SIGTERM or a SIGHUP to the
script does the same. A synthesis killed outright during a pair, rather than stopped with
Ctrl-C, leaves the pair's edits in the tree; the next synthesis first
restores the tree as it was before that pair, with a warning. When the kept
version changed the profile's code, the test gate runs again, and a test that the campaign's
gate passed and that now fails restores the pair's edits (GATE FAILED). Whether an edit
preserves what the protocol does rests on the prompt, that gate and you: review
`campaign/reach/TS-NNNN_<base>.diff`.

A pair that has a report is skipped, saying so, so a second synthesis goes straight to the new
cards and bases; a card's other pairs are untouched. `--redo` reverse-applies each selected
pair's diff, moves its reports aside as `TS-NNNN_<base>.<stamp>.*`, with their run and replay
lines rewritten to name the moved files, moves the crash files fuzzing wrote for its scaffold
to `TS-NNNN_<base>.<stamp>/artifacts/` (the corpus stays), and synthesizes the pair again.
Every other scaffold, the card's other pairs included, is first rebuilt and replayed, since the
undone diff takes away the pair's module, a public sibling of the other modules in one crate,
and its report takes the new verdict. That revalidation is recorded in
`campaign/reach/revalidation.json` before the undo, so one you interrupt is completed by the
next synthesis, before any pair; until then, the reports keep their earlier verdicts. A `--redo`
you interrupt after the undo and before the reports move finishes when you run it again.

```
statelens: cards      <n> tracked, <m> local
statelens: TS-NNNN    skipped: TS-NNNN on <base> was synthesized as <scaffold>; use --redo
statelens: TS-NNNN    <verdict>[ (<annotation>, ...)]   <scaffold | no scaffold on <base>>
statelens: synthesis  <k> pair(s), <s> scaffold(s); reports in statelens/campaign/reach/
statelens: run        cd <repo>/statelens && NIGHTLY_VERSION=<fuzz toolchain> just run <scaffold>
statelens: replay     cd <repo>/statelens && STATELENS_REACH=1 [<replay env> ]NIGHTLY_VERSION=<fuzz toolchain> just run <scaffold> <repo>/<package>/artifacts/<scaffold>/<crash file>
```

One `TS-NNNN` line per pair, and one `run` and `replay` pair of lines per scaffold that exists.

| Exit code | Result |
|---|---|
| 0 | at least one scaffold exists for the selection |
| 1 | usage error, `qmdb`, or no card and base selected |
| 2 | a failed precondition (no campaign of the profile at `HEAD`, a false invariant bound, a result other than `READY` or `PANIC (tests)`, no `plan.md`, a checkout instrumented before the read side existed or cleaned, a missing tool, a selected card with a lint problem), a missing or unreadable synthesis record in `campaign/reach/`, a checkout that differs from the baseline, an edit out of scope, a missing anchor, or a `--redo` that does not apply |
| 3 | no scaffold built: every selected pair ended NOT BUILT or GATE FAILED |

### Reports and verdicts

`campaign/reach/` holds, per pair, `TS-NNNN_<base>.md`: the shape, base and scaffold, the
verdict and its annotations, each stage's outcome and witness, the handoff, the attempts and the
crash attribution, and the `run` and `replay` lines; `TS-NNNN_<base>.diff`, every edit of the
kept version, the script's included, which is what to review; and
`TS-NNNN_<base>/attempt-<a>/`, the replays of each attempt with their logs and crash files, in
`swept/` the crash files a run of the agent left, in `version.diff` the version the attempt
built or the run used, and for a CRASH its `run` and `replay` lines in `replay.txt`, so a
finding stays reproducible after GATE FAILED restores the pair's edits.

| Verdict | Meaning |
|---|---|
| `REACHED n/n` | Every event of the history was witnessed, the state held at the handoff, and the control run did not reach it |
| `UNVERIFIED k/n` | No event was missed, but one could not be verified, a witness was rejected, or the control was vacuous, weak or missing |
| `PARTIAL k/n` | An event after the first was missed, or the state was lost before the handoff; `k` counts the events held before it |
| `UNREACHED 0/n` | The first event was missed: the setup is wrong, or a capability is missing (`cannot:`) |
| `NO REPORT` | The scaffold printed no report: it did not use the helper, or returned before its base's oracles |
| `CRASH (finding candidate)` | A replay failed: a panic, a violated invariant, a harness oracle, a sanitizer report, out of memory, a leak or a timeout; or a run of the agent left a crash file (`stray failure`) |
| `SCAFFOLD ERROR` | The helper rejected the scaffold (`[statelens-scaffold]`) before any engine started |
| `NOT BUILT` | No version passed the vetoes and built, or the kept version broke another standing scaffold (`breaks TS-MMMM_<b>`, the card's other pairs included); the pair's edits are restored |
| `GATE FAILED` | The kept version made a test of the gate fail; its edits are restored |

The other annotations include `nondeterministic` (the last replay of the canonical input
differed), `control missing`, `missing: <capability>`, `location in TS-NNNN diff`, and
`stray failure` beside another verdict when a later attempt left a crash file but was not
built; the console line then names the file.

Every scaffold that builds is fuzzed, whatever its verdict: only NOT BUILT and GATE FAILED
leave a pair without one. A verdict judges one input; how often fuzzed inputs reach the state
shows only when you fuzz. A CRASH (finding candidate) stops the pair's refinement, and that
version is kept and fuzzed as it is, never replaced by one that avoids the failure. Triage it
like any crash (see Investigating a panic): where it failed is context only, and
`location in TS-NNNN diff` says the failing line is one the pair's diff added or moved, which
does not make it the scaffold's fault. When triage does show a fault of the scaffold, run the
pair again with `--redo --match <base>_tsNNNN`, or the whole card with `--redo --match TS-NNNN`.

### Fuzzing the scaffolds

```
just fuzz simplex --parallel --tmux --state-reaching --state-targets TS-0004 --fuzz-targets "simplex_cert_*"
just fuzz simplex --tmux --state-reaching --state-targets TS-0003 --skip-campaign
just fuzz simplex --state-reaching --state-targets TS-0004 --fuzz-targets "simplex_cert_mock_twins_*" --invariants "simplex/INV-0001,simplex/INV-0002" -- -max_total_time=3600
just fuzz marshal --parallel --state-reaching -- -max_total_time=600
just run simplex_cert_mock_ts0004_statelens -- -fork=4
```

`just fuzz <profile> --state-reaching` runs a campaign, unless `--skip-campaign`, then
`synthesize`, then the scaffolds of the selection and never the variants, in turn, with
`--parallel` or with `--tmux`, as `just fuzz <profile>` runs variants; the tmux session is
`statelens-<profile>-reach`, with a window per scaffold, one per card and base, named after the
scaffold without `_statelens` (`simplex_cert_mock_ts0004`). `--state-targets` names cards
(`TS-0003`) and `--fuzz-targets` names the bases the scaffolds are written on, by any name a
variant or scaffold of theirs has; both may be repeated, and a pattern of the other flag's form
is refused, as is `--state-targets` without `--state-reaching`. Without `--fuzz-targets` every
base of the profile is used, so `just fuzz simplex --tmux --state-reaching` with three cards
opens up to 60 windows. The first command above opens one window per `simplex_cert_*` base of
TS-0004; the third synthesizes TS-0004 on each of the eight `simplex_cert_mock_twins_*` bases
and runs the eight scaffolds in turn, each with `-max_total_time=3600`:
`simplex_cert_mock_twins_campaign_ts0004_statelens`, its `_audit`, `_hb` and `_state_cov`
siblings (`simplex_cert_mock_twins_campaign_audit_ts0004_statelens` and so on), and the four
`simplex_cert_mock_twins_mutator*_ts0004_statelens`. The recipe's messages count scaffolds
("8 scaffold(s), one tmux window each"). A selection with no card, or with a card that has a
lint problem, fails before the campaign, and a failed synthesis stops the command. With a
single target, or with `qmdb`, `--state-reaching` is refused. As for a variant, libFuzzer gets
only the arguments you pass after `--`, and crashes land in `<package>/artifacts/<scaffold>/`.
libFuzzer runs the empty input, the canonical one, first, so a scaffold that fails on its
card's own history fails at once.

Replay a scaffold's crash with its `replay` line, which sets `STATELENS_REACH=1`, so the replay
also prints the `[statelens-reach]` stage lines: how far through the history that input got
before it failed. A failure the control run found replays with `STATELENS_REACH_CONTROL=1` as
well, which its `replay` line adds.

```
cd <repo>/statelens
STATELENS_REACH=1 CONSENSUS_FUZZ_LOG=1 NIGHTLY_VERSION=<fuzz toolchain> just run \
  simplex_cert_mock_ts0004_statelens \
  <repo>/consensus/fuzz/simplex/artifacts/simplex_cert_mock_ts0004_statelens/<crash file>
```

`just coverage` covers a profile's scaffolds with its variants, and takes a scaffold's name.
`just clean` deletes `target_states/`, the files git ignores there included, and the thin
targets and restores what synthesis edited in the fuzz packages, leaving their corpora, crash
files and coverage reports, and `campaign/reach/`, alone.

## Coverage

When a run is over, `just coverage` says what its corpus actually reaches. It takes a
profile, single targets, or neither (every target of the default profile), and a name
beginning `simplex_`, `marshal_` or `qmdb_` picks its own profile, as `just fuzz` does:

```
just coverage simplex
just coverage marshal
just coverage qmdb
just coverage simplex_cert_mock_twins_mutator_statelens
```

For each target that has a corpus it replays that corpus under coverage instrumentation
(`cargo fuzz coverage`), then writes, under the fuzz package's `coverage/html/`:

- `<target>/index.html`, one per target, and `unified/index.html` merged over all of them;
- `<target>.<subsystem>.txt`, the summary of the code the campaign instruments, which
  leaves out the profile's uninstrumented paths (`mocks/` and `scheme/` in consensus,
  `benches/` in qmdb);
- `<target>.workspace.txt`, the same without dependencies or the standard library.

A scaffold counts as a target of its profile, and its name works like a variant's. A target
with no corpus is skipped, so run this after the targets you care about, in the
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
statelens: profile    simplex | marshal | qmdb
statelens: invariants <n> (bound <b>, partial <p>, unbound <u>)[; inactive in the fuzz targets: <ID>, ...]
statelens: audit      <ID> <before> -> <after>, ... | no status change [stale: a repair changed the tree after it]
statelens: plan       <n> commit site(s) listed, <u> not checked, <p> lint problem(s)
statelens: coverage   UNVALIDATED: <why the counts above are not supported>
statelens: sites      <k> assertion sites, <m> probe sites, <d> deleted lines
statelens: components <f> failed, not gated: <test>, ... | all passed
statelens: result     READY | STOPPED after <step> | PANIC (tests) | BUILD FAILED | SETUP FAILED
statelens: reason     <why the campaign stopped, for PANIC (tests), BUILD FAILED or SETUP FAILED>
statelens: panic      <first [statelens][...] line, or the first panic message>
statelens: run        cd <repo>/statelens && NIGHTLY_VERSION=<fuzz toolchain> just run simplex_cert_mock_twins_mutator_statelens -- -rss_limit_mb=4000 -print_final_stats=1
statelens: replay     cd <repo>/statelens && CONSENSUS_FUZZ_LOG=1 NIGHTLY_VERSION=<fuzz toolchain> just run simplex_cert_mock_twins_mutator_statelens <repo>/consensus/fuzz/simplex/artifacts/simplex_cert_mock_twins_mutator_statelens/<crash file>
```

The `run` and `replay` lines appear only with `READY`, one pair per variant of the
profile. The `components` line appears for simplex and marshal only. The `replay` line is
a template: put in the crash file that libFuzzer wrote, and set the `STATELENS_BYZANTINE`
value of the run that found it. A campaign that passed its preconditions also saves the
lines to `campaign/summary.txt`. A run refused by the preconditions prints them only, so
the summary of the campaign that instrumented the checkout is kept.

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
   `rg '\[statelens\] <ID>' --type rust`, and every change in
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
| `STATELENS_FALSE_INVARIANTS=1` | Set on `just campaign`. Also binds the deliberately false invariants in `false-invariants/<subsystem>/`: FALSE-0001 with the `simplex` profile, FALSE-0001 and FALSE-0002 with the `marshal` profile, FALSE-0003 with the `qmdb` profile. A `simplex` campaign must end with `PANIC (tests)` and `[statelens][FALSE-0001]`, or, if it reports `READY`, a short run of its `run` command must panic with it. A `marshal` campaign must end with `PANIC (tests)`, and `campaign/logs/test.log` must contain both `[statelens][FALSE-0001]` and `[statelens][FALSE-0002]`. A `qmdb` campaign must end with `PANIC (tests)` and `[statelens][FALSE-0003]` in `campaign/logs/test.log`. |
| `STATELENS_BYZANTINE=panic` | Set on a `run` command. Panics when a compromised replica reaches an instrumented site, which shows the Byzantine guard is needed and wired: the simplex and marshal variants whose adversary runs a real Simplex engine (see Phase 3) must panic with `[statelens][BYZANTINE]`, `simplex_cert_mock_audit_statelens` only for an input that draws the RejectView choice and `simplex_cert_mock_mallory_statelens` only after an amnesia restart, and no other variant may; `[statelens] participant index mismatch` must never appear. `skip` is the default, `check` checks compromised replicas too. |
| `STATELENS_CLAUDE_EFFORT`, `STATELENS_CODEX_EFFORT` | Set in `config.env` or the environment. The reasoning effort the agent CLI runs with: `low`, `medium`, `high`, `xhigh` or `max` for claude, codex's own `model_reasoning_effort` levels for codex. Empty means the CLI's default, which is what a campaign uses unless you pin it. `STATELENS_CLAUDE_MODEL` and `STATELENS_CODEX_MODEL` work the same way for the model. Both land in `campaign/meta.json`, so pin them when you want two campaigns to be comparable. |
| `STATELENS_AUDIT=0` | Set on `just campaign`. Skips the audit pass over the bindings, which costs one agent run per batch of 8 invariants. The campaign then prints no `audit` line, a plan section keeps whatever `Status` the first pass gave it, and the summary's `coverage` line says `UNVALIDATED: no audit pass ran`. |
| `STATELENS_FEEDBACK=0` | Set on a `run` command. Leaves the StateLens counters unregistered. Run a target for the same time on two empty corpora, with and without it: `ft:` on the `DONE` line should be higher with feedback. Compare `ft:`, not `cov:`, which libFuzzer stops printing once the counters are registered. |

Each false-invariant campaign in a fresh clone of its own:

```
STATELENS_FALSE_INVARIANTS=1 just campaign
STATELENS_FALSE_INVARIANTS=1 just campaign --profile marshal
STATELENS_FALSE_INVARIANTS=1 just campaign --profile qmdb
```

In the checkout of a `READY` simplex campaign (for a `READY` marshal campaign, use a Twins
variant such as `marshal_e2e_standard_app_cert_mock_twins_statelens`):

```
cd <repo>/statelens
STATELENS_BYZANTINE=panic NIGHTLY_VERSION=<fuzz toolchain> just run simplex_cert_mock_twins_mutator_statelens -- \
  -max_total_time=120
STATELENS_FEEDBACK=0 NIGHTLY_VERSION=<fuzz toolchain> just run simplex_cert_mock_twins_mutator_statelens \
  <empty dir> -- -max_total_time=600
```

### The differential test of the TSS primitives

The marshal scenario prefixes (`consensus/fuzz/marshal/src/scenarios/`) are hand-written
reconstructions of six marshal standard tests that check the state they reach at the handoff.
`statelens/differential/` is a test-only crate that, for each of those tests, drives the
scenario's own prefix and a hand-written TSS prefix, built from the helper primitives
(`Stages`, `Witness`, `stamp`, `Stages::handoff`) and the same harness verbs as a scaffold
would use, on an identical setup and input, takes a canonical state digest of both, and
requires equal digests and a `REACHED n/n` verdict from the real reach-check validator
(`statelens.py reach-verdict`) on the TSS side's `[statelens-reach]` lines. Six negative
controls (a dropped event, `En` read before the handoff, swapped events, a certificate or a
finalization delivered to another node, a delivery left armed) must be caught, by the digest
or by the validator's verdict of a replay that ran to its digest line. It instruments
nothing, starts no engine and runs no fuzzer: it tests the method, not a campaign, and it
says nothing about what an agent writes.

```
statelens/scripts/differential.sh
DIFFERENTIAL_SCRATCH=/path/with/25GB/free SKIP_FUZZ_CHECKS=1 statelens/scripts/differential.sh
```

The script never builds in the checkout: it adds a detached worktree of `HEAD` under
`<scratch>/run.XXXXXX/wt-diff`, one `mktemp -d` directory per run (`DIFFERENTIAL_SCRATCH`,
default `$TMPDIR/statelens-differential`), copies `statelens/` and
`consensus/fuzz/marshal/` into it, checks the fuzz package there (clippy with `-D warnings`,
rustfmt of the touched files, nextest; `SKIP_FUZZ_CHECKS=1` skips this), builds the crate,
runs every test in its own process twice (the canonical and the control replay) with the
reach lines captured, runs the validator, prints a `| test | digest equal | verdict |` table
and `differential: PASSED` or `FAILED`, and removes the worktree with its target directory.
It needs about 25 GB of free disk, the `stable` toolchain with nextest and the pinned
nightly's rustfmt (`DIFFERENTIAL_RUSTFMT`), and takes a few minutes after the builds. The
logs and both digests of every test stay in `<scratch>/run.XXXXXX/logs/` (the path is
printed at the end) for a diff.

The crate is the one `Cargo.toml` under `statelens/`: its empty `[workspace]` table keeps it
out of the root workspace, so no workspace build, test, lint or CI job sees it. It needs the
scenario primitives of `consensus/fuzz/marshal/src` to be `pub` rather than `pub(crate)`, the
one change outside `statelens/`, a visibility change and nothing else.
[differential/README.md](differential/README.md) lists what the digest compares and the
test's limits: it compares settled states, so an event still in flight at the handoff is not
told apart. SPEC.md section 18.10.1 has the procedure and the expected table.
