# H2-v2 probe log

```
rule   = h2-v2 (RULE.md sha256 11621af4de70e2b39e1de20d3773805b46e25fc9cc3952fb378247680908db93)
seed   = 7bc58f68b25930aa17c68e7c870edb9a
sample = stage finish-A, 2026-10-03: enumeration 11:05:38Z, instances 11:05:58Z-11:10:20Z,
         probe 11:10:47Z-14:19:09Z, freeze 14:19Z
```

This file is the log RULE.md asks for: what was seen of the scope before
sampling, and every fix of the sampling tools with its reason. It names no
`- seen:` file, so no scope file left the scope (RULE.md 2.6).

## Before enumeration: what was seen

* **Development looked at no scope file.** The recorded tool calls of the
  two development stages, reader-widen (492 calls) and optimizer-generic
  (607 calls), name no path of the scope (RULE.md 1) in any command or any
  output (checked mechanically on the records kept in
  `sandblaster-wt/recovery/`). Stage finish-A's development (the shipped
  theorems decide, the walker's two gaps, L's slice leaves, a rewritten
  function's parameter `mut`) was driven by held-out v1's development
  functions, and its own record holds no scope file's content.
* **The rule's stage** listed the file names under `actor/src` and
  `glue/src` while computing the scope; its report says it read no
  function, and that it dropped a `simulate` test-path entry and a
  `Mailbox` purity token the listings had suggested.
* **A first evaluation attempt** (stage A5, 2026-10-02/03, after
  reader-widen and optimizer-generic, before finish-A) enumerated the
  scope and probed part of it in a scratch worktree that was lost before
  anything was committed; its last probe run was killed (exit 144). Its
  outputs (rejections, probe rows, one `grep -n "simulated"
  p2p/src/lib.rs`) are in its recorded tool calls. This sampling uses none
  of them and starts again from the enumeration. Its tool files were
  recovered from that record (below) by a replay that wrote files and ran
  none of its commands, on 2026-10-03 at 03:41 PDT: after finish-A's last
  reader, elaborator, optimizer or lowering change (03:19 PDT), while
  finish-A's acceptance ran. The finish-A agent read the record's commands
  to choose what to replay; its own record shows none of A5's outputs about
  scope functions (no scope path occurs in its tool results except A5's
  command above, without its output, and the rule stage's note).

## Tool fixes

**Made by the first attempt (A5), carried over with its tools.** Each is a
change of the tools, the same for every candidate; none changes a criterion
of RULE.md or names a function. In the order A5 made them:

| tool | fix |
| --- | --- |
| `sample.py` | the module-tree walk (which files `lib.rs` reaches through `mod` declarations); generics with a closing `>>` |
| `instance/` (the rustc driver of RULE.md 3.1) and `instance.py` | lifetimes aligned in the driver's output; `Self::` paths qualified in the call-form wrappers |
| `probe.py` | the generated root's declaration directory and the merging of its children; the note chosen for a missing MIR root (reason text only); extractions run in chunks inside one admission slot (`--exec-batch`: the same commands per candidate, queued once per chunk); the extraction run again whenever the callee closure changes its items or skipped functions (RULE.md 5.1) |
| `freeze.py` | the sample's MIR from the probe's planned extraction |
| `heldout_probe`, `evaluate.py` | run under the memory guard outside the admission gate |

**Made in this sampling:** none. The tools ran as recovered, unchanged from the
enumeration to the freeze.

## This sampling

Enumeration (`sample.py`): 3,162 functions in the scope files; 1,409
candidates (1,215 generic), 1,753 static rejections, 131 blocks not
entered, 21 files enumerated though not reached from `lib.rs` (their cfg is
not decided lexically; `rejections.tsv` names them). The rule-chosen
instances (`instance.py`): 675 generic candidates got one, 540 got none
(`no instance (RULE.md 3.1)`), leaving 869 candidates.

The probe (`probe.py`, 2 workers, chunks of 24) probed all 869 in the
seeded order and accepted **none**, so H2-v2 is empty: shortfall 40
(RULE.md 4: H2-v2 is every candidate that passed; the rule is not widened).
The first failing step:

| step | candidates | of them generic |
| --- | ---: | ---: |
| 1, extraction (no MIR root for the candidate, or the extraction failed) | 78 | 66 |
| 2, callee closure (an unresolved call, or more than 32 functions or 12 files) | 35 | 33 |
| 3, size (no loop and fewer than 10 MIR statements) | 651 | 482 |
| 4, reader (`driver::check` refused the generated root) | 104 | 94 |
| 5, exec-only elaboration (a definition not `Checked`) | 1 | 0 |

**What the evaluation should know** (observations, not fixes: RULE.md
allows a fix of the probe only when it fails on every candidate for an
infrastructural reason, and these do not):

* 39 of the 104 reader refusals, all generic candidates, are `rustc's MIR
  has no instance for the lifted function`: the extraction has the
  candidate's root at the rule's instance, but the in-place lift, given the
  instance as `instance = "<bound>: <type>"` with a workspace type of
  another crate, finds no instance for it. The other reader refusals are
  constructs the lift does not read (25 impls of a trait it does not know,
  13 callees without a MIR body, 8 `#[derive(Default)]` field types, 8
  generic parameters without a sealed-trait bound, and single cases).
* Extraction: candidates whose impl is skipped by the extractor's defaults
  (`Hash`, `Debug`, `Display` impls: `SBMIR_SKIP_TRAITS`), impls whose self
  type is an import alias or a primitive (`not among the items asked for`),
  and rustc failures inside the extractor (an internal compiler error while
  normalizing a projection; a panic in `rustc_public`'s bridge).
* The one candidate that passed the reader,
  `commonware-consensus::types::FixedEpocher::bounds` (rank 708), is
  `Unproven` in the exec-only path (an obligation its code does not
  discharge). RULE.md 5.5 asks for `Checked`; the optimizer could now take it
  through its panic-explicit reading (DESIGN.md §8.2 item 12, built after
  this rule was frozen), but the rule is not changed: a rule that admits it
  is version 3.
