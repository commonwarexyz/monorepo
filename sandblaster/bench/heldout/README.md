# Held-out v1: retired to the development set

**Status: development set since 2026-10-02.** This directory is held-out v1,
the first held-out evaluation of the fairness audit (manifest.toml, h1/ and
h2/). It is no longer held out.

Why: its measurement has been run and its refusal reasons have been read
(`REPORT.md`: 22 of 31 functions refused by the MIR reader, 6 by exec-only
elaboration, with each function's refusal). Anything seen can shape later
work, so v1 can no longer show that a change is general. From now on it is
development data, like the QMDB port, the optimizer corpus, codec and
storage. Its functions and its probe rows (`h2/probe.tsv`,
`h2/rejections.tsv`) may motivate reader and optimizer changes. Its numbers
are regression checks only. They never justify a feature, and a "faster than
rustc" statement never cites them (DESIGN.md §8.2 item 11).

What replaces it: held-out v2 (`sandblaster/bench/heldout-v2/`). Its protocol
was frozen before any reader or optimizer work that could be tuned to it:
- a new blind H1 set (`heldout-v2/h1/`);
- a new versioned H2 sampling rule with a new committed seed
  (`heldout-v2/h2/RULE.md`). It names the scope crates that development must
  not look at, and it excludes every function v1 probed.

The files stay frozen. G6 (`sandblaster/tools/gates/g6.sh`) still pins every
file here as recorded, except the generated `REPORT.md`. Retiring v1
changes its label, not its contents. This README was added at retirement,
and G6 freezes it too. The v1 harness (`sandblaster/bench/heldout-harness`)
still runs against these files as a development-set regression check.
