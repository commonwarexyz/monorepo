#!/usr/bin/env python3
"""StateLens for Simplex, marshal and qmdb: lint invariants, extract them with an agent, run
campaigns.

Invariants live in one registry per subsystem (invariants/simplex/, invariants/marshal/,
invariants/qmdb/). A campaign profile (simplex, marshal or qmdb) selects the registries it
binds, the code it instruments, the StateLens fuzz targets it builds and the tests it runs;
the operator runs the targets afterwards. See statelens/docs/SPEC.md. Standard library only;
Python 3.9 or later.
"""

import argparse
import collections
import contextlib
import datetime
import difflib
import fcntl
import fnmatch
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

# Subproject root, relative to the repository root.
SL = Path("statelens")

AGENTS = ("claude", "codex")
KINDS = ("issue", "design", "comment", "spec", "paper", "kb")
SOURCE_KINDS = ("human",) + KINDS
# SPEC section 18.4: target states are also extracted from tests and plain text, and a
# card may name either as its source_kind (section 18.3, lint rule 5).
STATE_KINDS = KINDS + ("test", "text")
CARD_SOURCE_KINDS = SOURCE_KINDS + ("test", "text")
# SPEC section 4.2: the registries and the scope values each of them allows.
SUBSYSTEMS = ("simplex", "marshal", "qmdb")
SCOPES = {
    "simplex": ("protocol", "replica", "voter", "batcher", "resolver", "cross-actor"),
    "marshal": (
        "protocol",
        "replica",
        "core",
        "resolver",
        "standard",
        "coding",
        "application",
        "cross-component",
    ),
    "qmdb": (
        "database",
        "proof",
        "sync",
        "any",
        "current",
        "immutable",
        "keyless",
        "store",
    ),
}
# The source directory of each subsystem, which its registry describes.
SOURCES = {
    "simplex": "consensus/src/simplex",
    "marshal": "consensus/src/marshal",
    "qmdb": "storage/src/qmdb",
}
ALL_SCOPES = tuple(dict.fromkeys(scope for name in SUBSYSTEMS for scope in SCOPES[name]))
REQUIRED_KEYS = ("id", "title", "source_kind", "source_ref", "scope")
REQUIRED_SECTIONS = ("Statement", "Rationale", "Evidence")
CARD_SECTIONS = REQUIRED_SECTIONS + ("History", "Knobs")
# Invariants derived from the knowledge base live in a local registry that git ignores,
# because nothing derived from a finding may reach a commit (R-KB-6); campaigns bind
# both, and IDs are unique across both.
LOCAL_INVARIANTS = "invariants.local"
# Target-state cards (SPEC section 18.3): a registry of their own, for the consensus
# subsystems only, with a local part for sources that are not public (section 18.4).
LOCAL_STATES = "target-states.local"
STATE_SUBSYSTEMS = ("simplex", "marshal")
FILE_NAMES = {
    "invariants": re.compile(r"^INV-\d{4,}\.md$"),
    LOCAL_INVARIANTS: re.compile(r"^INV-\d{4,}\.md$"),
    "false-invariants": re.compile(r"^FALSE-\d{4,}\.md$"),
    "target-states": re.compile(r"^TS-\d{4,}\.md$"),
    LOCAL_STATES: re.compile(r"^TS-\d{4,}\.md$"),
}
CARD_TREES = ("target-states", LOCAL_STATES)
# SPEC section 4.1: one global counter per ID prefix, over the trees that use it.
ID_TREES = {
    "INV": ("invariants", LOCAL_INVARIANTS),
    "FALSE": ("false-invariants",),
    "TS": CARD_TREES,
}

FINDING_STATES = ("valid", "tested", "triaged", "intake", "invalid")
STATE_RANK = {state: rank for rank, state in enumerate(FINDING_STATES)}
# SPEC section 5.6: the knowledge base and its index.
KB_INDEX = "extract/kb-index.json"
KB_DOC_DIRS = ("kb", "config", "context")
KB_STATE_SECTIONS = (
    "Context",
    "Root Cause",
    "Lifecycle Events",
    "Exploitation Or Trigger Conditions",
)
KB_CLAIM_FIELDS = (
    "module",
    "summary",
    "tags",
    "severity_current",
    "confidence",
    "remediation_status",
    "related_findings",
)
# A finding's own citations of code. Harvested from every section, because they sit mostly
# in sections whose prose is not retrievable; a citation is not exploit detail (SPEC 6.3).
KB_REF_PATH = re.compile(r"\b[a-z][a-z0-9_-]*/src/[A-Za-z0-9_/.-]+\.rs(?::\d+(?:-\d+)?)?")
KB_REF_SYMBOL = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+)`")
KB_REF_SHOWN = 6
KB_FIND_LIMIT = 20
KB_GREP_LIMIT = 40
KB_GREP_CONTEXT = 3
MODULE_FILTER = {
    "simplex": "consensus/simplex",
    "marshal": "consensus/marshal",
    "qmdb": "storage/qmdb",
}

CONFIG_KEYS = (
    "STATELENS_AGENT",
    "STATELENS_CLAUDE_MODEL",
    "STATELENS_CODEX_MODEL",
    "STATELENS_CLAUDE_EFFORT",
    "STATELENS_CODEX_EFFORT",
    "STATELENS_TEST_TOOLCHAIN",
    "STATELENS_FUZZ_TOOLCHAIN",
    "STATELENS_KB",
    "STATELENS_SEARCH_MODEL",
    "STATELENS_BEACONS",
    "STATELENS_AUDIT",
)

STOP_STEPS = ("materialize", "index", "instrument", "build")
BATCH_SIZE = 8
REPAIR_ATTEMPTS = 3
ERROR_LINES = 150

# Where a campaign puts the runtime module (SPEC section 9): one per crate it instruments.
STATELENS_RS = "consensus/src/simplex/statelens.rs"
QMDB_RS = "storage/src/qmdb/statelens.rs"
FUZZ_MANIFEST = "consensus/fuzz/simplex/Cargo.toml"
CORE_SIMPLEX = "consensus/fuzz/core/src/simplex.rs"
MARSHAL_TARGETS = "consensus/fuzz/marshal/fuzz_targets"
MARSHAL_MANIFEST = "consensus/fuzz/marshal/Cargo.toml"
MARSHAL_SRC = "consensus/fuzz/marshal/src"
STORAGE_MANIFEST = "storage/fuzz/Cargo.toml"
PLAN = "statelens/campaign/plan.md"
# Worked analyses the Phase 2 prompts point at. They name real functions and fields, so
# `lint-examples` checks those still exist; a document declares its non-code terms with a
# `<!-- statelens-lint: not-code: a, b -->` line.
EXAMPLES = "statelens/examples"
# Section 13 of the specification reproduces every prompt verbatim; `lint-prompts`
# compares the two and `--write` refreshes the copies from the files.
# Dependencies and the standard library are not what a campaign fuzzes, so the
# workspace summary of `coverage` leaves them out.
COVERAGE_DEPENDENCIES = r"(^|/)(\.cargo/registry|\.rustup|rustc/|library/std|/rustc)"
SPEC_DOC = "statelens/docs/SPEC.md"
# The closing fence is the one before the next heading or rule, so a prompt that quotes a
# fence of its own does not end its block early and `--write` cannot append to it forever.
SPEC_PROMPT = re.compile(
    r"^### 13\.\d+ `(prompts/[^`]+)`\n\n~~~markdown\n(.*?)\n~~~\n(?=\n*(?:#|---\n|\Z))",
    re.M | re.S,
)
NOT_CODE = re.compile(r"<!--\s*statelens-lint:\s*not-code:\s*(.*?)\s*-->", re.S)
CODE_WORD = re.compile(r"`([a-z_][a-z0-9_]*_[a-z0-9_]+)`")
# Everything a campaign creates (deleted by `clean`) or edits (restored by `clean`).
# The variants are found by glob, because their names come from the targets.
CREATED_PATHS = (STATELENS_RS, QMDB_RS)
EDITED_PATHS = (
    "consensus/src/simplex/mod.rs",
    "consensus/Cargo.toml",
    "Cargo.lock",
    "consensus/fuzz/core/src/lib.rs",
    "consensus/fuzz/simplex/src/byzzfuzz/runner.rs",
    "consensus/fuzz/simplex/src/chaos/twins.rs",
    "consensus/fuzz/simplex/src/lib.rs",
    "consensus/fuzz/simplex/src/mallory/runner.rs",
    "runtime/src/deterministic.rs",
    FUZZ_MANIFEST,
    MARSHAL_MANIFEST,
    "consensus/fuzz/marshal/src/marshal/end_to_end/scenario.rs",
    "storage/src/qmdb/mod.rs",
    "storage/Cargo.toml",
    STORAGE_MANIFEST,
)
SIMPLEX_TEST_FILTER = (
    "(test(/^simplex::tests::/) & not test(/::test_twins/)) | test(/^simplex::statelens::/)"
)
# Every other simplex test, which the gate leaves out: the actor, type and scheme
# tests and the rest, which drive one component with states built by hand. They run
# after the gate and are reported, not gated (SPEC section 7.7).
COMPONENT_TEST_FILTER = (
    "test(/^simplex::/) & not test(/^simplex::tests::/) & not test(/^simplex::statelens::/)"
)

# SPEC Appendix B.3: inserted into the Twins runner after the `compromised` anchor.
HOOK = """\
    // [statelens] Publish the compromised set before any engine starts, and check
    // that every scheme's own index matches its position in `participants`.
    commonware_consensus::simplex::statelens::set_compromised(compromised.iter().copied());
    for (idx, scheme) in setup.schemes.iter().enumerate() {
        assert_eq!(
            commonware_cryptography::certificate::Scheme::me(scheme),
            Some(commonware_utils::Participant::from_usize(idx)),
            "[statelens] participant index mismatch"
        );
    }"""

# SPEC Appendix B.4: the deterministic runtime's fresh-run hook, which clears StateLens
# ghost state when a fresh runtime starts an independent run.
FRESH_RUN_STATIC = """\
// [statelens] Fresh-run hook: `Runner::new` calls the registered function, which
// forgets StateLens ghost state, so an independent run does not inherit history
// from an earlier run on the same thread. A restart from a checkpoint keeps it.
pub static STATELENS_FRESH_RUN: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();
"""
FRESH_RUN_CALL = """\
        // [statelens] A fresh runtime starts an independent run.
        if let Some(hook) = STATELENS_FRESH_RUN.get() {
            hook();
        }"""

# SPEC Appendix F: inserted into the wedge scenario after the `router` anchor (edit M3).
WEDGE_HOOK = """\
        // [statelens] The Byzantine role runs a real engine and marshal behind the wedge:
        // publish it as compromised before any engine starts, and check that every
        // scheme's own index matches its position in `participants`.
        commonware_consensus::simplex::statelens::set_compromised([Role::Byzantine.index()]);
        for (idx, scheme) in schemes.iter().enumerate() {
            assert_eq!(
                commonware_cryptography::certificate::Scheme::me(scheme),
                Some(commonware_utils::Participant::from_usize(idx)),
                "[statelens] participant index mismatch"
            );
        }"""

# Anchored edits: (file, the only line equal to the anchor, "after" or "before", text).
# SPEC section 7.2, edits 7 and 8, made by every profile.
FRESH_RUN_ANCHORS = (
    ("runtime/src/deterministic.rs", "impl From<Config> for Runner {", "before", FRESH_RUN_STATIC),
    ("runtime/src/deterministic.rs", "    pub fn new(cfg: Config) -> Self {", "after", FRESH_RUN_CALL),
)
# SPEC section 7.2, edits 2, 3 and 6, made by both consensus profiles.
CONSENSUS_ANCHORS = (
    ("consensus/src/simplex/mod.rs", "pub mod types;", "after", "pub mod statelens;"),
    ("consensus/Cargo.toml", "thiserror.workspace = true", "after", "sancov.workspace = true"),
    (
        "consensus/fuzz/core/src/lib.rs",
        "    let compromised = case.compromised.iter().copied().collect::<HashSet<_>>();",
        "after",
        HOOK,
    ),
) + FRESH_RUN_ANCHORS
# SPEC section 8.3, edit M3.
WEDGE_ANCHOR = (
    "consensus/fuzz/marshal/src/marshal/end_to_end/scenario.rs",
    "        let router = Router::new([participants[Role::Byzantine.index()].clone()]);",
    "after",
    WEDGE_HOOK,
)
# SPEC Appendix B.5: the simplex runners besides Twins that run a real engine under a
# Byzantine identity publish it, as the Twins runner does. Standard and FaultyNet make
# their Byzantine nodes Disrupters, Mallory's Byzantine roles run no engine, and Chaos has
# no Byzantine node; Mallory's amnesia restart makes its honest node Byzantine mid-run.
BYZZFUZZ_HOOK = """\
    // [statelens] ByzzFuzz runs a real engine at `BYZANTINE_IDX` and rewrites what it
    // sends: publish it as compromised before any engine starts, and check that every
    // scheme's own index matches its position in `participants`.
    commonware_consensus::simplex::statelens::set_compromised([BYZANTINE_IDX]);
    for (idx, scheme) in schemes.iter().enumerate() {
        assert_eq!(
            commonware_cryptography::certificate::Scheme::me(scheme),
            Some(commonware_utils::Participant::from_usize(idx)),
            "[statelens] participant index mismatch"
        );
    }"""
CHAOS_TWINS_HOOK = """\
        // [statelens] The twin runs two real engines under `byz`: publish it as
        // compromised before any engine starts, and check that every scheme's own
        // index matches its position in `participants`.
        commonware_consensus::simplex::statelens::set_compromised([byz]);
        for (idx, scheme) in schemes.iter().enumerate() {
            assert_eq!(
                commonware_cryptography::certificate::Scheme::me(scheme),
                Some(commonware_utils::Participant::from_usize(idx)),
                "[statelens] participant index mismatch"
            );
        }"""
AUDIT_HOOK = """\
                // [statelens] Here a Byzantine participant runs a real engine: publish
                // the Byzantine participants as compromised before it starts, and check
                // that every scheme's own index matches its position in `participants`.
                commonware_consensus::simplex::statelens::set_compromised(0..config.faults as usize);
                for (idx, scheme) in schemes.iter().enumerate() {
                    assert_eq!(
                        commonware_cryptography::certificate::Scheme::me(scheme),
                        Some(commonware_utils::Participant::from_usize(idx)),
                        "[statelens] participant index mismatch"
                    );
                }"""
MALLORY_HOOK = """\
    // [statelens] An amnesia restart brings this node back on empty storage, where it
    // may sign what it signed before, and Mallory counts it as Byzantine from here on:
    // publish it as compromised before the new incarnation starts, and check that its
    // scheme's own index is its position in `participants`.
    if amnesia {
        commonware_consensus::simplex::statelens::set_compromised([mv.idx()]);
        assert_eq!(
            commonware_cryptography::certificate::Scheme::me(mv.scheme()),
            Some(commonware_utils::Participant::from_usize(mv.idx())),
            "[statelens] participant index mismatch"
        );
    }"""
# SPEC section 7.2, edits 9 to 12, made by the simplex profile only.
SIMPLEX_GUARD_ANCHORS = (
    (
        "consensus/fuzz/simplex/src/byzzfuzz/runner.rs",
        "        commonware_consensus_fuzz_core::setup_network::<P>(context, input).await;",
        "after",
        BYZZFUZZ_HOOK,
    ),
    (
        "consensus/fuzz/simplex/src/chaos/twins.rs",
        '        let crash = (0..n).find(|&idx| idx != byz).expect("an honest index exists");',
        "after",
        CHAOS_TWINS_HOOK,
    ),
    (
        "consensus/fuzz/simplex/src/lib.rs",
        "                // A Byzantine participant may behave correctly. For the audit",
        "before",
        AUDIT_HOOK,
    ),
    (
        "consensus/fuzz/simplex/src/mallory/runner.rs",
        "    lifecycle::abort_tasks(mv).await;",
        "after",
        MALLORY_HOOK,
    ),
)
# SPEC section 17.3, edits Q2 and Q3.
QMDB_ANCHORS = (
    ("storage/src/qmdb/mod.rs", "pub mod verify;", "after", "pub mod statelens;"),
    ("storage/Cargo.toml", "thiserror.workspace = true", "after", "sancov.workspace = true"),
) + FRESH_RUN_ANCHORS

# SPEC Appendix B.1: a variant is its target with a reset before the body of
# `fuzz_target!` and a clear after it. The opening line may sit at any indent, and the
# body ends at the first `});` at that indent. A one-line target is first written as a
# block, so the two insertions have a body to go around.
VARIANT_START = re.compile(r"^( *)fuzz_target!\(\|[a-z_]+: [^|]+\| \{$")
VARIANT_ONE_LINE = re.compile(r"^( *)fuzz_target!\(\|([a-z_]+: [^|]+)\| (.+)\);$")
# Appendix B.2: the keys of the original [[bin]] block that a variant's block copies, in order.
BIN_KEYS = ("test", "doc", "bench", "required-features")
# The line of the runtime template where its consensus-only tests start; they run to the
# end of the file, and a profile outside the consensus crate drops them (edit Q1).
RUNTIME_CONSENSUS_ONLY = "// [statelens] consensus only:"
# SPEC section 9.6: the read side of the runtime module. Scaffolds call it; instrumentation
# never does (section 7.5), and synthesis adds no call of it under the editable roots
# (guard 3 of section 18.6.1).
READ_SIDE = (
    "watch",
    "unwatch",
    "tick",
    "mark",
    "current_run",
    "truncated",
    "seen",
    "sites",
    "observations",
    "note",
)
RUNTIME_ALIAS = re.compile(
    r"\bstatelens\s+as\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"|\bstatelens\s*::\s*\{[^}]*?\bself\s+as\s+([A-Za-z_][A-Za-z0-9_]*)"
)

# SPEC section 5.5: where synthesis declares `target_states` in the fuzz package's crate
# root, as an anchored edit (file, anchor, "after", text) (section 18.6.2).
SIMPLEX_SCAFFOLD = (
    "consensus/fuzz/simplex/src/lib.rs",
    "pub mod state_cov;",
    "after",
    "pub mod target_states;",
)
MARSHAL_SCAFFOLD = (
    "consensus/fuzz/marshal/src/lib.rs",
    "pub mod scenarios;",
    "after",
    '#[cfg(feature = "mocks")]\npub mod target_states;',
)
# A scaffold's thin target, `<base>_tsNNNN_statelens` (SPEC section 18.7).
SCAFFOLD_NAME = re.compile(r"^(?P<base>[a-z][a-z0-9_]*)_ts(?P<number>\d{4,})_statelens$")
# The unit of synthesis is the pair (card, base): its key, `TS-NNNN_<base>`, names its
# reach outputs and records, and its module is `tsNNNN_<base>` (SPEC section 18.6.2).
PAIR_KEY = re.compile(r"^(?P<card>TS-\d{4,})_(?P<base>[a-z][a-z0-9_]*)$")
MODULE_NAME = re.compile(r"^ts(?P<number>\d{4,})_(?P<base>[a-z][a-z0-9_]*)$")

# SPEC section 5.5. Each profile names the registries it binds and the crate it
# instruments: where the runtime module goes (`runtime`), the module that declares it
# (`module`), the editable roots, the beacon components as (ACTOR, ACTOR_DIR, subsystem),
# the fuzz package whose targets it derives variants from, its anchored edits and its
# tests. `component_filter` selects the tests that run after the gate and are reported,
# not gated, or is None. `replay_env` goes before NIGHTLY_VERSION in the replay command.
# `scaffold` is the declaration of `target_states` that synthesis inserts, or None for a
# profile Target-State Synthesis refuses.
PROFILES = {
    "simplex": {
        "registries": ("simplex",),
        "crate": "consensus",
        "runtime": STATELENS_RS,
        "module": "simplex",
        "roots": ("consensus/src/simplex/",),
        "warn": ("consensus/src/simplex/mocks/", "consensus/src/simplex/scheme/"),
        "components": (
            ("voter", "consensus/src/simplex/actors/voter", "simplex"),
            ("batcher", "consensus/src/simplex/actors/batcher", "simplex"),
            ("resolver", "consensus/src/simplex/actors/resolver", "simplex"),
        ),
        "package": "consensus/fuzz/simplex",
        "anchors": CONSENSUS_ANCHORS + SIMPLEX_GUARD_ANCHORS,
        "test_filter": SIMPLEX_TEST_FILTER,
        "component_filter": COMPONENT_TEST_FILTER,
        "replay_env": "CONSENSUS_FUZZ_LOG=1",
        "scaffold": SIMPLEX_SCAFFOLD,
    },
    "marshal": {
        "registries": ("simplex", "marshal"),
        "crate": "consensus",
        "runtime": STATELENS_RS,
        "module": "simplex",
        "roots": ("consensus/src/simplex/", "consensus/src/marshal/"),
        "warn": (
            "consensus/src/simplex/mocks/",
            "consensus/src/simplex/scheme/",
            "consensus/src/marshal/mocks/",
        ),
        "components": (
            ("voter", "consensus/src/simplex/actors/voter", "simplex"),
            ("batcher", "consensus/src/simplex/actors/batcher", "simplex"),
            ("resolver", "consensus/src/simplex/actors/resolver", "simplex"),
            ("marshal.core", "consensus/src/marshal/core", "marshal"),
            ("marshal.standard", "consensus/src/marshal/standard", "marshal"),
            ("marshal.coding", "consensus/src/marshal/coding", "marshal"),
        ),
        "package": "consensus/fuzz/marshal",
        "anchors": CONSENSUS_ANCHORS + (WEDGE_ANCHOR,),
        "test_filter": SIMPLEX_TEST_FILTER + " | test(/^marshal::/)",
        "component_filter": COMPONENT_TEST_FILTER,
        "replay_env": "",
        "scaffold": MARSHAL_SCAFFOLD,
    },
    "qmdb": {
        "registries": ("qmdb",),
        "crate": "storage",
        "runtime": QMDB_RS,
        "module": "qmdb",
        "roots": ("storage/src/qmdb/",),
        "warn": ("storage/src/qmdb/benches/",),
        "components": (
            ("qmdb.any", "storage/src/qmdb/any", "qmdb"),
            ("qmdb.current", "storage/src/qmdb/current", "qmdb"),
            ("qmdb.immutable", "storage/src/qmdb/immutable", "qmdb"),
            ("qmdb.keyless", "storage/src/qmdb/keyless", "qmdb"),
            ("qmdb.store", "storage/src/qmdb/store", "qmdb"),
            ("qmdb.sync", "storage/src/qmdb/sync", "qmdb"),
        ),
        "package": "storage/fuzz",
        "anchors": QMDB_ANCHORS,
        "test_filter": "test(/^qmdb::/)",
        "component_filter": None,
        "replay_env": "",
        "scaffold": None,
    },
}

PLAN_TEMPLATE = """\
# StateLens instrumentation plan

- Base commit: {base}
- Agent: {agent}
- Profile: {profile}
- Invariants: {count} ({ids})

## Invariants

## Beacon probes

| Label | File and function | a | b | Beacon |
|---|---|---|---|---|
"""

# The tools a campaign runs besides the agent CLI (SPEC section 5.2).
CAMPAIGN_TOOLS = ("cargo", "cargo-nextest", "cargo-fuzz", "just")

PLACEHOLDER = re.compile(r"\{\{([A-Z_]+)\}\}")
PLAN_HEADING = re.compile(r"^###\s+((?:INV|FALSE)-\d+)\b")
PLAN_STATUS = re.compile(r"^-\s*\**Status\**\s*:\s*\**\s*`?(bound|partial|unbound)\b")
# The one qualifier a status may carry (SPEC section 11).
PLAN_INACTIVE = re.compile(r"\(inactive in the fuzz targets\)")
# The fields of an invariant's plan section (SPEC section 11). A section that binds
# nothing carries only `Status` and `Notes`.
PLAN_FIELD = re.compile(r"^-\s*\**([A-Z][A-Za-z ]*?)\**\s*:\s*(.*)$")
PLAN_FIELDS = (
    "Status",
    "Reading",
    "Sites",
    "Assertions",
    "Probes",
    "Ghost state",
    "Edited lines",
    "Notes",
)
# The verdict of a `Sites` entry. Both are required words, so an entry that says neither
# is reported rather than read as a claim: `unchecked` and `deferred` are not verdicts,
# and a phrase that merely contains `checked` still has to survive the check against the
# code below.
PLAN_UNCHECKED = re.compile(r"\bnot\s+checked\b", re.IGNORECASE)
PLAN_CHECKED = re.compile(r"(?<![A-Za-z0-9_])checked\b", re.IGNORECASE)
# The source a `Sites` entry names. An entry starts where a path appears, so an entry
# wrapped over several lines stays one entry and its `not checked` is not lost. The
# function it names is checked too, because a dispatch and the commit it leads to are
# often in one file.
PLAN_SITE_PATH = re.compile(r"`([A-Za-z0-9_./-]+\.rs)`")
PLAN_SITE_FN = re.compile(r"`((?:[A-Za-z0-9_]+::)*[a-z_][A-Za-z0-9_]*)`")
PLAN_FUNCTION = re.compile(
    r"^\s*(?:(?:pub(?:\([^)]*\))?|const|unsafe|async|extern(?:\s+\"[^\"]*\")?)\s+)*"
    r"fn\s+([a-z_][A-Za-z0-9_]*)",
    re.M,
)
# An assertion macro naming an invariant. The id is a separate line of the call, so the
# search spans the arguments, and stops at the first `;` so it cannot run into the next
# statement.
PLAN_ASSERTION = re.compile(r"\bsl_(?:assert|implies)!\s*\([^;]{0,400}?\"((?:INV|FALSE)-\d+)\"", re.S)

Materialization = collections.namedtuple("Materialization", "create modify targets anchors")


class Abort(Exception):
    """Stops a command with an exit code."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class Parser(argparse.ArgumentParser):
    """Argument parser that exits with code 1 on usage errors."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def say(message):
    print(f"statelens: {message}", flush=True)


def repo_root():
    here = Path(__file__).resolve().parent
    output = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=here,
        capture_output=True,
        text=True,
        check=True,
    )
    return Path(output.stdout.strip())


def git(repo, *args):
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def id_number(path):
    match = re.search(r"-(\d+)\.md$", path.name)
    return int(match.group(1)) if match else 0


def by_id(path):
    return (id_number(path), path.name)


def porcelain_entries(output):
    """(status, path) for `git status --porcelain -z` output.

    A rename or copy carries its source as the next record, and that source is
    reported as its own entry so callers see both paths.
    """
    entries = output.split("\0")
    found = []
    index = 0
    while index < len(entries):
        entry = entries[index]
        index += 1
        if len(entry) < 4:
            continue
        status, path = entry[:2], entry[3:]
        found.append((status, path))
        if "R" in status or "C" in status:
            if index < len(entries) and entries[index]:
                found.append((status, entries[index]))
            index += 1
    return found


def porcelain_paths(output):
    """Returns the paths of `git status --porcelain -z` output, including rename sources."""
    return [path for _status, path in porcelain_entries(output)]


CONFIG_LOCAL = "config.local.env"


def load_config(sl_dir):
    """Reads config.env, then config.local.env, then the environment.

    `config.env` is tracked and holds the defaults; `config.local.env` is ignored
    by git and holds what is specific to one machine or private, above all a
    knowledge-base root, which names a corpus of findings nobody should commit by
    filling in a tracked file. A non-empty environment variable overrides both.
    """
    values = {key: "" for key in CONFIG_KEYS}
    for name in ("config.env", CONFIG_LOCAL):
        path = sl_dir / name
        if not path.is_file():
            continue
        for number, raw in enumerate(path.read_text().splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.partition("=")
            if not sep:
                raise Abort(1, f"{name}:{number}: expected KEY=VALUE")
            values[key.strip()] = value.strip()
    for key in list(values):
        if os.environ.get(key):
            values[key] = os.environ[key]
    return values


def pinned_nightly(repo):
    workflow = repo / ".github/workflows/slow.yml"
    if workflow.is_file():
        for line in workflow.read_text().splitlines():
            match = re.match(r"^\s*NIGHTLY_VERSION:\s*(\S+)", line)
            if match:
                return match.group(1)
    return "nightly"


def cargo(toolchain):
    return ["cargo"] + ([f"+{toolchain}"] if toolchain else [])


# The rendering nextest_run parses, forced by flags, which override what the environment
# and nextest's user config set (NEXTEST_STATUS_LEVEL, CARGO_TERM_COLOR and the like). A
# passing test's output is never shown, and a failing test's comes before the summary.
NEXTEST_RENDERING = (
    "--color",
    "never",
    "--message-format",
    "human",
    "--status-level",
    "pass",
    "--final-status-level",
    "fail",
    "--success-output",
    "never",
    "--failure-output",
    "immediate",
)


def nextest_command(toolchain, crate, expression):
    return (
        cargo(toolchain)
        + ["nextest", "run", "-p", f"commonware-{crate}", "--lib", "--no-fail-fast"]
        + ["--ignore-default-filter", *NEXTEST_RENDERING, "-E", expression]
    )


def gate_test_command(toolchain, profile):
    """The test gate's command (SPEC section 7.7) for `profile`."""
    settings = PROFILES[profile]
    return nextest_command(toolchain, settings["crate"], settings["test_filter"])


def component_test_command(toolchain, profile):
    """The command for the component tests the gate leaves out (SPEC section 7.7), or None
    when the profile has none."""
    settings = PROFILES[profile]
    if settings["component_filter"] is None:
        return None
    return nextest_command(toolchain, settings["crate"], settings["component_filter"])


def failed_tests(lines):
    """The tests nextest reports as failed, timed out or killed, each once, in order."""
    names = []
    for line in lines:
        if re.match(r"^\s+(?:FAIL|TIMEOUT|ABORT|SIG[A-Z]+) \[", line):
            name = line.split()[-1]
            if name not in names:
                names.append(name)
    return names


ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
# A test's status line: a retry prefixes `TRY <n>`, a counter `(<i>/<n>)` may follow the
# duration, and the test's name is the last word.
NEXTEST_STATUS = re.compile(r"^\s*(?:TRY \d+ )?([A-Z][A-Z0-9 +-]*?) \[[^\]]*\] .*?(\S+)\s*$")
NEXTEST_PASSING = ("PASS", "LEAK")
NEXTEST_FAILING = re.compile(r"FAIL|FAIL \+ LEAK|LEAK-FAIL|XFAIL|TIMEOUT|ABORT|SIG[A-Z0-9]+")
NEXTEST_SUMMARY = re.compile(r"^\s*Summary \[[^\]]*\] (?:(\d+)/)?(\d+) tests? run: (.*)$")
NEXTEST_COUNT = re.compile(r"(\d+) (passed|exec failed|failed|timed out)")


def nextest_run(text, code):
    """The tests one run of the test gate passed and failed, from its log, checked against
    nextest's own summary line (SPEC section 18.6.1, guard 5).

    Returns ({"passed": set, "failed": set}, None), or (None, problem) when the log cannot be
    trusted: no single summary line, as after a build failure; a run that stopped early or
    ran no test; status lines the summary's counts do not match; or an exit code the failures
    do not explain. `code` None stands for a nonzero exit code that was not recorded. The
    failed tests are the ones nextest lists after its summary, where no test output reaches.
    """
    lines = [ANSI_ESCAPE.sub("", line) for line in text.splitlines()]
    found = [index for index, line in enumerate(lines) if NEXTEST_SUMMARY.match(line)]
    if len(found) != 1:
        return None, "no nextest summary line" if not found else "more than one summary line"
    at = found[0]
    finished, total, tail = NEXTEST_SUMMARY.match(lines[at]).groups()
    if finished is not None and finished != total:
        return None, f"the run stopped after {finished} of {total} tests"
    if int(total) == 0:
        return None, "the run ran no test"
    counts = collections.Counter()
    for number, kind in NEXTEST_COUNT.findall(tail):
        counts[kind] += int(number)
    failures = counts["failed"] + counts["exec failed"] + counts["timed out"]
    if counts["passed"] + failures != int(total):
        return None, f"the summary does not add up: {lines[at].strip()}"
    last = {}
    for line in lines[:at]:
        match = NEXTEST_STATUS.match(line)
        if match:
            last[match.group(2)] = match.group(1)
    failed = set()
    for line in lines[at + 1 :]:
        match = NEXTEST_STATUS.match(line)
        if match and NEXTEST_FAILING.fullmatch(match.group(1)):
            failed.add(match.group(2))
    passed = {name for name, status in last.items() if status in NEXTEST_PASSING} - failed
    if (len(passed), len(failed)) != (counts["passed"], failures):
        return None, (
            f"{len(passed)} passed and {len(failed)} failed by the status lines, "
            f"{counts['passed']} and {failures} by the summary"
        )
    if code == 0 and failed:
        return None, f"exit code 0 with {len(failed)} failed test(s)"
    if code != 0 and not failed:
        return None, f"exit code {code if code is not None else 'nonzero'} with no failed test"
    return {"passed": passed, "failed": failed}, None


def agent_name(config, flag):
    agent = flag or config["STATELENS_AGENT"]
    if agent not in AGENTS:
        raise Abort(1, f"unknown agent {agent!r}; use claude or codex")
    return agent


def check_agent_cli(agent):
    if shutil.which(agent) is None:
        raise Abort(2, f"the {agent} CLI is not on PATH")


def resolve_agent(config, flag):
    agent = agent_name(config, flag)
    check_agent_cli(agent)
    return agent


def agent_model(config, agent):
    key = "STATELENS_CLAUDE_MODEL" if agent == "claude" else "STATELENS_CODEX_MODEL"
    return config[key]


def agent_effort(config, agent):
    """The reasoning effort to ask the agent CLI for; empty means its own default.

    The value is passed through rather than checked here: each CLI owns its own
    levels, and a wrong one is the CLI's to reject.
    """
    key = "STATELENS_CLAUDE_EFFORT" if agent == "claude" else "STATELENS_CODEX_EFFORT"
    return config[key]


def agent_command(config, agent, phase, repo):
    """Non-interactive agent invocation (SPEC section 12); the prompt goes to stdin."""
    model = agent_model(config, agent)
    effort = agent_effort(config, agent)
    if agent == "claude":
        command = ["claude", "-p", "--output-format", "text"]
        if model:
            command += ["--model", model]
        if effort:
            command += ["--effort", effort]
        if phase in (1, "kb"):
            command += ["--permission-mode", "acceptEdits", "--allowedTools"]
            command += ["Read", "Grep", "Glob", "Write", "Edit", "WebFetch"]
            if phase == "kb":
                # The corpus is reachable only through the `kb` commands (SPEC section 12).
                command += [f"Bash(python3 {SL}/scripts/statelens.py kb:*)"]
            else:
                command += ["Bash(gh:*)", "Bash(curl:*)"]
        else:
            command += ["--dangerously-skip-permissions"]
        return command
    command = ["codex", "exec", "-C", str(repo)]
    if model:
        command += ["-m", model]
    if effort:
        command += ["-c", f"model_reasoning_effort={effort}"]
    if phase == "kb":
        # No per-tool allowlist: writes stay in the workspace and the network is off.
        command += ["-s", "workspace-write", "-c", "sandbox_workspace_write.network_access=false"]
    elif phase == 1:
        command += ["-s", "workspace-write", "-c", "sandbox_workspace_write.network_access=true"]
    else:
        command += ["--dangerously-bypass-approvals-and-sandbox"]
    return command + ["-"]


def run_logged(command, log_path, cwd, stdin_text=None, echo=True, timeout=None, env=None):
    """Runs a command, copying its output to the console and to `log_path`.

    With `echo` false the output goes to the log only, for a tool whose own
    logging is noise to an operator. The command runs in its own process group.
    With `timeout`, a command still running after that many seconds is killed
    with everything it started, whether or not its own process still runs, and
    its code is None (SPEC section 18.8). An interrupt, or any other exception
    while it runs, kills it the same way before it propagates, so what the
    caller does next never races it. `env` replaces the environment. Returns the
    exit code and the last `ERROR_LINES` lines of output.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    tail = collections.deque(maxlen=ERROR_LINES)
    killed = threading.Event()
    with open(log_path, "w", encoding="utf-8") as log:
        log.write("$ " + shlex.join(command) + "\n")
        log.flush()
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            # Its own process group, so a kill reaches what it started, which would
            # otherwise hold the output pipe open or write after an interrupt restored
            # the tree. The terminal's interrupt then reaches the script alone.
            start_new_session=True,
        )

        def kill():
            # The whole group, whether or not the command's own process still runs: a
            # process it started may outlive it holding the output pipe.
            killed.set()
            with contextlib.suppress(OSError):
                os.killpg(process.pid, signal.SIGKILL)

        timer = None
        if timeout is not None:
            timer = threading.Timer(timeout, kill)
            timer.daemon = True
            timer.start()
        if stdin_text is not None:

            def feed():
                try:
                    process.stdin.write(stdin_text)
                except BrokenPipeError:
                    pass
                finally:
                    try:
                        process.stdin.close()
                    except BrokenPipeError:
                        pass

            threading.Thread(target=feed, daemon=True).start()
        try:
            for line in process.stdout:
                if echo:
                    sys.stdout.write(line)
                    sys.stdout.flush()
                log.write(line)
                tail.append(line.rstrip("\n"))
            process.stdout.close()
            code = process.wait()
        except BaseException:
            # The interrupt did not reach the command in its own group: kill it, with
            # everything it started, and reap it before the caller restores anything.
            kill()
            process.wait()
            raise
        finally:
            if timer is not None:
                timer.cancel()
        if killed.is_set():
            code = None
            log.write(f"statelens: killed after {timeout} s\n")
    return code, list(tail)


def render(text, values):
    def substitute(match):
        key = match.group(1)
        if key not in values:
            raise Abort(2, f"prompt placeholder {{{{{key}}}}} has no value")
        return values[key]

    return PLACEHOLDER.sub(substitute, text)


def compose(sl_dir, first, second, values):
    """Renders two prompt files joined by a blank line."""
    prompts = sl_dir / "prompts"
    text = (prompts / first).read_text() + "\n" + (prompts / second).read_text()
    return render(text, values)


def subsystem_prompt(sl_dir, subsystem, part):
    """The `part` (analyst or instrument) of a subsystem's prompt (SPEC section 13)."""
    path = sl_dir / "prompts" / "subsystems" / f"{subsystem}-{part}.md"
    return path.read_text().rstrip("\n")


def front_matter(text):
    """Returns (front matter dict, index of the closing --- line) or (None, None)."""
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        return None, None
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        return None, None
    values = {}
    for line in lines[1:end]:
        key, sep, value = line.partition(":")
        if sep:
            values[key.strip()] = value.strip()
    return values, end


def title_of(path):
    values, _ = front_matter(path.read_text(errors="replace"))
    return (values or {}).get("title", "")


def id_of(path):
    """The front matter id, or the file stem when there is none (lint rule 9)."""
    values, _ = front_matter(path.read_text(errors="replace"))
    return (values or {}).get("id") or path.stem


def registry_files(sl_dir):
    """Every file lint checks by default (SPEC section 4.6), including misplaced ones."""
    paths = []
    for top in FILE_NAMES:
        root = sl_dir / top
        paths += sorted(root.glob("*.md"), key=by_id)
        for registry in sorted(path for path in root.glob("*") if path.is_dir()):
            paths += sorted(registry.glob("*.md"), key=by_id)
    return paths


def lint_file(path):
    """Checks one registry file against SPEC section 4.6, rules 1 to 8 and 10 to 13.

    A target-state card (section 18.3) is a file of a card tree or, misplaced, one named
    `TS-*`; rules 12 and 13 apply to cards only.
    """
    problems = []
    parent = path.resolve().parent
    registry = parent.name if parent.name in SUBSYSTEMS else None
    card = parent.parent.name in CARD_TREES or path.name.startswith("TS-")
    if parent.name in FILE_NAMES:
        allowed = STATE_SUBSYSTEMS if parent.name in CARD_TREES else SUBSYSTEMS
        problems.append(
            f"lies directly in {parent.name}/; move it to {parent.name}/<subsystem>/, "
            f"where <subsystem> is one of: {', '.join(allowed)}"
        )
    else:
        pattern = FILE_NAMES.get(parent.parent.name)
        known = STATE_SUBSYSTEMS if parent.parent.name in CARD_TREES else SUBSYSTEMS
        if registry not in known or pattern is None or not pattern.match(path.name):
            problems.append(
                "file name must be INV-NNNN.md in invariants/<subsystem>/ or "
                f"{LOCAL_INVARIANTS}/<subsystem>/, or FALSE-NNNN.md in "
                "false-invariants/<subsystem>/, where <subsystem> is one of: "
                + ", ".join(SUBSYSTEMS)
                + f"; or TS-NNNN.md in target-states/<subsystem>/ or {LOCAL_STATES}/"
                "<subsystem>/, where <subsystem> is one of: "
                + ", ".join(STATE_SUBSYSTEMS)
            )
    data = path.read_bytes()
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        problems.append("contains non-ASCII characters")
        text = data.decode("utf-8", errors="replace")
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        return problems + ["does not start with a --- line (front matter)"]
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        return problems + ["front matter is not closed by a --- line"]
    front = {}
    for line in lines[1:end]:
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        if not sep:
            problems.append(f"front matter line is not 'key: value': {line.strip()!r}")
            continue
        front[key.strip()] = value.strip()
    for key in REQUIRED_KEYS:
        if not front.get(key):
            problems.append(f"missing or empty front matter key: {key}")
    for key in front:
        if key not in REQUIRED_KEYS:
            problems.append(f"unknown front matter key: {key}")
    if front.get("id") and front["id"] != path.stem:
        problems.append(f"id {front['id']} does not match the file name")
    kind = front.get("source_kind")
    kinds = CARD_SOURCE_KINDS if card else SOURCE_KINDS
    if kind and kind not in kinds:
        problems.append(f"source_kind must be one of: {', '.join(kinds)}")
    scope = front.get("scope")
    if scope:
        allowed = SCOPES[registry] if registry else ALL_SCOPES
        match = re.fullmatch(r"\[(.*)\]", scope)
        items = [item.strip() for item in match.group(1).split(",")] if match else []
        if not match or not items or any(item not in allowed for item in items):
            owner = f" the {registry} registry's values" if registry else ""
            problems.append(f"scope must be a list of{owner}: {', '.join(allowed)}")
    sections = {}
    order = []
    current = None
    for line in lines[end + 1 :]:
        if line.startswith("## "):
            current = line[3:].strip()
            order.append(current)
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    positions = []
    required = CARD_SECTIONS if card else REQUIRED_SECTIONS
    for name in required:
        if name not in sections:
            problems.append(f"missing section: ## {name}")
        elif not any(line.strip() for line in sections[name]):
            problems.append(f"empty section: ## {name}")
        else:
            positions.append(order.index(name))
    if positions != sorted(positions):
        problems.append(
            f"sections {', '.join(required[:-1])} and {required[-1]} must be in this order"
        )
    if card:
        events = None
        if any(line.strip() for line in sections.get("History", ())):
            events, found = history_problems(sections["History"])
            problems += found
        if any(line.strip() for line in sections.get("Knobs", ())):
            problems += knobs_problems(sections["Knobs"], events)
    repo = git_toplevel(path.resolve().parent)
    body, excerpts = split_excerpts(text)
    problems += line_reference_problems(body, repo)
    if repo is not None and (excerpts or pinned_ranges(body)):
        if with_excerpts(text, repo).rstrip("\n") != text.rstrip("\n"):
            problems.append(
                "the Source excerpts section is missing or does not match the pinned "
                f"citations; regenerate it with `just excerpts {path.name}` (rule 11)"
            )
    return problems


# Rules 12 and 13 (SPEC section 18.3): the History and Knobs of a target-state card.
HISTORY_EVENT = re.compile(r"^E(\d+)\.(?:\s+(.*))?$")
HISTORY_ACTOR = re.compile(r"^([A-Za-z][A-Za-z0-9]*):")
HISTORY_ENTITIES = re.compile(r"^(Check|Holds) \(([^)]*)\)")
HISTORY_ENTITY = re.compile(r"^([A-Za-z][A-Za-z0-9]*)(?: as E(\d+))?$")
HISTORY_ORDER = re.compile(r"^E(\d+) and E(\d+) in either order\.?$")
EVENT_NAME = re.compile(r"\bE(\d+)\b")
KNOB_HEADER = ["Knob", "Event", "Domain", "Source value"]
KNOB_LIMIT = 16


def history_problems(lines):
    """Rule 12: the History's events, their Check and Holds lines, and the Order line.

    Returns (the number of events, problems).
    """
    events, _, problems = history_parse(lines)
    return len(events), problems


# A History event (SPEC section 18.3): its actor, `harness` or a replica's name, and the
# entities of its Check or Holds line as (name, k of `as Ek` or None).
HistoryEvent = collections.namedtuple("HistoryEvent", "actor entities")
# A card's History: its ID, its events E1 to En, and the pairs `Order:` frees, as
# frozensets of two event numbers.
History = collections.namedtuple("History", "id events free")


def history_parse(lines):
    """Parses a card's History and checks rule 12: (events, free pairs, problems).

    An event is `E<k>. <actor>: ...` at the start of a line; an indented line starting
    with `Check` or `Holds` belongs to the event above it, and any other indented line
    continues the line above it. Each event is a HistoryEvent; `free` holds the pairs of
    the Order: line.
    """
    problems = []
    events = []
    order = None
    last = None
    for raw in lines:
        text = raw.strip()
        if not text:
            continue
        if raw[0] in " \t":
            if text.startswith(("Check", "Holds")):
                word = text[:5]
                if order is not None:
                    problems.append(f"a {word} line follows the Order: line, which must be last")
                elif not events:
                    problems.append(f"a {word} line comes before E1.")
                else:
                    match = HISTORY_ENTITIES.match(text)
                    if not match:
                        problems.append(
                            f"E{len(events)}'s {word} line does not start with the entities it "
                            f"binds in parentheses, as in `{word} (R, v as E1): ...`"
                        )
                    events[-1]["lines"].append((word, match.group(2) if match else None))
                last = "line"
            elif text.startswith("Order:"):
                problems.append("the Order: line starts at the beginning of a line, not indented")
            elif last is None:
                problems.append(f"the indented line `{text[:40]}` comes before E1.")
            elif last == "order":
                order += " " + text
            continue
        if raw.startswith("Order:"):
            if order is not None:
                problems.append("the History has more than one Order: line")
            order = raw[len("Order:"):].strip()
            last = "order"
            continue
        match = HISTORY_EVENT.match(raw.rstrip())
        if not match:
            problems.append(
                f"`{text[:40]}` is neither an event `E<k>. <actor>: ...`, an indented Check, "
                "Holds or continuation line, nor the Order: line"
            )
            continue
        number, expected = int(match.group(1)), len(events) + 1
        if order is not None:
            problems.append(f"E{number}. follows the Order: line, which must be last")
        if number != expected:
            problems.append(
                f"E{number}. where E{expected}. comes next: events are numbered E1. to En. "
                "without a gap"
            )
        actor = HISTORY_ACTOR.match(match.group(2) or "")
        if not actor:
            problems.append(
                f"E{expected}. does not start with its actor and a colon: `harness:` or the "
                "name of the honest replica that acts"
            )
        events.append({"actor": actor.group(1) if actor else None, "lines": []})
        last = "event"
    if not events:
        problems.append("the History has no event; number them from E1.")
    names = []
    parsed = []
    for index, event in enumerate(events, 1):
        word = "Holds" if index == len(events) else "Check"
        found = [kind for kind, _ in event["lines"]]
        if found != [word]:
            problems.append(
                f"E{index}. needs exactly one indented {word} line, and has: "
                + (", ".join(found) or "none")
            )
        own = set()
        listed = []
        for kind, entities in event["lines"]:
            if entities is None:
                continue
            if not entities.strip():
                problems.append(f"E{index}.'s {kind} line has an empty entity list")
                continue
            for item in (part.strip() for part in entities.split(",")):
                entity = HISTORY_ENTITY.match(item)
                if not entity:
                    problems.append(
                        f"E{index}.'s {kind} line lists `{item}`; an entity is a name, "
                        "optionally followed by ` as E<k>`"
                    )
                    continue
                name, earlier = entity.group(1), entity.group(2)
                own.add(name)
                listed.append((name, int(earlier) if earlier else None))
                if earlier is None:
                    continue
                earlier = int(earlier)
                if not 1 <= earlier < index:
                    problems.append(f"E{index}.: `{item}` names E{earlier}, not an earlier event")
                elif name not in names[earlier - 1]:
                    problems.append(
                        f"E{index}.: `{item}`, but E{earlier}.'s entity list does not hold {name}"
                    )
        names.append(own)
        actor = event["actor"]
        if actor and actor != "harness" and event["lines"] and actor not in own:
            problems.append(
                f"E{index}.'s actor {actor} is neither harness nor a name in its own entity list"
            )
        if actor and actor != "harness" and not actor[0].isupper():
            problems.append(
                f"E{index}.'s actor {actor} is a replica, whose name starts with a capital "
                "letter: the reach check tells replicas apart by it"
            )
        parsed.append(HistoryEvent(actor, tuple(listed)))
    free = set()
    if order is not None:
        for part in (part.strip() for part in order.split(";")):
            pair = HISTORY_ORDER.match(part)
            if not pair:
                problems.append(f"Order: `{part}` is not `Ei and Ej in either order`")
                continue
            for number in (int(pair.group(1)), int(pair.group(2))):
                if not 1 <= number <= len(events):
                    problems.append(f"Order: names E{number}, which the History does not define")
            free.add(frozenset((int(pair.group(1)), int(pair.group(2)))))
    return parsed, free, [f"{problem} (rule 12)" for problem in problems]


def card_history(text):
    """The History of a card's text (SPEC section 18.3), with its ID. A card whose History
    breaks rule 12 is a usage error; synthesis lints its cards first."""
    values, end = front_matter(text)
    card = (values or {}).get("id", "")
    body = text.split("\n")[end + 1 :] if end is not None else text.split("\n")
    lines, inside = [], False
    for line in body:
        if line.startswith("## "):
            inside = line[3:].strip() == "History"
        elif inside:
            lines.append(line)
    events, free, problems = history_parse(lines)
    if not re.fullmatch(r"TS-\d{4,}", card) or problems:
        raise Abort(1, f"card {card or '?'}: " + "; ".join(problems or ["no TS- id"]))
    return History(card, events, free)


def table_cells(line):
    """The stripped cells of a Markdown table row, or None when `line` is not one."""
    text = line.strip()
    if len(text) < 2 or not (text.startswith("|") and text.endswith("|")):
        return None
    return [cell.strip() for cell in text[1:-1].split("|")]


def knobs_problems(lines, events):
    """Rule 13: `None.`, or the knob table: its header, 1 to 16 rows with no empty cell,
    and Event cells that name only events of the History, which has `events` of them."""
    rows = [line.strip() for line in lines if line.strip()]
    if rows == ["None."]:
        return []
    if table_cells(rows[0]) != KNOB_HEADER:
        return [
            "Knobs must be the line `None.` or a table with the header "
            "`| Knob | Event | Domain | Source value |` (rule 13)"
        ]
    problems = []
    separator = table_cells(rows[1]) if len(rows) > 1 else None
    if separator and len(separator) == 4 and all(re.fullmatch(r":?-+:?", c) for c in separator):
        body = rows[2:]
    else:
        problems.append("the Knobs table needs the line `|---|---|---|---|` under its header")
        body = rows[1:]
    if not 1 <= len(body) <= KNOB_LIMIT:
        problems.append(
            f"the Knobs table has {len(body)} row(s); it takes 1 to {KNOB_LIMIT}, one byte each"
        )
    for row in body:
        cells = table_cells(row)
        if cells is None or len(cells) != 4:
            problems.append(f"Knobs row `{row[:40]}` does not have the four cells of the header")
            continue
        if not all(cells):
            problems.append(f"Knobs row `{row[:40]}` has an empty cell")
        if not events or not cells[1]:
            continue
        named = [int(number) for number in EVENT_NAME.findall(cells[1])]
        if not named:
            problems.append(f"knob {cells[0]}: the Event cell `{cells[1]}` names no event")
        for number in named:
            if not 1 <= number <= events:
                problems.append(
                    f"knob {cells[0]}: the Event cell names E{number}, which the History "
                    "does not define"
                )
    return [f"{problem} (rule 13)" for problem in problems]


# Rule 10 (SPEC section 4.6). A line number means something only at one commit, so it
# is written `path:line@commit`, with the path from the repository root: `line` may be
# a range or a list of them. The path is matched only where it starts a word, so the
# host of a URL is not read as one.
LINE_REFERENCE = re.compile(
    r"(?<![\w/.-])((?:[\w.-]+/)*[\w.-]+\.[A-Za-z]{1,5})"
    r":(\d+(?:-\d+)?(?:,\s?\d+(?:-\d+)?)*)(?:@([0-9a-f]{7,40})\b)?"
)
BARE_LINES = re.compile(r"\blines? \d+", re.I)
BRANCH_PERMALINK = re.compile(
    r"https?://github\.com/[^\s)`]+?/blob/(?![0-9a-f]{7,40}/)[^/\s)`]+/[^\s)`#]+#L\d+"
)


def git_toplevel(directory):
    """The root of the git work tree holding `directory`, or None outside one."""
    try:
        done = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True,
        )
    except OSError:
        return None
    return Path(done.stdout.strip()) if done.returncode == 0 else None


def line_reference_problems(text, repo):
    """Rule 10: every line number names its file and the commit it was read at.

    Inside a git clone a pinned reference is also resolved: the path, read from the
    repository root, must exist at the commit, and the lines must lie within it. A
    reference that names no commit, a bare "line N", and a GitHub `#L` link into a
    branch are reported wherever they occur, because each points at different code
    as the tree changes.
    """
    problems = []
    for match in LINE_REFERENCE.finditer(text):
        path, spec, commit = match.group(1), match.group(2), match.group(3)
        if commit is None:
            problems.append(
                f"cites `{path}:{spec}` without a commit; write `<path from the repository "
                f"root>:{spec}@<commit>`, or name the section or item instead (rule 10)"
            )
            continue
        if repo is None:
            continue
        lines = git_file(repo, commit, path)
        if lines is None:
            problems.append(
                f"cites `{path}:{spec}@{commit}`, but no file {path} exists at {commit} in "
                "this clone; give the path from the repository root and a commit it has "
                "(rule 10)"
            )
            continue
        last = max(int(number) for number in re.findall(r"\d+", spec))
        if last > len(lines):
            problems.append(
                f"cites `{path}:{spec}@{commit}`, but {path} has {len(lines)} lines there "
                "(rule 10)"
            )
    for match in BARE_LINES.finditer(text):
        problems.append(
            f"says `{match.group(0)}` without its file and commit; write "
            "`path:line@<commit>`, or name the section or item instead (rule 10)"
        )
    for match in BRANCH_PERMALINK.finditer(text):
        problems.append(
            f"links `{match.group(0)}`, a line of a branch, which moves; link a commit "
            "instead (rule 10)"
        )
    return problems


_GIT_FILES = {}


def git_file(repo, commit, path):
    """The lines of `path` at `commit` in the clone at `repo`, or None when it has none."""
    key = (str(repo), commit, path)
    if key not in _GIT_FILES:
        done = subprocess.run(
            ["git", "-C", str(repo), "show", f"{commit}:{path}"],
            capture_output=True, text=True, errors="replace",
        )
        lines = done.stdout.split("\n") if done.returncode == 0 else None
        if lines and lines[-1] == "":
            lines.pop()
        _GIT_FILES[key] = lines
    return _GIT_FILES[key]


# The Source excerpts section (SPEC section 4.3, lint rule 11): the lines an invariant
# pins, as they read at their commits, so a reader sees what it was written against
# without fetching anything. It is the last section, and the script writes it.
EXCERPTS = "## Source excerpts"
EXCERPTS_NOTE = (
    "Generated by `statelens.py excerpts` from the pinned citations above: each cited range as\n"
    "it reads at the commit it names. They show the code this invariant was written against,\n"
    "not today's code. Edit the citations, not this section."
)
EXCERPT_LANGUAGES = {".rs": "rust", ".toml": "toml", ".md": "markdown", ".py": "python"}


def split_excerpts(text):
    """(`text` before its Source excerpts section, the section), the section "" if absent."""
    if text.startswith(EXCERPTS + "\n"):
        return "", text
    index = text.find("\n" + EXCERPTS + "\n")
    if index < 0:
        return text, ""
    return text[: index + 1], text[index + 1 :]


def pinned_ranges(text):
    """(path, commit, first, last) of every pinned citation in `text`.

    Ranges of one file at one commit are merged when they overlap or lie at most one line
    apart, so a heading and the paragraph below it make one excerpt. Files keep the order
    of their first citation.
    """
    order, spans = [], {}
    for match in LINE_REFERENCE.finditer(text):
        path, spec, commit = match.group(1), match.group(2), match.group(3)
        if commit is None:
            continue
        key = (path, commit)
        if key not in spans:
            spans[key] = []
            order.append(key)
        for part in spec.split(","):
            first, _, last = part.strip().partition("-")
            spans[key].append((int(first), int(last or first)))
    ranges = []
    for key in order:
        merged = []
        for first, last in sorted(spans[key]):
            if merged and first <= merged[-1][1] + 2:
                merged[-1] = (merged[-1][0], max(merged[-1][1], last))
            else:
                merged.append((first, last))
        ranges += [(key[0], key[1], first, last) for first, last in merged]
    return ranges


def excerpt_section(text, repo):
    """The Source excerpts section for the pinned citations of `text`; "" if it pins none.

    The lines are copied as they are, except that a non-ASCII character is written as a
    `\\u` escape, which keeps the registry ASCII (lint rule 8). A citation that does not
    resolve is left out, and lint rule 10 reports it.
    """
    blocks = []
    for path, commit, first, last in pinned_ranges(text):
        lines = git_file(repo, commit, path)
        if lines is None or first < 1 or last > len(lines):
            continue
        body = [
            line.encode("ascii", "backslashreplace").decode("ascii")
            for line in lines[first - 1 : last]
        ]
        fence = "```"
        while any(fence in line for line in body):
            fence += "`"
        where = f"{first}-{last}" if last != first else str(first)
        language = EXCERPT_LANGUAGES.get(Path(path).suffix, "")
        blocks.append(
            f"`{path}:{where}@{commit}`\n{fence}{language}\n" + "\n".join(body) + f"\n{fence}"
        )
    if not blocks:
        return ""
    return f"{EXCERPTS}\n{EXCERPTS_NOTE}\n\n" + "\n\n".join(blocks) + "\n"


def with_excerpts(text, repo):
    """`text` with its Source excerpts section written afresh from its pinned citations."""
    body, _section = split_excerpts(text)
    body = body.rstrip("\n") + "\n"
    section = excerpt_section(body, repo)
    return body + ("\n" + section if section else "")


def cmd_excerpts(args):
    """Writes the Source excerpts section of invariant files (SPEC section 4.3)."""
    repo = repo_root()
    sl_dir = repo / SL
    paths = [Path(path) for path in args.paths] if args.paths else registry_files(sl_dir)
    stale = []
    for path in paths:
        text = path.read_text()
        body, section = split_excerpts(text)
        if not section and not pinned_ranges(body):
            continue
        fresh = with_excerpts(text, repo)
        if fresh.rstrip("\n") == text.rstrip("\n"):
            continue
        stale.append(path)
        if not args.check:
            path.write_text(fresh)
    state = "out of date" if args.check else "rewritten"
    for path in stale:
        print(f"{path}: Source excerpts {state}", flush=True)
    say(f"excerpts: {len(stale)} of {len(paths)} file(s) {state}")
    return 3 if args.check and stale else 0


def lint_paths(paths, others=()):
    """Lints `paths`; their IDs must not repeat among `paths` and `others` (rule 9)."""
    ids = {}
    for path in list(paths) + list(others):
        key = path.resolve()
        if key not in ids and path.is_file():
            ids[key] = (id_of(path), path)
    owners = collections.defaultdict(list)
    for file_id, path in ids.values():
        owners[file_id].append(path)
    count = 0
    for path in paths:
        if not path.is_file():
            problems = ["not a file"]
        else:
            problems = lint_file(path)
            file_id = ids[path.resolve()][0]
            same = [other for other in owners[file_id] if other.resolve() != path.resolve()]
            if same:
                problems.append(
                    f"id {file_id} is also used by {', '.join(str(other) for other in same)}"
                )
        for problem in problems:
            print(f"{path}: {problem}", flush=True)
            count += 1
    return count


def cmd_lint(args):
    sl_dir = repo_root() / SL
    registries = registry_files(sl_dir)
    paths = [Path(path) for path in args.paths] if args.paths else registries
    count = lint_paths(paths, registries)
    say(f"lint: {len(paths)} file(s), {count} problem(s)")
    return 3 if count else 0


def next_id(sl_dir, prefix):
    """1 + the highest number of `prefix` (INV, FALSE or TS) over every tree that uses it,
    local ones included (SPEC section 4.1)."""
    paths = []
    for top in ID_TREES[prefix]:
        root = sl_dir / top
        paths += list(root.glob(f"{prefix}-*.md")) + list(root.glob(f"*/{prefix}-*.md"))
    numbers = [id_number(path) for path in paths]
    return f"{prefix}-{max(numbers, default=0) + 1:04d}"


def registry_invariants(sl_dir, registry, with_false=False):
    """The invariants a campaign binds for `registry`, by ID: the tracked registry, the
    local one and, with `with_false`, the false invariants (SPEC section 7.1)."""
    roots = [(sl_dir / "invariants" / registry, "INV-*.md")]
    roots.append((sl_dir / LOCAL_INVARIANTS / registry, "INV-*.md"))
    if with_false:
        roots.append((sl_dir / "false-invariants" / registry, "FALSE-*.md"))
    paths = [path for root, pattern in roots for path in root.glob(pattern)]
    return sorted(paths, key=lambda path: (path.name.startswith("FALSE-"), id_number(path)))


def select_invariants(profile, registries, invariants, selection):
    """The `(registry, path)` pairs of `invariants` that `--invariants` names, in the
    order they were collected (SPEC section 7.1). Each item of `selection` is a
    comma-separated list of `<registry>/INV-NNNN` ids (`FALSE-NNNN` when those are
    collected); a bare `INV-NNNN` is accepted only when the profile binds one registry.
    An id of another registry, one no file provides, or a list that names nothing is a
    setup failure that lists what can be selected."""
    available = [f"{registry}/{path.stem}" for registry, path in invariants]
    listing = "available: " + (", ".join(available) or "none")
    wanted = set()
    for item in selection:
        for name in filter(None, (part.strip() for part in item.split(","))):
            if "/" not in name:
                if len(registries) != 1:
                    raise Abort(
                        2,
                        f"--invariants: {name} is a bare id, but the {profile} profile binds "
                        f"{len(registries)} registries ({', '.join(registries)}); write "
                        f"<registry>/{name}",
                    )
                name = f"{registries[0]}/{name}"
            registry = name.split("/", 1)[0]
            if registry not in registries:
                raise Abort(
                    2,
                    f"--invariants: the {profile} profile does not bind the {registry} "
                    f"registry; {listing}",
                )
            if name not in available:
                raise Abort(2, f"--invariants: no invariant file provides {name}; {listing}")
            wanted.add(name)
    if not wanted:
        raise Abort(2, f"--invariants: the list selects no invariant; {listing}")
    return [
        (registry, path) for registry, path in invariants if f"{registry}/{path.stem}" in wanted
    ]


def paper_text(repo, sl_dir, source):
    """Converts a local PDF source to text; returns the text path or None."""
    location = Path(source.split("#", 1)[0])
    path = location if location.is_absolute() else repo / location
    if path.suffix.lower() != ".pdf" or not path.is_file():
        return None
    # The digest keeps papers with the same file name in different directories apart.
    digest = hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:10]
    output = sl_dir / "extract" / "papers" / f"{path.stem}-{digest}.txt"
    output.parent.mkdir(parents=True, exist_ok=True)
    if shutil.which("pdftotext"):
        if subprocess.run(["pdftotext", "-layout", str(path), str(output)]).returncode == 0:
            return output
    try:
        import pypdf
    except ImportError:
        return None
    reader = pypdf.PdfReader(str(path))
    output.write_text("\n\n".join(page.extract_text() or "" for page in reader.pages))
    return output


def extraction_count(number, states=False):
    """The COUNT placeholder: what `--number` asks of the analyst (SPEC section 6.2)."""
    if states:
        if number is None:
            return "Write as many cards as the sources justify; zero is a valid result."
        return (
            f"Write {number} card(s): the {number} target states the sources justify best, "
            f"whose reaching would matter most. If they justify fewer than {number}, write "
            f"fewer and say why in your reply. Never invent or split a target state to reach "
            f"{number}."
        )
    if number is None:
        return "Write as many invariants as the sources justify; zero is a valid result."
    return (
        f"Write {number} invariant(s): the {number} the sources justify best, whose "
        f"violation would matter most. If they justify fewer than {number}, write fewer "
        f"and say why in your reply. Never invent or split an invariant to reach {number}."
    )


def extraction_destination(kind, registry, states=False, local=False):
    """Where Phase 1 writes: the local registry for findings (R-KB-6), else the registry.

    Cards go to the local card registry when `local`, which `private_reason` decides.
    """
    if states:
        return SL / (LOCAL_STATES if local else "target-states") / registry
    return SL / (LOCAL_INVARIANTS if kind == "kb" else "invariants") / registry


def local_path(repo, source):
    """A source as a path: relative ones from the repository root, `~` expanded."""
    path = Path(source).expanduser()
    return path if path.is_absolute() else repo / path


def private_reason(repo, kind, sources, local):
    """Why an extraction's cards go to the local card registry, or None (SPEC 18.4).

    Routing is by disclosure, not location: a finding or a text is not public, nor is a
    path outside the repository, nor a source the operator marks with --local, such as a
    private advisory or a private repository. An issue is a URL or `owner/repo#N`.
    """
    if local:
        return "the run was given --local"
    if kind in ("kb", "text"):
        return f"a {kind} source is not public"
    if kind == "issue":
        return None
    for source in sources:
        if "://" in source:
            continue
        location = re.sub(r"(#.*|:\d+(?:-\d+)?)$", "", source)
        if not inside_repo(repo, local_path(repo, location)):
            return f"{source} lies outside the repository"
    return None


def check_test_sources(repo, registry, sources):
    """A `test` source is `path:line` or `path:start-end` in a file under the registry's
    source or its profile's fuzz package, where its tests are (SPEC section 18.4). The
    file exists at HEAD, where a card pins its citations (lint rule 10): an untracked or
    merely staged test could never be cited."""
    roots = (SOURCES[registry], PROFILES[registry]["package"])
    for source in sources:
        match = re.fullmatch(r"(.+):(\d+)(?:-(\d+))?", source)
        target = local_path(repo, match.group(1)).resolve() if match else None
        if target is not None and target.is_file() and any(
            (repo / root).resolve() in target.parents for root in roots
        ):
            first, last = int(match.group(2)), int(match.group(3) or match.group(2))
            if 1 <= first <= last <= len(target.read_text(errors="replace").splitlines()):
                relative = target.relative_to(repo.resolve()).as_posix()
                if git_file(repo, "HEAD", relative) is None:
                    raise Abort(
                        1,
                        f"{source} is not in HEAD, the commit a card cites its test at; "
                        "commit the file first, or give the test as a `text` source",
                    )
                continue
        raise Abort(
            1,
            f"{source} is not `path:line` or `path:start-end` within a file under "
            f"{roots[0]}/ or {roots[1]}/, where the tests of the {registry} registry are",
        )


def text_file(repo, source):
    """The file a `text` source names, or None when the source is a literal."""
    try:
        path = local_path(repo, source)
        return path if path.is_file() else None
    except (OSError, ValueError):
        return None


def text_sources(repo, sl_dir, sources, stamp):
    """The SOURCES lines of a `text` extraction (SPEC section 18.4).

    A source that names a file is read where it is. Any other is a literal, written to
    `extract/<stamp>-text.txt` for the agent to read; that copy is never a card's
    source_ref. A literal without a space is refused, because it is far more likely a
    mistyped path, or the first word of a text that was not quoted.
    """
    literals = [source for source in sources if text_file(repo, source) is None]
    for source in literals:
        if not any(character.isspace() for character in source.strip()):
            raise Abort(1, f"{source} is not a file; quote a text so that it is one argument")
    lines = []
    for source in sources:
        if source not in literals:
            lines.append(source)
            continue
        suffix = f"-{literals.index(source) + 1}" if len(literals) > 1 else ""
        copy = sl_dir / "extract" / f"{stamp}-text{suffix}.txt"
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_text(source.strip() + "\n")
        lines.append(
            f"a text given on the command line, saved at {copy.relative_to(repo)}; its "
            "source_ref is `text: <title>`, never this path"
        )
    return lines


def kb_directory(repo, source):
    """True when a `kb` source names a directory, a corpus root, rather than a finding."""
    try:
        return local_path(repo, source).is_dir()
    except (OSError, ValueError):
        return False


def kb_extraction_sources(sl_dir, registry, roots, finding=None):
    """The SOURCES of a `kb` extraction: every finding in the registry's module scope, or
    with `finding` the one with that identifier, as `kb show` resolves it (SPEC 18.4)."""
    entries, _ = kb_index(sl_dir, roots)
    found = [
        entry
        for entry in entries
        if entry["kind"] == "finding"
        and any(module_matches(module, registry) for module in entry["modules"])
        and (finding is None or entry["identifier"] == finding)
    ]
    if not found and finding is not None:
        raise Abort(
            1,
            f"no finding with identifier {finding} in scope for the {registry} registry in "
            + ", ".join(str(root) for root in roots),
        )
    if not found:
        raise Abort(
            2,
            f"no finding in {', '.join(str(root) for root in roots)} names a module of the "
            f"{registry} registry ({MODULE_FILTER[registry]})",
        )
    found.sort(key=lambda entry: (STATE_RANK.get(entry["state"], len(STATE_RANK)), entry["identifier"]))
    lines = []
    for entry in found:
        claim = entry["claim"]
        lines.append(
            f"- `{entry['identifier']}`: {entry['state']}, severity "
            f"{claim.get('severity_current') or '?'}, remediation "
            f"{claim.get('remediation_status') or '?'}. {claim.get('summary', '')}".rstrip()
        )
    return lines


def extract_values(
    repo, sl_dir, kind, registry, sources, number=None, states=False, local=False, finding=None
):
    """Placeholder values of the Phase 1 prompt (SPEC section 6.2, step 5).

    For `kb` the sources are corpus roots, and the prompt lists the findings in scope, or
    the one `finding`. With `states` the values are those of a target-state extraction
    (section 18.4): the TS counter, the card template and the card tree, the local one
    when `local`.
    """
    if kind == "kb":
        lines = kb_extraction_sources(
            sl_dir, registry, [Path(source) for source in sources], finding
        )
    else:
        lines = []
        for source in sources:
            text = paper_text(repo, sl_dir, source) if kind == "paper" else None
            suffix = f" (text: {text.relative_to(repo)})" if text else ""
            lines.append(f"- {source}{suffix}")
    template = "target-state.md" if states else "invariant.md"
    return {
        "KIND": kind,
        "NEXT_ID": next_id(sl_dir, "TS" if states else "INV"),
        "TEMPLATE": (sl_dir / "templates" / template).read_text().rstrip("\n"),
        "SOURCES": "\n".join(lines),
        "REGISTRY": registry,
        "DESTINATION": str(extraction_destination(kind, registry, states, local)),
        "COUNT": extraction_count(number, states),
        "QUERY": kb_query_help(registry, search=search_ready(sl_dir)),
        "CONTEXT": subsystem_prompt(sl_dir, registry, "analyst"),
        "SOURCE_ROOT": SOURCES[registry],
        # The commit every line the agent cites is pinned to (lint rule 10).
        "COMMIT": git(repo, "rev-parse", "--short=12", "HEAD").strip(),
    }


def unpinnable(tree):
    """Tracked files outside this subproject that differ from HEAD in a worktree state.

    The agent reads the tree as it stands but pins the lines it cites to HEAD, so a line
    cited in one of these files may not be the line HEAD has there.
    """
    return sorted(
        path for path, (status, _digest) in tree.items()
        if status != "??" and not path.startswith(f"{SL}/")
    )


def files_under(root):
    return {path: sha256(path) for path in root.rglob("*") if path.is_file()}


def worktree_state(repo):
    """Every path git reports as differing from HEAD, with a digest of each.

    A Phase 1 agent can write anywhere in the tree it runs in, and that tree is
    the operator's own, so the invariant registry is not enough to watch. This
    is the whole worktree as git sees it, which is cheap because git reports only
    what differs. `-uall` is passed so that an untracked directory is listed as
    its files rather than collapsed, and a digest is kept as well as the status
    because a file already modified before the run keeps its status when it is
    modified again. Ignored paths are not reported, so `extract/` and
    `campaign/` do not appear.
    """
    state = {}
    for status, path in porcelain_entries(
        git(repo, "status", "--porcelain", "-z", "-uall")
    ):
        target = repo / path
        state[path] = (status, sha256(target) if target.is_file() else None)
    return state


def check_comment_sources(repo, registry, sources):
    """A `comment` source is a file or directory of the registry's code (SPEC section 6.1).

    A path elsewhere would put into the registry words its code does not say, and one
    outside the repository, such as a knowledge-base root, could carry private material
    into the tracked registry: findings have their own kind.
    """
    root = (repo / SOURCES[registry]).resolve()
    for source in sources:
        target = (repo / re.sub(r":\d+(?:-\d+)?$", "", source)).resolve()
        if target.exists() and (target == root or root in target.parents):
            continue
        hint = ""
        if not inside_repo(repo, target):
            hint = (
                "; to extract from knowledge-base findings, run "
                f"`just extract-invariants --registry {registry} kb {source}`"
            )
        raise Abort(
            1,
            f"{source} is not a file or directory under {SOURCES[registry]}, the code the "
            f"{registry} registry describes{hint}",
        )


def cmd_extract(args):
    """Phase 1 (SPEC section 6.2), or with --states target-state cards (section 18.4)."""
    repo = repo_root()
    sl_dir = repo / SL
    states = getattr(args, "states", False)
    local = getattr(args, "local", False)
    if args.kind in ("test", "text") and not states:
        raise Abort(
            1,
            f"the {args.kind} kind is for target states; run `just extract-states "
            f"{args.kind} ...`",
        )
    if local and not states:
        raise Abort(1, f"--local sends target-state cards to {LOCAL_STATES}/; it needs --states")
    if states and args.registry not in STATE_SUBSYSTEMS:
        raise Abort(
            1,
            f"Target-State Synthesis has no {args.registry} registry; use one of: "
            + ", ".join(STATE_SUBSYSTEMS),
        )
    config = load_config(sl_dir)
    agent = resolve_agent(config, args.agent)
    if args.number is not None and args.number < 1:
        raise Abort(1, "--number must be at least 1")
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    sources = list(args.sources)
    finding = None
    if args.kind == "kb":
        if states and len(sources) == 1 and not kb_directory(repo, sources[0]):
            # With --states a kb source may be one finding identifier (SPEC 18.4); its
            # roots are STATELENS_KB, as for `kb show`.
            finding, sources = sources[0], []
        # The roots given, else STATELENS_KB. The agent reads the findings through the
        # `kb` commands, which must see the same corpus, so its environment names it.
        value = ":".join(sources) if sources else config.get("STATELENS_KB", "")
        roots = kb_roots(repo, dict(config, STATELENS_KB=value))
        sources = [str(root) for root in roots]
        os.environ["STATELENS_KB"] = ":".join(sources)
    elif not sources:
        raise Abort(1, f"extract {args.kind} needs at least one source")
    elif args.kind == "comment":
        check_comment_sources(repo, args.registry, sources)
    elif args.kind == "test":
        check_test_sources(repo, args.registry, sources)
    elif args.kind == "text":
        sources = text_sources(repo, sl_dir, sources, stamp)
    reason = private_reason(repo, args.kind, args.sources, local) if states else None
    noun = "card" if states else "invariant"
    tops = CARD_TREES if states else ("invariants", LOCAL_INVARIANTS)
    # Every registry tree is watched, the other kind's too: an edit to one is a problem
    # whichever kind this run writes, and the ignored local trees escape the worktree check.
    watched = tops + tuple(
        top for top in ("invariants", LOCAL_INVARIANTS) + CARD_TREES if top not in tops
    )
    trees = tuple(sl_dir / top for top in watched)
    registry = repo / extraction_destination(args.kind, args.registry, states, bool(reason))
    registry.mkdir(parents=True, exist_ok=True)
    before = {path: digest for tree in trees for path, digest in files_under(tree).items()}
    values = extract_values(
        repo, sl_dir, args.kind, args.registry, sources, args.number,
        states=states, local=bool(reason), finding=finding,
    )
    if states:
        # One prompt for every kind, rendered alone (SPEC section 18.4).
        prompt = render((sl_dir / "prompts" / "state-analyst.md").read_text(), values)
    else:
        prompt = compose(sl_dir, "analyst.md", f"analyst-{args.kind}.md", values)
    tree_before = worktree_state(repo)
    changed = unpinnable(tree_before)
    if changed:
        say(
            f"warning: {len(changed)} tracked file(s) differ from {values.get('COMMIT', 'HEAD')}, "
            "the commit the agent pins cited lines to, so a line it cites in one of them may "
            f"not match: {', '.join(changed[:5])}" + (" ..." if len(changed) > 5 else "")
        )

    log = sl_dir / "extract" / f"{stamp}-{args.kind}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    (sl_dir / "extract" / f"{stamp}-{args.kind}.prompt.md").write_text(prompt)
    read = f"finding {finding}" if finding else f"{len(sources)} {args.kind} source(s)"
    say(
        f"extract: {agent} reads {read} for {registry.relative_to(sl_dir)}/, from "
        f"{values['NEXT_ID']}; log {log.relative_to(repo)}"
    )
    phase = "kb" if args.kind == "kb" else 1
    code, _ = run_logged(agent_command(config, agent, phase, repo), log, repo, stdin_text=prompt)
    if code != 0:
        raise Abort(2, f"the agent exited with code {code}; see {log.relative_to(repo)}")

    after = {path: digest for tree in trees for path, digest in files_under(tree).items()}
    new = sorted((path for path in after if path not in before), key=by_id)
    problems = 0
    for path, digest in sorted(before.items()):
        if after.get(path) != digest:
            kind = "card" if path.name.startswith("TS-") else "invariant"
            print(f"{path}: the agent modified or deleted an existing {kind}")
            problems += 1
    for path in new:
        if path.parent != registry:
            print(f"{path}: the agent wrote outside the registry {registry.relative_to(sl_dir)}/")
            problems += 1
    written = [path for path in new if path.parent == registry]
    if args.number is not None and len(written) > args.number:
        print(
            f"{registry.relative_to(repo)}: the agent wrote {len(written)} {noun}s, more "
            f"than the {args.number} asked for"
        )
        problems += 1
    # Anything the agent touched outside the registry's trees. The trees themselves
    # are left to the checks above, which say more about them than this one can, and
    # this run's own log and prompt are named rather than assumed to be ignored,
    # so the check does not depend on a .gitignore being right.
    tree_after = worktree_state(repo)
    ours = tuple(str(SL / top) + "/" for top in watched + ("extract", "campaign"))
    for path in sorted(set(tree_before) | set(tree_after)):
        if path.startswith(ours) or tree_before.get(path) == tree_after.get(path):
            continue
        print(f"{path}: the agent changed a file outside {tops[0]}/")
        problems += 1
    # The agent pins the lines it cites; the script copies them in, so no excerpt is
    # retyped by hand (SPEC section 4.3).
    for path in new:
        if path.parent == registry and pinned_ranges(path.read_text()):
            path.write_text(with_excerpts(path.read_text(), repo))
    problems += lint_paths(new, registry_files(sl_dir))
    for path in new:
        say(f"new: {path.relative_to(sl_dir)}: {title_of(path)}")
    if args.number is not None:
        say(f"extract: {len(written)} of the {args.number} {noun}(s) asked for")
    if new and states:
        say(
            "Every card is used by the next synthesis of its profile. "
            "Review, edit or delete these files first."
        )
        if reason:
            say(
                f"These are in {LOCAL_STATES}/, which git ignores, because {reason}: never "
                "commit them as they are; to share one, rewrite it without private detail "
                "and move it by hand (D55)."
            )
    elif new:
        say(
            "Every file in a registry is used by the next campaign that binds it. "
            "Review, edit or delete these files first."
        )
        if args.kind == "kb":
            say(
                f"These derive from private findings, so they are in {LOCAL_INVARIANTS}/, "
                "which git ignores: never commit them as they are (R-KB-6)."
            )
    else:
        say(f"extract: the agent wrote no {noun}s")
    return 3 if problems else 0


def inside_repo(repo, path):
    """True when `path` is under `repo`, following symlinks (D34 depends on this)."""
    try:
        Path(os.path.realpath(str(path))).relative_to(Path(os.path.realpath(str(repo))))
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------------
# Knowledge base (SPEC section 5.6)
# ---------------------------------------------------------------------------


def kb_roots(repo, config):
    """Readable corpus roots outside this repository; skips what it cannot use."""
    value = (config.get("STATELENS_KB") or "").strip()
    if not value:
        raise Abort(
            2,
            "STATELENS_KB names no knowledge-base root; set it in config.env or in the "
            "environment to one or more corpus roots separated by ':'",
        )
    roots, tried = [], []
    for item in value.split(":"):
        item = item.strip()
        if not item:
            continue
        path = Path(item).expanduser()
        root = path if path.is_absolute() else repo / path
        tried.append(str(root))
        if inside_repo(repo, root):
            say(f"warning: knowledge-base root {root} is inside the repository; skipped")
            continue
        if not root.is_dir():
            say(f"warning: knowledge-base root {root} is not a readable directory; skipped")
            continue
        documents = any((root / name).is_dir() for name in KB_DOC_DIRS)
        if not (root / "findings").is_dir() and not documents:
            say(f"warning: {root} has no findings/ and no document directory; skipped")
            continue
        roots.append(root)
    if not roots:
        raise Abort(2, "no readable knowledge-base root; tried: " + ", ".join(tried))
    return roots


def claim_fields(text):
    """The fenced ```claim block of a finding as key -> value, or None when absent."""
    match = re.search(r"^```claim\s*\n(.*?)^```\s*$", text, re.S | re.M)
    if not match:
        return None
    values = {}
    for line in match.group(1).split("\n"):
        key, sep, value = line.partition(":")
        if sep:
            values[key.strip()] = value.strip()
    return values


def code_references(text):
    """The files and symbols a finding cites, most-cited first (SPEC section 5.6)."""
    found = {}
    for name, pattern, group in (("paths", KB_REF_PATH, 0), ("symbols", KB_REF_SYMBOL, 1)):
        counts = collections.Counter(match.group(group) for match in pattern.finditer(text))
        found[name] = [item for item, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    return found


def section_spans(text):
    """Level-2 section name -> [start, end] character offsets of its body."""
    spans, previous = {}, None
    for match in re.finditer(r"^## (.+)$", text, re.M):
        if previous:
            spans[previous[0]] = [previous[1], match.start()]
        previous = (match.group(1).strip(), match.end() + 1)
    if previous:
        spans[previous[0]] = [previous[1], len(text)]
    return spans


def normalize_module(value):
    """Maps a `module` value to its crate module (SPEC section 5.6)."""
    module = value.strip().strip("`")
    if not module:
        return ""
    if "/src/" in module:
        # A source path names its crate module: consensus/src/simplex/actors/x.rs
        # is consensus/simplex, so it ranks as an exact match like any other.
        crate, _, rest = module.partition("/src/")
        first = rest.split("/", 1)[0]
        module = f"{crate}/{first}" if first else crate
    tail = module.rsplit("/", 1)[-1]
    if "." in tail and "/" in module:
        module = module.rsplit("/", 1)[0]
    return module.rstrip("/")


def module_matches(module, registry):
    prefix = MODULE_FILTER[registry]
    return module == prefix or module.startswith(prefix + "/")


def kb_index(sl_dir, roots):
    """Builds or refreshes the index and returns (entries, unparsed count)."""
    path = sl_dir / KB_INDEX
    previous = {}
    if path.is_file():
        try:
            for entry in json.loads(path.read_text()).get("entries", []):
                previous[tuple(entry["key"])] = entry
        except (ValueError, KeyError):
            previous = {}
    entries, unparsed = [], 0
    for order, root in enumerate(roots):
        findings = root / "findings"
        states = sorted(p for p in findings.glob("*") if p.is_dir()) if findings.is_dir() else []
        for state_dir in states:
            for file in sorted(state_dir.glob("*.md")):
                relative = str(file.relative_to(root))
                key = (str(root), file.stem)
                try:
                    stat = file.stat()
                except OSError as error:
                    say(f"warning: cannot read {file}: {error.strerror or error}; skipped")
                    continue
                if not file.is_file():
                    continue
                cached = previous.get(key)
                if (
                    cached
                    and cached.get("path") == relative
                    and cached.get("mtime") == stat.st_mtime_ns
                    and cached.get("size") == stat.st_size
                ):
                    cached["order"] = order
                    entries.append(cached)
                    unparsed += 1 if cached.get("unparsed") else 0
                    continue
                text = read_corpus(file)
                if text is None:
                    continue
                claim = claim_fields(text)
                unreadable = claim is None
                if unreadable:
                    unparsed += 1
                    claim = {}
                modules = [
                    normalize_module(item)
                    for item in claim.get("module", "").split(",")
                    if item.strip()
                ]
                entries.append(
                    {
                        "key": list(key),
                        "kind": "finding",
                        "order": order,
                        "root": str(root),
                        "path": relative,
                        "identifier": file.stem,
                        "state": state_dir.name,
                        "mtime": stat.st_mtime_ns,
                        "size": stat.st_size,
                        "unparsed": unreadable,
                        "claim": {field: claim.get(field, "") for field in KB_CLAIM_FIELDS},
                        "modules": [module for module in modules if module],
                        "sections": {
                            name: span
                            for name, span in section_spans(text).items()
                            if name in KB_STATE_SECTIONS
                        },
                        "refs": code_references(text),
                    }
                )
        for name in KB_DOC_DIRS:
            base = root / name
            if not base.is_dir():
                continue
            for file in sorted(base.rglob("*.md")):
                relative = str(file.relative_to(root))
                try:
                    stat = file.stat()
                except OSError as error:
                    say(f"warning: cannot read {file}: {error.strerror or error}; skipped")
                    continue
                if not file.is_file():
                    continue
                entries.append(
                    {
                        "key": [str(root), relative],
                        "kind": "document",
                        "order": order,
                        "root": str(root),
                        "path": relative,
                        "identifier": relative,
                        "state": "",
                        "mtime": stat.st_mtime_ns,
                        "size": stat.st_size,
                        "unparsed": False,
                        "claim": {},
                        "modules": [],
                        "sections": {},
                        "refs": {"paths": [], "symbols": []},
                    }
                )
    fresh = {tuple(entry["key"]): (entry["mtime"], entry["size"]) for entry in entries}
    stale = {key: (entry.get("mtime"), entry.get("size")) for key, entry in previous.items()}
    if fresh != stale or not path.is_file():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"entries": entries}, indent=1, sort_keys=True) + "\n")
    return entries, unparsed


_CORPUS_CACHE = {}


def kb_text(entry):
    """A corpus file's text, read at most once per invocation."""
    key = (entry["root"], entry["path"])
    if key not in _CORPUS_CACHE:
        _CORPUS_CACHE[key] = read_corpus(Path(entry["root"]) / entry["path"]) or ""
    return _CORPUS_CACHE[key]


def read_corpus(path):
    """Text of a corpus file, or None when it cannot be read (R-KB-2: skip and report)."""
    try:
        text = path.read_text(errors="replace")
    except OSError as error:
        say(f"warning: cannot read {path}: {error.strerror or error}; skipped")
        return None
    return text.lstrip("\ufeff")


def kb_find(entries, registry, terms):
    """Findings whose claim fields match, ranked as SPEC section 5.6 says."""
    wanted = [term.lower() for term in terms]
    ranked = []
    for position, entry in enumerate(entries):
        if entry["kind"] != "finding":
            continue
        modules = [module for module in entry["modules"] if module_matches(module, registry)]
        if not modules:
            continue
        claim = entry["claim"]
        haystack = f"{claim.get('summary', '')} {claim.get('tags', '')}".lower()
        matched = sum(1 for term in set(wanted) if term in haystack)
        if wanted and not matched:
            continue
        exact = 1 if MODULE_FILTER[registry] in modules else 0
        rank = (-exact, -matched, STATE_RANK.get(entry["state"], len(FINDING_STATES)), position)
        ranked.append((rank, entry))
    ranked.sort(key=lambda item: item[0])
    return [entry for _, entry in ranked]


def kb_cites(entries, registry, prefix):
    """Findings citing a path under `prefix`, most citations first (SPEC section 5.6)."""
    ranked = []
    for position, entry in enumerate(entries):
        if entry["kind"] != "finding":
            continue
        if not any(module_matches(module, registry) for module in entry["modules"]):
            continue
        hits = [
            path
            for path in ((entry.get("refs") or {}).get("paths") or [])
            if path.startswith(prefix)
        ]
        if not hits:
            continue
        rank = (-len(hits), STATE_RANK.get(entry["state"], len(FINDING_STATES)), position)
        ranked.append((rank, entry, hits))
    ranked.sort(key=lambda item: item[0])
    return [(entry, hits) for _, entry, hits in ranked]


def kb_grep(entries, registry, needle):
    """Case-insensitive literal snippets, ordered by root, then path, then offset."""
    wanted = needle.lower()
    hits = []
    for entry in entries:
        if entry["kind"] == "finding":
            if not any(module_matches(module, registry) for module in entry["modules"]):
                continue
            spans = entry["sections"]
        else:
            spans = None
        text = kb_text(entry)
        regions = (
            [(name, span[0], span[1]) for name, span in sorted(spans.items())]
            if spans is not None
            else [("", 0, len(text))]
        )
        for name, start, end in regions:
            body = text[start:end]
            position = body.lower().find(wanted)
            while position >= 0:
                offset = start + position
                line = text.count("\n", 0, offset) + 1
                hits.append((entry["order"], entry["path"], offset, entry, name, line))
                position = body.lower().find(wanted, position + 1)
    hits.sort(key=lambda hit: hit[:3])
    return hits


def kb_section_bounds(entry, line):
    """The first and last line of the allowed section holding `line`, or None."""
    text = kb_text(entry)
    for start, end in (entry.get("sections") or {}).values():
        first = text.count("\n", 0, start) + 1
        last = text.count("\n", 0, max(start, end - 1)) + 1
        if first <= line <= last:
            return first, last
    return None


def kb_snippet(entry, line, context=None):
    """The lines around `line`, kept inside the section the hit was found in.

    A hit is confined to the sections the registry allows, and so is its context:
    the lines shown next to a match at a section's edge would otherwise come from
    the section the search excluded. A document has no sections and shows the
    whole-file context.
    """
    lines = kb_text(entry).split("\n")
    span = KB_GREP_CONTEXT if context is None else context
    first, last = kb_section_bounds(entry, line) or (1, len(lines))
    start = max(first - 1, line - 1 - span // 2)
    stop = min(last, start + span)
    return "\n".join(f"    {text}" for text in lines[start:stop])


def reference_lines(entry):
    """The `files:` and `symbols:` lines of a hit, or "" when the finding cites none."""
    refs = entry.get("refs") or {}
    lines = ""
    for name, label in (("paths", "files"), ("symbols", "symbols")):
        items = refs.get(name) or []
        if not items:
            continue
        shown = ", ".join(items[:KB_REF_SHOWN])
        more = len(items) - KB_REF_SHOWN
        lines += f"    {label}: {shown}" + (f" (+{more} more)" if more > 0 else "") + "\n"
    return lines


def cmd_kb(args):
    """The retrieval interface of SPEC section 5.6, used by the beacon agent."""
    if args.query == "search":
        # The search index covers this repository too, so it answers without a corpus.
        return cmd_kb_search(args)
    repo = repo_root()
    sl_dir = repo / SL
    config = load_config(sl_dir)
    entries, unparsed = kb_index(sl_dir, kb_roots(repo, config))
    if unparsed:
        say(f"warning: {unparsed} finding(s) have no parsable claim block")
    registry = args.registry
    if args.query == "modules":
        counts = collections.Counter()
        for entry in entries:
            for module in entry["modules"]:
                counts[module] += 1
        rows = [(module, count) for module, count in sorted(counts.items())]
        in_scope = [row for row in rows if module_matches(row[0], registry)]
        for module, count in in_scope:
            print(f"{count:5d}  {module}")
        outside = [row for row in rows if not module_matches(row[0], registry)]
        excluded = sum(count for _, count in outside)
        print(
            f"\n{len(in_scope)} module(s) in scope for the {registry} registry; "
            f"{excluded} finding-module pair(s) out of scope"
        )
        crate = MODULE_FILTER[registry].split("/", 1)[0]
        coarse = next((count for module, count in outside if module == crate), 0)
        if coarse:
            print(f"{coarse} finding(s) name only `{crate}`, too coarse to attribute")
        return 0
    if args.query == "find":
        found = kb_find(entries, registry, args.terms)
        for entry in found[:KB_FIND_LIMIT]:
            claim = entry["claim"]
            print(
                f"{entry['identifier']}  ({Path(entry['root']).name})\n"
                f"    state={entry['state']} module={', '.join(entry['modules'])} "
                f"severity={claim.get('severity_current', '?')} "
                f"remediation={claim.get('remediation_status', '?')}\n"
                f"    {claim.get('summary', '')}"
            )
            print(reference_lines(entry), end="")
        dropped = max(0, len(found) - KB_FIND_LIMIT)
        print(f"\n{min(len(found), KB_FIND_LIMIT)} hit(s), {dropped} dropped")
        return 0
    if args.query == "show":
        args.section = " ".join(args.section) if args.section else ""
    if args.query == "cites":
        found = kb_cites(entries, registry, args.prefix)
        for entry, hits in found[:KB_FIND_LIMIT]:
            claim = entry["claim"]
            print(
                f"{entry['identifier']}  ({Path(entry['root']).name})\n"
                f"    state={entry['state']} cites={len(hits)} "
                f"remediation={claim.get('remediation_status', '?')}\n"
                f"    {claim.get('summary', '')}\n"
                f"    here: {', '.join(hits[:KB_REF_SHOWN])}"
            )
            symbols = ((entry.get("refs") or {}).get("symbols") or [])[:KB_REF_SHOWN]
            if symbols:
                print(f"    symbols: {', '.join(symbols)}")
        dropped = max(0, len(found) - KB_FIND_LIMIT)
        print(f"\n{min(len(found), KB_FIND_LIMIT)} finding(s) cite {args.prefix}, {dropped} dropped")
        return 0
    if args.query == "grep":
        hits = kb_grep(entries, registry, args.text)
        for _, _, _, entry, section, line in hits[:KB_GREP_LIMIT]:
            where = f"{entry['identifier']} ({Path(entry['root']).name})"
            where += f" ## {section}" if section else ""
            print(f"{where} (line {line})")
            print(kb_snippet(entry, line))
        dropped = max(0, len(hits) - KB_GREP_LIMIT)
        print(f"\n{min(len(hits), KB_GREP_LIMIT)} snippet(s), {dropped} dropped")
        return 0
    wanted = [
        entry
        for entry in entries
        if entry["identifier"] == args.identifier
        and (
            entry["kind"] == "document"
            or any(module_matches(module, registry) for module in entry["modules"])
        )
    ]
    if not wanted:
        raise Abort(
            1,
            f"no knowledge-base entry with identifier {args.identifier} in scope for the "
            f"{registry} registry",
        )
    for index, entry in enumerate(wanted):
        if index:
            print()
        text = kb_text(entry)
        origin = f"{Path(entry['root']).name}/{entry['path']}"
        if entry["kind"] == "document":
            # A document has no claim block and no state-bearing sections, so
            # rendering it as a finding would print an empty shell of both. The
            # whole text is what `show` is for once a `grep` snippet has
            # justified reading it (R-KB-4).
            if args.section:
                raise Abort(
                    1,
                    f"{entry['identifier']} is a document, which has no sections; "
                    f"ask for it without one",
                )
            body = text.rstrip("\n")
            print(f"{entry['identifier']}  (document)  {origin}  "
                  f"{len(body.splitlines())} line(s)")
            print(body)
            continue
        if not args.section:
            match = re.search(r"^```claim\s*\n.*?^```\s*$", text, re.S | re.M)
            print(f"{entry['identifier']}  ({entry['state'] or entry['kind']})  {origin}")
            print(match.group(0) if match else "(no claim block)")
            print(reference_lines(entry), end="")
            print("state-bearing sections: " + ", ".join(sorted(entry["sections"])))
            continue
        if args.section not in KB_STATE_SECTIONS:
            raise Abort(
                1,
                f"{args.section} is not a state-bearing section; choose one of: "
                + ", ".join(KB_STATE_SECTIONS),
            )
        span = entry["sections"].get(args.section)
        if not span:
            raise Abort(1, f"{entry['identifier']} has no section {args.section}")
        print(f"{entry['identifier']} ## {args.section}  {origin}")
        print(text[span[0] : span[1]].rstrip("\n"))
    return 0


def kb_query_help(registry, kb=True, search=False):
    """The QUERY placeholder: the concrete command line of every query (SPEC 6.3).

    The search line appears whenever a search index exists, which a campaign builds
    even without a knowledge base; the other five need the knowledge base.
    """
    base = f"python3 {SL}/scripts/statelens.py kb"
    lines = []
    if search:
        lines += [
            f"- `{base} search --registry {registry} [--path PATH] QUESTION`",
            f"  up to {SEARCH_LIMIT} snippets ranked by meaning and by words, from the findings",
            "  in scope, the design documents, and this repository's comments, doc comments and",
            "  Markdown documentation. Each names where it is: a finding and its section, or",
            "  `path:line@commit` and the item a comment documents. Ask in plain words; `--path`",
            "  narrows the code and the documentation to a directory.",
        ]
    if not kb:
        return "\n".join(lines)
    return "\n".join(
        lines
        + [
            f"- `{base} modules --registry {registry}`",
            "  every `module` value in scope, with a count.",
            f"- `{base} find --registry {registry} TERM...`",
            f"  up to {KB_FIND_LIMIT} findings whose claim fields match, ranked; per hit the",
            "  identifier, state, module, severity, remediation status and summary.",
            f"- `{base} cites --registry {registry} PATH`",
            f"  up to {KB_FIND_LIMIT} findings that cite a file under PATH, most citations first;",
            "  per hit the identifier, state, how many citations, summary, and which of its files",
            "  fall under PATH. This is how a sweep starts.",
            f"- `{base} grep --registry {registry} TEXT`",
            f"  up to {KB_GREP_LIMIT} snippets from the state-bearing sections and the documents;",
            "  TEXT is matched as a case-insensitive literal, never a regular expression.",
            f"- `{base} show --registry {registry} IDENTIFIER [SECTION]`",
            "  one finding's claim block, or one of its state-bearing sections:",
            "  " + ", ".join(KB_STATE_SECTIONS) + ".",
        ]
    )


# SPEC section 5.10: semantic search over the knowledge base and over this repository's
# comments, doc comments and documentation, ranked by meaning and by words together. The
# index lives in extract/search/, which git ignores, and a query never uses the network.
SEARCH_DIR = "extract/search"
# Beside the index directory, which a publication empties, so that it is never deleted.
SEARCH_LOCK = "extract/search.lock"
SEARCH_DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
# Design documents live in kb/ and context/; config/ holds the corpus's own settings.
SEARCH_KB_DOC_DIRS = ("kb", "context")
SEARCH_SOURCES = ("finding", "kb", "code", "doc")
# A chunk stays within what a small model reads at once: MiniLM stops at 256 word pieces.
SEARCH_CHUNK_CHARS = 1000
SEARCH_MIN_CHARS = 24
SEARCH_LIMIT = 10
SEARCH_MAX_LIMIT = 40
# How many of each ranking's best enter the fusion, and the constant of reciprocal rank
# fusion, which weighs a rank r as 1 / (SEARCH_RRF_K + r).
SEARCH_POOL = 200
SEARCH_RRF_K = 60
SEARCH_BATCH = 512
SEARCH_SNIPPET_LINES = 4
SEARCH_STOPWORDS = frozenset(
    "a an and are as at be but by can do does for from has have how if in into is it its "
    "may must not of on or so that the then there this to was were what when where which "
    "while who why will with".split()
)
SEARCH_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+")
SEARCH_PART = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
SEARCH_ITEM = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:(?:async|const|unsafe|extern\s+\"[^\"]*\")\s+)*"
    r"(fn|struct|enum|trait|type|const|static|mod|union|macro_rules!)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
SEARCH_IMPL = re.compile(
    r"^\s*(?:unsafe\s+)?impl\b(?:\s*<.*?>)?\s+(?:[A-Za-z_][\w:]*(?:<.*?>)?\s+for\s+)?"
    r"(?:[A-Za-z_]\w*::)*([A-Za-z_]\w*)"
)
SEARCH_CONTAINERS = ("fn", "mod", "trait", "struct", "enum", "union", "macro_rules!")
SEARCH_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")


def search_tokens(text):
    """Lower-case words of `text`, each identifier followed by its parts.

    `CertifyState` and `try_propose` are words a question may use whole or in
    pieces, so both forms count.
    """
    tokens = []
    for word in SEARCH_WORD.findall(text):
        lower = word.lower()
        if len(lower) > 1 and lower not in SEARCH_STOPWORDS:
            tokens.append(lower)
        parts = [part.lower() for piece in word.split("_") for part in SEARCH_PART.findall(piece)]
        if len(parts) > 1:
            tokens += [part for part in parts if len(part) > 1 and part not in SEARCH_STOPWORDS]
    return tokens


def search_wrap(text, limit):
    """`text` cut at spaces into parts of at most `limit` characters; a longer word is cut."""
    parts = []
    while len(text) > limit:
        cut = text.rfind(" ", 0, limit + 1)
        if cut <= 0:
            cut = limit
        parts.append(text[:cut].rstrip())
        text = text[cut:].lstrip()
    if text:
        parts.append(text)
    return parts


def search_pieces(numbered, head="", fits=None):
    """(first line, last line, text) chunks of whole paragraphs from (line, text) pairs.

    A chunk closes at a paragraph once it holds SEARCH_CHUNK_CHARS, a longer paragraph
    is cut between lines, and a longer line between words, each part keeping its line
    number, so a citation still holds. With `fits`, the model's own test of whether a
    text fits its window, a chunk is halved until its heading and text fit together:
    characters say little about tokens in identifier-heavy text. A chunk with too
    little text is dropped.
    """
    if fits is not None and not fits(f"{head}\nx"):
        # A heading that fills the window alone leaves nothing a cut could save.
        fits = None
    paragraphs, current = [], []
    for number, text in numbered:
        text = text.rstrip()
        if not text.strip():
            if current:
                paragraphs.append(current)
                current = []
            continue
        current += [(number, part) for part in search_wrap(text, SEARCH_CHUNK_CHARS)]
    if current:
        paragraphs.append(current)

    def size(lines):
        return sum(len(text) + 1 for _, text in lines)

    def split(piece):
        body = "\n".join(text for _, text in piece)
        if fits is None or fits(f"{head}\n{body}"):
            return [piece]
        if len(piece) > 1:
            middle = len(piece) // 2
            return split(piece[:middle]) + split(piece[middle:])
        number, text = piece[0]
        words = text.split(" ")
        if len(words) < 2:
            return [piece]
        middle = len(words) // 2
        return split([(number, " ".join(words[:middle]))]) + split(
            [(number, " ".join(words[middle:]))]
        )

    groups, piece = [], []
    for paragraph in paragraphs:
        if piece and size(piece) + size(paragraph) > SEARCH_CHUNK_CHARS:
            groups.append(piece)
            piece = []
        for line in paragraph:
            if piece and size(piece) + len(line[1]) > SEARCH_CHUNK_CHARS:
                groups.append(piece)
                piece = []
            piece.append(line)
    if piece:
        groups.append(piece)
    pieces = []
    for group in groups:
        if sum(char.isalnum() for _, text in group for char in text) < SEARCH_MIN_CHARS:
            continue
        for part in split(group):
            pieces.append((part[0][0], part[-1][0], "\n".join(text for _, text in part)))
    return pieces


def search_module_name(path):
    """The module a Rust file is: consensus/src/simplex/mod.rs is consensus::simplex."""
    parts = [part for part in path[: -len(".rs")].split("/") if part != "src"]
    if parts and parts[-1] in ("mod", "lib", "main"):
        parts = parts[:-1]
    return "::".join(parts)


def search_context(lines, index):
    """The names of the items around `lines[index]`, outermost first.

    Read from indentation, which is what a comment's place in the code looks like
    without a parser: walking up, a less indented `impl`, `fn`, `struct` and the like
    encloses it, and any other less indented line, such as `loop {` or the `) {` of a
    signature, narrows the search without naming anything.
    """
    line = lines[index]
    limit = len(line) - len(line.lstrip())
    chain = []
    number = index - 1
    while number >= 0 and limit > 0:
        text = lines[number]
        number -= 1
        stripped = text.strip()
        if not stripped or stripped.startswith(("//", "#[", "/*", "*")):
            continue
        indent = len(text) - len(text.lstrip())
        if indent >= limit:
            continue
        impl = SEARCH_IMPL.match(text)
        found = SEARCH_ITEM.match(text)
        if impl:
            chain.append(impl.group(1))
            limit = indent
        elif found and found.group(1) in SEARCH_CONTAINERS:
            chain.append(found.group(2))
            limit = indent
        else:
            limit = min(limit, indent + 1)
    return chain[::-1]


def search_documented(lines, index):
    """What a doc comment ending just before `lines[index]` documents, with its container."""
    while index < len(lines) and (
        not lines[index].strip() or lines[index].lstrip().startswith(("#[", "#!["))
    ):
        index += 1
    if index >= len(lines):
        return ""
    line = lines[index]
    found = SEARCH_ITEM.match(line)
    impl = SEARCH_IMPL.match(line)
    if found:
        name = found.group(2)
    elif impl:
        name = impl.group(1)
    else:
        field = re.match(r"^\s*(?:pub(?:\([^)]*\))?\s+)?([A-Za-z_][A-Za-z0-9_]*)", line)
        name = field.group(1) if field else ""
    return "::".join(search_context(lines, index) + ([name] if name else []))


def search_cfg_test(line):
    """What follows a test-only `#[cfg(...)]` that opens `line`, or None.

    Test-only means `test`, or an `all(...)` that requires it: `cfg(all(test,
    feature = "loom"))` is test code, while `cfg(any(test, feature = "fuzz"))` is
    compiled into feature builds too and is not.
    """
    stripped = line.lstrip()
    if not stripped.startswith("#[cfg("):
        return None
    depth = 0
    for end, char in enumerate(stripped):
        depth += {"[": 1, "]": -1}.get(char, 0)
        if char == "]" and depth == 0:
            break
    else:
        return None
    expression = stripped[len("#[cfg(") : end - 1].strip()
    if expression != "test":
        if not (expression.startswith("all(") and expression.endswith(")")):
            return None
        arguments, nested, start = [], 0, 4
        for position, char in enumerate(expression[4:-1], 4):
            nested += {"(": 1, ")": -1}.get(char, 0)
            if char == "," and nested == 0:
                arguments.append(expression[start:position].strip())
                start = position + 1
        arguments.append(expression[start:-1].strip())
        if "test" not in arguments:
            return None
    return stripped[end + 1 :]


def search_test_modules(texts):
    """The files that test-only module declarations name, as paths and directory prefixes.

    `texts` maps each Rust path to its text. `#[cfg(test)] mod name;` in `mod.rs`,
    `lib.rs` or `main.rs` names `name.rs` or `name/` beside it, and in `x.rs` names them
    under `x/`; a `#[path = "..."]` between the two names the file outright, relative to
    the declaring file's directory. Everything such a file declares is test code too.
    """
    named = set()
    for path, text in texts.items():
        folder, _, filename = path.rpartition("/")
        stem = filename[: -len(".rs")]
        base = folder if stem in ("mod", "lib", "main") else f"{folder}/{stem}"
        lines = text.split("\n")
        for index, line in enumerate(lines):
            rest = search_cfg_test(line)
            if rest is None:
                continue
            explicit = None
            following = [rest] + lines[index + 1 :]
            for candidate in following:
                candidate = candidate.strip()
                attribute = re.match(r'#\[path\s*=\s*"([^"]+)"\]\s*(.*)$', candidate)
                if attribute:
                    explicit = attribute.group(1)
                    candidate = attribute.group(2).strip()
                if not candidate or (candidate.startswith("#[") and not attribute):
                    continue
                declared = re.match(r"^(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*;", candidate)
                if declared:
                    name = declared.group(1)
                    if explicit:
                        named.add(f"{folder}/{explicit}" if folder else explicit)
                    else:
                        named.update({f"{base}/{name}.rs", f"{base}/{name}/"})
                break
    return named


def search_test_ranges(path, text, test_modules=()):
    """The (first, last) line ranges of a Rust file that are test code.

    The whole file when its path is test support or test code (`mocks`, `tests/`,
    `benches/`), when a test-only declaration names it, or when it opens with
    `#![cfg(test)]`. Otherwise each item under a test-only `#[cfg(...)]`, from the
    documentation and attributes above it to its end, which is the brace that closes
    it or the `;` or `,` that ends it, counted with comments and literals blanked.
    """
    lines = text.split("\n")
    parts = Path(path).parts
    named = any(
        path == entry or (entry.endswith("/") and path.startswith(entry)) for entry in test_modules
    )
    if (
        named
        or "mocks" in parts
        or Path(path).stem == "mocks"
        or "tests" in parts
        or "benches" in parts
        or any(re.match(r"^\s*#!\[cfg\(\s*test\s*\)\]", line) for line in lines)
    ):
        return [(1, len(lines))]
    code = None
    ranges = []
    for index, line in enumerate(lines):
        if search_cfg_test(line) is None:
            continue
        if code is None:
            code = blank_inert(text, strings=True).split("\n")
        start = index
        while start > 0 and lines[start - 1].lstrip().startswith(("///", "#[")):
            start -= 1
        braces = nested = 0
        opened = False
        end = len(lines) - 1
        for number in range(index, len(code)):
            row = code[number]
            if number == index:
                row = row[row.index("]") + 1 :] if "]" in row else ""
            done = False
            for char in row:
                if char in "([":
                    nested += 1
                elif char in ")]":
                    nested -= 1
                elif nested == 0 and char == "{":
                    braces += 1
                    opened = True
                elif nested == 0 and char == "}":
                    braces -= 1
                    done = (opened and braces == 0) or braces < 0
                elif nested == 0 and braces == 0 and char in ";,":
                    done = True
                if done:
                    break
            if done:
                end = number
                break
        ranges.append((start + 1, end + 1))
    return ranges


def search_rust_chunks(path, text, commit, test_modules=(), fits=None):
    """The comment and doc-comment chunks of a Rust file, each with the item it belongs to.

    A `//!` block documents its module, a `///` block the item after it, and a plain
    comment the function or item it sits in. Lines marked `[statelens]` are
    instrumentation, never indexed, and a chunk in test code says so.
    """
    lines = text.split("\n")
    tests = search_test_ranges(path, text, test_modules)
    module = search_module_name(path)
    chunks = []
    index = 0
    while index < len(lines):
        stripped = lines[index].lstrip()
        if not stripped.startswith("//") or "[statelens]" in stripped:
            index += 1
            continue
        start = index
        if stripped.startswith("//!"):
            kind = "module"
        elif stripped.startswith("///") and not stripped.startswith("////"):
            kind = "doc"
        else:
            kind = "comment"
        body = []
        while index < len(lines):
            current = lines[index].lstrip()
            if not current.startswith("//") or "[statelens]" in current:
                break
            body.append((index + 1, re.sub(r"^//[/!]?\s?", "", current)))
            index += 1
        if kind == "module":
            item = module
        elif kind == "doc":
            item = search_documented(lines, index) or module
        else:
            item = "::".join(search_context(lines, start)) or module
        test = any(first <= start + 1 <= last for first, last in tests)
        for first, last, piece in search_pieces(body, head=item, fits=fits):
            chunks.append(
                {
                    "source": "code",
                    "path": path,
                    "commit": commit,
                    "lines": [first, last],
                    "kind": kind,
                    "item": item,
                    "test": test,
                    "head": item,
                    "text": piece,
                }
            )
    return chunks


def search_markdown_chunks(text, fits=None):
    """Chunks of a Markdown text, each inside one section and carrying its headings."""
    headings, numbered, chunks = [], [], []

    def close():
        title = " > ".join(headings)
        for first, last, piece in search_pieces(numbered, head=title, fits=fits):
            chunks.append({"section": title, "lines": [first, last], "head": title, "text": piece})

    fence = False
    for number, line in enumerate(text.split("\n"), 1):
        if line.lstrip().startswith(("```", "~~~")):
            fence = not fence
        heading = None if fence else SEARCH_HEADING.match(line)
        if heading:
            close()
            numbered = []
            headings = headings[: len(heading.group(1)) - 1] + [heading.group(2)]
            continue
        numbered.append((number, line))
    close()
    return chunks


def search_kb_chunks(entries, fits=None):
    """Chunks of the knowledge base: findings' state-bearing sections and design documents.

    A finding is cut only along the sections `kb show` serves, so the search reaches
    nothing the other commands withhold (R-KB-4), and each chunk carries the files and
    symbols the finding cites.
    """
    chunks = []
    for entry in entries:
        origin = Path(entry["root"]).name
        if entry["kind"] == "finding":
            text = kb_text(entry)
            claim = entry.get("claim") or {}
            refs = entry.get("refs") or {}
            for section in KB_STATE_SECTIONS:
                span = (entry.get("sections") or {}).get(section)
                if not span:
                    continue
                first = text.count("\n", 0, span[0]) + 1
                body = text[span[0] : span[1]].split("\n")
                numbered = [(first + offset, line) for offset, line in enumerate(body)]
                head = f"{claim.get('summary', '')}\n{section}"
                for start, last, piece in search_pieces(numbered, head=head, fits=fits):
                    chunks.append(
                        {
                            "source": "finding",
                            "root": entry["root"],
                            "origin": origin,
                            "identifier": entry["identifier"],
                            "path": entry["path"],
                            "section": section,
                            "lines": [start, last],
                            "state": entry["state"],
                            "modules": entry["modules"],
                            "severity": claim.get("severity_current", ""),
                            "remediation": claim.get("remediation_status", ""),
                            "files": (refs.get("paths") or [])[:KB_REF_SHOWN],
                            "symbols": (refs.get("symbols") or [])[:KB_REF_SHOWN],
                            "head": head,
                            "text": piece,
                        }
                    )
        elif entry["path"].split("/", 1)[0] in SEARCH_KB_DOC_DIRS:
            for chunk in search_markdown_chunks(kb_text(entry), fits=fits):
                chunk.update(
                    source="kb",
                    root=entry["root"],
                    origin=origin,
                    identifier=entry["identifier"],
                    path=entry["path"],
                )
                chunks.append(chunk)
    return chunks


def search_head_files(repo):
    """The commit at HEAD and its Rust and Markdown files outside statelens/, with blob ids."""
    commit = git(repo, "rev-parse", "--short=12", "HEAD").strip()
    files = []
    for record in git(repo, "ls-tree", "-r", "-z", "HEAD").split("\0"):
        meta, _, path = record.partition("\t")
        if not path or path.startswith(f"{SL}/") or not path.endswith((".rs", ".md")):
            continue
        _mode, kind, blob = meta.split()
        if kind == "blob":
            files.append((path, blob))
    return commit, files


def search_blobs(repo, blobs):
    """The text of every blob, read through one `git cat-file --batch`."""
    if not blobs:
        return {}
    output = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=repo,
        input="".join(f"{blob}\n" for blob in blobs).encode(),
        capture_output=True,
        check=True,
    ).stdout
    texts, position = {}, 0
    for blob in blobs:
        end = output.index(b"\n", position)
        header = output[position:end].split()
        if len(header) < 3:
            position = end + 1
            continue
        size = int(header[2])
        texts[blob] = output[end + 1 : end + 1 + size].decode("utf-8", "replace")
        position = end + 1 + size + 1
    return texts


def search_text(chunk):
    """What is embedded and matched for a chunk: its item or headings, then its text."""
    return f"{chunk['head']}\n{chunk['text']}"


@contextlib.contextmanager
def search_lock(sl_dir, exclusive):
    """The index's lock: exclusive while a generation is published, shared while one is read.

    A publication renames, switches and deletes generations, so two at once could each
    delete what the other made current, and either could delete the generation a query
    has chosen and not yet read. Writers therefore take turns, and a writer waits for the
    readers. The lock is advisory, and the kernel releases it if its holder dies; a
    thread holding it must not ask for it again.
    """
    path = sl_dir / SEARCH_LOCK
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def search_manifest(sl_dir):
    """The manifest of the index, naming the generation that is current, or None."""
    try:
        manifest = json.loads((sl_dir / SEARCH_DIR / "manifest.json").read_text())
    except (OSError, ValueError):
        return None
    generation = manifest.get("generation") if isinstance(manifest, dict) else None
    if not isinstance(generation, str) or not re.fullmatch(r"generation-\d+", generation):
        return None
    return manifest


def search_ready(sl_dir):
    with search_lock(sl_dir, exclusive=False):
        manifest = search_manifest(sl_dir)
        return manifest is not None and (
            sl_dir / SEARCH_DIR / manifest["generation"] / "chunks.jsonl"
        ).is_file()


def search_load(sl_dir):
    """The index as (manifest, chunks, vector bytes), or (None, [], b"") without one.

    A build writes a whole generation, its chunks and their vectors, and only then
    switches the manifest to it, so the manifest always names a finished one; a
    generation that does not add up all the same is no index at all, never a mix.
    """
    with search_lock(sl_dir, exclusive=False):
        manifest = search_manifest(sl_dir)
        if manifest is None:
            return None, [], b""
        folder = sl_dir / SEARCH_DIR / manifest["generation"]
        try:
            chunks = [
                json.loads(line)
                for line in (folder / "chunks.jsonl").read_text().splitlines()
                if line
            ]
            vectors = (folder / "vectors.f32").read_bytes() if manifest.get("model") else b""
        except (OSError, ValueError):
            return None, [], b""
    width = int(manifest.get("dim") or 0) * 4
    if len(chunks) != manifest.get("chunks") or (
        manifest.get("model") and len(vectors) != len(chunks) * width
    ):
        return None, [], b""
    return manifest, chunks, vectors


def search_publish(sl_dir, chunks, rows, manifest):
    """Writes a new generation of the index, then makes it current.

    The chunks and their vectors go to a staging directory, which is renamed into
    place whole, and only then does the manifest switch to it, itself by an atomic
    rename. An interruption anywhere before the switch leaves the previous
    generation current and complete; the next build removes what it left behind.
    All of it holds the exclusive lock, so no other publication or query is in the
    middle of a generation this one deletes.
    """
    base = sl_dir / SEARCH_DIR
    with search_lock(sl_dir, exclusive=True):
        base.mkdir(parents=True, exist_ok=True)
        generation = f"generation-{time.time_ns()}"
        staging = base / f"{generation}.tmp"
        staging.mkdir()
        (staging / "chunks.jsonl").write_text(
            "".join(json.dumps(chunk, sort_keys=True) + "\n" for chunk in chunks)
        )
        if rows:
            with (staging / "vectors.f32").open("wb") as out:
                for row in rows:
                    out.write(row)
        os.replace(staging, base / generation)
        manifest = dict(manifest, generation=generation)
        pending = base / "manifest.json.tmp"
        pending.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
        os.replace(pending, base / "manifest.json")
        for entry in base.iterdir():
            if entry.name in ("manifest.json", generation):
                continue
            if entry.is_dir():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink(missing_ok=True)
    return manifest


def search_embedder(model, offline):
    """A function turning texts into unit vectors on the CPU, or (None, why not).

    The model is a Hugging Face name or a local directory. A build may download it once;
    a query runs with the hub offline, so it uses what is on disk or nothing. A GPU is
    never needed: a small model embeds about 1,500 chunks a second on a laptop CPU.
    """
    if offline:
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        return None, "the sentence-transformers package is not installed"
    try:
        # Loading prints a progress bar per weight, which floods an agent's log.
        from transformers.utils import logging as transformers_logging

        transformers_logging.disable_progress_bar()
        transformers_logging.set_verbosity_error()
    except ImportError:
        pass
    def why(error):
        first = str(error).strip().splitlines()[0] if str(error).strip() else ""
        return first or type(error).__name__

    try:
        # From disk first: a model already here needs no network, even for a build.
        loaded = SentenceTransformer(model, device="cpu", local_files_only=True)
    except Exception as error:  # any failure to load leaves ranking by words
        if offline:
            return None, f"{model} is not on disk ({why(error)}); run `just search-index`"
        say(f"search-index: {model} is not on disk; downloading it")
        try:
            loaded = SentenceTransformer(model, device="cpu")
        except Exception as error:  # any failure to load leaves ranking by words
            return None, f"cannot load {model}: {why(error)}"

    def embed(texts):
        return loaded.encode(
            list(texts),
            batch_size=64,
            normalize_embeddings=True,
            show_progress_bar=False,
            convert_to_numpy=True,
        )

    # The model reads at most `max_seq_length` tokens and ignores the rest, so a chunk is
    # cut until it fits by the model's own tokenizer, special tokens included.
    window = int(getattr(loaded, "max_seq_length", 0) or 256)
    tokenizer = loaded.tokenizer

    def fits(text):
        ids = tokenizer(text, add_special_tokens=True, truncation=False, verbose=False)
        return len(ids["input_ids"]) <= window

    embed.fits = fits
    return embed, None


def search_pack(vector):
    """A vector as little-endian 32-bit floats."""
    if hasattr(vector, "astype"):
        return vector.astype("<f4").tobytes()
    return struct.pack(f"<{len(vector)}f", *vector)


def search_build(repo, sl_dir, config, rebuild=False, embed=None):
    """Builds or updates the search index and returns its manifest (SPEC section 5.10).

    The code and the documentation are read at HEAD, so every line a hit cites is
    `path:line@commit` and a checkout's uncommitted edits, instrumentation included,
    never reach the index. The model is loaded first, because its tokenizer decides
    where a chunk must be cut to fit what the model reads. A chunk whose text is
    unchanged keeps its vector, so an update embeds only what changed; a different
    model, or `rebuild`, embeds all. The result is published as a new generation
    (`search_publish`), so an interrupted build never leaves a mixed index.
    """
    model = (config.get("STATELENS_SEARCH_MODEL") or "").strip() or SEARCH_DEFAULT_MODEL
    started = time.monotonic()
    reason = None
    if embed is None:
        embed, reason = search_embedder(model, offline=False)
    fits = getattr(embed, "fits", None)
    commit, files = search_head_files(repo)
    texts = search_blobs(repo, sorted({blob for _, blob in files}))
    test_modules = search_test_modules(
        {path: texts.get(blob, "") for path, blob in files if path.endswith(".rs")}
    )
    chunks = []
    for path, blob in files:
        if path.endswith(".rs"):
            chunks += search_rust_chunks(path, texts.get(blob, ""), commit, test_modules, fits)
            continue
        for chunk in search_markdown_chunks(texts.get(blob, ""), fits=fits):
            chunk.update(source="doc", path=path, commit=commit)
            chunks.append(chunk)
    try:
        roots = kb_roots(repo, config)
    except Abort as error:
        roots = []
        say(f"search-index: no knowledge base ({error}); indexing this repository only")
    if roots:
        entries, _ = kb_index(sl_dir, roots)
        chunks += search_kb_chunks(entries, fits=fits)
    for number, chunk in enumerate(chunks):
        chunk["id"] = number
        chunk["hash"] = hashlib.sha1(search_text(chunk).encode()).hexdigest()
        chunk["ntok"] = len(search_tokens(search_text(chunk)))
    previous, old_chunks, old_vectors = search_load(sl_dir)
    reuse = {}
    if previous and old_vectors and not rebuild and previous.get("model") == model:
        width = int(previous["dim"]) * 4
        for index, chunk in enumerate(old_chunks):
            reuse[chunk["hash"]] = old_vectors[index * width : (index + 1) * width]
    fresh = {}
    if embed is not None:
        missing = list({chunk["hash"]: chunk for chunk in chunks if chunk["hash"] not in reuse}.values())
        if missing:
            say(f"search-index: embedding {len(missing)} of {len(chunks)} chunk(s) with {model} on the CPU")
        for start in range(0, len(missing), SEARCH_BATCH):
            batch = missing[start : start + SEARCH_BATCH]
            for chunk, vector in zip(batch, embed([search_text(item) for item in batch])):
                fresh[chunk["hash"]] = search_pack(vector)
    sample = next(iter(fresh.values()), None) or next(iter(reuse.values()), None)
    dim = len(sample) // 4 if embed is not None and sample else 0
    rows = [fresh.get(chunk["hash"]) or reuse[chunk["hash"]] for chunk in chunks] if dim else []
    sources = collections.Counter(chunk["source"] for chunk in chunks)
    manifest = search_publish(
        sl_dir,
        chunks,
        rows,
        {
            "model": model if dim else None,
            "dim": dim,
            "commit": commit,
            "built": utc_now().isoformat(timespec="seconds"),
            "chunks": len(chunks),
            "sources": dict(sorted(sources.items())),
            "embedded": len(fresh),
            "reason": None if dim else (reason or "nothing was embedded"),
        },
    )
    counts = ", ".join(f"{count} {name}" for name, count in sorted(sources.items()))
    how = f"{len(fresh)} embedded with {model}" if dim else f"ranked by words only: {manifest['reason']}"
    say(
        f"search-index: {len(chunks)} chunk(s) of commit {commit} ({counts}); {how}; "
        f"{time.monotonic() - started:.0f}s"
    )
    return manifest


def search_bm25(chunks, candidates, question):
    """The candidates sharing a word with `question`, best BM25 score first."""
    terms = list(dict.fromkeys(search_tokens(question)))
    if not terms or not candidates:
        return []
    wanted = set(terms)
    average = sum(chunks[index]["ntok"] for index in candidates) / len(candidates) or 1.0
    counts = {}
    for index in candidates:
        text = search_text(chunks[index])
        lowered = text.lower()
        if any(term in lowered for term in terms):
            counter = collections.Counter(token for token in search_tokens(text) if token in wanted)
            if counter:
                counts[index] = counter
    frequency = collections.Counter(term for counter in counts.values() for term in counter)
    total = len(candidates)
    scores = {}
    for index, counter in counts.items():
        length = chunks[index]["ntok"] or 1
        score = 0.0
        for term, seen in counter.items():
            idf = math.log(1 + (total - frequency[term] + 0.5) / (frequency[term] + 0.5))
            score += idf * seen * 2.2 / (seen + 1.2 * (0.25 + 0.75 * length / average))
        scores[index] = score
    return sorted(scores, key=lambda index: (-scores[index], index))


def search_cosine(vectors, dim, candidates, query):
    """Each candidate's similarity to `query`: the dot product of unit vectors."""
    try:
        import numpy
    except ImportError:
        numpy = None
    if numpy is not None:
        matrix = numpy.frombuffer(vectors, dtype="<f4").reshape(-1, dim)
        return (matrix[candidates] @ numpy.asarray(query, dtype="<f4").reshape(dim)).tolist()
    values = list(query)
    return [
        sum(a * b for a, b in zip(struct.unpack_from(f"<{dim}f", vectors, index * dim * 4), values))
        for index in candidates
    ]


def search_rank(chunks, vectors, dim, question, embed, keep):
    """(chunk indices best first, fused scores, chunks in scope, how they were ranked).

    BM25 and embedding similarity each rank the chunks `keep` admits, and reciprocal
    rank fusion merges the two: a small model misses exact identifiers that BM25
    finds, and BM25 misses the paraphrase the model finds. Without a model, BM25
    ranks alone.
    """
    candidates = [index for index, chunk in enumerate(chunks) if keep(chunk)]
    rankings = [search_bm25(chunks, candidates, question)]
    if embed is not None and vectors and candidates:
        query = embed([question])[0]
        scores = search_cosine(vectors, dim, candidates, query)
        order = sorted(range(len(candidates)), key=lambda at: (-scores[at], candidates[at]))
        rankings.append([candidates[at] for at in order])
    fused = collections.defaultdict(float)
    for ranking in rankings:
        for rank, index in enumerate(ranking[:SEARCH_POOL], 1):
            fused[index] += 1.0 / (SEARCH_RRF_K + rank)
    order = sorted(fused, key=lambda index: (-fused[index], index))
    return order, fused, len(candidates), len(rankings) == 2


def search_hit(rank, chunk):
    """One hit, as the agent reads it: where it is, then the start of its text."""
    first, last = chunk["lines"]
    lines = f"{first}" if first == last else f"{first}-{last}"
    source = chunk["source"]
    section = f" ## {chunk['section']}" if chunk.get("section") else ""
    if source == "finding":
        head = f"{chunk['identifier']} ({chunk['origin']}){section}"
    elif source == "kb":
        head = f"{chunk['path']}:{lines} ({chunk['origin']}){section}"
    elif source == "code":
        test = "  (test code)" if chunk.get("test") else ""
        head = f"{chunk['path']}:{lines}@{chunk['commit']}  {chunk['item']}{test}"
    else:
        head = f"{chunk['path']}:{lines}@{chunk['commit']}{section}"
    out = [f"{rank}. {source}  {head}"]
    if source == "finding":
        out.append(
            f"    state={chunk['state']} module={', '.join(chunk['modules'])} "
            f"severity={chunk.get('severity') or '?'} remediation={chunk.get('remediation') or '?'}"
        )
    text = [line.strip() for line in chunk["text"].split("\n") if line.strip()]
    for line in text[:SEARCH_SNIPPET_LINES]:
        out.append("    " + (line if len(line) <= 160 else line[:157] + "..."))
    if len(text) > SEARCH_SNIPPET_LINES:
        out.append(f"    ... {len(text) - SEARCH_SNIPPET_LINES} more line(s)")
    for name, label in (("files", "files"), ("symbols", "symbols")):
        if chunk.get(name):
            out.append(f"    {label}: {', '.join(chunk[name])}")
    return "\n".join(out)


def cmd_kb_search(args):
    """`kb search`: ranked snippets for a question in plain words (SPEC section 5.10)."""
    sl_dir = repo_root() / SL
    manifest, chunks, vectors = search_load(sl_dir)
    if manifest is None:
        raise Abort(1, "there is no search index yet; build it with `just search-index`")
    question = " ".join(args.question).strip()
    if not question:
        raise Abort(1, "kb search needs a question")
    sources = set(args.source or SEARCH_SOURCES)
    prefixes = [prefix.rstrip("/") for prefix in args.path or []]
    registry = args.registry

    def keep(chunk):
        if chunk["source"] not in sources:
            return False
        if chunk["source"] == "finding":
            return any(module_matches(module, registry) for module in chunk.get("modules") or [])
        if chunk["source"] == "code" and chunk.get("test") and not args.tests:
            return False
        if prefixes and chunk["source"] in ("code", "doc"):
            return any(chunk["path"] == p or chunk["path"].startswith(p + "/") for p in prefixes)
        return True

    embed, reason = None, manifest.get("reason") or "the index has no vectors"
    if manifest.get("model") and vectors:
        embed, reason = search_embedder(manifest["model"], offline=True)
    order, _scores, pool, dense = search_rank(
        chunks, vectors, int(manifest.get("dim") or 0), question, embed, keep
    )
    limit = max(1, min(args.limit, SEARCH_MAX_LIMIT))
    for rank, index in enumerate(order[:limit], 1):
        print(search_hit(rank, chunks[index]))
    how = f"by meaning and by words ({manifest['model']})" if dense else f"by words only ({reason})"
    print(
        f"\n{min(len(order), limit)} hit(s) of {pool} chunk(s) in scope, ranked {how}; "
        f"code and documentation as of commit {manifest.get('commit')}"
    )
    return 0


def cmd_search_index(args):
    """`just search-index`: build or update the search index (SPEC section 5.10)."""
    repo = repo_root()
    manifest = search_build(repo, repo / SL, load_config(repo / SL), rebuild=args.rebuild)
    return 0 if manifest.get("model") else 2


def campaign_artifacts(repo):
    """(created paths that exist, tracked paths a campaign edits) (SPEC section 5.4)."""
    variants = [
        path
        for profile in PROFILES
        for path in sorted((repo / profile_fuzz_dir(profile)).glob("*_statelens.rs"))
    ]
    created = [path for path in CREATED_PATHS if (repo / path).exists()]
    created += sorted({str(path.relative_to(repo)) for path in variants})
    edited = [path for path in EDITED_PATHS if (repo / path).exists()]
    return created, edited



# --- Code index (SPEC section 5.7) -------------------------------------------
#
# `rust-analyzer scip` writes a SCIP index: one protobuf file naming every
# definition and every reference in the crate, keyed by a symbol string that
# distinguishes a field from a same-named method. Text search cannot make that
# distinction, and in this crate the names collide often: `proposal` is five
# different methods, `construct_notarize` is three.
#
# The format is read here directly rather than through a protobuf library, so
# the subproject stays stdlib-only (R-LAYOUT-3). Only these fields are needed:
#
#   Index.documents            = 2   Document.relative_path     = 1
#   Document.occurrences       = 2   Document.symbols           = 3
#   Occurrence.range           = 1   Occurrence.symbol          = 2
#   Occurrence.symbol_roles    = 3   Occurrence.enclosing_range = 7
#   SymbolInformation.symbol   = 1   SymbolInformation.display_name = 6
#
# rust-analyzer leaves SymbolInformation.relationships empty, so the index
# carries no implementation edges, and it leaves the WriteAccess/ReadAccess role
# bits unset, so an occurrence does not say whether it reads or writes. It does
# populate enclosing_range on definitions, which is what makes callers and
# callees derivable: a reference belongs to whichever definition's range
# contains its line. A `local N` symbol is scoped to its document, and the
# numbering restarts in every file, so the loader keys locals by file.

SCIP_INDEX = "extract/code-index.scip"
SCIP_ROLE_DEFINITION = 0x1
SCIP_CALLABLE = "()."
SCIP_LOCAL = "local "
CODE_HITS_LIMIT = 40


def index_key(symbol, relative):
    """The identity a symbol has across the whole index.

    A global symbol is unique by construction. A `local N` symbol is unique
    only within its document: the same text names an unrelated binding in
    every other file (`local 0` occurs in 218 of this crate's files), so it is
    qualified by the file that defines it.
    """
    if symbol.startswith(SCIP_LOCAL):
        return f"{symbol} in {relative}"
    return symbol


def index_is_local(symbol):
    return symbol.startswith(SCIP_LOCAL)


def scip_varint(buf, i):
    """Decode one protobuf varint, returning (value, next offset)."""
    shift = result = 0
    while True:
        byte = buf[i]
        i += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, i
        shift += 7


def scip_fields(buf, start=0, end=None):
    """Yield (field number, wire type, payload) for one protobuf message."""
    i = start
    end = len(buf) if end is None else end
    while i < end:
        key, i = scip_varint(buf, i)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, i = scip_varint(buf, i)
            yield number, wire, value
        elif wire == 2:
            length, i = scip_varint(buf, i)
            yield number, wire, buf[i : i + length]
            i += length
        elif wire == 5:
            yield number, wire, buf[i : i + 4]
            i += 4
        elif wire == 1:
            yield number, wire, buf[i : i + 8]
            i += 8
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")


def scip_packed(payload):
    """Decode a packed repeated int32 field."""
    out, i = [], 0
    while i < len(payload):
        value, i = scip_varint(payload, i)
        out.append(value)
    return out


def index_load(path):
    """Read a SCIP index into (occurrences, definitions, display names).

    Occurrences are (symbol, path, line, is definition). Definitions map a
    symbol to (path, first line, last line) covering the whole item, 1-based.
    Symbols are the keys of `index_key`, so a file-local one never merges
    with its namesake in another file.
    """
    raw = memoryview(path.read_bytes())
    crate = index_crate(raw)
    occurrences = []
    definitions = {}
    names = {}
    for number, _wire, document in scip_fields(raw):
        if number != 2:
            continue
        relative, occs, syms = None, [], []
        for field, _w, payload in scip_fields(document):
            if field == 1:
                # SCIP paths are relative to the indexed crate; make them
                # repo-relative so that a hit can be opened and read directly.
                relative = f"{crate}/" + bytes(payload).decode("utf-8", "replace")
            elif field == 2:
                occs.append(payload)
            elif field == 3:
                syms.append(payload)
        if relative is None:
            continue
        for entry in syms:
            symbol = display = None
            for field, _w, payload in scip_fields(entry):
                if field == 1:
                    symbol = bytes(payload).decode("utf-8", "replace")
                elif field == 6:
                    display = bytes(payload).decode("utf-8", "replace")
            if symbol and display:
                names[index_key(symbol, relative)] = display
        for entry in occs:
            span = symbol = enclosing = None
            roles = 0
            for field, wire, payload in scip_fields(entry):
                if field == 1:
                    span = scip_packed(payload) if wire == 2 else [payload]
                elif field == 2:
                    symbol = bytes(payload).decode("utf-8", "replace")
                elif field == 3:
                    roles = payload
                elif field == 7:
                    enclosing = scip_packed(payload) if wire == 2 else None
            if not symbol or not span:
                continue
            symbol = index_key(symbol, relative)
            line = span[0] + 1
            is_def = bool(roles & SCIP_ROLE_DEFINITION)
            occurrences.append((symbol, relative, line, is_def))
            if roles & SCIP_ROLE_DEFINITION and enclosing:
                # A SCIP range is [start line, start char, end line, end char],
                # but collapses to [start line, start char, end char] when it
                # begins and ends on one line, so the third element is only a
                # line number in the four-element form.
                if len(enclosing) >= 4:
                    first, last = enclosing[0] + 1, enclosing[2] + 1
                elif len(enclosing) == 3:
                    first = last = enclosing[0] + 1
                else:
                    continue
                definitions[symbol] = (relative, first, last)
    return occurrences, definitions, names


def index_crate(raw):
    """The directory of the crate a SCIP index describes, from its metadata.

    `rust-analyzer scip <crate>` records the crate's directory as the project root
    (Index.metadata = 1, Metadata.project_root = 3), and every document path is relative
    to it. The crates StateLens indexes sit at the top of the repository, so the last
    component is the directory. An index without metadata is taken to be of consensus.
    """
    for number, _wire, metadata in scip_fields(raw):
        if number == 1:
            for field, _w, payload in scip_fields(metadata):
                if field == 3:
                    root = bytes(payload).decode("utf-8", "replace").rstrip("/")
                    return root.rsplit("/", 1)[-1] or "consensus"
    return "consensus"


def index_path(sl_dir):
    return sl_dir / SCIP_INDEX


def index_build(repo, sl_dir, subsystem):
    """Write the SCIP index for the crate that owns `subsystem`.

    rust-analyzer writes beside the index, and its output replaces the index only once
    the build succeeded, so a failed or interrupted build leaves the previous index
    whole rather than half overwritten. The previous snapshot goes with the previous
    index: a snapshot always describes the index beside it, or is absent.
    """
    if shutil.which("rust-analyzer") is None:
        say(
            "rust-analyzer is not installed, so the code index cannot be built.\n"
            "Install it with `rustup component add rust-analyzer`."
        )
        return None
    crate = PROFILES[subsystem]["crate"]
    out = index_path(sl_dir)
    out.parent.mkdir(parents=True, exist_ok=True)
    staged = out.with_name(out.name + ".new")
    say(f"building the code index for {crate} (several minutes)")
    command = [
        "rust-analyzer",
        "scip",
        crate,
        "--output",
        str(staged),
        "--exclude-vendored-libraries",
    ]
    log = sl_dir / "extract" / "code-index.log"
    # rust-analyzer logs at ERROR level for things that do not stop the build,
    # such as a definition inside a module a macro declared, which it cannot
    # name. On a console that reads as a failure scrolling past for minutes, so
    # the output goes to the log only, and to the console when the build fails.
    say(f"rust-analyzer output goes to {log.relative_to(repo)}")
    code, tail = run_logged(command, log, cwd=repo, echo=False)
    if code != 0 or not staged.exists():
        staged.unlink(missing_ok=True)
        for line in tail:
            print(line, flush=True)
        say(f"the code index build failed; see {log.relative_to(repo)}")
        return None
    os.replace(staged, out)
    snapshot_path(sl_dir).unlink(missing_ok=True)
    size = out.stat().st_size
    # Snapshot exactly the files the index describes, so a later query can
    # rebase its line numbers onto the tree as instrumentation changes it.
    try:
        occurrences, _definitions, _names = index_load(out)
        kept = snapshot_write(repo, sl_dir, {path for _s, path, _l, _d in occurrences})
    except (ValueError, IndexError, OSError) as error:
        # The index is written and queryable; only rebasing needs the snapshot,
        # and a query says so when it is absent.
        say(f"wrote {out.relative_to(repo)} ({size // (1 << 20)} MiB)")
        say(f"could not snapshot the indexed sources ({error}); lines will not be rebased")
        return out
    say(f"wrote {out.relative_to(repo)} ({size // (1 << 20)} MiB, {kept} file(s) snapshotted)")
    return out


def index_test_ranges(repo, relative):
    """The line ranges a file puts behind `#[cfg(test)]`.

    Much of this crate is test code living in the same files as the code it
    exercises, so neither the path nor the index separates them. A file suffix
    is the wrong rule: `simplex/actors/voter/mod.rs` gates a single re-export at
    line 18 and then declares production configuration at 22, with its test
    module only at 52, so treating everything from the first attribute as test
    code hides the configuration.

    An attribute is leading trivia of the item it annotates, so that item begins
    at the attribute and its extent is exactly the range to exclude. Without
    rust-analyzer there is no tree to ask, and the fallback looks for the test
    module alone, since a `#[cfg(test)] mod` is the shape that runs to the end
    of a file. A `mocks` file is test support throughout.
    """
    name = Path(relative)
    if "mocks" in name.parts or name.stem == "mocks":
        return [(1, None)]
    path = repo / relative
    if ast_available():
        try:
            nodes, line_of, source = ast_tree(path)
        except (Abort, OSError):
            nodes = None
        if nodes is not None:
            ranges = []
            for _index, node, ancestors in ast_walk(nodes):
                _depth, kind, start, end = node
                if kind != "ATTR" or b"cfg(test)" not in source[start:end]:
                    continue
                # An attribute is a child of the item it applies to, whatever
                # comes before it: a doc comment or a second attribute moves the
                # item's start, so its offset cannot identify it.
                found = ast_innermost(ancestors)
                if found is None:
                    continue
                _item_index, item = found
                if item[1] == "SOURCE_FILE":
                    return [(1, None)]
                ranges.append((line_of(item[2]), line_of(item[3] - 1)))
            return ranges
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    number = cfg_test_module_line(text.splitlines())
    return [(number, None)] if number else []


def cfg_test_module_line(lines):
    """The line of a `#[cfg(test)] mod`, which runs to the end of its file, or None."""
    for number, line in enumerate(lines, 1):
        if not line.startswith("#[cfg(test)]"):
            continue
        # The item may follow on the same line (`#[cfg(test)] mod tests {`), and a
        # comment there is not the item.
        following = line[len("#[cfg(test)]"):].split("//", 1)[0].strip() or next(
            (one for one in lines[number:] if one.strip() and not one.startswith("#[")),
            "",
        )
        if following.lstrip().startswith(("mod ", "pub mod ")):
            return number
    return None


def index_is_test(repo, ranges, relative, line):
    if relative not in ranges:
        ranges[relative] = index_test_ranges(repo, relative)
    return any(
        first <= line and (last is None or line <= last)
        for first, last in ranges[relative]
    )


def index_match(occurrences, definitions, names, needle):
    """Symbols whose display name or symbol string matches `needle`.

    An exact display name wins, so `refs construct_notarize` reports the three
    symbols that carry that name rather than everything containing the text.
    A local variable is visible only inside its function, and this crate has
    646 of them named `view` against 50 fields and methods, so locals are set
    aside whenever a global carries the name; `index_locals` counts them. The
    text of a local symbol is `local N` plus its file, which names nothing, so
    the substring fallbacks skip locals.
    """
    exact = {sym for sym, display in names.items() if display == needle}
    if any(not index_is_local(sym) for sym in exact):
        exact = {sym for sym in exact if not index_is_local(sym)}
    if not exact:
        exact = {sym for sym in definitions if needle in sym and not index_is_local(sym)}
    if not exact:
        exact = {
            sym
            for sym, _p, _l, _d in occurrences
            if needle in sym and not index_is_local(sym)
        }
    return sorted(exact)


def index_locals(names, needle, symbols):
    """How many locals named `needle` the match set aside."""
    if any(index_is_local(sym) for sym in symbols):
        return 0
    return sum(1 for sym, display in names.items() if display == needle and index_is_local(sym))


def index_enclosing(definitions, relative, line):
    """The definition whose extent contains `line`, innermost first.

    A local's extent is its own binding, so a call on a `let` line would
    otherwise be reported as inside the variable rather than the function.
    """
    best = None
    for symbol, (path, start, end) in definitions.items():
        if path != relative or not start <= line <= end or index_is_local(symbol):
            continue
        if best is None or (end - start) < (best[2] - best[1]):
            best = (symbol, start, end)
    return best[0] if best else None


def index_short(symbol, names):
    """A symbol string trimmed to what identifies it in output.

    A SCIP symbol is `scheme manager package version descriptor`, and the
    descriptor itself can contain spaces inside backticks (`impl#[`Round<S,
    D>`]method().`), so only the first four spaces separate fields.
    """
    parts = symbol.split(" ", 4)
    tail = parts[4] if len(parts) == 5 else symbol
    tail = tail.rstrip(".")
    display = names.get(symbol)
    if display and display not in tail:
        return f"{tail} ({display})"
    return tail


def index_subsystem(sl_dir):
    """The subsystem `code build` indexes when none is named (SPEC section 5.7).

    The campaign's profile when this checkout has one, so a rebuild in a campaign's
    checkout keeps the crate the campaign instruments; else a profile of the crate the
    current index describes; else simplex.
    """
    profile = campaign_profile(sl_dir)
    if profile in PROFILES:
        return profile
    index = index_path(sl_dir)
    if index.is_file():
        try:
            crate = index_crate(memoryview(index.read_bytes()))
        except (OSError, ValueError, IndexError):
            crate = None
        for name, settings in PROFILES.items():
            if settings["crate"] == crate:
                return name
    return "simplex"


def cmd_code(args):
    """Entity identification over the SCIP index (SPEC section 5.7)."""
    repo = repo_root()
    sl_dir = repo / SL
    if args.query == "build":
        subsystem = args.subsystem or index_subsystem(sl_dir)
        return 0 if index_build(repo, sl_dir, subsystem) else 1
    index = index_path(sl_dir)
    if not index.exists():
        say(
            f"no code index at {index.relative_to(repo)}.\n"
            "Build it with `just code-index`, or `statelens.py code build`."
        )
        return 1
    occurrences, definitions, names = index_load(index)
    rebaser = Rebaser(repo, sl_dir)
    # Said before any result, because an answer of "nothing matches" is the one
    # most likely to be wrong when the tree has moved on from the index.
    warning = rebaser.report()
    if warning:
        say(warning)
    symbols = index_match(occurrences, definitions, names, args.name)
    if not symbols:
        print(f"no symbol matches {args.name!r} in {index.relative_to(repo)}")
        return 1
    by_symbol = collections.defaultdict(list)
    for symbol, path, line, is_def in occurrences:
        by_symbol[symbol].append((path, line, is_def))
    boundaries = {}

    def wanted(path, line):
        if args.tests:
            return True
        # The boundary is read from the file as it stands, so the line has to be
        # rebased onto it first; comparing an indexed line with a current
        # boundary can let a test site through as a production one.
        at, _note = rebaser.place(path, line)
        return not index_is_test(repo, boundaries, path, at)

    print(f"{len(symbols)} symbol(s) matching {args.name!r}\n")
    for symbol in symbols[:CODE_HITS_LIMIT]:
        where = definitions.get(symbol)
        sites = sorted(set(by_symbol.get(symbol, [])))
        kept = [site for site in sites if wanted(site[0], site[1])]
        hidden = len(sites) - len(kept)
        header = index_short(symbol, names)
        # The name to look for when checking that a rebased line still holds
        # the entity: the symbol's own display name, or what was asked for.
        display = names.get(symbol) or args.name
        if args.query == "defs":
            print(f"{header}")
            if where:
                first, note = rebaser.place(where[0], where[1], display)
                last, last_note = rebaser.place(where[0], where[2])
                print(f"    {rebase_extent(where[0], first, note, last, last_note)}")
            else:
                print("    (no definition in this crate)")
            continue
        if args.query == "refs":
            print(f"{header}    {len(kept)} shown, {hidden} in test code")
            for path, line, is_def in kept:
                at, note = rebaser.place(path, line, display)
                mark = f"  [{note}]" if note else ""
                print(
                    f"    {'def' if is_def else 'ref'}  "
                    f"{path}:{rebase_line(at, note)}{mark}"
                )
            print()
            continue
        if args.query == "callers":
            print(f"{header}")
            found = 0
            for path, line, is_def in kept:
                if is_def or (where and path == where[0] and where[1] <= line <= where[2]):
                    continue  # the definition itself, and its own body
                holder = index_enclosing(definitions, path, line)
                label = index_short(holder, names) if holder else "(top level)"
                at, note = rebaser.place(path, line, display)
                mark = f"  [{note}]" if note else ""
                print(f"    {path}:{rebase_line(at, note)}  in {label}{mark}")
                found += 1
            if not found:
                print("    (no call site outside its own body)")
            print()
            continue
        if args.query == "callees":
            if not where:
                print(f"{header}\n    (no definition in this crate)\n")
                continue
            path, start, end = where
            first, first_note = rebaser.place(path, start, display)
            last, last_note = rebaser.place(path, end)
            print(f"{header}    {rebase_extent(path, first, first_note, last, last_note)}")
            # A callee defined outside the indexed crate has no definition
            # here, which is how `!` (`bool::not`) and `Option::and_then` are
            # told from this crate's own functions. --all keeps them.
            inner = sorted(
                {
                    (other, line)
                    for other, opath, line, is_def in occurrences
                    if opath == path and start <= line <= end and other != symbol
                    and not is_def and other.endswith(SCIP_CALLABLE)
                    and (args.all or other in definitions)
                },
                key=lambda item: item[1],
            )
            for other, line in inner:
                at, note = rebaser.place(path, line)
                mark = f"  [{note}]" if note else ""
                print(
                    f"    {path}:{rebase_line(at, note)}  "
                    f"{index_short(other, names)}{mark}"
                )
            if not inner:
                print("    (calls nothing defined in this crate)")
            print()
    dropped = max(0, len(symbols) - CODE_HITS_LIMIT)
    if dropped:
        print(f"{dropped} further symbol(s) not shown")
    set_aside = index_locals(names, args.name, symbols)
    if set_aside:
        print(
            f"{set_aside} local variable(s) named {args.name!r} not shown: "
            "a local is visible only inside its function"
        )
    # Said again, because placing the hits can discover a file with no snapshot.
    after = rebaser.report()
    if after and after != warning:
        say(after)
    return 0



# --- Keeping the index honest as the tree is edited ------------------------
#
# The index is built before instrumentation, and instrumentation then edits the
# files it describes. Which function calls which survives that, but line
# numbers do not: a probe inserted above a reference moves it, and the index
# would go on naming the line it used to be on. Line numbers are the whole
# answer here, so a stale one is not a degraded answer, it is a wrong one.
#
# So the build snapshots the sources it indexed, and every query rebases its
# hits from that snapshot onto the file as it now stands. A line inside an
# unchanged run of text maps exactly; a line inside an edited run cannot be
# mapped and is reported as lost rather than guessed. After mapping, the
# identifier is looked for on the line it landed on, which catches the rest.
#
# Entities added after the build are absent from the index no matter how well
# hits are rebased, so a query says which files have changed. The remedy for
# both is `just code-index`.

SNAPSHOT = "extract/code-index-sources.json"


def snapshot_path(sl_dir):
    return sl_dir / SNAPSHOT


def snapshot_write(repo, sl_dir, relatives):
    """Record the text of every file the index describes."""
    stored = {}
    for relative in sorted(set(relatives)):
        try:
            stored[str(relative)] = (repo / relative).read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            continue
    path = snapshot_path(sl_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(stored), encoding="utf-8")
    return len(stored)


# Worst first. A `lost` or `unindexed` line is not a location at all, an
# `unverified` one is a location the name has left, and a `moved` one is simply
# current. Combining with `or` would let the first nonempty note win, so a start
# that merely moved would hide an end that cannot be placed.
REBASE_SEVERITY = ("lost", "unindexed", "unverified", "moved")
REBASE_INVALID = ("lost", "unindexed")


def rebase_worst(*notes):
    """The most serious of several endpoint notes."""
    for note in REBASE_SEVERITY:
        if note in notes:
            return note
    return ""


def rebase_line(line, note):
    """A line number, or `?` when the note says it is not one."""
    return f"?({line})" if note in REBASE_INVALID else str(line)


def rebase_extent(path, first, first_note, last, last_note):
    """`path:first-last`, with an endpoint that is not a location marked."""
    note = rebase_worst(first_note, last_note)
    mark = f"  [{note}]" if note else ""
    return (
        f"{path}:{rebase_line(first, first_note)}"
        f"-{rebase_line(last, last_note)}{mark}"
    )


class Rebaser:
    """Maps a line in the indexed text to the same line in the file today.

    `place` returns (line, note). The note is empty when the file has not
    changed, `moved` when the line was carried across an edit, `lost` when it
    sat inside an edited run, and `unverified` when it mapped but the name is
    no longer on it.
    """

    def __init__(self, repo, sl_dir):
        self.repo = repo
        # A campaign builds the index before it instruments and rebases through its own
        # edits rather than rebuilding (D43), so in its checkout an edit is expected.
        self.campaign = campaign_profile(sl_dir) is not None
        self.maps = {}
        self.changed = set()
        self.missing = set()
        self.added = set()
        self.unsnapshotted = set()
        self.lines = {}
        path = snapshot_path(sl_dir)
        try:
            self.snapshot = json.loads(path.read_text(encoding="utf-8"))
            self.built = path.stat().st_mtime
        except (OSError, ValueError):
            self.snapshot = None
        self.survey()

    def survey(self):
        """Compare every snapshotted file with the tree, before any hit is placed.

        Deciding this lazily, one queried file at a time, made the report depend
        on which files a query happened to touch: a query that matched nothing,
        or that matched only in files nobody had edited, reported a clean tree
        while another file was stale. Reading the snapshotted text is cheap
        against diffing it, so what changed is settled up front and only the
        line map stays lazy.

        A file added since the build is in neither the index nor the snapshot,
        so its entities cannot be found however well hits are rebased. Only the
        directories the snapshot covers are scanned, so a build artifact or a
        template that was never indexable is not mistaken for new source, and
        only files written since the snapshot, so a source the index skipped
        because no module declares it, such as a bench file, is not either.
        """
        if self.snapshot is None:
            return
        for key, stored in self.snapshot.items():
            current = self._read(key)
            if current is None:
                self.missing.add(key)
            elif current != stored:
                self.changed.add(key)
        directories = {str(Path(key).parent) for key in self.snapshot}
        for directory in sorted(directories):
            for found in (self.repo / directory).glob("*.rs"):
                relative = str(found.relative_to(self.repo))
                if relative not in self.snapshot and found.stat().st_mtime >= self.built:
                    self.added.add(relative)

    def _read(self, relative):
        """The file's text, or None when it is gone or unreadable.

        An empty file is text, not absence: an emptied source must count as
        changed rather than fall through as unchanged.
        """
        try:
            return (self.repo / str(relative)).read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            return None

    def available(self):
        return self.snapshot is not None

    def _current(self, relative):
        """The file as it stands, read once per query rather than per hit."""
        key = str(relative)
        if key not in self.lines:
            try:
                self.lines[key] = (
                    (self.repo / key).read_text(encoding="utf-8", errors="replace")
                ).splitlines()
            except OSError:
                self.lines[key] = []
        return self.lines[key]

    def _map_for(self, relative):
        """old line -> current line, or None when no rebasing is possible."""
        key = str(relative)
        if key in self.maps:
            return self.maps[key]
        mapping = None
        if key in self.missing:
            # The file is gone, so no line of it survives.
            mapping = {}
        elif key in self.changed:
            stored = self.snapshot[key]
            current = self._read(key) or ""
            mapping = {}
            matcher = difflib.SequenceMatcher(
                a=stored.splitlines(), b=current.splitlines(), autojunk=False
            )
            for tag, a0, a1, b0, b1 in matcher.get_opcodes():
                if tag == "equal":
                    for step in range(a1 - a0):
                        mapping[a0 + step + 1] = b0 + step + 1
        elif (self.snapshot or {}).get(key) is None:
            # In the index but not in the snapshot: nothing to rebase against,
            # so say so rather than pass the indexed line off as current.
            self.unsnapshotted.add(key)
        self.maps[key] = mapping
        return mapping

    def place(self, relative, line, name=None):
        mapping = self._map_for(relative)
        if mapping is None:
            if str(relative) in self.unsnapshotted:
                return line, "unindexed"
            return line, ""
        moved = mapping.get(line)
        if moved is None:
            return line, "lost"
        note = "moved" if moved != line else ""
        if name:
            text = self._current(relative)
            if not (0 < moved <= len(text)) or name not in text[moved - 1]:
                note = "unverified"
        return moved, note

    def report(self):
        """One line for the operator, or nothing when the tree is unchanged."""
        if not self.available():
            return (
                "no source snapshot beside the index, so lines are not rebased; "
                "rebuild with `just code-index`"
            )
        parts = []
        if self.changed:
            parts.append(
                f"{len(self.changed)} indexed file(s) have changed since the index was "
                "built: lines are rebased, and entities added since are missing"
            )
        if self.missing:
            parts.append(
                f"{len(self.missing)} indexed file(s) are gone or unreadable, so their "
                "hits are marked `lost`"
            )
        if self.added:
            parts.append(
                f"{len(self.added)} source file(s) appeared since the index was built, "
                "so nothing they define can be found"
            )
        if self.unsnapshotted:
            parts.append(
                f"{len(self.unsnapshotted)} file(s) have no snapshot, so their lines "
                "are marked `unindexed` and not rebased"
            )
        if not parts:
            return None
        if self.campaign and not (self.missing or self.unsnapshotted):
            return "; ".join(parts) + (
                ". These are the campaign's own instrumentation edits, which rebasing "
                "absorbs, so the index needs no rebuild during the campaign."
            )
        return "; ".join(parts) + ". Rebuild with `just code-index`."


# --- Syntax trees (SPEC section 5.8) -----------------------------------------
#
# `rust-analyzer parse` reads one file on stdin and prints its concrete syntax
# tree with a byte span on every node. It needs no cargo, no project and no
# index, and costs about a tenth of a second for a file of two thousand lines,
# so it answers the two questions the SCIP index cannot.
#
# The first is polarity. The index records that a line mentions an entity, not
# whether it reads or writes it, because rust-analyzer leaves SCIP's read and
# write role bits unset. An assignment is a shape in the tree: the token after
# the field expression is `=`.
#
# The second is comments. A comment is a token here, so it can be told from the
# same words in code or in a string, and the item it sits above is the next
# node after it. A comment about an ordering, a race or a case that cannot
# happen names the state it is about, which is what makes it a beacon.
#
# The tree carries no types: `$x.armed` is the same shape whichever type owns
# `armed`. Identity comes from the index, shape from the tree.

AST_NODE = re.compile(r'^(\s*)([A-Z_0-9]+)@(\d+)\.\.(\d+)(?: "(.*)")?$')
AST_TRIVIA = ("WHITESPACE", "COMMENT")
# `x = 1` and every `x op= 1`.
AST_ASSIGN = (
    "EQ", "PLUSEQ", "MINUSEQ", "STAREQ", "SLASHEQ", "PERCENTEQ",
    "AMPEQ", "PIPEEQ", "CARETEQ", "SHLEQ", "SHREQ",
)
AST_ITEMS = (
    "FN", "STRUCT", "ENUM", "IMPL", "TRAIT", "VARIANT", "RECORD_FIELD",
    "LET_STMT", "EXPR_STMT", "MATCH_ARM", "IF_EXPR", "WHILE_EXPR", "CONST",
    "TYPE_ALIAS", "MACRO_CALL", "USE",
)
AST_NOTE_DEFAULT = r"race|order|recover|replay|cannot happen|must not|never|stale|evict|assume"


def ast_available():
    return shutil.which("rust-analyzer") is not None


def ast_tree(path):
    """Parse one file. Returns (nodes, line_of, source bytes).

    A node is (depth, kind, start, end). `line_of` maps a byte offset to a
    1-based line. Token text in the dump is elided when long, so callers slice
    the source instead of trusting it.
    """
    source = path.read_bytes()
    result = subprocess.run(
        ["rust-analyzer", "parse"], input=source, capture_output=True
    )
    if result.returncode != 0:
        raise Abort(2, f"rust-analyzer parse failed on {path}")
    starts, offset = [0], 0
    for line in source.split(b"\n"):
        offset += len(line) + 1
        starts.append(offset)

    def line_of(position):
        low, high = 0, len(starts) - 1
        while low < high:
            middle = (low + high + 1) // 2
            if starts[middle] <= position:
                low = middle
            else:
                high = middle - 1
        return low + 1

    nodes = []
    for raw in result.stdout.decode("utf-8", "replace").splitlines():
        found = AST_NODE.match(raw)
        if found:
            indent, kind, start, end, _text = found.groups()
            nodes.append((len(indent), kind, int(start), int(end)))
    return nodes, line_of, source


def ast_walk(nodes):
    """Yield (index, node, ancestors) for each node, ancestors outermost first.

    Pre-order plus a depth is all that ancestry needs, so one pass with a stack
    gives it exactly. Deriving it per node by scanning backwards needs a cutoff,
    and every cutoff is a case that quietly behaves as though the node had no
    ancestor at all: a doc comment or a second attribute moves an item's start
    offset, and a macro body longer than the cutoff puts its `TOKEN_TREE` out of
    reach, which drops sites rather than reporting them.

    Each ancestor is carried as (its index, its node), so a consumer that needs
    to scan an ancestor's children does not have to search for it. The yielded
    list is the walker's own stack, so read it before asking for the next node.
    """
    stack = []
    for index, node in enumerate(nodes):
        while stack and stack[-1][1][0] >= node[0]:
            stack.pop()
        yield index, node, stack
        stack.append((index, node))


def ast_innermost(ancestors, kinds=None):
    """The nearest enclosing (index, node), optionally of one of `kinds`."""
    for entry in reversed(ancestors):
        if kinds is None or entry[1][1] in kinds:
            return entry
    return None


def ast_leads(nodes, index, item_index, item):
    """Whether nodes[index] sits before the item's first real token.

    A doc comment and an attribute are children of the item they belong to, and
    they come before its keyword, so this is what separates a comment that
    documents an item from one inside its body. The scan is bounded by the item
    rather than by a node count.
    """
    child_depth = item[0] + 2
    start = nodes[index][2]
    for position in range(item_index + 1, len(nodes)):
        depth, kind, node_start, _end = nodes[position]
        if node_start >= item[3]:
            break
        if depth != child_depth or kind in ("WHITESPACE", "COMMENT", "ATTR"):
            continue
        return start < node_start
    return False


def ast_next_significant(nodes, index, after):
    """The first node at or past byte `after` that is not trivia."""
    for position in range(index, len(nodes)):
        _depth, kind, start, _end = nodes[position]
        if start < after or kind in AST_TRIVIA:
            continue
        return nodes[position]
    return None


def ast_in_token_tree(ancestors):
    """Whether a token sits inside a macro body.

    `rust-analyzer parse` does not expand macros, so a macro body is a
    `TOKEN_TREE` of bare tokens with no expressions in it. A name there cannot
    be called a read or a write from shape, and this crate puts a great deal of
    control flow inside `select!`, so such a site is reported rather than
    dropped. Asked of the ancestor chain, so a body of any length is seen.
    """
    return any(node[1] == "TOKEN_TREE" for _index, node in ancestors)


def ast_handed_out(nodes, ancestors, owner, source):
    """How a field expression is handed out, or None.

    `self.f.push(x)` makes `self.f` the receiver of a method call and `&mut self.f`
    lends it; either can write the field, and the tree carries no types to tell
    `push` from `len`. Returns `.push(..)` or `&mut` for those shapes, so the
    site is reported with what was done to it.
    """
    # A node's depth is its indentation in the dump, two columns per level, so a
    # direct child sits two deeper than its parent.
    position = ancestors.index(owner)
    if position == 0:
        return None
    parent_index, parent = ancestors[position - 1]
    _depth, kind, start, end = parent
    if kind == "METHOD_CALL_EXPR" and start == owner[1][2]:
        for node in nodes[parent_index + 1 :]:
            if node[2] >= end:
                break
            if node[0] == parent[0] + 2 and node[1] == "NAME_REF" and node[2] >= owner[1][3]:
                return f".{source[node[2]:node[3]].decode('utf-8', 'replace')}(..)"
        return ".(..)"
    if kind == "REF_EXPR":
        for node in nodes[parent_index + 1 :]:
            if node[2] >= end:
                break
            if node[0] == parent[0] + 2 and node[1] == "MUT_KW":
                return "&mut"
    return None


def ast_field_ops(path, name):
    """Where `name` is written, read, given an initial value, handed out, or unknown.

    Returns five sorted lists. A write is an assignment to a field or path
    expression; an init is a struct literal field; a site inside a macro body is
    unknown, because the tree does not structure one; a `maybe` is a field handed
    out as the receiver of a method call or by a `&mut` borrow, as (line, what),
    which the tree cannot classify because `push` and `len` have one shape; and
    everything else that names the entity is a read.
    """
    nodes, line_of, source = ast_tree(path)
    writes, reads, inits, opaque, maybe = set(), set(), set(), set(), set()
    for index, node, ancestors in ast_walk(nodes):
        _depth, kind, start, end = node
        if kind != "IDENT" or source[start:end].decode("utf-8", "replace") != name:
            continue
        line = line_of(start)
        # `NAME` is a declaration, `NAME_REF` a use. A declaration of the same
        # spelling is a different entity -- the method beside the field of that
        # name -- and the tree carries no types to tell them apart, so skip it.
        found = ast_innermost(ancestors)
        parent = found[1] if found else None
        if parent is None or parent[1] != "NAME_REF":
            if ast_in_token_tree(ancestors):
                opaque.add(line)
            continue
        if ast_in_token_tree(ancestors):
            opaque.add(line)
            continue
        # The expression that owns this identifier, which has to contain it: the
        # `self` in `self.f = x` is a PATH_EXPR ending before the field name,
        # and taking it would put `.` where `=` belongs.
        owner = ast_innermost(
            [one for one in ancestors if one[1][3] >= end],
            ("FIELD_EXPR", "RECORD_EXPR_FIELD", "RECORD_FIELD", "PATH_EXPR"),
        )
        if owner is None:
            reads.add(line)
            continue
        owner_kind = owner[1][1]
        if owner_kind in ("RECORD_EXPR_FIELD", "RECORD_FIELD"):
            inits.add(line)
            continue
        # The use is decided after the whole place expression: `(self.f).clear()`
        # hands the field out through parentheses, `self.f[i] = v` assigns through
        # the index, `self.f.g = v` writes a projection of it, `*self.f = v` and
        # `&mut *self.f` go through a deref, and `(self.f, self.g) = ..` assigns
        # through a tuple. A tuple or a negation that is not assigned ends in a
        # read, as before.
        position = ancestors.index(owner)
        while position > 0:
            parent = ancestors[position - 1][1]
            if parent[1] in ("PAREN_EXPR", "PREFIX_EXPR", "TUPLE_EXPR", "ARRAY_EXPR") or (
                parent[1] in ("INDEX_EXPR", "FIELD_EXPR") and parent[2] == owner[1][2]
            ):
                position -= 1
                owner = ancestors[position]
            else:
                break
        following = ast_next_significant(nodes, index, owner[1][3])
        if following and following[1] in AST_ASSIGN:
            writes.add(line)
            continue
        handed = ast_handed_out(nodes, ancestors, owner, source)
        if handed:
            maybe.add((line, handed))
        else:
            reads.add(line)
    return sorted(writes), sorted(reads), sorted(inits), sorted(opaque), sorted(maybe)


def ast_documented_item(nodes, index, ancestors, first, last, depth, line_of):
    """The item a comment block documents, or None.

    A doc comment and an attribute are children of the item they belong to and
    come before its keyword, so a documented item is the nearest enclosing item
    that the comment leads. Matching the item's start offset instead fails as
    soon as anything precedes the comment, because then the item begins at that
    instead.

    An ordinary comment inside a body documents what follows it, bounded by the
    scope it sits in rather than by a node count. Inside a macro body there is
    nothing to document: the body is an unstructured token tree, so no item of
    it exists to name.
    """
    if ast_in_token_tree(ancestors):
        return None
    holder = ast_innermost(ancestors, tuple(AST_ITEMS) + ("MODULE",))
    if holder is not None:
        item_index, item = holder
        if ast_leads(nodes, index, item_index, item):
            return item[1], line_of(item[2])
    scope = ast_innermost(ancestors)
    limit = scope[1][3] if scope else None
    for position in range(index, len(nodes)):
        node_depth, kind, start, _end = nodes[position]
        if limit is not None and start >= limit:
            break
        if start < last or kind in AST_TRIVIA or node_depth > depth:
            continue
        if kind in AST_ITEMS:
            return kind, line_of(start)
    return None


def ast_notes(path, pattern):
    """Comment blocks matching `pattern`, with the item each sits above.

    Consecutive comment tokens are one block, because a doc comment spanning
    several lines is several tokens and only the block as a whole documents the
    item below it.
    """
    nodes, line_of, source = ast_tree(path)
    wanted = re.compile(pattern, re.I)
    # The walk is forward-only, and the loop below jumps over comment blocks, so
    # the ancestor chains are taken first.
    chains = {}
    for index, _node, ancestors in ast_walk(nodes):
        if _node[1] == "COMMENT":
            chains[index] = list(ancestors)
    blocks = []
    index = 0
    while index < len(nodes):
        depth, kind, start, end = nodes[index]
        if kind != "COMMENT":
            index += 1
            continue
        first, last, after = start, end, index + 1
        while after < len(nodes):
            _d, next_kind, next_start, next_end = nodes[after]
            if next_kind == "COMMENT":
                last, after = next_end, after + 1
            elif next_kind == "WHITESPACE" and source[next_start:next_end].count(b"\n") <= 1:
                after += 1
            else:
                break
        text = source[first:last].decode("utf-8", "replace")
        if wanted.search(text):
            item = ast_documented_item(
                nodes, index, chains[index], first, last, depth, line_of
            )
            blocks.append((line_of(first), text, item))
        index = after
    return blocks


def ast_paths(repo, paths):
    """The Rust files the PATH arguments of an `ast` query name.

    A file stands for itself and a directory for every `.rs` file under it, so an
    actor's directory can be passed whole. A path that names neither is a usage error
    rather than a traceback.
    """
    files = []
    for one in paths:
        path = Path(one)
        full = repo / path
        if full.is_dir():
            files += [path / child.relative_to(full) for child in sorted(full.rglob("*.rs"))]
        elif full.is_file():
            files.append(path)
        else:
            raise Abort(1, f"{one}: no such file or directory")
    return files


def ast_files(repo, sl_dir, name, explicit):
    """Which files to parse: the ones given, else the ones the index names.

    Parsing every source of the crate costs about ten seconds; the index says
    which two or three files mention the entity, so scope narrows to those.
    """
    if explicit:
        return ast_paths(repo, explicit)
    index = index_path(sl_dir)
    if not index.exists():
        say("no code index, so every subsystem source is parsed; pass paths to narrow it")
        found = []
        for subsystem in SUBSYSTEMS:
            found += sorted((repo / SOURCES[subsystem]).rglob("*.rs"))
        return [one.relative_to(repo) for one in found]
    occurrences, definitions, names = index_load(index)
    symbols = set(index_match(occurrences, definitions, names, name))
    return sorted(
        {Path(path) for symbol, path, _line, _def in occurrences if symbol in symbols}
    )


def cmd_ast(args):
    """Syntax tree queries over the code (SPEC section 5.8)."""
    repo = repo_root()
    sl_dir = repo / SL
    if not ast_available():
        say(
            "rust-analyzer is not installed, so syntax trees are unavailable.\n"
            "Install it with `rustup component add rust-analyzer`."
        )
        return 1
    if args.query == "notes":
        targets = ast_paths(repo, args.paths) if args.paths else None
        if targets is None:
            targets = []
            for subsystem in SUBSYSTEMS:
                targets += [
                    one.relative_to(repo)
                    for one in sorted((repo / SOURCES[subsystem]).rglob("*.rs"))
                ]
        total = 0
        boundaries = {}
        for relative in targets:
            blocks = ast_notes(repo / relative, args.pattern)
            for line, text, item in blocks:
                if not args.tests and index_is_test(repo, boundaries, str(relative), line):
                    continue
                where = f"{item[0]}@{item[1]}" if item else "-"
                first = text.strip().splitlines()[0][:96]
                print(f"{relative}:{line}  {where:22s} {first}")
                total += 1
        print(f"\n{total} comment block(s) matching {args.pattern!r}")
        return 0
    targets = ast_files(repo, sl_dir, args.name, args.paths)
    if not targets:
        print(f"no file mentions {args.name!r}")
        return 1
    boundaries = {}
    shown = 0
    for relative in targets:
        writes, reads, inits, opaque, maybe = ast_field_ops(repo / relative, args.name)
        rows = (
            [("write", line, "") for line in writes]
            + [("maybe", line, what) for line, what in maybe]
            + [("init", line, "") for line in inits]
            + [("read", line, "") for line in reads]
            + [("macro", line, "") for line in opaque]
        )
        for kind, line, what in rows:
            if not args.tests and index_is_test(repo, boundaries, str(relative), line):
                continue
            if kind not in ("write", "maybe", "macro") and args.writes_only:
                continue
            print(f"{kind:6s} {relative}:{line}" + (f"  {what}" if what else ""))
            shown += 1
    print(f"\n{shown} site(s) for {args.name!r} in {len(targets)} file(s)")
    return 0


def clean_plan(repo):
    """What to delete and what to restore, taken from git's view of the tree.

    The instrumenter may add files of its own, so a fixed inventory of generated
    paths is not enough: git already knows which paths differ from HEAD. What
    decides between deleting and restoring is whether the path exists in HEAD,
    and that is asked of `git ls-tree` rather than inferred from a status code.
    The codes are easy to get wrong -- `git add --intent-to-add` reports ` A`
    while `git add` of a new file reports `A `, and a rename reports one code for
    two paths -- whereas presence in HEAD is exactly the question being asked.

    The distinction matters because the two need different commands. `git
    checkout` on an intent-to-add path succeeds, leaves the file staged, and
    empties it; only `git rm` removes it. A generated file git does not report,
    because it is ignored, is still ours to delete.
    """
    created, _edited = campaign_artifacts(repo)
    roots, scope = clean_scope(repo)
    in_head = {
        path
        for path in git(
            repo, "ls-tree", "-r", "HEAD", "--name-only", "-z", "--", *scope
        ).split("\0")
        if path
    }
    delete, restore = set(), set()
    # `-uall` so that a wholly untracked directory is listed as its files. Git
    # collapses one to a single `dir/` entry by default, and a directory is not
    # something to unlink; it is also what the operator's own git configuration
    # might change, so the mode is stated rather than assumed.
    for _status, path in porcelain_entries(
        git(repo, "status", "--porcelain", "-z", "-uall", "--", *scope)
    ):
        (restore if path in in_head else delete).add(path)
    for path in created:
        if (repo / path).exists():
            delete.add(path)
            restore.discard(path)
    # target_states/ is synthesis's whole, never in HEAD, and a campaign refuses a checkout
    # that has one: the files git ignores there, such as a module named `target`, go too.
    ignored = git(
        repo, "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--",
        *scaffold_dirs(),
    )
    delete.update(path for path in ignored.split("\0") if path and (repo / path).is_file())
    return sorted(delete), sorted(restore), roots


def clean_scope(repo):
    """(the directories `clean` covers, every path it covers) (SPEC section 5.4).

    The directories are the editable roots and the fuzz packages synthesis writes to
    (section 18.6), whole: git reports no path it ignores, so the `corpus/`, `artifacts/`
    and `coverage/` there are never in scope. The paths add the files a campaign edits
    elsewhere.
    """
    _created, edited = campaign_artifacts(repo)
    roots = {root for settings in PROFILES.values() for root in settings["roots"]}
    roots |= {
        settings["package"] + "/" for settings in PROFILES.values() if settings["scaffold"]
    }
    roots = sorted(roots)
    return roots, roots + [path for path in edited if not path.startswith(tuple(roots))]


def llvm_tools(toolchain):
    """The `llvm-cov` and `llvm-profdata` of a toolchain, from its own sysroot.

    They must come from the toolchain that built the binaries: a coverage
    mapping is only readable by the LLVM that wrote it, and the ones on PATH
    belong to whatever else is installed.
    """
    rustc = ["rustc"] + ([f"+{toolchain}"] if toolchain else [])
    try:
        sysroot = subprocess.run(
            rustc + ["--print", "sysroot"], capture_output=True, text=True, check=True
        ).stdout.strip()
        version = subprocess.run(rustc + ["-vV"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise Abort(2, f"cannot ask {' '.join(rustc)} for its sysroot: {error}")
    host = ""
    for line in version.splitlines():
        if line.startswith("host: "):
            host = line[len("host: ") :].strip()
    if not host:
        raise Abort(2, f"{' '.join(rustc)} -vV did not report a host triple")
    binaries = Path(sysroot) / "lib/rustlib" / host / "bin"
    tools = (binaries / "llvm-cov", binaries / "llvm-profdata")
    missing = [tool.name for tool in tools if not os.access(tool, os.X_OK)]
    if missing:
        raise Abort(
            2,
            f"{', '.join(missing)} not in {binaries}; install it with "
            f"`rustup component add llvm-tools-preview --toolchain {toolchain or 'nightly'}`",
        )
    return tools + (host,)


def coverage_binary(repo, package, host, target):
    """The coverage build of `target`, wherever cargo-fuzz put it.

    The fuzz packages are workspace members, so cargo builds into the workspace
    target directory, and cargo-fuzz nests a host build under its own profile
    directory. Both layouts are checked rather than assumed.
    """
    for candidate in (
        repo / "target" / host / "coverage" / host / "release" / target,
        repo / package / "target" / host / "coverage" / host / "release" / target,
        repo / "target" / host / "coverage" / target,
        repo / package / "target" / host / "coverage" / target,
    ):
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def coverage_scope(repo, profile):
    """(sources the report covers, paths the campaign does not instrument).

    llvm-cov reads a source argument as a path, so the roots are absolute and
    lose their trailing slash: a directory written with one is read as a file
    that does not exist, and the report widens to the whole binary with only a
    warning. The uninstrumented paths keep theirs, because they are a regex.
    """
    settings = PROFILES[profile]
    return [str(repo / root.rstrip("/")) for root in settings["roots"]], list(settings["warn"])


def cmd_coverage(args):
    """SPEC section 7.13: coverage of the corpora the StateLens targets built."""
    repo = repo_root()
    config = load_config(repo / SL)
    toolchain = config["STATELENS_FUZZ_TOOLCHAIN"] or pinned_nightly(repo)
    profile, targets = coverage_selection(repo, args)
    package = PROFILES[profile]["package"]
    coverage_dir = repo / package / "coverage"
    out = coverage_dir / "html"
    llvm_cov, llvm_profdata, host = llvm_tools(toolchain)

    ready = []
    for target in targets:
        corpus = repo / package / "corpus" / target
        if not corpus.is_dir() or not any(corpus.iterdir()):
            say(f"warning: {target} has no corpus in {package}/corpus; skipped")
            continue
        ready.append(target)
    if not ready:
        raise Abort(2, f"no {profile} target has a corpus; run the targets before this")

    out.mkdir(parents=True, exist_ok=True)
    sources, uninstrumented = coverage_scope(repo, profile)
    profiles, objects = [], []
    for number, target in enumerate(ready, 1):
        say(f"coverage: {target} ({number} of {len(ready)}); replaying its corpus")
        command = cargo(toolchain) + ["fuzz", "coverage", "--fuzz-dir", package, target]
        log = coverage_dir / target / "coverage.log"
        code, tail = run_logged(command, log, repo)
        if code != 0:
            for line in tail:
                print(line, flush=True)
            raise Abort(2, f"coverage: {target} exited with code {code}; see {log}")
        data = coverage_dir / target / "coverage.profdata"
        binary = coverage_binary(repo, package, host, target)
        if binary is None or not data.is_file():
            raise Abort(2, f"coverage: {target} produced no profile or binary")
        profiles.append(data)
        objects.append(binary)
        coverage_report(llvm_cov, out, target, [binary], data, sources, uninstrumented)

    if len(objects) > 1:
        say(f"coverage: merging {len(profiles)} profile(s)")
        unified = coverage_dir / "unified.profdata"
        merge = [str(llvm_profdata), "merge", "-sparse"] + [str(path) for path in profiles]
        run_tool(merge + ["-o", str(unified)])
        coverage_report(llvm_cov, out, "unified", objects, unified, sources, uninstrumented)
    say(f"coverage: reports in {out.relative_to(repo)}")
    return 0


def coverage_selection(repo, args):
    """(profile, targets) from the names given, as `just fuzz` reads them."""
    profile, targets = args.profile, []
    for name in args.targets:
        if name in PROFILES:
            profile = name
            continue
        owner = next((key for key in PROFILES if name.startswith(f"{key}_")), None)
        if owner is None:
            prefixes = "/".join(f"{key}_" for key in PROFILES)
            raise Abort(1, f"{name} is not a profile or a {prefixes} target")
        if profile is not None and profile != owner:
            raise Abort(1, f"{name} is a {owner} target, but the profile is {profile}")
        profile = owner
        targets.append(name)
    if profile is None:
        profile = "simplex"
    # A profile covers its scaffolds with its variants (SPEC section 18.9).
    known = profile_targets(repo, profile) + scaffold_targets(repo, profile)
    unknown = [name for name in targets if name not in known]
    if unknown:
        raise Abort(
            1,
            f"the {profile} profile builds no target called {', '.join(unknown)}; "
            f"it builds {', '.join(known)}",
        )
    return profile, targets or known


def run_tool(command, capture=False):
    """Runs an llvm tool, turning a failure into an `Abort` rather than a traceback."""
    try:
        done = subprocess.run(command, capture_output=capture, text=True)
    except OSError as error:
        raise Abort(2, f"could not run {Path(command[0]).name}: {error}")
    if done.returncode != 0:
        detail = (done.stderr or "").strip().splitlines()
        raise Abort(
            2,
            f"{Path(command[0]).name} exited with code {done.returncode}"
            + (f": {detail[-1]}" if detail else ""),
        )
    return done.stdout


def coverage_report(llvm_cov, out, name, objects, data, sources, uninstrumented):
    """One HTML report and its summaries, for one target or for the merge."""
    # llvm-cov reads the first positional as the main binary, so the rest take
    # `-object`; otherwise a source path is read as a binary.
    binaries = [str(objects[0])]
    for extra in objects[1:]:
        binaries += ["-object", str(extra)]
    profile_flag = [f"-instr-profile={data}"]
    # llvm-cov writes into the directory without clearing it, so a rerun over a
    # narrower scope would leave the pages of the wider one behind.
    shutil.rmtree(out / name, ignore_errors=True)
    run_tool(
        [str(llvm_cov), "show"]
        + binaries
        + profile_flag
        + [
            "-format=html",
            f"-output-dir={out / name}",
            "-show-line-counts-or-regions",
            "-show-instantiation-summary",
        ]
        + sources
    )
    for root in sources:
        subsystem = Path(root).name
        text = run_tool(
            [str(llvm_cov), "report"]
            + binaries
            + profile_flag
            + [f"-ignore-filename-regex={'|'.join(uninstrumented)}", root],
            capture=True,
        )
        (out / f"{name}.{subsystem}.txt").write_text(text)
        total = [line for line in text.splitlines() if line.startswith("TOTAL")]
        if total:
            columns = total[0].split()
            say(
                f"coverage: {name} {subsystem} regions {columns[3]}, "
                f"functions {columns[6]}, lines {columns[9]} (instrumented code)"
            )
    workspace = run_tool(
        [str(llvm_cov), "report"]
        + binaries
        + profile_flag
        + [f"-ignore-filename-regex={COVERAGE_DEPENDENCIES}"],
        capture=True,
    )
    (out / f"{name}.workspace.txt").write_text(workspace)


def select_targets(targets, patterns):
    """The targets a shell pattern names, by variant name or by the original target's.

    `simplex_cert_mock_twins_*` and `simplex_cert_mock_twins_mutator` both name
    `simplex_cert_mock_twins_mutator_statelens`; no pattern names every target.
    """
    if not patterns:
        return list(targets)
    return [
        target
        for target in targets
        if any(
            fnmatch.fnmatchcase(target, pattern)
            or fnmatch.fnmatchcase(target.removesuffix("_statelens"), pattern)
            for pattern in patterns
        )
    ]


def cmd_targets(args):
    """The StateLens targets a profile builds, one per line (SPEC section 5.5).

    `just fuzz <profile>` reads this rather than parsing a campaign summary, so
    the recipe and the campaign cannot disagree about what was built. `--match`
    narrows them, and a pattern that names none is an error, not an empty run.
    With `--state-reaching` it lists the scaffolds of the selected pairs (card, base)
    instead.
    """
    repo = repo_root()
    if args.state_reaching:
        return state_reaching_targets(repo, args.profile, args.match or [])
    targets = profile_targets(repo, args.profile)
    chosen = select_targets(targets, args.match or [])
    if not chosen:
        raise Abort(
            1,
            f"no {args.profile} target matches {' or '.join(args.match)}; the profile "
            f"builds: {', '.join(targets)}",
        )
    for target in chosen:
        print(target)
    return 0


def state_reaching_targets(repo, profile, patterns):
    """The scaffolds of the selected pairs whose thin target exists (SPEC section 18.9).

    `just fuzz <profile> --state-reaching` calls this before the campaign, so that a
    selection that is empty or has a card with a lint problem fails at once, and again
    after synthesis for the scaffolds to run. Only their names go to standard output.
    """
    sl_dir = repo / SL
    selection = select_scaffolds(repo, sl_dir, profile, patterns)
    cards = sorted({pair.path for pair in selection.pairs})
    if lint_paths(cards, registry_files(sl_dir)):
        raise Abort(1, "a selected card has lint problems (above); fix them before synthesis")
    for pair in selection.pairs:
        if pair.scaffold:
            print(pair.scaffold)
    return 0


def campaign_profile(sl_dir):
    """The profile the campaign in this checkout ran with, from its `meta.json`."""
    try:
        return json.loads((sl_dir / "campaign" / "meta.json").read_text())["profile"]
    except (OSError, ValueError, KeyError):
        return None


def campaign_invariants(sl_dir):
    """The ids the campaign in this checkout bound, from its `meta.json`, or None."""
    try:
        return set(json.loads((sl_dir / "campaign" / "meta.json").read_text())["invariants"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def cmd_test_gate(args):
    """Runs only the test gate on the checkout as it stands (SPEC section 5.4).

    It is the campaign's own command, so a fix to an instrumented checkout can be
    checked before fuzzing it, without running a campaign again.
    """
    repo = repo_root()
    sl_dir = repo / SL
    profile = args.profile or campaign_profile(sl_dir)
    if profile not in PROFILES:
        raise Abort(1, "no campaign in this checkout names its profile; pass --profile")
    toolchain = load_config(sl_dir)["STATELENS_TEST_TOOLCHAIN"]
    command = gate_test_command(toolchain, profile)
    say(f"test-gate: {shlex.join(command)}")
    code = subprocess.run(command, cwd=repo).returncode
    say(f"test-gate: the test gate {'passed' if code == 0 else 'failed'}")
    if code != 0:
        return 4
    components = component_test_command(toolchain, profile)
    if components is None:
        return 0
    say(f"test-gate: {shlex.join(components)}")
    failed = subprocess.run(components, cwd=repo).returncode
    say(
        "test-gate: the component tests passed"
        if failed == 0
        else "test-gate: component tests failed; they are reported, not gated"
    )
    return 0


def cmd_clean(args):
    """Undo what a campaign wrote, so a checkout can be reused (SPEC section 5.4)."""
    repo = repo_root()
    created, restore, roots = clean_plan(repo)
    # A target_states/ that holds no file, an empty directory say, still blocks a campaign.
    stale = [path for path in scaffold_dirs() if (repo / path).exists()]
    if not created and not restore and not stale:
        say("clean: nothing to undo; this checkout has no campaign artifacts")
        return 0
    say("clean: this restores the paths below to HEAD, losing any edit of your own in them")
    for path in created:
        print(f"  delete   {path}")
    for path in restore:
        print(f"  restore  {path}")
    if not args.yes:
        # A preview is the default and is not a failure, so it exits 0: `just` would
        # otherwise report the safe path as a broken recipe.
        say(
            f"clean: nothing done. Rerun as `just clean --yes` to delete {len(created)} "
            f"file(s) and restore {len(restore)} path(s)"
        )
        return 0
    # Restore first: a failure then leaves every generated file in place, so the
    # checkout is still recoverable. `checkout HEAD --` rather than `checkout --`,
    # because the latter restores the index, which keeps instrumentation the
    # operator happened to stage.
    if restore:
        git(repo, "checkout", "HEAD", "--", *restore)
    emptied = set()
    for path in created:
        git(repo, "rm", "-f", "--quiet", "--ignore-unmatch", "--", path)
        target = repo / path
        if target.is_dir():
            # `-uall` should have listed files, so this means a pathspec that
            # names a directory. Removing its contents unseen is not this
            # command's business; say so and leave it.
            say(f"clean: {path} is a directory, not a generated file; left in place")
            continue
        if target.exists():
            target.unlink()
        emptied.add(target.parent)
    # A directory this left empty was created by the campaign, so remove it, but
    # only while it is empty and only up to the roots.
    keep = {(repo / root).resolve() for root in roots}
    for directory in sorted(emptied, key=lambda one: len(str(one)), reverse=True):
        while directory.is_dir() and directory.resolve() not in keep:
            if any(directory.iterdir()) or not inside_repo(repo, directory):
                break
            parent = directory.parent
            directory.rmdir()
            directory = parent
    left = [
        f"{status} {path}" for status, path in porcelain_entries(
            git(repo, "status", "--porcelain", "-z", "-uall", "--", *clean_scope(repo)[1])
        )
    ]
    left += [f"?? {path}" for path in scaffold_dirs() if (repo / path).exists()]
    if left:
        say("clean: these paths still differ from HEAD, so the checkout is not reusable:")
        for row in left[:20]:
            print(f"  {row}")
        return 1
    say(f"clean: restored {len(restore)} path(s) and deleted {len(created)} file(s)")
    say("clean: campaign/ and extract/ were left alone; delete them by hand if you want to")
    return 0


def subsystem_sources(repo):
    """Every non-test Rust source of every subsystem, concatenated."""
    text = []
    for name in SUBSYSTEMS:
        for path in sorted((repo / SOURCES[name]).rglob("*.rs")):
            try:
                text.append(path.read_text(errors="replace"))
            except OSError as error:
                say(f"warning: cannot read {path}: {error.strerror or error}; skipped")
    return "\n".join(text)


def lint_example_file(path, sources):
    """Checks one worked analysis: ASCII, and every code name it cites still exists."""
    problems = []
    data = path.read_bytes()
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        problems.append("contains non-ASCII characters")
        text = data.decode("utf-8", errors="replace")
    declared = set()
    for match in NOT_CODE.finditer(text):
        declared |= {word.strip() for word in match.group(1).split(",") if word.strip()}
    cited = {match.group(1) for match in CODE_WORD.finditer(text)}
    missing = sorted(name for name in cited - declared if name not in sources)
    for name in missing:
        problems.append(
            f"cites `{name}`, which no longer exists in {', '.join(SOURCES.values())}; fix "
            "the reference, or declare it with a `<!-- statelens-lint: not-code: ... -->` "
            "line when it is not a code name"
        )
    return problems


def cmd_lint_examples(args):
    """SPEC chapter 3: the worked analyses must keep naming real code."""
    repo = repo_root()
    root = repo / EXAMPLES
    paths = [Path(p) for p in args.paths] if args.paths else sorted(root.glob("*.md"))
    sources = subsystem_sources(repo)
    count = 0
    for path in paths:
        if not path.is_file():
            print(f"{path}: not a file", flush=True)
            count += 1
            continue
        for problem in lint_example_file(path, sources):
            print(f"{path}: {problem}", flush=True)
            count += 1
    say(f"lint-examples: {len(paths)} file(s), {count} problem(s)")
    return 3 if count else 0


def plan_sections(text):
    """The invariant sections of a plan: id -> {field: value} (SPEC section 11).

    A field's value carries its continuation lines, so a `Sites` ledger written as an
    indented list reads the same as one written on the field's own line.
    """
    sections = {}
    repeated = []
    current = None
    field = None
    fenced = False
    for line in text.splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
            continue
        if fenced:
            continue
        heading = PLAN_HEADING.match(line)
        if heading:
            name = heading.group(1)
            if name in sections:
                repeated.append(name)
            current = sections.setdefault(name, {})
            field = None
            continue
        if line.startswith("#"):
            current, field = None, None
            continue
        if current is None:
            continue
        match = PLAN_FIELD.match(line)
        if match:
            field = match.group(1).strip()
            value = match.group(2).strip()
            # A ledger written as one bullet per site repeats the field, so extend it
            # rather than keeping the last bullet and losing the earlier sites.
            current[field] = (current[field] + "\n" + value).strip() if field in current else value
            continue
        if field is not None and line.strip() and line[:1].isspace():
            current[field] = (current[field] + "\n" + line.strip()).strip()
            continue
        field = None
    return sections, repeated


def plan_site_entries(value):
    """The entries of a `Sites` ledger: one per commit site, with the sources it names.

    An entry begins at a line that names a source, so an entry wrapped over several
    lines stays one entry and a `not checked` on its second line still counts.
    """
    entries = []
    for line in value.splitlines():
        if PLAN_SITE_PATH.search(line):
            entries.append(line)
        elif entries:
            entries[-1] += " " + line.strip()

    def functions(text):
        # The action comes before the file and is not a function claim, however it
        # is written; everything backticked after the file is one.
        path = PLAN_SITE_PATH.search(text)
        return PLAN_SITE_FN.findall(text[path.end():] if path else text)

    return [(text, PLAN_SITE_PATH.findall(text), functions(text)) for text in entries]


def enclosing_function(position, impls, fns):
    """The function whose body holds `position`: `Type::name` inside an `impl`
    block, `name` outside one, None when no body holds it.

    `impls` and `fns` come from `impl_extents` and `fn_extents` over the same
    literal-free text, so neither a comment nor a string spelling `fn` counts; the
    innermost of each holding the position is taken.
    """

    def innermost(extents):
        return min(
            ((end - start, name) for start, end, name in extents if start <= position <= end),
            default=None,
        )

    function = innermost(fns)
    if function is None:
        return None
    holder = innermost(impls)
    return f"{holder[1]}::{function[1]}" if holder else function[1]


def subsystem_assertions(repo):
    """The invariant each assertion site names, per instrumented source: path -> [ids].

    One entry per call, not per invariant, so the same list says which invariants a file
    asserts and how many sites it carries, and each carries the function it sits in, so a
    check at one site cannot certify another site of the same file. A file with no
    assertion is kept, because the question "which layer holds none at all" is answered by
    the empty lists.

    The scan is textual. Comments, string literals that quote an assertion macro, and
    the `#[cfg(test)]` items of a file are blanked first, so an assertion quoted in a
    comment or a string or placed in a test module certifies nothing; what remains is
    production code, where a site is attributed to the function whose body holds it,
    qualified by the `impl` block around it, and to nothing when no body does.
    """
    found = {}
    for name in SUBSYSTEMS:
        for path in sorted((repo / SOURCES[name]).rglob("*.rs")):
            relative = path.relative_to(repo).as_posix()
            # The runtime module documents the macros it defines, and a documented call
            # names an invariant without asserting it.
            if relative in CREATED_PATHS:
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError as error:
                say(f"warning: cannot read {path}: {error.strerror or error}; skipped")
                continue
            code = production_code(repo, relative, text)
            # Items are located on the text with every literal blanked, so a string
            # spelling `fn` opens nothing; the ids are read from the text with them.
            structure = blank_inert(code, strings=True)
            impls, fns = impl_extents(structure), fn_extents(structure)
            found[relative] = [
                (match.group(1), enclosing_function(match.start(), impls, fns))
                for match in PLAN_ASSERTION.finditer(code)
            ]
    return found


def production_code(repo, relative, text):
    """`text` with comments and `#[cfg(test)]` items blanked, line for line.

    A file that mentions no assertion macro is returned empty, so the syntax tree that
    locates test items is only asked for the files that need it.
    """
    if "sl_assert!" not in text and "sl_implies!" not in text:
        return ""
    ranges = index_test_ranges(repo, relative)
    lines = blank_inert(text).split("\n")
    for number in range(1, len(lines) + 1):
        if any(first <= number and (last is None or number <= last) for first, last in ranges):
            lines[number - 1] = ""
    return "\n".join(lines)


# Rust source, one token at a time: a string (raw ones with their hashes) or char
# literal is kept whole, so a comment marker inside it is text; `/*` opens a block
# comment, which nests; `//` runs to the end of the line. Inside a block comment
# only `/*`, `*/` and newlines matter.
CODE_TOKEN = re.compile(
    r'(?P<raw>r(?P<hashes>#*)"[\s\S]*?"(?P=hashes))'
    # An escape may be a backslash-newline continuation, and a char literal may
    # be `'\x41'` or `'\u{1F600}'`; a literal the scan cannot pair would desync
    # every quote after it.
    r'|(?P<string>"(?:\\[\s\S]|[^"\\])*"'
    r"|'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|.)|[^\\'])')"
    r"|/\*|//[^\n]*|\n|(?:[^\"'/\nr]+|r(?!#*\"))+|."
)
COMMENT_TOKEN = re.compile(r"/\*|\*/|\n|[^/*\n]+|.")
ASSERTION_MACROS = ("sl_assert!", "sl_implies!")


def blank_inert(text, strings=False):
    """`text` with what cannot be an assertion replaced by spaces, newlines kept.

    Comments go: a `//` comment may follow code on its line and block comments
    nest, so neither a line test nor a non-nesting pattern removes them all, and an
    assertion quoted in one would certify the function it sits in. So does a
    string literal that quotes an assertion macro, which is text, not a call. With
    `strings`, every string and char literal goes, for counting the braces of the
    code without the ones inside literals.
    """
    out, depth, position = [], 0, 0
    while position < len(text):
        match = (COMMENT_TOKEN if depth else CODE_TOKEN).match(text, position)
        token = match.group()
        position = match.end()
        if depth:
            if token == "/*":
                depth += 1
            elif token == "*/":
                depth -= 1
            blank = True
        elif token == "/*":
            depth = 1
            blank = True
        elif token.startswith("//"):
            blank = True
        elif match.lastgroup in ("raw", "string"):
            blank = strings or any(macro in token for macro in ASSERTION_MACROS)
        else:
            blank = False
        out.append(re.sub(r"[^\n]", " ", token) if blank else token)
    return "".join(out)


def runtime_calls(text, names):
    """How often Rust `text` reaches each function of `names` through the runtime module.

    Code outside the module reaches a function of it by path, `statelens::seen`, through
    an alias the file gives the module, `rt::seen` after `statelens as rt` or
    `statelens::{self as rt}`, or by importing it, `statelens::{seen, ...}`; each counts
    once. A bare `seen(` does not count, because the read side's names are common words.
    Comments and string literals do not count.
    """
    code = blank_inert(text, strings=True)
    counts = collections.Counter()
    aliases = [one or two for one, two in RUNTIME_ALIAS.findall(code)]
    for prefix in dict.fromkeys(["statelens"] + aliases):
        pattern = rf"\b{re.escape(prefix)}\s*::\s*(?:([A-Za-z_][A-Za-z0-9_]*)|\{{([^}}]*)\}})"
        for match in re.finditer(pattern, code):
            if match.group(1):
                items = [match.group(1)]
            else:
                items = [item.split()[0] for item in match.group(2).split(",") if item.strip()]
            counts.update(item for item in items if item in names)
    return counts


IMPL_HEADER = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?impl\b([^{;]*)(?=\{)", re.M
)


def block_extents(structure, header, name_of):
    """[(start, end, name)] of the block items `header` matches in a literal-free text.

    The body starts at the first `{` after the header outside brackets; a `;` there
    is a declaration without a body and is skipped, as is a header `name_of` gives
    no name for. Braces are counted on text with the literals blanked, so a brace
    inside one neither opens nor closes a block.
    """
    extents = []
    for match in header.finditer(structure):
        name = name_of(match)
        if name is None:
            continue
        depth, position, body = 0, match.end(), None
        while position < len(structure):
            char = structure[position]
            if char == "-" and structure[position + 1 : position + 2] == ">":
                position += 2
                continue
            if char in "([<":
                depth += 1
            elif char in ")]>":
                depth = max(0, depth - 1)
            elif depth == 0 and char == ";":
                break
            elif depth == 0 and char == "{":
                body = position
                break
            position += 1
        if body is None:
            continue
        depth = 0
        for end in range(body, len(structure)):
            if structure[end] == "{":
                depth += 1
            elif structure[end] == "}":
                depth -= 1
                if depth == 0:
                    extents.append((match.start(), end, name))
                    break
    return extents


def impl_extents(structure):
    """[(start, end, type)] of every `impl` block of a literal-free text."""

    def name_of(match):
        kind = impl_type(match.group(1))
        # An `impl Trait` argument that rustfmt put at the start of a line is not a
        # block: what it leaves after the generics is a `)` or a `,`, not a path.
        return kind if re.fullmatch(r"(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Za-z_][A-Za-z0-9_]*", kind) else None

    return block_extents(structure, IMPL_HEADER, name_of)


def fn_extents(structure):
    """[(start, end, name)] of every function with a body in a literal-free text."""
    return block_extents(structure, PLAN_FUNCTION, lambda match: match.group(1))


def impl_type(header):
    """The type an `impl` header is for, as spelled: `Round` from
    `impl<S: Scheme> Round<S>`, `RoundRobin` from
    `impl<S> Elector<S> for RoundRobin<S> where S: Scheme`, and `prunable::Archive`
    from `impl Blocks for prunable::Archive<E>`, since two modules may each have
    an `Archive`."""
    while re.search(r"<[^<>]*>", header):
        header = re.sub(r"<[^<>]*>", "", header)
    if " for " in header:
        header = header.split(" for ", 1)[1]
    header = re.split(r"\bwhere\b", header)[0].strip()
    return header.strip("& ")


def function_matches(found, named):
    """Whether the function the scanner found is the one a ledger entry names.

    A ledger entry of the form `Type::function` names that method and nothing else:
    a method of another type, or a free function of the same name, is a different
    item. The scanner keeps the type as the `impl` header spells it, so a claim may
    give the path (`prunable::Archive::sync`) or its tail (`Archive::sync`); the
    ledger check reports a tail that fits more than one type. A bare ledger name
    is a less precise claim, satisfied by any function or method of that name. A
    site outside every function body matches nothing.
    """
    if found is None:
        return False
    if "::" in named:
        return found == named or found.endswith("::" + named)
    return found.rsplit("::", 1)[-1] == named


def lint_plan_file(path, expected=(), assertions=None):
    """Checks one instrumentation plan against SPEC section 11.

    The status is a coverage claim and the ledger is the agent's own account of it, so
    neither is taken on trust: `bound` needs a ledger with nothing left unchecked, a
    bound or partial invariant needs an assertion in the code that names it, and a site
    the ledger calls `checked` needs that assertion in the source it names.
    """
    problems = []
    data = path.read_bytes()
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        problems.append("contains non-ASCII characters")
        text = data.decode("utf-8", errors="replace")
    sections, repeated = plan_sections(text)
    if "## Invariants" not in text:
        problems.append("has no `## Invariants` section")
    for name in sorted(set(repeated)):
        problems.append(f"{name}: has more than one section; the first one wins when parsed")
    for name in sorted(Path(item).stem for item in expected):
        if name not in sections:
            problems.append(f"{name}: has no section; the campaign marks it unbound")
    bound_ids = set()
    for name, fields in sections.items():
        # The status may be written back-quoted or bold; the campaign parser allows both.
        # A qualifier may follow the status: `partial (inactive in the fuzz targets)`.
        # It is the one phrase the summary looks for, so a paraphrase is a problem
        # rather than a binding silently counted as active.
        raw = fields.get("Status", "").strip("`* ")
        status = raw.split(" ")[0].strip("`*")
        qualifier = raw[len(raw.split(" ")[0]) :].strip()
        fields["Status"] = status
        if status not in ("bound", "partial", "unbound"):
            problems.append(
                f"{name}: Status is `{status or 'missing'}`; it must be bound, partial or unbound"
            )
            continue
        if qualifier and not PLAN_INACTIVE.fullmatch(qualifier):
            problems.append(
                f"{name}: Status qualifier `{qualifier}` is not recognised; after the status "
                "write `(inactive in the fuzz targets)` or nothing"
            )
        required = PLAN_FIELDS if status != "unbound" else ("Status", "Notes")
        for required_field in required:
            if not fields.get(required_field):
                problems.append(f"{name}: {required_field} is missing or empty")
        for unknown in sorted(set(fields) - set(PLAN_FIELDS)):
            problems.append(f"{name}: unknown field `{unknown}`")
        entries = plan_site_entries(fields.get("Sites", ""))
        uncovered = [entry for entry in entries if PLAN_UNCHECKED.search(entry[0])]
        if status != "unbound" and fields.get("Sites") and not entries:
            problems.append(
                f"{name}: Sites names no source; one entry per commit site, each with the "
                "action, the file, the function and `checked` or `not checked`"
            )
        if status == "bound" and uncovered:
            problems.append(
                f"{name}: Status is bound, but Sites leaves {len(uncovered)} commit site(s) "
                "not checked; a binding that misses a commit site is partial"
            )
        if status != "unbound" and fields.get("Assertions", "").lower().startswith("none"):
            problems.append(f"{name}: Status is {status}, but no assertion is listed")
        if status != "unbound":
            bound_ids.add(name)
        if assertions is not None:
            problems += plan_ledger_problems(name, entries, assertions)
    if assertions is not None:
        asserted = {found for sites in assertions.values() for found, _at in sites}
        for name in sorted(bound_ids - asserted):
            problems.append(
                f"{name}: Status claims a binding, but no sl_assert! or sl_implies! call "
                "in the instrumented code names it"
            )
        unbound = {key for key, values in sections.items() if values.get("Status") == "unbound"}
        for name in sorted(asserted & unbound):
            problems.append(f"{name}: Status is unbound, but the code asserts it")
    return problems


def plan_ledger_problems(name, entries, assertions):
    """Checks the `checked` entries of one `Sites` ledger against the code.

    The pass that writes the ledger is the pass that writes the status, so a ledger that
    certifies itself certifies nothing. A site called `checked` must carry an assertion
    that names the invariant, in the source the entry names.
    """
    problems = []
    for text, paths, functions in entries:
        if PLAN_UNCHECKED.search(text):
            continue
        if not PLAN_CHECKED.search(text):
            problems.append(
                f"{name}: the Sites entry for `{paths[0]}` says neither `checked` nor "
                "`not checked`"
            )
            continue
        for named in paths:
            matches = [
                source
                for source in assertions
                if source == named or source.endswith("/" + named.lstrip("./"))
            ]
            if not matches:
                problems.append(
                    f"{name}: Sites names `{named}`, which is not an instrumented source"
                )
                continue
            sites = [site for source in matches for site in assertions[source]]
            if not any(found == name for found, _function in sites):
                problems.append(
                    f"{name}: Sites calls `{named}` checked, but nothing there asserts "
                    f"{name}; mark the site not checked, or add the assertion"
                )
                continue
            # A dispatch and the commit it leads to often share a file, so the entry has
            # to name the function, and the assertion has to be in it. Without that, one
            # assertion certifies every site of its file.
            if not functions:
                problems.append(
                    f"{name}: the Sites entry for `{named}` is checked but names no "
                    "function; give it in backticks, as `Type::function` or `function`"
                )
                continue
            holders = sorted(
                {
                    at
                    for found, at in sites
                    if found == name and any(function_matches(at, named_fn) for named_fn in functions)
                }
            )
            if not holders:
                problems.append(
                    f"{name}: Sites calls `{named}` `{functions[0]}` checked, but the "
                    f"assertion naming {name} is elsewhere in that file"
                )
            elif len(holders) > 1:
                # Two types of one name, from two modules, each with the method.
                problems.append(
                    f"{name}: Sites calls `{named}` `{functions[0]}` checked, which names "
                    f"more than one method there ({', '.join(f'`{at}`' for at in holders)}); "
                    "name the type's path"
                )
    return problems


def spec_prompt_blocks(text):
    """The verbatim prompt copies of SPEC section 13: path -> (content, span)."""
    blocks = {}
    for match in SPEC_PROMPT.finditer(text):
        blocks[match.group(1)] = (match.group(2), match.span(2))
    return blocks


def lint_prompts(repo, write=False):
    """SPEC section 13 reproduces every prompt verbatim; checks that it still does.

    The claim is load-bearing: the prompts are what the agents actually read, and the
    SPEC is what a person reads to learn what the agents were told.
    """
    problems = []
    spec_path = repo / SPEC_DOC
    text = spec_path.read_text()
    blocks = spec_prompt_blocks(text)
    sl_dir = repo / SL
    stale = []
    for path in sorted((sl_dir / "prompts").rglob("*.md")):
        relative = path.relative_to(sl_dir).as_posix()
        content = path.read_text().rstrip("\n")
        if relative not in blocks:
            problems.append(
                (path, f"has no `### 13.N `{relative}`` block in {SPEC_DOC}; section 13 "
                       "must reproduce every prompt")
            )
            continue
        if blocks[relative][0] != content:
            problems.append((path, f"differs from its copy in {SPEC_DOC} section 13"))
            stale.append((relative, content))
    for relative in sorted(set(blocks) - {
        path.relative_to(sl_dir).as_posix() for path in (sl_dir / "prompts").rglob("*.md")
    }):
        problems.append((spec_path, f"section 13 copies `{relative}`, which does not exist"))
    if write and stale:
        # Back to front, so an earlier replacement does not move a later span.
        for relative, content in sorted(stale, key=lambda item: blocks[item[0]][1][0], reverse=True):
            start, end = blocks[relative][1]
            text = text[:start] + content + text[end:]
        spec_path.write_text(text)
        say(f"lint-prompts: rewrote {len(stale)} block(s) in {SPEC_DOC}")
    return problems


def cmd_lint_prompts(args):
    """SPEC section 13: the prompts and their copies in the specification must agree."""
    repo = repo_root()
    problems = lint_prompts(repo, args.write)
    if args.write:
        problems = lint_prompts(repo)
    for path, problem in problems:
        print(f"{path}: {problem}", flush=True)
    say(f"lint-prompts: {len(problems)} problem(s)")
    return 3 if problems else 0


def cmd_lint_plan(args):
    """SPEC section 11: the plan's claims must match its own sections and the code.

    Without `--profile` the profile is the campaign's, from `campaign/meta.json`, so the
    bare command the audit prompt gives checks the registries that campaign binds.
    """
    repo = repo_root()
    sl_dir = repo / SL
    recorded = campaign_profile(sl_dir)
    profile = args.profile or recorded or "simplex"
    if profile not in PROFILES:
        raise Abort(1, f"campaign/meta.json names an unknown profile {profile!r}; pass --profile")
    paths = [Path(path) for path in args.paths] if args.paths else [repo / PLAN]
    registries = PROFILES[profile]["registries"]
    # A campaign run with `--invariants` has sections for the ids it selected only, so
    # the campaign's profile, named or not, expects what its meta.json lists; another
    # profile expects every registry invariant.
    bound = campaign_invariants(sl_dir) if profile == recorded else None
    expected = [
        path
        for path in registry_files(sl_dir)
        if path.parent.name in registries
        and path.stem.startswith("INV-")
        and (bound is None or path.stem in bound)
    ]
    assertions = subsystem_assertions(repo)
    count = 0
    for path in paths:
        if not path.is_file():
            print(f"{path}: not a file", flush=True)
            count += 1
            continue
        for problem in lint_plan_file(path, expected, assertions):
            print(f"{path}: {problem}", flush=True)
            count += 1
    say(f"lint-plan: {len(paths)} file(s), {count} problem(s)")
    return 3 if count else 0


def read_edit_file(repo, relative, hint="update the paths and anchors in scripts/statelens.py"):
    """Text of a file the materialize step reads; a missing file aborts with exit code 2."""
    try:
        return (repo / relative).read_text()
    except FileNotFoundError:
        raise Abort(2, f"materialize: {relative} does not exist; {hint}") from None


def read_sl_file(repo, relative):
    """Text of a StateLens file that materialize copies (SL/runtime/)."""
    return read_edit_file(repo, relative, "restore it from HEAD")


def profile_fuzz_dir(profile):
    return f"{PROFILES[profile]['package']}/fuzz_targets"


def profile_manifest(profile):
    return f"{PROFILES[profile]['package']}/Cargo.toml"


def target_states_dir(profile):
    """Where synthesis writes the scaffold modules of `profile` (SPEC section 18.6)."""
    return f"{PROFILES[profile]['package']}/src/target_states"


def scaffold_dirs():
    """The target_states/ directory of every profile synthesis writes to."""
    return [target_states_dir(name) + "/" for name in PROFILES if PROFILES[name]["scaffold"]]


def profile_sources(repo, profile):
    """The existing targets `profile` derives StateLens variants from.

    A profile's targets are every target of its package named `<profile>_*`, in file
    name order, which is also how `just fuzz` and `coverage` tell a target's profile
    from its name, and how a profile picks up a target someone adds. A StateLens
    variant is never a source.
    """
    directory = repo / profile_fuzz_dir(profile)
    return sorted(
        path.name[: -len(".rs")]
        for path in directory.glob(f"{profile}_*.rs")
        if not path.name.endswith("_statelens.rs")
    )


def profile_targets(repo, profile):
    """The StateLens targets a campaign of `profile` builds (SPEC section 5.5)."""
    return [f"{stem}_statelens" for stem in profile_sources(repo, profile)]


def card_module(card_id):
    """The module name part of a card: `ts0003` for TS-0003 (section 18.7)."""
    return "ts" + card_id.split("-", 1)[1]


def pair_key(card_id, base):
    """The key of the pair (card, base), `TS-0003_<base>` (section 18.6.2)."""
    return f"{card_id}_{base}"


def pair_module(card_id, base):
    """The module of the pair, `ts0003_<base>` (section 18.7)."""
    return f"{card_module(card_id)}_{base}"


def scaffold_name(card_id, base):
    """The thin target, and scaffold name, of the pair, `<base>_ts0003_statelens`."""
    return f"{base}_{card_module(card_id)}_statelens"


def scaffold_targets(repo, profile):
    """The scaffolds whose thin target exists in `profile`'s package, by name (SPEC 18.7)."""
    return sorted(
        path.stem
        for path in (repo / profile_fuzz_dir(profile)).glob(f"{profile}_*_statelens.rs")
        if SCAFFOLD_NAME.match(path.stem)
    )


def scaffold_bases(repo, profile):
    """The candidate bases of `profile`: its targets but those with `fuzz_mutator!` (D63)."""
    directory = repo / profile_fuzz_dir(profile)
    return [
        stem
        for stem in profile_sources(repo, profile)
        if "fuzz_mutator!" not in (directory / f"{stem}.rs").read_text(errors="replace")
    ]


# One selected pair (SPEC section 18.6.2): its card and the card's path, its base, its key
# and module, its scaffold's name, that scaffold when its thin target exists, else None,
# and why synthesis skips it, or None.
ScaffoldPair = collections.namedtuple("ScaffoldPair", "card path base key module name scaffold skip")
# The selected pairs, in card order then base order, and how many cards the profile has in
# each tree.
ScaffoldSelection = collections.namedtuple("ScaffoldSelection", "pairs tracked local")


def select_scaffolds(repo, sl_dir, profile, patterns):
    """The pairs (card, base) `patterns` select, for `synthesize` and `targets
    --state-reaching`.

    A pattern `TS-...` names cards by ID. Any other pattern names a base when it matches,
    as `select_targets` matches, the base, its variant or the card's scaffold on it, with
    or without `_statelens`; with none, every candidate base is selected. A card is
    selected when no card pattern was given or one names it, and it yields one pair per
    base selected for it. Nothing selected is a usage error (exit code 1). A pair that
    has a report in `campaign/reach/` is skipped, with the reason in `skip`; `--redo` is
    what synthesizes it again (SPEC section 18.6.2).
    """
    if not PROFILES[profile]["scaffold"]:
        raise Abort(
            1, f"Target-State Synthesis refuses the {profile} profile; use simplex or marshal"
        )
    tracked, local = (list((sl_dir / top / profile).glob("TS-*.md")) for top in CARD_TREES)
    cards = sorted(tracked + local, key=lambda path: (id_number(path), str(path)))
    if not cards:
        raise Abort(
            1,
            f"no target-state cards in {SL}/target-states/{profile}/ or "
            f"{SL}/{LOCAL_STATES}/{profile}/; write them with `just extract-states`",
        )
    bases = scaffold_bases(repo, profile)
    if not bases:
        raise Abort(
            1, f"the {profile} profile has no candidate base in {profile_fuzz_dir(profile)}"
        )
    named = [pattern for pattern in patterns if pattern.startswith("TS-")]
    others = [pattern for pattern in patterns if not pattern.startswith("TS-")]
    existing = scaffold_targets(repo, profile)
    reports = sl_dir / "campaign" / "reach"
    selected = []
    for path in cards:
        card = path.stem
        if named and not any(fnmatch.fnmatchcase(card, pattern) for pattern in named):
            continue
        module = card_module(card)
        chosen = [
            base
            for base in bases
            if not others
            or any(
                fnmatch.fnmatchcase(name, pattern)
                for pattern in others
                for name in (
                    base,
                    f"{base}_statelens",
                    f"{base}_{module}",
                    f"{base}_{module}_statelens",
                )
            )
        ]
        for base in chosen:
            key, name = pair_key(card, base), scaffold_name(card, base)
            scaffold = name if name in existing else None
            skip = None
            if (reports / f"{key}.md").is_file():
                if scaffold:
                    skip = f"{card} on {base} was synthesized as {scaffold}; use --redo"
                else:
                    skip = f"{card} on {base} was synthesized without a scaffold; use --redo"
            selected.append(
                ScaffoldPair(card, path, base, key, pair_module(card, base), name, scaffold, skip)
            )
    if not selected:
        raise Abort(
            1,
            f"no {profile} card and candidate base match {' and '.join(patterns)}; the cards "
            f"are {', '.join(path.stem for path in cards)} and the bases {', '.join(bases)}",
        )
    return ScaffoldSelection(selected, len(tracked), len(local))


# SPEC section 18.8: the reach check. The helper of section 18.7 prints these lines in a
# replay; the script parses them, recomputes every witness record and decides the verdict.
# REACH_LINE is the SPEC's pattern, verbatim.
REACH_LINE = re.compile(
    r"^\[statelens-reach\] (TS-\d{4,}) (?:E(\d+)/(\d+) (held|missed|unverifiable|withheld)\b "
    r"?(.*)|entry ([^\[\s]+)\[([^\]\s]*)\]=(\S+) seq=(\d+)|restart (\S+) seq=(\d+) run=(\d+)|"
    r"trace (\S+)|handoff (holds|lost) mark=(\d+) next=(\d+:\d+|-)|reach (\d+)/(\d+) "
    r"control=([01])|phase (prefix|continuation)|panic (\S+) ?(.*)|truncated seq=(\d+)|done)$"
)
REACH_HELD = re.compile(r"^(exact|intrinsic|construction) bind=(\S+) (.*) read=(\d+)$")
REACH_EXACT = re.compile(r"exact=([^\[\s]+)\[([^\]\s]*)\]=(\S+) seq=(\d+|-)")
REACH_OBS = re.compile(r"obs=(\d+):(\d+):(\d+|-):([^@\s]+)@([^\s:]+:\d+:\d+):(\d+):(\d+)")
REACH_ACTION = re.compile(r"action=([^\[\s]+)\[([^\]\s]*)\] seq=(\d+)")
REACH_EVIDENCE = {"exact": REACH_EXACT, "intrinsic": REACH_OBS, "construction": REACH_ACTION}
# One item of `bind=`, `name=value@Ek`; `?` is the value of an entity a witness leaves
# unbound, and `inc<s>` the incarnation the restart at position s began.
REACH_BIND = re.compile(r"([A-Za-z][A-Za-z0-9]*)=([^,@\[\]\s]+)@E(\d+)")
INCARNATION = re.compile(r"inc(\d+)")
# The module header a scaffold opens with (section 18.7).
MODULE_TITLE = re.compile(r"^//! (TS-\d{4,}) on (\S+)\s*$")
MODULE_FIELD = re.compile(r"^//! (Shape|Knobs|Stages|Control|Injections|Missing):\s*(.*)$")
# A label a module passes to the read side; comments are blanked first.
MODULE_LABEL = re.compile(r"\b(?:seen|sites)\s*\(\s*\"([^\"\\]+)\"")
# Crash attribution: the libFuzzer and sanitizer reports, Rust's panic location, and a
# symbolized stack frame, of which the first outside the runtime libraries is the location.
PANICKED_AT = re.compile(r"panicked at (?:'.*', )?(\S+:\d+:\d+):?\s*$")
SANITIZER_ERROR = re.compile(r"ERROR: (\w+Sanitizer)\b")
STACK_FRAME = re.compile(r"^\s*#\d+ 0x[0-9a-fA-F]+ in .+? (\S+:\d+(?::\d+)?)\s*$")
RUNTIME_FRAME = re.compile(
    r"/rustc/|library/(?:std|core|alloc)/|compiler-rt|sanitizer_common|/(?:[almt]san|ubsan)/"
)
SCAFFOLD_ERROR = "[statelens-scaffold] "
DIFF_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
CRASH = "CRASH (finding candidate)"
# The verdicts of the reach check, best first, as synthesis keeps a version (section
# 18.6.2): a crash is always kept; NOT BUILT and GATE FAILED are not replays' verdicts.
VERDICT_ORDER = (
    CRASH,
    "REACHED",
    "UNVERIFIED",
    "PARTIAL",
    "UNREACHED",
    "NO REPORT",
    "SCAFFOLD ERROR",
)
# The verdict line of a report whose card kept a scaffold: the verdict, its k and its
# annotations (section 18.6.2, Finish, revalidation).
REPORT_VERDICT = re.compile(
    r"^- Verdict: (" + "|".join(re.escape(verdict) for verdict in VERDICT_ORDER) + r")"
    r"(?: (\d+)/\d+)?(?: \((.*)\))?$",
    re.M,
)
# The run and replay lines of a report whose card kept a scaffold: a revalidation rewrites
# them for the scaffold's latest check (section 18.6.2, Finish).
REPORT_RUN_BLOCK = re.compile(r"## Run and replay\n\n```\n.*?\n```", re.S)
# The feedback table of section 18.8: what each signal asks the next attempt to fix.
FEEDBACK_FIXES = {
    "veto": "That, as reported",
    "first": "The setup: configuration, pinned and dependent fields, roles, elector or shape",
    "middle": (
        "The event's content, recipient, channel or order; the trace's a, b and sites against "
        "what the stage expects"
    ),
    "last": "Knob domains, timing, and what keeps the state pending at handoff",
    "cannot": (
        "Nothing in the scaffold, unless an edit the contract allows, or another shape, "
        "gives the capability; otherwise a human adds it"
    ),
    "unverifiable": (
        "A witness that binds the relation: an intrinsic site for an existential line, "
        "otherwise an exact observable keyed by the bound entities, with positions where "
        "order matters"
    ),
    "weak": (
        "Withhold the event without which En cannot hold for these entities, or report that "
        "the History is not causal"
    ),
    "control": (
        "Name, or withhold, a later harness event before En; in the control run, drive every "
        "later event, the handoff check and the base's oracles"
    ),
    "no report": "Use the helper, and never return before the base's oracles",
    "scaffold": "The reason the helper named",
}


def reach_lines(text, card):
    """The `[statelens-reach]` lines of `card` in a replay's output, parsed, in order.

    Each is a dict with its `type` (stage, entry, restart, trace, handoff, reach, phase,
    panic, truncated or done, or unparsed for a line of the card that matches no form), its
    fields, and `text`, the line after the card ID. Lines of other cards are skipped.
    """
    found = []
    prefix = f"[statelens-reach] {card} "
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line.startswith(prefix):
            continue
        match = REACH_LINE.match(line)
        if not match:
            found.append({"type": "unparsed", "text": line[len(prefix) :]})
            continue
        group = match.group
        if group(2) is not None:
            item = {
                "type": "stage",
                "k": int(group(2)),
                "n": int(group(3)),
                "outcome": group(4),
                "rest": group(5),
            }
        elif group(6) is not None:
            item = {
                "type": "entry",
                "observable": group(6),
                "key": group(7),
                "value": group(8),
                "seq": int(group(9)),
            }
        elif group(10) is not None:
            replicas = set() if group(10) == "-" else set(group(10).split(","))
            item = {
                "type": "restart",
                "replicas": replicas,
                "seq": int(group(11)),
                "run": int(group(12)),
            }
        elif group(13) is not None:
            item = {"type": "trace"}
        elif group(14) is not None:
            following = None if group(16) == "-" else tuple(map(int, group(16).split(":")))
            item = {
                "type": "handoff",
                "holds": group(14) == "holds",
                "mark": int(group(15)),
                "next": following,
            }
        elif group(17) is not None:
            item = {
                "type": "reach",
                "k": int(group(17)),
                "n": int(group(18)),
                "control": group(19) == "1",
            }
        elif group(20) is not None:
            item = {"type": "phase", "phase": group(20)}
        elif group(21) is not None:
            item = {"type": "panic", "location": group(21), "message": group(22)}
        elif group(23) is not None:
            item = {"type": "truncated", "seq": int(group(23))}
        else:
            item = {"type": "done"}
        item["text"] = line[len(prefix) :]
        found.append(item)
    return found


def reach_pairs(key):
    """The `name=value` pairs of an exact item's key or an action's entities."""
    pairs = []
    for item in key.split(","):
        name, sep, value = item.partition("=")
        if sep and name:
            pairs.append((name, value))
    return pairs


def reach_items(pattern, text):
    """The groups of each item of `pattern` in `text`, which holds them separated by single
    spaces, or None when it holds anything else."""
    items, position = [], 0
    while position < len(text):
        match = pattern.match(text, position)
        if not match:
            return None
        items.append(match.groups())
        position = match.end()
        if position < len(text):
            if text[position] != " ":
                return None
            position += 1
    return items


def held_record(rest):
    """The witness record of a `held` line, from its text after `held` (SPEC section 18.8),
    or None when that does not match.

    `bind` maps each entity to its value and `by` to the event that bound it, and `bad`
    is set when an item of `bind=` is malformed or repeated. `items` holds the evidence
    items, or None when the evidence is not a sequence of its kind's items; `pairs` the
    `name=value` pairs of the exact keys or the action; `obs` the observations; and
    `position` the largest position the evidence carries, or None, also for an `exact`
    witness with an unstamped item, whose entry may come after any other.
    """
    match = REACH_HELD.match(rest)
    if not match:
        return None
    kind, bind_text, evidence, read = match.groups()
    record = {
        "kind": kind,
        "bind": {},
        "by": {},
        "bad": False,
        "evidence": evidence,
        "read": int(read),
        "items": reach_items(REACH_EVIDENCE[kind], evidence),
        "pairs": [],
        "obs": [],
        "position": None,
    }
    for item in bind_text.split(","):
        bound = REACH_BIND.fullmatch(item)
        if not bound or bound.group(1) in record["bind"]:
            record["bad"] = True
            continue
        record["bind"][bound.group(1)] = bound.group(2)
        record["by"][bound.group(1)] = int(bound.group(3))
    positions = []
    for item in record["items"] or ():
        if kind == "exact":
            record["pairs"] += reach_pairs(item[1])
            positions.append(0 if item[3] == "-" else int(item[3]))
        elif kind == "intrinsic":
            run, seq, me, label, site = item[:5]
            record["obs"].append(
                {"run": int(run), "seq": int(seq), "me": me, "label": label, "site": site}
            )
            positions.append(int(seq))
        else:
            record["pairs"] += reach_pairs(item[1])
            positions.append(int(item[2]))
    unstamped = kind == "exact" and 0 in positions
    positions = [position for position in positions if position]
    record["position"] = max(positions) if positions and not unstamped else None
    return record


def replica_entities(history):
    """The entities of a History that name replicas: every actor but `harness`, and every
    name that starts with a capital letter, as `R` and `B` do (SPEC section 18.3)."""
    names = {event.actor for event in history.events if event.actor not in (None, "harness")}
    for event in history.events:
        names.update(name for name, _ in event.entities if name[0].isupper())
    return names


def witness_rule(k, record, history, records, entries, replicas):
    """The first rule of SPEC section 18.7 that the record of held stage `k` breaks, among
    those that need no position: `bind`, `as`, `evidence`, `intrinsic` and `construction`;
    or None.

    `records` maps each held stage to its record, `entries` holds the `entry` lines printed
    before stage k's line as (observable, key, value, seq), and `replicas` the entities that
    name replicas.
    """
    event = history.events[k - 1]
    bind = record["bind"]
    if record["bad"] or any(name not in bind for name, _ in event.entities):
        return "bind"
    for name, earlier in event.entities:
        source = records.get(earlier) if earlier else None
        if earlier and (bind[name] == "?" or not source or source["bind"].get(name) != bind[name]):
            return "as"
    kind = record["kind"]
    if record["items"] is None:
        return "intrinsic" if kind == "intrinsic" else "evidence"
    if kind in ("exact", "construction"):
        named = collections.defaultdict(set)
        for name, value in record["pairs"]:
            named[name].add(value)
        keyed = False
        for name, _ in event.entities:
            value = bind[name]
            if named[name] and named[name] != {value}:
                return "evidence"
            keyed = keyed or bool(named[name])
            # An incarnation is witnessed by its `restart` line (the `incarnation` rule).
            if not named[name] and value != "?" and not INCARNATION.fullmatch(value):
                return "evidence"
        if not keyed:
            return "evidence"
        if kind == "exact":
            for observable, key, value, seq in record["items"]:
                if seq != "-" and (observable, key, value, int(seq)) not in entries:
                    return "evidence"
    if kind == "intrinsic":
        if len(record["obs"]) != 1:
            return "intrinsic"
        valued = [name for name, _ in event.entities if bind[name] != "?"]
        me = record["obs"][0]["me"]
        # A site without a replica, `me=-`, witnesses no replica.
        if len(valued) > 1 or any(
            name not in replicas or bind[name] != me or me == "-" for name in valued
        ):
            return "intrinsic"
    if kind == "construction" and (k == len(history.events) or event.actor != "harness"):
        return "construction"
    return None


def reach_replay(text, history, shape=None, control=False):
    """Recomputes the stage lines of one replay of the scaffold of `history` (SPEC 18.8).

    `shape` is the module's, A or B, or None when its header names none, and `control`
    marks the control run. Returns a dict: `lines` (reach_lines); `stages`, mapping each
    k that has an outcome to its stage, whose `outcome` (held, missed, unverifiable or
    withheld) and `detail` are those after the checks, `helper` the outcome its line
    printed, or None without one, `record` its witness record and `trace` the trace
    lines after a miss; `held` and `first_miss`; `handoff`, the helper's handoff line,
    and `holds`, whether the handoff holds after the recheck; `reach`, `done`, `restarts`,
    `truncated`, the smallest position a `truncated` line names, or None without one,
    `sites`, the `label@site` of every observation a witness cites, `annotations`; and
    `problems`, which make the replay report nothing usable.
    """
    n = len(history.events)
    lines = reach_lines(text, history.id)
    stages, entries, restarts, problems = {}, [], [], []
    others = set(re.findall(r"^\[statelens-reach\] (TS-\d{4,}) ", text, re.M)) - {history.id}
    if others:
        problems.append(f"the scaffold reports as {', '.join(sorted(others))}, not {history.id}")
    handoff = reach = last = None
    done = False
    for index, line in enumerate(lines):
        kind = line["type"]
        if kind == "trace":
            if last is not None and last["helper"] == "missed":
                last["trace"].append(line["text"])
            continue
        last = None
        if kind == "stage":
            k = line["k"]
            if line["n"] != n:
                problems.append(
                    f"E{k}/{line['n']}: the scaffold opened {line['n']} stages; the card has {n}"
                )
            # A repeated line is the panic hook's copy of the first.
            elif 1 <= k <= n and k not in stages:
                stage = {
                    "helper": line["outcome"],
                    "outcome": line["outcome"],
                    "detail": line["rest"],
                    "index": index,
                    "text": line["text"],
                    "record": held_record(line["rest"]) if line["outcome"] == "held" else None,
                    "entries": set(entries),
                    "trace": [],
                }
                stages[k] = stage
                last = stage
        elif kind == "entry":
            entries.append((line["observable"], line["key"], line["value"], line["seq"]))
        elif kind == "restart":
            restarts.append(line)
        elif kind == "handoff" and handoff is None:
            handoff = dict(line, index=index)
        elif kind == "reach" and reach is None:
            reach = line
            if line["n"] != n:
                problems.append(f"reach {line['k']}/{line['n']}: the card has {n} stages")
        elif kind == "done":
            done = True
    cut = min((line["seq"] for line in lines if line["type"] == "truncated"), default=None)
    records = {k: stage["record"] for k, stage in stages.items() if stage["record"]}
    replicas = replica_entities(history)
    starts = {restart["seq"] for restart in restarts}

    def downgrade(stage, reason):
        stage["outcome"], stage["detail"] = "unverifiable", reason

    def ordered(j, k):
        return j != k and frozenset((j, k)) not in history.free

    def restarted(low, high, replica=None):
        return [
            restart["seq"]
            for restart in restarts
            if low < restart["seq"] < high and (replica is None or replica in restart["replicas"])
        ]

    # The handoff holds only when En is held by the line right before it, read in the
    # handoff call: its mark directly follows the read (section 18.8). Otherwise En is missed.
    final = stages.get(n)
    if final and final["helper"] == "held":
        record = final["record"]
        if not (
            handoff
            and handoff["holds"]
            and record
            and handoff["index"] == final["index"] + 1
            and handoff["mark"] == record["read"] + 1
        ):
            final["outcome"] = "missed"
            final["detail"] = "handoff lost" + (
                f" (mark={handoff['mark']}, read={record['read']})" if handoff and record else ""
            )
    # From the first observation the trace dropped at TRACE_CAP on, what it holds is
    # incomplete (section 9.6): a witness read at or after that position, and En when the
    # cut comes at or before the handoff mark, cannot hold, wherever the line is printed.
    if cut is not None:
        for stage in stages.values():
            record = stage["record"]
            if stage["outcome"] == "held" and record and record["read"] >= cut:
                downgrade(stage, "(trace truncated)")
        if final and final["outcome"] == "held" and handoff["mark"] >= cut:
            downgrade(final, "(trace truncated)")
    for k in range(1, n + 1):
        stage = stages.get(k)
        if stage and stage["outcome"] == "held":
            rule = (
                witness_rule(k, stage["record"], history, records, stage["entries"], replicas)
                if stage["record"]
                else "evidence"
            )
            if rule:
                downgrade(stage, f"witness rejected: {rule}")
    # Both stages of an ordered pair need a position, and so do a line that binds a
    # restarted replica and the earlier stages its `as Ek` links it to.
    need = {k for k in range(1, n + 1) if any(ordered(j, k) for j in range(1, n + 1))}
    named = set().union(*(restart["replicas"] for restart in restarts))
    for k, record in records.items():
        event = history.events[k - 1]
        if {record["bind"].get(name) for name, _ in event.entities if name in replicas} & named:
            need.add(k)
            need.update(earlier for _, earlier in event.entities if earlier)
    for k in sorted(need):
        stage = stages.get(k)
        if stage and stage["outcome"] == "held" and stage["record"]["position"] is None:
            downgrade(stage, "(no position)")
    position = {k: record["position"] for k, record in records.items()}
    annotations = []
    for k, record in sorted(records.items()):
        event, here = history.events[k - 1], record["position"]
        linked = {earlier for _, earlier in event.entities if earlier}
        if here is not None and any(
            position.get(j) is not None and restarted(*sorted((position[j], here))) for j in linked
        ):
            annotations.append("relation across restart")
        stage = stages[k]
        if stage["outcome"] != "held":
            continue
        if here is None:
            # Without a position only the incarnation's existence can be checked.
            if any(
                (inc := INCARNATION.fullmatch(value)) and int(inc.group(1)) not in starts
                for value in record["bind"].values()
            ):
                downgrade(stage, "witness rejected: incarnation")
            continue
        rule = None
        if any(
            ordered(j, k) and position.get(j) is not None and here <= position[j]
            for j in range(1, k)
        ):
            rule = "order"
        elif record["kind"] == "intrinsic":
            seen = record["obs"][0]
            for j in range(1, k):
                other = records.get(j)
                if other and other["kind"] == "intrinsic" and other["obs"]:
                    run, seq = other["obs"][0]["run"], other["obs"][0]["seq"]
                    if run != seen["run"] and not restarted(*sorted((seq, seen["seq"]))):
                        rule = "run"
        if rule is None:
            for value in record["bind"].values():
                inc = INCARNATION.fullmatch(value)
                if inc and (int(inc.group(1)) not in starts or int(inc.group(1)) > here):
                    rule = "incarnation"
            # Only an entity of the line names the incarnation a relation crosses into.
            values = {record["bind"].get(name) for name, _ in event.entities}
            bound = {record["bind"][name] for name, _ in event.entities if name in replicas}
            for replica in bound - {"?"}:
                for j in linked:
                    if position.get(j) is None:
                        continue
                    inside = restarted(*sorted((position[j], here)), replica)
                    if inside and f"inc{max(inside)}" not in values:
                        rule = "incarnation"
        if rule:
            downgrade(stage, f"witness rejected: {rule}")
    # Shape A: En counts only with a later observation of an honest replica in its run.
    if shape == "A" and final and final["outcome"] == "held":
        record, following = final["record"], handoff["next"]
        if (
            record["position"] is None
            or following is None
            or following[1] <= record["position"]
            or (record["obs"] and following[0] != record["obs"][0]["run"])
        ):
            downgrade(final, "(no continuation)")
    missed = False
    for k in range(1, n + 1):
        stage = stages.get(k)
        if stage is None:
            if not missed:
                stages[k] = {
                    "helper": None,
                    "outcome": "unverifiable",
                    "detail": "(no line)",
                    "record": None,
                    "text": None,
                    "trace": [],
                }
            continue
        if stage["outcome"] == "withheld" and not control:
            downgrade(stage, "(withheld outside the control run)")
        missed = missed or stage["outcome"] == "missed"
    outcomes = {k: stage["outcome"] for k, stage in stages.items()}
    return {
        "lines": lines,
        "stages": stages,
        "held": sum(outcome == "held" for outcome in outcomes.values()),
        "first_miss": min((k for k, o in outcomes.items() if o == "missed"), default=None),
        "handoff": handoff,
        "holds": bool(final and final["outcome"] == "held"),
        "reach": reach,
        "done": done,
        "restarts": restarts,
        "truncated": cut,
        "sites": sorted(
            {
                f"{seen['label']}@{seen['site']}"
                for record in records.values()
                for seen in record["obs"]
            }
        ),
        "annotations": list(dict.fromkeys(annotations)),
        "problems": problems,
    }


def module_header(text):
    """The header a scaffold module opens with (SPEC section 18.7).

    Returns a dict: `card` and `base` from its first line; `shape`, A or B or None;
    `control`, the number of the event `Control: withholds Ek` names, `n/a`, the line's
    text when it says neither, or None without a Control: line; `missing`, the
    capabilities of its Missing: line; and `fields`, every field's text. A `//!` line
    that starts no field continues the one above it.
    """
    header = {"card": None, "base": None, "shape": None, "control": None, "missing": []}
    fields, field = {}, None
    for line in text.splitlines():
        if not line.startswith("//!"):
            if line.strip():
                break
            continue
        title, match = MODULE_TITLE.match(line), MODULE_FIELD.match(line)
        if title and header["card"] is None:
            header["card"], header["base"], field = title.group(1), title.group(2), None
        elif match:
            field = match.group(1) if match.group(1) not in fields else None
            if field:
                fields[field] = match.group(2).strip()
        elif field and line[3:].strip():
            fields[field] += " " + line[3:].strip()
    shape = re.match(r"([AB])\b", fields.get("Shape", ""))
    header["shape"] = shape.group(1) if shape else None
    control = fields.get("Control")
    if control is not None:
        value = control.strip().rstrip(".")
        withheld = re.fullmatch(r"withholds E(\d+)", value)
        header["control"] = int(withheld.group(1)) if withheld else value
    missing = fields.get("Missing", "").strip().rstrip(".")
    if missing and missing.lower() != "none":
        header["missing"] = [item.strip() for item in missing.split(";") if item.strip()]
    header["fields"] = fields
    return header


def unbound_labels(module, labels):
    """The labels `module` passes to `seen` or `sites` that `labels`, every `sl_probe!`
    label and `sl_implies!` ID under the editable roots, does not hold (SPEC 18.8)."""
    found = MODULE_LABEL.findall(blank_inert(module))
    return [label for label in dict.fromkeys(found) if label not in labels]


def frame_location(lines):
    """The location of the first symbolized stack frame outside the runtime libraries."""
    for line in lines:
        frame = STACK_FRAME.match(line)
        if frame and not RUNTIME_FRAME.search(frame.group(1)):
            return frame.group(1)
    return None


def replay_failure(code, text, card, n, shape=None):
    """How a reach replay failed (SPEC section 18.8, crash attribution), or None when it
    passed: its exit code is 0. A code of None is the script's kill.

    Returns a dict: `kind` (timeout, oom, leak, sanitizer or panic), `message`, `location`
    (the panic's, or the first frame outside the runtime libraries of a report's stack, or
    None), `phase` (prefix, continuation or unknown), and `scaffold`, the reason of the
    helper's scaffold error when the first panic is one at a location in
    `target_states/mod.rs`, else None.
    """
    if code == 0:
        return None
    lines = text.splitlines()
    # A `panic` line of the helper may quote a `[statelens][` message: first_panic skips it.
    other = [line for line in lines if not line.startswith("[statelens-reach] ")]
    sanitizer = next(
        (
            line.strip()
            for line in other
            if SANITIZER_ERROR.search(line) and "ERROR: LeakSanitizer" not in line
        ),
        None,
    )

    def marker(needle):
        return next((line.strip() for line in other if needle in line), None)

    if code is None or marker("ERROR: libFuzzer: timeout"):
        kind = "timeout"
        message = marker("ERROR: libFuzzer: timeout") or marker("statelens: killed after")
    elif marker("ERROR: libFuzzer: out-of-memory"):
        kind, message = "oom", marker("ERROR: libFuzzer: out-of-memory")
    elif marker("ERROR: LeakSanitizer"):
        kind, message = "leak", marker("ERROR: LeakSanitizer")
    elif sanitizer:
        kind, message = "sanitizer", sanitizer
    else:
        kind, message = "panic", first_panic(other)
    # The first panic: the helper's `panic` line, which it prints before the default hook
    # prints `panicked at`, or that line and the message on the next.
    location = panic = panic_index = None
    for index, line in enumerate(lines):
        helper = REACH_LINE.match(line)
        if helper and helper.group(21) is not None and panic_index is None:
            panic_index, panic = index, helper.group(22)
            if helper.group(21) != "-":
                location = helper.group(21)
                break
            continue
        default = PANICKED_AT.search(line)
        if default:
            location = default.group(1)
            if panic is None:
                panic = lines[index + 1].strip() if index + 1 < len(lines) else ""
            break
    if kind != "panic":
        location = frame_location(other)
    scaffold = None
    if kind == "panic" and panic and panic.startswith(SCAFFOLD_ERROR):
        if location and location.rsplit(":", 2)[0].endswith("target_states/mod.rs"):
            scaffold = panic[len(SCAFFOLD_ERROR) :].split(" ", 1)
            scaffold = scaffold[1] if len(scaffold) > 1 else ""
    if kind == "panic" and not message:
        message = panic or f"exit code {code}"
    return {
        "kind": kind,
        "message": message,
        "location": location,
        "phase": failure_phase(lines, card, n, shape, panic_index),
        "scaffold": scaffold,
    }


def failure_phase(lines, card, n, shape, panic_index):
    """The phase a replay failed in (SPEC section 18.7): for a panic the helper reported,
    the `phase` line it printed, and in Shape A `continuation` when the evaluation it ran
    found En held; otherwise the last `phase` line, which in Shape A says only that the
    failure came after the handoff. `unknown` without one."""
    phases = [
        (index, match.group(20))
        for index, match in ((index, REACH_LINE.match(line)) for index, line in enumerate(lines))
        if match and match.group(1) == card and match.group(20)
    ]
    if panic_index is not None:
        if shape == "A":
            held = f"[statelens-reach] {card} E{n}/{n} held "
            after = any(line.startswith(held) for line in lines[panic_index:])
            return "continuation" if after else "prefix"
        later = [phase for index, phase in phases if index > panic_index]
        earlier = [phase for index, phase in phases if index < panic_index]
        return (later or earlier[-1:] or ["unknown"])[0]
    last = phases[-1][1] if phases else "unknown"
    if shape == "A" and last != "continuation":
        return "unknown"
    return last


def diff_added_lines(diff):
    """Maps each file a unified diff changes to the new-side numbers of the lines it adds;
    a moved line is added where it lands."""
    added, path, old, new, line = {}, None, 0, 0, 0
    for raw in diff.splitlines():
        if old > 0 or new > 0:
            tag = raw[:1]
            if tag == "\\":
                continue
            if tag == "+":
                added.setdefault(path, set()).add(line)
                line, new = line + 1, new - 1
            elif tag == "-":
                old -= 1
            else:
                line, old, new = line + 1, old - 1, new - 1
            continue
        if raw.startswith("+++ "):
            name = raw[4:].split("\t")[0].strip()
            path = None if name == "/dev/null" else name[2:] if name.startswith("b/") else name
            continue
        hunk = DIFF_HUNK.match(raw)
        if hunk and path:
            old = int(hunk.group(1) or 1)
            line, new = int(hunk.group(2)), int(hunk.group(3) or 1)
    return added


def location_in_diff(location, added):
    """Whether `location`, `file:line[:col]`, is a line `added` (diff_added_lines) holds.
    The file may be relative to the repository, to the package, or absolute."""
    match = re.fullmatch(r"(.+?):(\d+)(?::\d+)?", location or "")
    if not match:
        return False
    path, number = match.group(1).removeprefix("./"), int(match.group(2))
    return any(
        number in lines
        and (path == changed or path.endswith("/" + changed) or changed.endswith("/" + path))
        for changed, lines in added.items()
    )


def stage_lines(replay):
    """The stage lines of a reach_replay, as printed, in order."""
    return [line["text"] for line in replay["lines"] if line["type"] == "stage"]


def stage_values(stage, names=None):
    """The values a stage's witness record binds, by entity, or {} without one."""
    record = stage and stage.get("record")
    values = dict(record["bind"]) if record else {}
    return values if names is None else {name: values.get(name) for name in names}


def control_status(history, header, canonical, control):
    """The control of SPEC section 18.8, from the canonical run's and the control run's
    reach_replay: (status, reason), the status being ok, vacuous, weak, missing, n/a
    (accepted) or n/a refused."""
    n = len(history.events)
    value = header["control"]
    if value is None:
        return "missing", "the module has no Control: line"
    harness = [k for k in range(1, n) if history.events[k - 1].actor == "harness"]
    if value == "n/a":
        if harness:
            return "n/a refused", f"Control: n/a, but E{harness[0]} is a harness event before E{n}"
        for k, stage in sorted(canonical["stages"].items()):
            kind = stage["record"]["kind"] if stage["record"] else None
            if stage["helper"] == "held" and kind not in ("exact", "construction"):
                return "n/a refused", f"Control: n/a, but E{k}'s witness is {kind}"
        return "n/a", None
    if not isinstance(value, int):
        return "vacuous", f"the Control: line `{value}` names no withheld event"
    if not 1 <= value < n or history.events[value - 1].actor != "harness":
        return "vacuous", f"E{value} is not a harness event before E{n}"
    if control is None:
        return "vacuous", "the control did not run"
    incomplete = control["problems"] + [
        f"no {line} line" for line in ("reach", "done") if not control[line]
    ]
    if incomplete:
        return "vacuous", "the control run is incomplete: " + "; ".join(incomplete)
    stages = control["stages"]
    if stages.get(value, {}).get("helper") != "withheld":
        return "vacuous", f"the control run printed no withheld line for E{value}"
    for j in range(1, value):
        if stages.get(j, {}).get("outcome") == "missed":
            return "vacuous", f"E{j} missed in the control run"
        if stage_values(stages.get(j)) != stage_values(canonical["stages"].get(j)):
            return "vacuous", f"E{j} binds other values in the control run than in the canonical"
    # Another omission after Ek could explain the final miss by itself.
    for j in range(value + 1, n):
        stage = stages.get(j)
        if not stage or stage["helper"] is None:
            return "vacuous", f"E{j} has no line in the control run"
        if stage["helper"] == "withheld":
            return "vacuous", f"E{j} is withheld in the control run too"
    last, theirs = stages.get(n), canonical["stages"].get(n)
    if not last or last["helper"] not in ("held", "missed"):
        return "vacuous", f"E{n} has neither a held nor a missed line in the control run"
    event = history.events[n - 1]
    names = [name for name, _ in event.entities]
    # Only an entity both witnesses bind to a value tells the states apart; one a witness
    # leaves out of bind=, or binds to `?`, is no evidence of another state, and neither
    # is a value the control witness's own evidence contradicts: its key, or the earlier
    # stage it cites as `as Ej`, names another.
    control_bind, canonical_bind = stage_values(last, names), stage_values(theirs, names)
    if last["record"]:
        for name, value in last["record"]["pairs"]:
            if control_bind.get(name) not in (None, "?", value):
                control_bind[name] = None
        for name, earlier in event.entities:
            source = stages.get(earlier, {}).get("record") if earlier else None
            if source and control_bind[name] not in (None, "?", source["bind"].get(name)):
                control_bind[name] = None
    apart = any(
        control_bind[name] not in (None, "?")
        and canonical_bind[name] not in (None, "?")
        and control_bind[name] != canonical_bind[name]
        for name in names
    )
    if (
        theirs
        and theirs["helper"] == "held"
        and last["helper"] == "held"
        and last["outcome"] != "missed"
        and not apart
    ):
        return "weak", f"E{n} holds in the control run for the bound entities"
    return "ok", None


def reach_verdict(
    history, module, canonical, control=None, final=None, stray=None, diff=None, labels=None
):
    """The verdict of a scaffold version's reach check (SPEC section 18.8).

    `module` is the scaffold module's text; `canonical`, `control` and `final` are each
    replay's (exit code, output), or None when it did not run, the code being None when
    the script killed it. `stray` names a crash file a run of the agent's left (section
    18.6.2), `diff` is the card's diff, and `labels` every probe label and `sl_implies!`
    ID under the editable roots. Returns a dict: `verdict`, `k`, `n`, `annotations`,
    `reasons`, `control` and `control_reason`, `crash` (replay_failure of the replay that
    failed, with its `replay`), `scaffold_error`, `header` and `replays`.
    """
    header = module_header(module or "")
    n = len(history.events)
    replays, failures = {}, []
    for name, replay in (("canonical", canonical), ("control", control), ("final", final)):
        if replay is None:
            continue
        code, text = replay
        replays[name] = reach_replay(text, history, header["shape"], control=name == "control")
        failure = replay_failure(code, text, history.id, n, header["shape"])
        if failure:
            failures.append(dict(failure, replay=name))
    base = replays.get("canonical")
    crashes = [failure for failure in failures if failure["scaffold"] is None]
    result = {
        "card": history.id,
        "n": n,
        "k": base["held"] if base else 0,
        "header": header,
        "replays": replays,
        "crash": crashes[0] if crashes else None,
        "scaffold_error": None,
        "control": None,
        "control_reason": None,
        "reasons": [],
    }
    reasons = result["reasons"]
    if crashes or stray:
        result["verdict"] = CRASH
        for failure in crashes:
            reasons.append(
                f"{failure['kind']} in the {failure['replay']} replay, phase {failure['phase']}, "
                f"at {failure['location'] or 'an unknown location'}: {failure['message']}"
            )
        if stray:
            reasons.append(f"a run of the agent's left {stray}")
    elif failures:
        result["verdict"] = "SCAFFOLD ERROR"
        result["scaffold_error"] = failures[0]["scaffold"]
        reasons.append(f"[statelens-scaffold] {failures[0]['scaffold']}")
    elif base is None or base["reach"] is None or not base["done"] or base["problems"]:
        result["verdict"] = "NO REPORT"
        if base is None:
            reasons.append("the canonical input was not replayed")
        else:
            reasons += base["problems"]
            if base["reach"] is None:
                reasons.append("the replay printed no reach line")
            if not base["done"]:
                reasons.append("the replay printed no done line")
    else:
        status, reason = control_status(history, header, base, replays.get("control"))
        result["control"], result["control_reason"] = status, reason
        stages = base["stages"]
        first = base["first_miss"]
        if first:
            result["verdict"] = "UNREACHED" if first == 1 else "PARTIAL"
            # k counts the stages held before the miss, as a version is kept by.
            result["k"] = sum(stages[k]["outcome"] == "held" for k in range(1, first))
            for k in range(1, first):
                if stages[k]["outcome"] != "held":
                    reasons.append(f"E{k} {stages[k]['outcome']} {stages[k]['detail']}".rstrip())
            detail = stages[first]["detail"]
            reasons.append(f"E{first} missed" + (f": {detail}" if detail else ""))
        else:
            for k, stage in sorted(stages.items()):
                if stage["outcome"] != "held":
                    reasons.append(f"E{k} {stage['outcome']} {stage['detail']}".rstrip())
            if reason:
                reasons.append(reason)
            if reasons:
                result["verdict"] = "UNVERIFIED"
            else:
                result["verdict"], result["k"] = "REACHED", n
    annotations = []
    later = replays.get("final")
    if base and later and not any(failure["replay"] == "final" for failure in failures):
        if stage_lines(base) != stage_lines(later):
            annotations.append("nondeterministic")
    status = result["control"]
    if status == "weak":
        annotations.append("weak")
    if status in ("n/a", "n/a refused"):
        annotations.append("control n/a")
    if status == "missing":
        annotations.append("control missing")
    if labels is not None:
        annotations += [f"unbound label {label}" for label in unbound_labels(module or "", labels)]
    annotations += [f"missing: {capability}" for capability in header["missing"]]
    if base:
        annotations += base["annotations"]
    if stray:
        annotations.append("stray failure")
    crash = result["crash"]
    if crash and diff and location_in_diff(crash["location"], diff_added_lines(diff)):
        annotations.append(f"location in {history.id} diff")
    result["annotations"] = annotations
    return result


def verdict_text(result):
    """A verdict as the console and the report print it, with its annotations."""
    verdict = result["verdict"]
    if verdict in ("REACHED", "UNVERIFIED", "PARTIAL", "UNREACHED"):
        verdict = f"{verdict} {result['k']}/{result['n']}"
    if result["annotations"]:
        verdict += f" ({', '.join(result['annotations'])})"
    return verdict


def verdict_key(result, attempt):
    """Sorts built versions best first, as synthesis keeps one (SPEC section 18.6.2): by
    verdict, then by the stages held, then the later attempt."""
    return (VERDICT_ORDER.index(result["verdict"]), -result["k"], -attempt)


def report_verdict(text):
    """The verdict of a reach report whose card kept a scaffold: a dict of `verdict`, `k`,
    `annotations` and `text`, the line after `- Verdict: `; None for NOT BUILT, GATE
    FAILED or no verdict line."""
    found = REPORT_VERDICT.search(text)
    if not found:
        return None
    return {
        "verdict": found[1],
        "k": int(found[2] or 0),
        "annotations": found[3].split(", ") if found[3] else [],
        "text": found[0][len("- Verdict: ") :],
    }


def crash_text(crash):
    """A report's `- Crash:` line for the reach check's crash attribution `crash`."""
    return (
        f"- Crash: {crash['kind']} in the {crash['replay']} replay, phase {crash['phase']}, "
        f"at {crash['location'] or 'an unknown location'}: {crash['message']}"
    )


def stands_worse(before, result):
    """Whether a kept scaffold's revalidation `result` stands worse than `before`, its
    report_verdict (section 18.6.2, Finish): a crash gained or lost, a verdict later in the
    order a version is kept by, or fewer stages held under the same verdict."""

    def rank(verdict, k):
        counted = verdict in ("REACHED", "UNVERIFIED", "PARTIAL", "UNREACHED")
        return VERDICT_ORDER.index(verdict), -k if counted else 0

    if (before["verdict"] == CRASH) != (result["verdict"] == CRASH):
        return True
    return rank(result["verdict"], result["k"]) > rank(before["verdict"], before["k"])


def reach_feedback(result):
    """The reach check's part of the next attempt's FEEDBACK (SPEC section 18.8): the
    verdict and why, the stage and trace lines, and what each signal asks for. None for a
    CRASH (finding candidate), which stops refinement."""
    verdict = result["verdict"]
    if verdict == CRASH:
        return None
    card, n = result["card"], result["n"]
    out = [f"Verdict: {verdict_text(result)}"] + [f"- {reason}" for reason in result["reasons"]]
    shown = ("stage", "trace", "truncated", "handoff", "reach", "unparsed")
    replays = [("canonical", result["replays"].get("canonical"))]
    if result["control"] in ("vacuous", "weak"):
        replays.append(("control", result["replays"].get("control")))
    for name, replay in replays:
        lines = [line for line in (replay or {}).get("lines", ()) if line["type"] in shown]
        if lines:
            out += ["", f"The lines of the {name} replay:"]
            out += [f"[statelens-reach] {card} {line['text']}" for line in lines]
    fixes = []
    if verdict == "SCAFFOLD ERROR":
        fixes.append((f"SCAFFOLD ERROR: {result['scaffold_error']}", FEEDBACK_FIXES["scaffold"]))
    elif verdict == "NO REPORT":
        fixes.append(("NO REPORT", FEEDBACK_FIXES["no report"]))
    else:
        stages = result["replays"]["canonical"]["stages"]
        for k, stage in sorted(stages.items()):
            if stage["outcome"] == "missed":
                part = "first" if k == 1 else "last" if k == n else "middle"
                if stage["detail"].startswith("cannot:"):
                    part = "cannot"
                signal = f"E{k} missed" + (f" ({stage['detail']})" if stage["detail"] else "")
                fixes.append((signal, FEEDBACK_FIXES[part]))
                break
            if stage["outcome"] != "held":
                signal = f"E{k} {stage['outcome']} {stage['detail']}".rstrip()
                fixes.append((signal, FEEDBACK_FIXES["unverifiable"]))
        status = result["control"]
        if status == "weak":
            fixes.append(("weak control", FEEDBACK_FIXES["weak"]))
        elif status in ("vacuous", "missing", "n/a refused"):
            fixes.append((f"{status} control: {result['control_reason']}", FEEDBACK_FIXES["control"]))
    if fixes:
        out += ["", "What to fix:"] + [f"- {signal}: {fix}" for signal, fix in fixes]
    return "\n".join(out)


def simplex_types(repo):
    """Maps each `impl Simplex for P` of the fuzz core to whether it uses cert_mock (D15)."""
    core = read_edit_file(repo, CORE_SIMPLEX)
    types = {}
    for match in re.finditer(r"impl Simplex for (\w+) \{", core):
        rest = core[match.end() :]
        following = re.search(r"\nimpl ", rest)
        block = rest[: following.start()] if following else rest
        types[match.group(1)] = "type Scheme = cert_mock::Scheme<" in block
    return types


def turbofish_arguments(text):
    """The type arguments of every `::<...>` in `text`, split at top-level commas."""
    arguments = []
    for match in re.finditer(r"::<", text):
        depth = 1
        start = index = match.end()
        while index < len(text) and depth:
            char = text[index]
            if char == "<":
                depth += 1
            elif char == ">":
                depth -= 1
                if not depth:
                    arguments.append(text[start:index])
            elif char == "," and depth == 1:
                arguments.append(text[start:index])
                start = index + 1
            index += 1
    return [argument.strip() for argument in arguments if argument.strip()]


def check_simplex_cert_mock(repo, stems):
    """Only a `cert_mock` scheme may become a StateLens variant (D15).

    The scheme is the first type argument of the target's call of a fuzz entry
    point, `fuzz::<...>` or one of the `fuzz_*::<...>` audit entry points; the
    others name its driver and its coverage mode, which this says nothing about.
    """
    types = simplex_types(repo)
    for stem in stems:
        text = (repo / profile_fuzz_dir("simplex") / f"{stem}.rs").read_text()
        names = re.findall(r"\bfuzz\w*::<\s*(\w+)", text)
        if not names:
            raise Abort(2, f"{stem}: no fuzz::<P, ...> call to check (D15)")
        for name in names:
            if not types.get(name):
                raise Abort(
                    2,
                    f"{stem}: {name} does not use the cert_mock certificate scheme; "
                    "StateLens fuzz targets may only use cert_mock (D15)",
                )


def check_marshal_cert_mock(repo, stems):
    """The cryptography check of the marshal profile (SPEC section 8.4)."""
    types = simplex_types(repo)
    others = sorted(name for name, cert_mock in types.items() if not cert_mock)
    shared = {
        str(path.relative_to(repo)): path.read_text()
        for path in sorted((repo / MARSHAL_SRC).rglob("*.rs"))
    }
    for stem in stems:
        text = (repo / MARSHAL_TARGETS / f"{stem}.rs").read_text()
        for argument in turbofish_arguments(text):
            if not types.get(argument):
                raise Abort(
                    2,
                    f"{stem}: type argument {argument} is not a Simplex type with the "
                    "cert_mock certificate scheme; StateLens fuzz targets may only use "
                    "cert_mock (SPEC section 8.4)",
                )
        for name in others:
            word = re.compile(r"\b" + re.escape(name) + r"\b")
            if word.search(text):
                raise Abort(
                    2,
                    f"{stem}: names {name}, whose Simplex impl does not use the cert_mock "
                    "certificate scheme (SPEC section 8.4)",
                )
            for relative, source in shared.items():
                if word.search(source):
                    raise Abort(
                        2,
                        f"{stem}: {relative} names {name}, whose Simplex impl does not use "
                        "the cert_mock certificate scheme (SPEC section 8.4)",
                    )


def runtime_text(repo, profile):
    """The runtime module a campaign of `profile` creates (SPEC section 9, edits 1 and Q1).

    The template is written for the consensus crate, where it is `simplex::statelens`.
    Elsewhere the module path is renamed, and the tests from the consensus-only marker to
    the end of the file are dropped, because they build Simplex signing schemes.
    """
    text = read_sl_file(repo, SL / "runtime" / "statelens.rs")
    module = PROFILES[profile]["module"]
    if module == "simplex":
        return text
    if text.count(RUNTIME_CONSENSUS_ONLY) != 1:
        raise Abort(
            2,
            f"materialize: expected one line {RUNTIME_CONSENSUS_ONLY!r} in "
            f"{SL}/runtime/statelens.rs; restore it from HEAD",
        )
    text = text[: text.index(RUNTIME_CONSENSUS_ONLY)].rstrip("\n") + "\n"
    return text.replace("simplex::statelens", f"{module}::statelens")


def variant_text(relative, lines, runtime):
    """A target's source with a reset before its body and a clear after it (Appendix B.1).

    `runtime` is the path the fuzz package calls the runtime module by. Returns the new
    lines and the anchors used, as (anchor, 1-based line).
    """
    starts = [index for index, line in enumerate(lines) if VARIANT_START.match(line)]
    if not starts:
        one_line = [index for index, line in enumerate(lines) if VARIANT_ONE_LINE.match(line)]
        if len(one_line) == 1:
            # Rewritten as a block: the body becomes a statement, which is what the
            # closure returns anyway, since a target that returns `Corpus` says so.
            indent, params, expression = VARIANT_ONE_LINE.match(lines[one_line[0]]).groups()
            block = [
                f"{indent}fuzz_target!(|{params}| {{",
                f"{indent}    {expression};",
                f"{indent}}});",
            ]
            lines = lines[: one_line[0]] + block + lines[one_line[0] + 1 :]
            starts = one_line
    if len(starts) != 1:
        raise Abort(
            2,
            f"materialize: expected one `fuzz_target!` block in {relative}, found "
            f"{len(starts)}; update the variant patterns in scripts/statelens.py",
        )
    start = starts[0]
    indent = VARIANT_START.match(lines[start]).group(1)
    closing = f"{indent}}});"
    end = next((index for index in range(start + 1, len(lines)) if lines[index] == closing), None)
    if end is None:
        raise Abort(
            2,
            f"materialize: the `fuzz_target!` block of {relative} has no closing "
            f"{closing!r} line; update the variant patterns in scripts/statelens.py",
        )
    inner = indent + "    "
    lines = insert_lines(
        lines,
        [
            (start + 1, f"{inner}{runtime}::reset();"),
            (end, f"{inner}{runtime}::clear_compromised();"),
        ],
    )
    return lines, [(VARIANT_START.pattern, start + 1), (closing, end + 1)]


def find_anchor(relative, lines, anchor):
    """Index of the only line equal to `anchor`, or matching it when it is a pattern."""
    if isinstance(anchor, str):
        found = [index for index, line in enumerate(lines) if line == anchor]
        shown = repr(anchor)
    else:
        found = [index for index, line in enumerate(lines) if anchor.match(line)]
        shown = f"matching {anchor.pattern!r}"
    if len(found) != 1:
        raise Abort(
            2,
            f"materialize: expected one line {shown} in {relative}, found {len(found)}; "
            "update the anchors in scripts/statelens.py",
        )
    return found[0]


def insert_lines(lines, insertions):
    """Applies (index, text) insertions from the bottom up, so no index moves.

    Insertions at the same index end up in the order given.
    """
    lines = list(lines)
    order = sorted(enumerate(insertions), key=lambda item: (item[1][0], item[0]), reverse=True)
    for _, (at, text) in order:
        lines[at:at] = text.split("\n")
    return lines


def bin_blocks(text):
    """The [[bin]] tables of a manifest, as lists of their lines."""
    blocks = []
    current = None
    for line in text.split("\n"):
        if line.strip().startswith("["):
            current = [] if line.strip() == "[[bin]]" else None
            if current is not None:
                blocks.append(current)
        elif current is not None:
            current.append(line)
    return blocks


def bin_entries(block):
    """Maps each key of a [[bin]] block to (unquoted value, line), first occurrence only."""
    entries = {}
    for line in block:
        key, sep, value = line.partition("=")
        if sep and key.strip() not in entries:
            entries[key.strip()] = (value.strip().strip('"'), line)
    return entries


def variant_bin_block(blocks, stem, manifest=None, name=None):
    """The [[bin]] block of a StateLens variant (SPEC section 8.3, edit M2).

    `name` renames it to another target than the variant, `<stem>_statelens`: a
    scaffold's block is its base's, renamed the same way (Appendix B.2).
    """
    owners = []
    for block in blocks:
        entries = bin_entries(block)
        owner = entries.get("name", ("", ""))[0]
        path = entries.get("path", ("", ""))[0]
        if owner == stem or path == f"fuzz_targets/{stem}.rs":
            owners.append(entries)
    if len(owners) != 1:
        raise Abort(
            2,
            f"materialize: expected one [[bin]] block for {stem} in {manifest}, "
            f"found {len(owners)}",
        )
    variant = name or f"{stem}_statelens"
    lines = ["", "[[bin]]", f'name = "{variant}"', f'path = "fuzz_targets/{variant}.rs"']
    for key in BIN_KEYS:
        if key in owners[0]:
            line = owners[0][key][1]
            if line.count("[") > line.count("]"):
                raise Abort(
                    2,
                    f"materialize: the {key} value of {stem} in {manifest} spans "
                    "several lines, which the variant block cannot copy",
                )
            lines.append(line)
    return "\n".join(lines) + "\n"


def materialize_edits(repo, sl_dir, profile):
    """Computes the materialize step of `profile` without writing (SPEC sections 7.2, 8.3).

    Runs the profile's cryptography check and finds every anchor first. Returns the files
    to create and the new content of the files to modify (text by path relative to the
    repository root), the StateLens targets, and every anchor as (file, anchor, line).
    """
    texts = {}
    create = {}
    appends = {}
    insertions = collections.defaultdict(list)
    anchors = []

    def lines_of(relative):
        if relative not in texts:
            texts[relative] = read_edit_file(repo, relative).split("\n")
        return texts[relative]

    def locate(relative, anchor, position):
        index = find_anchor(relative, lines_of(relative), anchor)
        anchors.append((relative, anchor if isinstance(anchor, str) else anchor.pattern, index + 1))
        return index + 1 if position == "after" else index

    settings = PROFILES[profile]
    stems = profile_sources(repo, profile)
    if not stems:
        raise Abort(2, f"materialize: no {profile}_ fuzz targets in {profile_fuzz_dir(profile)}")
    if profile == "marshal":
        check_marshal_cert_mock(repo, stems)
    elif profile == "simplex":
        check_simplex_cert_mock(repo, stems)

    for relative, anchor, position, text in settings["anchors"]:
        insertions[relative].append((locate(relative, anchor, position), text))
    create[settings["runtime"]] = runtime_text(repo, profile)
    # Every profile derives a variant the same way: the target's own source with
    # a reset before its body and a clear after it, plus a `[[bin]]` block taken
    # from the original's. There is no hand-written target to keep in step.
    runtime = f"commonware_{settings['crate']}::{settings['module']}::statelens"
    directory = profile_fuzz_dir(profile)
    manifest_path = profile_manifest(profile)
    blocks = bin_blocks(read_edit_file(repo, manifest_path))
    manifest = []
    for stem in stems:
        relative = f"{directory}/{stem}.rs"
        lines, found = variant_text(relative, lines_of(relative), runtime)
        anchors += [(relative, anchor, line) for anchor, line in found]
        create[f"{directory}/{stem}_statelens.rs"] = "\n".join(lines)
        manifest.append(variant_bin_block(blocks, stem, manifest_path))
    appends[manifest_path] = "".join(manifest)

    modify = {
        relative: "\n".join(insert_lines(lines_of(relative), items))
        for relative, items in insertions.items()
    }
    for relative, text in appends.items():
        base = modify[relative] if relative in modify else read_edit_file(repo, relative)
        modify[relative] = (base if base.endswith("\n") else base + "\n") + text
    return Materialization(create, modify, profile_targets(repo, profile), anchors)


class Campaign:
    """Phase 2 (SPEC sections 7 and 8), run in place in the checkout."""

    # What the plan's claims were validated against: a digest of every subsystem
    # source and of the plan, taken at the first plan lint, after the audit (SPEC
    # section 7.6). And the paths a repair changed after that, which make the audit
    # stale. Class defaults, because `finish` reads them whichever step aborted.
    audit_content = None
    stale = None
    # Whether `kb search` has an index to answer from (SPEC section 5.10).
    search = False
    # Bindings a later audit batch's edits escaped: id -> (batch, files).
    unreviewed = None
    # The `--invariants` lists, when the operator chose what to bind.
    selection = None

    def __init__(self, args):
        self.repo = repo_root()
        self.sl_dir = self.repo / SL
        self.config = load_config(self.sl_dir)
        # The CLI itself is checked with the preconditions, so a missing one is reported
        # in the summary.
        self.agent = agent_name(self.config, args.agent)
        self.profile_name = args.profile
        self.profile = PROFILES[args.profile]
        self.selection = args.invariants
        self.stop_after = args.stop_after
        self.test_toolchain = self.config["STATELENS_TEST_TOOLCHAIN"]
        self.fuzz_toolchain = self.config["STATELENS_FUZZ_TOOLCHAIN"] or pinned_nightly(self.repo)
        self.dir = self.sl_dir / "campaign"
        # Set once this run has created its own campaign directory.
        self.initialized = False
        self.base = None
        # (registry, path) pairs, in binding order.
        self.invariants = []
        self.targets = []
        self.baseline = {}
        self.statuses = None
        self.sites = None
        # The status changes the audit pass made, once it has run.
        self.audited = None
        # (commit sites listed, not checked) and the plan lint's problem count.
        self.coverage = None
        self.plan_problems = None
        # Invariants whose Status says the fuzz targets never evaluate them.
        self.inactive = None
        # The component tests that failed after the gate passed; they are not gated.
        self.components = None
        self.reason = None
        self.panic = None

    # Commands.

    def check_command(self):
        return cargo(self.test_toolchain) + [
            "check",
            "-p",
            f"commonware-{self.profile['crate']}",
            "--lib",
            "--tests",
        ]

    def fuzz_build_commands(self):
        """One `cargo fuzz build` per StateLens target, as (target, command)."""
        return [
            (
                target,
                cargo(self.fuzz_toolchain)
                + ["fuzz", "build", "--fuzz-dir", self.profile["package"], target],
            )
            for target in self.targets
        ]

    def test_command(self):
        return gate_test_command(self.test_toolchain, self.profile_name)

    def common_values(self):
        return {
            "BASE": self.base,
            "PLAN": PLAN,
            "CHECK": shlex.join(self.check_command()),
            "RUNTIME": self.profile["runtime"],
            "RUNTIME_MODULE": f"crate::{self.profile['module']}::statelens",
            "FUZZ_PACKAGE": self.profile["package"],
        }

    # Driver.

    def run(self):
        steps = (
            ("materialize", self.materialize),
            ("index", self.code_index),
            ("instrument", self.instrument),
            ("build", self.build),
            ("test", self.test_gate),
        )
        try:
            self.check_preconditions()
            self.setup()
            for name, step in steps:
                step()
                if self.stop_after == name:
                    return self.finish(0, f"STOPPED after {name}")
            return self.finish(0, "READY")
        except Abort as error:
            self.reason = str(error)
            result = {
                2: "SETUP FAILED",
                3: "BUILD FAILED",
                4: "PANIC (tests)",
            }.get(error.code, "SETUP FAILED")
            return self.finish(error.code, result)
        except OSError as error:
            self.reason = f"could not start a command: {error}"
            return self.finish(2, "SETUP FAILED")

    def finish(self, code, result):
        rows = [("checkout", self.repo)]
        if self.base:
            rows.append(("base", self.base))
        rows.append(("agent", self.agent))
        rows.append(("profile", self.profile_name))
        if self.statuses is not None:
            counts = collections.Counter(self.statuses.values())
            rows.append(
                (
                    "invariants",
                    f"{len(self.statuses)} (bound {counts['bound']}, "
                    f"partial {counts['partial']}, unbound {counts['unbound']})"
                    + inactive_note(self.inactive),
                )
            )
        if self.audited is not None:
            audit = ", ".join(self.audited) if self.audited else "no status change"
            if self.stale:
                audit += " [stale: a repair changed the tree after it]"
            rows.append(("audit", audit))
        problems = self.plan_problems or 0
        if self.coverage is not None:
            listed, unchecked = self.coverage
            rows.append(
                (
                    "plan",
                    f"{listed} commit site(s) listed, {unchecked} not checked, "
                    f"{problems} lint problem(s)",
                )
            )
        # The counts above are the plan's claims. A lint problem means the code does
        # not support them, and a repair after the audit means the audit speaks for a
        # tree that is gone, so a reader must not take READY for the coverage they
        # describe. A clean lint does not clear the second: it cannot see a condition
        # rewritten under the same id, site and function.
        unvalidated = []
        if problems:
            unvalidated.append(
                f"{problems} plan lint problem(s), so the code does not support the counts above"
            )
        if self.stale:
            unvalidated.append(
                f"a repair changed {len(self.stale)} validated file(s) after the audit "
                f"({', '.join(self.stale)}), so the audit and the statuses describe the "
                "tree before it; run a campaign with a new audit before relying on them"
            )
        if self.statuses and self.audited is None:
            unvalidated.append(
                "no audit pass ran (STATELENS_AUDIT=0), so the statuses are the binding "
                "agent's own claims"
            )
        if self.unreviewed:
            unvalidated.append(unreviewed_note(self.unreviewed))
        if unvalidated:
            rows.append(("coverage", "UNVALIDATED: " + "; ".join(unvalidated)))
        if self.sites is not None:
            assertions, probes, deleted = self.sites
            rows.append(
                (
                    "sites",
                    f"{assertions} assertion sites, {probes} probe sites, {deleted} deleted lines",
                )
            )
        if self.components is not None:
            rows.append(
                (
                    "components",
                    f"{len(self.components)} failed, not gated: {', '.join(self.components)}"
                    "; see campaign/logs/test-components.log"
                    if self.components
                    else "all passed",
                )
            )
        rows.append(("result", result))
        if self.reason:
            rows.append(("reason", self.reason))
        if self.panic:
            rows.append(("panic", self.panic))
        if result == "READY":
            rows += self.handover()
        text = "\n".join(f"statelens: {key:<10} {value}" for key, value in rows)
        print(text, flush=True)
        # A run refused by the preconditions must not overwrite the summary of the
        # campaign that instrumented this checkout.
        if self.initialized:
            (self.dir / "summary.txt").write_text(text + "\n")
        return code

    def handover(self):
        """The `run` and `replay` lines of every StateLens target (SPEC sections 7.9, 8.3).

        Both go through this subproject's `just run`, which finds the target's package, and
        the crash file is absolute, because that recipe runs cargo-fuzz elsewhere.
        """
        here = f"cd {self.repo / SL} && "
        nightly = f"NIGHTLY_VERSION={self.fuzz_toolchain}"
        replay_env = " ".join(filter(None, (self.profile["replay_env"], nightly)))
        artifacts = self.repo / self.profile["package"] / "artifacts"
        rows = []
        for target in self.targets:
            rows.append(
                (
                    "run",
                    f"{here}{nightly} just run {target} -- "
                    "-rss_limit_mb=4000 -print_final_stats=1",
                )
            )
            rows.append(
                (
                    "replay",
                    f"{here}{replay_env} just run {target} {artifacts}/{target}/<crash file>",
                )
            )
        return rows

    # Section 7.1.

    def check_preconditions(self):
        # Checked first, so a missing tool fails before any agent time is spent.
        check_agent_cli(self.agent)
        for tool in CAMPAIGN_TOOLS:
            if shutil.which(tool) is None:
                raise Abort(2, f"{tool} is not on PATH; see the prerequisites in README.md")
        variants = [
            path
            for name in PROFILES
            for path in sorted((self.repo / profile_fuzz_dir(name)).glob("*_statelens.rs"))
        ]
        created = list(CREATED_PATHS)
        # The thin targets of scaffolds match the glob as well (SPEC section 7.1).
        created += [str(path.relative_to(self.repo)) for path in variants]
        created += scaffold_dirs()
        for path in created:
            if (self.repo / path).exists():
                raise Abort(
                    2,
                    f"{path} exists: an earlier campaign or synthesis instrumented this "
                    "checkout; use a fresh clone",
                )
        status = git(self.repo, "status", "--porcelain", "--untracked-files=no", "-z")
        for path in porcelain_paths(status):
            if not path.startswith(f"{SL}/"):
                raise Abort(
                    2,
                    f"{path} has uncommitted changes; run campaigns in a fresh clone "
                    "(only statelens/ may differ from HEAD)",
                )

    def setup(self):
        self.base = git(self.repo, "rev-parse", "HEAD").strip()
        if self.dir.exists():
            shutil.rmtree(self.dir)
        (self.dir / "logs").mkdir(parents=True)
        (self.dir / "prompts").mkdir()
        self.initialized = True
        with_false = os.environ.get("STATELENS_FALSE_INVARIANTS") == "1"
        self.invariants = []
        checked = []
        tops = ("invariants", LOCAL_INVARIANTS) + (("false-invariants",) if with_false else ())
        for registry in self.profile["registries"]:
            bound = registry_invariants(self.sl_dir, registry, with_false)
            self.invariants += [(registry, path) for path in bound]
            # Every *.md is linted, so lint rule 1 reports a misnamed file.
            for top in tops:
                checked += sorted((self.sl_dir / top / registry).glob("*.md"), key=by_id)
        available = len(self.invariants)
        if self.selection:
            self.invariants = select_invariants(
                self.profile_name, self.profile["registries"], self.invariants, self.selection
            )
        paths = [path for _, path in self.invariants]
        if lint_paths(checked, registry_files(self.sl_dir)):
            say("warning: some invariant files have format problems (see above)")
        # SPEC section 7.4: the knowledge base, when one is configured. A campaign runs
        # without it and the beacon step then mines the code alone.
        self.kb = []
        try:
            self.kb = kb_roots(self.repo, self.config)
        except Abort as error:
            say(f"warning: no knowledge base for the beacon step ({error})")
        if self.kb:
            entries, _ = kb_index(self.sl_dir, self.kb)
            findings = sum(1 for entry in entries if entry["kind"] == "finding")
            say(f"campaign: knowledge base indexed, {findings} finding(s)")
        # SPEC section 5.10: the search index, refreshed before anything is instrumented.
        # It reads the code at HEAD, so it never sees instrumentation either way.
        try:
            search_build(self.repo, self.sl_dir, self.config)
        except (Abort, OSError, subprocess.CalledProcessError) as error:
            say(f"warning: search index not refreshed: {error}")
        self.search = search_ready(self.sl_dir)
        self.targets = profile_targets(self.repo, self.profile_name)
        ids = [path.stem for path in paths]
        meta = {
            "base": self.base,
            "agent": self.agent,
            "model": agent_model(self.config, self.agent),
            "effort": agent_effort(self.config, self.agent),
            "profile": self.profile_name,
            "test_toolchain": self.test_toolchain,
            "fuzz_toolchain": self.fuzz_toolchain,
            "started": utc_now().isoformat(timespec="seconds"),
            "invariants": ids,
            "invariants_available": available,
            "targets": self.targets,
        }
        (self.dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
        groups = []
        for registry in self.profile["registries"]:
            names = [path.stem for owner, path in self.invariants if owner == registry]
            groups.append(f"{registry}: {', '.join(names) if names else 'none'}")
        (self.dir / "plan.md").write_text(
            PLAN_TEMPLATE.format(
                base=self.base,
                agent=self.agent,
                profile=self.profile_name,
                count=len(ids),
                ids="; ".join(groups),
            )
        )
        if self.selection:
            counted = f"{len(ids)} of {available} invariant(s) bound ({'; '.join(groups)})"
        else:
            counted = f"{len(ids)} invariant(s)"
        say(
            f"campaign: profile {self.profile_name}, {counted}, "
            f"{len(self.targets)} target(s) at {self.base[:10]} with {self.agent}"
        )

    # Section 7.2 and section 8.3, edits M1 to M3.

    def code_index(self):
        """Index the crate before it is instrumented (SPEC section 5.7).

        The index is built here rather than during instrumentation so that its
        cost falls once on the campaign instead of on every query. The agent
        then edits the files it queries, which moves the lines the index names,
        so the build also snapshots the indexed sources and each query rebases
        its hits through a diff. A missing index degrades the sweep to search
        and reading rather than failing it.

        A failed build leaves no index at all. One an earlier build left may
        describe another crate, after a campaign of another profile, and the
        agents' queries would answer from it as though it were this campaign's.
        """
        if not index_build(self.repo, self.sl_dir, self.profile_name):
            index_path(self.sl_dir).unlink(missing_ok=True)
            snapshot_path(self.sl_dir).unlink(missing_ok=True)
            say("continuing without a code index; the agent falls back to search")

    def materialize(self):
        edits = materialize_edits(self.repo, self.sl_dir, self.profile_name)
        for relative, text in list(edits.create.items()) + list(edits.modify.items()):
            (self.repo / relative).write_text(text)
        git(self.repo, "add", "--intent-to-add", "--", *edits.create)
        self.baseline = self.snapshot()
        hooks = {
            "simplex": ["Twins runner hook"],
            "marshal": ["Twins runner hook", "wedge-scenario hook"],
        }.get(self.profile_name, [])
        parts = ["runtime module", f"{len(edits.targets)} StateLens variant(s)"] + hooks
        say(f"materialize: {', '.join(parts)} and fresh-run hook are in place")

    def snapshot(self):
        """Hashes every path that `git status` reports (SPEC section 7.2).

        The same view Phase 1 watches, so both phases judge scope alike.
        """
        return worktree_state(self.repo)

    # Sections 7.3 to 7.5.

    def agent_step(self, name, prompt):
        (self.dir / "prompts" / f"{name}.md").write_text(prompt)
        log = self.dir / "logs" / f"{name}.log"
        say(f"{name}: running {self.agent}; log {log.relative_to(self.repo)}")
        command = agent_command(self.config, self.agent, 2, self.repo)
        code, _ = run_logged(command, log, self.repo, stdin_text=prompt)
        if code != 0:
            raise Abort(
                2, f"{name}: the agent exited with code {code}; see {log.relative_to(self.repo)}"
            )

    def batch_prompts(self, task, stem):
        """(step name, prompt) of every invariant batch, registry by registry (SPEC 7.3)."""
        prompts = []
        for registry in self.profile["registries"]:
            paths = [path for owner, path in self.invariants if owner == registry]
            for number, start in enumerate(range(0, len(paths), BATCH_SIZE), 1):
                batch = paths[start : start + BATCH_SIZE]
                body = "\n\n".join(
                    f"===== {path.relative_to(self.repo)} =====\n{path.read_text().rstrip()}"
                    for path in batch
                )
                values = dict(
                    self.common_values(),
                    INVARIANT_IDS=", ".join(path.stem for path in batch),
                    INVARIANTS=body,
                    REGISTRY=registry,
                    SUBSYSTEM_RULES=subsystem_prompt(self.sl_dir, registry, "instrument"),
                )
                prompt = compose(self.sl_dir, "instrument.md", task, values)
                prompts.append((f"{stem}-{registry}-{number}", prompt))
        return prompts

    def invariant_prompts(self):
        return self.batch_prompts("instrument-invariants.md", "invariants")

    def audit_prompts(self):
        return self.batch_prompts("instrument-audit.md", "audit")

    def beacon_prompts(self):
        """(step name, prompt) of every beacon component of the profile (SPEC 7.4)."""
        prompts = []
        for actor, actor_dir, subsystem in self.profile["components"]:
            values = dict(
                self.common_values(),
                ACTOR=actor,
                ACTOR_DIR=actor_dir,
                QUERY=kb_query_help(subsystem, kb=bool(self.kb), search=self.search),
                SUBSYSTEM_RULES=subsystem_prompt(self.sl_dir, subsystem, "instrument"),
            )
            prompt = compose(self.sl_dir, "instrument.md", "instrument-beacons.md", values)
            prompts.append((f"beacons-{actor}", prompt))
        return prompts

    def instrument(self):
        if not self.invariants:
            say("warning: no invariants to bind; adding beacon probes only")
        for name, prompt in self.invariant_prompts():
            self.agent_step(name, prompt)
        for name, prompt in self.beacon_prompts():
            self.agent_step(name, prompt)
        # The audit is the last agent pass, so the tree it speaks for is the tree the
        # plan lint fingerprints and the build hands over (SPEC section 7.3, step 6).
        self.audit()
        self.complete_plan()
        self.check_plan()
        self.check_scope()
        self.record()

    def audit(self):
        """Re-reviews the bindings after the beacon step (SPEC section 7.3, steps 6 and 7).

        The first pass writes a binding and its own status; nothing there compares the
        two. This pass does, against the Statement and the sites that commit the actions
        it names, which is where a binding is silently incomplete rather than wrong. It
        runs last, after the beacon agents, so no agent edits the tree between the audit
        and the fingerprint the plan lint takes of it.
        """
        if not self.invariants:
            return
        if self.config["STATELENS_AUDIT"] == "0":
            say("audit: skipped (STATELENS_AUDIT=0)")
            return
        plan = self.dir / "plan.md"
        before = self.parse_statuses(plan.read_text())
        batches = []
        for name, prompt in self.audit_prompts():
            self.agent_step(name, prompt)
            # The tree each batch's verdict stands for, to tell a later batch's
            # additions from its edits to what an earlier batch reviewed.
            batches.append((name, prompt_invariants(prompt), subsystem_texts(self.repo)))
        self.unreviewed = audit_drift(batches)
        if self.unreviewed:
            say(
                f"audit: {len(self.unreviewed)} binding(s) were reviewed before a later "
                f"batch changed existing lines: {', '.join(sorted(self.unreviewed))}"
            )
        after = self.parse_statuses(plan.read_text())
        self.audited = [
            f"{key} {before.get(key) or 'none'} -> {after.get(key) or 'none'}"
            for key in sorted(set(before) | set(after))
            if before.get(key) != after.get(key)
        ]
        say(
            f"audit: {len(self.audited)} status change(s)"
            + (f": {', '.join(self.audited)}" if self.audited else "")
        )

    def check_plan(self):
        """Warns when the plan's claims do not match its own sections (SPEC section 7.5)."""
        plan = self.dir / "plan.md"
        expected = [path.stem for _, path in self.invariants]
        problems = lint_plan_file(plan, expected, subsystem_assertions(self.repo))
        for problem in problems:
            say(f"warning: plan.md: {problem}")
        self.plan_problems = len(problems)
        # Set here, not only in `record`, so an abort in between still reports it.
        self.coverage = self.commit_sites(plan.read_text())
        if self.audit_content is None:
            self.audit_content = self.validated_content()

    def validated_content(self):
        """A digest of everything the audit and the plan lint speak for.

        Every file of the subsystem sources the lint scans, helpers and ghost state
        included and not only the macro calls, and the plan without the summary the
        script appends. A repair that changes any of it leaves the audit describing
        a tree that no longer exists, which the lint cannot see when the change
        keeps the invariant's id, site and function and alters the condition.
        """
        content = {}
        for name in SUBSYSTEMS:
            for path in sorted((self.repo / SOURCES[name]).rglob("*")):
                if path.is_file():
                    content[path.relative_to(self.repo).as_posix()] = sha256(path)
        plan = self.dir / "plan.md"
        if plan.is_file():
            # Stripped the way `record` strips it before appending a new summary.
            text = re.sub(r"\n## Summary\n.*\Z", "\n", plan.read_text(), flags=re.S)
            content["plan.md"] = hashlib.sha256(text.rstrip("\n").encode()).hexdigest()
        return content

    def changed_since_validation(self):
        """The paths of `validated_content` that differ from the validated digest."""
        if self.audit_content is None:
            return []
        current = self.validated_content()
        return sorted(
            path
            for path in set(self.audit_content) | set(current)
            if self.audit_content.get(path) != current.get(path)
        )

    @staticmethod
    def inactive_invariants(text):
        """The invariants whose Status says the fuzz targets never evaluate the check.

        A binding can be complete and still silent in the campaign, when its `pre` needs
        what the `cert_mock` scheme or the targets never provide; the Status carries
        `(inactive in the fuzz targets)` for that (SPEC section 11), and it is reported
        apart from the statuses, which describe the binding and not its activation.
        """
        sections, _repeated = plan_sections(text)
        return sorted(
            name
            for name, fields in sections.items()
            if PLAN_INACTIVE.search(fields.get("Status", ""))
        )

    @staticmethod
    def commit_sites(text):
        """(listed, not checked) over every `Sites` ledger of the plan (SPEC section 11)."""
        listed = unchecked = 0
        sections, _repeated = plan_sections(text)
        for fields in sections.values():
            for entry, _paths, _functions in plan_site_entries(fields.get("Sites", "")):
                listed += 1
                unchecked += 1 if PLAN_UNCHECKED.search(entry) else 0
        return listed, unchecked

    def assertion_files(self):
        """Assertion sites per instrumented source, most first.

        The distribution is the statistic that shows a whole layer going unchecked: the
        campaign that prompted the audit pass put all of its invariant assertions in the
        state machines and none in the actors that commit their decisions.
        """
        counts = [
            (len(sites), re.sub(r"^[a-z_]+/src/", "", source))
            for source, sites in subsystem_assertions(self.repo).items()
            if sites
        ]
        counts.sort(key=lambda item: (-item[0], item[1]))
        return ", ".join(f"{source} {count}" for count, source in counts) or "none"

    def complete_plan(self):
        """Adds an unbound entry for every invariant the agents left out of the plan."""
        plan = self.dir / "plan.md"
        text = plan.read_text()
        statuses = self.parse_statuses(text)
        missing = [path for _, path in self.invariants if path.stem not in statuses]
        if not missing:
            return
        entries = "".join(
            f"### {path.stem}: {title_of(path)}\n- Status: unbound\n"
            "- Notes: not processed by the agent\n\n"
            for path in missing
        )
        marker = "## Beacon probes"
        if marker in text:
            text = text.replace(marker, entries + marker, 1)
        else:
            text = text.rstrip("\n") + "\n\n## Invariants\n\n" + entries
        plan.write_text(text)
        say(f"plan: {len(missing)} invariant(s) not processed by the agent are marked unbound")

    @staticmethod
    def parse_statuses(text):
        statuses = {}
        current = None
        fenced = False
        for line in text.splitlines():
            if line.lstrip().startswith(("```", "~~~")):
                fenced = not fenced
                continue
            if fenced:
                continue
            heading = PLAN_HEADING.match(line)
            if heading:
                current = heading.group(1)
                statuses.setdefault(current, None)
                continue
            if line.startswith("#"):
                current = None
                continue
            status = PLAN_STATUS.match(line)
            if status and current and statuses.get(current) is None:
                statuses[current] = status.group(1)
        return statuses

    def check_scope(self):
        """Every change since materialize must be under an editable root, and none may
        call the read side of the runtime module (SPEC 7.5)."""
        current = self.snapshot()
        changed = sorted(
            path
            for path in set(self.baseline) | set(current)
            if self.baseline.get(path) != current.get(path)
        )
        for path in changed:
            if path == "Cargo.lock":
                continue
            if not path.startswith(self.profile["roots"]):
                raise Abort(2, f"instrumentation edited {path}")
            if path.startswith(self.profile["warn"]):
                say(f"warning: instrumentation edited {path}")
            added = self.read_side_calls(path)
            if added:
                raise Abort(
                    2, f"instrumentation calls the read side: {path} ({', '.join(added)})"
                )

    def read_side_calls(self, path):
        """The read-side functions `path` reaches more often than at the base commit.

        Materialize adds no such call under the editable roots, so the base commit's
        content is the baseline's; the runtime module itself defines them.
        """
        target = self.repo / path
        if path == self.profile["runtime"] or not path.endswith(".rs") or not target.is_file():
            return []
        before = git_file(self.repo, self.base, path)
        added = runtime_calls(target.read_text(errors="replace"), READ_SIDE) - runtime_calls(
            "\n".join(before or []), READ_SIDE
        )
        return sorted(added)

    def record(self):
        """Updates the plan summary and writes instrumentation.diff."""
        plan = self.dir / "plan.md"
        text = plan.read_text()
        parsed = self.parse_statuses(text)
        statuses = {path.stem: parsed.get(path.stem) or "unbound" for _, path in self.invariants}
        self.statuses = statuses
        roots = list(self.profile["roots"])
        # Files the agents created are untracked: mark them intent-to-add (no content is
        # staged) so the diff and the site counts below include them.
        created = git(self.repo, "ls-files", "--others", "--exclude-standard", "-z", "--", *roots)
        created = [path for path in created.split("\0") if path]
        if created:
            git(self.repo, "add", "--intent-to-add", "--", *created)
        diff = git(self.repo, "diff", "--", *roots, f":(exclude){self.profile['runtime']}")
        added = [
            line
            for line in diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        assertions = sum(len(re.findall(r"\bsl_(?:assert|implies)!", line)) for line in added)
        probes = sum(len(re.findall(r"\bsl_probe!", line)) for line in added)
        deleted = 0
        for line in git(self.repo, "diff", "--numstat", "--", *roots).splitlines():
            parts = line.split("\t")
            if len(parts) == 3 and parts[1].isdigit():
                deleted += int(parts[1])
        self.sites = (assertions, probes, deleted)
        beacon_rows = 0
        if "## Beacon probes" in text:
            section = text.split("## Beacon probes", 1)[1].split("\n## ", 1)[0]
            rows = [line for line in section.splitlines() if line.startswith("|")]
            beacon_rows = max(len(rows) - 2, 0)
        listed, unchecked = self.commit_sites(text)
        self.inactive = self.inactive_invariants(text)
        counts = collections.Counter(statuses.values())
        summary = (
            "## Summary\n\n"
            f"- Invariants: {len(statuses)} (bound {counts['bound']}, partial "
            f"{counts['partial']}, unbound {counts['unbound']}){inactive_note(self.inactive)}\n"
            f"- Commit sites: {listed} listed, {unchecked} not checked\n"
            f"- Assertion call sites: {assertions}\n"
            f"- Assertion sites by file: {self.assertion_files()}\n"
            f"- Probe call sites: {probes}\n"
            f"- Beacon table rows: {beacon_rows}\n"
            f"- Deleted lines under {', '.join(roots)}: {deleted}"
            + (" (must match the 'Edited lines' entries)" if deleted else "")
            + "\n"
            + (
                f"- Audit: stale; a repair changed {len(self.stale)} validated file(s) "
                f"after it: {', '.join(self.stale)}\n"
                if self.stale
                else ""
            )
            + (f"- Audit: {unreviewed_note(self.unreviewed)}\n" if self.unreviewed else "")
        )
        self.coverage = (listed, unchecked)
        text = re.sub(r"\n## Summary\n.*\Z", "\n", text, flags=re.S).rstrip("\n")
        plan.write_text(text + "\n\n" + summary)
        (self.dir / "instrumentation.diff").write_text(git(self.repo, "diff"))
        say(
            f"plan: {counts['bound']} bound, {counts['partial']} partial, "
            f"{counts['unbound']} unbound; {assertions} assertion and {probes} probe sites; "
            f"{deleted} deleted lines"
        )

    # Section 7.6.

    def repair_prompt(self, attempt, command, tail):
        rules = "\n\n".join(
            subsystem_prompt(self.sl_dir, registry, "instrument")
            for registry in self.profile["registries"]
        )
        values = dict(
            self.common_values(),
            ATTEMPT=str(attempt),
            COMMAND=command,
            ERRORS="\n".join("    " + line for line in tail),
            SUBSYSTEM_RULES=rules,
        )
        return compose(self.sl_dir, "instrument.md", "repair.md", values)

    def build(self):
        for attempt in range(REPAIR_ATTEMPTS + 1):
            failure = self.build_once(attempt)
            if failure is None:
                if attempt:
                    # A repair may have removed or changed an assertion. The plan is
                    # linted again against the tree as repaired, and whatever the lint
                    # finds, the audit now describes a tree that is gone: it is marked
                    # stale for every file the repairs changed, because a condition
                    # rewritten under the same id, site and function passes the lint.
                    self.stale = self.changed_since_validation()
                    if self.stale:
                        say(
                            f"build: the repairs changed {len(self.stale)} validated "
                            f"file(s) ({', '.join(self.stale)}); the audit is stale"
                        )
                    self.check_plan()
                    self.record()
                say("build: the instrumented tree builds")
                return
            if attempt == REPAIR_ATTEMPTS:
                raise Abort(3, f"the build still fails after {REPAIR_ATTEMPTS} repair attempts")
            command, tail = failure
            self.agent_step(f"repair-{attempt + 1}", self.repair_prompt(attempt + 1, command, tail))
            self.check_scope()
            # Kept current after every repair, so a build that never succeeds still
            # reports the audit stale in the summary it leaves behind.
            self.stale = self.changed_since_validation()

    def build_once(self, attempt):
        """Runs CHECK, then FUZZBUILD target by target; returns the first failure."""
        commands = [("check", self.check_command())]
        for target, command in self.fuzz_build_commands():
            name = "fuzz-build" if len(self.targets) == 1 else f"fuzz-build-{target}"
            commands.append((name, command))
        for name, command in commands:
            log = self.dir / "logs" / f"{name}-{attempt}.log"
            say(f"build: {shlex.join(command)}")
            code, tail = run_logged(command, log, self.repo)
            if code != 0:
                return shlex.join(command), tail
        return None

    # Section 7.7.

    def test_gate(self):
        log = self.dir / "logs" / "test.log"
        say(
            f"test: the gated tests of {', '.join(self.profile['registries'])} and the "
            "StateLens self-tests"
        )
        code, _ = run_logged(self.test_command(), log, self.repo)
        if code == 0:
            say("test: the test gate passed")
            self.components = self.component_tests()
            return
        lines = log.read_text(errors="replace").splitlines()
        for line in lines:
            if re.match(r"^\s+FAIL \[", line):
                say(line.strip())
            elif "[statelens][" in line:
                say(line.strip())
        self.panic = first_panic(lines)
        raise Abort(4, f"the test gate failed; see {log.relative_to(self.repo)}")

    def component_tests(self):
        """Runs the component tests the gate leaves out; returns the failed ones, or None
        when the profile gates all of its tests.

        They drive one actor with states built by hand, where evidence another actor
        produces is absent, so a failure is a mismatch to judge rather than a verdict,
        and it never fails the campaign. Hiding them would hide more than that: an
        instrumented tree that no longer passes the crate's own suite.
        """
        command = component_test_command(self.test_toolchain, self.profile_name)
        if command is None:
            return None
        log = self.dir / "logs" / "test-components.log"
        say("test: component tests of simplex, reported but not gated")
        code, _ = run_logged(command, log, self.repo)
        if code == 0:
            say("test: the component tests passed")
            return []
        failed = failed_tests(log.read_text(errors="replace").splitlines())
        if not failed:
            failed = [f"(no FAIL line; see {log.relative_to(self.repo)})"]
        for name in failed:
            say(f"test: component test failed, not gated: {name}")
        return failed


def inactive_note(inactive):
    return f"; inactive in the fuzz targets: {', '.join(inactive)}" if inactive else ""


def prompt_invariants(prompt):
    """The invariant ids a binding or audit prompt is about, from its task line."""
    match = re.search(r"^## Task: .*?invariants (.+)$", prompt, re.M)
    text = match.group(1) if match else prompt
    return sorted(set(re.findall(r"\b(?:INV|FALSE)-\d+\b", text)))


def subsystem_texts(repo):
    """The text of every subsystem source, by repo-relative path."""
    texts = {}
    for name in SUBSYSTEMS:
        for path in sorted((repo / SOURCES[name]).rglob("*")):
            if path.is_file():
                texts[path.relative_to(repo).as_posix()] = path.read_text(errors="replace")
    return texts


def insertions(old, new):
    """The lines `new` adds to `old`, as (index in old, lines), or None when `new`
    changes or removes a line of `old`.

    A two-pointer walk rather than a diff: a diff can pair an old block with a
    later copy of it and call the lines between removed, though every old line
    survives in order.
    """
    old_lines, new_lines = old.split("\n"), new.split("\n")
    added, block, index = [], [], 0
    for line in new_lines:
        if index < len(old_lines) and line == old_lines[index]:
            if block:
                added.append((index, block))
                block = []
            index += 1
        else:
            block.append(line)
    if index < len(old_lines):
        return None
    if block:
        added.append((index, block))
    return added


def modified_lines(old, new):
    """Whether `new` changes or removes a line of `old`, rather than only adding lines."""
    return bool(old) and insertions(old, new) is None


QUIET_CALL = re.compile(r"\s*(?:crate::[a-z_]+::statelens::)?sl_(?:assert|implies|probe)!\s*\(")
ITEM_LINE = re.compile(
    r"^\s*(?:#\[|pub\b|fn\b|impl\b|struct\b|enum\b|trait\b|mod\b|type\b|const\b|static\b"
    r"|async\b|unsafe\b|extern\b)"
)


def quiet_block(lines):
    """Whether added lines are only blank lines, `//` comments and StateLens calls.

    A block comment marker is never quiet: `/*` above an existing check and `*/`
    below it comment the check out without touching its line.
    """
    if any("/*" in line or "*/" in line for line in lines):
        return False
    text = blank_inert("\n".join(lines), strings=True)
    position = 0
    while True:
        match = QUIET_CALL.match(text, position)
        if not match:
            return text[position:].strip() == ""
        depth, position = 1, match.end()
        while position < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[position], 0)
            position += 1
        if depth:
            return False
        if text[position : position + 1] == ";":
            position += 1


def drift_reason(old, new):
    """Why `new` may change what an earlier audit batch reviewed in `old`, or None.

    A changed or removed line is drift. So are lines added inside an existing
    function body unless every one is blank, a `//` comment or a StateLens macro
    call: a `let` that shadows, an early `return`, a call that prunes a ghost
    history or a `/*` all compile and change what an earlier binding rests on. So
    is an attribute or a comment opener added right above an existing item, which
    can compile it out. New items, and new checks beside existing code, are quiet.
    """
    added = insertions(old, new)
    if added is None:
        return "changed or removed lines"
    old_lines = old.split("\n")
    structure = blank_inert(old, strings=True)
    bodies = [
        (structure.count("\n", 0, start) + 1, structure.count("\n", 0, end) + 1, name)
        for start, end, name in fn_extents(structure)
    ]
    for index, block in added:
        # The block precedes old line `index + 1`; inside a body means after the
        # body's first line and at or before its closing brace.
        holder = next((name for first, last, name in bodies if first < index + 1 <= last), None)
        if holder and not quiet_block(block):
            return f"added lines inside `{holder}`"
        following = next((line for line in old_lines[index:] if line.strip()), "")
        if ITEM_LINE.match(following) and any(
            line.lstrip().startswith(("#[", "/*")) for line in block
        ):
            return "added an attribute or a comment opener above an item"
    return None


def audit_drift(batches):
    """The bindings whose audit verdict a later batch's edits escaped: id -> (batch, edits).

    `batches` is (name, invariant ids, subsystem texts after the batch), in order.
    Each batch's verdict stands for the tree it left. A later batch may add new
    items and new checks, which change nothing an earlier batch reviewed; but an
    edit `drift_reason` names may be to an earlier binding's assertion, ghost
    update or helper, and nothing reviews that binding again, so it is reported
    unreviewed with the batch and the edits, as `path (reason)`.
    """
    unreviewed = {}
    for later in range(1, len(batches)):
        name, _ids, texts = batches[later]
        _earlier_name, _earlier_ids, previous = batches[later - 1]
        edits = []
        for path in sorted(set(previous) | set(texts)):
            if path not in previous:
                continue  # a new file, which no earlier batch reviewed
            reason = drift_reason(previous[path], texts.get(path, ""))
            if reason:
                edits.append(f"{path} ({reason})")
        if not edits:
            continue
        for earlier in range(later):
            for invariant in batches[earlier][1]:
                unreviewed.setdefault(invariant, (name, edits))
    return unreviewed


def unreviewed_note(unreviewed):
    """One clause naming the bindings a later audit batch's edits escaped."""
    batches = sorted({batch for batch, _edits in unreviewed.values()})
    edits = sorted({edit for _batch, edits in unreviewed.values() for edit in edits})
    return (
        f"audit batch {', '.join(batches)} edited {', '.join(edits)} after the verdict on "
        f"{', '.join(sorted(unreviewed))}, which were not reviewed against the edit"
    )


# SPEC section 18.6: Target-State Synthesis. A replay is killed after this many seconds,
# longer than libFuzzer's default `-timeout` of 1,200 s (section 18.8).
REPLAY_TIMEOUT = 1500
# Files a run of a scaffold leaves (section 18.6.2, step 2.2); all but the last are failures.
STRAY_NAME = re.compile(r"^(?:crash|oom|timeout|leak|slow-unit)-")
STRAY_FAILURE = re.compile(r"^(?:crash|oom|timeout|leak)-")
# The undoes that owe a revalidation when they undo shared code (section 18.6.2, --redo and
# Last check), and the rollback of a card restored after its revalidation rewrote reports
# (Finish), with the tag of that revalidation's replay directories and build logs.
UNDO_TAGS = {
    "--redo": "after-redo",
    "the last check": "after-last-check",
    "a rollback": "after-rollback",
}
# Guard 3 of section 18.6.1: the runtime functions that write ghost state or counters, which
# only the helper and the scaffolds' thin targets may call anew; the literals of the helper's
# lines; the assertion and probe macros; and the module attribute that would redirect a
# module declaration to another file.
GHOST_WRITES = (
    "with_ghost",
    "with_global",
    "record",
    "note",
    "violation",
    "reset",
    "clear_compromised",
)
# The read side's calls only the helper makes: `tick` advances the event sequence, and
# `watch` and `unwatch` drop the trace and forget a truncation the helper has not seen yet.
HELPER_ONLY = ("tick", "watch", "unwatch")
GUARDED_CALLS = tuple(dict.fromkeys(GHOST_WRITES + ("set_compromised",) + HELPER_ONLY + READ_SIDE))
REACH_LITERALS = ("[statelens-reach]", "[statelens-scaffold]")
SL_CALL = re.compile(r"\bsl_(?:probe|assert|implies)!\s*\(")
# The label of an `sl_probe!` call and the ID of an `sl_implies!` call: the first string
# literal of each, after the replica.
SL_LABEL = re.compile(r'\bsl_(?:probe|implies)!\s*\([^;"]*"([^"\\]+)"')
MOD_STATELENS = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+statelens\s*;")
PATH_ATTRIBUTE = re.compile(r"#\s*\[\s*path\b")
# Guard 3: what no edit adds outside the helper. A print could forge a helper line however
# its literal is spelled, a panic hook could swallow an assertion's panic, and an included
# file or a `#[path]` module could hold code the guards never read. Text checks only, so
# they stop the plain forms; review of the card's diff covers the rest (section 18.11).
HIDDEN_CODE = (
    ("a print macro", re.compile(r"\be?print(?:ln)?\s*!")),
    ("a stdout or stderr handle", re.compile(r"\b(?:stdout|stderr)\s*\(")),
    ("a raw file descriptor", re.compile(r"\bfrom_raw_fd\b")),
    ("a panic hook", re.compile(r"\b(?:set_hook|take_hook)\b")),
    ("an include macro", re.compile(r"\binclude(?:_str|_bytes)?\s*!")),
    ("a #[path] attribute", PATH_ATTRIBUTE),
)
SUMMARY_RESULT = re.compile(r"^statelens: result\s+(.*?)\s*$", re.M)
TSS_MARKER = "// [statelens] tss:"
# The feedback of a first attempt (section 18.6.2).
FIRST_ATTEMPT = "none: first attempt"


def synthesis_stamp():
    return utc_now().strftime("%Y%m%dT%H%M%SZ")


def host_triple(toolchain):
    """The host triple of `toolchain`, where cargo-fuzz puts its builds."""
    rustc = ["rustc"] + ([f"+{toolchain}"] if toolchain else [])
    try:
        version = subprocess.run(rustc + ["-vV"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise Abort(2, f"cannot ask {' '.join(rustc)} for its host triple: {error}")
    for line in version.splitlines():
        if line.startswith("host: "):
            return line[len("host: ") :].strip()
    raise Abort(2, f"{' '.join(rustc)} -vV did not report a host triple")


def fuzz_binary(repo, package, host, target):
    """The fuzz build of `target`, in CARGO_TARGET_DIR, which cargo reads relative to the
    checkout the build runs in, or else in the workspace's target directory or the
    package's (SPEC section 18.8), or None. With the variable set, only its directory is
    checked, so an older build elsewhere is never taken for this one."""
    custom = os.environ.get("CARGO_TARGET_DIR")
    roots = [repo / custom] if custom else [repo / "target", repo / package / "target"]
    for root in roots:
        candidate = root / host / "release" / target
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def first_run(text, card):
    """A replay's output with the `[statelens-reach]` lines of `card` of one run of the
    input kept: libFuzzer runs a passing input a second time to look for leaks, inside the
    same replay, and the second run repeats every line (SPEC section 18.8).

    A run opens with the `phase prefix` line Stages::new prints; the panic hook reprints
    the phase after its `panic` line, so a `phase prefix` line after a `panic` line of its
    run opens none. The run kept is the one that printed a `panic` line, else the first,
    so a later run never completes an earlier one's report, and a failure in a later run
    is read in that run's phase. Every other line is kept.
    """
    prefix = f"[statelens-reach] {card} "
    tagged, run, opened, panicked, failed = [], 0, False, False, None
    for line in text.splitlines():
        if not line.startswith(prefix):
            tagged.append((None, line))
            continue
        rest = line[len(prefix) :].strip()
        if rest == "phase prefix" and opened and not panicked:
            run += 1
        opened = True
        if rest.startswith("panic "):
            panicked = True
            if failed is None:
                failed = run
        tagged.append((run, line))
    kept = 0 if failed is None else failed
    out = [line for run, line in tagged if run is None or run == kept]
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def campaign_labels(repo, profile):
    """Every `sl_probe!` label and `sl_implies!` ID under the editable roots of `profile`,
    as (label, `path:line`), from one scan (SPEC section 18.6.2, LABELS)."""
    settings = PROFILES[profile]
    found = []
    for root in settings["roots"]:
        for path in sorted((repo / root).rglob("*.rs")):
            relative = path.relative_to(repo).as_posix()
            if relative == settings["runtime"]:
                continue
            code = blank_inert(path.read_text(errors="replace"))
            for match in SL_LABEL.finditer(code):
                line = code.count("\n", 0, match.start()) + 1
                found.append((match.group(1), f"{relative}:{line}"))
    return found


def sl_calls(text):
    """The `sl_probe!`, `sl_assert!` and `sl_implies!` calls of Rust `text`, as a multiset
    of their texts with whitespace and trailing commas dropped, so a call that only moves
    or is reformatted is the same call (guard 3 of SPEC section 18.6.1)."""
    code = blank_inert(text)
    structure = blank_inert(text, strings=True)
    calls = collections.Counter()
    for match in SL_CALL.finditer(code):
        depth, index = 0, match.end() - 1
        while index < len(structure):
            char = structure[index]
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
                if not depth:
                    break
            index += 1
        call = re.sub(r"\s+", "", code[match.start() : index + 1])
        calls[re.sub(r",([)\]}])", r"\1", call)] += 1
    return calls


def module_declarations(text):
    """Every declaration of the runtime module in `text`, with the attribute lines directly
    above it."""
    lines = text.split("\n")
    found = []
    for index, line in enumerate(lines):
        if MOD_STATELENS.match(line):
            start = index
            while start > 0 and lines[start - 1].strip().startswith("#["):
                start -= 1
            found.append(tuple(item.strip() for item in lines[start : index + 1]))
    return found


def diff_added_text(diff):
    """Maps each file a unified diff changes to the multiset of the non-blank lines it adds,
    stripped of surrounding whitespace."""
    added, path, old, new = {}, None, 0, 0
    for raw in diff.splitlines():
        if old > 0 or new > 0:
            tag = raw[:1]
            if tag == "+":
                if path and raw[1:].strip():
                    added.setdefault(path, collections.Counter())[raw[1:].strip()] += 1
                new -= 1
            elif tag == "-":
                old -= 1
            elif tag != "\\":
                old, new = old - 1, new - 1
            continue
        if raw.startswith("+++ "):
            name = raw[4:].split("\t")[0].strip()
            path = None if name == "/dev/null" else name[2:] if name.startswith("b/") else name
            continue
        hunk = re.match(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@", raw)
        if hunk and path:
            old, new = int(hunk.group(1) or 1), int(hunk.group(2) or 1)
    return added


def file_diff(path, old, new):
    """A git-style unified diff of one file, from content `old` to `new` (bytes, or None
    for a file that does not exist), which `git apply` reads."""
    head = f"diff --git a/{path} b/{path}\n"
    if old is None:
        head += "new file mode 100644\n"
    elif new is None:
        head += "deleted file mode 100644\n"
    try:
        before = (old or b"").decode("utf-8").splitlines(keepends=True)
        after = (new or b"").decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        return head + f"Binary files a/{path} and b/{path} differ\n"
    lines = difflib.unified_diff(
        before,
        after,
        "/dev/null" if old is None else f"a/{path}",
        "/dev/null" if new is None else f"b/{path}",
    )
    body = "".join(
        line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in lines
    )
    return head + body


def tree_diff(before, after):
    """The diff between two snapshots, path -> bytes, of the synthesis scope."""
    return "".join(
        file_diff(path, before.get(path), after.get(path))
        for path in sorted(set(before) | set(after))
        if before.get(path) != after.get(path)
    )


def diff_sections(diff):
    """The per-file sections of a diff `tree_diff` wrote, as (path, text)."""
    sections = []
    for part in re.split(r"(?m)^(?=diff --git a/)", diff):
        match = re.match(r"diff --git a/(\S+) b/", part)
        if match:
            sections.append((match.group(1), part))
    return sections


def diff_hunks(text):
    """The hunks of one file's diff, as (header, lines)."""
    hunks = []
    for line in text.splitlines():
        if line.startswith("@@"):
            hunks.append((line, []))
        elif hunks:
            hunks[-1][1].append(line)
    return hunks


def fuzz_target_parts(text):
    """The closure parameters, the closure header line and the body of the one
    `fuzz_target!` of a target (Appendix B.1), or None. A one-line target's body is its
    expression as a statement."""
    lines = [line.rstrip() for line in text.split("\n")]
    starts = [index for index, line in enumerate(lines) if VARIANT_START.match(line)]
    if len(starts) == 1:
        start = starts[0]
        indent = VARIANT_START.match(lines[start]).group(1)
        closing = f"{indent}}});"
        end = next((i for i in range(start + 1, len(lines)) if lines[i] == closing), None)
        if end is None:
            return None
        params = re.match(r"^\s*fuzz_target!\(\|([^|]+)\|", lines[start]).group(1)
        return params, lines[start].strip(), "\n".join(lines[start + 1 : end])
    one = [index for index, line in enumerate(lines) if VARIANT_ONE_LINE.match(line)]
    if len(starts) == 0 and len(one) == 1:
        _indent, params, expression = VARIANT_ONE_LINE.match(lines[one[0]]).groups()
        return params, f"fuzz_target!(|{params}|", expression + ";"
    return None


def statements(body):
    """The statements of a block body, without comments, each with its whitespace dropped."""
    code = blank_inert(body, strings=True)
    return [re.sub(r"\s+", "", part) for part in code.split(";") if part.strip()]


def remove_bin_blocks(text, names):
    """`text`, a manifest, without the [[bin]] blocks whose name `names` matches as a shell
    pattern, each with the blank line before it (Appendix B.2 writes one)."""
    lines = text.split("\n")
    index = 0
    while index < len(lines):
        if lines[index].strip() != "[[bin]]":
            index += 1
            continue
        end = index + 1
        while end < len(lines) and not lines[end].strip().startswith("["):
            end += 1
        name = bin_entries(lines[index + 1 : end]).get("name", ("", ""))[0]
        if not fnmatch.fnmatchcase(name, names):
            index = end
            continue
        while end - 1 > index and not lines[end - 1].strip():
            end -= 1
        start = index - 1 if index > 0 and not lines[index - 1].strip() else index
        del lines[start:end]
        index = start
    return "\n".join(lines)


def base_runner(profile, base, body):
    """Whether the runner of `base` is hooked (Appendices B.3 to B.5 and F), for the agent."""
    if profile == "marshal":
        if base.endswith("_scenarios"):
            return "hooked: the wedge scenario runs a real Byzantine engine (Appendix F)"
        if "twins" in base:
            return "hooked: the Twins runner (Appendix B.3)"
    else:
        if re.search(r"\bfuzz_twins_audit\b|\bTwins(?:Campaign|Mutator)\b", body):
            return "hooked: the Twins runner (Appendix B.3)"
        if re.search(r"\bChaosTwins\b", body):
            return "hooked: the Chaos-Twins runner (Appendix B.5)"
        if re.search(r"\bByzzfuzz\b", body):
            return "hooked: the ByzzFuzz runner (Appendix B.5)"
        if re.search(r"\bfuzz_audit\w*::<", body):
            return "hooked: the audited Standard runner (Appendix B.5)"
    return "not hooked: it runs no engine under a Byzantine identity, so it needs no hook"


class Synthesis:
    """Target-State Synthesis (SPEC section 18.6), on the checkout a campaign instrumented."""

    def __init__(self, args):
        self.repo = repo_root()
        self.sl_dir = self.repo / SL
        self.config = load_config(self.sl_dir)
        self.agent = agent_name(self.config, args.agent)
        self.patterns = args.match or []
        self.redo = args.redo
        self.dir = self.sl_dir / "campaign"
        self.reach = self.dir / "reach"
        try:
            self.meta = json.loads((self.dir / "meta.json").read_text())
        except (OSError, ValueError):
            self.meta = None
        profile = args.profile or (self.meta or {}).get("profile")
        if profile in PROFILES and not PROFILES[profile]["scaffold"]:
            raise Abort(
                1, f"Target-State Synthesis refuses the {profile} profile; use simplex or marshal"
            )
        if self.meta is None or self.meta.get("profile") not in PROFILES:
            raise Abort(
                2,
                f"no campaign in this checkout names its profile ({SL}/campaign/meta.json); "
                "run `just campaign` first",
            )
        if self.meta["profile"] != profile:
            raise Abort(
                2,
                f"the campaign in this checkout ran the {self.meta['profile']} profile, not "
                f"{profile}; synthesize with the campaign's profile",
            )
        self.profile_name = profile
        self.profile = PROFILES[profile]
        self.package = self.profile["package"]
        self.manifest = profile_manifest(profile)
        self.states = target_states_dir(profile)
        self.mod_rs = f"{self.states}/mod.rs"
        self.lib_rs, self.anchor, _position, declaration = self.profile["scaffold"]
        self.declaration = declaration.split("\n")
        # SPEC section 18.6.1, Where: the editable roots and the fuzz package.
        self.scope = tuple(self.profile["roots"]) + (self.package + "/",)
        # Guard 2: the files the script owns whole.
        self.owned = (self.manifest, "Cargo.lock", self.mod_rs)
        self.base = self.meta.get("base") or ""
        self.fuzz_toolchain = self.meta.get("fuzz_toolchain") or pinned_nightly(self.repo)
        self.test_toolchain = self.meta.get("test_toolchain") or ""
        self.runtime_path = (
            f"commonware_{self.profile['crate']}::{self.profile['module']}::statelens"
        )
        self.baseline_dir = self.reach / "baseline"
        # The S0 of the pair in progress, kept on disk until the pair ends (`keep_pending`).
        self.pending = self.reach / "pending"
        self.empty = self.reach / "empty"
        # The revalidation an undo of shared code owes (`owe`), on disk from before the undo
        # until it completes, so a synthesis that stops first leaves it to the next; and the
        # one a pair's revalidation owes from before it rewrites a report until the pair's
        # report is written, for a restore of the pair's edits in between (`revalidate`).
        self.owed = self.reach / "revalidation.json"
        self.host = None
        self.labels = []
        self.b_files, self.b_worktree, self.run_state = set(), {}, {}
        self.declared, self.written = False, set()
        # What the guards compare against, read once per run before any agent runs: the
        # agent can write SL/campaign/, which git ignores, so no guard re-reads it, and
        # `seal` writes these back after every run of the agent.
        self.b_data, self.written_data = {}, {}
        self.campaign_added, self.campaign_diff, self.tests_record = {}, None, None
        # Guard 5's inventory, {"passed": set, "failed": set}, kept with B.
        self.tests = None
        self.campaign_result = None
        # The pair in progress, for `preserve`: its card, key, module, S0, attempt, step,
        # the strays snapshot of a running agent, stray failures, whether its version is
        # kept, and replay codes.
        self.live = None
        # The kept scaffolds a pair's shared edits revalidate: pair key -> its scaffold, its
        # card, base and module, its History and its report's text, read once per run and
        # kept up to date in memory.
        self.standing = {}

    def rel(self, path):
        return Path(path).relative_to(self.repo).as_posix()

    # Preconditions (section 18.6.2).

    def check_campaign(self):
        """The preconditions that read meta.json, reported before the agent CLI is checked."""
        head = git(self.repo, "rev-parse", "HEAD").strip()
        if self.base != head:
            raise Abort(
                2,
                f"campaign/meta.json names the base {self.base[:10] or 'none'}, but HEAD is "
                f"{head[:10]}; synthesize on the checkout the campaign instrumented",
            )
        false = [
            str(item) for item in self.meta.get("invariants", ()) if str(item).startswith("FALSE-")
        ]
        if false:
            raise Abort(
                2,
                f"the campaign bound {', '.join(false)}, and a false invariant panics in every "
                "scaffold; run a campaign without STATELENS_FALSE_INVARIANTS=1",
            )

    def check_preconditions(self):
        """The other preconditions, after the usage errors, the agent CLI first."""
        check_agent_cli(self.agent)
        summary = self.dir / "summary.txt"
        found = SUMMARY_RESULT.search(summary.read_text()) if summary.is_file() else None
        result = found.group(1) if found else None
        if result not in ("READY", "PANIC (tests)"):
            raise Abort(
                2,
                f"the campaign ended {result or 'without a summary'}; synthesis needs a campaign "
                "that ended READY or PANIC (tests)",
            )
        self.campaign_result = result
        runtime = self.repo / self.profile["runtime"]
        if not runtime.is_file() or "pub fn watch(" not in runtime.read_text(errors="replace"):
            raise Abort(2, "this checkout predates the read side or was cleaned; use a fresh clone")
        if not (self.dir / "plan.md").is_file():
            raise Abort(2, f"{PLAN} is missing; use a fresh clone and run a campaign")
        if shutil.which("cargo-fuzz") is None:
            raise Abort(2, "cargo-fuzz is not on PATH; see the prerequisites in README.md")

    # Snapshots: every file git does not ignore under the scope, and Cargo.lock, with the
    # ignored Rust files cargo compiles (guard 3 vetoes those).

    def scope_files(self):
        listed = git(
            self.repo,
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            *self.scope,
            "Cargo.lock",
        )
        return sorted(
            {path for path in listed.split("\0") if path and (self.repo / path).is_file()}
            | set(self.ignored_sources())
        )

    def ignored_sources(self):
        """The Rust files git ignores where cargo compiles them, under the editable roots
        and the package's src/ and fuzz_targets/: `target` in the repository's .gitignore
        ignores a module named `target`. Its build output, corpus and artifacts lie
        elsewhere in the package."""
        listed = git(
            self.repo,
            "ls-files",
            "-z",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--",
            *self.profile["roots"],
            f"{self.package}/src/",
            f"{self.package}/fuzz_targets/",
        )
        return sorted(
            path
            for path in listed.split("\0")
            if path.endswith(".rs") and (self.repo / path).is_file()
        )

    def snapshot(self):
        return {path: (self.repo / path).read_bytes() for path in self.scope_files()}

    def prune(self, directory):
        """Removes `directory` and its parents while they are empty, below the scope."""
        tops = {(self.repo / root).resolve() for root in self.scope}
        while directory.is_dir() and directory.resolve() not in tops:
            if not inside_repo(self.repo, directory) or any(directory.iterdir()):
                return
            parent = directory.parent
            directory.rmdir()
            directory = parent

    def write(self, path, content):
        """Writes `content` (bytes) to `path`, or deletes it for None. A symbolic link is an
        edit's, never a file of the scope: one at `path` is removed, not written through,
        and nothing is written below a directory one replaced, with a warning, since guard 1
        names that directory."""
        target = self.repo / path
        if target.parent.resolve() != (self.repo.resolve() / path).parent:
            say(f"warning: {path} lies behind a symbolic link; it was not restored")
            return
        removed = target.is_symlink()
        if removed:
            target.unlink()
        if content is None:
            if target.is_file():
                target.unlink()
                removed = True
            if removed:
                self.prune(target.parent)
            return
        if not target.is_file() or target.read_bytes() != content:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

    def restore(self, snapshot, version=None):
        """Rewrites the files of `snapshot` and deletes the files created in scope since;
        with `version`, the paths it changed (bytes, or None for deleted) are then as it
        has them. A file already as wanted is left alone, so cargo does not rebuild it."""
        wanted = dict(snapshot)
        for path, content in (version or {}).items():
            if content is None:
                wanted.pop(path, None)
            else:
                wanted[path] = content
        for path in self.scope_files():
            if path not in wanted:
                self.write(path, None)
        for path, content in wanted.items():
            self.write(path, content)
        self.own()

    # The baseline B (section 18.6.2, once per campaign) and the script's own files.

    def load_baseline(self):
        state_path = self.baseline_dir / "state.json"
        if not state_path.is_file():
            if (self.repo / self.states).exists():
                raise Abort(
                    2,
                    f"{self.states} exists, but the synthesis baseline "
                    f"{self.rel(self.baseline_dir)} does not; use a fresh clone",
                )
            partial = self.reach / "baseline.partial"
            if partial.exists():
                shutil.rmtree(partial)
            files = self.snapshot()
            for path, content in files.items():
                target = partial / "files" / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            self.b_files, self.b_data = set(files), dict(files)
            self.b_worktree = worktree_state(self.repo)
            self.declared, self.written, self.written_data = False, set(), {}
            (partial / "written").mkdir(parents=True, exist_ok=True)
            self.save_state(partial)
            self.take_tests(partial)
            if self.baseline_dir.exists():
                shutil.rmtree(self.baseline_dir)
            partial.rename(self.baseline_dir)
            say(f"synthesis: baseline of {len(files)} file(s) in {self.rel(self.baseline_dir)}")
            return
        self.load_tests()
        state = json.loads(state_path.read_text())
        self.b_files = set(state["files"])
        self.b_worktree = {path: tuple(value) for path, value in state["worktree"].items()}
        self.declared = state["declared"]
        self.written = set(state["written"])
        self.b_data = {
            path: (self.baseline_dir / "files" / path).read_bytes() for path in self.b_files
        }
        self.written_data = {
            path: (self.baseline_dir / "written" / path).read_bytes() for path in self.written
        }

    def save_state(self, directory=None):
        state = {
            "files": sorted(self.b_files),
            "worktree": {path: list(value) for path, value in sorted(self.b_worktree.items())},
            "declared": self.declared,
            "written": sorted(self.written),
        }
        (directory or self.baseline_dir).joinpath("state.json").write_text(
            json.dumps(state, indent=1) + "\n"
        )

    def b_content(self, path):
        return self.b_data.get(path)

    def expected(self, path):
        """What the script last wrote to one of its own files, or else its content in B."""
        if path in self.written:
            return self.written_data[path]
        return self.b_content(path)

    def own(self, *paths):
        """Records the current content of the script's own files as what it last wrote,
        in memory for the guards and on disk for the next synthesis."""
        for path in paths or self.owned:
            target = self.repo / path
            if not target.is_file():
                continue
            content = target.read_bytes()
            copy = self.baseline_dir / "written" / path
            copy.parent.mkdir(parents=True, exist_ok=True)
            copy.write_bytes(content)
            self.written.add(path)
            self.written_data[path] = content
        self.save_state()

    # Guard 5's inventory: the tests the gate passed and failed on the tree as the campaign
    # left it, validated by nextest_run and kept with B in tests.json.

    def campaign_tests(self):
        """The inventory from the campaign's gate log, `logs/test.log`, or (None, problem)
        when the log is missing, was written by another command or does not validate."""
        log = self.dir / "logs" / "test.log"
        if not log.is_file():
            return None, "missing"
        head, _, body = log.read_text(errors="replace").partition("\n")
        if head != "$ " + shlex.join(gate_test_command(self.test_toolchain, self.profile_name)):
            return None, "not written by this test gate's command"
        # The campaign records no exit code; one that ended PANIC (tests) had a nonzero one.
        return nextest_run(body, 0 if self.campaign_result == "READY" else None)

    def save_tests(self, directory, tests, source):
        self.tests = tests
        record = {key: sorted(tests[key]) for key in ("passed", "failed")}
        record["source"] = self.rel(source)
        self.tests_record = (json.dumps(record, indent=1) + "\n").encode()
        (directory / "tests.json").write_bytes(self.tests_record)

    def take_tests(self, directory):
        """Takes the inventory with B: from the campaign's gate log when it validates, or
        else from one run of the gate on the tree as the campaign left it. Output that cannot
        be validated, and a failed test after a campaign that ended READY, stop synthesis."""
        tests, problem = self.campaign_tests()
        log = self.dir / "logs" / "test.log"
        if problem:
            say(
                f"synthesis: {self.rel(log)} is unusable ({problem}); running the test gate on "
                "the tree as the campaign left it"
            )
            log = self.dir / "logs" / "test-baseline.log"
            command = gate_test_command(self.test_toolchain, self.profile_name)
            code, _ = run_logged(command, log, self.repo, echo=False)
            tests, problem = nextest_run(log.read_text(errors="replace"), code)
            if problem:
                raise Abort(
                    2,
                    f"the test gate's output on the tree as the campaign left it is unusable "
                    f"({problem}); see {self.rel(log)}",
                )
            if self.campaign_result == "READY" and tests["failed"]:
                # The campaign's own gate passed every test on this tree: a failure here is
                # a flaky or killed test, which the inventory must not excuse for every card.
                raise Abort(
                    2,
                    f"the campaign ended READY, but the test gate failed "
                    f"{', '.join(sorted(tests['failed']))} on the tree it left (a flaky or "
                    f"killed test); see {self.rel(log)} and run synthesis again",
                )
        self.save_tests(directory, tests, log)
        say(
            f"synthesis: test inventory of {len(tests['passed'])} passed and "
            f"{len(tests['failed'])} failed test(s) from {self.rel(log)}"
        )

    def load_tests(self):
        """Loads the inventory kept with B. A baseline without one stops synthesis: the
        campaign's gate log may have changed since, so the inventory is not taken anew."""
        path = self.baseline_dir / "tests.json"
        if not path.is_file():
            raise Abort(
                2,
                f"the synthesis baseline has no test inventory, {self.rel(path)}; use a fresh "
                "clone",
            )
        try:
            self.tests_record = path.read_bytes()
            record = json.loads(self.tests_record)
            self.tests = {key: {str(name) for name in record[key]} for key in ("passed", "failed")}
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise Abort(2, f"{self.rel(path)} is unreadable ({error}); use a fresh clone")

    def load_campaign(self):
        """The campaign's files the guards compare against, read once per run."""
        diff = self.dir / "instrumentation.diff"
        self.campaign_diff = diff.read_bytes() if diff.is_file() else None
        if self.campaign_diff is not None:
            self.campaign_added = diff_added_text(self.campaign_diff.decode(errors="replace"))

    def seal(self):
        """Writes back, with a warning, each record the guards compare with that is not as
        held in memory: the files of B, what the script last wrote to its own files, the
        test inventory and the instrumentation diff. The agent, and the code it wrote, can
        write SL/campaign/, so this runs after its every run and when the synthesis ends,
        and the next synthesis loads them unchanged."""
        records = {self.baseline_dir / "files" / path: self.b_data[path] for path in self.b_files}
        records.update(
            (self.baseline_dir / "written" / path, self.written_data[path]) for path in self.written
        )
        records[self.baseline_dir / "tests.json"] = self.tests_record
        records[self.dir / "instrumentation.diff"] = self.campaign_diff
        for target, content in records.items():
            if (target.read_bytes() if target.is_file() else None) == content:
                continue
            say(f"warning: the agent changed {self.rel(target)}; it was written back")
            if content is None:
                target.unlink()
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
        self.save_state()

    def load_standing(self):
        """The kept scaffolds of the campaign, for revalidation (section 18.6.2, Finish): the
        pair of each thin target in the package, its card's History and its report, read
        once per run before any agent runs, since the reports lie in SL/campaign/."""
        cards = {
            path.stem: path
            for top in CARD_TREES
            for path in (self.sl_dir / top / self.profile_name).glob("TS-*.md")
        }
        self.standing = {}
        for scaffold in scaffold_targets(self.repo, self.profile_name):
            found = SCAFFOLD_NAME.match(scaffold)
            card_id, base = "TS-" + found["number"], found["base"]
            key = pair_key(card_id, base)
            report = self.reach / f"{key}.md"
            text = report.read_text(errors="replace") if report.is_file() else ""
            try:
                history = card_history(cards[card_id].read_text())
            except (KeyError, Abort):
                history = None
            if history is None or report_verdict(text) is None:
                say(
                    f"warning: {scaffold} has no card or no report with its verdict, so no "
                    "pair's edits revalidate it; the last check still builds it"
                )
                continue
            self.standing[key] = {
                "scaffold": scaffold,
                "card": card_id,
                "base": base,
                "module": pair_module(card_id, base),
                "history": history,
                "report": text,
            }

    def write_owned(self, path, content):
        self.write(path, content)
        self.own(path)

    # Guards 1 to 3 against B (section 18.6.1).

    def outside_scope(self):
        """Guard 1: the paths outside the scope that differ from B. A path under statelens/
        is compared with the state this run started from instead, because the operator
        edits cards and prompts between syntheses."""
        current = worktree_state(self.repo)
        changed = []
        for path in sorted(set(current) | set(self.b_worktree) | set(self.run_state)):
            if path == "Cargo.lock" or path.startswith(self.scope):
                continue
            reference = self.run_state if path.startswith(f"{SL}/") else self.b_worktree
            if reference.get(path) != current.get(path):
                changed.append(path)
        return changed

    def declaration_at_anchor(self, lines):
        found = [index for index, line in enumerate(lines) if line == self.anchor]
        if len(found) != 1:
            return False
        start = found[0] + 1
        return lines[start : start + len(self.declaration)] == self.declaration

    def fix_declaration(self, fallback=None):
        """Writes the declaration of `target_states` back as the script wrote it."""
        target = self.repo / self.lib_rs
        lines = target.read_text().split("\n") if target.is_file() else []
        size = len(self.declaration)
        index = 0
        while index < len(lines):
            if lines[index : index + size] == self.declaration:
                del lines[index : index + size]
            elif lines[index].strip() == "pub mod target_states;":
                del lines[index]
            else:
                index += 1
        if self.declared:
            found = [index for index, line in enumerate(lines) if line == self.anchor]
            if len(found) != 1:
                # The anchor itself was edited: the file as the pair found it.
                if fallback is not None:
                    self.write(self.lib_rs, fallback)
                return
            lines[found[0] + 1 : found[0] + 1] = self.declaration
        self.write(self.lib_rs, "\n".join(lines).encode())

    def script_files(self, restore=False, s0=None):
        """Guard 2: (path, finding) for every change to the script's own files and to any
        manifest in scope; with `restore`, each is written back."""
        findings = []
        for path in self.owned:
            want = self.expected(path)
            target = self.repo / path
            have = target.read_bytes() if target.is_file() else None
            if have != want:
                findings.append(
                    (
                        path,
                        f"guard 2: {path} is the script's and was restored; leave the package "
                        "manifest, Cargo.lock and target_states/mod.rs as you found them",
                    )
                )
                if restore:
                    self.write(path, want)
        for path in sorted(set(self.scope_files()) | self.b_files):
            if not path.endswith("Cargo.toml") or path == self.manifest:
                continue
            if not path.startswith(self.scope):
                continue
            target = self.repo / path
            have = target.read_bytes() if target.is_file() else None
            if have != self.b_content(path):
                findings.append(
                    (
                        path,
                        f"guard 2: {path} changed; no Cargo.toml may change, and it was restored",
                    )
                )
                if restore:
                    self.write(path, self.b_content(path))
        lib = self.repo / self.lib_rs
        lines = lib.read_text(errors="replace").split("\n") if lib.is_file() else []
        before = (self.b_content(self.lib_rs) or b"").decode(errors="replace").split("\n")
        count = sum(line.strip() == "pub mod target_states;" for line in lines)
        expected = sum(line.strip() == "pub mod target_states;" for line in before)
        if self.declared:
            good = count == expected + 1 and self.declaration_at_anchor(lines)
        else:
            good = count == expected
        if not good:
            findings.append(
                (
                    self.lib_rs,
                    f"guard 2: the declaration of target_states in {self.lib_rs} is the "
                    "script's and was restored",
                )
            )
            if restore:
                self.fix_declaration((s0 or {}).get(self.lib_rs))
        if restore and findings:
            self.own()
        return findings

    def thin_problems(self, path):
        """Why a scaffold's thin target is not of the shape of Appendix B.6, if it is not."""
        relative = self.rel(path)
        match = SCAFFOLD_NAME.match(path.stem)
        base, module = match["base"], f"ts{match['number']}_{match['base']}"
        source = self.repo / profile_fuzz_dir(self.profile_name) / f"{base}.rs"
        if not source.is_file():
            return [f"{relative}: its base {base} is not a target of {self.package}"]
        wanted = fuzz_target_parts(source.read_text(errors="replace"))
        if wanted is None:
            return [f"{relative}: the fuzz_target! of its base {base} cannot be read"]
        text = path.read_text(errors="replace")
        code = blank_inert(text)
        parts = fuzz_target_parts(code)
        shape = (
            f"{relative}: its fuzz_target! must be the block of Appendix B.6, with the "
            f"closure parameter of {base} ({wanted[0]}) and exactly three statements: "
            f"{self.runtime_path}::reset(); {module}::fuzz with the generic arguments of "
            f"{base}'s entry; {self.runtime_path}::clear_compromised();"
        )
        if (
            code.count("fuzz_target!") != 1
            or parts is None
            or not VARIANT_START.match(
                next(line.rstrip() for line in code.split("\n") if "fuzz_target!" in line)
            )
        ):
            return [shape]
        params, _header, body = parts
        if re.sub(r"\s+", "", params) != re.sub(r"\s+", "", wanted[0]):
            return [shape]
        found = statements(body)
        name = re.sub(r"\s+", "", params).split(":", 1)[0]
        call = re.fullmatch(
            rf"(?:[A-Za-z_][A-Za-z0-9_]*::)*{module}::fuzz(::<.*>)?\({re.escape(name)},?\)",
            found[1] if len(found) == 3 else "",
        )
        generics = turbofish_arguments(wanted[2])
        if (
            len(found) != 3
            or found[0] != f"{self.runtime_path}::reset()"
            or found[2] != f"{self.runtime_path}::clear_compromised()"
            or not call
            or [re.sub(r"\s+", "", item) for item in turbofish_arguments(found[1])]
            != [re.sub(r"\s+", "", item) for item in generics]
        ):
            return [shape]
        return []

    def shaped_thin_targets(self):
        directory = self.repo / profile_fuzz_dir(self.profile_name)
        return {
            self.rel(path)
            for path in directory.glob("*_statelens.rs")
            if SCAFFOLD_NAME.match(path.stem) and not self.thin_problems(path)
        }

    def integrity(self):
        """Guard 3: (path, finding) for every breach of instrumentation integrity."""
        findings = []
        roots = tuple(self.profile["roots"])
        shaped = self.shaped_thin_targets()
        for path in sorted(set(self.scope_files()) | self.b_files):
            if not path.endswith(".rs"):
                continue
            target = self.repo / path
            now = target.read_text(errors="replace") if target.is_file() else ""
            before = (self.b_content(path) or b"").decode(errors="replace")
            if now == before:
                continue
            added, removed = sl_calls(now) - sl_calls(before), sl_calls(before) - sl_calls(now)
            if added or removed:
                calls = [f"removed {call}" for call in sorted(removed.elements())]
                calls += [f"added {call}" for call in sorted(added.elements())]
                findings.append(
                    (
                        path,
                        f"guard 3: {path}: an sl_probe!, sl_assert! or sl_implies! call was "
                        f"added, removed or changed ({'; '.join(calls)}); revert it",
                    )
                )
            more = runtime_calls(now, GUARDED_CALLS) - runtime_calls(before, GUARDED_CALLS)
            banned = set()
            if path != self.mod_rs and path not in shaped:
                banned |= {name for name in GHOST_WRITES if more[name]}
            if more["set_compromised"] and not path.startswith(self.states + "/"):
                banned.add("set_compromised")
            if path != self.mod_rs:
                banned |= {name for name in HELPER_ONLY if more[name]}
            if path.startswith(roots):
                banned |= {name for name in READ_SIDE if more[name]}
            if banned:
                findings.append(
                    (
                        path,
                        f"guard 3: {path} adds a call of {', '.join(sorted(banned))}, which the "
                        "edit contract does not allow there; remove it",
                    )
                )
            if path != self.mod_rs:
                code_now, code_before = blank_inert(now), blank_inert(before)
                for literal in REACH_LITERALS:
                    if code_now.count(literal) > code_before.count(literal):
                        findings.append(
                            (
                                path,
                                f"guard 3: {path} holds the literal {literal}, which only the "
                                "helper prints; remove it",
                            )
                        )
                code_now = blank_inert(now, strings=True)
                code_before = blank_inert(before, strings=True)
                hidden = [
                    name
                    for name, pattern in HIDDEN_CODE
                    if len(pattern.findall(code_now)) > len(pattern.findall(code_before))
                ]
                if hidden:
                    findings.append(
                        (
                            path,
                            f"guard 3: {path} adds {', '.join(hidden)}; only the helper prints, "
                            "and no edit installs a panic hook or includes another file, so "
                            "remove it, also from code copied from elsewhere",
                        )
                    )
        for path in self.ignored_sources():
            findings.append(
                (
                    path,
                    f"guard 3: git ignores {path}, but cargo compiles it, out of sight of git "
                    "status and of a fresh clone; rename it (the repository ignores any path "
                    "named target)",
                )
            )
        runtime = self.profile["runtime"]
        target = self.repo / runtime
        if (target.read_bytes() if target.is_file() else None) != self.b_content(runtime):
            findings.append(
                (
                    runtime,
                    f"guard 3: the runtime module {runtime} changed; it must stay byte-identical, "
                    "so observation code lives elsewhere; revert it",
                )
            )
        parent = runtime.rsplit("/", 1)[0] + "/mod.rs"
        declared = self.repo / parent
        now = declared.read_text(errors="replace") if declared.is_file() else ""
        if module_declarations(now) != module_declarations(
            (self.b_content(parent) or b"").decode(errors="replace")
        ):
            findings.append(
                (
                    parent,
                    f"guard 3: the declaration of the runtime module in {parent}, or an "
                    "attribute line directly above it, changed; revert it",
                )
            )
        # Guard 1 already covers a path outside the scope; statelens/ is not the campaign's.
        for path, needed in sorted(self.campaign_added.items()):
            if not path.startswith(self.scope):
                continue
            target = self.repo / path
            text = target.read_text(errors="replace") if target.is_file() else ""
            have = collections.Counter(line.strip() for line in text.split("\n") if line.strip())
            lost = needed - have
            if lost:
                shown = sorted(lost)[:3]
                findings.append(
                    (
                        path,
                        f"guard 3: {path} lost {sum(lost.values())} line(s) the campaign "
                        f"added (campaign/instrumentation.diff), such as {shown[0]!r}: a "
                        "ghost update, a field marked // [statelens] or a runner hook; "
                        "restore them",
                    )
                )
        return findings

    def review_hunks(self, card_id, s0, own):
        """The hunks of the pair's diff against S0, outside its module and thin target, that
        review must see: (unmarked, beside). Guard 4: those without the marker comment,
        which names the card, since a hunk is attributed to a pair by its own diff.
        Beside instrumentation: those whose changed lines are, or directly neighbor, an sl_*
        call or a line the campaign added, since such an edit can disable an assertion it
        leaves unchanged, by `if false` or a `cfg`, which guard 3 does not see."""
        marker = TSS_MARKER + card_id
        unmarked, beside = [], []
        current = self.snapshot()
        for path in sorted(set(s0) | set(current)):
            if path in own or path in self.owned or s0.get(path) == current.get(path):
                continue
            added = self.campaign_added.get(path, {})

            def instrumented(line):
                text = line[1:].strip()
                return bool(SL_CALL.search(text) or (re.search(r"\w", text) and text in added))

            for header, lines in diff_hunks(file_diff(path, s0.get(path), current.get(path))):
                if not any(marker in line for line in lines if line[:1] in ("+", " ")):
                    unmarked.append(f"{path} {header}")
                near = {
                    j
                    for i, line in enumerate(lines)
                    if line[:1] in ("+", "-")
                    for j in (i - 1, i, i + 1)
                    if 0 <= j < len(lines) and lines[j][:1] in ("+", "-", " ")
                }
                if any(instrumented(lines[j]) for j in near):
                    beside.append(f"{path} {header}")
        return unmarked, beside

    # The script's own edits (section 18.6.2).

    def declare(self):
        target = self.repo / self.lib_rs
        lines = target.read_text().split("\n")
        if not self.declaration_at_anchor(lines):
            found = [index for index, line in enumerate(lines) if line == self.anchor]
            if len(found) != 1:
                raise Abort(
                    2,
                    f"synthesize: expected one line {self.anchor!r} in {self.lib_rs}, found "
                    f"{len(found)}; update the scaffold anchor in scripts/statelens.py",
                )
            lines[found[0] + 1 : found[0] + 1] = self.declaration
            target.write_text("\n".join(lines))
        if not self.declared:
            self.declared = True
            self.save_state()

    def write_mod(self, add):
        """target_states/mod.rs: the helper template and a `pub mod` line for every module
        in the directory and `add`. The template keeps its code in a private module of its
        own, since a scaffold module, a child of this one, sees this one's private items."""
        directory = self.repo / self.states
        modules = {add}
        if directory.is_dir():
            modules |= {
                path.stem for path in directory.glob("ts*.rs") if MODULE_NAME.fullmatch(path.stem)
            }
        template = read_sl_file(self.repo, SL / "runtime" / "target_states.rs").rstrip("\n")
        lines = "".join(f"pub mod {module};\n" for module in sorted(modules))
        self.write_owned(self.mod_rs, (template + "\n\n" + lines).encode())

    def drop_module(self, module):
        target = self.repo / self.mod_rs
        if target.is_file():
            lines = target.read_text().split("\n")
            kept = [line for line in lines if line.strip() != f"pub mod {module};"]
            if kept != lines:
                self.write_owned(self.mod_rs, "\n".join(kept).encode())

    def undo(self, pair, diff, what):
        """Reverse-applies a pair's diff for `what`, `--redo` or the last check, then drops its
        [[bin]] block, by its exact name so a sibling pair's stays, and its line from
        target_states/mod.rs (section 18.6.2, --redo). Once the diff is known to
        reverse-apply, and before it does, the revalidation the undo owes is recorded
        (`owe`). A diff that applies forward instead was already undone, by an undo an
        interrupt stopped before the pair's reports moved, and is not applied again."""
        sections = diff_sections(diff)
        patch = "".join(
            text for path, text in sections if path not in (self.manifest, self.mod_rs)
        )

        def git_apply(*args):
            return subprocess.run(
                ["git", "apply", *args],
                input=patch,
                cwd=self.repo,
                capture_output=True,
                text=True,
            )

        if patch.strip():
            done = git_apply("-R", "--check")
            if done.returncode != 0 and git_apply("--check").returncode == 0:
                say(f"warning: {pair.key}: its edits were already undone, by an undo that stopped")
            else:
                if done.returncode == 0:
                    paths = (path for path, _ in sections)
                    self.owe(what, pair.key, self.shared_paths(pair, paths))
                    done = git_apply("-R")
                if done.returncode != 0:
                    detail = (done.stderr.strip().splitlines() or ["no detail"])[-1]
                    raise Abort(
                        2,
                        f"the diff of {pair.key} does not apply in reverse ({detail}); restore "
                        "the checkout by hand or use a fresh clone",
                    )
        manifest = self.repo / self.manifest
        text = manifest.read_text()
        kept = remove_bin_blocks(text, pair.name)
        if kept != text:
            self.write_owned(self.manifest, kept.encode())
        self.drop_module(pair.module)
        self.own()

    def redo_pairs(self, pairs):
        """Undoes each selected pair that has a report and moves its reports, and the crash
        files fuzzing wrote for its scaffold, aside (section 18.6.2, --redo). `undo` records
        the revalidation an undo of shared code owes before it applies the diff."""
        stamp = synthesis_stamp()
        for pair in reversed(pairs):
            report = self.reach / f"{pair.key}.md"
            if not report.is_file():
                continue
            diff = self.reach / f"{pair.key}.diff"
            text = diff.read_text() if diff.is_file() else ""
            self.undo(pair, text, "--redo")
            self.archive(pair.key, stamp)
            say(f"{pair.key}: --redo undid its edits; its reports are now {pair.key}.{stamp}.*")
            # The crash files fuzzing wrote for the undone version go with it; the corpus stays.
            directory = self.repo / self.package / "artifacts" / pair.name
            if directory.is_dir():
                destination = self.reach / f"{pair.key}.{stamp}" / "artifacts" / pair.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(directory), str(destination))
                say(f"{pair.key}: --redo moved {self.rel(directory)}/ to {self.rel(destination)}/")

    def archive(self, key, stamp):
        """Moves a pair's outputs to TS-NNNN_<base>.<stamp>.md, .diff and / (section
        18.6.2, --redo), and rewrites the paths its report and its attempts' notes give
        under TS-NNNN_<base>/, so their run and replay lines still name the moved files."""
        for suffix in (".md", ".diff", ""):
            source = self.reach / f"{key}{suffix}"
            if source.exists():
                source.rename(self.reach / f"{key}.{stamp}{suffix}")
        moved = self.reach / f"{key}.{stamp}"
        notes = [self.reach / f"{key}.{stamp}.md"]
        notes += sorted(moved.glob("attempt-*/replay.txt"))
        notes += sorted(moved.glob("attempt-*/interrupted.txt"))
        for path in notes:
            if path.is_file():
                text = path.read_text(errors="replace")
                path.write_text(text.replace(f"/reach/{key}/", f"/reach/{key}.{stamp}/"))

    # One pair (section 18.6.2, per pair).

    def bases_text(self, bases):
        blocks = bin_blocks((self.repo / self.manifest).read_text())
        out = []
        for base in bases:
            text = (self.repo / profile_fuzz_dir(self.profile_name) / f"{base}.rs").read_text(
                errors="replace"
            )
            parts = fuzz_target_parts(text)
            features = "none"
            for block in blocks:
                entries = bin_entries(block)
                if entries.get("name", ("", ""))[0] == base and "required-features" in entries:
                    features = entries["required-features"][1].split("=", 1)[1].strip()
            if parts is None:
                out.append(f"- `{base}`: its fuzz_target! cannot be read")
                continue
            params, header, body = parts
            entry = " ".join(body.split())
            kind = params.split(":", 1)[1].strip() if ":" in params else params
            out.append(
                f"- `{base}`: closure `{header}`, entry `{entry}`, required-features "
                f"{features}, input type `{kind}`, {base_runner(self.profile_name, base, body)}"
            )
        return "\n".join(out)

    def labels_text(self):
        if not self.labels:
            return "(none: the campaign installed no probe)"
        return "\n".join(f"- `{label}` at {where}" for label, where in self.labels)

    def build_command(self, scaffold):
        return cargo(self.fuzz_toolchain) + ["fuzz", "build", "--fuzz-dir", self.package, scaffold]

    def prompt(self, pair, n, attempt, feedback):
        check = cargo(self.test_toolchain) + [
            "check",
            "-p",
            f"commonware-{self.profile['crate']}",
            "--lib",
            "--tests",
        ]
        values = {
            "BASE": self.base,
            "PLAN": PLAN,
            "CHECK": shlex.join(check),
            "RUNTIME": self.profile["runtime"],
            "RUNTIME_MODULE": f"crate::{self.profile['module']}::statelens",
            "FUZZ_PACKAGE": self.package,
            "CARD_ID": pair.card,
            "CARD": pair.path.read_text().rstrip("\n"),
            "STAGES": str(n),
            "MODULE": f"{self.states}/{pair.module}.rs",
            "SCAFFOLD": pair.name,
            "BASE_TARGET": pair.base,
            "BASE_DETAILS": self.bases_text([pair.base]),
            "LABELS": self.labels_text(),
            "BUILD": shlex.join(self.build_command(pair.name)),
            "ATTEMPT": str(attempt),
            "FEEDBACK": feedback,
            "SUBSYSTEM_RULES": subsystem_prompt(self.sl_dir, self.profile_name, "synthesize"),
        }
        return render((self.sl_dir / "prompts" / "synthesize.md").read_text(), values)

    def run_agent(self, key, attempt, prompt):
        name = f"synthesize-{key}-{attempt}"
        (self.dir / "prompts").mkdir(parents=True, exist_ok=True)
        (self.dir / "prompts" / f"{name}.md").write_text(prompt)
        log = self.dir / "logs" / f"{name}.log"
        say(f"{key}: attempt {attempt}, running {self.agent}; log {self.rel(log)}")
        command = agent_command(self.config, self.agent, 2, self.repo)
        try:
            code, _ = run_logged(command, log, self.repo, stdin_text=prompt)
        except OSError as error:
            log.write_text(f"statelens: could not start the agent: {error}\n")
            code = -1
        finally:
            # An interrupted run included: its agent may have written SL/campaign/.
            self.seal()
        return code, log

    def strays(self, module):
        """The files a run of the scaffold may leave (step 2.2): untracked crash files
        anywhere, and the entries of the corpus and artifacts directories of the card's
        scaffolds, `module` its `tsNNNN`; a sibling pair's entries count only when new."""
        found = set()
        listed = git(self.repo, "ls-files", "-z", "--others", "--exclude-standard")
        for path in listed.split("\0"):
            if path and STRAY_NAME.match(path.rsplit("/", 1)[-1]):
                found.add(path)
        for kind in ("corpus", "artifacts"):
            for directory in (self.repo / self.package / kind).glob(f"*_{module}_statelens"):
                found.update(self.rel(item) for item in directory.rglob("*") if item.is_file())
        return found

    def sweep(self, pair, attempt, before):
        """Moves what a run of the scaffold left during an attempt to its swept/ directory;
        returns the moved files and those that are failures, finding candidates."""
        module = card_module(pair.card)
        target = self.reach / pair.key / f"attempt-{attempt}" / "swept"
        moved, failures = [], []
        for path in sorted(self.strays(module) - before):
            destination = target / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(self.repo / path), str(destination))
            say(f"warning: a run of the scaffold left {path}; moved to {self.rel(destination)}")
            moved.append(self.rel(destination))
            if STRAY_FAILURE.match(path.rsplit("/", 1)[-1]):
                failures.append(self.rel(destination))
        for kind in ("corpus", "artifacts"):
            for directory in (self.repo / self.package / kind).glob(f"*_{module}_statelens"):
                if directory.is_dir() and not any(item.is_file() for item in directory.rglob("*")):
                    shutil.rmtree(directory)
        return moved, failures

    def scaffold_checks(self, pair, s0):
        """Step 2.4, besides guards 2 and 3: the pair's thin target, no new thin target of
        the card on another base, the module header, the cryptography check of D15 and the
        guard rule. Returns (thin target, vetoes)."""
        targets = self.repo / profile_fuzz_dir(self.profile_name)
        own = sorted(targets.glob(f"*_{card_module(pair.card)}_statelens.rs"))
        expected = targets / f"{pair.name}.rs"
        vetoes, thin = [], None
        if expected.is_file():
            thin = expected
        else:
            vetoes.append(
                f"write the thin target {profile_fuzz_dir(self.profile_name)}/{pair.name}.rs"
            )
        for path in own:
            if path != expected and self.rel(path) not in s0:
                vetoes.append(
                    f"{self.rel(path)} is a thin target of this card on another base; this "
                    f"scaffold is {pair.name}"
                )
        for path in sorted(targets.glob("*_statelens.rs")):
            if SCAFFOLD_NAME.match(path.stem):
                vetoes += self.thin_problems(path)
        module_path = self.repo / self.states / f"{pair.module}.rs"
        if not module_path.is_file():
            vetoes.append(f"the module {self.rel(module_path)} does not exist")
            return thin, vetoes
        text = module_path.read_text(errors="replace")
        header = module_header(text)
        if header["card"] != pair.card or header["base"] != pair.base or not header["shape"]:
            vetoes.append(
                f"the module must open with the header of the prompt: `//! {pair.card} on "
                f"{pair.base}`, then `//! Shape: A` or `//! Shape: B`"
            )
        code = blank_inert(text, strings=True)
        if header["shape"] == "B" and not re.search(r"\bset_compromised\s*\(", code):
            vetoes.append(
                "a Shape B module calls set_compromised with the replicas it runs as real "
                "engines under a Byzantine identity, empty if none, before any engine starts"
            )
        if self.profile_name == "simplex":
            for name, cert_mock in sorted(simplex_types(self.repo).items()):
                if not cert_mock and re.search(rf"\b{re.escape(name)}\b", code):
                    vetoes.append(
                        f"the module names {name}, whose Simplex impl does not use the cert_mock "
                        "certificate scheme (D15)"
                    )
        if thin:
            try:
                if self.profile_name == "simplex":
                    check_simplex_cert_mock(self.repo, [thin.stem])
                else:
                    check_marshal_cert_mock(self.repo, [thin.stem])
            except Abort as error:
                vetoes.append(f"cryptography check (D15): {error}")
        return thin, vetoes

    def build(self, scaffold, name):
        command = self.build_command(scaffold)
        log = self.dir / "logs" / f"fuzz-build-{scaffold}-{name}.log"
        say(f"build: {shlex.join(command)}")
        code, tail = run_logged(command, log, self.repo, echo=False)
        # A build of a version that passed guard 2 may update Cargo.lock: that is the script's.
        self.own("Cargo.lock")
        binary = None
        if code == 0:
            if self.host is None:
                self.host = host_triple(self.fuzz_toolchain)
            binary = fuzz_binary(self.repo, self.package, self.host, scaffold)
            if binary is None:
                tail = tail + [f"statelens: the build left no binary {scaffold} for {self.host}"]
        return binary, command, tail, log

    def replay(self, card_id, binary, directory, control=False):
        """One replay of the empty input (section 18.8): (exit code or None, output)."""
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True)
        # SL/campaign/ is the agent's to write too: the canonical input is empty every time.
        self.empty.write_bytes(b"")
        env = dict(os.environ)
        env.pop("STATELENS_BYZANTINE", None)
        env.pop("STATELENS_REACH_CONTROL", None)
        env["STATELENS_REACH"] = "1"
        if control:
            env["STATELENS_REACH_CONTROL"] = "1"
        log = directory / "replay.log"
        code, _ = run_logged(
            [str(binary), str(self.empty)],
            log,
            directory,
            echo=False,
            timeout=REPLAY_TIMEOUT,
            env=env,
        )
        return code, first_run(log.read_text(errors="replace"), card_id)

    def attempt(self, pair, history, s0, attempt, feedback):
        """Steps 2.1 to 2.7 of one attempt. Returns its record."""
        module = pair.module
        # The agent finds the manifest as in S0; step 2.5 adds the scaffold's block.
        self.write_owned(self.manifest, s0.get(self.manifest))
        sa, sa_state = self.snapshot(), worktree_state(self.repo)
        sa_strays = self.strays(card_module(pair.card))
        live = self.live
        live.update(
            attempt=attempt,
            step="the agent's run",
            before=sa_strays,
            failures=[],
            kept=False,
            replays={},
            scaffold=None,
        )
        prompt = self.prompt(pair, len(history.events), attempt, feedback)
        code, log = self.run_agent(pair.key, attempt, prompt)
        swept, failures = self.sweep(pair, attempt, sa_strays)
        live.update(step="the checks", before=None, failures=failures)
        if failures:
            # The version a stray failure came from, for its triage, kept before anything
            # else runs.
            self.keep_version(pair.key, attempt, s0, self.snapshot())
        step = {
            "attempt": attempt,
            "changed": self.snapshot() != sa or worktree_state(self.repo) != sa_state,
            "swept": swept,
            "failures": failures,
            "version": None,
            "vetoes": [],
            "build": None,
            "unmarked": [],
            "beside": [],
        }
        if attempt and not step["changed"] and not failures:
            # The tree is the one the previous attempt was judged on: the pair ends (step 2.8).
            step["outcome"] = "no change, which ends the pair"
            return step
        outside = self.outside_scope()
        if outside:
            raise Abort(2, f"synthesis edited {outside[0]}; use a fresh clone")
        vetoes = [finding for _, finding in self.script_files(restore=True, s0=s0)]
        vetoes += [finding for _, finding in self.integrity()]
        thin, more = self.scaffold_checks(pair, s0)
        vetoes += more
        own = {f"{self.states}/{module}.rs"} | ({self.rel(thin)} if thin else set())
        step["unmarked"], step["beside"] = self.review_hunks(pair.card, s0, own)
        if code != 0:
            vetoes.insert(0, f"the agent exited with code {code}; see {self.rel(log)}")
        step["vetoes"] = vetoes
        if vetoes:
            step["outcome"] = (
                "NOT BUILT ("
                + ("the agent failed" if code != 0 else f"{len(vetoes)} veto(es)")
                + ")"
            )
            return step
        scaffold, base = pair.name, pair.base
        manifest = s0[self.manifest].decode()
        block = variant_bin_block(bin_blocks(manifest), base, self.manifest, name=scaffold)
        manifest = (manifest if manifest.endswith("\n") else manifest + "\n") + block
        self.write_owned(self.manifest, manifest.encode())
        live.update(step="the build", scaffold=scaffold)
        binary, command, tail, build_log = self.build(scaffold, attempt)
        if binary is None:
            step["build"] = (command, tail, build_log)
            step["outcome"] = "NOT BUILT (build failed)"
            return step
        # The version as built, kept before any replay: a failure a replay shows stays
        # reproducible when synthesis stops before the attempt ends.
        current = self.snapshot()
        diff = self.keep_version(pair.key, attempt, s0, current)
        directory = self.reach / pair.key / f"attempt-{attempt}"
        live["step"] = "the canonical replay"
        canonical = self.replay(pair.card, binary, directory / "canonical")
        live["replays"]["canonical"] = canonical[0]
        live["step"] = "the control replay"
        control = self.replay(pair.card, binary, directory / "control", control=True)
        live["replays"]["control"] = control[0]
        live["step"] = "the reach check"
        module_text = (self.repo / self.states / f"{module}.rs").read_text(errors="replace")
        stray = failures[0] if failures else None
        result = reach_verdict(
            history,
            module_text,
            canonical,
            control,
            stray=stray,
            diff=diff,
            labels={label for label, _ in self.labels},
        )
        if step["unmarked"]:
            result["annotations"].append("unmarked edit")
        if step["beside"]:
            result["annotations"].append("edit beside instrumentation")
        step["version"] = {
            "attempt": attempt,
            "files": {
                path: current.get(path)
                for path in set(s0) | set(current)
                if s0.get(path) != current.get(path)
            },
            "scaffold": scaffold,
            "base": base,
            "module": module_text,
            "canonical": canonical,
            "control": control,
            "diff": diff,
            "stray": stray,
            "unmarked": step["unmarked"],
            "beside": step["beside"],
            "result": result,
        }
        step["outcome"] = verdict_text(result)
        return step

    def keep_version(self, key, attempt, s0, current):
        """Keeps the version `current` beside the attempt's replays and swept files, so a
        failure stays reproducible after a restore: `attempt-<a>/version/`, a copy of every
        file it created or changed, which also holds what a diff cannot, and
        `attempt-<a>/version.diff`, its diff against S0. Returns the diff."""
        directory = self.reach / key / f"attempt-{attempt}"
        copies = directory / "version"
        if copies.exists():
            shutil.rmtree(copies)
        copies.mkdir(parents=True)
        for path, content in current.items():
            if s0.get(path) != content:
                target = copies / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
        diff = tree_diff(s0, current)
        (directory / "version.diff").write_text(diff)
        if self.live:
            self.live["kept"] = True
        return diff

    def preserve(self, error):
        """Before an exception, an interrupt included, restores S0 (section 18.6.2, Per
        pair): sweeps what a run of the scaffold left during a running agent, keeps the
        version a stray failure came from unless it is kept, and writes
        `attempt-<a>/interrupted.txt`: the step that stopped, the version, and each replay
        that finished, with the `run` and `replay` lines of one that failed and of one that
        stopped after it left a crash file, and the crash files of a revalidation that stopped.
        The replays' crash files and logs stay where they ran."""
        live = self.live
        if not live or live.get("attempt") is None:
            return
        card_id, key, attempt = live["card"], live["key"], live["attempt"]
        try:
            if live["before"] is not None:
                # The attempt's stray failures are what its swept/ holds, not what this sweep
                # returns: the sweep the attempt ran may have stopped after a move.
                self.sweep(live["pair"], attempt, live["before"])
                live["before"] = None
                swept = self.reach / key / f"attempt-{attempt}" / "swept"
                live["failures"] = sorted(
                    self.rel(path)
                    for path in swept.rglob("*")
                    if path.is_file() and STRAY_FAILURE.match(path.name)
                )
            if live["failures"] and not live["kept"]:
                self.keep_version(key, attempt, live["s0"], self.snapshot())
            cause = (
                "an interrupt"
                if isinstance(error, KeyboardInterrupt)
                else f"{type(error).__name__}: {error}"
            )
            lines = [
                f"{card_id} on {live['base']} attempt {attempt}: synthesis stopped during "
                f"{live['step']} ({cause}), and the pair's edits were restored to the tree "
                "before the pair.",
            ]
            if live["kept"]:
                lines.append(
                    "The version is version.diff, against that tree, and version/, a copy of "
                    "every file it created or changed: apply version.diff (`git apply`) and add "
                    f"`pub mod {live['module']};` to target_states/mod.rs first."
                )
            else:
                lines.append("No version was kept: none was replayed or left a stray failure.")
            lines += [f"Stray failure (finding candidate): {path}" for path in live["failures"]]
            directory = self.reach / key / f"attempt-{attempt}"
            for name, code in live["replays"].items():
                if code == 0:
                    lines.append(f"The {name} replay exited with code 0; its log is {name}/replay.log.")
                    continue
                how = "was killed" if code is None else f"exited with code {code}"
                crash = self.replay_input(directory / name)
                lines.append(
                    f"The {name} replay {how}, a failure; its log and any crash file are in "
                    f"{name}/. Its run and replay lines:"
                )
                lines += self.run_lines(live["scaffold"], crash, name == "control")
            # The replay that stopped may have left its crash file before it returned.
            for name in ("canonical", "control", "final"):
                if name in live["replays"] or live["step"] != f"the {name} replay":
                    continue
                crash = self.replay_input(directory / name)
                if crash != self.empty:
                    lines.append(
                        f"The {name} replay stopped after it left {crash.name}, a failure; its "
                        f"log and the crash file are in {name}/. Its run and replay lines:"
                    )
                    lines += self.run_lines(live["scaffold"], crash, name == "control")
            revalidation = live.get("revalidation")
            if revalidation and live["step"].startswith("the revalidation of "):
                other = live["step"][len("the revalidation of ") :]
                lines.append(
                    f"It stopped while revalidating {other}, whose replays are in "
                    f"{self.rel(revalidation)}/."
                )
                lines += [
                    f"That revalidation left {self.rel(path)}, a failure of {other}'s scaffold."
                    for path in sorted(revalidation.glob("*/*"))
                    if STRAY_FAILURE.match(path.name)
                ]
            directory.mkdir(parents=True, exist_ok=True)
            note = directory / "interrupted.txt"
            note.write_text("\n".join(lines) + "\n")
            say(f"{key}: stopped during {live['step']}; see {self.rel(note)}")
        except Exception as problem:
            say(f"warning: {key}: could not preserve attempt-{attempt}/: {problem}")

    def feedback(self, step, steps):
        """The next attempt's FEEDBACK (section 18.8)."""
        out = [f"Attempt {step['attempt']}: {step['outcome']}"]
        if step["vetoes"]:
            out += ["", "Vetoes and guard findings; this version was not built:"]
            out += [f"- {veto}" for veto in step["vetoes"]]
        if step["build"]:
            command, tail, _log = step["build"]
            out += ["", f"The build failed: {shlex.join(command)}", "Its last lines:"]
            out += ["    " + line for line in tail]
        if step["version"]:
            reach = reach_feedback(step["version"]["result"])
            if reach:
                out += ["", reach]
        if step["unmarked"]:
            out += ["", "Guard 4: these hunks lack the marker comment and are reported for review:"]
            out += [f"- unmarked edit: {hunk}" for hunk in step["unmarked"]]
        if step["swept"]:
            out += ["", "A run of the scaffold left files, moved aside; never run the scaffold:"]
            out += [f"- {path}" for path in step["swept"]]
        out += ["", "The attempts so far:"]
        out += [f"- attempt {item['attempt']}: {item['outcome']}" for item in steps]
        return "\n".join(out)

    def synthesize(self, pair):
        """Synthesizes one pair; returns its outcome. On any exception, an interrupt
        included, what the attempt holds is preserved first, then the pair's edits are
        restored and its line is dropped from target_states/mod.rs. Its S0 stays in pending/
        until then, or until its report is written, for a synthesis killed before either.
        The revalidation record its revalidation wrote (`revalidate`) is deleted when its
        report is written, and stays when its edits are restored."""
        module = pair.module
        text = pair.path.read_text()
        history = card_history(text)
        if (self.reach / pair.key).exists():
            self.archive(pair.key, synthesis_stamp())
        self.write_mod(module)
        s0 = self.snapshot()
        self.keep_pending(pair.key, s0)
        self.live = {
            "pair": pair,
            "card": pair.card,
            "base": pair.base,
            "key": pair.key,
            "module": module,
            "s0": s0,
            "attempt": None,
        }
        try:
            steps, versions, strays = [], [], []
            feedback = FIRST_ATTEMPT
            for attempt in range(REPAIR_ATTEMPTS + 1):
                step = self.attempt(pair, history, s0, attempt, feedback)
                steps.append(step)
                strays += step["failures"]
                if step["version"]:
                    versions.append(step["version"])
                verdict = step["version"]["result"]["verdict"] if step["version"] else None
                if verdict in ("REACHED", CRASH) or step["failures"] or not step["changed"]:
                    break
                feedback = self.feedback(step, steps)
            outcome = self.finish(pair, history, s0, steps, versions, strays)
        except BaseException as error:
            try:
                self.preserve(error)
            finally:
                self.restore(s0)
                self.drop_module(module)
                shutil.rmtree(self.pending, ignore_errors=True)
            if self.owed.exists():
                say(
                    f"synthesis: {pair.key}'s edits were restored after its revalidation "
                    "may have rewritten reports; the next synthesis revalidates every scaffold "
                    f"before any pair ({self.rel(self.owed)})"
                )
            raise
        finally:
            self.live = None
        # The report is written: the pair has ended, and no restore of its edits follows. The
        # record holds nothing but this pair's, since `revalidate_owed` deleted it before any
        # pair; a synthesis killed before this line keeps the pair (`recover`) and only
        # revalidates once more.
        self.owed.unlink(missing_ok=True)
        shutil.rmtree(self.pending, ignore_errors=True)
        return outcome

    def keep_pending(self, key, s0):
        """Keeps `s0` in pending/ until the pair ends: its key, its file list and a copy of
        each file not as in B. Written aside and renamed, so pending/ is whole or absent."""
        partial = self.reach / "pending.partial"
        for directory in (partial, self.pending):
            if directory.exists():
                shutil.rmtree(directory)
        for path, content in s0.items():
            if content != self.b_data.get(path):
                target = partial / "files" / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
        partial.mkdir(parents=True, exist_ok=True)
        state = {"pair": key, "files": sorted(s0)}
        (partial / "state.json").write_text(json.dumps(state, indent=1) + "\n")
        partial.rename(self.pending)

    def recover(self):
        """Once per run, before the guards (section 18.6.2): a pending/ whose pair has no
        report is the S0 of a synthesis that stopped without restoring that pair's edits,
        killed for example. Restores it and drops the pair's line from target_states/mod.rs,
        with a warning; then deletes pending/. A revalidation record the pair's revalidation
        wrote stays, for `revalidate_owed`."""
        if not self.pending.exists():
            return
        try:
            state = json.loads((self.pending / "state.json").read_text())
            key, files = state["pair"], state["files"]
            found = PAIR_KEY.fullmatch(key)
            if not found:
                raise ValueError(f"no pair key: {key!r}")
            s0 = {}
            for path in files:
                parts = path.split("/")
                if not (path == "Cargo.lock" or path.startswith(self.scope)) or any(
                    part in ("", ".", "..") for part in parts
                ):
                    raise ValueError(f"a path outside the scope: {path!r}")
                copy = self.pending / "files" / path
                s0[path] = copy.read_bytes() if copy.is_file() else self.b_data[path]
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            raise Abort(2, f"{self.rel(self.pending)} is unreadable ({error}); use a fresh clone")
        if not (self.reach / f"{key}.md").is_file():
            self.restore(s0)
            self.drop_module(pair_module(found["card"], found["base"]))
            say(
                f"warning: {key}: a synthesis stopped without restoring the pair's edits; "
                "they were restored"
            )
        shutil.rmtree(self.pending)

    def finish(self, pair, history, s0, steps, versions, strays):
        """Step 3: keep a version, check it, build it again, replay it once more, rerun the
        test gate when it changed the system under test, and write the report."""
        module = pair.module
        title = (front_matter(pair.path.read_text())[0] or {}).get("title", "")
        crashes = [version for version in versions if version["result"]["verdict"] == CRASH]
        if crashes:
            kept = crashes[-1]
        elif versions:
            kept = min(
                versions, key=lambda version: verdict_key(version["result"], version["attempt"])
            )
        else:
            kept = None
        outcome = {
            "pair": pair,
            "history": history,
            "title": title,
            "kept": kept,
            "steps": steps,
            "strays": strays,
            "result": None,
            "scaffold": None,
            "gate": None,
            "notes": [],
            "handover": None,
        }

        def not_built(note=None):
            self.restore(s0)
            self.drop_module(module)
            outcome["verdict"] = "NOT BUILT" + (" (stray failure)" if strays else "")
            if note:
                outcome["notes"].append(note)

        live = self.live
        live["step"] = "the finish"
        if kept is None:
            not_built()
        else:
            # The kept version's attempt; its version was kept before its replays.
            live.update(
                attempt=kept["attempt"],
                before=None,
                failures=list(strays),
                kept=True,
                replays={"canonical": kept["canonical"][0], "control": kept["control"][0]},
                scaffold=kept["scaffold"],
            )
            self.restore(s0, kept["files"])
            outside = self.outside_scope()
            if outside:
                raise Abort(2, f"synthesis edited {outside[0]}; use a fresh clone")
            problems = self.script_files(restore=True, s0=s0) + self.integrity()
            if problems:
                not_built(f"the kept version failed a guard: {problems[0][1]}")
            else:
                live["step"] = "the final build"
                binary, _command, _tail, log = self.build(kept["scaffold"], "final")
                if binary is None:
                    not_built(f"the kept version did not build again; see {self.rel(log)}")
                else:
                    directory = self.reach / pair.key / f"attempt-{kept['attempt']}" / "final"
                    live["step"] = "the final replay"
                    final = self.replay(pair.card, binary, directory)
                    live["replays"]["final"] = final[0]
                    live["step"] = "the finish"
                    result = reach_verdict(
                        history,
                        kept["module"],
                        kept["canonical"],
                        kept["control"],
                        final,
                        stray=kept["stray"],
                        diff=kept["diff"],
                        labels={label for label, _ in self.labels},
                    )
                    if kept["unmarked"]:
                        result["annotations"].append("unmarked edit")
                    if kept["beside"]:
                        result["annotations"].append("edit beside instrumentation")
                    if strays and result["verdict"] != CRASH:
                        # A later attempt left one and was not built: still a candidate.
                        result["annotations"].append("stray failure")
                    outcome["result"] = result
                    outcome["verdict"] = verdict_text(result)
                    outcome["scaffold"] = kept["scaffold"]
                    if result["verdict"] == CRASH:
                        # The failure's run and replay lines, kept with the version that
                        # failed (section 18.8), so the finding survives a restore.
                        outcome["handover"] = self.handover(outcome)
                        attempt_dir = self.reach / pair.key / f"attempt-{kept['attempt']}"
                        (attempt_dir / "replay.txt").write_text(
                            "\n".join(outcome["handover"]) + "\n"
                        )
                    roots = tuple(self.profile["roots"])
                    if any(path.startswith(roots) for path in kept["files"]):
                        live["step"] = "the test gate"
                        broken, log = self.gate(pair.key)
                        live["step"] = "the finish"
                        outcome["gate"] = (broken, log)
                        if broken:
                            self.restore(s0)
                            self.drop_module(module)
                            outcome["scaffold"] = None
                            outcome["verdict"] = "GATE FAILED" + (
                                f" (finding candidate in attempt-{kept['attempt']}/)"
                                if result["verdict"] == CRASH
                                else " (stray failure)"
                                if strays
                                else ""
                            )
                            outcome["notes"].append(
                                f"the version the gate restored is attempt-{kept['attempt']}/"
                                "version.diff, against the tree before the pair"
                            )
                    if outcome["scaffold"]:
                        self.revalidate(pair, s0, kept, outcome)
        outcome["diff"] = tree_diff(s0, self.snapshot()) if outcome["scaffold"] else ""
        (self.reach / f"{pair.key}.diff").write_text(outcome["diff"])
        self.write_report(outcome)
        return outcome

    def gate(self, key):
        """Guard 5: the test gate again; returns the tests that fail or no longer run and
        that the inventory does not record as failing, and the log. Output nextest_run
        cannot validate fails the gate."""
        command = gate_test_command(self.test_toolchain, self.profile_name)
        log = self.dir / "logs" / f"test-{key}.log"
        say(f"{key}: the kept version changed the system under test; running the test gate")
        code, _ = run_logged(command, log, self.repo, echo=False)
        run, problem = nextest_run(log.read_text(errors="replace"), code)
        if problem:
            return [f"(unusable output: {problem})"], log
        known = self.tests["failed"]
        missing = (self.tests["passed"] | known) - run["passed"] - run["failed"]
        return sorted((run["failed"] | missing) - known), log

    def revalidate(self, pair, s0, kept, outcome):
        """Revalidation (section 18.6.2, Finish): pairs share one tree, so when the kept
        version changed a file other than the pair's thin target, the manifest, mod.rs and
        Cargo.lock (`shared_paths`), which its own module always is, every other kept
        scaffold, the card's other pairs included, is built and replayed again. The first
        that no longer builds, stands worse than its report or gains or loses a crash
        restores the pair's edits, records NOT BUILT naming it, and is checked once more
        without them; otherwise each report takes its new verdict. Before the first report
        changes, the revalidation a restore of the pair's edits would then owe is recorded
        (`owe`), as `a rollback` of the pair; `synthesize` deletes it once the pair's report
        is written, and a restore before then, by an exception or by `recover`, leaves it."""
        now = self.snapshot()
        shared = self.shared_paths(
            pair, (path for path in set(s0) | set(now) if s0.get(path) != now.get(path))
        )
        others = sorted(other for other in self.standing if other != pair.key)
        if not shared or not others:
            return
        cause = f"{pair.key} changed {', '.join(shared)}"
        say(
            f"{pair.key}: the kept version changed {', '.join(shared)}; revalidating "
            f"{', '.join(others)}"
        )
        tag = f"after-{pair.key}"
        checked = []
        for other in others:
            before = report_verdict(self.standing[other]["report"])
            result, problem = self.check_scaffold(other, tag)
            if problem:
                break
            checked.append((other, before, result))
        else:
            self.owe("a rollback", pair.key, shared)
            for other, before, result in checked:
                self.restate(other, f"Revalidation after {pair.key}", cause, before, result)
            outcome["notes"].append(
                f"revalidated {', '.join(others)}: the kept version changed {', '.join(shared)}"
            )
            self.live["step"] = "the finish"
            return
        self.restore(s0)
        self.drop_module(pair.module)
        outcome["scaffold"] = None
        tags = [f"breaks {other}"]
        if outcome["result"]["verdict"] == CRASH:
            tags.append(f"finding candidate in attempt-{kept['attempt']}/")
        elif outcome["strays"]:
            tags.append("stray failure")
        outcome["verdict"] = f"NOT BUILT ({', '.join(tags)})"
        outcome["notes"].append(
            f"{problem}, so the pair's edits were restored; the version is "
            f"attempt-{kept['attempt']}/version.diff, against the tree before the pair"
        )
        # Its report holds again on the tree before the pair, unless something else broke it.
        tag = f"without-{pair.key}"
        result, still = self.check_scaffold(other, tag)
        if still:
            say(f"warning: {other}: {still}, also with {pair.key}'s edits restored")
            if result:
                cause = f"{pair.key}'s edits, which broke it, were restored"
                self.restate(other, f"Revalidation without {pair.key}", cause, before, result)
        outcome["notes"].append(
            f"{other} with the pair's edits restored: {still or verdict_text(result)}"
        )
        self.live["step"] = "the finish"

    def shared_paths(self, pair, paths):
        """The paths of `paths` other than the pair's thin target, the package manifest,
        target_states/mod.rs and Cargo.lock: a change to one of them can change another
        pair's scaffold (section 18.6.2, Finish). The pair's own module is one of them: the
        modules are public siblings of one crate, so one can use another's items, which no
        text scan can rule out; the thin target is a crate of its own, which no module can
        use. A sibling pair's thin target counts as shared."""
        own = {self.manifest, self.mod_rs, "Cargo.lock"}
        thin = f"{profile_fuzz_dir(self.profile_name)}/{pair.name}.rs"
        return sorted(path for path in set(paths) if path not in own and path != thin)

    def owe(self, what, key, shared):
        """Records in `revalidation.json`, before `what` undoes a pair whose diff changed the
        shared paths `shared`, the revalidation that undo owes (section 18.6.2, --redo); for
        `a rollback`, before a pair's revalidation rewrites reports, the one a restore of its
        edits would owe (Finish). Written aside and renamed, so the record is whole or absent."""
        if not shared:
            return
        owed = self.read_owed() or {"what": [], "undone": {}}
        if what not in owed["what"]:
            owed["what"].append(what)
        owed["undone"][key] = shared
        partial = self.owed.with_name(self.owed.name + ".partial")
        partial.write_text(json.dumps(owed, indent=1, sort_keys=True) + "\n")
        partial.replace(self.owed)

    def read_owed(self):
        """The revalidation `revalidation.json` records, or None; one that cannot be read
        exits with code 2."""
        if not self.owed.exists():
            return None
        try:
            owed = json.loads(self.owed.read_text())
            undos = owed["what"]
            if not (isinstance(undos, list) and undos and all(u in UNDO_TAGS for u in undos)):
                raise ValueError(f"unknown undo {undos!r}")
            for key, paths in owed["undone"].items():
                if not (isinstance(paths, list) and all(isinstance(p, str) for p in paths)):
                    raise ValueError(f"the paths of {key} are not a list of paths")
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            raise Abort(2, f"{self.rel(self.owed)} is unreadable ({error}); use a fresh clone")
        return owed

    def revalidate_owed(self):
        """Completes the revalidation `revalidation.json` records, this run's `--redo`'s or
        one an earlier synthesis did not finish or left with a rollback, then deletes the
        record (section 18.6.2, Once per run). A revalidation that stops leaves it, for the
        next synthesis."""
        owed = self.read_owed()
        if owed is None:
            return
        what = " and ".join(owed["what"])
        try:
            self.revalidate_undone(owed["undone"], what, UNDO_TAGS[owed["what"][0]])
        except BaseException:
            say(
                f"synthesis: the revalidation after {what} stopped; the next synthesis "
                f"completes it before any pair ({self.rel(self.owed)})"
            )
            raise
        # Code the revalidation replayed may have removed it.
        self.owed.unlink(missing_ok=True)

    def revalidate_undone(self, undone, what, tag):
        """Revalidation after an undo (section 18.6.2): `--redo` and the last check undo a
        pair's diff, its module and shared edits included, and a rollback restored a pair's
        edits after its revalidation rewrote reports, so every kept scaffold is built and
        replayed again, and its report takes the new verdict. No pair
        is rolled back for it. A scaffold that no longer builds is recorded NOT BUILT (no
        longer builds) and is not revalidated again; the last check's build still sees it.
        `undone` maps each undone pair's key to its shared paths."""
        changed = {key: paths for key, paths in sorted(undone.items()) if paths}
        others = sorted(self.standing)
        if not changed or not others:
            return
        cause = f"{what} undid " + "; ".join(
            f"{key}, which changed {', '.join(paths)}" for key, paths in changed.items()
        )
        say(f"synthesis: {cause}; revalidating {', '.join(others)}")
        # No pair is in progress: `preserve` has no attempt to keep.
        self.live = {"step": None}
        try:
            for other in others:
                before = report_verdict(self.standing[other]["report"])
                result, problem = self.check_scaffold(other, tag)
                if problem:
                    say(f"warning: {other}: {problem}")
                heading = f"Revalidation after {what}"
                self.restate(other, heading, cause, before, result, problem)
                if result is None:
                    del self.standing[other]
        finally:
            self.live = None

    def check_scaffold(self, key, tag):
        """Builds the kept scaffold of the pair `key` again and replays it, canonical,
        control and final, in `TS-NNNN_<base>/<tag>/`, or `<tag>.<stamp>/` when that
        exists, and keeps that directory in its entry. Returns (result, problem): the reach
        check's result, None when it does not build, and why it stands worse than its
        report, or None."""
        entry = self.standing[key]
        scaffold = entry["scaffold"]
        self.live.update(step=f"the revalidation of {key}", revalidation=None)
        binary, _command, _tail, log = self.build(scaffold, tag)
        if binary is None:
            return None, f"{key}'s scaffold {scaffold} no longer builds; see {self.rel(log)}"
        directory = self.reach / key / tag
        if directory.exists():
            # An earlier revalidation's, after a --redo, which a report may name: it stays.
            directory = directory.with_name(f"{tag}.{synthesis_stamp()}")
        entry["replays"] = directory
        # For `preserve`: where an interrupted revalidation left its replays.
        self.live["revalidation"] = directory
        replays = [
            self.replay(entry["card"], binary, directory / name, control=name == "control")
            for name in ("canonical", "control", "final")
        ]
        before = report_verdict(entry["report"])
        # A crash file an agent's run left stays its finding candidate (section 18.8).
        stray = None
        if before["verdict"] == CRASH and "stray failure" in before["annotations"]:
            stray = "the file its report names"
        path = self.repo / self.states / f"{entry['module']}.rs"
        result = reach_verdict(
            entry["history"],
            path.read_text(errors="replace") if path.is_file() else "",
            *replays,
            stray=stray,
            labels={label for label, _ in self.labels},
        )
        if stands_worse(before, result):
            return result, (
                f"{key}'s scaffold {scaffold} went from {before['text']} to "
                f"{verdict_text(result)}; see {self.rel(directory)}/"
            )
        return result, None

    def restate(self, key, heading, cause, before, result, problem=None):
        """Writes a revalidation into a kept scaffold's report: the new verdict on its
        Verdict line, and a section with the cause, the verdict before, the reasons, where
        the replays are and, for a CRASH, its crash line; the report's run and replay lines
        are rewritten for this check, the scaffold's latest, so they reproduce its failure
        or carry the placeholder. A scaffold that no longer builds, `result` None, is NOT
        BUILT (no longer builds), with `problem` as its reason."""
        entry = self.standing[key]
        now = verdict_text(result) if result else "NOT BUILT (no longer builds)"
        text = REPORT_VERDICT.sub(lambda _found: f"- Verdict: {now}", entry["report"], count=1)
        lines = [
            f"## {heading}",
            "",
            f"- Cause: {cause}",
            f"- Before: {before['text']}",
            f"- Now: {now}",
        ]
        if result:
            lines += [f"- Reason: {reason}" for reason in result["reasons"]]
            lines.append(f"- Replays: {self.rel(entry['replays'])}/")
            crash = result["crash"]
            if crash:
                lines.append(crash_text(crash))
            # A CRASH without a crash of its own is the stray failure the lines name already.
            if crash or result["verdict"] != CRASH:
                crash_file = (
                    self.replay_input(entry["replays"] / crash["replay"]) if crash else None
                )
                control = bool(crash) and crash["replay"] == "control"
                run, replay = self.run_lines(entry["scaffold"], crash_file, control)
                text = REPORT_RUN_BLOCK.sub(
                    lambda _found: f"## Run and replay\n\n```\n{run}\n{replay}\n```",
                    text,
                    count=1,
                )
        else:
            lines.append(f"- Reason: {problem}")
        entry["report"] = text.rstrip("\n") + "\n\n" + "\n".join(lines) + "\n"
        (self.reach / f"{key}.md").write_text(entry["report"])

    # Reports and the console.

    def crash_line(self, outcome):
        """What the console says of a kept CRASH (finding candidate), and the replay's
        crash file and whether it is the control's."""
        result = outcome["result"]
        kept = outcome["kept"]
        directory = self.reach / outcome["pair"].key / f"attempt-{kept['attempt']}"
        crash = result["crash"]
        if crash is None:
            stray = kept["stray"]
            return (
                f"a run of the agent's left {stray}, a finding candidate",
                self.repo / stray,
                False,
            )
        replay = crash["replay"]
        crash_file = self.replay_input(directory / replay)
        if replay == "control":
            note = (
                "failed in the control replay (STATELENS_REACH_CONTROL=1); the canonical input "
                "does not reproduce it"
            )
        else:
            note = (
                f"failed in the {replay} replay: the scaffold fails on its canonical input, which "
                "libFuzzer runs first, so its run line reproduces the failure at once"
            )
        return note, crash_file, replay == "control"

    def replay_input(self, directory):
        """The crash file a replay left in `directory`; every replay runs the empty input,
        so without a crash file it is the input."""
        files = sorted(directory.iterdir()) if directory.is_dir() else []
        files = [path for path in files if STRAY_FAILURE.match(path.name)]
        return files[0] if files else self.empty

    def write_report(self, outcome):
        pair, result, kept = outcome["pair"], outcome["result"], outcome["kept"]
        header = result["header"] if result else module_header(kept["module"] if kept else "")
        rows = [
            ("Card", f"{self.rel(pair.path)} ({outcome['title']})"),
            ("Profile", self.profile_name),
            ("Base commit", self.base),
            ("Shape", header.get("shape") or "-"),
            ("Base", pair.base),
            ("Scaffold", outcome["scaffold"] or "none"),
            ("Verdict", outcome["verdict"]),
        ]
        lines = [f"# {pair.card} on {pair.base}: {outcome['title']}", ""] + [
            f"- {key}: {value}" for key, value in rows
        ]
        lines += [f"- Note: {note}" for note in outcome["notes"]]
        if result:
            lines += [f"- Reason: {reason}" for reason in result["reasons"]]
            if result["control"]:
                lines.append(
                    f"- Control: {result['control']}"
                    + (f" ({result['control_reason']})" if result["control_reason"] else "")
                )
            canonical = result["replays"].get("canonical") or {}
            handoff = canonical.get("handoff")
            lines.append(f"- Handoff: {handoff['text'] if handoff else 'no handoff line'}")
            crash = result["crash"]
            if crash:
                lines.append(crash_text(crash))
            lines += [
                "",
                "## Stages",
                "",
                "| Stage | Outcome | Detail | Witness | Record |",
                "|---|---|---|---|---|",
            ]
            for k, stage in sorted(canonical.get("stages", {}).items()):
                record = stage.get("record")
                kind = record["kind"] if record else "-"
                bind = (
                    ",".join(f"{name}={value}" for name, value in record["bind"].items())
                    if record
                    else "-"
                )
                cell = (stage.get("detail") or "-").replace("|", "/")
                lines.append(f"| E{k} | {stage['outcome']} | {cell} | {kind} | {bind} |")
            sites = canonical.get("sites") or []
            lines += ["", "## Labels and sites read", ""]
            lines += [f"- {site}" for site in sites] or ["- none"]
        lines += ["", "## Attempts", ""]
        lines += [f"- attempt {step['attempt']}: {step['outcome']}" for step in outcome["steps"]]
        for step in outcome["steps"]:
            for veto in step["vetoes"]:
                lines.append(f"  - attempt {step['attempt']}: {veto}")
            for hunk in step["unmarked"]:
                lines.append(f"  - attempt {step['attempt']}: unmarked edit: {hunk}")
            for hunk in step["beside"]:
                lines.append(f"  - attempt {step['attempt']}: edit beside instrumentation: {hunk}")
        if outcome["strays"]:
            lines += ["", "## Stray failures (finding candidates)", ""]
            lines += [f"- {path}" for path in outcome["strays"]]
        if outcome["gate"]:
            broken, log = outcome["gate"]
            lines += ["", "## Test gate", "", f"- Log: {self.rel(log)}"]
            lines += [f"- Failed or no longer runs: {name}" for name in broken] or ["- passed"]
        if outcome["scaffold"]:
            run, replay = self.handover(outcome)
            lines += ["", "## Run and replay", "", "```", run, replay, "```"]
        elif outcome["handover"]:
            run, replay = outcome["handover"]
            lines += [
                "",
                "## Run and replay",
                "",
                f"The pair's edits were restored: apply attempt-{kept['attempt']}/version.diff "
                f"(`git apply`) and add `pub mod {pair.module};` to "
                "target_states/mod.rs first.",
                "",
                "```",
                run,
                replay,
                "```",
            ]
        if result:
            for name, replay in sorted(result["replays"].items()):
                shown = [
                    f"[statelens-reach] {pair.card} {line['text']}" for line in replay["lines"]
                ]
                lines += (
                    ["", f"## The {name} replay", "", "```"] + (shown or ["(no lines)"]) + ["```"]
                )
        text = "\n".join(lines) + "\n"
        (self.reach / f"{pair.key}.md").write_text(text)
        # The report as written is what a later pair's revalidation compares with.
        if outcome["scaffold"]:
            self.standing[pair.key] = {
                "scaffold": outcome["scaffold"],
                "card": pair.card,
                "base": pair.base,
                "module": pair.module,
                "history": outcome["history"],
                "report": text,
            }
        else:
            self.standing.pop(pair.key, None)

    def handover(self, outcome, scaffold=None):
        """The `run` and `replay` lines of a scaffold (section 18.6.2, Console)."""
        scaffold = scaffold or outcome["scaffold"]
        crash_file, control = None, False
        result = outcome["result"] if outcome else None
        if result and result["verdict"] == CRASH:
            _note, crash_file, control = self.crash_line(outcome)
        return self.run_lines(scaffold, crash_file, control)

    def run_lines(self, scaffold, crash_file=None, control=False):
        """The `run` line of a scaffold and the `replay` line of `crash_file`, by default a
        placeholder in its artifacts directory; `control` for a file of the control run.
        The paths are quoted for the shell, so a line runs as printed from a checkout whose
        path holds a space; the placeholder stays as it is."""
        here = f"cd {shlex.quote(str(self.repo / SL))} && "
        nightly = f"NIGHTLY_VERSION={self.fuzz_toolchain}"
        if crash_file is None:
            artifacts = self.repo / self.package / "artifacts" / scaffold
            crash_file = shlex.quote(str(artifacts)) + "/<crash file>"
        else:
            crash_file = shlex.quote(str(crash_file))
        env = ["STATELENS_REACH=1"] + (["STATELENS_REACH_CONTROL=1"] if control else [])
        env += [part for part in (self.profile["replay_env"], nightly) if part]
        run = f"{here}{nightly} just run {scaffold}"
        replay = f"{here}{' '.join(env)} just run {scaffold} {crash_file}"
        return run, replay

    # Driver.

    def last_check(self, outcomes):
        """Guards 1 to 3 once more over the whole tree (section 18.6.2, Last check)."""
        outside = self.outside_scope()
        if outside:
            raise Abort(2, f"synthesis edited {outside[0]}; use a fresh clone")
        for _path, finding in self.script_files(restore=True):
            say(f"warning: last check: {finding}")
        failing = {path for path, _ in self.integrity()}
        if not failing:
            return
        for outcome in reversed(outcomes):
            if not outcome["scaffold"]:
                continue
            pair = outcome["pair"]
            # The diff as this run wrote it: the reach directory is the agent's to write.
            diff = outcome["diff"]
            paths = [path for path, _ in diff_sections(diff)]
            if not failing & set(paths):
                continue
            self.undo(pair, diff, "the last check")
            outcome["scaffold"] = None
            outcome["verdict"] = "NOT BUILT"
            outcome["notes"].append(
                "the last check over the whole tree failed guard 3; the version is "
                f"attempt-{outcome['kept']['attempt']}/version.diff"
            )
            outcome["diff"] = ""
            (self.reach / f"{pair.key}.diff").write_text("")
            self.write_report(outcome)
            say(f"{pair.card:<10} {outcome['verdict']} (last check)   no scaffold on {pair.base}")
        for path, _finding in self.integrity():
            self.write(path, self.b_content(path))
        self.own()
        self.revalidate_owed()

    def last_build(self):
        """The last check's rebuild (section 18.6.2, Last check): every scaffold in the
        package, of this synthesis or an earlier one, is built once more on the tree as
        synthesis leaves it, also when the run synthesized no pair, so a scaffold an earlier
        synthesis recorded NOT BUILT (no longer builds), or one a helper template edited
        since broke, is never handed over while it does not build; one that does not build
        exits with code 2, naming it."""
        for scaffold in scaffold_targets(self.repo, self.profile_name):
            binary, _command, _tail, log = self.build(scaffold, "last")
            if binary is None:
                raise Abort(
                    2,
                    f"the last check: the scaffold {scaffold} does not build; see "
                    f"{self.rel(log)}, and undo the pair whose edits broke it with --redo or "
                    "use a fresh clone",
                )

    def run(self):
        self.check_campaign()
        selection = select_scaffolds(self.repo, self.sl_dir, self.profile_name, self.patterns)
        self.check_preconditions()
        cards = sorted({pair.path for pair in selection.pairs})
        if lint_paths(cards, registry_files(self.sl_dir)):
            raise Abort(2, "a selected card has lint problems (above); fix them before synthesis")
        say(f"{'cards':<10} {selection.tracked} tracked, {selection.local} local")
        self.run_state = worktree_state(self.repo)
        self.reach.mkdir(parents=True, exist_ok=True)
        self.load_baseline()
        self.load_campaign()
        try:
            return self.run_pairs(selection)
        finally:
            # Code the agent wrote also runs after its last run: replays and the test gate.
            self.seal()

    def run_pairs(self, selection):
        self.recover()
        problems = self.outside_scope()
        problems += [path for path, _ in self.script_files()]
        problems += [path for path, _ in self.integrity()]
        if problems:
            raise Abort(
                2,
                f"the checkout differs from the synthesis baseline: {problems[0]}; use a fresh "
                "clone",
            )
        if self.redo:
            self.redo_pairs([pair for pair in selection.pairs if pair.skip])
        self.load_standing()
        self.declare()
        self.empty.write_bytes(b"")
        self.labels = campaign_labels(self.repo, self.profile_name)
        # Before any pair, whatever is selected: an earlier synthesis's included.
        self.revalidate_owed()
        outcomes = []
        for pair in selection.pairs:
            if pair.skip and not self.redo:
                say(f"{pair.card:<10} skipped: {pair.skip}")
                continue
            outcome = self.synthesize(pair)
            outcomes.append(outcome)
            scaffold = outcome["scaffold"] or f"no scaffold on {pair.base}"
            line = f"{pair.card:<10} {outcome['verdict']}   {scaffold}"
            if outcome["scaffold"] and outcome["result"]["verdict"] == CRASH:
                line += "; " + self.crash_line(outcome)[0]
            elif outcome["strays"] and not (
                outcome["result"] and outcome["result"]["verdict"] == CRASH
            ):
                line += f"; a run of the agent's left {outcome['strays'][0]}, a finding candidate"
            say(line)
        self.last_check(outcomes)
        self.last_build()
        final = select_scaffolds(self.repo, self.sl_dir, self.profile_name, self.patterns)
        scaffolds = [pair for pair in final.pairs if pair.scaffold]
        say(
            f"{'synthesis':<10} {len(outcomes)} pair(s), {len(scaffolds)} scaffold(s); reports in "
            f"{SL}/campaign/reach/"
        )
        current = {outcome["scaffold"]: outcome for outcome in outcomes if outcome["scaffold"]}
        for pair in scaffolds:
            run, replay = self.handover(current.get(pair.scaffold), pair.scaffold)
            say(f"{'run':<10} {run}")
            say(f"{'replay':<10} {replay}")
        return 0 if scaffolds else 3


def first_panic(lines):
    """Returns the first StateLens violation, or else the first panic message."""
    for line in lines:
        if "[statelens][" in line:
            return line.strip()
    for index, line in enumerate(lines):
        if "panicked at" in line:
            message = lines[index + 1].strip() if index + 1 < len(lines) else ""
            return f"{line.strip()} {message}".strip()
    return None


def cmd_reach_verdict(args):
    """The reach verdict of one scaffold from replays captured outside synthesis (SPEC
    section 18.8): the card's History, the module's header and each replay's exit code
    and output, through the same `first_run` and `reach_verdict` the synthesis uses.
    Prints the verdict, then the reasons, annotations and control reason one per line.
    Exit code 0 for REACHED, 1 otherwise."""
    history = card_history(Path(args.card).read_text(errors="replace"))
    module = Path(args.module).read_text(errors="replace")

    def replay(path, code):
        if path is None:
            return None
        return code, first_run(Path(path).read_text(errors="replace"), history.id)

    result = reach_verdict(
        history,
        module,
        replay(args.canonical, args.canonical_code),
        replay(args.control, args.control_code),
    )
    print(verdict_text(result), flush=True)
    for reason in result["reasons"]:
        print(f"reason: {reason}")
    for annotation in result["annotations"]:
        print(f"annotation: {annotation}")
    if result["control_reason"]:
        print(f"control: {result['control_reason']}")
    return 0 if result["verdict"] == "REACHED" else 1


def main(argv):
    parser = Parser(
        prog="statelens.py",
        description=(
            "StateLens for Simplex, marshal and qmdb: check the invariant registries, "
            "extract invariants with an agent, query the knowledge base, and run campaigns "
            "(see statelens/docs/SPEC.md)."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    lint = commands.add_parser(
        "lint",
        help="check invariant files and target-state cards",
        description=(
            "Check invariant files and target-state cards (SPEC sections 4.6 and 18.3). "
            "Without PATH, checks every file in invariants/, invariants.local/, "
            "false-invariants/, target-states/ and target-states.local/. Exit code 0 when "
            "clean, 3 on problems."
        ),
    )
    lint.add_argument("paths", nargs="*", metavar="PATH", help="an invariant file or a card")
    excerpts = commands.add_parser(
        "excerpts",
        help="write the cited source lines into invariant files and cards",
        description=(
            "Write the Source excerpts section of invariant files and target-state cards "
            "from their pinned citations (SPEC section 4.3). Without PATH, every file lint "
            "checks by default. With --check, only report the files whose section is missing "
            "or out of date (exit code 3)."
        ),
    )
    excerpts.add_argument("paths", nargs="*", metavar="PATH", help="an invariant file or a card")
    excerpts.add_argument("--check", action="store_true", help="report, do not write")
    extract = commands.add_parser(
        "extract",
        help="turn sources into invariants of a registry (Phase 1)",
        description=(
            "Run the agent on sources of one kind and write new invariants to "
            "invariants/<registry>/, or for kb, which reads knowledge-base findings, to the "
            f"git-ignored {LOCAL_INVARIANTS}/<registry>/ (SPEC section 6). With --states, "
            "write target-state cards to target-states/<registry>/, or to the git-ignored "
            f"{LOCAL_STATES}/<registry>/ when the source is not public (SPEC section 18.4)."
        ),
    )
    extract.add_argument("--agent", choices=AGENTS, help="agent CLI (default: STATELENS_AGENT)")
    extract.add_argument(
        "--registry",
        choices=SUBSYSTEMS,
        default="simplex",
        help="registry of the new invariants (default: simplex)",
    )
    extract.add_argument(
        "--number",
        type=int,
        metavar="N",
        help=(
            "write N invariants, the ones the sources justify best; fewer when they justify "
            "fewer (default: as many as they justify)"
        ),
    )
    extract.add_argument(
        "--states",
        action="store_true",
        help="write target-state cards instead; the registry is simplex or marshal",
    )
    extract.add_argument(
        "--local",
        action="store_true",
        help=f"with --states, write to the git-ignored {LOCAL_STATES}/ (a private source)",
    )
    extract.add_argument(
        "kind", choices=STATE_KINDS, help="source kind; test and text need --states"
    )
    extract.add_argument(
        "sources",
        nargs="*",
        metavar="SOURCE",
        help=(
            "a source (SPEC sections 6.1 and 18.4); for kb, a corpus root (default: "
            "STATELENS_KB), or with --states one finding identifier"
        ),
    )
    lint_examples = commands.add_parser(
        "lint-examples",
        help="check that the worked analyses still name real code",
        description=(
            "Check the worked analyses in examples/: plain ASCII, and every code name they "
            "cite still exists in the instrumented subsystems."
        ),
    )
    lint_examples.add_argument("paths", nargs="*", metavar="PATH", help="an example file")
    lint_plan = commands.add_parser(
        "lint-plan",
        help="check an instrumentation plan against its own claims",
        description=(
            "Check campaign/plan.md (SPEC section 11): a section per registry invariant, a "
            "Status of bound, partial or unbound, the fields that status needs, a commit-site "
            "ledger that supports a `bound`, an assertion in the source and function of every "
            "entry the ledger calls checked, and an assertion in the code for every invariant "
            "the plan claims to bind. Exit code 0 when clean, 3 on problems."
        ),
    )
    lint_plan.add_argument(
        "--profile",
        choices=tuple(PROFILES),
        help=(
            "profile whose registries the plan must cover (default: the profile in "
            "campaign/meta.json, else simplex)"
        ),
    )
    lint_plan.add_argument("paths", nargs="*", metavar="PATH", help="a plan file")
    lint_prompts_parser = commands.add_parser(
        "lint-prompts",
        help="check that the specification still quotes the prompts verbatim",
        description=(
            "Compare every file in prompts/ with its copy in section 13 of the "
            "specification, which claims to reproduce them verbatim (SPEC section 13). "
            "Exit code 0 when clean, 3 on problems."
        ),
    )
    lint_prompts_parser.add_argument(
        "--write",
        action="store_true",
        help="rewrite the copies in the specification from the prompt files",
    )
    clean = commands.add_parser(
        "clean",
        help="undo what a campaign wrote to this checkout",
        description=(
            "Delete the files a campaign or a synthesis created and restore the paths they "
            "edit to HEAD, so a checkout can be reused (SPEC section 5.4). Prints what it "
            "would do and needs --yes to act."
        ),
    )
    clean.add_argument("--yes", action="store_true", help="actually do it")
    kb = commands.add_parser(
        "kb",
        help="query the knowledge base (the instrumenter uses it too)",
        description="The retrieval interface of SPEC section 5.6.",
    )
    kb.add_argument(
        "--registry",
        choices=SUBSYSTEMS,
        default="simplex",
        help="registry whose module filter applies (default: simplex)",
    )
    registry_flag = argparse.ArgumentParser(add_help=False)
    # SUPPRESS so that `kb --registry R find ...` and `kb find --registry R ...` agree:
    # without it the subparser default would overwrite the outer value.
    registry_flag.add_argument("--registry", choices=SUBSYSTEMS, default=argparse.SUPPRESS)
    queries = kb.add_subparsers(dest="query", required=True, parser_class=lambda **kw: Parser(parents=[registry_flag], **kw))
    queries.add_parser("modules", help="every module value in scope, with a count")
    kb_find_parser = queries.add_parser("find", help="findings whose claim fields match")
    kb_find_parser.add_argument("terms", nargs="*", metavar="TERM", help="a term to match")
    kb_cites_parser = queries.add_parser("cites", help="findings that cite a path in the code")
    kb_cites_parser.add_argument("prefix", metavar="PATH", help="a file or directory path")
    kb_grep_parser = queries.add_parser("grep", help="snippets of the state-bearing sections")
    kb_grep_parser.add_argument("text", metavar="TEXT", help="a case-insensitive literal")
    kb_show_parser = queries.add_parser("show", help="one finding's claim block or section")
    kb_show_parser.add_argument("identifier", metavar="IDENTIFIER")
    # Section names contain spaces ("Root Cause"), so accept them unquoted too.
    kb_show_parser.add_argument("section", nargs="*", metavar="SECTION")
    kb_search_parser = queries.add_parser(
        "search",
        help="snippets ranked by meaning and words: findings, design documents, comments, docs",
    )
    kb_search_parser.add_argument("question", nargs="+", metavar="QUESTION", help="plain words")
    kb_search_parser.add_argument(
        "--path", action="append", metavar="PATH", help="only code and docs under PATH (repeatable)"
    )
    kb_search_parser.add_argument(
        "--source", action="append", choices=SEARCH_SOURCES, help="only these sources (repeatable)"
    )
    kb_search_parser.add_argument("--tests", action="store_true", help="include test code")
    kb_search_parser.add_argument(
        "-k", "--limit", type=int, default=SEARCH_LIMIT, help=f"hits to print (default {SEARCH_LIMIT})"
    )
    search_index = commands.add_parser(
        "search-index",
        help="build or update the search index of `kb search`",
        description=(
            "Indexes the findings' state-bearing sections, the kb/ and context/ documents of "
            "the knowledge base, and the comments, doc comments and Markdown of this "
            "repository at HEAD, in extract/search/ (SPEC section 5.10). Downloads the model "
            "when it is not on disk yet; embeds on the CPU."
        ),
    )
    search_index.add_argument(
        "--rebuild", action="store_true", help="embed every chunk again instead of updating"
    )
    code = commands.add_parser(
        "code",
        help="identify entities in the code: definitions, references, callers, callees",
        description=(
            "Queries the SCIP index of the crate the last `code build` or campaign indexed "
            "(SPEC section 5.7): consensus for the simplex and marshal profiles, storage "
            "for qmdb. Names collide -- in consensus `proposal` is five different methods "
            "-- so a symbol index answers what text search cannot. Test sites are hidden "
            "unless --tests is passed, because most of each crate is test code."
        ),
    )
    code_queries = code.add_subparsers(dest="query", required=True, parser_class=Parser)
    code_build = code_queries.add_parser("build", help="write the index (several minutes)")
    code_build.add_argument(
        "--subsystem",
        choices=SUBSYSTEMS,
        help=(
            "subsystem whose campaign the index serves (default: the campaign's profile, "
            "else the crate of the current index, else simplex)"
        ),
    )
    for name, helptext in (
        ("defs", "where a name is defined, with the extent of each definition"),
        ("refs", "every reference to a name, definition included"),
        ("callers", "call sites outside the definition, with the enclosing function"),
        ("callees", "what a definition references inside its own extent"),
    ):
        query = code_queries.add_parser(name, help=helptext)
        query.add_argument("name", metavar="NAME", help="a display name or part of a symbol")
        query.add_argument(
            "--tests", action="store_true", help="include sites in test code"
        )
        query.add_argument(
            "--all",
            action="store_true",
            help="for callees, include functions defined outside this crate",
        )
    coverage = commands.add_parser(
        "coverage",
        help="coverage of the corpora the StateLens targets built",
        description=(
            "Replay each StateLens target's corpus under coverage instrumentation and "
            "write an HTML report per target plus one merged over all of them (SPEC "
            "section 7.13). Names a profile (`simplex`, `marshal`, `qmdb`) or single targets; "
            "with neither, every target of the default profile. A profile's targets are its "
            "variants and its scaffolds. A target with no corpus is skipped."
        ),
    )
    coverage.add_argument(
        "--profile",
        choices=tuple(PROFILES),
        help="profile whose targets to cover (default: simplex, or the one a name implies)",
    )
    coverage.add_argument(
        "targets", nargs="*", metavar="TARGET", help="a profile name or a StateLens target"
    )
    test_gate = commands.add_parser(
        "test-gate",
        help="run only the campaign's test gate on this checkout",
        description=(
            "Runs the test gate's command (SPEC section 7.7) on the checkout as it "
            "stands, for example after fixing an instrumented checkout by hand."
        ),
    )
    test_gate.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        help="profile whose tests to run (default: the one in campaign/meta.json)",
    )
    targets = commands.add_parser(
        "targets",
        help="the StateLens targets a profile builds, one per line",
        description=(
            "Used by `just fuzz <profile>` to run every target of a profile. With "
            "--state-reaching, the scaffolds of the selected target-state cards instead "
            "(SPEC section 18.9)."
        ),
    )
    targets.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default="simplex",
        help="profile whose targets to list (default: simplex)",
    )
    targets.add_argument(
        "--match",
        action="append",
        metavar="GLOB",
        help=(
            "only the targets this shell pattern names, by variant or original name; with "
            "--state-reaching, a TS-NNNN pattern names a card and any other a base (repeatable)"
        ),
    )
    targets.add_argument(
        "--state-reaching",
        action="store_true",
        help="list the scaffolds of the selected cards whose thin target exists",
    )
    ast = commands.add_parser(
        "ast",
        help="read the syntax tree: which sites write an entity, and what comments say",
        description=(
            "Queries `rust-analyzer parse` (SPEC section 5.8). The code index says "
            "where an entity occurs; the syntax tree says whether a site reads or "
            "writes it, and which item a comment documents. No cargo and no index "
            "are needed, though an index narrows which files are parsed."
        ),
    )
    ast_queries = ast.add_subparsers(dest="query", required=True, parser_class=Parser)
    ast_sites = ast_queries.add_parser(
        "sites",
        help=(
            "where a field or binding is written, handed to a method or a &mut borrow "
            "(maybe), initialized and read"
        ),
    )
    ast_sites.add_argument("name", metavar="NAME", help="a field or variable name")
    ast_sites.add_argument(
        "paths", nargs="*", metavar="PATH", help="files or directories to parse"
    )
    ast_sites.add_argument("--tests", action="store_true", help="include test code")
    ast_sites.add_argument(
        "--writes-only",
        action="store_true",
        help="only the sites that assign it or hand it out (write, maybe and macro)",
    )
    ast_notes_parser = ast_queries.add_parser(
        "notes", help="comment blocks matching a pattern, with the item each documents"
    )
    ast_notes_parser.add_argument(
        "--pattern",
        default=AST_NOTE_DEFAULT,
        help="case-insensitive regular expression (default: the beacon words)",
    )
    ast_notes_parser.add_argument(
        "paths", nargs="*", metavar="PATH", help="files or directories to parse"
    )
    ast_notes_parser.add_argument("--tests", action="store_true", help="include test code")
    campaign = commands.add_parser(
        "campaign",
        help="instrument this checkout, build the StateLens targets, run the test gate (Phase 2)",
        description=(
            "Instrument this checkout in place for the profile's registries, build its "
            "StateLens fuzz targets and run the test gate (SPEC sections 7 and 8). A READY "
            "campaign prints the command that runs each target and the command that "
            "replays a crash."
        ),
    )
    campaign.add_argument("--agent", choices=AGENTS, help="agent CLI (default: STATELENS_AGENT)")
    campaign.add_argument(
        "--profile",
        choices=tuple(PROFILES),
        default="simplex",
        help="what the campaign binds, instruments, builds and tests (default: simplex)",
    )
    campaign.add_argument(
        "--invariants",
        action="append",
        metavar="LIST",
        help=(
            "bind only these invariants: comma-separated <registry>/INV-NNNN ids, or bare "
            "INV-NNNN ids when the profile binds one registry (repeatable)"
        ),
    )
    campaign.add_argument("--stop-after", choices=STOP_STEPS, help="stop after this step")
    synthesize = commands.add_parser(
        "synthesize",
        help=(
            "write, build and check one scaffold per target-state card and base (after a "
            "campaign)"
        ),
        description=(
            "On the checkout a campaign of the profile instrumented, have the agent write one "
            "scaffold per selected card and base, a fuzz target that drives the card's History "
            "on that base target, and check it with fixed replays (SPEC section 18.6). Exit "
            "code 0 when a scaffold exists for the selection, 1 usage or nothing selected, 2 a "
            "failed precondition or an edit outside the edit contract, 3 no scaffold built."
        ),
    )
    synthesize.add_argument(
        "--agent", choices=AGENTS, help="agent CLI (default: STATELENS_AGENT)"
    )
    synthesize.add_argument(
        "--profile",
        choices=tuple(PROFILES),
        help="simplex or marshal (default: the profile in campaign/meta.json)",
    )
    synthesize.add_argument(
        "--match",
        action="append",
        metavar="GLOB",
        help="a TS-NNNN pattern names cards, any other pattern names bases (repeatable)",
    )
    synthesize.add_argument(
        "--redo",
        action="store_true",
        help="undo and synthesize again the selected pairs (card, base) that have a report",
    )
    reach = commands.add_parser(
        "reach-verdict",
        help="the reach verdict of a scaffold from captured replays",
        description=(
            "Compute the reach verdict (SPEC section 18.8) of one scaffold from a card, "
            "the scaffold module and the captured output of its canonical replay and, "
            "optionally, its control replay, as the synthesis computes it. Exit code 0 "
            "for REACHED, 1 otherwise."
        ),
    )
    reach.add_argument("--card", required=True, help="the target-state card (TS-NNNN.md)")
    reach.add_argument("--module", required=True, help="the scaffold module (tsNNNN.rs)")
    reach.add_argument(
        "--canonical", required=True, help="the canonical replay's output, with its stderr"
    )
    reach.add_argument(
        "--canonical-code", type=int, default=0, help="the canonical replay's exit code"
    )
    reach.add_argument("--control", help="the control replay's output, if it ran")
    reach.add_argument(
        "--control-code", type=int, default=0, help="the control replay's exit code"
    )
    args = parser.parse_args(argv)

    try:
        if args.command == "lint":
            return cmd_lint(args)
        if args.command == "excerpts":
            return cmd_excerpts(args)
        if args.command == "extract":
            return cmd_extract(args)
        if args.command == "kb":
            return cmd_kb(args)
        if args.command == "search-index":
            return cmd_search_index(args)
        if args.command == "targets":
            return cmd_targets(args)
        if args.command == "test-gate":
            return cmd_test_gate(args)
        if args.command == "coverage":
            return cmd_coverage(args)
        if args.command == "code":
            return cmd_code(args)
        if args.command == "ast":
            return cmd_ast(args)
        if args.command == "clean":
            return cmd_clean(args)
        if args.command == "lint-examples":
            return cmd_lint_examples(args)
        if args.command == "lint-plan":
            return cmd_lint_plan(args)
        if args.command == "lint-prompts":
            return cmd_lint_prompts(args)
        if args.command == "reach-verdict":
            return cmd_reach_verdict(args)
        if args.command == "synthesize":
            return Synthesis(args).run()
        return Campaign(args).run()
    except Abort as error:
        say(f"error: {error}")
        return error.code
    except KeyboardInterrupt:
        say("interrupted")
        return 130


def interrupt(_signum, _frame):
    """A supervisor's SIGTERM or a closed terminal's SIGHUP takes the interrupt's path: the
    command that runs, in its own process group, is killed with what it started, and a
    pair's edits are restored, instead of the script dying and the command living on."""
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGHUP, interrupt)
    sys.exit(main(sys.argv[1:]))
