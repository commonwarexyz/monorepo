#!/usr/bin/env python3
"""StateLens for Simplex and marshal: lint invariants, extract them with an agent, run campaigns.

Invariants live in one registry per subsystem (invariants/simplex/, invariants/marshal/).
A campaign profile (simplex or marshal) selects the registries it binds, the code it
instruments, the StateLens fuzz targets it builds and the tests it runs; the operator runs
the targets afterwards. See consensus/fuzz/statelens/docs/SPEC.md. Standard library only;
Python 3.9 or later.
"""

import argparse
import collections
import datetime
import difflib
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
from pathlib import Path

# Subproject root, relative to the repository root.
SL = Path("consensus/fuzz/statelens")

AGENTS = ("claude", "codex")
KINDS = ("issue", "design", "comment", "spec", "paper")
SOURCE_KINDS = ("human",) + KINDS
# SPEC section 4.2: the registries and the scope values each of them allows.
SUBSYSTEMS = ("simplex", "marshal")
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
}
ALL_SCOPES = tuple(dict.fromkeys(scope for name in SUBSYSTEMS for scope in SCOPES[name]))
REQUIRED_KEYS = ("id", "title", "source_kind", "source_ref", "scope")
REQUIRED_SECTIONS = ("Statement", "Rationale", "Evidence")
FILE_NAMES = {
    "invariants": re.compile(r"^INV-\d{4,}\.md$"),
    "false-invariants": re.compile(r"^FALSE-\d{4,}\.md$"),
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
MODULE_FILTER = {"simplex": "consensus/simplex", "marshal": "consensus/marshal"}

CONFIG_KEYS = (
    "STATELENS_AGENT",
    "STATELENS_CLAUDE_MODEL",
    "STATELENS_CODEX_MODEL",
    "STATELENS_TEST_TOOLCHAIN",
    "STATELENS_FUZZ_TOOLCHAIN",
    "STATELENS_KB",
    "STATELENS_BEACONS",
    "STATELENS_AUDIT",
)

STOP_STEPS = ("materialize", "index", "instrument", "build")
BATCH_SIZE = 8
REPAIR_ATTEMPTS = 3
ERROR_LINES = 150

# The existing simplex targets a campaign derives StateLens variants from. Only
# `cert_mock` targets may be listed (R-P2-4), and the list is curated rather
# than "every target in the directory" because simplex has twenty-one of them
# and most drive inputs StateLens has no interest in. Marshal derives from all
# of its targets, so its entry is None.
SIMPLEX_VARIANTS = (
    "simplex_cert_mock",
    "simplex_cert_mock_twins_campaign",
    "simplex_cert_mock_twins_mutator",
)
STATELENS_RS = "consensus/src/simplex/statelens.rs"
FUZZ_MANIFEST = "consensus/fuzz/simplex/Cargo.toml"
CORE_SIMPLEX = "consensus/fuzz/core/src/simplex.rs"
MARSHAL_TARGETS = "consensus/fuzz/marshal/fuzz_targets"
MARSHAL_MANIFEST = "consensus/fuzz/marshal/Cargo.toml"
MARSHAL_SRC = "consensus/fuzz/marshal/src"
PLAN = "consensus/fuzz/statelens/campaign/plan.md"
# Worked analyses the Phase 2 prompts point at. They name real functions and fields, so
# `lint-examples` checks those still exist; a document declares its non-code terms with a
# `<!-- statelens-lint: not-code: a, b -->` line.
EXAMPLES = "consensus/fuzz/statelens/examples"
# Section 13 of the specification reproduces every prompt verbatim; `lint-prompts`
# compares the two and `--write` refreshes the copies from the files.
# Dependencies and the standard library are not what a campaign fuzzes, so the
# workspace summary of `coverage` leaves them out.
COVERAGE_DEPENDENCIES = r"(^|/)(\.cargo/registry|\.rustup|rustc/|library/std|/rustc)"
SPEC_DOC = "consensus/fuzz/statelens/docs/SPEC.md"
# The closing fence is the one before the next heading or rule, so a prompt that quotes a
# fence of its own does not end its block early and `--write` cannot append to it forever.
SPEC_PROMPT = re.compile(
    r"^### 13\.\d+ `(prompts/[^`]+)`\n\n~~~markdown\n(.*?)\n~~~\n(?=\n*(?:#|---\n|\Z))",
    re.M | re.S,
)
NOT_CODE = re.compile(r"<!--\s*statelens-lint:\s*not-code:\s*(.*?)\s*-->", re.S)
CODE_WORD = re.compile(r"`([a-z_][a-z0-9_]*_[a-z0-9_]+)`")
# Everything a campaign creates (deleted by `clean`) or edits (restored by `clean`).
# The marshal variants are found by glob, because their names come from the targets.
CREATED_PATHS = (STATELENS_RS,)
EDITED_PATHS = (
    "consensus/src/simplex/mod.rs",
    "consensus/Cargo.toml",
    "Cargo.lock",
    "consensus/fuzz/core/src/lib.rs",
    "runtime/src/deterministic.rs",
    FUZZ_MANIFEST,
    MARSHAL_MANIFEST,
    "consensus/fuzz/marshal/src/marshal/end_to_end/scenario.rs",
)
SIMPLEX_TEST_FILTER = (
    "(test(/^simplex::tests::/) & not test(/::test_twins/)) | test(/^simplex::statelens::/)"
)

# SPEC section 5.5. Beacon components are (ACTOR, ACTOR_DIR, subsystem). `target` is the
# StateLens target made from SL/runtime/target.rs, or None when the campaign builds one
# variant of every target of the package (SPEC section 8.3, edit M1). `replay_env` goes
# before NIGHTLY_VERSION in the replay command.
PROFILES = {
    "simplex": {
        "registries": ("simplex",),
        "roots": ("consensus/src/simplex/",),
        "warn": ("consensus/src/simplex/mocks/", "consensus/src/simplex/scheme/"),
        "components": (
            ("voter", "consensus/src/simplex/actors/voter", "simplex"),
            ("batcher", "consensus/src/simplex/actors/batcher", "simplex"),
            ("resolver", "consensus/src/simplex/actors/resolver", "simplex"),
        ),
        "package": "consensus/fuzz/simplex",
        "variants": SIMPLEX_VARIANTS,
        "test_filter": SIMPLEX_TEST_FILTER,
        "replay_env": "CONSENSUS_FUZZ_LOG=1",
    },
    "marshal": {
        "registries": ("simplex", "marshal"),
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
        "variants": None,
        "test_filter": SIMPLEX_TEST_FILTER + " | test(/^marshal::/)",
        "replay_env": "",
    },
}

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

# SPEC section 7.2, edits 2, 3 and 6 to 8, made by both profiles: (file, the only line
# equal to the anchor, "after" or "before", text).
ANCHORS = (
    ("consensus/src/simplex/mod.rs", "pub mod types;", "after", "pub mod statelens;"),
    ("consensus/Cargo.toml", "thiserror.workspace = true", "after", "sancov.workspace = true"),
    (
        "consensus/fuzz/core/src/lib.rs",
        "    let compromised = case.compromised.iter().copied().collect::<HashSet<_>>();",
        "after",
        HOOK,
    ),
    ("runtime/src/deterministic.rs", "impl From<Config> for Runner {", "before", FRESH_RUN_STATIC),
    ("runtime/src/deterministic.rs", "    pub fn new(cfg: Config) -> Self {", "after", FRESH_RUN_CALL),
)

# SPEC section 8.3, edit M1: the two insertions that turn a marshal target into its variant.
VARIANT_START = re.compile(r"^    fuzz_target!\(\|input: [A-Za-z0-9_]+\| \{$")
VARIANT_END = "    });"
VARIANT_RESET = "        commonware_consensus::simplex::statelens::reset();"
VARIANT_CLEAR = "        commonware_consensus::simplex::statelens::clear_compromised();"
# Edit M2: the keys of the original [[bin]] block that a variant's block copies, in order.
BIN_KEYS = ("test", "doc", "bench", "required-features")
# Edit M3.
WEDGE_ANCHOR = (
    "consensus/fuzz/marshal/src/marshal/end_to_end/scenario.rs",
    "        let router = Router::new([participants[Role::Byzantine.index()].clone()]);",
    "after",
    WEDGE_HOOK,
)

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
PLAN_SITE_FN = re.compile(r"`(?:[A-Za-z0-9_]+::)?([a-z_][A-Za-z0-9_]*)`")
PLAN_FUNCTION = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([a-z_][A-Za-z0-9_]*)", re.M)
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


def load_config(sl_dir):
    """Reads config.env; a non-empty environment variable overrides a value."""
    values = {key: "" for key in CONFIG_KEYS}
    for number, raw in enumerate((sl_dir / "config.env").read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise Abort(1, f"config.env:{number}: expected KEY=VALUE")
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


def agent_command(config, agent, phase, repo):
    """Non-interactive agent invocation (SPEC section 12); the prompt goes to stdin."""
    model = agent_model(config, agent)
    if agent == "claude":
        command = ["claude", "-p", "--output-format", "text"]
        if model:
            command += ["--model", model]
        if phase in (1, "beacons"):
            command += ["--permission-mode", "acceptEdits", "--allowedTools"]
            command += ["Read", "Grep", "Glob", "Write", "Edit", "WebFetch"]
            if phase == "beacons":
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
    if phase == "beacons":
        # No per-tool allowlist: writes stay in the workspace and the network is off.
        command += ["-s", "workspace-write", "-c", "sandbox_workspace_write.network_access=false"]
    elif phase == 1:
        command += ["-s", "workspace-write", "-c", "sandbox_workspace_write.network_access=true"]
    else:
        command += ["--dangerously-bypass-approvals-and-sandbox"]
    return command + ["-"]


def run_logged(command, log_path, cwd, stdin_text=None):
    """Runs a command, copying its output to the console and to `log_path`.

    Returns the exit code and the last `ERROR_LINES` lines of output.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    tail = collections.deque(maxlen=ERROR_LINES)
    with open(log_path, "w", encoding="utf-8") as log:
        log.write("$ " + shlex.join(command) + "\n")
        log.flush()
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
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
        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            log.write(line)
            tail.append(line.rstrip("\n"))
        code = process.wait()
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
    """Checks one invariant file against SPEC section 4.6, rules 1 to 8."""
    problems = []
    parent = path.resolve().parent
    registry = parent.name if parent.name in SUBSYSTEMS else None
    if parent.name in FILE_NAMES:
        problems.append(
            f"lies directly in {parent.name}/; move it to {parent.name}/<subsystem>/, "
            f"where <subsystem> is one of: {', '.join(SUBSYSTEMS)}"
        )
    else:
        pattern = FILE_NAMES.get(parent.parent.name)
        if registry is None or pattern is None or not pattern.match(path.name):
            problems.append(
                "file name must be INV-NNNN.md in invariants/<subsystem>/ or FALSE-NNNN.md in "
                "false-invariants/<subsystem>/, where <subsystem> is one of: "
                + ", ".join(SUBSYSTEMS)
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
    if kind and kind not in SOURCE_KINDS:
        problems.append(f"source_kind must be one of: {', '.join(SOURCE_KINDS)}")
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
    for name in REQUIRED_SECTIONS:
        if name not in sections:
            problems.append(f"missing section: ## {name}")
        elif not any(line.strip() for line in sections[name]):
            problems.append(f"empty section: ## {name}")
        else:
            positions.append(order.index(name))
    if positions != sorted(positions):
        problems.append("sections Statement, Rationale and Evidence must be in this order")
    return problems


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


def next_invariant_id(sl_dir):
    """1 + the highest INV number over all registries (SPEC section 4.1)."""
    root = sl_dir / "invariants"
    paths = list(root.glob("INV-*.md")) + list(root.glob("*/INV-*.md"))
    numbers = [id_number(path) for path in paths]
    return f"INV-{max(numbers, default=0) + 1:04d}"


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


def extract_values(repo, sl_dir, kind, registry, sources):
    """Placeholder values of the Phase 1 prompt (SPEC section 6.2, step 5)."""
    lines = []
    for source in sources:
        text = paper_text(repo, sl_dir, source) if kind == "paper" else None
        suffix = f" (text: {text.relative_to(repo)})" if text else ""
        lines.append(f"- {source}{suffix}")
    return {
        "KIND": kind,
        "NEXT_ID": next_invariant_id(sl_dir),
        "TEMPLATE": (sl_dir / "templates" / "invariant.md").read_text().rstrip("\n"),
        "SOURCES": "\n".join(lines),
        "REGISTRY": registry,
        "CONTEXT": subsystem_prompt(sl_dir, registry, "analyst"),
        "SOURCE_ROOT": f"consensus/src/{registry}",
    }


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


def cmd_extract(args):
    """Phase 1 (SPEC section 6.2)."""
    repo = repo_root()
    sl_dir = repo / SL
    config = load_config(sl_dir)
    agent = resolve_agent(config, args.agent)
    invariants = sl_dir / "invariants"
    registry = invariants / args.registry
    registry.mkdir(parents=True, exist_ok=True)
    before = files_under(invariants)
    values = extract_values(repo, sl_dir, args.kind, args.registry, args.sources)
    prompt = compose(sl_dir, "analyst.md", f"analyst-{args.kind}.md", values)

    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    log = sl_dir / "extract" / f"{stamp}-{args.kind}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    (sl_dir / "extract" / f"{stamp}-{args.kind}.prompt.md").write_text(prompt)
    say(
        f"extract: {agent} reads {len(args.sources)} {args.kind} source(s) for the "
        f"{args.registry} registry, from {values['NEXT_ID']}; log {log.relative_to(repo)}"
    )
    tree_before = worktree_state(repo)
    code, _ = run_logged(agent_command(config, agent, 1, repo), log, repo, stdin_text=prompt)
    if code != 0:
        raise Abort(2, f"the agent exited with code {code}; see {log.relative_to(repo)}")

    after = files_under(invariants)
    new = sorted((path for path in after if path not in before), key=by_id)
    problems = 0
    for path, digest in sorted(before.items()):
        if after.get(path) != digest:
            print(f"{path}: the agent modified or deleted an existing invariant")
            problems += 1
    for path in new:
        if path.parent != registry:
            print(f"{path}: the agent wrote outside the registry invariants/{args.registry}/")
            problems += 1
    # Anything the agent touched outside the invariant tree. The tree itself is
    # left to the checks above, which say more about it than this one can, and
    # this run's own log and prompt are named rather than assumed to be ignored,
    # so the check does not depend on a .gitignore being right.
    tree_after = worktree_state(repo)
    ours = (
        str(SL / "invariants") + "/",
        str(SL / "extract") + "/",
        str(SL / "campaign") + "/",
    )
    for path in sorted(set(tree_before) | set(tree_after)):
        if path.startswith(ours) or tree_before.get(path) == tree_after.get(path):
            continue
        print(f"{path}: the agent changed a file outside invariants/")
        problems += 1
    problems += lint_paths(new, registry_files(sl_dir))
    for path in new:
        say(f"new: {path.relative_to(sl_dir)}: {title_of(path)}")
    if new:
        say(
            "Every file in a registry is used by the next campaign that binds it. "
            "Review, edit or delete these files first."
        )
    else:
        say("extract: the agent wrote no invariants")
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


def kb_snippet(entry, line, context=None):
    lines = kb_text(entry).split("\n")
    span = KB_GREP_CONTEXT if context is None else context
    start = max(0, line - 1 - span // 2)
    return "\n".join(f"    {text}" for text in lines[start : start + span])


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
        coarse = next((count for module, count in outside if module == "consensus"), 0)
        if coarse:
            print(f"{coarse} finding(s) name only `consensus`, too coarse to attribute")
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


def kb_query_help(registry):
    """The QUERY placeholder: the concrete command line of every query (SPEC 6.3)."""
    base = f"python3 {SL}/scripts/statelens.py kb"
    return "\n".join(
        [
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
# contains its line.

CODE_CRATE = "consensus"
SCIP_INDEX = "extract/code-index.scip"
SCIP_ROLE_DEFINITION = 0x1
SCIP_CALLABLE = "()."
CODE_HITS_LIMIT = 40


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
    """
    raw = memoryview(path.read_bytes())
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
                relative = f"{CODE_CRATE}/" + bytes(payload).decode("utf-8", "replace")
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
                names[symbol] = display
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


def index_path(sl_dir):
    return sl_dir / SCIP_INDEX


def index_build(repo, sl_dir, subsystem):
    """Write the SCIP index for the crate that owns `subsystem`."""
    if shutil.which("rust-analyzer") is None:
        say(
            "rust-analyzer is not installed, so the code index cannot be built.\n"
            "Install it with `rustup component add rust-analyzer`."
        )
        return None
    crate = CODE_CRATE
    out = index_path(sl_dir)
    out.parent.mkdir(parents=True, exist_ok=True)
    say(f"building the code index for {crate} (several minutes)")
    command = [
        "rust-analyzer",
        "scip",
        crate,
        "--output",
        str(out),
        "--exclude-vendored-libraries",
    ]
    log = sl_dir / "extract" / "code-index.log"
    code, _tail = run_logged(command, log, cwd=repo)
    if code != 0 or not out.exists():
        say(f"the code index build failed; see {log.relative_to(repo)}")
        return None
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
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        if not line.startswith("#[cfg(test)]"):
            continue
        following = next(
            (one for one in lines[number:] if one.strip() and not one.startswith("#[")),
            "",
        )
        if following.lstrip().startswith(("mod ", "pub mod ")):
            return [(number, None)]
    return []


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
    """
    exact = {sym for sym, display in names.items() if display == needle}
    if not exact:
        exact = {sym for sym in definitions if needle in sym}
    if not exact:
        exact = {sym for sym, _p, _l, _d in occurrences if needle in sym}
    return sorted(exact)


def index_enclosing(definitions, relative, line):
    """The definition whose extent contains `line`, innermost first."""
    best = None
    for symbol, (path, start, end) in definitions.items():
        if path != relative or not start <= line <= end:
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


def cmd_code(args):
    """Entity identification over the SCIP index (SPEC section 5.7)."""
    repo = repo_root()
    sl_dir = repo / SL
    if args.query == "build":
        return 0 if index_build(repo, sl_dir, args.subsystem) else 1
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
        self.maps = {}
        self.changed = set()
        self.missing = set()
        self.added = set()
        self.unsnapshotted = set()
        self.lines = {}
        path = snapshot_path(sl_dir)
        try:
            self.snapshot = json.loads(path.read_text(encoding="utf-8"))
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
        template that was never indexable is not mistaken for new source.
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
        for found in (self.repo / CODE_CRATE).rglob("*.rs"):
            relative = str(found.relative_to(self.repo))
            if relative not in self.snapshot and str(Path(relative).parent) in directories:
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


def ast_field_ops(path, name):
    """Where `name` is written, read, given an initial value, or unknown.

    Returns four sorted line lists. A write is an assignment to a field or
    path expression; an init is a struct literal field; everything else that
    names the entity is a read; and a site inside a macro body is unknown,
    because the tree does not structure one. A write through `&mut` is reported
    as a read, which is the known limit of reading shape alone.
    """
    nodes, line_of, source = ast_tree(path)
    writes, reads, inits, opaque = set(), set(), set(), set()
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
        owner_kind, owner_end = owner[1][1], owner[1][3]
        if owner_kind in ("RECORD_EXPR_FIELD", "RECORD_FIELD"):
            inits.add(line)
            continue
        following = ast_next_significant(nodes, index, owner_end)
        if following and following[1] in AST_ASSIGN:
            writes.add(line)
        else:
            reads.add(line)
    return sorted(writes), sorted(reads), sorted(inits), sorted(opaque)


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


def ast_files(repo, sl_dir, name, explicit):
    """Which files to parse: the ones given, else the ones the index names.

    Parsing every source of the crate costs about ten seconds; the index says
    which two or three files mention the entity, so scope narrows to those.
    """
    if explicit:
        return [Path(one) for one in explicit]
    index = index_path(sl_dir)
    if not index.exists():
        say("no code index, so every subsystem source is parsed; pass paths to narrow it")
        found = []
        for subsystem in SUBSYSTEMS:
            found += sorted((repo / "consensus/src" / subsystem).rglob("*.rs"))
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
        targets = [Path(one) for one in args.paths] if args.paths else None
        if targets is None:
            targets = []
            for subsystem in SUBSYSTEMS:
                targets += [
                    one.relative_to(repo)
                    for one in sorted((repo / "consensus/src" / subsystem).rglob("*.rs"))
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
        writes, reads, inits, opaque = ast_field_ops(repo / relative, args.name)
        rows = (
            [("write", line) for line in writes]
            + [("init", line) for line in inits]
            + [("read", line) for line in reads]
            + [("macro", line) for line in opaque]
        )
        for kind, line in rows:
            if not args.tests and index_is_test(repo, boundaries, str(relative), line):
                continue
            if kind not in ("write", "macro") and args.writes_only:
                continue
            print(f"{kind:6s} {relative}:{line}")
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
    created, edited = campaign_artifacts(repo)
    roots = sorted({root for profile in PROFILES.values() for root in profile["roots"]})
    scope = roots + [path for path in edited if path not in roots]
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
    return sorted(delete), sorted(restore), roots


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
            raise Abort(1, f"{name} is not a profile or a simplex_/marshal_ target")
        if profile is not None and profile != owner:
            raise Abort(1, f"{name} is a {owner} target, but the profile is {profile}")
        profile = owner
        targets.append(name)
    if profile is None:
        profile = "simplex"
    known = profile_targets(repo, profile)
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


def cmd_targets(args):
    """The StateLens targets a profile builds, one per line (SPEC section 5.5).

    `just fuzz <profile>` reads this rather than parsing a campaign summary, so
    the recipe and the campaign cannot disagree about what was built.
    """
    repo = repo_root()
    for target in profile_targets(repo, args.profile):
        print(target)
    return 0


def cmd_clean(args):
    """Undo what a campaign wrote, so a checkout can be reused (SPEC section 5.4)."""
    repo = repo_root()
    created, restore, roots = clean_plan(repo)
    if not created and not restore:
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
            git(repo, "status", "--porcelain", "-z", "-uall", "--", *(
                roots + [one for one in campaign_artifacts(repo)[1] if one not in roots]
            ))
        )
    ]
    if left:
        say("clean: these paths still differ from HEAD, so the checkout is not reusable:")
        for row in left[:20]:
            print(f"  {row}")
        return 1
    say(f"clean: restored {len(restore)} path(s) and deleted {len(created)} file(s)")
    say("clean: campaign/ and extract/ were left alone; delete them by hand if you want to")
    return 0


def subsystem_sources(repo):
    """Every non-test Rust source of both subsystems, concatenated."""
    text = []
    for name in SUBSYSTEMS:
        for path in sorted((repo / "consensus/src" / name).rglob("*.rs")):
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
            f"cites `{name}`, which no longer exists in consensus/src/simplex or "
            "consensus/src/marshal; fix the reference, or declare it with a "
            "`<!-- statelens-lint: not-code: ... -->` line when it is not a code name"
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
    return [
        (text, PLAN_SITE_PATH.findall(text), PLAN_SITE_FN.findall(text)) for text in entries
    ]


def enclosing_function(text, position):
    """The name of the `fn` a position sits in, or None."""
    name = None
    for match in PLAN_FUNCTION.finditer(text, 0, position):
        name = match.group(1)
    return name


def subsystem_assertions(repo):
    """The invariant each assertion site names, per instrumented source: path -> [ids].

    One entry per call, not per invariant, so the same list says which invariants a file
    asserts and how many sites it carries, and each carries the function it sits in, so a
    check at one site cannot certify another site of the same file. A file with no
    assertion is kept, because the question "which layer holds none at all" is answered by
    the empty lists.
    """
    found = {}
    for name in SUBSYSTEMS:
        for path in sorted((repo / "consensus/src" / name).rglob("*.rs")):
            relative = path.relative_to(repo).as_posix()
            # The runtime module documents the macros it defines, and a documented call
            # names an invariant without asserting it.
            if relative == STATELENS_RS:
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError as error:
                say(f"warning: cannot read {path}: {error.strerror or error}; skipped")
                continue
            code = "\n".join(
                line for line in text.splitlines() if not line.lstrip().startswith("//")
            )
            found[relative] = [
                (match.group(1), enclosing_function(code, match.start()))
                for match in PLAN_ASSERTION.finditer(code)
            ]
    return found


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
        status = fields.get("Status", "").strip("`* ").split(" ")[0]
        fields["Status"] = status
        if status not in ("bound", "partial", "unbound"):
            problems.append(
                f"{name}: Status is `{status or 'missing'}`; it must be bound, partial or unbound"
            )
            continue
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
            if not any(found == name and at in functions for found, at in sites):
                problems.append(
                    f"{name}: Sites calls `{named}` `{functions[0]}` checked, but the "
                    f"assertion naming {name} is elsewhere in that file"
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
    """SPEC section 11: the plan's claims must match its own sections and the code."""
    repo = repo_root()
    sl_dir = repo / SL
    paths = [Path(path) for path in args.paths] if args.paths else [repo / PLAN]
    registries = PROFILES[args.profile]["registries"]
    expected = [
        path
        for path in registry_files(sl_dir)
        if path.parent.name in registries and path.stem.startswith("INV-")
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


def profile_sources(repo, profile):
    """The existing targets `profile` derives StateLens variants from.

    A profile that names them takes them in that order; one that does not takes
    every target of its package, in file name order, which is how marshal picks
    up a target someone adds. A StateLens variant is never a source.
    """
    chosen = PROFILES[profile]["variants"]
    directory = repo / profile_fuzz_dir(profile)
    present = sorted(
        path.name[: -len(".rs")]
        for path in directory.glob("*.rs")
        if not path.name.endswith("_statelens.rs")
    )
    if chosen is None:
        return present
    missing = [stem for stem in chosen if stem not in present]
    if missing:
        raise Abort(
            2,
            f"materialize: {profile} names fuzz target(s) that do not exist in "
            f"{profile_fuzz_dir(profile)}: {', '.join(missing)}",
        )
    return [stem for stem in chosen]


def profile_targets(repo, profile):
    """The StateLens targets a campaign of `profile` builds (SPEC section 5.5)."""
    return [f"{stem}_statelens" for stem in profile_sources(repo, profile)]


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

    The scheme is the first type argument of the target's `fuzz::<...>` call;
    the others name its driver and its coverage mode, which this says nothing
    about.
    """
    types = simplex_types(repo)
    for stem in stems:
        text = (repo / profile_fuzz_dir("simplex") / f"{stem}.rs").read_text()
        names = re.findall(r"\bfuzz(?:_audit)?::<\s*(\w+)", text)
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


def variant_bin_block(blocks, stem, manifest=None):
    """The [[bin]] block of a StateLens variant (SPEC section 8.3, edit M2)."""
    owners = []
    for block in blocks:
        entries = bin_entries(block)
        name = entries.get("name", ("", ""))[0]
        path = entries.get("path", ("", ""))[0]
        if name == stem or path == f"fuzz_targets/{stem}.rs":
            owners.append(entries)
    if len(owners) != 1:
        raise Abort(
            2,
            f"materialize: expected one [[bin]] block for {stem} in {manifest}, "
            f"found {len(owners)}",
        )
    variant = f"{stem}_statelens"
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

    stems = profile_sources(repo, profile)
    if not stems:
        raise Abort(2, f"materialize: no fuzz targets in {profile_fuzz_dir(profile)}")
    if profile == "marshal":
        check_marshal_cert_mock(repo, stems)
    else:
        check_simplex_cert_mock(repo, stems)

    edits = ANCHORS + ((WEDGE_ANCHOR,) if profile == "marshal" else ())
    for relative, anchor, position, text in edits:
        insertions[relative].append((locate(relative, anchor, position), text))
    create[STATELENS_RS] = read_sl_file(repo, SL / "runtime" / "statelens.rs")
    # Both profiles derive a variant the same way: the target's own source with
    # a reset before its body and a clear after it, plus a `[[bin]]` block taken
    # from the original's. There is no hand-written target to keep in step.
    directory = profile_fuzz_dir(profile)
    manifest_path = profile_manifest(profile)
    blocks = bin_blocks(read_edit_file(repo, manifest_path))
    manifest = []
    for stem in stems:
        relative = f"{directory}/{stem}.rs"
        start = locate(relative, VARIANT_START, "after")
        end = locate(relative, VARIANT_END, "before")
        lines = insert_lines(lines_of(relative), [(start, VARIANT_RESET), (end, VARIANT_CLEAR)])
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

    def __init__(self, args):
        self.repo = repo_root()
        self.sl_dir = self.repo / SL
        self.config = load_config(self.sl_dir)
        # The CLI itself is checked with the preconditions, so a missing one is reported
        # in the summary.
        self.agent = agent_name(self.config, args.agent)
        self.profile_name = args.profile
        self.profile = PROFILES[args.profile]
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
        self.reason = None
        self.panic = None

    # Commands.

    def check_command(self):
        return cargo(self.test_toolchain) + [
            "check",
            "-p",
            "commonware-consensus",
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
        return cargo(self.test_toolchain) + [
            "nextest",
            "run",
            "-p",
            "commonware-consensus",
            "--lib",
            "--no-fail-fast",
            "--ignore-default-filter",
            "-E",
            self.profile["test_filter"],
        ]

    def common_values(self):
        return {"BASE": self.base, "PLAN": PLAN, "CHECK": shlex.join(self.check_command())}

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
                    f"partial {counts['partial']}, unbound {counts['unbound']})",
                )
            )
        if self.audited is not None:
            rows.append(("audit", ", ".join(self.audited) if self.audited else "no status change"))
        if self.coverage is not None:
            listed, unchecked = self.coverage
            problems = self.plan_problems or 0
            rows.append(
                (
                    "plan",
                    f"{listed} commit site(s) listed, {unchecked} not checked, "
                    f"{problems} lint problem(s)",
                )
            )
        if self.sites is not None:
            assertions, probes, deleted = self.sites
            rows.append(
                (
                    "sites",
                    f"{assertions} assertion sites, {probes} probe sites, {deleted} deleted lines",
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
        """The `run` and `replay` lines of every StateLens target (SPEC sections 7.9, 8.3)."""
        fuzz_dir = f"cd {self.repo}/consensus/fuzz && "
        nightly = f"NIGHTLY_VERSION={self.fuzz_toolchain}"
        replay_env = " ".join(filter(None, (self.profile["replay_env"], nightly)))
        package = Path(self.profile["package"]).relative_to("consensus/fuzz")
        rows = []
        for target in self.targets:
            rows.append(
                (
                    "run",
                    f"{fuzz_dir}{nightly} just run {target} -- "
                    "-rss_limit_mb=4000 -print_final_stats=1",
                )
            )
            rows.append(
                (
                    "replay",
                    f"{fuzz_dir}{replay_env} just run {target} "
                    f"{package}/artifacts/{target}/<crash file>",
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
        created = [STATELENS_RS]
        created += [str(path.relative_to(self.repo)) for path in variants]
        for path in created:
            if (self.repo / path).exists():
                raise Abort(
                    2,
                    f"{path} exists: an earlier campaign instrumented this checkout; "
                    "use a fresh clone",
                )
        status = git(self.repo, "status", "--porcelain", "--untracked-files=no", "-z")
        for path in porcelain_paths(status):
            if not path.startswith(f"{SL}/"):
                raise Abort(
                    2,
                    f"{path} has uncommitted changes; run campaigns in a fresh clone "
                    "(only consensus/fuzz/statelens/ may differ from HEAD)",
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
        for registry in self.profile["registries"]:
            roots = [(self.sl_dir / "invariants" / registry, "INV-*.md")]
            if with_false:
                roots.append((self.sl_dir / "false-invariants" / registry, "FALSE-*.md"))
            for root, pattern in roots:
                bound = sorted(root.glob(pattern), key=by_id)
                self.invariants += [(registry, path) for path in bound]
                # Every *.md is linted, so lint rule 1 reports a misnamed file.
                checked += sorted(root.glob("*.md"), key=by_id)
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
        self.targets = profile_targets(self.repo, self.profile_name)
        ids = [path.stem for path in paths]
        meta = {
            "base": self.base,
            "agent": self.agent,
            "model": agent_model(self.config, self.agent),
            "profile": self.profile_name,
            "test_toolchain": self.test_toolchain,
            "fuzz_toolchain": self.fuzz_toolchain,
            "started": utc_now().isoformat(timespec="seconds"),
            "invariants": ids,
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
        say(
            f"campaign: profile {self.profile_name}, {len(ids)} invariant(s), "
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
        """
        if not index_build(self.repo, self.sl_dir, self.profile_name):
            say("continuing without a code index; the agent falls back to search")

    def materialize(self):
        edits = materialize_edits(self.repo, self.sl_dir, self.profile_name)
        for relative, text in list(edits.create.items()) + list(edits.modify.items()):
            (self.repo / relative).write_text(text)
        git(self.repo, "add", "--intent-to-add", "--", *edits.create)
        self.baseline = self.snapshot()
        wedge = ", wedge-scenario hook" if self.profile_name == "marshal" else ""
        say(
            f"materialize: runtime module, {len(edits.targets)} StateLens variant(s), Twins "
            f"runner hook{wedge} and fresh-run hook are in place"
        )

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
                QUERY=kb_query_help(subsystem) if self.kb else "",
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
        self.audit()
        for name, prompt in self.beacon_prompts():
            self.agent_step(name, prompt)
        self.complete_plan()
        self.check_plan()
        self.check_scope()
        self.record()

    def audit(self):
        """Re-reviews the bindings before the beacon step (SPEC section 7.3, steps 6 and 7).

        The first pass writes a binding and its own status; nothing there compares the
        two. This pass does, against the Statement and the sites that commit the actions
        it names, which is where a binding is silently incomplete rather than wrong.
        """
        if not self.invariants:
            return
        if self.config["STATELENS_AUDIT"] == "0":
            say("audit: skipped (STATELENS_AUDIT=0)")
            return
        plan = self.dir / "plan.md"
        before = self.parse_statuses(plan.read_text())
        for name, prompt in self.audit_prompts():
            self.agent_step(name, prompt)
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
            (len(sites), source.replace("consensus/src/", ""))
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
        """Every change since materialize must be under an editable root (SPEC 7.5)."""
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
        diff = git(self.repo, "diff", "--", *roots, f":(exclude){STATELENS_RS}")
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
        counts = collections.Counter(statuses.values())
        summary = (
            "## Summary\n\n"
            f"- Invariants: {len(statuses)} (bound {counts['bound']}, partial "
            f"{counts['partial']}, unbound {counts['unbound']})\n"
            f"- Commit sites: {listed} listed, {unchecked} not checked\n"
            f"- Assertion call sites: {assertions}\n"
            f"- Assertion sites by file: {self.assertion_files()}\n"
            f"- Probe call sites: {probes}\n"
            f"- Beacon table rows: {beacon_rows}\n"
            f"- Deleted lines under {', '.join(roots)}: {deleted}"
            + (" (must match the 'Edited lines' entries)" if deleted else "")
            + "\n"
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
                    self.record()
                say("build: the instrumented tree builds")
                return
            if attempt == REPAIR_ATTEMPTS:
                raise Abort(3, f"the build still fails after {REPAIR_ATTEMPTS} repair attempts")
            command, tail = failure
            self.agent_step(f"repair-{attempt + 1}", self.repair_prompt(attempt + 1, command, tail))
            self.check_scope()

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
            f"test: engine-level tests of {', '.join(self.profile['registries'])} and the "
            "StateLens self-tests"
        )
        code, _ = run_logged(self.test_command(), log, self.repo)
        if code == 0:
            say("test: the test gate passed")
            return
        lines = log.read_text(errors="replace").splitlines()
        for line in lines:
            if re.match(r"^\s+FAIL \[", line):
                say(line.strip())
            elif "[statelens][" in line:
                say(line.strip())
        self.panic = first_panic(lines)
        raise Abort(4, f"the test gate failed; see {log.relative_to(self.repo)}")


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


def main(argv):
    parser = Parser(
        prog="statelens.py",
        description=(
            "StateLens for Simplex and marshal: check the invariant registry, extract "
            "invariants with an agent, query the knowledge base, and run campaigns "
            "(see consensus/fuzz/statelens/docs/SPEC.md)."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    lint = commands.add_parser(
        "lint",
        help="check invariant files",
        description=(
            "Check invariant files (SPEC section 4.6). Without PATH, checks every file in "
            "invariants/ and false-invariants/. Exit code 0 when clean, 3 on problems."
        ),
    )
    lint.add_argument("paths", nargs="*", metavar="PATH", help="an invariant file")
    extract = commands.add_parser(
        "extract",
        help="turn sources into invariants of a registry (Phase 1)",
        description=(
            "Run the agent on sources of one kind and write new invariants to "
            "invariants/<registry>/ (SPEC section 6)."
        ),
    )
    extract.add_argument("--agent", choices=AGENTS, help="agent CLI (default: STATELENS_AGENT)")
    extract.add_argument(
        "--registry",
        choices=SUBSYSTEMS,
        default="simplex",
        help="registry of the new invariants (default: simplex)",
    )
    extract.add_argument("kind", choices=KINDS, help="source kind")
    extract.add_argument("sources", nargs="+", metavar="SOURCE", help="a source (SPEC section 6.1)")
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
        default="simplex",
        help="profile whose registries the plan must cover (default: simplex)",
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
            "Delete the files a campaign created and restore the paths it edits to HEAD, "
            "so a checkout can be reused (SPEC section 5.4). Prints what it would do and "
            "needs --yes to act."
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
    code = commands.add_parser(
        "code",
        help="identify entities in the code: definitions, references, callers, callees",
        description=(
            "Queries the SCIP index of the consensus crate (SPEC section 5.7). "
            "Names in this crate collide -- `proposal` is five different methods -- "
            "so a symbol index answers what text search cannot. Test sites are "
            "hidden unless --tests is passed, because two thirds of the crate is "
            "test code."
        ),
    )
    code_queries = code.add_subparsers(dest="query", required=True, parser_class=Parser)
    code_build = code_queries.add_parser("build", help="write the index (several minutes)")
    code_build.add_argument(
        "--subsystem",
        choices=SUBSYSTEMS,
        default="simplex",
        help="subsystem whose campaign the index serves (default: simplex)",
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
            "section 7.13). Names a profile (`simplex`, `marshal`) or single targets; "
            "with neither, every target of the default profile. A target with no corpus "
            "is skipped."
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
    targets = commands.add_parser(
        "targets",
        help="the StateLens targets a profile builds, one per line",
        description="Used by `just fuzz <profile>` to run every target of a profile.",
    )
    targets.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default="simplex",
        help="profile whose targets to list (default: simplex)",
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
        "sites", help="where a field or binding is written, initialized and read"
    )
    ast_sites.add_argument("name", metavar="NAME", help="a field or variable name")
    ast_sites.add_argument("paths", nargs="*", metavar="PATH", help="files to parse")
    ast_sites.add_argument("--tests", action="store_true", help="include test code")
    ast_sites.add_argument(
        "--writes-only", action="store_true", help="only the sites that assign it"
    )
    ast_notes_parser = ast_queries.add_parser(
        "notes", help="comment blocks matching a pattern, with the item each documents"
    )
    ast_notes_parser.add_argument(
        "--pattern",
        default=AST_NOTE_DEFAULT,
        help="case-insensitive regular expression (default: the beacon words)",
    )
    ast_notes_parser.add_argument("paths", nargs="*", metavar="PATH", help="files to parse")
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
    campaign.add_argument("--stop-after", choices=STOP_STEPS, help="stop after this step")
    args = parser.parse_args(argv)

    try:
        if args.command == "lint":
            return cmd_lint(args)
        if args.command == "extract":
            return cmd_extract(args)
        if args.command == "kb":
            return cmd_kb(args)
        if args.command == "targets":
            return cmd_targets(args)
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
        return Campaign(args).run()
    except Abort as error:
        say(f"error: {error}")
        return error.code
    except KeyboardInterrupt:
        say("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
