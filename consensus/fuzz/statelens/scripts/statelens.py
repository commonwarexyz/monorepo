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
# SPEC section 6.3: the knowledge base and its index.
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
)

STOP_STEPS = ("materialize", "instrument", "build")
BATCH_SIZE = 8
REPAIR_ATTEMPTS = 3
ERROR_LINES = 150

TARGET = "simplex_statelens"
STATELENS_RS = "consensus/src/simplex/statelens.rs"
TARGET_RS = "consensus/fuzz/simplex/fuzz_targets/simplex_statelens.rs"
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
NOT_CODE = re.compile(r"<!--\s*statelens-lint:\s*not-code:\s*(.*?)\s*-->", re.S)
CODE_WORD = re.compile(r"`([a-z_][a-z0-9_]*_[a-z0-9_]+)`")
# Everything a campaign creates (deleted by `clean`) or edits (restored by `clean`).
# The marshal variants are found by glob, because their names come from the targets.
CREATED_PATHS = (STATELENS_RS, TARGET_RS)
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
        "target": TARGET,
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
        "target": None,
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

# SPEC Appendix B.2: appended to the Simplex fuzz package manifest.
BIN_BLOCK = """
[[bin]]
name = "simplex_statelens"
path = "fuzz_targets/simplex_statelens.rs"
test = false
doc = false
bench = false
required-features = ["twins"]
"""

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


def porcelain_paths(output):
    """Returns the paths of `git status --porcelain -z` output, including rename sources."""
    entries = output.split("\0")
    paths = []
    index = 0
    while index < len(entries):
        entry = entries[index]
        index += 1
        if len(entry) < 4:
            continue
        status, path = entry[:2], entry[3:]
        paths.append(path)
        if "R" in status or "C" in status:
            if index < len(entries) and entries[index]:
                paths.append(entries[index])
            index += 1
    return paths


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
# Knowledge base (SPEC section 6.3)
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
    """The files and symbols a finding cites, most-cited first (SPEC section 6.3)."""
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
    """Maps a `module` value to its crate module (SPEC section 6.3)."""
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
    """Findings whose claim fields match, ranked as SPEC section 6.3 says."""
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
    """Findings citing a path under `prefix`, most citations first (SPEC section 6.3)."""
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
    """The retrieval interface of SPEC section 6.3, used by the beacon agent."""
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
    """(created paths that exist, tracked paths a campaign edits) (SPEC section 7.13)."""
    variants = sorted((repo / MARSHAL_TARGETS).glob("*_statelens.rs"))
    created = [path for path in CREATED_PATHS if (repo / path).exists()]
    created += [str(path.relative_to(repo)) for path in variants]
    edited = [path for path in EDITED_PATHS if (repo / path).exists()]
    return created, edited


def cmd_clean(args):
    """Undo what a campaign wrote, so a checkout can be reused (SPEC section 7.13)."""
    repo = repo_root()
    created, edited = campaign_artifacts(repo)
    roots = sorted({root for profile in PROFILES.values() for root in profile["roots"]})
    dirty = porcelain_paths(git(repo, "status", "--porcelain", "-z", "--", *roots))
    touched = porcelain_paths(git(repo, "status", "--porcelain", "-z", "--", *edited))
    if not created and not dirty and not touched:
        say("clean: nothing to undo; this checkout has no campaign artifacts")
        return 0
    say("clean: this restores the paths below to HEAD, losing any edit of your own in them")
    for path in created:
        print(f"  delete   {path}")
    # A created file is deleted, not restored: after `git rm --cached` its pathspec is
    # unknown to git, and one unknown pathspec fails the whole `git checkout`.
    restore = sorted((set(touched) | set(dirty)) - set(created))
    for path in restore:
        print(f"  restore  {path}")
    if not args.yes:
        # A preview is the default and is not a failure, so it exits 0: `just` would
        # otherwise report the safe path as a broken recipe.
        say(
            f"clean: nothing done. Rerun as `just clean --yes` to delete {len(created)} "
            f"file(s) and restore {len(restore) + len(roots)} path(s)"
        )
        return 0
    # Restore first: a failure then leaves every generated file in place, so the
    # checkout is still recoverable. Only pathspecs git can resolve are passed, because
    # one unknown pathspec aborts the whole checkout.
    targets = sorted(set(restore) | {root for root in roots if (repo / root).is_dir()})
    if targets:
        git(repo, "checkout", "--", *targets)
    for path in created:
        git(repo, "rm", "--cached", "--quiet", "--ignore-unmatch", path)
        (repo / path).unlink()
    say(f"clean: restored {len(targets)} path(s) and deleted {len(created)} file(s)")
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


def read_edit_file(repo, relative, hint="update the paths and anchors in scripts/statelens.py"):
    """Text of a file the materialize step reads; a missing file aborts with exit code 2."""
    try:
        return (repo / relative).read_text()
    except FileNotFoundError:
        raise Abort(2, f"materialize: {relative} does not exist; {hint}") from None


def read_sl_file(repo, relative):
    """Text of a StateLens file that materialize copies (SL/runtime/)."""
    return read_edit_file(repo, relative, "restore it from HEAD")


def marshal_sources(repo):
    """Stems of the marshal fuzz targets, in file name order (StateLens variants excluded)."""
    names = sorted(
        path.name
        for path in (repo / MARSHAL_TARGETS).glob("*.rs")
        if not path.name.endswith("_statelens.rs")
    )
    return [name[: -len(".rs")] for name in names]


def profile_targets(repo, profile):
    """The StateLens targets a campaign of `profile` builds (SPEC section 5.5)."""
    target = PROFILES[profile]["target"]
    if target:
        return [target]
    return [f"{stem}_statelens" for stem in marshal_sources(repo)]


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


def check_cert_mock(repo, sl_dir):
    """D15 for the target templates in SL/runtime/ (SPEC section 7.2)."""
    types = simplex_types(repo)
    for template in sorted((sl_dir / "runtime").glob("*.rs")):
        if template.name == "statelens.rs":
            continue
        names = re.findall(r"\bfuzz(?:_audit)?::<\s*(\w+)", template.read_text())
        if not names:
            raise Abort(2, f"{template.name}: no fuzz::<P, ...> call to check (D15)")
        for name in names:
            if not types.get(name):
                raise Abort(
                    2,
                    f"{template.name}: {name} does not use the cert_mock certificate "
                    "scheme; StateLens fuzz targets may only use cert_mock (D15)",
                )


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


def variant_bin_block(blocks, stem):
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
            f"materialize: expected one [[bin]] block for {stem} in {MARSHAL_MANIFEST}, "
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
                    f"materialize: the {key} value of {stem} in {MARSHAL_MANIFEST} spans "
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

    if profile == "simplex":
        check_cert_mock(repo, sl_dir)
    else:
        stems = marshal_sources(repo)
        if not stems:
            raise Abort(2, f"materialize: no fuzz targets in {MARSHAL_TARGETS}")
        check_marshal_cert_mock(repo, stems)

    edits = ANCHORS + ((WEDGE_ANCHOR,) if profile == "marshal" else ())
    for relative, anchor, position, text in edits:
        insertions[relative].append((locate(relative, anchor, position), text))
    create[STATELENS_RS] = read_sl_file(repo, SL / "runtime" / "statelens.rs")
    if profile == "simplex":
        create[TARGET_RS] = read_sl_file(repo, SL / "runtime" / "target.rs")
        appends[FUZZ_MANIFEST] = BIN_BLOCK
    else:
        blocks = bin_blocks(read_edit_file(repo, MARSHAL_MANIFEST))
        manifest = []
        for stem in stems:
            relative = f"{MARSHAL_TARGETS}/{stem}.rs"
            start = locate(relative, VARIANT_START, "after")
            end = locate(relative, VARIANT_END, "before")
            lines = insert_lines(lines_of(relative), [(start, VARIANT_RESET), (end, VARIANT_CLEAR)])
            create[f"{MARSHAL_TARGETS}/{stem}_statelens.rs"] = "\n".join(lines)
            manifest.append(variant_bin_block(blocks, stem))
        appends[MARSHAL_MANIFEST] = "".join(manifest)

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
        variants = sorted((self.repo / MARSHAL_TARGETS).glob("*_statelens.rs"))
        created = [STATELENS_RS, TARGET_RS]
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

    def materialize(self):
        edits = materialize_edits(self.repo, self.sl_dir, self.profile_name)
        for relative, text in list(edits.create.items()) + list(edits.modify.items()):
            (self.repo / relative).write_text(text)
        git(self.repo, "add", "--intent-to-add", "--", *edits.create)
        self.baseline = self.snapshot()
        if self.profile["target"]:
            say(
                "materialize: runtime module, fuzz target, Twins runner hook and fresh-run "
                "hook are in place"
            )
        else:
            say(
                f"materialize: runtime module, {len(edits.targets)} StateLens variants, Twins "
                "runner hook, wedge-scenario hook and fresh-run hook are in place"
            )

    def snapshot(self):
        """Hashes every path that `git status` reports (SPEC section 7.2)."""
        status = git(self.repo, "status", "--porcelain", "--untracked-files=all", "-z")
        result = {}
        for path in porcelain_paths(status):
            full = self.repo / path
            result[path] = sha256(full) if full.is_file() else "absent"
        return result

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

    def invariant_prompts(self):
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
                prompt = compose(self.sl_dir, "instrument.md", "instrument-invariants.md", values)
                prompts.append((f"invariants-{registry}-{number}", prompt))
        return prompts

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
        for name, prompt in self.beacon_prompts():
            self.agent_step(name, prompt)
        self.complete_plan()
        self.check_scope()
        self.record()

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
        for line in text.splitlines():
            heading = PLAN_HEADING.match(line)
            if heading:
                current = heading.group(1)
                statuses.setdefault(current, None)
                continue
            if line.startswith("## "):
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
        counts = collections.Counter(statuses.values())
        summary = (
            "## Summary\n\n"
            f"- Invariants: {len(statuses)} (bound {counts['bound']}, partial "
            f"{counts['partial']}, unbound {counts['unbound']})\n"
            f"- Assertion call sites: {assertions}\n"
            f"- Probe call sites: {probes}\n"
            f"- Beacon table rows: {beacon_rows}\n"
            f"- Deleted lines under {', '.join(roots)}: {deleted}"
            + (" (must match the 'Edited lines' entries)" if deleted else "")
            + "\n"
        )
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
    clean = commands.add_parser(
        "clean",
        help="undo what a campaign wrote to this checkout",
        description=(
            "Delete the files a campaign created and restore the paths it edits to HEAD, "
            "so a checkout can be reused (SPEC section 7.13). Prints what it would do and "
            "needs --yes to act."
        ),
    )
    clean.add_argument("--yes", action="store_true", help="actually do it")
    kb = commands.add_parser(
        "kb",
        help="query the knowledge base (the instrumenter uses it too)",
        description="The retrieval interface of SPEC section 6.3.",
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
        if args.command == "clean":
            return cmd_clean(args)
        if args.command == "lint-examples":
            return cmd_lint_examples(args)
        return Campaign(args).run()
    except Abort as error:
        say(f"error: {error}")
        return error.code
    except KeyboardInterrupt:
        say("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
