#!/usr/bin/env python3
"""StateLens for Simplex: lint invariants, extract them with an agent, run campaigns.

See consensus/fuzz/statelens/SPEC.md. Standard library only; Python 3.9 or later.
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
import signal
import subprocess
import sys
import threading
from pathlib import Path

# Subproject root, relative to the repository root.
SL = Path("consensus/fuzz/statelens")

KINDS = ("issue", "design", "comment", "spec", "paper")
SOURCE_KINDS = ("human",) + KINDS
SCOPES = ("protocol", "replica", "voter", "batcher", "resolver", "cross-actor")
REQUIRED_KEYS = ("id", "title", "source_kind", "source_ref", "scope")
OPTIONAL_KEYS = ("author",)
REQUIRED_SECTIONS = ("Statement", "Rationale", "Evidence")
FILE_NAMES = {
    "invariants": re.compile(r"^INV-\d{4,}\.md$"),
    "false-invariants": re.compile(r"^FALSE-\d{4,}\.md$"),
}

CONFIG_KEYS = (
    "STATELENS_AGENT",
    "STATELENS_CLAUDE_MODEL",
    "STATELENS_CODEX_MODEL",
    "STATELENS_TEST_TOOLCHAIN",
    "STATELENS_FUZZ_TOOLCHAIN",
)

ACTORS = ("voter", "batcher", "resolver")
STEPS = ("materialize", "instrument", "build", "test")
BATCH_SIZE = 8
REPAIR_ATTEMPTS = 3
ERROR_LINES = 150

TARGET = "simplex_statelens"
SIMPLEX = "consensus/src/simplex/"
STATELENS_RS = "consensus/src/simplex/statelens.rs"
TARGET_RS = "consensus/fuzz/simplex/fuzz_targets/simplex_statelens.rs"
FUZZ_MANIFEST = "consensus/fuzz/simplex/Cargo.toml"
CORE_SIMPLEX = "consensus/fuzz/core/src/simplex.rs"
ARTIFACTS = "consensus/fuzz/simplex/artifacts/" + TARGET
PLAN = "consensus/fuzz/statelens/campaign/plan.md"
TEST_FILTER = (
    "(test(/^simplex::tests::/) & not test(/::test_twins/)) | test(/^simplex::statelens::/)"
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

# SPEC section 7.2: (file, the only line equal to the anchor, "after" or "before", text).
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

PLAN_TEMPLATE = """\
# StateLens instrumentation plan

- Base commit: {base}
- Agent: {agent}
- Invariants: {count} ({ids})

## Invariants

## Beacon probes

| Label | File and function | a | b | Beacon |
|---|---|---|---|---|
"""

PLACEHOLDER = re.compile(r"\{\{([A-Z_]+)\}\}")
PLAN_HEADING = re.compile(r"^###\s+((?:INV|FALSE)-\d+)\b")
PLAN_STATUS = re.compile(r"^-\s*\**Status\**\s*:\s*\**\s*`?(bound|partial|unbound)\b")


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


def resolve_agent(config, flag):
    agent = flag or config["STATELENS_AGENT"]
    if agent not in ("claude", "codex"):
        raise Abort(1, f"unknown agent {agent!r}; use claude or codex")
    if shutil.which(agent) is None:
        raise Abort(2, f"the {agent} CLI is not on PATH")
    return agent


def agent_model(config, agent):
    key = "STATELENS_CLAUDE_MODEL" if agent == "claude" else "STATELENS_CODEX_MODEL"
    return config[key]


def agent_command(config, agent, phase, repo):
    """Non-interactive agent invocation (SPEC section 11); the prompt goes to stdin."""
    model = agent_model(config, agent)
    if agent == "claude":
        command = ["claude", "-p", "--output-format", "text"]
        if model:
            command += ["--model", model]
        if phase == 1:
            command += [
                "--permission-mode",
                "acceptEdits",
                "--allowedTools",
                "Read",
                "Grep",
                "Glob",
                "Write",
                "Edit",
                "WebFetch",
                "Bash(gh:*)",
                "Bash(curl:*)",
            ]
        else:
            command += ["--dangerously-skip-permissions"]
        return command
    command = ["codex", "exec", "-C", str(repo)]
    if model:
        command += ["-m", model]
    if phase == 1:
        command += ["-s", "workspace-write", "-c", "sandbox_workspace_write.network_access=true"]
    else:
        command += ["--dangerously-bypass-approvals-and-sandbox"]
    return command + ["-"]


def run_logged(command, log_path, cwd, stdin_text=None, env=None, own_sigint=False):
    """Runs a command, copying its output to the console and to `log_path`.

    Returns the exit code and the last `ERROR_LINES` lines of output. With
    `own_sigint`, the child handles Ctrl-C with the default action even when this
    process ignores it.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    tail = collections.deque(maxlen=ERROR_LINES)
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
            preexec_fn=(lambda: signal.signal(signal.SIGINT, signal.SIG_DFL))
            if own_sigint
            else None,
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


def lint_file(path):
    """Checks one invariant file against SPEC section 4.6."""
    problems = []
    pattern = FILE_NAMES.get(path.parent.name)
    if pattern is None or not pattern.match(path.name):
        problems.append(
            "file name must be INV-NNNN.md in invariants/ or FALSE-NNNN.md in false-invariants/"
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
        if key not in REQUIRED_KEYS + OPTIONAL_KEYS:
            problems.append(f"unknown front matter key: {key}")
    if front.get("id") and front["id"] != path.stem:
        problems.append(f"id {front['id']} does not match the file name")
    kind = front.get("source_kind")
    if kind and kind not in SOURCE_KINDS:
        problems.append(f"source_kind must be one of: {', '.join(SOURCE_KINDS)}")
    scope = front.get("scope")
    if scope:
        match = re.fullmatch(r"\[(.*)\]", scope)
        items = [item.strip() for item in match.group(1).split(",")] if match else []
        if not match or not items or any(item not in SCOPES for item in items):
            problems.append(f"scope must be a list of: {', '.join(SCOPES)}")
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


def lint_paths(paths):
    count = 0
    for path in paths:
        for problem in lint_file(path):
            print(f"{path}: {problem}", flush=True)
            count += 1
    return count


def cmd_lint(args):
    if args.paths:
        paths = [Path(path) for path in args.paths]
    else:
        sl_dir = repo_root() / SL
        paths = sorted((sl_dir / "invariants").glob("*.md"), key=id_number)
        paths += sorted((sl_dir / "false-invariants").glob("*.md"), key=id_number)
    count = lint_paths(paths)
    say(f"lint: {len(paths)} file(s), {count} problem(s)")
    return 3 if count else 0


def next_invariant_id(registry):
    numbers = [id_number(path) for path in registry.glob("INV-*.md")]
    return f"INV-{max(numbers, default=0) + 1:04d}"


def paper_text(repo, sl_dir, source):
    """Converts a local PDF source to text; returns the text path or None."""
    location = Path(source.split("#", 1)[0])
    path = location if location.is_absolute() else repo / location
    if path.suffix.lower() != ".pdf" or not path.is_file():
        return None
    output = sl_dir / "extract" / "papers" / (path.stem + ".txt")
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


def cmd_extract(args):
    """Phase 1 (SPEC section 6.2)."""
    repo = repo_root()
    sl_dir = repo / SL
    config = load_config(sl_dir)
    agent = resolve_agent(config, args.agent)
    registry = sl_dir / "invariants"
    registry.mkdir(exist_ok=True)
    before = {path.name: sha256(path) for path in registry.glob("*.md")}
    next_id = next_invariant_id(registry)

    lines = []
    for source in args.sources:
        text = paper_text(repo, sl_dir, source) if args.kind == "paper" else None
        suffix = f" (text: {text.relative_to(repo)})" if text else ""
        lines.append(f"- {source}{suffix}")
    model = agent_model(config, agent)
    values = {
        "KIND": args.kind,
        "NEXT_ID": next_id,
        "AUTHOR": f"{agent}/{model}" if model else agent,
        "TEMPLATE": (sl_dir / "templates" / "invariant.md").read_text().rstrip("\n"),
        "SOURCES": "\n".join(lines),
    }
    prompt = compose(sl_dir, "analyst.md", f"analyst-{args.kind}.md", values)

    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    log = sl_dir / "extract" / f"{stamp}-{args.kind}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    (sl_dir / "extract" / f"{stamp}-{args.kind}.prompt.md").write_text(prompt)
    say(f"extract: {agent} reads {len(args.sources)} {args.kind} source(s); log {log.relative_to(repo)}")
    code, _ = run_logged(agent_command(config, agent, 1, repo), log, repo, stdin_text=prompt)
    if code != 0:
        raise Abort(2, f"the agent exited with code {code}; see {log.relative_to(repo)}")

    after = {path.name: sha256(path) for path in registry.glob("*.md")}
    new = sorted((name for name in after if name not in before), key=lambda name: id_number(Path(name)))
    problems = 0
    for name, digest in sorted(before.items()):
        if after.get(name) != digest:
            print(f"{registry / name}: the agent modified or deleted an existing invariant")
            problems += 1
    problems += lint_paths([registry / name for name in new])
    for name in new:
        say(f"new: invariants/{name}: {title_of(registry / name)}")
    if not new:
        say("extract: the agent wrote no invariants")
    say(
        "every file in invariants/ is used by the next campaign; "
        "review, edit or delete these files first"
    )
    return 3 if problems else 0


class Campaign:
    """Phase 2 (SPEC section 7), run in place in the checkout."""

    def __init__(self, args, libfuzzer_args):
        self.repo = repo_root()
        self.sl_dir = self.repo / SL
        self.config = load_config(self.sl_dir)
        self.agent = resolve_agent(self.config, args.agent)
        self.stop_after = args.stop_after
        self.libfuzzer_args = libfuzzer_args
        self.test_toolchain = self.config["STATELENS_TEST_TOOLCHAIN"]
        self.fuzz_toolchain = self.config["STATELENS_FUZZ_TOOLCHAIN"] or pinned_nightly(self.repo)
        self.dir = self.sl_dir / "campaign"
        self.base = None
        self.invariants = []
        self.baseline = {}
        self.statuses = None
        self.sites = None
        self.reason = None
        self.panic = None
        self.artifact = None

    # Commands.

    def check_command(self):
        return cargo(self.test_toolchain) + [
            "check",
            "-p",
            "commonware-consensus",
            "--lib",
            "--tests",
        ]

    def fuzz_build_command(self):
        return cargo(self.fuzz_toolchain) + [
            "fuzz",
            "build",
            "--fuzz-dir",
            "consensus/fuzz/simplex",
            TARGET,
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
            TEST_FILTER,
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
            return self.fuzz()
        except Abort as error:
            self.reason = str(error)
            result = {
                2: "SETUP FAILED",
                3: "BUILD FAILED",
                4: "PANIC (tests)",
                5: "PANIC (fuzz)",
            }.get(error.code, "SETUP FAILED")
            return self.finish(error.code, result)

    def finish(self, code, result):
        lines = [f"checkout   {self.repo}"]
        if self.base:
            lines.append(f"base       {self.base}")
        lines.append(f"agent      {self.agent}")
        if self.statuses is not None:
            counts = collections.Counter(self.statuses.values())
            lines.append(
                f"invariants {len(self.statuses)} (bound {counts['bound']}, "
                f"partial {counts['partial']}, unbound {counts['unbound']})"
            )
        if self.sites is not None:
            assertions, probes, deleted = self.sites
            lines.append(
                f"sites      {assertions} assertion sites, {probes} probe sites, "
                f"{deleted} deleted lines"
            )
        lines.append(f"result     {result}")
        if self.reason:
            lines.append(f"reason     {self.reason}")
        if self.panic:
            lines.append(f"panic      {self.panic}")
        if self.artifact:
            relative = Path(self.artifact).relative_to("consensus/fuzz")
            lines.append(f"artifact   {self.artifact}")
            lines.append(
                f"replay     cd {self.repo}/consensus/fuzz && "
                f"CONSENSUS_FUZZ_LOG=1 just run {TARGET} {relative}"
            )
        text = "\n".join(f"statelens: {line}" for line in lines)
        print(text, flush=True)
        if self.dir.is_dir():
            (self.dir / "summary.txt").write_text(text + "\n")
        return code

    # Section 7.1.

    def check_preconditions(self):
        for path in (STATELENS_RS, TARGET_RS):
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
        self.invariants = sorted((self.sl_dir / "invariants").glob("INV-*.md"), key=id_number)
        if os.environ.get("STATELENS_FALSE_INVARIANTS") == "1":
            self.invariants += sorted(
                (self.sl_dir / "false-invariants").glob("FALSE-*.md"), key=id_number
            )
        if lint_paths(self.invariants):
            say("warning: some invariant files have format problems (see above)")
        ids = [path.stem for path in self.invariants]
        meta = {
            "base": self.base,
            "agent": self.agent,
            "model": agent_model(self.config, self.agent),
            "test_toolchain": self.test_toolchain,
            "fuzz_toolchain": self.fuzz_toolchain,
            "started": utc_now().isoformat(timespec="seconds"),
            "invariants": ids,
        }
        (self.dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
        (self.dir / "plan.md").write_text(
            PLAN_TEMPLATE.format(
                base=self.base, agent=self.agent, count=len(ids), ids=", ".join(ids)
            )
        )
        say(f"campaign: {len(ids)} invariant(s) at {self.base[:10]} with {self.agent}")

    # Section 7.2.

    def check_cert_mock(self):
        core = (self.repo / CORE_SIMPLEX).read_text()
        for template in sorted((self.sl_dir / "runtime").glob("*.rs")):
            if template.name == "statelens.rs":
                continue
            names = re.findall(r"\bfuzz(?:_audit)?::<\s*(\w+)", template.read_text())
            if not names:
                raise Abort(2, f"{template.name}: no fuzz::<P, ...> call to check (D15)")
            for name in names:
                match = re.search(r"impl Simplex for " + re.escape(name) + r" \{", core)
                block = ""
                if match:
                    rest = core[match.end() :]
                    following = re.search(r"\nimpl ", rest)
                    block = rest[: following.start()] if following else rest
                if "type Scheme = cert_mock::Scheme<" not in block:
                    raise Abort(
                        2,
                        f"{template.name}: {name} does not use the cert_mock certificate "
                        "scheme; StateLens fuzz targets may only use cert_mock (D15)",
                    )

    def materialize(self):
        self.check_cert_mock()
        # Check every anchor before the first edit, so a moved anchor leaves the tree untouched.
        files = {}
        edits = collections.defaultdict(list)
        for relative, anchor, position, text in ANCHORS:
            if relative not in files:
                files[relative] = (self.repo / relative).read_text().split("\n")
            found = [index for index, line in enumerate(files[relative]) if line == anchor]
            if len(found) != 1:
                raise Abort(
                    2,
                    f"materialize: expected one line {anchor.strip()!r} in {relative}, "
                    f"found {len(found)}; update ANCHORS in scripts/statelens.py",
                )
            at = found[0] + 1 if position == "after" else found[0]
            edits[relative].append((at, text))
        shutil.copyfile(self.sl_dir / "runtime" / "statelens.rs", self.repo / STATELENS_RS)
        for relative, lines in files.items():
            # Insert from the bottom up so earlier insertions do not shift later anchors.
            for at, text in sorted(edits[relative], key=lambda edit: edit[0], reverse=True):
                lines[at:at] = text.split("\n")
            (self.repo / relative).write_text("\n".join(lines))
        shutil.copyfile(self.sl_dir / "runtime" / "target.rs", self.repo / TARGET_RS)
        with open(self.repo / FUZZ_MANIFEST, "a") as manifest:
            manifest.write(BIN_BLOCK)
        git(self.repo, "add", "--intent-to-add", STATELENS_RS, TARGET_RS)
        self.baseline = self.snapshot()
        say(
            "materialize: runtime module, fuzz target, Twins runner hook and fresh-run hook "
            "are in place"
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

    def instrument(self):
        if not self.invariants:
            say("warning: no invariants to bind; adding beacon probes only")
        for number, start in enumerate(range(0, len(self.invariants), BATCH_SIZE), 1):
            batch = self.invariants[start : start + BATCH_SIZE]
            body = "\n\n".join(
                f"===== {path.relative_to(self.repo)} =====\n{path.read_text().rstrip()}"
                for path in batch
            )
            values = dict(
                self.common_values(),
                INVARIANT_IDS=", ".join(path.stem for path in batch),
                INVARIANTS=body,
            )
            prompt = compose(self.sl_dir, "instrument.md", "instrument-invariants.md", values)
            self.agent_step(f"invariants-{number}", prompt)
        for actor in ACTORS:
            values = dict(
                self.common_values(),
                ACTOR=actor,
                ACTOR_DIR=f"consensus/src/simplex/actors/{actor}",
            )
            prompt = compose(self.sl_dir, "instrument.md", "instrument-beacons.md", values)
            self.agent_step(f"beacons-{actor}", prompt)
        self.complete_plan()
        self.check_scope()
        self.record()

    def complete_plan(self):
        """Adds an unbound entry for every invariant the agents left out of the plan."""
        plan = self.dir / "plan.md"
        text = plan.read_text()
        statuses = self.parse_statuses(text)
        missing = [path for path in self.invariants if path.stem not in statuses]
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
        """Every change since materialize must be under consensus/src/simplex/ (SPEC 7.5)."""
        current = self.snapshot()
        changed = sorted(
            path
            for path in set(self.baseline) | set(current)
            if self.baseline.get(path) != current.get(path)
        )
        for path in changed:
            if path == "Cargo.lock":
                continue
            if not path.startswith(SIMPLEX):
                raise Abort(2, f"instrumentation edited {path}")
            if path.startswith(SIMPLEX + "mocks/") or path.startswith(SIMPLEX + "scheme/"):
                say(f"warning: instrumentation edited {path}")

    def record(self):
        """Updates the plan summary and writes instrumentation.diff."""
        plan = self.dir / "plan.md"
        text = plan.read_text()
        parsed = self.parse_statuses(text)
        statuses = {path.stem: parsed.get(path.stem) or "unbound" for path in self.invariants}
        self.statuses = statuses
        diff = git(self.repo, "diff", "--", "consensus/src/simplex", f":(exclude){STATELENS_RS}")
        added = [line for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++")]
        assertions = sum(len(re.findall(r"\bsl_(?:assert|implies)!", line)) for line in added)
        probes = sum(len(re.findall(r"\bsl_probe!", line)) for line in added)
        deleted = 0
        for line in git(self.repo, "diff", "--numstat", "--", "consensus/src/simplex").splitlines():
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
            f"- Deleted lines under consensus/src/simplex: {deleted}"
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
            values = dict(
                self.common_values(),
                ATTEMPT=str(attempt + 1),
                COMMAND=command,
                ERRORS="\n".join("    " + line for line in tail),
            )
            prompt = compose(self.sl_dir, "instrument.md", "repair.md", values)
            self.agent_step(f"repair-{attempt + 1}", prompt)
            self.check_scope()

    def build_once(self, attempt):
        for name, command in (
            ("check", self.check_command()),
            ("fuzz-build", self.fuzz_build_command()),
        ):
            log = self.dir / "logs" / f"{name}-{attempt}.log"
            say(f"build: {shlex.join(command)}")
            code, tail = run_logged(command, log, self.repo)
            if code != 0:
                return shlex.join(command), tail
        return None

    # Section 7.7.

    def test_gate(self):
        log = self.dir / "logs" / "test.log"
        say("test: engine-level Simplex tests and StateLens self-tests")
        code, _ = run_logged(self.test_command(), log, self.repo)
        if code == 0:
            say("test: the test gate passed")
            return
        lines = log.read_text(errors="replace").splitlines()
        for line in lines:
            if re.match(r"^\s+FAIL \[", line):
                say(line.strip())
        self.panic = first_panic(lines)
        raise Abort(4, f"the test gate failed; see {log.relative_to(self.repo)}")

    # Section 7.8.

    def fuzz(self):
        artifacts = self.repo / ARTIFACTS
        before = set(os.listdir(artifacts)) if artifacts.is_dir() else set()
        log = self.dir / "logs" / "fuzz.log"
        command = [
            "just",
            "run",
            TARGET,
            "--",
            "-rss_limit_mb=4000",
            "-print_final_stats=1",
        ] + self.libfuzzer_args
        env = dict(os.environ, NIGHTLY_VERSION=self.fuzz_toolchain)
        say("fuzz: running until a panic or Ctrl-C")
        previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            run_logged(command, log, self.repo / "consensus/fuzz", env=env, own_sigint=True)
        finally:
            signal.signal(signal.SIGINT, previous)
        after = set(os.listdir(artifacts)) if artifacts.is_dir() else set()
        new = sorted(after - before)
        if not new:
            return self.finish(0, "NO PANIC")
        self.artifact = f"{ARTIFACTS}/{new[0]}"
        self.panic = first_panic(log.read_text(errors="replace").splitlines())
        return self.finish(5, "PANIC (fuzz)")


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
    libfuzzer_args = []
    if "--" in argv:
        split = argv.index("--")
        argv, libfuzzer_args = argv[:split], argv[split + 1 :]

    parser = Parser(prog="statelens.py", description="StateLens for Simplex (see SPEC.md)")
    commands = parser.add_subparsers(dest="command", required=True)
    lint = commands.add_parser("lint", help="check invariant files")
    lint.add_argument("paths", nargs="*")
    extract = commands.add_parser("extract", help="turn sources into invariants (Phase 1)")
    extract.add_argument("--agent", choices=("claude", "codex"))
    extract.add_argument("kind", choices=KINDS)
    extract.add_argument("sources", nargs="+")
    campaign = commands.add_parser("campaign", help="instrument this checkout, test and fuzz")
    campaign.add_argument("--agent", choices=("claude", "codex"))
    campaign.add_argument("--stop-after", choices=STEPS)
    args = parser.parse_args(argv)

    if libfuzzer_args and args.command != "campaign":
        parser.error("arguments after -- are only accepted by campaign")
    try:
        if args.command == "lint":
            return cmd_lint(args)
        if args.command == "extract":
            return cmd_extract(args)
        return Campaign(args, libfuzzer_args).run()
    except Abort as error:
        say(f"error: {error}")
        return error.code
    except KeyboardInterrupt:
        say("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
