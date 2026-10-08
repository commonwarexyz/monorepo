#!/usr/bin/env python3
"""Tests for the parts of statelens.py that fail quietly.

Run with `just check-scripts`. Standard library only, like the script itself.

These cover the three defects that reached review, all of which produced a
plausible wrong answer rather than an error: a result tuple compared against an
integer, a SCIP range read as four elements when it has three, and an
assignment classified by the wrong sub-expression.
"""

import argparse
import io
import os
import contextlib
import importlib.util
import json
import pathlib
import shutil
import signal
import struct
import subprocess
import tempfile
import sys
import textwrap
import threading
import time
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("statelens", HERE / "statelens.py")
sl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sl)


class IndexBuildResult(unittest.TestCase):
    """`run_logged` returns (code, tail); treating it as a code inverts the check."""

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / "statelens"
        (self.sl_dir / "extract").mkdir(parents=True)
        self.index = sl.index_path(self.sl_dir)
        self._which, self._run, self._say = sl.shutil.which, sl.run_logged, sl.say
        sl.shutil.which = lambda _name: "/usr/bin/rust-analyzer"
        sl.say = lambda *_args, **_kw: None

    def tearDown(self):
        sl.shutil.which, sl.run_logged, sl.say = self._which, self._run, self._say

    @staticmethod
    def output(command):
        """Where the command asks rust-analyzer to write the index."""
        return pathlib.Path(command[command.index("--output") + 1])

    def stub(self, command, _log, cwd=None, stdin_text=None, echo=True):
        """A successful run that leaves a real index behind, so the snapshot
        step runs exactly as it does in a campaign."""
        self.echoed = echo
        # SCIP paths are relative to the indexed crate, and index_load
        # prefixes them, so the file has to live under consensus/.
        (self.repo / "consensus/src").mkdir(parents=True, exist_ok=True)
        (self.repo / "consensus/src/x.rs").write_text("fn f() {}\n")
        self.output(command).write_bytes(scip_index("src/x.rs", "sym", [0, 3, 4], [0, 0, 0, 9]))
        return 0, []

    def test_success_returns_the_index_path(self):
        sl.run_logged = self.stub
        self.assertEqual(sl.index_build(self.repo, self.sl_dir, "simplex"), self.index)

    def test_success_snapshots_the_indexed_sources(self):
        # Without the snapshot no query can rebase, so a successful build that
        # skipped it would leave the index quietly serving stale lines.
        sl.run_logged = self.stub
        sl.index_build(self.repo, self.sl_dir, "simplex")
        stored = json.loads(sl.snapshot_path(self.sl_dir).read_text())
        self.assertEqual(stored, {"consensus/src/x.rs": "fn f() {}\n"})

    def test_unreadable_index_still_returns_the_path(self):
        # The index is queryable even when the snapshot cannot be taken, and the
        # snapshot of the index it replaced must not stay to rebase its lines.
        def stub(command, _log, cwd=None, stdin_text=None, echo=True):
            self.output(command).write_bytes(b"\x1f\x8bnot protobuf")
            return 0, []

        sl.snapshot_path(self.sl_dir).write_text('{"consensus/src/old.rs": ""}')
        sl.run_logged = stub
        self.assertEqual(sl.index_build(self.repo, self.sl_dir, "simplex"), self.index)
        self.assertFalse(sl.snapshot_path(self.sl_dir).exists())

    def test_a_failed_build_leaves_the_previous_index_whole(self):
        # rust-analyzer writes as it goes, so a build that fails halfway must not
        # leave a truncated index where the previous one was.
        previous = scip_index("src/x.rs", "sym", [0, 3, 4], [0, 0, 0, 9])
        self.index.write_bytes(previous)
        sl.snapshot_path(self.sl_dir).write_text("{}")

        def stub(command, _log, cwd=None, stdin_text=None, echo=True):
            self.output(command).write_bytes(previous[:7])
            return 1, ["error: interrupted"]

        sl.run_logged = stub
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(sl.index_build(self.repo, self.sl_dir, "qmdb"))
        self.assertEqual(self.index.read_bytes(), previous)
        self.assertEqual(sl.snapshot_path(self.sl_dir).read_text(), "{}")
        self.assertEqual(list((self.sl_dir / "extract").glob("*.new")), [])

    def test_a_campaign_whose_build_fails_answers_from_no_index(self):
        # A consensus index left by an earlier campaign would otherwise answer the
        # queries of a qmdb campaign whose own build failed.
        (self.repo / "consensus/src").mkdir(parents=True)
        (self.repo / "consensus/src/x.rs").write_text("fn f() {}\n")
        self.index.write_bytes(scip_index("src/x.rs", "sym", [0, 3, 4], [0, 0, 0, 9]))
        sl.snapshot_write(self.repo, self.sl_dir, ["consensus/src/x.rs"])
        sl.run_logged = lambda *_a, **_kw: (1, ["simulated failure"])
        campaign = sl.Campaign.__new__(sl.Campaign)
        campaign.repo, campaign.sl_dir, campaign.profile_name = self.repo, self.sl_dir, "qmdb"
        with contextlib.redirect_stdout(io.StringIO()):
            campaign.code_index()
        self.assertFalse(self.index.exists())
        self.assertFalse(sl.snapshot_path(self.sl_dir).exists())
        saved = sl.repo_root
        sl.repo_root = lambda: self.repo
        self.addCleanup(setattr, sl, "repo_root", saved)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sl.main(["code", "defs", "sym", "--tests"]), 1)

    def test_nonzero_exit_returns_none(self):
        sl.run_logged = lambda *_a, **_kw: (1, ["error"])
        self.assertIsNone(sl.index_build(self.repo, self.sl_dir, "simplex"))

    def test_zero_exit_but_no_file_returns_none(self):
        sl.run_logged = lambda *_a, **_kw: (0, [])
        self.assertIsNone(sl.index_build(self.repo, self.sl_dir, "simplex"))

    def test_missing_rust_analyzer_returns_none(self):
        sl.shutil.which = lambda _name: None
        self.assertIsNone(sl.index_build(self.repo, self.sl_dir, "simplex"))

    def test_rust_analyzer_output_stays_off_the_console(self):
        # rust-analyzer logs ERROR lines for definitions in macro-declared
        # modules and keeps going; on a console they read as a failure, and an
        # operator interrupted a campaign over them.
        sl.run_logged = self.stub
        sl.index_build(self.repo, self.sl_dir, "simplex")
        self.assertFalse(self.echoed, "the index build must not echo rust-analyzer")

    def test_a_failed_build_shows_why(self):
        sl.run_logged = lambda *_a, **_kw: (1, ["error: could not load the workspace"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertIsNone(sl.index_build(self.repo, self.sl_dir, "simplex"))
        self.assertIn("could not load the workspace", out.getvalue())


def packed(*values):
    """Encode ints as a protobuf packed repeated field."""
    out = bytearray()
    for value in values:
        while True:
            byte = value & 0x7F
            value >>= 7
            out.append(byte | (0x80 if value else 0))
            if not value:
                break
    return bytes(out)


class LoggedRuns(unittest.TestCase):
    """`run_logged` with `echo` off still has to keep the whole output in the log
    and return the tail, or a quiet step would hide its own failure."""

    def run_quiet(self, echo):
        directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        log = directory / "run.log"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code, tail = sl.run_logged(
                [sys.executable, "-c", "print('one'); print('two')"], log, directory, echo=echo
            )
        return code, tail, log.read_text(), out.getvalue()

    def test_echo_off_writes_the_log_and_not_the_console(self):
        code, tail, log, console = self.run_quiet(echo=False)
        self.assertEqual(code, 0)
        self.assertEqual(tail, ["one", "two"])
        self.assertIn("one\ntwo\n", log)
        self.assertEqual(console, "")

    def test_echo_on_writes_both(self):
        _code, _tail, log, console = self.run_quiet(echo=True)
        self.assertIn("one\ntwo\n", log)
        self.assertEqual(console, "one\ntwo\n")

    def run_timed(self, script, timeout, env=None):
        directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        log = directory / "run.log"
        started = time.monotonic()
        code, tail = sl.run_logged(
            [sys.executable, "-c", script], log, directory, echo=False, timeout=timeout, env=env
        )
        return code, tail, log.read_text(), time.monotonic() - started

    def test_a_timeout_kills_the_command_and_what_it_started(self):
        # The child holds the output pipe too, so killing the command alone would leave
        # the read waiting for the child's sleep: a replay's kill must reach both.
        script = (
            "import subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "print('started', flush=True)\n"
            "time.sleep(60)\n"
        )
        code, tail, log, elapsed = self.run_timed(script, 1)
        self.assertIsNone(code, "a kill is not an exit code")
        self.assertEqual(tail, ["started"])
        self.assertIn("statelens: killed after 1 s", log)
        self.assertLess(elapsed, 30)

    def test_a_timeout_kills_a_child_that_outlives_the_command(self):
        # The command exits at once; the child it started keeps the output pipe. The
        # deadline holds over what the command started, not over its own process.
        script = (
            "import subprocess, sys\n"
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "print('started', flush=True)\n"
        )
        code, tail, log, elapsed = self.run_timed(script, 1)
        self.assertIsNone(code, "a kill is not an exit code")
        self.assertEqual(tail, ["started"])
        self.assertIn("statelens: killed after 1 s", log)
        self.assertLess(elapsed, 30)

    def test_an_interrupt_kills_the_command_and_what_it_started(self):
        # The command ignores the interrupt and would write after the script restored the
        # tree. The interrupt reaches this process alone, as `kill -INT` does and as a
        # terminal's Ctrl-C does once the command has its own group: the script kills the
        # group before the interrupt propagates.
        directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        script = (
            "import signal, sys, time\n"
            "from pathlib import Path\n"
            "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
            "root = Path(sys.argv[1])\n"
            "(root / 'ready').write_text('')\n"
            "time.sleep(0.5)\n"
            "(root / 'late').write_text('late write')\n"
        )

        def interrupt():
            deadline = time.monotonic() + 10
            while not (directory / "ready").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            signal.pthread_kill(threading.main_thread().ident, signal.SIGINT)

        threading.Thread(target=interrupt, daemon=True).start()
        with self.assertRaises(KeyboardInterrupt):
            sl.run_logged(
                [sys.executable, "-c", script, str(directory)], directory / "run.log",
                directory, echo=False,
            )
        time.sleep(1)
        self.assertFalse((directory / "late").exists(), "the command wrote after the interrupt")

    def test_a_command_that_ends_in_time_keeps_its_code_and_its_environment(self):
        script = "import os, sys; print(os.environ['STATELENS_REACH']); sys.exit(3)"
        env = dict(os.environ, STATELENS_REACH="1")
        code, tail, log, _elapsed = self.run_timed(script, 60, env)
        self.assertEqual((code, tail), (3, ["1"]))
        self.assertNotIn("killed", log)


class ScipRanges(unittest.TestCase):
    """A range collapses to three elements on one line, where [2] is a column."""

    def test_three_element_range_round_trips(self):
        self.assertEqual(sl.scip_packed(packed(69, 4, 28)), [69, 4, 28])

    def test_four_element_range_round_trips(self):
        self.assertEqual(sl.scip_packed(packed(689, 4, 698, 5)), [689, 4, 698, 5])

    def test_multi_byte_varints(self):
        self.assertEqual(sl.scip_packed(packed(1, 300, 70000)), [1, 300, 70000])


def tag(field, wire):
    return packed((field << 3) | wire)


def length_delimited(field, payload):
    return tag(field, 2) + packed(len(payload)) + payload


def scip_index(relative, symbol, span, enclosing, roles=1):
    """The smallest SCIP index holding one definition occurrence."""
    occurrence = (
        length_delimited(1, packed(*span))
        + length_delimited(2, symbol.encode())
        + tag(3, 0)
        + packed(roles)
        + length_delimited(7, packed(*enclosing))
    )
    document = length_delimited(1, relative.encode()) + length_delimited(2, occurrence)
    return length_delimited(2, document)


class ScipExtents(unittest.TestCase):
    """The end line of a definition, which `callers` and `callees` depend on."""

    def load(self, enclosing):
        directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        path = directory / "i.scip"
        path.write_bytes(scip_index("src/x.rs", "sym", [69, 4, 28], enclosing))
        _occurrences, definitions, _names = sl.index_load(path)
        return definitions["sym"]

    def test_one_line_definition_does_not_end_before_it_starts(self):
        # [start line, start char, end char]: the third element is a column.
        self.assertEqual(self.load([69, 4, 28]), ("consensus/src/x.rs", 70, 70))

    def test_multi_line_definition_keeps_its_end_line(self):
        # [start line, start char, end line, end char]
        self.assertEqual(self.load([689, 4, 698, 5]), ("consensus/src/x.rs", 690, 699))


class SyntaxSites(unittest.TestCase):
    """Polarity comes from the token after the whole field expression."""

    @classmethod
    def setUpClass(cls):
        if not sl.ast_available():
            raise unittest.SkipTest("rust-analyzer is not installed")
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.path = cls.tmp / "t.rs"
        cls.path.write_text(
            "struct S { armed: bool, items: Vec<u8> }\n"                 # 1
            "impl S {\n"                                                  # 2
            "    fn new() -> S { S { armed: false, items: vec![] } }\n"   # 3
            "    fn arm(&mut self) { self.armed = true; }\n"              # 4
            "    fn ready(&self) -> bool { self.armed }\n"                # 5
            "    fn armed(&self) -> bool { self.armed }\n"                # 6
            "    fn add(&mut self) { self.items.push(1); }\n"             # 7
            "    fn lend(&mut self) { fill(&mut self.items); }\n"         # 8
            "    fn count(&self) -> usize { self.items.len() }\n"         # 9
            "    fn peek(&self) -> &Vec<u8> { &self.items }\n"             # 10
            "    fn set(&mut self) { self.items[0] = 2; }\n"               # 11
            "    fn bump(&mut self) { self.items[0] += 1; }\n"             # 12
            "    fn wrap(&mut self) { (self.items).push(3); }\n"           # 13
            "    fn lend_paren(&mut self) { fill(&mut (self.items)); }\n"  # 14
            "}\n"                                                         # 15
            "fn fill(_items: &mut Vec<u8>) {}\n"                          # 16
        )

    def test_classifies_write_init_and_read(self):
        writes, reads, inits, opaque, maybe = sl.ast_field_ops(self.path, "armed")
        self.assertEqual(opaque, [], "no macro bodies in this fixture")
        self.assertEqual(maybe, [], "a bool is never handed out here")
        # `self.armed = true` is a write, not a read of the `self` path.
        self.assertEqual(writes, [4])
        # a struct literal field is an initial value, not a write
        self.assertEqual(inits, [3])
        # the two bodies that read it; the method declaration on line 6 is a
        # different entity of the same spelling and is not counted
        self.assertEqual(reads, [5, 6])

    def test_a_field_handed_out_is_neither_a_read_nor_a_write(self):
        # The gap: `self.items.push(1)` and `fill(&mut self.items)` were reads, so
        # `--writes-only` left every mutation through a method out of the
        # transition inventory.
        writes, reads, inits, _opaque, maybe = sl.ast_field_ops(self.path, "items")
        # An assignment through an index is a write of the field.
        self.assertEqual(writes, [11, 12])
        self.assertEqual(inits, [3])
        # Parentheses around the receiver or the borrowed place change nothing.
        self.assertEqual(
            maybe,
            [(7, ".push(..)"), (8, "&mut"), (9, ".len(..)"), (13, ".push(..)"), (14, "&mut")],
        )
        self.assertEqual(reads, [10], "a shared borrow cannot write, so it stays a read")

    def test_a_write_through_a_projection_is_a_write_of_the_field(self):
        path = self.tmp / "p.rs"
        path.write_text(
            "struct Inner { count: u8 }\n"                        # 1
            "struct S { inner: Inner }\n"                         # 2
            "impl S {\n"                                          # 3
            "    fn set(&mut self) { self.inner.count = 1; }\n"   # 4
            "    fn add(&mut self) { self.inner.count += 1; }\n"  # 5
            "    fn get(&self) -> u8 { self.inner.count }\n"      # 6
            "}\n"                                                 # 7
        )
        writes, reads, _inits, _opaque, maybe = sl.ast_field_ops(path, "inner")
        self.assertEqual((writes, reads, maybe), ([4, 5], [6], []))
        writes, reads, _inits, _opaque, maybe = sl.ast_field_ops(path, "count")
        self.assertEqual((writes, reads, maybe), ([4, 5], [6], []))

    def test_derefs_and_tuple_assignments_reach_the_field(self):
        path = self.tmp / "d.rs"
        path.write_text(
            "struct S { boxed: Box<Vec<u8>>, items: Vec<u8>, n: u8 }\n"        # 1
            "impl S {\n"                                                        # 2
            "    fn clear_boxed(&mut self) { (*self.boxed).clear(); }\n"        # 3
            "    fn lend_boxed(&mut self) { fill(&mut *self.boxed); }\n"        # 4
            "    fn reset(&mut self) { *self.boxed = Box::new(vec![]); }\n"     # 5
            "    fn pair(&mut self) { (self.items, self.n) = (vec![], 0); }\n"  # 6
            "    fn neg(&self) -> i32 { -(self.n as i32) }\n"                   # 7
            "    fn both(&self) -> (u8, u8) { (self.n, self.n) }\n"             # 8
            "}\n"                                                               # 9
            "fn fill(_v: &mut Vec<u8>) {}\n"                                    # 10
        )
        writes, reads, _inits, _opaque, maybe = sl.ast_field_ops(path, "boxed")
        self.assertEqual((writes, reads, maybe), ([5], [], [(3, ".clear(..)"), (4, "&mut")]))
        writes, reads, _inits, _opaque, maybe = sl.ast_field_ops(path, "items")
        self.assertEqual((writes, reads, maybe), ([6], [], []))
        writes, reads, _inits, _opaque, maybe = sl.ast_field_ops(path, "n")
        self.assertEqual((writes, reads, maybe), ([6], [7, 8], []))

    def test_writes_only_keeps_the_maybe_sites(self):
        saved = sl.repo_root
        sl.repo_root = lambda: self.tmp
        self.addCleanup(setattr, sl, "repo_root", saved)
        out = io.StringIO()
        args = argparse.Namespace(
            query="sites", name="items", paths=["t.rs"], tests=True, writes_only=True
        )
        with contextlib.redirect_stdout(out):
            sl.cmd_ast(args)
        text = out.getvalue()
        self.assertIn("write  t.rs:11", text)
        self.assertIn("maybe  t.rs:7  .push(..)", text)
        self.assertIn("maybe  t.rs:8  &mut", text)
        self.assertNotIn("read", text)
        self.assertNotIn("init", text)

    def test_a_directory_stands_for_its_rust_files(self):
        # The beacon prompt works one actor directory at a time, and both queries
        # raised IsADirectoryError when given one.
        saved = sl.repo_root
        sl.repo_root = lambda: self.tmp
        self.addCleanup(setattr, sl, "repo_root", saved)
        actor = self.tmp / "actor"
        (actor / "round").mkdir(parents=True, exist_ok=True)
        (actor / "round" / "state.rs").write_text(
            "struct R { armed: bool }\n"
            "impl R {\n"
            "    // A race with the timer is recovered from the journal.\n"
            "    fn arm(&mut self) { self.armed = true; }\n"
            "}\n"
        )
        (actor / "README.md").write_text("// race, but not Rust\n")
        notes = argparse.Namespace(
            query="notes", pattern="race", paths=["actor"], tests=True
        )
        sites = argparse.Namespace(
            query="sites", name="armed", paths=["actor"], tests=True, writes_only=True
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(sl.cmd_ast(notes), 0)
            self.assertEqual(sl.cmd_ast(sites), 0)
        text = out.getvalue()
        self.assertIn("actor/round/state.rs:3  FN@", text)
        self.assertIn("1 comment block(s)", text)
        self.assertIn("write  actor/round/state.rs:4", text)
        self.assertNotIn("README", text)


class AstPaths(unittest.TestCase):
    """What the PATH arguments of the `ast` queries name, without parsing anything."""

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        for relative in ("src/a.rs", "src/b/c.rs", "src/b/notes.md", "lib.rs"):
            (self.repo / relative).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / relative).write_text("")

    def test_a_directory_expands_to_its_rust_files_in_order(self):
        self.assertEqual(
            sl.ast_paths(self.repo, ["src", "lib.rs"]),
            [pathlib.Path("src/a.rs"), pathlib.Path("src/b/c.rs"), pathlib.Path("lib.rs")],
        )

    def test_a_missing_path_is_a_usage_error(self):
        with self.assertRaises(sl.Abort) as raised:
            sl.ast_paths(self.repo, ["src/gone.rs"])
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("src/gone.rs", str(raised.exception))


class Rebasing(unittest.TestCase):
    """Instrumentation moves lines, so an indexed line is not a current line."""

    ORIGINAL = (
        "pub struct Round { armed: bool }\n"
        "\n"
        "impl Round {\n"
        "    pub fn arm(&mut self) {\n"
        "        self.armed = true;\n"
        "    }\n"
        "}\n"
    )

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / "statelens"
        (self.sl_dir / "extract").mkdir(parents=True)
        self.rel = "src/lib.rs"
        self.file = self.repo / self.rel
        self.file.parent.mkdir(parents=True, exist_ok=True)
        self.file.write_text(self.ORIGINAL)
        sl.snapshot_write(self.repo, self.sl_dir, [self.rel])

    def rebaser(self):
        return sl.Rebaser(self.repo, self.sl_dir)

    def test_unchanged_file_keeps_its_lines(self):
        self.assertEqual(self.rebaser().place(self.rel, 5, "armed"), (5, ""))

    def test_insertion_above_moves_the_line(self):
        # an earlier batch inserts two lines above `arm`
        self.file.write_text(
            self.ORIGINAL.replace(
                "impl Round {", "impl Round {\n    // probe\n    fn note(&self) {}", 1
            )
        )
        where, note = self.rebaser().place(self.rel, 5, "armed")
        self.assertEqual((where, note), (7, "moved"))
        # and the name really is there now
        self.assertIn("armed", self.file.read_text().splitlines()[where - 1])

    def test_edited_line_is_reported_lost_not_guessed(self):
        self.file.write_text(self.ORIGINAL.replace("        self.armed = true;\n", ""))
        _where, note = self.rebaser().place(self.rel, 5, "armed")
        self.assertEqual(note, "lost")

    def test_report_names_the_changed_files(self):
        self.file.write_text(self.ORIGINAL.replace("impl Round {", "impl Round {\n", 1))
        rebaser = self.rebaser()
        rebaser.place(self.rel, 5)
        self.assertIn("1 indexed file(s) have changed", rebaser.report())

    def test_file_absent_from_the_snapshot_is_marked_not_trusted(self):
        # An empty or partial snapshot must not make a stale line look current.
        sl.snapshot_path(self.sl_dir).write_text("{}")
        rebaser = self.rebaser()
        self.assertEqual(rebaser.place(self.rel, 5, "armed"), (5, "unindexed"))
        self.assertIn("no snapshot", rebaser.report())

    def test_missing_snapshot_is_announced(self):
        sl.snapshot_path(self.sl_dir).unlink()
        self.assertIn("no source snapshot", self.rebaser().report())

    def test_a_campaign_is_told_its_own_edits_need_no_rebuild(self):
        # A campaign builds the index once and rebases through its own instrumentation
        # (D43). Advising a rebuild made its agent report the index as broken.
        (self.sl_dir / "campaign").mkdir()
        (self.sl_dir / "campaign" / "meta.json").write_text(json.dumps({"profile": "simplex"}))
        self.file.write_text(self.ORIGINAL.replace("impl Round {", "impl Round {\n", 1))
        report = self.rebaser().report()
        self.assertIn("1 indexed file(s) have changed", report)
        self.assertIn("the campaign's own instrumentation", report)
        self.assertNotIn("Rebuild", report)
        # A file that is gone is not an instrumentation edit, so the advice stays.
        self.file.unlink()
        self.assertIn("Rebuild with `just code-index`", self.rebaser().report())

    def test_test_boundary_uses_the_rebased_line(self):
        # production code above, `#[cfg(test)]` below; a hit on the last
        # production line must not become a test hit when lines shift.
        text = "fn a() {}\n" * 4 + "#[cfg(test)]\nmod t {}\n"
        self.file.write_text(text)
        sl.snapshot_write(self.repo, self.sl_dir, [self.rel])
        boundaries = {}
        self.assertFalse(sl.index_is_test(self.repo, boundaries, self.rel, 4))
        # insert two lines at the top: the old line 4 is now line 6, and the
        # boundary has moved from 5 to 7, so it is still production.
        self.file.write_text("// probe\n// probe\n" + text)
        where, _note = self.rebaser().place(self.rel, 4)
        self.assertEqual(where, 6)
        self.assertFalse(sl.index_is_test(self.repo, {}, self.rel, where))
        # without rebasing, line 4 would be compared against the new boundary
        self.assertFalse(sl.index_is_test(self.repo, {}, self.rel, 4))


class CommentAttribution(unittest.TestCase):
    """A doc comment is the first token of its item, so the item begins at the
    comment; searching forward first lands on the body's first statement."""

    SOURCE = (
        "struct S { armed: bool }\n"                    # 1
        "\n"                                            # 2
        "impl S {\n"                                    # 3
        "    /// Recovers the latch after a replay.\n"   # 4  doc -> FN at 4
        "    fn recover(&mut self) {\n"                  # 5
        "        let first = 1;\n"                       # 6
        "        // never clear it twice in one view\n"  # 7  in body -> stmt at 8
        "        self.armed = true;\n"                   # 8
        "        let _ = first;\n"                       # 9
        "    }\n"                                        # 10
        "}\n"                                            # 11
    )

    @classmethod
    def setUpClass(cls):
        if not sl.ast_available():
            raise unittest.SkipTest("rust-analyzer is not installed")
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.path = cls.tmp / "t.rs"
        cls.path.write_text(cls.SOURCE)

    def notes(self, pattern):
        return sl.ast_notes(self.path, pattern)

    def test_doc_comment_names_its_function_not_a_nested_statement(self):
        found = self.notes("replay")
        self.assertEqual(len(found), 1, found)
        line, _text, item = found[0]
        self.assertEqual(line, 4)
        self.assertEqual(item, ("FN", 5 - 1))  # the FN begins at the doc comment

    def test_comment_in_a_body_names_what_follows_it(self):
        found = self.notes("never")
        self.assertEqual(len(found), 1, found)
        line, _text, item = found[0]
        self.assertEqual(line, 7)
        self.assertIsNotNone(item)
        self.assertEqual(item[1], 8)
        self.assertIn(item[0], ("EXPR_STMT", "LET_STMT"))


class MacroBodies(unittest.TestCase):
    """`rust-analyzer parse` does not expand macros, so a macro body is a bare
    token tree. A name there must be reported, not dropped."""

    SOURCE = (
        "macro_rules! pick { ($($t:tt)*) => { $($t)* } }\n"
        "struct S { armed: bool }\n"
        "impl S {\n"
        "    fn plain(&mut self) { self.armed = true; }\n"
        "    fn wrapped(&mut self) { pick! { self.armed = true; } }\n"
        "}\n"
    )

    @classmethod
    def setUpClass(cls):
        if not sl.ast_available():
            raise unittest.SkipTest("rust-analyzer is not installed")
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.path = cls.tmp / "t.rs"
        cls.path.write_text(cls.SOURCE)

    def test_a_write_inside_a_macro_is_reported_as_unknown_not_dropped(self):
        writes, reads, inits, opaque, _maybe = sl.ast_field_ops(self.path, "armed")
        self.assertEqual(writes, [4], "the plain write")
        self.assertEqual(opaque, [5], "the write inside the macro body")
        self.assertNotIn(5, reads, "a macro-body site must not pass as a read")
        self.assertEqual(inits, [])


class Cleaning(unittest.TestCase):
    """`clean --yes` has to leave a checkout a next campaign will accept.

    Two ways it did not: `git checkout --` on an intent-to-add path succeeds and
    leaves an empty staged file, and `git checkout --` restores the index, so
    instrumentation the operator staged survived.
    """

    def run_git(self, *args):
        return subprocess.run(
            ("git",) + args, cwd=self.repo, capture_output=True, text=True, check=True
        ).stdout

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        for relative in (
            "consensus/src/simplex/mod.rs",
            "consensus/src/marshal/mod.rs",
            "consensus/fuzz/marshal/fuzz_targets/keep.rs",
        ):
            target = self.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("fn original() {}\n")
        self.run_git("init", "-q", ".")
        self.run_git("config", "user.email", "t@example.invalid")
        self.run_git("config", "user.name", "t")
        self.run_git("config", "commit.gpgsign", "false")
        self.run_git("add", "-A")
        self.run_git("commit", "-qm", "base")
        self._root, self._say = sl.repo_root, sl.say
        sl.repo_root = lambda: self.repo
        sl.say = lambda *_a, **_kw: None

    def tearDown(self):
        sl.repo_root, sl.say = self._root, self._say

    def clean(self):
        return sl.cmd_clean(argparse.Namespace(yes=True))

    def status(self):
        return self.run_git("status", "--porcelain").strip()

    def test_agent_added_file_is_deleted(self):
        helper = self.repo / "consensus/src/simplex/helper.rs"
        helper.write_text("fn helper() {}\n")
        self.run_git("add", "--intent-to-add", "consensus/src/simplex/helper.rs")
        delete, restore, _roots = sl.clean_plan(self.repo)
        self.assertIn("consensus/src/simplex/helper.rs", delete)
        self.assertNotIn("consensus/src/simplex/helper.rs", restore)
        self.assertEqual(self.clean(), 0)
        self.assertFalse(helper.exists(), "an added file must be deleted, not emptied")
        self.assertEqual(self.status(), "")

    def test_untracked_file_is_deleted(self):
        stray = self.repo / "consensus/src/marshal/stray.rs"
        stray.write_text("fn stray() {}\n")
        self.assertEqual(self.clean(), 0)
        self.assertFalse(stray.exists())
        self.assertEqual(self.status(), "")

    def test_staged_instrumentation_is_restored_from_head(self):
        edited = self.repo / "consensus/src/simplex/mod.rs"
        edited.write_text("fn original() { sl_probe!(); }\n")
        self.run_git("add", "consensus/src/simplex/mod.rs")
        self.assertEqual(self.clean(), 0)
        self.assertNotIn("sl_probe", edited.read_text())
        self.assertEqual(self.status(), "", "the index must match HEAD too")

    def test_unstaged_edit_is_restored(self):
        edited = self.repo / "consensus/src/marshal/mod.rs"
        edited.write_text("fn original() { sl_assert!(); }\n")
        self.assertEqual(self.clean(), 0)
        self.assertNotIn("sl_assert", edited.read_text())

    def test_clean_tree_is_left_alone(self):
        self.assertEqual(self.clean(), 0)
        self.assertEqual(self.status(), "")

    def test_an_untracked_helper_directory_is_deleted(self):
        # Git collapses a wholly untracked directory to one `dir/` entry, and a
        # directory cannot be unlinked; `record()` has not run, so the files are
        # untracked.
        extra = self.repo / "consensus/src/simplex/extra"
        extra.mkdir()
        (extra / "helper.rs").write_text("fn helper() {}\n")
        (extra / "second.rs").write_text("fn second() {}\n")
        delete, _restore, _roots = sl.clean_plan(self.repo)
        self.assertIn("consensus/src/simplex/extra/helper.rs", delete)
        self.assertIn("consensus/src/simplex/extra/second.rs", delete)
        self.assertNotIn("consensus/src/simplex/extra/", delete)
        self.assertEqual(self.clean(), 0)
        self.assertFalse((extra / "helper.rs").exists())
        self.assertFalse(extra.exists(), "the emptied directory should go too")
        self.assertEqual(self.status(), "")

    def test_a_root_directory_is_never_removed(self):
        (self.repo / "consensus/src/simplex/stray.rs").write_text("fn s() {}\n")
        self.assertEqual(self.clean(), 0)
        self.assertTrue((self.repo / "consensus/src/simplex").is_dir())

    def test_a_qmdb_campaign_is_undone(self):
        for relative in (
            "storage/src/qmdb/mod.rs",
            "storage/Cargo.toml",
            "storage/fuzz/Cargo.toml",
            "storage/fuzz/fuzz_targets/qmdb_x.rs",
        ):
            target = self.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("original\n")
        self.run_git("add", "-A")
        self.run_git("commit", "-qm", "storage")
        runtime = self.repo / sl.QMDB_RS
        runtime.write_text("//! runtime\n")
        self.run_git("add", "--intent-to-add", sl.QMDB_RS)
        variant = self.repo / "storage/fuzz/fuzz_targets/qmdb_x_statelens.rs"
        variant.write_text("fuzz_target!(|input: In| {});\n")
        for relative in ("storage/src/qmdb/mod.rs", "storage/Cargo.toml", "storage/fuzz/Cargo.toml"):
            (self.repo / relative).write_text("original\nedited\n")
        self.assertEqual(self.clean(), 0)
        self.assertEqual(self.status(), "")
        self.assertFalse(runtime.exists())
        self.assertFalse(variant.exists())
        self.assertEqual((self.repo / "storage/Cargo.toml").read_text(), "original\n")

    def test_what_synthesis_wrote_in_a_fuzz_package_is_undone_but_not_its_corpus(self):
        package = self.repo / "consensus/fuzz/simplex"
        for relative, text in (
            (".gitignore", "*/fuzz/*/artifacts\n*/fuzz/*/corpus\n*/fuzz/*/coverage\n"),
            ("consensus/fuzz/simplex/src/lib.rs", "pub mod state_cov;\n"),
            ("consensus/fuzz/simplex/src/chaos/runner.rs", "fn run() {}\n"),
            ("consensus/fuzz/simplex/fuzz_targets/simplex_a.rs", "fuzz_target!(|i: I| f(i));\n"),
        ):
            (self.repo / relative).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / relative).write_text(text)
        self.run_git("add", "-A")
        self.run_git("commit", "-qm", "package")
        modules = package / "src/target_states"
        modules.mkdir()
        (modules / "mod.rs").write_text("pub mod ts0001_simplex_a;\n")
        (modules / "ts0001_simplex_a.rs").write_text("pub fn fuzz() {}\n")
        self.run_git("add", "--intent-to-add", "consensus/fuzz/simplex/src/target_states/mod.rs")
        thin = package / "fuzz_targets/simplex_a_ts0001_statelens.rs"
        thin.write_text("fuzz_target!(|i: I| {});\n")
        (package / "src/lib.rs").write_text("pub mod state_cov;\npub mod target_states;\n")
        (package / "src/chaos/runner.rs").write_text("fn run() {} // [statelens] tss:TS-0001\n")
        (package / "crash-stray").write_text("x")
        kept = [package / "corpus/simplex_a_ts0001_statelens/input",
                package / "artifacts/simplex_a_ts0001_statelens/crash-1",
                package / "coverage/simplex_a_ts0001_statelens/coverage.log"]
        for path in kept:
            path.parent.mkdir(parents=True)
            path.write_text("kept")
        _delete, _restore, roots = sl.clean_plan(self.repo)
        self.assertIn("consensus/fuzz/simplex/", roots)
        self.assertIn("consensus/fuzz/marshal/", roots)
        self.assertNotIn("storage/fuzz/", roots, "synthesis refuses qmdb")
        self.assertEqual(self.clean(), 0)
        self.assertEqual(self.status(), "")
        self.assertFalse(modules.exists(), "target_states/ must go")
        self.assertFalse(thin.exists())
        self.assertFalse((package / "crash-stray").exists())
        self.assertEqual((package / "src/lib.rs").read_text(), "pub mod state_cov;\n")
        for path in kept:
            self.assertEqual(path.read_text(), "kept", "git ignores it, so clean keeps it")

    def test_what_git_ignores_under_target_states_is_deleted(self):
        # A module named `target`, an agent's scratch or a Finder file there survives a
        # synthesis's restore, and a campaign refuses a checkout with target_states/.
        (self.repo / ".gitignore").write_text("target\n*.DS_Store\n")
        self.run_git("add", ".gitignore")
        self.run_git("commit", "-qm", "ignore")
        modules = self.repo / "consensus/fuzz/simplex/src/target_states"
        ignored = ["consensus/fuzz/simplex/src/target_states/target/mod.rs",
                   "consensus/fuzz/simplex/src/target_states/target/notes.txt",
                   "consensus/fuzz/simplex/src/target_states/.DS_Store"]
        for files in ([], ["consensus/fuzz/simplex/src/target_states/mod.rs"]):
            for relative in ignored + files:
                (self.repo / relative).parent.mkdir(parents=True, exist_ok=True)
                (self.repo / relative).write_text("x\n")
            delete, _restore, _roots = sl.clean_plan(self.repo)
            self.assertEqual(sorted(set(delete) & set(ignored + files)), sorted(ignored + files))
            self.assertEqual(self.clean(), 0)
            self.assertFalse(modules.exists(), files)
            self.assertEqual(self.status(), "")

    def test_a_target_states_directory_left_is_reported(self):
        modules = self.repo / "consensus/fuzz/simplex/src/target_states"
        (modules / "empty").mkdir(parents=True)
        (modules / "mod.rs").write_text("pub mod ts0004_simplex_a;\n")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(self.clean(), 1)
        self.assertIn("?? consensus/fuzz/simplex/src/target_states/", output.getvalue())
        # Nothing is left to delete, but the directory still blocks a campaign.
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(self.clean(), 1)
        self.assertIn("?? consensus/fuzz/simplex/src/target_states/", output.getvalue())

    def test_all_four_kinds_at_once(self):
        (self.repo / "consensus/src/simplex/helper.rs").write_text("fn h() {}\n")
        self.run_git("add", "--intent-to-add", "consensus/src/simplex/helper.rs")
        (self.repo / "consensus/src/marshal/stray.rs").write_text("fn s() {}\n")
        (self.repo / "consensus/src/simplex/mod.rs").write_text("fn original() { a(); }\n")
        self.run_git("add", "consensus/src/simplex/mod.rs")
        (self.repo / "consensus/src/marshal/mod.rs").write_text("fn original() { b(); }\n")
        self.assertEqual(self.clean(), 0)
        self.assertEqual(self.status(), "")
        self.assertFalse((self.repo / "consensus/src/simplex/helper.rs").exists())
        self.assertFalse((self.repo / "consensus/src/marshal/stray.rs").exists())


class WorktreeScope(unittest.TestCase):
    """A Phase 1 agent can write anywhere in the operator's tree, so the whole
    worktree is watched, not only the invariant registry."""

    def run_git(self, *args):
        return subprocess.run(
            ("git",) + args, cwd=self.repo, capture_output=True, text=True, check=True
        ).stdout

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        (self.repo / "docs").mkdir(parents=True)
        (self.repo / "README.md").write_text("original\n")
        (self.repo / "docs/guide.md").write_text("original\n")
        (self.repo / "untracked").mkdir()
        self.run_git("init", "-q", ".")
        self.run_git("config", "user.email", "t@example.invalid")
        self.run_git("config", "user.name", "t")
        self.run_git("config", "commit.gpgsign", "false")
        self.run_git("add", "README.md", "docs/guide.md")
        self.run_git("commit", "-qm", "base")

    def changed(self, before, after):
        return sorted(
            path
            for path in set(before) | set(after)
            if before.get(path) != after.get(path)
        )

    def test_a_new_file_is_seen(self):
        before = sl.worktree_state(self.repo)
        (self.repo / "docs/stray.md").write_text("written by an agent\n")
        self.assertEqual(self.changed(before, sl.worktree_state(self.repo)),
                         ["docs/stray.md"])

    def test_a_modified_tracked_file_is_seen(self):
        before = sl.worktree_state(self.repo)
        (self.repo / "README.md").write_text("edited\n")
        self.assertEqual(self.changed(before, sl.worktree_state(self.repo)),
                         ["README.md"])

    def test_a_deleted_tracked_file_is_seen(self):
        before = sl.worktree_state(self.repo)
        (self.repo / "docs/guide.md").unlink()
        self.assertEqual(self.changed(before, sl.worktree_state(self.repo)),
                         ["docs/guide.md"])

    def test_a_second_edit_to_an_already_dirty_file_is_seen(self):
        # The status code stays ` M`, so only a digest catches this. It is the
        # normal case in a development checkout, which is already dirty.
        (self.repo / "README.md").write_text("the operator's own edit\n")
        before = sl.worktree_state(self.repo)
        self.assertIn("README.md", before)
        (self.repo / "README.md").write_text("the operator's edit, plus the agent's\n")
        self.assertEqual(self.changed(before, sl.worktree_state(self.repo)),
                         ["README.md"])

    def test_a_file_in_an_untracked_directory_is_seen(self):
        # Without -uall git collapses this to `untracked/` and a new file in it
        # would not change the report.
        (self.repo / "untracked/first.txt").write_text("one\n")
        before = sl.worktree_state(self.repo)
        (self.repo / "untracked/second.txt").write_text("two\n")
        self.assertEqual(self.changed(before, sl.worktree_state(self.repo)),
                         ["untracked/second.txt"])

    def test_an_unchanged_tree_reports_nothing(self):
        before = sl.worktree_state(self.repo)
        self.assertEqual(self.changed(before, sl.worktree_state(self.repo)), [])


class ExtractScope(unittest.TestCase):
    """`extract` must report what the agent wrote outside the registry.

    The prompt machinery is stubbed: what is under test is the scope check, not
    prompt composition.
    """

    def run_git(self, *args):
        return subprocess.run(
            ("git",) + args, cwd=self.repo, capture_output=True, text=True, check=True
        ).stdout

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / "statelens"
        (self.sl_dir / "invariants/simplex").mkdir(parents=True)
        (self.repo / "README.md").write_text("original\n")
        self.run_git("init", "-q", ".")
        self.run_git("config", "user.email", "t@example.invalid")
        self.run_git("config", "user.name", "t")
        self.run_git("config", "commit.gpgsign", "false")
        self.run_git("add", "-A")
        self.run_git("commit", "-qm", "base")
        self.saved = {
            name: getattr(sl, name)
            for name in ("repo_root", "say", "load_config", "resolve_agent",
                         "extract_values", "compose", "agent_command", "run_logged",
                         "lint_paths", "registry_files")
        }
        sl.repo_root = lambda: self.repo
        sl.say = lambda *_a, **_kw: None
        sl.load_config = lambda _d: {}
        sl.resolve_agent = lambda _c, _a: "claude"
        sl.extract_values = lambda *_a, **_kw: {"NEXT_ID": "INV-0001"}
        sl.compose = lambda *_a, **_kw: "prompt"
        sl.agent_command = lambda *_a, **_kw: ["true"]
        sl.lint_paths = lambda *_a, **_kw: 0
        sl.registry_files = lambda *_a, **_kw: []
        self.addCleanup(self.restore)

    def restore(self):
        for name, value in self.saved.items():
            setattr(sl, name, value)

    def extract(self, agent_does):
        def stub(_command, log, _cwd, stdin_text=None):
            pathlib.Path(log).parent.mkdir(parents=True, exist_ok=True)
            pathlib.Path(log).write_text("stub\n")
            agent_does()
            return 0, []

        sl.run_logged = stub
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = sl.cmd_extract(
                argparse.Namespace(agent=None, registry="simplex", kind="issue",
                                   sources=["x"], number=self.number)
            )
        return code, out.getvalue()

    number = None

    def write_invariants(self, count):
        def write():
            for index in range(count):
                (self.sl_dir / f"invariants/simplex/INV-{index + 1:04d}.md").write_text("x\n")
        return write

    def test_more_invariants_than_asked_for_is_a_problem(self):
        self.number = 1
        code, output = self.extract(self.write_invariants(2))
        self.assertEqual(code, 3, output)
        self.assertIn("more than the 1 asked for", output)

    def test_as_many_as_asked_for_is_clean(self):
        self.number = 2
        code, output = self.extract(self.write_invariants(2))
        self.assertEqual(code, 0, output)

    def test_a_number_below_one_is_refused(self):
        self.number = 0
        with self.assertRaises(sl.Abort):
            self.extract(lambda: None)

    def test_a_quiet_run_is_clean(self):
        code, output = self.extract(lambda: None)
        self.assertEqual(code, 0, output)

    def test_an_edit_outside_the_registry_is_reported(self):
        def touch_readme():
            (self.repo / "README.md").write_text("the agent edited this\n")

        code, output = self.extract(touch_readme)
        self.assertEqual(code, 3, output)
        self.assertIn("README.md", output)
        self.assertIn("outside invariants/", output)

    def test_a_new_file_outside_the_registry_is_reported(self):
        def write_stray():
            (self.repo / "consensus").mkdir(parents=True, exist_ok=True)
            (self.repo / "consensus/stray.rs").write_text("fn stray() {}\n")

        code, output = self.extract(write_stray)
        self.assertEqual(code, 3, output)
        self.assertIn("consensus/stray.rs", output)



class ExtractionInputs(unittest.TestCase):
    """What `--number` asks of the analyst, which sources `comment` accepts, and where
    invariants go, so a private finding never lands in the tracked registry."""

    REPO = HERE.parents[1]

    def test_the_count_is_a_ceiling_never_a_quota(self):
        self.assertIn("as many invariants as the sources justify", sl.extraction_count(None))
        text = sl.extraction_count(10)
        self.assertIn("Write 10 invariant(s)", text)
        self.assertIn("write fewer", text)
        self.assertIn("Never invent", text)

    def test_findings_go_to_the_local_registry_and_git_ignores_it(self):
        self.assertEqual(
            sl.extraction_destination("kb", "qmdb"), sl.SL / "invariants.local" / "qmdb"
        )
        self.assertEqual(sl.extraction_destination("comment", "qmdb"), sl.SL / "invariants" / "qmdb")
        ignored = (HERE.parent / ".gitignore").read_text().splitlines()
        self.assertIn("invariants.local/", ignored)

    def test_comment_sources_are_the_registry_code(self):
        sl.check_comment_sources(self.REPO, "qmdb", ["storage/src/qmdb/mod.rs:1-93"])
        sl.check_comment_sources(self.REPO, "qmdb", ["storage/src/qmdb/current"])
        with self.assertRaises(sl.Abort) as caught:
            sl.check_comment_sources(self.REPO, "qmdb", ["consensus/src/simplex/mod.rs"])
        self.assertNotIn("kb", str(caught.exception))

    def test_a_corpus_root_given_as_a_comment_source_points_to_the_kb_kind(self):
        corpus = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, corpus, True)
        with self.assertRaises(sl.Abort) as caught:
            sl.check_comment_sources(self.REPO, "qmdb", ["storage/src/qmdb/mod.rs", str(corpus)])
        self.assertIn(f"just extract-invariants --registry qmdb kb {corpus}", str(caught.exception))

    def test_ids_and_bindings_span_the_local_registry(self):
        sl_dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, sl_dir, True)
        for relative in (
            "invariants/qmdb/INV-0002.md",
            "invariants.local/qmdb/INV-0005.md",
            "invariants.local/qmdb/INV-0001.md",
            "false-invariants/qmdb/FALSE-0003.md",
        ):
            (sl_dir / relative).parent.mkdir(parents=True, exist_ok=True)
            (sl_dir / relative).write_text("x\n")
        self.assertEqual(sl.next_id(sl_dir, "INV"), "INV-0006")
        self.assertEqual(sl.next_id(sl_dir, "FALSE"), "FALSE-0004")
        bound = [path.name for path in sl.registry_invariants(sl_dir, "qmdb", with_false=True)]
        self.assertEqual(bound, ["INV-0001.md", "INV-0002.md", "INV-0005.md", "FALSE-0003.md"])
        self.assertNotIn("FALSE-0003.md", [p.name for p in sl.registry_invariants(sl_dir, "qmdb")])

    def test_the_lint_accepts_the_local_registry(self):
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        path = root / "invariants.local" / "qmdb" / "INV-0001.md"
        path.parent.mkdir(parents=True)
        path.write_text(
            "---\nid: INV-0001\ntitle: A title\nsource_kind: kb\nsource_ref: finding QMDB-1\n"
            "scope: [database]\n---\n\n## Statement\nThe database shall keep its root.\n\n"
            "## Rationale\nIt must.\n\n## Evidence\nA finding.\n"
        )
        self.assertEqual(sl.lint_file(path), [])


class KbExtraction(unittest.TestCase):
    """`extract kb` reads the findings of a registry's scope through the `kb` commands
    and writes what it derives to the local registry, never the tracked one."""

    FINDING = (
        "# {title}\n\n```claim\nmodule: {module}\nsummary: {summary}\n"
        "severity_current: high\nremediation_status: fixed\n```\n\n## Root Cause\nSomething.\n"
    )

    def run_git(self, *args):
        subprocess.run(("git",) + args, cwd=self.repo, capture_output=True, check=True)

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.corpus = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.corpus, True)
        self.sl_dir = self.repo / sl.SL
        for part in ("prompts", "templates"):
            shutil.copytree(HERE.parent / part, self.sl_dir / part)
        (self.repo / "README.md").write_text("x\n")
        for args in (("init", "-q", "."), ("config", "user.email", "t@example.invalid"),
                     ("config", "user.name", "t"), ("config", "commit.gpgsign", "false"),
                     ("add", "-A"), ("commit", "-qm", "base")):
            self.run_git(*args)
        for state, identifier, module, summary in (
            ("valid", "QMDB-1", "storage/qmdb/any", "stale batch applied"),
            ("valid", "SIMPLEX-1", "consensus/simplex", "vote twice"),
        ):
            path = self.corpus / "findings" / state / f"{identifier}.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.FINDING.format(title=identifier, module=module, summary=summary))
        saved = {name: getattr(sl, name) for name in
                 ("repo_root", "say", "resolve_agent", "agent_command", "run_logged")}
        self.addCleanup(lambda: [setattr(sl, k, v) for k, v in saved.items()])
        environment = os.environ.get("STATELENS_KB")
        self.addCleanup(
            lambda: os.environ.pop("STATELENS_KB", None) if environment is None
            else os.environ.__setitem__("STATELENS_KB", environment)
        )
        sl.repo_root = lambda: self.repo
        sl.say = lambda *_a, **_kw: None
        sl.resolve_agent = lambda _c, _a: "claude"
        self.phases = []
        sl.agent_command = lambda _c, _a, phase, _r: self.phases.append(phase) or ["true"]

    def extract(self, write):
        seen = {}

        def agent(_command, log, _cwd, stdin_text=None):
            pathlib.Path(log).write_text("stub\n")
            seen["prompt"] = stdin_text
            seen["kb"] = os.environ.get("STATELENS_KB")
            write()
            return 0, []

        sl.run_logged = agent
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = sl.cmd_extract(argparse.Namespace(
                agent=None, registry="qmdb", kind="kb", sources=[str(self.corpus)], number=1
            ))
        return code, out.getvalue(), seen

    def invariant(self):
        path = self.sl_dir / "invariants.local/qmdb/INV-0001.md"
        path.write_text(
            "---\nid: INV-0001\ntitle: No stale batch is applied\nsource_kind: kb\n"
            "source_ref: finding QMDB-1\nscope: [database, any]\n---\n\n## Statement\n"
            "The database shall not apply a stale batch.\n\n## Rationale\nIt corrupts.\n\n"
            "## Evidence\nA finding.\n"
        )

    def test_the_findings_in_scope_reach_the_agent_and_the_result_stays_local(self):
        code, output, seen = self.extract(self.invariant)
        self.assertEqual(code, 0, output)
        self.assertEqual(self.phases, ["kb"])
        self.assertEqual(seen["kb"], str(self.corpus))
        prompt = seen["prompt"]
        self.assertIn("`QMDB-1`: valid", prompt)
        self.assertNotIn("SIMPLEX-1", prompt)
        self.assertIn("statelens/invariants.local/qmdb/<ID>.md", prompt)
        self.assertIn("kb show --registry qmdb", prompt)
        self.assertIn("Write 1 invariant(s)", prompt)
        self.assertNotIn("{{", prompt)
        self.assertFalse((self.sl_dir / "invariants" / "qmdb").exists())

    def test_a_write_to_the_tracked_registry_is_a_problem(self):
        def tracked():
            path = self.sl_dir / "invariants/qmdb/INV-0001.md"
            path.parent.mkdir(parents=True)
            path.write_text("x\n")

        code, output, _seen = self.extract(tracked)
        self.assertEqual(code, 3, output)
        self.assertIn("outside the registry invariants.local/qmdb/", output)

    def test_a_corpus_without_findings_in_scope_is_refused(self):
        shutil.rmtree(self.corpus / "findings" / "valid")
        (self.corpus / "findings" / "valid").mkdir()
        with self.assertRaises(sl.Abort) as caught:
            self.extract(lambda: None)
        self.assertIn("names a module of the qmdb registry", str(caught.exception))


CARD = """\
---
id: {id}
title: A replica certifying after its own nullify vote
source_kind: {kind}
source_ref: {ref}
scope: [replica]
---

## Statement
While the replica has voted nullify in view v and holds a notarization of v, the replica is
certifying that notarization.

## Rationale
A certification that waits on a verdict the nullify vote discarded wedges the view.

## Evidence
The source says so.

## History
E1. harness: runs four replicas, R honest, in view v.
    Check (R, v): R is in view v.
E2. R: votes nullify in v.
    Check (R as E1, v as E1): R broadcast its nullify vote for v.
E3. harness: delivers to R a notarization of payload d for v, signed by the
    three other replicas.
    Check (R as E1, v as E1, d): R holds that notarization and did not
    sign it.
E4. R: starts certifying d for v.
    Holds (R as E1, v as E1, d as E3): R's certification of d for v is outstanding.
Order: E2 and E3 in either order.

## Knobs
| Knob | Event | Domain | Source value |
|---|---|---|---|
| pause between harness actions | E2-E3 | 250, 0, 1000 ms | 250 ms |
| E2 against E3 | E2, E3 | E2 first; E3 first | E2 first |
"""


def card_text(id="TS-0001", kind="text", ref="text: nullify then certify"):
    return CARD.format(id=id, kind=kind, ref=ref)


class TargetStateLint(unittest.TestCase):
    """Lint rules 1, 5 and 7 as they apply to cards, and rules 12 (History) and 13 (Knobs),
    which apply to cards only (SPEC section 18.3)."""

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)

    def lint(self, text, where="target-states/simplex/TS-0001.md"):
        path = self.root / where
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return sl.lint_file(path)

    def history(self, old, new):
        self.assertIn(old, CARD)
        return [p for p in self.lint(card_text().replace(old, new)) if "(rule 12)" in p]

    def knobs(self, table):
        text = card_text().split("## Knobs\n")[0] + "## Knobs\n" + table
        return [p for p in self.lint(text) if "(rule 13)" in p]

    def test_the_worked_card_is_clean_in_both_trees(self):
        self.assertEqual(self.lint(card_text()), [])
        self.assertEqual(self.lint(card_text(), "target-states.local/marshal/TS-0001.md"), [])

    def test_example_cards_bind_what_their_checks_name(self):
        root = HERE.parent / "target-states/marshal"
        ts1 = sl.card_history((root / "TS-0001.md").read_text())
        self.assertIn(("p1", 2), ts1.events[4].entities)
        ts2 = sl.card_history((root / "TS-0002.md").read_text())
        self.assertIn(("B", 1), ts2.events[3].entities)

    def test_a_card_lives_in_a_consensus_card_tree(self):
        for where in ("target-states/qmdb/TS-0001.md", "invariants/simplex/TS-0001.md",
                      "target-states/simplex/INV-0001.md"):
            problems = self.lint(card_text(id=pathlib.Path(where).stem), where)
            self.assertTrue(any(p.startswith("file name must be") for p in problems), where)
        problems = self.lint(card_text(), "target-states/TS-0001.md")
        self.assertTrue(any("lies directly in target-states/" in p for p in problems), problems)

    def test_test_and_text_are_source_kinds_of_cards_only(self):
        self.assertEqual(self.lint(card_text(kind="test")), [])
        invariant = self.root / "invariants/simplex/INV-0001.md"
        invariant.parent.mkdir(parents=True)
        invariant.write_text(
            "---\nid: INV-0001\ntitle: t\nsource_kind: test\nsource_ref: x\nscope: [replica]\n"
            "---\n\n## Statement\nThe replica shall hold.\n\n## Rationale\nR.\n\n## Evidence\nE.\n"
        )
        self.assertTrue(any(p.startswith("source_kind") for p in sl.lint_file(invariant)))

    def test_a_card_needs_its_five_sections_in_order(self):
        text = card_text()
        no_knobs = text.split("## Knobs\n")[0]
        self.assertIn("missing section: ## Knobs", self.lint(no_knobs))
        history, knobs = text.split("## History\n")[1].split("## Knobs\n")
        swapped = text.split("## History\n")[0] + "## Knobs\n" + knobs + "\n## History\n" + history
        self.assertIn(
            "sections Statement, Rationale, Evidence, History and Knobs must be in this order",
            self.lint(swapped),
        )

    def test_events_are_numbered_without_a_gap(self):
        problems = self.history("E3. harness: delivers", "E5. harness: delivers")
        self.assertTrue(any("E5. where E3. comes next" in p for p in problems), problems)

    def test_each_event_starts_with_its_actor(self):
        problems = self.history("E2. R: votes", "E2. votes")
        self.assertTrue(any("E2. does not start with its actor" in p for p in problems), problems)
        problems = self.history("E2. R: votes", "E2. B: votes")
        self.assertTrue(any("E2.'s actor B is neither harness" in p for p in problems), problems)
        # A replica's name starts with a capital letter: the reach check reads it so.
        head, rest = card_text().split("## History\n")
        history, knobs = rest.split("## Knobs\n")
        history = sl.re.sub(r"\bR\b", "r", history)
        lower = f"{head}## History\n{history}## Knobs\n{knobs}"
        problems = [p for p in self.lint(lower) if "(rule 12)" in p]
        self.assertTrue(any("E2.'s actor r is a replica, whose name starts with a capital"
                            in p for p in problems), problems)

    def test_one_check_line_per_event_and_one_holds_line_for_the_last(self):
        problems = self.history("    Check (R, v): R is in view v.\n", "")
        self.assertTrue(any("E1. needs exactly one indented Check line, and has: none" in p
                            for p in problems), problems)
        problems = self.history("    Holds (R as E1", "    Check (R as E1")
        self.assertTrue(any("E4. needs exactly one indented Holds line, and has: Check" in p
                            for p in problems), problems)
        problems = self.history("    Check (R, v): R is in view v.\n",
                                "    Check (R, v): R is in view v.\n    Check (R): again.\n")
        self.assertTrue(any("has: Check, Check" in p for p in problems), problems)
        problems = self.history("    Check (R, v): R", "    Check R, v: R")
        self.assertTrue(any("does not start with the entities it binds" in p
                            for p in problems), problems)

    def test_entity_lists_are_names_optionally_bound_to_an_earlier_event(self):
        problems = self.history("Check (R, v)", "Check ()")
        self.assertTrue(any("empty entity list" in p for p in problems), problems)
        problems = self.history("Check (R, v)", "Check (R, the view)")
        self.assertTrue(any("lists `the view`" in p for p in problems), problems)
        problems = self.history("(R as E1, v as E1, d as E3)", "(R as E1, v as E1, d as E4)")
        self.assertTrue(any("`d as E4` names E4, not an earlier event" in p
                            for p in problems), problems)
        problems = self.history("Check (R as E1, v as E1): R broadcast",
                                "Check (R as E1, v as E1, d as E1): R broadcast")
        self.assertTrue(any("E1.'s entity list does not hold d" in p for p in problems), problems)

    def test_the_order_line_is_last_and_names_defined_events(self):
        self.assertEqual(self.history("Order: E2 and E3 in either order.",
                                      "Order: E2 and E3 in either order; E1 and\n"
                                      "    E2 in either order"), [])
        problems = self.history("Order: E2 and E3", "Order: E2 and E9")
        self.assertTrue(any("Order: names E9" in p for p in problems), problems)
        problems = self.history("Order: E2 and E3 in either order.", "Order: E2 before E3.")
        self.assertTrue(any("is not `Ei and Ej in either order`" in p for p in problems), problems)
        moved = "Order: E2 and E3 in either order.\n"
        problems = self.history("E4. R:", moved + "E4. R:")
        self.assertTrue(any("E4. follows the Order: line" in p for p in problems), problems)
        problems = self.history(moved, moved + moved)
        self.assertTrue(any("more than one Order: line" in p for p in problems), problems)
        problems = self.history("Order: E2", "    Order: E2")
        self.assertTrue(any("the Order: line starts at the beginning of a line" in p
                            for p in problems), problems)

    def test_a_history_without_events_is_reported(self):
        text = card_text().split("## History\n")
        text = text[0] + "## History\nThe replica votes, then certifies.\n\n## Knobs\nNone.\n"
        problems = [p for p in self.lint(text) if "(rule 12)" in p]
        self.assertTrue(any("no event" in p for p in problems), problems)

    def test_knobs_are_none_or_the_table(self):
        self.assertEqual(self.knobs("None.\n"), [])
        self.assertTrue(self.knobs("Nothing to vary.\n"))
        self.assertTrue(self.knobs("| Knob | Events | Domain | Source value |\n|---|---|---|---|\n"
                                   "| a | E1 | 1, 2 | 1 |\n"))
        problems = self.knobs("| Knob | Event | Domain | Source value |\n| a | E1 | 1, 2 | 1 |\n")
        self.assertTrue(any("|---|---|---|---|" in p for p in problems), problems)

    def test_knob_rows_are_bounded_complete_and_name_defined_events(self):
        header = "| Knob | Event | Domain | Source value |\n|---|---|---|---|\n"
        self.assertTrue(any("0 row(s)" in p for p in self.knobs(header)))
        rows = "".join(f"| k{n} | E1 | 1, 2 | 1 |\n" for n in range(17))
        self.assertTrue(any("17 row(s)" in p for p in self.knobs(header + rows)))
        self.assertEqual(self.knobs(header + rows.split("\n", 1)[1]), [])
        problems = self.knobs(header + "| a | E1 |  | 1 |\n")
        self.assertTrue(any("has an empty cell" in p for p in problems), problems)
        problems = self.knobs(header + "| a | E2-E9 | 1, 2 | 1 |\n")
        self.assertTrue(any("names E9, which the History does not define" in p
                            for p in problems), problems)
        problems = self.knobs(header + "| a | all | 1, 2 | 1 |\n")
        self.assertTrue(any("names no event" in p for p in problems), problems)
        problems = self.knobs(header + "| a | E1 | 1, 2 |\n")
        self.assertTrue(any("four cells" in p for p in problems), problems)

    def test_cards_are_registry_files_and_share_the_ts_counter(self):
        sl_dir = self.root / "statelens"
        for relative in ("target-states/marshal/TS-0002.md", "target-states.local/simplex/TS-0007.md",
                         "invariants/simplex/INV-0009.md"):
            (sl_dir / relative).parent.mkdir(parents=True, exist_ok=True)
            (sl_dir / relative).write_text("x\n")
        self.assertEqual(sl.next_id(sl_dir, "TS"), "TS-0008")
        self.assertEqual(sl.next_id(sl_dir, "INV"), "INV-0010")
        names = [path.name for path in sl.registry_files(sl_dir)]
        self.assertEqual(sorted(names), ["INV-0009.md", "TS-0002.md", "TS-0007.md"])


class ExtractStates(unittest.TestCase):
    """`extract --states` (SPEC section 18.4): the new kinds and their refusals, the one
    prompt rendered alone, routing by disclosure, and the post-checks over the card trees.
    The agent is a stub; the prompt files are fixtures, so the real prompts may change."""

    def run_git(self, *args):
        return subprocess.run(
            ("git",) + args, cwd=self.repo, capture_output=True, text=True, check=True
        ).stdout

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / sl.SL
        placeholders = " ".join("{{%s}}" % name for name in (
            "KIND", "NEXT_ID", "TEMPLATE", "SOURCES", "REGISTRY", "DESTINATION", "COUNT",
            "QUERY", "CONTEXT", "SOURCE_ROOT", "COMMIT"))
        for relative, text in (
            ("prompts/state-analyst.md", "STATE ANALYST " + placeholders + "\n"),
            ("prompts/analyst.md", "SHARED INVARIANT PART {{KIND}}\n"),
            ("prompts/subsystems/simplex-analyst.md", "SIMPLEX CONTEXT\n"),
            ("prompts/subsystems/marshal-analyst.md", "MARSHAL CONTEXT\n"),
            ("templates/target-state.md", "CARD TEMPLATE\n"),
            ("templates/invariant.md", "INVARIANT TEMPLATE\n"),
        ):
            (self.sl_dir / relative).parent.mkdir(parents=True, exist_ok=True)
            (self.sl_dir / relative).write_text(text)
        lines = "".join(f"line {n}\n" for n in range(1, 11))
        for relative in ("consensus/src/simplex/mod.rs", "consensus/src/marshal/mod.rs",
                         "consensus/fuzz/simplex/src/lib.rs", "docs/design.md"):
            (self.repo / relative).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / relative).write_text(lines)
        for args in (("init", "-q", "."), ("config", "user.email", "t@example.invalid"),
                     ("config", "user.name", "t"), ("config", "commit.gpgsign", "false"),
                     ("add", "-A"), ("commit", "-qm", "base")):
            self.run_git(*args)
        self.commit = self.run_git("rev-parse", "--short=12", "HEAD").strip()
        sl._GIT_FILES.clear()
        saved = {name: getattr(sl, name) for name in
                 ("repo_root", "say", "load_config", "resolve_agent", "agent_command",
                  "run_logged")}
        self.addCleanup(lambda: [setattr(sl, k, v) for k, v in saved.items()])
        environment = os.environ.get("STATELENS_KB")
        self.addCleanup(
            lambda: os.environ.pop("STATELENS_KB", None) if environment is None
            else os.environ.__setitem__("STATELENS_KB", environment)
        )
        self.config = {}
        self.said = []
        self.phases = []
        sl.repo_root = lambda: self.repo
        sl.say = self.said.append
        sl.load_config = lambda _d: self.config
        sl.resolve_agent = lambda _c, _a: "claude"
        sl.agent_command = lambda _c, _a, phase, _r: self.phases.append(phase) or ["true"]

    def extract(self, kind, *sources, agent_does=lambda: None, registry="simplex",
                local=False, number=None, states=True):
        seen = {}

        def agent(_command, log, _cwd, stdin_text=None):
            pathlib.Path(log).write_text("stub\n")
            seen["prompt"] = stdin_text
            agent_does()
            return 0, []

        sl.run_logged = agent
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = sl.cmd_extract(argparse.Namespace(
                agent=None, registry=registry, kind=kind, sources=list(sources),
                number=number, states=states, local=local,
            ))
        return code, out.getvalue(), seen.get("prompt")

    def write(self, relative, text=None):
        def write():
            path = self.sl_dir / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text if text is not None else card_text(id=path.stem))
        return write

    def refused(self, *args, **kwargs):
        with self.assertRaises(sl.Abort) as caught:
            self.extract(*args, **kwargs)
        self.assertEqual(caught.exception.code, 1, str(caught.exception))
        return str(caught.exception)

    def test_test_text_and_local_need_states_and_qmdb_is_refused(self):
        self.assertIn("just extract-states test",
                      self.refused("test", "consensus/src/simplex/mod.rs:1", states=False))
        self.refused("text", "a text about a view", states=False)
        self.assertIn("needs --states", self.refused("issue", "o/r#1", local=True, states=False))
        self.assertIn("no qmdb registry", self.refused("issue", "o/r#1", registry="qmdb"))

    def test_a_test_source_is_a_line_of_the_registry_code_or_its_fuzz_package(self):
        sl.check_test_sources(self.repo, "simplex", [
            "consensus/src/simplex/mod.rs:3", "consensus/fuzz/simplex/src/lib.rs:2-10"])
        for source in ("consensus/src/marshal/mod.rs:1", "consensus/src/simplex/mod.rs",
                       "consensus/src/simplex/mod.rs:11", "consensus/src/simplex/mod.rs:5-4",
                       "consensus/src/simplex/none.rs:1", "consensus/src/simplex:1"):
            with self.assertRaises(sl.Abort) as caught:
                sl.check_test_sources(self.repo, "simplex", [source])
            self.assertEqual(caught.exception.code, 1, source)
        sl.check_test_sources(self.repo, "marshal", ["consensus/src/marshal/mod.rs:1"])
        self.refused("test", "consensus/src/marshal/mod.rs:1")

    def test_a_test_that_head_does_not_have_is_refused_before_the_agent(self):
        # A card cites its test at HEAD (rule 10), where an untracked or merely staged file
        # does not exist: the refusal comes at preflight, not after the agent's attempt.
        source = "consensus/src/simplex/new_test.rs"
        (self.repo / source).write_text("#[test]\nfn new_test() {}\n")
        for staged in (False, True):
            if staged:
                self.run_git("add", source)
                sl._GIT_FILES.clear()
            with self.assertRaises(sl.Abort) as caught:
                sl.check_test_sources(self.repo, "simplex", [f"{source}:2"])
            self.assertEqual(caught.exception.code, 1)
            self.assertIn("is not in HEAD", str(caught.exception))
            self.assertIn("`text` source", str(caught.exception))
        self.assertIn("is not in HEAD", self.refused("test", f"{source}:2"))
        self.assertEqual(self.phases, [], "the agent ran for a test no card can cite")
        # A tracked test edited in the worktree exists at HEAD: it passes, and the run
        # warns that its lines may not be HEAD's (the staged file is in the index too).
        tracked = self.repo / "consensus/src/simplex/mod.rs"
        tracked.write_text(tracked.read_text() + "// edited\n")
        sl.check_test_sources(self.repo, "simplex", ["consensus/src/simplex/mod.rs:3"])
        self.assertEqual(
            sl.unpinnable(sl.worktree_state(self.repo)),
            ["consensus/src/simplex/mod.rs", source],
        )

    def test_a_test_card_is_tracked_rendered_alone_and_gets_its_excerpts(self):
        ref = f"consensus/src/simplex/mod.rs:2-3@{self.commit} (a_test)"
        card = "target-states/simplex/TS-0001.md"
        code, output, prompt = self.extract(
            "test", "consensus/src/simplex/mod.rs:2",
            agent_does=self.write(card, card_text(kind="test", ref=ref)),
        )
        self.assertEqual(code, 0, output)
        self.assertEqual(self.phases, [1])
        self.assertTrue(prompt.startswith("STATE ANALYST test TS-0001 CARD TEMPLATE"), prompt)
        for expected in ("- consensus/src/simplex/mod.rs:2", "statelens/target-states/simplex",
                         "SIMPLEX CONTEXT", "consensus/src/simplex", self.commit,
                         "as many cards as the sources justify"):
            self.assertIn(expected, prompt)
        self.assertNotIn("SHARED INVARIANT PART", prompt)
        self.assertNotIn("{{", prompt)
        text = (self.sl_dir / card).read_text()
        self.assertIn("## Source excerpts\n", text)
        self.assertIn("line 2\nline 3\n", text)
        self.assertTrue(any("next synthesis of its profile" in line for line in self.said))
        self.assertFalse(any("git ignores" in line for line in self.said))

    def test_a_text_literal_is_saved_for_the_agent_and_its_card_stays_local(self):
        literal = "R votes nullify in v, then a notarization of v reaches R."
        code, output, prompt = self.extract(
            "text", literal, agent_does=self.write("target-states.local/simplex/TS-0001.md"))
        self.assertEqual(code, 0, output)
        copies = list((self.sl_dir / "extract").glob("*-text.txt"))
        self.assertEqual(len(copies), 1)
        self.assertEqual(copies[0].read_text(), literal + "\n")
        self.assertIn(str(copies[0].relative_to(self.repo)), prompt)
        self.assertIn("`text: <title>`, never this path", prompt)
        self.assertIn("statelens/target-states.local/simplex", prompt)
        self.assertTrue(any("target-states.local/, which git ignores" in line
                            for line in self.said), self.said)

    def test_a_text_file_is_read_where_it_is_and_a_word_is_refused(self):
        code, output, prompt = self.extract("text", "docs/design.md")
        self.assertEqual(code, 0, output)
        self.assertIn("- docs/design.md ", prompt)
        self.assertNotIn("saved at", prompt)
        self.assertIn("statelens/target-states.local/simplex", prompt)
        self.assertIn("quote a text", self.refused("text", "notes.txt"))

    def test_a_card_written_to_the_tracked_tree_from_a_private_source_is_a_problem(self):
        code, output, _ = self.extract(
            "text", "a text about the view", agent_does=self.write("target-states/simplex/TS-0001.md"))
        self.assertEqual(code, 3, output)
        self.assertIn("outside the registry target-states.local/simplex/", output)

    def test_routing_is_by_disclosure(self):
        outside = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, outside, True)
        public = (("issue", ["https://github.com/o/r/pull/1"]), ("issue", ["o/r#1"]),
                  ("design", ["docs/design.md#intro"]), ("paper", ["https://e.org/p.pdf#page=2"]),
                  ("spec", ["docs/design.md:3"]), ("test", ["consensus/src/simplex/mod.rs:2"]))
        for kind, sources in public:
            self.assertIsNone(sl.private_reason(self.repo, kind, sources, False), kind)
        self.assertIn("--local", sl.private_reason(self.repo, "issue", ["o/r#1"], True))
        self.assertIn("kb", sl.private_reason(self.repo, "kb", [], False))
        self.assertIn("text", sl.private_reason(self.repo, "text", ["docs/design.md"], False))
        reason = sl.private_reason(self.repo, "design", [str(outside / "d.md") + "#s"], False)
        self.assertIn("outside the repository", reason)
        code, output, prompt = self.extract(
            "test", "consensus/src/simplex/mod.rs:2", local=True,
            agent_does=self.write("target-states.local/simplex/TS-0001.md"))
        self.assertEqual(code, 0, output)
        self.assertIn("statelens/target-states.local/simplex", prompt)
        self.assertTrue(any("--local" in line for line in self.said), self.said)

    def test_a_change_outside_the_card_trees_is_a_problem(self):
        code, output, _ = self.extract(
            "issue", "o/r#1", agent_does=self.write("invariants/simplex/INV-0001.md", "x\n"))
        self.assertEqual(code, 3, output)
        self.assertIn("statelens/invariants/simplex/INV-0001.md: the agent wrote outside the "
                      "registry target-states/simplex/", output)

    def test_every_registry_tree_is_watched_whichever_kind_is_written(self):
        # The local trees are ignored, so the worktree check cannot see an edit there.
        (self.sl_dir / ".gitignore").write_text("invariants.local/\ntarget-states.local/\n")
        (self.sl_dir / "prompts/analyst-issue.md").write_text("ISSUE\n")
        self.write("invariants.local/simplex/INV-0001.md", "x\n")()
        self.write("target-states.local/simplex/TS-0001.md")()
        code, output, _ = self.extract(
            "issue", "o/r#1",
            agent_does=self.write("invariants.local/simplex/INV-0001.md", "changed\n"))
        self.assertEqual(code, 3, output)
        self.assertIn("invariants.local/simplex/INV-0001.md: the agent modified or deleted an "
                      "existing invariant", output)
        code, output, _ = self.extract(
            "issue", "o/r#1", states=False,
            agent_does=self.write("target-states.local/simplex/TS-0001.md", "changed\n"))
        self.assertEqual(code, 3, output)
        self.assertIn("target-states.local/simplex/TS-0001.md: the agent modified or deleted an "
                      "existing card", output)

    def test_an_existing_card_is_never_modified_and_ids_continue(self):
        self.write("target-states.local/marshal/TS-0004.md")()
        code, output, prompt = self.extract(
            "issue", "o/r#1",
            agent_does=self.write("target-states.local/marshal/TS-0004.md", "changed\n"))
        self.assertEqual(code, 3, output)
        self.assertIn("modified or deleted an existing card", output)
        self.assertIn("TS-0005", prompt)

    def test_more_cards_than_asked_for_is_a_problem(self):
        def two():
            self.write("target-states/simplex/TS-0001.md")()
            self.write("target-states/simplex/TS-0002.md")()

        code, output, prompt = self.extract("issue", "o/r#1", number=1, agent_does=two)
        self.assertEqual(code, 3, output)
        self.assertIn("wrote 2 cards, more than the 1 asked for", output)
        self.assertIn("Write 1 card(s)", prompt)

    def test_a_new_card_is_linted_with_rules_12_and_13(self):
        bad = card_text().replace("E3. harness", "E5. harness").replace("| E2-E3 |", "| E9 |")
        code, output, _ = self.extract(
            "issue", "o/r#1", agent_does=self.write("target-states/simplex/TS-0001.md", bad))
        self.assertEqual(code, 3, output)
        self.assertIn("(rule 12)", output)
        self.assertIn("(rule 13)", output)

    def test_a_kb_finding_identifier_is_resolved_and_its_card_stays_local(self):
        corpus = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, corpus, True)
        for identifier, module in (("SIMPLEX-1", "consensus/simplex"),
                                   ("SIMPLEX-2", "consensus/simplex"),
                                   ("MARSHAL-1", "consensus/marshal")):
            path = corpus / "findings" / "valid" / f"{identifier}.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(KbExtraction.FINDING.format(
                title=identifier, module=module, summary=f"summary of {identifier}"))
        self.config = {"STATELENS_KB": str(corpus)}
        code, output, prompt = self.extract(
            "kb", "SIMPLEX-2", agent_does=self.write("target-states.local/simplex/TS-0001.md"))
        self.assertEqual(code, 0, output)
        self.assertEqual(self.phases, ["kb"])
        self.assertIn("`SIMPLEX-2`: valid", prompt)
        self.assertNotIn("SIMPLEX-1", prompt)
        self.assertIn("statelens/target-states.local/simplex", prompt)
        self.assertEqual(os.environ.get("STATELENS_KB"), str(corpus))
        self.assertIn("MARSHAL-1", self.refused("kb", "MARSHAL-1"))

    def test_the_recipe_and_the_ignored_local_tree(self):
        self.assertIn('extract-states *args:\n    python3 scripts/statelens.py extract --states "$@"',
                      (HERE.parent / "justfile").read_text())
        self.assertIn("target-states.local/", (HERE.parent / ".gitignore").read_text().splitlines())


class TestCodeRanges(unittest.TestCase):
    """`#[cfg(test)]` marks an item, not a file suffix.

    `simplex/actors/voter/mod.rs` gates one re-export at line 18 and declares
    production configuration after it, with its test module only at 52, so a
    suffix rule labelled the configuration as test code.
    """

    SOURCE = (
        "use core::num::NonZeroUsize;\n"          # 1
        "pub use ingress::Mailbox;\n"             # 2
        "#[cfg(test)]\n"                          # 3  gates only line 4
        "pub use ingress::Message;\n"             # 4
        "\n"                                      # 5
        "pub struct Config {\n"                   # 6  production
        "    pub scheme: u8,\n"                   # 7  production
        "}\n"                                     # 8
        "\n"                                      # 9
        "impl Config {\n"                         # 10
        "    #[cfg(test)]\n"                      # 11 gates only lines 11-12
        "    pub fn only_for_tests() {}\n"        # 12
        "    pub fn used_in_production() {}\n"    # 13 production
        "}\n"                                     # 14
        "\n"                                      # 15
        "#[cfg(test)]\n"                          # 16 the real test module
        "mod tests {\n"                           # 17
        "    fn t() {}\n"                         # 18
        "}\n"                                     # 19
    )

    @classmethod
    def setUpClass(cls):
        if not sl.ast_available():
            raise unittest.SkipTest("rust-analyzer is not installed")

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.rel = "consensus/src/x/mod.rs"
        (self.repo / self.rel).parent.mkdir(parents=True)
        (self.repo / self.rel).write_text(self.SOURCE)

    def is_test(self, line):
        return sl.index_is_test(self.repo, {}, self.rel, line)

    def test_a_gated_re_export_is_test_code(self):
        self.assertTrue(self.is_test(4))

    def test_production_code_after_a_gated_re_export_is_not_test_code(self):
        # the defect: a suffix rule marked everything from line 3 onwards
        self.assertFalse(self.is_test(6), "the struct")
        self.assertFalse(self.is_test(7), "its field")

    def test_a_gated_method_is_test_code_but_its_neighbour_is_not(self):
        self.assertTrue(self.is_test(12))
        self.assertFalse(self.is_test(13))

    def test_the_test_module_is_test_code(self):
        self.assertTrue(self.is_test(17))
        self.assertTrue(self.is_test(18))

    def test_ranges_are_the_item_extents(self):
        self.assertEqual(
            sl.index_test_ranges(self.repo, self.rel), [(3, 4), (11, 12), (16, 19)]
        )

    def test_a_mocks_file_is_test_support_throughout(self):
        other = "consensus/src/x/mocks.rs"
        (self.repo / other).write_text("pub fn harness() {}\n")
        self.assertTrue(sl.index_is_test(self.repo, {}, other, 1))


class KbDocuments(unittest.TestCase):
    """`kb show` on a document must print the document.

    A document has no claim block and no state-bearing sections, so rendering it
    as a finding printed an empty shell of both.
    """

    def setUp(self):
        self.corpus = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.corpus, True)
        (self.corpus / "kb").mkdir()
        self.body = "# Certification design\n\nNullification does not cancel it.\n"
        (self.corpus / "kb/design.md").write_text(self.body)
        # A repository of its own: the query writes its index under the repository, and
        # must not replace the operator's statelens/extract/kb-index.json.
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        (self.repo / sl.SL / "extract").mkdir(parents=True)
        self.saved = {name: getattr(sl, name) for name in ("repo_root", "say")}
        sl.repo_root = lambda: self.repo
        sl.say = lambda *_a, **_kw: None
        self.addCleanup(lambda: [setattr(sl, k, v) for k, v in self.saved.items()])

    def show(self, section=None):
        out = io.StringIO()
        args = argparse.Namespace(
            query="show", registry="simplex", identifier="kb/design.md",
            section=(section.split() if section else []),
        )
        old = os.environ.get("STATELENS_KB")
        os.environ["STATELENS_KB"] = str(self.corpus)
        try:
            with contextlib.redirect_stdout(out):
                code = sl.cmd_kb(args)
        finally:
            if old is None:
                del os.environ["STATELENS_KB"]
            else:
                os.environ["STATELENS_KB"] = old
        return code, out.getvalue()

    def test_show_prints_the_document_body(self):
        code, output = self.show()
        self.assertEqual(code, 0, output)
        self.assertIn("Nullification does not cancel it.", output)
        self.assertIn("(document)", output)
        self.assertNotIn("no claim block", output)

    def test_asking_for_a_section_is_refused_clearly(self):
        with self.assertRaises(sl.Abort) as caught:
            self.show("Root Cause")
        self.assertIn("is a document, which has no sections", str(caught.exception))


def scip_document(relative, occurrences, names=None):
    """A SCIP index of one document holding several occurrences.

    Each occurrence is (symbol, span, enclosing or None, roles). `names` maps
    a symbol to the display name its symbol information carries.
    """
    body = length_delimited(1, relative.encode())
    for symbol, span, enclosing, roles in occurrences:
        one = length_delimited(1, packed(*span)) + length_delimited(2, symbol.encode())
        one += tag(3, 0) + packed(roles)
        if enclosing:
            one += length_delimited(7, packed(*enclosing))
        body += length_delimited(2, one)
    for symbol, display in (names or {}).items():
        info = length_delimited(1, symbol.encode()) + length_delimited(6, display.encode())
        body += length_delimited(3, info)
    return length_delimited(2, body)


class ScipLocals(unittest.TestCase):
    """A `local N` symbol is unique within its document only. rust-analyzer
    starts the numbering afresh in every file, so two files' `local 0` are two
    unrelated bindings, and merging them attributes one file's name, definition
    and references to the other."""

    A = "consensus/src/a.rs"
    B = "consensus/src/b.rs"
    RUN = "rust-analyzer cargo c 1 a/run()."
    QUORUM = "rust-analyzer cargo c 1 a/quorum()."
    SOURCE_A = (
        "fn run() {\n"                  # 1  run spans 1-4
        "    let view = quorum();\n"    # 2  local 0 (view) defined, quorum called
        "    view;\n"                   # 3  local 0 referenced
        "}\n"                           # 4
        "fn quorum() {}\n"              # 5
    )
    SOURCE_B = (
        "fn other() {\n"                # 1
        "    let round = 1;\n"          # 2  local 0 (round) defined
        "    round;\n"                  # 3  local 0 referenced
        "}\n"                           # 4
    )

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / "statelens"
        (self.sl_dir / "extract").mkdir(parents=True)
        (self.repo / "consensus/src").mkdir(parents=True)
        (self.repo / self.A).write_text(self.SOURCE_A)
        (self.repo / self.B).write_text(self.SOURCE_B)
        self.index = sl.index_path(self.sl_dir)
        self.write_index()
        sl.snapshot_write(self.repo, self.sl_dir, [self.A, self.B])
        self.saved = {n: getattr(sl, n) for n in ("repo_root", "say")}
        sl.repo_root = lambda: self.repo
        sl.say = lambda *_args, **_kw: None
        self.addCleanup(lambda: [setattr(sl, k, v) for k, v in self.saved.items()])
        self.loaded = sl.index_load(self.index)

    def write_index(self, run="run"):
        """Two documents that both define `local 0`; `run` names the function."""
        self.index.write_bytes(
            scip_document(
                "src/a.rs",
                [
                    (self.RUN, [0, 3, 6], [0, 0, 3, 1], 1),
                    ("local 0", [1, 8, 12], [1, 8, 12], 1),
                    (self.QUORUM, [1, 15, 21], None, 0),
                    ("local 0", [2, 4, 8], None, 0),
                    (self.QUORUM, [4, 3, 9], [4, 0, 4, 15], 1),
                ],
                {"local 0": "view", self.RUN: run, self.QUORUM: "quorum"},
            )
            + scip_document(
                "src/b.rs",
                [
                    ("local 0", [1, 8, 13], [1, 8, 13], 1),
                    ("local 0", [2, 4, 9], None, 0),
                ],
                {"local 0": "round"},
            )
        )

    def code(self, query, name):
        out = io.StringIO()
        args = argparse.Namespace(query=query, name=name, paths=[], tests=False, all=False)
        with contextlib.redirect_stdout(out):
            sl.cmd_code(args)
        return out.getvalue()

    def test_each_file_keeps_its_own_local(self):
        _occurrences, definitions, names = self.loaded
        locals_ = {sym: where for sym, where in definitions.items() if sl.index_is_local(sym)}
        self.assertEqual(
            locals_,
            {
                f"local 0 in {self.A}": (self.A, 2, 2),
                f"local 0 in {self.B}": (self.B, 2, 2),
            },
        )
        self.assertEqual(names[f"local 0 in {self.A}"], "view")
        self.assertEqual(names[f"local 0 in {self.B}"], "round")

    def test_a_locals_references_never_cross_into_another_file(self):
        out = self.code("refs", "view")
        self.assertIn("1 symbol(s) matching 'view'", out)
        self.assertIn(f"def  {self.A}:2", out)
        self.assertIn(f"ref  {self.A}:3", out)
        self.assertNotIn(self.B, out)
        other = self.code("refs", "round")
        self.assertIn("1 symbol(s) matching 'round'", other)
        self.assertNotIn(self.A, other)

    def test_a_local_is_named_in_its_file(self):
        out = self.code("defs", "round")
        self.assertIn(f"local 0 in {self.B} (round)", out)
        self.assertIn(f"{self.B}:2-2", out)

    def test_a_call_on_a_let_line_belongs_to_the_function(self):
        # The gap: the local's extent is its own binding on the `let` line, and
        # as the innermost definition containing the call it was reported as
        # the caller in place of the function.
        out = self.code("callers", "quorum")
        self.assertIn(f"{self.A}:2  in a/run()", out)
        self.assertNotIn("local", out)

    def test_a_local_is_not_matched_by_its_file_name(self):
        occurrences, definitions, names = self.loaded
        self.assertEqual(sl.index_match(occurrences, definitions, names, "src/b"), [])
        self.assertEqual(sl.index_match(occurrences, definitions, names, "local"), [])

    def test_locals_are_set_aside_when_a_global_carries_the_name(self):
        occurrences, definitions, names = self.loaded
        names = dict(names, **{self.RUN: "view"})
        found = sl.index_match(occurrences, definitions, names, "view")
        self.assertEqual(found, [self.RUN])
        self.assertEqual(sl.index_locals(names, "view", found), 1)
        self.assertEqual(sl.index_locals(names, "round", [f"local 0 in {self.B}"]), 0)

    def test_set_aside_locals_are_counted_in_the_listing(self):
        self.write_index(run="view")
        out = self.code("refs", "view")
        self.assertIn("1 symbol(s) matching 'view'", out)
        self.assertIn("a/run()", out)
        self.assertNotIn("local 0", out)
        self.assertIn("1 local variable(s) named 'view' not shown", out)

    def test_ast_scope_follows_the_files_that_mention_the_name(self):
        self.assertEqual(
            sl.ast_files(self.repo, self.sl_dir, "round", []), [pathlib.Path(self.B)]
        )


class IndexFreshness(unittest.TestCase):
    """A query must never present index coordinates as current ones, and must
    say when the tree has moved on -- including when it matches nothing."""

    REL = "consensus/src/x.rs"
    OUTER = "rust-analyzer cargo c 1 x/outer()."
    INNER = "rust-analyzer cargo c 1 x/inner()."
    SOURCE = (
        "fn outer() {\n"      # 1  outer spans 1-3
        "    inner();\n"      # 2  a call to inner
        "}\n"                 # 3
        "\n"                  # 4
        "fn inner() {}\n"     # 5  inner spans 5-5
    )

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / "statelens"
        (self.sl_dir / "extract").mkdir(parents=True)
        self.file = self.repo / self.REL
        self.file.parent.mkdir(parents=True, exist_ok=True)
        self.file.write_text(self.SOURCE)
        sl.index_path(self.sl_dir).write_bytes(
            scip_document(
                "src/x.rs",
                [
                    (self.OUTER, [0, 3, 8], [0, 0, 2, 1], 1),
                    (self.INNER, [1, 4, 9], None, 0),
                    (self.INNER, [4, 3, 8], [4, 0, 4, 13], 1),
                ],
            )
        )
        sl.snapshot_write(self.repo, self.sl_dir, [self.REL])
        self.saved = {n: getattr(sl, n) for n in ("repo_root", "say")}
        sl.repo_root = lambda: self.repo
        self.said = []
        sl.say = lambda message, *a, **k: self.said.append(str(message))
        self.addCleanup(lambda: [setattr(sl, k, v) for k, v in self.saved.items()])

    def code(self, query, name, **extra):
        out = io.StringIO()
        args = argparse.Namespace(
            query=query, name=name, paths=[], tests=False, all=False, **extra
        )
        with contextlib.redirect_stdout(out):
            code = sl.cmd_code(args)
        return code, out.getvalue(), "\n".join(self.said)

    def test_clean_tree_says_nothing(self):
        _code, _out, said = self.code("refs", "outer")
        self.assertNotIn("changed", said)

    def test_appending_a_function_warns_even_when_nothing_matches(self):
        # The gap: the warning was taken before any hit was placed, so a query
        # that matched nothing reported a clean tree.
        self.file.write_text(self.SOURCE + "\nfn appended() {}\n")
        code, out, said = self.code("refs", "appended")
        self.assertEqual(code, 1)
        self.assertIn("no symbol matches", out)
        self.assertIn("have changed since the index was built", said)

    def test_appending_warns_on_an_ordinary_listing_too(self):
        self.file.write_text(self.SOURCE + "\nfn appended() {}\n")
        _code, _out, said = self.code("refs", "outer")
        self.assertIn("have changed since the index was built", said)

    def test_callees_header_is_rebased(self):
        # The gap: the header printed the index extent verbatim.
        _code, before, _said = self.code("callees", "outer")
        self.assertIn(f"{self.REL}:1-3", before)
        self.file.write_text("// probe\n// probe\n" + self.SOURCE)
        _code, after, _said = self.code("callees", "outer")
        self.assertIn(f"{self.REL}:3-5", after)
        self.assertNotIn(f"{self.REL}:1-3", after)

    def test_a_lost_end_is_not_hidden_by_a_moved_start(self):
        # Prepend two lines so the start moves, and edit the closing brace so
        # the end cannot be mapped. Combining with `or` let `moved` win and
        # printed the stale end as though it were current.
        edited = "// probe\n// probe\n" + self.SOURCE.replace(
            "}\n\nfn inner", "} // touched\n\nfn inner", 1
        )
        self.file.write_text(edited)
        _code, out, _said = self.code("defs", "outer")
        self.assertIn("[lost]", out, out)
        self.assertNotIn("3-3  [moved]", out)
        _code, callees, _said = self.code("callees", "outer")
        self.assertIn("[lost]", callees, callees)

    def test_severity_puts_validity_first(self):
        self.assertEqual(sl.rebase_worst("moved", "lost"), "lost")
        self.assertEqual(sl.rebase_worst("unverified", "lost"), "lost")
        self.assertEqual(sl.rebase_worst("moved", "unverified"), "unverified")
        self.assertEqual(sl.rebase_worst("moved", ""), "moved")
        self.assertEqual(sl.rebase_worst("", ""), "")

    def test_an_unavailable_line_is_not_shown_as_a_number(self):
        self.assertEqual(sl.rebase_line(7, "lost"), "?(7)")
        self.assertEqual(sl.rebase_line(7, "unindexed"), "?(7)")
        self.assertEqual(sl.rebase_line(7, "moved"), "7")
        self.assertEqual(sl.rebase_line(7, ""), "7")

    def test_an_emptied_file_is_not_treated_as_unchanged(self):
        # The gap: the change test required the current text to be nonempty.
        self.file.write_text("")
        _code, out, said = self.code("refs", "outer")
        self.assertIn("lost", out)
        self.assertIn("have changed since the index was built", said)

    def test_a_deleted_file_is_reported(self):
        self.file.unlink()
        _code, out, said = self.code("refs", "outer")
        self.assertIn("lost", out)
        self.assertIn("gone or unreadable", said)

    def test_a_new_source_file_is_reported(self):
        (self.file.parent / "added.rs").write_text("fn fresh() {}\n")
        _code, _out, said = self.code("refs", "outer")
        self.assertIn("appeared since the index was built", said)

    def test_a_source_the_index_skipped_is_not_new(self):
        # storage keeps bench sources no module declares beside indexed code, and
        # calling them new told every query of a qmdb campaign to rebuild the index.
        skipped = self.file.parent / "bench.rs"
        skipped.write_text("fn bench() {}\n")
        built = sl.snapshot_path(self.sl_dir).stat().st_mtime
        os.utime(skipped, (built - 60, built - 60))
        _code, _out, said = self.code("refs", "outer")
        self.assertNotIn("appeared since the index was built", said)


class Ancestry(unittest.TestCase):
    """Anything before a `#[cfg(test)]` or a doc comment moves its item's start,
    so ancestry has to be real rather than an offset match or a node window."""

    @classmethod
    def setUpClass(cls):
        if not sl.ast_available():
            raise unittest.SkipTest("rust-analyzer is not installed")

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, text):
        path = self.tmp / "t.rs"
        path.write_text(text)
        return path

    def test_a_documented_test_module_is_found(self):
        self.write(
            "/// Documented test module.\n"      # 1
            "#[cfg(test)]\n"                     # 2
            "mod helpers {\n"                    # 3
            "    pub fn helper() {}\n"           # 4
            "}\n"                                # 5
            "pub fn production() {}\n"           # 6
        )
        self.assertEqual(sl.index_test_ranges(self.tmp, "t.rs"), [(1, 5)])
        self.assertTrue(sl.index_is_test(self.tmp, {}, "t.rs", 4))
        self.assertFalse(sl.index_is_test(self.tmp, {}, "t.rs", 6))

    def test_a_second_attribute_before_cfg_test(self):
        self.write(
            "#[allow(dead_code)]\n"              # 1
            "#[cfg(test)]\n"                     # 2
            "mod helpers {}\n"                   # 3
            "pub fn production() {}\n"           # 4
        )
        self.assertEqual(sl.index_test_ranges(self.tmp, "t.rs"), [(1, 3)])
        self.assertFalse(sl.index_is_test(self.tmp, {}, "t.rs", 4))

    def test_a_doc_comment_after_an_attribute_finds_its_item(self):
        path = self.write(
            "struct S { armed: bool }\n"                       # 1
            "impl S {\n"                                       # 2
            "    #[inline]\n"                                  # 3  the FN starts here
            "    /// Recover the state.\n"                     # 4
            "    fn recover(&mut self) { self.armed = true; }\n"  # 5
            "}\n"                                              # 6
        )
        found = sl.ast_notes(path, "Recover")
        self.assertEqual(len(found), 1, found)
        _line, _text, item = found[0]
        self.assertIsNotNone(item, "an earlier attribute must not hide the item")
        self.assertEqual(item[0], "FN")

    def test_a_comment_in_a_macro_body_has_no_item(self):
        path = self.write(
            "macro_rules! pick { ($($t:tt)*) => { $($t)* } }\n"  # 1
            "fn holder() {\n"                                    # 2
            "    pick! {\n"                                      # 3
            "        // never clear it twice\n"                  # 4
            "        let _ = 1;\n"                               # 5
            "    }\n"                                            # 6
            "}\n"                                                # 7
            "fn unrelated() {}\n"                                # 8
        )
        found = sl.ast_notes(path, "never clear")
        self.assertEqual(len(found), 1, found)
        _line, _text, item = found[0]
        self.assertIsNone(item, "must not reach past the macro to the next fn")

    def test_a_write_deep_in_a_macro_body_is_reported(self):
        body = "".join("        step();\n" for _ in range(90))
        path = self.write(
            "struct S { armed: bool }\n"
            "macro_rules! pick { ($($t:tt)*) => { $($t)* } }\n"
            "fn step() {}\n"
            "impl S {\n"
            "    fn wrapped(&mut self) {\n"
            "        pick! {\n" + body + "        self.armed = true;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        _writes, reads, _inits, opaque, _maybe = sl.ast_field_ops(path, "armed")
        self.assertEqual(len(opaque), 1, "the write far into the body must be seen")
        self.assertNotIn(opaque[0], reads)


class PromptPaths(unittest.TestCase):
    """Phase 2 runs the agent from the repository root, so prompt paths are
    relative to it, not to this subproject. The script lives two levels down,
    and a prompt that says `scripts/statelens.py` fails there."""

    REPO = HERE.parents[1]
    PROMPTS = sorted((HERE.parent / "prompts").rglob("*.md"))

    def test_there_are_prompts_to_check(self):
        self.assertTrue(self.PROMPTS, "no prompt files found")

    def test_script_is_named_from_the_repository_root(self):
        for path in self.PROMPTS:
            text = path.read_text()
            for line_number, line in enumerate(text.splitlines(), 1):
                if "scripts/statelens.py" not in line:
                    continue
                self.assertIn(
                    "statelens/scripts/statelens.py",
                    line,
                    f"{path.name}:{line_number} names the script relative to this "
                    f"subproject, but the agent runs from the repository root",
                )

    def test_referenced_subproject_files_exist(self):
        reference = __import__("re").compile(
            r"(?<![A-Za-z0-9_./-])statelens/[A-Za-z0-9_./-]+[A-Za-z0-9_/]"
        )
        for path in self.PROMPTS:
            for line_number, line in enumerate(path.read_text().splitlines(), 1):
                for found in reference.finditer(line):
                    target = self.REPO / found.group(0)
                    self.assertTrue(
                        target.exists(),
                        f"{path.name}:{line_number} refers to {found.group(0)}, "
                        f"which does not exist",
                    )


class AgentInvocation(unittest.TestCase):
    """A model or an effort that `config.env` sets has to reach the CLI. An option
    that is silently dropped looks exactly like one the CLI honoured, and the
    campaign would record a setting it never used."""

    def config(self, **values):
        base = {key: "" for key in sl.CONFIG_KEYS}
        base.update(values)
        return base

    def command(self, agent, phase=2, **values):
        return sl.agent_command(self.config(**values), agent, phase, pathlib.Path("/repo"))

    def test_an_empty_value_leaves_the_flag_out(self):
        for agent in ("claude", "codex"):
            command = self.command(agent)
            self.assertNotIn("--effort", command)
            self.assertNotIn("--model", command)
            self.assertFalse(
                [word for word in command if word.startswith("model_reasoning_effort")],
                f"{agent} must fall back to its own default",
            )

    def test_claude_takes_the_model_and_the_effort(self):
        command = self.command(
            "claude", STATELENS_CLAUDE_MODEL="claude-opus-5", STATELENS_CLAUDE_EFFORT="xhigh"
        )
        self.assertEqual(command[command.index("--model") + 1], "claude-opus-5")
        self.assertEqual(command[command.index("--effort") + 1], "xhigh")

    def test_codex_takes_the_effort_as_a_config_override(self):
        command = self.command("codex", STATELENS_CODEX_EFFORT="high")
        self.assertIn("model_reasoning_effort=high", command)
        self.assertEqual(command[command.index("model_reasoning_effort=high") - 1], "-c")

    def test_each_agent_reads_only_its_own_settings(self):
        command = self.command(
            "claude", STATELENS_CODEX_MODEL="gpt", STATELENS_CODEX_EFFORT="high"
        )
        self.assertNotIn("--model", command)
        self.assertNotIn("--effort", command)

    def test_the_effort_reaches_every_phase(self):
        for phase in (1, 2, "kb"):
            command = self.command("claude", phase, STATELENS_CLAUDE_EFFORT="max")
            self.assertIn("--effort", command, f"phase {phase} must carry the effort")

    def test_a_kb_extraction_reaches_the_corpus_only_through_the_kb_commands(self):
        command = self.command("claude", "kb")
        self.assertIn("Bash(python3 statelens/scripts/statelens.py kb:*)", command)
        self.assertNotIn("Bash(gh:*)", command)
        self.assertNotIn("--dangerously-skip-permissions", command)
        command = self.command("codex", "kb")
        self.assertIn("sandbox_workspace_write.network_access=false", command)


class TestGate(unittest.TestCase):
    """`just test` must run the campaign's own gate, for the profile the
    checkout was instrumented with, or a fix would be checked against other tests."""

    def test_the_campaign_and_the_recipe_share_one_command(self):
        campaign = sl.Campaign.__new__(sl.Campaign)
        campaign.test_toolchain, campaign.profile_name = "stable", "marshal"
        self.assertEqual(campaign.test_command(), sl.gate_test_command("stable", "marshal"))

    def test_the_component_tests_are_the_simplex_tests_the_gate_leaves_out(self):
        # The gap: the gate excluded every `simplex::actors::` test, and nothing ran
        # them, so an instrumented tree that failed seven of them reported READY
        # without a word about it.
        for profile in ("simplex", "marshal"):
            command = sl.component_test_command("stable", profile)
            self.assertEqual(command[:3], ["cargo", "+stable", "nextest"])
            expression = command[-1]
            self.assertIn("test(/^simplex::/)", expression)
            self.assertIn("not test(/^simplex::tests::/)", expression)
            self.assertIn("not test(/^simplex::statelens::/)", expression)
            self.assertNotIn("marshal", expression)
        # qmdb gates every one of its tests, so nothing runs after the gate.
        self.assertIsNone(sl.component_test_command("stable", "qmdb"))

    def test_failed_tests_are_named_once_each(self):
        lines = [
            "        PASS [   0.010s] commonware-consensus simplex::actors::voter::ok",
            "        FAIL [   0.123s] commonware-consensus simplex::actors::voter::tests::a",
            "thread 'x' panicked at [statelens][INV-0012] replica=1 timeout",
            "        FAIL [   0.456s] commonware-consensus simplex::actors::batcher::b",
            "     TIMEOUT [  60.000s] commonware-consensus simplex::actors::resolver::c",
            "     SIGSEGV [   0.001s] commonware-consensus simplex::types::d",
            "     Summary [   3.000s] 4 tests run: 0 passed, 4 failed",
            "        FAIL [   0.123s] commonware-consensus simplex::actors::voter::tests::a",
            "        FAIL [   0.456s] commonware-consensus simplex::actors::batcher::b",
        ]
        self.assertEqual(
            sl.failed_tests(lines),
            [
                "simplex::actors::voter::tests::a",
                "simplex::actors::batcher::b",
                "simplex::actors::resolver::c",
                "simplex::types::d",
            ],
        )

    def test_the_gate_forces_the_rendering_it_parses(self):
        # Flags override NEXTEST_STATUS_LEVEL, CARGO_TERM_COLOR and nextest's user config.
        command = sl.gate_test_command("stable", "simplex")
        for flag, value in (("--color", "never"), ("--message-format", "human"),
                            ("--status-level", "pass"), ("--final-status-level", "fail"),
                            ("--success-output", "never"), ("--failure-output", "immediate")):
            self.assertEqual(command[command.index(flag) + 1], value)

    # nextest_run, on output as cargo-nextest 0.9.127 printed it in the forced rendering.
    RUN = (
        "    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.18s\n"
        "    Starting 5 tests across 1 binary\n"
        "  TRY 1 FAIL [   0.034s] commonware-consensus simplex::tests::two\n"
        "  stdout ---\n"
        "    thread 'simplex::tests::two' panicked at src/lib.rs:9:60:\n"
        "        PASS [   0.054s] (1/5) commonware-consensus simplex::tests::one\n"
        "  TRY 1 FAIL [   0.074s] commonware-consensus flaky::sometimes\n"
        "        SLOW [>  1.000s] commonware-consensus flaky::hangs\n"
        " TERMINATING [>  2.000s] commonware-consensus flaky::hangs\n"
        "     TIMEOUT [   2.004s] commonware-consensus flaky::hangs\n"
        "     SIGABRT [   0.052s] commonware-consensus crash::aborts\n"
        "  TRY 2 FAIL [   0.099s] commonware-consensus simplex::tests::two\n"
        "  TRY 2 PASS [   0.069s] commonware-consensus flaky::sometimes\n"
        "------------\n"
        "     Summary [   2.145s] 5 tests run: 2 passed (1 flaky), 2 failed, 1 timed out, "
        "0 skipped\n"
        "     SIGABRT [   0.052s] commonware-consensus crash::aborts\n"
        "     TIMEOUT [   2.004s] commonware-consensus flaky::hangs\n"
        "  TRY 2 FAIL [   0.099s] commonware-consensus simplex::tests::two\n"
        "error: test run failed\n"
    )

    def test_a_run_is_read_by_its_final_statuses(self):
        run, problem = sl.nextest_run(self.RUN, 100)
        self.assertIsNone(problem)
        self.assertEqual(run["passed"], {"simplex::tests::one", "flaky::sometimes"})
        self.assertEqual(run["failed"], {"simplex::tests::two", "flaky::hangs", "crash::aborts"})
        self.assertEqual(sl.nextest_run(colored(self.RUN), 100), (run, None))

    def test_a_run_that_cannot_be_trusted_has_a_problem(self):
        summary = "     Summary [   0.020s] 2 tests run: 2 passed, 0 skipped\n"
        both = ("        PASS [   0.010s] commonware-consensus a\n"
                "        PASS [   0.010s] commonware-consensus b\n")
        for text, code, problem in (
            ("error: could not compile `commonware-consensus`\n", 101,
             "no nextest summary line"),
            (summary, 0, "0 passed and 0 failed by the status lines, 2 and 0 by the summary"),
            (both + summary, 100, "exit code 100 with no failed test"),
            (both + summary, None, "exit code nonzero with no failed test"),
            (both + summary + summary, 0, "more than one summary line"),
            (both.replace("PASS", "FAIL") + summary.replace("2 passed", "0 passed, 2 failed")
             + both.replace("PASS", "FAIL"), 0, "exit code 0 with 2 failed test(s)"),
            (both + "     Summary [   0.020s] 2/3 tests run: 2 passed, 0 skipped\n", 0,
             "the run stopped after 2 of 3 tests"),
            ("     Summary [   0.000s] 0 tests run: 0 passed, 0 skipped\n", 0,
             "the run ran no test"),
            (both + "     Summary [   0.020s] 3 tests run: 2 passed, 1 frobbed, 0 skipped\n", 0,
             "the summary does not add up: Summary [   0.020s] 3 tests run: 2 passed, "
             "1 frobbed, 0 skipped"),
        ):
            with self.subTest(problem=problem):
                self.assertEqual(sl.nextest_run(text, code), (None, problem))

    def test_a_status_line_a_failing_test_prints_is_not_its_status(self):
        # Test output reaches the log only before the summary; the failures after it are
        # nextest's own, and a forged PASS line makes the counts disagree.
        text = ("        PASS [   0.010s] commonware-consensus a\n"
                "        FAIL [   0.010s] commonware-consensus b\n"
                "    panicked: forged\n"
                "        PASS [   0.010s] commonware-consensus b\n"
                "        PASS [   0.010s] commonware-consensus c\n"
                "     Summary [   0.020s] 2 tests run: 1 passed, 1 failed, 0 skipped\n"
                "        FAIL [   0.010s] commonware-consensus b\n")
        self.assertEqual(sl.nextest_run(text, 100), (None, "2 passed and 1 failed by the status "
                                                     "lines, 1 and 1 by the summary"))

    def test_failed_component_tests_are_reported_and_do_not_fail_the_campaign(self):
        campaign = sl.Campaign.__new__(sl.Campaign)
        with tempfile.TemporaryDirectory() as root:
            campaign.repo = campaign.dir = pathlib.Path(root)
            (campaign.dir / "logs").mkdir()
            campaign.test_toolchain, campaign.profile_name = "", "simplex"
            said = []
            saved = {name: getattr(sl, name) for name in ("run_logged", "say")}
            sl.say = lambda message, *a, **k: said.append(str(message))

            def run(command, log, cwd, stdin_text=None, echo=True):
                log.write_text(
                    "        FAIL [   0.1s] commonware-consensus simplex::actors::voter::t\n"
                )
                return 100, []

            sl.run_logged = run
            try:
                failed = campaign.component_tests()
            finally:
                for key, value in saved.items():
                    setattr(sl, key, value)
        self.assertEqual(failed, ["simplex::actors::voter::t"])
        self.assertTrue(any("not gated" in line for line in said), said)

    def test_each_profile_runs_its_own_filter(self):
        for profile, settings in sl.PROFILES.items():
            command = sl.gate_test_command("stable", profile)
            self.assertEqual(command[:3], ["cargo", "+stable", "nextest"])
            self.assertEqual(command[command.index("-p") + 1], f"commonware-{settings['crate']}")
            self.assertEqual(command[-1], settings["test_filter"])
        self.assertIn("marshal::", sl.gate_test_command("", "marshal")[-1])
        self.assertNotIn("marshal::", sl.gate_test_command("", "simplex")[-1])

    def test_the_profile_comes_from_the_campaign_in_the_checkout(self):
        with tempfile.TemporaryDirectory() as root:
            sl_dir = pathlib.Path(root)
            self.assertIsNone(sl.campaign_profile(sl_dir))
            (sl_dir / "campaign").mkdir()
            (sl_dir / "campaign" / "meta.json").write_text(json.dumps({"profile": "marshal"}))
            self.assertEqual(sl.campaign_profile(sl_dir), "marshal")


class CoverageSelection(unittest.TestCase):
    """`just coverage` takes the names `just fuzz` takes, so a marshal target must
    not be covered against the simplex profile's package, and a typo must name the
    targets that exist rather than silently covering all of them."""

    def select(self, *names, profile=None):
        return sl.coverage_selection(
            HERE.parents[1], argparse.Namespace(profile=profile, targets=list(names))
        )

    def test_no_name_covers_every_target_of_the_default_profile(self):
        profile, targets = self.select()
        self.assertEqual(profile, "simplex")
        self.assertEqual(targets, sl.profile_targets(HERE.parents[1], "simplex"))

    def test_a_profile_name_covers_that_profile(self):
        profile, targets = self.select("marshal")
        self.assertEqual(profile, "marshal")
        self.assertEqual(targets, sl.profile_targets(HERE.parents[1], "marshal"))

    def test_a_target_name_implies_its_profile(self):
        profile, targets = self.select("marshal_scenario_standard_inline_cert_mock_statelens")
        self.assertEqual(profile, "marshal")
        self.assertEqual(targets, ["marshal_scenario_standard_inline_cert_mock_statelens"])
        profile, targets = self.select("qmdb_verify_proof_statelens")
        self.assertEqual(profile, "qmdb")
        self.assertEqual(targets, ["qmdb_verify_proof_statelens"])

    def test_a_name_of_neither_profile_is_refused(self):
        with self.assertRaises(sl.Abort) as caught:
            self.select("nonsense")
        self.assertIn("not a profile", str(caught.exception))

    def test_a_target_the_profile_does_not_build_is_refused(self):
        with self.assertRaises(sl.Abort) as caught:
            self.select("simplex_does_not_exist")
        self.assertIn("builds no target", str(caught.exception))

    def test_a_profile_covers_its_scaffolds_and_a_scaffold_is_named_like_a_variant(self):
        repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, repo, True)
        targets = repo / sl.profile_fuzz_dir("simplex")
        targets.mkdir(parents=True)
        for stem in ("simplex_a", "simplex_a_statelens", "simplex_a_ts0003_statelens"):
            (targets / f"{stem}.rs").write_text("")
        both = ["simplex_a_statelens", "simplex_a_ts0003_statelens"]
        names = argparse.Namespace(profile=None, targets=["simplex"])
        self.assertEqual(sl.coverage_selection(repo, names), ("simplex", both))
        names = argparse.Namespace(profile=None, targets=["simplex_a_ts0003_statelens"])
        self.assertEqual(sl.coverage_selection(repo, names), ("simplex", both[1:]))
        with self.assertRaises(sl.Abort):
            sl.coverage_selection(
                repo, argparse.Namespace(profile=None, targets=["simplex_a_ts0004_statelens"])
            )

    def test_the_report_is_scoped_to_what_the_profile_instruments(self):
        repo = HERE.parents[1]
        for profile in sl.PROFILES:
            sources, uninstrumented = sl.coverage_scope(repo, profile)
            self.assertEqual(
                sources,
                [str(repo / root.rstrip("/")) for root in sl.PROFILES[profile]["roots"]],
                "llvm-cov reads a trailing slash as a file and widens the report",
            )
            for source in sources:
                self.assertTrue(pathlib.Path(source).is_dir(), f"{source} must exist")
            self.assertEqual(uninstrumented, list(sl.PROFILES[profile]["warn"]))
            for path in uninstrumented:
                self.assertTrue(
                    any(str(repo / path).startswith(source) for source in sources),
                    f"{path} is left out of a report that does not cover it",
                )


class PlanClaims(unittest.TestCase):
    """A plan's Status is a coverage claim, and the first campaign that wrote one
    claimed `bound` for an invariant whose action is committed in a handler it never
    instrumented. The lint reads the claim against the section's own ledger and
    against the code."""

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.plan = self.dir / "plan.md"

    def write(self, body):
        self.plan.write_text("# StateLens instrumentation plan\n\n## Invariants\n\n" + body)
        return self.plan

    SITES = (
        "- Sites: `voter/state.rs` `State::construct_notarize`, signature - checked\n"
        "- Assertions: `voter/state.rs` `State::construct_notarize`, `sl_implies!`\n"
        "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
    )
    # What `subsystem_assertions` returns: (invariant, enclosing function) per site.
    CODE = {
        "consensus/src/simplex/actors/voter/state.rs": [
            ("INV-0016", "State::try_propose"),
            ("INV-0016", "State::construct_notarize"),
        ],
        "consensus/src/simplex/actors/voter/actor.rs": [],
    }
    EMPTY = {"consensus/src/simplex/actors/voter/state.rs": []}

    def test_a_bound_status_with_an_unchecked_commit_site_is_reported(self):
        path = self.write(
            "### INV-0016: A proposal rejected by certification is never built upon\n"
            "- Status: bound\n- Reading: pre and post\n"
            "- Sites:\n"
            "  - `voter/state.rs` `State::try_propose`, dispatch - checked\n"
            "  - `voter/actor.rs` `Actor::process_proposed`, relay - not checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
        )
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("not checked" in problem for problem in problems),
            f"a bound status over an unchecked commit site must be reported: {problems}",
        )

    def test_the_same_ledger_is_accepted_for_a_partial_status(self):
        path = self.write(
            "### INV-0016: A proposal rejected by certification is never built upon\n"
            "- Status: partial\n- Reading: pre and post\n"
            "- Sites:\n"
            "  - `voter/state.rs` `State::try_propose`, dispatch - checked\n"
            "  - `voter/actor.rs` `Actor::process_proposed`, relay - not checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n"
            "- Notes: the relay is reached one iteration later\n"
        )
        self.assertEqual(sl.lint_plan_file(path, ["INV-0016"], self.CODE), [])

    def test_a_claimed_binding_the_code_never_asserts_is_reported(self):
        path = self.write("### INV-0016: title\n- Status: bound\n- Reading: r\n" + self.SITES)
        problems = sl.lint_plan_file(path, ["INV-0016"], self.EMPTY)
        self.assertTrue(
            any("names it" in problem for problem in problems),
            f"a Status with no assertion in the code must be reported: {problems}",
        )

    def test_an_unbound_section_needs_only_a_status_and_a_reason(self):
        path = self.write("### INV-0016: title\n- Status: unbound\n- Notes: not reachable\n")
        self.assertEqual(sl.lint_plan_file(path, ["INV-0016"], self.EMPTY), [])

    def test_an_unbound_section_the_code_asserts_is_reported(self):
        path = self.write("### INV-0016: title\n- Status: unbound\n- Notes: not reachable\n")
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("unbound, but the code asserts it" in problem for problem in problems),
            f"an unbound invariant with assertions must be reported: {problems}",
        )

    def test_a_site_called_checked_that_asserts_nothing_is_reported(self):
        path = self.write(
            "### INV-0016: A proposal rejected by certification is never built upon\n"
            "- Status: bound\n- Reading: pre and post\n"
            "- Sites:\n"
            "  - `voter/state.rs` `State::try_propose`, dispatch - checked\n"
            "  - `voter/actor.rs` `Actor::process_proposed`, the relay - checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
        )
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("calls `voter/actor.rs` checked" in problem for problem in problems),
            f"a ledger that certifies a site the code never asserts must be reported: {problems}",
        )

    def test_an_entry_wrapped_over_two_lines_keeps_its_not_checked(self):
        path = self.write(
            "### INV-0016: A proposal rejected by certification is never built upon\n"
            "- Status: partial\n- Reading: pre and post\n"
            "- Sites:\n"
            "  - `voter/state.rs` `State::try_propose`, dispatch - checked\n"
            "  - `voter/actor.rs` `Actor::process_proposed`, the relay of a local\n"
            "    proposal - not checked (the parent can be rejected while the build runs)\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n"
            "- Notes: the relay is reached one iteration later\n"
        )
        self.assertEqual(sl.lint_plan_file(path, ["INV-0016"], self.CODE), [])

    def test_a_ledger_that_claims_coverage_without_naming_a_source_is_reported(self):
        for sites in ("- Sites: all of them, checked\n", "- Sites: checked\n"):
            path = self.write(
                "### INV-0016: title\n- Status: bound\n- Reading: r\n" + sites
                + "- Assertions: `voter/state.rs` `State::construct_notarize`, `sl_implies!`\n"
                "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
            )
            problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
            self.assertTrue(
                any("names no source" in problem for problem in problems),
                f"a ledger without a source must be reported: {sites!r} -> {problems}",
            )

    def test_an_entry_with_no_verdict_is_reported(self):
        for verdict in ("unchecked", "deferred", "no site available"):
            path = self.write(
                "### INV-0016: title\n- Status: bound\n- Reading: r\n"
                "- Sites:\n"
                "  - `voter/state.rs` `State::construct_notarize`, signature - checked\n"
                f"  - `voter/actor.rs` `Actor::process_proposed`, the relay - {verdict}\n"
                "- Assertions: `voter/state.rs` `State::construct_notarize`, `sl_implies!`\n"
                "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
            )
            problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
            self.assertTrue(
                any("neither `checked` nor `not checked`" in problem for problem in problems),
                f"an entry with no verdict must be reported: {verdict!r} -> {problems}",
            )

    def test_a_site_in_a_source_that_does_not_exist_is_reported(self):
        path = self.write(
            "### INV-0016: title\n- Status: bound\n- Reading: r\n"
            "- Sites: `voter/sate.rs` `State::construct_notarize`, signature - checked\n"
            "- Assertions: `voter/state.rs` `State::construct_notarize`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
        )
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("not an instrumented source" in problem for problem in problems),
            f"a ledger naming a source that does not exist must be reported: {problems}",
        )

    def test_a_ledger_written_as_one_bullet_per_site_keeps_every_site(self):
        path = self.write(
            "### INV-0016: title\n- Status: bound\n- Reading: r\n"
            "- Sites: `voter/state.rs` `State::try_propose`, dispatch - checked\n"
            "- Sites: `voter/actor.rs` `Actor::process_proposed`, relay - not checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
        )
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("not checked" in problem for problem in problems),
            f"a repeated field must extend the ledger, not replace it: {problems}",
        )
        self.assertEqual(sl.Campaign.commit_sites(path.read_text()), (2, 1))

    def test_an_assertion_elsewhere_in_the_file_does_not_certify_a_site(self):
        path = self.write(
            "### INV-0016: title\n- Status: bound\n- Reading: r\n"
            "- Sites: `voter/state.rs` `State::proposed`, the completion - checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
        )
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("elsewhere in that file" in problem for problem in problems),
            f"a dispatch assertion must not certify the commit site beside it: {problems}",
        )

    def test_a_site_named_without_its_type_is_read_like_a_qualified_one(self):
        path = self.write(
            "### INV-0016: title\n- Status: bound\n- Reading: r\n"
            "- Sites: `voter/state.rs` `try_propose`, dispatch - checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
        )
        self.assertEqual(sl.lint_plan_file(path, ["INV-0016"], self.CODE), [])

    def test_a_checked_site_with_no_function_is_reported(self):
        path = self.write(
            "### INV-0016: title\n- Status: bound\n- Reading: r\n"
            "- Sites: `voter/state.rs`, the completion - checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
        )
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("names no function" in problem for problem in problems),
            f"a checked entry must not fall back to file-only coverage: {problems}",
        )

    def test_a_fenced_block_inside_a_section_is_not_read_as_fields(self):
        body = (
            "### INV-0016: title\n- Status: partial\n- Reading: r\n"
            "- Sites: `voter/state.rs` `State::try_propose`, dispatch - checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n"
            "- Edited lines: the match arm below\n\n"
            "```rust\n- Status: bound\n- Sites: nothing\n```\n\n"
            "- Notes: the fence is quoted code\n"
        )
        path = self.write(body)
        self.assertEqual(sl.lint_plan_file(path, ["INV-0016"], self.CODE), [])
        self.assertEqual(sl.Campaign.parse_statuses(path.read_text()), {"INV-0016": "partial"})

    def test_a_bold_or_quoted_status_is_read_like_the_campaign_reads_it(self):
        path = self.write(
            "### INV-0016: title\n- **Status**: `bound`\n- Reading: r\n" + self.SITES
        )
        self.assertEqual(sl.lint_plan_file(path, ["INV-0016"], self.CODE), [])

    def test_a_missing_section_is_reported(self):
        path = self.write("### INV-0016: title\n- Status: bound\n- Reading: r\n" + self.SITES)
        problems = sl.lint_plan_file(path, ["INV-0016", "INV-0017"], self.CODE)
        self.assertTrue(
            any(problem.startswith("INV-0017: has no section") for problem in problems),
            f"an invariant with no section must be reported: {problems}",
        )

    def test_a_repeated_section_is_reported(self):
        body = "### INV-0016: title\n- Status: bound\n- Reading: r\n" + self.SITES
        path = self.write(body + "\n" + body)
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("more than one section" in problem for problem in problems),
            f"a repeated section must be reported: {problems}",
        )


class AssertionScanner(unittest.TestCase):
    """The ledger check reads assertions out of the code with a textual scan, which
    certified an assertion quoted in a block comment, and one in a `#[cfg(test)]`
    module sharing the production function's name, as production coverage."""

    PLAN = (
        "# Plan\n\n## Invariants\n\n### INV-0016: example\n"
        "- Status: bound\n- Reading: check dispatch\n"
        "- Sites: `actors/voter/state.rs` `State::try_propose`, dispatch - checked\n"
        "- Assertions: `actors/voter/state.rs` `State::try_propose`, `sl_assert!`\n"
        "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
    )
    TEST_MODULE = (
        "struct State;\n"
        "impl State { fn try_propose() {} }\n"
        "#[cfg(test)] mod tests {\n"
        '  fn try_propose() { sl_assert!(None, "INV-0016", true, "test only"); }\n'
        "}\n"
    )

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.source = self.root / "consensus/src/simplex/actors/voter/state.rs"
        self.source.parent.mkdir(parents=True)
        self.plan = self.root / "plan.md"
        self.plan.write_text(self.PLAN)

    def problems(self, code):
        self.source.write_text(code)
        return sl.lint_plan_file(self.plan, ["INV-0016"], sl.subsystem_assertions(self.root))

    def test_a_production_assertion_certifies_its_site(self):
        code = (
            "struct State;\nimpl State {\n"
            '    fn try_propose() { sl_assert!(None, "INV-0016", true, "checked"); }\n'
            "}\n"
        )
        self.assertEqual(self.problems(code), [])

    def test_a_free_function_does_not_certify_a_method_claim(self):
        # The gap: a free function has no type, and that was taken for a match
        # with any type the ledger named; it is a different item.
        code = (
            "struct State;\nimpl State {\n    fn try_propose() {}\n}\n"
            'fn try_propose() { sl_assert!(None, "INV-0016", true, "free"); }\n'
        )
        self.assertTrue(self.problems(code), "a free function certified State::try_propose")
        # A bare ledger name is the less precise claim that a free function meets.
        self.plan.write_text(self.PLAN.replace("`State::try_propose`", "`try_propose`"))
        self.assertEqual(self.problems(code), [])

    def test_a_function_spelled_in_a_string_opens_nothing(self):
        # The gap: a string holding `fn try_propose() {}` was the last `fn` before
        # the site, so an assertion in another method was attributed to it.
        code = (
            "struct State;\nimpl State {\n    fn try_propose() {}\n"
            "    fn unrelated() {\n"
            '        let _example = r#"\nfn try_propose() {}\n"#;\n'
            '        sl_assert!(None, "INV-0016", true, "in unrelated");\n'
            "    }\n}\n"
        )
        self.assertTrue(self.problems(code), "a string's `fn` claimed the assertion")
        self.assertEqual(
            sl.subsystem_assertions(self.root)["consensus/src/simplex/actors/voter/state.rs"],
            [("INV-0016", "State::unrelated")],
        )

    def test_a_site_after_the_last_function_belongs_to_none(self):
        code = (
            "struct State;\nimpl State {\n    fn try_propose() {}\n}\n"
            "macro_rules! trailing {\n"
            '    () => { sl_assert!(None, "INV-0016", true, "after every body") };\n'
            "}\n"
        )
        self.assertTrue(self.problems(code), "a site outside every body certified a method")
        self.assertEqual(
            sl.subsystem_assertions(self.root)["consensus/src/simplex/actors/voter/state.rs"],
            [("INV-0016", None)],
        )

    def test_a_body_is_found_past_a_semicolon_in_the_signature(self):
        code = (
            "struct State;\nimpl State {\n"
            "    fn try_propose() -> [u8; 4] {\n"
            '        sl_assert!(None, "INV-0016", true, "checked");\n'
            "        [0; 4]\n    }\n"
            "    fn declared(&self) -> u8;\n"
            "}\n"
        )
        self.assertEqual(self.problems(code), [])

    def test_an_assertion_in_a_block_comment_certifies_nothing(self):
        problems = self.problems(
            "fn try_propose() {}\n"
            "/* Example only:\n"
            'sl_assert!(None, "INV-0016", true, "documentation");\n'
            "*/\n"
        )
        self.assertTrue(problems, "a comment after the function certified it")

    def test_an_assertion_in_a_line_comment_certifies_nothing(self):
        problems = self.problems(
            'fn try_propose() {\n    // sl_assert!(None, "INV-0016", true, "todo");\n}\n'
        )
        self.assertTrue(problems, "a commented-out assertion certified its function")

    def test_an_assertion_in_a_test_module_certifies_nothing(self):
        problems = self.problems(self.TEST_MODULE)
        self.assertTrue(problems, "a test function of the production name certified it")

    def test_a_test_module_on_one_line_is_found_without_the_tree(self):
        saved = sl.ast_available
        sl.ast_available = lambda: False
        self.addCleanup(setattr, sl, "ast_available", saved)
        problems = self.problems(self.TEST_MODULE)
        self.assertTrue(problems, "the fallback must see `#[cfg(test)] mod` on one line")
        commented = self.TEST_MODULE.replace("#[cfg(test)] mod tests {", "#[cfg(test)] // t\nmod tests {")
        self.assertTrue(self.problems(commented), "a comment after the attribute is not the item")

    def test_a_comment_after_code_certifies_nothing(self):
        problems = self.problems(
            "fn try_propose() {\n"
            '    let x = 1; // sl_assert!(None, "INV-0016", true, "trailing");\n'
            "}\n"
        )
        self.assertTrue(problems, "a trailing comment certified its function")

    def test_a_nested_block_comment_certifies_nothing(self):
        problems = self.problems(
            "fn try_propose() {}\n"
            "/* outer /* inner */\n"
            'sl_assert!(None, "INV-0016", true, "still a comment");\n'
            "*/\n"
        )
        self.assertTrue(problems, "a nested block comment certified its function")

    def test_a_comment_marker_in_a_string_is_text(self):
        code = (
            "struct State;\nimpl State {\n"
            "    fn try_propose() {\n"
            '        let url = "https://example.invalid/*";\n'
            '        sl_assert!(None, "INV-0016", true, "{url}");\n'
            "    }\n}\n"
        )
        self.assertEqual(self.problems(code), [])

    def test_blanking_keeps_every_line(self):
        text = 'a /* b\nc */ d // e\n"f // g" h\n'
        blanked = sl.blank_inert(text)
        self.assertEqual(blanked.count("\n"), text.count("\n"))
        self.assertEqual(blanked.splitlines()[2], '"f // g" h')
        self.assertNotIn("b", blanked.splitlines()[0])
        self.assertNotIn("e", blanked.splitlines()[1])
        self.assertEqual(sl.blank_inert(text, strings=True).splitlines()[2], "         h")

    def test_an_assertion_in_a_raw_string_certifies_nothing(self):
        problems = self.problems(
            "fn try_propose() {\n"
            '    let _example = r#"sl_assert!(None, "INV-0016", true, "example");"#;\n'
            "}\n"
        )
        self.assertTrue(problems, "a raw string certified its function")

    def test_a_method_of_another_type_certifies_nothing(self):
        # The gap: both `State::try_propose` and `Other::try_propose` reduced to the
        # bare name, so the other type's method certified the ledger's site.
        problems = self.problems(
            "struct State;\nimpl State {\n    fn try_propose() {}\n}\n"
            "struct Other;\nimpl Other {\n"
            '    fn try_propose() { sl_assert!(None, "INV-0016", true, "other"); }\n'
            "}\n"
        )
        self.assertTrue(problems, "Other::try_propose certified State::try_propose")

    def test_a_method_of_the_named_type_certifies_its_site(self):
        code = (
            "struct State;\n"
            "impl<S: Scheme> Elector<S> for State where S: Scheme {\n"
            '    fn try_propose() { sl_assert!(None, "INV-0016", true, "checked"); }\n'
            "}\n"
        )
        self.assertEqual(self.problems(code), [])
        self.assertEqual(
            sl.subsystem_assertions(self.root),
            {"consensus/src/simplex/actors/voter/state.rs": [("INV-0016", "State::try_propose")]},
        )

    def test_a_const_method_certifies_its_site(self):
        code = (
            "struct State;\nimpl State {\n"
            '    pub const fn try_propose() { sl_assert!(None, "INV-0016", true, "c"); }\n'
            "}\n"
        )
        self.assertEqual(self.problems(code), [])

    def test_an_assertion_before_any_function_is_reported_not_a_crash(self):
        # The gap: a site with no `fn` before it had no function, and the ledger
        # comparison raised on it instead of refusing to certify.
        problems = self.problems(
            "macro_rules! helper {\n"
            '    () => { sl_assert!(None, "INV-0016", true, "in a macro body") };\n'
            "}\n"
            "struct State;\nimpl State { fn try_propose() { helper!(); } }\n"
        )
        self.assertTrue(problems, "a site in no function certified the ledger")

    def test_an_impl_trait_argument_is_not_an_impl_block(self):
        # rustfmt puts a tuple of `impl Trait` arguments one per line, so a line
        # starts with `impl`, exactly as a block header does.
        code = (
            "struct State;\n"
            "impl State {\n"
            "    fn try_propose(\n"
            "        net: (\n"
            "            impl Sender,\n"
            "            impl Receiver,\n"
            "        ),\n"
            '    ) { sl_assert!(None, "INV-0016", true, "checked"); }\n'
            "}\n"
        )
        self.assertEqual(self.problems(code), [])
        self.assertEqual(
            sl.subsystem_assertions(self.root),
            {"consensus/src/simplex/actors/voter/state.rs": [("INV-0016", "State::try_propose")]},
        )

    def test_a_string_continuation_keeps_the_scan_in_sync(self):
        literals = (
            '        let _a = "x \\\n y";\n'
            '        let _b = "{";\n'
            "        let _d = '\"';\n"
            "        let _e = '\\u{1F600}';\n"
        )
        other = (
            "struct State;\nimpl State { fn try_propose(&self) {} }\n"
            "struct Other;\nimpl Other {\n    fn try_propose(&self) {\n"
            + literals
            + '        sl_assert!(None, "INV-0016", true, "other");\n    }\n}\n'
        )
        self.assertTrue(self.problems(other), "a desynced scan certified Other's method")
        own = (
            "struct State;\nimpl State {\n    fn try_propose(&self) {\n"
            + literals
            + '        sl_assert!(None, "INV-0016", true, "checked");\n    }\n}\n'
        )
        self.assertEqual(self.problems(own), [])

    def test_two_types_of_one_name_need_the_path(self):
        code = (
            "mod immutable { pub struct Archive; }\nmod prunable { pub struct Archive; }\n"
            "trait Blocks { fn try_propose(&self); }\n"
            "impl Blocks for immutable::Archive {\n"
            '    fn try_propose(&self) { sl_assert!(None, "INV-0016", true, "immutable"); }\n'
            "}\n"
            "impl Blocks for prunable::Archive {\n"
            "    fn try_propose(&self) {}\n"
            "}\n"
        )
        self.source.write_text(code)
        found = sl.subsystem_assertions(self.root)["consensus/src/simplex/actors/voter/state.rs"]
        self.assertEqual(found, [("INV-0016", "immutable::Archive::try_propose")])
        tail = self.PLAN.replace("`State::try_propose`", "`Archive::try_propose`")
        self.plan.write_text(tail)
        self.assertEqual(sl.lint_plan_file(self.plan, ["INV-0016"], sl.subsystem_assertions(self.root)), [])
        self.plan.write_text(tail.replace("`Archive::try_propose`", "`prunable::Archive::try_propose`"))
        self.assertTrue(sl.lint_plan_file(self.plan, ["INV-0016"], sl.subsystem_assertions(self.root)))
        # With the method asserted under both types, the tail is ambiguous.
        self.source.write_text(code.replace("fn try_propose(&self) {}", 'fn try_propose(&self) { sl_assert!(None, "INV-0016", true, "prunable"); }'))
        self.plan.write_text(tail)
        problems = sl.lint_plan_file(self.plan, ["INV-0016"], sl.subsystem_assertions(self.root))
        self.assertTrue(any("more than one method" in problem for problem in problems), problems)

    def test_a_backticked_action_word_is_not_a_function_claim(self):
        # The gap: every backticked word of a ledger entry was a function claim, so
        # an action written as `notarize` matched a method of that name.
        self.plan.write_text(
            self.PLAN.replace(
                "- Sites: `actors/voter/state.rs` `State::try_propose`, dispatch - checked",
                "- Sites: `notarize` `actors/voter/state.rs` `State::try_propose` - checked",
            )
        )
        code = (
            "struct State;\nimpl State {\n    fn try_propose() {}\n"
            '    fn notarize() { sl_assert!(None, "INV-0016", true, "action"); }\n'
            "}\n"
        )
        self.assertTrue(self.problems(code), "an action word certified the method")

    def test_an_extern_function_is_a_function(self):
        code = (
            "struct State;\nimpl State {\n"
            '    extern "C" fn try_propose() { sl_assert!(None, "INV-0016", true, "c"); }\n'
            "}\n"
        )
        self.assertEqual(self.problems(code), [])

    def test_impl_types_and_function_matching(self):
        self.assertFalse(sl.function_matches(None, "State::f"))
        self.assertEqual(sl.impl_type("<S: Scheme> Round<S> "), "Round")
        self.assertEqual(sl.impl_type("<S> Elector<S> for RoundRobin<S> where S: Scheme "), "RoundRobin")
        self.assertEqual(sl.impl_type(" crate::marshal::Actor<E, S> "), "crate::marshal::Actor")
        self.assertEqual(sl.impl_type(" Blocks for prunable::Archive<E> "), "prunable::Archive")
        # A claim may give the type's path or its tail; the tail of another path is
        # not it.
        self.assertTrue(sl.function_matches("prunable::Archive::f", "Archive::f"))
        self.assertTrue(sl.function_matches("prunable::Archive::f", "prunable::Archive::f"))
        self.assertFalse(sl.function_matches("prunable::Archive::f", "immutable::Archive::f"))
        self.assertFalse(sl.function_matches("State::f", "a::State::f"))
        self.assertTrue(sl.function_matches("State::f", "State::f"))
        self.assertFalse(sl.function_matches("Other::f", "State::f"))
        # A qualified claim names a method; a free function is a different item. A
        # bare claim is met by any function or method of the name.
        self.assertFalse(sl.function_matches("f", "State::f"))
        self.assertTrue(sl.function_matches("State::f", "f"))
        self.assertTrue(sl.function_matches("f", "f"))
        self.assertFalse(sl.function_matches("State::g", "f"))


class RepairRevalidation(unittest.TestCase):
    """A repair may remove the assertion a plan certifies, and the campaign kept the
    plan verdict taken before the repair: a buildable, passing tree handed over with
    a stale clean audit."""

    ORIGINAL = (
        "struct State;\nimpl State {\n"
        "    fn try_propose(required: bool) {\n"
        '        sl_assert!(None, "INV-0016", required, "checked");\n'
        "    }\n}\n"
    )

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.source = self.root / "consensus/src/simplex/actors/voter/state.rs"
        self.source.parent.mkdir(parents=True)
        self.source.write_text(self.ORIGINAL)
        self.helper = self.root / "consensus/src/simplex/statelens.rs"
        self.helper.write_text("pub fn evidence() -> bool { true }\n")
        self.plan = self.root / "plan.md"
        self.plan.write_text(AssertionScanner.PLAN)
        self.campaign = sl.Campaign.__new__(sl.Campaign)
        self.campaign.repo = self.campaign.dir = self.root
        self.campaign.profile = sl.PROFILES["simplex"]
        self.campaign.invariants = [("simplex", pathlib.Path("INV-0016.md"))]
        self.campaign.repair_prompt = lambda *_args: "fixture repair"
        self.campaign.check_scope = lambda: None
        self.campaign.record = lambda: None
        self.saved_say = sl.say
        sl.say = lambda *_args, **_kw: None
        self.addCleanup(setattr, sl, "say", self.saved_say)
        # The audit's verdict stands for the tree at the first plan lint.
        self.campaign.check_plan()
        self.assertEqual(self.campaign.plan_problems, 0)
        self.assertIsNotNone(self.campaign.audit_content)

    def build(self, repair, failures=1):
        outcomes = iter([("compiler", ["fixture diagnostic"])] * failures + [None])
        self.campaign.build_once = lambda _attempt: next(outcomes)
        self.campaign.agent_step = lambda *_args: repair()
        self.campaign.build()

    def test_a_repair_that_removes_the_assertion_is_linted(self):
        self.build(
            lambda: self.source.write_text(
                "struct State;\nimpl State { fn try_propose(required: bool) {} }\n"
            )
        )
        self.assertGreater(self.campaign.plan_problems, 0, "the old clean verdict survived")
        self.assertEqual(self.campaign.stale, ["consensus/src/simplex/actors/voter/state.rs"])

    def test_a_repair_that_keeps_the_assertion_stays_clean(self):
        self.build(lambda: None)
        self.assertEqual(self.campaign.plan_problems, 0)
        self.assertEqual(self.campaign.stale, [])

    def test_a_repair_that_rewrites_the_condition_makes_the_audit_stale(self):
        # The gap: the lint sees the id, the site and the function, all unchanged,
        # and passes; only the digest of the audited tree can say the audit is stale.
        self.build(lambda: self.source.write_text(self.ORIGINAL.replace(", required,", ", true,")))
        self.assertEqual(self.campaign.plan_problems, 0, "the lint cannot see this change")
        self.assertEqual(self.campaign.stale, ["consensus/src/simplex/actors/voter/state.rs"])

    def test_a_repair_to_a_helper_or_the_plan_makes_the_audit_stale(self):
        def repair():
            self.helper.write_text("pub fn evidence() -> bool { false }\n")
            self.plan.write_text(self.plan.read_text().replace("Notes: none", "Notes: weakened"))

        self.build(repair)
        self.assertEqual(self.campaign.stale, ["consensus/src/simplex/statelens.rs", "plan.md"])

    def test_the_summary_the_script_appends_does_not_count_as_a_change(self):
        self.plan.write_text(self.plan.read_text() + "\n## Summary\n\n- Invariants: 1\n")
        self.build(lambda: None)
        self.assertEqual(self.campaign.stale, [])

    def test_a_build_without_repair_leaves_the_audit_current(self):
        self.build(lambda: self.fail("no repair is run"), failures=0)
        self.assertIsNone(self.campaign.stale)

    def test_a_build_that_never_succeeds_still_marks_the_audit_stale(self):
        # The summary a failed build leaves behind is read before the checkout is
        # fixed by hand and fuzzed with --skip-campaign, so it must not certify
        # the tree the repairs replaced.
        with self.assertRaises(sl.Abort):
            self.build(
                lambda: self.source.write_text(self.ORIGINAL.replace(", required,", ", true,")),
                failures=sl.REPAIR_ATTEMPTS + 1,
            )
        self.assertEqual(self.campaign.stale, ["consensus/src/simplex/actors/voter/state.rs"])

    def test_the_plan_summary_records_a_stale_audit(self):
        run = lambda *args: subprocess.run(  # noqa: E731
            ("git",) + args, cwd=self.root, capture_output=True, text=True, check=True
        )
        run("init", "-q", ".")
        run("config", "user.email", "t@example.invalid")
        run("config", "user.name", "t")
        run("config", "commit.gpgsign", "false")
        run("add", "-A")
        run("commit", "-qm", "base")
        del self.campaign.record  # the real method, over the stub of setUp
        self.campaign.stale = ["consensus/src/simplex/actors/voter/state.rs"]
        self.campaign.record()
        summary = self.plan.read_text().split("## Summary", 1)[1]
        self.assertIn(
            "- Audit: stale; a repair changed 1 validated file(s) after it: "
            "consensus/src/simplex/actors/voter/state.rs",
            summary,
        )
        self.campaign.stale = []
        self.campaign.record()
        self.assertNotIn("Audit", self.plan.read_text().split("## Summary", 1)[1])

    def test_a_later_lint_does_not_move_the_validated_content(self):
        self.source.write_text(self.ORIGINAL.replace(", required,", ", true,"))
        self.campaign.check_plan()
        self.assertEqual(
            self.campaign.changed_since_validation(),
            ["consensus/src/simplex/actors/voter/state.rs"],
            "a clean lint must not re-validate the tree",
        )

    def summary(self, **values):
        campaign = sl.Campaign.__new__(sl.Campaign)
        fields = dict(
            repo=self.root, base=None, agent="claude", profile_name="simplex",
            profile=sl.PROFILES["simplex"], targets=[], fuzz_toolchain="nightly",
            statuses={"INV-0016": "bound"}, inactive=[], audited=[],
            coverage=(3, 1), plan_problems=0, sites=None, components=None,
            stale=None, reason=None, panic=None, initialized=False, dir=self.root,
        )
        fields.update(values)
        for key, value in fields.items():
            setattr(campaign, key, value)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            campaign.finish(0, "READY")
        return out.getvalue()

    def test_lint_problems_mark_the_coverage_unvalidated(self):
        text = self.summary(plan_problems=2)
        self.assertIn("coverage   UNVALIDATED: 2 plan lint problem(s)", text)
        self.assertIn("result     READY", text)
        self.assertNotIn("UNVALIDATED", self.summary())

    def test_a_stale_audit_marks_the_coverage_unvalidated_despite_a_clean_lint(self):
        text = self.summary(audited=[], stale=["consensus/src/simplex/actors/voter/state.rs"])
        self.assertIn("audit      no status change [stale: a repair changed the tree after it]", text)
        self.assertIn(
            "coverage   UNVALIDATED: a repair changed 1 validated file(s) after the audit "
            "(consensus/src/simplex/actors/voter/state.rs)",
            text,
        )
        self.assertIn("result     READY", text)
        both = self.summary(plan_problems=1, stale=["plan.md"])
        self.assertIn("1 plan lint problem(s), so the code does not support", both)
        self.assertIn("; a repair changed 1 validated file(s)", both)
        self.assertNotIn("stale", self.summary(audited=[], stale=[]))

    def test_failed_component_tests_are_named_beside_the_result(self):
        text = self.summary(components=["simplex::actors::voter::t"])
        self.assertIn("components 1 failed, not gated: simplex::actors::voter::t", text)
        self.assertIn("components all passed", self.summary(components=[]))
        self.assertNotIn("components", self.summary(components=None))

    def test_inactive_bindings_are_named_beside_the_statuses(self):
        text = self.summary(inactive=["INV-0007"])
        self.assertIn("unbound 0); inactive in the fuzz targets: INV-0007", text)

    def test_no_audit_marks_the_coverage_unvalidated(self):
        text = self.summary(audited=None)
        self.assertNotIn("statelens: audit", text)
        self.assertIn("coverage   UNVALIDATED: no audit pass ran (STATELENS_AUDIT=0)", text)
        self.assertNotIn("UNVALIDATED", self.summary(audited=None, statuses={}))


class PhaseOrder(unittest.TestCase):
    """The audit is the last agent pass, so its verdict stands for the tree the plan
    lint fingerprints and the build hands over. Before, the beacon agents ran after
    it and could rewrite an assertion the audit had endorsed, unseen by anything."""

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.source = self.root / "consensus/src/simplex/actors/voter/state.rs"
        self.source.parent.mkdir(parents=True)
        self.source.write_text(RepairRevalidation.ORIGINAL)
        (self.root / "plan.md").write_text(AssertionScanner.PLAN)
        self.campaign = sl.Campaign.__new__(sl.Campaign)
        fields = dict(
            repo=self.root, dir=self.root, base=None, agent="fixture",
            profile_name="simplex", profile=sl.PROFILES["simplex"], targets=[],
            fuzz_toolchain="nightly", invariants=[("simplex", pathlib.Path("INV-0016.md"))],
            config={"STATELENS_AUDIT": "1"}, statuses={"INV-0016": "bound"}, inactive=[],
            audited=None, coverage=None, plan_problems=None, sites=None, components=None,
            reason=None, panic=None, initialized=False,
        )
        for key, value in fields.items():
            setattr(self.campaign, key, value)
        self.campaign.invariant_prompts = lambda: []
        self.campaign.beacon_prompts = lambda: [("beacons", "fixture beacons")]
        self.campaign.audit_prompts = lambda: [("audit", "fixture audit")]
        self.campaign.check_scope = lambda: None
        self.campaign.record = lambda: None
        self.campaign.build_once = lambda _attempt: None
        self.steps, self.audited = [], []
        saved = sl.say
        sl.say = lambda *_args, **_kw: None
        self.addCleanup(setattr, sl, "say", saved)

    def handover(self, beacon_edit=None, audit_edit=None):
        def agent_step(name, _prompt):
            self.steps.append(name)
            if name == "beacons" and beacon_edit:
                self.source.write_text(beacon_edit)
            if name == "audit":
                if audit_edit:
                    self.source.write_text(audit_edit)
                self.audited.append(sl.sha256(self.source))

        self.campaign.agent_step = agent_step
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.campaign.instrument()
            self.campaign.build()
            self.campaign.finish(0, "READY")
        return out.getvalue()

    def test_the_audit_runs_after_the_beacon_step(self):
        self.handover()
        self.assertEqual(self.steps, ["beacons", "audit"])

    def test_an_assertion_the_beacon_agent_rewrote_is_audited_as_handed_over(self):
        weakened = RepairRevalidation.ORIGINAL.replace(", required,", ", true,")
        out = self.handover(weakened)
        self.assertEqual(self.audited, [sl.sha256(self.source)], "the audit must see the final tree")
        self.assertEqual(self.campaign.plan_problems, 0)
        self.assertIsNotNone(self.campaign.audit_content, "the fingerprint follows the audit")
        self.assertNotIn("UNVALIDATED", out)
        self.assertIn("result     READY", out)

    def test_the_fingerprint_is_of_the_tree_the_audit_left(self):
        # The audit's own edits are what the build validates, so the fingerprint
        # must be taken after them, and a first-attempt build hands them over
        # with nothing stale.
        edited = RepairRevalidation.ORIGINAL.replace('"checked"', '"audited"')
        out = self.handover(audit_edit=edited)
        self.assertEqual(
            self.campaign.audit_content["consensus/src/simplex/actors/voter/state.rs"],
            sl.sha256(self.source),
        )
        self.assertIsNone(self.campaign.stale)
        self.assertNotIn("UNVALIDATED", out)

    def test_without_an_audit_the_statuses_are_reported_unvalidated(self):
        self.campaign.config = {"STATELENS_AUDIT": "0"}
        out = self.handover()
        self.assertEqual(self.steps, ["beacons"])
        self.assertIn("coverage   UNVALIDATED: no audit pass ran (STATELENS_AUDIT=0)", out)
        self.assertIn("result     READY", out)


class InactiveBindings(unittest.TestCase):
    """A binding can be complete and still never evaluated by the fuzz targets,
    whose `cert_mock` scheme hides what its `pre` needs; the Status qualifier says so
    and the campaign reports it apart from the statuses."""

    PLAN = (
        "# Plan\n\n## Invariants\n\n### INV-0007: title\n"
        "- Status: partial (inactive in the fuzz targets)\n- Reading: r\n"
        "- Sites: `voter/state.rs` `State::construct_notarize`, signature - checked\n"
        "- Assertions: `voter/state.rs` `State::construct_notarize`, `sl_implies!`\n"
        "- Probes: none\n- Ghost state: none\n- Edited lines: none\n"
        "- Notes: the mock certificate is an opaque handle\n"
    )
    CODE = {"consensus/src/simplex/actors/voter/state.rs": [("INV-0007", "State::construct_notarize")]}

    def test_the_qualifier_lints_as_its_status(self):
        with tempfile.TemporaryDirectory() as root:
            plan = pathlib.Path(root) / "plan.md"
            plan.write_text(self.PLAN)
            self.assertEqual(sl.lint_plan_file(plan, ["INV-0007"], self.CODE), [])
        self.assertEqual(sl.Campaign.parse_statuses(self.PLAN), {"INV-0007": "partial"})
        self.assertEqual(sl.Campaign.inactive_invariants(self.PLAN), ["INV-0007"])

    def test_a_plain_status_is_active(self):
        plain = self.PLAN.replace(" (inactive in the fuzz targets)", "")
        self.assertEqual(sl.Campaign.inactive_invariants(plain), [])
        self.assertEqual(sl.inactive_note([]), "")
        self.assertEqual(sl.inactive_note(["INV-0007"]), "; inactive in the fuzz targets: INV-0007")

    def test_a_paraphrased_qualifier_is_reported_not_dropped(self):
        # The gap: `partial (not active under cert_mock)` passed the lint and was
        # counted as an active partial binding.
        paraphrased = self.PLAN.replace(
            "(inactive in the fuzz targets)", "(not active under cert_mock)"
        )
        with tempfile.TemporaryDirectory() as root:
            plan = pathlib.Path(root) / "plan.md"
            plan.write_text(paraphrased)
            problems = sl.lint_plan_file(plan, ["INV-0007"], self.CODE)
        self.assertTrue(any("qualifier" in problem for problem in problems), problems)
        self.assertEqual(sl.Campaign.inactive_invariants(paraphrased), [])


class KbSnippets(unittest.TestCase):
    """`kb grep` confines a match to the sections the registry allows, but the
    snippet around it was cut from the whole file, so a match on a section's last
    line showed the heading of the section the search excluded."""

    BODY = (
        "# Finding\n"             # 1
        "\n"                      # 2
        "## Root Cause\n"         # 3
        "needle\n"                # 4
        "## Excluded sentinel\n"  # 5
        "excluded body\n"         # 6
        "## Context\n"            # 7
        "more\n"                  # 8
    )

    def setUp(self):
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "f.md").write_text(self.BODY)
        spans = sl.section_spans(self.BODY)
        self.entry = {
            "kind": "finding", "order": 0, "root": str(root), "path": "f.md",
            "identifier": "f", "modules": ["consensus/simplex"],
            "sections": {k: v for k, v in spans.items() if k in sl.KB_STATE_SECTIONS},
            "refs": {"paths": [], "symbols": []},
        }

    def hit(self, needle):
        hits = sl.kb_grep([self.entry], "simplex", needle)
        self.assertEqual(len(hits), 1, hits)
        _order, _path, _offset, entry, section, line = hits[0]
        return section, line, sl.kb_snippet(entry, line)

    def test_a_hit_on_a_sections_last_line_shows_no_excluded_heading(self):
        section, line, snippet = self.hit("needle")
        self.assertEqual((section, line), ("Root Cause", 4))
        self.assertIn("needle", snippet)
        self.assertNotIn("Excluded sentinel", snippet)

    def test_a_hit_on_a_sections_first_line_shows_no_excluded_body(self):
        section, line, snippet = self.hit("more")
        self.assertEqual((section, line), ("Context", 8))
        self.assertIn("more", snippet)
        self.assertNotIn("excluded body", snippet)
        # With more context the window reaches two lines back, into the excluded
        # section, unless it is clamped.
        wider = sl.kb_snippet(self.entry, line, context=5)
        self.assertIn("more", wider)
        self.assertNotIn("excluded body", wider)
        self.assertNotIn("Excluded sentinel", wider)

    def test_an_excluded_section_is_not_searched(self):
        self.assertEqual(sl.kb_grep([self.entry], "simplex", "excluded"), [])

    def test_a_document_keeps_the_whole_file_context(self):
        document = dict(self.entry, kind="document", sections={}, modules=[])
        snippet = sl.kb_snippet(document, 4)
        self.assertIn("Root Cause", snippet)
        self.assertIn("Excluded sentinel", snippet)


class LineCitations(unittest.TestCase):
    """A line number means something only at one commit: an invariant cites lines as
    `path:line@commit` (lint rule 10), and ends with the cited lines copied in at that
    commit (rule 11), which `statelens.py excerpts` writes."""

    SOURCE = (
        "//! First line\n"                       # 1
        "//! Second, with a dash — here\n"  # 2  non-ASCII, escaped in an excerpt
        "//! see line 5 of the table\n"          # 3  prose a bare-line check must not read
        "/// ```rust\n"                          # 4  a fence inside the excerpt
        "/// code\n"                             # 5
        "/// ```\n"                              # 6
        "fn main() {}\n"                         # 7
    )

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        source = self.repo / "consensus/src/x.rs"
        source.parent.mkdir(parents=True)
        source.write_text(self.SOURCE)
        self.registry = self.repo / "statelens/invariants/simplex"
        self.registry.mkdir(parents=True)
        for args in (("init", "-q", "."), ("config", "user.email", "t@example.invalid"),
                     ("config", "user.name", "t"), ("config", "commit.gpgsign", "false"),
                     ("add", "-A"), ("commit", "-qm", "base")):
            subprocess.run(("git",) + args, cwd=self.repo, capture_output=True, check=True)
        self.commit = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"], cwd=self.repo,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        sl._GIT_FILES.clear()

    def invariant(self, evidence, name="INV-0001.md"):
        path = self.registry / name
        path.write_text(
            "---\nid: INV-0001\ntitle: t\nsource_kind: comment\n"
            f"source_ref: consensus/src/x.rs:1@{self.commit}\nscope: [replica]\n---\n\n"
            "## Statement\nThe replica shall hold.\n\n## Rationale\nBecause.\n\n"
            f"## Evidence\n{evidence}\n"
        )
        return path

    def rule(self, path, number):
        return [problem for problem in sl.lint_file(path) if f"(rule {number})" in problem]

    def test_a_line_without_a_commit_is_reported(self):
        path = self.invariant("`consensus/src/x.rs:3` says so.")
        self.assertTrue(any("without a commit" in p for p in self.rule(path, 10)))

    def test_a_pinned_line_that_resolves_needs_only_its_excerpt(self):
        path = self.invariant(f"`consensus/src/x.rs:3-6@{self.commit}` says so.")
        self.assertEqual(self.rule(path, 10), [])
        self.assertTrue(self.rule(path, 11), "a pinned citation needs its excerpt")
        path.write_text(sl.with_excerpts(path.read_text(), self.repo))
        self.assertEqual(sl.lint_file(path), [])

    def test_a_citation_that_does_not_resolve_is_reported(self):
        path = self.invariant(
            f"`x.rs:3@{self.commit}` and `consensus/src/x.rs:99@{self.commit}` say so."
        )
        problems = self.rule(path, 10)
        self.assertTrue(any("no file x.rs exists" in p for p in problems), problems)
        self.assertTrue(any("has 7 lines there" in p for p in problems), problems)

    def test_bare_lines_and_branch_links_are_reported(self):
        path = self.invariant(
            "It says so (lines 3-4), in https://github.com/o/r/blob/main/x.rs#L3, unlike "
            f"https://github.com/o/r/blob/{self.commit}/x.rs#L3 and https://example.invalid:443/."
        )
        problems = self.rule(path, 10)
        self.assertEqual(len(problems), 2, problems)
        self.assertTrue(any("`lines 3`" in p for p in problems))
        self.assertTrue(any("a line of a branch" in p for p in problems))

    def test_an_excerpt_merges_near_ranges_escapes_and_fences(self):
        text = self.invariant(
            f"`consensus/src/x.rs:3-6@{self.commit}` says so."
        ).read_text()
        section = sl.excerpt_section(text, self.repo)
        # source_ref cites line 1 and the text 3-6: one line apart, so one excerpt.
        self.assertIn(f"`consensus/src/x.rs:1-6@{self.commit}`\n````rust\n", section)
        self.assertIn("//! Second, with a dash \\u2014 here", section)
        self.assertIn("/// ```\n````", section, "the fence outgrows the one inside")
        self.assertTrue(section.isascii())

    def test_the_excerpt_section_is_not_read_as_citations(self):
        path = self.invariant(f"`consensus/src/x.rs:3@{self.commit}` says so.")
        path.write_text(sl.with_excerpts(path.read_text(), self.repo))
        self.assertIn("see line 5 of the table", path.read_text())
        self.assertEqual(sl.lint_file(path), [], "prose inside an excerpt is not a bare line")
        self.assertEqual(sl.with_excerpts(path.read_text(), self.repo), path.read_text())

    def test_a_stale_excerpt_is_reported_and_rewritten(self):
        path = self.invariant(f"`consensus/src/x.rs:3@{self.commit}` says so.")
        path.write_text(sl.with_excerpts(path.read_text(), self.repo).replace("code", "edited"))
        self.assertTrue(self.rule(path, 11))
        saved = (sl.repo_root, sl.say)
        sl.repo_root, sl.say = (lambda: self.repo), (lambda *_a, **_k: None)
        self.addCleanup(lambda: (setattr(sl, "repo_root", saved[0]), setattr(sl, "say", saved[1])))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sl.cmd_excerpts(argparse.Namespace(paths=[str(path)], check=True)), 3)
            self.assertEqual(sl.cmd_excerpts(argparse.Namespace(paths=[str(path)], check=False)), 0)
            self.assertEqual(sl.cmd_excerpts(argparse.Namespace(paths=[str(path)], check=True)), 0)
        self.assertEqual(sl.lint_file(path), [])

    def test_a_file_without_pinned_citations_gets_no_section(self):
        path = self.invariant("Human-authored.")
        path.write_text(path.read_text().replace(f"consensus/src/x.rs:1@{self.commit}", "x"))
        self.assertEqual(sl.lint_file(path), [])
        self.assertNotIn(sl.EXCERPTS, sl.with_excerpts(path.read_text(), self.repo))

    def test_outside_a_clone_citations_are_not_resolved(self):
        elsewhere = pathlib.Path(tempfile.mkdtemp()) / "invariants/simplex"
        self.addCleanup(shutil.rmtree, elsewhere.parent.parent, True)
        elsewhere.mkdir(parents=True)
        path = self.invariant(f"`consensus/src/x.rs:99@{self.commit}` says so.")
        moved = elsewhere / "INV-0001.md"
        moved.write_text(path.read_text())
        self.assertEqual(self.rule(moved, 10) + self.rule(moved, 11), [])

    def test_extraction_pins_head_and_names_tracked_changes(self):
        values = sl.extract_values(
            self.repo, HERE.parent, "comment", "simplex", ["consensus/src/x.rs"]
        )
        self.assertEqual(values["COMMIT"], self.commit)
        (self.repo / "consensus/src/x.rs").write_text(self.SOURCE + "// edited\n")
        (self.repo / "consensus/src/new.rs").write_text("// untracked\n")
        (self.registry / "INV-0002.md").write_text("draft\n")
        self.assertEqual(sl.unpinnable(sl.worktree_state(self.repo)), ["consensus/src/x.rs"])


class ConfigLayers(unittest.TestCase):
    """`config.env` is tracked, so a knowledge-base root or any private value goes
    in `config.local.env`, which git ignores and which overrides the tracked file;
    the environment overrides both."""

    def setUp(self):
        self.sl_dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.sl_dir, True)
        (self.sl_dir / "config.env").write_text(
            "# defaults\nSTATELENS_AGENT=claude\nSTATELENS_KB=\nSTATELENS_AUDIT=1\n"
        )
        saved = os.environ.pop("STATELENS_KB", None)
        self.addCleanup(lambda: os.environ.update({"STATELENS_KB": saved}) if saved else None)

    def test_the_tracked_file_alone_gives_the_defaults(self):
        values = sl.load_config(self.sl_dir)
        self.assertEqual((values["STATELENS_AGENT"], values["STATELENS_KB"]), ("claude", ""))

    def test_the_local_file_overrides_the_tracked_one(self):
        (self.sl_dir / sl.CONFIG_LOCAL).write_text("STATELENS_KB=/private/findings\n")
        values = sl.load_config(self.sl_dir)
        self.assertEqual(values["STATELENS_KB"], "/private/findings")
        self.assertEqual(values["STATELENS_AGENT"], "claude", "untouched keys keep the default")

    def test_the_environment_overrides_both(self):
        (self.sl_dir / sl.CONFIG_LOCAL).write_text("STATELENS_KB=/private/findings\n")
        os.environ["STATELENS_KB"] = "/other"
        try:
            self.assertEqual(sl.load_config(self.sl_dir)["STATELENS_KB"], "/other")
        finally:
            del os.environ["STATELENS_KB"]

    def test_a_malformed_local_line_names_its_file(self):
        (self.sl_dir / sl.CONFIG_LOCAL).write_text("no equals sign\n")
        with self.assertRaises(sl.Abort) as caught:
            sl.load_config(self.sl_dir)
        self.assertIn("config.local.env:1", str(caught.exception))

    def test_the_local_file_is_ignored_by_git(self):
        ignored = (HERE.parent / ".gitignore").read_text().splitlines()
        self.assertIn(sl.CONFIG_LOCAL, ignored)
        tracked = (HERE.parent / "config.env").read_text().splitlines()
        self.assertIn("STATELENS_KB=", tracked, "the tracked file must leave the corpus root empty")


class AuditBatches(unittest.TestCase):
    """The audit runs one agent per batch, and each batch's verdict stands for the
    tree it left. A later batch that changes or removes a line may have edited what
    an earlier binding rests on, which nothing reviews again, so those bindings are
    reported unreviewed; a batch that only adds lines changes nothing reviewed."""

    SOURCE = (
        "struct State;\nimpl State {\n"
        "    fn try_propose(required: bool) {\n"
        '        sl_assert!(None, "INV-0016", evidence(required), "a");\n'
        "    }\n"
        "    fn try_other(required: bool) {\n"
        '        sl_assert!(None, "INV-0017", evidence(required), "b");\n'
        "    }\n}\n"
    )
    HELPER = "pub fn evidence(required: bool) -> bool {\n    required\n}\n"
    FIRST = "## Task: audit the bindings of invariants INV-0016 of the simplex registry\n"
    SECOND = "## Task: audit the bindings of invariants INV-0017 of the simplex registry\n"

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.source = self.root / "consensus/src/simplex/actors/voter/state.rs"
        self.source.parent.mkdir(parents=True)
        self.source.write_text(self.SOURCE)
        self.helper = self.root / "consensus/src/simplex/statelens.rs"
        self.helper.write_text(self.HELPER)
        second = AssertionScanner.PLAN.split("### ", 1)[1]
        second = second.replace("INV-0016", "INV-0017").replace("try_propose", "try_other")
        (self.root / "plan.md").write_text(AssertionScanner.PLAN + "\n### " + second)
        self.campaign = sl.Campaign.__new__(sl.Campaign)
        fields = dict(
            repo=self.root, dir=self.root, base=None, agent="fixture",
            profile_name="simplex", profile=sl.PROFILES["simplex"], targets=[],
            fuzz_toolchain="nightly",
            invariants=[("simplex", pathlib.Path("INV-0016.md")), ("simplex", pathlib.Path("INV-0017.md"))],
            config={"STATELENS_AUDIT": "1"}, statuses={"INV-0016": "bound", "INV-0017": "bound"},
            inactive=[], audited=None, coverage=None, plan_problems=None, sites=None,
            components=None, reason=None, panic=None, initialized=False,
        )
        for key, value in fields.items():
            setattr(self.campaign, key, value)
        self.campaign.invariant_prompts = lambda: []
        self.campaign.beacon_prompts = lambda: []
        self.campaign.audit_prompts = lambda: [
            ("audit-simplex-1", self.FIRST), ("audit-simplex-2", self.SECOND)
        ]
        self.campaign.check_scope = lambda: None
        self.campaign.record = lambda: None
        self.campaign.build_once = lambda _attempt: None
        saved = sl.say
        sl.say = lambda *_args, **_kw: None
        self.addCleanup(setattr, sl, "say", saved)

    def handover(self, second_batch=None, lint_clean=True):
        def agent_step(name, _prompt):
            if name == "audit-simplex-2" and second_batch:
                second_batch()

        self.campaign.agent_step = agent_step
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.campaign.instrument()
            self.campaign.build()
            self.campaign.finish(0, "READY")
        if lint_clean:
            self.assertEqual(self.campaign.plan_problems, 0, "the lint cannot see these edits")
        return out.getvalue()

    def test_a_later_batch_that_edits_a_helper_leaves_earlier_bindings_unreviewed(self):
        out = self.handover(
            lambda: self.helper.write_text(self.HELPER.replace("    required\n", "    true\n"))
        )
        self.assertEqual(
            self.campaign.unreviewed,
            {
                "INV-0016": (
                    "audit-simplex-2",
                    ["consensus/src/simplex/statelens.rs (changed or removed lines)"],
                )
            },
        )
        self.assertIn(
            "coverage   UNVALIDATED: audit batch audit-simplex-2 edited "
            "consensus/src/simplex/statelens.rs (changed or removed lines) after the verdict "
            "on INV-0016, which were not reviewed against the edit",
            out,
        )
        self.assertIn("result     READY", out)

    def test_lines_added_inside_an_existing_body_are_an_edit(self):
        # The gap: a pure insertion was quiet wherever it landed, but a `let` that
        # shadows the argument changes what the earlier assertion evaluates.
        out = self.handover(
            lambda: self.helper.write_text(
                self.HELPER.replace("{\n", "{\n    let required = true;\n")
            )
        )
        self.assertIn("UNVALIDATED", out)
        self.assertEqual(
            self.campaign.unreviewed["INV-0016"][1],
            ["consensus/src/simplex/statelens.rs (added lines inside `evidence`)"],
        )

    def test_a_check_added_inside_a_body_is_quiet(self):
        def add_check():
            self.source.write_text(
                self.SOURCE.replace(
                    '        sl_assert!(None, "INV-0017", evidence(required), "b");\n',
                    '        sl_assert!(None, "INV-0017", evidence(required), "b");\n'
                    "        // [statelens] INV-0017\n"
                    "        crate::simplex::statelens::sl_implies!(\n"
                    "            None,\n"
                    '            "INV-0017",\n'
                    "            required,\n"
                    "            evidence(required),\n"
                    '            "b again: {}", required\n'
                    "        );\n",
                )
            )

        out = self.handover(add_check)
        self.assertEqual(self.campaign.unreviewed, {})
        self.assertNotIn("UNVALIDATED", out)

    def test_an_attribute_or_comment_opener_above_an_item_is_an_edit(self):
        for edit, expected in (
            (
                lambda: self.helper.write_text("#[cfg(any())]\n" + self.HELPER),
                "added an attribute or a comment opener above an item",
            ),
            (
                lambda: self.source.write_text(
                    self.SOURCE.replace(
                        '        sl_assert!(None, "INV-0016", evidence(required), "a");\n',
                        "        /*\n"
                        '        sl_assert!(None, "INV-0016", evidence(required), "a");\n'
                        "        */\n",
                    )
                ),
                "added lines inside `try_propose`",
            ),
        ):
            with self.subTest(expected=expected):
                self.setUp()
                # Commenting the check out is also a lint problem; the drift check
                # must name the edit regardless.
                out = self.handover(edit, lint_clean=False)
                self.assertIn("UNVALIDATED", out)
                self.assertIn(expected, self.campaign.unreviewed["INV-0016"][1][0])

    def test_an_appended_copy_of_an_earlier_block_is_an_addition(self):
        # A diff pairs the old block with its later copy and calls the lines between
        # removed; the subsequence walk sees every old line survive.
        twice = self.HELPER + "pub fn more() -> bool { true }\n" + self.HELPER.replace(
            "evidence", "evidence_again"
        )
        out = self.handover(lambda: self.helper.write_text(twice))
        self.assertEqual(self.campaign.unreviewed, {})
        self.assertNotIn("UNVALIDATED", out)

    def test_the_plan_summary_records_the_unreviewed_bindings(self):
        run = lambda *args: subprocess.run(  # noqa: E731
            ("git",) + args, cwd=self.root, capture_output=True, text=True, check=True
        )
        run("init", "-q", ".")
        run("config", "user.email", "t@example.invalid")
        run("config", "user.name", "t")
        run("config", "commit.gpgsign", "false")
        run("add", "-A")
        run("commit", "-qm", "base")
        del self.campaign.record
        self.campaign.unreviewed = {
            "INV-0016": ("audit-simplex-2", ["consensus/src/simplex/statelens.rs (changed or removed lines)"])
        }
        self.campaign.record()
        summary = (self.root / "plan.md").read_text().split("## Summary", 1)[1]
        self.assertIn(
            "- Audit: audit batch audit-simplex-2 edited consensus/src/simplex/statelens.rs "
            "(changed or removed lines) after the verdict on INV-0016",
            summary,
        )

    def test_a_later_batch_that_only_adds_lines_leaves_nothing_unreviewed(self):
        def add():
            self.helper.write_text(self.HELPER + "pub fn more() -> bool { true }\n")
            self.source.write_text(
                self.SOURCE.replace("    fn try_other", '    // [statelens] INV-0017\n    fn try_other')
            )

        out = self.handover(add)
        self.assertEqual(self.campaign.unreviewed, {})
        self.assertNotIn("UNVALIDATED", out)

    def test_a_removed_line_counts_as_an_edit(self):
        out = self.handover(lambda: self.helper.write_text(""))
        self.assertEqual(list(self.campaign.unreviewed), ["INV-0016"])
        self.assertIn("UNVALIDATED", out)

    def test_the_task_line_names_the_batch(self):
        prompt = (
            "# StateLens instrumenter\n\n## Task: audit the bindings of invariants INV-0001, "
            "INV-0002 of the simplex registry\n\nINV-0003 and INV-0004 cover the rest.\n"
        )
        self.assertEqual(sl.prompt_invariants(prompt), ["INV-0001", "INV-0002"])
        self.assertEqual(sl.prompt_invariants("INV-0016"), ["INV-0016"])
        self.assertFalse(sl.modified_lines("", "new file\n"))
        self.assertFalse(sl.modified_lines("a\nb\n", "a\nb\nc\n"))
        self.assertTrue(sl.modified_lines("a\nb\n", "a\nB\n"))
        self.assertTrue(sl.modified_lines("a\nb\n", "a\n"))


class PromptCopies(unittest.TestCase):
    """Section 13 of the specification claims to reproduce every prompt verbatim.
    Nothing enforced it, and two prompts had drifted from their copies, so the
    specification described rules the agents were never given."""

    SPEC = (
        "# Spec\n\n## 13. Prompts (verbatim)\n\n"
        "### 13.1 `prompts/one.md`\n\n~~~markdown\nfirst\n~~~\n\n"
        "### 13.2 `prompts/two.md`\n\n~~~markdown\nsecond\n~~~\n\n## 14. Next\n"
    )

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / sl.SL
        (self.sl_dir / "prompts").mkdir(parents=True)
        (self.sl_dir / "docs").mkdir(parents=True)
        self.spec = self.repo / sl.SPEC_DOC
        self.spec.write_text(self.SPEC)
        (self.sl_dir / "prompts/one.md").write_text("first\n")
        (self.sl_dir / "prompts/two.md").write_text("second\n")
        self.saved = sl.say
        sl.say = lambda *_args, **_kwargs: None
        self.addCleanup(lambda: setattr(sl, "say", self.saved))

    def test_matching_copies_are_clean(self):
        self.assertEqual(sl.lint_prompts(self.repo), [])

    def test_a_drifted_copy_is_reported(self):
        (self.sl_dir / "prompts/two.md").write_text("second, with a new rule\n")
        problems = sl.lint_prompts(self.repo)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("differs from its copy", problems[0][1])

    def test_write_refreshes_the_copy_and_leaves_the_rest_alone(self):
        (self.sl_dir / "prompts/one.md").write_text("first, with a new rule\n")
        sl.lint_prompts(self.repo, write=True)
        self.assertEqual(sl.lint_prompts(self.repo), [])
        text = self.spec.read_text()
        self.assertIn("first, with a new rule\n~~~", text)
        self.assertIn("### 13.2 `prompts/two.md`\n\n~~~markdown\nsecond\n~~~", text)
        self.assertTrue(text.endswith("## 14. Next\n"), "the rest of the document must survive")

    def test_write_refreshes_several_stale_copies_at_once(self):
        (self.sl_dir / "prompts/one.md").write_text("first, rewritten\n")
        (self.sl_dir / "prompts/two.md").write_text("second, rewritten\n")
        sl.lint_prompts(self.repo, write=True)
        self.assertEqual(sl.lint_prompts(self.repo), [])
        text = self.spec.read_text()
        self.assertIn("~~~markdown\nfirst, rewritten\n~~~", text)
        self.assertIn("~~~markdown\nsecond, rewritten\n~~~", text)

    def test_a_prompt_that_quotes_a_fence_round_trips(self):
        (self.sl_dir / "prompts/two.md").write_text("second\n\n~~~markdown\ninner\n~~~\n\ntail\n")
        sl.lint_prompts(self.repo, write=True)
        self.assertEqual(sl.lint_prompts(self.repo), [], "a quoted fence must not end the block")
        self.assertTrue(self.spec.read_text().endswith("## 14. Next\n"))

    def test_a_prompt_with_no_copy_is_reported(self):
        (self.sl_dir / "prompts/three.md").write_text("third\n")
        problems = sl.lint_prompts(self.repo)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("has no `### 13.N", problems[0][1])

    def test_a_copy_with_no_prompt_is_reported(self):
        (self.sl_dir / "prompts/two.md").unlink()
        problems = sl.lint_prompts(self.repo)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("which does not exist", problems[0][1])



class PlanProfile(unittest.TestCase):
    """The audit prompt runs `lint-plan` with no profile, so in a qmdb campaign the
    bare command must check the qmdb registry, not the simplex default."""

    PLAN = (
        "# StateLens instrumentation plan\n\n## Invariants\n\n"
        "### INV-0034: Example\n- Status: unbound\n- Notes: fixture.\n"
    )

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / sl.SL
        for registry, identifier in (("simplex", "INV-0001"), ("qmdb", "INV-0034")):
            directory = self.sl_dir / "invariants" / registry
            directory.mkdir(parents=True)
            (directory / f"{identifier}.md").write_text("unused by the plan lint\n")
        (self.sl_dir / "campaign").mkdir()
        (self.repo / sl.PLAN).write_text(self.PLAN)
        saved = {name: getattr(sl, name) for name in ("repo_root", "say")}
        sl.repo_root = lambda: self.repo
        sl.say = lambda *_args, **_kw: None
        self.addCleanup(lambda: [setattr(sl, k, v) for k, v in saved.items()])

    def lint(self, *flags, profile="qmdb"):
        if profile:
            meta = self.sl_dir / "campaign" / "meta.json"
            meta.write_text(json.dumps({"profile": profile}))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = sl.main(["lint-plan", *flags])
        return code, out.getvalue()

    def test_the_bare_command_checks_the_campaign_profile(self):
        code, output = self.lint()
        self.assertEqual(code, 0, output)

    def test_the_bare_command_expects_the_campaign_selection(self):
        # A campaign run with --invariants has sections for the ids it selected only.
        (self.sl_dir / "invariants" / "simplex" / "INV-0002.md").write_text("unused\n")
        (self.repo / sl.PLAN).write_text(self.PLAN.replace("INV-0034", "INV-0002"))
        meta = self.sl_dir / "campaign" / "meta.json"
        meta.write_text(json.dumps({"profile": "simplex", "invariants": ["INV-0002"]}))
        code, output = self.lint(profile=None)
        self.assertEqual(code, 0, output)
        # Naming the campaign's own profile keeps its selection.
        code, output = self.lint("--profile", "simplex", profile=None)
        self.assertEqual(code, 0, output)
        # Another profile expects every invariant of its registries.
        code, output = self.lint("--profile", "qmdb", profile=None)
        self.assertEqual(code, 3, output)
        self.assertIn("INV-0034: has no section", output)
        self.assertNotIn("INV-0001", output)

    def test_an_explicit_profile_wins(self):
        code, output = self.lint("--profile", "simplex")
        self.assertEqual(code, 3, output)
        self.assertIn("INV-0001: has no section", output)

    def test_without_a_campaign_the_default_is_simplex(self):
        code, output = self.lint(profile=None)
        self.assertEqual(code, 3, output)
        self.assertIn("INV-0001: has no section", output)

    def test_an_unknown_campaign_profile_is_refused(self):
        code, _output = self.lint(profile="nonsense")
        self.assertEqual(code, 1)

def fake_embed(texts):
    """Unit vectors of letter counts: deterministic, and no model to load."""
    import math

    rows = []
    for text in texts:
        row = [0.0] * 8
        for char in text.lower():
            if char.isalpha():
                row[ord(char) % 8] += 1.0
        norm = math.sqrt(sum(value * value for value in row)) or 1.0
        rows.append([value / norm for value in row])
    return rows


class SemanticSearch(unittest.TestCase):
    """`kb search` and its index (SPEC section 5.10): what is chunked, what each chunk says
    it belongs to, what an update re-embeds, and what a query may reach."""

    RUST = (
        "//! Module docs explain the voter state machine and its rounds.\n"
        "use std::fmt;\n"
        "\n"
        "/// The state of one round of the voter state machine.\n"
        "pub struct Round {\n"
        "    /// The view this round belongs to, set once at creation.\n"
        "    view: u64,\n"
        "}\n"
        "\n"
        "impl Round {\n"
        "    /// Records the proposal and broadcasts it to every peer.\n"
        "    #[inline]\n"
        "    pub fn propose(&mut self) {\n"
        "        loop {\n"
        "            // Wait until the leader has proposed before voting here.\n"
        "            break;\n"
        "        }\n"
        "        // [statelens] INV-0001\n"
        "        let _ = 1;\n"
        "    }\n"
        "}\n"
        "\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    // Builds a round by hand and checks that proposing twice is refused.\n"
        "    fn t() {}\n"
        "}\n"
    )
    FINDING = (
        "# {identifier}\n\n```claim\nmodule: {module}\nsummary: {summary}\n"
        "severity_current: low\nremediation_status: fixed\n```\n\n"
        "## Root Cause\n\n{cause}\n\n## Impact\n\nexploit detail the search must never reach\n"
    )

    def test_rust_chunks_name_the_item_they_belong_to(self):
        chunks = sl.search_rust_chunks("consensus/src/simplex/actors/voter/round.rs", self.RUST, "c0ffee")

        def chunk(start):
            return next(item for item in chunks if item["text"].startswith(start))

        self.assertEqual(chunk("Module docs")["item"], "consensus::simplex::actors::voter::round")
        self.assertEqual(chunk("Module docs")["kind"], "module")
        self.assertEqual(chunk("Module docs")["lines"], [1, 1])
        self.assertEqual(chunk("The state")["item"], "Round")
        self.assertEqual(chunk("The view")["item"], "Round::view")
        self.assertEqual(chunk("Records")["item"], "Round::propose")
        self.assertEqual(chunk("Wait")["item"], "Round::propose")
        self.assertEqual(chunk("Wait")["kind"], "comment")
        self.assertEqual(chunk("Wait")["lines"], [15, 15])
        self.assertFalse(chunk("Wait")["test"])
        self.assertTrue(chunk("Builds")["test"])
        self.assertNotIn("INV-0001", "".join(item["text"] for item in chunks))
        self.assertTrue(all(item["commit"] == "c0ffee" for item in chunks))

    def test_markdown_chunks_carry_their_headings_and_skip_fences(self):
        text = (
            "# Guide\n\nThe guide explains how replicas agree on blocks.\n\n"
            "## Safety\n\n```\n# not a heading inside a fence\n```\n"
            "The safety argument relies on quorum intersection.\n"
        )
        chunks = sl.search_markdown_chunks(text)
        self.assertEqual([chunk["section"] for chunk in chunks], ["Guide", "Guide > Safety"])
        self.assertIn("# not a heading", chunks[1]["text"])
        self.assertEqual(chunks[0]["lines"], [3, 3])

    def test_long_text_is_cut_between_paragraphs(self):
        numbered = [(number, f"line {number} " + "x" * 300) for number in range(1, 9)]
        pieces = sl.search_pieces(numbered)
        self.assertGreater(len(pieces), 1)
        self.assertTrue(all(len(text) <= sl.SEARCH_CHUNK_CHARS for _, _, text in pieces))
        self.assertEqual(pieces[0][0], 1)
        self.assertEqual(pieces[-1][1], 8)

    GATED = (
        "/// Production helper, documented for every build.\n"
        "pub fn live() {\n"
        "    // A production comment that the search should offer by default.\n"
        "}\n"
        "\n"
        "/// Returns whether certification was aborted, for tests only.\n"
        "#[cfg(test)]\n"
        "pub fn is_aborted(&self) -> bool {\n"
        "    // Reads the flag that the tests set by hand before asserting.\n"
        "    true\n"
        "}\n"
        "\n"
        "/// Back in production once the gated item has ended.\n"
        "pub fn after() {}\n"
    )

    def test_gated_items_and_test_files_are_test_code(self):
        chunks = sl.search_rust_chunks("consensus/src/simplex/actors/voter/state.rs", self.GATED, "c")
        test = {chunk["text"].split()[0]: chunk["test"] for chunk in chunks}
        self.assertEqual(test, {"Production": False, "A": False, "Returns": True, "Reads": True, "Back": False})
        declared = sl.search_test_modules({
            "storage/src/qmdb/any/sync/mod.rs": "#[cfg(test)]\npub(crate) mod tests;\n",
            "runtime/src/iouring/runtime.rs": '#[cfg(test)]\n#[path = "tests.rs"]\nmod tests;\n',
            "consensus/src/x/mod.rs": "#[cfg(test)]\nmod fixtures;\npub mod live;\n",
            "consensus/src/x/y.rs": "#[cfg(all(test, feature = \"std\"))]\npub(crate) mod helpers;\n",
            "math/src/lib.rs": "#[cfg(any(test, feature = \"arbitrary\"))]\npub mod test;\n",
        })
        for path in ("storage/src/qmdb/any/sync/tests.rs", "runtime/src/iouring/tests.rs",
                     "consensus/src/x/fixtures.rs", "consensus/src/x/fixtures/mod.rs",
                     "consensus/src/x/fixtures/deep.rs", "consensus/src/x/y/helpers.rs"):
            chunk = sl.search_rust_chunks(path, self.GATED, "c", test_modules=declared)
            self.assertTrue(all(item["test"] for item in chunk), path)
        # Compiled into feature builds as well, so not test code; nor is a file merely
        # named tests.rs that no test-only declaration names.
        for path in ("math/src/test.rs", "consensus/src/x/live.rs", "tools/src/tests.rs"):
            chunk = sl.search_rust_chunks(path, self.GATED, "c", test_modules=declared)
            self.assertFalse(chunk[0]["test"], path)

    def test_long_lines_are_split_and_keep_their_line(self):
        numbered = [(7, " ".join(["word"] * 900))]
        pieces = sl.search_pieces(numbered)
        self.assertGreater(len(pieces), 1)
        self.assertTrue(all(len(text) <= sl.SEARCH_CHUNK_CHARS for _, _, text in pieces))
        self.assertTrue(all((first, last) == (7, 7) for first, last, _ in pieces))

    def test_chunks_fit_the_model_window_with_their_heading(self):
        def fits(text):
            return len(text.split()) <= 40

        numbered = [(number, f"line {number} " + "alpha beta gamma " * 6) for number in range(1, 13)]
        pieces = sl.search_pieces(numbered, head="Heading words here", fits=fits)
        self.assertTrue(all(fits(f"Heading words here\n{text}") for _, _, text in pieces))
        self.assertEqual(pieces[0][0], 1)
        self.assertEqual(pieces[-1][1], 12)
        self.assertEqual(" ".join(" ".join(text.split()) for _, _, text in pieces),
                         " ".join(" ".join(text.split()) for _, text in numbered))

    def test_identifiers_count_whole_and_in_parts(self):
        tokens = sl.search_tokens("The CertifyState of try_propose")
        for token in ("certifystate", "certify", "state", "try_propose", "try", "propose"):
            self.assertIn(token, tokens)
        self.assertNotIn("the", tokens)

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.corpus = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.corpus, True)
        self.sl_dir = self.repo / sl.SL
        self.sl_dir.mkdir()
        (self.sl_dir / "README.md").write_text("# StateLens\n\nTooling, never indexed by its own search.\n")
        source = self.repo / "consensus/src/simplex/actors/voter/round.rs"
        source.parent.mkdir(parents=True)
        source.write_text(self.RUST)
        (self.repo / "docs").mkdir()
        (self.repo / "docs/design.md").write_text(
            "# Design\n\nA nullification lets replicas skip a view whose leader is slow.\n"
        )
        for args in (("init", "-q", "."), ("config", "user.email", "t@example.invalid"),
                     ("config", "user.name", "t"), ("config", "commit.gpgsign", "false"),
                     ("add", "-A"), ("commit", "-qm", "base")):
            subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)
        for state, identifier, module, cause in (
            ("valid", "SIMPLEX-1", "consensus/simplex", "The voter signs a nullify vote after a finalize vote."),
            ("valid", "QMDB-1", "storage/qmdb/any", "A stale batch is applied after a fork."),
        ):
            path = self.corpus / "findings" / state / f"{identifier}.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.FINDING.format(identifier=identifier, module=module,
                                                summary=identifier.lower(), cause=cause))
        for directory, text in (("kb", "Design decision: votes are journaled before they are sent."),
                                ("context", "Context: the voter, batcher and resolver actors."),
                                ("config", "Settings of the corpus tooling, never indexed.")):
            (self.corpus / directory).mkdir()
            (self.corpus / directory / "note.md").write_text(f"# Note\n\n{text}\n")
        self.config = {"STATELENS_KB": str(self.corpus), "STATELENS_SEARCH_MODEL": "fake-model"}
        saved = {name: getattr(sl, name) for name in ("say", "repo_root", "search_embedder")}
        self.addCleanup(lambda: [setattr(sl, name, value) for name, value in saved.items()])
        sl.say = lambda message: None
        sl.repo_root = lambda: self.repo
        sl.search_embedder = lambda model, offline: (fake_embed, None)

    def calls(self):
        seen = []

        def embed(texts):
            seen.extend(texts)
            return fake_embed(texts)

        return seen, embed

    def test_build_indexes_every_source_and_never_the_tooling_or_config(self):
        seen, embed = self.calls()
        manifest = sl.search_build(self.repo, self.sl_dir, self.config, embed=embed)
        self.assertEqual(manifest["model"], "fake-model")
        self.assertEqual(set(manifest["sources"]), {"code", "doc", "finding", "kb"})
        _manifest, chunks, vectors = sl.search_load(self.sl_dir)
        self.assertEqual(len(vectors), len(chunks) * manifest["dim"] * 4)
        text = "\n".join(chunk["text"] for chunk in chunks)
        self.assertNotIn("never indexed", text)
        self.assertNotIn("exploit detail", text)
        self.assertIn("journaled before they are sent", text)
        self.assertIn("the voter, batcher and resolver actors", text)
        self.assertEqual(len(seen), len({sl.search_text(chunk) for chunk in chunks}))

    def test_an_update_embeds_only_what_changed(self):
        seen, embed = self.calls()
        sl.search_build(self.repo, self.sl_dir, self.config, embed=embed)
        seen.clear()
        sl.search_build(self.repo, self.sl_dir, self.config, embed=embed)
        self.assertEqual(seen, [], "an unchanged tree embeds nothing")
        (self.repo / "docs/design.md").write_text(
            "# Design\n\nA finalization makes certification below it obsolete.\n"
        )
        subprocess.run(["git", "commit", "-qam", "edit"], cwd=self.repo, check=True)
        sl.search_build(self.repo, self.sl_dir, self.config, embed=embed)
        self.assertEqual(len(seen), 1)
        self.assertIn("certification below it obsolete", seen[0])
        seen.clear()
        sl.search_build(self.repo, self.sl_dir, self.config, rebuild=True, embed=embed)
        self.assertGreater(len(seen), 1, "a rebuild embeds every chunk again")

    def test_the_index_reads_the_code_at_head_not_the_worktree(self):
        _seen, embed = self.calls()
        source = self.repo / "consensus/src/simplex/actors/voter/round.rs"
        source.write_text("// [statelens] beacon:x\n// An uncommitted edit, invisible to the index.\n")
        sl.search_build(self.repo, self.sl_dir, self.config, embed=embed)
        _manifest, chunks, _vectors = sl.search_load(self.sl_dir)
        self.assertNotIn("uncommitted edit", "\n".join(chunk["text"] for chunk in chunks))

    def search(self, *question, **flags):
        args = argparse.Namespace(
            question=list(question), registry=flags.get("registry", "simplex"),
            source=flags.get("source"), path=flags.get("path"),
            tests=flags.get("tests", False), limit=flags.get("limit", 40),
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(sl.cmd_kb_search(args), 0)
        return output.getvalue()

    def test_a_query_reaches_only_what_is_in_scope(self):
        _seen, embed = self.calls()
        sl.search_build(self.repo, self.sl_dir, self.config, embed=embed)
        found = self.search("voter nullify finalize vote")
        self.assertIn("SIMPLEX-1", found)
        self.assertNotIn("QMDB-1", found, "a finding outside the registry's modules")
        self.assertNotIn("proposing twice", found, "test code is hidden by default")
        self.assertIn("proposing twice", self.search("proposing twice refused", tests=True))
        self.assertIn("ranked by meaning and by words (fake-model)", found)
        code = self.search("leader proposed voting", path=["docs"])
        self.assertNotIn("round.rs", code, "--path narrows the code")
        self.assertIn("consensus/src/simplex/actors/voter/round.rs:15@", self.search("leader proposed voting"))

    def test_without_vectors_a_query_ranks_by_words(self):
        sl.search_embedder = lambda model, offline: (None, "no model here")
        manifest = sl.search_build(self.repo, self.sl_dir, self.config)
        self.assertIsNone(manifest["model"])
        folder = self.sl_dir / sl.SEARCH_DIR / manifest["generation"]
        self.assertTrue((folder / "chunks.jsonl").is_file())
        self.assertFalse((folder / "vectors.f32").exists())
        found = self.search("stale batch applied fork", registry="qmdb")
        self.assertIn("QMDB-1", found)
        self.assertIn("ranked by words only (no model here)", found)

    def assert_vectors_match_texts(self):
        manifest, chunks, vectors = sl.search_load(self.sl_dir)
        dim = manifest["dim"]
        for index, chunk in enumerate(chunks):
            stored = struct.unpack_from(f"<{dim}f", vectors, index * dim * 4)
            expected = fake_embed([sl.search_text(chunk)])[0]
            self.assertTrue(
                all(abs(a - b) < 1e-5 for a, b in zip(stored, expected)),
                f"chunk {index} has another text's vector: {chunk['text'][:50]!r}",
            )

    def test_an_interrupted_update_leaves_a_consistent_index(self):
        _seen, embed = self.calls()
        sl.search_build(self.repo, self.sl_dir, self.config, embed=embed)
        (self.repo / "docs/design.md").write_text(
            "# Design\n\nA finalization makes certification below it obsolete.\n"
        )
        subprocess.run(["git", "commit", "-qam", "edit"], cwd=self.repo, check=True)
        replace, calls = os.replace, []

        def failing(source, target):
            calls.append(target)
            if len(calls) == 2:
                raise OSError("injected write failure")
            return replace(source, target)

        os.replace = failing
        try:
            with self.assertRaises(OSError):
                sl.search_build(self.repo, self.sl_dir, self.config, embed=embed)
        finally:
            os.replace = replace
        self.assert_vectors_match_texts()
        sl.search_build(self.repo, self.sl_dir, self.config, embed=embed)
        self.assert_vectors_match_texts()

    MANIFEST = {"chunks": 1, "dim": 0, "model": None}

    def test_overlapping_publications_take_turns(self):
        # Two refreshes at once, say a campaign's and a manual one: without a lock, the
        # first one's cleanup deleted the generation the second had just made current.
        sl.search_publish(self.sl_dir, [{"text": "initial"}], [], self.MANIFEST)
        switched, release, b_done, errors = threading.Event(), threading.Event(), threading.Event(), []
        replace = os.replace

        def pausing(source, target):
            replace(source, target)
            if threading.current_thread().name == "a" and pathlib.Path(target).name == "manifest.json":
                switched.set()
                release.wait(10)

        def publish(text, done=None):
            try:
                sl.search_publish(self.sl_dir, [{"text": text}], [], self.MANIFEST)
            except Exception as error:  # reported by the assertion below
                errors.append(error)
            if done is not None:
                done.set()

        os.replace = pausing
        try:
            first = threading.Thread(target=publish, args=("generation A",), name="a")
            first.start()
            self.assertTrue(switched.wait(10))
            second = threading.Thread(target=publish, args=("generation B", b_done), name="b")
            second.start()
            self.assertFalse(b_done.wait(0.5), "a second publication must wait for the first")
            release.set()
            first.join(10)
            second.join(10)
        finally:
            release.set()
            os.replace = replace
        self.assertEqual(errors, [])
        manifest, chunks, _ = sl.search_load(self.sl_dir)
        self.assertIsNotNone(manifest, "the current generation must exist")
        self.assertEqual(chunks[0]["text"], "generation B")

    def test_a_query_keeps_its_generation_while_an_update_waits(self):
        # A refresh used to delete the generation a query had selected and not yet read.
        sl.search_publish(self.sl_dir, [{"text": "generation A"}], [], self.MANIFEST)
        read, b_done, errors, threads = sl.search_manifest, threading.Event(), [], []

        def publish():
            try:
                sl.search_publish(self.sl_dir, [{"text": "generation B"}], [], self.MANIFEST)
            except Exception as error:  # reported by the assertion below
                errors.append(error)
            b_done.set()

        def selecting(sl_dir):
            selected = read(sl_dir)
            if not threads:
                threads.append(threading.Thread(target=publish))
                threads[0].start()
                self.assertFalse(b_done.wait(0.5), "an update must wait for a query reading")
            return selected

        sl.search_manifest = selecting
        try:
            manifest, chunks, _ = sl.search_load(self.sl_dir)
        finally:
            sl.search_manifest = read
            for thread in threads:
                thread.join(10)
        self.assertEqual(errors, [])
        self.assertIsNotNone(manifest)
        self.assertEqual(chunks[0]["text"], "generation A")
        self.assertEqual(sl.search_load(self.sl_dir)[1][0]["text"], "generation B")

    def test_no_index_is_an_error_that_names_the_command(self):
        with self.assertRaises(sl.Abort) as caught:
            self.search("anything")
        self.assertIn("just search-index", str(caught.exception))


class SimplexProfile(unittest.TestCase):
    """The simplex profile derives a variant from every simplex target, as marshal and
    qmdb do, so every runner that runs a real engine under a Byzantine identity must
    publish it; and a target whose entry point names another scheme is refused."""

    REPO = HERE.parents[1]

    def test_the_sources_are_every_simplex_target(self):
        directory = self.REPO / "consensus/fuzz/simplex/fuzz_targets"
        expected = sorted(
            path.stem for path in directory.glob("simplex_*.rs")
            if not path.stem.endswith("_statelens")
        )
        self.assertGreater(len(expected), 3)
        self.assertEqual(sl.profile_sources(self.REPO, "simplex"), expected)

    def test_materialize_guards_every_runner_with_a_byzantine_engine(self):
        edits = sl.materialize_edits(self.REPO, self.REPO / sl.SL, "simplex")
        published = {
            "consensus/fuzz/core/src/lib.rs": "set_compromised(compromised.iter().copied())",
            "consensus/fuzz/simplex/src/byzzfuzz/runner.rs": "set_compromised([BYZANTINE_IDX])",
            "consensus/fuzz/simplex/src/chaos/twins.rs": "set_compromised([byz])",
            "consensus/fuzz/simplex/src/lib.rs": "set_compromised(0..config.faults as usize)",
            "consensus/fuzz/simplex/src/mallory/runner.rs": "set_compromised([mv.idx()])",
        }
        for relative, call in published.items():
            self.assertEqual(edits.modify[relative].count(call), 1, relative)
            self.assertIn(relative, sl.EDITED_PATHS, "clean must restore it")
        self.assertEqual(len(edits.targets), len(sl.profile_sources(self.REPO, "simplex")))
        for target in edits.targets:
            text = edits.create[f"consensus/fuzz/simplex/fuzz_targets/{target}.rs"]
            self.assertEqual(text.count("commonware_consensus::simplex::statelens::reset();"), 1)

    def test_every_fuzz_entry_point_is_checked_for_cert_mock(self):
        repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, repo, True)
        core = repo / sl.CORE_SIMPLEX
        core.parent.mkdir(parents=True)
        core.write_text(
            "impl Simplex for Mock {\n    type Scheme = cert_mock::Scheme<X>;\n}\n"
            "impl Simplex for Real {\n    type Scheme = ed25519::Scheme;\n}\n"
        )
        targets = repo / sl.profile_fuzz_dir("simplex")
        targets.mkdir(parents=True)
        (targets / "simplex_a.rs").write_text("fuzz_twins_audit::<Mock, TwinsMutator>(input);\n")
        (targets / "simplex_b.rs").write_text("fuzz_twins_audit::<Real, TwinsMutator>(input);\n")
        sl.check_simplex_cert_mock(repo, ["simplex_a"])
        with self.assertRaises(sl.Abort) as caught:
            sl.check_simplex_cert_mock(repo, ["simplex_b"])
        self.assertIn("Real does not use the cert_mock certificate scheme", str(caught.exception))


class QmdbProfile(unittest.TestCase):
    """The qmdb profile instruments storage, not consensus: its own crate, runtime
    path, anchors, fuzz package and tests, with every target derived the same way."""

    REPO = HERE.parents[1]

    def test_the_sources_are_the_qmdb_targets_of_the_storage_package(self):
        directory = self.REPO / "storage/fuzz/fuzz_targets"
        expected = sorted(
            path.stem for path in directory.glob("qmdb_*.rs")
            if not path.stem.endswith("_statelens")
        )
        self.assertTrue(expected)
        self.assertEqual(sl.profile_sources(self.REPO, "qmdb"), expected)

    def test_materialize_edits_storage_and_no_consensus_file(self):
        edits = sl.materialize_edits(self.REPO, self.REPO / sl.SL, "qmdb")
        self.assertEqual(
            sorted(edits.modify),
            [
                "runtime/src/deterministic.rs",
                "storage/Cargo.toml",
                "storage/fuzz/Cargo.toml",
                "storage/src/qmdb/mod.rs",
            ],
        )
        self.assertIn("pub mod statelens;", edits.modify["storage/src/qmdb/mod.rs"])
        self.assertIn("sancov.workspace = true", edits.modify["storage/Cargo.toml"])
        runtime = edits.create[sl.QMDB_RS]
        self.assertIn("crate::qmdb::statelens::sl_probe!", runtime)
        self.assertNotIn("simplex::", runtime, "the module path must be renamed")
        self.assertNotIn(sl.RUNTIME_CONSENSUS_ONLY, runtime, "consensus tests must be left out")
        self.assertTrue(runtime.endswith("}\n"))
        self.assertEqual(len(edits.create), 1 + len(edits.targets))
        manifest = edits.modify["storage/fuzz/Cargo.toml"]
        for target in edits.targets:
            text = edits.create[f"storage/fuzz/fuzz_targets/{target}.rs"]
            self.assertEqual(text.count("commonware_storage::qmdb::statelens::reset();"), 1)
            self.assertEqual(
                text.count("commonware_storage::qmdb::statelens::clear_compromised();"), 1
            )
            self.assertIn(f'name = "{target}"', manifest)

    def test_the_consensus_profiles_copy_the_template_unchanged(self):
        template = (self.REPO / sl.SL / "runtime/statelens.rs").read_text()
        self.assertEqual(template.count(sl.RUNTIME_CONSENSUS_ONLY), 1)
        for profile in ("simplex", "marshal"):
            self.assertEqual(sl.runtime_text(self.REPO, profile), template)

    def test_the_gate_runs_the_qmdb_tests_of_storage(self):
        command = sl.gate_test_command("stable", "qmdb")
        self.assertEqual(command[command.index("-p") + 1], "commonware-storage")
        self.assertEqual(command[-1], "test(/^qmdb::/)")
        campaign = sl.Campaign.__new__(sl.Campaign)
        campaign.profile, campaign.test_toolchain = sl.PROFILES["qmdb"], "stable"
        self.assertEqual(
            campaign.check_command(),
            ["cargo", "+stable", "check", "-p", "commonware-storage", "--lib", "--tests"],
        )

    def test_the_handover_runs_through_this_subproject(self):
        campaign = sl.Campaign.__new__(sl.Campaign)
        campaign.repo = pathlib.Path("/repo")
        campaign.profile = sl.PROFILES["qmdb"]
        campaign.fuzz_toolchain = "nightly-x"
        campaign.targets = ["qmdb_verify_proof_statelens"]
        rows = dict(campaign.handover())
        self.assertEqual(
            rows["run"],
            "cd /repo/statelens && NIGHTLY_VERSION=nightly-x just run "
            "qmdb_verify_proof_statelens -- -rss_limit_mb=4000 -print_final_stats=1",
        )
        self.assertEqual(
            rows["replay"],
            "cd /repo/statelens && NIGHTLY_VERSION=nightly-x just run "
            "qmdb_verify_proof_statelens "
            "/repo/storage/fuzz/artifacts/qmdb_verify_proof_statelens/<crash file>",
        )

    def test_each_profile_renders_its_own_runtime_into_the_prompts(self):
        sl_dir = self.REPO / sl.SL
        for profile, runtime, module, package in (
            ("simplex", sl.STATELENS_RS, "crate::simplex::statelens", "consensus/fuzz/simplex"),
            ("qmdb", sl.QMDB_RS, "crate::qmdb::statelens", "storage/fuzz"),
        ):
            campaign = sl.Campaign.__new__(sl.Campaign)
            campaign.base, campaign.test_toolchain = "0" * 40, "stable"
            campaign.profile = sl.PROFILES[profile]
            registry = sl.PROFILES[profile]["registries"][-1]
            values = dict(
                campaign.common_values(),
                INVARIANT_IDS="INV-0001",
                INVARIANTS="(none)",
                REGISTRY=registry,
                SUBSYSTEM_RULES=sl.subsystem_prompt(sl_dir, registry, "instrument"),
            )
            for task in ("instrument-invariants.md", "instrument-audit.md"):
                text = sl.compose(sl_dir, "instrument.md", task, values)
                self.assertIn(f"Read `{runtime}` first", text)
                self.assertIn(f"## Runtime API (`{module}`)", text)
                self.assertIn(f"`{package}`", text)
                self.assertNotIn("{{", text)
            if profile == "qmdb":
                self.assertNotIn("simplex::statelens", text)

    def test_extract_reads_the_qmdb_context(self):
        values = sl.extract_values(
            self.REPO, self.REPO / sl.SL, "comment", "qmdb", ["storage/src/qmdb/mod.rs"]
        )
        self.assertEqual(values["SOURCE_ROOT"], "storage/src/qmdb")
        self.assertIn("System: `database`", values["CONTEXT"])
        prompt = sl.compose(self.REPO / sl.SL, "analyst.md", "analyst-comment.md", values)
        self.assertNotIn("{{", prompt)
        self.assertIn("`storage/src/qmdb`", prompt)


class VariantDerivation(unittest.TestCase):
    """Every profile derives a variant by putting a reset and a clear around the body of
    `fuzz_target!`, whatever the indent, the parameter or the form of the target."""

    RUNTIME = "commonware_x::m::statelens"

    def derive(self, text):
        lines, _anchors = sl.variant_text("t.rs", text.split("\n"), self.RUNTIME)
        return "\n".join(lines)

    def test_an_indented_block_keeps_its_indent(self):
        self.assertEqual(
            self.derive("mod m {\n    fuzz_target!(|input: In| {\n        go(input);\n    });\n}\n"),
            "mod m {\n    fuzz_target!(|input: In| {\n"
            "        commonware_x::m::statelens::reset();\n"
            "        go(input);\n"
            "        commonware_x::m::statelens::clear_compromised();\n"
            "    });\n}\n",
        )

    def test_a_top_level_block_over_bytes(self):
        self.assertEqual(
            self.derive("fuzz_target!(|data: &[u8]| {\n    go(data);\n});\n"),
            "fuzz_target!(|data: &[u8]| {\n"
            "    commonware_x::m::statelens::reset();\n"
            "    go(data);\n"
            "    commonware_x::m::statelens::clear_compromised();\n"
            "});\n",
        )

    def test_the_body_ends_at_the_closing_line_of_its_own_indent(self):
        derived = self.derive(
            "fuzz_target!(|input: In| {\n    run(|c| {\n        go(c);\n    });\n});\n"
        )
        self.assertTrue(
            derived.endswith(
                "    });\n    commonware_x::m::statelens::clear_compromised();\n});\n"
            ),
            derived,
        )

    def test_a_one_line_target_becomes_a_block(self):
        self.assertEqual(
            self.derive("use x;\nfuzz_target!(|input: In| fuzz(input));\n"),
            "use x;\nfuzz_target!(|input: In| {\n"
            "    commonware_x::m::statelens::reset();\n"
            "    fuzz(input);\n"
            "    commonware_x::m::statelens::clear_compromised();\n"
            "});\n",
        )

    def test_a_file_without_exactly_one_target_is_refused(self):
        for text in (
            "fn main() {}\n",
            "fuzz_target!(|a: A| {\n});\nfuzz_target!(|b: B| {\n});\n",
            "fuzz_target!(|input: In| {\n    go(input);\n",
        ):
            with self.assertRaises(sl.Abort):
                self.derive(text)


class IndexCrate(unittest.TestCase):
    """SCIP paths are relative to the indexed crate, which a qmdb campaign makes storage,
    so the loader must take the crate from the index rather than assume consensus."""

    def load(self, raw):
        directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        path = directory / "i.scip"
        path.write_bytes(raw)
        _occurrences, definitions, _names = sl.index_load(path)
        return definitions["sym"][0]

    def test_the_crate_comes_from_the_project_root(self):
        metadata = length_delimited(1, length_delimited(3, b"file:///work/repo/storage"))
        index = scip_index("src/qmdb/mod.rs", "sym", [0, 3, 4], [0, 0, 0, 9])
        self.assertEqual(self.load(metadata + index), "storage/src/qmdb/mod.rs")

    def test_an_index_without_metadata_is_of_consensus(self):
        index = scip_index("src/x.rs", "sym", [0, 3, 4], [0, 0, 0, 9])
        self.assertEqual(self.load(index), "consensus/src/x.rs")

    def test_each_profile_indexes_its_own_crate(self):
        self.assertEqual(
            {name: settings["crate"] for name, settings in sl.PROFILES.items()},
            {"simplex": "consensus", "marshal": "consensus", "qmdb": "storage"},
        )



class IndexRebuildProfile(unittest.TestCase):
    """A query that finds edited sources says to run `just code-index`, which builds
    with no subsystem, so an omitted one must keep the crate in use rather than switch a
    qmdb checkout's index back to consensus."""

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / sl.SL
        (self.sl_dir / "extract").mkdir(parents=True)
        (self.sl_dir / "campaign").mkdir()
        saved = {name: getattr(sl, name) for name in ("repo_root", "say", "index_build")}
        sl.repo_root = lambda: self.repo
        sl.say = lambda *_args, **_kw: None
        self.built = []
        sl.index_build = lambda _repo, _sl_dir, subsystem: self.built.append(subsystem) or True
        self.addCleanup(lambda: [setattr(sl, k, v) for k, v in saved.items()])

    def index(self, crate):
        root = length_delimited(3, f"file:///work/repo/{crate}".encode())
        sl.index_path(self.sl_dir).write_bytes(
            length_delimited(1, root) + scip_index("src/f.rs", "sym", [0, 3, 4], [0, 0, 0, 9])
        )

    def build(self, *flags, campaign=None):
        if campaign:
            (self.sl_dir / "campaign" / "meta.json").write_text(json.dumps({"profile": campaign}))
        self.assertEqual(sl.main(["code", "build", *flags]), 0)
        return self.built[-1]

    def test_the_advice_after_an_edit_keeps_a_qmdb_campaign_on_storage(self):
        source = self.repo / "storage/src/f.rs"
        source.parent.mkdir(parents=True)
        source.write_text("fn f() {}\n")
        self.index("storage")
        sl.snapshot_write(self.repo, self.sl_dir, ["storage/src/f.rs"])
        source.write_text("fn f() { let _edited = 1; }\n")
        self.assertIn("Rebuild with `just code-index`", sl.Rebaser(self.repo, self.sl_dir).report())
        self.assertEqual(self.build(campaign="qmdb"), "qmdb")

    def test_without_a_campaign_the_index_keeps_its_crate(self):
        self.index("storage")
        self.assertEqual(self.build(), "qmdb")
        self.index("consensus")
        self.assertEqual(self.build(), "simplex")

    def test_without_a_campaign_or_an_index_the_default_is_simplex(self):
        self.assertEqual(self.build(), "simplex")

    def test_an_explicit_subsystem_wins(self):
        self.index("storage")
        self.assertEqual(self.build("--subsystem", "marshal", campaign="qmdb"), "marshal")

class TargetSelection(unittest.TestCase):
    """`just fuzz <profile> --fuzz-targets GLOB` runs the targets a pattern names."""

    TARGETS = [
        "simplex_cert_mock_statelens",
        "simplex_cert_mock_twins_campaign_statelens",
        "simplex_cert_mock_twins_mutator_statelens",
    ]

    def test_a_pattern_names_targets_by_variant_or_original_name(self):
        self.assertEqual(sl.select_targets(self.TARGETS, ["simplex_cert_mock_twins_*"]), self.TARGETS[1:])
        self.assertEqual(sl.select_targets(self.TARGETS, ["simplex_cert_mock"]), self.TARGETS[:1])
        self.assertEqual(sl.select_targets(self.TARGETS, ["*_mutator_statelens"]), self.TARGETS[2:])

    def test_several_patterns_add_up_and_none_keeps_every_target(self):
        both = sl.select_targets(self.TARGETS, ["*_campaign", "simplex_cert_mock"])
        self.assertEqual(both, [self.TARGETS[0], self.TARGETS[1]])
        self.assertEqual(sl.select_targets(self.TARGETS, []), self.TARGETS)
        self.assertEqual(sl.select_targets(self.TARGETS, ["nothing_*"]), [])


class ScaffoldSelection(unittest.TestCase):
    """The one selection `synthesize` and `targets --state-reaching` share (SPEC section
    18.6.2): cards from both trees of the profile, bases without `fuzz_mutator!`, card
    and base patterns, one pair (card, base) per selected base of each card, and the
    per-pair skip rule."""

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / sl.SL
        self.targets = self.repo / sl.profile_fuzz_dir("simplex")
        self.targets.mkdir(parents=True)
        for stem, text in (
            ("simplex_a", "fuzz_target!(|input: FuzzInput| fuzz(input));\n"),
            ("simplex_b", "fuzz_target!(|input: FuzzInput| fuzz(input));\n"),
            ("simplex_mallory", "fuzz_mutator!(|data, size, max, seed| 0);\n"),
            ("simplex_a_statelens", "variant\n"),
        ):
            (self.targets / f"{stem}.rs").write_text(text)
        for relative in ("target-states/simplex/TS-0001.md",
                         "target-states.local/simplex/TS-0002.md",
                         "target-states/marshal/TS-0003.md"):
            path = self.sl_dir / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(card_text(id=path.stem))
        saved = sl.repo_root
        sl.repo_root = lambda: self.repo
        self.addCleanup(setattr, sl, "repo_root", saved)

    def select(self, *patterns, profile="simplex"):
        return sl.select_scaffolds(self.repo, self.sl_dir, profile, list(patterns))

    def picked(self, *patterns):
        return [(pair.card, pair.base) for pair in self.select(*patterns).pairs]

    def refused(self, *patterns, profile="simplex"):
        with self.assertRaises(sl.Abort) as caught:
            self.select(*patterns, profile=profile)
        self.assertEqual(caught.exception.code, 1, str(caught.exception))
        return str(caught.exception)

    def scaffold(self, name=None, report=None):
        if name:
            (self.targets / f"{name}.rs").write_text("thin target\n")
        if report:
            path = self.sl_dir / "campaign/reach" / f"{report}.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("report\n")

    def listing(self, *patterns, profile="simplex"):
        argv = ["targets", "--profile", profile, "--state-reaching"]
        for pattern in patterns:
            argv += ["--match", pattern]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = sl.main(argv)
        return code, out.getvalue().split()

    ALL = [("TS-0001", "simplex_a"), ("TS-0001", "simplex_b"),
           ("TS-0002", "simplex_a"), ("TS-0002", "simplex_b")]

    def test_cards_come_from_both_trees_and_no_base_has_a_mutator(self):
        selection = self.select()
        self.assertEqual(self.picked(), self.ALL)
        self.assertEqual((selection.tracked, selection.local), (1, 1))
        self.assertEqual([pair.skip for pair in selection.pairs], [None] * 4)

    def test_a_card_yields_one_pair_per_selected_base(self):
        # In card order, then in the bases' file name order; each pair carries its key,
        # module and scaffold name, and no scaffold until its thin target exists.
        pairs = self.select().pairs
        self.assertEqual([pair.key for pair in pairs],
                         ["TS-0001_simplex_a", "TS-0001_simplex_b",
                          "TS-0002_simplex_a", "TS-0002_simplex_b"])
        self.assertEqual([pair.module for pair in pairs],
                         ["ts0001_simplex_a", "ts0001_simplex_b",
                          "ts0002_simplex_a", "ts0002_simplex_b"])
        self.assertEqual([pair.name for pair in pairs],
                         ["simplex_a_ts0001_statelens", "simplex_b_ts0001_statelens",
                          "simplex_a_ts0002_statelens", "simplex_b_ts0002_statelens"])
        self.assertEqual([pair.scaffold for pair in pairs], [None] * 4)
        self.assertEqual([pair.path.stem for pair in pairs],
                         ["TS-0001", "TS-0001", "TS-0002", "TS-0002"])
        # A base pattern narrows each card to one pair; a scaffold's name to one pair.
        self.assertEqual(self.picked("simplex_b"), [("TS-0001", "simplex_b"),
                                                    ("TS-0002", "simplex_b")])
        self.assertEqual(self.picked("simplex_b_ts0002"), [("TS-0002", "simplex_b")])
        self.scaffold("simplex_b_ts0002_statelens")
        pair = self.select("simplex_b_ts0002").pairs[0]
        self.assertEqual((pair.scaffold, pair.skip), ("simplex_b_ts0002_statelens", None))

    def test_a_card_pattern_names_cards_and_any_other_names_bases(self):
        self.assertEqual(self.picked("TS-0002"), self.ALL[2:])
        self.assertEqual(self.picked("TS-000*"), self.ALL)
        self.assertEqual(self.picked("simplex_b"), [("TS-0001", "simplex_b"),
                                                    ("TS-0002", "simplex_b")])
        self.assertEqual(self.picked("simplex_a_statelens", "TS-0001"),
                         [("TS-0001", "simplex_a")])
        self.assertEqual(self.picked("simplex_*"), self.ALL)
        # A scaffold's name selects its card on its base, and no other card.
        self.assertEqual(self.picked("simplex_b_ts0002"), [("TS-0002", "simplex_b")])
        self.assertEqual(self.picked("*_ts0001_statelens"), self.ALL[:2])

    def test_nothing_selected_is_a_usage_error(self):
        self.assertIn("TS-0001, TS-0002", self.refused("nothing*"))
        self.refused("TS-0009")
        self.refused("simplex_mallory")
        self.refused("simplex_b_ts0001", "TS-0002")
        self.assertIn("refuses the qmdb profile", self.refused(profile="qmdb"))
        self.assertIn("no candidate base", self.refused(profile="marshal"))
        shutil.rmtree(self.sl_dir / "target-states/simplex")
        shutil.rmtree(self.sl_dir / "target-states.local/simplex")
        self.assertIn("no target-state cards", self.refused())

    def test_a_pair_with_a_report_is_skipped_until_redo(self):
        # The skip rule is per pair: TS-0001 on simplex_b has a report, TS-0001 on
        # simplex_a has none, and TS-0002 on simplex_a has a scaffold but no report yet.
        self.scaffold("simplex_b_ts0001_statelens", report="TS-0001_simplex_b")
        self.scaffold("simplex_a_ts0002_statelens")
        on_a, on_b, second, _ = self.select().pairs
        self.assertEqual((on_a.scaffold, on_a.skip), (None, None))
        self.assertEqual(on_b.scaffold, "simplex_b_ts0001_statelens")
        self.assertEqual(on_b.skip, "TS-0001 on simplex_b was synthesized as "
                                    "simplex_b_ts0001_statelens; use --redo")
        self.assertEqual((second.scaffold, second.skip), ("simplex_a_ts0002_statelens", None))
        self.assertEqual([pair.skip for pair in self.select("simplex_a").pairs], [None, None])
        (self.targets / "simplex_a_ts0002_statelens.rs").unlink()
        self.scaffold(report="TS-0002_simplex_a")
        second = self.select().pairs[2]
        self.assertEqual((second.scaffold, second.skip),
                         (None, "TS-0002 on simplex_a was synthesized without a scaffold; "
                                "use --redo"))
        # A report keyed by the card alone is no pair's.
        self.scaffold(report="TS-0002")
        self.assertEqual(self.select("simplex_b", "TS-0002").pairs[0].skip, None)

    def test_targets_lists_the_scaffolds_of_the_selection_only(self):
        self.assertEqual(self.listing(), (0, []), "no scaffold yet is not an error")
        self.scaffold("simplex_b_ts0001_statelens", report="TS-0001_simplex_b")
        self.scaffold("simplex_a_ts0002_statelens", report="TS-0002_simplex_a")
        self.assertEqual(self.listing(),
                         (0, ["simplex_b_ts0001_statelens", "simplex_a_ts0002_statelens"]))
        self.assertEqual(self.listing("simplex_a"), (0, ["simplex_a_ts0002_statelens"]))
        self.assertEqual(self.listing("TS-0001"), (0, ["simplex_b_ts0001_statelens"]))
        # One card on two bases lists both scaffolds, in the bases' order.
        self.scaffold("simplex_a_ts0001_statelens", report="TS-0001_simplex_a")
        self.assertEqual(self.listing("TS-0001"),
                         (0, ["simplex_a_ts0001_statelens", "simplex_b_ts0001_statelens"]))
        self.assertEqual(self.listing("nothing*")[0], 1)
        self.assertEqual(self.listing(profile="qmdb")[0], 1)
        self.assertNotIn("simplex_a_ts0002_statelens", sl.profile_targets(self.repo, "simplex"),
                         "a scaffold is not a variant, so plain `targets` never lists it")

    def test_a_selected_card_with_a_lint_problem_fails_the_listing(self):
        (self.sl_dir / "target-states.local/simplex/TS-0002.md").write_text(
            card_text(id="TS-0002").replace("E3. harness", "E5. harness"))
        code, output = self.listing()
        self.assertEqual(code, 1)
        self.assertIn("(rule", " ".join(output))
        self.assertEqual(self.listing("TS-0001"), (0, []), "only the selected cards are linted")

    def test_each_consensus_profile_declares_target_states_after_one_anchor(self):
        repo = HERE.parents[1]
        self.assertIsNone(sl.PROFILES["qmdb"]["scaffold"])
        for profile in ("simplex", "marshal"):
            relative, anchor, position, text = sl.PROFILES[profile]["scaffold"]
            self.assertEqual(relative, f"{sl.PROFILES[profile]['package']}/src/lib.rs")
            self.assertEqual(position, "after")
            self.assertEqual(text.split("\n")[-1], "pub mod target_states;")
            lines = (repo / relative).read_text().split("\n")
            sl.find_anchor(relative, lines, anchor)
            self.assertNotIn("pub mod target_states;", lines)
            self.assertEqual(sl.target_states_dir(profile),
                             f"{sl.PROFILES[profile]['package']}/src/target_states")


class SynthesisManifest(unittest.TestCase):
    """A scaffold's `[[bin]]` block is its base's, renamed as a variant's is (Appendix B.2)."""

    MANIFEST = (
        '[[bin]]\nname = "simplex_a"\npath = "fuzz_targets/simplex_a.rs"\ntest = false\n'
        'doc = false\nbench = false\nrequired-features = ["twins"]\n'
    )

    def test_the_block_is_the_bases_with_the_scaffolds_name_and_path(self):
        blocks = sl.bin_blocks(self.MANIFEST)
        block = sl.variant_bin_block(blocks, "simplex_a", "Cargo.toml",
                                     name="simplex_a_ts0003_statelens")
        self.assertEqual(
            block,
            '\n[[bin]]\nname = "simplex_a_ts0003_statelens"\n'
            'path = "fuzz_targets/simplex_a_ts0003_statelens.rs"\ntest = false\n'
            'doc = false\nbench = false\nrequired-features = ["twins"]\n',
        )
        self.assertIn('name = "simplex_a_statelens"', sl.variant_bin_block(blocks, "simplex_a"))


class CampaignRefusals(unittest.TestCase):
    """A campaign refuses a checkout a synthesis wrote to (SPEC section 7.1), and
    instrumentation that calls the read side of the runtime module (section 7.5)."""

    def run_git(self, *args):
        return subprocess.run(
            ("git",) + args, cwd=self.repo, capture_output=True, text=True, check=True
        ).stdout

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        for relative, text in (
            ("consensus/src/simplex/voter.rs",
             "fn f(x: X) {\n    let seen = x.seen();\n    statelens::mark_down();\n}\n"),
            ("consensus/src/simplex/old.rs", "fn g() {\n    statelens::mark();\n}\n"),
            ("consensus/fuzz/simplex/src/lib.rs", "pub mod state_cov;\n"),
        ):
            (self.repo / relative).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / relative).write_text(text)
        for args in (("init", "-q", "."), ("config", "user.email", "t@example.invalid"),
                     ("config", "user.name", "t"), ("config", "commit.gpgsign", "false"),
                     ("add", "-A"), ("commit", "-qm", "base")):
            self.run_git(*args)
        saved = {name: getattr(sl, name) for name in ("say", "check_agent_cli")}
        self.addCleanup(lambda: [setattr(sl, k, v) for k, v in saved.items()])
        self.said = []
        sl.say = self.said.append
        sl.check_agent_cli = lambda _agent: None
        self.campaign = sl.Campaign.__new__(sl.Campaign)
        self.campaign.repo, self.campaign.agent = self.repo, "claude"
        self.campaign.profile_name, self.campaign.profile = "simplex", sl.PROFILES["simplex"]
        self.campaign.base = self.run_git("rev-parse", "HEAD").strip()
        # Materialize: the runtime module, which defines the read side.
        runtime = self.repo / sl.STATELENS_RS
        runtime.write_text("pub fn seen() {}\npub fn tick() -> u64 { statelens::tick() }\n")
        self.campaign.baseline = self.campaign.snapshot()

    def edit(self, relative, text):
        (self.repo / relative).parent.mkdir(parents=True, exist_ok=True)
        (self.repo / relative).write_text(text)

    def scope(self):
        with self.assertRaises(sl.Abort) as caught:
            self.campaign.check_scope()
        self.assertEqual(caught.exception.code, 2)
        return str(caught.exception)

    def test_a_checkout_a_synthesis_wrote_to_is_refused(self):
        tools = sl.shutil.which
        self.addCleanup(setattr, sl.shutil, "which", tools)
        sl.shutil.which = lambda tool: f"/usr/bin/{tool}"
        (self.repo / sl.STATELENS_RS).unlink()
        self.campaign.check_preconditions()
        for relative in ("consensus/fuzz/simplex/src/target_states/mod.rs",
                         "consensus/fuzz/marshal/src/target_states/ts0001.rs",
                         "consensus/fuzz/marshal/fuzz_targets/marshal_x_ts0001_statelens.rs"):
            self.edit(relative, "x\n")
            with self.assertRaises(sl.Abort) as caught:
                self.campaign.check_preconditions()
            self.assertEqual(caught.exception.code, 2)
            self.assertIn("earlier campaign or synthesis", str(caught.exception))
            shutil.rmtree(self.repo / "consensus/fuzz/simplex/src/target_states", True)
            shutil.rmtree(self.repo / "consensus/fuzz/marshal", True)

    def test_instrumentation_that_calls_the_read_side_stops_the_campaign(self):
        self.edit("consensus/src/simplex/voter.rs",
                  "fn f(x: X) {\n    let seen = x.seen();\n    statelens::mark_down();\n"
                  "    crate::simplex::statelens::seen(\"l\", None, 0, |_| true);\n}\n")
        self.assertEqual(self.scope(), "instrumentation calls the read side: "
                                       "consensus/src/simplex/voter.rs (seen)")
        self.edit("consensus/src/simplex/voter.rs", "fn f() {}\n")
        self.edit("consensus/src/simplex/new.rs",
                  "use crate::simplex::statelens::{self, tick, Seen};\n"
                  "use crate::simplex::statelens as rt;\nfn h() { rt::observations(0); }\n")
        self.assertIn("consensus/src/simplex/new.rs (observations, tick)", self.scope())
        # `self as` inside an import group is an alias as well.
        self.edit("consensus/src/simplex/new.rs",
                  "use crate::simplex::{statelens::{self as lens, Seen}, types};\n"
                  "fn h() { let _ = lens::sites(\"l\"); }\n")
        self.assertIn("consensus/src/simplex/new.rs (sites)", self.scope())

    def test_instrumentation_may_call_the_rest_of_the_runtime(self):
        self.edit("consensus/src/simplex/voter.rs",
                  "fn f(x: X) {\n    let seen = x.seen();\n    statelens::mark_down();\n"
                  "    sl_probe!(\"voter.f\", 1, 2);\n"
                  "    crate::simplex::statelens::with_ghost(|g| g.n += 1);\n"
                  "    // statelens::seen is for scaffolds\n"
                  "    let _ = \"statelens::tick\";\n    let _ = seen(x);\n}\n")
        self.edit("consensus/src/simplex/old.rs", "fn g() {\n    statelens::mark();\n}\n// moved\n")
        self.edit(sl.STATELENS_RS, "pub fn seen() {}\npub fn watch() { statelens::watch() }\n")
        self.campaign.check_scope()


class InvariantSelection(unittest.TestCase):
    """`--invariants` narrows what a campaign binds (SPEC section 7.1): the filter keeps
    the registries' order, reaches local and false invariants, refuses an id it cannot
    place with the list of those it can, and the campaign's record says what was chosen
    out of how many."""

    FILES = (
        "invariants/simplex/INV-0001.md",
        "invariants/simplex/INV-0003.md",
        "invariants.local/simplex/INV-0002.md",
        "false-invariants/simplex/FALSE-0001.md",
    )
    PAIRS = [
        ("simplex", pathlib.Path(f"invariants/simplex/{name}.md"))
        for name in ("INV-0001", "INV-0002", "INV-0003", "FALSE-0001")
    ]
    LISTING = "available: simplex/INV-0001, simplex/INV-0002, simplex/INV-0003, simplex/FALSE-0001"

    def run_git(self, *args):
        return subprocess.run(
            ("git",) + args, cwd=self.repo, capture_output=True, text=True, check=True
        ).stdout

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / sl.SL
        for relative in self.FILES:
            (self.sl_dir / relative).parent.mkdir(parents=True, exist_ok=True)
            (self.sl_dir / relative).write_text("x\n")
        for args in (("init", "-q", "."), ("config", "user.email", "t@example.invalid"),
                     ("config", "user.name", "t"), ("config", "commit.gpgsign", "false"),
                     ("add", "-A"), ("commit", "-qm", "base")):
            self.run_git(*args)
        names = ("say", "lint_paths", "registry_files", "kb_roots", "search_build",
                 "search_ready", "profile_targets", "agent_model", "agent_effort")
        saved = {name: getattr(sl, name) for name in names}
        self.addCleanup(lambda: [setattr(sl, k, v) for k, v in saved.items()])
        self.said = []
        sl.say = self.said.append
        sl.lint_paths = lambda *_a, **_kw: 0
        sl.registry_files = lambda *_a, **_kw: []

        def no_kb(*_a):
            raise sl.Abort(2, "no STATELENS_KB")

        sl.kb_roots = no_kb
        sl.search_build = lambda *_a, **_kw: None
        sl.search_ready = lambda *_a: False
        sl.profile_targets = lambda *_a: ["simplex_a_statelens"]
        sl.agent_model = sl.agent_effort = lambda *_a: "x"
        self.addCleanup(os.environ.pop, "STATELENS_FALSE_INVARIANTS", None)

    def select(self, registries, *selection, pairs=None):
        profile = "simplex" if registries == ("simplex",) else "marshal"
        chosen = sl.select_invariants(profile, registries, pairs or self.PAIRS, list(selection))
        return [f"{registry}/{path.stem}" for registry, path in chosen]

    def refused(self, registries, *selection, pairs=None):
        with self.assertRaises(sl.Abort) as caught:
            self.select(registries, *selection, pairs=pairs)
        self.assertEqual(caught.exception.code, 2)
        return str(caught.exception)

    def campaign(self, *selection):
        campaign = sl.Campaign.__new__(sl.Campaign)
        campaign.repo, campaign.sl_dir, campaign.config = self.repo, self.sl_dir, {}
        campaign.agent, campaign.profile_name = "claude", "simplex"
        campaign.profile = sl.PROFILES["simplex"]
        campaign.test_toolchain = campaign.fuzz_toolchain = "stable"
        campaign.dir = self.sl_dir / "campaign"
        campaign.initialized = False
        campaign.selection = list(selection) or None
        return campaign

    def setup(self, *selection):
        """meta.json, plan.md and the console line of a campaign's setup."""
        campaign = self.campaign(*selection)
        campaign.setup()
        meta = json.loads((campaign.dir / "meta.json").read_text())
        plan = (campaign.dir / "plan.md").read_text()
        lines = [line for line in self.said if line.startswith("campaign: profile ")]
        return meta, plan, lines[-1]

    def test_the_filter_keeps_the_binding_order_and_reaches_local_and_false_ids(self):
        self.assertEqual(
            self.select(("simplex",), "simplex/FALSE-0001,simplex/INV-0001", "INV-0003"),
            ["simplex/INV-0001", "simplex/INV-0003", "simplex/FALSE-0001"],
        )
        # Through a campaign: INV-0002 is local, and FALSE-0001 is collected with the flag.
        meta, plan, line = self.setup("INV-0003, INV-0002")
        self.assertEqual(meta["invariants"], ["INV-0002", "INV-0003"])
        self.assertEqual(meta["invariants_available"], 3)
        self.assertIn("- Invariants: 2 (simplex: INV-0002, INV-0003)\n", plan)
        self.assertNotIn("INV-0001", plan)
        self.assertIn(", 2 of 3 invariant(s) bound (simplex: INV-0002, INV-0003), ", line)
        os.environ["STATELENS_FALSE_INVARIANTS"] = "1"
        meta, _plan, line = self.setup("simplex/FALSE-0001")
        self.assertEqual((meta["invariants"], meta["invariants_available"]), (["FALSE-0001"], 4))
        self.assertIn(", 1 of 4 invariant(s) bound (simplex: FALSE-0001), ", line)

    def test_without_a_selection_the_record_only_gains_the_count(self):
        meta, plan, line = self.setup()
        self.assertEqual(meta["invariants"], ["INV-0001", "INV-0002", "INV-0003"])
        self.assertEqual(meta["invariants_available"], 3)
        self.assertIn("- Invariants: 3 (simplex: INV-0001, INV-0002, INV-0003)\n", plan)
        self.assertIn(", 3 invariant(s), ", line)
        self.assertNotIn(" of ", line)

    def test_a_bare_id_needs_a_profile_of_one_registry(self):
        self.assertEqual(self.select(("simplex",), "INV-0002"), ["simplex/INV-0002"])
        pairs = self.PAIRS + [("marshal", pathlib.Path("invariants/marshal/INV-0024.md"))]
        self.assertEqual(
            self.select(("simplex", "marshal"), "marshal/INV-0024,simplex/INV-0002", pairs=pairs),
            ["simplex/INV-0002", "marshal/INV-0024"],
        )
        message = self.refused(("simplex", "marshal"), "simplex/INV-0001,INV-0024", pairs=pairs)
        self.assertIn("INV-0024 is a bare id", message)
        self.assertIn("binds 2 registries (simplex, marshal)", message)
        self.assertIn("write <registry>/INV-0024", message)

    def test_an_unknown_id_a_wrong_registry_and_an_empty_list_are_refused(self):
        message = self.refused(("simplex",), "INV-0001,simplex/INV-0009")
        self.assertIn("no invariant file provides simplex/INV-0009; " + self.LISTING, message)
        message = self.refused(("simplex",), "qmdb/INV-0001")
        self.assertIn("does not bind the qmdb registry; " + self.LISTING, message)
        message = self.refused(("simplex",), "", " , ")
        self.assertIn("selects no invariant; " + self.LISTING, message)
        # A false invariant is selectable only when the campaign collects it.
        message = self.refused(("simplex",), "simplex/FALSE-0001", pairs=self.PAIRS[:3])
        self.assertIn("no invariant file provides simplex/FALSE-0001; available: simplex/INV-0001, "
                      "simplex/INV-0002, simplex/INV-0003", message)
        # Through a campaign, the refusal is a setup failure.
        with self.assertRaises(sl.Abort) as caught:
            self.campaign("INV-0009").setup()
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("available: simplex/INV-0001, simplex/INV-0002, simplex/INV-0003",
                      str(caught.exception))


class JustfileProfiles(unittest.TestCase):
    """`just fuzz` and `just run` decide by name which profile and which package a
    target belongs to, so each profile must be known to both recipes."""

    TEXT = (HERE.parent / "justfile").read_text()

    def recipe(self, name):
        return self.TEXT.split(f"\n{name} ", 1)[1].split("\n# ", 1)[0]

    def test_fuzz_accepts_every_profile_and_its_targets(self):
        fuzz = self.recipe("fuzz")
        self.assertIn("|".join(sl.PROFILES) + ")", fuzz)
        for profile in sl.PROFILES:
            self.assertRegex(fuzz, rf"\n\s+{profile}_\*\)\s+profile={profile};")

    def test_run_reaches_every_package(self):
        run = self.recipe("run")
        for profile, settings in sl.PROFILES.items():
            package = settings["package"]
            if package.startswith("consensus/fuzz/"):
                # consensus/fuzz's own `run` finds the package that defines a target.
                self.assertIn("cd ../consensus/fuzz && just run", run)
                continue
            self.assertIn(f"{profile}_*)", run)
            self.assertIn(f"--fuzz-dir {package}", run)

    def test_synthesize_has_its_recipe(self):
        self.assertIn('synthesize *args:\n    python3 scripts/statelens.py synthesize "$@"', self.TEXT)
        # One scaffold per pair (card, base), as the script says.
        usage = self.TEXT.split("\nsynthesize ", 1)[0].rsplit("\n# ", 1)[1]
        self.assertIn("a scaffold per target-state card and base", usage)
        self.assertIn("one scaffold per card and base", self.recipe("fuzz"))

    def test_campaign_and_fuzz_take_an_invariant_list(self):
        for name in ("campaign", "fuzz"):
            usage = self.TEXT.split(f"\n{name} ", 1)[0].rsplit("\n# ", 1)[1]
            self.assertIn("[--invariants LIST]...", usage, name)
        self.assertIn(
            'just campaign --profile "$profile" ${invariants[@]+"${invariants[@]}"}',
            self.recipe("fuzz"),
        )


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class FuzzRecipe(unittest.TestCase):
    """`just fuzz` parses its flags in bash, where a mistake fails quietly: an unknown flag
    used to reach libFuzzer. The recipe's body runs here as `just` runs it, under bash with
    the arguments as positional parameters, with `python3`, `just` and `tmux` stubbed to
    record their calls (SPEC sections 5.3 and 18.9)."""

    STUBS = {
        # `targets` prints $BEFORE until a synthesis ran and $AFTER from then on.
        "python3": (
            'echo "python3 $*" >> "$FUZZ_LOG"\n'
            'case "$2" in\n'
            '  synthesize) touch "$FUZZ_STATE/synthesized"; exit "${SYNTHESIZE_CODE:-0}" ;;\n'
            '  targets) if [ -e "$FUZZ_STATE/synthesized" ]; then printf "%s" "$AFTER"; '
            'else printf "%s" "$BEFORE"; fi; exit "${TARGETS_CODE:-0}" ;;\n'
            "esac\n"
        ),
        "just": 'echo "just $*" >> "$FUZZ_LOG"\n[ "$1" != campaign ] || exit "${CAMPAIGN_CODE:-0}"\n',
        "tmux": 'echo "tmux $*" >> "$FUZZ_LOG"\n[ "$1" != has-session ] || exit 1\n',
    }
    SCAFFOLDS = ["simplex_cert_mock_chaos_ts0003_statelens", "simplex_cert_mock_ts0004_statelens"]
    # TS-0004 on every `simplex_cert_mock_twins_*` base: one scaffold per pair (card, base).
    TWINS = [
        f"simplex_cert_mock_twins_{runner}{suffix}_ts0004_statelens"
        for runner in ("campaign", "mutator")
        for suffix in ("", "_audit", "_hb", "_state_cov")
    ]

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        recipe = JustfileProfiles.TEXT.split("\nfuzz ", 1)[1].split("\n# ", 1)[0]
        body = textwrap.dedent(recipe.split("\n", 1)[1])
        self.assertTrue(body.startswith("#!/usr/bin/env bash\n"))
        self.assertNotIn("{{", body)
        self.script = self.root / "fuzz.sh"
        self.script.write_text(body)
        stubs = self.root / "bin"
        stubs.mkdir()
        for name, text in self.STUBS.items():
            (stubs / name).write_text("#!/bin/sh\n" + text)
            (stubs / name).chmod(0o755)
        self.path = f"{stubs}{os.pathsep}{os.environ['PATH']}"

    def fuzz(self, *args, before="", after="", **codes):
        log = self.root / "calls.log"
        for stale in (log, self.root / "synthesized"):
            stale.unlink(missing_ok=True)
        env ={key: value for key, value in os.environ.items() if key not in ("TMUX", "STATELENS_JOBS")}
        env.update(PATH=self.path, FUZZ_LOG=str(log), FUZZ_STATE=str(self.root), BEFORE=before, AFTER=after)
        env.update({f"{key.upper()}_CODE": str(code) for key, code in codes.items()})
        result = subprocess.run(
            ["bash", str(self.script), *args],
            cwd=self.root, env=env, capture_output=True, text=True, timeout=60,
        )
        calls = log.read_text().splitlines() if log.exists() else []
        return result.returncode, calls, result.stderr

    @staticmethod
    def lines(names):
        return "".join(f"{name}\n" for name in names)

    def test_the_state_reaching_command_runs_one_window_per_scaffold(self):
        code, calls, err = self.fuzz(
            "simplex", "--parallel", "--tmux", "--state-reaching",
            "--state-targets", "TS-000*", "--fuzz-targets", "simplex_cert_*",
            after=self.lines(self.SCAFFOLDS),
        )
        self.assertEqual(code, 0, err)
        matches = "--match TS-000* --match simplex_cert_*"
        listing = f"python3 scripts/statelens.py targets --profile simplex --state-reaching {matches}"
        self.assertEqual(
            calls[:5],
            [
                listing,
                "just campaign --profile simplex",
                f"python3 scripts/statelens.py synthesize --profile simplex {matches}",
                listing,
                "tmux has-session -t statelens-simplex-reach",
            ],
        )
        windows = calls[5:7]
        self.assertTrue(windows[0].startswith(
            "tmux new-session -d -s statelens-simplex-reach -n simplex_cert_mock_chaos_ts0003 "))
        self.assertTrue(windows[1].startswith(
            "tmux new-window -t statelens-simplex-reach -n simplex_cert_mock_ts0004 "))
        for window, name in zip(windows, self.SCAFFOLDS):
            # No libFuzzer argument follows the scaffold.
            self.assertIn(f"just run '{name}' ;", window)
        self.assertEqual(calls[7:], ["tmux attach -t statelens-simplex-reach"])
        # The recipe counts scaffolds, not targets, once a synthesis ran.
        self.assertIn("just fuzz: 2 scaffold(s), one tmux window each", err)
        # One card on the eight twins bases: eight scaffolds, eight windows named after them.
        code, calls, err = self.fuzz(
            "simplex", "--tmux", "--state-reaching", "--state-targets", "TS-0004",
            "--fuzz-targets", "simplex_cert_mock_twins_*", after=self.lines(self.TWINS),
        )
        self.assertEqual(code, 0, err)
        self.assertIn("just fuzz: 8 scaffold(s), one tmux window each", err)
        windows = [call for call in calls if call.startswith("tmux new-")]
        self.assertEqual(len(windows), 8)
        self.assertTrue(windows[0].startswith("tmux new-session -d -s statelens-simplex-reach "
                                              "-n simplex_cert_mock_twins_campaign_ts0004 "))
        for window, name in zip(windows[1:], self.TWINS[1:]):
            self.assertTrue(window.startswith(
                f"tmux new-window -t statelens-simplex-reach -n {name[:-len('_statelens')]} "),
                window)
            self.assertIn(f"just run '{name}' ;", window)

    def test_an_unknown_double_dash_flag_is_refused(self):
        # --targets was the one pattern flag before --fuzz-targets and --state-targets
        # split its rule; it is unknown now, not an alias.
        for args in (["simplex", "--bogus"], ["simplex", "--tmux", "--state-reachin"],
                     ["simplex_cert_mock_statelens", "--skip-campaign", "--fork=8"],
                     ["simplex", "--state-reaching", "--targets=TS-0003"]):
            code, calls, err = self.fuzz(*args)
            self.assertEqual((code, calls), (1, []), args)
            self.assertIn(f"just fuzz: unknown flag {args[-1]}", err)
        code, calls, err = self.fuzz("simplex", "--targets", "simplex_cert_*")
        self.assertEqual((code, calls), (1, []))
        self.assertIn("just fuzz: unknown flag --targets", err)
        # libFuzzer's one-dash flags, and anything after `--`, still pass through.
        for args, tail in ((["-runs=1"], "-runs=1"), (["--", "--x", "-runs=1"], "--x -runs=1")):
            code, calls, err = self.fuzz("simplex_cert_mock_statelens", "--skip-campaign", *args)
            self.assertEqual(code, 0, err)
            self.assertEqual(calls, [f"just run simplex_cert_mock_statelens -- {tail}"])

    def test_state_reaching_needs_simplex_or_marshal(self):
        for target in ("qmdb", "simplex_cert_mock", "marshal_e2e_standard_app_cert_mock_twins_ts0001_statelens"):
            code, calls, err = self.fuzz(target, "--state-reaching", "--skip-campaign")
            self.assertEqual((code, calls), (1, []), target)
            self.assertIn("simplex or marshal", err)

    def test_a_bad_selection_fails_before_the_campaign(self):
        code, calls, err = self.fuzz(
            "simplex", "--state-reaching", "--fuzz-targets", "nothing*",
            before="statelens: error: no simplex card and candidate base match nothing*\n", targets=1,
        )
        self.assertEqual(code, 1)
        self.assertEqual(calls, [
            "python3 scripts/statelens.py targets --profile simplex --state-reaching --match nothing*"])
        self.assertIn("no simplex card and candidate base match nothing*", err)

    def test_a_failed_campaign_or_synthesis_stops_the_recipe(self):
        code, calls, _ = self.fuzz("simplex", "--state-reaching", campaign=4)
        self.assertEqual((code, len(calls)), (4, 2))
        code, calls, _ = self.fuzz("simplex", "--state-reaching", synthesize=3,
                                   after=self.lines(self.SCAFFOLDS))
        self.assertEqual(code, 3)
        self.assertTrue(calls[-1].startswith("python3 scripts/statelens.py synthesize "))

    def test_no_scaffold_after_synthesis_fails(self):
        code, calls, err = self.fuzz("simplex", "--state-reaching", "--skip-campaign", "--state-targets=TS-0003")
        self.assertEqual(code, 1)
        self.assertEqual(calls, [
            "python3 scripts/statelens.py targets --profile simplex --state-reaching --match TS-0003",
            "python3 scripts/statelens.py synthesize --profile simplex --match TS-0003",
            "python3 scripts/statelens.py targets --profile simplex --state-reaching --match TS-0003",
        ])
        self.assertIn("campaign/reach/", err)

    def test_the_sequential_and_parallel_forms_run_the_scaffolds(self):
        code, calls, err = self.fuzz("simplex", "--state-reaching", "--skip-campaign",
                                     after=self.lines(self.SCAFFOLDS))
        self.assertEqual(code, 0, err)
        self.assertEqual(calls[-2:], [f"just run {name}" for name in self.SCAFFOLDS])
        self.assertIn("no -max_total_time, so scaffold 1 of 2 runs until it", err)
        self.assertIn("just fuzz: 2 simplex scaffold(s), in turn", err)
        # A bound on the number of runs ends each target too; -runs=-1 is no bound.
        for bound, warned in (("-runs=5", False), ("-max_total_time=5", False), ("-runs=-1", True)):
            code, _calls, err = self.fuzz("simplex", "--state-reaching", "--skip-campaign",
                                          "--", bound, after=self.lines(self.SCAFFOLDS))
            self.assertEqual(code, 0, err)
            self.assertEqual("no -max_total_time" in err, warned, bound)
        code, calls, err = self.fuzz("simplex", "--state-reaching", "--skip-campaign", "--parallel",
                                     "--", "-max_total_time=5", after=self.lines(self.SCAFFOLDS))
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(calls[-2:]),
                         [f"just run {name} -- -max_total_time=5" for name in self.SCAFFOLDS])
        for name in self.SCAFFOLDS:
            self.assertTrue((self.root / "campaign" / "logs" / f"{name}.run.log").is_file())
        self.assertRegex(err, r"just fuzz: 2 simplex scaffold\(s\), [12] at a time, \d+ core\(s\)")
        self.assertIn("output goes to campaign/logs/<scaffold>.run.log", err)

    def test_an_invariant_list_goes_to_the_campaign(self):
        # A selected campaign, then one card's scaffold on each matching base, bounded: the
        # eight `simplex_cert_mock_twins_*` bases yield eight scaffolds, each named after its
        # base, run one after another.
        code, calls, err = self.fuzz(
            "simplex", "--state-reaching", "--state-targets", "TS-0004",
            "--fuzz-targets", "simplex_cert_mock_twins_*",
            "--invariants", "simplex/INV-0001,simplex/INV-0002", "--", "-max_total_time=3600",
            after=self.lines(self.TWINS),
        )
        self.assertEqual(code, 0, err)
        matches = "--match TS-0004 --match simplex_cert_mock_twins_*"
        listing = f"python3 scripts/statelens.py targets --profile simplex --state-reaching {matches}"
        self.assertEqual(calls, [
            listing,
            "just campaign --profile simplex --invariants simplex/INV-0001,simplex/INV-0002",
            f"python3 scripts/statelens.py synthesize --profile simplex {matches}",
            listing,
        ] + [f"just run {name} -- -max_total_time=3600" for name in self.TWINS])
        self.assertIn("just fuzz: 8 simplex scaffold(s), in turn", err)
        # The `=` form, repeated, and the variants of a profile, which stay "target(s)".
        variant = "simplex_cert_mock_twins_campaign_statelens"
        code, calls, err = self.fuzz("simplex", "--invariants=INV-0001", "--invariants", "INV-0002",
                                     "--", "-runs=1", before=self.lines([variant]))
        self.assertEqual(code, 0, err)
        self.assertEqual(calls[1:], [
            "just campaign --profile simplex --invariants INV-0001 --invariants INV-0002",
            f"just run {variant} -- -runs=1",
        ])
        self.assertIn("just fuzz: 1 simplex target(s), in turn", err)

    def test_an_invariant_list_needs_a_campaign_and_a_profile(self):
        code, calls, err = self.fuzz("simplex", "--skip-campaign", "--invariants", "INV-0001")
        self.assertEqual((code, calls), (1, []))
        self.assertIn("--invariants selects what a campaign binds; drop --skip-campaign", err)
        code, calls, err = self.fuzz("simplex_cert_mock_statelens", "--invariants=INV-0001")
        self.assertEqual((code, calls), (1, []))
        self.assertIn("--invariants selects what a campaign binds; name simplex, marshal or qmdb", err)
        code, calls, err = self.fuzz("simplex", "--invariants")
        self.assertEqual((code, calls), (1, []))
        self.assertIn("--invariants needs a list", err)

    def test_without_state_reaching_nothing_changes(self):
        variant = "simplex_cert_mock_twins_campaign_statelens"
        code, calls, err = self.fuzz("simplex", "--tmux", "--fuzz-targets", "simplex_cert_mock_twins_*",
                                     "--", "-fork=4", before=self.lines([variant]))
        self.assertEqual(code, 0, err)
        self.assertEqual(calls[:3], [
            "python3 scripts/statelens.py targets --profile simplex --match simplex_cert_mock_twins_*",
            "just campaign --profile simplex",
            "tmux has-session -t statelens-simplex",
        ])
        self.assertIn(f"just run '{variant}' -- -fork=4;", calls[3])
        self.assertNotIn("synthesize", "\n".join(calls))
        # The `=` form narrows the same way; a pattern naming nothing fails at once.
        code, calls, err = self.fuzz("simplex", "--fuzz-targets=nothing*", before="statelens: error: "
                                     "no simplex target matches nothing*\n", targets=1)
        self.assertEqual(code, 1)
        self.assertEqual(calls, ["python3 scripts/statelens.py targets --profile simplex --match nothing*"])
        self.assertIn("no simplex target matches nothing*", err)

    def test_the_pattern_flags_split_the_match_rule(self):
        # Both flags, in both forms, go to the listing and the synthesis as --match,
        # in the order given.
        code, calls, err = self.fuzz(
            "simplex", "--state-reaching", "--skip-campaign", "--state-targets=TS-0003",
            "--state-targets", "TS-0004", "--fuzz-targets=simplex_cert_*", "--fuzz-targets", "*_chaos",
            after=self.lines(self.SCAFFOLDS),
        )
        self.assertEqual(code, 0, err)
        matches = "--match TS-0003 --match TS-0004 --match simplex_cert_* --match *_chaos"
        self.assertEqual(calls[:2], [
            f"python3 scripts/statelens.py targets --profile simplex --state-reaching {matches}",
            f"python3 scripts/statelens.py synthesize --profile simplex {matches}",
        ])
        # A card is only a scaffold's; a pattern of the other flag's form is refused.
        for args, message in (
            (["simplex", "--state-targets", "TS-0003"], "--state-targets needs --state-reaching"),
            (["simplex", "--state-reaching", "--fuzz-targets", "TS-0003"],
             "--fuzz-targets names fuzz targets; a card is --state-targets TS-0003"),
            (["simplex", "--state-reaching", "--fuzz-targets=TS-*"],
             "--fuzz-targets names fuzz targets; a card is --state-targets TS-*"),
            (["simplex", "--state-reaching", "--state-targets", "simplex_cert_*"],
             "--state-targets names cards (TS-NNNN); a fuzz target is --fuzz-targets simplex_cert_*"),
            (["simplex", "--state-reaching", "--state-targets=*"],
             "--state-targets names cards (TS-NNNN); a fuzz target is --fuzz-targets *"),
            (["simplex_cert_mock_statelens", "--fuzz-targets", "simplex_cert_*"],
             "--fuzz-targets narrows a profile; name simplex, marshal or qmdb"),
            (["simplex", "--fuzz-targets"], "--fuzz-targets needs a pattern"),
            (["simplex", "--state-reaching", "--state-targets"], "--state-targets needs a pattern"),
        ):
            code, calls, err = self.fuzz(*args)
            self.assertEqual((code, calls), (1, []), args)
            self.assertIn(f"just fuzz: {message}", err, args)


class QmdbRegistry(unittest.TestCase):
    """The qmdb registry takes its own scope values and no other registry's."""

    def lint(self, scope):
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        path = root / "invariants" / "qmdb" / "INV-0001.md"
        path.parent.mkdir(parents=True)
        path.write_text(
            "---\nid: INV-0001\ntitle: A title\nsource_kind: human\n"
            f"source_ref: storage/src/qmdb/mod.rs\nscope: [{scope}]\n---\n\n"
            "## Statement\nThe database shall keep its root.\n\n## Rationale\nIt must.\n\n"
            "## Evidence\nHuman-authored.\n"
        )
        return sl.lint_file(path)

    def test_qmdb_scopes_are_accepted(self):
        self.assertEqual(self.lint("database, current"), [])

    def test_another_registry_scope_is_refused(self):
        self.assertEqual(
            self.lint("voter"),
            [
                "scope must be a list of the qmdb registry's values: "
                + ", ".join(sl.SCOPES["qmdb"])
            ],
        )

    def test_every_registry_has_a_false_invariant(self):
        root = HERE.parent / "false-invariants"
        for registry in sl.SUBSYSTEMS:
            self.assertTrue(list((root / registry).glob("FALSE-*.md")), registry)


REACH_CARD = """---
id: {id}
title: t
source_kind: text
source_ref: text: t
scope: [replica]
---

## Statement
While R waits, the replica holds a state.

## History
{history}

## Knobs
None.
"""

# TS-0004's History, shortened: harness, R, harness, R.
TS4 = """E1. harness: holds back every message sent to R in view v.
    Check (R, v): every message sent to R in view v is held back.
E2. R: signs a nullify vote for v.
    Check (R as E1, v as E1): R signed a nullify vote for v.
E3. harness: delivers to R a notarization of d for v.
    Check (R as E1, v as E1, d): R holds a notarization of d for v.
E4. R: dispatches certification of d for v.
    Holds (R as E1, v as E1, d as E3): R's certification of d for v is outstanding."""

# Lines are the helper's after `[statelens-reach] <card> `; a `!` line is printed as is.
REACHED = (
    "phase prefix",
    "E1/4 held construction bind=R=1@E1,v=2@E1 action=hold_back[R=1,v=2] seq=1 read=1",
    "entry votes[R=1,v=2]=nullify seq=5",
    "E2/4 held exact bind=R=1@E1,v=2@E1 exact=votes[R=1,v=2]=nullify seq=5 read=6",
    "E3/4 held construction bind=R=1@E1,v=2@E1,d=ab@E3 action=deliver[R=1,v=2,d=ab] seq=7 read=7",
    "entry certify[R=1,v=2,d=ab]=pending seq=9",
    "E4/4 held exact bind=R=1@E1,v=2@E1,d=ab@E3 exact=certify[R=1,v=2,d=ab]=pending seq=9 "
    "read=11",
    "handoff holds mark=12 next=1:13",
    "phase continuation",
    "reach 4/4 control=0",
    "done",
)
CONTROL = REACHED[:4] + (
    "E3/4 withheld",
    "E4/4 missed not held at handoff",
    "handoff lost mark=9 next=-",
    "phase continuation",
    "reach 2/4 control=1",
    "done",
)
# A control whose En witness names d in its key but leaves it out of bind=.
UNBOUND = (
    "phase prefix",
    "E1/4 held construction bind=R=1@E1,v=2@E1 action=hold_back[R=1,v=2] seq=1 read=1",
    "entry votes[R=1,v=2]=nullify seq=2",
    "E2/4 held exact bind=R=1@E1,v=2@E1 exact=votes[R=1,v=2]=nullify seq=2 read=3",
    "E3/4 withheld",
    "entry certify[R=1,v=2,d=ab]=pending seq=4",
    "E4/4 held exact bind=R=1@E1,v=2@E1 exact=certify[R=1,v=2,d=ab]=pending seq=4 read=6",
    "handoff holds mark=7 next=-",
    "phase continuation",
    "reach 3/4 control=1",
    "done",
)
MODULE = """//! TS-0004 on simplex_cert_mock
//! Shape: B
//! Knobs: raw_bytes[0..1]: [0] v
//! Stages: E1 construction hold_back; E2 exact votes; E3 construction deliver;
//!     E4 exact certify
//! Control: withholds E3
//! Injections: none
//! Missing: none

use crate::target_states::{Stages, Witness};
"""

# Only R acts after E1: intrinsic witnesses, which bind R and leave the views unbound.
INTRINSIC = """E1. harness: starts R.
    Check (R): R runs.
E2. R: signs a nullify vote for some view.
    Check (R as E1, v): R signed a nullify vote for some view v.
E3. R: queues certification of some view.
    Holds (R as E1, w): R queued certification of some view w."""
INTRINSIC_RUN = (
    "phase prefix",
    "E1/3 held construction bind=R=1@E1 action=start[R=1] seq=1 read=1",
    "E2/3 held intrinsic bind=R=1@E1,v=?@E2 "
    "obs=1:4:1:voter_nullify@consensus/src/simplex/actors/voter/round.rs:10:5:1:0 read=6",
    "E3/3 held intrinsic bind=R=1@E1,w=?@E3 "
    "obs=1:8:1:voter_certify@consensus/src/simplex/actors/voter/round.rs:20:5:2:1 read=10",
    "handoff holds mark=11 next=1:12",
    "phase continuation",
    "reach 3/3 control=0",
    "done",
)
INTRINSIC_CONTROL = (
    "phase prefix",
    "E1/3 withheld",
    "E2/3 missed no nullify vote by the deadline",
    "E3/3 missed not held at handoff",
    "handoff lost mark=4 next=-",
    "phase continuation",
    "reach 0/3 control=1",
    "done",
)

# A restart between a vote and the state its journal restores (TS-0003, shortened).
RESTART = """E1. harness: runs R.
    Check (R): R runs.
E2. R: signs a nullify vote for v.
    Check (R as E1, v): R signed a nullify vote for v.
E3. harness: restarts R.
    Check (R as E1, i): R runs again, in the incarnation i this restart began.
E4. R: resumes in view v.
    Holds (R as E1, v as E2, i as E3): in incarnation i, R holds its nullify vote for v."""
RESTART_RUN = (
    "phase prefix",
    "E1/4 held construction bind=R=1@E1 action=start[R=1] seq=1 read=1",
    "entry votes[R=1,v=2]=nullify seq=3",
    "E2/4 held exact bind=R=1@E1,v=2@E2 exact=votes[R=1,v=2]=nullify seq=3 read=4",
    "restart 1 seq=5 run=1",
    "entry running[R=1]=yes seq=7",
    "E3/4 held exact bind=R=1@E1,i=inc5@E3 exact=running[R=1]=yes seq=7 read=8",
    "entry votes[R=1,v=2]=restored seq=10",
    "E4/4 held exact bind=R=1@E1,v=2@E2,i=inc5@E3 exact=votes[R=1,v=2]=restored seq=10 "
    "read=12",
    "handoff holds mark=13 next=1:14",
    "phase continuation",
    "reach 4/4 control=0",
    "done",
)

# A replay of the runtime and helper, captured from a throwaway scaffold of TS-9999: E1
# fills the trace to TRACE_CAP with R's certification queued, R's state then changes past
# the cap, so the trace drops that observation, and the handoff reads the latest
# observation the trace kept, which is stale.
TRUNCATION = """E1. harness: starts R.
    Check (R): R runs.
E2. R: queues certification of some view.
    Holds (R as E1, w): R queued certification of some view w."""
TRUNCATION_MODULE = """//! TS-9999 on simplex_cert_mock
//! Shape: B
//! Knobs: none
//! Stages: E1 construction start; E2 intrinsic voter_certify
//! Control: withholds E1
//! Injections: none
//! Missing: none
"""
TRUNCATION_RUN = """\
[statelens-reach] TS-9999 phase prefix
[statelens-reach] TS-9999 E1/2 held construction bind=R=1@E1 action=start[R=1] seq=1 read=1
[statelens-reach] TS-9999 truncated seq=1048578
[statelens-reach] TS-9999 E2/2 unverifiable (trace truncated)
[statelens-reach] TS-9999 handoff lost mark=1048581 next=-
[statelens-reach] TS-9999 phase continuation
[statelens-reach] TS-9999 reach 1/2 control=0
[statelens-reach] TS-9999 done
"""
TRUNCATION_CONTROL = """\
[statelens-reach] TS-9999 phase prefix
[statelens-reach] TS-9999 E1/2 withheld
[statelens-reach] TS-9999 E2/2 missed not held at handoff
[statelens-reach] TS-9999 handoff lost mark=2 next=-
[statelens-reach] TS-9999 phase continuation
[statelens-reach] TS-9999 reach 0/2 control=1
[statelens-reach] TS-9999 done
"""
# The same replay with the helper's downgrade switched off.
TRUNCATION_STALE = """\
[statelens-reach] TS-9999 phase prefix
[statelens-reach] TS-9999 E1/2 held construction bind=R=1@E1 action=start[R=1] seq=1 read=1
[statelens-reach] TS-9999 truncated seq=1048578
[statelens-reach] TS-9999 E2/2 held intrinsic bind=R=1@E1,w=?@E2 \
obs=1:1048577:1:voter_certify@consensus/fuzz/simplex/src/target_states/ts9999.rs:18:56:1:1 \
read=1048580
[statelens-reach] TS-9999 handoff holds mark=1048581 next=-
[statelens-reach] TS-9999 phase continuation
[statelens-reach] TS-9999 reach 2/2 control=0
[statelens-reach] TS-9999 done
"""

# The default hook's report of a panic at `location`, which aborts under libFuzzer.
def panicked(location, message):
    return (
        f"!thread '<unnamed>' panicked at {location}:",
        f"!{message}",
        "!==4242== ERROR: libFuzzer: deadly signal",
    )


def reach_card(history=TS4, id="TS-0004"):
    return sl.card_history(REACH_CARD.format(id=id, history=history))


def replay_output(lines, card="TS-0004"):
    """A replay's output: libFuzzer's lines around the helper's."""
    text = ["INFO: Running with entropic power schedule (0xFF, 100).", "Running: reach/empty"]
    for line in lines:
        text.append(line[1:] if line.startswith("!") else f"[statelens-reach] {card} {line}")
    return "\n".join(text) + "\n"


def swap(lines, old, new):
    """`lines` with the line starting with `old` replaced by `new`, or dropped for None."""
    found = [line for line in lines if line.startswith(old)]
    assert len(found) == 1, (old, found)
    return tuple(new if line == found[0] else line for line in lines if new or line != found[0])


class ReachCheck(unittest.TestCase):
    """The reach check of SPEC section 18.8 over synthetic replays (AC-26): the line
    grammar, every witness rejection rule, positions, incarnations, the handoff recheck,
    the control, the verdicts, crash attribution and the feedback."""

    def verdict(self, canonical=REACHED, control=CONTROL, module=MODULE, card=None,
                codes=(0, 0), **kw):
        card = card or reach_card()
        runs = [
            None if lines is None else (code, replay_output(lines, card.id))
            for lines, code in zip((canonical, control), codes)
        ]
        return sl.reach_verdict(card, module, runs[0], runs[1], **kw)

    def stage(self, result, k):
        return result["replays"]["canonical"]["stages"][k]

    def rejected(self, rule, canonical, k, **kw):
        result = self.verdict(canonical, **kw)
        self.assertEqual(self.stage(result, k)["detail"], f"witness rejected: {rule}")
        self.assertEqual(result["verdict"], "UNVERIFIED", result["reasons"])
        self.assertIn(f"E{k} unverifiable witness rejected: {rule}", result["reasons"])
        return result

    def test_the_patterns_are_the_spec_s(self):
        spec = (HERE.parent / "docs/SPEC.md").read_text()
        for pattern in (sl.REACH_LINE, sl.REACH_HELD, sl.REACH_EXACT, sl.REACH_OBS,
                        sl.REACH_ACTION):
            self.assertIn(pattern.pattern, spec)

    def test_every_line_form_parses(self):
        text = replay_output(REACHED + (
            "restart 1,2 seq=14 run=2",
            "trace 1:3:-:voter_timeout@consensus/src/simplex/a.rs:5:5:1:0",
            "truncated seq=1048578",
            "panic consensus/src/simplex/a.rs:1:2 boom at once",
            "E9/4 bogus",
        )) + "[statelens-reach] TS-0003 done\n"
        lines = sl.reach_lines(text, "TS-0004")
        self.assertEqual(
            [line["type"] for line in lines],
            ["phase", "stage", "entry", "stage", "stage", "entry", "stage", "handoff", "phase",
             "reach", "done", "restart", "trace", "truncated", "panic", "unparsed"],
        )
        self.assertEqual(lines[2]["seq"], 5)
        self.assertEqual(lines[7]["next"], (1, 13))
        self.assertEqual(lines[9]["k"], 4)
        self.assertEqual(lines[11]["replicas"], {"1", "2"})
        self.assertEqual(lines[13]["seq"], 1048578)
        self.assertEqual(lines[14]["message"], "boom at once")

    def test_a_reached_card(self):
        result = self.verdict()
        self.assertEqual(sl.verdict_text(result), "REACHED 4/4", result["reasons"])
        self.assertEqual(result["control"], "ok")
        self.assertIsNone(sl.reach_feedback(result).partition("What to fix")[2] or None)

    def test_an_as_value_that_differs_or_is_unbound(self):
        changed = swap(REACHED, "E2/4", "E2/4 held exact bind=R=3@E1,v=2@E1 "
                       "exact=votes[R=3,v=2]=nullify seq=5 read=6")
        self.rejected("as", swap(changed, "entry votes", "entry votes[R=3,v=2]=nullify seq=5"), 2)
        unbound = swap(REACHED, "E2/4", "E2/4 held exact bind=R=1@E1,v=?@E1 "
                       "exact=votes[R=1]=nullify seq=5 read=6")
        self.rejected("as", swap(unbound, "entry votes", "entry votes[R=1]=nullify seq=5"), 2)

    def test_an_entity_missing_from_bind(self):
        self.rejected("bind", swap(REACHED, "E2/4", "E2/4 held exact bind=R=1@E1 "
                                   "exact=votes[R=1,v=2]=nullify seq=5 read=6"), 2)

    def test_an_exact_key_without_an_entity_of_the_line(self):
        self.rejected("evidence", swap(REACHED, "E2/4", "E2/4 held exact bind=R=1@E1,v=2@E1 "
                                       "exact=votes[slot=4]=nullify seq=- read=6"), 2)
        # A key that names a bound entity with another value contradicts the record.
        self.rejected("evidence", swap(REACHED, "E3/4", "E3/4 held construction "
                                       "bind=R=1@E1,v=2@E1,d=ab@E3 action=deliver[R=1,v=3,d=ab] "
                                       "seq=7 read=7"), 3)

    def test_a_stamp_no_entry_line_names(self):
        self.rejected("evidence", swap(REACHED, "E2/4", "E2/4 held exact bind=R=1@E1,v=2@E1 "
                                       "exact=votes[R=1,v=2]=nullify seq=4 read=6"), 2)
        # The entry must come before the record and match its observable, key and value.
        late = swap(REACHED, "entry votes", None)
        late = late[:4] + ("entry votes[R=1,v=2]=nullify seq=5",) + late[4:]
        self.rejected("evidence", late, 2)
        other = swap(REACHED, "entry votes", "entry votes[R=1,v=2]=notarize seq=5")
        self.rejected("evidence", other, 2)

    def test_positions_against_the_history_s_order(self):
        self.rejected("order", swap(REACHED, "E3/4", "E3/4 held construction "
                                    "bind=R=1@E1,v=2@E1,d=ab@E3 action=deliver[R=1,v=2,d=ab] "
                                    "seq=3 read=3"), 3)

    def test_two_harness_actions_with_no_probe_between(self):
        card = reach_card("""E1. harness: pins the elector so that B leads v.
    Check (B, v): B leads v.
E2. harness: delivers a nullification of v to R.
    Check (R, v as E1): the nullification of v was delivered to R.
E3. R: enters view v.
    Holds (R as E2, v as E1): R is in view v.""")
        first = "E1/3 held construction bind=B=0@E1,v=2@E1 action=pin[B=0,v=2] seq={} read={}"
        second = "E2/3 held construction bind=R=1@E2,v=2@E1 action=deliver[R=1,v=2] seq={} read={}"
        tail = (
            "entry view[R=1,v=2]=entered seq=4",
            "E3/3 held exact bind=R=1@E2,v=2@E1 exact=view[R=1,v=2]=entered seq=4 read=6",
            "handoff holds mark=7 next=1:8",
            "phase continuation",
            "reach 3/3 control=0",
            "done",
        )
        control = ("E1/3 held construction bind=B=0@E1,v=2@E1 action=pin[B=0,v=2] seq=1 read=1",
                   "E2/3 withheld", "E3/3 missed not held at handoff",
                   "handoff lost mark=4 next=-", "reach 1/3 control=1", "done")
        module = MODULE.replace("withholds E3", "withholds E2")
        ordered = ("phase prefix", first.format(1, 1), second.format(2, 2)) + tail
        result = self.verdict(ordered, control, module, card)
        self.assertEqual(sl.verdict_text(result), "REACHED 3/3", result["reasons"])
        swapped = ("phase prefix", first.format(2, 2), second.format(1, 1)) + tail
        result = self.verdict(swapped, control, module, card)
        self.assertEqual(self.stage(result, 2)["detail"], "witness rejected: order")
        self.assertEqual(result["verdict"], "UNVERIFIED")

    def test_a_foreign_run(self):
        card, module = reach_card(INTRINSIC), MODULE.replace("withholds E3", "withholds E1")
        result = self.verdict(INTRINSIC_RUN, INTRINSIC_CONTROL, module, card)
        self.assertEqual(sl.verdict_text(result), "REACHED 3/3", result["reasons"])
        foreign = swap(INTRINSIC_RUN, "E3/3", INTRINSIC_RUN[3].replace("obs=1:8", "obs=2:8"))
        self.rejected("run", foreign, 3, control=INTRINSIC_CONTROL, module=module, card=card)
        # A restart line between the two observations is a marked boundary.
        marked = foreign[:3] + ("restart 0 seq=6 run=2",) + foreign[3:]
        result = self.verdict(marked, INTRINSIC_CONTROL, module, card)
        self.assertEqual(self.stage(result, 3)["outcome"], "held", result["reasons"])
        self.assertIn("relation across restart", result["annotations"])

    def test_intrinsic_witnesses(self):
        card, module = reach_card(INTRINSIC), MODULE.replace("withholds E3", "withholds E1")
        wrong_me = INTRINSIC_RUN[2].replace(":4:1:", ":4:3:")
        two = INTRINSIC_RUN[2].replace(" read=6", " obs=1:5:1:x@a.rs:1:1:0:0 read=6")
        view = INTRINSIC_RUN[2].replace("v=?@E2", "v=5@E2")
        for line in (wrong_me, two, view):
            self.rejected("intrinsic", swap(INTRINSIC_RUN, "E2/3", line), 2,
                          control=INTRINSIC_CONTROL, module=module, card=card)
        # A site without a replica witnesses none, even for a replica bound to `-`.
        dashed = tuple(line.replace("R=1", "R=-") for line in INTRINSIC_RUN)
        dashed = swap(dashed, "E2/3", dashed[2].replace(":4:1:", ":4:-:"))
        self.rejected("intrinsic", dashed, 2, control=INTRINSIC_CONTROL, module=module, card=card)

    def test_construction_witnesses(self):
        last = ("E4/4 held construction bind=R=1@E1,v=2@E1,d=ab@E3 "
                "action=certify[R=1,v=2,d=ab] seq=10 read=10")
        canonical = swap(swap(REACHED, "E4/4", last), "handoff", "handoff holds mark=11 next=1:12")
        self.rejected("construction", canonical, 4)
        actor = "E2/4 held construction bind=R=1@E1,v=2@E1 action=vote[R=1,v=2] seq=5 read=5"
        self.rejected("construction", swap(REACHED, "E2/4", actor), 2)

    def test_presence_only_on_either_side_of_an_ordered_pair(self):
        later = swap(REACHED, "E4/4", REACHED[6].replace("pending seq=9", "pending seq=-"))
        result = self.verdict(later)
        self.assertEqual(self.stage(result, 4)["detail"], "(no position)")
        self.assertEqual(sl.verdict_text(result), "UNVERIFIED 3/4")
        earlier = swap(REACHED, "E2/4", REACHED[3].replace("nullify seq=5", "nullify seq=-"))
        result = self.verdict(earlier)
        self.assertEqual(self.stage(result, 2)["detail"], "(no position)")
        self.assertEqual(self.stage(result, 3)["outcome"], "held")
        self.assertEqual(result["verdict"], "UNVERIFIED")
        # Stages that `Order:` frees need no position relative to each other.
        card = reach_card("""E1. harness: delivers d to R.
    Check (R, d): R holds d.
E2. R: holds e.
    Holds (R as E1, e): R holds e.
Order: E1 and E2 in either order.""")
        free = (
            "E1/2 held exact bind=R=1@E1,d=x@E1 exact=held[R=1,d=x]=yes seq=- read=1",
            "E2/2 held exact bind=R=1@E1,e=y@E2 exact=held[R=1,e=y]=yes seq=- read=3",
            "handoff holds mark=4 next=-",
            "reach 2/2 control=0",
            "done",
        )
        replay = sl.reach_replay(replay_output(free, "TS-0004"), card)
        self.assertEqual(replay["held"], 2, replay["stages"])
        # An unstamped item beside a stamped one: that entry may come after any other.
        mixed = swap(REACHED, "E2/4", REACHED[3].replace(
            " read=6", " exact=late[R=1,v=2]=yes seq=- read=6"))
        result = self.verdict(mixed)
        self.assertEqual(self.stage(result, 2)["detail"], "(no position)")
        self.assertEqual(result["verdict"], "UNVERIFIED")

    def test_a_relation_across_a_restart(self):
        card = reach_card(RESTART)
        module = MODULE.replace("withholds E3", "withholds E1")
        control = ("E1/4 withheld", "E2/4 missed no vote", "E3/4 missed no restart",
                   "E4/4 missed not held at handoff", "handoff lost mark=3 next=-",
                   "reach 0/4 control=1", "done")
        result = self.verdict(RESTART_RUN, control, module, card)
        self.assertEqual(sl.verdict_text(result), "REACHED 4/4 (relation across restart)",
                         result["reasons"])
        # Two restarts with nothing between them begin two incarnations.
        twice = RESTART_RUN[:5] + ("restart 1 seq=6 run=1",) + RESTART_RUN[5:]
        result = self.verdict(twice, control, module, card)
        self.assertEqual(self.stage(result, 3)["detail"], "witness rejected: incarnation")
        self.assertEqual(self.stage(result, 4)["detail"], "witness rejected: incarnation")
        named = tuple(line.replace("inc5", "inc6") for line in twice)
        result = self.verdict(named, control, module, card)
        self.assertEqual(result["verdict"], "REACHED", result["reasons"])
        # An incarnation no restart began, and a line that names none.
        unknown = tuple(line.replace("inc5", "inc99") for line in RESTART_RUN)
        self.rejected("incarnation", unknown, 3, control=control, module=module, card=card)
        # Without a position, and with no restart line, the incarnation must still exist.
        lone = reach_card("""E1. R: runs.
    Holds (R, i): R runs in the incarnation i.""")
        lines = (
            "phase prefix",
            "E1/1 held exact bind=R=1@E1,i=inc99@E1 exact=state[R=1]=yes seq=- read=2",
            "handoff holds mark=3 next=-",
            "phase continuation",
            "reach 1/1 control=0",
            "done",
        )
        na = MODULE.replace("withholds E3", "n/a")
        self.rejected("incarnation", lines, 1, control=None, module=na, card=lone)
        bare = reach_card(RESTART.replace("(R as E1, i)", "(R as E1)").replace(", i as E3", ""))
        lines = tuple(line.replace(",i=inc5@E3", "") for line in RESTART_RUN)
        self.rejected("incarnation", lines, 3, control=control, module=module, card=bare)
        # An extra item of bind= is no entity of the line, so it names no incarnation.
        extra = tuple(line.replace(",i=inc5@E3", ",zz=inc5@E3") for line in RESTART_RUN)
        self.rejected("incarnation", extra, 3, control=control, module=module, card=bare)

    def test_the_handoff_recheck(self):
        # AC-25: a witness built before the handoff call.
        lost = swap(REACHED, "handoff", "handoff lost mark=14 next=1:15")
        result = self.verdict(lost)
        self.assertEqual(sl.verdict_text(result), "PARTIAL 3/4")
        self.assertEqual(self.stage(result, 4)["outcome"], "missed")
        self.assertIn("handoff lost", self.stage(result, 4)["detail"])
        self.assertFalse(result["replays"]["canonical"]["holds"])
        stale = swap(REACHED, "handoff", "handoff holds mark=13 next=1:14")
        self.assertEqual(sl.verdict_text(self.verdict(stale)), "PARTIAL 3/4")
        between = REACHED[:7] + ("entry certify[R=1,v=2,d=ab]=done seq=12",) + REACHED[7:]
        self.assertEqual(sl.verdict_text(self.verdict(between)), "PARTIAL 3/4")
        missed = swap(swap(REACHED, "E4/4", "E4/4 missed not held at handoff"),
                      "handoff", "handoff lost mark=11 next=-")
        result = self.verdict(missed)
        self.assertEqual(sl.verdict_text(result), "PARTIAL 3/4")
        self.assertIn(sl.FEEDBACK_FIXES["last"], sl.reach_feedback(result))

    def test_a_stage_read_after_the_trace_was_cut(self):
        # The trace dropped its first observation at position 9: E4, read at 11, cannot
        # hold, wherever the line is printed, and neither can the handoff.
        for at in (5, len(REACHED) - 1):
            result = self.verdict(REACHED[:at] + ("truncated seq=9",) + REACHED[at:])
            self.assertEqual(sl.verdict_text(result), "UNVERIFIED 3/4", at)
            self.assertEqual(self.stage(result, 4)["helper"], "held")
            self.assertEqual(self.stage(result, 4)["detail"], "(trace truncated)")
            self.assertIn("E4 unverifiable (trace truncated)", result["reasons"])
            self.assertFalse(result["replays"]["canonical"]["holds"])
            self.assertEqual(result["replays"]["canonical"]["truncated"], 9)
        feedback = sl.reach_feedback(result)
        self.assertIn("[statelens-reach] TS-0004 truncated seq=9", feedback)
        self.assertIn(sl.FEEDBACK_FIXES["unverifiable"], feedback)
        # Every stage read at or after the cut, the earliest a line names.
        cuts = ("truncated seq=13", "truncated seq=6")
        result = self.verdict(REACHED[:2] + cuts + REACHED[2:])
        self.assertEqual(sl.verdict_text(result), "UNVERIFIED 1/4")
        self.assertEqual([self.stage(result, k)["detail"] for k in (2, 3, 4)],
                         ["(trace truncated)"] * 3)
        # A cut at the handoff mark: E4 was read before it, but the handoff cannot hold.
        result = self.verdict(REACHED[:-1] + ("truncated seq=12",) + REACHED[-1:])
        self.assertEqual(sl.verdict_text(result), "UNVERIFIED 3/4")
        self.assertEqual(self.stage(result, 4)["detail"], "(trace truncated)")
        self.assertFalse(result["replays"]["canonical"]["holds"])
        # A cut after the mark changes nothing.
        result = self.verdict(REACHED[:-1] + ("truncated seq=13",) + REACHED[-1:])
        self.assertEqual(sl.verdict_text(result), "REACHED 4/4", result["reasons"])
        self.assertTrue(result["replays"]["canonical"]["holds"])
        self.assertEqual(result["replays"]["canonical"]["truncated"], 13)
        # The helper's own downgrade stands.
        helper = swap(swap(REACHED, "E4/4", "E4/4 unverifiable (trace truncated)"),
                      "handoff", "handoff lost mark=12 next=-")
        result = self.verdict(helper[:6] + ("truncated seq=10",) + helper[6:])
        self.assertEqual(sl.verdict_text(result), "UNVERIFIED 3/4")
        self.assertEqual(result["reasons"], ["E4 unverifiable (trace truncated)"])

    def test_the_runtime_s_lines_past_the_trace_cap(self):
        # The helper's own lines (TRUNCATION_RUN): E2 is unverifiable and the handoff lost.
        card = reach_card(TRUNCATION, "TS-9999")
        result = sl.reach_verdict(card, TRUNCATION_MODULE, (0, TRUNCATION_RUN),
                                  (0, TRUNCATION_CONTROL))
        self.assertEqual(sl.verdict_text(result), "UNVERIFIED 1/2", result["reasons"])
        self.assertEqual(result["reasons"], ["E2 unverifiable (trace truncated)"])
        self.assertEqual(result["control"], "ok")
        stage = result["replays"]["canonical"]["stages"][2]
        self.assertEqual((stage["helper"], stage["detail"]), ("unverifiable", "(trace truncated)"))
        self.assertEqual(result["replays"]["canonical"]["truncated"], 1048578)
        # Without the helper's downgrade, the stale observation held E2 and the handoff
        # held: the script's recheck, over a replay log libFuzzer ran twice, still refuses it.
        log = sl.first_run(TRUNCATION_STALE + TRUNCATION_STALE, "TS-9999")
        result = sl.reach_verdict(card, TRUNCATION_MODULE, (0, log), (0, TRUNCATION_CONTROL))
        self.assertEqual(sl.verdict_text(result), "UNVERIFIED 1/2", result["reasons"])
        stage = result["replays"]["canonical"]["stages"][2]
        self.assertEqual((stage["helper"], stage["outcome"], stage["detail"]),
                         ("held", "unverifiable", "(trace truncated)"))
        self.assertFalse(result["replays"]["canonical"]["holds"])
        # The truncated line is what refuses it: without it, the same lines reach.
        uncut = "".join(line for line in TRUNCATION_STALE.splitlines(keepends=True)
                        if " truncated seq=" not in line)
        result = sl.reach_verdict(card, TRUNCATION_MODULE, (0, uncut), (0, TRUNCATION_CONTROL))
        self.assertEqual(sl.verdict_text(result), "REACHED 2/2", result["reasons"])

    def test_shape_a_needs_a_continuation(self):
        module = MODULE.replace("Shape: B", "Shape: A")
        self.assertEqual(self.verdict(module=module)["verdict"], "REACHED")
        for following in ("-", "1:8"):
            canonical = swap(REACHED, "handoff", f"handoff holds mark=12 next={following}")
            result = self.verdict(canonical, module=module)
            self.assertEqual(self.stage(result, 4)["detail"], "(no continuation)", following)
            self.assertEqual(result["verdict"], "UNVERIFIED")
        card = reach_card(INTRINSIC)
        module = module.replace("withholds E3", "withholds E1")
        other = swap(INTRINSIC_RUN, "handoff", "handoff holds mark=11 next=2:12")
        result = self.verdict(other, INTRINSIC_CONTROL, module, card)
        self.assertEqual(self.stage(result, 3)["detail"], "(no continuation)")

    def test_missed_stages(self):
        missed = (
            "phase prefix",
            REACHED[1],
            "E2/4 missed no nullify vote of R for v by the deadline",
            "trace 1:3:1:voter_timeout@consensus/src/simplex/actors/voter/round.rs:5:5:1:0",
            "trace 1:4:2:voter_timeout@consensus/src/simplex/actors/voter/round.rs:5:5:1:0",
            "handoff lost mark=6 next=-",
            "phase continuation",
            "reach 1/4 control=0",
            "done",
        )
        result = self.verdict(missed)
        self.assertEqual(sl.verdict_text(result), "PARTIAL 1/4")
        stages = result["replays"]["canonical"]["stages"]
        self.assertEqual(len(stages[2]["trace"]), 2)
        self.assertEqual(sorted(stages), [1, 2])
        feedback = sl.reach_feedback(result)
        self.assertIn(sl.FEEDBACK_FIXES["middle"], feedback)
        self.assertIn("trace 1:4:2:voter_timeout", feedback)
        first = ("phase prefix", "E1/4 missed cannot: journal seeding",
                 "handoff lost mark=2 next=-", "reach 0/4 control=0", "done")
        result = self.verdict(first)
        self.assertEqual(sl.verdict_text(result), "UNREACHED 0/4")
        # A missing capability is no setup to change, wherever the miss is.
        self.assertIn(sl.FEEDBACK_FIXES["cannot"], sl.reach_feedback(result))
        self.assertNotIn(sl.FEEDBACK_FIXES["first"], sl.reach_feedback(result))
        last = swap(swap(REACHED, "E4/4", "E4/4 missed cannot: journal seeding"),
                    "handoff", "handoff lost mark=11 next=-")
        result = self.verdict(last)
        self.assertEqual(sl.verdict_text(result), "PARTIAL 3/4")
        self.assertIn(sl.FEEDBACK_FIXES["cannot"], sl.reach_feedback(result))
        self.assertNotIn(sl.FEEDBACK_FIXES["last"], sl.reach_feedback(result))
        # A stage without a line, when none before it missed; a later `d as E3` has no
        # value of E3's to agree with.
        result = self.verdict(swap(REACHED, "E3/4", None))
        self.assertEqual(self.stage(result, 3)["detail"], "(no line)")
        self.assertEqual(self.stage(result, 4)["detail"], "witness rejected: as")
        self.assertEqual(sl.verdict_text(result), "UNVERIFIED 2/4")

    def test_partial_counts_the_stages_held(self):
        # A version that holds nothing before its miss ranks below one that holds E1.
        none = ("phase prefix",) + tuple(
            f"E{k}/4 unverifiable no observable" for k in (1, 2, 3)) + (
            "E4/4 missed not held at handoff",
            "handoff lost mark=2 next=-",
            "phase continuation",
            "reach 0/4 control=0",
            "done",
        )
        nothing = self.verdict(none)
        self.assertEqual(sl.verdict_text(nothing), "PARTIAL 0/4")
        self.assertEqual(nothing["reasons"], [
            "E1 unverifiable no observable", "E2 unverifiable no observable",
            "E3 unverifiable no observable", "E4 missed: not held at handoff"])
        one = self.verdict(("phase prefix", REACHED[1], "E2/4 missed no nullify vote",
                            "handoff lost mark=3 next=-", "reach 1/4 control=0", "done"))
        self.assertEqual(sl.verdict_text(one), "PARTIAL 1/4")
        kept = sorted([(nothing, 2), (one, 1)], key=lambda version: sl.verdict_key(*version))
        self.assertIs(kept[0][0], one)
        before = sl.report_verdict(f"- Verdict: {sl.verdict_text(one)}\n")
        self.assertTrue(sl.stands_worse(before, nothing))

    def test_vacuous_controls(self):
        cases = (
            (swap(CONTROL, "E3/4", None), MODULE, "no withheld line for E3"),
            (CONTROL, MODULE.replace("withholds E3", "withholds E2"), "E2 is not a harness"),
            (CONTROL, MODULE.replace("withholds E3", "withholds E4"), "E4 is not a harness"),
            (CONTROL, MODULE.replace("withholds E3", "withholds the delivery"), "names no"),
            (swap(CONTROL, "E2/4", "E2/4 missed no vote"), MODULE, "E2 missed"),
            (swap(CONTROL, "E2/4", REACHED[3].replace("v=2", "v=3")), MODULE, "other values"),
            (swap(CONTROL, "E4/4", "E4/4 unverifiable (trace truncated)"), MODULE,
             "neither a held nor a missed line"),
            (None, MODULE, "did not run"),
            # A control that returns before the base's oracles, or reports another card.
            (swap(CONTROL, "done", None), MODULE, "incomplete: no done line"),
            (swap(CONTROL, "reach", None), MODULE, "incomplete: no reach line"),
            (CONTROL + ("![statelens-reach] TS-0009 done",), MODULE, "reports as TS-0009"),
        )
        for control, module, reason in cases:
            result = self.verdict(control=control, module=module)
            self.assertEqual(result["control"], "vacuous", reason)
            self.assertIn(reason, result["control_reason"])
            self.assertEqual(sl.verdict_text(result), "UNVERIFIED 4/4", reason)
            self.assertIn(sl.FEEDBACK_FIXES["control"], sl.reach_feedback(result))

    def test_a_weak_control(self):
        weak = REACHED[:4] + ("E3/4 withheld",) + REACHED[5:7] + (
            "handoff holds mark=12 next=1:13", "reach 3/4 control=1", "done")
        result = self.verdict(control=weak)
        self.assertEqual(sl.verdict_text(result), "UNVERIFIED 4/4 (weak)")
        self.assertIn(sl.FEEDBACK_FIXES["weak"], sl.reach_feedback(result))
        # En held for other entities is what a control should show.
        other = tuple(line.replace("d=ab", "d=cd") for line in weak)
        self.assertEqual(sl.verdict_text(self.verdict(control=other)), "REACHED 4/4")

    def test_a_control_that_omits_a_later_event_too(self):
        # Another omission after Ek could explain the final miss by itself: the helper's
        # lines with E1 withheld and E3, a harness event, withheld too or without a line.
        module = MODULE.replace("withholds E3", "withholds E1")
        head = ("phase prefix", "E1/4 withheld", "E2/4 missed no scalar event observed")
        tail = ("E4/4 missed not held at handoff", "handoff lost mark=2 next=-",
                "phase continuation", "reach 0/4 control=1", "done")
        cases = (("E3/4 withheld", "E3 is withheld in the control run too"),
                 (None, "E3 has no line in the control run"))
        for third, reason in cases:
            control = head + ((third,) if third else ()) + tail
            result = self.verdict(control=control, module=module)
            self.assertEqual(result["control"], "vacuous", reason)
            self.assertEqual(result["control_reason"], reason)
            self.assertEqual(sl.verdict_text(result), "UNVERIFIED 4/4", reason)
            self.assertIn(sl.FEEDBACK_FIXES["control"], sl.reach_feedback(result))
        # A later miss is an outcome: the control drove E3, which did not hold.
        result = self.verdict(control=head + ("E3/4 missed nothing to deliver",) + tail,
                              module=module)
        self.assertEqual(sl.verdict_text(result), "REACHED 4/4", result["reasons"])
        self.assertEqual(result["control"], "ok")

    def test_a_control_witness_that_leaves_an_entity_unbound(self):
        # The rejected witness of UNBOUND tells no other state apart.
        result = self.verdict(control=UNBOUND)
        self.assertEqual(sl.verdict_text(result), "UNVERIFIED 4/4 (weak)")
        self.assertEqual(result["replays"]["control"]["stages"][4]["detail"],
                         "witness rejected: bind")
        self.assertIn(sl.FEEDBACK_FIXES["weak"], sl.reach_feedback(result))
        # Bound to `?`, the same; bound to another value, the control holds.
        question = tuple(line.replace("v=2@E1 exact=certify", "v=2@E1,d=?@E3 exact=certify")
                         for line in UNBOUND)
        self.assertEqual(sl.verdict_text(self.verdict(control=question)),
                         "UNVERIFIED 4/4 (weak)")
        other = tuple(line.replace("v=2@E1 exact=certify", "v=2@E1,d=cd@E3 exact=certify")
                      .replace("d=ab]", "d=cd]") for line in UNBOUND)
        result = self.verdict(control=other)
        self.assertEqual(sl.verdict_text(result), "REACHED 4/4", result["reasons"])

    def test_a_control_bind_its_own_evidence_contradicts_tells_nothing_apart(self):
        # The control's En witness reads the canonical's state, certify[..,d=ab], but
        # binds d=cd: its key names the value, so the bind is no evidence of another
        # state (the `as` rejection it earns fires before the `evidence` one).
        lie = tuple(line.replace("v=2@E1 exact=certify", "v=2@E1,d=cd@E3 exact=certify")
                    for line in UNBOUND)
        result = self.verdict(control=lie)
        self.assertEqual(sl.verdict_text(result), "UNVERIFIED 4/4 (weak)")
        self.assertEqual(result["replays"]["control"]["stages"][4]["detail"],
                         "witness rejected: as")
        self.assertIn(sl.FEEDBACK_FIXES["weak"], sl.reach_feedback(result))
        # A bind of R or v the key contradicts, the same.
        old = "bind=R=1@E1,v=2@E1 exact=certify"
        for new in ("bind=R=2@E1,v=2@E1 exact=certify", "bind=R=1@E1,v=3@E1 exact=certify"):
            lie = tuple(line.replace(old, new) for line in UNBOUND)
            self.assertEqual(sl.verdict_text(self.verdict(control=lie)),
                             "UNVERIFIED 4/4 (weak)", new)
        # A key and bind that agree on R=2 while E1 bound R=1: another entity's state,
        # not another state of the card's R.
        lie = tuple(line.replace("entry certify[R=1,", "entry certify[R=2,")
                    .replace("bind=R=1@E1,v=2@E1 exact=certify[R=1,",
                             "bind=R=2@E1,v=2@E1 exact=certify[R=2,")
                    for line in UNBOUND)
        result = self.verdict(control=lie)
        self.assertEqual(sl.verdict_text(result), "UNVERIFIED 4/4 (weak)")
        self.assertEqual(result["replays"]["control"]["stages"][4]["detail"],
                         "witness rejected: bind")
        # Another value the key confirms is another state.
        other = tuple(line.replace("v=2@E1 exact=certify", "v=2@E1,d=cd@E3 exact=certify")
                      .replace("d=ab]", "d=cd]") for line in UNBOUND)
        self.assertEqual(sl.verdict_text(self.verdict(control=other)), "REACHED 4/4")

    def test_missing_and_n_a_controls(self):
        missing = MODULE.replace("//! Control: withholds E3\n", "")
        result = self.verdict(module=missing)
        self.assertEqual(sl.verdict_text(result), "UNVERIFIED 4/4 (control missing)")
        self.assertIn(sl.FEEDBACK_FIXES["control"], sl.reach_feedback(result))
        na = MODULE.replace("withholds E3", "n/a")
        result = self.verdict(control=None, module=na)
        self.assertEqual(sl.verdict_text(result), "UNVERIFIED 4/4 (control n/a)")
        self.assertIn("harness event before E4", result["control_reason"])
        card = reach_card("""E1. R: signs a nullify vote for some view.
    Check (R, v): R signed a nullify vote for some view v.
E2. R: queues certification of a view.
    Holds (R as E1, w): R queued certification of some view w.""")
        second = ("E2/2 held exact bind=R=1@E1,w=3@E2 exact=certify[R=1,w=3]=queued seq=5 "
                  "read=7")
        canonical = (
            "phase prefix",
            "E1/2 held intrinsic bind=R=1@E1,v=?@E1 obs=1:3:1:nullify@a.rs:1:1:1:0 read=4",
            "entry certify[R=1,w=3]=queued seq=5",
            second,
            "handoff holds mark=8 next=1:9",
            "reach 2/2 control=0",
            "done",
        )
        result = self.verdict(canonical, None, na, card)
        self.assertEqual(sl.verdict_text(result), "UNVERIFIED 2/2 (control n/a)")
        self.assertIn("E1's witness is intrinsic", result["control_reason"])
        exact = swap(canonical, "E1/2", "E1/2 held exact bind=R=1@E1,v=2@E1 "
                     "exact=votes[R=1,v=2]=nullify seq=3 read=4")
        exact = exact[:1] + ("entry votes[R=1,v=2]=nullify seq=3",) + exact[1:]
        result = self.verdict(exact, None, na, card)
        self.assertEqual(sl.verdict_text(result), "REACHED 2/2 (control n/a)", result["reasons"])

    def test_no_report(self):
        for lines in (REACHED[:-1], swap(REACHED, "reach", None),
                      tuple(line.replace("/4 ", "/5 ") for line in REACHED)):
            result = self.verdict(lines)
            self.assertEqual(result["verdict"], "NO REPORT", lines)
            self.assertIn(sl.FEEDBACK_FIXES["no report"], sl.reach_feedback(result))
        self.assertEqual(self.verdict(None, None)["verdict"], "NO REPORT")
        card = reach_card(id="TS-0005")
        text = replay_output(REACHED)
        result = sl.reach_verdict(card, MODULE, (0, text), (0, replay_output(CONTROL)))
        self.assertEqual(result["verdict"], "NO REPORT")
        self.assertIn("the scaffold reports as TS-0004, not TS-0005", result["reasons"])

    def test_an_invariant_panic_in_the_prefix(self):
        location = "consensus/src/simplex/actors/voter/round.rs:120:9"
        crash = REACHED[:4] + (
            f"panic {location} [statelens][INV-0003] R certified twice",
            "phase prefix",
            REACHED[1],
            REACHED[3],
            "E3/4 unverifiable (crashed)",
            "E4/4 unverifiable (crashed)",
        ) + panicked(location, "[statelens][INV-0003] R certified twice")
        diff = (
            "diff --git a/consensus/src/simplex/actors/voter/round.rs "
            "b/consensus/src/simplex/actors/voter/round.rs\n"
            "--- a/consensus/src/simplex/actors/voter/round.rs\n"
            "+++ b/consensus/src/simplex/actors/voter/round.rs\n"
            "@@ -118,4 +118,5 @@ impl Round {\n"
            "     fn certify(&mut self) {\n"
            "         let x = 1;\n"
            "+        // [statelens] tss:TS-0004\n"
            "         sl_assert!(x == 1, \"INV-0003\");\n"
            "     }\n"
        )
        result = self.verdict(crash, codes=(1, 0))
        self.assertEqual(result["verdict"], sl.CRASH)
        self.assertEqual(
            {key: result["crash"][key] for key in ("replay", "kind", "location", "phase")},
            {"replay": "canonical", "kind": "panic", "location": location, "phase": "prefix"},
        )
        self.assertEqual(result["crash"]["message"], "[statelens][INV-0003] R certified twice")
        self.assertNotIn("location in TS-0004 diff", result["annotations"])
        self.assertIsNone(sl.reach_feedback(result))
        # The panic hook repeats the stage lines it already printed; the first counts.
        self.assertEqual(self.stage(result, 2)["outcome"], "held")
        moved = diff.replace("+        // [statelens] tss:TS-0004\n         sl_assert",
                             "-        // gone\n+        sl_assert")
        moved = moved.replace("@@ -118,4 +118,5 @@", "@@ -118,5 +118,4 @@")
        self.assertEqual(sl.diff_added_lines(moved), {
            "consensus/src/simplex/actors/voter/round.rs": {120}})
        result = self.verdict(crash, codes=(1, 0), diff=moved)
        self.assertEqual(sl.verdict_text(result), f"{sl.CRASH} (location in TS-0004 diff)")

    def test_a_sanitizer_report_in_an_added_accessor(self):
        crash = REACHED[:4] + (
            "!==77==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010",
            "!    #0 0x55d1 in core::ptr::read /rustc/abc123/library/core/src/ptr/mod.rs:1300:5",
            "!    #1 0x55d2 in <V as commonware_consensus::Peek>::peek "
            "/home/u/repo/consensus/src/simplex/actors/voter/actor.rs:77:13",
            "!SUMMARY: AddressSanitizer: heap-buffer-overflow",
        )
        diff = (
            "--- a/consensus/src/simplex/actors/voter/actor.rs\n"
            "+++ b/consensus/src/simplex/actors/voter/actor.rs\n"
            "@@ -76,0 +77,2 @@\n"
            "+    // [statelens] tss:TS-0004\n"
            "+    pub fn peek(&self) -> u8 { self.x }\n"
        )
        result = self.verdict(crash, codes=(1, 0), diff=diff)
        self.assertEqual(result["crash"]["kind"], "sanitizer")
        self.assertEqual(result["crash"]["location"],
                         "/home/u/repo/consensus/src/simplex/actors/voter/actor.rs:77:13")
        self.assertEqual(result["crash"]["phase"], "prefix")
        self.assertIn("location in TS-0004 diff", result["annotations"])

    def test_failure_kinds(self):
        def kind(code, *extra):
            result = self.verdict(REACHED[:4] + extra, codes=(code, 0))
            return result["crash"]["kind"], result["crash"]["message"]

        self.assertEqual(kind(None, "!statelens: killed after 1500 s"),
                         ("timeout", "statelens: killed after 1500 s"))
        self.assertEqual(kind(1, "!==1== ERROR: libFuzzer: timeout after 1201 seconds")[0],
                         "timeout")
        self.assertEqual(kind(1, "!==1== ERROR: libFuzzer: out-of-memory (used: 2049Mb)")[0],
                         "oom")
        self.assertEqual(kind(1, "!==1==ERROR: LeakSanitizer: detected memory leaks")[0],
                         "leak")
        self.assertEqual(kind(1, *panicked("a.rs:1:1", "boom")), ("panic", "thread '<unnamed>' "
                         "panicked at a.rs:1:1: boom"))
        self.assertEqual(kind(1)[1], "exit code 1")

    def test_failure_phases(self):
        after = REACHED[:9] + ("panic a.rs:1:1 boom", "phase continuation") + panicked(
            "a.rs:1:1", "boom")
        self.assertEqual(self.verdict(after, codes=(1, 0))["crash"]["phase"], "continuation")
        shape_a = MODULE.replace("Shape: B", "Shape: A")
        found = ("phase prefix", "panic a.rs:1:1 boom", "phase prefix") + REACHED[1:8] + (
            "phase continuation", "reach 4/4 control=0") + panicked("a.rs:1:1", "boom")
        result = self.verdict(found, module=shape_a, codes=(1, 0))
        self.assertEqual(result["crash"]["phase"], "continuation")
        result = self.verdict(found[:3] + panicked("a.rs:1:1", "boom"), module=shape_a,
                              codes=(1, 0))
        self.assertEqual(result["crash"]["phase"], "prefix")
        result = self.verdict(("phase prefix", "!statelens: killed after 1500 s"),
                              module=shape_a, codes=(None, 0))
        self.assertEqual(result["crash"]["phase"], "unknown")

    def test_a_failure_in_the_control_run_only(self):
        control = CONTROL[:4] + panicked("a.rs:1:1", "assertion failed: liveness")
        result = self.verdict(control=control, codes=(0, 1))
        self.assertEqual((result["verdict"], result["crash"]["replay"]), (sl.CRASH, "control"))

    def test_a_replay_log_holds_one_run_of_the_input(self):
        # libFuzzer's leak-check rerun completes nothing: a first run that returned before
        # `done` and a second that printed everything is NO REPORT.
        control = (0, replay_output(CONTROL))
        log = sl.first_run(replay_output(REACHED[:-1]) + replay_output(REACHED), "TS-0004")
        self.assertNotIn("TS-0004 done", log)
        result = sl.reach_verdict(reach_card(), MODULE, (0, log), control)
        self.assertEqual(sl.verdict_text(result), "NO REPORT")
        self.assertIn("the replay printed no done line", result["reasons"])
        # A passing run printed twice reads as the first.
        log = sl.first_run(replay_output(REACHED) * 2, "TS-0004")
        self.assertEqual(log.count("TS-0004 done"), 1)
        result = sl.reach_verdict(reach_card(), MODULE, (0, log), control)
        self.assertEqual(sl.verdict_text(result), "REACHED 4/4", result["reasons"])

    def test_a_panic_in_the_second_run_is_read_in_its_own_phase(self):
        # The hook's lines of a second run that panicked in its prefix after the first run
        # passed: the failure is read there, with the stages the hook could not evaluate.
        location = "consensus/src/simplex/actors/voter/round.rs:9:9"
        message = "[statelens][INV-0001] votes counted"
        hook = ("phase prefix", f"panic {location} {message}", "phase prefix") + tuple(
            f"E{k}/4 unverifiable (crashed)" for k in range(1, 5)) + panicked(location, message)
        log = sl.first_run(replay_output(REACHED) + replay_output(hook), "TS-0004")
        result = sl.reach_verdict(reach_card(), MODULE, (1, log), (0, replay_output(CONTROL)))
        self.assertEqual(result["verdict"], sl.CRASH)
        self.assertEqual((result["crash"]["phase"], result["crash"]["location"]),
                         ("prefix", location))
        replay = result["replays"]["canonical"]
        self.assertEqual(replay["stages"][1]["detail"], "(crashed)")
        self.assertFalse(replay["done"])
        # A panic after `done` inside the first run stays in it: the hook reprints the
        # phase, `continuation`, which opens no run.
        late = REACHED + ("panic a.rs:1:1 late", "phase continuation") + REACHED[1:7]
        log = sl.first_run(replay_output(late + panicked("a.rs:1:1", "late")), "TS-0004")
        self.assertIn("panic a.rs:1:1 late", log)
        self.assertEqual(sl.replay_failure(1, log, "TS-0004", 4, "B")["phase"], "continuation")

    def test_scaffold_errors(self):
        helper = "consensus/fuzz/simplex/src/target_states/mod.rs:149:13"
        reason = "knob 0 has a domain of 1 value(s); it needs two or more"
        error = panicked(helper, f"[statelens-scaffold] TS-0004 {reason}")
        result = self.verdict(error, error, codes=(1, 1))
        self.assertEqual((result["verdict"], result["scaffold_error"]), ("SCAFFOLD ERROR", reason))
        feedback = sl.reach_feedback(result)
        self.assertIn(reason, feedback)
        self.assertIn(sl.FEEDBACK_FIXES["scaffold"], feedback)
        # The helper's own `panic` line, once the stages are open (Stages::budget).
        budget = ("phase prefix", f"panic {helper} [statelens-scaffold] TS-0004 budget",
                  "phase prefix") + panicked(helper, "[statelens-scaffold] TS-0004 budget")
        self.assertEqual(self.verdict(budget, codes=(1, 0))["verdict"], "SCAFFOLD ERROR")
        # The same text raised anywhere else, or a real crash beside it, is a crash.
        module = panicked("consensus/fuzz/simplex/src/target_states/ts0004.rs:9:5",
                          f"[statelens-scaffold] TS-0004 {reason}")
        self.assertEqual(self.verdict(module, codes=(1, 0))["verdict"], sl.CRASH)
        crash = CONTROL[:4] + panicked("a.rs:1:1", "boom")
        self.assertEqual(self.verdict(error, crash, codes=(1, 1))["verdict"], sl.CRASH)

    def test_stray_failures_and_the_final_replay(self):
        result = self.verdict(stray="swept/crash-0a1b")
        self.assertEqual(sl.verdict_text(result), f"{sl.CRASH} (stray failure)")
        card = reach_card()
        canonical, control = (0, replay_output(REACHED)), (0, replay_output(CONTROL))
        same = sl.reach_verdict(card, MODULE, canonical, control, canonical)
        self.assertEqual(sl.verdict_text(same), "REACHED 4/4")
        other = (0, replay_output(swap(REACHED, "E2/4", REACHED[3].replace("read=6", "read=7"))))
        changed = sl.reach_verdict(card, MODULE, canonical, control, other)
        self.assertEqual(sl.verdict_text(changed), "REACHED 4/4 (nondeterministic)")
        failed = (1, replay_output(REACHED[:4] + panicked("a.rs:1:1", "boom")))
        result = sl.reach_verdict(card, MODULE, canonical, control, failed)
        self.assertEqual((result["verdict"], result["crash"]["replay"]), (sl.CRASH, "final"))

    def test_header_annotations(self):
        module = MODULE.replace("//! Missing: none", "//! Missing: journal seeding; a floor") + (
            '    let a = statelens::seen("voter_nullify", None, since, |_| true);\n'
            '    // statelens::seen("in_a_comment", None, 0, |_| true);\n'
            '    let b = statelens::sites("voter_certify");\n'
        )
        result = self.verdict(module=module, labels={"voter_nullify"})
        self.assertEqual(result["annotations"], [
            "unbound label voter_certify", "missing: journal seeding", "missing: a floor"])
        header = sl.module_header(module)
        self.assertEqual((header["card"], header["base"], header["shape"], header["control"]),
                         ("TS-0004", "simplex_cert_mock", "B", 3))
        self.assertEqual(header["fields"]["Stages"].split("; ")[-1], "E4 exact certify")
        self.assertEqual(sl.module_header("//! Control: n/a.\n")["control"], "n/a")
        self.assertIsNone(sl.module_header("//! TS-0004 on x\n")["control"])

    def test_best_version(self):
        def result(verdict, k):
            return {"verdict": verdict, "k": k}

        versions = [(result("PARTIAL", 2), 0), (result("UNVERIFIED", 1), 1),
                    (result("PARTIAL", 3), 2), (result("UNVERIFIED", 1), 3),
                    (result("SCAFFOLD ERROR", 0), 4), (result("NO REPORT", 0), 5)]
        ranked = sorted(versions, key=lambda version: sl.verdict_key(*version))
        self.assertEqual([attempt for _, attempt in ranked], [3, 1, 2, 0, 5, 4])

    def test_locations_match_any_path_form(self):
        added = {"consensus/fuzz/simplex/src/target_states/ts0004.rs": {12}}
        for location in ("consensus/fuzz/simplex/src/target_states/ts0004.rs:12:5",
                         "src/target_states/ts0004.rs:12:5",
                         "/home/u/repo/consensus/fuzz/simplex/src/target_states/ts0004.rs:12"):
            self.assertTrue(sl.location_in_diff(location, added), location)
        for location in ("consensus/fuzz/simplex/src/target_states/ts0004.rs:13:5",
                         "x_ts0004.rs:12:5", None):
            self.assertFalse(sl.location_in_diff(location, added), location)

    def test_a_card_whose_history_breaks_rule_12_is_refused(self):
        with self.assertRaises(sl.Abort) as caught:
            reach_card(TS4.replace("E3.", "E5."))
        self.assertEqual(caught.exception.code, 1)


VOTER_BASE = """\
pub struct Voter {
    votes: u32,
}

impl Voter {
    pub fn vote(&mut self) {
        self.votes += 1;
    }
}
"""
# The campaign's instrumentation: a ghost update, a probe and an assertion.
VOTER = VOTER_BASE.replace(
    "        self.votes += 1;\n",
    "        self.votes += 1;\n"
    "        crate::simplex::statelens::with_ghost(|ghost| ghost.votes += 1); // [statelens]\n"
    '        sl_probe!(None, "voter.vote", self.votes, 0u32);\n'
    '        sl_assert!(None, "INV-0001", self.votes > 0, "votes counted");\n',
)
TWINS_BASE = "fn run(byz: usize) {\n    let crash = 0;\n}\n"
TWINS = TWINS_BASE.replace(
    "    let crash = 0;\n",
    "    let crash = 0;\n"
    "    commonware_consensus::simplex::statelens::set_compromised([byz]);\n",
)
FUZZ_MANIFEST = """\
[package]
name = "fuzz"

[dependencies]
libfuzzer-sys = "0.4"

[[bin]]
name = "simplex_a"
path = "fuzz_targets/simplex_a.rs"
test = false
doc = false
bench = false
required-features = ["mocks"]
"""
BASE_TARGET = """\
#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz_simplex::{
        Chaos, CodeCoverage, FuzzInput, SimplexCertificateMock, fuzz,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        fuzz::<SimplexCertificateMock, Chaos, CodeCoverage>(input);
    });
}
"""
THIN = """\
#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz_simplex::{
        Chaos, CodeCoverage, FuzzInput, SimplexCertificateMock, target_states::ts0004_simplex_a,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        commonware_consensus::simplex::statelens::reset();
        ts0004_simplex_a::fuzz::<SimplexCertificateMock, Chaos, CodeCoverage>(input);
        commonware_consensus::simplex::statelens::clear_compromised();
    });
}
"""
SCAFFOLD_MODULE = """\
//! TS-0004 on simplex_a
//! Shape: B
//! Knobs: raw_bytes[0..1]: [0] v
//! Stages: E1 construction hold_back; E2 exact votes; E3 construction deliver; E4 exact certify
//! Control: withholds E3
//! Injections: none
//! Missing: none

use commonware_consensus::simplex::statelens;

pub fn fuzz<P, D, C>(input: crate::FuzzInput) {
    statelens::set_compromised([]);
    let _ = input;
}
"""
CORE = """\
impl Simplex for SimplexCertificateMock {
    type Scheme = cert_mock::Scheme<Sha256>;
}

impl Simplex for SimplexEd25519 {
    type Scheme = ed25519::Scheme;
}
"""
# The campaign's own gate passed these two tests.
GATE_TESTS = ("simplex::tests::one", "simplex::tests::two")
MARKER = "// [statelens] tss:TS-0004"


def gate_log(passed, failed=(), pass_lines=True):
    """nextest's output in the gate's forced rendering, for a run that passed `passed` and
    failed `failed`; without `pass_lines`, as NEXTEST_STATUS_LEVEL=fail renders it."""
    fail = [f"        FAIL [   0.010s] commonware-consensus {name}" for name in failed]
    lines = [f"        PASS [   0.010s] commonware-consensus {name}" for name in passed]
    lines = (lines if pass_lines else []) + fail + ["------------"]
    total = len(passed) + len(failed)
    counts = f"{len(passed)} passed, " + (f"{len(failed)} failed, " if failed else "")
    lines.append(f"     Summary [   0.020s] {total} tests run: {counts}0 skipped")
    lines += fail + (["error: test run failed"] if failed else [])
    return "\n".join(lines) + "\n"


def colored(text):
    """`text` with the ANSI escapes CARGO_TERM_COLOR=always adds."""
    for word in ("PASS", "FAIL", "Summary", "passed", "failed", "skipped"):
        text = text.replace(word, f"\x1b[32;1m{word}\x1b[0m")
    return text


def campaign_log(text, toolchain="stable", profile="simplex"):
    """The campaign's test.log: run_logged's command line, then the output."""
    return f"$ {sl.shlex.join(sl.gate_test_command(toolchain, profile))}\n{text}"


def state_card(id="TS-0004"):
    """A lint-clean card whose History is TS4's, which REACHED and CONTROL replay."""
    head = card_text(id=id).split("## History")[0]
    return head + "## History\n" + TS4 + "\n\n## Knobs\nNone.\n"


def without_cargo_target_dir(test):
    """Unsets CARGO_TARGET_DIR for `test`, and restores it afterwards."""
    saved = os.environ.pop("CARGO_TARGET_DIR", None)
    if saved is not None:
        test.addCleanup(os.environ.__setitem__, "CARGO_TARGET_DIR", saved)
    test.addCleanup(os.environ.pop, "CARGO_TARGET_DIR", None)


class FuzzBinary(unittest.TestCase):
    """Where synthesis finds a scaffold's fuzz build (SPEC section 18.8). cargo-fuzz writes
    it to CARGO_TARGET_DIR when that is set, which the lookup ignored: every build was NOT
    BUILT, or an older binary in the default directory was replayed for the one just built."""

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        without_cargo_target_dir(self)

    def build(self, root):
        binary = root / "host/release/toy"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        return binary

    def find(self):
        return sl.fuzz_binary(self.repo, "pkg", "host", "toy")

    def test_the_default_directories_without_the_variable(self):
        self.assertIsNone(self.find())
        package = self.build(self.repo / "pkg/target")
        self.assertEqual(self.find(), package)
        workspace = self.build(self.repo / "target")
        self.assertEqual(self.find(), workspace)

    def test_cargo_target_dir_absolute_or_relative_to_the_checkout(self):
        stale = self.build(self.repo / "target")
        elsewhere = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, elsewhere, True)
        for value, root in ((str(elsewhere), elsewhere), ("custom", self.repo / "custom")):
            os.environ["CARGO_TARGET_DIR"] = value
            self.assertIsNone(self.find(), f"{value}: an older build in target/ is not this one")
            built = self.build(root)
            self.assertEqual(self.find(), built)
        del os.environ["CARGO_TARGET_DIR"]
        self.assertEqual(self.find(), stale)


class RestoreLinks(unittest.TestCase):
    """`Synthesis.restore` over symbolic links an edit left in the scope (SPEC section 18.6.2,
    step 1): a snapshot holds regular files, so a restore never writes through a link."""

    ORIGINAL = b"pub fn scalar() -> u32 { 0 }\n"
    SIBLING = b"pub fn scalar() -> u32 { 1 }\n"

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.source = self.repo / "consensus/src/simplex/scalar.rs"
        self.sibling = self.repo / "other/scalar.rs"
        for path, content in ((self.source, self.ORIGINAL), (self.sibling, self.SIBLING)):
            path.parent.mkdir(parents=True)
            path.write_bytes(content)
        for args in (("init", "-q", "."), ("config", "user.email", "t@example.invalid"),
                     ("config", "user.name", "t"), ("config", "commit.gpgsign", "false"),
                     ("add", "-A"), ("commit", "-qm", "base")):
            subprocess.run(("git",) + args, cwd=self.repo, capture_output=True, check=True)
        self.synthesis = sl.Synthesis.__new__(sl.Synthesis)
        self.synthesis.repo = self.repo
        self.synthesis.scope = ("consensus/src/simplex/", "consensus/fuzz/simplex/")
        self.synthesis.profile = {"roots": ("consensus/src/simplex/",)}
        self.synthesis.package = "consensus/fuzz/simplex"
        self.synthesis.own = lambda *_paths: None
        self.said = []
        self.addCleanup(setattr, sl, "say", sl.say)
        sl.say = self.said.append
        self.snapshot = self.synthesis.snapshot()

    def test_a_file_replaced_by_a_link_is_restored_as_a_file(self):
        # The review's case: the edit made the source a link to an unchanged file outside
        # the scope, and the restore wrote the source's content through it.
        self.source.unlink()
        self.source.symlink_to(self.sibling)
        self.synthesis.restore(self.snapshot)
        self.assertFalse(self.source.is_symlink())
        self.assertEqual(self.source.read_bytes(), self.ORIGINAL)
        self.assertEqual(self.sibling.read_bytes(), self.SIBLING)
        self.assertEqual(self.said, [])

    def test_a_link_an_edit_added_is_removed_not_followed(self):
        link = self.source.with_name("added.rs")
        link.symlink_to(self.sibling)
        self.synthesis.restore(self.snapshot)
        self.assertFalse(link.is_symlink() or link.exists())
        self.assertEqual(self.sibling.read_bytes(), self.SIBLING)
        self.assertEqual(self.source.read_bytes(), self.ORIGINAL)

    def test_nothing_is_written_below_a_directory_a_link_replaced(self):
        # Guard 1 names the directory and synthesis exits with code 2; the restore on the
        # way out writes nothing through the link.
        shutil.rmtree(self.source.parent)
        self.source.parent.symlink_to(self.repo / "other")
        self.synthesis.restore(self.snapshot)
        self.assertTrue(self.source.parent.is_symlink())
        self.assertEqual(self.sibling.read_bytes(), self.SIBLING)
        self.assertEqual(self.said, ["warning: consensus/src/simplex/scalar.rs lies behind a "
                                     "symbolic link; it was not restored"])


class HandoverLines(unittest.TestCase):
    """`Synthesis.run_lines` (SPEC section 18.6.2, Console): the run and replay lines run
    as printed, also from a checkout, or with a crash file, whose path holds a space."""

    SCAFFOLD = "x_ts0001_statelens"

    def synthesis(self, repo):
        synthesis = sl.Synthesis.__new__(sl.Synthesis)
        synthesis.repo = pathlib.Path(repo)
        synthesis.package = "consensus/fuzz/simplex"
        synthesis.profile = {"replay_env": "CONSENSUS_FUZZ_LOG=1"}
        synthesis.fuzz_toolchain = "nightly"
        return synthesis

    def test_a_space_free_checkout_renders_unquoted(self):
        run, replay = self.synthesis("/repo").run_lines(self.SCAFFOLD)
        self.assertEqual(
            run, f"cd /repo/statelens && NIGHTLY_VERSION=nightly just run {self.SCAFFOLD}"
        )
        self.assertEqual(
            replay,
            "cd /repo/statelens && STATELENS_REACH=1 CONSENSUS_FUZZ_LOG=1 "
            f"NIGHTLY_VERSION=nightly just run {self.SCAFFOLD} "
            f"/repo/consensus/fuzz/simplex/artifacts/{self.SCAFFOLD}/<crash file>",
        )
        _run, control = self.synthesis("/repo").run_lines(
            self.SCAFFOLD, pathlib.Path("/repo/statelens/campaign/reach/empty"), True
        )
        self.assertEqual(
            control,
            "cd /repo/statelens && STATELENS_REACH=1 STATELENS_REACH_CONTROL=1 "
            f"CONSENSUS_FUZZ_LOG=1 NIGHTLY_VERSION=nightly just run {self.SCAFFOLD} "
            "/repo/statelens/campaign/reach/empty",
        )

    def test_a_checkout_with_a_space_is_quoted_and_the_placeholder_is_not(self):
        run, replay = self.synthesis("/a b").run_lines(self.SCAFFOLD)
        self.assertTrue(run.startswith("cd '/a b/statelens' && "), run)
        self.assertTrue(
            replay.endswith(
                f" '/a b/consensus/fuzz/simplex/artifacts/{self.SCAFFOLD}'/<crash file>"
            ),
            replay,
        )

    def test_the_lines_run_as_printed_from_a_checkout_with_a_space(self):
        # The review's case, with a stub `just` on PATH that records its arguments: the
        # run line's `cd` succeeds, and the crash path reaches `just` as one argument.
        repo = pathlib.Path(tempfile.mkdtemp(prefix="tss r2 "))
        self.addCleanup(shutil.rmtree, repo, True)
        (repo / "statelens").mkdir()
        seen = repo / "seen.txt"
        just = repo / "bin" / "just"
        just.parent.mkdir()
        just.write_text(
            "#!/bin/sh\n"
            f"for a in \"$@\"; do printf '%s\\n' \"$a\" >> '{seen}'; done\n"
        )
        just.chmod(0o755)
        crash = repo / "consensus/fuzz/simplex/artifacts" / self.SCAFFOLD / "crash-1"
        run, replay = self.synthesis(repo).run_lines(self.SCAFFOLD, crash)
        env = dict(os.environ, PATH=str(just.parent) + os.pathsep + os.environ["PATH"])
        for line in (run, replay):
            done = subprocess.run(["bash", "-c", line], env=env, capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, f"{line}: {done.stderr}")
        self.assertEqual(
            seen.read_text().splitlines(),
            ["run", self.SCAFFOLD, "run", self.SCAFFOLD, str(crash)],
        )


class Synthesize(unittest.TestCase):
    """`synthesize` (SPEC section 18.6) with a stub agent, build, replays and test gate, on a
    checkout a stub campaign instrumented: the edit contract's guards (AC-24), the stop
    rules, restores, reports, the console and the exit codes."""

    def run_git(self, *args):
        return subprocess.run(
            ("git",) + args, cwd=self.repo, capture_output=True, text=True, check=True
        ).stdout

    def put(self, relative, text):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def read(self, relative):
        path = self.repo / relative
        return path.read_text() if path.is_file() else None

    def edit(self, relative, old, new):
        text = self.read(relative)
        self.assertIn(old, text)
        self.put(relative, text.replace(old, new, 1))

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        prompts = HERE.parent / "prompts"
        for relative, text in (
            (".gitignore", "target/\n*/fuzz/artifacts\n*/fuzz/corpus\n*/fuzz/coverage\n"
                           "*/fuzz/*/artifacts\n*/fuzz/*/corpus\n*/fuzz/*/coverage\n"),
            ("Cargo.lock", "# lock\n"),
            ("statelens/.gitignore", "campaign/\nextract/\ntarget-states.local/\n"),
            ("statelens/config.env", "STATELENS_AGENT=claude\n"),
            ("statelens/runtime/target_states.rs",
             "//! The helper.\n\npub fn emit() {\n    eprintln!(\"[statelens-reach] x\");\n}\n"),
            ("statelens/prompts/synthesize.md", (prompts / "synthesize.md").read_text()),
            ("statelens/prompts/subsystems/simplex-synthesize.md",
             (prompts / "subsystems/simplex-synthesize.md").read_text()),
            ("statelens/target-states/simplex/TS-0004.md", state_card()),
            ("consensus/src/simplex/mod.rs", "pub mod types;\n"),
            ("consensus/src/simplex/voter.rs", VOTER_BASE),
            ("consensus/fuzz/core/src/simplex.rs", CORE),
            ("consensus/fuzz/simplex/Cargo.toml", FUZZ_MANIFEST),
            ("consensus/fuzz/simplex/src/lib.rs", "pub mod state_cov;\n\npub fn fuzz() {}\n"),
            ("consensus/fuzz/simplex/src/chaos/twins.rs", TWINS_BASE),
            ("consensus/fuzz/simplex/fuzz_targets/simplex_a.rs", BASE_TARGET),
        ):
            self.put(relative, text)
        for args in (("init", "-q", "."), ("config", "user.email", "t@example.invalid"),
                     ("config", "user.name", "t"), ("config", "commit.gpgsign", "false"),
                     ("add", "-A"), ("commit", "-qm", "base")):
            self.run_git(*args)
        # A stub campaign: materialize, instrumentation, and what it leaves in campaign/.
        self.put("consensus/src/simplex/mod.rs", "pub mod types;\npub mod statelens;\n")
        self.put(sl.STATELENS_RS, "pub fn watch() {}\n\npub fn seen() {}\n")
        self.put("consensus/src/simplex/voter.rs", VOTER)
        self.put("consensus/fuzz/simplex/src/chaos/twins.rs", TWINS)
        manifest = sl.bin_blocks(FUZZ_MANIFEST)
        self.put(sl.FUZZ_MANIFEST,
                 FUZZ_MANIFEST + sl.variant_bin_block(manifest, "simplex_a", sl.FUZZ_MANIFEST))
        variant, _ = sl.variant_text("x", BASE_TARGET.split("\n"),
                                     "commonware_consensus::simplex::statelens")
        self.put("consensus/fuzz/simplex/fuzz_targets/simplex_a_statelens.rs", "\n".join(variant))
        self.run_git("add", "--intent-to-add", sl.STATELENS_RS,
                     "consensus/fuzz/simplex/fuzz_targets/simplex_a_statelens.rs")
        self.base = self.run_git("rev-parse", "HEAD").strip()
        self.meta = {
            "base": self.base, "agent": "claude", "profile": "simplex",
            "test_toolchain": "stable", "fuzz_toolchain": "nightly-test",
            "invariants": ["INV-0001"], "targets": ["simplex_a_statelens"],
        }
        self.put("statelens/campaign/meta.json", json.dumps(self.meta))
        self.put("statelens/campaign/summary.txt", "statelens: result     READY\n")
        self.put("statelens/campaign/plan.md", "# StateLens instrumentation plan\n")
        self.put("statelens/campaign/logs/test.log", campaign_log(gate_log(GATE_TESTS)))
        self.put("statelens/campaign/instrumentation.diff", self.run_git("diff"))
        saved = {name: getattr(sl, name) for name in (
            "repo_root", "run_logged", "agent_command", "check_agent_cli", "host_triple", "say")}
        which = sl.shutil.which
        self.addCleanup(setattr, sl.shutil, "which", which)
        self.addCleanup(lambda: [setattr(sl, key, value) for key, value in saved.items()])
        sl.shutil.which = lambda tool: f"/usr/bin/{tool}"
        sl.repo_root = lambda: self.repo
        sl.check_agent_cli = lambda _agent: None
        sl.host_triple = lambda _toolchain: "host"
        without_cargo_target_dir(self)
        sl.agent_command = lambda _config, _agent, phase, _repo: ["stub-agent", str(phase)]
        sl.run_logged = self.fake_run
        self.said = []
        sl.say = self.said.append
        # What the stubs do: one agent step per call, the build, the replays and the gate.
        self.steps = []
        self.prompts = []
        self.builds = []
        self.build_fails = False
        self.replays = {"canonical": (0, REACHED), "control": (0, CONTROL)}
        self.gate_passes = GATE_TESTS
        # (exit code, output) of the next gate runs, ahead of the default from gate_passes.
        self.gate_runs = []
        self.gates = 0
        # The run the operator interrupts: "canonical", "control", "final" or "gate", or a
        # replay as (card, directory, replay); with `interrupt_crash`, after the replay left
        # its crash file.
        self.interrupt = None
        self.interrupt_crash = False
        # Whether a scaffold compiles on the tree as it is, and a replay's (exit code, lines)
        # by card, directory and replay, ahead of `replays`, or None.
        self.compiles = lambda _scaffold: True
        self.replay_for = lambda _key, _tag, _name: None

    def fake_run(self, command, log_path, cwd, stdin_text=None, echo=True, timeout=None,
                 env=None):
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if command[0] == "stub-agent":
            self.assertEqual(command[1], "2", "synthesis runs the Phase 2 invocation")
            self.prompts.append(stdin_text)
            step = self.steps.pop(0) if self.steps else None
            log_path.write_text("agent\n")
            return (step() or 0) if step else 0, []
        if "fuzz" in command and "build" in command:
            scaffold = command[-1]
            self.builds.append(scaffold)
            if self.build_fails:
                log_path.write_text("error[E0425]: cannot find value `x`\n")
                return 101, ["error[E0425]: cannot find value `x`"]
            if not self.compiles(scaffold):
                error = "error[E0061]: this function takes 2 arguments but 1 argument was supplied"
                log_path.write_text(error + "\n")
                return 101, [error]
            # Where cargo puts it: CARGO_TARGET_DIR, relative to the checkout it runs in.
            target = os.environ.get("CARGO_TARGET_DIR") or "target"
            binary = self.repo / target / "host/release" / scaffold
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_text("#!/bin/sh\n")
            binary.chmod(0o755)
            log_path.write_text("built\n")
            return 0, []
        if "nextest" in command:
            self.assertEqual(command, sl.gate_test_command("stable", "simplex"))
            self.gates += 1
            if self.interrupt == "gate":
                log_path.write_text(f"$ {sl.shlex.join(command)}\n")
                raise KeyboardInterrupt
            if self.gate_runs:
                code, text = self.gate_runs.pop(0)
            else:
                failed = [name for name in GATE_TESTS if name not in self.gate_passes]
                code, text = (100 if failed else 0), gate_log(self.gate_passes, failed)
            log_path.write_text(f"$ {sl.shlex.join(command)}\n{text}")
            return code, []
        # A replay: no corpus and no flag, the empty input, the reach environment.
        self.assertEqual(command[1:], [str(self.repo / "statelens/campaign/reach/empty")])
        self.assertEqual(pathlib.Path(command[1]).read_bytes(), b"")
        self.assertEqual(timeout, sl.REPLAY_TIMEOUT)
        self.assertEqual(env["STATELENS_REACH"], "1")
        self.assertNotIn("STATELENS_BYZANTINE", env)
        cwd = pathlib.Path(cwd)
        name = "control" if env.get("STATELENS_REACH_CONTROL") == "1" else cwd.name
        key, tag = cwd.parts[-3], cwd.parts[-2]
        card = sl.PAIR_KEY.match(key)["card"]
        crash = cwd / "crash-da39a3ee5e6b4b0d3255bfef95601890afd80709"
        if self.interrupt in (name, (key, tag, name)):
            log_path.write_text(f"$ {' '.join(command)}\n")
            if self.interrupt_crash:
                crash.write_text("")
            raise KeyboardInterrupt
        code, lines = self.replay_for(key, tag, name) or self.replays.get(
            name, self.replays["canonical"])
        if code:
            crash.write_text("")
        # libFuzzer runs a passing input twice: the second run repeats every line.
        text = replay_output(lines, card) * (1 if code else 2)
        log_path.write_text(f"$ {' '.join(command)}\n{text}")
        return code, []

    def synthesize(self, *args):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = sl.main(["synthesize"] + list(args))
        self.output = out.getvalue()
        return code

    def scaffold(self, module=SCAFFOLD_MODULE, thin=THIN, base="simplex_a"):
        """The module and thin target of the pair (TS-0004, `base`): SCAFFOLD_MODULE's and
        THIN's, written for simplex_a, rewritten for another base."""
        module = module.replace("//! TS-0004 on simplex_a\n", f"//! TS-0004 on {base}\n", 1)
        thin = thin.replace("ts0004_simplex_a", f"ts0004_{base}")
        self.put(f"consensus/fuzz/simplex/src/target_states/ts0004_{base}.rs", module)
        self.put(f"consensus/fuzz/simplex/fuzz_targets/{base}_ts0004_statelens.rs", thin)

    def write_scaffold(self, then=None):
        """An agent step that writes a valid scaffold, then makes the edit `then`."""
        def step():
            self.scaffold()
            if then:
                then()
        return step

    def line(self, card="TS-0004"):
        return next(line for line in self.said if line.startswith(card + " "))

    def report(self, key="TS-0004_simplex_a"):
        return self.read(f"statelens/campaign/reach/{key}.md")

    def section(self, report, heading):
        """The last section `heading` of `report`, up to the next section or the end."""
        return report.rsplit(f"\n## {heading}\n\n", 1)[1].split("\n## ", 1)[0]

    def run_block(self, report):
        """The run and replay lines of `report`."""
        return report.split("## Run and replay\n\n```\n", 1)[1].split("\n```", 1)[0].split("\n")

    def rel(self, path):
        return path.relative_to(self.repo).as_posix()

    def feedback(self, attempt):
        return self.prompts[attempt].split("## Feedback", 1)[1].split("What each signal", 1)[0]

    def assert_restored(self):
        """The pair's edits are gone: the tree as the campaign left it, with the helper."""
        self.assertIsNone(self.read("consensus/fuzz/simplex/src/target_states/ts0004_simplex_a.rs"))
        self.assertIsNone(
            self.read("consensus/fuzz/simplex/fuzz_targets/simplex_a_ts0004_statelens.rs"))
        self.assertNotIn("ts0004", self.read(sl.FUZZ_MANIFEST))
        self.assertEqual(self.read("consensus/src/simplex/voter.rs"), VOTER)
        self.assertNotIn("pub mod ts0004_simplex_a;", self.read(
            "consensus/fuzz/simplex/src/target_states/mod.rs"))

    def test_a_scaffold_is_built_replayed_kept_and_reported(self):
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(len(self.prompts), 1, "REACHED stops refinement")
        self.assertNotIn("{{", self.prompts[0])
        self.assertIn("none: first attempt", self.prompts[0])
        self.assertIn("- `voter.vote` at consensus/src/simplex/voter.rs:", self.prompts[0])
        self.assertIn("`simplex_a`: closure `fuzz_target!(|input: FuzzInput| {`", self.prompts[0])
        self.assertIn("cargo +nightly-test fuzz build --fuzz-dir consensus/fuzz/simplex "
                      "simplex_a_ts0004_statelens",
                      self.prompts[0])
        self.assertIn("cards      1 tracked, 0 local", self.said)
        self.assertEqual(self.line(), "TS-0004    REACHED 4/4   simplex_a_ts0004_statelens")
        here = f"cd {self.repo / 'statelens'} && "
        self.assertIn(f"run        {here}NIGHTLY_VERSION=nightly-test just run "
                      "simplex_a_ts0004_statelens", self.said)
        self.assertIn(
            f"replay     {here}STATELENS_REACH=1 CONSENSUS_FUZZ_LOG=1 NIGHTLY_VERSION=nightly-test "
            f"just run simplex_a_ts0004_statelens {self.repo}/consensus/fuzz/simplex/artifacts/"
            "simplex_a_ts0004_statelens/<crash file>", self.said)
        self.assertEqual(self.builds, ["simplex_a_ts0004_statelens"] * 3,
                         "built again when kept, and once more by the last check")
        self.assertTrue(
            (self.repo / "statelens/campaign/logs/fuzz-build-simplex_a_ts0004_statelens-last.log")
            .is_file())
        # The script's own edits: the declaration, the helper and its line, the [[bin]] block.
        lib = self.read("consensus/fuzz/simplex/src/lib.rs")
        self.assertIn("pub mod state_cov;\npub mod target_states;\n", lib)
        helper = self.read("consensus/fuzz/simplex/src/target_states/mod.rs")
        self.assertTrue(helper.startswith("//! The helper."))
        self.assertTrue(helper.endswith("\n\npub mod ts0004_simplex_a;\n"))
        self.assertIn('name = "simplex_a_ts0004_statelens"\n'
                      'path = "fuzz_targets/simplex_a_ts0004_statelens.rs"',
                      self.read(sl.FUZZ_MANIFEST))
        reach = self.repo / "statelens/campaign/reach"
        self.assertEqual((reach / "empty").read_bytes(), b"")
        self.assertTrue((reach / "baseline/state.json").is_file())
        self.assertFalse((reach / "pending").exists(), "kept only until the card ends")
        for replay in ("canonical", "control", "final"):
            self.assertTrue((reach / "TS-0004_simplex_a/attempt-0" / replay / "replay.log").is_file())
        report = self.report()
        self.assertIn("- Verdict: REACHED 4/4", report)
        self.assertIn("- Handoff: handoff holds mark=12 next=1:13", report)
        self.assertIn("| E4 | held |", report)
        self.assertIn("- attempt 0: REACHED 4/4", report)
        diff = self.read("statelens/campaign/reach/TS-0004_simplex_a.diff")
        self.assertIn("+++ b/consensus/fuzz/simplex/src/target_states/ts0004_simplex_a.rs", diff)
        self.assertIn('+name = "simplex_a_ts0004_statelens"', diff)
        version = (reach / "TS-0004_simplex_a/attempt-0/version.diff").read_text()
        self.assertIn("+++ b/consensus/fuzz/simplex/src/target_states/ts0004_simplex_a.rs", version)
        self.assertEqual(self.gates, 0, "no edit under the editable roots, no gate")
        # The second run skips the card and still has its scaffold.
        self.said.clear()
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(len(self.prompts), 1)
        self.assertIn("TS-0004    skipped: TS-0004 on simplex_a was synthesized as simplex_a_ts0004_statelens; "
                      "use --redo", self.said)
        self.assertEqual(len(self.builds), 4,
                         "a run that synthesizes no card still builds every scaffold")
        # --redo undoes the card's diff, keeps its reports aside and synthesizes it again.
        self.steps = [self.write_scaffold()]
        self.said.clear()
        self.assertEqual(self.synthesize("--redo"), 0)
        self.assertEqual(len(self.prompts), 2)
        self.assertIn("none: first attempt", self.prompts[1])
        self.assertEqual(len(list(reach.glob("TS-0004_simplex_a.*.md"))), 1)
        self.assertEqual(len(list(reach.glob("TS-0004_simplex_a.*.diff"))), 1)
        self.assertEqual(len([path for path in reach.glob("TS-0004_simplex_a.*") if path.is_dir()]), 1)
        self.assertEqual(self.line(), "TS-0004    REACHED 4/4   simplex_a_ts0004_statelens")
        self.assertEqual(self.read(sl.FUZZ_MANIFEST).count("simplex_a_ts0004_statelens"), 2,
                         "one [[bin]] block, its name and its path")

    def test_an_edit_outside_the_scope_stops_synthesis_until_undone(self):
        self.steps = [self.write_scaffold(lambda: self.edit(
            "consensus/fuzz/core/src/simplex.rs", "Sha256", "Sha512"))]
        self.assertEqual(self.synthesize(), 2)
        self.assertIn("error: synthesis edited consensus/fuzz/core/src/simplex.rs; use a fresh "
                      "clone", self.output + "\n".join(self.said))
        self.assert_restored()
        self.assertIsNone(self.report(), "a card stopped by guard 1 has no report")
        note = self.read("statelens/campaign/reach/TS-0004_simplex_a/attempt-0/interrupted.txt")
        self.assertIn("synthesis stopped during the checks (Abort: synthesis edited "
                      "consensus/fuzz/core/src/simplex.rs; use a fresh clone)", note)
        self.assertIn("No version was kept", note)
        # The next synthesis refuses before any pair, naming the path.
        self.assertEqual(self.synthesize(), 2)
        self.assertEqual(len(self.prompts), 1)
        self.assertIn("the checkout differs from the synthesis baseline: "
                      "consensus/fuzz/core/src/simplex.rs", "\n".join(self.said))
        self.run_git("checkout", "--", "consensus/fuzz/core/src/simplex.rs")
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line(), "TS-0004    REACHED 4/4   simplex_a_ts0004_statelens")

    def test_a_manifest_dependency_is_restored_with_feedback(self):
        self.steps = [
            self.write_scaffold(lambda: self.edit(
                sl.FUZZ_MANIFEST, 'libfuzzer-sys = "0.4"\n',
                'libfuzzer-sys = "0.4"\nrand = "0.8"\n')),
            lambda: self.edit("consensus/fuzz/simplex/src/target_states/ts0004_simplex_a.rs",
                              "let _ = input;", "let _input = input;"),
        ]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(len(self.prompts), 2)
        self.assertIn("guard 2: consensus/fuzz/simplex/Cargo.toml is the script's and was "
                      "restored", self.feedback(1))
        self.assertIn("Attempt 0: NOT BUILT (1 veto(es))", self.feedback(1))
        self.assertNotIn("rand", self.read(sl.FUZZ_MANIFEST))
        self.assertEqual(self.builds, ["simplex_a_ts0004_statelens"] * 3)
        self.assertEqual(self.line(), "TS-0004    REACHED 4/4   simplex_a_ts0004_statelens")

    def drop_assertion(self):
        self.edit("consensus/src/simplex/voter.rs",
                  '        sl_assert!(None, "INV-0001", self.votes > 0, "votes counted");\n', "")

    def touch_module(self, text):
        return lambda: self.edit("consensus/fuzz/simplex/src/target_states/ts0004_simplex_a.rs",
                                 "pub fn fuzz", f"// {text}\npub fn fuzz")

    def test_a_removed_assertion_is_vetoed_in_every_attempt_that_keeps_it(self):
        # Attempt 0 removes the assertion; attempt 1 makes an unrelated edit and leaves the
        # removal in place; attempt 2 changes nothing, which ends the card.
        self.steps = [self.write_scaffold(self.drop_assertion), self.touch_module("one")]
        self.assertEqual(self.synthesize(), 3)
        self.assertEqual(len(self.prompts), 3)
        self.assertEqual(self.builds, [], "a vetoed version is never built")
        finding = ("guard 3: consensus/src/simplex/voter.rs: an sl_probe!, sl_assert! or "
                   "sl_implies! call was added, removed or changed (removed sl_assert!(None,"
                   '"INV-0001",self.votes>0,"votescounted")); revert it')
        self.assertIn(finding, self.feedback(1))
        self.assertIn(finding, self.feedback(2))
        self.assertEqual(self.line(), "TS-0004    NOT BUILT   no scaffold on simplex_a")
        self.assert_restored()
        self.assertIn("sl_assert!", self.read("consensus/src/simplex/voter.rs"))
        self.assertEqual(self.read("statelens/campaign/reach/TS-0004_simplex_a.diff"), "")
        self.assertIn("synthesis  1 pair(s), 0 scaffold(s)", "\n".join(self.said))

    def test_a_reverted_assertion_lets_the_next_attempt_build(self):
        self.steps = [
            self.write_scaffold(self.drop_assertion),
            lambda: self.put("consensus/src/simplex/voter.rs", VOTER),
        ]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(len(self.prompts), 2)
        self.assertEqual(self.builds, ["simplex_a_ts0004_statelens"] * 3)
        self.assertEqual(self.line(), "TS-0004    REACHED 4/4   simplex_a_ts0004_statelens")

    def test_a_deleted_ghost_update_and_a_changed_hook_are_vetoed(self):
        ghost = ("        crate::simplex::statelens::with_ghost(|ghost| ghost.votes += 1); "
                 "// [statelens]\n")

        def hook():
            self.put("consensus/src/simplex/voter.rs", VOTER)
            self.edit("consensus/fuzz/simplex/src/chaos/twins.rs", "set_compromised([byz])",
                      "set_compromised([byz, 0])")

        self.steps = [
            self.write_scaffold(lambda: self.edit("consensus/src/simplex/voter.rs", ghost, "")),
            hook,
        ]
        self.assertEqual(self.synthesize(), 3)
        self.assertIn("guard 3: consensus/src/simplex/voter.rs lost 1 line(s) the campaign added",
                      self.feedback(1))
        self.assertIn("guard 3: consensus/fuzz/simplex/src/chaos/twins.rs lost 1 line(s) the "
                      "campaign added", self.feedback(2))
        self.assertEqual(self.read("consensus/fuzz/simplex/src/chaos/twins.rs"), TWINS)
        self.assert_restored()

    def test_integrity_breaches_are_vetoed(self):
        module = "consensus/fuzz/simplex/src/target_states/ts0004_simplex_a.rs"
        cases = (
            ("an added probe", lambda: self.edit(
                "consensus/src/simplex/voter.rs", "        self.votes += 1;\n",
                '        self.votes += 1; // [statelens] tss:TS-0004\n'
                '        sl_probe!(None, "voter.extra", 1u32, 2u32);\n'),
             "call was added, removed or changed (added sl_probe!(None,\"voter.extra\""),
            ("a #[path] attribute", lambda: self.edit(
                "consensus/src/simplex/mod.rs", "pub mod statelens;",
                '#[path = "statelens.rs"]\npub mod statelens;'),
             "guard 3: the declaration of the runtime module in consensus/src/simplex/mod.rs"),
            ("the runtime module", lambda: self.edit(
                sl.STATELENS_RS, "pub fn seen() {}", "pub fn seen() {}\n\npub fn peek() {}"),
             f"guard 3: the runtime module {sl.STATELENS_RS} changed"),
            ("a reach literal", lambda: self.edit(
                module, "let _ = input;", 'eprintln!("[statelens-reach] TS-0004 done");'),
             f"guard 3: {module} holds the literal [statelens-reach]"),
            ("a tick", lambda: self.edit(module, "let _ = input;", "statelens::tick();"),
             f"guard 3: {module} adds a call of tick"),
            # A new trace forgets a truncation the helper has not seen: a stale En could hold.
            ("a watch", lambda: self.edit(module, "let _ = input;", "statelens::watch();"),
             f"guard 3: {module} adds a call of watch"),
            ("an unwatch in the fuzz package", lambda: self.edit(
                "consensus/fuzz/simplex/src/lib.rs", "pub fn fuzz() {}",
                f"pub fn fuzz() {{\n    {MARKER}\n"
                "    commonware_consensus::simplex::statelens::unwatch();\n}"),
             "guard 3: consensus/fuzz/simplex/src/lib.rs adds a call of unwatch"),
            ("a ghost write", lambda: self.edit(module, "let _ = input;",
                                                "statelens::with_ghost(|_| ());"),
             f"guard 3: {module} adds a call of with_ghost"),
            ("the read side under a root", lambda: self.edit(
                "consensus/src/simplex/voter.rs", "        self.votes += 1;\n",
                "        self.votes += 1; // [statelens] tss:TS-0004\n"
                "        let _ = crate::simplex::statelens::seen("
                '"voter.vote", None, 0, |_| true);\n'),
             "guard 3: consensus/src/simplex/voter.rs adds a call of seen"),
            ("Shape B without set_compromised", lambda: self.edit(
                module, "statelens::set_compromised([]);", ""),
             "a Shape B module calls set_compromised"),
            ("a thin target of another shape", lambda: self.edit(
                "consensus/fuzz/simplex/fuzz_targets/simplex_a_ts0004_statelens.rs",
                "        commonware_consensus::simplex::statelens::clear_compromised();\n", ""),
             "its fuzz_target! must be the block of Appendix B.6"),
            ("a type without cert_mock", lambda: self.edit(
                module, "let _ = input;", "let _ = core::mem::size_of::<SimplexEd25519>();"),
             "the module names SimplexEd25519"),
            ("a reach literal split in two", lambda: self.edit(
                module, "let _ = input;", 'eprintln!("[statelens{}] TS-0004 done", "-reach");'),
             f"guard 3: {module} adds a print macro"),
            ("a panic hook", lambda: self.edit(
                module, "let _ = input;", "std::panic::set_hook(Box::new(|_| {}));"),
             f"guard 3: {module} adds a panic hook"),
            ("an included file", lambda: self.edit(
                module, "let _ = input;", 'include!("../../../../src/simplex/voter.rs");'),
             f"guard 3: {module} adds an include macro"),
            ("a #[path] module in the fuzz package", lambda: self.edit(
                module, "pub fn fuzz", '#[path = "../x.rs"]\nmod x;\n\npub fn fuzz'),
             f"guard 3: {module} adds a #[path] attribute"),
        )
        for name, breach, finding in cases:
            with self.subTest(name):
                del self.prompts[:]
                self.builds = []
                self.steps = [self.write_scaffold(breach)]
                self.assertEqual(self.synthesize("--redo"), 3)
                self.assertEqual(len(self.prompts), 2, "the second attempt changes nothing")
                self.assertIn(finding, self.feedback(1))
                self.assertEqual(self.builds, [])
                self.assert_restored()
                self.assertEqual(self.read(sl.STATELENS_RS),
                                 "pub fn watch() {}\n\npub fn seen() {}\n")
                self.assertEqual(self.read("consensus/src/simplex/mod.rs"),
                                 "pub mod types;\npub mod statelens;\n")

    def accessor(self, card="TS-0004"):
        self.edit("consensus/src/simplex/voter.rs", "impl Voter {\n",
                  f"impl Voter {{\n    {sl.TSS_MARKER}{card}\n    pub fn votes(&self) -> u32 {{\n"
                  "        self.votes\n    }\n\n")

    def test_a_marked_accessor_reruns_the_test_gate(self):
        self.steps = [self.write_scaffold(self.accessor)]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.gates, 1)
        self.assertTrue((self.repo / "statelens/campaign/logs/test-TS-0004_simplex_a.log").is_file())
        self.assertEqual(self.line(), "TS-0004    REACHED 4/4   simplex_a_ts0004_statelens")
        self.assertIn("pub fn votes", self.read("consensus/src/simplex/voter.rs"))
        self.assertIn("## Test gate", self.report())
        # Guard 5's inventory is the campaign's log, validated and kept with B.
        self.assertEqual(self.inventory(), {"passed": list(GATE_TESTS), "failed": [],
                                        "source": "statelens/campaign/logs/test.log"})
        self.assertIn("synthesis: test inventory of 2 passed and 0 failed test(s) from "
                      "statelens/campaign/logs/test.log", self.said)

    def inventory(self):
        return json.loads(self.read("statelens/campaign/reach/baseline/tests.json"))

    def gate_failed(self, reason):
        self.assertEqual(self.line(), "TS-0004    GATE FAILED   no scaffold on simplex_a")
        self.assertIn(f"- Failed or no longer runs: {reason}", self.report())
        self.assert_restored()

    def test_a_test_the_campaign_passed_that_fails_now_restores_the_card(self):
        self.steps = [self.write_scaffold(self.accessor)]
        self.gate_passes = GATE_TESTS[:1]
        self.assertEqual(self.synthesize(), 3)
        self.gate_failed("simplex::tests::two")

    # Guard 5 fails closed: output nextest_run cannot validate is a failed gate.

    def test_a_gate_without_pass_lines_fails(self):
        # NEXTEST_STATUS_LEVEL=fail, had it reached nextest: a summary of 2 passed, no PASS.
        self.steps = [self.write_scaffold(self.accessor)]
        self.gate_runs = [(0, gate_log(GATE_TESTS, pass_lines=False))]
        self.assertEqual(self.synthesize(), 3)
        self.gate_failed("(unusable output: 0 passed and 0 failed by the status lines, 2 and 0 "
                         "by the summary)")

    def test_the_reviewed_gate_that_exited_100_fails(self):
        # The review's case, NEXTEST_STATUS_LEVEL=fail: the campaign's log has no PASS line,
        # and the card's gate fails a test and exits 100 without a PASS line either.
        self.put("statelens/campaign/logs/test.log",
                 campaign_log(gate_log(GATE_TESTS, pass_lines=False)))
        failing = (100, gate_log(GATE_TESTS[:1], GATE_TESTS[1:], pass_lines=False))
        self.steps = [self.write_scaffold(self.accessor)]
        self.gate_runs = [(0, gate_log(GATE_TESTS, pass_lines=False)), failing]
        self.assertEqual(self.synthesize(), 2, "no validated inventory, no synthesis")
        self.assertEqual(self.prompts, [])
        # With a validated inventory, the card's gate fails.
        self.gate_runs = [(0, gate_log(GATE_TESTS)), failing]
        self.assertEqual(self.synthesize(), 3)
        self.gate_failed("(unusable output: 0 passed and 1 failed by the status lines, 1 and 1 "
                         "by the summary)")

    def test_colored_output_is_parsed(self):
        self.put("statelens/campaign/logs/test.log", campaign_log(colored(gate_log(GATE_TESTS))))
        self.steps = [self.write_scaffold(self.accessor)]
        self.gate_runs = [(100, colored(gate_log(GATE_TESTS[:1], GATE_TESTS[1:])))]
        self.assertEqual(self.synthesize(), 3)
        self.assertEqual(self.gates, 1, "the colored campaign log is the inventory")
        self.gate_failed("simplex::tests::two")

    def test_a_gate_that_does_not_build_fails(self):
        self.steps = [self.write_scaffold(self.accessor)]
        self.gate_runs = [(101, "error[E0061]: this function takes 2 arguments but 1 argument "
                                "was supplied\nerror: command `cargo test --no-run` exited with "
                                "code 101\n")]
        self.assertEqual(self.synthesize(), 3)
        self.gate_failed("(unusable output: no nextest summary line)")

    def test_a_gate_that_exits_nonzero_without_a_failed_test_fails(self):
        self.steps = [self.write_scaffold(self.accessor)]
        self.gate_runs = [(100, gate_log(GATE_TESTS))]
        self.assertEqual(self.synthesize(), 3)
        self.gate_failed("(unusable output: exit code 100 with no failed test)")

    def test_an_unusable_campaign_log_is_replaced_by_one_gate_on_the_baseline(self):
        self.put("statelens/campaign/logs/test.log",
                 campaign_log(gate_log(GATE_TESTS, pass_lines=False)))
        self.steps = [self.write_scaffold(self.accessor)]
        self.gate_runs = [(0, gate_log(GATE_TESTS)),
                          (100, gate_log(GATE_TESTS[:1], GATE_TESTS[1:]))]
        self.assertEqual(self.synthesize(), 3)
        self.assertEqual(self.gates, 2)
        self.assertIn("synthesis: statelens/campaign/logs/test.log is unusable (0 passed and 0 "
                      "failed by the status lines, 2 and 0 by the summary); running the test "
                      "gate on the tree as the campaign left it", self.said)
        self.assertEqual(self.inventory(), {"passed": list(GATE_TESTS), "failed": [],
                                        "source": "statelens/campaign/logs/test-baseline.log"})
        self.gate_failed("simplex::tests::two")
        # The next synthesis loads the inventory and runs no gate for it.
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize("--redo"), 0)
        self.assertEqual(self.gates, 2)

    def test_a_campaign_log_of_another_command_is_not_the_inventory(self):
        # A log from before the gate forced its rendering.
        self.put("statelens/campaign/logs/test.log", "$ cargo nextest run\n" + gate_log(GATE_TESTS))
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.gates, 1)
        self.assertEqual(self.inventory()["source"], "statelens/campaign/logs/test-baseline.log")

    def test_an_unusable_gate_on_the_baseline_stops_synthesis(self):
        self.put("statelens/campaign/logs/test.log", "")
        self.steps = [self.write_scaffold(self.accessor)]
        self.gate_runs = [(0, gate_log(GATE_TESTS, pass_lines=False))]
        self.assertEqual(self.synthesize(), 2)
        self.assertEqual(self.prompts, [], "no agent runs")
        self.assertIn("error: the test gate's output on the tree as the campaign left it is "
                      "unusable (0 passed and 0 failed by the status lines, 2 and 0 by the "
                      "summary); see statelens/campaign/logs/test-baseline.log", self.said)
        self.assertFalse((self.repo / "statelens/campaign/reach/baseline").exists())

    def test_a_ready_campaign_whose_baseline_gate_fails_stops_synthesis(self):
        # The campaign's own gate passed every test on this tree, so a test that fails in the
        # baseline run flaked or was killed; recorded, it would excuse that test for every card.
        (self.repo / "statelens/campaign/logs/test.log").unlink()
        self.steps = [self.write_scaffold(self.accessor)]
        self.gate_runs = [(100, gate_log(GATE_TESTS[:1], GATE_TESTS[1:]))]
        self.assertEqual(self.synthesize(), 2)
        self.assertEqual(self.prompts, [], "no agent runs")
        self.assertIn("error: the campaign ended READY, but the test gate failed "
                      "simplex::tests::two on the tree it left (a flaky or killed test); see "
                      "statelens/campaign/logs/test-baseline.log and run synthesis again",
                      self.said)
        self.assertFalse((self.repo / "statelens/campaign/reach/baseline").exists())
        # The next synthesis runs the gate on the baseline again; this time it passes.
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.inventory(), {"passed": list(GATE_TESTS), "failed": [],
                                        "source": "statelens/campaign/logs/test-baseline.log"})
        self.assertEqual(self.line(), "TS-0004    REACHED 4/4   simplex_a_ts0004_statelens")
        self.assertEqual(self.gates, 3, "two baseline runs and the card's")

    def test_a_baseline_without_an_inventory_stops_synthesis(self):
        # The baseline is taken with its inventory; one taken anew from the campaign's log,
        # which an agent can rewrite, could excuse a test that no longer runs.
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize(), 0)
        (self.repo / "statelens/campaign/reach/baseline/tests.json").unlink()
        self.put("statelens/campaign/logs/test.log", campaign_log(gate_log(GATE_TESTS[:1])))
        self.assertEqual(self.synthesize(), 2)
        self.assertIn("error: the synthesis baseline has no test inventory, "
                      "statelens/campaign/reach/baseline/tests.json; use a fresh clone", self.said)
        self.assertEqual(self.gates, 0)

    def test_a_test_the_campaign_failed_may_still_fail_or_stop_running(self):
        # A campaign that ended PANIC (tests) recorded `two` failing.
        self.put("statelens/campaign/summary.txt", "statelens: result     PANIC (tests)\n")
        self.put("statelens/campaign/logs/test.log",
                 campaign_log(gate_log(GATE_TESTS[:1], GATE_TESTS[1:])))
        self.steps = [self.write_scaffold(self.accessor)]
        self.gate_runs = [(100, gate_log(GATE_TESTS[:1], GATE_TESTS[1:]))]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line(), "TS-0004    REACHED 4/4   simplex_a_ts0004_statelens")
        self.assertEqual(self.inventory()["failed"], list(GATE_TESTS[1:]))
        self.assertIn("- passed", self.report())
        # Undone with --redo: `one`, which the campaign passed, no longer runs.
        self.said.clear()
        self.steps = [self.write_scaffold(self.accessor)]
        self.gate_runs = [(100, gate_log((), GATE_TESTS[1:]))]
        self.assertEqual(self.synthesize("--redo"), 3)
        self.gate_failed("simplex::tests::one")

    def test_a_gate_failure_over_a_crash_stays_a_finding_candidate(self):
        self.steps = [self.write_scaffold(self.accessor)]
        self.gate_passes = GATE_TESTS[:1]
        self.replays["canonical"] = (77, REACHED[:3] + panicked(
            "consensus/src/simplex/voter.rs:9:9", "[statelens][INV-0001] votes counted"))
        self.assertEqual(self.synthesize(), 3)
        self.assertEqual(self.line(),
                         "TS-0004    GATE FAILED (finding candidate in attempt-0/)   no scaffold on simplex_a")
        attempt = self.repo / "statelens/campaign/reach/TS-0004_simplex_a/attempt-0"
        self.assertTrue(any((attempt / "canonical").glob("crash-*")))
        # The version that failed survives the restore, with its run and replay lines.
        self.assert_restored()
        self.assertEqual(self.read("statelens/campaign/reach/TS-0004_simplex_a.diff"), "")
        version = (attempt / "version.diff").read_text()
        self.assertIn("+++ b/consensus/fuzz/simplex/src/target_states/ts0004_simplex_a.rs", version)
        self.assertIn("+    pub fn votes(&self) -> u32 {", version)
        self.run_git("apply", "--check", str(attempt / "version.diff"))
        self.assertIn("just run simplex_a_ts0004_statelens", (attempt / "replay.txt").read_text())
        self.assertIn("apply attempt-0/version.diff (`git apply`) and add `pub mod ts0004_simplex_a;`",
                      self.report())

    def test_an_interrupt_keeps_a_failed_replay_and_its_whole_version(self):
        # The reviewed case: the canonical replay fails, the operator interrupts the control.
        blob = bytes(range(256))
        binary = "consensus/fuzz/simplex/src/target_states/ts0004.bin"

        def edits():
            self.accessor()
            (self.repo / binary).write_bytes(blob)

        self.steps = [self.write_scaffold(edits)]
        self.replays["canonical"] = (77, REACHED[:3] + panicked(
            "consensus/src/simplex/voter.rs:9:9", "[statelens][INV-0001] votes counted"))
        self.interrupt = "control"
        self.assertEqual(self.synthesize(), 130)
        self.assertEqual(self.said[-1], "interrupted")
        self.assert_restored()
        self.assertFalse((self.repo / binary).exists())
        self.assertIsNone(self.report())
        attempt = self.repo / "statelens/campaign/reach/TS-0004_simplex_a/attempt-0"
        crash = next((attempt / "canonical").glob("crash-*"))
        self.assertIn("[statelens][INV-0001] votes counted",
                      (attempt / "canonical/replay.log").read_text())
        self.assertTrue((attempt / "control/replay.log").is_file())
        # The whole version, kept before the replays: its diff applies, and its copies hold
        # every file it created or changed, the binary one the diff cannot.
        version = (attempt / "version.diff").read_text()
        self.assertIn(f"Binary files a/{binary} and b/{binary} differ", version)
        self.run_git("apply", "--check", "--exclude", binary, str(attempt / "version.diff"))
        copies = attempt / "version"
        self.assertEqual((copies / binary).read_bytes(), blob)
        self.assertEqual(
            (copies / "consensus/fuzz/simplex/src/target_states/ts0004_simplex_a.rs").read_text(),
            SCAFFOLD_MODULE)
        self.assertEqual(
            (copies / "consensus/fuzz/simplex/fuzz_targets/simplex_a_ts0004_statelens.rs")
            .read_text(), THIN)
        self.assertIn("pub fn votes", (copies / "consensus/src/simplex/voter.rs").read_text())
        self.assertIn('name = "simplex_a_ts0004_statelens"', (copies / sl.FUZZ_MANIFEST).read_text())
        self.assertFalse((copies / "consensus/fuzz/simplex/src/lib.rs").exists(), "unchanged")
        note = (attempt / "interrupted.txt").read_text()
        self.assertIn("TS-0004 on simplex_a attempt 0: synthesis stopped during the control replay (an "
                      "interrupt), and the pair's edits were restored", note)
        self.assertIn("add `pub mod ts0004_simplex_a;` to target_states/mod.rs first", note)
        self.assertIn("The canonical replay exited with code 77, a failure", note)
        self.assertIn(f"just run simplex_a_ts0004_statelens {crash}\n", note)
        self.assertNotIn("STATELENS_REACH_CONTROL", note)
        self.assertIn("TS-0004_simplex_a: stopped during the control replay; see "
                      "statelens/campaign/reach/TS-0004_simplex_a/attempt-0/interrupted.txt", self.said)
        # The next synthesis moves the attempts aside, never deleting them, and runs again.
        self.interrupt = None
        self.replays["canonical"] = (0, REACHED)
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line(), "TS-0004    REACHED 4/4   simplex_a_ts0004_statelens")
        reach = self.repo / "statelens/campaign/reach"
        aside = [path for path in reach.glob("TS-0004_simplex_a.*") if path.is_dir()]
        self.assertEqual(len(aside), 1)
        self.assertTrue(any((aside[0] / "attempt-0/canonical").glob("crash-*")))
        self.assertEqual((aside[0] / "attempt-0/version" / binary).read_bytes(), blob)
        # Its note names the crash file where it now is.
        moved = aside[0] / "attempt-0/canonical" / crash.name
        self.assertIn(f"just run simplex_a_ts0004_statelens {moved}\n",
                      (aside[0] / "attempt-0/interrupted.txt").read_text())

    def test_an_interrupted_agent_run_keeps_what_its_scaffold_left(self):
        def step():
            self.scaffold()
            self.put("crash-0123", "input")
            raise KeyboardInterrupt

        self.steps = [step]
        self.assertEqual(self.synthesize(), 130)
        self.assert_restored()
        self.assertFalse((self.repo / "statelens/campaign/reach/pending").exists())
        self.assertFalse((self.repo / "crash-0123").exists())
        attempt = self.repo / "statelens/campaign/reach/TS-0004_simplex_a/attempt-0"
        self.assertEqual((attempt / "swept/crash-0123").read_text(), "input")
        self.assertIn("+++ b/consensus/fuzz/simplex/src/target_states/ts0004_simplex_a.rs",
                      (attempt / "version.diff").read_text())
        self.assertEqual(
            (attempt / "version/consensus/fuzz/simplex/src/target_states/ts0004_simplex_a.rs").read_text(),
            SCAFFOLD_MODULE)
        note = (attempt / "interrupted.txt").read_text()
        self.assertIn("synthesis stopped during the agent's run (an interrupt)", note)
        self.assertIn("Stray failure (finding candidate): "
                      "statelens/campaign/reach/TS-0004_simplex_a/attempt-0/swept/crash-0123", note)
        # Nothing is left in the tree to stop the next synthesis.
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line(), "TS-0004    REACHED 4/4   simplex_a_ts0004_statelens")

    def assert_stray_version_kept(self, *strays):
        """After an interrupt during the sweep: the pair's edits restored, the stray failures
        in swept/, the version they came from kept, and the note naming each."""
        self.assert_restored()
        attempt = self.repo / "statelens/campaign/reach/TS-0004_simplex_a/attempt-0"
        for name in strays:
            self.assertFalse((self.repo / name).exists())
            self.assertEqual((attempt / "swept" / name).read_text(), "input")
        self.assertTrue((attempt / "version.diff").is_file(), "the version is kept")
        self.run_git("apply", "--check", str(attempt / "version.diff"))
        self.assertEqual(
            (attempt / "version/consensus/fuzz/simplex/src/target_states/ts0004_simplex_a.rs").read_text(),
            SCAFFOLD_MODULE)
        note = (attempt / "interrupted.txt").read_text()
        self.assertIn("synthesis stopped during the agent's run (an interrupt)", note)
        self.assertIn("add `pub mod ts0004_simplex_a;` to target_states/mod.rs first", note)
        self.assertNotIn("No version was kept", note)
        for name in strays:
            self.assertIn(
                f"Stray failure (finding candidate): {self.rel(attempt)}/swept/{name}\n", note)

    def test_an_interrupt_after_the_sweep_moved_a_stray_failure_keeps_its_version(self):
        # The reviewed case, with a second stray failure: the operator interrupts the sweep
        # right after its first move, so the failure is in swept/ and no longer in the tree.
        def say(message):
            self.said.append(message)
            if message.startswith("warning: a run of the scaffold left crash-0123;"):
                sl.say = self.said.append
                raise KeyboardInterrupt

        def edits():
            self.put("crash-0123", "input")
            self.put("timeout-0456", "input")

        sl.say = say
        self.steps = [self.write_scaffold(edits)]
        self.assertEqual(self.synthesize(), 130)
        self.assert_stray_version_kept("crash-0123", "timeout-0456")

    def test_an_interrupt_after_the_sweep_returned_keeps_the_version(self):
        sweep = sl.Synthesis.sweep
        self.addCleanup(setattr, sl.Synthesis, "sweep", sweep)

        def interrupted(synthesis, *args):
            sl.Synthesis.sweep = sweep
            sweep(synthesis, *args)
            raise KeyboardInterrupt

        sl.Synthesis.sweep = interrupted
        self.steps = [self.write_scaffold(lambda: self.put("crash-0123", "input"))]
        self.assertEqual(self.synthesize(), 130)
        self.assert_stray_version_kept("crash-0123")

    def test_an_interrupted_finish_names_a_later_attempts_stray_failure(self):
        # Attempt 0 is kept, UNVERIFIED; attempt 1 fails and leaves a stray failure; the
        # operator interrupts the kept version's final replay.
        module = SCAFFOLD_MODULE.replace("//! Control: withholds E3\n", "")

        def second():
            self.put("crash-0123", "input")
            return 1

        self.steps = [lambda: self.scaffold(module=module), second]
        self.interrupt = "final"
        self.assertEqual(self.synthesize(), 130)
        self.assert_restored()
        reach = self.repo / "statelens/campaign/reach/TS-0004_simplex_a"
        note = (reach / "attempt-0/interrupted.txt").read_text()
        self.assertIn("synthesis stopped during the final replay (an interrupt)", note)
        self.assertIn(f"Stray failure (finding candidate): {self.rel(reach)}/attempt-1/swept/"
                      "crash-0123\n", note)

    def killed(self):
        """Copies the checkout, then interrupts: `revive` puts the copy back, the disk as a
        synthesis killed at this point leaves it, without its cleanup."""
        self.copy = pathlib.Path(tempfile.mkdtemp()) / "repo"
        self.addCleanup(shutil.rmtree, self.copy.parent, True)
        shutil.copytree(self.repo, self.copy, symlinks=True)
        raise KeyboardInterrupt

    def revive(self):
        shutil.rmtree(self.repo)
        shutil.copytree(self.copy, self.repo, symlinks=True)

    def test_a_synthesis_killed_during_the_agents_run_is_undone_by_the_next(self):
        def step():
            self.scaffold()
            self.accessor()
            self.killed()

        self.steps = [step]
        self.assertEqual(self.synthesize(), 130)
        self.revive()
        self.assertIn("pub fn votes", self.read("consensus/src/simplex/voter.rs"))
        # The snapshot names the pair, so the next synthesis knows which module to drop.
        state = json.loads(self.read("statelens/campaign/reach/pending/state.json"))
        self.assertEqual(state["pair"], "TS-0004_simplex_a")
        # The next synthesis restores the tree before the pair; the accessor, which would
        # have been part of the pair's S0, is gone, and the pair runs again.
        self.said.clear()
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize(), 0)
        self.assertIn("warning: TS-0004_simplex_a: a synthesis stopped without restoring the pair's "
                      "edits; they were restored", self.said)
        self.assertEqual(self.line(), "TS-0004    REACHED 4/4   simplex_a_ts0004_statelens")
        self.assertEqual(self.read("consensus/src/simplex/voter.rs"), VOTER)
        self.assertNotIn("voter.rs", self.read("statelens/campaign/reach/TS-0004_simplex_a.diff"))
        self.assertFalse((self.repo / "statelens/campaign/reach/pending").exists())

    def test_a_synthesis_killed_during_a_build_leaves_no_scaffold(self):
        # Killed after step 2.5 added the scaffold's [[bin]] block: the next synthesis must
        # neither keep that block, which a second one would duplicate, nor hand it over.
        def compiles(scaffold):
            if not hasattr(self, "copy"):
                self.killed()
            return True

        self.compiles = compiles
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize(), 130)
        self.revive()
        self.assertIn("simplex_a_ts0004_statelens", self.read(sl.FUZZ_MANIFEST))
        self.said.clear()
        self.steps = [lambda: 1, self.second_card()]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line("TS-0004"), "TS-0004    NOT BUILT   no scaffold on simplex_a")
        self.assertEqual(self.line("TS-0005"),
                         "TS-0005    REACHED 4/4   simplex_a_ts0005_statelens")
        self.assert_restored()
        self.assertEqual([line for line in self.said if line.startswith("run ")],
                         [f"run        cd {self.repo / 'statelens'} && NIGHTLY_VERSION="
                          f"nightly-test just run {self.SECOND}"])
        # The killed card builds once more: its block is not added twice.
        self.said.clear()
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize("--redo", "--match", "TS-0004"), 0)
        self.assertEqual(self.line("TS-0004"),
                         "TS-0004    REACHED 4/4   simplex_a_ts0004_statelens")
        self.assertEqual(self.read(sl.FUZZ_MANIFEST).count('name = "simplex_a_ts0004_statelens"'),
                         1)

    def test_an_unreadable_pending_snapshot_stops_synthesis(self):
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize(), 0)
        # A path outside the scope, a key that names a card but no base, and no JSON at all.
        for state in ('{"pair": "TS-0004_simplex_a", "files": ["../outside"]}',
                      '{"pair": "TS-0004", "files": []}', "{"):
            self.put("statelens/campaign/reach/pending/state.json", state)
            self.assertEqual(self.synthesize(), 2)
            self.assertIn("use a fresh clone", self.said[-1])
            self.assertTrue(self.said[-1].startswith(
                "error: statelens/campaign/reach/pending is unreadable ("))
        # A card with a report ended: its pending/ is only deleted.
        self.put("statelens/campaign/reach/pending/state.json",
                 '{"pair": "TS-0004_simplex_a", "files": []}')
        self.said.clear()
        self.assertEqual(self.synthesize(), 0)
        self.assertFalse((self.repo / "statelens/campaign/reach/pending").exists())
        self.assertEqual(self.line(), "TS-0004    skipped: TS-0004 on simplex_a was synthesized as "
                                      "simplex_a_ts0004_statelens; use --redo")

    def test_an_interrupted_test_gate_keeps_the_kept_crash(self):
        self.steps = [self.write_scaffold(self.accessor)]
        self.replays["canonical"] = (77, REACHED[:3] + panicked(
            "consensus/src/simplex/voter.rs:9:9", "[statelens][INV-0001] votes counted"))
        self.interrupt = "gate"
        self.assertEqual(self.synthesize(), 130)
        self.assert_restored()
        attempt = self.repo / "statelens/campaign/reach/TS-0004_simplex_a/attempt-0"
        self.assertIn("just run simplex_a_ts0004_statelens", (attempt / "replay.txt").read_text())
        self.assertTrue(any((attempt / "final").glob("crash-*")))
        self.run_git("apply", "--check", str(attempt / "version.diff"))
        note = (attempt / "interrupted.txt").read_text()
        self.assertIn("synthesis stopped during the test gate (an interrupt)", note)
        self.assertIn("The canonical replay exited with code 77, a failure", note)
        self.assertIn("The control replay exited with code 0; its log is control/replay.log.", note)
        self.assertIn("The final replay exited with code 77, a failure", note)
        final = next((attempt / "final").glob("crash-*"))
        self.assertIn(f"just run simplex_a_ts0004_statelens {final}\n", note)

    def test_an_interrupt_after_a_replay_left_a_crash_file_names_it(self):
        # The operator interrupts while libFuzzer prints the crash report of a crash file it
        # already wrote: the replay never returned, and its failure is in the note anyway.
        for replay in ("canonical", "control"):
            with self.subTest(replay):
                self.steps = [self.write_scaffold()]
                self.interrupt, self.interrupt_crash = replay, True
                self.assertEqual(self.synthesize(), 130)
                self.assert_restored()
                attempt = self.repo / "statelens/campaign/reach/TS-0004_simplex_a/attempt-0"
                crash = next((attempt / replay).glob("crash-*"))
                note = (attempt / "interrupted.txt").read_text()
                self.assertIn(f"synthesis stopped during the {replay} replay (an interrupt)", note)
                self.assertIn(f"The {replay} replay stopped after it left {crash.name}, a failure; "
                              f"its log and the crash file are in {replay}/. Its run and replay "
                              "lines:", note)
                self.assertIn(f"just run simplex_a_ts0004_statelens {crash}\n", note)
                self.assertEqual("STATELENS_REACH_CONTROL=1" in note, replay == "control")
                # The version is kept before the canonical replay.
                self.run_git("apply", "--check", str(attempt / "version.diff"))

    def test_an_interrupted_revalidation_names_what_it_left(self):
        # TS-0005_simplex_a's accessor makes TS-0004_simplex_a's scaffold crash; the operator interrupts the
        # revalidation's control replay.
        crash = (77, REACHED[:3] + panicked(
            "consensus/src/simplex/voter.rs:9:9", "[statelens][INV-0001] votes counted"))
        after = ("TS-0004_simplex_a", "after-TS-0005_simplex_a")
        self.replay_for = lambda key, tag, name: (
            crash if (key, tag, name) == after + ("canonical",) else None)
        self.interrupt = after + ("control",)
        self.steps = [self.write_scaffold(), self.second_card(lambda: self.accessor("TS-0005"))]
        self.assertEqual(self.synthesize(), 130)
        self.assertEqual(self.read("consensus/src/simplex/voter.rs"), VOTER)
        self.assertIsNone(self.read("consensus/fuzz/simplex/src/target_states/ts0005_simplex_a.rs"))
        self.assertNotIn("Revalidation", self.report("TS-0004_simplex_a"))
        reach = "statelens/campaign/reach"
        left = next((self.repo / reach / "TS-0004_simplex_a/after-TS-0005_simplex_a/canonical").glob("crash-*"))
        note = self.read(f"{reach}/TS-0005_simplex_a/attempt-0/interrupted.txt")
        self.assertIn("synthesis stopped during the revalidation of TS-0004_simplex_a (an interrupt)", note)
        self.assertIn(f"It stopped while revalidating TS-0004_simplex_a, whose replays are in "
                      f"{reach}/TS-0004_simplex_a/after-TS-0005_simplex_a/.", note)
        self.assertIn(f"That revalidation left {reach}/TS-0004_simplex_a/after-TS-0005_simplex_a/canonical/"
                      f"{left.name}, a failure of TS-0004_simplex_a's scaffold.", note)
        self.run_git("apply", "--check", str(self.repo / reach / "TS-0005_simplex_a/attempt-0/version.diff"))

    def test_an_edit_beside_an_assertion_is_annotated(self):
        # Guard 3 sees the assertion unchanged; review sees the edit around it.
        assertion = '        sl_assert!(None, "INV-0001", self.votes > 0, "votes counted");\n'
        self.steps = [self.write_scaffold(lambda: self.edit(
            "consensus/src/simplex/voter.rs", assertion,
            f"        if false {{ {MARKER}\n{assertion}        }}\n"))]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line(), "TS-0004    REACHED 4/4 (edit beside instrumentation)   "
                                      "simplex_a_ts0004_statelens")
        self.assertIn("edit beside instrumentation: consensus/src/simplex/voter.rs @@",
                      self.report())

    def test_the_guards_hold_what_they_compare_against_in_memory(self):
        # SL/campaign/ is ignored, so an agent can rewrite B there and the instrumentation
        # diff; neither changes what the guards compare against.
        assertion = '        sl_assert!(None, "INV-0001", self.votes > 0, "votes counted");\n'

        def tamper():
            self.drop_assertion()
            copy = "statelens/campaign/reach/baseline/files/consensus/src/simplex/voter.rs"
            self.put(copy, self.read(copy).replace(assertion, ""))
            diff = "statelens/campaign/instrumentation.diff"
            self.put(diff, self.read(diff).replace("+" + assertion, ""))

        self.steps = [self.write_scaffold(tamper)]
        self.assertEqual(self.synthesize(), 3)
        self.assertIn("removed sl_assert!", self.feedback(1))
        self.assertEqual(self.builds, [])
        self.assert_restored()

    def test_records_an_agent_changes_are_written_back_for_the_next_synthesis(self):
        voter = "statelens/campaign/reach/baseline/files/consensus/src/simplex/voter.rs"
        tests = "statelens/campaign/reach/baseline/tests.json"
        diff = "statelens/campaign/instrumentation.diff"
        ghost = ("        crate::simplex::statelens::with_ghost(|ghost| ghost.votes += 1); "
                 "// [statelens]\n")
        printed = f'        eprintln!("[statelens-reach] x"); {MARKER}\n'
        kept = {}

        def tamper():
            # Each change would let the next synthesis accept one edit below.
            kept.update((path, self.read(path)) for path in (voter, tests, diff))
            self.put(voter, VOTER.replace(ghost, ghost + printed))
            self.put(tests, json.dumps({"passed": list(GATE_TESTS[:1]),
                                        "failed": list(GATE_TESTS[1:]), "source": "x"}))
            self.put(diff, kept[diff].replace("+" + ghost, ""))

        def interrupted():
            self.put(tests, "{}")
            raise KeyboardInterrupt

        self.steps = [self.write_scaffold(tamper)]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line(), "TS-0004    REACHED 4/4   simplex_a_ts0004_statelens")
        for path in (voter, tests, diff):
            self.assertEqual(self.read(path), kept[path])
            self.assertIn(f"warning: the agent changed {path}; it was written back", self.said)
        # Each later synthesis compares with the records as the campaign left them.
        for edit, veto in (
            (lambda: self.edit("consensus/src/simplex/voter.rs", ghost, ""),
             "guard 3: consensus/src/simplex/voter.rs lost 1 line(s) the campaign added"),
            (lambda: self.edit("consensus/src/simplex/voter.rs", ghost, ghost + printed),
             "guard 3: consensus/src/simplex/voter.rs holds the literal [statelens-reach]"),
        ):
            self.said.clear()
            self.steps = [self.write_scaffold(edit)]
            self.assertEqual(self.synthesize("--redo"), 3)
            self.assertEqual(self.line(), "TS-0004    NOT BUILT   no scaffold on simplex_a")
            self.assertIn(veto, self.report())
            self.assert_restored()
        self.said.clear()
        self.steps = [self.write_scaffold(self.accessor)]
        self.gate_passes = GATE_TESTS[:1]
        self.assertEqual(self.synthesize("--redo"), 3)
        self.gate_failed("simplex::tests::two")
        # An interrupted run of the agent too.
        self.steps = [interrupted]
        self.assertEqual(self.synthesize("--redo"), 130)
        self.assertEqual(self.read(tests), kept[tests])

    def test_records_a_scaffold_changes_after_the_last_agent_run_are_written_back(self):
        # The final replay runs code the agent wrote after the agent's last run.
        tests = "statelens/campaign/reach/baseline/tests.json"
        kept = []

        def replay_for(_card, _tag, name):
            if name == "final" and not kept:
                kept.append(self.read(tests))
                self.put(tests, json.dumps({"passed": list(GATE_TESTS[:1]),
                                            "failed": list(GATE_TESTS[1:]), "source": "x"}))

        self.replay_for = replay_for
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.read(tests), kept[0])
        self.assertIn(f"warning: the agent changed {tests}; it was written back", self.said)
        self.said.clear()
        self.replay_for = lambda _key, _tag, _name: None
        self.steps = [self.write_scaffold(self.accessor)]
        self.gate_passes = GATE_TESTS[:1]
        self.assertEqual(self.synthesize("--redo"), 3)
        self.gate_failed("simplex::tests::two")

    def test_a_rewritten_test_log_or_input_changes_no_gate_or_replay(self):
        def tamper():
            self.accessor()
            self.put("statelens/campaign/logs/test.log", "")
            self.put("statelens/campaign/reach/empty", "input")

        self.steps = [self.write_scaffold(tamper)]
        self.gate_passes = GATE_TESTS[:1]
        self.assertEqual(self.synthesize(), 3)
        self.assertEqual(self.line(), "TS-0004    GATE FAILED   no scaffold on simplex_a")

    def test_an_ignored_rust_file_is_vetoed_and_removed(self):
        ignored = "consensus/src/simplex/target/mod.rs"
        self.steps = [self.write_scaffold(lambda: self.put(ignored, "pub fn f() {}\n"))]
        self.assertEqual(self.synthesize(), 3)
        self.assertIn(f"guard 3: git ignores {ignored}", self.feedback(1))
        self.assertEqual(self.builds, [])
        self.assert_restored()
        self.assertIsNone(self.read(ignored))
        # One left behind stops the next synthesis before any pair.
        self.put(ignored, "pub fn f() {}\n")
        self.assertEqual(self.synthesize("--redo"), 2)
        self.assertIn(f"the checkout differs from the synthesis baseline: {ignored}",
                      "\n".join(self.said))

    def test_a_stray_failure_beside_a_kept_version_is_on_the_console(self):
        module = SCAFFOLD_MODULE.replace("//! Control: withholds E3\n", "")

        def second():
            self.put("crash-0123", "input")
            self.edit("consensus/fuzz/simplex/src/target_states/ts0004_simplex_a.rs", "let _ = input;",
                      "statelens::tick();")

        self.steps = [lambda: self.scaffold(module=module), second]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(len(self.prompts), 2, "a stray failure stops refinement")
        swept = "statelens/campaign/reach/TS-0004_simplex_a/attempt-1/swept/crash-0123"
        self.assertEqual(self.line(), "TS-0004    UNVERIFIED 4/4 (control missing, stray failure)"
                                      "   simplex_a_ts0004_statelens; a run of the agent's left "
                                      f"{swept}, a finding candidate")
        version = self.repo / "statelens/campaign/reach/TS-0004_simplex_a/attempt-1/version.diff"
        self.assertIn("statelens::tick();", version.read_text())

    def test_an_unmarked_hunk_is_annotated(self):
        self.steps = [self.write_scaffold(lambda: self.edit(
            "consensus/fuzz/simplex/src/lib.rs", "pub fn fuzz() {}",
            "pub fn fuzz() {}\n\npub fn x() {}"))]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line(),
                         "TS-0004    REACHED 4/4 (unmarked edit)   simplex_a_ts0004_statelens")
        self.assertIn("unmarked edit: consensus/fuzz/simplex/src/lib.rs @@", self.report())

    def test_a_scaffold_that_never_builds_is_not_built(self):
        self.build_fails = True
        self.steps = [self.write_scaffold()] + [self.touch_module(n) for n in ("a", "b", "c")]
        self.assertEqual(self.synthesize(), 3)
        self.assertEqual(len(self.prompts), 4, "attempts 0 to 3")
        self.assertEqual(len(self.builds), 4)
        self.assertIn("The build failed: cargo +nightly-test fuzz build --fuzz-dir "
                      "consensus/fuzz/simplex simplex_a_ts0004_statelens", self.feedback(3))
        self.assertIn("    error[E0425]: cannot find value `x`", self.feedback(3))
        self.assertIn("- attempt 2: NOT BUILT (build failed)", self.feedback(3))
        self.assertEqual(self.line(), "TS-0004    NOT BUILT   no scaffold on simplex_a")
        self.assert_restored()
        self.assertTrue((self.repo / "consensus/fuzz/simplex/fuzz_targets/simplex_a_statelens.rs")
                        .is_file(), "the variants are untouched")

    def test_a_failed_agent_run_is_a_failed_attempt_and_the_next_card_runs(self):
        self.put("statelens/target-states/simplex/TS-0005.md", state_card("TS-0005"))

        def second():
            self.put("consensus/fuzz/simplex/src/target_states/ts0005_simplex_a.rs",
                     SCAFFOLD_MODULE.replace("TS-0004", "TS-0005"))
            self.put("consensus/fuzz/simplex/fuzz_targets/simplex_a_ts0005_statelens.rs",
                     THIN.replace("ts0004", "ts0005"))

        self.steps = [lambda: 1, second]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line("TS-0004"), "TS-0004    NOT BUILT   no scaffold on simplex_a")
        self.assertIn("- attempt 0: NOT BUILT (the agent failed)", self.report("TS-0004_simplex_a"))
        self.assertEqual(self.line("TS-0005"),
                         "TS-0005    REACHED 4/4   simplex_a_ts0005_statelens")
        helper = self.read("consensus/fuzz/simplex/src/target_states/mod.rs")
        self.assertIn("pub mod ts0005_simplex_a;", helper)
        self.assertNotIn("pub mod ts0004_simplex_a;", helper)

    # Revalidation: a later pair's edits to shared code rebuild and replay the earlier
    # scaffolds, and a card that breaks one is rolled back.

    FIRST = "simplex_a_ts0004_statelens"
    SECOND = "simplex_a_ts0005_statelens"
    FIRST_MODULE = "consensus/fuzz/simplex/src/target_states/ts0004_simplex_a.rs"
    SECOND_MODULE = "consensus/fuzz/simplex/src/target_states/ts0005_simplex_a.rs"
    ROLLED_BACK = "TS-0005    NOT BUILT (breaks TS-0004_simplex_a)   no scaffold on simplex_a"

    def second_card(self, then=None):
        """Adds card TS-0005; returns an agent step that writes its valid scaffold, then makes
        the edit `then`."""
        self.put("statelens/target-states/simplex/TS-0005.md", state_card("TS-0005"))

        def step():
            self.put(self.SECOND_MODULE, SCAFFOLD_MODULE.replace("TS-0004", "TS-0005"))
            self.put(f"consensus/fuzz/simplex/fuzz_targets/{self.SECOND}.rs",
                     THIN.replace("ts0004", "ts0005"))
            if then:
                then()
        return step

    def assert_second_restored(self):
        self.assertIsNone(self.read("consensus/fuzz/simplex/src/target_states/ts0005_simplex_a.rs"))
        self.assertIsNone(self.read(f"consensus/fuzz/simplex/fuzz_targets/{self.SECOND}.rs"))
        self.assertNotIn("ts0005", self.read(sl.FUZZ_MANIFEST))
        helper = self.read("consensus/fuzz/simplex/src/target_states/mod.rs")
        self.assertNotIn("pub mod ts0005_simplex_a;", helper)
        self.assertIn("pub mod ts0004_simplex_a;", helper)
        self.assertEqual(self.read("statelens/campaign/reach/TS-0005_simplex_a.diff"), "")

    def test_a_card_that_breaks_an_earlier_scaffold_is_rolled_back(self):
        # The review's case: the second card changes the first scaffold's fuzz signature. The
        # second builds, but the first thin target, which passes one argument, does not.
        def signature():
            self.edit(self.FIRST_MODULE, "(input: crate::FuzzInput)",
                      "(input: crate::FuzzInput, extra: u8)")

        self.steps = [self.write_scaffold(), self.second_card(signature)]
        self.compiles = lambda scaffold: (
            scaffold != self.FIRST or "extra: u8" not in self.read(self.FIRST_MODULE))
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line("TS-0004"), "TS-0004    REACHED 4/4   " + self.FIRST)
        self.assertEqual(self.line("TS-0005"), self.ROLLED_BACK)
        # Built: TS-0004 twice, TS-0005 twice, TS-0004 with TS-0005_simplex_a's edits (which fails) and
        # without them, and the last check's build of the one scaffold left.
        self.assertEqual(self.builds, [self.FIRST] * 2 + [self.SECOND] * 2 + [self.FIRST] * 3)
        logs = "statelens/campaign/logs"
        report = self.report("TS-0005_simplex_a")
        self.assertIn(f"- Note: TS-0004_simplex_a's scaffold {self.FIRST} no longer builds; see "
                      f"{logs}/fuzz-build-{self.FIRST}-after-TS-0005_simplex_a.log, so the pair's edits "
                      "were restored; the version is attempt-0/version.diff", report)
        self.assertIn("error[E0061]",
                      self.read(f"{logs}/fuzz-build-{self.FIRST}-after-TS-0005_simplex_a.log"))
        self.assertIn("- Note: TS-0004_simplex_a with the pair's edits restored: REACHED 4/4", report)
        self.assertEqual(self.read(self.FIRST_MODULE), SCAFFOLD_MODULE)
        self.assert_second_restored()
        reach = self.repo / "statelens/campaign/reach"
        self.assertTrue((reach / "TS-0004_simplex_a/without-TS-0005_simplex_a/canonical/replay.log").is_file())
        version = (reach / "TS-0005_simplex_a/attempt-0/version.diff").read_text()
        self.assertIn("+pub fn fuzz<P, D, C>(input: crate::FuzzInput, extra: u8) {", version)
        # The first card's report is the one its own synthesis wrote.
        first = self.report("TS-0004_simplex_a")
        self.assertIn("- Verdict: REACHED 4/4\n", first)
        self.assertNotIn("Revalidation", first)

    def test_a_card_that_changes_shared_code_revalidates_the_earlier_scaffolds(self):
        # TS-0004 is synthesized first; a later synthesis gives TS-0005 a marked accessor
        # under the editable roots, which keeps TS-0004 REACHED.
        step = self.second_card(lambda: self.accessor("TS-0005"))
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize("--match", "TS-0004"), 0)
        before = self.report("TS-0004_simplex_a")
        self.builds.clear()
        self.steps = [step]
        self.assertEqual(self.synthesize("--match", "TS-0005"), 0)
        self.assertEqual(self.line("TS-0005"), "TS-0005    REACHED 4/4   " + self.SECOND)
        self.assertEqual(self.gates, 1)
        self.assertEqual(self.builds, [self.SECOND] * 2 + [self.FIRST, self.FIRST, self.SECOND])
        self.assertIn("pub fn votes", self.read("consensus/src/simplex/voter.rs"))
        reach = self.repo / "statelens/campaign/reach"
        for replay in ("canonical", "control", "final"):
            self.assertTrue((reach / "TS-0004_simplex_a/after-TS-0005_simplex_a" / replay / "replay.log").is_file())
        report = self.report("TS-0004_simplex_a")
        self.assertTrue(report.startswith(before))
        changed = f"{self.SECOND_MODULE}, consensus/src/simplex/voter.rs"
        self.assertTrue(report.endswith(
            "\n## Revalidation after TS-0005_simplex_a\n\n"
            f"- Cause: TS-0005_simplex_a changed {changed}\n"
            "- Before: REACHED 4/4\n- Now: REACHED 4/4\n"
            "- Replays: statelens/campaign/reach/TS-0004_simplex_a/after-TS-0005_simplex_a/\n"), report)
        self.assertIn(f"- Note: revalidated TS-0004_simplex_a: the kept version changed {changed}",
                      self.report("TS-0005_simplex_a"))
        self.assertIn(f"TS-0005_simplex_a: the kept version changed {changed}; revalidating TS-0004_simplex_a",
                      self.said)
        # The record a restore of TS-0005_simplex_a's edits would have owed went with its report.
        self.assertIsNone(self.read(self.OWED))

    def test_a_card_that_touches_only_its_own_files_revalidates_the_earlier_scaffolds_too(self):
        # The modules are public siblings of one crate, so TS-0005_simplex_a's module may use TS-0004_simplex_a's
        # or the other way round: TS-0005_simplex_a's own module counts as shared code, its thin
        # target, a crate of its own, does not.
        self.steps = [self.write_scaffold(), self.second_card()]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line("TS-0005"), "TS-0005    REACHED 4/4   " + self.SECOND)
        self.assertEqual(self.builds, [self.FIRST] * 2 + [self.SECOND] * 2
                         + [self.FIRST, self.FIRST, self.SECOND])
        self.assertTrue((self.repo / "statelens/campaign/reach/TS-0004_simplex_a/after-TS-0005_simplex_a").is_dir())
        self.assertIn(f"TS-0005_simplex_a: the kept version changed {self.SECOND_MODULE}; revalidating "
                      "TS-0004_simplex_a", self.said)
        self.assertEqual(self.section(self.report("TS-0004_simplex_a"), "Revalidation after TS-0005_simplex_a"),
                         f"- Cause: TS-0005_simplex_a changed {self.SECOND_MODULE}\n"
                         "- Before: REACHED 4/4\n- Now: REACHED 4/4\n"
                         "- Replays: statelens/campaign/reach/TS-0004_simplex_a/after-TS-0005_simplex_a/\n")

    def test_a_redo_whose_module_changes_a_helper_a_sibling_uses_revalidates_it(self):
        # The review's case: TS-0005_simplex_a's module calls a helper of TS-0004_simplex_a's module, and a
        # --redo of TS-0004 gives that helper another value, which makes TS-0005 PARTIAL.
        # TS-0005 is replayed after the undo and again with the new version, which is
        # rolled back; its REACHED stands on a tree without TS-0004_simplex_a's helper.
        def first(value):
            return lambda: self.scaffold(
                module=SCAFFOLD_MODULE + f"\npub fn limit() -> u8 {{ {value} }}\n")

        def dependent():
            self.put(self.SECOND_MODULE, self.read(self.SECOND_MODULE)
                     + "\npub fn limit() -> u8 { super::ts0004_simplex_a::limit() }\n")

        self.replay_for = lambda key, _tag, name: (
            self.PARTIAL if key == "TS-0005_simplex_a" and name != "control"
            and "limit() -> u8 { 0 }" in (self.read(self.FIRST_MODULE) or "") else None)
        self.steps = [first(1), self.second_card(dependent)]
        self.assertEqual(self.synthesize(), 0)
        self.assertIn("- Verdict: REACHED 4/4\n", self.report("TS-0005_simplex_a"))
        self.said.clear()
        self.builds.clear()
        self.steps = [first(0)]
        self.assertEqual(self.synthesize("--redo", "--match", "TS-0004"), 3)
        self.assertIn(f"synthesis: --redo undid TS-0004_simplex_a, which changed {self.FIRST_MODULE}; "
                      "revalidating TS-0005_simplex_a", self.said)
        self.assertEqual(self.line("TS-0004"),
                         "TS-0004    NOT BUILT (breaks TS-0005_simplex_a)   no scaffold on simplex_a")
        self.assertIn(f"- Note: TS-0005_simplex_a's scaffold {self.SECOND} went from REACHED 4/4 to "
                      "PARTIAL 1/4; see statelens/campaign/reach/TS-0005_simplex_a/after-TS-0004_simplex_a/, so the "
                      "pair's edits were restored", self.report("TS-0004_simplex_a"))
        self.assertIsNone(self.read(self.FIRST_MODULE))
        self.assertIn("- Verdict: REACHED 4/4\n", self.report("TS-0005_simplex_a"))
        # TS-0005 after the undo, TS-0004 twice, TS-0005 with and without TS-0004_simplex_a's new
        # version, and the last check's build of TS-0005.
        self.assertEqual(self.builds, [self.SECOND] + [self.FIRST] * 2 + [self.SECOND] * 3)

    def worsened_by_an_accessor(self, replay):
        """TS-0005 adds a marked accessor; while it is in the tree, TS-0004_simplex_a's canonical and
        final replays print `replay`. Returns TS-0005_simplex_a's report."""
        def replay_for(key, _tag, name):
            if key == "TS-0004_simplex_a" and name != "control" and "pub fn votes" in self.read(
                    "consensus/src/simplex/voter.rs"):
                return replay
            return None

        self.steps = [self.write_scaffold(), self.second_card(lambda: self.accessor("TS-0005"))]
        self.replay_for = replay_for
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line("TS-0004"), "TS-0004    REACHED 4/4   " + self.FIRST)
        self.assertEqual(self.line("TS-0005"), self.ROLLED_BACK)
        self.assertEqual(self.read("consensus/src/simplex/voter.rs"), VOTER)
        self.assert_second_restored()
        self.assertNotIn("Revalidation", self.report("TS-0004_simplex_a"))
        report = self.report("TS-0005_simplex_a")
        self.assertIn("- Note: TS-0004_simplex_a with the pair's edits restored: REACHED 4/4", report)
        self.assertIn("## Test gate", report, "the gate passed before the revalidation")
        return report

    def test_a_card_that_makes_an_earlier_verdict_worse_is_rolled_back(self):
        partial = (
            "phase prefix",
            REACHED[1],
            "E2/4 missed no nullify vote of R for v by the deadline",
            "handoff lost mark=6 next=-",
            "phase continuation",
            "reach 1/4 control=0",
            "done",
        )
        report = self.worsened_by_an_accessor((0, partial))
        self.assertIn(f"- Note: TS-0004_simplex_a's scaffold {self.FIRST} went from REACHED 4/4 to PARTIAL "
                      "1/4; see statelens/campaign/reach/TS-0004_simplex_a/after-TS-0005_simplex_a/, so the pair's "
                      "edits were restored", report)

    def test_a_card_that_makes_an_earlier_scaffold_crash_is_rolled_back(self):
        crash = (77, REACHED[:3] + panicked(
            "consensus/src/simplex/voter.rs:9:9", "[statelens][INV-0001] votes counted"))
        report = self.worsened_by_an_accessor(crash)
        self.assertIn(f"- Note: TS-0004_simplex_a's scaffold {self.FIRST} went from REACHED 4/4 to CRASH "
                      "(finding candidate); see statelens/campaign/reach/TS-0004_simplex_a/after-TS-0005_simplex_a/",
                      report)
        after = self.repo / "statelens/campaign/reach/TS-0004_simplex_a/after-TS-0005_simplex_a"
        self.assertTrue(any((after / "canonical").glob("crash-*")), "the crash file is kept")

    def test_an_earlier_revalidation_directory_stays_where_reports_name_it(self):
        # TS-0005 makes TS-0004 crash; a --redo of TS-0005 with the same edit now holds.
        crash = (77, REACHED[:3] + panicked(
            "consensus/src/simplex/voter.rs:9:9", "[statelens][INV-0001] votes counted"))
        self.worsened_by_an_accessor(crash)
        reach = self.repo / "statelens/campaign/reach"
        after = reach / "TS-0004_simplex_a/after-TS-0005_simplex_a"
        crashes = sorted(after.rglob("crash-*"))
        self.assertTrue(crashes)
        self.said.clear()
        self.replay_for = lambda _key, _tag, _name: None
        self.steps = [self.second_card(lambda: self.accessor("TS-0005"))]
        self.assertEqual(self.synthesize("--redo", "--match", "TS-0005"), 0)
        self.assertEqual(self.line("TS-0005"), "TS-0005    REACHED 4/4   " + self.SECOND)
        self.assertEqual(sorted(after.rglob("crash-*")), crashes)
        archived = next(reach.glob("TS-0005_simplex_a.*.md")).read_text()
        self.assertIn(f"see {self.rel(after)}/, so the pair's edits were restored", archived)
        moved = [path for path in (reach / "TS-0004_simplex_a").glob("after-TS-0005_simplex_a.*")]
        self.assertEqual(len(moved), 1)
        self.assertTrue((moved[0] / "final/replay.log").is_file())
        self.assertTrue(self.report("TS-0004_simplex_a").endswith(f"- Replays: {self.rel(moved[0])}/\n"))

    def test_an_earlier_scaffold_worse_without_the_card_too_takes_the_new_verdict(self):
        # TS-0004 is worse in every replay after its own synthesis, the pair's edits or not.
        partial = (0, ("phase prefix", "E1/4 missed cannot: journal seeding",
                       "handoff lost mark=2 next=-", "reach 0/4 control=0", "done"))
        self.steps = [self.write_scaffold(), self.second_card(lambda: self.accessor("TS-0005"))]
        self.replay_for = lambda key, tag, name: (
            partial if key == "TS-0004_simplex_a" and tag != "attempt-0" and name != "control" else None)
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line("TS-0005"), self.ROLLED_BACK)
        problem = (f"TS-0004_simplex_a's scaffold {self.FIRST} went from REACHED 4/4 to UNREACHED 0/4; see "
                   "statelens/campaign/reach/TS-0004_simplex_a/without-TS-0005_simplex_a/")
        self.assertIn(f"warning: TS-0004_simplex_a: {problem}, also with TS-0005_simplex_a's edits restored",
                      self.said)
        self.assertIn(f"- Note: TS-0004_simplex_a with the pair's edits restored: {problem}",
                      self.report("TS-0005_simplex_a"))
        report = self.report("TS-0004_simplex_a")
        self.assertIn("- Verdict: UNREACHED 0/4\n", report)
        self.assertIn("## Revalidation without TS-0005_simplex_a\n\n"
                      "- Cause: TS-0005_simplex_a's edits, which broke it, were restored\n"
                      "- Before: REACHED 4/4\n- Now: UNREACHED 0/4\n- Reason: E1 missed: cannot: "
                      "journal seeding\n", report)

    def test_the_last_check_builds_every_scaffold(self):
        # Something outside every card's diff, the fuzz toolchain for example, stops
        # TS-0004_simplex_a's scaffold from compiling between syntheses. The next synthesis has no
        # card to synthesize, so no revalidation sees it; the last check builds it all the
        # same, and the scaffold is not handed over.
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize(), 0)
        self.compiles = lambda scaffold: scaffold != self.FIRST
        self.said.clear()
        self.builds.clear()
        self.assertEqual(self.synthesize(), 2)
        self.assertIn("TS-0004    skipped: TS-0004 on simplex_a was synthesized as simplex_a_ts0004_statelens; "
                      "use --redo", self.said)
        self.assertEqual(self.builds, [self.FIRST])
        self.assertIn(f"error: the last check: the scaffold {self.FIRST} does not build; see "
                      f"statelens/campaign/logs/fuzz-build-{self.FIRST}-last.log, and undo the "
                      "pair whose edits broke it with --redo or use a fresh clone", self.said)
        self.assertFalse([line for line in self.said if line.startswith("run ")],
                         "no run line for a scaffold that does not build")

    # Revalidation after an undo: --redo and the last check undo a card's shared edits too.

    PARTIAL = (0, ("phase prefix", REACHED[1],
                   "E2/4 missed no nullify vote of R for v by the deadline",
                   "handoff lost mark=6 next=-", "phase continuation", "reach 1/4 control=0",
                   "done"))
    VOTER_PATH = "consensus/src/simplex/voter.rs"
    # An undone diff always changes the card's module, a public sibling of the others.
    UNDID = f"undid TS-0005_simplex_a, which changed {SECOND_MODULE}, {VOTER_PATH}"

    def partial_without_an_accessor(self):
        """TS-0004_simplex_a's scaffold replays PARTIAL 1/4 while voter.rs has no accessor."""
        self.replay_for = lambda key, _tag, name: (
            self.PARTIAL if key == "TS-0004_simplex_a" and name != "control"
            and "pub fn votes" not in self.read(self.VOTER_PATH) else None)

    def test_a_redo_that_undoes_shared_code_revalidates_the_kept_scaffolds(self):
        # The review's case: TS-0005_simplex_a's accessor raised TS-0004 to REACHED, and a --redo of
        # TS-0005 whose new version adds none takes it away again.
        self.partial_without_an_accessor()
        self.steps = [self.write_scaffold(), lambda: None]
        self.assertEqual(self.synthesize("--match", "TS-0004"), 0)
        self.assertIn("- Verdict: PARTIAL 1/4\n", self.report("TS-0004_simplex_a"))
        self.steps = [self.second_card(lambda: self.accessor("TS-0005"))]
        self.assertEqual(self.synthesize("--match", "TS-0005"), 0)
        self.assertIn("- Verdict: REACHED 4/4\n", self.report("TS-0004_simplex_a"))
        self.said.clear()
        self.builds.clear()
        self.steps = [self.second_card()]
        self.assertEqual(self.synthesize("--redo", "--match", "TS-0005"), 0)
        self.assertEqual(self.read(self.VOTER_PATH), VOTER)
        self.assertEqual(self.line("TS-0005"), "TS-0005    REACHED 4/4   " + self.SECOND)
        after = "statelens/campaign/reach/TS-0004_simplex_a/after-redo"
        self.assertIn(f"synthesis: --redo {self.UNDID}; revalidating TS-0004_simplex_a", self.said)
        self.assertIn(f"warning: TS-0004_simplex_a: TS-0004_simplex_a's scaffold {self.FIRST} went from REACHED 4/4 "
                      f"to PARTIAL 1/4; see {after}/", self.said)
        report = self.report("TS-0004_simplex_a")
        self.assertIn("- Verdict: PARTIAL 1/4\n", report)
        section = self.section(report, "Revalidation after --redo")
        self.assertTrue(section.startswith(f"- Cause: --redo {self.UNDID}\n- Before: REACHED 4/4\n"
                                           "- Now: PARTIAL 1/4\n- Reason: "), section)
        self.assertTrue(section.endswith(f"- Replays: {after}/\n"), section)
        for replay in ("canonical", "control", "final"):
            self.assertTrue((self.repo / after / replay / "replay.log").is_file())
        # TS-0004 is built for the revalidation, TS-0005 twice, TS-0004 for the new version's
        # revalidation, and both by the last check.
        self.assertEqual(self.builds, [self.FIRST] + [self.SECOND] * 2
                         + [self.FIRST, self.FIRST, self.SECOND])

    def test_a_redo_that_breaks_a_kept_scaffold_records_it_not_built(self):
        # TS-0005_simplex_a's scaffold compiles only with TS-0004_simplex_a's accessor, and a --redo of TS-0004
        # whose new version adds none takes it away.
        self.compiles = lambda scaffold: (
            scaffold != self.SECOND or "pub fn votes" in self.read(self.VOTER_PATH))
        self.steps = [self.write_scaffold(self.accessor), self.second_card()]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line("TS-0005"), "TS-0005    REACHED 4/4   " + self.SECOND)
        self.said.clear()
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize("--redo", "--match", "TS-0004"), 2)
        self.assertEqual(self.line("TS-0004"), "TS-0004    REACHED 4/4   " + self.FIRST)
        log = f"statelens/campaign/logs/fuzz-build-{self.SECOND}"
        problem = f"TS-0005_simplex_a's scaffold {self.SECOND} no longer builds; see {log}-after-redo.log"
        self.assertIn(f"warning: TS-0005_simplex_a: {problem}", self.said)
        report = self.report("TS-0005_simplex_a")
        self.assertIn("- Verdict: NOT BUILT (no longer builds)\n", report)
        self.assertTrue(report.endswith(
            "\n## Revalidation after --redo\n\n"
            f"- Cause: --redo undid TS-0004_simplex_a, which changed {self.FIRST_MODULE}, "
            "consensus/src/simplex/voter.rs\n"
            "- Before: REACHED 4/4\n- Now: NOT BUILT (no longer builds)\n"
            f"- Reason: {problem}\n"), report)
        error = (f"error: the last check: the scaffold {self.SECOND} does not build; see "
                 f"{log}-last.log")
        self.assertIn(error, "\n".join(self.said))
        # The report no longer records a verdict for a later card's revalidation; the last
        # check still builds the scaffold, so a run that synthesizes no card exits with code
        # 2 too and hands over no scaffold, until a --redo or a later card makes it build.
        self.said.clear()
        self.builds.clear()
        self.assertEqual(self.synthesize(), 2)
        self.assertIn(f"warning: {self.SECOND} has no card or no report with its verdict, so no "
                      "pair's edits revalidate it; the last check still builds it", self.said)
        self.assertEqual(self.builds, [self.FIRST, self.SECOND])
        self.assertIn(error, "\n".join(self.said))
        self.assertFalse([line for line in self.said if line.startswith("run ")],
                         "no run line for a scaffold that does not build")

    def force_a_last_check_undo(self):
        """The agent steps of TS-0004, then of TS-0005 with an accessor that raises TS-0004 to
        REACHED, and a guard 3 failure over the whole tree, which the per-attempt checks make
        impossible, forced on that accessor: the last check undoes TS-0005."""
        integrity, last_check = sl.Synthesis.integrity, sl.Synthesis.last_check
        self.addCleanup(setattr, sl.Synthesis, "integrity", integrity)
        self.addCleanup(setattr, sl.Synthesis, "last_check", last_check)

        def forced_integrity(synthesis):
            found = integrity(synthesis)
            if getattr(synthesis, "forced", False) and "pub fn votes" in self.read(
                    self.VOTER_PATH):
                found.append((self.VOTER_PATH, "guard 3: forced"))
            return found

        def forced_last_check(synthesis, outcomes):
            synthesis.forced = True
            return last_check(synthesis, outcomes)

        sl.Synthesis.integrity = forced_integrity
        sl.Synthesis.last_check = forced_last_check
        self.partial_without_an_accessor()
        self.steps = [self.write_scaffold(), lambda: None,
                      self.second_card(lambda: self.accessor("TS-0005"))]

    def test_a_last_check_that_undoes_shared_code_revalidates_the_kept_scaffolds(self):
        self.force_a_last_check_undo()
        self.assertEqual(self.synthesize(), 0)
        self.assertIn("TS-0005    NOT BUILT (last check)   no scaffold on simplex_a", self.said)
        self.assertEqual(self.read(self.VOTER_PATH), VOTER)
        self.assertIn(f"synthesis: the last check {self.UNDID}; revalidating TS-0004_simplex_a", self.said)
        report = self.report("TS-0004_simplex_a")
        self.assertIn("- Verdict: PARTIAL 1/4\n", report)
        self.assertIn("\n## Revalidation after TS-0005_simplex_a\n\n", report)
        section = report.split("\n## Revalidation after the last check\n\n", 1)[1]
        self.assertTrue(section.startswith(f"- Cause: the last check {self.UNDID}\n- Before: "
                                           "REACHED 4/4\n- Now: PARTIAL 1/4\n"), section)
        self.assertTrue((self.repo / "statelens/campaign/reach/TS-0004_simplex_a/after-last-check/final/"
                         "replay.log").is_file())
        self.assertIsNone(self.read(self.OWED))

    # An undo's revalidation an interrupt stops is completed by the next synthesis.

    OWED = "statelens/campaign/reach/revalidation.json"

    def assert_revalidation_stopped(self, what, key="TS-0005_simplex_a"):
        """The undo is done, TS-0004_simplex_a's report still says REACHED, and the revalidation the
        undo owes is recorded for the next synthesis."""
        self.assertEqual(self.read(self.VOTER_PATH), VOTER)
        self.assertIn("- Verdict: REACHED 4/4\n", self.report("TS-0004_simplex_a"))
        self.assertIsNotNone(self.read(self.OWED), "the revalidation owed is recorded")
        self.assertEqual(json.loads(self.read(self.OWED)),
                         {"what": [what], "undone": {key: [self.SECOND_MODULE, self.VOTER_PATH]}})
        self.assertEqual(self.said[-2:], [
            f"synthesis: the revalidation after {what} stopped; the next synthesis completes it "
            f"before any pair ({self.OWED})", "interrupted"])
        self.interrupt = None
        self.said.clear()
        self.builds.clear()

    def assert_revalidation_completed(self, what):
        self.assertIn(f"synthesis: {what} {self.UNDID}; revalidating TS-0004_simplex_a", self.said)
        report = self.report("TS-0004_simplex_a")
        self.assertIn("- Verdict: PARTIAL 1/4\n", report)
        section = self.section(report, f"Revalidation after {what}")
        self.assertTrue(section.startswith(f"- Cause: {what} {self.UNDID}\n- Before: REACHED 4/4"
                                           "\n- Now: PARTIAL 1/4\n"), section)
        # The interrupted revalidation's replays stay where they are.
        tag = sl.UNDO_TAGS[what]
        self.assertIn(f"- Replays: statelens/campaign/reach/TS-0004_simplex_a/{tag}.", section)
        self.assertTrue((self.repo / f"statelens/campaign/reach/TS-0004_simplex_a/{tag}/canonical/"
                         "replay.log").is_file())
        self.assertIsNone(self.read(self.OWED))

    def first_partial(self):
        """TS-0004, PARTIAL while voter.rs has no accessor."""
        self.partial_without_an_accessor()
        self.steps = [self.write_scaffold(), lambda: None]
        self.assertEqual(self.synthesize("--match", "TS-0004"), 0)
        self.assertIn("- Verdict: PARTIAL 1/4\n", self.report("TS-0004_simplex_a"))

    def an_accessor_raises_the_first(self):
        """TS-0004, PARTIAL without an accessor, then TS-0005, whose accessor raises it to
        REACHED: what a --redo of TS-0005 undoes."""
        self.first_partial()
        self.steps = [self.second_card(lambda: self.accessor("TS-0005"))]
        self.assertEqual(self.synthesize("--match", "TS-0005"), 0)
        self.assertIn("- Verdict: REACHED 4/4\n", self.report("TS-0004_simplex_a"))
        self.assertIsNone(self.read(self.OWED), "deleted once TS-0005_simplex_a's report was written")
        self.said.clear()
        self.builds.clear()

    def interrupted_redo(self):
        """The case of test_a_redo_that_undoes_shared_code_revalidates_the_kept_scaffolds, with
        the revalidation's control replay interrupted."""
        self.an_accessor_raises_the_first()
        self.interrupt = ("TS-0004_simplex_a", "after-redo", "control")
        self.assertEqual(self.synthesize("--redo", "--match", "TS-0005"), 130)
        self.assertIsNone(self.report("TS-0005_simplex_a"), "--redo moved it aside")
        self.assert_revalidation_stopped("--redo")

    def test_an_interrupted_redo_revalidation_is_completed_by_the_next_synthesis(self):
        # The review's case: the next synthesis of TS-0005, whose new version changes only its
        # own files, so it owes no revalidation of its own.
        self.interrupted_redo()
        self.steps = [self.second_card()]
        self.assertEqual(self.synthesize("--match", "TS-0005"), 0)
        self.assert_revalidation_completed("--redo")
        self.assertEqual(self.line("TS-0005"), "TS-0005    REACHED 4/4   " + self.SECOND)
        # TS-0004 is revalidated before the pair, and after its new version.
        self.assertEqual(self.builds, [self.FIRST] + [self.SECOND] * 2
                         + [self.FIRST, self.FIRST, self.SECOND])

    def test_a_synthesis_of_no_card_completes_an_interrupted_revalidation(self):
        self.interrupted_redo()
        self.assertEqual(self.synthesize("--match", "TS-0004"), 0)
        self.assertIn("TS-0004    skipped: TS-0004 on simplex_a was synthesized as "
                      "simplex_a_ts0004_statelens; use --redo", self.said)
        self.assert_revalidation_completed("--redo")
        # The revalidation's build and the last check's.
        self.assertEqual(self.builds, [self.FIRST, self.FIRST])

    def test_an_interrupted_last_check_revalidation_is_completed_by_the_next_synthesis(self):
        self.force_a_last_check_undo()
        self.interrupt = ("TS-0004_simplex_a", "after-last-check", "control")
        self.assertEqual(self.synthesize(), 130)
        self.assertIn("TS-0005    NOT BUILT (last check)   no scaffold on simplex_a", self.said)
        self.assert_revalidation_stopped("the last check")
        self.assertEqual(self.synthesize("--match", "TS-0004"), 0)
        self.assert_revalidation_completed("the last check")
        self.assertEqual(self.builds, [self.FIRST, self.FIRST])

    def test_an_unreadable_revalidation_record_stops_synthesis(self):
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize(), 0)
        self.put(self.OWED, json.dumps({"what": ["--bogus"], "undone": {}}))
        self.said.clear()
        self.assertEqual(self.synthesize("--match", "TS-0004"), 2)
        self.assertEqual(self.said[-1], f"error: {self.OWED} is unreadable (unknown undo "
                                        "['--bogus']); use a fresh clone")

    def test_an_undo_that_does_not_apply_records_no_revalidation(self):
        # A record of an undo that did not happen would make the next synthesis write "--redo
        # undid TS-0005" into every report, TS-0005_simplex_a's included, while its accessor stays.
        self.an_accessor_raises_the_first()
        self.edit("statelens/campaign/reach/TS-0005_simplex_a.diff", " impl Voter {\n", " impl Voter  {\n")
        self.assertEqual(self.synthesize("--redo", "--match", "TS-0005"), 2)
        self.assertTrue(self.said[-1].startswith(
            "error: the diff of TS-0005_simplex_a does not apply in reverse"), self.said[-1])
        self.assertIsNone(self.read(self.OWED))
        self.assertIn("pub fn votes", self.read(self.VOTER_PATH))
        self.assertIn("- Verdict: REACHED 4/4\n", self.report("TS-0005_simplex_a"))

    def test_a_redo_completes_an_undo_an_interrupt_stopped_before_the_reports_moved(self):
        # The diff no longer reverse-applies, but applies forward: the next --redo goes on.
        self.an_accessor_raises_the_first()
        archive = sl.Synthesis.archive
        self.addCleanup(setattr, sl.Synthesis, "archive", archive)

        def interrupted(*_args):
            raise KeyboardInterrupt

        sl.Synthesis.archive = interrupted
        self.assertEqual(self.synthesize("--redo", "--match", "TS-0005"), 130)
        sl.Synthesis.archive = archive
        self.assertEqual(self.read(self.VOTER_PATH), VOTER)
        self.assertIn("- Verdict: REACHED 4/4\n", self.report("TS-0005_simplex_a"))
        self.said.clear()
        self.steps = [self.second_card()]
        self.assertEqual(self.synthesize("--redo", "--match", "TS-0005"), 0)
        self.assertIn("warning: TS-0005_simplex_a: its edits were already undone, by an undo that stopped",
                      self.said)
        self.assertEqual(self.line("TS-0005"), "TS-0005    REACHED 4/4   " + self.SECOND)
        self.assertIn(f"synthesis: --redo {self.UNDID}; revalidating TS-0004_simplex_a", self.said)
        report = self.report("TS-0004_simplex_a")
        self.assertIn("- Verdict: PARTIAL 1/4\n", report)
        self.assertEqual(report.count("\n## Revalidation after --redo\n"), 1)
        self.assertIsNone(self.read(self.OWED))

    def test_a_revalidation_record_a_replay_removed_is_no_error(self):
        self.an_accessor_raises_the_first()
        partial = self.replay_for

        def removing(key, tag, name):
            (self.repo / self.OWED).unlink(missing_ok=True)
            return partial(key, tag, name)

        self.replay_for = removing
        self.steps = [self.second_card()]
        self.assertEqual(self.synthesize("--redo", "--match", "TS-0005"), 0)
        self.assertIn("- Verdict: PARTIAL 1/4\n", self.report("TS-0004_simplex_a"))

    # A card whose revalidation rewrote reports and whose edits are then restored owes that
    # revalidation: the reports hold verdicts the restored edits gave them.

    ROLLBACK = {"what": ["a rollback"], "undone": {"TS-0005_simplex_a": [SECOND_MODULE, VOTER_PATH]}}

    def assert_rollback_owed(self):
        owed = self.read(self.OWED)
        self.assertIsNotNone(owed, "the restore of TS-0005_simplex_a's edits owes TS-0004_simplex_a's revalidation")
        self.assertEqual(json.loads(owed), self.ROLLBACK)

    def assert_rollback_revalidated(self):
        """The next synthesis of TS-0005, whose new version writes only its own files and so
        owes no revalidation of its own, revalidates TS-0004 first: PARTIAL again."""
        self.said.clear()
        self.builds.clear()
        self.steps = [self.second_card()]
        self.assertEqual(self.synthesize("--match", "TS-0005"), 0)
        self.assertEqual(self.line("TS-0005"), "TS-0005    REACHED 4/4   " + self.SECOND)
        self.assertEqual(self.read(self.VOTER_PATH), VOTER)
        self.assertIn(f"synthesis: a rollback {self.UNDID}; revalidating TS-0004_simplex_a", self.said)
        report = self.report("TS-0004_simplex_a")
        self.assertIn("- Verdict: PARTIAL 1/4\n", report)
        section = self.section(report, "Revalidation after a rollback")
        self.assertTrue(section.startswith(f"- Cause: a rollback {self.UNDID}\n- Before: "
                                           "REACHED 4/4\n- Now: PARTIAL 1/4\n"), section)
        self.assertTrue(section.endswith(
            "- Replays: statelens/campaign/reach/TS-0004_simplex_a/after-rollback/\n"), section)
        self.assertIsNone(self.read(self.OWED))
        # TS-0004 is revalidated before the pair, and after its new version.
        self.assertEqual(self.builds, [self.FIRST] + [self.SECOND] * 2
                         + [self.FIRST, self.FIRST, self.SECOND])

    def test_a_card_interrupted_after_its_revalidation_rewrote_a_report_owes_it(self):
        # The review's case: TS-0005_simplex_a's accessor raises TS-0004 to REACHED, and the operator
        # interrupts right after TS-0004_simplex_a's report says so. The rollback takes the accessor
        # away; the reports are not restored, so TS-0004_simplex_a's REACHED rests on nothing.
        self.first_partial()
        restate = sl.Synthesis.restate
        self.addCleanup(setattr, sl.Synthesis, "restate", restate)

        def interrupted(synthesis, card_id, heading, *args):
            restate(synthesis, card_id, heading, *args)
            if heading == "Revalidation after TS-0005_simplex_a":
                self.assertIn("- Verdict: REACHED 4/4\n", self.report("TS-0004_simplex_a"))
                raise KeyboardInterrupt

        sl.Synthesis.restate = interrupted
        self.steps = [self.second_card(lambda: self.accessor("TS-0005"))]
        self.assertEqual(self.synthesize("--match", "TS-0005"), 130)
        sl.Synthesis.restate = restate
        self.assertEqual(self.read(self.VOTER_PATH), VOTER)
        self.assertIsNone(self.report("TS-0005_simplex_a"))
        self.assertFalse((self.repo / "statelens/campaign/reach/pending").exists())
        self.assertIn("- Verdict: REACHED 4/4\n", self.report("TS-0004_simplex_a"))
        self.assert_rollback_owed()
        self.assertEqual(self.said[-2:], [
            "synthesis: TS-0005_simplex_a's edits were restored after its revalidation may have "
            "rewritten reports; the next synthesis revalidates every scaffold before any pair "
            f"({self.OWED})",
            "interrupted"])
        self.assert_rollback_revalidated()

    def test_a_card_killed_after_its_revalidation_rewrote_a_report_owes_it(self):
        # Killed while writing TS-0005_simplex_a's report: the next synthesis restores TS-0005_simplex_a's edits
        # from pending/, then revalidates TS-0004.
        self.first_partial()
        write_report = sl.Synthesis.write_report
        self.addCleanup(setattr, sl.Synthesis, "write_report", write_report)

        def killed(synthesis, outcome):
            if outcome["pair"].key == "TS-0005_simplex_a":
                self.assertIn("- Verdict: REACHED 4/4\n", self.report("TS-0004_simplex_a"))
                self.killed()
            return write_report(synthesis, outcome)

        sl.Synthesis.write_report = killed
        self.steps = [self.second_card(lambda: self.accessor("TS-0005"))]
        self.assertEqual(self.synthesize("--match", "TS-0005"), 130)
        sl.Synthesis.write_report = write_report
        self.revive()
        self.assertIn("pub fn votes", self.read(self.VOTER_PATH))
        self.assertTrue((self.repo / "statelens/campaign/reach/pending").is_dir())
        self.assertIsNone(self.report("TS-0005_simplex_a"))
        self.assert_rollback_owed()
        self.assert_rollback_revalidated()
        self.assertIn("warning: TS-0005_simplex_a: a synthesis stopped without restoring the pair's "
                      "edits; they were restored", self.said)

    def test_a_card_interrupted_before_its_revalidation_rewrote_a_report_owes_nothing(self):
        # Interrupted during the last replay of TS-0004_simplex_a's revalidation: no report changed.
        self.first_partial()
        self.interrupt = ("TS-0004_simplex_a", "after-TS-0005_simplex_a", "final")
        self.steps = [self.second_card(lambda: self.accessor("TS-0005"))]
        self.assertEqual(self.synthesize("--match", "TS-0005"), 130)
        self.assertEqual(self.read(self.VOTER_PATH), VOTER)
        report = self.report("TS-0004_simplex_a")
        self.assertIn("- Verdict: PARTIAL 1/4\n", report)
        self.assertNotIn("Revalidation", report)
        self.assertIsNone(self.read(self.OWED))

    def test_a_crash_stops_refinement_and_is_kept(self):
        self.steps = [self.write_scaffold()]
        self.replays["canonical"] = (77, REACHED[:3] + panicked(
            "consensus/src/simplex/voter.rs:9:9", "[statelens][INV-0001] votes counted"))
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(len(self.prompts), 1)
        line = self.line()
        self.assertTrue(line.startswith("TS-0004    CRASH (finding candidate)"), line)
        self.assertIn("simplex_a_ts0004_statelens; failed in the canonical replay", line)
        attempt = self.repo / "statelens/campaign/reach/TS-0004_simplex_a/attempt-0"
        crash = next((attempt / "canonical").glob("crash-*"))
        replay = next(line for line in self.said if line.startswith("replay "))
        self.assertTrue(replay.endswith(f"just run simplex_a_ts0004_statelens {crash}"), replay)
        self.assertNotIn("STATELENS_REACH_CONTROL", replay)
        self.assertTrue((attempt / "final/replay.log").is_file())
        self.assertIn("- Crash: panic in the canonical replay", self.report())

    def test_a_crash_in_the_control_run_only_names_the_control(self):
        self.steps = [self.write_scaffold()]
        self.replays["control"] = (77, CONTROL[:2] + panicked(
            "consensus/src/simplex/voter.rs:9:9", "[statelens][INV-0001] votes counted"))
        self.assertEqual(self.synthesize(), 0)
        self.assertIn("failed in the control replay", self.line())
        replay = next(line for line in self.said if line.startswith("replay "))
        self.assertIn("STATELENS_REACH=1 STATELENS_REACH_CONTROL=1 CONSENSUS_FUZZ_LOG=1", replay)

    def test_a_revalidation_rewrites_the_run_and_replay_lines_for_its_failure(self):
        # The review's case: TS-0004_simplex_a's canonical replay fails at its synthesis, and after
        # TS-0005_simplex_a's accessor the failure moves to the control replay, a CRASH still. The
        # report's lines reproduce the latest check: the control replay of the revalidation.
        crash = REACHED[:4] + panicked("toy.rs:1:1", "toy assertion failed")
        self.replay_for = lambda key, tag, name: (
            (77, crash) if key == "TS-0004_simplex_a" and (
                (tag == "attempt-0" and name != "control")
                or (tag == "after-TS-0005_simplex_a" and name == "control")) else None)
        self.steps = [self.write_scaffold(), self.second_card(lambda: self.accessor("TS-0005"))]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line("TS-0005"), "TS-0005    REACHED 4/4   " + self.SECOND)
        report = self.report("TS-0004_simplex_a")
        self.assertIn("- Verdict: CRASH (finding candidate)\n", report)
        # The top line is the synthesis-time record; the section carries the current one.
        self.assertIn("- Crash: panic in the canonical replay, phase prefix, at toy.rs:1:1: ",
                      report)
        section = self.section(report, "Revalidation after TS-0005_simplex_a")
        self.assertIn("- Now: CRASH (finding candidate)\n", section)
        self.assertIn("- Crash: panic in the control replay, phase prefix, at toy.rs:1:1: ",
                      section)
        run, replay = self.run_block(report)
        here = f"cd {self.repo / 'statelens'} && "
        self.assertEqual(run, f"{here}NIGHTLY_VERSION=nightly-test just run {self.FIRST}")
        after = self.repo / "statelens/campaign/reach/TS-0004_simplex_a/after-TS-0005_simplex_a/control"
        self.assertEqual(replay, f"{here}STATELENS_REACH=1 STATELENS_REACH_CONTROL=1 "
                         f"CONSENSUS_FUZZ_LOG=1 NIGHTLY_VERSION=nightly-test just run "
                         f"{self.FIRST} {next(after.glob('crash-*'))}")

    def test_a_revalidation_that_loses_the_failure_restores_the_placeholder(self):
        # TS-0004 fails on its canonical input at its synthesis and while TS-0005_simplex_a's accessor
        # is in the tree; a --redo of TS-0005 whose new version adds none takes the failure
        # away, and the lines carry the placeholder again.
        crash = (77, REACHED[:4] + panicked("toy.rs:1:1", "toy assertion failed"))
        self.replay_for = lambda key, tag, name: (
            crash if key == "TS-0004_simplex_a" and name != "control" and (
                tag == "attempt-0" or "pub fn votes" in self.read(self.VOTER_PATH)) else None)
        self.steps = [self.write_scaffold(), self.second_card(lambda: self.accessor("TS-0005"))]
        self.assertEqual(self.synthesize(), 0)
        _run, replay = self.run_block(self.report("TS-0004_simplex_a"))
        after = self.repo / "statelens/campaign/reach/TS-0004_simplex_a/after-TS-0005_simplex_a/canonical"
        self.assertTrue(replay.endswith(f"just run {self.FIRST} {next(after.glob('crash-*'))}"),
                        replay)
        self.steps = [self.second_card()]
        self.assertEqual(self.synthesize("--redo", "--match", "TS-0005"), 0)
        report = self.report("TS-0004_simplex_a")
        self.assertIn("- Verdict: REACHED 4/4\n", report)
        self.assertIn("- Crash: panic in the canonical replay", report)
        section = self.section(report, "Revalidation after --redo")
        self.assertTrue(section.startswith(
            f"- Cause: --redo {self.UNDID}\n- Before: CRASH (finding candidate)\n"
            "- Now: REACHED 4/4\n"), section)
        self.assertNotIn("- Crash:", section)
        _run, replay = self.run_block(report)
        self.assertTrue(replay.endswith(f"just run {self.FIRST} {self.repo}/consensus/fuzz/"
                                        f"simplex/artifacts/{self.FIRST}/<crash file>"), replay)
        self.assertNotIn("STATELENS_REACH_CONTROL", replay)

    def test_a_redo_moves_the_crash_files_and_the_lines_that_name_them(self):
        # The archived report and replay.txt named crash files under the live TS-0004_simplex_a/, and
        # the crash files fuzzing wrote for the undone version stayed beside its replacement.
        self.steps = [self.write_scaffold(lambda: self.put("crash-0123", "input"))]
        self.replays["canonical"] = (77, REACHED[:3] + panicked(
            "consensus/src/simplex/voter.rs:9:9", "[statelens][INV-0001] votes counted"))
        self.assertEqual(self.synthesize(), 0)
        fuzzed = "consensus/fuzz/simplex/artifacts/simplex_a_ts0004_statelens/crash-old"
        self.put(fuzzed, "an input of the undone version")
        seed = "consensus/fuzz/simplex/corpus/simplex_a_ts0004_statelens/seed"
        self.put(seed, "seed")
        self.replays["canonical"] = (0, REACHED)
        self.steps = [self.write_scaffold()]
        self.said.clear()
        self.assertEqual(self.synthesize("--redo"), 0)
        self.assertEqual(self.line(), "TS-0004    REACHED 4/4   simplex_a_ts0004_statelens")
        reach = self.repo / "statelens/campaign/reach"
        archived = next(path for path in reach.glob("TS-0004_simplex_a.*") if path.is_dir())
        moved = archived / "artifacts/simplex_a_ts0004_statelens"
        self.assertFalse((self.repo / fuzzed).parent.exists())
        self.assertEqual((moved / "crash-old").read_text(), "an input of the undone version")
        self.assertIn(f"TS-0004_simplex_a: --redo moved consensus/fuzz/simplex/artifacts/"
                      f"simplex_a_ts0004_statelens/ to {self.rel(moved)}/", self.said)
        self.assertEqual(self.read(seed), "seed", "the corpus stays")
        report = (reach / f"{archived.name}.md").read_text()
        replay = (archived / "attempt-0/replay.txt").read_text()
        crash = next((archived / "attempt-0/canonical").glob("crash-*"))
        swept = archived / "attempt-0/swept/crash-0123"
        self.assertTrue(swept.is_file())
        self.assertIn(f"just run simplex_a_ts0004_statelens {crash}\n", replay)
        self.assertIn(f"just run simplex_a_ts0004_statelens {crash}\n", report)
        self.assertIn(self.rel(swept), report)
        for text in (report, replay):
            self.assertNotIn("/reach/TS-0004_simplex_a/", text)

    # One card on several bases: a pair per base, each a transaction of its own.

    ON_B = "simplex_b_ts0004_statelens"
    MODULE_ON_B = "consensus/fuzz/simplex/src/target_states/ts0004_simplex_b.rs"

    def add_base(self, base="simplex_b"):
        """Adds the target `base` to the package, its file and its [[bin]] block, before the
        first synthesis, so that the baseline B holds it; TS-0004 then has two pairs."""
        self.put(f"consensus/fuzz/simplex/fuzz_targets/{base}.rs", BASE_TARGET)
        self.run_git("add", "--intent-to-add", f"consensus/fuzz/simplex/fuzz_targets/{base}.rs")
        block = FUZZ_MANIFEST.split("\n[[bin]]\n", 1)[1].replace("simplex_a", base)
        self.put(sl.FUZZ_MANIFEST, self.read(sl.FUZZ_MANIFEST) + "\n[[bin]]\n" + block)

    def lines(self, card="TS-0004"):
        return [line for line in self.said if line.startswith(card + " ")]

    def test_one_card_on_several_bases_gets_a_scaffold_per_base(self):
        self.add_base()
        self.steps = [self.write_scaffold(), lambda: self.scaffold(base="simplex_b")]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(len(self.prompts), 2, "one agent run per pair")
        for prompt, base in zip(self.prompts, ("simplex_a", "simplex_b")):
            self.assertIn(f"The base, `{base}`:", prompt)
            self.assertIn(f"- `{base}`: closure `fuzz_target!(|input: FuzzInput| {{`", prompt)
            self.assertNotIn("simplex_b" if base == "simplex_a" else "simplex_a", prompt)
            self.assertIn(f"consensus/fuzz/simplex/src/target_states/ts0004_{base}.rs", prompt)
            self.assertIn(f"consensus/fuzz/simplex/fuzz_targets/{base}_ts0004_statelens.rs",
                          prompt)
            self.assertIn(f"//! TS-0004 on {base}\n", prompt)
            self.assertIn(f"cargo +nightly-test fuzz build --fuzz-dir consensus/fuzz/simplex "
                          f"{base}_ts0004_statelens", prompt)
        self.assertEqual(self.lines(), ["TS-0004    REACHED 4/4   " + self.FIRST,
                                        "TS-0004    REACHED 4/4   " + self.ON_B])
        self.assertIn("synthesis  2 pair(s), 2 scaffold(s); reports in statelens/campaign/reach/",
                      self.said)
        here = f"run        cd {self.repo / 'statelens'} && NIGHTLY_VERSION=nightly-test just run "
        self.assertEqual([line for line in self.said if line.startswith("run ")],
                         [here + self.FIRST, here + self.ON_B])
        # Each pair has its own reports, attempt directory and diff; the tree holds both.
        reach = self.repo / "statelens/campaign/reach"
        for key, module in (("TS-0004_simplex_a", self.FIRST_MODULE),
                            ("TS-0004_simplex_b", self.MODULE_ON_B)):
            self.assertIn("- Verdict: REACHED 4/4\n", self.report(key))
            self.assertIn(f"# TS-0004 on {key.split('_', 1)[1]}: ", self.report(key))
            self.assertTrue((reach / key / "attempt-0/final/replay.log").is_file())
            self.assertIn(f"+++ b/{module}", (reach / f"{key}.diff").read_text())
            self.assertEqual(self.read(module).splitlines()[0],
                             f"//! TS-0004 on {key.split('_', 1)[1]}")
        helper = self.read("consensus/fuzz/simplex/src/target_states/mod.rs")
        self.assertTrue(helper.endswith("\n\npub mod ts0004_simplex_a;\npub mod ts0004_simplex_b;\n"))
        manifest = self.read(sl.FUZZ_MANIFEST)
        for name in (self.FIRST, self.ON_B):
            self.assertIn(f'name = "{name}"\npath = "fuzz_targets/{name}.rs"', manifest)
        # The second pair's module is shared code, so it revalidates the first pair's scaffold.
        self.assertEqual(self.builds, [self.FIRST] * 2 + [self.ON_B] * 2
                         + [self.FIRST, self.FIRST, self.ON_B])
        self.assertTrue((reach / "TS-0004_simplex_a/after-TS-0004_simplex_b/final/replay.log")
                        .is_file())
        self.assertEqual(
            self.section(self.report("TS-0004_simplex_a"), "Revalidation after TS-0004_simplex_b"),
            f"- Cause: TS-0004_simplex_b changed {self.MODULE_ON_B}\n"
            "- Before: REACHED 4/4\n- Now: REACHED 4/4\n"
            "- Replays: statelens/campaign/reach/TS-0004_simplex_a/after-TS-0004_simplex_b/\n")
        self.assertNotIn("Revalidation", self.report("TS-0004_simplex_b"))
        # Both pairs are skipped by the next run, each with its own line.
        self.said.clear()
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.lines(), [
            "TS-0004    skipped: TS-0004 on simplex_a was synthesized as "
            f"{self.FIRST}; use --redo",
            f"TS-0004    skipped: TS-0004 on simplex_b was synthesized as {self.ON_B}; use --redo",
        ])

    def test_a_pair_is_skipped_while_its_sibling_is_synthesized(self):
        self.add_base()
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize("--match", "simplex_a"), 0)
        self.assertEqual(self.lines(), ["TS-0004    REACHED 4/4   " + self.FIRST])
        self.said.clear()
        self.steps = [lambda: self.scaffold(base="simplex_b")]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.lines(), [
            f"TS-0004    skipped: TS-0004 on simplex_a was synthesized as {self.FIRST}; use --redo",
            "TS-0004    REACHED 4/4   " + self.ON_B,
        ])
        self.assertEqual(len(self.prompts), 2)
        self.assertIn("synthesis  1 pair(s), 2 scaffold(s)", "\n".join(self.said))

    def test_a_redo_of_one_pair_leaves_its_sibling_standing(self):
        self.add_base()
        self.steps = [self.write_scaffold(), lambda: self.scaffold(base="simplex_b")]
        self.assertEqual(self.synthesize(), 0)
        before = self.read(sl.FUZZ_MANIFEST)
        self.said.clear()
        self.builds.clear()
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize("--redo", "--match", "simplex_a_ts0004"), 0)
        self.assertEqual(len(self.prompts), 3, "only the selected pair runs again")
        self.assertEqual(self.lines(), ["TS-0004    REACHED 4/4   " + self.FIRST])
        reach = self.repo / "statelens/campaign/reach"
        self.assertEqual(len(list(reach.glob("TS-0004_simplex_a.*.md"))), 1)
        self.assertEqual(len([path for path in reach.glob("TS-0004_simplex_a.*")
                              if path.is_dir()]), 1)
        self.assertEqual(sorted(path.name for path in reach.glob("TS-0004_simplex_b*")),
                         ["TS-0004_simplex_b", "TS-0004_simplex_b.diff", "TS-0004_simplex_b.md"],
                         "the sibling's outputs stay where they are")
        self.assertIn(f"TS-0004_simplex_a: --redo undid its edits; its reports are now "
                      "TS-0004_simplex_a.", "\n".join(self.said))
        # The sibling's block, thin target and module were never touched; the pair's block
        # was removed by its exact name and added again after the sibling's.
        manifest = self.read(sl.FUZZ_MANIFEST)
        self.assertEqual(sorted(sl.bin_blocks(manifest)), sorted(sl.bin_blocks(before)))
        self.assertEqual(manifest.count(f'name = "{self.ON_B}"'), 1)
        self.assertLess(manifest.index(self.ON_B), manifest.index(self.FIRST))
        self.assertTrue((self.repo / f"consensus/fuzz/simplex/fuzz_targets/{self.ON_B}.rs").is_file())
        self.assertEqual(self.read(self.MODULE_ON_B).splitlines()[0], "//! TS-0004 on simplex_b")
        # The undo of the first pair's module revalidates the sibling, and so does the new
        # version; the sibling is built for each, the pair twice, and both by the last check.
        self.assertIn(f"synthesis: --redo undid TS-0004_simplex_a, which changed "
                      f"{self.FIRST_MODULE}; revalidating TS-0004_simplex_b", self.said)
        self.assertEqual(self.builds, [self.ON_B] + [self.FIRST] * 2
                         + [self.ON_B, self.FIRST, self.ON_B])
        report = self.report("TS-0004_simplex_b")
        self.assertIn("- Verdict: REACHED 4/4\n", report)
        section = self.section(report, "Revalidation after --redo")
        self.assertTrue(section.startswith(
            f"- Cause: --redo undid TS-0004_simplex_a, which changed {self.FIRST_MODULE}\n"
            "- Before: REACHED 4/4\n- Now: REACHED 4/4\n"), section)
        self.assertIn("## Revalidation after TS-0004_simplex_a\n", report)
        self.assertIsNone(self.read(self.OWED))

    def test_a_pair_that_breaks_its_sibling_is_rolled_back(self):
        # The second pair changes the first pair's fuzz signature; the first thin target,
        # which passes one argument, no longer builds.
        self.add_base()

        def signature():
            self.scaffold(base="simplex_b")
            self.edit(self.FIRST_MODULE, "(input: crate::FuzzInput)",
                      "(input: crate::FuzzInput, extra: u8)")

        self.steps = [self.write_scaffold(), signature]
        self.compiles = lambda scaffold: (
            scaffold != self.FIRST or "extra: u8" not in self.read(self.FIRST_MODULE))
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.lines(), [
            "TS-0004    REACHED 4/4   " + self.FIRST,
            "TS-0004    NOT BUILT (breaks TS-0004_simplex_a)   no scaffold on simplex_b",
        ])
        self.assertEqual(self.builds, [self.FIRST] * 2 + [self.ON_B] * 2 + [self.FIRST] * 3)
        self.assertEqual(self.read(self.FIRST_MODULE), SCAFFOLD_MODULE)
        self.assertIsNone(self.read(self.MODULE_ON_B))
        self.assertIsNone(self.read(f"consensus/fuzz/simplex/fuzz_targets/{self.ON_B}.rs"))
        self.assertNotIn(self.ON_B, self.read(sl.FUZZ_MANIFEST))
        helper = self.read("consensus/fuzz/simplex/src/target_states/mod.rs")
        self.assertIn("pub mod ts0004_simplex_a;", helper)
        self.assertNotIn("pub mod ts0004_simplex_b;", helper)
        report = self.report("TS-0004_simplex_b")
        self.assertIn(f"- Note: TS-0004_simplex_a's scaffold {self.FIRST} no longer builds; see "
                      f"statelens/campaign/logs/fuzz-build-{self.FIRST}-after-TS-0004_simplex_b.log, "
                      "so the pair's edits were restored", report)
        self.assertIn("- Note: TS-0004_simplex_a with the pair's edits restored: REACHED 4/4",
                      report)
        self.assertEqual(self.read("statelens/campaign/reach/TS-0004_simplex_b.diff"), "")
        self.assertNotIn("Revalidation", self.report("TS-0004_simplex_a"))
        self.assertEqual([line for line in self.said if line.startswith("run ")],
                         [f"run        cd {self.repo / 'statelens'} && NIGHTLY_VERSION="
                          f"nightly-test just run {self.FIRST}"])

    def test_a_thin_target_of_another_base_is_vetoed(self):
        self.add_base()
        other = f"consensus/fuzz/simplex/fuzz_targets/{self.ON_B}.rs"
        for name, breach, finding in (
            ("a thin target on another base", lambda: self.put(
                other, THIN.replace("ts0004_simplex_a", "ts0004_simplex_b")),
             f"{other} is a thin target of this card on another base; this scaffold is "
             f"{self.FIRST}"),
            ("a header naming another base", lambda: self.edit(
                self.FIRST_MODULE, "//! TS-0004 on simplex_a\n", "//! TS-0004 on simplex_b\n"),
             "the module must open with the header of the prompt: `//! TS-0004 on simplex_a`"),
        ):
            with self.subTest(name):
                del self.prompts[:]
                self.builds = []
                self.steps = [self.write_scaffold(breach)]
                self.assertEqual(self.synthesize("--redo", "--match", "simplex_a"), 3)
                self.assertEqual(len(self.prompts), 2, "the second attempt changes nothing")
                self.assertIn(finding, self.feedback(1))
                self.assertEqual(self.builds, [])
                self.assert_restored()
                self.assertIsNone(self.read(other))
                self.assertEqual(self.lines(), ["TS-0004    NOT BUILT   no scaffold on simplex_a"])
                self.said.clear()

    def test_a_build_in_cargo_target_dir_is_found(self):
        # cargo-fuzz builds into CARGO_TARGET_DIR, where synthesis did not look: NOT BUILT.
        custom = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, custom, True)
        os.environ["CARGO_TARGET_DIR"] = str(custom)
        self.steps = [self.write_scaffold()]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(self.line(), "TS-0004    REACHED 4/4   simplex_a_ts0004_statelens")
        self.assertTrue((custom / "host/release/simplex_a_ts0004_statelens").is_file())
        self.assertFalse((self.repo / "target").exists())

    def test_a_stray_crash_file_is_swept_and_a_finding_candidate(self):
        self.steps = [self.write_scaffold(lambda: self.put("crash-0123", "input"))]
        self.assertEqual(self.synthesize(), 0)
        self.assertEqual(len(self.prompts), 1, "a stray failure stops refinement")
        self.assertFalse((self.repo / "crash-0123").exists())
        swept = "statelens/campaign/reach/TS-0004_simplex_a/attempt-0/swept/crash-0123"
        self.assertTrue((self.repo / swept).is_file())
        line = self.line()
        self.assertTrue(line.startswith("TS-0004    CRASH (finding candidate)"), line)
        self.assertIn("stray failure", line)
        self.assertIn(swept, line)

    def test_preconditions(self):
        self.assertEqual(self.synthesize("--profile", "qmdb"), 1)
        self.assertEqual(self.synthesize("--match", "nothing*"), 1)
        for name, change, message in (
            ("base", lambda: self.meta.update(base="0" * 40), "but HEAD is"),
            ("false", lambda: self.meta.update(invariants=["FALSE-0001"]), "FALSE-0001"),
            ("profile", lambda: self.meta.update(profile="marshal"), "ran the marshal profile"),
        ):
            with self.subTest(name):
                saved = dict(self.meta)
                change()
                self.put("statelens/campaign/meta.json", json.dumps(self.meta))
                self.said.clear()
                self.assertEqual(self.synthesize("--profile", "simplex"), 2)
                self.assertIn(message, "\n".join(self.said))
                self.meta = saved
                self.put("statelens/campaign/meta.json", json.dumps(self.meta))
        self.put("statelens/campaign/summary.txt", "statelens: result     BUILD FAILED\n")
        self.assertEqual(self.synthesize(), 2)
        self.put("statelens/campaign/summary.txt", "statelens: result     PANIC (tests)\n")
        self.put(sl.STATELENS_RS, "pub fn seen() {}\n")
        self.assertEqual(self.synthesize(), 2)
        self.assertIn("predates the read side", "\n".join(self.said))
        (self.repo / "statelens/campaign/meta.json").unlink()
        self.assertEqual(self.synthesize(), 2)
        self.assertEqual(self.prompts, [])

    def test_usage_and_campaign_errors_come_before_the_agent_cli(self):
        def missing(_agent):
            raise sl.Abort(2, "claude is not on PATH")

        sl.check_agent_cli = missing
        self.assertEqual(self.synthesize("--match", "nothing*"), 1)
        self.meta.update(base="0" * 40)
        self.put("statelens/campaign/meta.json", json.dumps(self.meta))
        self.said.clear()
        self.assertEqual(self.synthesize(), 2)
        self.assertIn("but HEAD is", "\n".join(self.said))
        self.assertNotIn("not on PATH", "\n".join(self.said))

    def test_first_run_drops_the_lines_of_the_leak_check_rerun(self):
        text = replay_output(REACHED) * 2 + "INFO: done\n"
        trimmed = sl.first_run(text, "TS-0004")
        self.assertEqual(trimmed.count("[statelens-reach] TS-0004 done"), 1)
        self.assertEqual(trimmed.count("Running: reach/empty"), 2)
        self.assertTrue(trimmed.endswith("INFO: done\n"))
        self.assertEqual(sl.first_run("x\n", "TS-0004"), "x\n")

    def test_remove_bin_blocks_undoes_the_appended_block(self):
        blocks = sl.bin_blocks(FUZZ_MANIFEST)
        first = sl.variant_bin_block(blocks, "simplex_a", name="simplex_a_ts0004_statelens")
        second = sl.variant_bin_block(blocks, "simplex_a", name="simplex_a_ts0005_statelens")
        both = FUZZ_MANIFEST + first + second
        self.assertEqual(sl.remove_bin_blocks(both, "*_ts0004_statelens"), FUZZ_MANIFEST + second)
        self.assertEqual(sl.remove_bin_blocks(both, "*_ts0005_statelens"), FUZZ_MANIFEST + first)
        # An undo names the pair's block exactly, so a sibling pair's block of the same card
        # survives it.
        sibling = sl.variant_bin_block(blocks, "simplex_a", name="simplex_b_ts0004_statelens")
        self.assertEqual(sl.remove_bin_blocks(both + sibling, "simplex_a_ts0004_statelens"),
                         FUZZ_MANIFEST + second + sibling)

    def test_sl_calls_ignore_moves_and_reformatting(self):
        one = 'fn f() {\n    sl_assert!(None, "INV-1", a > 0, "x");\n}\n'
        moved = 'fn g() {}\nfn f() {\n    if y {\n        sl_assert!(\n            None,\n' \
                '            "INV-1",\n            a > 0,\n            "x",\n        );\n    }\n}\n'
        self.assertEqual(sl.sl_calls(one), sl.sl_calls(moved))
        self.assertNotEqual(sl.sl_calls(one), sl.sl_calls(one.replace("a > 0", "a >= 0")))
        self.assertEqual(sl.sl_calls("// sl_assert!(None, \"INV-1\", a, \"x\");\n"),
                         sl.collections.Counter())


if __name__ == "__main__":
    unittest.main(verbosity=2)
